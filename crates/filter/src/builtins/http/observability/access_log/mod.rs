// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Structured access log filter with configurable format, field selection,
//! sampling, header projection, and emit-time conditions.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    BodyAccess, FilterAction, FilterError,
    factory::parse_filter_config,
    filter::{HttpFilter, HttpFilterContext},
};

mod config;
mod emit;
mod format;
mod sink;
#[cfg(feature = "access-log-syslog")]
mod syslog;

use config::{AccessLogConfig, AccessLogEmitConditions, validate_emit_conditions};
pub use emit::{access_record_already_emitted, bodyless_response, emit_access_record, mark_access_record_emitted};
use emit::{request_is_grpc, truncate_u128};
use format::{
    EmitPlan, EmitShape, FieldToken, TemplatePart, normalize_header_names, parse_field_tokens, parse_template,
};
pub use sink::shutdown_sinks;
use sink::{RuntimeSink, build_runtime_sink};

// -----------------------------------------------------------------------------
// AccessLogFilter
// -----------------------------------------------------------------------------

/// Logs structured access records for each request and response.
///
/// # YAML configuration
///
/// ```yaml
/// filter: access_log
/// sample_rate: 0.1   # optional; log ~10% of requests (default 1.0)
/// fields:            # optional; replaces default ten fields when present
///   - method
///   - path
///   - status
///   - duration_ms
///   - request_header.user-agent
///   - trace_id
/// request_headers: [user-agent]   # optional; pairs with request_header.* tokens
/// response_headers: [content-type]
/// conditions:                   # optional emit-time gates (AND across keys)
///   min_duration_ms: 1000
///   status_classes: [4xx, 5xx]  # OR within list
///   paths: ["/api"]             # OR within list; segment-boundary prefixes
/// sink:                         # optional; default emits via the subscriber
///   type: file                  # `stdout` or `file`
///   path: /var/log/praxis/access.log  # required for `file`, rejected for `stdout`
/// ```
///
/// # Template YAML
///
/// ```yaml
/// filter: access_log
/// # Mutually exclusive with `fields`; quote client-controlled tokens.
/// template: '{method} {path} [{status}] {duration_ms}ms ua="{request_header.user-agent}"'
/// request_headers: [user-agent]
/// ```
///
/// When `fields` is omitted, the default ten fields are emitted:
/// `method`, `path`, `client_ip`, `status`, `duration_ms`, `cluster`,
/// `upstream`, `request_id`, `request_body_bytes`, `response_body_bytes`.
///
/// When `template` is set, the rendered string is logged as the `line` field of
/// the `access` event; `PRAXIS_LOG_FORMAT` still decides whether the subscriber
/// writes text or JSON. Otherwise the record is a field projection. Each resolved
/// value is control-character sanitized and has `"` and `\` escaped, so quote
/// client-controlled tokens (`{request_header.*}`, `{request_id}`) in the
/// template to keep fields unambiguous.
///
/// Template tokens follow the same names as field tokens: `{method}`,
/// `{path}`, `{client_ip}`, `{status}`, `{duration_ms}`, `{cluster}`,
/// `{upstream}`, `{request_id}`, `{request_body_bytes}`,
/// `{response_body_bytes}`, `{trace_id}`, `{span_id}`,
/// `{request_header.user-agent}`, `{response_header.content-type}`.
///
/// Pipeline `conditions` / `response_conditions` on the filter entry still gate
/// whether this filter runs; access-log `conditions` are evaluated at emit time.
/// Both layers must pass when configured.
///
/// # Example
///
/// ```ignore
/// use praxis_filter::AccessLogFilter;
///
/// let yaml: serde_yaml::Value = serde_yaml::from_str("sample_rate: 0.5").unwrap();
/// let filter = AccessLogFilter::from_config(&yaml).unwrap();
/// assert_eq!(filter.name(), "access_log");
/// ```
pub struct AccessLogFilter {
    /// Monotonic counter for deterministic sampling.
    pub(crate) counter: AtomicU64,

    /// Fraction of requests to log, in `(0.0, 1.0]`; `1.0` logs everything.
    pub(crate) sample_rate: f64,

    /// Selected fields, format shape, and header projections.
    pub(crate) emit_plan: EmitPlan,

    /// Emit-time gates evaluated after the response is known.
    pub(crate) emit_conditions: Option<AccessLogEmitConditions>,

    /// Whether response headers must be cached for emit.
    pub(crate) needs_response_headers: bool,

    /// Where emitted records are written (tracing by default).
    pub(crate) sink: RuntimeSink,
}

/// Cached response metadata for emit on the body phase.
#[derive(Clone, Debug)]
struct AccessLogState {
    /// Response status captured on `on_response`.
    status: u16,
    /// Response headers, cached only when a selected field needs them.
    response_headers: Option<http::HeaderMap>,
}

// -----------------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------------

impl AccessLogFilter {
    /// Create an access log filter from parsed YAML config.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if config is invalid.
    ///
    /// [`FilterError`]: crate::FilterError
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: AccessLogConfig = parse_filter_config("access_log", config)?;
        Ok(Box::new(Self::build(cfg)?))
    }

    /// Validate config and assemble the runtime emit plan and sink.
    #[expect(clippy::too_many_lines, reason = "config validation and emit plan assembly")]
    fn build(cfg: AccessLogConfig) -> Result<Self, FilterError> {
        // NaN compares false against both bounds, so a plain range check
        // lets it through and then every sampling comparison fails.
        if !cfg.sample_rate.is_finite() || cfg.sample_rate <= 0.0 || cfg.sample_rate > 1.0 {
            return Err(format!("access_log: sample_rate must be in (0.0, 1.0], got {}", cfg.sample_rate).into());
        }

        // A template names its own fields inline, so pairing it with a `fields`
        // projection is ambiguous.
        if cfg.fields.is_some() && cfg.template.is_some() {
            return Err("access_log: fields and template are mutually exclusive".into());
        }

        if let Some(fields) = &cfg.fields {
            if fields.is_empty() {
                return Err("access_log: fields must not be empty when present".into());
            }
            for value in fields {
                if !value.is_string() {
                    return Err(
                        "access_log: fields must be a list of scalar tokens; nested maps are not allowed".into(),
                    );
                }
            }
        }

        let request_headers = normalize_header_names(cfg.request_headers.as_deref())?;
        let response_headers = normalize_header_names(cfg.response_headers.as_deref())?;

        if request_headers.is_empty() && cfg.request_headers.is_some() {
            return Err("access_log: request_headers must not be empty when present".into());
        }
        if response_headers.is_empty() && cfg.response_headers.is_some() {
            return Err("access_log: response_headers must not be empty when present".into());
        }

        let shape = if let Some(template) = cfg.template {
            if template.trim().is_empty() {
                return Err("access_log: template must not be empty".into());
            }
            let parts = parse_template(&template, &request_headers, &response_headers)?;
            if !parts.iter().any(|part| matches!(part, TemplatePart::Field(_))) {
                return Err("access_log: template must contain at least one {field} token".into());
            }
            EmitShape::Text(parts)
        } else {
            let field_tokens = parse_field_tokens(
                cfg.fields
                    .as_ref()
                    .map(|values| values.iter().filter_map(serde_yaml::Value::as_str).collect::<Vec<_>>()),
                &request_headers,
                &response_headers,
            )?;
            if cfg.fields.is_none() {
                EmitShape::DefaultFlat
            } else {
                EmitShape::JsonRecord(field_tokens)
            }
        };

        let needs_response_headers = match &shape {
            EmitShape::DefaultFlat => false,
            EmitShape::JsonRecord(fields) => fields.iter().any(|t| matches!(t, FieldToken::ResponseHeader(_))),
            EmitShape::Text(parts) => parts
                .iter()
                .any(|p| matches!(p, TemplatePart::Field(FieldToken::ResponseHeader(_)))),
        };

        validate_emit_conditions(cfg.conditions.as_ref())?;

        let sink = build_runtime_sink(cfg.sink)?;

        Ok(Self {
            sample_rate: cfg.sample_rate,
            counter: AtomicU64::default(),
            emit_plan: EmitPlan { shape },
            emit_conditions: cfg.conditions,
            needs_response_headers,
            sink,
        })
    }

    /// Returns `true` if this request should be logged (sampling check).
    ///
    /// Deterministic accumulator: of the first `n` requests exactly
    /// `floor(n × sample_rate)` are logged, so rates that are not a
    /// reciprocal integer (`0.7`, `0.4`) are honored rather than rounded to
    /// one-in-N.
    #[expect(clippy::cast_precision_loss, reason = "the counter stays far below 2^53")]
    pub(crate) fn should_log(&self) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        let seen = self.counter.fetch_add(1, Ordering::Relaxed) as f64;
        ((seen + 1.0) * self.sample_rate).floor() > (seen * self.sample_rate).floor()
    }

    /// Returns `true` for responses that Pingora delivers without a body phase.
    fn is_bodyless(status: http::StatusCode, req_method: &http::Method) -> bool {
        bodyless_response(status, req_method)
    }
}

#[async_trait]
impl HttpFilter for AccessLogFilter {
    fn name(&self) -> &'static str {
        "access_log"
    }

    async fn on_request(&self, _ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    /// Emit the record for a request that never reached the completion
    /// hooks, honouring the configured `fields`.
    ///
    /// A complete gRPC call carries its outcome in trailers, so it reaches
    /// the log only through this path; it is sampled and gated like any
    /// other response. A request with no completion is genuinely incomplete
    /// (rejected before the upstream, or aborted mid-stream) and is always
    /// recorded, so no failure goes unlogged. Returns `true` once the record
    /// is claimed, including when sampling or conditions drop it, so the
    /// caller does not re-emit it through the fixed-shape fallback.
    fn emit_deferred_record(&self, ctx: &HttpFilterContext<'_>, status: u16) -> bool {
        // Direct sinks (stdout/file) bypass tracing, so the level gate must not
        // suppress them; it stays a fast path only for the tracing sink.
        if matches!(self.sink, RuntimeSink::Tracing) && !tracing::enabled!(tracing::Level::INFO) {
            return false;
        }
        let duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis());
        if ctx.grpc_completion.is_some()
            && request_is_grpc(ctx)
            && (!self.passes_emit_conditions(ctx, status, duration_ms) || !self.should_log())
        {
            return true;
        }
        let response_headers = ctx.response_header.as_ref().map(|response| &response.headers);
        self.emit_access_log(ctx, status, response_headers, duration_ms);
        true
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(resp) = &ctx.response_header else {
            return Ok(FilterAction::Continue);
        };
        let status = resp.status.as_u16();
        let bodyless = Self::is_bodyless(resp.status, &ctx.request.method);
        let response_headers = self.needs_response_headers.then(|| resp.headers.clone());

        // Emit from the captured map before storing it: re-reading the
        // freshly inserted state cloned the header map a second time on
        // every bodyless response.
        if bodyless {
            self.maybe_emit(ctx, status, response_headers.as_ref());
        }
        ctx.insert_filter_state(AccessLogState {
            status,
            response_headers,
        });
        Ok(FilterAction::Continue)
    }

    fn response_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn on_response_body(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        _body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        if end_of_stream {
            // The record is emitted at most once, so the stored map can
            // be moved out rather than cloned per response.
            let (status, headers) = ctx
                .get_filter_state_mut::<AccessLogState>()
                .map_or((0, None), |state| (state.status, state.response_headers.take()));
            self.maybe_emit(ctx, status, headers.as_ref());
        }
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests;

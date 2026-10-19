// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Emit orchestration: the per-request emit path, emit-time conditions, the
//! tracing/direct-sink dispatch, OTel/gRPC helpers, and the record-emitted marker.

#![allow(clippy::missing_docs_in_private_items, reason = "internal emit helpers")]

use std::{borrow::Cow, collections::BTreeMap};

use tracing::info;

use super::{
    AccessLogFilter,
    format::{EmitShape, build_record_from_fields, default_field_tokens, render_text_template, sanitize_for_log},
    sink::{RuntimeSink, sink_timestamp},
};
use crate::{filter::HttpFilterContext, path_match::path_prefix_matches};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "emit methods live in the emit submodule, construction in the parent"
)]
impl AccessLogFilter {
    pub(crate) fn maybe_emit(
        &self,
        ctx: &mut HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
    ) {
        // Emit at most once per request: the bodyless on_response path and the
        // on_response_body end-of-stream path can both reach here, and the
        // protocol-layer fallback already relies on this marker.
        if access_record_already_emitted(ctx) {
            return;
        }
        // Skip all per-request record work when the access-log level is
        // disabled: the info! callsites below would discard the output, but
        // the duration sampling, condition evaluation, and record formatting
        // run regardless unless gated here. Direct sinks (stdout/file) bypass
        // tracing entirely, so the level gate must not suppress them.
        if matches!(self.sink, RuntimeSink::Tracing) && !tracing::enabled!(tracing::Level::INFO) {
            return;
        }
        // Sample the duration once so the emit-time condition and the logged
        // value can never disagree around the min_duration_ms boundary.
        let duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis());
        if !self.passes_emit_conditions(ctx, status, duration_ms) {
            return;
        }
        if !self.should_log() {
            return;
        }
        self.emit_access_log(ctx, status, response_headers, duration_ms);
        mark_access_record_emitted(ctx);
    }

    pub(crate) fn passes_emit_conditions(&self, ctx: &HttpFilterContext<'_>, status: u16, duration_ms: u64) -> bool {
        let Some(conditions) = &self.emit_conditions else {
            return true;
        };

        if let Some(min_ms) = conditions.min_duration_ms
            && duration_ms < min_ms
        {
            return false;
        }

        // A gRPC call's outcome is its grpc-status, not the transport 200, so
        // match status_classes against the status the gRPC code maps to. This
        // lets an "errors only" listener (e.g. status_classes: [4xx, 5xx])
        // capture gRPC failures, which would otherwise all read as 2xx. A
        // non-canonical code (outside 0..=16) is still a failure, so it maps
        // to 500 rather than falling back to the transport 200.
        let class_status = if request_is_grpc(ctx) {
            ctx.grpc_completion.as_ref().map_or(status, |completion| {
                completion
                    .code()
                    .map_or(500, praxis_core::grpc::GrpcStatusCode::to_http_status)
            })
        } else {
            status
        };
        if let Some(classes) = &conditions.status_classes
            && !classes.iter().any(|class| class.matches(class_status))
        {
            return false;
        }

        if let Some(prefixes) = &conditions.paths {
            let path = sanitize_for_log(ctx.request.uri.path());
            if !prefixes.iter().any(|prefix| path_prefix_matches(&path, prefix)) {
                return false;
            }
        }

        true
    }

    /// Emit a structured access log entry for the current request through the
    /// tracing subscriber, shaping the record per the configured [`EmitShape`].
    pub(crate) fn emit_access_log(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
        duration_ms: u64,
    ) {
        match &self.sink {
            RuntimeSink::Tracing => self.emit_via_tracing(ctx, status, response_headers, duration_ms),
            RuntimeSink::Direct(sink) => {
                let line = self.format_line_for_sink(ctx, status, response_headers, duration_ms);
                sink.record(line);
            },
        }
    }

    /// Emit through the tracing subscriber, shaping the record per the
    /// configured [`EmitShape`].
    fn emit_via_tracing(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
        duration_ms: u64,
    ) {
        match &self.emit_plan.shape {
            EmitShape::DefaultFlat => Self::emit_default(ctx, status, duration_ms),
            EmitShape::JsonRecord(fields) => {
                let record = build_record_from_fields(fields, ctx, status, response_headers, duration_ms);
                emit_projected_record(&record);
            },
            EmitShape::Text(parts) => {
                let line = render_text_template(parts, ctx, status, response_headers, duration_ms);
                emit_projected_line(&line);
            },
        }
    }

    /// Format one line for a direct sink (stdout or file).
    ///
    /// A text template renders its own line verbatim, matching the `line` field
    /// the tracing path would log. The default and projected plans serialize a
    /// single JSON object per request, with a `timestamp` key (RFC 3339 UTC,
    /// millisecond precision) injected so a file log records when each request
    /// completed; the tracing path gets this from the subscriber instead.
    fn format_line_for_sink(
        &self,
        ctx: &HttpFilterContext<'_>,
        status: u16,
        response_headers: Option<&http::HeaderMap>,
        duration_ms: u64,
    ) -> String {
        let fields = match &self.emit_plan.shape {
            EmitShape::Text(parts) => {
                return render_text_template(parts, ctx, status, response_headers, duration_ms);
            },
            EmitShape::JsonRecord(fields) => Cow::Borrowed(fields.as_slice()),
            EmitShape::DefaultFlat => Cow::Owned(default_field_tokens()),
        };
        let mut record = build_record_from_fields(&fields, ctx, status, response_headers, duration_ms);
        record.insert("timestamp".to_owned(), sink_timestamp(ctx));
        serde_json::to_string(&record).unwrap_or_default()
    }

    /// Default ten-field emit path.
    fn emit_default(ctx: &HttpFilterContext<'_>, status: u16, duration_ms: u64) {
        let path = sanitize_for_log(ctx.request.uri.path());
        let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
        info!(
            method = %ctx.request.method,
            path = %path,
            client_ip = %client_ip,
            status,
            duration_ms,
            cluster = ctx.cluster_name().unwrap_or("-"),
            upstream = ctx.upstream_addr().unwrap_or("-"),
            request_id = ctx.request_id().unwrap_or("-"),
            request_body_bytes = ctx.request_body_bytes,
            response_body_bytes = ctx.response_body_bytes,
            "access"
        );
    }
}

/// Returns `true` for responses that Pingora delivers without a body phase.
///
/// Shared by [`AccessLogFilter`] and the protocol layer's delivery
/// completion tracking: bodyless responses finish at the response
/// phase, everything else finishes at body end-of-stream.
pub fn bodyless_response(status: http::StatusCode, req_method: &http::Method) -> bool {
    status.as_u16() < 200
        || status == http::StatusCode::NO_CONTENT
        || status == http::StatusCode::NOT_MODIFIED
        || req_method == http::Method::HEAD
}

/// Whether the request itself is gRPC. A stray `grpc-status` on an ordinary
/// response must not make it look like a completed gRPC call.
pub(crate) fn request_is_grpc(ctx: &HttpFilterContext<'_>) -> bool {
    praxis_core::grpc::GrpcKind::from_headers(&ctx.request.headers).is_grpc()
}

/// Marker inserted into request extensions once an access record has been
/// emitted for this request.
///
/// The protocol-layer fallback checks for it via
/// [`access_record_already_emitted`] so a request the filter already logged
/// (e.g. a bodyless response whose `on_response` emitted before a later
/// response filter rejected) does not gain a duplicate fallback record.
struct AccessRecordEmitted;

/// Whether an access record has already been emitted for this request.
#[must_use]
pub fn access_record_already_emitted(ctx: &HttpFilterContext<'_>) -> bool {
    ctx.extensions.get::<AccessRecordEmitted>().is_some()
}

/// Record that an access record has been emitted for this request.
pub fn mark_access_record_emitted(ctx: &mut HttpFilterContext<'_>) {
    ctx.extensions.insert(AccessRecordEmitted);
}

/// Emit a structured access log record for the current request.
///
/// When the `otel` feature is enabled and a valid `OpenTelemetry` context
/// is attached to the current tracing span, the entry includes `trace_id`
/// (32-char hex, W3C format) and `span_id` (16-char hex) fields for
/// correlation with OTLP-exported traces. The fields are omitted when
/// no `OTel` context is available.
///
/// Shared by [`AccessLogFilter`]'s completion hooks and the protocol
/// layer's fallback for requests whose lifecycle ended before those
/// hooks could run (pre-upstream rejections, upstream failures, and
/// streamed responses aborted mid-body). Fallback records bypass the
/// filter's sampling: incomplete requests are always worth a record.
#[expect(clippy::too_many_lines, reason = "dual info! paths for optional OTel trace fields")]
pub fn emit_access_record(ctx: &HttpFilterContext<'_>, status: u16) {
    let path = sanitize_for_log(ctx.request.uri.path());
    let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();

    #[cfg(feature = "otel")]
    if let Some((trace_id, span_id)) = extract_otel_ids() {
        info!(
            method = %ctx.request.method,
            path = %path,
            client_ip = %client_ip,
            cluster = ctx.cluster_name().unwrap_or("-"),
            duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()),
            request_body_bytes = ctx.request_body_bytes,
            request_id = ctx.request_id().unwrap_or("-"),
            response_body_bytes = ctx.response_body_bytes,
            span_id = %span_id,
            status,
            trace_id = %trace_id,
            upstream = ctx.upstream_addr().unwrap_or("-"),
            "access"
        );
        return;
    }

    info!(
        method = %ctx.request.method,
        path = %path,
        client_ip = %client_ip,
        status,
        duration_ms = truncate_u128(ctx.request_start.elapsed().as_millis()),
        cluster = ctx.cluster_name().unwrap_or("-"),
        upstream = ctx.upstream_addr().unwrap_or("-"),
        request_id = ctx.request_id().unwrap_or("-"),
        request_body_bytes = ctx.request_body_bytes,
        response_body_bytes = ctx.response_body_bytes,
        "access"
    );
}

/// Extract `trace_id` and `span_id` from the `OpenTelemetry` context
/// attached to the current tracing span.
///
/// Returns `None` when no `OTel` layer is active or the span context
/// is invalid (e.g. tracing is not configured with OTLP export).
#[cfg(feature = "otel")]
pub(crate) fn extract_otel_ids() -> Option<(String, String)> {
    use opentelemetry::trace::TraceContextExt as _;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;

    let span = tracing::Span::current();
    let otel_ctx = span.context();
    let span_ref = otel_ctx.span();
    let span_context = span_ref.span_context();

    span_context
        .is_valid()
        .then(|| (span_context.trace_id().to_string(), span_context.span_id().to_string()))
}

/// Current request's trace id, or `-` when no `OTel` context is available.
pub(crate) fn current_trace_id() -> String {
    #[cfg(feature = "otel")]
    if let Some((trace_id, _)) = extract_otel_ids() {
        return trace_id;
    }
    "-".to_owned()
}

/// Current request's span id, or `-` when no `OTel` context is available.
pub(crate) fn current_span_id() -> String {
    #[cfg(feature = "otel")]
    if let Some((_, span_id)) = extract_otel_ids() {
        return span_id;
    }
    "-".to_owned()
}

/// Project selected fields into a single `tracing::info!` record.
///
/// `tracing` requires field names to be static, so a custom field set is
/// emitted as one JSON object under the `record` field. This keeps the log
/// schema stable regardless of which or how many fields are selected; the
/// default field set keeps the flat legacy shape via `emit_default`.
fn emit_projected_record(record: &BTreeMap<String, String>) {
    if record.is_empty() {
        return;
    }

    let json = serde_json::to_string(record).unwrap_or_default();
    info!(message = "access", record = %json);
}

/// Emit a rendered text-template line through the tracing subscriber.
///
/// Unlike [`emit_projected_record`], a template always renders to exactly one
/// string, so it needs no dynamic-field workaround: it fits a single static
/// tracing field regardless of what the template contains.
fn emit_projected_line(line: &str) {
    info!(message = "access", line = %line);
}

/// Truncate a `u128` to `u64`, saturating at `u64::MAX`.
pub(crate) fn truncate_u128(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

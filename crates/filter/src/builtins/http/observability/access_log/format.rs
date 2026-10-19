// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Field tokens, text templates, record building, and field-value helpers for
//! the access log filter.

#![allow(clippy::missing_docs_in_private_items, reason = "internal field projection types")]

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
};

use http::header::HeaderName;

use super::emit::{current_span_id, current_trace_id};
use crate::{FilterError, filter::HttpFilterContext};

/// Default field tokens when `fields` is omitted.
const DEFAULT_FIELDS: &[&str] = &[
    "method",
    "path",
    "client_ip",
    "status",
    "duration_ms",
    "cluster",
    "upstream",
    "request_id",
    "request_body_bytes",
    "response_body_bytes",
];

/// Parsed scalar field token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FieldToken {
    Method,
    Path,
    ClientIp,
    Status,
    DurationMs,
    Cluster,
    Upstream,
    RequestId,
    RequestBodyBytes,
    ResponseBodyBytes,
    TraceId,
    SpanId,
    GrpcStatus,
    GrpcStatusName,
    GrpcMessage,
    GrpcStatusDetailsBin,
    RequestHeader(String),
    ResponseHeader(String),
    /// A filter-metadata key, such as `llm.model`.
    Metadata(String),
}

/// A segment in a parsed text template: a static string or an interpolated field.
#[derive(Clone, Debug)]
pub(crate) enum TemplatePart {
    Literal(String),
    Field(FieldToken),
}

/// Emit shape for a log record.
#[derive(Clone, Debug)]
pub(crate) enum EmitShape {
    /// Ten hardcoded default fields via `tracing::info!` flat format.
    DefaultFlat,
    /// User-selected field projection emitted as a `record` JSON field.
    JsonRecord(Vec<FieldToken>),
    /// Text line built from a parsed template, logged as the event's `line` field.
    Text(Vec<TemplatePart>),
}

/// Runtime emit plan built from config.
#[derive(Clone, Debug)]
pub(crate) struct EmitPlan {
    pub(crate) shape: EmitShape,
}

/// Parse a text template string into a `Vec<TemplatePart>`.
///
/// Each `{token}` in the template is parsed as a [`FieldToken`] and becomes a
/// [`TemplatePart::Field`]. All other text becomes [`TemplatePart::Literal`].
/// Header tokens are validated against `request_headers` and `response_headers`.
///
/// # Errors
///
/// Returns [`FilterError`] for unclosed braces, unknown field tokens, or header
/// tokens that are not listed in the corresponding allowlist.
#[expect(clippy::too_many_lines, reason = "single-pass brace/token scanner")]
pub(crate) fn parse_template(
    template: &str,
    request_headers: &HashSet<String>,
    response_headers: &HashSet<String>,
) -> Result<Vec<TemplatePart>, FilterError> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut chars = template.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                // Flush the literal text accumulated before this token.
                if !literal.is_empty() {
                    parts.push(TemplatePart::Literal(std::mem::take(&mut literal)));
                }

                // Collect the token name up to the closing brace. A second '{'
                // (or the end of the string) before a '}' means this brace was
                // never closed.
                let mut token = String::new();
                let mut closed = false;
                for next in chars.by_ref() {
                    match next {
                        '}' => {
                            closed = true;
                            break;
                        },
                        '{' => return Err("access_log: unclosed brace in template".into()),
                        _ => token.push(next),
                    }
                }
                if !closed {
                    return Err("access_log: unclosed brace in template".into());
                }

                let field = parse_scalar_field_token(token.trim())?;
                match &field {
                    FieldToken::RequestHeader(name) if !request_headers.contains(name) => {
                        return Err(
                            format!("access_log: request_header.{name} requires {name:?} in request_headers").into(),
                        );
                    },
                    FieldToken::ResponseHeader(name) if !response_headers.contains(name) => {
                        return Err(format!(
                            "access_log: response_header.{name} requires {name:?} in response_headers"
                        )
                        .into());
                    },
                    _ => {},
                }
                parts.push(TemplatePart::Field(field));
            },
            '}' => return Err("access_log: unexpected '}' in template".into()),
            _ => literal.push(ch),
        }
    }

    if !literal.is_empty() {
        parts.push(TemplatePart::Literal(literal));
    }

    Ok(parts)
}

/// Render template parts into a log line string.
///
/// Each [`TemplatePart::Literal`] is emitted verbatim. Each
/// [`TemplatePart::Field`] is resolved to its value for this request/response
/// and passed through [`push_escaped_field`]; unknown or missing values fall
/// back to `"-"`.
pub(crate) fn render_text_template(
    parts: &[TemplatePart],
    ctx: &HttpFilterContext<'_>,
    status: u16,
    response_headers: Option<&http::HeaderMap>,
    duration_ms: u64,
) -> String {
    let mut result = String::new();

    for part in parts {
        match part {
            TemplatePart::Literal(literal) => {
                result.push_str(literal);
            },
            TemplatePart::Field(field) => {
                let map =
                    build_record_from_fields(std::slice::from_ref(field), ctx, status, response_headers, duration_ms);
                let value = map.into_values().next().unwrap_or_else(|| "-".to_owned());
                push_escaped_field(&mut result, &value);
            },
        }
    }
    result
}

/// Append a resolved field value to a rendered template line, defending against
/// log injection.
///
/// The value is first control-character sanitized with [`sanitize_for_log`]
/// (dropping newlines so it cannot forge a new log line), then `"` and `\` are
/// backslash-escaped nginx-style so a client-controlled value cannot break out
/// of a quoted template field (e.g. forging a status by closing an earlier
/// quote).
fn push_escaped_field(result: &mut String, value: &str) {
    for ch in sanitize_for_log(value).chars() {
        if matches!(ch, '"' | '\\') {
            result.push('\\');
        }
        result.push(ch);
    }
}

/// Build a record from an explicit list of field tokens.
#[expect(clippy::too_many_lines, reason = "field projection match arms")]
pub(crate) fn build_record_from_fields(
    fields: &[FieldToken],
    ctx: &HttpFilterContext<'_>,
    status: u16,
    response_headers: Option<&http::HeaderMap>,
    duration_ms: u64,
) -> BTreeMap<String, String> {
    let path = sanitize_for_log(ctx.request.uri.path());
    let client_ip = ctx.client_addr.map(|a| a.to_string()).unwrap_or_default();
    let duration_ms = duration_ms.to_string();

    let mut record = BTreeMap::new();
    for token in fields {
        match token {
            FieldToken::Method => {
                record.insert("method".to_owned(), ctx.request.method.to_string());
            },
            FieldToken::Path => {
                record.insert("path".to_owned(), path.to_string());
            },
            FieldToken::ClientIp => {
                record.insert("client_ip".to_owned(), client_ip.clone());
            },
            FieldToken::Status => {
                record.insert("status".to_owned(), status.to_string());
            },
            FieldToken::DurationMs => {
                record.insert("duration_ms".to_owned(), duration_ms.clone());
            },
            FieldToken::Cluster => {
                record.insert("cluster".to_owned(), ctx.cluster_name().unwrap_or("-").to_owned());
            },
            FieldToken::Upstream => {
                record.insert("upstream".to_owned(), ctx.upstream_addr().unwrap_or("-").to_owned());
            },
            FieldToken::RequestId => {
                record.insert("request_id".to_owned(), ctx.request_id().unwrap_or("-").to_owned());
            },
            FieldToken::RequestBodyBytes => {
                record.insert("request_body_bytes".to_owned(), ctx.request_body_bytes.to_string());
            },
            FieldToken::ResponseBodyBytes => {
                record.insert("response_body_bytes".to_owned(), ctx.response_body_bytes.to_string());
            },
            FieldToken::TraceId => {
                record.insert("trace_id".to_owned(), current_trace_id());
            },
            FieldToken::SpanId => {
                record.insert("span_id".to_owned(), current_span_id());
            },
            FieldToken::GrpcStatus => {
                let value = ctx
                    .grpc_completion()
                    .map_or_else(|| "-".to_owned(), |completion| completion.raw_code().to_string());
                record.insert("grpc_status".to_owned(), value);
            },
            FieldToken::GrpcStatusName => {
                let value = ctx
                    .grpc_completion()
                    .map_or_else(|| "-".to_owned(), praxis_core::grpc::GrpcCompletion::code_name);
                record.insert("grpc_status_name".to_owned(), value);
            },
            FieldToken::GrpcMessage => {
                let value = ctx
                    .grpc_completion()
                    .and_then(|completion| completion.message())
                    .map_or_else(|| "-".to_owned(), |message| sanitize_for_log(message).into_owned());
                record.insert("grpc_message".to_owned(), value);
            },
            FieldToken::GrpcStatusDetailsBin => {
                let value = ctx
                    .grpc_completion()
                    .and_then(|completion| completion.status_details_bin())
                    .unwrap_or("-")
                    .to_owned();
                record.insert("grpc_status_details_bin".to_owned(), value);
            },
            FieldToken::RequestHeader(name) => {
                let value = first_header_value(&ctx.request.headers, name).unwrap_or_else(|| "-".to_owned());
                let key = format!("request_header.{}", header_json_key(name));
                record.insert(key, value);
            },
            FieldToken::ResponseHeader(name) => {
                let value = response_headers
                    .and_then(|headers| first_header_value(headers, name))
                    .unwrap_or_else(|| "-".to_owned());
                let key = format!("response_header.{}", header_json_key(name));
                record.insert(key, value);
            },
            FieldToken::Metadata(key) => {
                let value = ctx.get_metadata(key).unwrap_or("-").to_owned();
                record.insert(format!("metadata.{key}"), value);
            },
        }
    }
    record
}

/// Normalize and validate configured header names into a lowercased set.
pub(crate) fn normalize_header_names(names: Option<&[String]>) -> Result<HashSet<String>, FilterError> {
    let Some(names) = names else {
        return Ok(HashSet::new());
    };

    let mut normalized = HashSet::with_capacity(names.len());
    for name in names {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("access_log: header names must not be empty".into());
        }
        if super::super::is_sensitive_header(trimmed) {
            return Err(format!("access_log: header {trimmed:?} is not allowed in v1").into());
        }
        normalized.insert(trimmed.to_ascii_lowercase());
    }
    Ok(normalized)
}

/// Parse the configured scalar field tokens (or the defaults), validating header
/// tokens against the allowlists.
pub(crate) fn parse_field_tokens(
    fields: Option<Vec<&str>>,
    request_headers: &HashSet<String>,
    response_headers: &HashSet<String>,
) -> Result<Vec<FieldToken>, FilterError> {
    let tokens = match fields {
        None => DEFAULT_FIELDS
            .iter()
            .copied()
            .map(parse_scalar_field_token)
            .collect::<Result<Vec<_>, _>>()?,
        Some(values) => values
            .iter()
            .copied()
            .map(parse_scalar_field_token)
            .collect::<Result<Vec<_>, _>>()?,
    };

    for token in &tokens {
        match token {
            FieldToken::RequestHeader(name) if !request_headers.contains(name) => {
                return Err(format!("access_log: request_header.{name} requires {name:?} in request_headers").into());
            },
            FieldToken::ResponseHeader(name) if !response_headers.contains(name) => {
                return Err(format!("access_log: response_header.{name} requires {name:?} in response_headers").into());
            },
            _ => {},
        }
    }

    Ok(tokens)
}

/// Field tokens for the default flat shape.
///
/// The tracing path logs the default shape through the flat
/// [`AccessLogFilter::emit_default`] method, so it never needs these tokens; a
/// direct sink serializes a JSON
/// object instead and builds it from this list. Every name is a known-valid
/// scalar token, so parse failures are impossible and dropped.
///
/// [`AccessLogFilter::emit_default`]: super::AccessLogFilter
pub(crate) fn default_field_tokens() -> Vec<FieldToken> {
    DEFAULT_FIELDS
        .iter()
        .copied()
        .filter_map(|name| parse_scalar_field_token(name).ok())
        .collect()
}

/// Parse a prefixed field token.
fn parse_prefixed_field_token(token: &str) -> Option<Result<FieldToken, FilterError>> {
    if let Some(name) = token.strip_prefix("request_header.") {
        return Some(if name.is_empty() {
            Err("access_log: request_header token must include a header name".into())
        } else {
            Ok(FieldToken::RequestHeader(name.to_ascii_lowercase()))
        });
    }
    if let Some(name) = token.strip_prefix("response_header.") {
        return Some(if name.is_empty() {
            Err("access_log: response_header token must include a header name".into())
        } else {
            Ok(FieldToken::ResponseHeader(name.to_ascii_lowercase()))
        });
    }
    if let Some(key) = token.strip_prefix("metadata.") {
        return Some(if key.is_empty() {
            Err("access_log: metadata token must include a key".into())
        } else {
            Ok(FieldToken::Metadata(key.to_owned()))
        });
    }
    None
}

/// Parse a single scalar field token name into a [`FieldToken`].
pub(crate) fn parse_scalar_field_token(token: &str) -> Result<FieldToken, FilterError> {
    if let Some(prefixed) = parse_prefixed_field_token(token) {
        return prefixed;
    }
    if let Some(parsed) = parse_grpc_field_token(token) {
        return Ok(parsed);
    }

    match token {
        "method" => Ok(FieldToken::Method),
        "path" => Ok(FieldToken::Path),
        "client_ip" => Ok(FieldToken::ClientIp),
        "status" => Ok(FieldToken::Status),
        "duration_ms" => Ok(FieldToken::DurationMs),
        "cluster" => Ok(FieldToken::Cluster),
        "upstream" => Ok(FieldToken::Upstream),
        "request_id" => Ok(FieldToken::RequestId),
        "request_body_bytes" => Ok(FieldToken::RequestBodyBytes),
        "response_body_bytes" => Ok(FieldToken::ResponseBodyBytes),
        "trace_id" => Ok(FieldToken::TraceId),
        "span_id" => Ok(FieldToken::SpanId),
        "filter_results" => Err("access_log: filter_results is not supported in v1".into()),
        other => Err(format!("access_log: unknown field token {other:?}").into()),
    }
}

/// Parse the gRPC completion field tokens.
///
/// These read the `grpc-status` family of response trailers and render
/// `-` for any response that carries none.
fn parse_grpc_field_token(token: &str) -> Option<FieldToken> {
    match token {
        "grpc_status" => Some(FieldToken::GrpcStatus),
        "grpc_status_name" => Some(FieldToken::GrpcStatusName),
        "grpc_message" => Some(FieldToken::GrpcMessage),
        "grpc_status_details_bin" => Some(FieldToken::GrpcStatusDetailsBin),
        _ => None,
    }
}

/// Lowercase a header name for use as a JSON record key.
fn header_json_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// First value of `name` in `headers`, as a string, if present and valid UTF-8.
fn first_header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Strip control characters (C0/C1, ANSI escapes) from a string before
/// logging. Prevents log injection via crafted request URIs.
///
/// Returns [`Cow::Borrowed`] when the input contains no control
/// characters (the common case for HTTP paths).
pub(crate) fn sanitize_for_log(s: &str) -> Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        out.push(c);
    }
    Cow::Owned(out)
}

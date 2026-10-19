// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Deserialized YAML configuration, sink/syslog config types, and config-time
//! validation for the access log filter.

#![allow(clippy::missing_docs_in_private_items, reason = "internal config types")]

use serde::Deserialize;

use crate::FilterError;

/// Deserialized YAML config for the access log filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessLogConfig {
    /// Fraction of requests to log (0.0, 1.0]. Defaults to 1.0.
    #[serde(default = "default_sample_rate")]
    pub(crate) sample_rate: f64,

    /// Scalar field tokens; replaces the default ten when present.
    /// Mutually exclusive with `template`.
    pub(crate) fields: Option<Vec<serde_yaml::Value>>,

    /// Request header names allowed for `request_header.<name>` tokens.
    pub(crate) request_headers: Option<Vec<String>>,

    /// Response header names allowed for `response_header.<name>` tokens.
    pub(crate) response_headers: Option<Vec<String>>,

    /// Emit-time conditions (AND across keys).
    pub(crate) conditions: Option<AccessLogEmitConditions>,

    /// Text template with `{field}` placeholders. The rendered string is logged
    /// as the `line` field of the `access` event, and `PRAXIS_LOG_FORMAT` still
    /// decides text or JSON output. Mutually exclusive with `fields`.
    pub(crate) template: Option<String>,

    /// Output sink: `{type: stdout}`, `{type: file, path: ...}`, or (with the
    /// `access-log-syslog` feature) `{type: syslog, ...}`. Omitted means emit
    /// through the tracing subscriber.
    #[serde(default)]
    pub(crate) sink: Option<SinkConfig>,
}

/// Output sink configuration.
///
/// Deserialized via [`RawSinkConfig`] so serde rejects unknown fields and the
/// invalid `(type, path)` pairings during deserialization, leaving a resolved
/// enum whose variants carry exactly the fields valid for each sink.
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawSinkConfig")]
pub(crate) enum SinkConfig {
    /// Write NDJSON lines to stdout, bypassing tracing.
    Stdout,
    /// Append NDJSON lines to a file (no rotation).
    File {
        /// Destination path, opened in append+create mode.
        path: String,
    },
    /// Send each line as an RFC 3164 syslog message over a local socket, UDP, or TCP.
    #[cfg(feature = "access-log-syslog")]
    Syslog {
        /// Syslog facility encoded in the message PRI header.
        facility: SyslogFacility,
        /// Resolved transport destination.
        target: SyslogDestination,
    },
}

/// Resolved syslog destination; the `(transport, address, path)` pairing is
/// validated in [`SinkConfig::try_syslog`] during deserialization.
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Debug)]
pub(crate) enum SyslogDestination {
    /// Local `AF_UNIX` socket; `None` path means `/dev/log`.
    Unix {
        /// Socket path override (`None` means `/dev/log`).
        path: Option<String>,
    },
    /// Remote UDP datagram target (RFC 5426).
    Udp {
        /// Collector `host:port`.
        address: String,
    },
    /// Remote TCP stream target (RFC 6587).
    Tcp {
        /// Collector `host:port`.
        address: String,
    },
}

/// Sink config exactly as written in YAML, before validation into
/// [`SinkConfig`]. Keeps `#[serde(deny_unknown_fields)]` so a stray key is still
/// rejected (an internally tagged enum would silently ignore it).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSinkConfig {
    /// Sink kind (`stdout`, `file`, or `syslog` with the `access-log-syslog`
    /// feature).
    #[serde(rename = "type")]
    kind: SinkKind,

    /// File path; required for `file`, rejected for `stdout`. Doubles as the
    /// local socket path override for `syslog` + `transport: unix`.
    #[serde(default)]
    path: Option<String>,

    /// Syslog transport. Only valid for `type: syslog`; defaults to `unix`.
    #[cfg(feature = "access-log-syslog")]
    #[serde(default)]
    transport: Option<SyslogTransport>,

    /// Remote `host:port` for `syslog` with `transport: udp`/`tcp`.
    #[cfg(feature = "access-log-syslog")]
    #[serde(default)]
    address: Option<String>,

    /// Syslog facility. Only valid for `type: syslog`; defaults to `user`.
    #[cfg(feature = "access-log-syslog")]
    #[serde(default)]
    facility: Option<SyslogFacility>,
}

/// Direct output sink kind discriminant.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SinkKind {
    /// Write NDJSON lines to stdout.
    Stdout,
    /// Append NDJSON lines to a file.
    File,
    /// Send lines as syslog messages.
    #[cfg(feature = "access-log-syslog")]
    Syslog,
}

impl TryFrom<RawSinkConfig> for SinkConfig {
    type Error = String;

    fn try_from(raw: RawSinkConfig) -> Result<Self, Self::Error> {
        match raw.kind {
            SinkKind::Stdout => {
                #[cfg(feature = "access-log-syslog")]
                raw.reject_syslog_fields("stdout")?;
                match raw.path {
                    None => Ok(Self::Stdout),
                    Some(_) => Err("access_log: sink type stdout does not accept a path".to_owned()),
                }
            },
            SinkKind::File => {
                #[cfg(feature = "access-log-syslog")]
                raw.reject_syslog_fields("file")?;
                match raw.path {
                    Some(path) => Ok(Self::File { path }),
                    None => Err("access_log: sink type file requires a path".to_owned()),
                }
            },
            #[cfg(feature = "access-log-syslog")]
            SinkKind::Syslog => Self::try_syslog(raw),
        }
    }
}

#[cfg(feature = "access-log-syslog")]
impl RawSinkConfig {
    /// Reject the syslog-only keys (`transport`, `address`, `facility`) on a
    /// non-syslog sink, so a misplaced key is a config error rather than a
    /// silently ignored one.
    fn reject_syslog_fields(&self, kind: &str) -> Result<(), String> {
        if self.transport.is_some() || self.address.is_some() || self.facility.is_some() {
            return Err(format!(
                "access_log: sink type {kind} does not accept syslog fields (transport, address, facility)"
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "access-log-syslog")]
impl SinkConfig {
    /// Resolve a `syslog` sink into a [`SyslogDestination`], rejecting fields the
    /// chosen transport ignores (`unix` takes a `path`; `udp`/`tcp` take an `address`).
    fn try_syslog(raw: RawSinkConfig) -> Result<Self, String> {
        let facility = raw.facility.unwrap_or_default();
        let target = match raw.transport.unwrap_or_default() {
            SyslogTransport::Unix => match raw.address {
                Some(_) => return Err("access_log: sink transport unix does not accept an address".to_owned()),
                None => SyslogDestination::Unix { path: raw.path },
            },
            SyslogTransport::Udp => SyslogDestination::Udp {
                address: remote_address(raw.path.is_some(), raw.address)?,
            },
            SyslogTransport::Tcp => SyslogDestination::Tcp {
                address: remote_address(raw.path.is_some(), raw.address)?,
            },
        };
        Ok(Self::Syslog { facility, target })
    }
}

/// Validate a remote (`udp`/`tcp`) syslog destination: a `host:port` `address`, no `path`.
#[cfg(feature = "access-log-syslog")]
pub(crate) fn remote_address(has_path: bool, address: Option<String>) -> Result<String, String> {
    if has_path {
        return Err("access_log: sink transport udp/tcp does not accept a path".to_owned());
    }
    let address = address.ok_or_else(|| "access_log: sink transport udp/tcp requires an address".to_owned())?;
    validate_host_port(&address)?;
    Ok(address)
}

/// Reject an `address` that is not `host:port` (non-zero port, non-empty host), without DNS.
#[cfg(feature = "access-log-syslog")]
fn validate_host_port(address: &str) -> Result<(), String> {
    let invalid = || format!("access_log: syslog address {address:?} is not host:port");
    let (host, port) = address.rsplit_once(':').ok_or_else(invalid)?;
    // A bracketed IPv6 host may contain colons (`[::1]`); an unbracketed host may
    // not, so `collector:514:123` is rejected rather than read as host `collector:514`.
    let host_ok = match host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')) {
        Some(inner) => !inner.is_empty(),
        None => !host.is_empty() && !host.contains(':'),
    };
    match port.parse::<u16>() {
        Ok(port) if port != 0 && host_ok => Ok(()),
        _ => Err(invalid()),
    }
}

/// Standard syslog facility codes (RFC 3164 §4.1.1).
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SyslogFacility {
    /// Kernel messages.
    Kern,
    /// User-level messages (default).
    #[default]
    User,
    /// Mail system.
    Mail,
    /// System daemons.
    Daemon,
    /// Security/authorization messages.
    Auth,
    /// Messages generated internally by syslogd.
    Syslog,
    /// Line printer subsystem.
    Lpr,
    /// Network news subsystem.
    News,
    /// UUCP subsystem.
    Uucp,
    /// Clock daemon.
    Cron,
    /// Security/authorization messages (private).
    Authpriv,
    /// FTP daemon.
    Ftp,
    /// Local use 0.
    Local0,
    /// Local use 1.
    Local1,
    /// Local use 2.
    Local2,
    /// Local use 3.
    Local3,
    /// Local use 4.
    Local4,
    /// Local use 5.
    Local5,
    /// Local use 6.
    Local6,
    /// Local use 7.
    Local7,
}

#[cfg(feature = "access-log-syslog")]
impl SyslogFacility {
    /// Facility contribution to PRI (`facility * 8`); literals avoid an `as` cast.
    pub(crate) fn priority_base(self) -> u8 {
        match self {
            SyslogFacility::Kern => 0,      //     0 * 8
            SyslogFacility::User => 8,      //     1 * 8
            SyslogFacility::Mail => 16,     //     2 * 8
            SyslogFacility::Daemon => 24,   //     3 * 8
            SyslogFacility::Auth => 32,     //     4 * 8
            SyslogFacility::Syslog => 40,   //     5 * 8
            SyslogFacility::Lpr => 48,      //     6 * 8
            SyslogFacility::News => 56,     //     7 * 8
            SyslogFacility::Uucp => 64,     //     8 * 8
            SyslogFacility::Cron => 72,     //     9 * 8
            SyslogFacility::Authpriv => 80, //    10 * 8
            SyslogFacility::Ftp => 88,      //    11 * 8
            SyslogFacility::Local0 => 128,  //    16 * 8
            SyslogFacility::Local1 => 136,  //    17 * 8
            SyslogFacility::Local2 => 144,  //    18 * 8
            SyslogFacility::Local3 => 152,  //    19 * 8
            SyslogFacility::Local4 => 160,  //    20 * 8
            SyslogFacility::Local5 => 168,  //    21 * 8
            SyslogFacility::Local6 => 176,  //    22 * 8
            SyslogFacility::Local7 => 184,  //    23 * 8
        }
    }
}

/// Syslog transport carrier.
#[cfg(feature = "access-log-syslog")]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyslogTransport {
    /// Local `AF_UNIX` socket (default `/dev/log`).
    #[default]
    Unix,
    /// Remote UDP datagram (RFC 5426).
    Udp,
    /// Remote TCP stream (RFC 6587).
    Tcp,
}

/// Emit-time access log conditions.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessLogEmitConditions {
    pub(crate) min_duration_ms: Option<u64>,
    pub(crate) status_classes: Option<Vec<StatusClass>>,
    pub(crate) paths: Option<Vec<String>>,
}

/// HTTP status class for emit-time conditions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum StatusClass {
    /// 100-199.
    #[serde(rename = "1xx")]
    Informational,
    /// 200-299.
    #[serde(rename = "2xx")]
    Success,
    /// 300-399.
    #[serde(rename = "3xx")]
    Redirection,
    /// 400-499.
    #[serde(rename = "4xx")]
    ClientError,
    /// 500-599.
    #[serde(rename = "5xx")]
    ServerError,
}

impl StatusClass {
    /// Whether `status` falls into this class.
    pub(crate) fn matches(self, status: u16) -> bool {
        let hundred = status / 100;
        matches!(
            (self, hundred),
            (Self::Informational, 1)
                | (Self::Success, 2)
                | (Self::Redirection, 3)
                | (Self::ClientError, 4)
                | (Self::ServerError, 5)
        )
    }
}

/// Default sample rate: log every request.
fn default_sample_rate() -> f64 {
    1.0
}

/// Validate emit-time conditions: at least one key present, no empty lists, and
/// `paths` are glob-free prefixes.
pub(crate) fn validate_emit_conditions(conditions: Option<&AccessLogEmitConditions>) -> Result<(), FilterError> {
    let Some(conditions) = conditions else {
        return Ok(());
    };

    if conditions.min_duration_ms.is_none()
        && conditions.status_classes.as_ref().is_none_or(Vec::is_empty)
        && conditions.paths.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(
            "access_log: conditions must include at least one of min_duration_ms, status_classes, or paths".into(),
        );
    }

    // Invalid class strings are rejected by serde at deserialization time
    // (StatusClass is a closed enum), so only emptiness needs checking here.
    if let Some(classes) = &conditions.status_classes
        && classes.is_empty()
    {
        return Err("access_log: status_classes must not be empty when present".into());
    }

    if let Some(paths) = &conditions.paths {
        if paths.is_empty() {
            return Err("access_log: paths must not be empty when present".into());
        }
        for path in paths {
            if path.contains('*') {
                return Err(format!("access_log: paths must be prefixes without globs, got {path:?}").into());
            }
        }
    }

    Ok(())
}

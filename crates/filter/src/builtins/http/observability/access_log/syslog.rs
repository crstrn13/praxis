// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! RFC 3164 syslog sink: formatter, writer thread, connection lifecycle, and the
//! unix/udp/tcp transports. The whole module is gated on `access-log-syslog`.

#![allow(clippy::missing_docs_in_private_items, reason = "internal syslog types")]

use std::{
    io::BufWriter,
    net::{SocketAddr, ToSocketAddrs as _},
    os::unix::net::{UnixDatagram, UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, RecvTimeoutError, sync_channel},
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Local};
use syslog::{Formatter3164, LogFormat, Logger, LoggerBackend, Severity};

use super::{
    config::{SyslogDestination, SyslogFacility},
    sink::{
        DirectSink, SINK_POLL_INTERVAL, SINK_QUEUE_CAPACITY, SINK_SHUTDOWN, WriteWarnThrottle, register_sink_writer,
    },
};
use crate::FilterError;

/// Connect/write timeout for the TCP and Unix syslog transports, so a stalled
/// collector cannot block the writer thread (and its bounded queue) indefinitely.
const SYSLOG_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// RFC 3164 formatter for the `syslog` `Logger`, replacing `Formatter3164`: unlike
/// the crate it renders the header in local time (via `chrono::Local`, which reads
/// the zone soundly where the crate forces UTC) and wraps each TCP record in RFC
/// 6587 octet-counted framing (`LEN SP MSG`) so a collector can split records.
#[derive(Clone, Debug)]
pub(crate) struct Rfc3164Formatter {
    /// Facility contribution to PRI (`facility * 8`); see [`SyslogFacility`].
    pub(crate) priority_base: u8,
    /// Local host name for remote (`udp`/`tcp`) targets; `None` on `unix`.
    pub(crate) hostname: Option<String>,
    /// Syslog TAG process name (always `praxis`).
    pub(crate) process: String,
    /// Process id recorded in the TAG.
    pub(crate) pid: u32,
    /// Wrap each record in RFC 6587 octet-counted framing (TCP only).
    pub(crate) octet_framed: bool,
}

/// Render the RFC 3164 timestamp (`Mmm _d HH:MM:SS`) for `now` in its own zone.
pub(crate) fn rfc3164_timestamp<Tz: chrono::TimeZone<Offset: std::fmt::Display>>(now: &DateTime<Tz>) -> String {
    now.format("%b %e %H:%M:%S").to_string()
}

/// RFC 3164 §4.1 caps a complete syslog message (header included) at 1024 bytes;
/// a receiver may truncate or discard anything longer.
pub(crate) const RFC3164_MAX_BYTES: usize = 1024;

/// Truncate `record` in place to at most [`RFC3164_MAX_BYTES`], on a UTF-8 char
/// boundary so the emitted message stays valid and within the RFC 3164 §4.1 limit.
fn cap_rfc3164(record: &mut String) {
    if record.len() <= RFC3164_MAX_BYTES {
        return;
    }
    let mut end = RFC3164_MAX_BYTES;
    while end > 0 && !record.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    record.truncate(end);
}

impl<T: std::fmt::Display> LogFormat<T> for Rfc3164Formatter {
    fn format<W: std::io::Write>(&self, w: &mut W, _severity: Severity, message: T) -> syslog::Result<()> {
        // The access_log sink emits every record at info, so PRI is facility | 6.
        let pri = self.priority_base.saturating_add(6); // 6 = info
        let timestamp = rfc3164_timestamp(&Local::now());
        let host = self
            .hostname
            .as_deref()
            .map_or_else(String::new, |name| format!("{name} "));
        let mut record = format!("<{pri}>{timestamp} {host}{}[{}]: {message}", self.process, self.pid);
        cap_rfc3164(&mut record);
        if self.octet_framed {
            write!(w, "{} {record}", record.len())?;
        } else {
            write!(w, "{record}")?;
        }
        Ok(())
    }
}

/// Everything the writer needs to (re)build its `Logger`: the crate's `Logger` has
/// no reconnect method, so the writer rebuilds it from this after a write error.
pub(crate) struct SyslogTarget {
    /// Resolved transport destination for the connection.
    pub(crate) destination: SyslogDestination,
    /// Message formatter carrying the facility and process identity.
    pub(crate) formatter: Rfc3164Formatter,
    /// Destination label for diagnostics.
    pub(crate) dest: Arc<str>,
}

/// Build a syslog [`DirectSink`]: assemble the formatter, then spawn the writer
/// thread and keep its bounded-queue sender. A remote (`udp`/`tcp`) target fills in
/// the local host name for the RFC 3164 HEADER; `unix` leaves the daemon to stamp it.
pub(crate) fn syslog_sink(
    facility: SyslogFacility,
    destination: SyslogDestination,
) -> Result<Arc<DirectSink>, FilterError> {
    let dest: Arc<str> = Arc::from(syslog_dest(&destination));
    let hostname = match destination {
        SyslogDestination::Unix { .. } => None,
        // Borrow the crate's host-name detection for the remote HEADER.
        SyslogDestination::Udp { .. } | SyslogDestination::Tcp { .. } => Formatter3164::default().hostname,
    };
    let formatter = Rfc3164Formatter {
        priority_base: facility.priority_base(),
        hostname,
        process: "praxis".to_owned(),
        pid: std::process::id(),
        // RFC 6587 octet framing delimits records on a TCP stream; datagram
        // transports (udp, unix) carry one record per message already.
        octet_framed: matches!(destination, SyslogDestination::Tcp { .. }),
    };
    let target = SyslogTarget {
        destination,
        formatter,
        dest: Arc::clone(&dest),
    };
    let (tx, rx) = sync_channel(SINK_QUEUE_CAPACITY);
    spawn_syslog_writer(rx, target).map_err(|e| format!("access_log: cannot start syslog sink writer: {e}"))?;
    Ok(Arc::new(DirectSink::new(tx, dest)))
}

/// Human-readable destination label for diagnostics.
fn syslog_dest(destination: &SyslogDestination) -> String {
    match destination {
        SyslogDestination::Unix { path } => format!("syslog:unix:{}", path.as_deref().unwrap_or("/dev/log")),
        SyslogDestination::Udp { address } => format!("syslog:udp:{address}"),
        SyslogDestination::Tcp { address } => format!("syslog:tcp:{address}"),
    }
}

/// Spawn the syslog writer thread and register its handle for shutdown.
fn spawn_syslog_writer(rx: Receiver<String>, target: SyslogTarget) -> std::io::Result<()> {
    let handle = std::thread::Builder::new()
        .name("access-log-syslog".to_owned())
        .spawn(move || run_syslog_writer(&rx, &target, &SINK_SHUTDOWN))?;
    register_sink_writer(handle);
    Ok(())
}

/// Drain the queue into the syslog `Logger`, owning its connection lifecycle and
/// honouring [`SINK_SHUTDOWN`] so an idle writer still exits at shutdown.
fn run_syslog_writer(rx: &Receiver<String>, target: &SyslogTarget, shutdown: &AtomicBool) {
    let mut state = SyslogWriterState::default();
    loop {
        match rx.recv_timeout(SINK_POLL_INTERVAL) {
            Ok(line) => state.emit(target, &line),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) if shutdown.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Timeout) => {},
        }
    }
    while let Ok(line) = rx.try_recv() {
        state.emit(target, &line);
    }
}

/// After a failed (re)connection the writer suppresses reconnects for this long,
/// dropping records meanwhile. Every connect attempt may spawn a `syslog-io` helper
/// thread (for a Unix connect or DNS resolution) that a hung syscall can leave
/// blocked, so bounding the reconnect rate bounds how fast those helpers can pile up
/// during a sustained outage.
const SYSLOG_RECONNECT_COOLDOWN: Duration = Duration::from_secs(30);

/// State the syslog writer carries across records: the lazily-built `Logger`, the
/// failure-warning throttle, and the post-failure reconnect-cooldown deadline.
#[derive(Default)]
pub(crate) struct SyslogWriterState {
    /// Active logger, or `None` before the first record and after a failure.
    pub(crate) logger: Option<Logger<LoggerBackend, Rfc3164Formatter>>,
    /// Rate-limits connect/write failure warnings.
    throttle: WriteWarnThrottle,
    /// When set, reconnect attempts are suppressed until this instant.
    cooldown_until: Option<Instant>,
}

impl SyslogWriterState {
    /// Emit one line, lazily (re)connecting the `Logger`. A failed connect *or* send
    /// starts a cooldown during which records are dropped, so a stalled peer or
    /// resolver cannot make every queued record block for the I/O timeout or spawn
    /// another blocked helper thread.
    pub(crate) fn emit(&mut self, target: &SyslogTarget, line: &str) {
        if self.logger.is_none() {
            if self.in_cooldown() {
                return;
            }
            match connect_logger(target) {
                Ok(active) => {
                    self.logger = Some(active);
                    self.cooldown_until = None;
                },
                Err(e) => {
                    self.throttle.warn_display(&target.dest, &e);
                    self.start_cooldown();
                    return;
                },
            }
        }
        if let Some(active) = self.logger.as_mut()
            && let Err(e) = active.info(line)
        {
            self.throttle.warn_display(&target.dest, &e);
            // A send failure forces a reconnect on the next record; cool down too so a
            // collector that stalls after connecting cannot loop one timed-out write
            // (and reconnect) per record.
            self.logger = None;
            self.start_cooldown();
        }
    }

    /// Begin the post-failure reconnect cooldown from now.
    fn start_cooldown(&mut self) {
        self.cooldown_until = Instant::now().checked_add(SYSLOG_RECONNECT_COOLDOWN);
    }

    /// Whether the post-failure reconnect cooldown is still in effect.
    pub(crate) fn in_cooldown(&self) -> bool {
        self.cooldown_until.is_some_and(|until| Instant::now() < until)
    }
}

/// (Re)connect the `syslog` crate `Logger` for the target's destination.
fn connect_logger(target: &SyslogTarget) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let formatter = target.formatter.clone();
    match &target.destination {
        SyslogDestination::Unix { path } => connect_unix(formatter, path.as_deref(), SYSLOG_IO_TIMEOUT),
        SyslogDestination::Udp { address } => connect_udp(formatter, address, SYSLOG_IO_TIMEOUT),
        SyslogDestination::Tcp { address } => connect_tcp(formatter, address, SYSLOG_IO_TIMEOUT),
    }
}

/// Run a blocking I/O op on a short-lived thread, returning its result or a
/// `TimedOut` error if it does not finish within `timeout`. Bounds operations std
/// offers no timeout for (unix stream connect, DNS resolution) so a stalled peer or
/// resolver cannot block the writer thread (and thus its bounded queue) forever.
pub(crate) fn with_timeout<T, F>(timeout: Duration, op: F) -> std::io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
{
    let (tx, rx) = sync_channel(1);
    std::thread::Builder::new()
        .name("syslog-io".to_owned())
        .spawn(move || {
            drop(tx.send(op()));
        })?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "syslog io timed out")),
    }
}

/// Resolve `address` to socket addresses within `timeout`, so a stalled resolver
/// cannot block the writer thread before the connect timeout even begins.
fn resolve_addrs(address: &str, timeout: Duration) -> std::io::Result<Vec<SocketAddr>> {
    let owned = address.to_owned();
    with_timeout(timeout, move || Ok(owned.to_socket_addrs()?.collect()))
}

/// Connect a Unix syslog logger with bounded connect and write timeouts (the crate's
/// helpers set none), trying a datagram socket first (the usual `/dev/log` shape) and
/// falling through to a `SOCK_STREAM` collector only when the datagram connect fails
/// with the socket-type mismatch, so a missing socket or denied permission surfaces as
/// itself rather than a masked stream-connect error.
pub(crate) fn connect_unix(
    formatter: Rfc3164Formatter,
    path: Option<&str>,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let path = path.unwrap_or("/dev/log");
    match unix_datagram(path, timeout) {
        Ok(socket) => Ok(Logger::new(LoggerBackend::Unix(socket), formatter)),
        Err(e) if is_wrong_socket_type(&e) => connect_unix_stream_logger(formatter, path, timeout),
        Err(e) => Err(e.into()),
    }
}

/// Build a stream-backed Unix syslog logger for a `SOCK_STREAM` collector, bounding
/// both the connect and subsequent writes by `timeout`.
fn connect_unix_stream_logger(
    formatter: Rfc3164Formatter,
    path: &str,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let stream = connect_unix_stream(path, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(Logger::new(
        LoggerBackend::UnixStream(BufWriter::new(stream)),
        formatter,
    ))
}

/// Raw `EPROTOTYPE` errno: a datagram connect to a `SOCK_STREAM` endpoint reports it
/// (Linux `91`). The lone datagram error that warrants the stream fallback.
#[cfg(target_os = "linux")]
pub(crate) const EPROTOTYPE_ERRNO: i32 = 91;
/// Raw `EPROTOTYPE` errno on BSD/macOS targets (`41`).
#[cfg(not(target_os = "linux"))]
pub(crate) const EPROTOTYPE_ERRNO: i32 = 41;

/// Whether a Unix datagram connect error means the endpoint is a `SOCK_STREAM` socket
/// (retry it as a stream) rather than a real failure such as a missing socket or
/// denied permission. `EPROTOTYPE` has no std `ErrorKind`, so match its raw errno;
/// `InvalidInput` covers the same mismatch surfaced as a kind.
pub(crate) fn is_wrong_socket_type(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::InvalidInput || err.raw_os_error() == Some(EPROTOTYPE_ERRNO)
}

/// Connect a Unix stream within `timeout` so a full listen backlog cannot block the
/// writer; std has no bounded `UnixStream::connect`, so it runs via [`with_timeout`].
fn connect_unix_stream(path: &str, timeout: Duration) -> std::io::Result<UnixStream> {
    let owned = path.to_owned();
    with_timeout(timeout, move || UnixStream::connect(owned))
}

/// Bind an unbound `AF_UNIX` datagram socket with a write timeout and connect it
/// to `path`, so `send` on a full collector buffer times out instead of blocking.
fn unix_datagram(path: &str, write_timeout: Duration) -> std::io::Result<UnixDatagram> {
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(write_timeout))?;
    socket.connect(path)?;
    Ok(socket)
}

/// Connect a UDP syslog logger, resolving the collector within `timeout` and binding
/// the local socket in its address family so an IPv6 target (e.g. `[::1]:514`) works.
fn connect_udp(
    formatter: Rfc3164Formatter,
    address: &str,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let server = resolve_addrs(address, timeout)?
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "syslog udp address did not resolve"))?;
    // Resolved SocketAddr for both local and server keeps the crate's bind DNS-free.
    let local: SocketAddr = if server.is_ipv6() {
        ([0_u8; 16], 0).into()
    } else {
        ([0_u8; 4], 0).into()
    };
    syslog::udp(formatter, local, server)
}

/// Connect a TCP syslog logger with bounded connect and write timeouts so a stalled
/// collector cannot block the writer. `Logger::info` flushes the backend per message.
fn connect_tcp(
    formatter: Rfc3164Formatter,
    address: &str,
    timeout: Duration,
) -> syslog::Result<Logger<LoggerBackend, Rfc3164Formatter>> {
    let stream = dial_tcp(address, timeout)?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(Logger::new(LoggerBackend::Tcp(BufWriter::new(stream)), formatter))
}

/// Dial the first reachable address `address` resolves to, bounding both resolution
/// and each connect by `timeout`. `connect_timeout` takes one `SocketAddr`, so we
/// iterate the resolved set ourselves and surface the last error if none work.
fn dial_tcp(address: &str, timeout: Duration) -> std::io::Result<std::net::TcpStream> {
    let mut last_err = std::io::Error::new(std::io::ErrorKind::NotFound, "syslog tcp address did not resolve");
    for addr in resolve_addrs(address, timeout)? {
        match std::net::TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

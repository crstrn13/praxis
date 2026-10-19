// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Direct stdout/file output sinks: bounded background writers, their shutdown
//! lifecycle, and runtime-sink construction from config.

#![allow(clippy::missing_docs_in_private_items, reason = "internal sink types")]

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::BufWriter,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use chrono::{DateTime, SecondsFormat, Utc};

use super::config::SinkConfig;
#[cfg(feature = "access-log-syslog")]
use super::syslog::syslog_sink;
use crate::{FilterError, filter::HttpFilterContext};

/// Runtime output sink resolved from [`SinkConfig`].
pub(crate) enum RuntimeSink {
    /// Emit via `tracing::info!`; the subscriber controls the format.
    Tracing,
    /// Write NDJSON lines to a background writer (stdout or a file).
    Direct(Arc<DirectSink>),
}

/// Bounded queue capacity for a direct sink's background writer. Records are
/// dropped (not blocked on) once this many are queued, so a slow or stalled
/// sink can never block a request executor thread.
pub(crate) const SINK_QUEUE_CAPACITY: usize = 8_192;

/// How often an idle writer wakes to observe [`SINK_SHUTDOWN`]. Bounds how long
/// `shutdown_sinks` waits for a quiescent writer (e.g. stdout, whose sender
/// never drops) to notice the flag and exit.
pub(crate) const SINK_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Poll interval while waiting for a writer to finish during shutdown.
const SINK_JOIN_POLL: Duration = Duration::from_millis(5);

/// Set once at process shutdown so idle writers flush and exit even when their
/// sender never drops (the stdout singleton), making their handles joinable.
pub(crate) static SINK_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Join handles for every spawned writer thread, drained and joined by
/// [`shutdown_sinks`]. Finished handles are pruned as new writers register.
static SINK_WRITERS: OnceLock<Mutex<Vec<JoinHandle<()>>>> = OnceLock::new();

/// Handle to a background NDJSON writer shared by every filter instance that
/// targets the same destination.
///
/// Emitting hands an owned line to a bounded channel and returns immediately;
/// the blocking write and flush happen on a dedicated writer thread. A full
/// channel drops the line (counted, with a rate-limited warning) rather than
/// stalling the request path. Filters hold an `Arc<DirectSink>`; the file
/// registry keeps only a `Weak`, so the writer thread exits once the last
/// filter using a path is dropped (for example after a config reload).
pub(crate) struct DirectSink {
    /// Sender into the writer thread's bounded queue.
    tx: SyncSender<String>,
    /// Destination label for diagnostics (`"stdout"` or the file path).
    pub(crate) dest: Arc<str>,
    /// Count of lines dropped because the queue was full.
    dropped: AtomicU64,
    /// Unix-seconds timestamp of the last drop warning, for rate limiting.
    last_drop_warn: AtomicU64,
}

impl DirectSink {
    /// Build a handle around a channel sender.
    pub(crate) fn new(tx: SyncSender<String>, dest: Arc<str>) -> Self {
        Self {
            tx,
            dest,
            dropped: AtomicU64::new(0),
            last_drop_warn: AtomicU64::new(0),
        }
    }

    /// Queue one line for the background writer, dropping it if the queue is
    /// full so the caller never blocks.
    pub(crate) fn record(&self, line: String) {
        if self.tx.try_send(line).is_err() {
            let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            let now = unix_secs();
            let prev = self.last_drop_warn.load(Ordering::Relaxed);
            if now > prev
                && self
                    .last_drop_warn
                    .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                tracing::warn!(sink = %self.dest, dropped = total, "access_log sink queue full; dropping records");
            }
        }
    }
}

/// Throttles write-failure warnings on a writer thread to at most one per
/// second so a persistently failing sink cannot flood the logs.
#[derive(Default)]
pub(crate) struct WriteWarnThrottle {
    /// Unix-seconds timestamp of the last emitted warning.
    last_secs: u64,
}

impl WriteWarnThrottle {
    /// Warn about a write/flush failure unless one was already logged this
    /// second.
    fn warn(&mut self, dest: &str, err: &std::io::Error) {
        let now = unix_secs();
        if now != self.last_secs {
            self.last_secs = now;
            tracing::warn!(sink = %dest, error = %err, "access_log sink write failed");
        }
    }

    /// Warn about a sink failure carrying a non-`io::Error` cause (e.g. a syslog
    /// connect error), throttled identically to [`WriteWarnThrottle::warn`].
    #[cfg(feature = "access-log-syslog")]
    pub(crate) fn warn_display(&mut self, dest: &str, err: &dyn std::fmt::Display) {
        let now = unix_secs();
        if now != self.last_secs {
            self.last_secs = now;
            tracing::warn!(sink = %dest, error = %err, "access_log sink write failed");
        }
    }
}

/// Seconds since the Unix epoch, saturating to 0 before 1970.
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// RFC 3339 UTC timestamp (millisecond precision) for a sink record, taken from
/// the request's clock abstraction so tests can pin it, mirroring `cloud_events`.
pub(crate) fn sink_timestamp(ctx: &HttpFilterContext<'_>) -> String {
    let now = ctx.time_source.now();
    DateTime::<Utc>::from_timestamp(i64::try_from(now.as_secs()).unwrap_or(i64::MAX), now.subsec_nanos()).map_or_else(
        || "1970-01-01T00:00:00.000Z".to_owned(),
        |time| time.to_rfc3339_opts(SecondsFormat::Millis, true),
    )
}

/// Write `first` and any further queued lines, then flush once, reporting
/// (rate-limited) write or flush failures.
fn flush_batch<W: std::io::Write>(
    writer: &mut W,
    rx: &Receiver<String>,
    throttle: &mut WriteWarnThrottle,
    dest: &str,
    first: &str,
) {
    let mut result = writeln!(writer, "{first}");
    // Write any further queued lines before paying for a single flush.
    while result.is_ok() {
        match rx.try_recv() {
            Ok(next) => result = writeln!(writer, "{next}"),
            Err(_) => break,
        }
    }
    if let Err(e) = result.and_then(|()| writer.flush()) {
        throttle.warn(dest, &e);
    }
}

/// Drain the queue onto `writer`, batching available lines before each flush and
/// reporting (rate-limited) failures. Returns when every sender is dropped or
/// `shutdown` is set, flushing whatever is still queued first. `shutdown` is
/// injected (rather than read from [`SINK_SHUTDOWN`] directly) so the exit path
/// is unit-testable in isolation.
pub(crate) fn run_sink_writer<W: std::io::Write>(
    mut writer: W,
    rx: &Receiver<String>,
    dest: &str,
    shutdown: &AtomicBool,
) {
    let mut throttle = WriteWarnThrottle::default();
    loop {
        match rx.recv_timeout(SINK_POLL_INTERVAL) {
            Ok(line) => flush_batch(&mut writer, rx, &mut throttle, dest, &line),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) if shutdown.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Timeout) => {},
        }
    }
    // Flush records queued between the last receive and the exit condition.
    if let Ok(line) = rx.try_recv() {
        flush_batch(&mut writer, rx, &mut throttle, dest, &line);
    }
    drop(writer.flush());
}

/// Spawn the dedicated writer thread for a destination and register its handle
/// for shutdown.
///
/// The caller must only cache the sink once this succeeds: a dropped `rx` would
/// make every send fail as "disconnected" while a dead sink lingered until
/// restart.
fn spawn_sink_writer<W: std::io::Write + Send + 'static>(
    writer: W,
    rx: Receiver<String>,
    dest: Arc<str>,
) -> std::io::Result<()> {
    let handle = std::thread::Builder::new()
        .name("access-log-sink".to_owned())
        .spawn(move || run_sink_writer(writer, &rx, &dest, &SINK_SHUTDOWN))?;
    register_sink_writer(handle);
    Ok(())
}

/// Record a writer's join handle so [`shutdown_sinks`] can drain it, pruning
/// handles whose threads already finished (e.g. writers replaced by a reload).
pub(crate) fn register_sink_writer(handle: JoinHandle<()>) {
    let registry = SINK_WRITERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.retain(|existing| !existing.is_finished());
    guard.push(handle);
}

/// Signal every access-log sink writer to flush and exit, then wait up to
/// `timeout` (total) for them to finish before the process exits.
///
/// Writers already flush after each batch, so this only recovers records still
/// queued at shutdown. A writer that has not finished by the deadline is left to
/// the exiting process rather than blocking it, matching the drop-on-overflow
/// queue: the sink is best-effort, never the system of record.
#[expect(
    clippy::disallowed_methods,
    reason = "bounded synchronous wait during process shutdown, not on the async runtime"
)]
pub fn shutdown_sinks(timeout: Duration) {
    SINK_SHUTDOWN.store(true, Ordering::Release);
    let Some(registry) = SINK_WRITERS.get() else {
        return;
    };
    let handles: Vec<JoinHandle<()>> = {
        let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut guard)
    };
    let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);
    for handle in handles {
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(SINK_JOIN_POLL);
        }
        if handle.is_finished() {
            drop(handle.join());
        }
    }
}

/// The process-wide stdout sink, created on first use.
///
/// Returns an error if the writer thread cannot be spawned so the sink is never
/// cached without a live writer behind it.
fn stdout_sink() -> Result<Arc<DirectSink>, FilterError> {
    static STDOUT: OnceLock<Arc<DirectSink>> = OnceLock::new();
    if let Some(sink) = STDOUT.get() {
        return Ok(Arc::clone(sink));
    }
    let (tx, rx) = sync_channel(SINK_QUEUE_CAPACITY);
    let dest: Arc<str> = Arc::from("stdout");
    spawn_sink_writer(std::io::stdout(), rx, Arc::clone(&dest))
        .map_err(|e| format!("access_log: cannot start stdout sink writer: {e}"))?;
    // A concurrent first-init may have stored its sink first; keep that one and
    // let this writer thread exit when its unused sender drops. stdout lives for
    // the whole process, so this handle is intentionally never reclaimed.
    Ok(Arc::clone(STDOUT.get_or_init(|| Arc::new(DirectSink::new(tx, dest)))))
}

/// A file sink for `path`, shared across filter instances that name the same
/// destination so a single writer and queue serialize all writes and NDJSON
/// records never interleave.
fn file_sink(path: &str) -> Result<Arc<DirectSink>, FilterError> {
    static FILES: OnceLock<Mutex<HashMap<PathBuf, Weak<DirectSink>>>> = OnceLock::new();
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("access_log: cannot open log file {path:?}: {e}"))?;
    // Canonicalize so `./a.log` and `a.log` resolve to one writer; fall back to
    // the raw path if the resolve fails (it cannot, having just opened it).
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let registry = FILES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(sink) = guard.get(&key).and_then(Weak::upgrade) {
        return Ok(sink);
    }
    let (tx, rx) = sync_channel(SINK_QUEUE_CAPACITY);
    let dest: Arc<str> = Arc::from(path);
    spawn_sink_writer(BufWriter::new(file), rx, Arc::clone(&dest))
        .map_err(|e| format!("access_log: cannot start writer for log file {path:?}: {e}"))?;
    let sink = Arc::new(DirectSink::new(tx, dest));
    guard.insert(key, Arc::downgrade(&sink));
    drop(guard);
    Ok(sink)
}

/// Build a [`RuntimeSink`] from the deserialized `sink` config.
///
/// No `sink` emits through the tracing subscriber (the default). `stdout` and
/// `file` bypass tracing and write NDJSON lines directly; `file` requires a
/// `path` and `stdout` rejects one.
pub(crate) fn build_runtime_sink(sink_cfg: Option<SinkConfig>) -> Result<RuntimeSink, FilterError> {
    match sink_cfg {
        None => Ok(RuntimeSink::Tracing),
        Some(SinkConfig::Stdout) => Ok(RuntimeSink::Direct(stdout_sink()?)),
        Some(SinkConfig::File { path }) => Ok(RuntimeSink::Direct(file_sink(&path)?)),
        #[cfg(feature = "access-log-syslog")]
        Some(SinkConfig::Syslog { facility, target }) => Ok(RuntimeSink::Direct(syslog_sink(facility, target)?)),
    }
}

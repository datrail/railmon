//! The capture pipeline.
//!
//! Everything hard about reading agent traffic — reconstructing HTTP from raw
//! SSL reads and writes, SSE streams, gzip, chunked transfer-encoding,
//! truncation, stripping `Authorization` — is AgentSight's, consumed as a
//! library. What stays here is the part that is RailMon's own: spawning the
//! probe, unwrapping what it emits, pairing a request with its response, and
//! attributing the result, plus two byte-level stages in front of the HTTP/1
//! parser (`http1_guard`, `http1_decode`).

use crate::http1_decode::CompressedReplyDecoder;
use crate::http1_guard::{Http1FramingGuard, RestoreDiverted};
use agentsight_capture::analyzers::{
    Analyzer, AuthHeaderRemover, HTTPDecompressor, HTTPParser, TimestampNormalizer,
};
use agentsight_capture::runners::EventStream;
use agentsight_capture::Event;
use anyhow::{Context, Result};
use futures::{stream, FutureExt, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Filters handed to the probe, so unwanted traffic is dropped at the source
/// rather than carried through the chain.
#[derive(Debug, Default, Clone)]
pub struct CaptureFilters {
    pub binary_path: Option<String>,
    pub pid: Option<i32>,
    pub uid: Option<i32>,
    pub comm: Option<String>,
    pub process_session: Option<u32>,
}

/// Build the probe's command line.
///
/// Two shapes, because the flags are not interchangeable and the Python
/// supported both:
///
/// * a bare `sslsniff` binary takes long filter flags directly;
/// * `agentsight debug ssl` takes `--binary-path` itself but forwards the
///   sslsniff filters *after a `--` separator, as short flags*. Passing
///   `--pid` to agentsight is not the same thing and does not reach the probe.
///
/// `--comm` is suppressed whenever `--binary-path` is set: the probe compares
/// against the thread name rather than the process name, so combining them
/// silently matches nothing.
pub fn build_command(agentsight_path: &str, filters: &CaptureFilters) -> Vec<String> {
    let path = agentsight_path.to_string();
    let is_bare_sslsniff = Path::new(agentsight_path)
        .file_name()
        .map(|n| n == "sslsniff")
        .unwrap_or(false);

    if is_bare_sslsniff {
        let mut cmd = vec![path];
        if let Some(b) = &filters.binary_path {
            cmd.extend(["--binary-path".into(), b.clone()]);
        }
        if let Some(p) = filters.pid {
            cmd.extend(["--pid".into(), p.to_string()]);
        }
        if let Some(u) = filters.uid {
            cmd.extend(["--uid".into(), u.to_string()]);
        }
        if let Some(s) = filters.process_session {
            cmd.extend(["--session".into(), s.to_string()]);
        }
        if let (Some(c), None) = (&filters.comm, &filters.binary_path) {
            cmd.extend(["--comm".into(), c.clone()]);
        }
        return cmd;
    }

    let mut cmd = vec![path, "debug".into(), "ssl".into()];
    if let Some(b) = &filters.binary_path {
        cmd.extend(["--binary-path".into(), b.clone()]);
    }

    let mut ssl_args: Vec<String> = Vec::new();
    if let Some(p) = filters.pid {
        ssl_args.extend(["-p".into(), p.to_string()]);
    }
    if let Some(u) = filters.uid {
        ssl_args.extend(["-u".into(), u.to_string()]);
    }
    if let Some(s) = filters.process_session {
        ssl_args.extend(["--session".into(), s.to_string()]);
    }
    if let (Some(c), None) = (&filters.comm, &filters.binary_path) {
        ssl_args.extend(["-c".into(), c.clone()]);
    }
    if !ssl_args.is_empty() {
        cmd.push("--".into());
        cmd.extend(ssl_args);
    }
    cmd
}

/// Flatten one line of probe output into an SSL event body.
///
/// `agentsight debug ssl` wraps each sslsniff event in an envelope — the
/// sslsniff fields, including `timestamp_ns` and `tid`, sit under `data` while
/// the envelope carries its own `timestamp`. A bare `sslsniff` emits them flat.
/// The analyzers want them flat, so the envelope is unwrapped here.
///
/// Getting this wrong fails silently rather than loudly: an un-unwrapped
/// envelope has no payload string where the HTTP parser looks, so it passes
/// through the entire chain untouched, never becomes a request or a response,
/// and the collector reports success while capturing nothing.
pub fn normalize_ssl_event(raw: &Value) -> Option<Value> {
    let mut event = raw.as_object()?.clone();

    let is_envelope = event.get("source").and_then(Value::as_str) == Some("ssl")
        && event.get("data").map(Value::is_object).unwrap_or(false);

    if is_envelope {
        event = event.get("data")?.as_object()?.clone();
    } else if !event.contains_key("function") {
        // Defensive: some builds nest without naming the source.
        if let Some(nested) = event.get("data").and_then(Value::as_object) {
            if nested.contains_key("function") || nested.contains_key("data") {
                event = nested.clone();
            }
        }
    }

    if !event.contains_key("function") && event.get("data").map(Value::is_null).unwrap_or(true) {
        return None;
    }

    // sslsniff sends non-UTF-8 payloads hex-encoded behind a HEX: marker.
    if let Some(text) = event.get("data").and_then(Value::as_str) {
        if let Some(hexed) = text.strip_prefix("HEX:") {
            if let Some(decoded) = decode_hex_latin1(hexed) {
                event.insert("data".into(), Value::String(decoded));
            }
        }
    }

    Some(Value::Object(event))
}

/// latin-1 rather than UTF-8 on purpose: this is a byte stream and every byte
/// has to reach the HTTP parser intact. Decoding as UTF-8 would collapse runs
/// of a binary body into replacement characters and shift every offset after
/// them.
fn decode_hex_latin1(hexed: &str) -> Option<String> {
    crate::http1_guard::hex_decode(hexed).map(|bytes| bytes.into_iter().map(char::from).collect())
}

/// The probe's exit status, resolved once its output ends.
pub type ProbeStatus = tokio::sync::oneshot::Receiver<Option<std::process::ExitStatus>>;

/// Header names carrying a credential that AgentSight's own allowlist does not
/// cover: Azure OpenAI, Gemini, and forward proxies.
const EXTRA_CREDENTIAL_HEADERS: [&str; 3] = ["api-key", "x-goog-api-key", "proxy-authorization"];

/// Says when the probe lost records: its ring buffer was full, so whole TLS
/// reads and writes never reached us. The counter is the probe's own, for
/// every connection at once, so AgentSight's parser (1.0.35 on) stops pairing
/// every connection open at that moment until it closes, rather than guess
/// where the lost bytes belonged. Requests it had in flight come through as
/// incomplete; later ones on the same connection don't come through at all,
/// and this is the only line that says so.
#[derive(Default)]
struct CaptureLossLog {
    failures: u64,
}

#[async_trait::async_trait]
impl Analyzer for CaptureLossLog {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut seen = std::mem::take(&mut self.failures);
        Ok(Box::pin(stream.map(move |event| {
            if let Some(now) = event
                .data
                .get("ringbuf_reserve_failures")
                .and_then(Value::as_u64)
            {
                if now > seen {
                    log::warn!(
                        "the TLS probe lost {} record(s) (ring buffer full, {now} so far); AgentSight \
                         stops pairing the connections open now until each closes, so their later \
                         requests are not captured",
                        now - seen
                    );
                }
                seen = seen.max(now);
            }
            event
        })))
    }
}

/// Redacts the credential headers upstream misses.
///
/// An analyzer rather than a step in `message_body`, so it covers `--mode raw`
/// too: that mode serialises the analyzer event straight to the sink without
/// going near the pairing code, and a scrub that only the paired path applies
/// is a scrub with a documented way around it.
struct ExtraCredentialRedactor;

#[async_trait::async_trait]
impl Analyzer for ExtraCredentialRedactor {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::pin(stream.map(|mut event| {
            if let Some(headers) = event.data.get_mut("headers").and_then(Value::as_object_mut) {
                for (key, value) in headers.iter_mut() {
                    if EXTRA_CREDENTIAL_HEADERS
                        .iter()
                        .any(|e| key.eq_ignore_ascii_case(e))
                    {
                        *value = Value::String("[REDACTED]".into());
                    }
                }
            }

            // An SSL event the parser did not recognise passes through with the
            // whole wire text intact and no `headers` map — a CONNECT to a
            // forward proxy, for instance, which is exactly where
            // Proxy-Authorization lives. `--mode raw` writes that verbatim, so
            // the credentials have to be taken out of the text itself.
            if event.data.get("headers").is_none() {
                if let Some(text) = event.data.get("data").and_then(Value::as_str) {
                    if let Some(scrubbed) = redact_header_lines(text) {
                        event.data["data"] = Value::String(scrubbed);
                    }
                }
            }
            event
        })))
    }
}

/// Every credential header name we know of, for scrubbing raw wire text.
const ALL_CREDENTIAL_HEADERS: [&str; 12] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "cookie",
    "set-cookie",
    "token",
    "bearer",
];

/// Replace the value of any credential header in a raw HTTP message, keeping
/// the line so the shape of the request is still visible. Returns None when
/// there was nothing to redact, so the common case allocates nothing.
fn redact_header_lines(text: &str) -> Option<String> {
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    // Past the blank line is the body, where a colon is not a header
    // separator. Tracked as a flag rather than by slicing the remainder: an
    // earlier version resumed with `&text[out.len()..]`, and once a line has
    // been rewritten the output length no longer matches the input offset, so
    // it spliced original bytes back in — including the very Authorization
    // header it had just redacted.
    let mut in_headers = true;
    let mut redacting_continuation = false;

    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !in_headers && is_http_start_line(trimmed) {
            // One SSL read may coalesce multiple HTTP messages. The blank line
            // ended the previous header block; this request/status line opens
            // the next one.
            in_headers = true;
        }
        if in_headers && trimmed.is_empty() {
            in_headers = false;
            redacting_continuation = false;
        }
        if in_headers && (trimmed.starts_with(' ') || trimmed.starts_with('\t')) {
            if redacting_continuation {
                let indentation_len = trimmed.len() - trimmed.trim_start_matches([' ', '\t']).len();
                out.push_str(&trimmed[..indentation_len]);
                out.push_str("[REDACTED]");
                out.push_str(&line[trimmed.len()..]);
                changed = true;
                continue;
            }
            out.push_str(line);
            continue;
        }
        redacting_continuation = false;
        if in_headers {
            if let Some((name, _)) = trimmed.split_once(':') {
                if ALL_CREDENTIAL_HEADERS
                    .iter()
                    .any(|h| name.trim().eq_ignore_ascii_case(h))
                {
                    out.push_str(name);
                    out.push_str(": [REDACTED]");
                    out.push_str(&line[trimmed.len()..]);
                    changed = true;
                    redacting_continuation = true;
                    continue;
                }
            }
        }
        out.push_str(line);
    }
    changed.then_some(out)
}

fn is_http_start_line(line: &str) -> bool {
    // Content-Length bodies need not end in CR/LF. A coalesced response can
    // therefore begin mid-line, e.g. `{}HTTP/1.1 200 OK`.
    if let Some(status_at) = line.rfind("HTTP/") {
        let mut status_parts = line[status_at..].split_whitespace();
        let _version = status_parts.next();
        if status_parts
            .next()
            .is_some_and(|status| status.len() == 3 && status.bytes().all(|b| b.is_ascii_digit()))
        {
            return true;
        }
    }
    // Likewise, a pipelined request may start directly after body bytes. Be
    // conservative: a trailing HTTP version plus a method/target separator is
    // enough to reopen header mode in raw capture data.
    let Some(request_version_at) = line.rfind(" HTTP/") else {
        return false;
    };
    line[..request_version_at]
        .trim_end()
        .chars()
        .any(char::is_whitespace)
}

/// Spawn the probe and return a stream of analyzed events, plus a handle to the
/// probe's exit status so the caller can tell "captured nothing because the
/// agent was idle" from "captured nothing because the probe could not attach".
pub async fn event_stream(
    agentsight_path: &str,
    filters: &CaptureFilters,
) -> Result<(EventStream, ProbeStatus)> {
    let cmd = build_command(agentsight_path, filters);
    log::info!("starting: {}", cmd.join(" "));

    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // Otherwise the probe outlives us with its eBPF programs still
        // attached, and the next run fails to attach.
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {}", cmd[0]))?;

    let stdout = child
        .stdout
        .take()
        .context("probe produced no stdout pipe")?;
    let lines = BufReader::new(stdout).lines();

    let (status_tx, status_rx) = tokio::sync::oneshot::channel();

    // The child rides in the stream's state, so it lives exactly as long as the
    // capture and `kill_on_drop` stops it when the stream is dropped. When its
    // output ends we reap it and publish the exit status.
    let raw = stream::unfold(
        (lines, child, Some(status_tx)),
        |(mut lines, mut child, mut status_tx)| async move {
            loop {
                let line = match lines.next_line().await {
                    Ok(Some(line)) => line,
                    end => {
                        if let Err(error) = end {
                            log::warn!("reading probe output: {error}");
                        }
                        if let Some(tx) = status_tx.take() {
                            let _ = tx.send(child.wait().await.ok());
                        }
                        return None;
                    }
                };
                if let Some(event) = ssl_event_from_line(&line) {
                    return Some((event, (lines, child, status_tx)));
                }
            }
        },
    );

    // Redaction is last: it needs fully reassembled headers, not a fragment
    // that happens not to contain the token yet.
    //
    // `disable_raw_data` is load-bearing rather than a size optimisation. With
    // raw data on, every event carries the original HTTP text, and
    // AuthHeaderRemover scrubs only the parsed header map — so credentials
    // would survive into the record written to disk and posted onward.
    let mut analyzers: Vec<Box<dyn Analyzer>> = vec![
        // First, and required, not optional: sslsniff timestamps are
        // `bpf_ktime_get_ns()`, nanoseconds since *boot*, and this is the
        // only thing converting them to epoch milliseconds. Without it every
        // interaction is dated 1970 and `interaction_id` hashes that. Before
        // the parser, as AgentSight's own chain has it: since 1.0.35 the
        // parser ages its connections on these timestamps in milliseconds,
        // and on boot nanoseconds it retires every connection after 0.6 ms of
        // its ten-minute idle limit, so no reply finds its request.
        Box::new(TimestampNormalizer::new()),
        Box::new(CaptureLossLog::default()),
        // Keeps another connection's reads out of a chunked reply in flight
        // on the same thread, then hands them back unchanged (#70). Only for
        // a capture whose records name no TLS connection.
        Box::new(Http1FramingGuard::new()),
        // Decodes a gzip/deflate/br/zstd HTTP/1 reply on its bytes, because
        // the parser's text conversion destroys a compressed body before
        // HTTPDecompressor can read it (#93). HTTPDecompressor stays for
        // HTTP/2 replies.
        Box::new(CompressedReplyDecoder::new()),
        Box::new(HTTPParser::new().disable_raw_data()),
        Box::new(RestoreDiverted),
        Box::new(HTTPDecompressor::new()),
        // No SSEProcessor, deliberately. It is a filter_map: for a streaming
        // response it swallows the parser's response event and emits its own,
        // carrying no `message_type` — so the request never pairs, sits in
        // `pending` for ever, and nothing is written. Since agent traffic to
        // Anthropic and OpenAI is overwhelmingly `stream: true`, including it
        // means capturing almost nothing. The Python chain did not use it
        // either; it treated an SSE response as a response.
        //
        // What leaving it out costs, on agentsight 1.0.35. A chunked HTTP/1.1
        // reply is held until its last chunk and emitted whole (the parser
        // test in http1_guard.rs relies on it), and HTTP/2 DATA frames are
        // reassembled per stream. But the response keeps the timestamp of its
        // first read, so `latency_ms` is time-to-first-byte rather than stream
        // duration; a chunked reply past 1 MiB is emitted cut, as
        // `body_truncated`, and stops matching its connection; and a
        // close-delimited reply (neither Content-Length nor chunked) is
        // recorded at its connection's close, or from its first read when
        // the capture names no connection. (At DR-20, on 1.0.14, chunked
        // replies were cut to their first read too: 81 of 532 bytes on an
        // Anthropic-shaped stream.) The holding buffer is per connection, or
        // per (pid, tid) without one, which is what Http1FramingGuard
        // protects.
        Box::new(AuthHeaderRemover::new()),
        Box::new(ExtraCredentialRedactor),
    ];

    let mut stream: EventStream = Box::pin(raw);
    for analyzer in analyzers.iter_mut() {
        stream = analyzer
            .process(stream)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok((contain_analyzer_panics(stream), status_rx))
}

/// Ends the tap's stream, instead of the whole process, when an analyzer
/// panics on captured bytes (DR-129).
///
/// The analyzers are lazy stream adapters, so their code runs inside our own
/// poll, on bytes from traffic the monitored agent — or any server it talks
/// to — controls. The panic that prompted it, `hpack` 0.3.0 on a malformed
/// dynamic-table-size update inside HTTPParser, is gone since agentsight-capture
/// 1.0.34 moved to loona-hpack; the guard stays for whatever panics next, since
/// the agentsight-capture crate is a caret requirement in Cargo.toml, not an
/// exact pin, and one panic would otherwise abort every keyed target.
/// On a panic the inner stream is dropped right away, not merely no longer
/// polled: the probe child and the status sender live in its state, so
/// dropping it kills the probe (`kill_on_drop`) and closes the status channel,
/// which is what lets a keyed target restart through the ordinary tap-ended
/// path. The parser's state after a panic is unknown, so nothing more is read
/// from it.
fn contain_analyzer_panics(stream: EventStream) -> EventStream {
    Box::pin(
        stream::unfold(Some(stream), |state| async move {
            let mut inner = state?;
            match AssertUnwindSafe(inner.next()).catch_unwind().await {
                Ok(Some(event)) => Some((event, Some(inner))),
                Ok(None) => None,
                Err(panic) => {
                    let message = panic
                        .downcast_ref::<&str>()
                        .map(|text| text.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic payload".into());
                    log::error!(
                        "capture analyzer panicked on captured traffic ({message}); \
                         stopping this tap"
                    );
                    drop(inner);
                    None
                }
            }
        })
        // Fused, so a caller polling once more after the end gets `None` rather
        // than `unfold`'s own polled-after-completion panic.
        .fuse(),
    )
}

/// One line of probe output becomes at most one `Event` the analyzers accept.
fn ssl_event_from_line(line: &str) -> Option<Event> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let raw: Value = serde_json::from_str(line).ok()?;

    // Identity comes from the envelope, read before unwrapping: the inner event
    // repeats pid but not comm.
    let comm = raw
        .get("comm")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let outer_pid = raw.get("pid").and_then(Value::as_u64);

    let data = normalize_ssl_event(&raw)?;
    let pid = data
        .get("pid")
        .and_then(Value::as_u64)
        .or(outer_pid)
        .unwrap_or(0) as u32;
    let timestamp_ns = data
        .get("timestamp_ns")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    // Raw boot-relative nanoseconds, which is the crate's convention on the
    // way in: TimestampNormalizer later converts the field to epoch ms.
    Some(Event::new_with_timestamp(
        timestamp_ns,
        "ssl".to_string(),
        pid,
        comm,
        data,
    ))
}

/// Pairs parsed HTTP messages into interactions.
///
/// By AgentSight's `http_exchange_id` when the parser gives one (1.0.35 on):
/// it shares one id between a request and the reply it reassembled for it on
/// the same connection (HTTP/1.1 per-connection FIFO, HTTP/2 stream), so two
/// connections on one thread, as a Node agent runs them, can no longer swap
/// replies (datrail/railmon#70). A reply whose exchange has no request here
/// is counted as unmatched and never falls back to another request, which is
/// AgentSight's own rule. A record that ends an exchange without a reply
/// (`http_correlation`: the connection closed or timed out, the capture lost
/// bytes or ended) forwards its request as incomplete at once rather than
/// after `--pending-timeout`.
///
/// A message without an exchange id falls back to a FIFO per `(pid, tid)`,
/// matching the Python: an agent can have several requests in flight on one
/// thread, and responses come back in order, so the oldest outstanding
/// request owns the next response. Keying on the pair rather than the pid
/// alone is what keeps two concurrent threads from stealing each other's
/// responses.
#[derive(Default)]
pub struct Pairer {
    exchanges: HashMap<String, PendingRequest>,
    pending: HashMap<(u32, u64), VecDeque<PendingRequest>>,
    /// Responses that arrived with no request outstanding on their thread.
    /// Counted, not paired: there is nothing to pair them with.
    unmatched_responses: u64,
}

struct PendingRequest {
    epoch_ms: u64,
    /// When the pairer took it, on this process's monotonic clock. Ages are
    /// measured on this, never on `epoch_ms`: the probe's clock is
    /// CLOCK_MONOTONIC plus a boot time read once, so it falls behind the
    /// wall clock by every second the host has been suspended.
    queued: std::time::Instant,
    pid: u32,
    tid: u64,
    request: Value,
    size: usize,
}

impl Pairer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one analyzed event. Returns a paired interaction when this event
    /// completes one.
    ///
    /// `epoch_ms` is the event's own clock after normalization — when the
    /// traffic happened, not when we got round to formatting it. The parsed
    /// HTTP event carries no timestamp of its own, so this is the only source.
    pub fn accept(&mut self, pid: u32, data: &Value, epoch_ms: u64) -> Option<Value> {
        let tid = data.get("tid").and_then(Value::as_u64).unwrap_or(0);
        let key = (pid, tid);
        let exchange = data
            .get("http_exchange_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty());

        match data.get("message_type").and_then(Value::as_str) {
            Some("request") => {
                let pending = PendingRequest {
                    epoch_ms,
                    queued: std::time::Instant::now(),
                    pid,
                    tid,
                    request: message_body(data),
                    size: body_len(data),
                };
                if data.get("protocol").and_then(Value::as_str) == Some("WebSocket") {
                    // A WebSocket message the agent sent: nothing answers it,
                    // so queued here it could only take the next reply on its
                    // thread, or wait out the pending timeout. It goes on as
                    // it would have then, with no response.
                    return Some(incomplete(pending));
                }
                match exchange {
                    Some(id) => {
                        let older = self.exchanges.insert(id.to_string(), pending)?;
                        log::warn!(
                            "pid {} tid {}: exchange {id} opened twice; the earlier request is forwarded as incomplete",
                            older.pid,
                            older.tid
                        );
                        Some(incomplete(older))
                    }
                    None => {
                        self.pending.entry(key).or_default().push_back(pending);
                        None
                    }
                }
            }
            Some("response") => {
                let pending = match exchange {
                    Some(id) => self.exchanges.remove(id),
                    None => self.pending.get_mut(&key).and_then(VecDeque::pop_front),
                };
                let Some(pending) = pending else {
                    self.unmatched_responses += 1;
                    log::debug!(
                        "pid {pid} tid {tid}: a response with no request outstanding for it ({})",
                        exchange.unwrap_or("no exchange id")
                    );
                    return None;
                };
                let latency_ms = epoch_ms.checked_sub(pending.epoch_ms).map(|d| d as f64);

                // Rail Center requires `method` and `path` when a `request`
                // object is present, but accepts an interaction with no request
                // at all. An HTTP/2 stream whose HEADERS frame was never
                // decoded — normal for a connection already open at attach
                // time — has neither, and one of those rejects the entire
                // batch. Drop the unusable request rather than lose every good
                // interaction beside it.
                let request = usable_request(pending.request);

                Some(json!({
                    "timestamp": ms_to_rfc3339(pending.epoch_ms),
                    "timestamp_ns": pending.epoch_ms.saturating_mul(1_000_000),
                    "pid": pid,
                    "tid": pending.tid,
                    "request": request,
                    "response": message_body(data),
                    "request_size": pending.size,
                    "response_size": body_len(data),
                    "latency_ms": latency_ms,
                }))
            }
            // AgentSight ended this exchange without a reply.
            None if data.get("completion_reason").is_some() => {
                let pending = self.exchanges.remove(exchange?)?;
                let reason = data["completion_reason"].as_str().unwrap_or("unknown");
                if matches!(reason, "capture_loss" | "truncated" | "protocol_error") {
                    // AgentSight stops matching the whole connection after
                    // these, until it closes (http-correlation.md, "Loss and
                    // incomplete captures"): its later requests aren't paired
                    // or forwarded either.
                    log::warn!(
                        "pid {} tid {}: AgentSight ended an exchange on {reason} and stops \
                         pairing its connection until it closes; the request is forwarded as incomplete",
                        pending.pid,
                        pending.tid
                    );
                } else {
                    log::debug!(
                        "pid {} tid {}: exchange ended with no reply ({reason}); forwarded as incomplete",
                        pending.pid,
                        pending.tid
                    );
                }
                Some(incomplete(pending))
            }
            _ => None,
        }
    }

    /// Requests still outstanding — a response never arrived, or the capture
    /// stopped mid-flight. Reported rather than dropped silently.
    pub fn outstanding(&self) -> usize {
        self.exchanges.len() + self.pending.values().map(VecDeque::len).sum::<usize>()
    }

    /// Drains every still-pending request into a synthetic, response-less
    /// interaction marked `"incomplete": true`, for a tap that is stopping
    /// (target exit, PID reuse, or shutdown). A request whose response never
    /// arrived is otherwise indistinguishable from one that just never
    /// happened; this is what design doc §4.4 means by "pending requests are
    /// flushed as incomplete" rather than silently dropped.
    pub fn flush_incomplete(&mut self) -> Vec<Value> {
        let mut flushed: Vec<PendingRequest> = self.exchanges.drain().map(|(_, p)| p).collect();
        flushed.extend(self.pending.drain().flat_map(|(_, queue)| queue));
        flushed.sort_by_key(|pending| pending.epoch_ms);
        flushed.into_iter().map(incomplete).collect()
    }

    /// Takes out every request that has waited longer than `max_age` for
    /// its response, as incomplete interactions (DR-186), oldest first.
    ///
    /// Without this a lost response holds its request for the life of the
    /// tap, and nothing is ever forwarded or logged for it. AgentSight ends
    /// most such exchanges itself when it knows the connection (above); what
    /// is left is a capture without connection identity, where its HTTP/1
    /// parser keeps one buffer per thread and direction. A Node agent does
    /// all its TLS on one thread. A non-HTTP read at a chunk boundary is kept
    /// out of that buffer (Http1FramingGuard), but a second HTTP connection,
    /// or a foreign read in the middle of a chunk, still corrupts it and the
    /// reply never completes (datrail/railmon#70).
    ///
    /// Without an exchange id, a response that does arrive after its request
    /// expired finds the next request on that thread or none at all; the
    /// bound has to sit well past any real stream so that stays rare.
    pub fn expire(&mut self, now: std::time::Instant, max_age: std::time::Duration) -> Vec<Value> {
        let stale =
            |pending: &PendingRequest| now.saturating_duration_since(pending.queued) > max_age;
        let mut expired = Vec::new();
        let ids: Vec<String> = self
            .exchanges
            .iter()
            .filter(|(_, pending)| stale(pending))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            expired.extend(self.exchanges.remove(&id));
        }
        for queue in self.pending.values_mut() {
            // FIFO per thread, so the stale ones are at the front.
            while queue.front().is_some_and(stale) {
                expired.push(queue.pop_front().expect("front was checked"));
            }
        }
        self.pending.retain(|_, queue| !queue.is_empty());
        expired.sort_by_key(|pending| pending.epoch_ms);
        expired.into_iter().map(incomplete).collect()
    }

    /// Responses so far that found no request to pair with.
    pub fn unmatched_responses(&self) -> u64 {
        self.unmatched_responses
    }
}

fn incomplete(pending: PendingRequest) -> Value {
    json!({
        "timestamp": ms_to_rfc3339(pending.epoch_ms),
        "timestamp_ns": pending.epoch_ms.saturating_mul(1_000_000),
        "pid": pending.pid,
        "tid": pending.tid,
        "request": usable_request(pending.request),
        "response": Value::Null,
        "request_size": pending.size,
        "response_size": 0,
        "latency_ms": Value::Null,
        "incomplete": true,
    })
}

fn ms_to_rfc3339(epoch_ms: u64) -> Value {
    match chrono::DateTime::from_timestamp(
        (epoch_ms / 1_000) as i64,
        ((epoch_ms % 1_000) * 1_000_000) as u32,
    ) {
        Some(dt) => Value::String(dt.to_rfc3339()),
        None => Value::Null,
    }
}

/// The analyzed event's own fields are the message. Bookkeeping keys go, and so
/// does anything carrying unredacted wire bytes — `AuthHeaderRemover` scrubs the
/// parsed header map only, so a surviving `raw_data` would put the credentials
/// straight back into the record.
///
/// AgentSight 1.0.35's correlation and capture provenance go too
/// ([`CORRELATION_KEYS`]): they say how the message was matched, which the
/// pairing has already used, not what the agent sent. `transport_handle` is a
/// TLS object's address in the agent's memory, which AgentSight itself keeps
/// out of its stored call records.
fn message_body(data: &Value) -> Value {
    let mut out = data.clone();
    if let Some(obj) = out.as_object_mut() {
        for key in [
            "message_type",
            "tid",
            "timestamp_ns",
            "raw_data",
            "body_hex",
            "data_hex",
        ]
        .into_iter()
        .chain(CORRELATION_KEYS)
        {
            obj.remove(key);
        }
    }
    parse_json_body(&mut out);
    strip_nul(&mut out);
    out
}

/// What AgentSight 1.0.35's HTTP parser adds to every message besides the
/// message itself: its connection and exchange correlation, and the capture
/// provenance of the TLS records it was reassembled from.
const CORRELATION_KEYS: [&str; 29] = [
    "connection_id",
    "connection_generation",
    "stream_id",
    "http_exchange_id",
    "correlation_method",
    "correlation_status",
    "confidence",
    "correlation_version",
    "completion_reason",
    "end_stream",
    "transport_handle",
    "process_start_ns",
    "tls_library",
    "capture_seq_start",
    "capture_seq_end",
    "capture_fragment_count",
    "capture_original_len",
    "capture_captured_len",
    "capture_truncated",
    "capture_bytes_lost",
    "ringbuf_reserve_failures_start",
    "ringbuf_reserve_failures_end",
    "ringbuf_reserve_failures_delta",
    "capture_tids",
    "capture_tid_count",
    "capture_tids_truncated",
    "capture_identity_consistent",
    "capture_metadata_complete",
    "response_id",
];

/// A request is only usable to Rail Center if it carries both a method and a
/// path; the schema types them as required strings. Returning null for the
/// whole object is valid there and the router substitutes `UNKNOWN` and `/`.
fn usable_request(request: Value) -> Value {
    let has = |key: &str| {
        request
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty())
    };
    if has("method") && has("path") {
        request
    } else {
        log::debug!("dropping a request with no method/path (undecoded HTTP/2 headers)");
        Value::Null
    }
}

/// Rail Center types `body` as an object (`HttpRequestPayload.body: dict | None`),
/// but the HTTP parser hands it over as a string. Left as a string, every
/// interaction is rejected with a 422 — verified against rail-center's own
/// Pydantic model.
///
/// Anything that is not a JSON object is wrapped as `{"raw": "…"}` rather than
/// dropped. Dropping it looked reasonable and was not: an SSE response, a
/// form-encoded request, an HTML error page and a top-level JSON array are all
/// non-objects, so the body of most streaming traffic would vanish silently
/// while `response_size` went on reporting the bytes that were there. The
/// Python kept the raw string on a parse failure; this keeps it too, in the one
/// shape the schema can hold.
fn parse_json_body(message: &mut Value) {
    let Some(obj) = message.as_object_mut() else {
        return;
    };
    let Some(text) = obj.get("body").and_then(Value::as_str) else {
        return;
    };
    let wrapped = match serde_json::from_str::<Value>(text) {
        Ok(parsed @ Value::Object(_)) => parsed,
        _ => json!({ "raw": text }),
    };
    obj.insert("body".into(), wrapped);
}

/// Rail Center stores the interaction in a Postgres TEXT column, and Postgres
/// rejects a NUL byte outright. One binary body would otherwise fail the insert
/// and take the rest of its batch down with it. The Python replaced the whole
/// body; replacing just the NULs keeps more of it while staying insertable.
fn strip_nul(value: &mut Value) {
    match value {
        Value::String(s) => {
            if s.contains('\0') {
                *s = s.replace('\0', "\u{fffd}");
            }
        }
        Value::Array(items) => items.iter_mut().for_each(strip_nul),
        Value::Object(map) => map.values_mut().for_each(strip_nul),
        _ => {}
    }
}

/// The parsed message's size as the HTTP parser measured it (`total_size`).
///
/// Not identical to the Python's `event["len"]`, which was the length of the
/// SSL write: for a message split across reads the parser's figure covers what
/// it reassembled, so the two differ. Both fields feed `interaction_id`, so ids
/// are not comparable with the Python's for the same traffic — the formatter is
/// faithful, the inputs are not.
fn body_len(data: &Value) -> usize {
    for key in ["total_size", "len", "size"] {
        if let Some(v) = data.get(key).and_then(Value::as_u64) {
            return v as usize;
        }
    }
    data.get("body")
        .and_then(Value::as_str)
        .map(str::len)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_panicking_analyzer_ends_the_stream_and_drops_it_at_once() {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        let inner: EventStream = Box::pin(stream::iter(0..3).map(move |n| {
            let _keep = &flag;
            if n == 1 {
                panic!("malformed input");
            }
            Event::new_with_timestamp(n, "ssl".into(), 1, "x".into(), json!({}))
        }));
        let mut guarded = contain_analyzer_panics(inner);
        assert_eq!(guarded.next().await.map(|event| event.timestamp), Some(0));
        assert!(guarded.next().await.is_none(), "a panic ends the stream");
        // Dropped on the panic itself, while the wrapper is still alive: that
        // is what kills the probe and closes its status channel.
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(guarded.next().await.is_none());
    }

    /// A probe that emits one HTTP/2 HEADERS frame whose HPACK block is a
    /// dynamic-table-size update too large for the table (it panicked hpack
    /// 0.3.0, which unwrapped a `None`), then an ordinary request on another
    /// thread, then exits. Captured bytes like these are attacker-shaped.
    fn malformed_hpack_probe(dir: &Path) -> String {
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        let block = [0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        let len = block.len();
        bytes.extend_from_slice(&[0, 0, len as u8, 0x1, 0x4, 0, 0, 0, 1]);
        bytes.extend_from_slice(&block);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let malformed = json!({
            "source": "ssl", "pid": 4242, "comm": "node",
            "data": {"pid": 4242, "tid": 7, "timestamp_ns": 1, "function": "WRITE/SEND", "data": format!("HEX:{hex}")}
        });
        let request = json!({
            "source": "ssl", "pid": 4242, "comm": "node",
            "data": {"pid": 4242, "tid": 8, "timestamp_ns": 2, "function": "SSL_write",
                     "message_type": "request", "method": "POST", "path": "/ok",
                     "headers": {"host": "example.test"}, "body": "{}"}
        });
        let path = dir.join("agentsight");
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho '{malformed}'\necho '{request}'\nexec sleep 1\n"),
        )
        .expect("write probe");
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod probe");
        path.display().to_string()
    }

    /// DR-129 upstream: AgentSight 1.0.34 decodes HPACK with loona-hpack, which
    /// rejects the block instead of panicking. The tap reads on past it, so the
    /// next request is still captured; `contain_analyzer_panics` stays for any
    /// other analyzer panic.
    #[tokio::test]
    async fn malformed_hpack_from_the_wire_does_not_stop_the_tap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = malformed_hpack_probe(dir.path());
        let (stream, _status) = event_stream(&probe, &CaptureFilters::default())
            .await
            .expect("start fake probe");
        let events: Vec<Event> =
            tokio::time::timeout(std::time::Duration::from_secs(10), stream.collect())
                .await
                .expect("the stream ends when the probe exits");
        assert!(
            events
                .iter()
                .any(|event| event.data.get("path").and_then(Value::as_str) == Some("/ok")),
            "the request after the malformed block was captured: {events:?}"
        );
    }

    /// The envelope agentsight actually emits, pinned by the Python's deleted
    /// `test_unwrap_agentsight_envelope`. This is the seam a port can get wrong
    /// while every other test still passes.
    fn envelope() -> Value {
        json!({
            "comm": "curl", "source": "ssl", "pid": 1, "timestamp": 123,
            "data": {
                "function": "WRITE/SEND",
                "data": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "pid": 1, "tid": 1, "timestamp_ns": 99, "is_handshake": false
            }
        })
    }

    #[test]
    fn the_agentsight_envelope_is_unwrapped() {
        let out = normalize_ssl_event(&envelope()).expect("unwrapped");
        assert_eq!(out["function"], "WRITE/SEND");
        assert_eq!(out["timestamp_ns"], 99);
        assert_eq!(out["tid"], 1);
        assert!(out["data"].as_str().unwrap().starts_with("GET /"));
    }

    #[test]
    fn a_bare_sslsniff_event_passes_through_flat() {
        let flat = json!({
            "function": "READ/RECV", "data": "HTTP/1.1 200 OK\r\n\r\n",
            "pid": 2, "tid": 2, "timestamp_ns": 1, "is_handshake": false
        });
        let out = normalize_ssl_event(&flat).expect("passthrough");
        assert_eq!(out["function"], "READ/RECV");
        assert_eq!(out["timestamp_ns"], 1);
    }

    #[test]
    fn a_line_becomes_an_event_the_analyzers_will_accept() {
        // The regression that mattered: source must be "ssl" and the payload
        // reachable at data["data"], or HTTPParser skips the event entirely and
        // the collector silently captures nothing.
        let line = serde_json::to_string(&envelope()).unwrap();
        let event = ssl_event_from_line(&line).expect("event");
        assert_eq!(event.source, "ssl");
        assert_eq!(event.pid, 1);
        assert_eq!(event.comm, "curl");
        assert!(event.data.get("data").and_then(Value::as_str).is_some());
        assert_eq!(event.data["tid"], 1);
    }

    #[test]
    fn hex_payloads_are_decoded_byte_for_byte() {
        let mut v = envelope();
        v["data"]["data"] = json!("HEX:474554202f20485454502f312e310d0a0d0a");
        let out = normalize_ssl_event(&v).unwrap();
        assert_eq!(out["data"], "GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn non_event_lines_are_dropped() {
        assert!(normalize_ssl_event(&json!({"level": "info", "msg": "started"})).is_none());
        assert!(ssl_event_from_line("not json").is_none());
        assert!(ssl_event_from_line("").is_none());
    }

    #[test]
    fn agentsight_filters_go_after_a_separator_as_short_flags() {
        let cmd = build_command(
            "/opt/agentsight",
            &CaptureFilters {
                binary_path: Some("/bin/node".into()),
                pid: Some(42),
                ..Default::default()
            },
        );
        assert_eq!(
            cmd,
            vec![
                "/opt/agentsight",
                "debug",
                "ssl",
                "--binary-path",
                "/bin/node",
                "--",
                "-p",
                "42"
            ]
        );
    }

    #[test]
    fn comm_is_suppressed_when_a_binary_path_is_given() {
        let cmd = build_command(
            "/opt/agentsight",
            &CaptureFilters {
                binary_path: Some("/bin/node".into()),
                comm: Some("node".into()),
                ..Default::default()
            },
        );
        assert!(!cmd.iter().any(|a| a == "-c" || a == "--comm"));
    }

    #[test]
    fn comm_is_passed_when_it_is_the_only_filter() {
        let cmd = build_command(
            "/opt/agentsight",
            &CaptureFilters {
                comm: Some("node".into()),
                ..Default::default()
            },
        );
        assert_eq!(
            cmd,
            vec!["/opt/agentsight", "debug", "ssl", "--", "-c", "node"]
        );
    }

    #[test]
    fn a_bare_sslsniff_binary_keeps_the_historical_flags() {
        let cmd = build_command(
            "/usr/local/bin/sslsniff",
            &CaptureFilters {
                pid: Some(42),
                ..Default::default()
            },
        );
        assert_eq!(cmd, vec!["/usr/local/bin/sslsniff", "--pid", "42"]);
        assert!(!cmd.iter().any(|a| a == "debug"));
    }

    fn req(tid: u64, ns: u64) -> Value {
        json!({"message_type": "request", "tid": tid, "timestamp_ns": ns, "total_size": 180,
               "method": "POST", "path": "/v1/messages", "headers": {"host": "api.anthropic.com"}})
    }
    fn resp(tid: u64, ns: u64, status: u16) -> Value {
        json!({"message_type": "response", "tid": tid, "timestamp_ns": ns, "status_code": status})
    }

    #[test]
    fn raw_wire_text_has_every_credential_header_redacted() {
        let text = "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\
                    Proxy-Authorization: Basic UFJPWFk=\r\n\
                    api-key: AZURE-SECRET\r\n\
                    Authorization: Bearer sk-ant-SECRET\r\n\
                    Host: api.anthropic.com\r\n\r\n";
        let out = redact_header_lines(text).expect("something was redacted");
        for secret in ["UFJPWFk=", "AZURE-SECRET", "sk-ant-SECRET"] {
            assert!(!out.contains(secret), "{secret} survived: {out}");
        }
        // Structure is kept, so the request is still readable.
        assert!(out.contains("CONNECT api.anthropic.com:443"));
        assert!(out.contains("Host: api.anthropic.com"));
        assert_eq!(out.matches("[REDACTED]").count(), 3);
    }

    #[test]
    fn a_colon_in_the_body_is_not_mistaken_for_a_header() {
        let text = "POST /x HTTP/1.1\r\nHost: h\r\n\r\ntoken: not-a-header\r\n";
        // Nothing in the headers is a credential, so no rewrite at all.
        assert!(redact_header_lines(text).is_none());
    }

    #[test]
    fn folded_and_coalesced_credential_headers_are_fully_scrubbed() {
        let text = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Authorization: Bearer\r\n",
            " FOLDED-SECRET\r\n",
            "Content-Length: 2\r\n\r\n",
            "{}HTTP/1.1 200 OK\r\n",
            "Set-Cookie: SECOND-SECRET\r\n",
            "Content-Length: 2\r\n\r\n",
            "hello worldPOST /three HTTP/1.1\r\n",
            "Cookie: THIRD-SECRET\r\n\r\n",
        );
        let out = redact_header_lines(text).expect("credentials are present");
        assert!(
            !out.contains("FOLDED-SECRET"),
            "folded value survived: {out}"
        );
        assert!(
            !out.contains("SECOND-SECRET"),
            "second message survived: {out}"
        );
        assert!(
            !out.contains("THIRD-SECRET"),
            "third message survived: {out}"
        );
        assert_eq!(out.matches("[REDACTED]").count(), 4);
    }

    #[test]
    fn nul_bytes_never_reach_the_sink() {
        // Rail Center stores `raw` in a Postgres TEXT column, which rejects
        // NUL outright — one binary body would fail the insert and take its
        // whole batch with it.
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        // A *parseable* object carrying a NUL, so parse_json_body keeps it and
        // strip_nul is genuinely exercised. The earlier version used a
        // non-JSON body, which parse_json_body removed outright — the
        // assertion held vacuously and tested nothing.
        let mut r = resp(7, 1_100_000_000, 200);
        r["body"] = json!("{\"note\":\"ok\u{0}binary\"}");
        let out = p.accept(1, &r, 1100).unwrap();
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("\\u0000"), "NUL survived: {text}");
        assert!(
            text.contains("\u{fffd}"),
            "body was dropped instead of sanitised: {text}"
        );
    }

    #[tokio::test]
    async fn provider_specific_credential_headers_are_scrubbed_in_the_chain() {
        // In the chain, not in message_body: --mode raw serialises the analyzer
        // event straight to the sink and never touches the pairing code, so a
        // scrub that lives only there has a documented way around it.
        use futures::StreamExt as _;
        let event = Event::new_with_timestamp(
            0,
            "http_parser".into(),
            1,
            "curl".into(),
            json!({"message_type": "request", "headers": {
                "api-key": "AZURE-SECRET",
                "X-Goog-Api-Key": "GEMINI-SECRET",
                "Proxy-Authorization": "Basic PROXY-SECRET",
                "host": "api.anthropic.com"
            }}),
        );
        let stream: EventStream = Box::pin(stream::iter(vec![event]));
        let out = ExtraCredentialRedactor
            .process(stream)
            .await
            .expect("analyzer")
            .collect::<Vec<_>>()
            .await;

        let text = serde_json::to_string(&out[0].data).unwrap();
        for secret in ["AZURE-SECRET", "GEMINI-SECRET", "PROXY-SECRET"] {
            assert!(!text.contains(secret), "{secret} survived: {text}");
        }
        assert_eq!(out[0].data["headers"]["host"], "api.anthropic.com");
    }

    /// A probe that prints `records` and exits, for replaying a capture.
    fn replay_probe(dir: &Path, records: &[Value]) -> String {
        let lines: Vec<String> = records.iter().map(Value::to_string).collect();
        let capture = dir.join("capture.jsonl");
        std::fs::write(&capture, lines.join("\n") + "\n").expect("write capture");
        let path = dir.join("agentsight");
        std::fs::write(
            &path,
            format!("#!/bin/sh\nexec cat '{}'\n", capture.display()),
        )
        .expect("write probe");
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod probe");
        path.display().to_string()
    }

    fn two_connections_capture() -> Vec<Value> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/agentsight-v1.0.35/ssl.two-connections.jsonl");
        std::fs::read_to_string(path)
            .expect("fixture")
            .lines()
            .map(|line| serde_json::from_str(line).expect("a JSON record"))
            .collect()
    }

    /// Every interaction the chain and the pairer make of `records`, and the
    /// pairer after the stream ended.
    async fn pair_replayed(records: &[Value]) -> (Vec<Value>, Pairer) {
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = replay_probe(dir.path(), records);
        let (stream, _status) = event_stream(&probe, &CaptureFilters::default())
            .await
            .expect("start replay");
        let events: Vec<Event> =
            tokio::time::timeout(std::time::Duration::from_secs(10), stream.collect())
                .await
                .expect("the stream ends with the capture");
        let mut pairer = Pairer::new();
        let paired = events
            .iter()
            .filter_map(|event| pairer.accept(event.pid, &event.data, event.timestamp))
            .collect();
        (paired, pairer)
    }

    /// The path a demo reply names in its own events, `{"path": "/fast", …}`.
    fn answered_path(interaction: &Value) -> Option<String> {
        let raw = interaction["response"]["body"]["raw"].as_str()?;
        let start = raw.find("\"path\": \"")? + 9;
        Some(raw[start..].split('"').next()?.to_string())
    }

    /// railmon#70's second case, on a real AgentSight v1.0.35 capture: two
    /// TLS connections on one Node thread whose streamed replies interleave,
    /// the later request's ending first. Paired per thread, `/slow` took
    /// `/fast`'s reply.
    #[tokio::test]
    async fn two_connections_on_one_thread_each_pair_with_their_own_reply() {
        let (paired, pairer) = pair_replayed(&two_connections_capture()).await;
        let pairs: Vec<(Option<String>, Option<String>)> = paired
            .iter()
            .map(|i| {
                (
                    i["request"]["path"].as_str().map(str::to_string),
                    answered_path(i),
                )
            })
            .collect();
        let want = |p: &str| (Some(p.to_string()), Some(p.to_string()));
        assert_eq!(pairs, vec![want("/fast"), want("/slow")], "{paired:#?}");
        assert!(paired.iter().all(|i| i.get("incomplete").is_none()));
        assert_eq!(pairer.outstanding(), 0);
        assert_eq!(pairer.unmatched_responses(), 0);
        // The timestamps were made epoch milliseconds before the parser saw
        // them: a 2026 date, and a latency of a stream, not of nanoseconds.
        assert!(paired[0]["timestamp"]
            .as_str()
            .unwrap()
            .starts_with("2026-"));
        let latency = paired[1]["latency_ms"].as_f64().unwrap();
        assert!((1_000.0..10_000.0).contains(&latency), "{latency}");
        // How the parser matched them stays out of the message.
        for message in [&paired[0]["request"], &paired[0]["response"]] {
            for key in CORRELATION_KEYS {
                assert!(message.get(key).is_none(), "{key} in {message}");
            }
        }
    }

    /// The same records without the fields that name their connection, as a
    /// rustls agent or an older probe sends them, take the per-thread path,
    /// and that path can't tell the two connections apart: `/fast`'s reply
    /// opens while `/slow`'s is in flight on the same thread, so it answers
    /// the older request, and `/fast` is forwarded incomplete. Every request
    /// is still accounted for. This is the limit connection identity removes;
    /// for a capture without it the limit stays.
    #[tokio::test]
    async fn without_connection_identity_the_same_capture_pairs_by_thread() {
        let records: Vec<Value> = two_connections_capture()
            .into_iter()
            .map(|mut record| {
                let data = record["data"].as_object_mut().unwrap();
                for key in ["transport_handle", "process_start_ns", "tls_library"] {
                    data.remove(key);
                }
                record
            })
            .collect();
        let (paired, pairer) = pair_replayed(&records).await;
        let pairs: Vec<(Option<&str>, Option<String>, bool)> = paired
            .iter()
            .map(|i| {
                (
                    i["request"]["path"].as_str(),
                    answered_path(i),
                    i.get("incomplete").is_some(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                (Some("/slow"), Some("/fast".to_string()), false),
                (Some("/fast"), None, true),
            ],
            "{paired:#?}"
        );
        assert_eq!(pairer.outstanding(), 0);
    }

    fn exchange(message: &str, id: &str) -> Value {
        json!({"message_type": message, "tid": 7, "http_exchange_id": id,
               "method": "POST", "path": format!("/{id}"), "status_code": 200})
    }

    #[test]
    fn replies_pair_by_exchange_id_in_any_order() {
        let mut p = Pairer::new();
        assert!(p.accept(1, &exchange("request", "a"), 1000).is_none());
        assert!(p.accept(1, &exchange("request", "b"), 1100).is_none());
        let b = p
            .accept(1, &exchange("response", "b"), 1200)
            .expect("b paired");
        assert_eq!(b["request"]["path"], "/b");
        assert_eq!(b["latency_ms"], 100.0);
        let a = p
            .accept(1, &exchange("response", "a"), 1300)
            .expect("a paired");
        assert_eq!(a["request"]["path"], "/a");
        assert_eq!(p.outstanding(), 0);
    }

    #[test]
    fn an_exchange_opened_twice_forwards_the_earlier_request() {
        let mut p = Pairer::new();
        assert!(p.accept(1, &exchange("request", "a"), 1000).is_none());
        let mut again = exchange("request", "a");
        again["path"] = json!("/again");
        let older = p
            .accept(1, &again, 1100)
            .expect("the earlier one is forwarded");
        assert_eq!(older["incomplete"], true);
        assert_eq!(older["request"]["path"], "/a");
        let paired = p.accept(1, &exchange("response", "a"), 1200).unwrap();
        assert_eq!(paired["request"]["path"], "/again");
    }

    #[test]
    fn a_reply_to_an_unknown_exchange_takes_no_other_request() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 0), 1000);
        p.accept(1, &exchange("request", "a"), 1000);
        assert!(p
            .accept(1, &exchange("response", "elsewhere"), 1100)
            .is_none());
        assert_eq!(p.unmatched_responses(), 1);
        assert_eq!(p.outstanding(), 2);
    }

    #[test]
    fn an_exchange_agentsight_ends_without_a_reply_is_forwarded_at_once() {
        let mut p = Pairer::new();
        p.accept(1, &exchange("request", "a"), 1000);
        p.accept(1, &exchange("request", "b"), 1000);
        let ended = json!({"http_exchange_id": "a", "correlation_status": "unlinked",
                           "completion_reason": "closed"});
        let out = p.accept(1, &ended, 1500).expect("forwarded");
        assert_eq!(out["incomplete"], true);
        assert_eq!(out["request"]["path"], "/a");
        // Once only: the stream's end doesn't forward it a second time.
        assert!(p.accept(1, &ended, 1600).is_none());
        let flushed = p.flush_incomplete();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0]["request"]["path"], "/b");
    }

    #[test]
    fn a_websocket_message_is_forwarded_and_takes_no_reply() {
        let mut p = Pairer::new();
        let mut frame = req(7, 0);
        frame["protocol"] = json!("WebSocket");
        frame["path"] = json!("/gateway");
        let out = p.accept(1, &frame, 1000).expect("forwarded at once");
        assert_eq!(out["incomplete"], true);
        assert_eq!(out["request"]["path"], "/gateway");
        p.accept(1, &req(7, 0), 1100);
        let paired = p.accept(1, &resp(7, 0, 200), 1200).expect("paired");
        assert_eq!(paired["request"]["path"], "/v1/messages");
    }

    #[test]
    fn expiry_covers_exchanges_too() {
        let mut p = Pairer::new();
        p.accept(1, &exchange("request", "a"), 2000);
        p.accept(1, &req(7, 0), 1000);
        let later = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let expired = p.expire(later, std::time::Duration::from_secs(1));
        let paths: Vec<_> = expired
            .iter()
            .map(|i| i["request"]["path"].clone())
            .collect();
        assert_eq!(
            paths,
            vec![json!("/v1/messages"), json!("/a")],
            "oldest first"
        );
        assert_eq!(p.outstanding(), 0);
    }

    #[test]
    fn a_response_pairs_with_the_request_on_its_thread() {
        let mut p = Pairer::new();
        assert!(p.accept(1, &req(7, 1_000_000_000), 1000).is_none());
        let out = p
            .accept(1, &resp(7, 1_500_000_000, 200), 1500)
            .expect("paired");
        assert_eq!(out["response"]["status_code"], 200);
        assert_eq!(out["latency_ms"], 500.0);
        assert_eq!(p.outstanding(), 0);
    }

    #[test]
    fn the_timestamp_is_the_events_epoch_clock() {
        // The previous version of this test asserted a 1970 date and passed,
        // which is how a broken clock shipped: the probe's timestamps are
        // nanoseconds since *boot*, and the assertion enshrined the unconverted
        // value as correct. Pairer now works in epoch milliseconds, which is
        // what TimestampNormalizer produces.
        let mut p = Pairer::new();
        let t0 = 1_786_600_000_000u64; // 2026-08-13, epoch ms
        p.accept(1, &req(7, 0), t0);
        let out = p.accept(1, &resp(7, 0, 200), t0 + 500).unwrap();
        assert_eq!(out["timestamp"], "2026-08-13T05:46:40+00:00");
        assert_eq!(out["latency_ms"], 500.0);
    }

    #[test]
    fn request_size_is_the_bytes_on_the_wire() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        let out = p.accept(1, &resp(7, 1_100_000_000, 200), 1100).unwrap();
        assert_eq!(out["request_size"], 180);
    }

    #[test]
    fn concurrent_threads_do_not_steal_each_others_responses() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        p.accept(1, &req(9, 1_100_000_000), 1100);
        let a = p
            .accept(1, &resp(9, 1_200_000_000, 500), 1200)
            .expect("tid 9");
        assert_eq!(a["tid"], 9);
        let b = p
            .accept(1, &resp(7, 1_900_000_000, 200), 1900)
            .expect("tid 7");
        assert_eq!(b["tid"], 7);
    }

    #[test]
    fn requests_in_flight_on_one_thread_are_answered_oldest_first() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        p.accept(1, &req(7, 2_000_000_000), 2000);
        let first = p.accept(1, &resp(7, 3_000_000_000, 200), 3000).unwrap();
        assert_eq!(first["timestamp_ns"], 1_000_000_000u64);
        assert_eq!(p.outstanding(), 1);
    }

    #[test]
    fn flush_incomplete_drains_pending_requests_with_no_response() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        p.accept(1, &req(7, 2_000_000_000), 2000);
        assert_eq!(p.outstanding(), 2);
        let flushed = p.flush_incomplete();
        assert_eq!(flushed.len(), 2);
        for event in &flushed {
            assert_eq!(event["incomplete"], true);
            assert_eq!(event["response"], Value::Null);
            assert_eq!(event["pid"], 1);
        }
        // Draining leaves nothing behind, and nothing left to answer later.
        assert_eq!(p.outstanding(), 0);
        assert!(p.flush_incomplete().is_empty());
    }

    #[test]
    fn flush_incomplete_leaves_an_already_paired_response_alone() {
        // A completed pair was already returned by `accept` and removed from
        // `pending` — flushing must not manufacture a second, incomplete copy
        // of traffic that already has a real response.
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        let paired = p.accept(1, &resp(7, 1_100_000_000, 200), 1100);
        assert!(paired.is_some());
        assert!(p.flush_incomplete().is_empty());
    }

    #[test]
    fn a_response_with_no_request_is_dropped_not_paired_to_a_stranger() {
        let mut p = Pairer::new();
        assert!(p.accept(1, &resp(7, 1_000_000_000, 200), 1000).is_none());
        // Dropped, but counted, so the collector can say so (DR-186).
        assert_eq!(p.unmatched_responses(), 1);
    }

    #[test]
    fn a_request_past_the_timeout_comes_out_incomplete_and_a_newer_one_waits() {
        // railmon#70: a streamed reply lost to another connection on the same
        // thread used to leave its request pending for the life of the tap.
        use std::time::{Duration, Instant};
        let mut p = Pairer::new();
        p.accept(1, &req(7, 0), 1_000);
        p.accept(2, &req(3, 0), 2_000);
        std::thread::sleep(Duration::from_millis(30));
        let cut = Instant::now();
        p.accept(1, &req(7, 0), 50_000);
        let timeout = Duration::from_millis(10);

        assert!(
            p.expire(cut, Duration::from_secs(60)).is_empty(),
            "nothing is old enough yet"
        );

        let expired = p.expire(cut, timeout);
        assert_eq!(expired.len(), 2);
        assert_eq!(expired[0]["pid"], 1, "oldest first");
        assert_eq!(expired[1]["pid"], 2);
        for event in &expired {
            assert_eq!(event["incomplete"], true);
            assert_eq!(event["response"], Value::Null);
            assert_eq!(event["request"]["method"], "POST");
        }
        assert_eq!(p.outstanding(), 1);

        // The newer request still pairs with the next response on its thread.
        let out = p.accept(1, &resp(7, 0, 200), 126_000).expect("paired");
        assert_eq!(out["timestamp_ns"], 50_000_000_000u64);
        assert_eq!(p.outstanding(), 0);
        assert!(p
            .expire(Instant::now() + Duration::from_secs(3600), timeout)
            .is_empty());
    }

    #[test]
    fn a_request_is_aged_on_our_clock_not_the_probes() {
        // An event clock far behind the wall clock (a host that suspended
        // since boot) must not make a fresh request look stale.
        use std::time::{Duration, Instant};
        let mut p = Pairer::new();
        p.accept(1, &req(7, 0), 1);
        assert!(p
            .expire(Instant::now(), Duration::from_secs(600))
            .is_empty());
    }

    #[test]
    fn the_wire_bytes_never_survive_into_the_interaction() {
        let mut p = Pairer::new();
        let mut r = req(7, 1_000_000_000);
        r["raw_data"] =
            json!("POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer sk-SECRET\r\n\r\n");
        r["body_hex"] = json!("deadbeef");
        p.accept(1, &r, 1000);
        let out = p.accept(1, &resp(7, 1_100_000_000, 200), 1100).unwrap();
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("sk-SECRET"), "credential survived: {text}");
        assert!(!text.contains("deadbeef"));
    }

    /// datrail/railmon#93: a streamed `content-encoding: gzip` reply, chunked
    /// the way Node frames it and read a few bytes at a time, comes out of the
    /// whole pipeline as the SSE text the agent's SDK reads, tool call and all.
    #[tokio::test]
    async fn a_gzip_chunked_sse_reply_is_paired_decoded() {
        use std::io::Write as _;
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",",
            "\"type\":\"function\",\"function\":{\"name\":\"delivery__delivery_track_package\",",
            "\"arguments\":\"{}\"}}]},\"index\":0}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(sse.as_bytes()).unwrap();
        let gz = gz.finish().unwrap();
        let mut reply = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
            Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
            .to_vec();
        for (i, piece) in gz.chunks(1).take(3).chain(gz[3..].chunks(37)).enumerate() {
            let size = if i < 3 {
                format!("{:08x}", piece.len())
            } else {
                format!("{:x}", piece.len())
            };
            reply.extend_from_slice(format!("{size}\r\n").as_bytes());
            reply.extend_from_slice(piece);
            reply.extend_from_slice(b"\r\n");
        }
        reply.extend_from_slice(b"0\r\n\r\n");

        let line = |ts: u64, function: &str, bytes: &[u8]| {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            json!({"source": "ssl", "pid": 4242, "comm": "node", "data": {
                "pid": 4242, "tid": 7, "timestamp_ns": ts, "function": function,
                "data": format!("HEX:{hex}")}})
            .to_string()
        };
        let mut lines = vec![line(
            1,
            "WRITE/SEND",
            b"POST /v1beta/openai/chat/completions HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\
              Content-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"stream\":true}",
        )];
        // The header block in one read, as a TLS record carries it; the body
        // five bytes at a time, cutting across chunk framing.
        let head_end = reply.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        lines.push(line(1_000, "READ/RECV", &reply[..head_end]));
        for (i, piece) in reply[head_end..].chunks(5).enumerate() {
            lines.push(line(1_001 + i as u64, "READ/RECV", piece));
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let capture = dir.path().join("capture.jsonl");
        std::fs::write(&capture, lines.join("\n") + "\n").expect("write capture");
        let probe = dir.path().join("agentsight");
        std::fs::write(&probe, format!("#!/bin/sh\ncat '{}'\n", capture.display()))
            .expect("write probe");
        std::fs::set_permissions(&probe, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod probe");

        let (stream, _status) =
            event_stream(&probe.display().to_string(), &CaptureFilters::default())
                .await
                .expect("start fake probe");
        let events: Vec<Event> =
            tokio::time::timeout(std::time::Duration::from_secs(10), stream.collect())
                .await
                .expect("the stream ends when the probe exits");
        let mut pairer = Pairer::new();
        let paired: Vec<Value> = events
            .iter()
            .filter_map(|e| pairer.accept(e.pid, &e.data, e.timestamp))
            .collect();
        assert_eq!(paired.len(), 1, "{events:?}");
        let response = &paired[0]["response"];
        assert_eq!(response["body"], json!({ "raw": sse }));
        let raw = response["body"]["raw"].as_str().unwrap();
        assert!(raw.contains("\"tool_calls\"") && raw.contains("delivery__delivery_track_package"));
        let headers = response["headers"].as_object().unwrap();
        assert!(!headers.contains_key("content-encoding"), "{headers:?}");
        assert!(!headers.contains_key("transfer-encoding"), "{headers:?}");
        assert_eq!(headers["content-length"], json!(sse.len().to_string()));
        assert_eq!(headers["content-type"], json!("text/event-stream"));
    }
}

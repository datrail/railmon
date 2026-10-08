//! The capture pipeline.
//!
//! Everything hard about reading agent traffic — reconstructing HTTP from raw
//! SSL reads and writes, SSE streams, gzip, chunked transfer-encoding,
//! truncation, stripping `Authorization` — is AgentSight's, consumed as a
//! library. What stays here is the part that is RailMon's own: spawning the
//! probe, unwrapping what it emits, pairing a request with its response, and
//! attributing the result.

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
    if !hexed.len().is_multiple_of(2) {
        return None;
    }
    let mut out = String::with_capacity(hexed.len() / 2);
    for pair in hexed.as_bytes().chunks(2) {
        let byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        out.push(byte as char);
    }
    Some(out)
}

/// The probe's exit status, resolved once its output ends.
pub type ProbeStatus = tokio::sync::oneshot::Receiver<Option<std::process::ExitStatus>>;

/// Header names carrying a credential that AgentSight's own allowlist does not
/// cover: Azure OpenAI, Gemini, and forward proxies.
const EXTRA_CREDENTIAL_HEADERS: [&str; 3] = ["api-key", "x-goog-api-key", "proxy-authorization"];

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
        use futures::StreamExt as _;
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
                    Ok(None) => {
                        if let Some(tx) = status_tx.take() {
                            let _ = tx.send(child.wait().await.ok());
                        }
                        return None;
                    }
                    Err(error) => {
                        log::warn!("reading probe output: {error}");
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
        Box::new(HTTPParser::new().disable_raw_data()),
        Box::new(HTTPDecompressor::new()),
        // No SSEProcessor, deliberately. It is a filter_map: for a streaming
        // response it swallows the parser's response event and emits its own,
        // carrying no `message_type` — so the request never pairs, sits in
        // `pending` for ever, and nothing is written. Since agent traffic to
        // Anthropic and OpenAI is overwhelmingly `stream: true`, including it
        // means capturing almost nothing. The Python chain did not use it
        // either; it treated an SSE response as a response.
        //
        // This does cost something, and it is a regression rather than
        // something inherited: the Python kept its own `active_streams` map
        // keyed on (pid, tid), appended every later READ/RECV to the body and
        // finalised on the next request or at shutdown. Without that, an
        // HTTP/1.1 streamed response is recorded from its first SSL read only —
        // measured at 81 of 532 bytes on an Anthropic-shaped stream, losing the
        // model's reply text — and `latency_ms` is time-to-first-byte rather
        // than stream duration. Destination, status and the request are intact,
        // and HTTP/2 is unaffected because the crate reassembles DATA frames
        // per stream. Re-accumulating HTTP/1.1 bodies is its own ticket.
        //
        // TimestampNormalizer is required, not optional: sslsniff timestamps
        // are `bpf_ktime_get_ns()`, nanoseconds since *boot*, and this is the
        // only thing converting them to epoch milliseconds. Without it every
        // interaction is dated 1970 and `interaction_id` hashes that.
        Box::new(TimestampNormalizer::new()),
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
/// AgentSight is tracked, not pinned, and one panic would otherwise abort every
/// keyed target.
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
/// A FIFO per `(pid, tid)`, matching the Python: an agent can have several
/// requests in flight on one thread, and responses come back in order, so the
/// oldest outstanding request owns the next response. Keying on the pair rather
/// than the pid alone is what keeps two concurrent threads from stealing each
/// other's responses.
#[derive(Default)]
pub struct Pairer {
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

        match data.get("message_type").and_then(Value::as_str) {
            Some("request") => {
                self.pending
                    .entry(key)
                    .or_default()
                    .push_back(PendingRequest {
                        epoch_ms,
                        queued: std::time::Instant::now(),
                        tid,
                        request: message_body(data),
                        size: body_len(data),
                    });
                None
            }
            Some("response") => {
                let Some(pending) = self.pending.get_mut(&key).and_then(VecDeque::pop_front) else {
                    self.unmatched_responses += 1;
                    log::debug!(
                        "pid {pid} tid {tid}: a response with no request outstanding on its thread"
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
            _ => None,
        }
    }

    /// Requests still outstanding — a response never arrived, or the capture
    /// stopped mid-flight. Reported rather than dropped silently.
    pub fn outstanding(&self) -> usize {
        self.pending.values().map(VecDeque::len).sum()
    }

    /// Drains every still-pending request into a synthetic, response-less
    /// interaction marked `"incomplete": true`, for a tap that is stopping
    /// (target exit, PID reuse, or shutdown). A request whose response never
    /// arrived is otherwise indistinguishable from one that just never
    /// happened; this is what design doc §4.4 means by "pending requests are
    /// flushed as incomplete" rather than silently dropped.
    pub fn flush_incomplete(&mut self) -> Vec<Value> {
        self.pending
            .drain()
            .flat_map(|((pid, _tid), queue)| {
                queue
                    .into_iter()
                    .map(move |pending| incomplete(pid, pending))
            })
            .collect()
    }

    /// Takes out every request that has waited longer than `max_age` for
    /// its response, as incomplete interactions (DR-186), oldest first.
    ///
    /// Without this a lost response holds its request for the life of the
    /// tap, and nothing is ever forwarded or logged for it. It is lost more
    /// often than it sounds: AgentSight's SSL events carry a pid and tid but
    /// no connection, and its HTTP/1 parser keeps one buffer per thread and
    /// direction. A Node agent does all its TLS on one thread, so a second
    /// connection read during a streamed reply resets or corrupts that
    /// buffer and the reply never completes (datrail/railmon#70).
    ///
    /// A response that does arrive after its request expired finds the next
    /// request on that thread or none at all; the bound has to sit well past
    /// any real stream so that stays rare.
    pub fn expire(&mut self, now: std::time::Instant, max_age: std::time::Duration) -> Vec<Value> {
        let mut expired = Vec::new();
        for (&(pid, _tid), queue) in self.pending.iter_mut() {
            // FIFO per thread, so the stale ones are at the front.
            while queue
                .front()
                .is_some_and(|pending| now.saturating_duration_since(pending.queued) > max_age)
            {
                let pending = queue.pop_front().expect("front was checked");
                expired.push(incomplete(pid, pending));
            }
        }
        self.pending.retain(|_, queue| !queue.is_empty());
        expired.sort_by_key(|value| value["timestamp_ns"].as_u64().unwrap_or(0));
        expired
    }

    /// Responses so far that found no request to pair with.
    pub fn unmatched_responses(&self) -> u64 {
        self.unmatched_responses
    }
}

fn incomplete(pid: u32, pending: PendingRequest) -> Value {
    json!({
        "timestamp": ms_to_rfc3339(pending.epoch_ms),
        "timestamp_ns": pending.epoch_ms.saturating_mul(1_000_000),
        "pid": pid,
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
        ] {
            obj.remove(key);
        }
    }
    parse_json_body(&mut out);
    strip_nul(&mut out);
    out
}

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
}

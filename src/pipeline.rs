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
use futures::stream;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
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
        // Known limitation, inherited from that choice: a body split across
        // several SSL reads is recorded from the first fragment only. The
        // interaction's metadata — destination, status, latency — is complete;
        // the body may be truncated. Accumulating it is worth its own change.
        //
        // TimestampNormalizer is required, not optional: sslsniff timestamps
        // are `bpf_ktime_get_ns()`, nanoseconds since *boot*, and this is the
        // only thing converting them to epoch milliseconds. Without it every
        // interaction is dated 1970 and `interaction_id` hashes that.
        Box::new(TimestampNormalizer::new()),
        Box::new(AuthHeaderRemover::new()),
    ];

    let mut stream: EventStream = Box::pin(raw);
    for analyzer in analyzers.iter_mut() {
        stream = analyzer
            .process(stream)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok((stream, status_rx))
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
}

struct PendingRequest {
    epoch_ms: u64,
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
                        tid,
                        request: message_body(data),
                        size: body_len(data),
                    });
                None
            }
            Some("response") => {
                let pending = self.pending.get_mut(&key)?.pop_front()?;
                let latency_ms = epoch_ms.checked_sub(pending.epoch_ms).map(|d| d as f64);

                Some(json!({
                    "timestamp": ms_to_rfc3339(pending.epoch_ms),
                    "timestamp_ns": pending.epoch_ms.saturating_mul(1_000_000),
                    "pid": pid,
                    "tid": pending.tid,
                    "request": pending.request,
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
        // The upstream allowlist misses the header names Azure OpenAI, Gemini
        // and forward proxies use, so scrub them here too rather than trusting
        // one list. Belt and braces on the one thing that must not leak.
        if let Some(headers) = obj.get_mut("headers").and_then(Value::as_object_mut) {
            let extra = ["api-key", "x-goog-api-key", "proxy-authorization"];
            for (key, value) in headers.iter_mut() {
                if extra.iter().any(|e| key.eq_ignore_ascii_case(e)) {
                    *value = Value::String("[REDACTED]".into());
                }
            }
        }
    }
    strip_nul(&mut out);
    out
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
    fn nul_bytes_never_reach_the_sink() {
        // Rail Center stores `raw` in a Postgres TEXT column, which rejects
        // NUL outright — one binary body would fail the insert and take its
        // whole batch with it.
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        let mut r = resp(7, 1_100_000_000, 200);
        r["body"] = json!("ok\u{0}binary");
        let out = p.accept(1, &r, 1100).unwrap();
        assert!(!serde_json::to_string(&out).unwrap().contains("\\u0000"));
    }

    #[test]
    fn provider_specific_credential_headers_are_scrubbed_too() {
        // The upstream allowlist covers Authorization and x-api-key but not
        // these, and they are what Azure OpenAI, Gemini and proxies send.
        let mut p = Pairer::new();
        let mut r = req(7, 1_000_000_000);
        r["headers"] = json!({
            "api-key": "AZURE-SECRET",
            "x-goog-api-key": "GEMINI-SECRET",
            "proxy-authorization": "Basic PROXY-SECRET",
            "host": "api.anthropic.com"
        });
        p.accept(1, &r, 1000);
        let out = p.accept(1, &resp(7, 1_100_000_000, 200), 1100).unwrap();
        let text = serde_json::to_string(&out).unwrap();
        for secret in ["AZURE-SECRET", "GEMINI-SECRET", "PROXY-SECRET"] {
            assert!(!text.contains(secret), "{secret} survived: {text}");
        }
        assert_eq!(out["request"]["headers"]["host"], "api.anthropic.com");
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
    fn a_response_with_no_request_is_dropped_not_paired_to_a_stranger() {
        let mut p = Pairer::new();
        assert!(p.accept(1, &resp(7, 1_000_000_000, 200), 1000).is_none());
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

//! The capture pipeline.
//!
//! Everything hard about reading agent traffic — reconstructing HTTP from raw
//! SSL reads and writes, SSE streams, gzip, chunked transfer-encoding,
//! truncation, stripping `Authorization` — is AgentSight's, consumed as a
//! library. What stays here is the part that is RailMon's own: pairing a
//! request with its response into one interaction, and attributing it.

use agentsight_capture::analyzers::{
    AuthHeaderRemover, HTTPDecompressor, HTTPParser, SSEProcessor, SSLFilter, TimestampNormalizer,
};
use agentsight_capture::runners::{BinaryRunner, EventStream, Runner};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};

/// Filters handed to the agentsight binary itself, so unwanted traffic is
/// dropped at the source rather than carried through the chain.
#[derive(Debug, Default, Clone)]
pub struct CaptureFilters {
    pub binary_path: Option<String>,
    pub pid: Option<i32>,
    pub uid: Option<i32>,
    pub comm: Option<String>,
}

impl CaptureFilters {
    fn to_args(&self) -> Vec<String> {
        let mut args = vec!["debug".into(), "ssl".into()];
        if let Some(p) = &self.binary_path {
            args.push("--binary-path".into());
            args.push(p.clone());
        }
        if let Some(p) = self.pid {
            args.push("--pid".into());
            args.push(p.to_string());
        }
        if let Some(u) = self.uid {
            args.push("--uid".into());
            args.push(u.to_string());
        }
        if let Some(c) = &self.comm {
            args.push("--comm".into());
            args.push(c.clone());
        }
        args
    }
}

/// Spawn agentsight and return a stream of analyzed events.
///
/// The analyzer order matters and mirrors AgentSight's own: filter to SSL
/// traffic, parse HTTP, decompress, reassemble SSE, then strip credentials.
/// Redaction is deliberately last, so it sees fully reassembled headers rather
/// than a fragment that happens not to contain the token yet.
pub async fn event_stream(agentsight_path: &str, filters: &CaptureFilters) -> Result<EventStream> {
    // `ssl` is the purpose-built constructor: it names the runner, tags events
    // with source "ssl" and reads `timestamp_ns` as the event clock.
    let mut runner = BinaryRunner::ssl(agentsight_path)
        .with_args(filters.to_args())
        // No patterns: filtering by pid/uid/comm/binary happens in agentsight
        // itself, so this stage only enforces that the event is SSL-shaped.
        .add_analyzer(Box::new(SSLFilter::with_patterns(Vec::new())))
        .add_analyzer(Box::new(HTTPParser::new()))
        .add_analyzer(Box::new(HTTPDecompressor::new()))
        .add_analyzer(Box::new(SSEProcessor::default()))
        .add_analyzer(Box::new(TimestampNormalizer::new()))
        .add_analyzer(Box::new(AuthHeaderRemover::new()));

    runner
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to start agentsight at {agentsight_path}"))
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
    timestamp_ns: u64,
    timestamp: Option<String>,
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
    pub fn accept(&mut self, pid: u32, data: &Value, timestamp_ms: u64) -> Option<Value> {
        let tid = data.get("tid").and_then(Value::as_u64).unwrap_or(0);
        let key = (pid, tid);
        let timestamp_ns = data
            .get("timestamp_ns")
            .and_then(Value::as_u64)
            .unwrap_or(timestamp_ms.saturating_mul(1_000_000));

        match data.get("message_type").and_then(Value::as_str) {
            Some("request") => {
                self.pending
                    .entry(key)
                    .or_default()
                    .push_back(PendingRequest {
                        timestamp_ns,
                        timestamp: data
                            .get("timestamp")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        tid,
                        request: message_body(data),
                        size: body_len(data),
                    });
                None
            }
            Some("response") => {
                let pending = self.pending.get_mut(&key)?.pop_front()?;
                let latency_ms = timestamp_ns
                    .checked_sub(pending.timestamp_ns)
                    .map(|d| d as f64 / 1e6);

                Some(json!({
                    "timestamp": pending.timestamp,
                    "timestamp_ns": pending.timestamp_ns,
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

/// The analyzed event's own fields are the message; drop the bookkeeping keys
/// the pipeline added so the interaction reads like the Python's.
fn message_body(data: &Value) -> Value {
    let mut out = data.clone();
    if let Some(obj) = out.as_object_mut() {
        for key in ["message_type", "tid", "timestamp_ns"] {
            obj.remove(key);
        }
    }
    out
}

fn body_len(data: &Value) -> usize {
    data.get("body")
        .and_then(Value::as_str)
        .map(str::len)
        .or_else(|| {
            data.get("body_size")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tid: u64, ns: u64) -> Value {
        json!({"message_type": "request", "tid": tid, "timestamp_ns": ns,
               "method": "POST", "path": "/v1/messages", "headers": {"host": "api.anthropic.com"}})
    }
    fn resp(tid: u64, ns: u64, status: u16) -> Value {
        json!({"message_type": "response", "tid": tid, "timestamp_ns": ns, "status_code": status})
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
    fn concurrent_threads_do_not_steal_each_others_responses() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        p.accept(1, &req(9, 1_100_000_000), 1100);
        let a = p
            .accept(1, &resp(9, 1_200_000_000, 500), 1200)
            .expect("tid 9");
        assert_eq!(a["tid"], 9);
        assert_eq!(a["response"]["status_code"], 500);
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
    fn an_unanswered_request_stays_outstanding() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        assert_eq!(p.outstanding(), 1);
    }

    #[test]
    fn bookkeeping_keys_do_not_leak_into_the_interaction() {
        let mut p = Pairer::new();
        p.accept(1, &req(7, 1_000_000_000), 1000);
        let out = p.accept(1, &resp(7, 1_100_000_000, 200), 1100).unwrap();
        assert!(out["request"].get("message_type").is_none());
        assert!(out["request"].get("tid").is_none());
        assert_eq!(out["request"]["path"], "/v1/messages");
    }

    #[test]
    fn filters_reach_the_agentsight_command_line() {
        let f = CaptureFilters {
            binary_path: Some("/usr/bin/claude".into()),
            pid: Some(42),
            uid: None,
            comm: Some("claude".into()),
        };
        let args = f.to_args();
        assert_eq!(&args[0..2], &["debug", "ssl"]);
        assert!(args
            .windows(2)
            .any(|w| w == ["--binary-path", "/usr/bin/claude"]));
        assert!(args.windows(2).any(|w| w == ["--pid", "42"]));
        assert!(args.windows(2).any(|w| w == ["--comm", "claude"]));
        assert!(!args.iter().any(|a| a == "--uid"));
    }
}

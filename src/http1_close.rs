//! Ends a chunked HTTP/1 reply whose connection closed between two chunks
//! (datrail/railmon#70).
//!
//! An agent that has what it needs from a streamed reply can close the
//! connection without reading the terminating chunk. OpenClaw does it with
//! the last, text-only reply of a turn: the model's stream is complete
//! (`message_stop`), but `0\r\n\r\n` was never read. AgentSight's parser
//! then holds a chunked message that never ends. On the close it reports the
//! buffered bytes as `partial` evidence with no exchange id (and RailMon runs
//! it without raw data, which would carry credentials), and ends the
//! exchange with no reply, so the request went on as incomplete while every
//! byte of its answer had been captured.
//!
//! [`ClosedReplyEnder`] sits in front of [`CompressedReplyDecoder`] and the
//! parser and follows each named TLS connection's chunked reply framing, as
//! [`Http1FramingGuard`](crate::http1_guard) does for unnamed ones. When that
//! connection's close arrives while its reply waits for the next chunk-size
//! line, it passes on one more read first, the terminating chunk, so the
//! parser emits the reply as captured and pairs it with its request.
//! [`MarkEndedAtClose`], after the parser, marks that response
//! `ended_at_close`, so the record says its last chunk was never read.
//!
//! Anything else it leaves as today: a close inside a chunk's data (the
//! reply really is cut), a Content-Length or close-delimited reply (the
//! parser already ends those at the close), a connection AgentSight does not
//! name (its close retires nothing in the parser), and requests.
//!
//! [`CompressedReplyDecoder`]: crate::http1_decode::CompressedReplyDecoder

use crate::http1_guard::{
    chunk_position, connection_key, event_bytes, looks_like_http1_start, Position, MAX_BODY_BYTES,
    MAX_STREAMS,
};
use agentsight_capture::analyzers::Analyzer;
use agentsight_capture::runners::EventStream;
use agentsight_capture::Event;
use futures::StreamExt;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A followed reply that has not moved for this long is let go, as
/// [`Http1FramingGuard`](crate::http1_guard) lets its keys go: its
/// connection may never report a close (a killed agent, a missed event).
const IDLE_RELEASE: Duration = Duration::from_secs(120);

/// The record field AgentSight's parser reads a capture loss from: a change
/// in it, on any record, ends every connection it is following.
const LOSS_COUNTER: &str = "ringbuf_reserve_failures";

/// The terminating chunk passed on for a reply its connection closed on.
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// The connections whose reply was ended here, keyed as [`connection_key`]
/// keys them, until [`MarkEndedAtClose`] marks the parsed reply.
pub type Ended = Arc<Mutex<HashSet<(u32, u64)>>>;

struct Reply {
    /// The reply's bytes so far, for its framing.
    buf: Vec<u8>,
    /// Where its body starts.
    head_end: usize,
    /// The reply's last read, which the terminating chunk is cut from.
    last: Event,
    /// When it last moved, on this process's clock.
    moved: Instant,
}

#[derive(Default)]
pub struct ClosedReplyEnder {
    replies: HashMap<(u32, u64), Reply>,
    ended: Ended,
}

impl ClosedReplyEnder {
    pub fn new(ended: Ended) -> Self {
        Self {
            replies: HashMap::new(),
            ended,
        }
    }

    fn observe(&mut self, event: Event) -> Vec<Event> {
        if event.source != "ssl" {
            return vec![event];
        }
        let Some(connection) = connection_key(&event) else {
            return vec![event];
        };
        let key = (event.pid, connection);
        if event.data.get("connection_closed").and_then(Value::as_bool) == Some(true) {
            let Some(reply) = self.replies.remove(&key) else {
                return vec![event];
            };
            if !at_chunk_boundary(&reply) {
                return vec![event];
            }
            // The probe lost records since the reply's last read: the parser
            // ends this connection on the close's counter anyway, and a read
            // carrying the older counter would look like one more loss to it,
            // ending every other connection it follows.
            if reply.last.data.get(LOSS_COUNTER) != event.data.get(LOSS_COUNTER) {
                return vec![event];
            }
            let mut last = reply.last;
            if let Some(obj) = last.data.as_object_mut() {
                let text: String = LAST_CHUNK.iter().map(|&b| char::from(b)).collect();
                obj.insert("data".into(), Value::String(text));
                obj.remove("data_hex");
                // A whole record of its own, as a real read of it would be.
                obj.insert("truncated".into(), json!(false));
                for field in ["len", "buf_size"] {
                    if obj.contains_key(field) {
                        obj.insert(field.into(), json!(LAST_CHUNK.len()));
                    }
                }
            }
            // Dated with the reply's last read: when it really ended.
            self.ended.lock().expect("ended set").insert(key);
            log::debug!(
                "pid {}: a chunked reply's connection closed between chunks; its last chunk is \
                 supplied so the reply is recorded",
                key.0
            );
            return vec![last, event];
        }
        let Some(text) = event.data.get("data").and_then(Value::as_str) else {
            return vec![event];
        };
        let function = event
            .data
            .get("function")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase();
        if !(function.contains("READ") || function.contains("RECV")) {
            return vec![event];
        }
        let truncated = event.data.get("truncated").and_then(Value::as_bool) == Some(true);
        let bytes = event_bytes(&event, text);
        if truncated {
            self.replies.remove(&key);
            return vec![event];
        }
        let now = Instant::now();
        self.replies
            .retain(|_, reply| now.duration_since(reply.moved) < IDLE_RELEASE);
        if looks_like_http1_start(&bytes) {
            self.replies.remove(&key);
            if let Some(head_end) = chunked_reply_head(&bytes) {
                let reply = Reply {
                    buf: bytes,
                    head_end,
                    last: event.clone(),
                    moved: now,
                };
                if !ended(&reply) {
                    if self.replies.len() >= MAX_STREAMS {
                        // The longest-quiet reply goes, not the new one.
                        if let Some(oldest) = self
                            .replies
                            .iter()
                            .min_by_key(|(_, r)| r.moved)
                            .map(|(k, _)| *k)
                        {
                            self.replies.remove(&oldest);
                        }
                    }
                    self.replies.insert(key, reply);
                }
            }
            return vec![event];
        }
        if let Some(reply) = self.replies.get_mut(&key) {
            reply.buf.extend_from_slice(&bytes);
            reply.last = event.clone();
            reply.moved = now;
            if reply.buf.len() > MAX_BODY_BYTES || ended(reply) {
                self.replies.remove(&key);
            }
        }
        vec![event]
    }
}

/// The end of a response head whose body is framed by `chunked` alone.
fn chunked_reply_head(bytes: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(bytes);
    if !text.starts_with("HTTP/1.") {
        return None;
    }
    let end = text.find("\r\n\r\n")? + 4;
    // `chunked` last, as framing requires (`gzip, chunked` too).
    let chunked = text[..end].split("\r\n").any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value
                    .rsplit(',')
                    .next()
                    .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
        })
    });
    chunked.then_some(end)
}

/// The reply is whole, or its framing broke: nothing to follow.
fn ended(reply: &Reply) -> bool {
    !matches!(chunk_position(&reply.buf, reply.head_end), Ok((_, None)))
}

/// Waiting for a chunk-size line with none of it read: the last chunk (or
/// the head) ended exactly where the reads stop.
fn at_chunk_boundary(reply: &Reply) -> bool {
    matches!(
        chunk_position(&reply.buf, reply.head_end),
        Ok((Position::SizeLine, None))
    ) && (reply.buf.len() == reply.head_end || reply.buf.ends_with(b"\r\n"))
}

#[async_trait::async_trait]
impl Analyzer for ClosedReplyEnder {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut ender = std::mem::take(self);
        Ok(Box::pin(stream.flat_map(move |event| {
            futures::stream::iter(ender.observe(event))
        })))
    }
}

/// After the parser: the response [`ClosedReplyEnder`] supplied the last
/// chunk of says so, `ended_at_close: true`. The parser emits it while
/// handling the supplied read, before the close that follows; if it emits
/// none (it had stopped following the connection), that close clears the
/// entry, so a later connection reusing the handle is never marked.
#[derive(Default)]
pub struct MarkEndedAtClose {
    ended: Ended,
}

impl MarkEndedAtClose {
    pub fn new(ended: Ended) -> Self {
        Self { ended }
    }

    fn observe(&mut self, mut event: Event) -> Event {
        let Some(connection) = connection_key(&event) else {
            return event;
        };
        if event.source == "ssl"
            && event.data.get("connection_closed").and_then(Value::as_bool) == Some(true)
        {
            self.ended
                .lock()
                .expect("ended set")
                .remove(&(event.pid, connection));
            return event;
        }
        if event.data.get("message_type").and_then(Value::as_str) != Some("response") {
            return event;
        }
        if self
            .ended
            .lock()
            .expect("ended set")
            .remove(&(event.pid, connection))
        {
            event.data["ended_at_close"] = json!(true);
        }
        event
    }
}

#[async_trait::async_trait]
impl Analyzer for MarkEndedAtClose {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut marker = std::mem::take(self);
        Ok(Box::pin(stream.map(move |event| marker.observe(event))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1_decode::CompressedReplyDecoder;
    use agentsight_capture::analyzers::{HTTPDecompressor, HTTPParser};
    use std::io::Write;

    fn ssl(ts: u64, function: &str, bytes: &[u8], handle: Option<&str>) -> Event {
        let text: String = bytes.iter().map(|&b| b as char).collect();
        let mut event = Event::new_with_timestamp(
            ts,
            "ssl".into(),
            7,
            "node".into(),
            json!({"function": function, "tid": 1, "data": text, "len": bytes.len()}),
        );
        if let Some(handle) = handle {
            event.data["transport_handle"] = json!(handle);
            event.data["process_start_ns"] = json!(12345);
            event.data["tls_library"] = json!("openssl");
        }
        event
    }

    fn close(ts: u64, handle: Option<&str>) -> Event {
        let mut event = ssl(ts, "CLOSE", b"null", handle);
        event.data["connection_closed"] = json!(true);
        event
    }

    const REQUEST: &[u8] = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
        Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
        Transfer-Encoding: chunked\r\n\r\n";
    /// The end of a text-only Anthropic stream, as the agent read it: every
    /// event, each in its own chunk, and no terminating chunk.
    const EVENTS: [&str; 2] = [
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"READY\"}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ];

    fn chunk(text: &[u8]) -> Vec<u8> {
        let mut out = format!("{:x}\r\n", text.len()).into_bytes();
        out.extend_from_slice(text);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The request, the reply's head and chunks on connection `handle`.
    fn exchange(handle: Option<&str>, head: &[u8], body: &[u8]) -> Vec<Event> {
        let mut events = vec![
            ssl(10, "WRITE/SEND", REQUEST, handle),
            ssl(20, "READ/RECV", head, handle),
        ];
        for (i, piece) in body.chunks(40).enumerate() {
            events.push(ssl(21 + i as u64, "READ/RECV", piece, handle));
        }
        events
    }

    async fn chain(events: Vec<Event>) -> Vec<Event> {
        let ended = Ended::default();
        let mut stream: EventStream = Box::pin(futures::stream::iter(events));
        let mut analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(ClosedReplyEnder::new(ended.clone())),
            Box::new(CompressedReplyDecoder::new()),
            Box::new(HTTPParser::new().disable_raw_data()),
            Box::new(MarkEndedAtClose::new(ended)),
            Box::new(HTTPDecompressor::new()),
        ];
        for a in analyzers.iter_mut() {
            stream = a.process(stream).await.unwrap();
        }
        stream.collect().await
    }

    fn of_type<'a>(out: &'a [Event], kind: &str) -> Vec<&'a Event> {
        out.iter()
            .filter(|e| e.data.get("message_type").and_then(Value::as_str) == Some(kind))
            .collect()
    }

    fn body() -> Vec<u8> {
        EVENTS.iter().flat_map(|e| chunk(e.as_bytes())).collect()
    }

    #[tokio::test]
    async fn a_reply_closed_between_chunks_is_recorded_and_paired() {
        let mut events = exchange(Some("0xa"), HEAD, &body());
        events.push(close(90, Some("0xa")));
        let out = chain(events).await;
        let [request] = of_type(&out, "request")[..] else {
            panic!("{out:?}")
        };
        let [response] = of_type(&out, "response")[..] else {
            panic!("{out:?}")
        };
        assert_eq!(
            response.data["http_exchange_id"],
            request.data["http_exchange_id"]
        );
        assert_eq!(response.data["status_code"], 200);
        assert_eq!(response.data["ended_at_close"], true);
        let text = response.data["body"].as_str().unwrap();
        assert!(
            text.contains("READY") && text.contains("message_stop"),
            "{text}"
        );
        // Nothing ended the exchange without a reply (a terminal record
        // names its exchange; the CLOSE itself only gains a reason).
        assert!(!out
            .iter()
            .any(|e| e.data.get("message_type").is_none()
                && e.data.get("http_exchange_id").is_some()));
    }

    /// As sslsniff writes them: every record, the close too, carries the
    /// tracer's loss counter. Equal on all of them, the parser sees no loss,
    /// and the reply is dated by its last read.
    #[tokio::test]
    async fn with_the_probes_loss_counter_the_reply_still_pairs() {
        let mut events = exchange(Some("0xa"), HEAD, &body());
        events.push(close(90, Some("0xa")));
        for event in &mut events {
            event.data[LOSS_COUNTER] = json!(3);
            event.data["truncated"] = json!(false);
            event.data["buf_size"] = event.data["len"].clone();
        }
        let last_read = events[events.len() - 2].timestamp;
        let out = chain(events).await;
        let [response] = of_type(&out, "response")[..] else {
            panic!("{out:?}")
        };
        assert_eq!(response.data["ended_at_close"], true);
        assert!(!out.iter().any(
            |e| e.data.get("completion_reason").and_then(Value::as_str) == Some("capture_loss")
        ));
        assert_eq!(response.data["capture_truncated"], false);
        assert!(
            response.timestamp <= last_read,
            "dated by its reads, not the close"
        );
    }

    #[tokio::test]
    async fn a_compressed_reply_closed_between_chunks_is_decoded() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(EVENTS.concat().as_bytes()).unwrap();
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
            Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n";
        let mut events = exchange(Some("0xa"), head, &chunk(&gz.finish().unwrap()));
        events.push(close(90, Some("0xa")));
        let out = chain(events).await;
        let [response] = of_type(&out, "response")[..] else {
            panic!("{out:?}")
        };
        assert_eq!(response.data["ended_at_close"], true);
        assert!(response.data["body"]
            .as_str()
            .unwrap()
            .contains("message_stop"));
    }

    #[tokio::test]
    async fn a_close_inside_a_chunk_leaves_the_reply_cut() {
        let full = body();
        let mut events = exchange(Some("0xa"), HEAD, &full[..full.len() - 10]);
        events.push(close(90, Some("0xa")));
        let out = chain(events).await;
        assert!(of_type(&out, "response").is_empty(), "{out:?}");
    }

    #[tokio::test]
    async fn a_whole_reply_is_left_alone() {
        let mut full = body();
        full.extend_from_slice(b"0\r\n\r\n");
        let mut events = exchange(Some("0xa"), HEAD, &full);
        events.push(close(90, Some("0xa")));
        let out = chain(events).await;
        let [response] = of_type(&out, "response")[..] else {
            panic!("{out:?}")
        };
        assert!(response.data.get("ended_at_close").is_none());
    }

    /// A loss between the reply's last read and its close: the parser ends
    /// the connection on the close's counter, and a supplied read with the
    /// older counter would read to it as one more loss, ending every other
    /// connection. Nothing is supplied.
    #[test]
    fn a_capture_loss_before_the_close_supplies_nothing() {
        let mut events = exchange(Some("0xa"), HEAD, &body());
        for event in &mut events {
            event.data[LOSS_COUNTER] = json!(0);
        }
        let mut closing = close(90, Some("0xa"));
        closing.data[LOSS_COUNTER] = json!(1);
        events.push(closing);
        let ended = Ended::default();
        let mut ender = ClosedReplyEnder::new(ended.clone());
        let out: Vec<Event> = events
            .clone()
            .into_iter()
            .flat_map(|e| ender.observe(e))
            .collect();
        assert_eq!(out.len(), events.len());
        assert!(ended.lock().unwrap().is_empty());
    }

    /// The parser emitted no reply for the supplied chunk: the close clears
    /// the entry, so the next connection on a reused handle isn't marked.
    #[test]
    fn a_close_clears_an_entry_the_parser_never_answered() {
        let ended = Ended::default();
        let key = (7, connection_key(&close(1, Some("0xa"))).unwrap());
        ended.lock().unwrap().insert(key);
        let mut marker = MarkEndedAtClose::new(ended.clone());
        marker.observe(close(90, Some("0xa")));
        assert!(ended.lock().unwrap().is_empty());
        let mut later = ssl(100, "READ/RECV", b"", Some("0xa"));
        later.source = "http_parser".into();
        later.data["message_type"] = json!("response");
        assert!(marker.observe(later).data.get("ended_at_close").is_none());
    }

    #[test]
    fn a_coding_list_ending_in_chunked_is_followed() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert_eq!(chunked_reply_head(head), Some(head.len()));
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
        assert_eq!(chunked_reply_head(head), None);
        assert_eq!(chunked_reply_head(HEAD), Some(HEAD.len()));
    }

    #[tokio::test]
    async fn a_connection_agentsight_does_not_name_is_left_alone() {
        let mut events = exchange(None, HEAD, &body());
        events.push(close(90, None));
        let mut ender = ClosedReplyEnder::new(Ended::default());
        let out: Vec<Event> = events
            .clone()
            .into_iter()
            .flat_map(|e| ender.observe(e))
            .collect();
        assert_eq!(out.len(), events.len());
    }

    #[tokio::test]
    async fn another_connections_close_ends_nothing() {
        let mut events = exchange(Some("0xa"), HEAD, &body());
        events.push(close(90, Some("0xb")));
        let mut ender = ClosedReplyEnder::new(Ended::default());
        let out: Vec<Event> = events
            .clone()
            .into_iter()
            .flat_map(|e| ender.observe(e))
            .collect();
        assert_eq!(out.len(), events.len());
    }
}

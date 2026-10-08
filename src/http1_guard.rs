//! Keeps reads from another connection out of an HTTP/1.1 chunked message
//! (datrail/railmon#70).
//!
//! AgentSight's SSL events carry a pid and tid but no connection, and its
//! HTTP/1 parser keeps one buffer per `(pid, tid, direction)`. A Node agent
//! does all its TLS on one thread, so a WebSocket frame read between two SSE
//! chunks lands in the middle of the streamed reply's buffer, the chunked
//! framing no longer parses, the parser drops the whole message, and the
//! request is never answered.
//!
//! This guard sits in front of the parser and mirrors only the one thing it
//! can know for certain: where a chunked message's framing stands after the
//! bytes the parser has been given. When the next read on that key arrives
//! while the message is waiting for a chunk-size line (or the CRLF closing a
//! chunk) and the read cannot continue that framing, the read did not come
//! from this connection. It is hidden from the parser — moved to
//! [`DIVERTED_KEY`] — and put back right after it, so `--mode raw` still
//! records it and nothing is dropped.
//!
//! Everything it cannot decide it leaves alone, exactly as today: reads inside
//! a chunk's data, Content-Length bodies, header blocks, and a read that opens
//! a new HTTP/1 message (the parser resyncs on those itself).
//!
//! A reply that stops at a chunk boundary and never resumes (a cancelled SSE
//! stream) would otherwise keep its key guarded for good, keeping every later
//! read on that thread from the parser. So a key whose reply has not moved
//! for [`IDLE_RELEASE`] is let go, and its reads reach the parser as they did
//! before this guard existed.

use agentsight_capture::analyzers::Analyzer;
use agentsight_capture::runners::EventStream;
use agentsight_capture::Event;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Where a diverted read's payload waits while the parser runs.
pub const DIVERTED_KEY: &str = "railmon_diverted_data";
const DIVERTED_HEX_KEY: &str = "railmon_diverted_data_hex";

/// The parser's own bounds, so this never holds state it has already dropped.
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_STREAMS: usize = 1024;
/// A chunk-size line is a hex number plus optional extensions; anything this
/// long without a CRLF is not one.
const MAX_SIZE_LINE: usize = 1024;

/// How long a guarded reply may go without a byte of its own before its key
/// is released. Model streams send keep-alive events well inside this.
pub const IDLE_RELEASE: Duration = Duration::from_secs(60);

type Key = (u32, u64, bool);

struct Held {
    /// The bytes the parser is holding for this key, as it holds them.
    buf: Vec<u8>,
    /// When the reply last took a read.
    moved: Instant,
}

pub struct Http1FramingGuard {
    streams: HashMap<Key, Held>,
    idle_release: Duration,
}

impl Default for Http1FramingGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Http1FramingGuard {
    pub fn new() -> Self {
        Self::with_idle_release(IDLE_RELEASE)
    }

    fn with_idle_release(idle_release: Duration) -> Self {
        Self {
            streams: HashMap::new(),
            idle_release,
        }
    }

    /// True when the event should be hidden from the parser.
    fn observe(&mut self, event: &Event) -> bool {
        let Some(text) = event.data.get("data").and_then(Value::as_str) else {
            return false;
        };
        let function = event
            .data
            .get("function")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_uppercase();
        let is_read = function.contains("READ") || function.contains("RECV");
        let is_write = function.contains("WRITE") || function.contains("SEND");
        if !is_read && !is_write {
            return false;
        }
        let tid = event.data.get("tid").and_then(Value::as_u64).unwrap_or(0);
        let key = (event.pid, tid, is_read);
        let bytes = event_bytes(event, text);

        let truncated = event
            .data
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if truncated || bytes.len() > MAX_BODY_BYTES {
            self.streams.remove(&key);
            return false;
        }

        let now = Instant::now();
        if looks_like_http1_start(&bytes) {
            self.streams.insert(
                key,
                Held {
                    buf: bytes,
                    moved: now,
                },
            );
            self.settle(key);
            return false;
        }

        let Some(held) = self.streams.get_mut(&key) else {
            return false;
        };
        if cannot_continue(&held.buf, &bytes) {
            if now.duration_since(held.moved) < self.idle_release {
                return true;
            }
            // Stalled for good: the parser takes this read into the reply it
            // holds and drops both once the framing breaks or 1 MiB is
            // reached, as it did before the guard.
            self.streams.remove(&key);
            return false;
        }
        if held.buf.len() + bytes.len() > MAX_BODY_BYTES {
            self.streams.remove(&key);
            return false;
        }
        held.buf.extend_from_slice(&bytes);
        held.moved = now;
        self.settle(key);
        false
    }

    /// Drop complete messages off the front, as the parser does, so the
    /// buffer always starts at the message still in flight.
    fn settle(&mut self, key: Key) {
        let Some(Held { buf, .. }) = self.streams.get_mut(&key) else {
            return;
        };
        loop {
            match message_end(buf) {
                End::Complete(end) => {
                    buf.drain(..end);
                    if buf.is_empty() {
                        break;
                    }
                }
                End::Incomplete => break,
                End::Unknown => {
                    // The parser dropped it, or we cannot follow it: stop
                    // guarding this key rather than guess.
                    buf.clear();
                    break;
                }
            }
        }
        if buf.is_empty() {
            self.streams.remove(&key);
        }
        while self.streams.len() > MAX_STREAMS {
            let Some(k) = self.streams.keys().next().copied() else {
                break;
            };
            self.streams.remove(&k);
        }
    }
}

#[async_trait::async_trait]
impl Analyzer for Http1FramingGuard {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = std::mem::replace(self, Self::with_idle_release(self.idle_release));
        Ok(Box::pin(stream.map(move |mut event| {
            if event.source == "ssl" && guard.observe(&event) {
                if let Some(obj) = event.data.as_object_mut() {
                    log::debug!(
                        "pid {} tid {}: read cannot continue the chunked reply in flight \
                         on this thread; kept away from the HTTP parser",
                        event.pid,
                        obj.get("tid").and_then(Value::as_u64).unwrap_or(0)
                    );
                    if let Some(data) = obj.remove("data") {
                        obj.insert(DIVERTED_KEY.into(), data);
                    }
                    if let Some(hex) = obj.remove("data_hex") {
                        obj.insert(DIVERTED_HEX_KEY.into(), hex);
                    }
                }
            }
            event
        })))
    }
}

/// Puts a diverted read's payload back once the parser has passed it by.
pub struct RestoreDiverted;

#[async_trait::async_trait]
impl Analyzer for RestoreDiverted {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Box::pin(stream.map(|mut event| {
            if let Some(obj) = event.data.as_object_mut() {
                if let Some(data) = obj.remove(DIVERTED_KEY) {
                    obj.insert("data".into(), data);
                }
                if let Some(hex) = obj.remove(DIVERTED_HEX_KEY) {
                    obj.insert("data_hex".into(), hex);
                }
            }
            event
        })))
    }
}

/// The parser's own decoding of an SSL payload.
fn event_bytes(event: &Event, text: &str) -> Vec<u8> {
    if let Some(bytes) = event
        .data
        .get("data_hex")
        .and_then(Value::as_str)
        .and_then(hex_decode)
    {
        return bytes;
    }
    let mut bytes = Vec::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        if code <= 0xff {
            bytes.push(code as u8);
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
    bytes
}

fn hex_decode(hexed: &str) -> Option<Vec<u8>> {
    if !hexed.len().is_multiple_of(2) {
        return None;
    }
    hexed
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// Same rule as the parser's: resync only on a start line at offset zero.
fn looks_like_http1_start(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let first = text.split(['\r', '\n']).next().unwrap_or("");
    if first.starts_with("HTTP/1.") {
        return true;
    }
    let parts: Vec<&str> = first.splitn(3, ' ').collect();
    parts.len() >= 3
        && matches!(
            parts[0],
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
        )
        && parts[2].starts_with("HTTP/1.")
}

enum End {
    Complete(usize),
    Incomplete,
    /// Malformed, or framing this guard does not follow.
    Unknown,
}

/// Where the chunked framing of the buffered message stands at its end.
enum Position {
    /// Waiting for (the rest of) a chunk-size line.
    SizeLine,
    /// Chunk data still to come, then CRLF.
    Data,
    /// Chunk data complete; its closing CRLF is not all buffered yet.
    DataCrlf,
    /// In the trailer section, or anything else not checked.
    Unchecked,
}

fn find(buf: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

struct Head {
    end: usize,
    chunked: bool,
    length: Option<usize>,
    is_response: bool,
}

/// None while the header block is incomplete; Err when its framing headers
/// are malformed (the parser drops those).
fn header_info(buf: &[u8]) -> Result<Option<Head>, ()> {
    let lead = buf
        .iter()
        .take_while(|b| **b == b'\r' || **b == b'\n')
        .count();
    let Some(pos) = find(buf, b"\r\n\r\n", lead) else {
        return Ok(None);
    };
    let headers = String::from_utf8_lossy(&buf[lead..pos]);
    let mut chunked = false;
    let mut length = None;
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            match value.trim().parse::<usize>() {
                Ok(v) if length.is_none_or(|l| l == v) => length = Some(v),
                _ => return Err(()),
            }
        }
    }
    Ok(Some(Head {
        end: pos + 4,
        chunked,
        length,
        is_response: headers.starts_with("HTTP/1."),
    }))
}

fn message_end(buf: &[u8]) -> End {
    let head = match header_info(buf) {
        Ok(Some(head)) => head,
        Ok(None) => return End::Incomplete,
        Err(()) => return End::Unknown,
    };
    if head.chunked {
        return match chunk_position(buf, head.end) {
            Ok((_, Some(end))) => End::Complete(end),
            Ok((_, None)) => End::Incomplete,
            Err(()) => End::Unknown,
        };
    }
    match head.length {
        Some(n) if buf.len() >= head.end + n => End::Complete(head.end + n),
        Some(_) => End::Incomplete,
        // A request ends at its headers; the parser emits a close-delimited
        // response from what it holds on this read and keeps nothing.
        None if head.is_response => End::Complete(buf.len()),
        None => End::Complete(head.end),
    }
}

/// Walk the chunk framing from `start`; returns where it stands at the end of
/// `buf`, or the end of the message if it is complete.
fn chunk_position(buf: &[u8], start: usize) -> Result<(Position, Option<usize>), ()> {
    let mut cursor = start;
    loop {
        let Some(line_end) = find(buf, b"\r\n", cursor) else {
            let partial = &buf[cursor..];
            if !valid_size_prefix(partial) {
                return Err(());
            }
            return Ok((Position::SizeLine, None));
        };
        let size = parse_size(&buf[cursor..line_end]).ok_or(())?;
        let data_start = line_end + 2;
        if size == 0 {
            let mut t = data_start;
            loop {
                let Some(e) = find(buf, b"\r\n", t) else {
                    return Ok((Position::Unchecked, None));
                };
                if e == t {
                    return Ok((Position::Unchecked, Some(e + 2)));
                }
                t = e + 2;
            }
        }
        let data_end = data_start.checked_add(size).ok_or(())?;
        if buf.len() < data_end {
            return Ok((Position::Data, None));
        }
        let have = &buf[data_end..buf.len().min(data_end + 2)];
        if !b"\r\n".starts_with(have) {
            return Err(());
        }
        if have.len() < 2 {
            return Ok((Position::DataCrlf, None));
        }
        cursor = data_end + 2;
    }
}

fn parse_size(line: &[u8]) -> Option<usize> {
    let end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
    let digits = std::str::from_utf8(&line[..end]).ok()?;
    if digits.is_empty() {
        return None;
    }
    usize::from_str_radix(digits, 16).ok()
}

/// Could `partial` be the start of a chunk-size line?
fn valid_size_prefix(partial: &[u8]) -> bool {
    if partial.len() > MAX_SIZE_LINE {
        return false;
    }
    let digits = partial
        .iter()
        .position(|&b| b == b';')
        .unwrap_or(partial.len());
    let (num, ext) = partial.split_at(digits);
    let num = num.strip_suffix(b"\r").unwrap_or(num);
    let ext_ok = ext.is_empty() || ext.iter().all(|&b| b != b'\n');
    num.iter().all(u8::is_ascii_hexdigit)
        && ext_ok
        && (!num.is_empty() || ext.is_empty())
        && !partial.ends_with(b"\n")
}

/// True only when `buf` is a chunked message whose framing is known exactly
/// at its end, and `next` cannot continue that framing.
fn cannot_continue(buf: &[u8], next: &[u8]) -> bool {
    let Ok(Some(Head {
        end: header_end,
        chunked: true,
        ..
    })) = header_info(buf)
    else {
        return false;
    };
    let Ok((position, None)) = chunk_position(buf, header_end) else {
        return false;
    };
    match position {
        Position::SizeLine | Position::DataCrlf => {}
        // Inside chunk data any byte is legal, and a read that overruns the
        // chunk could equally mean an earlier read was the foreign one; the
        // parser is left to fail on it as it does today.
        Position::Data | Position::Unchecked => return false,
    }
    let mut joined = Vec::with_capacity(buf.len() + next.len());
    joined.extend_from_slice(buf);
    joined.extend_from_slice(next);
    chunk_position(&joined, header_end).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read(tid: u64, bytes: &[u8]) -> Event {
        let text: String = bytes.iter().map(|&b| b as char).collect();
        Event::new_with_timestamp(
            0,
            "ssl".into(),
            7,
            "node".into(),
            json!({"function": "READ/RECV", "tid": tid, "data": text}),
        )
    }

    const HEAD: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    const WS: &[u8] = b"\x81\x05frame";

    fn chunk(n: u8) -> Vec<u8> {
        let body = format!("data: tok{n}\n\n");
        format!("{:x}\r\n{body}\r\n", body.len()).into_bytes()
    }

    #[test]
    fn diverts_a_foreign_read_at_a_chunk_boundary() {
        let mut g = Http1FramingGuard::new();
        assert!(!g.observe(&read(1, HEAD)));
        assert!(!g.observe(&read(1, &chunk(0))));
        assert!(g.observe(&read(1, WS)));
        assert!(!g.observe(&read(1, &chunk(1))));
        assert!(g.observe(&read(1, WS)));
        assert!(!g.observe(&read(1, b"0\r\n\r\n")));
        // Message complete: the thread is idle and nothing is diverted.
        assert!(!g.observe(&read(1, WS)));
        assert!(g.streams.is_empty());
    }

    #[test]
    fn a_stalled_reply_releases_its_key() {
        // A cancelled stream left at a chunk boundary must not keep the
        // thread's later reads (an HTTP/2 frame here) from the parser for ever.
        let mut g = Http1FramingGuard::with_idle_release(Duration::ZERO);
        assert!(!g.observe(&read(1, HEAD)));
        assert!(!g.observe(&read(1, &chunk(0))));
        assert!(!g.observe(&read(1, b"\x00\x00\x08\x00\x01\x00\x00\x00\x01")));
        assert!(g.streams.is_empty());
    }

    #[test]
    fn leaves_reads_inside_chunk_data_alone() {
        let mut g = Http1FramingGuard::new();
        let mut head = HEAD.to_vec();
        head.extend_from_slice(b"20\r\nabc");
        assert!(!g.observe(&read(1, &head)));
        // Could be the rest of the chunk: undecidable, so passed on.
        assert!(!g.observe(&read(1, WS)));
        // Overrunning the chunk is not decided here either.
        assert!(!g.observe(&read(1, &[b'y'; 64])));
    }

    #[test]
    fn split_size_line_and_crlf_continue() {
        let mut g = Http1FramingGuard::new();
        assert!(!g.observe(&read(1, HEAD)));
        assert!(!g.observe(&read(1, b"1")));
        assert!(!g.observe(&read(1, b"0\r\n0123456789abcdef")));
        assert!(!g.observe(&read(1, b"\r")));
        assert!(g.observe(&read(1, WS)));
        assert!(!g.observe(&read(1, b"\n0\r\n\r\n")));
        assert!(g.streams.is_empty());
    }

    #[test]
    fn a_new_message_start_is_never_diverted() {
        let mut g = Http1FramingGuard::new();
        assert!(!g.observe(&read(1, HEAD)));
        assert!(!g.observe(&read(1, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")));
        assert!(g.streams.is_empty());
    }

    #[test]
    fn other_threads_and_content_length_bodies_are_untouched() {
        let mut g = Http1FramingGuard::new();
        assert!(!g.observe(&read(1, HEAD)));
        assert!(!g.observe(&read(2, WS)));
        assert!(!g.observe(&read(3, b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")));
        assert!(!g.observe(&read(3, WS)));
    }

    #[tokio::test]
    async fn parser_reassembles_the_reply_around_diverted_reads() {
        use agentsight_capture::analyzers::HTTPParser;
        let mut events = vec![read(1, HEAD), read(1, &chunk(0)), read(1, WS)];
        events.push(read(1, &chunk(1)));
        events.push(read(1, WS));
        events.push(read(1, b"0\r\n\r\n"));
        let mut stream: EventStream = Box::pin(futures::stream::iter(events));
        let mut chain: Vec<Box<dyn Analyzer>> = vec![
            Box::new(Http1FramingGuard::new()),
            Box::new(HTTPParser::new().disable_raw_data()),
            Box::new(RestoreDiverted),
        ];
        for a in chain.iter_mut() {
            stream = a.process(stream).await.unwrap();
        }
        let out: Vec<Event> = stream.collect().await;
        let responses: Vec<&Event> = out
            .iter()
            .filter(|e| e.data.get("message_type").and_then(Value::as_str) == Some("response"))
            .collect();
        assert_eq!(responses.len(), 1);
        let body = responses[0].data.to_string();
        assert!(body.contains("tok0") && body.contains("tok1"), "{body}");
        assert!(!body.contains("frame"), "{body}");
        // Both foreign reads still come out, payload restored.
        let restored = out
            .iter()
            .filter(|e| e.data.get("data").and_then(Value::as_str) == Some("\u{81}\u{5}frame"))
            .count();
        assert_eq!(restored, 2);
        assert!(out.iter().all(|e| e.data.get(DIVERTED_KEY).is_none()));
    }
}

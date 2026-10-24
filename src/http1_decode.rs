//! Hands the HTTP parser a compressed HTTP/1 reply already decoded
//! (datrail/railmon#93).
//!
//! AgentSight's HTTP/1 parser turns a message into text before
//! `HTTPDecompressor` sees its body, and that text conversion replaces every
//! byte that is not valid UTF-8. A gzip, deflate, Brotli or zstd body does not
//! survive it, so the decompressor fails and passes the reply on still
//! chunk-framed and compressed — a streamed `content-encoding: gzip` SSE reply
//! (what Node's fetch asks Gemini for by default) reached RailDash unreadable.
//!
//! This stage sits between [`Http1FramingGuard`](crate::http1_guard) and the
//! parser and works on the bytes. When a read opens an HTTP/1 response whose
//! complete header block names one content coding it can decode, the reply's
//! reads are held back until the message is whole (the terminal chunk of a
//! chunked reply, or `Content-Length` bytes). The body is then de-chunked and
//! decoded, and the parser is given one read carrying the message as it would
//! look sent uncompressed: `Content-Encoding` and `Transfer-Encoding` removed,
//! `Content-Length` set to the decoded length, every other header kept in
//! order. That read keeps the timestamp of the reply's first read, as the
//! parser's own response would.
//!
//! Anything it cannot do it leaves exactly as today, by releasing the held
//! reads unchanged and in order: a decode error, a corrupt or truncated body,
//! a decoded message past [`MAX_BODY_BYTES`] (the parser's own bound, which
//! also bounds a decompression bomb), broken framing, a new message on the
//! same key before this one ends, a truncated read, a stacked coding list, a
//! transfer coding other than `chunked`, and a close-delimited reply. Requests
//! and uncompressed replies are never touched.

use crate::http1_guard::{
    chunk_position, connection_key, event_bytes, find, header_info, looks_like_http1_start,
    parse_size, MAX_BODY_BYTES, MAX_STREAMS,
};
use agentsight_capture::analyzers::Analyzer;
use agentsight_capture::runners::EventStream;
use agentsight_capture::Event;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;

type Key = (u32, u64, bool);

/// The parser's own buffer a read goes to: its TLS connection when the record
/// names one, otherwise its thread.
fn stream_key(event: &Event, is_read: bool) -> Key {
    let stream = connection_key(event)
        .unwrap_or_else(|| event.data.get("tid").and_then(Value::as_u64).unwrap_or(0));
    (event.pid, stream, is_read)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

struct Pending {
    /// The reply's reads, untouched, in arrival order.
    events: Vec<Event>,
    /// Their bytes, concatenated.
    buf: Vec<u8>,
    coding: Coding,
    head_end: usize,
    chunked: bool,
    length: Option<usize>,
}

#[derive(Default)]
pub struct CompressedReplyDecoder {
    pending: HashMap<Key, Pending>,
}

impl CompressedReplyDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The events to pass on for this one: none while a reply is held, the
    /// decoded reply once it is whole, the held reads unchanged otherwise.
    fn observe(&mut self, event: Event) -> Vec<Event> {
        if event.source != "ssl" {
            return vec![event];
        }
        if event.data.get("connection_closed").and_then(Value::as_bool) == Some(true)
            && connection_key(&event).is_some()
        {
            // The parser retires a connection it can name on its close, so a
            // reply still held here has to reach it first, as captured: once
            // the connection is gone the reply could only open a new one with
            // no request to answer. A close that names no connection retires
            // nothing there, and keyed by thread it could belong to another.
            let mut out = Vec::new();
            for is_read in [true, false] {
                if let Some(pending) = self.pending.remove(&stream_key(&event, is_read)) {
                    out.extend(pending.events);
                }
            }
            out.push(event);
            return out;
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
        let is_read = function.contains("READ") || function.contains("RECV");
        let is_write = function.contains("WRITE") || function.contains("SEND");
        if !is_read && !is_write {
            return vec![event];
        }
        let key = stream_key(&event, is_read);
        let bytes = event_bytes(&event, text);
        let truncated = event
            .data
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut out = Vec::new();
        if let Some(mut pending) = self.pending.remove(&key) {
            if truncated || looks_like_http1_start(&bytes) {
                // The parser drops or resyncs on this read; let it see the
                // held reads first, as it would have.
                out.append(&mut pending.events);
            } else {
                pending.buf.extend_from_slice(&bytes);
                pending.events.push(event);
                out.extend(self.advance(key, pending));
                return out;
            }
        }

        if truncated || bytes.len() > MAX_BODY_BYTES {
            out.push(event);
            return out;
        }
        let Some((coding, head_end, chunked, length)) = compressed_reply_head(&bytes) else {
            out.push(event);
            return out;
        };
        let pending = Pending {
            events: vec![event],
            buf: bytes,
            coding,
            head_end,
            chunked,
            length,
        };
        out.extend(self.advance(key, pending));
        out
    }

    /// Hold the reply, decode it once whole, or give up and release it.
    fn advance(&mut self, key: Key, pending: Pending) -> Vec<Event> {
        if pending.buf.len() > MAX_BODY_BYTES {
            return pending.events;
        }
        let end = if pending.chunked {
            match chunk_position(&pending.buf, pending.head_end) {
                Ok((_, Some(end))) => end,
                Ok((_, None)) => return self.hold(key, pending),
                Err(()) => return pending.events,
            }
        } else {
            let Some(end) = pending.length.and_then(|n| pending.head_end.checked_add(n)) else {
                return pending.events;
            };
            if pending.buf.len() < end {
                return self.hold(key, pending);
            }
            end
        };
        match decoded_message(&pending, end) {
            Some(message) => {
                let mut first = pending.events.into_iter().next().expect("one read");
                if let Some(obj) = first.data.as_object_mut() {
                    // latin-1, as for sslsniff's HEX: payloads: one char per
                    // byte is what the parser turns back into these bytes.
                    let text: String = message.iter().map(|&b| char::from(b)).collect();
                    obj.insert("data".into(), Value::String(text));
                    obj.remove("data_hex");
                    if obj.contains_key("len") {
                        obj.insert("len".into(), message.len().into());
                    }
                }
                vec![first]
            }
            None => {
                log::debug!(
                    "pid {} stream {:x}: a {:?}-encoded reply could not be decoded within {} bytes; \
                     passed on as captured",
                    key.0,
                    key.1,
                    pending.coding,
                    MAX_BODY_BYTES
                );
                pending.events
            }
        }
    }

    fn hold(&mut self, key: Key, pending: Pending) -> Vec<Event> {
        self.pending.insert(key, pending);
        let mut released = Vec::new();
        while self.pending.len() > MAX_STREAMS {
            let Some(k) = self.pending.keys().find(|k| **k != key).copied() else {
                break;
            };
            if let Some(p) = self.pending.remove(&k) {
                released.extend(p.events);
            }
        }
        released
    }
}

#[async_trait::async_trait]
impl Analyzer for CompressedReplyDecoder {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> std::result::Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut decoder = std::mem::take(self);
        Ok(Box::pin(stream.flat_map(move |event| {
            futures::stream::iter(decoder.observe(event))
        })))
    }
}

/// A response start whose whole header block is here and whose body this
/// stage can decode: one supported content coding, framed by `chunked` alone
/// or by `Content-Length`.
fn compressed_reply_head(bytes: &[u8]) -> Option<(Coding, usize, bool, Option<usize>)> {
    if !looks_like_http1_start(bytes) || !bytes.starts_with(b"HTTP/1.") {
        return None;
    }
    let head = header_info(bytes).ok()??;
    if !head.is_response {
        return None;
    }
    // 1xx, 204 and 304 carry no body.
    let status = bytes.get(9..12)?;
    if status[0] == b'1' || status == b"204" || status == b"304" {
        return None;
    }
    let text = std::str::from_utf8(&bytes[..head.end]).ok()?;
    let mut codings = Vec::new();
    let mut transfer = Vec::new();
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let list = if name.trim().eq_ignore_ascii_case("content-encoding") {
            &mut codings
        } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            &mut transfer
        } else {
            continue;
        };
        list.extend(
            value
                .split(',')
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty()),
        );
    }
    codings.retain(|c| c != "identity");
    let [coding] = codings.as_slice() else {
        return None;
    };
    let coding = match coding.as_str() {
        "gzip" | "x-gzip" => Coding::Gzip,
        "deflate" => Coding::Deflate,
        "br" => Coding::Brotli,
        "zstd" => Coding::Zstd,
        _ => return None,
    };
    let chunked = match transfer.as_slice() {
        [] => false,
        [only] if only == "chunked" => true,
        _ => return None,
    };
    if !chunked && head.length.is_none() {
        return None;
    }
    Some((coding, head.end, chunked, head.length))
}

/// The whole message as it would be sent uncompressed, followed by whatever
/// came after it in the same reads; None to leave the reply as captured.
fn decoded_message(pending: &Pending, end: usize) -> Option<Vec<u8>> {
    let body = &pending.buf[pending.head_end..end];
    let encoded = if pending.chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    let decoded = decode(pending.coding, &encoded, MAX_BODY_BYTES)?;
    let mut message = rewrite_head(&pending.buf[..pending.head_end], decoded.len())?;
    message.extend_from_slice(&decoded);
    message.extend_from_slice(&pending.buf[end..]);
    (message.len() <= MAX_BODY_BYTES).then_some(message)
}

/// The data of a complete chunked body (framing already validated).
fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut cursor = 0;
    loop {
        let line_end = find(body, b"\r\n", cursor)?;
        let size = parse_size(&body[cursor..line_end])?;
        if size == 0 {
            return Some(out);
        }
        let start = line_end + 2;
        let stop = start.checked_add(size)?;
        out.extend_from_slice(body.get(start..stop)?);
        cursor = stop + 2;
    }
}

/// Decode `data`, or None on any error, an unfinished stream, or output past
/// `cap` bytes.
fn decode(coding: Coding, data: &[u8], cap: usize) -> Option<Vec<u8>> {
    match coding {
        Coding::Gzip => read_capped(flate2::read::GzDecoder::new(data), cap),
        // RFC 9110's deflate is zlib-wrapped; some servers send it raw.
        Coding::Deflate => inflate(data, true, cap).or_else(|| inflate(data, false, cap)),
        Coding::Brotli => read_capped(brotli_decompressor::Decompressor::new(data, 4096), cap),
        Coding::Zstd => read_capped(zstd::stream::read::Decoder::new(data).ok()?, cap),
    }
}

fn read_capped<R: Read>(reader: R, cap: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(cap as u64 + 1).read_to_end(&mut out).ok()?;
    (out.len() <= cap).then_some(out)
}

/// zlib or raw deflate, required to reach the end of the stream: flate2's
/// `Read` adapters return a truncated stream's prefix as success.
fn inflate(data: &[u8], zlib: bool, cap: usize) -> Option<Vec<u8>> {
    let mut inflater = flate2::Decompress::new(zlib);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let (read, written) = (inflater.total_in(), inflater.total_out());
        let status = inflater
            .decompress(
                data.get(read as usize..)?,
                &mut buf,
                flate2::FlushDecompress::None,
            )
            .ok()?;
        let produced = (inflater.total_out() - written) as usize;
        out.extend_from_slice(&buf[..produced]);
        if out.len() > cap {
            return None;
        }
        if status == flate2::Status::StreamEnd {
            return Some(out);
        }
        if produced == 0 && inflater.total_in() == read {
            // The input ran out before the stream ended.
            return None;
        }
    }
}

/// The header block with the content and transfer codings gone and
/// `Content-Length` set to `length`, every other line kept in order.
fn rewrite_head(head: &[u8], length: usize) -> Option<Vec<u8>> {
    let lead = head
        .iter()
        .take_while(|b| **b == b'\r' || **b == b'\n')
        .count();
    let text = std::str::from_utf8(&head[lead..]).ok()?;
    let text = text.strip_suffix("\r\n\r\n")?;
    let mut out = Vec::with_capacity(head.len());
    let mut length_written = false;
    let mut dropping = false;
    for (i, line) in text.split("\r\n").enumerate() {
        if i > 0 && (line.starts_with(' ') || line.starts_with('\t')) {
            // An obsolete folded continuation belongs to the line above.
            if !dropping {
                out.extend_from_slice(line.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            continue;
        }
        dropping = false;
        if i > 0 {
            if let Some((name, _)) = line.split_once(':') {
                let name = name.trim();
                if name.eq_ignore_ascii_case("content-encoding")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                {
                    dropping = true;
                    continue;
                }
                if name.eq_ignore_ascii_case("content-length") {
                    dropping = true;
                    if !length_written {
                        out.extend_from_slice(format!("{name}: {length}\r\n").as_bytes());
                        length_written = true;
                    }
                    continue;
                }
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !length_written {
        out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsight_capture::analyzers::{HTTPDecompressor, HTTPParser};
    use serde_json::json;
    use std::io::Write;

    fn ssl(ts: u64, function: &str, tid: u64, bytes: &[u8]) -> Event {
        let text: String = bytes.iter().map(|&b| b as char).collect();
        Event::new_with_timestamp(
            ts,
            "ssl".into(),
            7,
            "node".into(),
            json!({"function": function, "tid": tid, "data": text, "len": bytes.len()}),
        )
    }

    /// An OpenAI-compatible streamed reply that calls a tool, as Gemini sends it.
    const SSE: &str = concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,",
        "\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":",
        "\"delivery__delivery_track_package\",\"arguments\":\"{\\\"id\\\":\\\"PKG-42\\\"}\"}}]},",
        "\"index\":0}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\",\"index\":0}]}\n\n",
        "data: [DONE]\n\n",
    );

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    /// Chunked framing the way Node/undici frames a gzip stream: the first
    /// bytes in one-byte chunks with zero-padded sizes, then uneven chunks.
    fn node_chunked(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        let mut size = 1;
        while i < body.len() {
            let n = size.min(body.len() - i);
            if i < 3 {
                out.extend_from_slice(format!("{n:08x}\r\n").as_bytes());
            } else {
                out.extend_from_slice(format!("{n:x}\r\n").as_bytes());
            }
            out.extend_from_slice(&body[i..i + n]);
            out.extend_from_slice(b"\r\n");
            i += n;
            if i >= 3 {
                size = size * 3 + 7;
            }
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    const GZIP_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
        Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nX-Request-Id: abc\r\n\r\n";

    /// The reply as reads: the header block alone, then the framed body cut
    /// every `step` bytes, regardless of where chunks start and end.
    fn reads(head: &[u8], framed: &[u8], step: usize, ts: u64) -> Vec<Event> {
        let mut events = vec![ssl(ts, "READ/RECV", 1, head)];
        for (i, piece) in framed.chunks(step).enumerate() {
            events.push(ssl(ts + 1 + i as u64, "READ/RECV", 1, piece));
        }
        events
    }

    fn run(events: Vec<Event>) -> Vec<Event> {
        let mut d = CompressedReplyDecoder::new();
        events.into_iter().flat_map(|e| d.observe(e)).collect()
    }

    fn data_bytes(event: &Event) -> Vec<u8> {
        event.data["data"]
            .as_str()
            .unwrap()
            .chars()
            .map(|c| c as u32 as u8)
            .collect()
    }

    fn snapshot(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| format!("{} {}", e.timestamp, e.data))
            .collect()
    }

    fn split_message(bytes: &[u8]) -> (String, Vec<u8>) {
        let end = find(bytes, b"\r\n\r\n", 0).unwrap() + 4;
        (
            String::from_utf8(bytes[..end].to_vec()).unwrap(),
            bytes[end..].to_vec(),
        )
    }

    #[test]
    fn a_gzip_chunked_stream_becomes_one_decoded_read() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        assert!(framed.starts_with(b"00000001\r\n\x1f\r\n00000001\r\n\x8b\r\n"));
        for step in [1, 2, 5, 13, 64, framed.len()] {
            let out = run(reads(GZIP_HEAD, &framed, step, 100));
            assert_eq!(out.len(), 1, "step {step}");
            assert_eq!(out[0].timestamp, 100, "the first read's timestamp");
            let (head, body) = split_message(&data_bytes(&out[0]));
            assert_eq!(body, SSE.as_bytes());
            assert_eq!(
                head,
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                     X-Request-Id: abc\r\nContent-Length: {}\r\n\r\n",
                    SSE.len()
                )
            );
            assert_eq!(out[0].data["len"], json!(head.len() + SSE.len()));
        }
    }

    /// The fields AgentSight 1.0.35 names a record's TLS connection with.
    fn on(mut event: Event, handle: &str) -> Event {
        event.data["transport_handle"] = json!(handle);
        event.data["process_start_ns"] = json!(12345);
        event.data["tls_library"] = json!("openssl");
        event
    }

    /// Two connections on one Node thread, each with a compressed streamed
    /// reply, read interleaved: keyed by thread, the second reply's head
    /// would release the first unchanged, still compressed.
    #[test]
    fn interleaved_replies_on_two_connections_are_each_decoded() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        let a = reads(GZIP_HEAD, &framed, 16, 100);
        let b = reads(GZIP_HEAD, &framed, 16, 500);
        let mut events = Vec::new();
        for i in 0..a.len().max(b.len()) {
            events.extend(a.get(i).cloned().map(|e| on(e, "0xa")));
            events.extend(b.get(i).cloned().map(|e| on(e, "0xb")));
        }
        let out = run(events);
        assert_eq!(out.len(), 2, "{}", snapshot(&out).join("\n"));
        for (event, handle) in out.iter().zip(["0xa", "0xb"]) {
            assert_eq!(event.data["transport_handle"], handle);
            assert_eq!(split_message(&data_bytes(event)).1, SSE.as_bytes());
        }
    }

    /// The parser retires a connection on its close, so a reply still held
    /// for it reaches the parser first.
    #[test]
    fn a_close_releases_its_connections_held_reply_first() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        let mut events: Vec<Event> = reads(GZIP_HEAD, &framed[..framed.len() / 2], 8, 1)
            .into_iter()
            .map(|e| on(e, "0xa"))
            .collect();
        let held = events.len();
        let other = on(ssl(90, "READ/RECV", 1, GZIP_HEAD), "0xb");
        events.push(other);
        let mut close = on(ssl(99, "CLOSE", 1, b"null"), "0xa");
        close.data["connection_closed"] = json!(true);
        events.push(close);
        let out = run(events.clone());
        assert_eq!(out.len(), held + 1, "0xb's reply stays held");
        assert_eq!(
            snapshot(&out[..held]),
            snapshot(&events[..held]),
            "as captured"
        );
        assert_eq!(out[held].data["function"], "CLOSE");
    }

    /// A close that names no connection retires nothing in the parser, and
    /// keyed by thread it could be another connection's.
    #[test]
    fn a_close_without_a_connection_releases_nothing() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        let mut events = reads(GZIP_HEAD, &framed[..framed.len() / 2], 8, 1);
        let mut close = ssl(50, "CLOSE", 1, b"null");
        close.data["connection_closed"] = json!(true);
        events.push(close);
        events.extend(
            reads(b"", &framed[framed.len() / 2..], 8, 60)
                .into_iter()
                .skip(1),
        );
        let out = run(events);
        assert_eq!(out.len(), 2, "{}", snapshot(&out).join("\n"));
        assert_eq!(out[0].data["function"], "CLOSE");
        assert_eq!(split_message(&data_bytes(&out[1])).1, SSE.as_bytes());
    }

    #[test]
    fn a_sized_reply_keeps_its_content_length_line_in_place() {
        for (coding, body) in [
            ("deflate", zlib(SSE.as_bytes())),
            ("deflate", raw_deflate(SSE.as_bytes())),
            ("br", brotli(SSE.as_bytes())),
            ("zstd", zstd::stream::encode_all(SSE.as_bytes(), 3).unwrap()),
            ("x-gzip", gzip(SSE.as_bytes())),
        ] {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\ncontent-encoding: {coding}\r\n\
                 Content-Type: text/event-stream\r\n\r\n",
                body.len()
            );
            let out = run(reads(head.as_bytes(), &body, 7, 5));
            assert_eq!(out.len(), 1, "{coding}");
            let (head, decoded) = split_message(&data_bytes(&out[0]));
            assert_eq!(decoded, SSE.as_bytes(), "{coding}");
            assert_eq!(
                head,
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                     Content-Type: text/event-stream\r\n\r\n",
                    SSE.len()
                )
            );
        }
    }

    #[test]
    fn an_identity_reply_and_requests_pass_untouched() {
        let mut events = reads(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: identity\r\n\r\n",
            &node_chunked(SSE.as_bytes()),
            9,
            1,
        );
        events.extend(reads(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            &node_chunked(SSE.as_bytes()),
            9,
            50,
        ));
        let body = gzip(b"{}");
        let mut request = format!(
            "POST /v1 HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        events.push(ssl(99, "WRITE/SEND", 1, &request));
        assert_eq!(snapshot(&run(events.clone())), snapshot(&events));
    }

    #[test]
    fn a_reply_that_cannot_be_decoded_passes_as_captured() {
        let mut corrupt = gzip(SSE.as_bytes());
        corrupt[20] ^= 0xff;
        corrupt[21] ^= 0xff;
        let mut truncated = gzip(SSE.as_bytes());
        truncated.truncate(truncated.len() - 12);
        let zlib_cut = zlib(SSE.as_bytes())[..30].to_vec();
        for (coding, body) in [
            ("gzip", corrupt),
            ("gzip", truncated),
            ("deflate", zlib_cut),
            ("br", b"not brotli at all".to_vec()),
            ("zstd", b"not zstd".to_vec()),
        ] {
            let head = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: {coding}\r\n\r\n"
            );
            let events = reads(head.as_bytes(), &node_chunked(&body), 11, 3);
            assert_eq!(
                snapshot(&run(events.clone())),
                snapshot(&events),
                "{coding}"
            );
        }
    }

    #[test]
    fn a_decompression_bomb_passes_as_captured() {
        let bomb = gzip(&vec![b'a'; MAX_BODY_BYTES + 1]);
        assert!(bomb.len() < 8 * 1024);
        let events = reads(GZIP_HEAD, &node_chunked(&bomb), 512, 3);
        assert_eq!(snapshot(&run(events.clone())), snapshot(&events));
        // Just under the bound still decodes.
        let fits = gzip(&vec![b'a'; MAX_BODY_BYTES - 200]);
        let out = run(reads(GZIP_HEAD, &node_chunked(&fits), 512, 3));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn stacked_codings_and_close_delimited_replies_are_left_alone() {
        let body = gzip(&gzip(SSE.as_bytes()));
        for head in [
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip, gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Encoding: gzip\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        ] {
            let events = reads(head.as_bytes(), &node_chunked(&body), 16, 3);
            assert_eq!(snapshot(&run(events.clone())), snapshot(&events), "{head}");
        }
    }

    #[test]
    fn a_new_message_before_the_end_releases_the_held_reads_first() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        let mut events = reads(GZIP_HEAD, &framed[..40], 10, 1);
        let next = ssl(90, "READ/RECV", 1, b"HTTP/1.1 204 No Content\r\n\r\n");
        events.push(next);
        assert_eq!(snapshot(&run(events.clone())), snapshot(&events));
    }

    #[test]
    fn other_threads_flow_past_a_held_reply() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        let mut events = reads(GZIP_HEAD, &framed[..40], 10, 1);
        let other = ssl(50, "READ/RECV", 2, b"\x81\x05frame");
        events.push(other.clone());
        events.push(ssl(60, "READ/RECV", 1, &framed[40..]));
        let out = run(events);
        assert_eq!(out.len(), 2);
        assert_eq!(snapshot(&out[..1]), snapshot(&[other]));
        assert_eq!(split_message(&data_bytes(&out[1])).1, SSE.as_bytes());
    }

    async fn chain(events: Vec<Event>) -> Vec<Event> {
        use crate::http1_guard::{Http1FramingGuard, RestoreDiverted};
        let mut stream: EventStream = Box::pin(futures::stream::iter(events));
        let mut analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(Http1FramingGuard::new()),
            Box::new(CompressedReplyDecoder::new()),
            Box::new(HTTPParser::new().disable_raw_data()),
            Box::new(RestoreDiverted),
            Box::new(HTTPDecompressor::new()),
        ];
        for a in analyzers.iter_mut() {
            stream = a.process(stream).await.unwrap();
        }
        stream.collect().await
    }

    fn response(out: &[Event]) -> &Event {
        let responses: Vec<&Event> = out
            .iter()
            .filter(|e| e.data.get("message_type").and_then(Value::as_str) == Some("response"))
            .collect();
        assert_eq!(responses.len(), 1, "{out:?}");
        responses[0]
    }

    #[tokio::test]
    async fn the_parser_reads_the_tool_call_out_of_a_gzip_stream() {
        let framed = node_chunked(&gzip(SSE.as_bytes()));
        let mut events = reads(GZIP_HEAD, &framed[..25], 3, 10);
        // A WebSocket frame on the same thread, between two chunks' reads,
        // is still kept out of the reply by the framing guard.
        let boundary = (26..framed.len())
            .find(|&k| {
                let mut buf = GZIP_HEAD.to_vec();
                buf.extend_from_slice(&framed[..k]);
                matches!(
                    chunk_position(&buf, GZIP_HEAD.len()),
                    Ok((crate::http1_guard::Position::SizeLine, None))
                ) && buf.ends_with(b"\r\n")
            })
            .unwrap();
        events.extend(reads(b"", &framed[25..boundary], 4, 40).into_iter().skip(1));
        events.push(ssl(70, "READ/RECV", 1, b"\x81\x05frame"));
        events.extend(reads(b"", &framed[boundary..], 1, 80).into_iter().skip(1));
        let out = chain(events).await;
        let reply = response(&out);
        let body = reply.data["body"].as_str().unwrap();
        assert_eq!(body, SSE);
        assert!(
            body.contains("\"tool_calls\"") && body.contains("delivery__delivery_track_package")
        );
        let headers = reply.data["headers"].as_object().unwrap();
        assert!(!headers.contains_key("content-encoding"), "{headers:?}");
        assert!(!headers.contains_key("transfer-encoding"), "{headers:?}");
        assert_eq!(headers["content-length"], json!(SSE.len().to_string()));
        assert_eq!(headers["x-request-id"], json!("abc"));
        assert_eq!(reply.timestamp, 10);
        assert!(out
            .iter()
            .any(|e| e.data.get("data").and_then(Value::as_str) == Some("\u{81}\u{5}frame")));
    }

    #[tokio::test]
    async fn a_corrupt_gzip_stream_reaches_the_parser_as_before() {
        let mut corrupt = gzip(SSE.as_bytes());
        corrupt[20] ^= 0xff;
        let events = reads(GZIP_HEAD, &node_chunked(&corrupt), 6, 10);
        let with = chain(events.clone()).await;
        let mut stream: EventStream = Box::pin(futures::stream::iter(events));
        stream = HTTPParser::new()
            .disable_raw_data()
            .process(stream)
            .await
            .unwrap();
        stream = HTTPDecompressor::new().process(stream).await.unwrap();
        let without: Vec<Event> = stream.collect().await;
        assert_eq!(snapshot(&with), snapshot(&without));
        assert_eq!(response(&with).data["headers"]["content-encoding"], "gzip");
    }
}

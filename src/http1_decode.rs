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
    chunk_position, event_bytes, find, header_info, looks_like_http1_start, parse_size,
    MAX_BODY_BYTES, MAX_STREAMS,
};
use agentsight_capture::analyzers::Analyzer;
use agentsight_capture::runners::EventStream;
use agentsight_capture::Event;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;

type Key = (u32, u64, bool);

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
        let tid = event.data.get("tid").and_then(Value::as_u64).unwrap_or(0);
        let key = (event.pid, tid, is_read);
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
            let Some(end) = pending
                .length
                .and_then(|n| pending.head_end.checked_add(n))
            else {
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
                    "pid {} tid {}: a {:?}-encoded reply could not be decoded within {} bytes; \
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
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
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

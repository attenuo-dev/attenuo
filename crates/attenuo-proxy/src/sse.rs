//! Rewriting of `text/event-stream` bodies.
//!
//! A Streamable HTTP server may answer a `POST` with an SSE stream instead of a JSON body. The
//! response to a `tools/list` (or any list request) is then the `data:` of one of the stream's
//! events, possibly after notifications and server requests, possibly inside a JSON-RPC batch.
//! [`rewrite_stream`] parses the stream incrementally, runs a callback over the JSON-RPC
//! message(s) of each event, and emits the event again. Events with no `data`, and comments, are
//! passed through; an event whose `data` does not parse is dropped (SR-80); the stream is never
//! buffered beyond one event.
//!
//! The framing rules are those of the WHATWG SSE specification: lines end in `\n`, `\r\n` or
//! `\r`; an empty line ends an event; several `data:` lines of one event are joined with `\n`;
//! one space after the colon is dropped; a final event that is not terminated by an empty line
//! is discarded (a client would discard it too). A UTF-8 byte order mark that opens the stream
//! is dropped, as clients drop it, and an event that is not UTF-8 ends the stream with an
//! error: a client that decodes leniently would read it, so the proxy must not relay what it
//! could not read (SR-77).

use std::io;

use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::Value;

/// The largest single event the proxy buffers by default (the proxy passes
/// `[proxy] max_upstream_body_bytes`).
pub const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;

/// The UTF-8 byte order mark, which a client drops when it opens an event stream.
const BOM: &[u8] = b"\xef\xbb\xbf";

/// Drop a byte order mark that opens the stream from `buf`. Returns `false` while `buf` is
/// still too short to tell (a strict prefix of the mark): wait for more bytes. `start` is
/// cleared once decided.
fn strip_leading_bom(buf: &mut Vec<u8>, start: &mut bool) -> bool {
    if !*start {
        return true;
    }
    if buf.len() < BOM.len() && BOM.starts_with(buf) {
        return false;
    }
    if buf.starts_with(BOM) {
        buf.drain(..BOM.len());
    }
    *start = false;
    true
}

/// Incremental SSE event splitter and rewriter.
pub struct SseRewriter {
    buf: Vec<u8>,
    limit: usize,
    start: bool,
}

impl Default for SseRewriter {
    fn default() -> Self {
        Self::new()
    }
}

impl SseRewriter {
    pub fn new() -> Self {
        Self::with_limit(MAX_EVENT_BYTES)
    }

    /// Buffer at most `limit` bytes of an incomplete event.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            start: true,
        }
    }

    /// Feed a chunk of the stream; returns the bytes of every event completed by it, rewritten.
    /// `f` is called with the parsed JSON of each event that carries valid JSON `data`, and may
    /// modify it. Such an event is re-serialized (so duplicate object keys cannot survive);
    /// an event with no data is emitted byte for byte, one whose data does not parse is dropped.
    pub fn push(
        &mut self,
        chunk: &[u8],
        f: &mut impl FnMut(&mut Value),
    ) -> Result<Vec<u8>, io::Error> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        if !strip_leading_bom(&mut self.buf, &mut self.start) {
            return Ok(out);
        }
        while let Some(end) = find_event_end(&self.buf) {
            let event: Vec<u8> = self.buf.drain(..end).collect();
            rewrite_event(&event, f, &mut out)?;
        }
        if self.buf.len() > self.limit {
            return Err(io::Error::other("SSE event larger than the proxy's limit"));
        }
        Ok(out)
    }
}

/// Byte offset just past the first complete event in `buf` (past its terminating empty line).
fn find_event_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    let mut line_start = 0;
    while i < buf.len() {
        let term = match buf[i] {
            b'\n' => 1,
            b'\r' => match buf.get(i + 1) {
                Some(b'\n') => 2,
                Some(_) => 1,
                // `\r` last in the buffer: it may be the first half of `\r\n`.
                None => return None,
            },
            _ => {
                i += 1;
                continue;
            }
        };
        let empty_line = i == line_start;
        i += term;
        if empty_line {
            return Some(i);
        }
        line_start = i;
    }
    None
}

fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                lines.push(&text[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                lines.push(&text[start..i]);
                i += if bytes.get(i + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Split `buf`, which holds whole events (as [`frame_stream`] and [`rewrite_stream`] emit
/// them), into those events, each with its terminating empty line. Trailing bytes that do not
/// end an event are returned as a last element, unchanged.
pub(crate) fn split_events(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = buf;
    while let Some(end) = find_event_end(rest) {
        let (event, tail) = rest.split_at(end);
        out.push(event);
        rest = tail;
    }
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

/// The JSON of an event's `data`, if it has data that parses as JSON (the same reading as
/// [`SseRewriter`]).
pub(crate) fn event_json(event: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(event).ok()?;
    let lines = split_lines(text);
    let data = data_lines(&lines);
    (!data.is_empty())
        .then(|| parse_data(&data.join("\n")))
        .flatten()
}

/// Parse an event's joined `data` as JSON the way clients do. `serde_json` refuses a `\u`
/// escape of a UTF-16 surrogate without its pair (`"\ud800"`), which `JSON.parse` and
/// Python's `json` accept, so a message the proxy could not parse would still be read by
/// those clients, unlabelled and unrewritten (SR-78). Such an escape is read as U+FFFD, as
/// `JSON.parse` would print it; everything else is parsed as is.
pub(crate) fn parse_data(text: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => Some(v),
        Err(_) if text.contains("\\u") => {
            serde_json::from_str::<Value>(&replace_lone_surrogates(text)).ok()
        }
        Err(_) => None,
    }
}

/// `text` with every `\uXXXX` escape of an unpaired UTF-16 surrogate replaced by `\ufffd`.
/// A backslash is only valid JSON inside a string, so escapes are found without tracking
/// strings: each `\` takes the character after it.
fn replace_lone_surrogates(text: &str) -> String {
    fn unit(b: &[u8], at: usize) -> Option<u16> {
        let hex = b.get(at..at + 6)?;
        if hex[0] != b'\\' || hex[1] != b'u' {
            return None;
        }
        u16::from_str_radix(std::str::from_utf8(&hex[2..]).ok()?, 16).ok()
    }
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        match unit(b, i) {
            // A pair: kept.
            Some(0xD800..=0xDBFF) if matches!(unit(b, i + 6), Some(0xDC00..=0xDFFF)) => i += 12,
            Some(0xD800..=0xDFFF) => {
                out.push_str(&text[copied..i]);
                out.push_str("\\ufffd");
                i += 6;
                copied = i;
            }
            Some(_) => i += 6,
            None => i += 2,
        }
    }
    out.push_str(&text[copied.min(text.len())..]);
    out
}

/// Does `event` carry data (at least one `data` line)? True for an event that is not UTF-8,
/// whose lines the proxy cannot read. With [`event_json`], tells an event whose data the proxy
/// could not parse, which a client with another JSON parser may still read (SR-79).
pub(crate) fn has_data(event: &[u8]) -> bool {
    std::str::from_utf8(event).map_or(true, |text| !data_lines(&split_lines(text)).is_empty())
}

/// One `message` event carrying `message` as its data.
pub(crate) fn message_event(message: &Value) -> Vec<u8> {
    format!(
        "event: message\ndata: {}\n\n",
        serde_json::to_string(message).unwrap_or_default()
    )
    .into_bytes()
}

/// The values of an event's `data` lines.
fn data_lines<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("data"))
        .filter_map(|rest| {
            // `data:value` or `data: value`; a bare `data` line is an empty data line.
            if rest.is_empty() {
                Some("")
            } else {
                rest.strip_prefix(':')
                    .map(|v| v.strip_prefix(' ').unwrap_or(v))
            }
        })
        .collect()
}

/// Run `f` over the JSON `data` of one whole `event` and write the event to `out`: re-encoded
/// (other fields kept) when the data is JSON, byte for byte when it has no data, and not at
/// all when its data does not parse (SR-80).
pub(crate) fn rewrite_event(
    event: &[u8],
    f: &mut impl FnMut(&mut Value),
    out: &mut Vec<u8>,
) -> Result<(), io::Error> {
    let text = std::str::from_utf8(event)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SSE event is not UTF-8"))?;
    let lines = split_lines(text);
    let data = data_lines(&lines);
    let parsed = (!data.is_empty())
        .then(|| parse_data(&data.join("\n")))
        .flatten();
    let Some(mut message) = parsed else {
        if data.is_empty() {
            out.extend_from_slice(event);
        } else {
            // Data the proxy cannot parse, which a client with another JSON parser may still
            // read: `f` never saw it, so it is not relayed (SR-80).
            tracing::warn!(
                bytes = event.len(),
                "upstream SSE event whose data does not parse; dropped"
            );
        }
        return Ok(());
    };
    f(&mut message);
    let encoded = serde_json::to_string(&message)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut wrote_data = false;
    for line in lines.iter().filter(|l| !l.is_empty()) {
        let is_data = line
            .strip_prefix("data")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'));
        if is_data {
            if !wrote_data {
                out.extend_from_slice(format!("data: {encoded}\n").as_bytes());
                wrote_data = true;
            }
        } else {
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
    }
    out.push(b'\n');
    Ok(())
}

/// Incremental SSE event splitter that emits complete events byte for byte, holding back a
/// partial one. Used where the proxy relays a stream unchanged but must be able to append an
/// event of its own at any point (see [`crate::guard`]).
pub struct SseFramer {
    buf: Vec<u8>,
    limit: usize,
    start: bool,
}

impl Default for SseFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl SseFramer {
    pub fn new() -> Self {
        Self::with_limit(MAX_EVENT_BYTES)
    }

    /// Buffer at most `limit` bytes of an incomplete event.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            start: true,
        }
    }

    /// Feed a chunk; returns the bytes of every event it completes, unchanged, but for a byte
    /// order mark that opens the stream, which is dropped. An event that is not UTF-8 is an
    /// error (SR-77): what the proxy relays, it must have been able to read.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, io::Error> {
        self.buf.extend_from_slice(chunk);
        if !strip_leading_bom(&mut self.buf, &mut self.start) {
            return Ok(Vec::new());
        }
        let mut end = 0;
        while let Some(n) = find_event_end(&self.buf[end..]) {
            end += n;
        }
        if self.buf.len() - end > self.limit {
            return Err(io::Error::other("SSE event larger than the proxy's limit"));
        }
        // Whole events end in a line break, so no character is split at `end`.
        if std::str::from_utf8(&self.buf[..end]).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSE event is not UTF-8",
            ));
        }
        Ok(self.buf.drain(..end).collect())
    }
}

/// Run every chunk of `upstream` through `push` and emit what it returns, skipping empty
/// output. A transport error or an error from `push` ends the stream with that error.
fn process_stream<S, E>(
    upstream: S,
    push: impl FnMut(&[u8]) -> Result<Vec<u8>, io::Error> + Send + 'static,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    futures_util::stream::unfold(
        (upstream, push, false),
        |(mut upstream, mut push, failed)| async move {
            if failed {
                return None;
            }
            loop {
                match upstream.next().await {
                    None => return None,
                    Some(Err(e)) => {
                        return Some((Err(io::Error::other(e)), (upstream, push, true)))
                    }
                    Some(Ok(chunk)) => match push(&chunk) {
                        Err(e) => return Some((Err(e), (upstream, push, true))),
                        Ok(out) if out.is_empty() => continue,
                        Ok(out) => return Some((Ok(Bytes::from(out)), (upstream, push, false))),
                    },
                }
            }
        },
    )
}

/// Wrap an upstream byte stream so that every JSON-RPC message in its events passes through
/// `f`. A trailing event without its empty line is dropped; a transport error, an event over
/// `limit` bytes or a non-UTF-8 event ends the stream with an error.
pub fn rewrite_stream<S, E>(
    upstream: S,
    limit: usize,
    mut f: impl FnMut(&mut Value) + Send + 'static,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut rewriter = SseRewriter::with_limit(limit);
    process_stream(upstream, move |chunk| rewriter.push(chunk, &mut f))
}

/// Wrap an upstream byte stream so that it yields whole events only, unchanged but for a
/// leading byte order mark, which is dropped. A trailing event without its empty line is
/// dropped (a client would discard it too); a transport error, an event over `limit` bytes or
/// a non-UTF-8 event ends the stream with an error.
pub fn frame_stream<S, E>(
    upstream: S,
    limit: usize,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut framer = SseFramer::with_limit(limit);
    process_stream(upstream, move |chunk| framer.push(chunk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(chunks: &[&[u8]]) -> String {
        let mut r = SseRewriter::new();
        let mut out = Vec::new();
        let mut f = |v: &mut Value| {
            if v.get("mark").is_some() {
                v["marked"] = json!(true);
            }
        };
        for c in chunks {
            out.extend(r.push(c, &mut f).unwrap());
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn rewrites_data_and_keeps_other_fields() {
        let out = run(&[b"id: 7\nevent: message\ndata: {\"mark\":1}\n\n"]);
        assert_eq!(
            out,
            "id: 7\nevent: message\ndata: {\"mark\":1,\"marked\":true}\n\n"
        );
    }

    #[test]
    fn handles_chunks_split_anywhere() {
        let whole = "event: message\r\ndata: {\"mark\":1}\r\n\r\n: ping\n\ndata: {\"x\":2}\n\n";
        let expected = run(&[whole.as_bytes()]);
        for cut in 0..whole.len() {
            let (a, b) = whole.as_bytes().split_at(cut);
            assert_eq!(run(&[a, b]), expected, "cut at {cut}");
        }
        assert!(expected.contains("\"marked\":true"));
        assert!(expected.contains(": ping\n\n"));
    }

    #[test]
    fn multi_line_data_is_joined_and_collapsed() {
        let out = run(&[b"data: {\"mark\":\ndata: 1}\n\n"]);
        assert_eq!(out, "data: {\"mark\":1,\"marked\":true}\n\n");
    }

    #[test]
    fn data_without_space_and_cr_only_line_ends() {
        // A final lone `\r` could be half of `\r\n`, so it is held back until more arrives.
        let out = run(&[b"data:{\"mark\":1}\r\r", b"data: 2\n\n"]);
        assert_eq!(out, "data: {\"mark\":1,\"marked\":true}\n\ndata: 2\n\n");
    }

    #[test]
    fn data_less_events_pass_through_and_unparsed_data_is_dropped_sr80() {
        let input = ": comment\n\nretry: 5\n\n";
        assert_eq!(run(&[input.as_bytes()]), input);
        // Not JSON, or nested deeper than `serde_json` allows: dropped, the rest kept.
        let deep = format!("data: {}{}\n\n", "[".repeat(200), "]".repeat(200));
        let mixed = format!("data: not json\n\n{deep}: comment\n\ndata: {{\"a\":1}}\n\n");
        assert_eq!(run(&[mixed.as_bytes()]), ": comment\n\ndata: {\"a\":1}\n\n");
    }

    #[test]
    fn unterminated_trailing_event_is_dropped() {
        assert_eq!(
            run(&[b"data: {\"a\":1}\n\ndata: {\"mark\":1}\n"]),
            "data: {\"a\":1}\n\n"
        );
    }

    #[test]
    fn duplicate_keys_do_not_survive() {
        let out = run(&[b"data: {\"id\":1,\"id\":2}\n\n"]);
        assert_eq!(out, "data: {\"id\":2}\n\n");
    }

    #[test]
    fn oversized_event_is_an_error() {
        let mut r = SseRewriter::new();
        let big = vec![b'a'; MAX_EVENT_BYTES + 1];
        assert!(r.push(&big, &mut |_| {}).is_err());
    }

    #[test]
    fn the_event_limit_is_configurable_sr36() {
        let mut r = SseRewriter::with_limit(8);
        assert!(r.push(b"data: 1\n\n", &mut |_| {}).is_ok());
        assert!(r.push(b"data: 123456789", &mut |_| {}).is_err());
        let mut f = SseFramer::with_limit(8);
        assert!(f.push(b"data: 123456789").is_err());
    }

    #[test]
    fn non_utf8_event_is_an_error() {
        let mut r = SseRewriter::new();
        assert!(r.push(b"data: \xff\xfe\n\n", &mut |_| {}).is_err());
    }

    #[test]
    fn a_leading_bom_is_dropped_and_a_non_utf8_event_is_refused_sr77() {
        let whole = b"\xef\xbb\xbfdata: {\"a\":1}\n\n";
        for cut in 0..whole.len() {
            let (a, b) = whole.split_at(cut);
            let mut f = SseFramer::new();
            let mut out = f.push(a).unwrap();
            out.extend(f.push(b).unwrap());
            assert_eq!(out, b"data: {\"a\":1}\n\n", "framer, cut at {cut}");
            let mut r = SseRewriter::new();
            let mut seen = 0;
            let mut out = r.push(a, &mut |_: &mut Value| seen += 1).unwrap();
            out.extend(r.push(b, &mut |_: &mut Value| seen += 1).unwrap());
            assert_eq!(seen, 1, "rewriter, cut at {cut}");
            assert_eq!(out, b"data: {\"a\":1}\n\n", "rewriter, cut at {cut}");
        }
        // Only the stream's first bytes: a later mark is an ordinary (unknown) field name.
        let mut f = SseFramer::new();
        assert_eq!(f.push(b"data: 1\n\n").unwrap(), b"data: 1\n\n");
        let later = b"\xef\xbb\xbfdata: 2\n\n";
        assert_eq!(f.push(later).unwrap(), later);
        // Not UTF-8, in a comment or in the data: the stream ends with an error.
        for event in [&b": \xff\ndata: {}\n\n"[..], &b"data: \"\xc3\"\n\n"[..]] {
            let mut f = SseFramer::new();
            assert!(f.push(b"data: ok\n\n").is_ok());
            assert!(f.push(event).is_err(), "{event:?}");
        }
        // A character split across chunks is fine once its event is whole.
        let mut f = SseFramer::new();
        assert!(f.push(b"data: \"\xc3").unwrap().is_empty());
        assert_eq!(
            f.push(b"\xa9\"\n\n").unwrap(),
            "data: \"\u{e9}\"\n\n".as_bytes()
        );
    }

    #[test]
    fn a_lone_surrogate_escape_is_read_as_a_replacement_character_sr78() {
        assert_eq!(parse_data(r#""\ud800""#), Some(json!("\u{fffd}")));
        assert_eq!(
            parse_data(r#""\udc00x\ud800""#),
            Some(json!("\u{fffd}x\u{fffd}"))
        );
        // A pair is kept, and so is an escaped backslash before a `u`.
        assert_eq!(parse_data(r#""\ud83d\ude00""#), Some(json!("\u{1f600}")));
        assert_eq!(
            parse_data(r#""\ud800\ud83d\ude00""#),
            Some(json!("\u{fffd}\u{1f600}"))
        );
        assert_eq!(parse_data(r#""\\ud800""#), Some(json!("\\ud800")));
        // Still not JSON.
        assert_eq!(parse_data(r#""\ud800"#), None);
        assert_eq!(parse_data("\\u"), None);
        assert_eq!(parse_data(r#""\u12""#), None);
    }

    #[test]
    fn framer_emits_whole_events_unchanged() {
        let whole = "event: message\r\ndata: {\"a\":1}\r\n\r\n: ping\n\ndata: x\rdata: y\r\r\n";
        for cut in 0..whole.len() {
            let (a, b) = whole.as_bytes().split_at(cut);
            let mut f = SseFramer::new();
            let mut out = f.push(a).unwrap();
            out.extend(f.push(b).unwrap());
            out.extend(f.push(b"\n").unwrap());
            assert_eq!(out, format!("{whole}\n").as_bytes(), "cut at {cut}");
        }
        let mut f = SseFramer::new();
        assert_eq!(f.push(b"data: 1\n\ndata: 2\n").unwrap(), b"data: 1\n\n");
        assert_eq!(f.push(b"\n").unwrap(), b"data: 2\n\n");
        assert!(SseFramer::new()
            .push(&vec![b'a'; MAX_EVENT_BYTES + 1])
            .is_err());
    }

    #[tokio::test]
    async fn stream_wrapper_rewrites_and_stops_on_error() {
        let chunks: Vec<Result<Bytes, io::Error>> = vec![
            Ok(Bytes::from_static(b"data: {\"mark\":1}\n")),
            Ok(Bytes::from_static(b"\n")),
            Err(io::Error::other("boom")),
        ];
        let mut s = Box::pin(rewrite_stream(
            futures_util::stream::iter(chunks),
            MAX_EVENT_BYTES,
            |v: &mut Value| v["marked"] = json!(true),
        ));
        let first = s.next().await.unwrap().unwrap();
        assert_eq!(&first[..], b"data: {\"mark\":1,\"marked\":true}\n\n");
        assert!(s.next().await.unwrap().is_err());
        assert!(s.next().await.is_none());
    }
}

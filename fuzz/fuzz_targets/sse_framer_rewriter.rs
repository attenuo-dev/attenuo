//! The SSE code security pass 7 changed (#124): `SseFramer::push`, `SseRewriter::push`,
//! `strip_leading_bom`, `rewrite_event`, `has_data`, and the stream-end guard's
//! `disown_events` / `may_hold_stream_end_code`, on arbitrary bytes split at arbitrary points.
//!
//! Invariants: no panic; `strip_leading_bom` leaves the same bytes whatever the chunking; the
//! framer's output is the input less a leading BOM, cut at event ends, and is a run of whole
//! UTF-8 events; the rewriter's output does not depend on the chunking and is at most a
//! bounded multiple of its input; `rewrite_event` relays a data-less event byte for byte and
//! drops one whose data does not parse; `may_hold_stream_end_code` never misses a JSON number
//! equal to -32001; and after `disown_events` no whole event a client can parse has the
//! stream-end shape.
#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_proxy::fuzzing::{
    disown_events, event_json, has_data, may_hold_stream_end_code, rewrite_event, split_events,
    strip_leading_bom,
};
use attenuo_proxy::guard::has_stream_end_shape;
use attenuo_proxy::sse::{SseFramer, SseRewriter};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const BOM: &[u8] = b"\xef\xbb\xbf";

const CODES: &[&str] = &[
    "-32001",
    "-32001.0",
    "-32001e0",
    "-3.2001e4",
    "-3.2001E+4",
    "-0.32001e5",
    "-320010e-1",
    "-32000.99999999999999999",
    "-32001.0000000000000001",
    "-0.0000032001e10",
    "-32001.00000000000000000000000000001",
    "-32002",
    "32001",
];

#[derive(Debug)]
struct Input {
    stream: Vec<u8>,
    cuts: Vec<u16>,
    limit: usize,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut stream: Vec<u8> = Vec::new();
        if u.arbitrary()? {
            stream = u.arbitrary()?;
        } else {
            if u.arbitrary()? {
                stream.extend_from_slice(BOM);
            }
            for _ in 0..u.int_in_range(0usize..=5)? {
                let nl = *u.choose(&["\n", "\r\n", "\r"])?;
                let code = *u.choose(CODES)?;
                let id = *u.choose(&["null", "1", "\"x\""])?;
                let body = match u.int_in_range(0u8..=4)? {
                    0 => format!(
                        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":"m"}}}}"#
                    ),
                    1 => format!(
                        r#"[{{"jsonrpc":"2.0","error":{{"code":{code},"message":"\ud800"}}}}]"#
                    ),
                    2 => format!(
                        r#"{{"jsonrpc":"2.0","error":{{"code":{code},"message":"\udc00😀"}}}}"#
                    ),
                    3 => format!(r#"{{"jsonrpc":"2.0","result":{{"n":1e9,"s":"é"}},"id":{id}}}"#),
                    _ => String::from_utf8_lossy(u.arbitrary::<&[u8]>()?).into_owned(),
                };
                if u.arbitrary()? {
                    stream.extend_from_slice(format!("event: message{nl}id: 7{nl}").as_bytes());
                }
                let sep = *u.choose(&["data:", "data: ", "data:  ", "data"])?;
                if u.arbitrary()? {
                    // Split the body over two data lines.
                    let at = (0..=body.len() / 2)
                        .rev()
                        .find(|i| body.is_char_boundary(*i))
                        .unwrap_or(0);
                    stream.extend_from_slice(format!("{sep}{}{nl}", &body[..at]).as_bytes());
                    stream.extend_from_slice(format!("data:{}{nl}", &body[at..]).as_bytes());
                } else {
                    stream.extend_from_slice(format!("{sep}{body}{nl}").as_bytes());
                }
                stream.extend_from_slice(nl.as_bytes());
            }
            let tail: Vec<u8> = u.arbitrary()?;
            stream.extend_from_slice(&tail);
        }
        Ok(Input {
            stream,
            cuts: u.arbitrary()?,
            limit: *u.choose(&[8usize, 64, 4096, usize::MAX])?,
        })
    }
}

fn chunks<'a>(data: &'a [u8], cuts: &[u16]) -> Vec<&'a [u8]> {
    let mut points: Vec<usize> = cuts
        .iter()
        .map(|c| *c as usize % (data.len() + 1))
        .collect();
    points.sort_unstable();
    let mut out = Vec::new();
    let mut last = 0;
    for p in points {
        out.push(&data[last..p]);
        last = p;
    }
    out.push(&data[last..]);
    out
}

/// Does a message a client could read from `event` have the stream-end shape?
fn shaped(event: &[u8]) -> bool {
    match event_json(event) {
        Some(Value::Array(items)) => items.iter().any(has_stream_end_shape),
        Some(v) => has_stream_end_shape(&v),
        None => false,
    }
}

/// Is there a `-` in `event` followed by a JSON number equal to -32001?
fn holds_code(event: &[u8]) -> bool {
    event.iter().enumerate().any(|(i, &b)| {
        if b != b'-' {
            return false;
        }
        let run: Vec<u8> = event[i + 1..]
            .iter()
            .copied()
            .take_while(|c| c.is_ascii_digit() || b".eE+-".contains(c))
            .take(64)
            .collect();
        (1..=run.len()).any(|n| {
            let mut text = b"-".to_vec();
            text.extend_from_slice(&run[..n]);
            serde_json::from_slice::<f64>(&text).is_ok_and(|v| v == -32001.0)
        })
    })
}

/// Does `e` end with the empty line that closes an event?
fn ends_event(e: &[u8]) -> bool {
    // A line end (`\n`, `\r` or `\r\n`) followed by an empty line.
    let ends: [&[u8]; 5] = [b"\n\n", b"\n\r", b"\r\r", b"\n\r\n", b"\r\r\n"];
    ends.iter().any(|end| e.ends_with(end)) || e == b"\n" || e == b"\r\n" || e == b"\r"
}

fuzz_target!(|input: Input| {
    let parts = chunks(&input.stream, &input.cuts);
    let unbom = input.stream.strip_prefix(BOM).unwrap_or(&input.stream);

    // strip_leading_bom: the same bytes left whatever the chunking.
    let mut buf = Vec::new();
    let mut start = true;
    for p in &parts {
        buf.extend_from_slice(p);
        let decided = strip_leading_bom(&mut buf, &mut start);
        assert_eq!(decided, !start, "decided but still at the start");
    }
    if start {
        assert!(input.stream.len() < BOM.len() && BOM.starts_with(&input.stream));
    } else {
        assert_eq!(buf, unbom, "BOM strip depends on chunking");
    }

    // Framer: whole UTF-8 events of the BOM-less input, identical for any chunking.
    let mut framer = SseFramer::with_limit(input.limit);
    let mut framed = Vec::new();
    let mut framer_failed = false;
    for p in &parts {
        match framer.push(p) {
            Ok(out) => framed.extend_from_slice(&out),
            Err(_) => {
                framer_failed = true;
                break;
            }
        }
    }
    assert!(unbom.starts_with(&framed), "framer altered the stream");
    assert!(
        std::str::from_utf8(&framed).is_ok(),
        "framer relayed non-UTF-8"
    );
    for e in split_events(&framed) {
        assert!(ends_event(e), "framed output is not whole events: {e:?}");
    }
    if !framer_failed {
        let mut whole = SseFramer::with_limit(usize::MAX);
        assert_eq!(whole.push(&input.stream).unwrap(), framed);
    }

    // Rewriter: chunking-independent, bounded growth.
    let run = |ps: &[&[u8]]| -> (Vec<u8>, bool) {
        let mut rw = SseRewriter::with_limit(usize::MAX);
        let mut out = Vec::new();
        for p in ps {
            match rw.push(p, &mut |_| {}) {
                Ok(o) => out.extend(o),
                Err(_) => return (out, false),
            }
        }
        (out, true)
    };
    let (a, a_ok) = run(&parts);
    let (b, b_ok) = run(&[&input.stream[..]]);
    assert_eq!(a_ok, b_ok, "SSE rewrite error depends on chunking");
    if a_ok {
        assert_eq!(a, b, "SSE rewrite depends on chunking");
    }
    // A number re-printed grows at most from `1e15` (4 bytes) to `1000000000000000.0` (18),
    // and a bare `data` line gains `: `, so 5x plus a little bounds it.
    assert!(
        a.len() <= 5 * input.stream.len() + 8,
        "rewriter output {} bytes from {} input bytes",
        a.len(),
        input.stream.len()
    );
    let mut limited = SseRewriter::with_limit(input.limit);
    for p in &parts {
        if limited.push(p, &mut |_| {}).is_err() {
            break;
        }
    }

    // Per event: has_data, rewrite_event, and the stream-end scan.
    for e in split_events(&input.stream) {
        let parsed = event_json(e);
        if parsed.is_some() {
            assert!(has_data(e), "parsed data from an event without data");
        }
        let mut out = Vec::new();
        let mut saw = false;
        match rewrite_event(e, &mut |_| saw = true, &mut out) {
            Err(_) => assert!(std::str::from_utf8(e).is_err()),
            Ok(()) => {
                assert_eq!(saw, parsed.is_some());
                if !has_data(e) {
                    assert_eq!(out, e, "a data-less event was changed");
                } else if parsed.is_none() {
                    assert!(out.is_empty(), "unparsed data was relayed");
                }
            }
        }
        if holds_code(e) {
            assert!(may_hold_stream_end_code(e), "scan missed -32001 in {e:?}");
        }
        if shaped(e) {
            assert!(
                may_hold_stream_end_code(e),
                "scan missed a stream-end shape in {e:?}"
            );
        }
    }

    // disown_events: no whole event a client parses keeps the stream-end shape.
    for chunk in [&framed[..], &input.stream[..]] {
        let disowned = disown_events(chunk);
        for e in split_events(&disowned) {
            if ends_event(e) {
                assert!(!shaped(e), "stream-end shape survived disown_events: {e:?}");
            }
        }
        assert_eq!(
            disown_events(&disowned),
            disowned,
            "disown_events is not idempotent"
        );
    }
});

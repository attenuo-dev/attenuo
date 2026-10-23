//! The proxy's incremental SSE parsers (`SseRewriter`, `SseFramer`) and list filter
//! (`ListFilter`) on arbitrary upstream bytes split into arbitrary chunks.
//!
//! Invariants: no panic; the framer emits the input unchanged, cut only at event boundaries,
//! and never buffers past its limit; the rewriter's output does not depend on how the stream
//! was chunked; and after filtering, no `tools/list` answer to a pending request carries a tool
//! the capabilities could not permit.
#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use attenuo_core::{Capability, CapabilitySet};
use attenuo_proxy::filter::{could_permit_tool, ListFilter, ListKind};
use attenuo_proxy::sse::{SseFramer, SseRewriter};
use serde_json::{json, Value};

#[derive(Debug)]
struct Input {
    stream: Vec<u8>,
    cuts: Vec<u16>,
    limit: usize,
    pending: Vec<(Value, u8)>,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut stream: Vec<u8> = Vec::new();
        if u.arbitrary()? {
            stream = u.arbitrary()?;
        } else {
            for _ in 0..u.int_in_range(0usize..=6)? {
                let id = u
                    .choose(&[json!(1), json!(1.0), json!("1"), json!(2), Value::Null])?
                    .clone();
                let msg = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [
                    {"name": "read_file"}, {"name": "delete_repo"}, {"name": 5}, {}
                ]}});
                let nl = *u.choose(&["\n", "\r\n", "\r"])?;
                if u.arbitrary()? {
                    stream.extend_from_slice(format!(": comment{nl}").as_bytes());
                }
                if u.arbitrary()? {
                    stream.extend_from_slice(format!("event: message{nl}id: 7{nl}").as_bytes());
                }
                let text = if u.arbitrary()? {
                    msg.to_string()
                } else {
                    serde_json::to_string_pretty(&msg).unwrap()
                };
                for line in text.split('\n') {
                    let sep = *u.choose(&["data:", "data: ", "data:  "])?;
                    stream.extend_from_slice(format!("{sep}{line}{nl}").as_bytes());
                }
                stream.extend_from_slice(nl.as_bytes());
            }
            let tail: Vec<u8> = u.arbitrary()?;
            stream.extend_from_slice(&tail);
        }
        Ok(Input {
            stream,
            cuts: u.arbitrary()?,
            limit: *u.choose(&[16usize, 256, 4096, 1 << 20])?,
            pending: u
                .arbitrary::<Vec<(u8, u8)>>()?
                .into_iter()
                .map(|(i, k)| (json!(i % 3), k))
                .collect(),
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

fuzz_target!(|input: Input| {
    let caps = CapabilitySet::from_iter([Capability::new("fuzz", "read_*")]);
    let kinds = ListKind::ALL;
    let pending: Vec<(Value, ListKind)> = input
        .pending
        .iter()
        .map(|(id, k)| (id.clone(), kinds[*k as usize % kinds.len()]))
        .collect();
    let filter = ListFilter::new(&pending, &caps, "fuzz");

    // Framer: output is a prefix of the input, cut at event ends, the same for any chunking.
    let mut framer = SseFramer::with_limit(input.limit);
    let mut framed = Vec::new();
    let mut framer_failed = false;
    for c in chunks(&input.stream, &input.cuts) {
        match framer.push(c) {
            Ok(out) => framed.extend_from_slice(&out),
            Err(_) => {
                framer_failed = true;
                break;
            }
        }
    }
    assert!(
        input.stream.starts_with(&framed),
        "framer altered the stream"
    );
    if !framer_failed {
        let mut whole = SseFramer::with_limit(usize::MAX);
        assert_eq!(whole.push(&input.stream).unwrap(), framed);
    }

    // Rewriter: filter every event's JSON, then check nothing unpermitted is left.
    let run = |parts: Vec<&[u8]>| -> Option<Vec<u8>> {
        let mut rw = SseRewriter::with_limit(usize::MAX);
        let mut out = Vec::new();
        let mut f = |msg: &mut Value| {
            filter.apply(msg);
            if let Value::Array(items) = msg {
                for m in items {
                    check_filtered(m, &pending, &caps);
                }
            } else {
                check_filtered(msg, &pending, &caps);
            }
        };
        for p in parts {
            out.extend(rw.push(p, &mut f).ok()?);
        }
        Some(out)
    };
    let a = run(chunks(&input.stream, &input.cuts));
    let b = run(vec![&input.stream[..]]);
    assert_eq!(a, b, "SSE rewrite depends on chunking");

    let mut limited = SseRewriter::with_limit(input.limit);
    for c in chunks(&input.stream, &input.cuts) {
        if limited.push(c, &mut |_| {}).is_err() {
            break;
        }
    }

    // The filter on arbitrary JSON.
    if let Ok(mut v) = serde_json::from_slice::<Value>(&input.stream) {
        let _ = filter.listed_tool_names(&v);
        filter.apply(&mut v);
    }
});

fn check_filtered(msg: &Value, pending: &[(Value, ListKind)], caps: &CapabilitySet) {
    if msg.get("method").is_some() {
        return;
    }
    let Some(id) = msg.get("id") else { return };
    if !pending
        .iter()
        .any(|(p, k)| p == id && *k == ListKind::Tools)
    {
        return;
    }
    if let Some(tools) = msg.pointer("/result/tools").and_then(Value::as_array) {
        for t in tools {
            let name = t.get("name").and_then(Value::as_str);
            assert!(
                name.is_some_and(|n| could_permit_tool(caps, "fuzz", n)),
                "unfiltered tool in a tools/list answer: {t}"
            );
        }
    }
}

//! `parse_data` and `replace_lone_surrogates` (security pass 7, SR-78) on arbitrary text and
//! on JSON strings built from surrogate escapes.
//!
//! Invariants: no panic; when `serde_json` accepts the text, `parse_data` returns the same
//! value and `replace_lone_surrogates` leaves the text alone; text without `\u` is never
//! changed; the replacement keeps the length; a result is JSON that round-trips; and a JSON
//! string literal of escapes (paired or not) always parses.
#![no_main]

use arbitrary::{Result, Unstructured};
use attenuo_proxy::fuzzing::{parse_data, replace_lone_surrogates};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const PIECES: &[&str] = &[
    "a",
    "\\ud800",
    "\\udbff",
    "\\udc00",
    "\\udfff",
    "\\ud83d\\ude00",
    "\\ud83d",
    "\\ude00",
    "\\\\",
    "\\\\ud800",
    "\\u0041",
    "\\uD800",
    "\\uDC00",
    "\\uFFFD",
    "\\n",
    "\\\"",
    "é",
    "\\/",
];

fn build(u: &mut Unstructured) -> Result<(String, bool)> {
    if u.arbitrary()? {
        let s: &str = u.arbitrary()?;
        return Ok((s.to_owned(), false));
    }
    let mut s = String::from("\"");
    for _ in 0..u.int_in_range(0usize..=12)? {
        s.push_str(u.choose(PIECES)?);
    }
    s.push('"');
    if u.arbitrary()? {
        s = format!("{{\"k\":[{s},1,{s}]}}");
    }
    Ok((s, true))
}

fn check(text: &str, literal: bool) {
    let parsed = parse_data(text);
    let replaced = replace_lone_surrogates(text);
    assert_eq!(replaced.len(), text.len(), "replacement changed the length");
    if !text.contains("\\u") {
        assert_eq!(replaced, text, "changed a text without \\u");
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        assert_eq!(
            parsed.as_ref(),
            Some(&v),
            "parse_data differs from serde_json"
        );
        assert_eq!(replaced, text, "changed a text serde_json accepts");
    }
    if let Some(v) = &parsed {
        let again: Value = serde_json::from_str(&serde_json::to_string(v).unwrap()).unwrap();
        assert_eq!(&again, v, "result does not round-trip");
        // No lone surrogate escape survives: the replaced text parses with serde_json alone.
        assert!(serde_json::from_str::<Value>(&replaced).is_ok());
    }
    if literal {
        assert!(
            parsed.is_some(),
            "a JSON literal of escapes did not parse: {text}"
        );
    }
    // Idempotent.
    assert_eq!(replace_lone_surrogates(&replaced), replaced);
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok((text, literal)) = build(&mut u) {
        check(&text, literal);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        check(text, false);
    }
});

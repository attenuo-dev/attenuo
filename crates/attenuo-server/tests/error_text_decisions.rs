//! No refusal is classified by its words: the server and the proxy never choose an HTTP status,
//! an error class, a code, a retry or a security decision by matching the text of an error
//! (its message, `detail` or `description`). They match on a typed value instead (an enum
//! variant, or a code carried on the error), so rewording a message cannot change what a
//! client is told.
//!
//! This is a source scan, like `error_codes.rs`. It flags, in the non-test sources of
//! `crates/attenuo-server/src` and `crates/attenuo-proxy/src`, a string comparison
//! (`.contains("`, `.starts_with("`, `.ends_with("`, `== Some("`, `!= Some("`, `== "`,
//! `!= "`) whose receiver names an error's text: `msg`, `message`, `detail`, `description`,
//! `e`, `err`, `error`, `text` or anything ending in `.to_string()`, and a `match` on such a
//! text (`.to_string()`, a text field, or `.as_str()` of one). A comparison that is not a
//! decision on an error's words but trips it is listed in [`ALLOWED`] with why.
//!
//! What it cannot catch: text matched under another variable name (`let t = e.to_string();
//! t.contains(…)`), a comparison split over lines so that the receiver is on an earlier line,
//! `str::find` or a hand-written loop, a `matches!` on an error's text, or a decision made in
//! a crate it does not scan. It is a tripwire for the usual shape, not a proof; review still
//! applies.

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, without its `#[cfg(test)] mod tests` tail and without the
/// files that are tests or test doubles (`*_tests.rs`, `testing.rs`).
fn sources(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let name = p.file_name().unwrap().to_string_lossy();
                if name == "testing.rs" || name.ends_with("_tests.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap();
                let text = match text.find("#[cfg(test)]\nmod tests") {
                    Some(i) => text[..i].to_string(),
                    None => text,
                };
                out.push((p, text));
            }
        }
    }
    out
}

/// The string comparisons the scan looks for.
const COMPARISONS: &[&str] = &[
    ".contains(\"",
    ".starts_with(\"",
    ".ends_with(\"",
    "== Some(\"",
    "!= Some(\"",
    "== \"",
    "!= \"",
];

/// Names whose text is an error's words.
const TEXT_NAMES: &[&str] = &[
    "msg",
    "message",
    "detail",
    "description",
    "e",
    "err",
    "error",
    "text",
];

/// The expression just before `at` in `line`: back to an opening bracket, a space or an
/// operator, with whole bracketed groups (such as `to_string()`) kept.
fn receiver(line: &str, at: usize) -> &str {
    let b = line.as_bytes();
    let at = line[..at].trim_end().len();
    let mut i = at;
    let mut depth = 0usize;
    while i > 0 {
        let c = b[i - 1];
        match c {
            b')' | b']' => depth += 1,
            b'(' | b'[' if depth > 0 => depth -= 1,
            b'(' | b'[' | b'{' | b' ' | b'!' | b'&' | b'|' | b',' | b'=' if depth == 0 => break,
            _ => {}
        }
        i -= 1;
    }
    line[i..at].trim()
}

/// Does `receiver` name an error's text?
fn names_error_text(receiver: &str) -> bool {
    if receiver.ends_with(".to_string()") || receiver.ends_with(".to_string().as_str()") {
        return true;
    }
    receiver
        .split(['.', '(', ')', '&', '*'])
        .filter(|seg| !seg.is_empty())
        .any(|seg| TEXT_NAMES.contains(&seg))
}

/// The suspect comparisons on one line: each `(pattern, receiver)`.
fn suspects(line: &str) -> Vec<(&'static str, String)> {
    let code = line.split("//").next().unwrap_or("");
    let mut out = Vec::new();
    for pat in COMPARISONS {
        let mut from = 0;
        while let Some(i) = code[from..].find(pat) {
            let at = from + i;
            // For `== "` and `== Some("` the receiver is before the operator.
            let r = receiver(code, at);
            if names_error_text(r) {
                out.push((*pat, r.to_string()));
            }
            from = at + pat.len();
        }
    }
    // `match <text> {`, or `match <text>.as_str() {`.
    if let Some(scrutinee) = code.trim().strip_prefix("match ") {
        let scrutinee = scrutinee.trim_end_matches('{').trim();
        // A typed error (`match e {`) is what we want; its text, or a text field, is not.
        let as_str = scrutinee.strip_suffix(".as_str()");
        let inner = as_str.unwrap_or(scrutinee);
        let last = inner.rsplit('.').next().unwrap_or(inner);
        let text_field = ["msg", "message", "detail", "description"].contains(&last);
        if inner.ends_with(".to_string()")
            || text_field
            || (as_str.is_some() && TEXT_NAMES.contains(&last))
        {
            out.push(("match", scrutinee.to_string()));
        }
    }
    out
}

/// Comparisons on text that are not decisions on an error's words, with why: (file under
/// `crates/`, receiver as the scan prints it, reason).
const ALLOWED: &[(&str, &str, &str)] = &[(
    "attenuo-proxy/src/sse.rs",
    "text",
    "the SSE event data being parsed, not an error's text: when serde_json refuses it and it \
     holds a `\\u` escape, it is parsed again with lone surrogates replaced (SR-78); the \
     parse error itself decides nothing",
)];

#[test]
fn the_scan_finds_what_it_is_meant_to_find() {
    // The two decisions this guard was written after, as they were.
    assert_eq!(
        suspects(r#"        if msg.contains("unsupported grant_type") {"#),
        vec![(".contains(\"", "msg".to_string())]
    );
    assert_eq!(
        suspects(r#"                if e.description == Some("replayed") {"#),
        vec![("== Some(\"", "e.description".to_string())]
    );
    assert_eq!(
        suspects(r#"    if err.to_string().contains("timed out") {"#).len(),
        1
    );
    assert_eq!(
        suspects(r#"    if api.detail.starts_with("lease") {"#).len(),
        1
    );
    assert_eq!(suspects(r#"    match e.to_string().as_str() {"#).len(), 1);
    assert_eq!(suspects(r#"        match err.detail.as_str() {"#).len(), 1);
    // Input and protocol fields are not error text, nor is a typed error.
    for ok in [
        r#"        match e {"#,
        r#"            "may_act" if v.trim_start().starts_with(['[', '{']) => x,"#,
        r#"    let is_json = content_type.starts_with("application/json");"#,
        r#"        if obj.get("kty").and_then(Value::as_str) == Some("oct") {"#,
        r#"    if self.code == "invalid_client" {"#,
        r#"    // e.contains("x") in a comment"#,
        r#"        match self.leases.refund(&decision_id.to_string(), now) {"#,
    ] {
        assert!(suspects(ok).is_empty(), "{ok}");
    }
}

/// The server and the proxy decide nothing on an error's words, outside [`ALLOWED`].
#[test]
fn no_decision_is_made_on_error_text() {
    let root = workspace().join("crates");
    let mut found = Vec::new();
    let mut allowed_seen = vec![false; ALLOWED.len()];
    for krate in ["attenuo-server", "attenuo-proxy"] {
        for (path, text) in sources(&root.join(krate).join("src")) {
            let file = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            for (n, line) in text.lines().enumerate() {
                for (pat, recv) in suspects(line) {
                    match ALLOWED
                        .iter()
                        .position(|(f, r, _)| *f == file && *r == recv)
                    {
                        Some(i) => allowed_seen[i] = true,
                        None => found.push(format!(
                            "{file}:{}: `{recv}` {pat}…: {}",
                            n + 1,
                            line.trim()
                        )),
                    }
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "a decision on an error's text (match on a typed error instead, or add the line to \
         ALLOWED with why it is not a decision on error text):\n{}",
        found.join("\n")
    );
    for (i, seen) in allowed_seen.iter().enumerate() {
        assert!(
            seen,
            "ALLOWED lists {:?}, which the scan no longer finds: remove it",
            ALLOWED[i]
        );
    }
}

//! The stable error codes (audit K-8): every code the server and the proxy name in their
//! sources is in `attenuo_core::error_codes::ERROR_CODES`, and the list in
//! `docs/reference/http-api.md` is that table.
//!
//! The table's own invariants (sorted, no two entries with the same code, snake_case) are
//! tested next to it in `attenuo-core`. Each answer is also checked against the table at run
//! time in debug builds (`ApiError::into_response`, `attenuo_proxy::jsonrpc::attenuo_error`), so
//! a route test that reaches an unlisted code fails too; this file covers the paths no test
//! reaches.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use attenuo_core::error_codes::{lookup, ErrorCode, ERROR_CODES};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, recursively, without its `#[cfg(test)]` tail (unit tests
/// build bodies of their own, such as an upstream's error).
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
                // A fake upstream and the proxy's test doubles, not answers of the proxy.
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

/// `text` with every run of whitespace turned into one space.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The string literal at the start of `s` (after optional spaces), if there is one.
fn literal_at(s: &str) -> Option<&str> {
    let s = s.trim_start().strip_prefix('"')?;
    s.find('"').map(|end| &s[..end])
}

/// Every string literal that follows one of `markers` in `text` (squashed). A marker may be
/// followed by a `StatusCode::NAME,` first argument, which is skipped.
fn literals_after(text: &str, markers: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for m in markers {
        let mut rest = text;
        while let Some(i) = rest.find(m) {
            rest = &rest[i + m.len()..];
            let mut arg = rest.trim_start();
            for prefix in ["axum::http::StatusCode::", "StatusCode::"] {
                if let Some(after) = arg.strip_prefix(prefix) {
                    arg = after.split_once(',').map_or("", |(_, r)| r);
                    break;
                }
            }
            if let Some(lit) = literal_at(arg) {
                out.push(lit.to_string());
            }
        }
    }
    out
}

/// The `=> "code"` arms of every `fn description(&self) -> &'static str` (the IdP intake and
/// actor token sub-codes) and of `fn none_configured(self) -> &'static str` (client
/// authentication).
fn description_arms(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for marker in [
        "fn description(&self) -> &'static str {",
        "fn none_configured(self) -> &'static str {",
    ] {
        out.extend(arms_of(text, marker));
    }
    out
}

fn arms_of(text: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(marker) {
        rest = &rest[i + marker.len()..];
        let mut depth = 1;
        let end = rest
            .char_indices()
            .find(|&(_, c)| {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .map_or(rest.len(), |(i, _)| i);
        let body = &rest[..end];
        let mut arms = body;
        while let Some(j) = arms.find("=> ") {
            arms = &arms[j + 3..];
            if let Some(lit) = literal_at(arms) {
                out.push(lit.to_string());
            }
        }
    }
    out
}

/// The values of `const NAME: &str = "value";` for every `NAME` that is a reason code
/// (`REASON_...`) or one of `names`.
fn constants(text: &str, names: &[&str]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("const ") {
        rest = &rest[i + 6..];
        let Some((name, after)) = rest.split_once(": &str = ") else {
            continue;
        };
        if name.contains(' ') || !(name.starts_with("REASON_") || names.contains(&name)) {
            continue;
        }
        if let Some(lit) = literal_at(after) {
            out.push((name.to_string(), lit.to_string()));
        }
    }
    out
}

/// Reason codes that are not error codes: the reasons of allowed decisions and of other audit
/// records, and the audit reasons of refused token exchanges, which the wire answers with
/// `invalid_scope`, `invalid_request` or `invalid_grant` and a sub-code (`docs/reference/
/// http-api.md`, "Refused exchanges are audited").
const NOT_ERROR_CODES: &[&str] = &[
    "admin_action",
    "approval_declined",
    "approval_granted",
    "approval_requested",
    "capability_allow",
    "exchange_actor_mismatch",
    "exchange_actor_not_permitted",
    "exchange_duplicate_actor",
    "exchange_invalid_capability",
    "exchange_no_lifetime_left",
    "exchange_refused",
    "exchange_replayed",
    "exchange_reserved_agent",
    "exchange_too_deep",
    "exchange_widening",
    "lease_renewed",
    "policy_allow",
    "token_issued",
    "tool_result",
];

/// Constants that hold an error code but are not named `REASON_...`.
const CODE_CONSTANTS: &[&str] = &[
    "BATCH_TOO_LARGE",
    "CHAIN_NOT_ISSUED",
    "CHAIN_TOO_DEEP",
    "CHARGE_PRUNED",
    "DPOP_REPLAY_CACHE_FULL",
    "DPOP_REQUIRED",
    "INVALID_AGENT",
    "INVALID_CAPABILITY",
    "INVALID_CHAIN",
    "INVALID_CURSOR",
    "INVALID_DPOP_PROOF",
    "INVALID_HOST",
    "INVALID_SUBJECT",
    "LIMIT_SPLIT_AT_ROOT",
    "MALFORMED_REQUEST",
    "NO_CAPABILITIES_REQUESTED",
    "ONE_OF_TOO_LONG",
    "OVERLOADED",
    "REQUEST_TIMEOUT",
    "REQUEST_TOO_LARGE",
    "SCOPE_EXCEEDS_GRANT",
    "SCOPE_EXCEEDS_PARENT",
    "TOO_MANY_CAPABILITIES",
    "TTL_OUT_OF_RANGE",
    "UNSUPPORTED_TOKEN_TYPE",
    "USE_DPOP_NONCE",
];

/// Every code a source file of the server, the proxy, the policy engine or the core names, in
/// an error constructor, a sub-code, a JSON `reason`, or a reason constant.
fn codes_in_sources() -> BTreeSet<(String, String)> {
    let root = workspace().join("crates");
    let mut found = BTreeSet::new();
    for krate in [
        "attenuo-server",
        "attenuo-proxy",
        "attenuo-policy",
        "attenuo-core",
    ] {
        for (path, text) in sources(&root.join(krate).join("src")) {
            let file = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let flat = squash(&text);
            let mut add = |code: String| {
                found.insert((code, file.clone()));
            };
            for lit in literals_after(
                &flat,
                &[
                    "ApiError::new(",
                    "Self::new(",
                    "ApiError::bad_request(",
                    "with_description(",
                    "with_code(",
                    "invalid_client(",
                    "invalid_request(",
                    "invalid_scope(",
                    "\"reason\": ",
                ],
            ) {
                add(lit);
            }
            // `attenuo_error(id, number, "code", ...)`: the third argument.
            let mut rest = flat.as_str();
            while let Some(i) = rest.find("attenuo_error(") {
                rest = &rest[i + "attenuo_error(".len()..];
                let third = rest.splitn(3, ',').nth(2).unwrap_or("");
                if let Some(lit) = literal_at(third) {
                    add(lit.to_string());
                }
            }
            for lit in description_arms(&text) {
                add(lit);
            }
            for (_, value) in constants(&text, CODE_CONSTANTS) {
                add(value);
            }
        }
    }
    found
        .into_iter()
        // Only identifiers: `"reason": "..."` in a doc example is not a code.
        .filter(|(c, _)| c.bytes().any(|b| b.is_ascii_alphabetic()))
        .filter(|(c, _)| !NOT_ERROR_CODES.contains(&c.as_str()))
        .collect()
}

/// A code named in a source but missing from the table fails here, whether or not a test
/// reaches the path that sends it.
#[test]
fn every_code_in_the_sources_is_in_the_table() {
    let found = codes_in_sources();
    // The scan finds the codes it is meant to find (a broken scan would pass vacuously).
    for expected in [
        "invalid_request",
        "audience_mismatch",
        "actor_token_unknown_kid",
        "client_authentication_failed",
        "charge_pruned",
        "policy_deny",
        "budget_exhausted",
        "upstream_timeout",
        "session_unknown",
        "parse_error",
    ] {
        assert!(
            found.iter().any(|(c, _)| c == expected),
            "the scan no longer finds `{expected}`"
        );
    }
    // An `error` member that is always sent with a sub-code (`unauthorized`,
    // `temporarily_unavailable`) is listed in the table's REST forms, not as a code.
    let is_error_member = |c: &str| {
        ERROR_CODES
            .iter()
            .any(|e| e.rest.iter().any(|r| r.error == c))
    };
    let missing: Vec<String> = found
        .iter()
        .filter(|(c, _)| lookup(c).is_none() && !is_error_member(c))
        .map(|(c, f)| format!("`{c}` ({f})"))
        .collect();
    assert!(
        missing.is_empty(),
        "codes named in the sources but not in attenuo_core::error_codes::ERROR_CODES (add \
         them there, or to NOT_ERROR_CODES if they are not error codes): {}",
        missing.join(", ")
    );
    // And no reason that is not an error code has slipped into the table.
    for c in NOT_ERROR_CODES {
        assert!(lookup(c).is_none(), "`{c}` is in both lists");
    }
}

/// Every table entry is named somewhere in the sources: a code no answer sends any more is
/// removed from the table (and so from the docs) rather than left to rot.
#[test]
fn every_code_in_the_table_is_sent() {
    let found: BTreeSet<String> = codes_in_sources().into_iter().map(|(c, _)| c).collect();
    // Codes that only an `error` member names (the scan reads `error_description` sub-codes
    // and `error` members alike, so these are found too) or that a variable carries.
    let unused: Vec<&str> = ERROR_CODES
        .iter()
        .map(|e| e.code)
        .filter(|c| !found.contains(*c))
        .collect();
    assert!(
        unused.is_empty(),
        "in ERROR_CODES but named by no source: {unused:?}"
    );
}

fn rest_cell(e: &ErrorCode) -> String {
    e.rest
        .iter()
        .map(|r| {
            if r.error == e.code {
                r.status.to_string()
            } else {
                format!("{} `{}`", r.status, r.error)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn rpc_cell(e: &ErrorCode) -> String {
    e.jsonrpc
        .iter()
        .map(|j| format!("`{}` ({})", j.number, j.status))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The Markdown table `docs/reference/http-api.md` must hold between its markers.
fn rendered() -> String {
    let mut s = String::from(
        "| `code` | REST status (`error`) | JSON-RPC (HTTP status) | Deny `reason` | Meaning |\n\
         | --- | --- | --- | --- | --- |\n",
    );
    for e in ERROR_CODES {
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            e.code,
            rest_cell(e),
            rpc_cell(e),
            if e.reason { "yes" } else { "" },
            e.meaning
        ));
    }
    s
}

const START: &str = "<!-- error-codes:start (generated from attenuo_core::error_codes; see crates/attenuo-server/tests/error_codes.rs) -->\n";
const END: &str = "<!-- error-codes:end -->";

/// The docs list every code of the table, with its forms, and nothing else, so the page
/// cannot drift from the server. On a mismatch the expected block is printed: paste it in.
#[test]
fn http_api_doc_lists_the_table() {
    let path = workspace().join("docs/reference/http-api.md");
    let doc = std::fs::read_to_string(&path).unwrap();
    let start = doc.find(START).map(|i| i + START.len());
    let end = doc.find(END);
    let want = rendered();
    let (Some(start), Some(end)) = (start, end) else {
        panic!("docs/reference/http-api.md has no error-codes markers; add:\n{START}{want}{END}");
    };
    let got = &doc[start..end];
    assert!(
        got == want,
        "docs/reference/http-api.md is out of date with ERROR_CODES; replace the block with:\n{want}"
    );
}

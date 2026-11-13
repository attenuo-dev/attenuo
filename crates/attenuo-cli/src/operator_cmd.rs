//! `attenuo admin operator new` and `attenuo admin operator hash` (ADR-0016): make the
//! credential of a named admin operator. Both run offline: nothing is written to disk and
//! nothing is sent to a server. `attenuo admin operator reload` asks the server to re-read
//! the operators from its config file ([`reload_output`] prints its answer).

use anyhow::{bail, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::cli::OperatorRole;

/// Random bytes in a generated operator token (256 bits).
pub(crate) const TOKEN_BYTES: usize = 32;

/// Longest operator name, as the server checks it.
const MAX_NAME: usize = 64;

/// The name `[admin] token` is recorded under; no `[[admin.operators]]` entry may take it.
const RESERVED_NAME: &str = "admin";

/// Check a name as the server does (`[a-z0-9_-]{1,64}`, not `admin`), so that a snippet the
/// server would refuse is never printed.
pub(crate) fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME {
        bail!("operator name `{name}` must be 1 to {MAX_NAME} characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        bail!("operator name `{name}` may hold only a-z, 0-9, `_` and `-`");
    }
    if name == RESERVED_NAME {
        bail!("operator name `{RESERVED_NAME}` is reserved for [admin] token");
    }
    Ok(())
}

/// SHA-256 of `token`, as 64 lowercase hex characters: the `token_sha256` of the config.
pub(crate) fn token_sha256_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A new operator token: [`TOKEN_BYTES`] bytes from the system's secure random source,
/// base64url without padding (43 characters).
pub(crate) fn generate_token() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system random source failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// `t` as RFC 3339 (`expires_at` in the config).
pub(crate) fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

/// The `[[admin.operators]]` entry for an operator, with `expires_at` when it expires.
pub(crate) fn toml_entry(
    name: &str,
    token_sha256: &str,
    role: OperatorRole,
    expires_at: Option<OffsetDateTime>,
) -> String {
    let mut entry = format!(
        "[[admin.operators]]\nname = \"{name}\"\ntoken_sha256 = \"{token_sha256}\"\nrole = \"{}\"\n",
        role.as_str()
    );
    if let Some(t) = expires_at {
        entry.push_str(&format!("expires_at = \"{}\"\n", rfc3339(t)));
    }
    entry
}

/// What `admin operator new` prints: `(stdout, stderr)`. Stdout holds the token on its own
/// first line, a blank line and the config entry (or, with `json`, one JSON object with
/// `name`, `role`, `token`, `token_sha256`, `expires_at` (or null) and `toml`); stderr says
/// what to do with them.
pub(crate) fn new_output(
    name: &str,
    role: OperatorRole,
    token: &str,
    expires_at: Option<OffsetDateTime>,
    json: bool,
) -> (String, String) {
    let digest = token_sha256_hex(token);
    let entry = toml_entry(name, &digest, role, expires_at);
    let stderr = format!(
        "The token above is shown once and is stored nowhere: give it to `{name}` over a \
         secure channel.\nAdd the [[admin.operators]] entry to the server's config file, then \
         run `attenuo admin operator reload` (or restart the server).\n"
    );
    let stdout = if json {
        let v: Value = json!({
            "name": name,
            "role": role.as_str(),
            "token": token,
            "token_sha256": digest,
            "expires_at": expires_at.map(rfc3339),
            "toml": entry,
        });
        format!("{}\n", serde_json::to_string_pretty(&v).unwrap_or_default())
    } else {
        format!("{token}\n\n{entry}")
    };
    (stdout, stderr)
}

/// What `admin operator hash` prints for `token`: its `token_sha256`, or with `json`
/// `{"token_sha256": ...}`.
pub(crate) fn hash_output(token: &str, json: bool) -> String {
    let digest = token_sha256_hex(token);
    if json {
        format!("{}\n", json!({ "token_sha256": digest }))
    } else {
        format!("{digest}\n")
    }
}

/// What `admin operator reload` prints for the server's answer: a summary line, then one
/// line per operator added, removed or changed.
pub(crate) fn reload_output(resp: &Value) -> String {
    let names = |key: &str| -> Vec<String> {
        resp[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    };
    let (added, removed, changed) = (names("added"), names("removed"), names("changed"));
    let mut out = format!(
        "reloaded operators: {} added, {} removed, {} changed\n",
        added.len(),
        removed.len(),
        changed.len()
    );
    for (what, list) in [
        ("added", &added),
        ("removed", &removed),
        ("changed", &changed),
    ] {
        for name in list {
            out.push_str(&format!("  {what:<8} {name}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_256_bit_base64url_and_differ() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), TOKEN_BYTES);
    }

    #[test]
    fn new_prints_the_token_once_and_the_entry() {
        // Not hex, so it cannot turn up inside the digest.
        let token = "Zz_token_Zz";
        let digest = token_sha256_hex(token);
        let (out, err) = new_output("alice", OperatorRole::Operator, token, None, false);
        assert_eq!(
            out,
            format!(
                "{token}\n\n[[admin.operators]]\nname = \"alice\"\ntoken_sha256 = \"{digest}\"\nrole = \"operator\"\n"
            )
        );
        assert_eq!(out.matches(token).count(), 1);
        assert!(!err.contains(token), "{err}");
        // The entry parses as TOML with exactly the three keys.
        let entry = out.split_once("\n\n").unwrap().1;
        assert!(entry
            .lines()
            .all(|l| l == "[[admin.operators]]" || l.contains(" = ")));
        let (out, err) = new_output("alice", OperatorRole::Viewer, token, None, true);
        assert!(!err.contains(token), "{err}");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["name"], "alice");
        assert_eq!(v["role"], "viewer");
        assert_eq!(v["token"], token);
        assert_eq!(v["token_sha256"], digest);
        assert_eq!(
            v["toml"],
            toml_entry("alice", &digest, OperatorRole::Viewer, None)
        );
        assert_eq!(v["expires_at"], Value::Null);
    }

    #[test]
    fn an_expiry_is_written_into_the_entry() {
        let at = OffsetDateTime::parse("2026-12-31T23:59:59+01:00", &Rfc3339).unwrap();
        let (out, _) = new_output("alice", OperatorRole::Admin, "Zz", Some(at), false);
        assert!(
            out.ends_with("role = \"admin\"\nexpires_at = \"2026-12-31T23:59:59+01:00\"\n"),
            "{out}"
        );
        let (out, _) = new_output("alice", OperatorRole::Admin, "Zz", Some(at), true);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["expires_at"], "2026-12-31T23:59:59+01:00");
        assert!(v["toml"]
            .as_str()
            .unwrap()
            .contains("expires_at = \"2026-12-31T23:59:59+01:00\""));
    }

    #[test]
    fn reload_lists_the_names() {
        let out = reload_output(&json!({
            "added": ["frank"],
            "removed": ["vera"],
            "changed": ["bob", "carol"],
            "audit_id": "x",
        }));
        assert_eq!(
            out,
            "reloaded operators: 1 added, 1 removed, 2 changed\n  added    frank\n  \
             removed  vera\n  changed  bob\n  changed  carol\n"
        );
        assert_eq!(
            reload_output(&json!({"added": [], "removed": [], "changed": []})),
            "reloaded operators: 0 added, 0 removed, 0 changed\n"
        );
    }

    #[test]
    fn names_are_checked_as_the_server_checks_them() {
        for ok in ["a", "alice", "on_call", "ops-1", &"x".repeat(64)] {
            check_name(ok).unwrap();
        }
        for bad in [
            "",
            "admin",
            "Alice",
            "a b",
            "a.b",
            "é",
            "a\"b",
            &"x".repeat(65),
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hash_is_lowercase_sha256_hex() {
        // SHA-256("abc").
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hash_output("abc", false), format!("{want}\n"));
        let v: Value = serde_json::from_str(&hash_output("abc", true)).unwrap();
        assert_eq!(v["token_sha256"], want);
    }
}

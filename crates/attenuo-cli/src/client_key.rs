//! `private_key_jwt` client keys (RFC 7523): `attenuo key gen --client <path>` and
//! `token exchange --client-key`.
//!
//! A client key file is a private JWK, as for DPoP keys ([`crate::dpop_key`]): Ed25519 as
//! generated here, or a P-256 key made elsewhere, plus an optional `kid`. The server holds the
//! public half in the agent's `jwks` ([`jwks_line`] prints it).

use std::path::Path;

use anyhow::{Context, Result};
use attenuo_token::client_assertion;
use attenuo_token::DpopKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use time::OffsetDateTime;

/// Generate an Ed25519 key and write it to `path` with its `kid` (default: the thumbprint),
/// mode 0600 on Unix, never over an existing file. Returns the key and its `kid`.
pub(crate) fn generate(path: &Path, kid: Option<&str>) -> Result<(DpopKey, String)> {
    let key = DpopKey::generate().context("generating a client key")?;
    let kid = kid.map_or_else(|| key.thumbprint().to_owned(), str::to_owned);
    let mut jwk = key.private_jwk();
    jwk["kid"] = kid.clone().into();
    crate::dpop_key::write_new(path, &jwk)?;
    Ok((key, kid))
}

/// The public JWK of `key` with `kid`, as the server's config lists it.
pub(crate) fn public_jwk(key: &DpopKey, kid: &str) -> Value {
    let mut jwk = key.public_jwk().clone();
    jwk["kid"] = kid.into();
    jwk["alg"] = key.alg().into();
    jwk["use"] = "sig".into();
    jwk
}

/// The config line for an entry holding only this key: `jwks = '''{"keys":[...]}'''`.
pub(crate) fn jwks_line(key: &DpopKey, kid: &str) -> String {
    format!("jwks = '''{}'''", json!({ "keys": [public_jwk(key, kid)] }))
}

/// Load a client key: the private JWK at `path` and its `kid`, if it has one.
pub(crate) fn load(path: &Path) -> Result<(DpopKey, Option<String>)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading client key {}", path.display()))?;
    let jwk: Value = serde_json::from_str(&text)
        .with_context(|| format!("client key {} is not JSON (a private JWK)", path.display()))?;
    let key = DpopKey::from_jwk(&jwk).with_context(|| format!("client key {}", path.display()))?;
    let kid = jwk.get("kid").and_then(Value::as_str).map(str::to_owned);
    Ok((key, kid))
}

/// A fresh client assertion for `client_id`, for the server whose issuer identifier is
/// `audience`, signed with the key at `path`.
pub(crate) fn assertion(path: &Path, client_id: &str, audience: &str) -> Result<String> {
    let (key, kid) = load(path)?;
    Ok(client_assertion::sign(
        &key,
        kid.as_deref(),
        client_id,
        audience,
        client_assertion::DEFAULT_LIFETIME,
        OffsetDateTime::now_utc(),
    ))
}

/// The `iss` of a token, read from its payload without verification: for an attenuo token,
/// the server's issuer identifier, the `aud` a client assertion to it must carry.
pub(crate) fn token_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    claims["iss"].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(jwt: &str, i: usize) -> Value {
        let seg = jwt.split('.').nth(i).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(seg).unwrap()).unwrap()
    }

    #[test]
    fn generated_key_signs_assertions_with_its_kid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coder.jwk");
        let (key, kid) = generate(&path, Some("2026-11")).unwrap();
        assert_eq!(kid, "2026-11");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Never overwritten.
        assert!(generate(&path, None).is_err());
        let line = jwks_line(&key, &kid);
        assert!(line.starts_with("jwks = '''{\"keys\":[") && line.ends_with("]}'''"));
        assert!(!line.contains("\"d\""), "{line}");
        let a = assertion(&path, "coder", "https://attenuo.example").unwrap();
        assert_eq!(part(&a, 0)["kid"], "2026-11");
        assert_eq!(part(&a, 1)["sub"], "coder");
        assert_eq!(part(&a, 1)["aud"], "https://attenuo.example");
        // Default kid: the thumbprint.
        let (key, kid) = generate(&dir.path().join("b.jwk"), None).unwrap();
        assert_eq!(kid, key.thumbprint());
    }

    #[test]
    fn token_issuer_reads_iss() {
        let p = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://attenuo.example"}"#);
        assert_eq!(
            token_issuer(&format!("h.{p}.s")).as_deref(),
            Some("https://attenuo.example")
        );
        assert_eq!(token_issuer("garbage"), None);
    }
}

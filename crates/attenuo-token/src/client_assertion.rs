//! `private_key_jwt` client authentication (RFC 7523 §2.2, RFC 7521 §4.2): the JWT a client
//! signs with its own key to authenticate to the server's `POST /token` and AuthZEN endpoints,
//! in place of a client secret.
//!
//! The request carries `client_assertion_type` = [`CLIENT_ASSERTION_TYPE`] and
//! `client_assertion` = the JWT. The server checks it against the client's public keys in its
//! `[[agents]]` or `[[peps]]` entry (`attenuo-server`, `clientauth`). [`sign`] makes one the way
//! the server expects it: `iss` = `sub` = the client id, `aud` = the server's issuer identifier
//! (its `[issuer] issuer`), a fresh random `jti`, `iat`, and a short `exp`.

use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use crate::DpopKey;

/// RFC 7523 §2.2 `client_assertion_type` of a JWT client assertion.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Header `typ` of the assertions [`sign`] makes (draft-ietf-oauth-rfc7523bis). The server
/// does not require it; it refuses only a `typ` that names another kind of token.
pub const CLIENT_ASSERTION_TYP: &str = "client-authentication+jwt";

/// Lifetime of the assertions [`sign`] makes when the caller names none: one minute, well
/// within the server's default `[token] client_assertion_max_lifetime_seconds` (300).
pub const DEFAULT_LIFETIME: Duration = Duration::seconds(60);

/// A client assertion for `client_id`, for a server whose issuer identifier is `audience`,
/// signed by `key`, with `kid` in the header when given, valid from `now` for `lifetime`.
/// Each call makes a new `jti`: the server accepts an assertion once.
pub fn sign(
    key: &DpopKey,
    kid: Option<&str>,
    client_id: &str,
    audience: &str,
    lifetime: Duration,
    now: OffsetDateTime,
) -> String {
    let mut header = json!({"alg": key.alg(), "typ": CLIENT_ASSERTION_TYP});
    if let Some(kid) = kid {
        header["kid"] = Value::from(kid);
    }
    let iat = now.unix_timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": iat,
        "exp": iat.saturating_add(lifetime.whole_seconds()),
    });
    key.sign_jws(&header, &claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn part(jwt: &str, i: usize) -> Value {
        let seg = jwt.split('.').nth(i).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(seg).unwrap()).unwrap()
    }

    #[test]
    fn assertion_names_the_client_the_server_and_a_fresh_jti() {
        let key = DpopKey::generate().unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let a = sign(
            &key,
            Some("k1"),
            "coder",
            "https://as.example",
            DEFAULT_LIFETIME,
            now,
        );
        let b = sign(
            &key,
            None,
            "coder",
            "https://as.example",
            DEFAULT_LIFETIME,
            now,
        );
        let (h, c) = (part(&a, 0), part(&a, 1));
        assert_eq!(h["alg"], "EdDSA");
        assert_eq!(h["kid"], "k1");
        assert_eq!(h["typ"], CLIENT_ASSERTION_TYP);
        assert!(h.get("jwk").is_none());
        assert!(part(&b, 0).get("kid").is_none());
        assert_eq!(c["iss"], "coder");
        assert_eq!(c["sub"], "coder");
        assert_eq!(c["aud"], "https://as.example");
        assert_eq!(c["iat"], 1_000_000);
        assert_eq!(c["exp"], 1_000_060);
        assert_ne!(c["jti"], part(&b, 1)["jti"]);
    }
}

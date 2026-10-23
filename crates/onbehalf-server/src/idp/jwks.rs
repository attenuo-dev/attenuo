//! Fetching and caching one IdP's signing keys.
//!
//! The JWKS location is `[[idps]] jwks_url`, or `jwks_uri` from
//! `<issuer>/.well-known/openid-configuration` (whose `issuer` must equal the configured one,
//! OIDC Discovery §4.3). A fetched key set is used for `jwks_ttl_seconds`. A token whose `kid`
//! is not in the cache triggers one immediate refetch (key rotation), at most once per
//! [`UNKNOWN_KID_REFETCH_COOLDOWN`], so a stream of tokens with made-up `kid`s cannot turn the
//! server into a load generator against the IdP.
//!
//! Bounds: a JWKS or discovery body over [`MAX_JWKS_BYTES`] is rejected, at most
//! [`MAX_JWKS_KEYS`] keys are kept, and symmetric (`oct`) keys, keys marked for encryption and
//! keys that fail to parse are skipped. A failed refresh fails closed: stale keys are not used.

use std::str::FromStr;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use tokio::sync::Mutex;

/// Largest JWKS or discovery document accepted.
pub const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Most keys kept from one JWKS.
pub const MAX_JWKS_KEYS: usize = 32;
/// Minimum time between two refetches triggered by an unknown `kid`.
pub const UNKNOWN_KID_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/// Why no key could be found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwksError {
    #[error("JWKS unavailable: {0}")]
    Unavailable(String),
    #[error("no key with this kid in the IdP's JWKS")]
    UnknownKid,
    #[error("token has no kid and the IdP's JWKS has several candidate keys")]
    MissingKid,
    #[error("the JWK for this kid is for algorithm {jwk:?}, the token says {token:?}")]
    AlgMismatch { jwk: Algorithm, token: Algorithm },
}

#[derive(Clone)]
struct CachedKey {
    kid: Option<String>,
    alg: Option<Algorithm>,
    key: DecodingKey,
}

#[derive(Default)]
struct CacheState {
    jwks_uri: Option<String>,
    keys: Vec<CachedKey>,
    fetched_at: Option<Instant>,
    last_forced: Option<Instant>,
}

/// The key cache for one IdP.
pub struct JwksCache {
    client: reqwest::Client,
    issuer: String,
    configured_url: Option<String>,
    ttl: Duration,
    state: Mutex<CacheState>,
}

impl JwksCache {
    pub fn new(
        client: reqwest::Client,
        issuer: String,
        jwks_url: Option<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            client,
            issuer,
            configured_url: jwks_url,
            ttl,
            state: Mutex::new(CacheState::default()),
        }
    }

    /// The verification key for a token signed with `alg` and header `kid`.
    ///
    /// The lock is held across a fetch so concurrent requests share one fetch.
    pub async fn key_for(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, JwksError> {
        let mut st = self.state.lock().await;
        let mut fetched_now = false;
        if !st.fetched_at.is_some_and(|t| t.elapsed() < self.ttl) {
            self.refresh(&mut st).await?;
            fetched_now = true;
        }
        if let Some(k) = select(&st.keys, kid, alg)? {
            return Ok(k);
        }
        let cooling = st
            .last_forced
            .is_some_and(|t| t.elapsed() < UNKNOWN_KID_REFETCH_COOLDOWN);
        if fetched_now || cooling {
            return Err(JwksError::UnknownKid);
        }
        st.last_forced = Some(Instant::now());
        tracing::info!(issuer = %self.issuer, kid = ?kid, "unknown kid; refetching JWKS");
        self.refresh(&mut st).await?;
        select(&st.keys, kid, alg)?.ok_or(JwksError::UnknownKid)
    }

    async fn refresh(&self, st: &mut CacheState) -> Result<(), JwksError> {
        // Fail closed: if the refresh fails, the old keys are not used either.
        st.keys.clear();
        st.fetched_at = None;
        let uri = match (&self.configured_url, &st.jwks_uri) {
            (Some(u), _) | (None, Some(u)) => u.clone(),
            (None, None) => {
                let uri = self.discover().await?;
                st.jwks_uri = Some(uri.clone());
                uri
            }
        };
        let doc = match self.get_json(&uri).await {
            Ok(doc) => doc,
            Err(e) => {
                // A discovered jwks_uri may have moved; rediscover next time.
                st.jwks_uri = None;
                return Err(e);
            }
        };
        st.keys = parse_jwks(&doc, &self.issuer);
        st.fetched_at = Some(Instant::now());
        tracing::debug!(issuer = %self.issuer, keys = st.keys.len(), "JWKS fetched");
        Ok(())
    }

    async fn discover(&self) -> Result<String, JwksError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let doc = self.get_json(&url).await?;
        if doc.get("issuer").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(JwksError::Unavailable(format!(
                "discovery document at {url} names a different issuer"
            )));
        }
        doc.get("jwks_uri")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| JwksError::Unavailable(format!("no jwks_uri in {url}")))
    }

    async fn get_json(&self, url: &str) -> Result<Value, JwksError> {
        let fail = |e: String| JwksError::Unavailable(format!("{url}: {e}"));
        let mut resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| fail(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(fail(format!("HTTP {}", resp.status())));
        }
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_JWKS_BYTES as u64)
        {
            return Err(fail("document too large".into()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| fail(e.to_string()))? {
            if body.len() + chunk.len() > MAX_JWKS_BYTES {
                return Err(fail("document too large".into()));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| fail(e.to_string()))
    }
}

/// Keep the usable signature keys of a JWKS document.
fn parse_jwks(doc: &Value, issuer: &str) -> Vec<CachedKey> {
    let Some(keys) = doc.get("keys").and_then(Value::as_array) else {
        tracing::warn!(%issuer, "JWKS has no `keys` array");
        return Vec::new();
    };
    let mut out = Vec::new();
    for raw in keys {
        if out.len() == MAX_JWKS_KEYS {
            tracing::warn!(%issuer, max = MAX_JWKS_KEYS, "JWKS has too many keys; ignoring the rest");
            break;
        }
        let Ok(jwk) = serde_json::from_value::<Jwk>(raw.clone()) else {
            tracing::debug!(%issuer, "skipping a JWK that does not parse");
            continue;
        };
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            tracing::warn!(%issuer, "skipping a symmetric key in the JWKS");
            continue;
        }
        // A SPIFFE bundle marks JWT-SVID signing keys `use` = `jwt-svid` (X.509 roots are
        // `x509-svid` and skipped); `[[actor_trust]]` reads such bundles through this cache.
        if matches!(jwk.common.public_key_use, Some(ref u)
            if *u != PublicKeyUse::Signature && *u != PublicKeyUse::Other("jwt-svid".into()))
        {
            continue;
        }
        let alg = match jwk.common.key_algorithm {
            None => None,
            Some(a) => match Algorithm::from_str(&a.to_string()) {
                Ok(a) => Some(a),
                Err(_) => continue, // an encryption algorithm
            },
        };
        let Ok(key) = DecodingKey::from_jwk(&jwk) else {
            continue;
        };
        out.push(CachedKey {
            kid: jwk.common.key_id.clone(),
            alg,
            key,
        });
    }
    out
}

/// Pick the key for (`kid`, `alg`). `Ok(None)` means "not in this set" (worth a refetch).
fn select(
    keys: &[CachedKey],
    kid: Option<&str>,
    alg: Algorithm,
) -> Result<Option<DecodingKey>, JwksError> {
    match kid {
        Some(kid) => match keys.iter().find(|k| k.kid.as_deref() == Some(kid)) {
            None => Ok(None),
            Some(k) => match k.alg {
                Some(jwk) if jwk != alg => Err(JwksError::AlgMismatch { jwk, token: alg }),
                _ => Ok(Some(k.key.clone())),
            },
        },
        None => {
            let mut candidates = keys.iter().filter(|k| k.alg.is_none_or(|a| a == alg));
            match (candidates.next(), candidates.next()) {
                (None, _) => Ok(None),
                (Some(k), None) => Ok(Some(k.key.clone())),
                (Some(_), Some(_)) => Err(JwksError::MissingKid),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ed_jwk(kid: &str) -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
               "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
    }

    #[test]
    fn parse_skips_symmetric_encryption_and_garbage_keys() {
        let doc = json!({"keys": [
            ed_jwk("a"),
            {"kty": "oct", "k": "c2VjcmV0", "kid": "hmac"},
            {"kty": "RSA", "use": "enc", "kid": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "nope"},
        ]});
        let keys = parse_jwks(&doc, "i");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid.as_deref(), Some("a"));
    }

    #[test]
    fn parse_keeps_spiffe_jwt_svid_keys_only() {
        let mut svid = ed_jwk("svid");
        svid["use"] = json!("jwt-svid");
        svid.as_object_mut().unwrap().remove("alg");
        let mut x509 = ed_jwk("x509");
        x509["use"] = json!("x509-svid");
        let keys = parse_jwks(&json!({"spiffe_sequence": 1, "keys": [svid, x509]}), "i");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid.as_deref(), Some("svid"));
    }

    #[test]
    fn parse_is_bounded() {
        let many: Vec<Value> = (0..100).map(|i| ed_jwk(&format!("k{i}"))).collect();
        assert_eq!(
            parse_jwks(&json!({ "keys": many }), "i").len(),
            MAX_JWKS_KEYS
        );
    }

    #[test]
    fn select_by_kid_and_without_kid() {
        let keys = parse_jwks(&json!({"keys": [ed_jwk("a"), ed_jwk("b")]}), "i");
        assert!(select(&keys, Some("a"), Algorithm::EdDSA)
            .unwrap()
            .is_some());
        assert!(select(&keys, Some("z"), Algorithm::EdDSA)
            .unwrap()
            .is_none());
        assert!(matches!(
            select(&keys, Some("a"), Algorithm::RS256),
            Err(JwksError::AlgMismatch { .. })
        ));
        assert!(matches!(
            select(&keys, None, Algorithm::EdDSA),
            Err(JwksError::MissingKid)
        ));
        assert!(select(&keys[..1], None, Algorithm::EdDSA)
            .unwrap()
            .is_some());
    }
}

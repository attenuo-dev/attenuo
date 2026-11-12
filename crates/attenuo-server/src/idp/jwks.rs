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
//!
//! Transport (S-8): every URL fetched (a configured `jwks_url` or SPIFFE bundle URL, the
//! discovery document and the `jwks_uri` it names) must be `https://`; plain `http://` is
//! accepted only for a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), for local
//! development and tests ([`check_fetch_url`]). Redirects are never followed: a 3xx answer
//! fails the fetch and names the `Location`, so a redirect cannot move a fetch from https to
//! http or to another host. Configure the final URL instead.

use std::str::FromStr;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use tokio::sync::Mutex;

/// Largest JWKS or discovery document accepted.
pub(crate) const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Most keys kept from one JWKS.
pub(crate) const MAX_JWKS_KEYS: usize = 32;
/// Minimum time between two refetches triggered by an unknown `kid`.
pub(crate) const UNKNOWN_KID_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/// The HTTP client for key fetches: `timeout` per request, no redirects followed (S-8).
///
/// # Errors
///
/// When the TLS backend cannot be initialised.
pub(crate) fn fetch_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Is `url` acceptable for a key fetch (S-8)? `https://` with a host, or `http://` with a
/// loopback host (`localhost`, `127.0.0.0/8`, `[::1]`) for local development and tests.
///
/// # Errors
///
/// A message saying why not, without the URL (callers name it).
pub(crate) fn check_fetch_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("not a URL ({e})"))?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("the URL has no host".into());
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if crate::config::url_host_is_loopback(url) => Ok(()),
        "http" => Err(
            "must be https:// (plain http:// is accepted only for a loopback host \
                       such as 127.0.0.1 or localhost, for local development)"
                .into(),
        ),
        other => Err(format!("must be https://, not {other}://")),
    }
}

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
pub(crate) struct JwksCache {
    client: reqwest::Client,
    issuer: String,
    configured_url: Option<String>,
    ttl: Duration,
    state: Mutex<CacheState>,
}

impl JwksCache {
    pub(crate) fn new(
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
    pub(crate) async fn key_for(
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
        check_fetch_url(url).map_err(fail)?;
        let mut resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| fail(e.to_string()))?;
        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(fail(format!(
                "answered with a redirect (HTTP {} to {location:?}); redirects are not \
                 followed for key fetches, configure the final https:// URL",
                resp.status()
            )));
        }
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
    fn fetch_urls_must_be_https_or_loopback_http_s8() {
        for ok in [
            "https://idp.example/jwks",
            "https://10.0.0.5:8443/bundle",
            "http://127.0.0.1:9000/jwks",
            "http://localhost/jwks",
            "http://[::1]:1/jwks",
        ] {
            check_fetch_url(ok).unwrap();
        }
        for bad in [
            "http://idp.example/jwks",
            "http://10.0.0.5/jwks",
            "http://localhost.idp.example/jwks",
            "http://127.0.0.1@idp.example/jwks",
            "ftp://idp.example/jwks",
            "file:///etc/jwks.json",
            "idp.example/jwks",
            "",
        ] {
            assert!(check_fetch_url(bad).is_err(), "{bad}");
        }
        let err = check_fetch_url("http://idp.example/jwks").unwrap_err();
        assert!(err.contains("must be https://"), "{err}");
    }

    /// A local key server: `/jwks` serves a key, `/moved` redirects to it, `/away` redirects to
    /// a plain-http host off loopback, and the discovery document names an off-loopback
    /// `http://` `jwks_uri`.
    async fn key_server() -> String {
        use axum::response::Redirect;
        use axum::routing::get;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let issuer = base.clone();
        let app = axum::Router::new()
            .route(
                "/jwks",
                get(|| async { axum::Json(json!({"keys": [ed_jwk("a")]})) }),
            )
            .route("/moved", get(|| async { Redirect::temporary("/jwks") }))
            .route(
                "/away",
                get(|| async { Redirect::permanent("http://keys.example/jwks") }),
            )
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let issuer = issuer.clone();
                    async move {
                        axum::Json(
                            json!({"issuer": issuer, "jwks_uri": "http://keys.example/jwks"}),
                        )
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    fn cache(issuer: &str, url: Option<String>) -> JwksCache {
        JwksCache::new(
            fetch_client(Duration::from_secs(5)).unwrap(),
            issuer.into(),
            url,
            Duration::from_secs(300),
        )
    }

    #[tokio::test]
    async fn redirects_are_refused_not_followed_s8() {
        let base = key_server().await;
        // Plain http on loopback is the development escape: the direct URL works.
        cache("i", Some(format!("{base}/jwks")))
            .key_for(Some("a"), Algorithm::EdDSA)
            .await
            .unwrap();
        for path in ["/moved", "/away"] {
            let Err(JwksError::Unavailable(msg)) = cache("i", Some(format!("{base}{path}")))
                .key_for(Some("a"), Algorithm::EdDSA)
                .await
            else {
                panic!("{path}: a redirect must fail the fetch");
            };
            assert!(msg.contains("redirect"), "{path}: {msg}");
            assert!(msg.contains("not followed"), "{path}: {msg}");
        }
    }

    /// Off loopback, http is refused before anything is sent: no network is needed.
    #[tokio::test]
    async fn plain_http_off_loopback_is_refused_before_connecting_s8() {
        let Err(JwksError::Unavailable(msg)) = cache("i", Some("http://keys.example/jwks".into()))
            .key_for(Some("a"), Algorithm::EdDSA)
            .await
        else {
            panic!("plain http off loopback must fail");
        };
        assert!(msg.contains("must be https://"), "{msg}");
        // A discovered jwks_uri is held to the same rule.
        let base = key_server().await;
        let Err(JwksError::Unavailable(msg)) = cache(&base, None)
            .key_for(Some("a"), Algorithm::EdDSA)
            .await
        else {
            panic!("a discovered http jwks_uri off loopback must fail");
        };
        assert!(msg.contains("http://keys.example/jwks"), "{msg}");
        assert!(msg.contains("must be https://"), "{msg}");
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

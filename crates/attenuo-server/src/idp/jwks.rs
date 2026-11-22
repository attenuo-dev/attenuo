//! Fetching and caching one IdP's signing keys, and the keys of an `[[actor_trust]]` entry or
//! of an `[[agents]]` / `[[peps]]` entry with `jwks_url` (`crate::clientauth`), which use the
//! same cache with an explicit URL and a stricter parser of their own ([`ParseKeys`]).
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
//! Concurrency: a fetch runs in a task of its own, one at a time per cache, and no lock is
//! held across it; the requests that need it wait for its end, the others go on with the
//! cached keys. A slow or dead key URL holds up only the requests that need its keys.
//!
//! Transport (S-8): every URL fetched (a configured `jwks_url` or SPIFFE bundle URL, the
//! discovery document and the `jwks_uri` it names) must be `https://`; plain `http://` is
//! accepted only for a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), for local
//! development and tests ([`check_fetch_url`]). Redirects are never followed: a 3xx answer
//! fails the fetch and names the `Location`, so a redirect cannot move a fetch from https to
//! http or to another host. Configure the final URL instead.
//!
//! Trust: a key URL's certificate is checked against the web PKI roots built in (the
//! `webpki-roots` set), plus, for an entry that sets `ca_pem_path`, the CA certificates in that
//! file ([`read_ca_pem`]). The extra roots are added to the built-in ones, never replace them,
//! and belong to that entry's client alone: another entry, and every other outbound client of
//! the server, does not trust them (the checkpoint sink has its own `[audit.sink]
//! ca_pem_path`). Nothing here can turn verification or the hostname check off.

use std::str::FromStr;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use tokio::sync::watch;

/// Largest JWKS or discovery document accepted.
pub(crate) const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Most keys kept from one JWKS.
pub(crate) const MAX_JWKS_KEYS: usize = 32;
/// Minimum time between two refetches triggered by an unknown `kid`.
pub(crate) const UNKNOWN_KID_REFETCH_COOLDOWN: Duration = Duration::from_secs(30);

/// The HTTP client for key fetches: `timeout` per request, no redirects followed (S-8), and
/// the name `localhost` connected to `127.0.0.1` or `[::1]` without asking the resolver.
///
/// [`check_fetch_url`] accepts plain `http://` for `localhost` because it is this machine.
/// The system resolver need not agree: on a host whose `/etc/hosts` has no `localhost` line,
/// or whose `nsswitch` asks DNS first, `localhost` can be looked up in DNS (through the search
/// list, as `localhost.<search domain>`) and answered with any address, and the key set would
/// then come over cleartext from another machine. Pinning the name keeps the local-development
/// exception on the machine itself, whatever the resolver says (SR-107).
///
/// `extra_roots` (an entry's `ca_pem_path`, from [`read_ca_pem`]) are trusted in addition to
/// the built-in web PKI roots, for this client only.
///
/// # Errors
///
/// When the TLS backend cannot be initialised, or a certificate of `extra_roots` cannot be
/// used as a trust anchor.
pub(crate) fn fetch_client(
    timeout: Duration,
    extra_roots: &[reqwest::Certificate],
) -> reqwest::Result<reqwest::Client> {
    extra_roots
        .iter()
        .fold(fetch_client_builder(timeout), |b, c| {
            b.add_root_certificate(c.clone())
        })
        .build()
}

/// The CA certificates of an `[[idps]]` or `[[actor_trust]]` `ca_pem_path`: every
/// `CERTIFICATE` block of a PEM file. Other blocks (a private key, say) are ignored.
///
/// # Errors
///
/// A message, without the path (callers name it), when the file cannot be read, is not PEM,
/// or holds no certificate.
pub(crate) fn read_ca_pem(path: &std::path::Path) -> Result<Vec<reqwest::Certificate>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("cannot read the file ({e})"))?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err("the file is empty; it must hold PEM CA certificates".into());
    }
    let certs = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|e| format!("not a PEM certificate file ({e})"))?;
    if certs.is_empty() {
        return Err("no PEM certificate (-----BEGIN CERTIFICATE-----) in the file".into());
    }
    Ok(certs)
}

/// The key-fetch client of one entry: `shared` (built-in roots only) when it names no
/// `ca_pem_path`, else a client of its own that also trusts that file's CAs.
///
/// # Errors
///
/// A message, without the entry's name (callers give it), naming the path and the problem.
pub(crate) fn entry_client(
    shared: &reqwest::Client,
    ca_pem_path: Option<&std::path::Path>,
    timeout: Duration,
) -> Result<reqwest::Client, String> {
    let Some(path) = ca_pem_path else {
        return Ok(shared.clone());
    };
    let fail = |e: String| format!("ca_pem_path {:?}: {e}", path.display().to_string());
    let roots = read_ca_pem(path).map_err(fail)?;
    fetch_client(timeout, &roots).map_err(|e| {
        fail(format!(
            "a certificate cannot be used as a trust anchor ({})",
            error_chain(&e)
        ))
    })
}

/// [`fetch_client`]'s builder, for a test that swaps the resolver underneath the pin.
fn fetch_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    // The port is ignored: reqwest connects to the URL's port.
    let loopback = [
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
    ];
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs("localhost", &loopback)
}

/// Is `url` acceptable for a key fetch (S-8)? `https://` with a host, or `http://` with a
/// loopback host (`localhost`, `127.0.0.0/8`, `[::1]`) for local development and tests.
/// [`fetch_client`] connects `localhost` to the loopback addresses itself, so the name cannot
/// be resolved elsewhere (SR-107).
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

/// `err` and its causes, outermost first, joined by `: ` (for a failed fetch: `error sending
/// request: client error (Connect): invalid peer certificate: UnknownIssuer`). A cause whose
/// text the previous one already contains is left out, as some errors repeat their source.
///
/// For the server log only: the HTTP answer to a failed fetch is the stable
/// `jwks_unavailable` and never this text (SR-17). A key fetch sends no credential, so the
/// causes of its failure carry none.
pub(crate) fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut last = out.clone();
    let mut next = err.source();
    while let Some(cause) = next {
        let text = cause.to_string();
        if !text.is_empty() && !last.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        last = text;
        next = cause.source();
    }
    out
}

/// `url` as the fetch error names it: a password in its user info is replaced by `***`, so
/// a `https://user:secret@host/jwks` cannot put the secret in the log.
fn url_for_log(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("***"));
            u.to_string()
        }
        _ => url.to_owned(),
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

/// A key of an IdP's or `[[actor_trust]]` entry's JWKS, as [`parse_jwks`] keeps it.
#[derive(Clone)]
pub(crate) struct CachedKey {
    kid: Option<String>,
    alg: Option<Algorithm>,
    key: DecodingKey,
}

/// Turns a fetched JWKS document into the keys a cache keeps, or says why the document is
/// refused (a fetch failure, so it fails closed). The second argument is the cache's label.
pub(crate) type ParseKeys<K> = fn(&Value, &str) -> Result<Vec<K>, String>;

struct CacheState<K> {
    jwks_uri: Option<String>,
    keys: Vec<K>,
    fetched_at: Option<Instant>,
    last_forced: Option<Instant>,
    /// When the last fetch failed and why, while no later fetch has succeeded.
    failed: Option<(Instant, JwksError)>,
    /// A fetch is running (in a task of its own); callers that need it wait for it.
    fetching: bool,
}

struct Inner<K> {
    client: reqwest::Client,
    issuer: String,
    configured_url: Option<String>,
    ttl: Duration,
    /// How long after a failed fetch the next one may start; until then the failure is the
    /// answer. Zero for IdPs and `[[actor_trust]]` entries.
    failure_backoff: Duration,
    parse: ParseKeys<K>,
    state: StdMutex<CacheState<K>>,
    /// Bumped each time a fetch ends, so that callers waiting for it wake up.
    done: watch::Sender<u64>,
}

impl<K> Inner<K> {
    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState<K>> {
        // Every update is a few plain stores that cannot be left half done by a panic.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The key cache for one IdP, one `[[actor_trust]]` entry or one `[[agents]]` / `[[peps]]`
/// entry with `jwks_url`.
///
/// No lock is held across a network call: a fetch runs in a task of its own, at most one
/// per cache at a time, and the callers that need it wait for it to end without holding the
/// lock. So concurrent requests share one fetch, and a slow key URL holds up only the
/// requests that need that cache's keys.
pub(crate) struct JwksCache<K = CachedKey> {
    inner: Arc<Inner<K>>,
}

impl JwksCache<CachedKey> {
    pub(crate) fn new(
        client: reqwest::Client,
        issuer: String,
        jwks_url: Option<String>,
        ttl: Duration,
    ) -> Self {
        Self::with_parser(
            client,
            issuer,
            jwks_url,
            ttl,
            Duration::ZERO,
            |doc, issuer| Ok(parse_jwks(doc, issuer)),
        )
    }

    /// The verification key for a token signed with `alg` and header `kid`.
    pub(crate) async fn key_for(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, JwksError> {
        self.find(kid, |keys| select(keys, kid, alg)).await
    }
}

impl<K: Clone + Send + Sync + 'static> JwksCache<K> {
    /// A cache whose fetched documents `parse` turns into keys, and which, after a failed
    /// fetch, starts no other for `failure_backoff`. `label` names the cache in log lines and
    /// is given to `parse`. With `jwks_url` unset the URL is discovered at `label`, which is
    /// then the issuer.
    pub(crate) fn with_parser(
        client: reqwest::Client,
        label: String,
        jwks_url: Option<String>,
        ttl: Duration,
        failure_backoff: Duration,
        parse: ParseKeys<K>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                client,
                issuer: label,
                configured_url: jwks_url,
                ttl,
                failure_backoff,
                parse,
                state: StdMutex::new(CacheState {
                    jwks_uri: None,
                    keys: Vec::new(),
                    fetched_at: None,
                    last_forced: None,
                    failed: None,
                    fetching: false,
                }),
                done: watch::channel(0).0,
            }),
        }
    }

    /// The key `pick` chooses from the cached keys. `pick` answers `Ok(None)` for "not in
    /// this set", which is worth one refetch (key rotation), and an error for a refusal that
    /// a refetch would not change.
    ///
    /// The keys are fetched when there are none younger than the TTL. When `pick` finds
    /// nothing in keys that were not just fetched, they are fetched once more, at most once
    /// per [`UNKNOWN_KID_REFETCH_COOLDOWN`]; within it the answer is
    /// [`JwksError::UnknownKid`] without a fetch. A failed fetch drops the cached keys (fail
    /// closed); with a `failure_backoff`, the next fetch starts only after it.
    /// `kid` is the token's, for the log line of a refetch.
    pub(crate) async fn find<T>(
        &self,
        kid: Option<&str>,
        pick: impl Fn(&[K]) -> Result<Option<T>, JwksError>,
    ) -> Result<T, JwksError> {
        let inner = &self.inner;
        let mut waited = false;
        loop {
            let mut done = {
                let mut st = inner.lock();
                let fresh = st.fetched_at.is_some_and(|t| t.elapsed() < inner.ttl);
                if waited {
                    // The fetch this call waited for has ended; it decides.
                    if !fresh {
                        return Err(st.failed.as_ref().map_or_else(
                            || JwksError::Unavailable("the key fetch did not finish".into()),
                            |(_, e)| e.clone(),
                        ));
                    }
                    return pick(&st.keys)?.ok_or(JwksError::UnknownKid);
                }
                if fresh {
                    if let Some(k) = pick(&st.keys)? {
                        return Ok(k);
                    }
                    if !st.fetching {
                        let cooling = st
                            .last_forced
                            .is_some_and(|t| t.elapsed() < UNKNOWN_KID_REFETCH_COOLDOWN);
                        if cooling {
                            return Err(JwksError::UnknownKid);
                        }
                        st.last_forced = Some(Instant::now());
                        tracing::info!(issuer = %inner.issuer, kid = ?kid, "unknown kid; refetching JWKS");
                        self.start_fetch(&mut st);
                    }
                } else if !st.fetching {
                    if let Some((at, e)) = &st.failed {
                        if at.elapsed() < inner.failure_backoff {
                            return Err(e.clone());
                        }
                    }
                    self.start_fetch(&mut st);
                }
                waited = true;
                // Subscribed under the lock, so the end of the running fetch is not missed.
                inner.done.subscribe()
            };
            // The sender lives in `inner`, which `self` keeps: this ends when a fetch does.
            let _ = done.changed().await;
        }
    }

    /// Start a fetch in a task of its own. The caller holds the lock and saw none running.
    fn start_fetch(&self, st: &mut CacheState<K>) {
        st.fetching = true;
        let discovered = st.jwks_uri.clone();
        let guard = FetchGuard(Some(Arc::clone(&self.inner)));
        tokio::spawn(async move {
            let Some(inner) = guard.0.as_ref() else {
                return;
            };
            let outcome = inner.fetch(discovered).await;
            guard.finish(outcome);
        });
    }
}

/// Ends a running fetch: [`finish`](Self::finish) stores its outcome; dropped without it (the
/// task panicked or the runtime shut down), the fetch counts as failed, so that no caller
/// waits for it forever.
struct FetchGuard<K>(Option<Arc<Inner<K>>>);

impl<K> FetchGuard<K> {
    fn finish(mut self, outcome: Result<(Option<String>, Vec<K>), JwksError>) {
        if let Some(inner) = self.0.take() {
            end_fetch(&inner, outcome);
        }
    }
}

impl<K> Drop for FetchGuard<K> {
    fn drop(&mut self) {
        if let Some(inner) = self.0.take() {
            end_fetch(
                &inner,
                Err(JwksError::Unavailable("the key fetch stopped".into())),
            );
        }
    }
}

fn end_fetch<K>(inner: &Inner<K>, outcome: Result<(Option<String>, Vec<K>), JwksError>) {
    {
        let mut st = inner.lock();
        st.fetching = false;
        match outcome {
            Ok((discovered, keys)) => {
                tracing::debug!(issuer = %inner.issuer, keys = keys.len(), "JWKS fetched");
                st.jwks_uri = discovered;
                st.keys = keys;
                st.fetched_at = Some(Instant::now());
                st.failed = None;
            }
            Err(e) => {
                // Fail closed: if the refresh fails, the old keys are not used either. A
                // discovered jwks_uri may have moved; rediscover next time.
                st.jwks_uri = None;
                st.keys.clear();
                st.fetched_at = None;
                st.failed = Some((Instant::now(), e));
            }
        }
    }
    inner.done.send_modify(|n| *n = n.wrapping_add(1));
}

impl<K> Inner<K> {
    /// Fetch and parse the key set: from the configured URL, or the one discovered before
    /// (`discovered`), or found by discovery now. Returns the discovered URL to keep.
    async fn fetch(
        &self,
        discovered: Option<String>,
    ) -> Result<(Option<String>, Vec<K>), JwksError> {
        let uri = match (&self.configured_url, discovered) {
            (Some(u), _) => u.clone(),
            (None, Some(u)) => u,
            (None, None) => self.discover().await?,
        };
        let doc = self.get_json(&uri).await?;
        let keys = (self.parse)(&doc, &self.issuer)
            .map_err(|e| JwksError::Unavailable(format!("{}: {e}", url_for_log(&uri))))?;
        Ok((self.configured_url.is_none().then_some(uri), keys))
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
        let shown = url_for_log(url);
        let fail = |e: String| JwksError::Unavailable(format!("{shown}: {e}"));
        // The transport error with its causes (the TLS error under "error sending request"),
        // without reqwest's copy of the URL, which `fail` already names.
        let transport = |e: reqwest::Error| fail(error_chain(&e.without_url()));
        check_fetch_url(url).map_err(fail)?;
        let mut resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(transport)?;
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
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
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

    /// SR-107: a resolver that answers `localhost` with an address off this machine does not
    /// move a key fetch there: the client connects `localhost` to loopback itself. Without
    /// the pin this client asked the resolver and tried 192.0.2.1 (TEST-NET-1).
    #[tokio::test]
    async fn localhost_is_pinned_to_loopback_whatever_the_resolver_says_sr107() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        struct Elsewhere(Arc<AtomicUsize>);
        impl reqwest::dns::Resolve for Elsewhere {
            fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(
                        std::net::SocketAddr::from(([192, 0, 2, 1], 0)),
                    ));
                    Ok(addrs)
                })
            }
        }
        let base = key_server().await;
        let port = base.rsplit(':').next().unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let client = fetch_client_builder(Duration::from_secs(2))
            .dns_resolver(Arc::new(Elsewhere(Arc::clone(&asked))))
            .build()
            .unwrap();
        let url = format!("http://localhost:{port}/jwks");
        check_fetch_url(&url).unwrap();
        let resp = client
            .get(&url)
            .send()
            .await
            .expect("fetched from loopback");
        assert!(resp.status().is_success());
        assert_eq!(asked.load(Ordering::SeqCst), 0, "the resolver was asked");
    }

    fn cache(issuer: &str, url: Option<String>) -> JwksCache {
        JwksCache::new(
            fetch_client(Duration::from_secs(5), &[]).unwrap(),
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

    /// An error with an optional cause, for the chain formatter.
    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);
    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|l| l as _)
        }
    }

    #[test]
    fn the_error_chain_names_every_cause_once() {
        let chain = Layer(
            "error sending request",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer(
                    "invalid peer certificate: UnknownIssuer",
                    // Repeats its parent's text, as `io::Error` wrappers do.
                    Some(Box::new(Layer("UnknownIssuer", None))),
                ))),
            ))),
        );
        assert_eq!(
            error_chain(&chain),
            "error sending request: client error (Connect): \
             invalid peer certificate: UnknownIssuer"
        );
        assert_eq!(error_chain(&Layer("alone", None)), "alone");
        // An empty cause adds no separator.
        let empty = Layer("outer", Some(Box::new(Layer("", None))));
        assert_eq!(error_chain(&empty), "outer");
    }

    #[test]
    fn a_password_in_a_key_url_is_not_logged() {
        assert_eq!(
            url_for_log("https://keys:s3cret@idp.example/jwks"),
            "https://keys:***@idp.example/jwks"
        );
        assert_eq!(
            url_for_log("https://idp.example/jwks?x=1"),
            "https://idp.example/jwks?x=1"
        );
        assert_eq!(url_for_log("not a url"), "not a url");
    }

    /// A transport failure is reported with its cause, not as a bare "error sending request".
    #[tokio::test]
    async fn a_failed_fetch_names_the_transport_cause() {
        // A port that refuses connections: bind, note the port, close.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let Err(JwksError::Unavailable(msg)) = cache(
            "i",
            Some(format!("http://keys:s3cret@127.0.0.1:{port}/jwks")),
        )
        .key_for(Some("a"), Algorithm::EdDSA)
        .await
        else {
            panic!("the fetch must fail");
        };
        assert!(
            msg.starts_with(&format!("http://keys:***@127.0.0.1:{port}/jwks: ")),
            "{msg}"
        );
        assert!(msg.contains("error sending request"), "{msg}");
        assert!(
            msg.len() > msg.find("error sending request").unwrap() + 22,
            "no cause: {msg}"
        );
        assert!(!msg.contains("s3cret"), "{msg}");
        // reqwest's own copy of the URL is left out: the URL is named once.
        assert_eq!(msg.matches("127.0.0.1").count(), 1, "{msg}");
    }

    /// A key server whose `/jwks` counts its requests and answers after `delay`: with the key
    /// `a`, or with HTTP 500 while `down` is set.
    async fn slow_key_server(
        delay: Duration,
    ) -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use axum::routing::get;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let down = std::sync::Arc::new(AtomicBool::new(false));
        let (h, d) = (hits.clone(), down.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/jwks",
            get(move || {
                let (h, d) = (h.clone(), d.clone());
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    if d.load(Ordering::SeqCst) {
                        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                    }
                    Ok(axum::Json(json!({"keys": [ed_jwk("a")]})))
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("{base}/jwks"), hits, down)
    }

    /// Requests that need the keys at once share one fetch.
    #[tokio::test]
    async fn concurrent_requests_share_one_fetch() {
        use std::sync::atomic::Ordering;
        let (url, hits, _) = slow_key_server(Duration::from_millis(200)).await;
        let c = std::sync::Arc::new(cache("i", Some(url)));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move { c.key_for(Some("a"), Algorithm::EdDSA).await })
            })
            .collect();
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// No lock is held across a fetch: while an unknown `kid` waits for a slow refetch, a
    /// request with a cached key is answered from the cache.
    #[tokio::test]
    async fn a_slow_refetch_does_not_hold_up_cached_keys() {
        use std::sync::atomic::Ordering;
        let (url, hits, _) = slow_key_server(Duration::from_secs(3)).await;
        let c = std::sync::Arc::new(cache("i", Some(url)));
        c.key_for(Some("a"), Algorithm::EdDSA).await.unwrap();
        let unknown = {
            let c = c.clone();
            tokio::spawn(async move { c.key_for(Some("zzz"), Algorithm::EdDSA).await })
        };
        // Wait until the refetch has reached the server.
        let deadline = Instant::now() + Duration::from_secs(20);
        while hits.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "the refetch never started");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        c.key_for(Some("a"), Algorithm::EdDSA).await.unwrap();
        assert!(
            !unknown.is_finished(),
            "the cached key was answered only after the refetch ended"
        );
        assert!(matches!(unknown.await.unwrap(), Err(JwksError::UnknownKid)));
    }

    /// With a failure backoff, a failed fetch is the answer until it has passed: no new fetch.
    /// Without one (IdPs), the next request fetches again.
    #[tokio::test]
    async fn a_failure_backoff_holds_back_the_next_fetch() {
        use std::sync::atomic::Ordering;
        let (url, hits, down) = slow_key_server(Duration::ZERO).await;
        down.store(true, Ordering::SeqCst);
        let client = fetch_client(Duration::from_secs(5), &[]).unwrap();
        let backoff = JwksCache::with_parser(
            client.clone(),
            "i".into(),
            Some(url.clone()),
            Duration::from_secs(300),
            Duration::from_secs(3600),
            |doc, issuer| Ok(parse_jwks(doc, issuer)),
        );
        let pick = |keys: &[CachedKey]| select(keys, Some("a"), Algorithm::EdDSA);
        for _ in 0..5 {
            let Err(e) = backoff.find(Some("a"), pick).await else {
                panic!("the fetch must fail");
            };
            assert!(
                matches!(e, JwksError::Unavailable(ref m) if m.contains("500")),
                "{e}"
            );
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let plain = cache("i", Some(url));
        for _ in 0..3 {
            assert!(plain.key_for(Some("a"), Algorithm::EdDSA).await.is_err());
        }
        assert_eq!(hits.load(Ordering::SeqCst), 4);
        // Back up: the cache without a backoff recovers on the next request.
        down.store(false, Ordering::SeqCst);
        plain.key_for(Some("a"), Algorithm::EdDSA).await.unwrap();
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

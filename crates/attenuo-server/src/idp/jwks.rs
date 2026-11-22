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
//! A client cache ([`FailurePolicy`]) also waits a backoff after a failed fetch, and keeps keys
//! still within their TTL when only a refetch for an unknown `kid` failed.
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
    ca_pem_certs(&read_ca_file(path)?)
}

/// Largest `ca_pem_path` file read, as for a key file
/// ([`crate::issuer_keys::MAX_KEY_FILE_BYTES`]): room for dozens of CA certificates. The
/// file adds roots to the built-in ones, so it needs only the private CAs.
pub(crate) const MAX_CA_FILE_BYTES: u64 = 64 * 1024;

/// The bytes of a `ca_pem_path` file: a regular file of at most [`MAX_CA_FILE_BYTES`],
/// checked before reading and again while reading, in case it grows in between.
///
/// # Errors
///
/// A message, without the path (callers name it).
fn read_ca_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let unreadable = |e: std::io::Error| format!("cannot read the file ({e})");
    let too_big = || {
        format!(
            "the file is larger than {} KiB; list only the private CA certificates (the \
             built-in web PKI roots are trusted already)",
            MAX_CA_FILE_BYTES / 1024
        )
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let meta = file.metadata().map_err(unreadable)?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_CA_FILE_BYTES {
        return Err(too_big());
    }
    let mut pem = Vec::new();
    file.take(MAX_CA_FILE_BYTES + 1)
        .read_to_end(&mut pem)
        .map_err(unreadable)?;
    if pem.len() as u64 > MAX_CA_FILE_BYTES {
        return Err(too_big());
    }
    Ok(pem)
}

/// [`read_ca_pem`] of the bytes of the file.
fn ca_pem_certs(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, String> {
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err("the file is empty; it must hold PEM CA certificates".into());
    }
    let certs = reqwest::Certificate::from_pem_bundle(pem)
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
    entry_client_and_ca_digest(shared, ca_pem_path, timeout).map(|(client, _)| client)
}

/// [`entry_client`], and the SHA-256 of the `ca_pem_path` file's bytes as they were read for
/// it (lowercase hex), so that a change of the file's content can be told.
///
/// # Errors
///
/// As [`entry_client`].
pub(crate) fn entry_client_and_ca_digest(
    shared: &reqwest::Client,
    ca_pem_path: Option<&std::path::Path>,
    timeout: Duration,
) -> Result<(reqwest::Client, Option<String>), String> {
    use sha2::{Digest, Sha256};
    let Some(path) = ca_pem_path else {
        return Ok((shared.clone(), None));
    };
    let fail = |e: String| format!("ca_pem_path {:?}: {e}", path.display().to_string());
    let pem = read_ca_file(path).map_err(fail)?;
    let roots = ca_pem_certs(&pem).map_err(fail)?;
    let client = fetch_client(timeout, &roots).map_err(|e| {
        fail(format!(
            "a certificate cannot be used as a trust anchor ({})",
            error_chain(&e)
        ))
    })?;
    Ok((client, Some(hex::encode(Sha256::digest(&pem)))))
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

/// What a cache does when a fetch fails. The default is the IdP and `[[actor_trust]]`
/// behaviour: the keys are dropped, the next request fetches again, and the caller logs.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FailurePolicy {
    /// How long after a failed fetch the next one may start; until then the stored failure is
    /// the answer, without a fetch.
    pub(crate) backoff: Duration,
    /// A failed refetch for an unknown `kid` keeps the keys that are still within their TTL:
    /// only the request with the unknown `kid` is refused. A failed fetch of keys past their
    /// TTL still drops them (fail closed).
    pub(crate) keep_fresh_keys: bool,
    /// Log each failed fetch here, once, at warn level as `client JWKS unavailable`, so that
    /// callers answered with a stored failure log it at debug level only.
    pub(crate) warn: bool,
}

struct CacheState<K> {
    jwks_uri: Option<String>,
    keys: Vec<K>,
    fetched_at: Option<Instant>,
    last_forced: Option<Instant>,
    /// When the last failed fetch ended and why, while no later fetch has succeeded.
    failed: Option<(Instant, JwksError)>,
    /// A fetch is running (in a task of its own); callers that need it wait for it.
    fetching: bool,
    /// Fetches started so far; the one running, if any, is number `started`.
    started: u64,
    /// Fetches ended so far. A caller that started or joined fetch `n` waits until
    /// `ended >= n`, so a wake-up by the end of an earlier fetch is not taken for its own.
    ended: u64,
    /// Whether the last fetch that ended failed: what the callers that waited for it get.
    last_failed: bool,
    /// The task of the last fetch started, for a test that stops it.
    #[cfg(test)]
    task: Option<tokio::task::AbortHandle>,
}

/// A fetch made up by a test instead of an HTTP request.
#[cfg(test)]
type FakeFetch<K> = Arc<
    dyn Fn()
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<K>, JwksError>> + Send>>
        + Send
        + Sync,
>;

struct Inner<K> {
    client: reqwest::Client,
    issuer: String,
    configured_url: Option<String>,
    ttl: Duration,
    on_failure: FailurePolicy,
    parse: ParseKeys<K>,
    state: StdMutex<CacheState<K>>,
    /// Bumped each time a fetch ends, so that callers waiting for it wake up.
    done: watch::Sender<u64>,
    #[cfg(test)]
    fake: Option<FakeFetch<K>>,
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
            FailurePolicy::default(),
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
    /// A cache whose fetched documents `parse` turns into keys, and which handles a failed
    /// fetch as `on_failure` says. `label` names the cache in log lines and is given to
    /// `parse`. With `jwks_url` unset the URL is discovered at `label`, which is then the
    /// issuer.
    pub(crate) fn with_parser(
        client: reqwest::Client,
        label: String,
        jwks_url: Option<String>,
        ttl: Duration,
        on_failure: FailurePolicy,
        parse: ParseKeys<K>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                client,
                issuer: label,
                configured_url: jwks_url,
                ttl,
                on_failure,
                parse,
                state: StdMutex::new(CacheState {
                    jwks_uri: None,
                    keys: Vec::new(),
                    fetched_at: None,
                    last_forced: None,
                    failed: None,
                    fetching: false,
                    started: 0,
                    ended: 0,
                    last_failed: false,
                    #[cfg(test)]
                    task: None,
                }),
                done: watch::channel(0).0,
                #[cfg(test)]
                fake: None,
            }),
        }
    }

    /// The key `pick` chooses from the cached keys. `pick` answers `Ok(None)` for "not in
    /// this set", which is worth one refetch (key rotation), and an error for a refusal that
    /// a refetch would not change.
    ///
    /// The keys are fetched when there are none younger than the TTL. When `pick` finds
    /// nothing in fresh keys, they are fetched once more, at most once per
    /// [`UNKNOWN_KID_REFETCH_COOLDOWN`]; within it the answer is [`JwksError::UnknownKid`]
    /// without a fetch. A failed fetch drops the cached keys (fail closed), except as the
    /// cache's [`FailurePolicy`] says. A caller that waited for a fetch is answered from the
    /// outcome of that fetch, or of a later one: the keys it fetched are used even if their
    /// TTL has passed since. `kid` is the token's, for the log line of a refetch.
    pub(crate) async fn find<T>(
        &self,
        kid: Option<&str>,
        pick: impl Fn(&[K]) -> Result<Option<T>, JwksError>,
    ) -> Result<T, JwksError> {
        let inner = &self.inner;
        // The fetch this call waits for: one it started or joined.
        let mut waiting_for: Option<u64> = None;
        loop {
            // A fetch this call is to start, once the lock is released: never spawned under
            // it, as a runtime that is shutting down drops a new task on the spot, and the
            // task's guard then takes the lock to end its fetch.
            let mut start: Option<StartFetch<K>> = None;
            let mut done = {
                let mut st = inner.lock();
                if let Some(n) = waiting_for {
                    if st.ended >= n {
                        if st.last_failed {
                            return Err(st.failed.as_ref().map_or_else(
                                || JwksError::Unavailable("the key fetch failed".into()),
                                |(_, e)| e.clone(),
                            ));
                        }
                        return pick(&st.keys)?.ok_or(JwksError::UnknownKid);
                    }
                    // Woken by the end of an earlier fetch: this one still runs.
                } else {
                    let fresh = st.fetched_at.is_some_and(|t| t.elapsed() < inner.ttl);
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
                            start = Some(self.begin_fetch(&mut st, true));
                        }
                    } else if !st.fetching {
                        // Within the backoff the stored failure is the answer: fail closed.
                        if let Some((at, e)) = &st.failed {
                            if at.elapsed() < inner.on_failure.backoff {
                                return Err(e.clone());
                            }
                        }
                        start = Some(self.begin_fetch(&mut st, false));
                    }
                    waiting_for = Some(st.started);
                }
                // Subscribed under the lock, so the end of the running fetch is not missed.
                inner.done.subscribe()
            };
            if let Some(start) = start {
                start.spawn();
            }
            // The sender lives in `inner`, which `self` keeps: this ends when a fetch does.
            let _ = done.changed().await;
        }
    }

    /// Mark a fetch as running, under the lock, which the caller holds after seeing none
    /// running; [`StartFetch::spawn`] starts it once the lock is released. `forced`: a
    /// refetch for an unknown `kid`, while the cached keys are fresh.
    fn begin_fetch(&self, st: &mut CacheState<K>, forced: bool) -> StartFetch<K> {
        st.fetching = true;
        st.started += 1;
        StartFetch {
            discovered: st.jwks_uri.clone(),
            guard: FetchGuard(Some((Arc::clone(&self.inner), forced))),
        }
    }
}

/// A fetch marked as running and not yet started ([`JwksCache::begin_fetch`]). Dropped
/// without [`spawn`](Self::spawn), its guard ends the fetch as failed.
struct StartFetch<K> {
    discovered: Option<String>,
    guard: FetchGuard<K>,
}

impl<K: Send + Sync + 'static> StartFetch<K> {
    /// Run the fetch in a task of its own. The state lock must not be held: if the runtime is
    /// shutting down, the task is dropped here, and its guard takes the lock.
    fn spawn(self) {
        let Self { discovered, guard } = self;
        #[cfg(test)]
        let inner = guard.0.as_ref().map(|(inner, _)| Arc::clone(inner));
        let _task = tokio::spawn(async move {
            let Some((inner, _)) = guard.0.as_ref() else {
                return;
            };
            let outcome = inner.fetch(discovered).await;
            guard.finish(outcome);
        });
        #[cfg(test)]
        if let Some(inner) = inner {
            inner.lock().task = Some(_task.abort_handle());
        }
    }
}

/// Ends a running fetch: [`finish`](Self::finish) stores its outcome; dropped without it (the
/// task panicked, was stopped, or the runtime shut down), the fetch counts as failed, so that
/// no caller waits for it forever.
struct FetchGuard<K>(Option<(Arc<Inner<K>>, bool)>);

impl<K> FetchGuard<K> {
    fn finish(mut self, outcome: Result<(Option<String>, Vec<K>), JwksError>) {
        if let Some((inner, forced)) = self.0.take() {
            end_fetch(&inner, forced, outcome);
        }
    }
}

impl<K> Drop for FetchGuard<K> {
    fn drop(&mut self) {
        if let Some((inner, forced)) = self.0.take() {
            end_fetch(
                &inner,
                forced,
                Err(JwksError::Unavailable("the key fetch stopped".into())),
            );
        }
    }
}

fn end_fetch<K>(
    inner: &Inner<K>,
    forced: bool,
    outcome: Result<(Option<String>, Vec<K>), JwksError>,
) {
    {
        let mut st = inner.lock();
        st.fetching = false;
        // One fetch at a time: the one ending is the last one started.
        st.ended = st.started;
        match outcome {
            Ok((discovered, keys)) => {
                tracing::debug!(issuer = %inner.issuer, keys = keys.len(), "JWKS fetched");
                st.jwks_uri = discovered;
                st.keys = keys;
                st.fetched_at = Some(Instant::now());
                st.failed = None;
                st.last_failed = false;
            }
            Err(e) => {
                if inner.on_failure.warn {
                    // The detail names the URL and the cause: logged, never answered (SR-17).
                    tracing::warn!(
                        client = %inner.issuer,
                        detail = ?e.to_string(),
                        "client JWKS unavailable"
                    );
                }
                let fresh = st.fetched_at.is_some_and(|t| t.elapsed() < inner.ttl);
                if !(forced && fresh && inner.on_failure.keep_fresh_keys) {
                    // Fail closed: if the refresh fails, the old keys are not used either. A
                    // discovered jwks_uri may have moved; rediscover next time.
                    st.jwks_uri = None;
                    st.keys.clear();
                    st.fetched_at = None;
                }
                st.failed = Some((Instant::now(), e));
                st.last_failed = true;
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
        #[cfg(test)]
        if let Some(fake) = &self.fake {
            return fake().await.map(|keys| (None, keys));
        }
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

    /// How long a test waits for anything that waits on another task: a fetch, a join.
    const BOUND: Duration = Duration::from_secs(10);

    /// `.bounded()` on a future: its output, or a panic after [`BOUND`], so a bug that leaves
    /// a caller waiting fails the test at once instead of hanging the run.
    trait Bounded: std::future::Future + Sized {
        fn bounded(self) -> impl std::future::Future<Output = Self::Output> {
            async move {
                tokio::time::timeout(BOUND, self)
                    .await
                    .expect("waited longer than the test bound: a caller was left waiting")
            }
        }
    }

    impl<F: std::future::Future> Bounded for F {}

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
            .bounded()
            .await
            .unwrap();
        for path in ["/moved", "/away"] {
            let Err(JwksError::Unavailable(msg)) = cache("i", Some(format!("{base}{path}")))
                .key_for(Some("a"), Algorithm::EdDSA)
                .bounded()
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
            .bounded()
            .await
        else {
            panic!("plain http off loopback must fail");
        };
        assert!(msg.contains("must be https://"), "{msg}");
        // A discovered jwks_uri is held to the same rule.
        let base = key_server().await;
        let Err(JwksError::Unavailable(msg)) = cache(&base, None)
            .key_for(Some("a"), Algorithm::EdDSA)
            .bounded()
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
        .bounded()
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_share_one_fetch() {
        use std::sync::atomic::Ordering;
        let (url, hits, _) = slow_key_server(Duration::from_millis(200)).await;
        let c = std::sync::Arc::new(cache("i", Some(url)));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move { c.key_for(Some("a"), Algorithm::EdDSA).bounded().await })
            })
            .collect();
        for t in tasks {
            t.bounded().await.unwrap().unwrap();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// No lock is held across a fetch: while an unknown `kid` waits for a slow refetch, a
    /// request with a cached key is answered from the cache.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_slow_refetch_does_not_hold_up_cached_keys() {
        use std::sync::atomic::Ordering;
        let (url, hits, _) = slow_key_server(Duration::from_secs(3)).await;
        let c = std::sync::Arc::new(cache("i", Some(url)));
        c.key_for(Some("a"), Algorithm::EdDSA)
            .bounded()
            .await
            .unwrap();
        let unknown = {
            let c = c.clone();
            tokio::spawn(async move { c.key_for(Some("zzz"), Algorithm::EdDSA).bounded().await })
        };
        // Wait until the refetch has reached the server.
        let deadline = Instant::now() + Duration::from_secs(20);
        while hits.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "the refetch never started");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        c.key_for(Some("a"), Algorithm::EdDSA)
            .bounded()
            .await
            .unwrap();
        assert!(
            !unknown.is_finished(),
            "the cached key was answered only after the refetch ended"
        );
        assert!(matches!(
            unknown.bounded().await.unwrap(),
            Err(JwksError::UnknownKid)
        ));
    }

    /// With a failure backoff, a failed fetch is the answer until it has passed: no new fetch.
    /// Without one (IdPs), the next request fetches again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
            FailurePolicy {
                backoff: Duration::from_secs(3600),
                ..FailurePolicy::default()
            },
            |doc, issuer| Ok(parse_jwks(doc, issuer)),
        );
        let pick = |keys: &[CachedKey]| select(keys, Some("a"), Algorithm::EdDSA);
        for _ in 0..5 {
            let Err(e) = backoff.find(Some("a"), pick).bounded().await else {
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
            assert!(plain
                .key_for(Some("a"), Algorithm::EdDSA)
                .bounded()
                .await
                .is_err());
        }
        assert_eq!(hits.load(Ordering::SeqCst), 4);
        // Back up: the cache without a backoff recovers on the next request.
        down.store(false, Ordering::SeqCst);
        plain
            .key_for(Some("a"), Algorithm::EdDSA)
            .bounded()
            .await
            .unwrap();
    }

    /// What one made-up fetch does.
    enum Step {
        Answer(Result<Vec<&'static str>, JwksError>),
        Panic,
        Hang,
    }

    /// A cache of made-up keys (`kid`s) whose fetches the test answers one by one with
    /// `steps`; `calls` counts the fetches started.
    fn scripted(
        ttl: Duration,
        on_failure: FailurePolicy,
    ) -> (
        JwksCache<&'static str>,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::sync::mpsc::UnboundedSender<Step>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Step>();
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let fake: FakeFetch<&'static str> = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            let rx = Arc::clone(&rx);
            Box::pin(async move {
                let step = rx.lock().await.recv().await;
                match step {
                    Some(Step::Answer(outcome)) => outcome,
                    Some(Step::Panic) => panic!("a made-up fetch panics"),
                    Some(Step::Hang) => std::future::pending().await,
                    None => Err(JwksError::Unavailable("no more steps".into())),
                }
            })
        });
        let mut cache = JwksCache::with_parser(
            reqwest::Client::new(),
            "scripted".into(),
            Some("https://keys.invalid/jwks".into()),
            ttl,
            on_failure,
            |_, _| Err("not fetched over HTTP".into()),
        );
        Arc::get_mut(&mut cache.inner).expect("not shared yet").fake = Some(fake);
        (cache, calls, tx)
    }

    fn keys(kids: &[&'static str]) -> Step {
        Step::Answer(Ok(kids.to_vec()))
    }

    fn down() -> Step {
        Step::Answer(Err(JwksError::Unavailable("down".into())))
    }

    /// Look `kid` up in a scripted cache.
    async fn lookup(
        cache: &JwksCache<&'static str>,
        kid: &'static str,
    ) -> Result<&'static str, JwksError> {
        cache
            .find(Some(kid), |keys| {
                Ok(keys.iter().copied().find(|k| *k == kid))
            })
            .bounded()
            .await
    }

    async fn calls_reach(calls: &std::sync::atomic::AtomicUsize, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while calls.load(std::sync::atomic::Ordering::SeqCst) < n {
            assert!(Instant::now() < deadline, "fetch {n} never started");
            tokio::task::yield_now().await;
        }
    }

    /// Wait until `n` callers wait for a fetch of `cache` (each holds a receiver of its end).
    async fn callers_wait(cache: &JwksCache<&'static str>, n: usize) {
        let deadline = Instant::now() + BOUND;
        while cache.inner.done.receiver_count() < n {
            assert!(Instant::now() < deadline, "{n} callers never waited");
            tokio::task::yield_now().await;
        }
    }

    /// The task of the fetch running in `cache`, once its spawn has stored it.
    async fn fetch_task(cache: &JwksCache<&'static str>) -> tokio::task::AbortHandle {
        let deadline = Instant::now() + BOUND;
        loop {
            if let Some(task) = cache.inner.lock().task.take() {
                return task;
            }
            assert!(Instant::now() < deadline, "no fetch task was stored");
            tokio::task::yield_now().await;
        }
    }

    const CLIENT: FailurePolicy = FailurePolicy {
        backoff: Duration::ZERO,
        keep_fresh_keys: true,
        warn: false,
    };

    /// A caller woken by the end of an earlier fetch keeps waiting for its own: here the
    /// wake-up that fetch 1 sends after fetch 2 has started.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stale_wake_up_does_not_answer_from_an_earlier_fetch() {
        let (cache, calls, steps) = scripted(Duration::from_secs(300), FailurePolicy::default());
        let cache = Arc::new(cache);
        steps.send(down()).unwrap();
        assert!(matches!(
            lookup(&cache, "a").await,
            Err(JwksError::Unavailable(_))
        ));
        let mut second = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { lookup(&cache, "a").await })
        };
        calls_reach(&calls, 2).await;
        // What the end of fetch 1 did, late: wake every waiter.
        cache.inner.done.send_modify(|n| *n = n.wrapping_add(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut second)
                .await
                .is_err(),
            "the caller took the end of fetch 1 for the end of its own"
        );
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(second.bounded().await.unwrap(), Ok("a"));
    }

    /// A caller that waited for a fetch takes the set it got, even when the TTL has passed by
    /// the time it looks (here a TTL of zero).
    #[tokio::test]
    async fn a_waiter_takes_the_set_its_fetch_got_even_past_the_ttl() {
        let (cache, _, steps) = scripted(Duration::ZERO, FailurePolicy::default());
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
    }

    /// A client cache: a refetch for an unknown `kid` that fails keeps the fresh keys, so
    /// made-up `kid`s and a flaky key host cannot lock the real client out.
    #[tokio::test]
    async fn a_failed_unknown_kid_refetch_keeps_fresh_client_keys() {
        let (cache, calls, steps) = scripted(Duration::from_secs(300), CLIENT);
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        steps.send(down()).unwrap();
        assert!(matches!(
            lookup(&cache, "made-up").await,
            Err(JwksError::Unavailable(_))
        ));
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        // The refetch allowance is used up: no fetch, and the key in force still works.
        assert_eq!(lookup(&cache, "other").await, Err(JwksError::UnknownKid));
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A client cache still fails closed when the refresh of keys past their TTL fails.
    #[tokio::test]
    async fn a_failed_refresh_past_the_ttl_drops_client_keys() {
        let (cache, _, steps) = scripted(Duration::ZERO, CLIENT);
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        steps.send(down()).unwrap();
        assert!(matches!(
            lookup(&cache, "a").await,
            Err(JwksError::Unavailable(_))
        ));
        assert!(cache.inner.lock().keys.is_empty());
    }

    /// Without the client policy (IdPs, `[[actor_trust]]`), a failed refetch for an unknown
    /// `kid` drops the keys, as before.
    #[tokio::test]
    async fn without_the_client_policy_a_failed_refetch_drops_the_keys() {
        let (cache, calls, steps) = scripted(Duration::from_secs(300), FailurePolicy::default());
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        steps.send(down()).unwrap();
        assert!(lookup(&cache, "made-up").await.is_err());
        assert!(cache.inner.lock().keys.is_empty());
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// A fetch task that panics ends its fetch: the waiters get an error, and the next call
    /// fetches again. The panic is sent only once all four callers wait for fetch 1: a caller
    /// that came later would rightly start fetch 2, which waits for a step this script sends
    /// only after every caller has its answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_fetch_task_that_panics_ends_the_fetch() {
        let (cache, calls, steps) = scripted(Duration::from_secs(300), FailurePolicy::default());
        let cache = Arc::new(cache);
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let cache = Arc::clone(&cache);
                tokio::spawn(async move { lookup(&cache, "a").await })
            })
            .collect();
        calls_reach(&calls, 1).await;
        callers_wait(&cache, 4).await;
        steps.send(Step::Panic).unwrap();
        for w in waiters {
            let Err(JwksError::Unavailable(msg)) = w.bounded().await.unwrap() else {
                panic!("a waiter of a panicked fetch must get an error");
            };
            assert!(msg.contains("stopped"), "{msg}");
        }
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A fetch task that is stopped (aborted) ends its fetch the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stopped_fetch_task_ends_the_fetch() {
        let (cache, calls, steps) = scripted(Duration::from_secs(300), FailurePolicy::default());
        let cache = Arc::new(cache);
        steps.send(Step::Hang).unwrap();
        let waiter = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { lookup(&cache, "a").await })
        };
        calls_reach(&calls, 1).await;
        fetch_task(&cache).await.abort();
        let Err(JwksError::Unavailable(msg)) = waiter.bounded().await.unwrap() else {
            panic!("a waiter of a stopped fetch must get an error");
        };
        assert!(msg.contains("stopped"), "{msg}");
        steps.send(keys(&["a"])).unwrap();
        assert_eq!(lookup(&cache, "a").await, Ok("a"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A fetch started while the runtime shuts down: tokio drops the new task where it is
    /// spawned, and the task's guard takes the state lock to end the fetch. Were the task
    /// spawned under that lock, this thread would hang on it; instead the fetch ends as failed
    /// and `find` answers. The runtime here is shut down before the call, so every spawn is
    /// dropped at once; the lookup is polled by hand, since no runtime runs it.
    #[test]
    fn a_fetch_started_while_the_runtime_shuts_down_does_not_hang() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = rt.handle().clone();
        drop(rt);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _entered = handle.enter();
            let (cache, _, _steps) = scripted(Duration::from_secs(300), CLIENT);
            let mut lookup = std::pin::pin!(lookup(&cache, "a"));
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let deadline = Instant::now() + Duration::from_secs(20);
            let out = loop {
                if let std::task::Poll::Ready(out) =
                    std::future::Future::poll(lookup.as_mut(), &mut cx)
                {
                    break Some(out);
                }
                if Instant::now() > deadline {
                    break None;
                }
                std::thread::yield_now();
            };
            let _ = tx.send(out);
        });
        let out = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the lookup hung: the fetch task was dropped under the state lock")
            .expect("the lookup never ended");
        let Err(JwksError::Unavailable(msg)) = out else {
            panic!("a fetch the runtime dropped must fail: {out:?}");
        };
        assert!(msg.contains("stopped"), "{msg}");
    }

    /// A `ca_pem_path` file over 64 KiB, or one that is not a regular file, is refused with
    /// a message that says why; one at the limit is read.
    #[test]
    fn the_ca_file_read_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let limit = usize::try_from(MAX_CA_FILE_BYTES).unwrap();
        std::fs::write(&path, vec![b' '; limit + 1]).unwrap();
        let e = read_ca_pem(&path).unwrap_err();
        assert!(e.contains("larger than 64 KiB"), "{e}");
        let shared = reqwest::Client::new();
        let e = entry_client(&shared, Some(&path), Duration::from_secs(1)).unwrap_err();
        assert!(
            e.contains("ca.pem") && e.contains("larger than 64 KiB"),
            "{e}"
        );
        // At the limit the size is not the problem: an empty (all-space) file is.
        std::fs::write(&path, vec![b' '; limit]).unwrap();
        assert!(read_ca_pem(&path).unwrap_err().contains("empty"));
        let e = read_ca_pem(dir.path()).unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
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

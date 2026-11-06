//! Sender-constrained delegation tokens (SR-24): DPoP (RFC 9449) on every route that issues or
//! accepts a token.
//!
//! **Binding.** A request to `POST /token` (exchange or hop-0 intake), or to the dev
//! `POST /admin/root-token`, that carries a valid `DPoP` header gets a token bound to the
//! proof's key: the token's `cnf.jkt` is the key's RFC 7638 thumbprint, and the token response
//! says `token_type: "DPoP"`. `[token] dpop` decides when that happens:
//!
//! | `[token] dpop` | request without a proof | request with a proof |
//! |---|---|---|
//! | `off` | unbound token | proof ignored, unbound token |
//! | `optional` (default) | unbound token | bound token |
//! | `required` | 401 `dpop_required` | bound token |
//!
//! **Use.** A bound token is accepted only with a valid proof from its key: by the proxy, as
//! the bearer of `POST /token/renew` and of AuthZEN, and as the `subject_token` of an exchange.
//! The proof must name the request's method (`htm`) and URL (`htu`: `[server] public_url` plus
//! the request path, or `http://<Host>` plus the path when `public_url` is unset; scheme, host,
//! port and path are compared, the query is not), carry `ath` = base64url(SHA-256(token)),
//! have an `iat` within `[token] dpop_max_age_seconds` of the server's clock, and a `jti` this
//! process has not seen. This holds whatever `[token] dpop` says: once bound, always bound.
//! With `dpop = "required"`, an unbound token is refused on these routes too.
//!
//! **Attenuation.** A child of a bound token must be bound (`TokenError::BindingRequired`).
//! The `DPoP` header names the key the child is bound to. When that is the parent's key, the
//! header proof must also carry the subject token's `ath`. When it is another key (a sub-agent
//! with its own key), the parent's holder must authorize the exchange with a second proof in
//! the body field `subject_token_dpop`: made by the parent's key for `POST` and the `/token`
//! URL, with `ath` of the subject token, and naming the child's key in `child_jkt` and the
//! actor in `child_actor` (SR-40), so the parent can make it and hand it to the sub-agent
//! without handing over its own key, and it is good for that key and that agent only. A stolen
//! bound token is then useless for exchange, too.
//!
//! A proof's `jti` is recorded only once every check of the request's proofs has passed
//! (including the key match and the sign-off's names), so proofs that are refused anyway never
//! take a replay-cache slot (SR-41).
//!
//! **Errors.** 401 with `error` `dpop_required` (no proof where one is needed) or
//! `invalid_dpop_proof` (the proof fails a check, is made by another key, or is replayed), the
//! same value in `error_description`, and a `WWW-Authenticate: DPoP` challenge (RFC 9449
//! §7.1). The proxy answers with JSON-RPC `-32001` and the same reason codes.
//!
//! **Server nonces** (RFC 9449 §8). With `[token] dpop_nonce = "required"`, every proof the
//! server checks in a `DPoP` header must also carry a `nonce` the server issued. Nonces need no
//! storage: a nonce is base64url(HMAC-SHA256(k, bucket)), where `bucket` is the Unix time
//! divided by `[token] dpop_max_age_seconds` and `k` is derived from the issuer's signing key
//! (an ephemeral issuer key gives an ephemeral nonce key; servers that share a signing key
//! share nonces). The current and the previous bucket's nonces are accepted, so a nonce lives
//! between one and two windows. Every response to a request with a `DPoP` header, and every
//! `WWW-Authenticate: DPoP` challenge, carries the current nonce in `DPoP-Nonce`
//! ([`nonce_header`]). A proof with no nonce, or a stale or foreign one, is refused with 401
//! `use_dpop_nonce` (and `WWW-Authenticate: DPoP error="use_dpop_nonce"`) before its `jti` is
//! recorded, so the client retries once with a new proof carrying the nonce from that
//! response. The nonce is checked after the proof's signature and claims, so a bad proof is
//! still `invalid_dpop_proof`. The exchange sign-off (`subject_token_dpop`) is not a request
//! proof and needs no nonce: the parent makes it ahead of time, and it is already limited to
//! one key, one agent and the `iat` window. With `dpop_nonce = "off"` (default) a proof's
//! `nonce` is ignored.
//!
//! **Replay.** Proof `jti`s are kept in a bounded in-memory cache, per process, until the
//! proof's `iat` plus the window has passed (after that the `iat` check refuses it anyway).
//! Entries sit in time buckets, so expired ones are dropped a bucket at a time. When the cache
//! holds `[token] dpop_replay_capacity` live entries, new proofs are refused with 503
//! `temporarily_unavailable` (`dpop_replay_cache_full`): fail closed, as the credential replay
//! cache does (`crate::replay`).

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use std::sync::Arc;

use attenuo_proxy::AuthError;
use attenuo_token::dpop::{
    verify_proof, ProofCheck, VerifiedProof, DPOP_NONCE_HEADER, USE_DPOP_NONCE,
};
use attenuo_token::{Confirmation, DpopError};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::hmac;
use time::{Duration, OffsetDateTime};

use crate::config::{DpopMode, DpopNonceMode};
use crate::error::ApiError;

/// `error` / `error_description` when a proof is needed and absent.
pub const DPOP_REQUIRED: &str = "dpop_required";
/// `error` / `error_description` when a proof is present and fails.
pub const INVALID_DPOP_PROOF: &str = "invalid_dpop_proof";
/// `error` / `error_description` when a proof lacks a current server nonce (RFC 9449 §8, §9).
pub const USE_NONCE: &str = USE_DPOP_NONCE;
/// `error_description` (and the proxy's `data.reason`, with HTTP 503) when the replay cache is
/// full of live proofs.
pub const DPOP_REPLAY_CACHE_FULL: &str = "dpop_replay_cache_full";

/// Why DPoP refused a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopFailure {
    /// A proof is needed and none was sent.
    Required(String),
    /// The proof failed a check.
    Invalid(String),
    /// The proof is fine but carries no current server nonce (`[token] dpop_nonce`).
    UseNonce(String),
    /// The replay cache is full of live entries.
    Unavailable,
}

impl From<DpopError> for DpopFailure {
    fn from(e: DpopError) -> Self {
        DpopFailure::Invalid(e.to_string())
    }
}

impl From<DpopFailure> for ApiError {
    fn from(f: DpopFailure) -> Self {
        match f {
            DpopFailure::Required(detail) => {
                ApiError::new(StatusCode::UNAUTHORIZED, DPOP_REQUIRED, detail)
                    .with_description(DPOP_REQUIRED)
            }
            DpopFailure::Invalid(detail) => {
                ApiError::new(StatusCode::UNAUTHORIZED, INVALID_DPOP_PROOF, detail)
                    .with_description(INVALID_DPOP_PROOF)
            }
            DpopFailure::UseNonce(detail) => {
                ApiError::new(StatusCode::UNAUTHORIZED, USE_NONCE, detail)
                    .with_description(USE_NONCE)
            }
            DpopFailure::Unavailable => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "too many DPoP proofs in flight; retry later",
            )
            .with_description(DPOP_REPLAY_CACHE_FULL),
        }
    }
}

impl From<DpopFailure> for AuthError {
    fn from(f: DpopFailure) -> Self {
        match f {
            DpopFailure::Required(_) => AuthError::DpopRequired,
            DpopFailure::Invalid(detail) => AuthError::InvalidDpopProof(detail),
            DpopFailure::UseNonce(detail) => AuthError::UseDpopNonce(detail),
            // 503, not 401: the proof may be fine (SR-47).
            DpopFailure::Unavailable => AuthError::Unavailable(DPOP_REPLAY_CACHE_FULL.into()),
        }
    }
}

/// The DPoP checks, configured from `[token]`.
pub struct Dpop {
    mode: DpopMode,
    max_age: Duration,
    public_url: Option<String>,
    replay: ProofReplayCache,
    nonces: Option<Nonces>,
}

impl Dpop {
    /// DPoP checks in `mode`, accepting proofs whose `iat` is within `max_age_seconds` of the
    /// clock (at least 1) and remembering up to `replay_capacity` of them for replay detection.
    /// `public_url` (a trailing `/` dropped) is the base of the expected `htu`. No server nonces
    /// until [`Self::with_nonce`].
    pub fn new(
        mode: DpopMode,
        max_age_seconds: u64,
        replay_capacity: usize,
        public_url: Option<String>,
    ) -> Self {
        let secs = i64::try_from(max_age_seconds).unwrap_or(i64::MAX).max(1);
        Self {
            mode,
            max_age: Duration::seconds(secs),
            public_url: public_url.map(|u| u.trim_end_matches('/').to_owned()),
            replay: ProofReplayCache::new(replay_capacity, secs),
            nonces: None,
        }
    }

    /// Require server nonces when `mode` says so, with a nonce key derived from `secret` (the
    /// issuer's private key material). Nonce buckets are `dpop_max_age_seconds` wide.
    pub fn with_nonce(mut self, mode: DpopNonceMode, secret: &[u8]) -> Self {
        self.nonces = match mode {
            DpopNonceMode::Off => None,
            DpopNonceMode::Required => Some(Nonces::new(secret, self.max_age.whole_seconds())),
        };
        self
    }

    /// The nonce to hand out at `now`, when `[token] dpop_nonce = "required"`.
    pub fn current_nonce(&self, now: OffsetDateTime) -> Option<String> {
        self.nonces.as_ref().map(|n| n.issue(now.unix_timestamp()))
    }

    /// `[token] dpop`.
    pub fn mode(&self) -> DpopMode {
        self.mode
    }

    /// The URL a proof for a request to `path` must name in `htu`: `[server] public_url` plus
    /// the path, or `http://<Host>` plus the path when no public URL is configured. Without a
    /// public URL the server listens on loopback only (SR-19), and only a loopback `Host`
    /// (`localhost`, `127.0.0.1`, `[::1]`, optional port) is taken from the request; any other
    /// `Host` counts as `localhost`, so a proof made for another server cannot be replayed here
    /// by sending that server's name as `Host` (SR-42).
    pub fn expected_url(&self, host: Option<&str>, path: &str) -> String {
        match &self.public_url {
            Some(base) => format!("{base}{path}"),
            None => {
                let host = host
                    .filter(|h| crate::config::is_loopback_host(h))
                    .unwrap_or("localhost");
                format!("http://{host}{path}")
            }
        }
    }

    /// [`Dpop::expected_url`] with the `Host` of `headers`.
    pub fn expected_url_for(&self, headers: &HeaderMap, path: &str) -> String {
        let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
        self.expected_url(host, path)
    }

    /// Verify `proof` for a request (`method`, `url`), with `ath` checked when `access_token`
    /// is given, and use its `jti` once.
    pub fn verify(
        &self,
        proof: &str,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<VerifiedProof, DpopFailure> {
        let verified = self.check(proof, method, url, access_token, now)?;
        self.use_once(&[&verified], now)?;
        Ok(verified)
    }

    /// [`Dpop::verify`] without using up the `jti`. A caller that has more to check about the
    /// proof (whose key it is, what a sign-off names) calls [`Dpop::use_once`] after those
    /// checks, so a proof that is refused anyway never takes a replay-cache slot (SR-41). With
    /// `[token] dpop_nonce = "required"` the proof must carry a current server nonce.
    fn check(
        &self,
        proof: &str,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<VerifiedProof, DpopFailure> {
        let verified = self.check_without_nonce(proof, method, url, access_token, now)?;
        if let Some(nonces) = &self.nonces {
            match verified.nonce.as_deref() {
                None => {
                    return Err(DpopFailure::UseNonce(
                        "this server requires a nonce in DPoP proofs: retry with the \
                         `DPoP-Nonce` of this response"
                            .into(),
                    ))
                }
                Some(n) if !nonces.accepts(n, now.unix_timestamp()) => {
                    return Err(DpopFailure::UseNonce(
                        "the DPoP proof's nonce is not current: retry with the `DPoP-Nonce` of \
                         this response"
                            .into(),
                    ))
                }
                Some(_) => {}
            }
        }
        Ok(verified)
    }

    /// [`Dpop::check`] without the server nonce: for the exchange sign-off, which is made by
    /// the parent ahead of time and is not a proof of the request itself.
    fn check_without_nonce(
        &self,
        proof: &str,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<VerifiedProof, DpopFailure> {
        Ok(verify_proof(
            proof,
            &ProofCheck {
                method,
                url,
                access_token,
                now,
                max_age: self.max_age,
            },
        )?)
    }

    /// Record the `jti`s of `proofs` as used: all of them, or none when one was already used or
    /// the cache is full.
    fn use_once(&self, proofs: &[&VerifiedProof], now: OffsetDateTime) -> Result<(), DpopFailure> {
        let keys: Vec<(String, i64)> = proofs
            .iter()
            .map(|p| (p.replay_key(), p.replay_until(self.max_age)))
            .collect();
        self.replay.use_all_once(&keys, now.unix_timestamp())
    }

    /// A presented token (proxy bearer, renewal, AuthZEN bearer): when it is bound
    /// (`cnf`), require a proof by its key for this request with `ath` of `token`. With
    /// `[token] dpop = "required"`, an unbound token is refused. Returns whether the request
    /// was bound. A proof sent with an unbound token is not checked.
    pub fn check_presented(
        &self,
        cnf: Option<&Confirmation>,
        token: &str,
        proof: Option<&str>,
        method: &str,
        url: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DpopFailure> {
        let Some(cnf) = cnf else {
            if self.mode == DpopMode::Required {
                return Err(DpopFailure::Required(
                    "this server accepts only DPoP-bound tokens ([token] dpop = \"required\")"
                        .into(),
                ));
            }
            return Ok(false);
        };
        let proof = proof.ok_or_else(|| {
            DpopFailure::Required("the token is bound to a key: send a DPoP proof".into())
        })?;
        let verified = self.check(proof, method, url, Some(token), now)?;
        if verified.jkt != cnf.jkt {
            // Checked before the `jti` is recorded: the holder of a stolen token, who can make
            // proofs only with keys of its own, must not be able to fill the cache (SR-41).
            return Err(DpopError::KeyMismatch.into());
        }
        self.use_once(&[&verified], now)?;
        Ok(true)
    }

    /// The key a newly issued token is bound to, from the request's `DPoP` header (a proof with
    /// no `ath` requirement): `None` without a proof (refused with `dpop = "required"`) and
    /// whenever `dpop = "off"`. For hop 0 and the dev root mint.
    pub fn bind_new(
        &self,
        proof: Option<&str>,
        method: &str,
        url: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Confirmation>, DpopFailure> {
        match (self.mode, proof) {
            (DpopMode::Off, _) => Ok(None),
            (DpopMode::Required, None) => Err(DpopFailure::Required(
                "this server issues only DPoP-bound tokens: send a DPoP proof".into(),
            )),
            (DpopMode::Optional, None) => Ok(None),
            (_, Some(p)) => {
                let v = self.verify(p, method, url, None, now)?;
                Ok(Some(Confirmation::jkt(v.jkt)))
            }
        }
    }

    /// The binding of a child token in an exchange for `actor`, and whether the requester
    /// proved possession of a bound parent's key. `header` is the request's `DPoP` header and
    /// `subject_proof` the body's `subject_token_dpop`; see the module docs for the rule.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_exchange(
        &self,
        parent_cnf: Option<&Confirmation>,
        subject_token: &str,
        actor: &str,
        header: Option<&str>,
        subject_proof: Option<&str>,
        url: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Confirmation>, DpopFailure> {
        let Some(parent) = parent_cnf else {
            return self.bind_new(header, "POST", url, now);
        };
        let Some(header) = header else {
            return Err(DpopFailure::Required(
                "the subject token is bound to a key: send a DPoP proof, and the new token is \
                 bound too"
                    .into(),
            ));
        };
        let child = self.check(header, "POST", url, None, now)?;
        if child.jkt == parent.jkt {
            // One proof by the parent's key: it must cover the subject token.
            if !child.covers(subject_token) {
                return Err(DpopError::AthMismatch.into());
            }
            self.use_once(&[&child], now)?;
        } else {
            // A new key for the child: the parent's holder signs off with its own proof, which
            // names the child's key and agent (SR-40), so it cannot be used for another key or
            // another agent than the one the parent agreed to.
            let proof = subject_proof.ok_or_else(|| {
                DpopFailure::Required(
                    "binding the new token to another key than the subject token's needs \
                     `subject_token_dpop`, a proof by the subject token's key"
                        .into(),
                )
            })?;
            let parent_proof =
                self.check_without_nonce(proof, "POST", url, Some(subject_token), now)?;
            if parent_proof.jkt != parent.jkt {
                return Err(DpopError::KeyMismatch.into());
            }
            if parent_proof.child_jkt.as_deref() != Some(child.jkt.as_str())
                || parent_proof.child_actor.as_deref() != Some(actor)
            {
                return Err(DpopError::SignOffMismatch.into());
            }
            self.use_once(&[&child, &parent_proof], now)?;
        }
        Ok(Some(Confirmation::jkt(child.jkt)))
    }
}

/// Stateless server nonces (RFC 9449 §8): HMAC-SHA256 over a time bucket.
struct Nonces {
    key: hmac::Key,
    width: i64,
}

impl Nonces {
    /// Label of the nonce key derivation, so the key is used for nothing else.
    const LABEL: &'static [u8] = b"attenuo/dpop-nonce/v1";

    fn new(secret: &[u8], width_seconds: i64) -> Self {
        let derived = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), Self::LABEL);
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref()),
            width: width_seconds.max(1),
        }
    }

    fn bucket(&self, now: i64) -> i64 {
        now.div_euclid(self.width)
    }

    fn for_bucket(&self, bucket: i64) -> String {
        URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, &bucket.to_be_bytes()))
    }

    /// The nonce of the current bucket.
    fn issue(&self, now: i64) -> String {
        self.for_bucket(self.bucket(now))
    }

    /// Is `nonce` the current or the previous bucket's? Compared in constant time.
    fn accepts(&self, nonce: &str, now: i64) -> bool {
        let Ok(tag) = URL_SAFE_NO_PAD.decode(nonce) else {
            return false;
        };
        let current = self.bucket(now);
        [current, current.saturating_sub(1)]
            .iter()
            .any(|b| hmac::verify(&self.key, &b.to_be_bytes(), &tag).is_ok())
    }
}

/// Middleware: with `[token] dpop_nonce = "required"`, put the current nonce in a `DPoP-Nonce`
/// header on every response to a request that sent a `DPoP` proof, and on every
/// `WWW-Authenticate: DPoP` challenge (RFC 9449 §8.1), so a client always has the nonce its
/// next proof needs.
pub async fn nonce_header(State(dpop): State<Arc<Dpop>>, req: Request, next: Next) -> Response {
    let proof_sent = req.headers().contains_key("dpop");
    let mut resp = next.run(req).await;
    let Some(nonce) = dpop.current_nonce(OffsetDateTime::now_utc()) else {
        return resp;
    };
    let challenged = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("DPoP"));
    if proof_sent || challenged {
        if let Ok(v) = HeaderValue::from_str(&nonce) {
            resp.headers_mut().insert(DPOP_NONCE_HEADER, v);
        }
    }
    resp
}

/// The request's single `DPoP` header (RFC 9449 §4.3): two or more, or a non-ASCII one, is an
/// invalid proof.
pub fn header_proof(headers: &HeaderMap) -> Result<Option<&str>, DpopFailure> {
    let mut values = headers.get_all("dpop").iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(DpopFailure::Invalid("more than one DPoP header".into()));
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| DpopFailure::Invalid("DPoP header is not ASCII".into()))
}

/// Bounded one-time-use cache of proof `jti`s.
///
/// Keys are stored as 16-byte SHA-256 prefixes in buckets by expiry (a quarter of the window
/// wide), so one proof costs a few dozen bytes and expired proofs are dropped a bucket at a
/// time, without scanning. An entry may outlive its expiry by up to one bucket width, which
/// only makes the cache stricter. Full of live entries, it refuses (fail closed).
struct ProofReplayCache {
    inner: Mutex<Buckets>,
    capacity: usize,
    width: i64,
}

#[derive(Default)]
struct Buckets {
    by_end: BTreeMap<i64, HashSet<[u8; 16]>>,
    len: usize,
}

impl ProofReplayCache {
    fn new(capacity: usize, window_seconds: i64) -> Self {
        Self {
            inner: Mutex::new(Buckets::default()),
            capacity: capacity.max(1),
            width: (window_seconds / 4).max(1),
        }
    }

    #[cfg(test)]
    fn use_once(&self, key: &str, until: i64, now: i64) -> Result<(), DpopFailure> {
        self.use_all_once(&[(key.to_owned(), until)], now)
    }

    /// Record every `(key, until)` as used, or none: a key already used (or given twice) is
    /// [`DpopError::Replayed`], and a cache without room for all of them is
    /// [`DpopFailure::Unavailable`].
    fn use_all_once(&self, keys: &[(String, i64)], now: i64) -> Result<(), DpopFailure> {
        let digests: Vec<[u8; 16]> = keys.iter().map(|(k, _)| key_digest(k)).collect();
        let mut b = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Drop every bucket whose entries have all expired.
        while let Some((&end, _)) = b.by_end.first_key_value() {
            if end > now {
                break;
            }
            if let Some(set) = b.by_end.remove(&end) {
                b.len -= set.len();
            }
        }
        for (i, digest) in digests.iter().enumerate() {
            if digests[..i].contains(digest) || b.by_end.values().any(|set| set.contains(digest)) {
                return Err(DpopError::Replayed.into());
            }
        }
        if b.len.saturating_add(digests.len()) > self.capacity {
            tracing::error!(
                capacity = self.capacity,
                "DPoP replay cache full of live proofs; refusing"
            );
            return Err(DpopFailure::Unavailable);
        }
        for ((_, until), digest) in keys.iter().zip(digests) {
            // The bucket ends at the first multiple of `width` after `until`.
            let end = (until.div_euclid(self.width) + 1).saturating_mul(self.width);
            b.by_end.entry(end).or_default().insert(digest);
            b.len += 1;
        }
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len
    }
}

fn key_digest(key: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let full = Sha256::digest(key.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_token::DpopKey;

    fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    #[test]
    fn replay_cache_refuses_reuse_until_expiry_and_fails_closed_when_full() {
        let c = ProofReplayCache::new(2, 300);
        c.use_once("a", 1_300, 1_000).unwrap();
        assert_eq!(
            c.use_once("a", 1_300, 1_000),
            Err(DpopFailure::Invalid(DpopError::Replayed.to_string()))
        );
        c.use_once("b", 1_300, 1_000).unwrap();
        assert_eq!(c.use_once("c", 1_300, 1_000), Err(DpopFailure::Unavailable));
        // Once both have expired (plus at most one bucket), the slots are free again.
        c.use_once("c", 1_500, 1_400).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn replayed_proof_is_refused() {
        let d = Dpop::new(DpopMode::Optional, 300, 100, None);
        let key = DpopKey::generate().unwrap();
        let now = t(1_000_000);
        let url = d.expected_url(Some("127.0.0.1:8080"), "/token");
        assert_eq!(url, "http://127.0.0.1:8080/token");
        let proof = key.proof("POST", &url, None, now);
        assert!(d
            .bind_new(Some(&proof), "POST", &url, now)
            .unwrap()
            .is_some());
        assert!(matches!(
            d.bind_new(Some(&proof), "POST", &url, now),
            Err(DpopFailure::Invalid(_))
        ));
    }

    #[test]
    fn presented_tokens_need_a_proof_by_their_key() {
        let d = Dpop::new(
            DpopMode::Optional,
            300,
            100,
            Some("https://ob.example/".into()),
        );
        let (key, other) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
        let now = t(1_000_000);
        let url = d.expected_url(Some("ignored"), "/token/renew");
        assert_eq!(url, "https://ob.example/token/renew");
        let cnf = Confirmation::jkt(key.thumbprint());
        let check =
            |proof: Option<&str>| d.check_presented(Some(&cnf), "tok", proof, "POST", &url, now);
        assert!(matches!(check(None), Err(DpopFailure::Required(_))));
        let wrong_key = other.proof("POST", &url, Some("tok"), now);
        assert_eq!(check(Some(&wrong_key)), Err(DpopError::KeyMismatch.into()));
        assert_eq!(
            check(Some(&key.proof("POST", &url, Some("tok"), now))),
            Ok(true)
        );
        // Unbound tokens pass unless DPoP is required.
        assert_eq!(
            d.check_presented(None, "tok", None, "POST", &url, now),
            Ok(false)
        );
        let strict = Dpop::new(DpopMode::Required, 300, 100, None);
        assert!(matches!(
            strict.check_presented(None, "tok", None, "POST", &url, now),
            Err(DpopFailure::Required(_))
        ));
    }

    #[test]
    fn exchange_binding_rule() {
        let d = Dpop::new(DpopMode::Optional, 300, 100, None);
        let (parent, child) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
        let now = t(1_000_000);
        let url = d.expected_url(None, "/token");
        let cnf = Confirmation::jkt(parent.thumbprint());
        let bind = |h: Option<&str>, s: Option<&str>| {
            d.bind_exchange(Some(&cnf), "sub", "coder", h, s, &url, now)
        };
        // No proof at all: the child cannot be unbound.
        assert!(matches!(bind(None, None), Err(DpopFailure::Required(_))));
        // Parent key, but without `ath` of the subject token.
        let no_ath = parent.proof("POST", &url, None, now);
        assert_eq!(
            bind(Some(&no_ath), None),
            Err(DpopError::AthMismatch.into())
        );
        // Parent key with `ath`: the child is bound to the same key.
        let same = parent.proof("POST", &url, Some("sub"), now);
        assert_eq!(bind(Some(&same), None), Ok(Some(cnf.clone())));
        // Another key needs the parent's sign-off, by the parent's key.
        let new_key = child.proof("POST", &url, None, now);
        assert!(matches!(
            bind(Some(&new_key), None),
            Err(DpopFailure::Required(_))
        ));
        let forged = child.sign_off(&url, "sub", child.thumbprint(), "coder", now);
        let new_key = child.proof("POST", &url, None, now);
        assert_eq!(
            bind(Some(&new_key), Some(&forged)),
            Err(DpopError::KeyMismatch.into())
        );
        // SR-40: the sign-off must name this child's key and this actor. A plain proof by the
        // parent's key, or a sign-off for another key or another agent, is refused; none of
        // the refused attempts uses up the child's header proof (SR-41).
        let other = DpopKey::generate().unwrap();
        for wrong in [
            parent.proof("POST", &url, Some("sub"), now),
            parent.sign_off(&url, "sub", other.thumbprint(), "coder", now),
            parent.sign_off(&url, "sub", child.thumbprint(), "reviewer", now),
        ] {
            assert_eq!(
                bind(Some(&new_key), Some(&wrong)),
                Err(DpopError::SignOffMismatch.into())
            );
        }
        let sign_off = parent.sign_off(&url, "sub", child.thumbprint(), "coder", now);
        assert_eq!(
            bind(Some(&new_key), Some(&sign_off)),
            Ok(Some(Confirmation::jkt(child.thumbprint())))
        );
        // Both proofs are now used.
        let fresh = child.proof("POST", &url, None, now);
        assert_eq!(
            bind(Some(&fresh), Some(&sign_off)),
            Err(DpopError::Replayed.into())
        );
        // `off` and an unbound parent: no binding; `required`: a proof is needed.
        let off = Dpop::new(DpopMode::Off, 300, 100, None);
        let p = child.proof("POST", &url, None, now);
        assert_eq!(
            off.bind_exchange(None, "sub", "coder", Some(&p), None, &url, now),
            Ok(None)
        );
        let strict = Dpop::new(DpopMode::Required, 300, 100, None);
        assert!(matches!(
            strict.bind_exchange(None, "sub", "coder", None, None, &url, now),
            Err(DpopFailure::Required(_))
        ));
    }

    /// SR-41: proofs by the wrong key never reach the replay cache, so a stolen bound token
    /// cannot be used to fill it and lock out the key's holder.
    #[test]
    fn wrong_key_proofs_do_not_fill_the_replay_cache() {
        let d = Dpop::new(DpopMode::Optional, 300, 1, None);
        let (key, thief) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
        let now = t(1_000_000);
        let url = d.expected_url(None, "/mcp/github");
        let cnf = Confirmation::jkt(key.thumbprint());
        for _ in 0..5 {
            let p = thief.proof("POST", &url, Some("tok"), now);
            assert_eq!(
                d.check_presented(Some(&cnf), "tok", Some(&p), "POST", &url, now),
                Err(DpopError::KeyMismatch.into())
            );
        }
        assert_eq!(d.replay.len(), 0);
        let p = key.proof("POST", &url, Some("tok"), now);
        assert_eq!(
            d.check_presented(Some(&cnf), "tok", Some(&p), "POST", &url, now),
            Ok(true)
        );
    }

    fn nonced(width: u64) -> Dpop {
        Dpop::new(DpopMode::Optional, width, 100, None)
            .with_nonce(DpopNonceMode::Required, b"issuer key material")
    }

    #[test]
    fn nonce_buckets_roll_over_and_the_previous_one_is_accepted() {
        let d = nonced(300);
        let n = |secs| d.current_nonce(t(secs)).unwrap();
        // One nonce per 300-second bucket.
        assert_eq!(n(1_000_200), n(1_000_499));
        assert_ne!(n(1_000_499), n(1_000_500));
        let nonces = d.nonces.as_ref().unwrap();
        let issued = n(1_000_200); // bucket [1_000_200, 1_000_500)
        assert!(nonces.accepts(&issued, 1_000_499));
        // The next bucket still takes it, the one after does not.
        assert!(nonces.accepts(&issued, 1_000_500));
        assert!(nonces.accepts(&issued, 1_000_799));
        assert!(!nonces.accepts(&issued, 1_000_800));
        // A nonce of a bucket that has not started yet is not accepted either.
        assert!(!nonces.accepts(&n(1_000_500), 1_000_499));
        // The key is the server's: another key's nonces are refused.
        let other = Dpop::new(DpopMode::Optional, 300, 100, None)
            .with_nonce(DpopNonceMode::Required, b"another key");
        assert!(!nonces.accepts(&other.current_nonce(t(1_000_200)).unwrap(), 1_000_200));
        assert!(!nonces.accepts("not base64url!", 1_000_200));
        assert!(!nonces.accepts("", 1_000_200));
    }

    #[test]
    fn proofs_need_a_current_nonce_when_required() {
        let d = nonced(300);
        let key = DpopKey::generate().unwrap();
        let now = t(1_000_000);
        let url = d.expected_url(None, "/token");
        let current = d.current_nonce(now).unwrap();
        let bind = |p: &str| d.bind_new(Some(p), "POST", &url, now);
        // Missing.
        assert!(matches!(
            bind(&key.proof("POST", &url, None, now)),
            Err(DpopFailure::UseNonce(_))
        ));
        // Wrong, and stale (two buckets old).
        for wrong in ["bm9wZQ".to_string(), d.current_nonce(t(999_000)).unwrap()] {
            let p = key.proof_with_nonce("POST", &url, None, Some(&wrong), now);
            assert!(matches!(bind(&p), Err(DpopFailure::UseNonce(_))));
        }
        // A bad proof is still `invalid_dpop_proof`, nonce or not.
        let wrong_url = key.proof_with_nonce("POST", "http://localhost/x", None, None, now);
        assert!(matches!(bind(&wrong_url), Err(DpopFailure::Invalid(_))));
        // Refused proofs did not use up a replay slot; the right nonce is accepted.
        assert_eq!(d.replay.len(), 0);
        let good = key.proof_with_nonce("POST", &url, None, Some(&current), now);
        assert!(bind(&good).unwrap().is_some());
        // The same holds for a presented bound token.
        let cnf = Confirmation::jkt(key.thumbprint());
        let mcp = d.expected_url(None, "/mcp/github");
        let without = key.proof("POST", &mcp, Some("tok"), now);
        assert!(matches!(
            d.check_presented(Some(&cnf), "tok", Some(&without), "POST", &mcp, now),
            Err(DpopFailure::UseNonce(_))
        ));
        let with = key.proof_with_nonce("POST", &mcp, Some("tok"), Some(&current), now);
        assert_eq!(
            d.check_presented(Some(&cnf), "tok", Some(&with), "POST", &mcp, now),
            Ok(true)
        );
        // The failure maps to 401 `use_dpop_nonce` and the matching proxy reason.
        let api: ApiError = DpopFailure::UseNonce("x".into()).into();
        assert_eq!(api.status, StatusCode::UNAUTHORIZED);
        assert_eq!(api.code, USE_NONCE);
        let auth: AuthError = DpopFailure::UseNonce("x".into()).into();
        assert_eq!(auth.reason(), "use_dpop_nonce");
        assert!(auth
            .challenge()
            .starts_with("DPoP error=\"use_dpop_nonce\""));
    }

    #[test]
    fn exchange_sign_off_needs_no_nonce() {
        let d = nonced(300);
        let (parent, child) = (DpopKey::generate().unwrap(), DpopKey::generate().unwrap());
        let now = t(1_000_000);
        let url = d.expected_url(None, "/token");
        let nonce = d.current_nonce(now).unwrap();
        let cnf = Confirmation::jkt(parent.thumbprint());
        let header = child.proof_with_nonce("POST", &url, None, Some(&nonce), now);
        let sign_off = parent.sign_off(&url, "sub", child.thumbprint(), "coder", now);
        assert_eq!(
            d.bind_exchange(
                Some(&cnf),
                "sub",
                "coder",
                Some(&header),
                Some(&sign_off),
                &url,
                now
            ),
            Ok(Some(Confirmation::jkt(child.thumbprint())))
        );
    }

    #[test]
    fn nonce_is_ignored_when_off() {
        let d = Dpop::new(DpopMode::Optional, 300, 100, None)
            .with_nonce(DpopNonceMode::Off, b"issuer key material");
        assert_eq!(d.current_nonce(t(1_000_000)), None);
        let key = DpopKey::generate().unwrap();
        let now = t(1_000_000);
        let url = d.expected_url(None, "/token");
        for nonce in [None, Some("anything at all")] {
            let p = key.proof_with_nonce("POST", &url, None, nonce, now);
            assert!(d.bind_new(Some(&p), "POST", &url, now).unwrap().is_some());
        }
    }

    /// SR-42: without `public_url`, only a loopback `Host` goes into the expected `htu`.
    #[test]
    fn htu_takes_only_a_loopback_host() {
        let d = Dpop::new(DpopMode::Optional, 300, 10, None);
        for host in ["127.0.0.1:8080", "localhost", "[::1]:9"] {
            assert_eq!(
                d.expected_url(Some(host), "/token"),
                format!("http://{host}/token")
            );
        }
        for host in ["evil.example", "attenuo.example.com:443", "127.0.0.1.evil"] {
            assert_eq!(
                d.expected_url(Some(host), "/token"),
                "http://localhost/token"
            );
        }
    }
}

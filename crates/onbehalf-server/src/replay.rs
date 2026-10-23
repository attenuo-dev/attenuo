//! One-time use of the credentials `POST /token` consumes.
//!
//! - **IdP intake.** An OIDC ID token or ID-JAG mints at most one root token. The key is the
//!   credential's (`iss`, `jti`), or the SHA-256 of the whole credential when it carries no
//!   `jti`. The entry lives until the credential's `exp` plus the IdP's clock skew, the last
//!   instant it could be accepted.
//! - **Exchange.** A parent token delegates to a given actor at most once. The key is the
//!   parent's `jti` and the actor, and the entry lives until the parent's `exp`. A parent can
//!   still delegate to any number of different agents; re-delegating to the same agent needs a
//!   new parent token. Renewal (`POST /token/renew`) is the way to keep a child alive.
//! - **Actor token.** An `actor_token` authenticates one request: an exchange, or a hop-0
//!   intake (where it is recorded together with the IdP credential, so a request refused for
//!   one does not use up the other). The key is the
//!   `[[actor_trust]]` entry and the token's `jti`, or the SHA-256 of its signing input when it
//!   has none; the entry lives until its `exp` plus the entry's clock skew.
//!
//! A replay is `400 invalid_grant` with `error_description` `replayed`. The cache is in
//! memory, so it is per process and empty after a restart, and it is bounded: expired entries
//! are dropped first, and when it is still full the request is refused with `503
//! temporarily_unavailable` (`replay_cache_full`) rather than forgetting an entry that might be
//! replayed. Filling it takes [`DEFAULT_REPLAY_CAPACITY`] live credentials from authenticated
//! agents.

use std::collections::HashMap;
use std::sync::Mutex;

use axum::http::StatusCode;
use time::OffsetDateTime;

use crate::error::ApiError;

/// Default number of live entries held.
pub const DEFAULT_REPLAY_CAPACITY: usize = 100_000;

/// The replay cache.
pub struct ReplayCache {
    /// Key to expiry (unix seconds).
    entries: Mutex<HashMap<String, i64>>,
    capacity: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new(DEFAULT_REPLAY_CAPACITY)
    }
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Record `key` as used until `expires_at`. Fails if it was already used and has not
    /// expired, or if the cache is full of live entries. Check and insert are one step, so two
    /// concurrent requests with the same key cannot both pass.
    pub fn use_once(
        &self,
        key: &str,
        expires_at: i64,
        now: OffsetDateTime,
    ) -> Result<(), ApiError> {
        self.use_all_once(&[(key, expires_at)], now)
    }

    /// [`ReplayCache::use_once`] for several keys at once: either every key is recorded, or
    /// none is (so a request refused for one credential does not use up the others).
    pub fn use_all_once(&self, keys: &[(&str, i64)], now: OffsetDateTime) -> Result<(), ApiError> {
        let now = now.unix_timestamp();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        for (i, (key, _)) in keys.iter().enumerate() {
            let live = entries.get(*key).is_some_and(|&exp| exp > now);
            // The same key twice in one request is a replay as well.
            if live || keys[..i].iter().any(|(k, _)| k == key) {
                return Err(ApiError::bad_request(
                    "invalid_grant",
                    "this credential was already used; present a fresh one",
                )
                .with_description("replayed"));
            }
        }
        let new = |entries: &HashMap<String, i64>| {
            keys.iter()
                .filter(|(k, _)| !entries.contains_key(*k))
                .count()
        };
        if entries.len() + new(&entries) > self.capacity {
            entries.retain(|_, exp| *exp > now);
            if entries.len() + new(&entries) > self.capacity {
                tracing::error!(
                    capacity = self.capacity,
                    "replay cache full of live entries; refusing issuance"
                );
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "too many credentials in flight; retry later",
                )
                .with_description("replay_cache_full"));
            }
        }
        for (key, expires_at) in keys {
            entries.insert((*key).to_owned(), *expires_at);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_use_is_refused_until_expiry() {
        let c = ReplayCache::new(10);
        let t = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        c.use_once("a", 1_100, t).unwrap();
        let e = c.use_once("a", 1_100, t).unwrap_err();
        assert_eq!(e.description, Some("replayed"));
        c.use_once("b", 1_100, t).unwrap();
        // Once the credential has expired it cannot be accepted anyway, so the key is free.
        let later = OffsetDateTime::from_unix_timestamp(1_100).unwrap();
        c.use_once("a", 1_200, later).unwrap();
    }

    #[test]
    fn full_cache_drops_expired_entries_then_fails_closed() {
        let c = ReplayCache::new(2);
        let t = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        c.use_once("a", 1_010, t).unwrap();
        c.use_once("b", 1_100, t).unwrap();
        let e = c.use_once("c", 1_100, t).unwrap_err();
        assert_eq!(e.description, Some("replay_cache_full"));
        // `a` expires; its slot is reused.
        let later = OffsetDateTime::from_unix_timestamp(1_050).unwrap();
        c.use_once("c", 1_100, later).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(
            c.use_once("b", 1_100, later).unwrap_err().description,
            Some("replayed")
        );
    }

    #[test]
    fn several_keys_are_used_together_or_not_at_all() {
        let c = ReplayCache::new(3);
        let t = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        c.use_once("used", 1_100, t).unwrap();
        // One key replayed: the other is not recorded.
        let e = c
            .use_all_once(&[("fresh", 1_100), ("used", 1_100)], t)
            .unwrap_err();
        assert_eq!(e.description, Some("replayed"));
        assert_eq!(c.len(), 1);
        // The same key twice in one call is a replay.
        let e = c
            .use_all_once(&[("dup", 1_100), ("dup", 1_100)], t)
            .unwrap_err();
        assert_eq!(e.description, Some("replayed"));
        // Two keys that do not both fit: neither is recorded.
        c.use_once("b", 1_100, t).unwrap();
        let e = c
            .use_all_once(&[("x", 1_100), ("y", 1_100)], t)
            .unwrap_err();
        assert_eq!(e.description, Some("replay_cache_full"));
        assert_eq!(c.len(), 2);
        c.use_all_once(&[("x", 1_100)], t).unwrap();
        assert_eq!(c.len(), 3);
    }
}

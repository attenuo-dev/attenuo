//! One-time use of the credentials `POST /token` and `POST /approvals/{id}` consume.
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
//! - **Approval ID token.** An approver's ID token decides one approval
//!   (`routes/approvals.rs`), keyed and timed like an intake credential.
//!
//! A replay is `400 invalid_grant` with `error_description` `replayed`. The markers live in
//! the lease store ([`attenuo_audit::ReplayStore`]): with a database file they are rows of its
//! `used_credentials` table, so a credential redeemed before a restart stays redeemed; with
//! `sqlite_path = ":memory:"` they go with the process, like everything else in it. The
//! store's `INSERT` is the decision itself, in one transaction for every key of the request,
//! and nothing is cached in front of it. A store fault refuses the request with `503
//! temporarily_unavailable` (`replay_store_unavailable`): a credential whose use cannot be
//! recorded is not accepted. The store is bounded: each call deletes a batch of expired
//! markers, and when it is still full the request is refused with `503
//! temporarily_unavailable` (`replay_cache_full`) rather than forgetting a marker that might
//! be replayed. Filling it takes [`DEFAULT_REPLAY_CAPACITY`] live credentials from
//! authenticated agents.
//!
//! DPoP proofs have their own cache in memory (`crate::dpop`), not this one: see there.

use std::sync::Arc;

use attenuo_audit::{ReplayOutcome, ReplayStore};
use axum::http::StatusCode;
use time::OffsetDateTime;

use crate::error::ApiError;

/// Default number of markers held.
pub(crate) const DEFAULT_REPLAY_CAPACITY: usize = 100_000;

/// The replay cache: single use of credentials, over the lease store's markers.
pub struct ReplayCache {
    store: Arc<dyn ReplayStore>,
    capacity: usize,
}

impl ReplayCache {
    pub fn new(store: Arc<dyn ReplayStore>, capacity: usize) -> Self {
        Self {
            store,
            capacity: capacity.max(1),
        }
    }

    /// Record `key` as used until `expires_at`. Fails if it was already used and has not
    /// expired, if the store is full of live markers, or if it cannot be written. Check and
    /// insert are one step, so two concurrent requests with the same key cannot both pass.
    /// Runs a store write: call it on the blocking pool.
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
        match self
            .store
            .use_all_once(keys, now.unix_timestamp(), self.capacity)
        {
            Ok(ReplayOutcome::Recorded) => Ok(()),
            Ok(ReplayOutcome::Replayed) => Err(ApiError::bad_request(
                "invalid_grant",
                "this credential was already used; present a fresh one",
            )
            .with_description("replayed")),
            Ok(ReplayOutcome::Full) => {
                tracing::error!(
                    capacity = self.capacity,
                    "replay cache full of live entries; refusing issuance"
                );
                Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "too many credentials in flight; retry later",
                )
                .with_description("replay_cache_full"))
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "could not record a single-use credential; refusing it"
                );
                Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "the server cannot record the use of this credential; retry later",
                )
                .with_description("replay_store_unavailable"))
            }
        }
    }

    /// How many markers the store holds (live, or expired and not yet deleted); 0 when it
    /// cannot be read.
    pub fn len(&self) -> usize {
        self.store.replay_markers().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use attenuo_audit::{MemoryLeaseStore, SqliteLeaseStore};

    use super::*;

    fn caches(capacity: usize) -> Vec<ReplayCache> {
        vec![
            ReplayCache::new(Arc::new(MemoryLeaseStore::new()), capacity),
            ReplayCache::new(
                Arc::new(SqliteLeaseStore::open_in_memory().unwrap()),
                capacity,
            ),
        ]
    }

    #[test]
    fn second_use_is_refused_until_expiry() {
        for c in caches(10) {
            let t = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
            c.use_once("a", 1_100, t).unwrap();
            let e = c.use_once("a", 1_100, t).unwrap_err();
            assert_eq!(e.status, StatusCode::BAD_REQUEST);
            assert_eq!(e.description, Some("replayed"));
            c.use_once("b", 1_100, t).unwrap();
            // Once the credential has expired it cannot be accepted anyway, so the key is free.
            let later = OffsetDateTime::from_unix_timestamp(1_100).unwrap();
            c.use_once("a", 1_200, later).unwrap();
        }
    }

    #[test]
    fn full_cache_drops_expired_entries_then_fails_closed() {
        for c in caches(2) {
            let t = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
            c.use_once("a", 1_010, t).unwrap();
            c.use_once("b", 1_100, t).unwrap();
            let e = c.use_once("c", 1_100, t).unwrap_err();
            assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
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
    }

    #[test]
    fn several_keys_are_used_together_or_not_at_all() {
        for c in caches(3) {
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

    /// A marker that cannot be written refuses the credential (fail closed) with a 503 the
    /// client may retry, and the code is in the table.
    #[test]
    fn a_store_fault_refuses_the_credential() {
        let store = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
        store
            .with_connection(|c| Ok(c.execute_batch("DROP TABLE used_credentials")?))
            .unwrap();
        let c = ReplayCache::new(store, 10);
        let t = OffsetDateTime::from_unix_timestamp(1_000).unwrap();
        let e = c.use_once("a", 1_100, t).unwrap_err();
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.code, "temporarily_unavailable");
        assert_eq!(e.description, Some("replay_store_unavailable"));
        e.debug_check();
    }
}

//! Single use of credentials: the markers behind the server's replay cache.
//!
//! A credential that may be redeemed once (an IdP ID token or ID-JAG at hop 0, an actor token,
//! a `(parent jti, actor)` exchange, an approver's ID token) is recorded under a key until the
//! last instant it could still be accepted. [`ReplayStore::use_all_once`] is the one step that
//! both decides "first use" and records it: a key whose marker is live is refused, and a
//! request with several keys records all of them or none.
//!
//! [`SqliteLeaseStore`] keeps the markers in the `used_credentials` table of its file (schema
//! version 3), so they survive a restart. The decision is the `INSERT` itself: in one `BEGIN
//! IMMEDIATE` transaction each key is inserted, or its expired marker overwritten, and an
//! insert that changes no row (a live marker) rolls the whole transaction back. Nothing is
//! cached in front of it, so there is no second copy that could disagree with the file. The
//! key is stored as its SHA-256, so the table holds no issuer, `jti` or agent id.
//! [`MemoryLeaseStore`] keeps a map, lost with the process.
//!
//! Both are bounded: a call that would leave more than `capacity` markers is refused with
//! [`ReplayOutcome::Full`] instead of forgetting a live one. The file store deletes up to
//! [`REPLAY_PRUNE_BATCH`] expired markers (or as many as the call has keys, if more) in every
//! call, through an index on the expiry, so the work per call is bounded and the table does
//! not fill with dead rows while credentials keep arriving. Since a call deletes at least as
//! many expired markers as it adds, whenever that many have expired, it is refused only when
//! every marker left is live. The memory store drops every expired marker when it is full, as
//! the server's cache did before the file store.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::AuditError;
#[cfg(doc)]
use crate::{MemoryLeaseStore, SqliteLeaseStore};

/// The most expired markers one [`ReplayStore::use_all_once`] call deletes, unless it records
/// more keys than this.
pub const REPLAY_PRUNE_BATCH: usize = 64;

/// What [`ReplayStore::use_all_once`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// No key had a live marker; every key is now recorded.
    Recorded,
    /// A key has a live marker, or was given twice in one call; nothing was recorded.
    Replayed,
    /// Recording the keys would leave more than `capacity` markers, even after expired ones
    /// were dropped; nothing was recorded.
    Full,
}

/// Single-use markers of credentials (see the [module docs](self)).
///
/// # Errors
///
/// Every method fails on a store fault: [`AuditError::Poisoned`] when a writer panicked
/// holding the store's lock, and for [`SqliteLeaseStore`] [`AuditError::Sqlite`] when a query
/// or the commit fails. A fault records nothing, and the caller must treat it as a refusal.
pub trait ReplayStore: Send + Sync {
    /// Record every key in `keys` as used until its expiry (Unix seconds), or none of them.
    ///
    /// A marker is live while its expiry is after `now`; an expired marker for the same key is
    /// overwritten. The check and the write are one step, so of two concurrent calls with the
    /// same key exactly one gets [`ReplayOutcome::Recorded`]. At most `capacity` markers
    /// (at least 1) are kept.
    ///
    /// # Errors
    ///
    /// A store fault (see [`ReplayStore`]); nothing is recorded.
    fn use_all_once(
        &self,
        keys: &[(&str, i64)],
        now: i64,
        capacity: usize,
    ) -> Result<ReplayOutcome, AuditError>;

    /// How many markers are stored, live or expired but not yet deleted.
    ///
    /// # Errors
    ///
    /// A store fault (see [`ReplayStore`]).
    fn replay_markers(&self) -> Result<usize, AuditError>;

    /// Whether `key` has a live marker at `now` (its expiry after `now`). Reads only: nothing
    /// is recorded or deleted. For a refusal that must not use a credential up but must not
    /// treat a used one as fresh either. A later [`use_all_once`](Self::use_all_once) still
    /// decides the use.
    ///
    /// # Errors
    ///
    /// A store fault (see [`ReplayStore`]).
    fn is_used(&self, key: &str, now: i64) -> Result<bool, AuditError>;
}

/// Whether some key appears twice in `keys`: the same credential twice in one request is a
/// replay of itself.
pub(crate) fn has_duplicate(keys: &[(&str, i64)]) -> bool {
    keys.iter()
        .enumerate()
        .any(|(i, (key, _))| keys[..i].iter().any(|(k, _)| k == key))
}

/// How many expired markers a call that records `keys` deletes at most.
pub(crate) fn prune_batch(keys: usize) -> usize {
    REPLAY_PRUNE_BATCH.max(keys)
}

/// The in-memory markers of [`MemoryLeaseStore`].
#[derive(Debug, Default)]
pub(crate) struct MemoryReplay {
    /// Key to expiry (Unix seconds).
    entries: Mutex<HashMap<String, i64>>,
}

impl MemoryReplay {
    pub(crate) fn use_all_once(
        &self,
        keys: &[(&str, i64)],
        now: i64,
        capacity: usize,
    ) -> Result<ReplayOutcome, AuditError> {
        if has_duplicate(keys) {
            return Ok(ReplayOutcome::Replayed);
        }
        let mut entries = self.entries.lock()?;
        if keys
            .iter()
            .any(|(key, _)| entries.get(*key).is_some_and(|&exp| exp > now))
        {
            return Ok(ReplayOutcome::Replayed);
        }
        let new = |entries: &HashMap<String, i64>| {
            keys.iter()
                .filter(|(k, _)| !entries.contains_key(*k))
                .count()
        };
        let capacity = capacity.max(1);
        if entries.len() + new(&entries) > capacity {
            entries.retain(|_, exp| *exp > now);
            if entries.len() + new(&entries) > capacity {
                return Ok(ReplayOutcome::Full);
            }
        }
        for (key, expires_at) in keys {
            entries.insert((*key).to_owned(), *expires_at);
        }
        Ok(ReplayOutcome::Recorded)
    }

    pub(crate) fn len(&self) -> Result<usize, AuditError> {
        Ok(self.entries.lock()?.len())
    }

    pub(crate) fn is_used(&self, key: &str, now: i64) -> Result<bool, AuditError> {
        Ok(self
            .entries
            .lock()?
            .get(key)
            .is_some_and(|&expires_at| expires_at > now))
    }
}

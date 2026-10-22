//! Lease registry: the revocation half of accountability.
//!
//! Every delegation hop holds a [`LeaseId`]. Leases form a tree through their `parent` link, so
//! revoking one revokes everything delegated from it. A lease the store does not know is
//! reported as `unknown` and counts as inactive: a store that lost rows fails closed.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use onbehalf_core::LeaseId;
use time::OffsetDateTime;

use crate::error::AuditError;

/// Outcome of checking a set of leases together (typically every lease in a chain).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeaseStatus {
    /// `true` only when every lease is known, unrevoked and unexpired.
    pub active: bool,
    pub revoked: Vec<LeaseId>,
    pub expired: Vec<LeaseId>,
    pub unknown: Vec<LeaseId>,
}

/// Registry of leases and their revocation state.
pub trait LeaseStore: Send + Sync {
    /// Record a lease. Registering an id that already exists overwrites its parent and expiry
    /// but never clears a revocation.
    fn register(
        &self,
        lease: &LeaseId,
        parent: Option<&LeaseId>,
        expires_at: OffsetDateTime,
    ) -> Result<(), AuditError>;

    /// Revoke `lease` and every lease descended from it. Returns how many leases changed from
    /// unrevoked to revoked (already-revoked ones are not counted again). Revoking an unknown
    /// lease is an error, so a typo cannot pass for a successful revocation.
    fn revoke(&self, lease: &LeaseId, reason: &str, now: OffsetDateTime)
        -> Result<u64, AuditError>;

    /// Set the expiry of `lease` to `new_expires_at` (a heartbeat). The caller computes the
    /// new value and is responsible for capping it (token expiry, parent lease); the store
    /// only refuses leases it must not revive: an unknown id is [`AuditError::UnknownLease`]
    /// and a revoked one is [`AuditError::LeaseRevoked`]. An expired but unrevoked lease may
    /// be renewed. Revocation state and the parent link are untouched.
    fn renew(
        &self,
        lease: &LeaseId,
        new_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), AuditError>;

    /// Known, not revoked, and `expires_at > now`.
    fn is_active(&self, lease: &LeaseId, now: OffsetDateTime) -> Result<bool, AuditError>;

    /// Classify every lease. A lease that is both revoked and expired is reported as revoked.
    fn check_all(
        &self,
        leases: &[&LeaseId],
        now: OffsetDateTime,
    ) -> Result<LeaseStatus, AuditError>;
}

/// What a store holds per lease. Shared by the memory and SQLite implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub parent: Option<LeaseId>,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoke_reason: Option<String>,
}

impl LeaseRow {
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// Fold per-lease lookups into a [`LeaseStatus`].
pub(crate) fn classify(
    leases: &[&LeaseId],
    now: OffsetDateTime,
    mut lookup: impl FnMut(&LeaseId) -> Result<Option<LeaseRow>, AuditError>,
) -> Result<LeaseStatus, AuditError> {
    let mut status = LeaseStatus::default();
    for &lease in leases {
        match lookup(lease)? {
            None => status.unknown.push(lease.clone()),
            Some(row) if row.revoked_at.is_some() => status.revoked.push(lease.clone()),
            Some(row) if row.expires_at <= now => status.expired.push(lease.clone()),
            Some(_) => {}
        }
    }
    status.active =
        status.revoked.is_empty() && status.expired.is_empty() && status.unknown.is_empty();
    Ok(status)
}

/// In-memory lease store.
#[derive(Debug, Default)]
pub struct MemoryLeaseStore {
    rows: Mutex<BTreeMap<LeaseId, LeaseRow>>,
}

impl MemoryLeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy of one lease's row, if known.
    pub fn get(&self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        Ok(self.rows.lock()?.get(lease).cloned())
    }
}

impl LeaseStore for MemoryLeaseStore {
    fn register(
        &self,
        lease: &LeaseId,
        parent: Option<&LeaseId>,
        expires_at: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let mut rows = self.rows.lock()?;
        let existing = rows.get(lease);
        let row = LeaseRow {
            parent: parent.cloned(),
            expires_at,
            revoked_at: existing.and_then(|r| r.revoked_at),
            revoke_reason: existing.and_then(|r| r.revoke_reason.clone()),
        };
        rows.insert(lease.clone(), row);
        Ok(())
    }

    fn revoke(
        &self,
        lease: &LeaseId,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<u64, AuditError> {
        let mut rows = self.rows.lock()?;
        if !rows.contains_key(lease) {
            return Err(AuditError::UnknownLease(lease.0.clone()));
        }
        // Breadth-first over the parent links. `visited` guards against a cycle a buggy caller
        // might register; a real tree never has one.
        let mut queue = VecDeque::from([lease.clone()]);
        let mut visited = std::collections::BTreeSet::new();
        let mut revoked = 0u64;
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id.clone()) {
                continue;
            }
            if let Some(row) = rows.get_mut(&id) {
                if row.revoked_at.is_none() {
                    row.revoked_at = Some(now);
                    row.revoke_reason = Some(reason.to_string());
                    revoked += 1;
                }
            }
            queue.extend(
                rows.iter()
                    .filter(|(_, r)| r.parent.as_ref() == Some(&id))
                    .map(|(child, _)| child.clone()),
            );
        }
        Ok(revoked)
    }

    fn renew(
        &self,
        lease: &LeaseId,
        new_expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let mut rows = self.rows.lock()?;
        let row = rows
            .get_mut(lease)
            .ok_or_else(|| AuditError::UnknownLease(lease.0.clone()))?;
        if row.revoked_at.is_some() {
            return Err(AuditError::LeaseRevoked(lease.0.clone()));
        }
        row.expires_at = new_expires_at;
        Ok(())
    }

    fn is_active(&self, lease: &LeaseId, now: OffsetDateTime) -> Result<bool, AuditError> {
        Ok(self
            .rows
            .lock()?
            .get(lease)
            .is_some_and(|r| r.is_active(now)))
    }

    fn check_all(
        &self,
        leases: &[&LeaseId],
        now: OffsetDateTime,
    ) -> Result<LeaseStatus, AuditError> {
        let rows = self.rows.lock()?;
        classify(leases, now, |id| Ok(rows.get(id).cloned()))
    }
}

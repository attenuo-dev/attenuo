//! Lease registry: the revocation half of accountability.
//!
//! Every delegation hop holds a [`LeaseId`]. Leases form a tree through their `parent` link, so
//! revoking one revokes everything delegated from it. A lease the store does not know is
//! reported as `unknown` and counts as inactive: a store that lost rows fails closed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use attenuo_core::LeaseId;
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

    /// Record which chain `lease` was issued for: the digest of the chain up to and including
    /// the hop that holds the lease (`DelegationChain::prefix_digest`). Write-once: binding a
    /// lease again to the same value is a no-op, to a different value is
    /// [`AuditError::BindingConflict`], and an unknown lease is [`AuditError::UnknownLease`].
    ///
    /// The issuer binds every lease it registers. A chain presented without its signed token
    /// (an AuthZEN body chain) is accepted only if every hop's prefix digest equals its lease's
    /// binding, so lease ids alone, which are not secret, cannot be stitched into a forged
    /// chain.
    fn bind(&self, lease: &LeaseId, binding: &str) -> Result<(), AuditError>;

    /// The binding recorded by [`bind`](Self::bind), or `None` (unknown or never bound).
    fn binding(&self, lease: &LeaseId) -> Result<Option<String>, AuditError>;

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

/// One lease in a [`LeaseSubtree`]: its id and its registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseNode {
    /// The lease.
    pub id: LeaseId,
    /// Its row as the store holds it (parent, expiry, revocation).
    pub row: LeaseRow,
}

/// Read-only picture of what revoking a lease would touch: the lease, everything delegated
/// from it, and the leases it was delegated from. Built by `subtree` on the lease stores; the
/// admin console shows it before an operator confirms a revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseSubtree {
    /// The lease asked about first, then its descendants breadth-first (each level ordered
    /// by id). Breadth-first so that a truncated answer keeps the leases closest to it.
    pub nodes: Vec<LeaseNode>,
    /// The lease's ancestors, nearest first: its parent, then the parent's parent, up to the
    /// root of the chain. The walk stops at a lease with no parent, at a parent the store
    /// does not know, or at a lease it has already seen (a cycle no real tree has).
    pub ancestors: Vec<LeaseNode>,
    /// Unrevoked leases in the whole subtree, counted without the `max_nodes` cap: exactly
    /// the number a revocation of this lease would report if run now.
    pub would_revoke: u64,
    /// `nodes` stops short of the whole subtree because it reached `max_nodes`.
    pub truncated: bool,
}

impl LeaseSubtree {
    /// The topmost lease reached by walking `parent`. For a well-formed tree this is the
    /// chain's first hop, which is also the audit records' `chain_id`.
    pub fn root(&self) -> &LeaseId {
        match self.ancestors.last() {
            Some(top) => &top.id,
            None => &self.nodes[0].id,
        }
    }
}

/// Order `rows` breadth-first from `start` along their parent links, children of one lease by
/// id. `rows` is a subtree found by a recursive query, whose own order is not something to
/// rely on; this gives both stores the same, stable order. Rows not reachable from `start`
/// are dropped and a lease is visited once, so a cycle cannot loop.
pub(crate) fn breadth_first(start: &LeaseId, rows: Vec<(LeaseId, LeaseRow)>) -> Vec<LeaseNode> {
    let mut children: BTreeMap<LeaseId, Vec<LeaseId>> = BTreeMap::new();
    for (id, row) in &rows {
        if let Some(parent) = &row.parent {
            children.entry(parent.clone()).or_default().push(id.clone());
        }
    }
    for kids in children.values_mut() {
        kids.sort();
    }
    let mut by_id: BTreeMap<LeaseId, LeaseRow> = rows.into_iter().collect();
    let mut out = Vec::with_capacity(by_id.len());
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([start.clone()]);
    while let Some(id) = queue.pop_front() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let Some(row) = by_id.remove(&id) else {
            continue;
        };
        if let Some(kids) = children.get(&id) {
            queue.extend(kids.iter().cloned());
        }
        out.push(LeaseNode { id, row });
    }
    out
}

/// Walk `parent` links up from `row` (the row of `start`), nearest first. Stops at a lease
/// with no parent, an unknown parent, or a lease already seen, so a cycle terminates.
pub(crate) fn ancestors_of(
    start: &LeaseId,
    row: &LeaseRow,
    mut lookup: impl FnMut(&LeaseId) -> Result<Option<LeaseRow>, AuditError>,
) -> Result<Vec<LeaseNode>, AuditError> {
    let mut seen = BTreeSet::from([start.clone()]);
    let mut out = Vec::new();
    let mut next = row.parent.clone();
    while let Some(id) = next {
        if !seen.insert(id.clone()) {
            break;
        }
        let Some(row) = lookup(&id)? else {
            break;
        };
        next = row.parent.clone();
        out.push(LeaseNode { id, row });
    }
    Ok(out)
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
    bindings: Mutex<BTreeMap<LeaseId, String>>,
}

impl MemoryLeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy of one lease's row, if known.
    pub fn get(&self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        Ok(self.rows.lock()?.get(lease).cloned())
    }

    /// What revoking `lease` would touch, without changing anything; `None` for an unknown
    /// lease. `nodes` holds at most `max_nodes` leases (at least 1); `would_revoke` counts
    /// the whole subtree. See [`LeaseSubtree`]; the SQLite store answers the same way.
    pub fn subtree(
        &self,
        lease: &LeaseId,
        max_nodes: usize,
    ) -> Result<Option<LeaseSubtree>, AuditError> {
        let rows = self.rows.lock()?;
        let Some(row) = rows.get(lease) else {
            return Ok(None);
        };
        // Same walk as `revoke`, without the writes.
        let mut found = Vec::new();
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::from([lease.clone()]);
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id.clone()) {
                continue;
            }
            if let Some(r) = rows.get(&id) {
                found.push((id.clone(), r.clone()));
            }
            queue.extend(
                rows.iter()
                    .filter(|(_, r)| r.parent.as_ref() == Some(&id))
                    .map(|(child, _)| child.clone()),
            );
        }
        let would_revoke = found.iter().filter(|(_, r)| r.revoked_at.is_none()).count() as u64;
        let mut nodes = breadth_first(lease, found);
        let max_nodes = max_nodes.max(1);
        let truncated = nodes.len() > max_nodes;
        nodes.truncate(max_nodes);
        let ancestors = ancestors_of(lease, row, |id| Ok(rows.get(id).cloned()))?;
        Ok(Some(LeaseSubtree {
            nodes,
            ancestors,
            would_revoke,
            truncated,
        }))
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

    fn bind(&self, lease: &LeaseId, binding: &str) -> Result<(), AuditError> {
        if !self.rows.lock()?.contains_key(lease) {
            return Err(AuditError::UnknownLease(lease.0.clone()));
        }
        let mut bindings = self.bindings.lock()?;
        match bindings.get(lease) {
            Some(b) if b == binding => Ok(()),
            Some(_) => Err(AuditError::BindingConflict(lease.0.clone())),
            None => {
                bindings.insert(lease.clone(), binding.to_owned());
                Ok(())
            }
        }
    }

    fn binding(&self, lease: &LeaseId) -> Result<Option<String>, AuditError> {
        Ok(self.bindings.lock()?.get(lease).cloned())
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

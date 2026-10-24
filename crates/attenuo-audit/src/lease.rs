//! Lease registry: the revocation half of accountability.
//!
//! Every delegation hop holds a [`LeaseId`]. Leases form a tree through their `parent` link, so
//! revoking one revokes everything delegated from it. A lease the store does not know is
//! reported as `unknown` and counts as inactive: a store that lost rows fails closed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use attenuo_core::LeaseId;
use time::OffsetDateTime;

use crate::approval::{rules, Approval, ApprovalState, Approver};
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

    /// Add an output label to the taint state of the delegation run `chain_id` (the lease of
    /// the run's first hop; ADR-0009). The run's lease must be known
    /// ([`AuditError::UnknownLease`] otherwise); the check and the write are one transaction.
    /// The store keeps one label per source, the one with the smallest `seq`, so reading the
    /// taint state costs the same however many results the run reads (every result is in the
    /// audit log as a `tool_result` record). Labels are never removed: taint only grows.
    fn add_label(&self, chain_id: &LeaseId, label: &RunLabel) -> Result<(), AuditError>;

    /// The taint state of the run `chain_id`: the first label of each source, ordered by
    /// `seq`. Empty for a run that has read nothing untrusted. Callers must treat an error as
    /// tainted (fail closed).
    fn labels(&self, chain_id: &LeaseId) -> Result<Vec<RunLabel>, AuditError>;

    /// Store a pending approval (ADR-0009). `approval.state` is ignored (stored as pending);
    /// `approval.expires_at` is lowered to the expiry of `approval.lease`, which must be known
    /// and live ([`AuditError::UnknownLease`], [`AuditError::LeaseRevoked`] or
    /// [`AuditError::ApprovalExpired`] otherwise); the check and the write are one
    /// transaction. When a pending, unexpired approval for the same run, lease and call hash
    /// already exists, nothing is written and that one is returned with `false`, so an agent
    /// that repeats a gated call gets the same approval id. Returns the stored approval and
    /// whether it is new.
    fn create_approval(&self, approval: &Approval) -> Result<(Approval, bool), AuditError>;

    /// One approval by id, or `None`.
    fn approval(&self, id: &str) -> Result<Option<Approval>, AuditError>;

    /// Approvals newest first, at most `limit`; only those of the run `chain_id` when given.
    fn approvals(
        &self,
        chain_id: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<Approval>, AuditError>;

    /// Grant (`grant = true`) or decline a pending approval. Refused with
    /// [`AuditError::UnknownApproval`], [`AuditError::ApprovalNotPending`],
    /// [`AuditError::ApprovalExpired`] (the approval or its lease), or
    /// [`AuditError::LeaseRevoked`]; the checks and the write are one transaction.
    fn decide_approval(
        &self,
        id: &str,
        grant: bool,
        approver: &Approver,
        now: OffsetDateTime,
    ) -> Result<Approval, AuditError>;

    /// Find a granted, unexpired approval for `call_hash` made by the hop holding `lease` in
    /// the run `chain_id`, and mark it consumed by `decision_id`, in one transaction, so two
    /// concurrent retries cannot both use it. The lease must be live. `None` when there is
    /// none.
    fn take_approval(
        &self,
        chain_id: &LeaseId,
        lease: &LeaseId,
        call_hash: &str,
        decision_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError>;

    /// Undo [`take_approval`](Self::take_approval) for a decision that did not go through
    /// (denied anyway, or its audit append failed): an approval consumed by `decision_id` is
    /// granted again. Anything else is left alone.
    fn restore_approval(&self, id: &str, decision_id: &str) -> Result<(), AuditError>;

    /// Delete an approval whose request could not be recorded.
    fn remove_approval(&self, id: &str) -> Result<(), AuditError>;
}

/// One output label on a delegation run: an untrusted result the run read (ADR-0009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLabel {
    /// `<server>/<tool>` of the call whose result carried the label.
    pub source: String,
    /// Id of the decision record that allowed that call.
    pub decision_id: String,
    /// Audit `seq` of the `tool_result` record of the result: the label's provenance.
    pub seq: u64,
    /// When the result was recorded.
    pub at: OffsetDateTime,
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
    /// Per run, the first label of each source.
    labels: Mutex<BTreeMap<LeaseId, BTreeMap<String, RunLabel>>>,
    /// Approvals by id.
    approvals: Mutex<BTreeMap<String, Approval>>,
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

    fn add_label(&self, chain_id: &LeaseId, label: &RunLabel) -> Result<(), AuditError> {
        // The rows lock is held across the insert, so the lease cannot appear or vanish in
        // between (the memory store's "transaction").
        let rows = self.rows.lock()?;
        if !rows.contains_key(chain_id) {
            return Err(AuditError::UnknownLease(chain_id.0.clone()));
        }
        let mut labels = self.labels.lock()?;
        let first = labels.entry(chain_id.clone()).or_default();
        match first.get(&label.source) {
            Some(cur) if cur.seq <= label.seq => {}
            _ => {
                first.insert(label.source.clone(), label.clone());
            }
        }
        Ok(())
    }

    fn labels(&self, chain_id: &LeaseId) -> Result<Vec<RunLabel>, AuditError> {
        Ok(self
            .labels
            .lock()?
            .get(chain_id)
            .map(|first| {
                let mut out: Vec<RunLabel> = first.values().cloned().collect();
                out.sort_by_key(|l| l.seq);
                out
            })
            .unwrap_or_default())
    }

    fn create_approval(&self, approval: &Approval) -> Result<(Approval, bool), AuditError> {
        // Lock order as in `add_label`: rows, then approvals.
        let rows = self.rows.lock()?;
        let now = approval.created_at;
        let lease_expiry = rules::live_lease(&approval.lease, rows.get(&approval.lease), now)?;
        let mut approvals = self.approvals.lock()?;
        if let Some(existing) = approvals
            .values()
            .find(|a| rules::reusable(a, approval, now))
        {
            return Ok((existing.clone(), false));
        }
        let mut stored = approval.clone();
        stored.state = ApprovalState::Pending;
        stored.approver = None;
        stored.decided_at = None;
        stored.consumed_by = None;
        stored.expires_at = stored.expires_at.min(lease_expiry);
        approvals.insert(stored.id.clone(), stored.clone());
        Ok((stored, true))
    }

    fn approval(&self, id: &str) -> Result<Option<Approval>, AuditError> {
        Ok(self.approvals.lock()?.get(id).cloned())
    }

    fn approvals(
        &self,
        chain_id: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<Approval>, AuditError> {
        let mut out: Vec<Approval> = self
            .approvals
            .lock()?
            .values()
            .filter(|a| chain_id.is_none_or(|c| &a.chain_id == c))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        out.truncate(limit);
        Ok(out)
    }

    fn decide_approval(
        &self,
        id: &str,
        grant: bool,
        approver: &Approver,
        now: OffsetDateTime,
    ) -> Result<Approval, AuditError> {
        let rows = self.rows.lock()?;
        let mut approvals = self.approvals.lock()?;
        let a = approvals
            .get_mut(id)
            .ok_or_else(|| AuditError::UnknownApproval(id.to_owned()))?;
        rules::decidable(a, now)?;
        rules::live_lease(&a.lease, rows.get(&a.lease), now)?;
        a.state = if grant {
            ApprovalState::Granted
        } else {
            ApprovalState::Declined
        };
        a.approver = Some(approver.clone());
        a.decided_at = Some(now);
        Ok(a.clone())
    }

    fn take_approval(
        &self,
        chain_id: &LeaseId,
        lease: &LeaseId,
        call_hash: &str,
        decision_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError> {
        let rows = self.rows.lock()?;
        if rules::live_lease(lease, rows.get(lease), now).is_err() {
            return Ok(None);
        }
        let mut approvals = self.approvals.lock()?;
        let Some(a) = approvals
            .values_mut()
            .filter(|a| rules::usable(a, chain_id, lease, call_hash, now))
            .min_by(|a, b| a.created_at.cmp(&b.created_at))
        else {
            return Ok(None);
        };
        a.state = ApprovalState::Consumed;
        a.consumed_by = Some(decision_id.to_owned());
        Ok(Some(a.clone()))
    }

    fn restore_approval(&self, id: &str, decision_id: &str) -> Result<(), AuditError> {
        if let Some(a) = self.approvals.lock()?.get_mut(id) {
            if a.state == ApprovalState::Consumed && a.consumed_by.as_deref() == Some(decision_id) {
                a.state = ApprovalState::Granted;
                a.consumed_by = None;
            }
        }
        Ok(())
    }

    fn remove_approval(&self, id: &str) -> Result<(), AuditError> {
        self.approvals.lock()?.remove(id);
        Ok(())
    }
}

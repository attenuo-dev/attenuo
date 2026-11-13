//! Lease registry: the revocation half of accountability.
//!
//! Every delegation hop holds a [`LeaseId`]. Leases form a tree through their `parent` link, so
//! revoking one revokes everything delegated from it. A lease the store does not know is
//! reported as `unknown` and counts as inactive: a store that lost rows fails closed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use attenuo_core::fingerprint::Fingerprint;
use attenuo_core::limits::MAX_LIMIT;
use attenuo_core::{Charge, LeaseId, LimitKind, WindowCharge};
use time::OffsetDateTime;

use crate::approval::{rules, Approval, ApprovalState, Approver};
use crate::budget::{
    plan, summarize, ChargeOutcome, CounterKey, CounterSummary, HopLimit, ValueKey,
    DISTINCT_VALUE_KIND, USAGE_KINDS,
};
use crate::error::AuditError;
use crate::spans::{
    distinct_hashes, evictions, SpanHit, SpanKey, MAX_SEQS_PER_PROBE, MAX_SPANS_PER_RUN,
};
use crate::window::{plan_windows, window_prunable, UserKey, WindowKey, WindowPrune};

/// The store traits live in [`crate::store`]; re-exported so `attenuo_audit::lease::LeaseStore`
/// keeps resolving.
pub use crate::store::LeaseStore;
use crate::store::{ApprovalStore, LeaseRegistry, RunLimits, RunState, StoreRetention};

/// Outcome of checking a set of leases together (typically every lease in a chain).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeaseStatus {
    /// `true` only when every lease is known, unrevoked and unexpired.
    pub active: bool,
    /// The leases that have been revoked.
    pub revoked: Vec<LeaseId>,
    /// The leases past their expiry.
    pub expired: Vec<LeaseId>,
    /// The leases the store has no row for, which count as inactive.
    pub unknown: Vec<LeaseId>,
}

/// Which leases a selector revocation names (`POST /admin/leases/revoke`).
///
/// A selector matches leases that are not revoked. An expired lease matches too: while its
/// token is valid, `POST /token/renew` can bring it back, so an incident revocation must not
/// leave it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseSelector {
    /// Every lease issued for this originating user (`sub`), as recorded by
    /// [`LeaseRegistry::record_subject`]. The subject is matched under every issuer.
    Subject(String),
    /// Every lease of one delegation chain: the chain id is the lease of the chain's first
    /// hop (`attenuo_core::chain_id_of`), so this is that lease and everything delegated
    /// from it. A lease that has a parent is not a chain id and matches nothing. Found
    /// through the parent links, so leases registered before subjects were recorded match.
    Chain(LeaseId),
    /// Every lease of the chains an MCP session was opened by, as recorded by
    /// [`RunState::record_session`]: the value is the session digest (SHA-256 of the
    /// `Mcp-Session-Id`, lowercase hex), and each bound chain is matched as
    /// [`LeaseSelector::Chain`] matches it. A session opened through more than one upstream
    /// can name more than one chain; an unknown session matches nothing.
    Session(String),
}

/// One recorded session binding ([`RunState::record_session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The upstream server the session was opened with.
    pub server: String,
    /// The chain id (the lease of the chain's first hop) of the caller that opened it.
    pub chain_id: LeaseId,
    /// When the proxy bound it.
    pub bound_at: OffsetDateTime,
}

/// What one [`StoreRetention::prune_sessions`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionPrune {
    /// Bindings the pass looked at (at most its `max_rows`).
    pub examined: u64,
    /// Bindings it deleted.
    pub pruned: u64,
    /// The pass reached the last binding; the next one starts from the first.
    pub wrapped: bool,
}

/// Whether a session binding may be deleted, given the row of its chain's root lease: the
/// root is revoked (a revoked lease is never renewed, so the chain can never be used again),
/// has been expired for longer than `retention` (an expired lease can be renewed while its
/// token is valid, so the grace period must cover the longest token lifetime the issuer
/// grants), or is unknown (a store that lost the row; an unknown lease is inactive). A
/// binding whose root is live, or expired within the grace period, is kept, so revoking by
/// session keeps working for every session that is or may again be in use.
pub fn session_prunable(
    root: Option<&LeaseRow>,
    now: OffsetDateTime,
    retention: time::Duration,
) -> bool {
    match root {
        None => true,
        Some(row) => row.revoked_at.is_some() || row.expires_at.saturating_add(retention) < now,
    }
}

/// What one [`StoreRetention::prune_leases`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeasePrune {
    /// Leases the pass's window looked at, tops or not.
    pub examined: u64,
    /// Leases it read outside its window, walking a run from its top to decide whether the
    /// run may go.
    pub walked: u64,
    /// Leases it deleted, descendants outside the window included. A run too wide for one
    /// pass is deleted over several, children first and its top last.
    ///
    /// `examined + walked + pruned` is at most the pass's `max_rows` (at least 1).
    pub pruned: u64,
    /// The pass reached the last lease; the next one starts from the first.
    pub wrapped: bool,
}

/// When a lease stopped being usable: when it was revoked, or when it expired if it never was.
/// An expired lease that is revoked later was renewable until the revocation, so the
/// revocation is its end.
pub fn lease_end(row: &LeaseRow) -> OffsetDateTime {
    row.revoked_at.unwrap_or(row.expires_at)
}

/// Whether a whole lease tree (a chain's root and everything delegated from it) may be
/// deleted, given the rows of all its leases: every lease ended (see [`lease_end`]) longer
/// than `retention` ago. So every lease is revoked or expired, and none can come back: a
/// revoked lease is never renewed, and an expired one can be renewed only while its token is
/// valid, which the grace period must outlast (retention above the longest token lifetime the
/// issuer grants). One lease still live, or ended within the grace period, keeps the whole
/// tree, so a child is never left without its parent row. Revoked leases wait out the grace
/// period too: deleting them would change nothing a caller can do, but it keeps them in the
/// console tree and in `lease_revoked` refusals (not `lease_unknown`) for that long. An empty
/// tree is not prunable.
pub fn tree_prunable<'a>(
    rows: impl IntoIterator<Item = &'a LeaseRow>,
    now: OffsetDateTime,
    retention: time::Duration,
) -> bool {
    let mut any = false;
    for row in rows {
        any = true;
        if lease_end(row).saturating_add(retention) >= now {
            return false;
        }
    }
    any
}

/// What a store gives [`prune_pass`]: its leases in a fixed order (SQLite `rowid`, the memory
/// store's id order), the children of one lease, one row, and the delete of one lease with
/// everything keyed by it. Every call runs inside the pass's transaction.
pub(crate) trait PruneOps {
    /// Where the window stands: the position of the last lease a pass looked at.
    type Pos: Clone;
    /// Up to `limit` leases after `after` (from the first for `None`): position, id, whether
    /// it is a top (no parent, or a parent row the store does not have), and row.
    #[allow(clippy::type_complexity)]
    fn window(
        &mut self,
        after: Option<&Self::Pos>,
        limit: usize,
    ) -> Result<Vec<(Self::Pos, LeaseId, bool, LeaseRow)>, AuditError>;
    /// Up to `limit` children of `parent`, in a fixed order, after the child `after` (from
    /// the first for `None`, or when `after` is no longer there), each with whether it has
    /// children of its own (so a leaf costs no query of its own).
    #[allow(clippy::type_complexity)]
    fn children(
        &mut self,
        parent: &LeaseId,
        after: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<(LeaseId, LeaseRow, bool)>, AuditError>;
    /// One lease's row.
    fn row(&mut self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError>;
    /// Delete `lease` with its subject, chain binding, session bindings, hop limits, run
    /// labels and span index. Whether the lease row was there.
    fn delete(&mut self, lease: &LeaseId) -> Result<bool, AuditError>;
}

/// The lease-retention state a store keeps between [`StoreRetention::prune_leases`] passes: the
/// window's position and the run being pruned, if one is.
#[derive(Debug)]
pub(crate) struct LeasePruneState<P> {
    /// The last lease the window looked at; `None` to start from the first.
    pub(crate) cursor: Option<P>,
    /// A run that did not fit in one pass, being walked or deleted.
    pub(crate) sweep: Option<RunSweep>,
}

impl<P> Default for LeasePruneState<P> {
    fn default() -> Self {
        Self {
            cursor: None,
            sweep: None,
        }
    }
}

impl<P> LeasePruneState<P> {
    /// Before `lease` is renewed or registered again. While its run is being deleted this is
    /// refused as [`AuditError::UnknownLease`]: the run was found prunable, it reads as pruned
    /// to anything that would revive it, and no part of it can become live again. While its
    /// run is being walked, the walk is abandoned and the run is decided again from its top
    /// on a later sweep, as a renewal inside one pass's transaction would have kept it.
    pub(crate) fn before_revival(&mut self, lease: &LeaseId) -> Result<(), AuditError> {
        match self.sweep.as_mut() {
            Some(s) => s.before_revival(lease),
            None => Ok(()),
        }
    }

    /// After `lease` was revoked, or a lease was registered with `lease` as its parent. A
    /// walk that has seen it is abandoned: a late revocation restarts the grace period, and a
    /// new child would be missed. Nothing changes while the run is being deleted: a revoked
    /// lease cannot come back, and a child registered under a lease being deleted becomes the
    /// top of its own run once its parent is gone, like a child registered after its parent
    /// was pruned.
    pub(crate) fn after_write(&mut self, lease: &LeaseId) {
        if let Some(s) = self.sweep.as_mut() {
            s.after_write(lease);
        }
    }

    /// Forget the run being pruned (after a failed pass, whose transaction rolled back). What
    /// earlier passes deleted is gone children first, so what is left is a whole run again,
    /// decided from its top on a later sweep.
    pub(crate) fn abandon_sweep(&mut self) {
        self.sweep = None;
    }
}

/// A run being pruned across passes. First it is walked from its top, breadth-first, checking
/// that every lease ended longer than the retention ago. Once the whole run has been seen and
/// no write touched it meanwhile, it is deleted children before parents, the top last. Both
/// take a bounded number of rows per pass.
#[derive(Debug)]
pub(crate) struct RunSweep {
    /// The parent the top names, if any (a store that lost rows): registering it again would
    /// make the top part of another run.
    top_parent: Option<LeaseId>,
    /// Every lease of the run found so far, breadth-first, the top first, with whether it has
    /// children to read. While deleting, what is left to delete, taken from the end.
    order: Vec<(LeaseId, bool)>,
    /// The leases in `order`.
    members: HashSet<LeaseId>,
    phase: SweepPhase,
}

#[derive(Debug)]
enum SweepPhase {
    /// `order[next]` is the lease whose children are being read, `after` the last child read.
    /// `tainted`: a write touched a lease already seen, so the walk is abandoned.
    Walk {
        next: usize,
        after: Option<LeaseId>,
        tainted: bool,
    },
    Delete,
}

/// How far [`RunSweep::advance`] got.
enum SweepStep {
    /// The budget ran out first.
    Pending,
    /// The run is deleted.
    Done,
    /// The run is kept: a lease in it is live or ended within the retention, or a write
    /// touched it during the walk. Nothing of it was deleted.
    Kept,
}

impl RunSweep {
    fn new(top: LeaseId, top_parent: Option<LeaseId>) -> Self {
        Self {
            top_parent,
            members: HashSet::from([top.clone()]),
            order: vec![(top, true)],
            phase: SweepPhase::Walk {
                next: 0,
                after: None,
                tainted: false,
            },
        }
    }

    fn before_revival(&mut self, lease: &LeaseId) -> Result<(), AuditError> {
        match &mut self.phase {
            SweepPhase::Walk { tainted, .. } => {
                if self.members.contains(lease) || self.top_parent.as_ref() == Some(lease) {
                    *tainted = true;
                }
                Ok(())
            }
            SweepPhase::Delete if self.members.contains(lease) => {
                Err(AuditError::UnknownLease(lease.0.clone()))
            }
            SweepPhase::Delete => Ok(()),
        }
    }

    fn after_write(&mut self, lease: &LeaseId) {
        if let SweepPhase::Walk { tainted, .. } = &mut self.phase {
            if self.members.contains(lease) {
                *tainted = true;
            }
        }
    }

    /// Spend at most `budget` lease rows on the run: each child read while walking and each
    /// lease deleted costs one, and so does reading the children of a lease that turned out
    /// to have none left. Counts them in `out`.
    fn advance(
        &mut self,
        ops: &mut impl PruneOps,
        now: OffsetDateTime,
        retention: time::Duration,
        budget: &mut usize,
        out: &mut LeasePrune,
    ) -> Result<SweepStep, AuditError> {
        while let SweepPhase::Walk {
            next,
            after,
            tainted,
        } = &mut self.phase
        {
            if *tainted {
                return Ok(SweepStep::Kept);
            }
            let Some((parent, has_kids)) = self.order.get(*next).cloned() else {
                self.phase = SweepPhase::Delete;
                break;
            };
            if !has_kids {
                *next += 1;
                continue;
            }
            if *budget == 0 {
                return Ok(SweepStep::Pending);
            }
            let limit = *budget;
            let kids = ops.children(&parent, after.as_ref(), limit)?;
            *budget -= kids.len().max(1);
            out.walked += kids.len() as u64;
            let more = kids.len() == limit;
            for (id, row, has_kids) in kids {
                if !tree_prunable([&row], now, retention) {
                    return Ok(SweepStep::Kept);
                }
                if self.members.insert(id.clone()) {
                    self.order.push((id.clone(), has_kids));
                }
                *after = Some(id);
            }
            if !more {
                *next += 1;
                *after = None;
            }
        }
        // Children before parents: breadth-first, every lease comes after its parent, so
        // taking from the end never leaves a lease whose parent row is gone, and the top goes
        // last.
        while let Some((id, _)) = self.order.last().cloned() {
            if *budget == 0 {
                return Ok(SweepStep::Pending);
            }
            *budget -= 1;
            // Defence in depth: revivals through this store are refused above, so a lease
            // that can be used again here was changed by another writer of the same file.
            // What is left is still whole (every parent is there), and is decided again.
            if let Some(row) = ops.row(&id)? {
                if row.revoked_at.is_none() && row.expires_at.saturating_add(retention) >= now {
                    return Ok(SweepStep::Kept);
                }
            }
            if ops.delete(&id)? {
                out.pruned += 1;
            }
            self.order.pop();
            self.members.remove(&id);
        }
        Ok(SweepStep::Done)
    }
}

/// One [`StoreRetention::prune_leases`] pass over `ops`: both stores' logic. The pass spends at
/// most `max_rows` lease rows (at least one): each lease the window looks at, each lease read
/// while walking a run from its top, and each lease deleted costs one. A run that does not fit
/// in what is left is carried over in `state.sweep` and continued first by the next pass; the
/// window waits at its top until it is done.
pub(crate) fn prune_pass<O: PruneOps>(
    ops: &mut O,
    state: &mut LeasePruneState<O::Pos>,
    now: OffsetDateTime,
    retention: time::Duration,
    max_rows: usize,
) -> Result<LeasePrune, AuditError> {
    let mut budget = max_rows.max(1);
    let mut out = LeasePrune::default();
    if let Some(sweep) = state.sweep.as_mut() {
        match sweep.advance(ops, now, retention, &mut budget, &mut out)? {
            SweepStep::Pending => return Ok(out),
            SweepStep::Done | SweepStep::Kept => state.sweep = None,
        }
    }
    if budget == 0 {
        return Ok(out);
    }
    let limit = budget;
    let window = ops.window(state.cursor.as_ref(), limit)?;
    let reached_end = window.len() < limit;
    for (pos, id, is_top, row) in window {
        if budget == 0 {
            return Ok(out);
        }
        budget -= 1;
        out.examined += 1;
        state.cursor = Some(pos);
        // A live top keeps its run without a walk: the common case costs its one row.
        if !is_top || !tree_prunable([&row], now, retention) {
            continue;
        }
        let mut sweep = RunSweep::new(id, row.parent);
        if let SweepStep::Pending = sweep.advance(ops, now, retention, &mut budget, &mut out)? {
            state.sweep = Some(sweep);
            return Ok(out);
        }
    }
    if reached_end {
        out.wrapped = true;
        state.cursor = None;
    }
    Ok(out)
}

/// What one [`StoreRetention::prune_run_state`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunStatePrune {
    /// Rows the pass looked at across the charge log, the counters and the approvals (at most
    /// its `max_rows`). The memory store counts one per charged decision in the log.
    pub examined: u64,
    /// Run-limit and run-usage counters deleted.
    pub pruned_counters: u64,
    /// Charge-log entries deleted, one per charged decision (however many counters it
    /// charged).
    pub pruned_charges: u64,
    /// Approvals deleted.
    pub pruned_approvals: u64,
    /// The pass reached the last approval; the next one starts from the charge log again.
    pub wrapped: bool,
}

/// Whether per-run state (a decision's charge log entry, an approval) may be deleted:
/// `lease_known` is whether any lease it is kept under (the leases a decision charged; an
/// approval's lease and its run's chain id) is still in the registry, and `last` the newest
/// time it records (a charge and its refund; an approval's creation, decision and expiry).
/// State of a lease the registry still holds is always kept: the lease registry keeps a run
/// until it has been over for `[leases] retention_seconds`, and this retention starts only
/// after that. A lease the registry does not know (pruned, or a store that lost rows) leaves
/// its state for `retention` past `last`, so the charge log stays available to an operator
/// refund and to incident review for that long. Counters have no time of their own: a counter
/// goes once its lease is unknown and no charge under that lease is left in the log.
pub fn run_state_prunable(
    lease_known: bool,
    last: OffsetDateTime,
    now: OffsetDateTime,
    retention: time::Duration,
) -> bool {
    !lease_known && last.saturating_add(retention) < now
}

/// The newest time an approval records: its creation, its decision and its expiry. An
/// approval is never pruned before it has expired.
pub fn approval_last_touched(approval: &Approval) -> OffsetDateTime {
    let mut last = approval.created_at.max(approval.expires_at);
    if let Some(d) = approval.decided_at {
        last = last.max(d);
    }
    last
}

/// The result of [`LeaseRegistry::revoke_selected`] or [`LeaseRegistry::preview_selected`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectorRevocation {
    /// The unrevoked leases the selector named, ordered by id.
    pub matched: Vec<LeaseId>,
    /// Every lease the revocation changed (or would change) from unrevoked to revoked: the
    /// matches first, ordered by id, then the descendants revoked by the cascade that were not
    /// matches themselves, ordered by id.
    pub revoked: Vec<LeaseId>,
}

impl SelectorRevocation {
    /// Build from the matches and the cascade's ids (in any order, duplicates allowed).
    pub(crate) fn from_parts(
        mut matched: Vec<LeaseId>,
        cascade: impl IntoIterator<Item = LeaseId>,
    ) -> Self {
        matched.sort();
        matched.dedup();
        let first: BTreeSet<&LeaseId> = matched.iter().collect();
        let rest: BTreeSet<LeaseId> = cascade.into_iter().filter(|l| !first.contains(l)).collect();
        let revoked = matched.iter().cloned().chain(rest).collect();
        Self { matched, revoked }
    }
}

/// One logged charge: the counter and what was added to it.
#[derive(Debug, Clone)]
struct LoggedCharge {
    counter: CounterKey,
    amount: u64,
}

/// What a decision charged, when, and whether it was refunded.
#[derive(Debug, Clone)]
struct ChargeLog {
    charges: Vec<LoggedCharge>,
    /// When the decision was charged.
    at: OffsetDateTime,
    /// When it was refunded, if it was.
    refunded_at: Option<OffsetDateTime>,
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
    /// The lease this one was delegated from; `None` for a run's root.
    pub parent: Option<LeaseId>,
    /// When the lease stops being active.
    pub expires_at: OffsetDateTime,
    /// When it was revoked, directly or as a descendant of a revoked lease.
    pub revoked_at: Option<OffsetDateTime>,
    /// The reason given with the revocation.
    pub revoke_reason: Option<String>,
}

impl LeaseRow {
    /// Unrevoked and not yet expired at `now`.
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

/// Walk `lease` and everything delegated from it, breadth-first over the parent links, and
/// return the unrevoked leases found. With `write`, mark them revoked with that reason and
/// time. `visited` is shared across calls so one revocation of several leases walks each
/// subtree once, and guards against a cycle a buggy caller might register; a real tree never
/// has one.
fn cascade(
    rows: &mut BTreeMap<LeaseId, LeaseRow>,
    lease: &LeaseId,
    write: Option<(&str, OffsetDateTime)>,
    visited: &mut BTreeSet<LeaseId>,
) -> Vec<LeaseId> {
    let mut changed = Vec::new();
    let mut queue = VecDeque::from([lease.clone()]);
    while let Some(id) = queue.pop_front() {
        if !visited.insert(id.clone()) {
            continue;
        }
        if let Some(row) = rows.get_mut(&id) {
            if row.revoked_at.is_none() {
                if let Some((reason, now)) = write {
                    row.revoked_at = Some(now);
                    row.revoke_reason = Some(reason.to_string());
                }
                changed.push(id.clone());
            }
        }
        queue.extend(
            rows.iter()
                .filter(|(_, r)| r.parent.as_ref() == Some(&id))
                .map(|(child, _)| child.clone()),
        );
    }
    changed
}

/// What [`LeaseSelector::Chain`] matches in the memory store: the unrevoked leases of the
/// subtree of `root`, or nothing when `root` is unknown or has a parent.
fn chain_matches(rows: &mut BTreeMap<LeaseId, LeaseRow>, root: &LeaseId) -> Vec<LeaseId> {
    match rows.get(root) {
        Some(r) if r.parent.is_none() => {
            let mut visited = BTreeSet::new();
            cascade(rows, root, None, &mut visited)
        }
        _ => Vec::new(),
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
    bindings: Mutex<BTreeMap<LeaseId, String>>,
    /// The originating user's subject of each lease (`record_subject`).
    subjects: Mutex<BTreeMap<LeaseId, String>>,
    /// Session bindings by `(session digest, server)` (`record_session`).
    sessions: Mutex<BTreeMap<(String, String), (LeaseId, OffsetDateTime)>>,
    /// The last session binding a `prune_sessions` pass looked at; `None` to start from the
    /// first.
    session_cursor: Mutex<Option<(String, String)>>,
    /// Where the next `prune_leases` pass starts, and the run it is pruning, if any. Taken
    /// under the rows lock.
    lease_prune: Mutex<LeasePruneState<LeaseId>>,
    /// Where the next `prune_run_state` pass starts.
    run_state_cursor: Mutex<RunStateCursor>,
    /// Per run, the first label of each source.
    labels: Mutex<BTreeMap<LeaseId, BTreeMap<String, RunLabel>>>,
    /// Per run, the span index (ADR-0009 phase 2).
    spans: Mutex<Spans>,
    /// Approvals by id, each with its position (see [`ApprovalStore::approvals`]).
    approvals: Mutex<BTreeMap<String, (u64, Approval)>>,
    /// The position the last created approval got; read and bumped under `approvals`, never
    /// lowered (removing or pruning approvals leaves it), so no position is given twice.
    approval_pos: std::sync::atomic::AtomicU64,
    /// Run-limit counters and the charges of each decision, under one lock (ADR-0010).
    budgets: Mutex<Budgets>,
    /// The limited capabilities of each hop, as issued (display only).
    hop_limits: Mutex<BTreeMap<LeaseId, Vec<HopLimit>>>,
    /// Single-use credential markers ([`crate::replay`]).
    used_credentials: crate::replay::MemoryReplay,
}

/// Where a memory store's `prune_run_state` pass resumes: the table, and the last key a pass
/// looked at in it (`None` to start from its first).
#[derive(Debug, Clone)]
enum RunStateCursor {
    Charges(Option<String>),
    Counters(Option<CounterKey>),
    Approvals(Option<String>),
}

impl Default for RunStateCursor {
    fn default() -> Self {
        Self::Charges(None)
    }
}

/// The memory store's run-limit state.
#[derive(Debug, Default)]
struct Budgets {
    /// Created on first use: generating a key can fail, and `Default` cannot.
    key: Option<ValueKey>,
    counters: BTreeMap<CounterKey, u64>,
    log: BTreeMap<String, ChargeLog>,
    /// For each `distinct` value row, how many unrefunded decisions logged it: a refund frees
    /// the value only when it was the last (SR-62).
    holders: BTreeMap<CounterKey, usize>,
    /// Per-user windows ([`crate::window`]): created on first use, like `key`.
    user_key: Option<UserKey>,
    /// What each window counter holds.
    windows: BTreeMap<WindowKey, u64>,
    /// What each decision charged to windows (counter, amount), and whether it was refunded.
    window_log: BTreeMap<String, WindowLog>,
}

/// What one decision charged to windows (counter, amount), and when it was refunded.
type WindowLog = (Vec<(WindowKey, u64)>, Option<OffsetDateTime>);

impl Budgets {
    fn keys(&mut self, charges: &[Charge]) -> Result<Vec<CounterKey>, AuditError> {
        let key = match &mut self.key {
            Some(key) => key,
            slot => slot.insert(ValueKey::random()?),
        };
        charges.iter().map(|c| key.counter(c)).collect()
    }

    fn window_keys(&mut self, windows: &[WindowCharge]) -> Result<Vec<WindowKey>, AuditError> {
        let key = match &mut self.user_key {
            Some(key) => key,
            slot => slot.insert(UserKey::random()?),
        };
        windows.iter().map(|w| key.key(w)).collect()
    }
}

/// The memory store's span indexes.
#[derive(Debug, Default)]
struct Spans {
    /// Created on first use: generating a key can fail, and `Default` cannot.
    key: Option<SpanKey>,
    runs: BTreeMap<LeaseId, RunSpans>,
}

impl Spans {
    fn key(&mut self) -> Result<SpanKey, AuditError> {
        match &self.key {
            Some(key) => Ok(key.clone()),
            None => Ok(self.key.insert(SpanKey::random()?).clone()),
        }
    }
}

/// One run's span index: each result's hashes by `seq`, and the reverse map for lookups.
#[derive(Debug, Default)]
struct RunSpans {
    by_seq: BTreeMap<u64, Vec<[u8; 32]>>,
    index: HashMap<[u8; 32], BTreeSet<u64>>,
    len: usize,
}

impl RunSpans {
    fn remove(&mut self, seq: u64) {
        for h in self.by_seq.remove(&seq).unwrap_or_default() {
            if let Some(seqs) = self.index.get_mut(&h) {
                seqs.remove(&seq);
                if seqs.is_empty() {
                    self.index.remove(&h);
                }
            }
            self.len -= 1;
        }
    }
}

impl MemoryLeaseStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// After a revocation: a revoked run's span index ends with it (`crate::spans`), and so
    /// does its run usage (`crate::budget`). Called with the rows lock held, so the lock order
    /// is rows, spans, then rows, budgets.
    fn end_runs(&self, visited: &BTreeSet<LeaseId>) -> Result<(), AuditError> {
        let mut spans = self.spans.lock()?;
        for id in visited {
            spans.runs.remove(id);
        }
        drop(spans);
        let ended = |k: &CounterKey| {
            USAGE_KINDS.contains(&k.kind) && visited.contains(&LeaseId::new(&k.lease))
        };
        let mut b = self.budgets.lock()?;
        b.counters.retain(|k, _| !ended(k));
        for entry in b.log.values_mut() {
            entry.charges.retain(|c| !ended(&c.counter));
        }
        Ok(())
    }

    /// [`LeaseRegistry::preview_selected`] and [`LeaseRegistry::revoke_selected`]: `write` carries
    /// the reason and time of a real revocation, `None` for a preview.
    fn selected(
        &self,
        selector: &LeaseSelector,
        write: Option<(&str, OffsetDateTime)>,
    ) -> Result<SelectorRevocation, AuditError> {
        let mut rows = self.rows.lock()?;
        let matched: Vec<LeaseId> = match selector {
            LeaseSelector::Subject(subject) => {
                let subjects = self.subjects.lock()?;
                subjects
                    .iter()
                    .filter(|(_, s)| *s == subject)
                    .map(|(id, _)| id)
                    .filter(|id| rows.get(*id).is_some_and(|r| r.revoked_at.is_none()))
                    .cloned()
                    .collect()
            }
            LeaseSelector::Chain(root) => chain_matches(&mut rows, root),
            LeaseSelector::Session(session) => {
                let roots: Vec<LeaseId> = self
                    .sessions
                    .lock()?
                    .range((session.clone(), String::new())..)
                    .take_while(|((s, _), _)| s == session)
                    .map(|(_, (chain, _))| chain.clone())
                    .collect();
                roots
                    .iter()
                    .flat_map(|root| chain_matches(&mut rows, root))
                    .collect()
            }
        };
        let mut visited = BTreeSet::new();
        let mut changed = Vec::new();
        for m in &matched {
            changed.extend(cascade(&mut rows, m, write, &mut visited));
        }
        if write.is_some() {
            self.end_runs(&visited)?;
            let mut prune = self.lease_prune.lock()?;
            for id in &changed {
                prune.after_write(id);
            }
        }
        Ok(SelectorRevocation::from_parts(matched, changed))
    }

    /// Copy of one lease's row, if known.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked while holding the lease table's lock.
    pub fn get(&self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        Ok(self.rows.lock()?.get(lease).cloned())
    }

    /// What revoking `lease` would touch, without changing anything; `None` for an unknown
    /// lease. `nodes` holds at most `max_nodes` leases (at least 1); `would_revoke` counts
    /// the whole subtree. See [`LeaseSubtree`]; the SQLite store answers the same way.
    ///
    /// # Errors
    ///
    /// [`AuditError::Poisoned`] when a writer panicked while holding the lease table's lock. An
    /// unknown lease is `Ok(None)`.
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

/// The memory store's side of [`prune_pass`], with its rows lock held.
struct MemoryPrune<'a> {
    store: &'a MemoryLeaseStore,
    rows: &'a mut BTreeMap<LeaseId, LeaseRow>,
}

impl PruneOps for MemoryPrune<'_> {
    type Pos = LeaseId;

    fn window(
        &mut self,
        after: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<(LeaseId, LeaseId, bool, LeaseRow)>, AuditError> {
        use std::ops::Bound;
        let start = match after {
            Some(id) => Bound::Excluded(id),
            None => Bound::Unbounded,
        };
        let rows = &*self.rows;
        Ok(rows
            .range::<LeaseId, _>((start, Bound::Unbounded))
            .take(limit)
            .map(|(id, row)| {
                let top = row.parent.as_ref().is_none_or(|p| !rows.contains_key(p));
                (id.clone(), id.clone(), top, row.clone())
            })
            .collect())
    }

    fn children(
        &mut self,
        parent: &LeaseId,
        after: Option<&LeaseId>,
        limit: usize,
    ) -> Result<Vec<(LeaseId, LeaseRow, bool)>, AuditError> {
        // Scans of every row: the memory store is for tests and development.
        let rows = &*self.rows;
        Ok(rows
            .iter()
            .filter(|(id, row)| {
                row.parent.as_ref() == Some(parent) && after.is_none_or(|a| *id > a)
            })
            .take(limit)
            .map(|(id, row)| {
                let kids = rows.values().any(|r| r.parent.as_ref() == Some(id));
                (id.clone(), row.clone(), kids)
            })
            .collect())
    }

    fn row(&mut self, lease: &LeaseId) -> Result<Option<LeaseRow>, AuditError> {
        Ok(self.rows.get(lease).cloned())
    }

    fn delete(&mut self, lease: &LeaseId) -> Result<bool, AuditError> {
        let s = self.store;
        let found = self.rows.remove(lease).is_some();
        s.bindings.lock()?.remove(lease);
        s.subjects.lock()?.remove(lease);
        s.sessions.lock()?.retain(|_, (chain, _)| chain != lease);
        s.labels.lock()?.remove(lease);
        s.spans.lock()?.runs.remove(lease);
        s.hop_limits.lock()?.remove(lease);
        Ok(found)
    }
}

impl LeaseRegistry for MemoryLeaseStore {
    fn register(
        &self,
        lease: &LeaseId,
        parent: Option<&LeaseId>,
        expires_at: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let mut rows = self.rows.lock()?;
        {
            let mut prune = self.lease_prune.lock()?;
            prune.before_revival(lease)?;
            if let Some(p) = parent {
                prune.after_write(p);
            }
        }
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
        self.lease_prune.lock()?.after_write(lease);
        let mut visited = BTreeSet::new();
        let changed = cascade(&mut rows, lease, Some((reason, now)), &mut visited);
        self.end_runs(&visited)?;
        Ok(changed.len() as u64)
    }

    fn renew(
        &self,
        lease: &LeaseId,
        new_expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), AuditError> {
        let mut rows = self.rows.lock()?;
        self.lease_prune.lock()?.before_revival(lease)?;
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

    fn record_subject(&self, lease: &LeaseId, subject: &str) -> Result<(), AuditError> {
        let rows = self.rows.lock()?;
        if !rows.contains_key(lease) {
            return Err(AuditError::UnknownLease(lease.0.clone()));
        }
        let mut subjects = self.subjects.lock()?;
        match subjects.get(lease) {
            Some(s) if s == subject => Ok(()),
            Some(_) => Err(AuditError::BindingConflict(lease.0.clone())),
            None => {
                subjects.insert(lease.clone(), subject.to_string());
                Ok(())
            }
        }
    }

    fn subject(&self, lease: &LeaseId) -> Result<Option<String>, AuditError> {
        Ok(self.subjects.lock()?.get(lease).cloned())
    }

    fn subjects(&self, leases: &[&LeaseId]) -> Result<BTreeMap<LeaseId, String>, AuditError> {
        let subjects = self.subjects.lock()?;
        Ok(leases
            .iter()
            .filter_map(|l| Some(((*l).clone(), subjects.get(*l)?.clone())))
            .collect())
    }

    fn preview_selected(&self, selector: &LeaseSelector) -> Result<SelectorRevocation, AuditError> {
        self.selected(selector, None)
    }

    fn revoke_selected(
        &self,
        selector: &LeaseSelector,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<SelectorRevocation, AuditError> {
        self.selected(selector, Some((reason, now)))
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

impl RunState for MemoryLeaseStore {
    fn record_session(
        &self,
        session: &str,
        server: &str,
        chain_id: &LeaseId,
        now: OffsetDateTime,
    ) -> Result<bool, AuditError> {
        let rows = self.rows.lock()?;
        if !rows.contains_key(chain_id) {
            return Err(AuditError::UnknownLease(chain_id.0.clone()));
        }
        let mut sessions = self.sessions.lock()?;
        let key = (session.to_owned(), server.to_owned());
        if sessions.contains_key(&key) {
            return Ok(false);
        }
        sessions.insert(key, (chain_id.clone(), now));
        Ok(true)
    }

    fn sessions(&self, session: &str) -> Result<Vec<SessionBinding>, AuditError> {
        Ok(self
            .sessions
            .lock()?
            .range((session.to_owned(), String::new())..)
            .take_while(|((s, _), _)| s == session)
            .map(|((_, server), (chain_id, bound_at))| SessionBinding {
                server: server.clone(),
                chain_id: chain_id.clone(),
                bound_at: *bound_at,
            })
            .collect())
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

    fn add_spans(
        &self,
        chain_id: &LeaseId,
        seq: u64,
        spans: &[Fingerprint],
    ) -> Result<(), AuditError> {
        // As in `add_label`, the rows lock is held across the write.
        let rows = self.rows.lock()?;
        if !rows.contains_key(chain_id) {
            return Err(AuditError::UnknownLease(chain_id.0.clone()));
        }
        if spans.is_empty() {
            return Ok(());
        }
        let mut all = self.spans.lock()?;
        let key = all.key()?;
        let mut hashes = distinct_hashes(&key, spans);
        hashes.truncate(MAX_SPANS_PER_RUN);
        let run = all.runs.entry(chain_id.clone()).or_default();
        let stored: Vec<(u64, usize)> = run.by_seq.iter().map(|(s, v)| (*s, v.len())).collect();
        for old in evictions(&stored, hashes.len()) {
            run.remove(old);
        }
        run.remove(seq);
        for h in &hashes {
            run.index.entry(*h).or_default().insert(seq);
        }
        run.len += hashes.len();
        run.by_seq.insert(seq, hashes);
        Ok(())
    }

    fn find_spans(
        &self,
        chain_id: &LeaseId,
        probes: &[Fingerprint],
    ) -> Result<Vec<SpanHit>, AuditError> {
        let mut all = self.spans.lock()?;
        let key = all.key()?;
        let Some(run) = all.runs.get(chain_id) else {
            return Ok(Vec::new());
        };
        let mut hits = Vec::new();
        for (probe, f) in probes.iter().enumerate() {
            if let Some(seqs) = run.index.get(&key.hash(f)) {
                hits.extend(
                    seqs.iter()
                        .take(MAX_SEQS_PER_PROBE)
                        .map(|&seq| SpanHit { probe, seq }),
                );
            }
        }
        Ok(hits)
    }
}

impl ApprovalStore for MemoryLeaseStore {
    fn create_approval(&self, approval: &Approval) -> Result<(Approval, bool), AuditError> {
        // Lock order as in `add_label`: rows, then approvals.
        let rows = self.rows.lock()?;
        let now = approval.created_at;
        let lease_expiry = rules::live_lease(&approval.lease, rows.get(&approval.lease), now)?;
        let mut approvals = self.approvals.lock()?;
        if let Some((_, existing)) = approvals
            .values()
            .find(|(_, a)| rules::reusable(a, approval, now))
        {
            return Ok((existing.clone(), false));
        }
        let pending = approvals
            .values()
            .filter(|(_, a)| {
                rules::counts_as_pending(a, rows.get(&a.lease), &approval.chain_id, now)
            })
            .count();
        rules::below_pending_cap(&approval.chain_id, pending)?;
        let mut stored = approval.clone();
        stored.state = ApprovalState::Pending;
        stored.approver = None;
        stored.decided_at = None;
        stored.consumed_by = None;
        stored.expires_at = stored.expires_at.min(lease_expiry);
        // Bumped under the `approvals` lock, so positions follow insertion order.
        let pos = self
            .approval_pos
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        approvals.insert(stored.id.clone(), (pos, stored.clone()));
        Ok((stored, true))
    }

    fn approval(&self, id: &str) -> Result<Option<Approval>, AuditError> {
        Ok(self.approvals.lock()?.get(id).map(|(_, a)| a.clone()))
    }

    fn approvals(
        &self,
        chain_id: Option<&LeaseId>,
        state: Option<ApprovalState>,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, Approval)>, AuditError> {
        let mut out: Vec<(u64, Approval)> = self
            .approvals
            .lock()?
            .values()
            .filter(|(pos, a)| {
                before.is_none_or(|b| *pos < b)
                    && chain_id.is_none_or(|c| &a.chain_id == c)
                    && state.is_none_or(|s| a.state == s)
            })
            .cloned()
            .collect();
        out.sort_by_key(|(pos, _)| std::cmp::Reverse(*pos));
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
        let (_, a) = approvals
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
            .map(|(_, a)| a)
            .filter(|a| rules::usable(a, chain_id, lease, call_hash, now))
            .min_by(|a, b| a.created_at.cmp(&b.created_at))
        else {
            return Ok(None);
        };
        a.state = ApprovalState::Consumed;
        a.consumed_by = Some(decision_id.to_owned());
        Ok(Some(a.clone()))
    }

    fn take_approval_by_id(
        &self,
        id: &str,
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
            .get_mut(id)
            .map(|(_, a)| a)
            .filter(|a| rules::usable(a, chain_id, lease, call_hash, now))
        else {
            return Ok(None);
        };
        a.state = ApprovalState::Consumed;
        a.consumed_by = Some(decision_id.to_owned());
        Ok(Some(a.clone()))
    }

    fn restore_approval(&self, id: &str, decision_id: &str) -> Result<(), AuditError> {
        if let Some((_, a)) = self.approvals.lock()?.get_mut(id) {
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

impl RunLimits for MemoryLeaseStore {
    fn budget_used(&self, charges: &[Charge]) -> Result<Vec<u64>, AuditError> {
        let mut b = self.budgets.lock()?;
        let keys = b.keys(charges)?;
        Ok(keys
            .iter()
            .map(|k| b.counters.get(k).copied().unwrap_or(0))
            .collect())
    }

    fn charge(
        &self,
        decision_id: &str,
        charges: &[Charge],
        at: OffsetDateTime,
    ) -> Result<ChargeOutcome, AuditError> {
        self.charge_windowed(decision_id, charges, &[], at, false)
            .map(|(outcome, _)| outcome)
    }

    fn window_used(&self, windows: &[WindowCharge]) -> Result<Vec<u64>, AuditError> {
        let mut b = self.budgets.lock()?;
        let keys = b.window_keys(windows)?;
        Ok(keys
            .iter()
            .map(|k| b.windows.get(k).copied().unwrap_or(0))
            .collect())
    }

    fn charge_windowed(
        &self,
        decision_id: &str,
        charges: &[Charge],
        windows: &[WindowCharge],
        at: OffsetDateTime,
        _defer: bool,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        if charges.is_empty() && windows.is_empty() {
            let none = ChargeOutcome::Charged {
                used_after: Vec::new(),
            };
            return Ok((none, false));
        }
        // The lock is held from the check to the write: the memory store's transaction.
        let mut b = self.budgets.lock()?;
        if b.log.contains_key(decision_id) || b.window_log.contains_key(decision_id) {
            return Err(AuditError::Storage(format!(
                "decision `{decision_id}` is already charged"
            )));
        }
        let window_keys = b.window_keys(windows)?;
        let keys = b.keys(charges)?;
        let planned = match plan(&keys, charges, |k| {
            Ok(b.counters.get(k).copied().unwrap_or(0))
        })? {
            Ok(planned) => planned,
            Err(exhausted) => return Ok((exhausted, false)),
        };
        let window_writes = plan_windows(&window_keys, windows, |k| {
            Ok(b.windows.get(k).copied().unwrap_or(0))
        })?;
        if !window_writes.is_empty() {
            let mut logged = Vec::with_capacity(window_writes.len());
            for (key, after, amount) in window_writes {
                b.windows.insert(key.clone(), after);
                logged.push((key, amount));
            }
            b.window_log.insert(decision_id.to_owned(), (logged, None));
        }
        if charges.is_empty() {
            let none = ChargeOutcome::Charged {
                used_after: Vec::new(),
            };
            return Ok((none, false));
        }
        let mut log = ChargeLog {
            charges: Vec::new(),
            at,
            refunded_at: None,
        };
        for w in planned.writes {
            if w.key.kind == DISTINCT_VALUE_KIND {
                *b.holders.entry(w.key.clone()).or_insert(0) += 1;
            }
            b.counters.insert(w.key.clone(), w.after);
            log.charges.push(LoggedCharge {
                counter: w.key,
                amount: w.amount,
            });
        }
        b.log.insert(decision_id.to_owned(), log);
        let outcome = ChargeOutcome::Charged {
            used_after: planned.used_after,
        };
        Ok((outcome, false))
    }

    fn record_hop_limits(&self, lease: &LeaseId, limits: &[HopLimit]) -> Result<(), AuditError> {
        self.hop_limits
            .lock()?
            .insert(lease.clone(), limits.to_vec());
        Ok(())
    }

    fn hop_limits(&self, lease: &LeaseId) -> Result<Option<Vec<HopLimit>>, AuditError> {
        Ok(self.hop_limits.lock()?.get(lease).cloned())
    }

    fn budget_summary(&self, lease: &LeaseId) -> Result<Vec<CounterSummary>, AuditError> {
        let b = self.budgets.lock()?;
        Ok(summarize(
            b.counters
                .iter()
                .filter(|(k, _)| k.lease == lease.0)
                .map(|(k, v)| (k, *v)),
        ))
    }

    fn refund(&self, decision_id: &str, at: OffsetDateTime) -> Result<u64, AuditError> {
        let mut b = self.budgets.lock()?;
        let Budgets {
            counters,
            log,
            holders,
            windows,
            window_log,
            ..
        } = &mut *b;
        // Per-user windows the decision charged: returned with the rest, each recomputed from
        // the unrefunded charges left, since a window saturates like run usage.
        let windowed = match window_log.get(decision_id) {
            Some((_, Some(_))) => {
                return Err(AuditError::ChargeRefunded(decision_id.to_owned()));
            }
            Some((charged, None)) => Some(charged.clone()),
            None => None,
        };
        let refund_windows =
            |windows: &mut BTreeMap<WindowKey, u64>,
             window_log: &mut BTreeMap<String, WindowLog>| {
                let Some(charged) = &windowed else { return };
                if let Some(entry) = window_log.get_mut(decision_id) {
                    entry.1 = Some(at);
                }
                for (key, _) in charged {
                    let total = window_log
                        .values()
                        .filter(|(_, refunded)| refunded.is_none())
                        .flat_map(|(c, _)| c)
                        .filter(|(k, _)| k == key)
                        .fold(0u64, |t, (_, a)| t.saturating_add(*a))
                        .min(WindowCharge::MAX);
                    windows.insert(key.clone(), total);
                }
            };
        // An entry left empty by a revocation that ended its run's usage charged nothing now.
        let Some(entry) = log.get_mut(decision_id).filter(|e| !e.charges.is_empty()) else {
            if windowed.is_none() {
                return Err(AuditError::UnknownCharge(decision_id.to_owned()));
            }
            refund_windows(windows, window_log);
            return Ok(0);
        };
        if entry.refunded_at.is_some() {
            return Err(AuditError::ChargeRefunded(decision_id.to_owned()));
        }
        refund_windows(windows, window_log);
        let distinct = LimitKind::Distinct.as_str();
        let mut restored = 0u64;
        for c in &entry.charges {
            let key = &c.counter;
            if key.kind == DISTINCT_VALUE_KIND {
                // Free the value only when no other unrefunded decision used it (SR-62); the
                // limit's count moves with it.
                let left = holders.get_mut(key).map_or(0, |n| {
                    *n = n.saturating_sub(1);
                    *n
                });
                if left == 0 {
                    holders.remove(key);
                    if counters.get(key).is_some_and(|v| *v > 0) {
                        counters.insert(key.clone(), 0);
                        let count_key = CounterKey {
                            kind: distinct,
                            value: String::new(),
                            ..key.clone()
                        };
                        if let Some(v) = counters.get_mut(&count_key) {
                            *v = v.saturating_sub(1);
                        }
                        restored += 1;
                    }
                }
                continue;
            }
            if key.kind == distinct {
                continue;
            }
            if USAGE_KINDS.contains(&key.kind) {
                continue; // Recomputed below.
            }
            if let Some(v) = counters.get_mut(key) {
                *v = v.saturating_sub(c.amount);
            }
            restored += 1;
        }
        entry.refunded_at = Some(at);
        // A run-usage counter saturates at `MAX_LIMIT`, so what one decision logged is not
        // what it added once the counter was full: recompute it from the decisions left
        // (fuzzing round 2, FZ2-4).
        let usage: Vec<CounterKey> = entry
            .charges
            .iter()
            .filter(|c| USAGE_KINDS.contains(&c.counter.kind))
            .map(|c| c.counter.clone())
            .collect();
        for key in usage {
            let total = log
                .values()
                .filter(|e| e.refunded_at.is_none())
                .flat_map(|e| &e.charges)
                .filter(|c| c.counter == key)
                .fold(0u64, |t, c| t.saturating_add(c.amount))
                .min(MAX_LIMIT);
            counters.insert(key, total);
        }
        Ok(restored)
    }
}

impl crate::replay::ReplayStore for MemoryLeaseStore {
    fn use_all_once(
        &self,
        keys: &[(&str, i64)],
        now: i64,
        capacity: usize,
    ) -> Result<crate::replay::ReplayOutcome, AuditError> {
        self.used_credentials.use_all_once(keys, now, capacity)
    }

    fn replay_markers(&self) -> Result<usize, AuditError> {
        self.used_credentials.len()
    }
}

impl StoreRetention for MemoryLeaseStore {
    fn prune_sessions(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<SessionPrune, AuditError> {
        use std::ops::Bound;
        let max_rows = max_rows.max(1);
        // The lock order of `record_session`: rows, then sessions.
        let rows = self.rows.lock()?;
        let mut sessions = self.sessions.lock()?;
        let mut cursor = self.session_cursor.lock()?;
        let start = match cursor.take() {
            Some(key) => Bound::Excluded(key),
            None => Bound::Unbounded,
        };
        let seen: Vec<((String, String), bool)> = sessions
            .range((start, Bound::Unbounded))
            .take(max_rows)
            .map(|(key, (chain, _))| {
                let prunable = session_prunable(rows.get(chain), now, retention);
                (key.clone(), prunable)
            })
            .collect();
        let wrapped = seen.len() < max_rows;
        if !wrapped {
            *cursor = seen.last().map(|(key, _)| key.clone());
        }
        let mut pruned = 0;
        for (key, prunable) in &seen {
            if *prunable && sessions.remove(key).is_some() {
                pruned += 1;
            }
        }
        Ok(SessionPrune {
            examined: seen.len() as u64,
            pruned,
            wrapped,
        })
    }

    fn prune_leases(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<LeasePrune, AuditError> {
        // The rows lock is held for the whole pass (the memory store's transaction); every
        // other lock is taken under it, one at a time, as everywhere else in this store.
        let mut rows = self.rows.lock()?;
        let mut state = self.lease_prune.lock()?;
        let mut ops = MemoryPrune {
            store: self,
            rows: &mut rows,
        };
        let pass = prune_pass(&mut ops, &mut state, now, retention, max_rows);
        if pass.is_err() {
            state.abandon_sweep();
        }
        pass
    }

    fn prune_run_state(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<RunStatePrune, AuditError> {
        use std::ops::Bound;
        fn after<K: Ord + Clone>(k: &Option<K>) -> (Bound<K>, Bound<K>) {
            match k {
                Some(k) => (Bound::Excluded(k.clone()), Bound::Unbounded),
                None => (Bound::Unbounded, Bound::Unbounded),
            }
        }
        let max_rows = max_rows.max(1);
        // The rows lock is held for the whole pass (the memory store's transaction); budgets
        // and approvals are taken under it, one at a time, in the order used elsewhere.
        let rows = self.rows.lock()?;
        let known = |lease: &str| rows.contains_key(&LeaseId::new(lease));
        let mut cursor = self.run_state_cursor.lock()?;
        let mut out = RunStatePrune::default();
        let mut budget = max_rows;
        while budget > 0 {
            match cursor.clone() {
                RunStateCursor::Charges(from) => {
                    let mut b = self.budgets.lock()?;
                    let window: Vec<String> = b
                        .log
                        .range(after(&from))
                        .take(budget)
                        .map(|(d, _)| d.clone())
                        .collect();
                    for d in &window {
                        let entry = &b.log[d];
                        let lease_known = entry.charges.iter().any(|c| known(&c.counter.lease));
                        let last = entry.refunded_at.map_or(entry.at, |r| r.max(entry.at));
                        if !run_state_prunable(lease_known, last, now, retention) {
                            continue;
                        }
                        let entry = b.log.remove(d).expect("in the window");
                        if entry.refunded_at.is_none() {
                            // As if its rows were deleted: it no longer holds its values.
                            for c in &entry.charges {
                                if c.counter.kind == DISTINCT_VALUE_KIND {
                                    if let Some(n) = b.holders.get_mut(&c.counter) {
                                        *n = n.saturating_sub(1);
                                        if *n == 0 {
                                            b.holders.remove(&c.counter);
                                        }
                                    }
                                }
                            }
                        }
                        out.pruned_charges += 1;
                    }
                    out.examined += window.len() as u64;
                    if window.len() < budget {
                        *cursor = RunStateCursor::Counters(None);
                    } else {
                        *cursor = RunStateCursor::Charges(window.last().cloned());
                    }
                    budget -= window.len();
                }
                RunStateCursor::Counters(from) => {
                    let mut b = self.budgets.lock()?;
                    let logged: BTreeSet<&str> = b
                        .log
                        .values()
                        .flat_map(|e| &e.charges)
                        .map(|c| c.counter.lease.as_str())
                        .collect();
                    let window: Vec<(CounterKey, bool)> = b
                        .counters
                        .range(after(&from))
                        .take(budget)
                        .map(|(k, _)| {
                            (
                                k.clone(),
                                !known(&k.lease) && !logged.contains(k.lease.as_str()),
                            )
                        })
                        .collect();
                    drop(logged);
                    for (k, prunable) in &window {
                        if *prunable && b.counters.remove(k).is_some() {
                            b.holders.remove(k);
                            out.pruned_counters += 1;
                        }
                    }
                    out.examined += window.len() as u64;
                    if window.len() < budget {
                        *cursor = RunStateCursor::Approvals(None);
                    } else {
                        *cursor = RunStateCursor::Counters(window.last().map(|(k, _)| k.clone()));
                    }
                    budget -= window.len();
                }
                RunStateCursor::Approvals(from) => {
                    let mut approvals = self.approvals.lock()?;
                    let window: Vec<(String, bool)> = approvals
                        .range(after(&from))
                        .take(budget)
                        .map(|(id, (_, a))| {
                            let lease_known =
                                rows.contains_key(&a.lease) || rows.contains_key(&a.chain_id);
                            let prunable = run_state_prunable(
                                lease_known,
                                approval_last_touched(a),
                                now,
                                retention,
                            );
                            (id.clone(), prunable)
                        })
                        .collect();
                    for (id, prunable) in &window {
                        if *prunable && approvals.remove(id).is_some() {
                            out.pruned_approvals += 1;
                        }
                    }
                    out.examined += window.len() as u64;
                    if window.len() < budget {
                        *cursor = RunStateCursor::default();
                        out.wrapped = true;
                        break;
                    }
                    *cursor = RunStateCursor::Approvals(window.last().map(|(id, _)| id.clone()));
                    budget -= window.len();
                }
            }
        }
        Ok(out)
    }

    fn prune_user_windows(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<WindowPrune, AuditError> {
        let max_rows = max_rows.max(1);
        let mut b = self.budgets.lock()?;
        let gone: Vec<WindowKey> = b
            .windows
            .keys()
            .filter(|k| window_prunable(k.end(), now, retention))
            .take(max_rows)
            .cloned()
            .collect();
        for k in &gone {
            b.windows.remove(k);
        }
        let mut pruned_charges = 0u64;
        b.window_log.retain(|_, (charges, _)| {
            let before = charges.len();
            charges.retain(|(k, _)| !window_prunable(k.end(), now, retention));
            pruned_charges += (before - charges.len()) as u64;
            !charges.is_empty()
        });
        Ok(WindowPrune {
            pruned_windows: gone.len() as u64,
            pruned_charges,
            wrapped: gone.len() < max_rows,
        })
    }
}

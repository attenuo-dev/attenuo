//! Lease registry: the revocation half of accountability.
//!
//! Every delegation hop holds a [`LeaseId`]. Leases form a tree through their `parent` link, so
//! revoking one revokes everything delegated from it. A lease the store does not know is
//! reported as `unknown` and counts as inactive: a store that lost rows fails closed.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;

use attenuo_core::fingerprint::Fingerprint;
use attenuo_core::limits::MAX_LIMIT;
use attenuo_core::{Charge, LeaseId, LimitKind};
use time::OffsetDateTime;

use crate::approval::{rules, Approval, ApprovalState, Approver};
use crate::budget::{
    plan, summarize, ChargeOutcome, CounterKey, CounterSummary, HopLimit, ValueKey,
    DISTINCT_VALUE_KIND, USAGE_KINDS,
};
use crate::error::AuditError;
use crate::spans::{distinct_hashes, evictions, SpanHit, SpanKey, MAX_SPANS_PER_RUN};

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

    /// Record the originating user's subject (`sub` of the chain's originating-user block) of
    /// the token `lease` was issued for, so [`LeaseSelector::Subject`] can find it. The issuer
    /// records it for every lease it registers. Write-once, like [`bind`](Self::bind):
    /// recording the same subject again is a no-op, a different one is
    /// [`AuditError::BindingConflict`], and an unknown lease is [`AuditError::UnknownLease`].
    /// Leases registered before the store kept subjects have none and are never matched by a
    /// subject selector.
    fn record_subject(&self, lease: &LeaseId, subject: &str) -> Result<(), AuditError>;

    /// The subject recorded by [`record_subject`](Self::record_subject), or `None`.
    fn subject(&self, lease: &LeaseId) -> Result<Option<String>, AuditError>;

    /// [`subject`](Self::subject) for many leases at once: the recorded subject of each lease
    /// in `leases` that has one. Leases with no recorded subject (unknown, or registered before
    /// subjects were kept) are absent from the map. The stores answer with one lock (the file
    /// store with `IN (...)` queries), so a lease tree of thousands of nodes costs no query per
    /// node; the default asks [`subject`](Self::subject) once per lease.
    fn subjects(&self, leases: &[&LeaseId]) -> Result<BTreeMap<LeaseId, String>, AuditError> {
        let mut out = BTreeMap::new();
        for lease in leases {
            if let Some(s) = self.subject(lease)? {
                out.insert((*lease).clone(), s);
            }
        }
        Ok(out)
    }

    /// Record that the MCP session whose id hashes to `session` was opened through the proxy
    /// to upstream `server` by a caller of the chain `chain_id` (the lease of the chain's
    /// first hop), at `now`, so [`LeaseSelector::Session`] can find the chain. `session` is the
    /// SHA-256 of the `Mcp-Session-Id` in lowercase hex (`attenuo_proxy::session::session_digest`;
    /// the audit tag of the session is its first 12 characters): raw session ids are never
    /// stored. Write-once per `(session, server)`: returns `true` when the binding is new and
    /// `false` when one was already recorded, whatever its chain, which is then kept. An
    /// unknown `chain_id` is [`AuditError::UnknownLease`].
    fn record_session(
        &self,
        session: &str,
        server: &str,
        chain_id: &LeaseId,
        now: OffsetDateTime,
    ) -> Result<bool, AuditError>;

    /// The bindings [`record_session`](Self::record_session) recorded for the session digest
    /// `session`, ordered by server; empty for an unknown session.
    fn sessions(&self, session: &str) -> Result<Vec<SessionBinding>, AuditError>;

    /// One pass of session retention: look at up to `max_rows` session bindings, in the order
    /// they were recorded and continuing after the last binding the previous pass looked at,
    /// and delete those [`session_prunable`] at `now` with `retention` as the grace period.
    /// When a pass reaches the last binding it reports `wrapped`, and the next pass starts
    /// from the first again. One transaction per pass, so a pass never deletes a binding whose
    /// chain a concurrent renewal has just revived. A pruned session resolves to no chain,
    /// like a session that was never recorded: [`LeaseSelector::Session`] matches nothing and
    /// [`sessions`](Self::sessions) is empty.
    fn prune_sessions(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<SessionPrune, AuditError>;

    /// One pass of lease retention: look at up to `max_rows` leases, in the order they were
    /// registered and continuing after the last lease the previous pass looked at, and delete
    /// every lease tree whose top is among them and that is [`tree_prunable`] at `now` with
    /// `retention` as the grace period. A tree is the top lease (one with no parent, or whose
    /// parent the store does not know) and everything delegated from it; it is deleted whole,
    /// with the subjects, chain bindings, session bindings, hop limits, run labels and span
    /// indexes of its leases, so no lease is ever left whose parent row is gone. Leases that
    /// are not tops are skipped (their tree is decided at its top), but count as examined.
    /// When a pass reaches the last lease it reports `wrapped`, and the next pass starts from
    /// the first again. One write transaction per pass, so a renewal cannot revive a tree
    /// between the check and the delete. A pruned lease reads as unknown, which every check
    /// treats as inactive (`lease_unknown`); selectors no longer match it.
    fn prune_leases(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<LeasePrune, AuditError>;

    /// What [`revoke_selected`](Self::revoke_selected) would do now, without writing:
    /// `matched` is every unrevoked lease the selector names, `revoked` every unrevoked lease
    /// a revocation would change (the matches and their descendants). Read in one
    /// transaction.
    fn preview_selected(&self, selector: &LeaseSelector) -> Result<SelectorRevocation, AuditError>;

    /// Revoke every unrevoked lease `selector` names, each with the cascade of
    /// [`revoke`](Self::revoke), in one transaction. Returns the matches and every lease that
    /// changed from unrevoked to revoked. Matching nothing is not an error (an empty result):
    /// a selector names a set, and an empty set is a valid answer during an incident.
    fn revoke_selected(
        &self,
        selector: &LeaseSelector,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<SelectorRevocation, AuditError>;

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

    /// Add the fingerprints of one untrusted result to the span index of the run `chain_id`
    /// (ADR-0009 phase 2, [`crate::spans`]), tagged with `seq`, the audit `seq` of the result's
    /// `tool_result` record. The run's lease must be known ([`AuditError::UnknownLease`]
    /// otherwise). Keeps at most [`MAX_SPANS_PER_RUN`] per run, evicting the oldest results'
    /// sets first; the check, the eviction and the write are one transaction. Nothing is
    /// written for an empty `spans`.
    fn add_spans(
        &self,
        chain_id: &LeaseId,
        seq: u64,
        spans: &[Fingerprint],
    ) -> Result<(), AuditError>;

    /// Look `probes` up in the span index of the run `chain_id`: one [`SpanHit`] per probe and
    /// stored result that holds it, ordered by probe, then `seq`. Empty for a run with no
    /// index. Callers must treat an error as a match (fail closed).
    fn find_spans(
        &self,
        chain_id: &LeaseId,
        probes: &[Fingerprint],
    ) -> Result<Vec<SpanHit>, AuditError>;

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

    /// [`take_approval`](Self::take_approval) for one approval named by `id` (the `jti` of a
    /// presented approval token): mark it consumed by `decision_id` only if it is granted,
    /// unexpired, of the run `chain_id`, of the hop holding `lease` (which must be live) and
    /// for `call_hash`, in one transaction. `None` otherwise (unknown, pending, declined,
    /// already consumed, expired, another call or hop, or a dead lease).
    fn take_approval_by_id(
        &self,
        id: &str,
        chain_id: &LeaseId,
        lease: &LeaseId,
        call_hash: &str,
        decision_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Approval>, AuditError>;

    /// Undo [`take_approval`](Self::take_approval) (or
    /// [`take_approval_by_id`](Self::take_approval_by_id)) for a decision that did not go through
    /// (denied anyway, or its audit append failed): an approval consumed by `decision_id` is
    /// granted again. Anything else is left alone.
    fn restore_approval(&self, id: &str, decision_id: &str) -> Result<(), AuditError>;

    /// Delete an approval whose request could not be recorded.
    fn remove_approval(&self, id: &str) -> Result<(), AuditError>;

    /// Run limits (ADR-0010): what the counter of each charge holds now, in order. A counter
    /// never charged holds 0. The charges' `amount` and `max` are ignored. Reading does not
    /// look at the leases, so the counters of a revoked or expired lease can still be read.
    /// Callers must deny a limited call when this fails (`budget_error`).
    fn budget_used(&self, charges: &[Charge]) -> Result<Vec<u64>, AuditError>;

    /// Charge one allowed call (ADR-0010): check every charge against its counter and either
    /// apply all of them, logged under `decision_id`, or none (`Exhausted`, naming the first
    /// that would go over its `max`), in one transaction. An empty `charges` writes nothing.
    /// A decision id that already has charges is refused, so a decision is charged once.
    fn charge(
        &self,
        decision_id: &str,
        charges: &[Charge],
        at: OffsetDateTime,
    ) -> Result<ChargeOutcome, AuditError>;

    /// [`charge`](Self::charge), except that a store which would sync the commit of a `sum`
    /// charge itself (a file store below `durability = "full"`, design 3.4) may commit it
    /// unsynced and leave the sync to the caller. The `bool` says whether it did: then the
    /// caller must not act on the charge (forward the call) before an
    /// [`AuditSink::append_synced`](crate::AuditSink::append_synced) on a sink with the same
    /// [`sync_file`](Self::sync_file) has returned, since that sync covers this commit too.
    /// The default charges and syncs as `charge` does and returns `false`.
    fn charge_sync_deferred(
        &self,
        decision_id: &str,
        charges: &[Charge],
        at: OffsetDateTime,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        self.charge(decision_id, charges, at).map(|o| (o, false))
    }

    /// The database file whose sync makes this store's commits durable (canonical path), when
    /// [`charge_sync_deferred`](Self::charge_sync_deferred) can leave a sync to a sink sharing
    /// it. `None` (the default) for a store that never defers.
    fn sync_file(&self) -> Option<&std::path::Path> {
        None
    }

    /// Return what `decision_id` charged to every counter it charged, at most once, in one
    /// transaction, run-usage counters included. Returns how many token-limit counters were
    /// restored (run usage is not counted, so a decision that charged only usage returns 0).
    /// A `distinct` value is freed, and counted, only when no other unrefunded decision used
    /// it (SR-62; see [`crate::budget`]). [`AuditError::UnknownCharge`]
    /// when the decision charged nothing, [`AuditError::ChargeRefunded`] when it was already
    /// refunded. Used by the pipeline when a charged decision's audit append fails, and by
    /// the operator refund (`POST /admin/budgets/refund`).
    fn refund(&self, decision_id: &str, at: OffsetDateTime) -> Result<u64, AuditError>;

    /// Keep the limited capabilities of the hop whose lease is `lease`, as issued (ADR-0010),
    /// for the admin console. Display only: enforcement reads the limits from the token. The
    /// default keeps nothing.
    fn record_hop_limits(&self, lease: &LeaseId, limits: &[HopLimit]) -> Result<(), AuditError> {
        let _ = (lease, limits);
        Ok(())
    }

    /// What [`record_hop_limits`](Self::record_hop_limits) kept for `lease`. `None` when
    /// nothing was kept (a hop without limits, a lease issued before this was recorded, or a
    /// store that keeps none, the default).
    fn hop_limits(&self, lease: &LeaseId) -> Result<Option<Vec<HopLimit>>, AuditError> {
        let _ = lease;
        Ok(None)
    }

    /// Every counter under `lease`, grouped ([`CounterSummary`]): its limits' counters and,
    /// for a run's root lease, the run's usage. Empty when nothing was charged, and by default.
    fn budget_summary(&self, lease: &LeaseId) -> Result<Vec<CounterSummary>, AuditError> {
        let _ = lease;
        Ok(Vec::new())
    }
}

/// Which leases a selector revocation names (`POST /admin/leases/revoke`).
///
/// A selector matches leases that are not revoked. An expired lease matches too: while its
/// token is valid, `POST /token/renew` can bring it back, so an incident revocation must not
/// leave it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseSelector {
    /// Every lease issued for this originating user (`sub`), as recorded by
    /// [`LeaseStore::record_subject`]. The subject is matched under every issuer.
    Subject(String),
    /// Every lease of one delegation chain: the chain id is the lease of the chain's first
    /// hop (`attenuo_core::chain_id_of`), so this is that lease and everything delegated
    /// from it. A lease that has a parent is not a chain id and matches nothing. Found
    /// through the parent links, so leases registered before subjects were recorded match.
    Chain(LeaseId),
    /// Every lease of the chains an MCP session was opened by, as recorded by
    /// [`LeaseStore::record_session`]: the value is the session digest (SHA-256 of the
    /// `Mcp-Session-Id`, lowercase hex), and each bound chain is matched as
    /// [`LeaseSelector::Chain`] matches it. A session opened through more than one upstream
    /// can name more than one chain; an unknown session matches nothing.
    Session(String),
}

/// One recorded session binding ([`LeaseStore::record_session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The upstream server the session was opened with.
    pub server: String,
    /// The chain id (the lease of the chain's first hop) of the caller that opened it.
    pub chain_id: LeaseId,
    /// When the proxy bound it.
    pub bound_at: OffsetDateTime,
}

/// What one [`LeaseStore::prune_sessions`] pass did.
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

/// What one [`LeaseStore::prune_leases`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LeasePrune {
    /// Leases the pass looked at (at most its `max_rows`), tops or not.
    pub examined: u64,
    /// Leases it deleted: every lease of each pruned tree, including descendants registered
    /// after the pass's window.
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

/// The result of [`LeaseStore::revoke_selected`] or [`LeaseStore::preview_selected`].
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

/// What a decision charged, and whether it was refunded.
#[derive(Debug, Clone, Default)]
struct ChargeLog {
    charges: Vec<LoggedCharge>,
    refunded: bool,
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
    /// The last lease a `prune_leases` pass looked at; `None` to start from the first.
    lease_cursor: Mutex<Option<LeaseId>>,
    /// Per run, the first label of each source.
    labels: Mutex<BTreeMap<LeaseId, BTreeMap<String, RunLabel>>>,
    /// Per run, the span index (ADR-0009 phase 2).
    spans: Mutex<Spans>,
    /// Approvals by id.
    approvals: Mutex<BTreeMap<String, Approval>>,
    /// Run-limit counters and the charges of each decision, under one lock (ADR-0010).
    budgets: Mutex<Budgets>,
    /// The limited capabilities of each hop, as issued (display only).
    hop_limits: Mutex<BTreeMap<LeaseId, Vec<HopLimit>>>,
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
}

impl Budgets {
    fn keys(&mut self, charges: &[Charge]) -> Result<Vec<CounterKey>, AuditError> {
        if self.key.is_none() {
            self.key = Some(ValueKey::random()?);
        }
        let key = self.key.as_ref().expect("set above");
        charges.iter().map(|c| key.counter(c)).collect()
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
        if self.key.is_none() {
            self.key = Some(SpanKey::random()?);
        }
        Ok(self.key.clone().expect("set above"))
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

    /// [`LeaseStore::preview_selected`] and [`LeaseStore::revoke_selected`]: `write` carries
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
        }
        Ok(SelectorRevocation::from_parts(matched, changed))
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
        use std::ops::Bound;
        let max_rows = max_rows.max(1);
        // The rows lock is held for the whole pass (the memory store's transaction); every
        // other lock is taken under it, one at a time, as everywhere else in this store.
        let mut rows = self.rows.lock()?;
        let mut cursor = self.lease_cursor.lock()?;
        let start = match cursor.take() {
            Some(id) => Bound::Excluded(id),
            None => Bound::Unbounded,
        };
        let window: Vec<LeaseId> = rows
            .range((start, Bound::Unbounded))
            .take(max_rows)
            .map(|(id, _)| id.clone())
            .collect();
        let wrapped = window.len() < max_rows;
        if !wrapped {
            *cursor = window.last().cloned();
        }
        // Tops whose own row ended past the grace period; a live top keeps its tree.
        let is_top = |r: &LeaseRow| r.parent.as_ref().is_none_or(|p| !rows.contains_key(p));
        let tops: Vec<LeaseId> = window
            .iter()
            .filter(|id| {
                rows.get(*id)
                    .is_some_and(|r| is_top(r) && tree_prunable([r], now, retention))
            })
            .cloned()
            .collect();
        let mut children: BTreeMap<&LeaseId, Vec<&LeaseId>> = BTreeMap::new();
        for (id, row) in rows.iter() {
            if let Some(p) = &row.parent {
                children.entry(p).or_default().push(id);
            }
        }
        let mut gone: BTreeSet<LeaseId> = BTreeSet::new();
        for top in &tops {
            let mut tree = Vec::new();
            let mut seen = BTreeSet::new();
            let mut queue = VecDeque::from([top]);
            while let Some(id) = queue.pop_front() {
                if !seen.insert(id) {
                    continue;
                }
                tree.push(id);
                if let Some(kids) = children.get(id) {
                    queue.extend(kids.iter().copied());
                }
            }
            if tree_prunable(tree.iter().filter_map(|id| rows.get(*id)), now, retention) {
                gone.extend(tree.into_iter().cloned());
            }
        }
        drop(children);
        for id in &gone {
            rows.remove(id);
        }
        if !gone.is_empty() {
            self.bindings.lock()?.retain(|id, _| !gone.contains(id));
            self.subjects.lock()?.retain(|id, _| !gone.contains(id));
            self.sessions
                .lock()?
                .retain(|_, (chain, _)| !gone.contains(chain));
            self.labels.lock()?.retain(|id, _| !gone.contains(id));
            self.spans.lock()?.runs.retain(|id, _| !gone.contains(id));
            self.hop_limits.lock()?.retain(|id, _| !gone.contains(id));
        }
        Ok(LeasePrune {
            examined: window.len() as u64,
            pruned: gone.len() as u64,
            wrapped,
        })
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
                hits.extend(seqs.iter().map(|&seq| SpanHit { probe, seq }));
            }
        }
        Ok(hits)
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
            .filter(|a| rules::usable(a, chain_id, lease, call_hash, now))
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
        _at: OffsetDateTime,
    ) -> Result<ChargeOutcome, AuditError> {
        if charges.is_empty() {
            return Ok(ChargeOutcome::Charged {
                used_after: Vec::new(),
            });
        }
        // The lock is held from the check to the write: the memory store's transaction.
        let mut b = self.budgets.lock()?;
        if b.log.contains_key(decision_id) {
            return Err(AuditError::Storage(format!(
                "decision `{decision_id}` is already charged"
            )));
        }
        let keys = b.keys(charges)?;
        let planned = match plan(&keys, charges, |k| {
            Ok(b.counters.get(k).copied().unwrap_or(0))
        })? {
            Ok(planned) => planned,
            Err(exhausted) => return Ok(exhausted),
        };
        let mut log = ChargeLog::default();
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
        Ok(ChargeOutcome::Charged {
            used_after: planned.used_after,
        })
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

    fn refund(&self, decision_id: &str, _at: OffsetDateTime) -> Result<u64, AuditError> {
        let mut b = self.budgets.lock()?;
        let Budgets {
            counters,
            log,
            holders,
            ..
        } = &mut *b;
        // An entry left empty by a revocation that ended its run's usage charged nothing now.
        let entry = log
            .get_mut(decision_id)
            .filter(|e| !e.charges.is_empty())
            .ok_or_else(|| AuditError::UnknownCharge(decision_id.to_owned()))?;
        if entry.refunded {
            return Err(AuditError::ChargeRefunded(decision_id.to_owned()));
        }
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
        entry.refunded = true;
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
                .filter(|e| !e.refunded)
                .flat_map(|e| &e.charges)
                .filter(|c| c.counter == key)
                .fold(0u64, |t, c| t.saturating_add(c.amount))
                .min(MAX_LIMIT);
            counters.insert(key, total);
        }
        Ok(restored)
    }
}

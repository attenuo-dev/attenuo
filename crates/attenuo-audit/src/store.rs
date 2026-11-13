//! The lease store's traits, one per concern.
//!
//! The lease store keeps everything the decision pipeline needs to remember between calls. It
//! is split into five traits so that code which needs one concern names only that one:
//!
//! - [`LeaseRegistry`]: leases, their tree, revocation (one lease or a selector), chain
//!   bindings and subjects.
//! - [`RunState`]: what a delegation run has accumulated under its chain id: taint labels,
//!   the span index of the untrusted results it read, and the MCP sessions it opened.
//! - [`ApprovalStore`]: human approvals, from the pending request to the decision that
//!   consumes the grant.
//! - [`RunLimits`]: run-limit counters and the charge log, per-user windows, and the limits
//!   kept per hop for display.
//! - [`StoreRetention`]: the bounded passes that delete what can no longer be used.
//!
//! [`LeaseStore`] is all five together, implemented for every type that implements them, so a
//! component that needs the whole store (the decision pipeline) keeps taking
//! `Arc<dyn LeaseStore>`. [`MemoryLeaseStore`](crate::MemoryLeaseStore) and
//! [`SqliteLeaseStore`](crate::SqliteLeaseStore) implement every trait. Calling a method on a
//! concrete store needs the trait that declares it in scope; on a `dyn LeaseStore` every method
//! is available.

use std::collections::BTreeMap;

use attenuo_core::fingerprint::Fingerprint;
use attenuo_core::{Charge, LeaseId, WindowCharge};
use time::OffsetDateTime;

use crate::approval::{Approval, ApprovalState, Approver};
use crate::budget::{ChargeOutcome, CounterSummary, HopLimit};
use crate::error::AuditError;
use crate::lease::{
    LeasePrune, LeaseSelector, LeaseStatus, RunLabel, RunStatePrune, SelectorRevocation,
    SessionBinding, SessionPrune,
};
use crate::spans::SpanHit;
use crate::window::WindowPrune;
#[cfg(doc)]
use crate::{
    lease::{run_state_prunable, session_prunable, tree_prunable},
    spans::{MAX_SEQS_PER_PROBE, MAX_SPANS_PER_RUN},
    window::window_prunable,
};

/// The whole lease store: [`LeaseRegistry`], [`RunState`], [`ApprovalStore`], [`RunLimits`]
/// and [`StoreRetention`] together. Implemented for every type that implements all five, so
/// there is nothing to implement here; take the narrower trait where one concern is enough.
///
/// # Errors
///
/// Every method can fail on a store fault, which each method's own `# Errors` section calls
/// that: [`AuditError::Poisoned`] when a writer panicked holding one of the store's locks,
/// and, for the file store, [`AuditError::Sqlite`] when a query or commit fails,
/// [`AuditError::Serde`], [`AuditError::TimeFormat`] or [`AuditError::TimeParse`] when a
/// stored value cannot be written or read back, [`AuditError::Storage`] when a stored figure
/// is out of range or the store is not as it must be, and [`AuditError::Corrupt`] when a
/// row cannot be read back. The refusals a method makes on purpose (an unknown lease, a
/// conflicting binding, an approval that is not pending) are listed on that method.
pub trait LeaseStore:
    LeaseRegistry + RunState + ApprovalStore + RunLimits + StoreRetention
{
}

impl<T> LeaseStore for T where
    T: LeaseRegistry + RunState + ApprovalStore + RunLimits + StoreRetention + ?Sized
{
}

/// Registry of leases and their revocation state: the revocation half of accountability
/// (see [`crate::lease`]). Leases form a tree through their parent link; revoking one revokes
/// everything delegated from it, and a lease the store does not know counts as inactive. The
/// registry also keeps what the issuer records per lease: the chain binding and the
/// originating user's subject.
///
/// # Errors
///
/// Store faults are listed on [`LeaseStore`].
pub trait LeaseRegistry: Send + Sync {
    /// Record a lease. Registering an id that already exists overwrites its parent and expiry
    /// but never clears a revocation.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when `lease` belongs to a tree that
    /// [`prune_leases`](StoreRetention::prune_leases) has started deleting, or a store fault (see
    /// [`LeaseStore`]).
    fn register(
        &self,
        lease: &LeaseId,
        parent: Option<&LeaseId>,
        expires_at: OffsetDateTime,
    ) -> Result<(), AuditError>;

    /// Revoke `lease` and every lease descended from it. Returns how many leases changed from
    /// unrevoked to revoked (already-revoked ones are not counted again).
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `lease`, so a typo cannot pass
    /// for a successful revocation, or a store fault (see [`LeaseStore`]).
    fn revoke(&self, lease: &LeaseId, reason: &str, now: OffsetDateTime)
        -> Result<u64, AuditError>;

    /// Set the expiry of `lease` to `new_expires_at` (a heartbeat). The caller computes the
    /// new value and is responsible for capping it (token expiry, parent lease); the store
    /// only refuses leases it must not revive. An expired but unrevoked lease may be renewed.
    /// Revocation state and the parent link are untouched.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `lease` or its tree is being
    /// deleted by [`prune_leases`](StoreRetention::prune_leases),
    /// [`AuditError::LeaseRevoked`] when it is revoked, or a store fault (see [`LeaseStore`]).
    fn renew(
        &self,
        lease: &LeaseId,
        new_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), AuditError>;

    /// Known, not revoked, and `expires_at > now`.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown lease is `Ok(false)`, not an error.
    fn is_active(&self, lease: &LeaseId, now: OffsetDateTime) -> Result<bool, AuditError>;

    /// Record which chain `lease` was issued for: the digest of the chain up to and including
    /// the hop that holds the lease (`DelegationChain::prefix_digest`). Write-once: binding a
    /// lease again to the same value is a no-op, to a different value an error.
    ///
    /// The issuer binds every lease it registers. A chain presented without its signed token
    /// (an AuthZEN body chain) is accepted only if every hop's prefix digest equals its lease's
    /// binding, so lease ids alone, which are not secret, cannot be stitched into a forged
    /// chain.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `lease`,
    /// [`AuditError::BindingConflict`] when it is already bound to a different value, or a store
    /// fault (see [`LeaseStore`]).
    fn bind(&self, lease: &LeaseId, binding: &str) -> Result<(), AuditError>;

    /// The binding recorded by [`bind`](Self::bind), or `None` (unknown or never bound).
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown or unbound lease is `Ok(None)`.
    fn binding(&self, lease: &LeaseId) -> Result<Option<String>, AuditError>;

    /// Record the originating user's subject (`sub` of the chain's originating-user block) of
    /// the token `lease` was issued for, so [`LeaseSelector::Subject`] can find it. The issuer
    /// records it for every lease it registers. Write-once, like [`bind`](Self::bind):
    /// recording the same subject again is a no-op, a different one an error.
    /// Leases registered before the store kept subjects have none and are never matched by a
    /// subject selector.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `lease`,
    /// [`AuditError::BindingConflict`] when a different subject is already recorded, or a store
    /// fault (see [`LeaseStore`]).
    fn record_subject(&self, lease: &LeaseId, subject: &str) -> Result<(), AuditError>;

    /// The subject recorded by [`record_subject`](Self::record_subject), or `None`.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown lease or one without a subject is
    /// `Ok(None)`.
    fn subject(&self, lease: &LeaseId) -> Result<Option<String>, AuditError>;

    /// [`subject`](Self::subject) for many leases at once: the recorded subject of each lease
    /// in `leases` that has one. Leases with no recorded subject (unknown, or registered before
    /// subjects were kept) are absent from the map. The stores answer with one lock (the file
    /// store with `IN (...)` queries), so a lease tree of thousands of nodes costs no query per
    /// node; the default asks [`subject`](Self::subject) once per lease.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]), the first one met; unknown leases are left out of
    /// the map.
    fn subjects(&self, leases: &[&LeaseId]) -> Result<BTreeMap<LeaseId, String>, AuditError> {
        let mut out = BTreeMap::new();
        for lease in leases {
            if let Some(s) = self.subject(lease)? {
                out.insert((*lease).clone(), s);
            }
        }
        Ok(out)
    }

    /// What [`revoke_selected`](Self::revoke_selected) would do now, without writing:
    /// `matched` is every unrevoked lease the selector names, `revoked` every unrevoked lease
    /// a revocation would change (the matches and their descendants). Read in one
    /// transaction.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): a selector that matches nothing is an empty result.
    fn preview_selected(&self, selector: &LeaseSelector) -> Result<SelectorRevocation, AuditError>;

    /// Revoke every unrevoked lease `selector` names, each with the cascade of
    /// [`revoke`](Self::revoke), in one transaction. Returns the matches and every lease that
    /// changed from unrevoked to revoked. Matching nothing is not an error (an empty result):
    /// a selector names a set, and an empty set is a valid answer during an incident.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]), in which case nothing is revoked: a selector that
    /// matches nothing is an empty result.
    fn revoke_selected(
        &self,
        selector: &LeaseSelector,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<SelectorRevocation, AuditError>;

    /// Classify every lease. A lease that is both revoked and expired is reported as revoked.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): unknown leases are reported in
    /// [`LeaseStatus::unknown`], not as an error.
    fn check_all(
        &self,
        leases: &[&LeaseId],
        now: OffsetDateTime,
    ) -> Result<LeaseStatus, AuditError>;
}

/// What a delegation run accumulates, keyed by its chain id (the lease of the run's first
/// hop): the taint labels and span index of the untrusted results it read (ADR-0009), and the
/// MCP sessions opened by its callers, which [`LeaseSelector::Session`] revokes by.
///
/// # Errors
///
/// Store faults are listed on [`LeaseStore`].
pub trait RunState: Send + Sync {
    /// Record that the MCP session whose id hashes to `session` was opened through the proxy
    /// to upstream `server` by a caller of the chain `chain_id` (the lease of the chain's
    /// first hop), at `now`, so [`LeaseSelector::Session`] can find the chain. `session` is the
    /// SHA-256 of the `Mcp-Session-Id` in lowercase hex (`attenuo_proxy::session::session_digest`;
    /// the audit tag of the session is its first 12 characters): raw session ids are never
    /// stored. Write-once per `(session, server)`: returns `true` when the binding is new and
    /// `false` when one was already recorded, whatever its chain, which is then kept.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `chain_id`, or a store fault (see
    /// [`LeaseStore`]). A binding already recorded for `(session, server)` is `Ok(false)`.
    fn record_session(
        &self,
        session: &str,
        server: &str,
        chain_id: &LeaseId,
        now: OffsetDateTime,
    ) -> Result<bool, AuditError>;

    /// The bindings [`record_session`](Self::record_session) recorded for the session digest
    /// `session`, ordered by server; empty for an unknown session.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown session is an empty list.
    fn sessions(&self, session: &str) -> Result<Vec<SessionBinding>, AuditError>;

    /// Add an output label to the taint state of the delegation run `chain_id` (the lease of
    /// the run's first hop; ADR-0009). The run's lease must be known; the check and the write
    /// are one transaction.
    /// The store keeps one label per source, the one with the smallest `seq`, so reading the
    /// taint state costs the same however many results the run reads (every result is in the
    /// audit log as a `tool_result` record). Labels are never removed: taint only grows.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `chain_id`, or a store fault (see
    /// [`LeaseStore`]), including a `label.seq` the file store cannot hold
    /// ([`AuditError::Storage`]).
    fn add_label(&self, chain_id: &LeaseId, label: &RunLabel) -> Result<(), AuditError>;

    /// The taint state of the run `chain_id`: the first label of each source, ordered by
    /// `seq`. Empty for a run that has read nothing untrusted. Callers must treat an error as
    /// tainted (fail closed).
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]), which the caller must read as tainted.
    fn labels(&self, chain_id: &LeaseId) -> Result<Vec<RunLabel>, AuditError>;

    /// Add the fingerprints of one untrusted result to the span index of the run `chain_id`
    /// (ADR-0009 phase 2, [`crate::spans`]), tagged with `seq`, the audit `seq` of the result's
    /// `tool_result` record. The run's lease must be known. Keeps at most [`MAX_SPANS_PER_RUN`] per
    /// run, evicting the oldest results' sets first; the check, the eviction and the write are one
    /// transaction. Nothing is written for an empty `spans`.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when the store has no row for `chain_id`, or a store fault (see
    /// [`LeaseStore`]), including a `seq` the file store cannot hold ([`AuditError::Storage`]).
    fn add_spans(
        &self,
        chain_id: &LeaseId,
        seq: u64,
        spans: &[Fingerprint],
    ) -> Result<(), AuditError>;

    /// Look `probes` up in the span index of the run `chain_id`: one [`SpanHit`] per probe and
    /// stored result that holds it, at most [`MAX_SEQS_PER_PROBE`] per probe (the lowest
    /// `seq`s), ordered by probe, then `seq`. Empty for a run with no index. One lookup per
    /// probe, so callers bound and deduplicate `probes`. Callers must treat an error as a
    /// match (fail closed).
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]), which the caller must read as a match.
    fn find_spans(
        &self,
        chain_id: &LeaseId,
        probes: &[Fingerprint],
    ) -> Result<Vec<SpanHit>, AuditError>;
}

/// Human approvals of gated calls (ADR-0009): created pending, granted or declined by an
/// approver, then consumed once by the decision that retries the call.
///
/// # Errors
///
/// Store faults are listed on [`LeaseStore`].
pub trait ApprovalStore: Send + Sync {
    /// Store a pending approval (ADR-0009). `approval.state` is ignored (stored as pending);
    /// `approval.expires_at` is lowered to the expiry of `approval.lease`, which must be known
    /// and live; the check and the write are one transaction. When a pending, unexpired approval
    /// for the same run, lease and call hash already exists, nothing is written and that one is
    /// returned with `false`, so an agent that repeats a gated call gets the same approval id.
    /// Otherwise, when the run already has [`crate::MAX_PENDING_APPROVALS_PER_RUN`] pending,
    /// unexpired approvals, nothing is written and the approval is refused (SR-92). Returns the
    /// stored approval and whether it is new.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownLease`] when `approval.lease` is unknown, [`AuditError::LeaseRevoked`]
    /// when it is revoked, [`AuditError::ApprovalExpired`] when it has expired,
    /// [`AuditError::TooManyPendingApprovals`] when the run is at the cap, or a store fault (see
    /// [`LeaseStore`]).
    fn create_approval(&self, approval: &Approval) -> Result<(Approval, bool), AuditError>;

    /// One approval by id, or `None`.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown id is `Ok(None)`.
    fn approval(&self, id: &str) -> Result<Option<Approval>, AuditError>;

    /// Approvals newest first, each with its position, at most `limit`: only those of the run
    /// `chain_id` and in `state` when given, and only those positioned below `before` when
    /// given.
    ///
    /// The position is a number the store gives an approval when it creates it: larger than
    /// that of every approval the store has ever created, including removed and pruned ones,
    /// so no position is given twice, and kept until the approval is removed.
    /// Passing the position of the last approval of one call as `before` of the next lists
    /// the following ones (keyset paging, used by `GET /admin/approvals`): every approval
    /// that existed when the first call was made is listed exactly once, whatever is created
    /// in between (it sorts above the first page), and the state filter is applied before
    /// `limit`, so a filtered page is never cut short by approvals in other states.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown run is an empty list.
    fn approvals(
        &self,
        chain_id: Option<&LeaseId>,
        state: Option<ApprovalState>,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, Approval)>, AuditError>;

    /// Grant (`grant = true`) or decline a pending approval; the checks and the write are one
    /// transaction.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownApproval`] when no approval has this id,
    /// [`AuditError::ApprovalNotPending`] when it was already decided or consumed,
    /// [`AuditError::ApprovalExpired`] when it or its lease has expired,
    /// [`AuditError::LeaseRevoked`] when its lease is revoked, [`AuditError::UnknownLease`] when
    /// its lease is gone, or a store fault (see [`LeaseStore`]).
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
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): a dead lease or no usable approval is `Ok(None)`.
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
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): every refusal listed above is `Ok(None)`.
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
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): an unknown id or an approval not consumed by
    /// `decision_id` is left alone and is `Ok(())`.
    fn restore_approval(&self, id: &str, decision_id: &str) -> Result<(), AuditError>;

    /// Delete an approval whose request could not be recorded.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]): removing an unknown id is `Ok(())`.
    fn remove_approval(&self, id: &str) -> Result<(), AuditError>;
}

/// Run limits (ADR-0010): the counters a decision charges and refunds, with the charge log,
/// the per-user windows (run limits phase 3), and the limits of each hop kept for display.
///
/// # Errors
///
/// Store faults are listed on [`LeaseStore`].
pub trait RunLimits: Send + Sync {
    /// Run limits (ADR-0010): what the counter of each charge holds now, in order. A counter
    /// never charged holds 0. The charges' `amount` and `max` are ignored. Reading does not
    /// look at the leases, so the counters of a revoked or expired lease can still be read.
    /// Callers must deny a limited call when this fails (`budget_error`).
    ///
    /// # Errors
    ///
    /// A charge whose capability index does not fit the counter key ([`AuditError::Storage`]), or a
    /// store fault (see [`LeaseStore`]).
    fn budget_used(&self, charges: &[Charge]) -> Result<Vec<u64>, AuditError>;

    /// Charge one allowed call (ADR-0010): check every charge against its counter and either
    /// apply all of them, logged under `decision_id`, or none (`Exhausted`, naming the first
    /// that would go over its `max`), in one transaction. An empty `charges` writes nothing.
    /// A decision id that already has charges is refused, so a decision is charged once.
    ///
    /// # Errors
    ///
    /// [`AuditError::Storage`] when `decision_id` already has charges or a charge's figures do not
    /// fit the store, or a store fault (see [`LeaseStore`]); nothing is charged then. A charge that
    /// would go over its `max` is not an error but `Ok(ChargeOutcome::Exhausted { .. })`.
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
    ///
    /// # Errors
    ///
    /// As [`charge`](Self::charge).
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
    /// it (SR-62; see [`crate::budget`]). Used by the pipeline when a charged decision's audit
    /// append fails, and by the operator refund (`POST /admin/budgets/refund`).
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownCharge`] when `decision_id` charged nothing (or its charge was pruned),
    /// [`AuditError::ChargeRefunded`] when it was already refunded, or a store fault (see
    /// [`LeaseStore`]).
    fn refund(&self, decision_id: &str, at: OffsetDateTime) -> Result<u64, AuditError>;

    /// Per-user windows (run limits phase 3, [`crate::window`]): what the window counter of
    /// each charge holds now, in order. A window never charged holds 0. The charges' `amount`
    /// is ignored. Callers decide on the worst case when this fails. The default keeps no
    /// windows and fails, so a store without them is read as the worst case.
    ///
    /// # Errors
    ///
    /// [`AuditError::Storage`] when the store keeps no windows (the default) or a counter does
    /// not fit, or a store fault (see [`LeaseStore`]).
    fn window_used(&self, windows: &[WindowCharge]) -> Result<Vec<u64>, AuditError> {
        let _ = windows;
        Err(AuditError::Storage(
            "this lease store keeps no per-user windows".into(),
        ))
    }

    /// [`charge`](Self::charge) (or, with `defer`,
    /// [`charge_sync_deferred`](Self::charge_sync_deferred)) together with the per-user
    /// window charges of the same decision, in one transaction: either everything is applied,
    /// logged under `decision_id`, or nothing. A window charge never refuses (it saturates at
    /// [`WindowCharge::MAX`]) and never adds a sync of its own. A refund returns the window
    /// charges with the rest. The default refuses any window charge, and otherwise is
    /// `charge` or `charge_sync_deferred`.
    ///
    /// # Errors
    ///
    /// As [`charge`](Self::charge), plus [`AuditError::Storage`] when `windows` is not empty
    /// and the store keeps no windows (the default).
    fn charge_windowed(
        &self,
        decision_id: &str,
        charges: &[Charge],
        windows: &[WindowCharge],
        at: OffsetDateTime,
        defer: bool,
    ) -> Result<(ChargeOutcome, bool), AuditError> {
        if !windows.is_empty() {
            return Err(AuditError::Storage(
                "this lease store keeps no per-user windows".into(),
            ));
        }
        if defer {
            self.charge_sync_deferred(decision_id, charges, at)
        } else {
            self.charge(decision_id, charges, at).map(|o| (o, false))
        }
    }

    /// Keep the limited capabilities of the hop whose lease is `lease`, as issued (ADR-0010),
    /// for the admin console. Display only: enforcement reads the limits from the token. The
    /// default keeps nothing.
    ///
    /// # Errors
    ///
    /// A store that keeps the limits fails on a store fault (see [`LeaseStore`]) or when `limits`
    /// cannot be serialized ([`AuditError::Storage`]). The default cannot fail.
    fn record_hop_limits(&self, lease: &LeaseId, limits: &[HopLimit]) -> Result<(), AuditError> {
        let _ = (lease, limits);
        Ok(())
    }

    /// What [`record_hop_limits`](Self::record_hop_limits) kept for `lease`. `None` when
    /// nothing was kept (a hop without limits, a lease issued before this was recorded, or a
    /// store that keeps none, the default).
    ///
    /// # Errors
    ///
    /// A store that keeps the limits fails on a store fault (see [`LeaseStore`]) or when the kept
    /// value no longer deserializes ([`AuditError::Storage`]). The default cannot fail.
    fn hop_limits(&self, lease: &LeaseId) -> Result<Option<Vec<HopLimit>>, AuditError> {
        let _ = lease;
        Ok(None)
    }

    /// Every counter under `lease`, grouped ([`CounterSummary`]): its limits' counters and,
    /// for a run's root lease, the run's usage. Empty when nothing was charged, and by default.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]). The default cannot fail.
    fn budget_summary(&self, lease: &LeaseId) -> Result<Vec<CounterSummary>, AuditError> {
        let _ = lease;
        Ok(Vec::new())
    }
}

/// Retention of the lease store: one bounded pass at a time, each in one write transaction,
/// over the session bindings, the lease registry, the run state (charge log, counters,
/// approvals) and the per-user windows. Each pass deletes only what can no longer be used.
///
/// # Errors
///
/// Store faults are listed on [`LeaseStore`].
pub trait StoreRetention: Send + Sync {
    /// One pass of session retention: look at up to `max_rows` session bindings, in the order
    /// they were recorded and continuing after the last binding the previous pass looked at,
    /// and delete those [`session_prunable`] at `now` with `retention` as the grace period.
    /// When a pass reaches the last binding it reports `wrapped`, and the next pass starts
    /// from the first again. One transaction per pass, so a pass never deletes a binding whose
    /// chain a concurrent renewal has just revived. A pruned session resolves to no chain,
    /// like a session that was never recorded: [`LeaseSelector::Session`] matches nothing and
    /// [`sessions`](RunState::sessions) is empty.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]); the pass's transaction is then rolled back and
    /// nothing is deleted.
    fn prune_sessions(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<SessionPrune, AuditError>;

    /// One pass of lease retention: look at leases in the order they were registered,
    /// continuing after the last lease the previous pass looked at, and delete every lease
    /// tree whose top is among them and that is [`tree_prunable`] at `now` with `retention` as
    /// the grace period. A tree is the top lease (one with no parent, or whose parent the
    /// store does not know) and everything delegated from it; it is deleted whole, with the
    /// subjects, chain bindings, session bindings, hop limits, run labels and span indexes of
    /// its leases. Leases that are not tops are skipped (their tree is decided at its top),
    /// but count as examined. When a pass reaches the last lease it reports `wrapped`, and the
    /// next pass starts from the first again.
    ///
    /// A pass touches at most `max_rows` lease rows (see [`LeasePrune`]): those its window
    /// looks at, those it reads walking a tree from a prunable top, and those it deletes. A
    /// tree that does not fit is carried over and finished first by the following passes:
    /// walked to the end before anything of it is deleted, then deleted children before
    /// parents, the top last, so no lease is ever left whose parent row is gone and the top
    /// (in every chain of the tree) is there until the end. One write transaction per pass.
    /// Between passes, a renewal or a new registration of a lease of a tree being walked, a
    /// revocation of one, or a child registered under one, abandons the walk (the tree is
    /// decided again from its top on a later sweep, so a late revocation still restarts the
    /// grace period); once deleting has started, renewing or registering again a lease of the
    /// tree is refused as [`AuditError::UnknownLease`], so no part of it is live again.
    /// Every lease of such a tree is inactive throughout: a check reads it as revoked or
    /// expired until its row goes, then as unknown. A pruned lease reads as unknown, which
    /// every check treats as inactive (`lease_unknown`); selectors no longer match it.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]); the pass's transaction is then rolled back and
    /// nothing is deleted.
    fn prune_leases(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<LeasePrune, AuditError>;

    /// One pass of run-state retention: look at up to `max_rows` rows of run-limit state and
    /// approvals, continuing after the last row the previous pass looked at, and delete what
    /// [`run_state_prunable`] allows at `now` with `retention` as the grace period. The tables
    /// are walked in a fixed order, each in insertion order: the charge log (decided per
    /// charged decision: every lease it charged must be gone from the registry, and its charge
    /// and any refund older than `retention`), then the counters (a counter goes once its
    /// lease is gone and no charge under that lease is left in the log, so a counter outlives
    /// its newest charge by at least `retention`), then the approvals (gone once neither their
    /// lease nor their run's chain id is in the registry and their creation, decision and
    /// expiry are all older than `retention`). Nothing of a lease the registry still holds is
    /// ever deleted, whatever its age; the lease registry itself waits
    /// [`prune_leases`](Self::prune_leases)' retention after a run ended. When a pass reaches
    /// the end of the approvals it reports `wrapped`, and the next pass starts again with the
    /// charge log. One write transaction per pass. A refund of a pruned charge is refused as
    /// [`AuditError::UnknownCharge`], like a decision that charged nothing.
    ///
    /// # Errors
    ///
    /// Only a store fault (see [`LeaseStore`]); the pass's transaction is then rolled back and
    /// nothing is deleted.
    fn prune_run_state(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<RunStatePrune, AuditError>;

    /// One pass of per-user window retention: delete up to `max_rows` window counters, and
    /// the charges logged against them, whose window ended more than `retention` before
    /// `now` ([`window_prunable`]). Open windows are never touched.
    /// One write transaction per pass. The default keeps nothing and reports `wrapped`.
    ///
    /// # Errors
    ///
    /// A store fault (see [`LeaseStore`]); the default never fails.
    fn prune_user_windows(
        &self,
        now: OffsetDateTime,
        retention: time::Duration,
        max_rows: usize,
    ) -> Result<WindowPrune, AuditError> {
        let _ = (now, retention, max_rows);
        Ok(WindowPrune {
            wrapped: true,
            ..WindowPrune::default()
        })
    }
}

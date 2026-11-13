//! [`Pipeline`]: the decision pipeline, steps 1 to 7 of the [module docs](super).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use attenuo_audit::{
    Approval, ApprovalLabel, ApprovalState, AuditSink, ChargeOutcome, LeaseStore, RunLabel,
};
use attenuo_core::fingerprint::{fingerprints, pinned_arguments, Fingerprint};
use attenuo_core::limits::{
    charges_for, MAX_LIMIT, REASON_BUDGET_ERROR, REASON_BUDGET_EXHAUSTED, REASON_LIMIT_ARG_INVALID,
};
use attenuo_core::{
    chain_id_of, ApprovalInfo, BudgetCharge, Charge, Decision, DecisionRecord, DelegationChain,
    LeaseId, LimitKind, OutputLabel, RecordBudget, RecordKind, RecordLabels, ResultInfo, ToolCall,
    UntrustedArg, UntrustedKind, REASON_APPROVAL_INVALID, REASON_APPROVAL_REQUESTED,
};
use attenuo_policy::{
    ApprovalContext, ArgLabels, BudgetContext, BudgetRefusal, CallLabels, PolicyEngine,
    SessionLabels, UsageContext,
};
use attenuo_proxy::{ApprovalTicket, CallContext, Stage};
use attenuo_token::Verifier;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::metrics::{ExhaustedAt, Metrics, RefundSource};

use super::budgets::{distinct_step, read_counters};
use super::usage::{micros, record_usage, run_usage_charges, UsageInputs};
use super::windows::{read_windows, user_stripe, USER_LOCK_STRIPES};
use super::{
    ArgTaint, BudgetView, CounterSource, LimitHit, RunLabels, SharedPolicy, MAX_ARG_PROBES,
    MAX_UNTRUSTED_ARG_ENTRIES, UNREADABLE_USAGE,
};

/// Reason code: a lease in the chain (or an ancestor of one) was revoked.
pub const REASON_LEASE_REVOKED: &str = "lease_revoked";
/// Reason code: a lease in the chain has expired.
pub const REASON_LEASE_EXPIRED: &str = "lease_expired";
/// Reason code: a lease in the chain is not in the registry (fail closed).
pub const REASON_LEASE_UNKNOWN: &str = "lease_unknown";
/// Reason code: the lease registry could not be read (fail closed).
pub const REASON_LEASE_ERROR: &str = "lease_error";
/// Reason code: the decision could not be written to the audit log (fail closed).
pub const REASON_AUDIT_ERROR: &str = "audit_error";
/// Reason code: a result's `tool_result` record or the run's label could not be written, so
/// the result is withheld (ADR-0009).
pub const REASON_LABEL_ERROR: &str = attenuo_proxy::REASON_LABEL_ERROR;
/// The diagnostic of a gated call whose run already has
/// [`attenuo_audit::MAX_PENDING_APPROVALS_PER_RUN`] approvals pending (SR-92): the call is
/// denied `approval_required` with no approval to grant, as when the store fails.
pub const DIAG_TOO_MANY_PENDING_APPROVALS: &str = "too many pending approvals for this run";

/// The result of running the pipeline once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineDecision {
    /// Allow or deny.
    pub decision: Decision,
    /// The reason code the record and any denial carry, such as `policy_allow`, `policy_deny`,
    /// `budget_exhausted` or `audit_error`.
    pub reason: String,
    /// Id of the audit record. When the append failed this id is not in the log.
    pub decision_id: Uuid,
    /// Audit sequence number of the record, if it was written.
    pub audit_seq: Option<u64>,
    /// Ids of the Cedar policies that determined the decision. Empty for a capability denial, a
    /// default deny, or a call refused before the policy ran (a lease or approval-token problem).
    pub policy_ids: Vec<String>,
    /// Human-readable details for the record: policy evaluation errors and lease, label, usage
    /// and approval problems.
    pub diagnostics: Vec<String>,
    /// For `approval_required`: the pending approval stored for the call. `None` otherwise,
    /// or when it could not be stored or recorded (the diagnostics say why).
    pub approval: Option<ApprovalTicket>,
    /// For an allowed call that consumed an approval: its id and `by` (`user` or `operator`).
    pub consumed_approval: Option<(Uuid, String)>,
    /// The consumed approval was presented as a signed approval token.
    pub approval_by_token: bool,
    /// The run limits that matched the call, as Cedar saw them (ADR-0010). The default when
    /// none matched or the call was decided before the budget was read.
    pub budget: BudgetContext,
    /// For `budget_exhausted`: the limit that was hit.
    pub limit: Option<LimitHit>,
    /// For an allowed call that matched limits: what it charged (the record's `budget`).
    pub charged: Option<RecordBudget>,
    /// The arguments that matched the run's span index (the record's
    /// `labels.untrusted_args`). Empty when none did.
    pub untrusted_args: Vec<UntrustedArg>,
    /// For a call to a destructive tool: the run's usage of it before the call, as Cedar saw
    /// it (the record's `usage`). `None` for any other tool, or when the call was decided
    /// before usage was read.
    pub usage: Option<UsageContext>,
}

impl PipelineDecision {
    /// Whether the call is allowed.
    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// Lease check, policy evaluation and audit, in that order.
pub struct Pipeline {
    pub(super) policy: Arc<SharedPolicy>,
    leases: Arc<dyn LeaseStore>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<Metrics>,
    /// `[approvals] ttl_seconds`.
    approval_ttl: time::Duration,
    /// Checks presented approval tokens: the issuer's public keys, `iss` and `aud`. `None`
    /// refuses every presented token (`approval_invalid`).
    approval_verifier: Option<Verifier>,
    /// The lease store and the audit log are the same database file, so the synced append of
    /// a decision also makes its `sum` charge durable: the charge leaves its sync to the
    /// append (one `fsync` per call instead of a synced charge then an append, and under load
    /// the append's group commit shares it). See [`RunLimits::charge_sync_deferred`].
    pub(super) charge_sync_on_append: bool,
    /// Serialises, per delegation run, the decisions whose policy input includes run usage or
    /// budget figures, from reading those figures to charging them (SR-55). See
    /// `Pipeline::run_guard`.
    run_locks: Box<[Mutex<()>]>,
    /// The same for every run of one originating user, for calls that keep a per-user window
    /// (run limits phase 3), taken after the run's lock. See `Pipeline::run_guard`.
    user_locks: Box<[Mutex<()>]>,
    /// `[approvals.notify]`: told about each new pending approval; it only queues.
    approval_notifier: Option<crate::notify::NotifierHandle>,
    /// `[telemetry]`: the key of the subject digest on the exported `attenuo.decide` span
    /// ([`crate::telemetry::SubjectDigest`]); `None` when telemetry is off.
    subject_digest: Option<crate::telemetry::SubjectDigest>,
    /// Tests: run in a decision between the run-state stage and the policy stage.
    #[cfg(test)]
    pub(super) mid_decision_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// `[logging] redact_subjects`: how the decision and rejection log lines name the user.
    subject_log: attenuo_proxy::SubjectLog,
}

/// The lookups [`Pipeline::arg_taint`] makes for a call: one probe per distinct fingerprint of
/// the unpinned arguments, with the arguments that carry it (SR-91).
#[derive(Debug, Default)]
pub(super) struct ArgProbes<'a> {
    /// The distinct fingerprints, in first-seen order. Empty past [`MAX_ARG_PROBES`].
    pub(super) probes: Vec<Fingerprint>,
    /// For each probe, the arguments that carry it, in argument order.
    pub(super) owners: Vec<Vec<&'a str>>,
    /// Every unpinned argument with at least one fingerprint, in argument order.
    pub(super) fingerprinted: Vec<&'a str>,
    /// `(argument, fingerprint)` pairs over all unpinned arguments, duplicates included.
    pub(super) pairs: usize,
}

/// The probes of `call`'s arguments not in `pinned`. Once the pairs pass [`MAX_ARG_PROBES`]
/// nothing more is kept for lookup (the caller then looks nothing up). The remaining
/// arguments are still fingerprinted, in full, to learn which of them have a fingerprint, so
/// the fail-closed answer names each of them: the bound limits the lookups and what they
/// return, not the fingerprinting, whose cost is that of the request body (each value at
/// most [`MAX_FINGERPRINTS_PER_VALUE`] fingerprints from its first [`MAX_TEXT_BYTES`]; SR-99).
///
/// [`MAX_FINGERPRINTS_PER_VALUE`]: attenuo_core::fingerprint::MAX_FINGERPRINTS_PER_VALUE
/// [`MAX_TEXT_BYTES`]: attenuo_core::fingerprint::MAX_TEXT_BYTES
pub(super) fn arg_probes<'a>(call: &'a ToolCall, pinned: &BTreeSet<String>) -> ArgProbes<'a> {
    let mut out = ArgProbes::default();
    let mut slot: HashMap<Fingerprint, usize> = HashMap::new();
    for (name, value) in &call.arguments {
        if pinned.contains(name) {
            continue;
        }
        let fps = fingerprints(value);
        if fps.is_empty() {
            continue;
        }
        out.fingerprinted.push(name);
        out.pairs = out.pairs.saturating_add(fps.len());
        if out.pairs > MAX_ARG_PROBES {
            continue;
        }
        for f in fps {
            let i = *slot.entry(f).or_insert_with(|| {
                out.probes.push(f);
                out.owners.push(Vec::new());
                out.probes.len() - 1
            });
            out.owners[i].push(name);
        }
    }
    if out.pairs > MAX_ARG_PROBES {
        out.probes.clear();
        out.owners.clear();
    }
    out
}

/// How many locks `Pipeline::run_guard` spreads runs over. Two runs that share one only
/// wait for each other's budgeted decisions; correctness needs only that one run always maps
/// to the same lock.
const RUN_LOCK_STRIPES: usize = 64;

#[cfg(test)]
pub(super) const RUN_LOCK_STRIPES_FOR_TESTS: usize = RUN_LOCK_STRIPES;

impl Pipeline {
    /// A pipeline over this policy, lease store and audit log, with the default approval TTL and
    /// no approval-token verifier or approval notifier (see the `with_*` methods). When the lease
    /// store and the audit log are the same database file, a `sum` charge leaves its sync to the
    /// decision's append.
    pub fn new(
        policy: Arc<SharedPolicy>,
        leases: Arc<dyn LeaseStore>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        let charge_sync_on_append = matches!(
            (leases.sync_file(), audit.sync_file()),
            (Some(a), Some(b)) if a == b
        );
        Self {
            charge_sync_on_append,
            policy,
            leases,
            audit,
            metrics: Metrics::new(),
            approval_ttl: time::Duration::seconds(
                i64::try_from(crate::config::DEFAULT_APPROVAL_TTL_SECONDS).unwrap_or(i64::MAX),
            ),
            approval_verifier: None,
            run_locks: (0..RUN_LOCK_STRIPES).map(|_| Mutex::new(())).collect(),
            user_locks: (0..USER_LOCK_STRIPES).map(|_| Mutex::new(())).collect(),
            approval_notifier: None,
            subject_digest: None,
            subject_log: attenuo_proxy::SubjectLog::clear(),
            #[cfg(test)]
            mid_decision_hook: Mutex::new(None),
        }
    }

    /// Tests: run the hook set in `mid_decision_hook`, if any.
    #[cfg(test)]
    fn mid_decision(&self) {
        if let Some(hook) = self.mid_decision_hook.lock().unwrap().as_ref() {
            hook();
        }
    }

    /// Hold the run's lock while a decision reads budget or usage figures, evaluates the
    /// policy over them and charges them, so that the next decision of the same run sees what
    /// this one charged (SR-55). The store's charge re-checks token limits on its own, but
    /// nothing re-checks a policy over `context.usage` (a "hard" rule such as
    /// `usage.amount + input.amount > 2000`, or a soft rule that asks on the second call) or
    /// over `context.budget`: without the lock, concurrent calls of one run all read the same
    /// figures and are all allowed. `None` (no lock) for a call that neither matches a token
    /// limit's hop nor keeps run usage, so other calls never wait. A call that keeps a
    /// per-user window (run limits phase 3) also holds its user's lock, taken after the run's
    /// from a separate set of stripes, so a rule over `context.usage.user_window` sees what
    /// every earlier call of the user's other runs charged. The wait for both is one
    /// `run_lock_wait_seconds` observation. In process only: two servers on one store would
    /// not share them (not a supported deployment).
    fn run_guard(
        &self,
        engine: &PolicyEngine,
        chain: &DelegationChain,
        call: &ToolCall,
    ) -> Option<(
        std::sync::MutexGuard<'_, ()>,
        Option<std::sync::MutexGuard<'_, ()>>,
    )> {
        let limited = chain
            .hops
            .iter()
            .any(|h| h.capabilities.iter().any(|c| !c.limits.is_empty()));
        if !limited && usage_inputs(engine, call).is_none() {
            return None;
        }
        let chain_id = chain_id_of(chain)?;
        let digest = attenuo_core::digest::sha256_bytes(chain_id.as_bytes());
        let stripe = usize::from_str_radix(&digest[..8], 16).unwrap_or(0) % self.run_locks.len();
        let waiting = Instant::now();
        // A panic while holding the lock leaves nothing half-written that the lock guards.
        let guard = self.run_locks[stripe]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Run first, then user, from separate arrays: no deadlock and no self-block.
        let user = keeps_user_window(engine, call).then(|| {
            self.user_locks[user_stripe(&chain.originating_user, self.user_locks.len())]
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        self.metrics.observe_run_lock_wait(waiting.elapsed());
        Some((guard, user))
    }

    /// Add the originating user's per-user windows (run limits phase 3) to `view`, read from
    /// the lease store at `now`: the window charges go into `view.windows` and the figures into
    /// `view.usage.user_window`, for the kinds a loaded policy reads
    /// ([`PolicyEngine::user_window_kinds`]). Does nothing for a call that keeps no run usage.
    /// An unreadable store gives the worst case for every kept kind, and the policy decides.
    /// The admin dry run uses this when it reads usage from the store.
    pub fn add_user_windows(
        &self,
        engine: &PolicyEngine,
        view: &mut BudgetView,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) {
        let Some(inputs) = usage_inputs(engine, call) else {
            return;
        };
        let amount = inputs.amount;
        let kinds = engine.user_window_kinds().to_vec();
        read_windows(
            self.leases.as_ref(),
            view,
            &chain.originating_user,
            call,
            amount.as_deref(),
            &kinds,
            now,
        );
    }

    /// Accept signed approval tokens that verify under `verifier` (the issuer's own verifier:
    /// its public keys, `iss` and `aud`). Without this every presented token is refused.
    pub fn with_approval_verifier(mut self, verifier: Verifier) -> Self {
        self.approval_verifier = Some(verifier);
        self
    }

    /// How long a pending approval stays usable (`[approvals] ttl_seconds`, default 120 s).
    pub fn with_approval_ttl(mut self, ttl: time::Duration) -> Self {
        self.approval_ttl = ttl;
        self
    }

    /// Queue an `approval.pending` notice for every new pending approval
    /// (`[approvals.notify]`). Queuing never waits on the receiver.
    pub fn with_approval_notifier(mut self, notifier: crate::notify::NotifierHandle) -> Self {
        self.approval_notifier = Some(notifier);
        self
    }

    /// Put a keyed digest of the originating subject on the exported `attenuo.decide` span
    /// (`[telemetry]`, design section 3.3): never the subject itself.
    pub fn with_subject_digest(mut self, digest: crate::telemetry::SubjectDigest) -> Self {
        self.subject_digest = Some(digest);
        self
    }

    /// Write user subjects into log lines as `log` says (`[logging] redact_subjects`). The
    /// audit records keep the subject either way.
    pub fn with_subject_log(mut self, log: attenuo_proxy::SubjectLog) -> Self {
        self.subject_log = log;
        self
    }

    /// How user subjects appear in log lines, for every log site that names one: the
    /// pipeline's, the routes' and, through the authorizer, the proxy's.
    pub fn subject_log(&self) -> &attenuo_proxy::SubjectLog {
        &self.subject_log
    }

    /// Report decisions and audit failures to a shared [`Metrics`] instead of a private one.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// The metrics this pipeline reports to.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The shared policy engine (for hot reload).
    pub fn policy(&self) -> &Arc<SharedPolicy> {
        &self.policy
    }

    /// The engine in force now: what a caller that runs several stages on its own (the admin
    /// dry run) passes to each, so they all see one policy set.
    pub fn policy_snapshot(&self) -> Arc<PolicyEngine> {
        self.policy.snapshot()
    }

    /// Decide `call` for the agent at the end of `chain`, and record the decision.
    pub fn decide(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> PipelineDecision {
        self.decide_with(chain, call, &CallContext::default(), now)
    }

    /// [`decide`](Self::decide) with what the caller knows besides the chain: a presented
    /// approval token and the calling hop's key binding (`cnf.jkt`, when the request proved
    /// possession). The key binding is also stored with a pending approval, so the approval
    /// token a grant returns is bound to the same key.
    pub fn decide_with(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        ctx: &CallContext,
        now: OffsetDateTime,
    ) -> PipelineDecision {
        let span = crate::telemetry::decide_span(call);
        let entered = span.enter();
        let started = Instant::now();
        let out = self.decide_inner(chain, call, ctx, now);
        self.metrics.observe_authorize(started.elapsed());
        self.metrics.decision(out.decision.as_str(), &out.reason);
        drop(entered);
        crate::telemetry::record_decision(&span, &out, chain, self.subject_digest.as_ref());
        out
    }

    /// The policy stage alone: `PolicyEngine::authorize_labelled` (the capability stage, the
    /// catalog, then Cedar) on `engine`, with `labels` as the run's output labels. No lease
    /// check, no audit record, no metrics.
    ///
    /// [`decide`](Self::decide) runs this after the lease check and the label read, on the
    /// snapshot it took first, and the admin dry run (`POST /admin/policies/evaluate`) runs it
    /// on its own snapshot ([`policy_snapshot`](Self::policy_snapshot)), so the two cannot
    /// disagree about what the policy says.
    pub fn evaluate_policy(
        &self,
        engine: &PolicyEngine,
        chain: &DelegationChain,
        call: &ToolCall,
        labels: &CallLabels,
        now: OffsetDateTime,
    ) -> attenuo_policy::Outcome {
        engine.authorize_labelled(chain, call, labels, now)
    }

    /// The list screen (ADR-0011, `[proxy] list_filter = "policy"`): for each of `tools` on
    /// `server`, whether it stays listed for `chain` (`PolicyEngine::screen_tools`). No lease
    /// check, no audit record, no approval, no charge, no run state: a hidden tool that is
    /// called anyway is decided by [`decide`](Self::decide) as before. Hidden entries are
    /// counted by reason. One policy snapshot screens the whole list.
    pub fn screen_tools(
        &self,
        chain: &DelegationChain,
        server: &str,
        tools: &[String],
    ) -> Vec<bool> {
        self.policy
            .snapshot()
            .screen_tools(chain, server, tools)
            .into_iter()
            .map(|verdict| match verdict {
                attenuo_policy::ListScreen::Keep => true,
                attenuo_policy::ListScreen::Hide(reason) => {
                    self.metrics.list_entry_hidden(reason);
                    false
                }
            })
            .collect()
    }

    fn decide_inner(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        ctx: &CallContext,
        now: OffsetDateTime,
    ) -> PipelineDecision {
        // One policy set for the whole decision (A-8): every stage below reads `engine`, so a
        // reload that lands meanwhile cannot mix its policies with the old ones.
        let engine = self.policy.snapshot();
        let engine = engine.as_ref();
        // Stage timings: one `Instant::now()` per boundary (see `Stage`).
        let t0 = Instant::now();
        let leases = crate::telemetry::stage_span!("attenuo.lease_check").in_scope(|| {
            let leases = self.check_leases(chain, now);
            if let Err((reason, _)) = &leases {
                tracing::Span::current().record("attenuo.reason", *reason);
            }
            leases
        });
        let t1 = Instant::now();
        let mut policy_time = None;
        let mut record_labels = RecordLabels::default();
        let mut label_sources = Vec::new();
        // The record id is fixed first: a taken approval names the decision that consumed it.
        let decision_id = Uuid::new_v4();
        let mut taken: Option<Approval> = None;
        let mut budget = BudgetView::default();
        // Held from the budget read to the charge (SR-55).
        let run_guard = leases
            .is_ok()
            .then(|| self.run_guard(engine, chain, call))
            .flatten();
        let (mut decision, mut reason, mut policy_ids, mut diagnostics) = match leases {
            Err((reason, detail)) => (Decision::Deny, reason.to_string(), Vec::new(), detail),
            Ok(()) => {
                let (run, args) =
                    crate::telemetry::stage_span!("attenuo.run_state").in_scope(|| {
                        let run = self.run_labels(chain);
                        budget = self.budget_view(engine, chain, call);
                        self.add_user_windows(engine, &mut budget, chain, call, now);
                        let args = self.arg_taint(engine, chain, call, &run.session);
                        (run, args)
                    });
                tracing::Span::current().record("attenuo.tainted", run.session.tainted);
                let mut diagnostics = Vec::new();
                record_labels = run.record;
                record_labels.untrusted_args = args.record;
                label_sources = run.sources;
                // Leases are live, so a granted approval for this exact call may be used: the
                // one a presented token names, or else the one the identical retry finds.
                let took = match ctx.approval_token.as_deref() {
                    Some(token) => self
                        .take_presented(chain, call, token, ctx.jkt.as_deref(), decision_id, now)
                        .map(Some),
                    None => Ok(self.take_approval(chain, call, decision_id, now, &mut diagnostics)),
                };
                match took {
                    Err(detail) => {
                        tracing::info!(detail = ?detail, "approval token refused");
                        diagnostics.push(detail);
                        diagnostics.extend(run.error);
                        diagnostics.extend(args.error);
                        diagnostics.extend(budget.usage_error.clone());
                        (
                            Decision::Deny,
                            REASON_APPROVAL_INVALID.to_string(),
                            Vec::new(),
                            diagnostics,
                        )
                    }
                    Ok(t) => {
                        taken = t;
                        let labels = CallLabels {
                            session: run.session,
                            args: args.context,
                            approval: taken
                                .as_ref()
                                .and_then(|a| a.approver.as_ref())
                                .map(|a| ApprovalContext::by(a.method.by()))
                                .unwrap_or_default(),
                            budget: budget.context.clone(),
                            usage: budget.usage.unwrap_or_default(),
                        };
                        #[cfg(test)]
                        self.mid_decision();
                        let o = crate::telemetry::stage_span!("attenuo.policy")
                            .in_scope(|| self.evaluate_policy(engine, chain, call, &labels, now));
                        policy_time = Some(t1.elapsed());
                        diagnostics.extend(o.diagnostics);
                        diagnostics.extend(run.error);
                        diagnostics.extend(args.error);
                        diagnostics.extend(budget.usage_error.clone());
                        (o.decision, o.reason, o.policy_ids, diagnostics)
                    }
                }
            }
        };
        let mut limit = (reason == REASON_BUDGET_EXHAUSTED)
            .then(|| budget.hit.clone())
            .flatten();
        // Where the limit was met, for `budget_exhausted_total`.
        let mut exhausted_at = ExhaustedAt::Check;
        // Charge an allowed call against every matching limit, re-checking in the store's
        // transaction: a concurrent call may have spent the budget since it was read.
        let mut charged: Option<RecordBudget> = None;
        // Something was charged, a limit or run usage: refunded if the append fails.
        let mut any_charged = false;
        // The charge left its sync to the decision's append (see `charge_sync_on_append`).
        let mut sync_on_append = false;
        if decision.is_allow() && !(budget.charges.is_empty() && budget.windows.is_empty()) {
            let id = decision_id.to_string();
            let charge_span = crate::telemetry::stage_span!("attenuo.charge");
            let charging = charge_span.enter();
            // Per-user windows go in the same transaction (run limits phase 3).
            let defer = self.charge_sync_on_append;
            let outcome = self
                .leases
                .charge_windowed(&id, &budget.charges, &budget.windows, now, defer)
                .map(|(outcome, owed)| {
                    sync_on_append = owed;
                    outcome
                });
            if matches!(outcome, Ok(ChargeOutcome::Exhausted { .. })) {
                charge_span.record("attenuo.budget.exhausted_at", "charge");
            }
            drop(charging);
            match outcome {
                Ok(ChargeOutcome::Charged { used_after }) => {
                    any_charged = true;
                    for c in budget.charges.iter().filter(|c| !c.usage) {
                        self.metrics.budget_charged(c.kind);
                    }
                    let limits: Vec<BudgetCharge> = budget
                        .charges
                        .iter()
                        .zip(used_after)
                        .filter(|(c, _)| !c.usage)
                        .map(|(c, used_after)| BudgetCharge {
                            hop: c.hop,
                            cap: c.cap,
                            kind: c.kind,
                            arg: c.arg.clone(),
                            used_after,
                            max: c.max,
                        })
                        .collect();
                    charged = (!limits.is_empty()).then_some(RecordBudget { charged: limits });
                }
                Ok(ChargeOutcome::Exhausted { index, used }) => {
                    exhausted_at = ExhaustedAt::Charge;
                    let hit = LimitHit::of(&budget.charges[index], used);
                    diagnostics.push(hit.detail());
                    limit = Some(hit);
                    (decision, reason, policy_ids) = (
                        Decision::Deny,
                        REASON_BUDGET_EXHAUSTED.to_string(),
                        Vec::new(),
                    );
                }
                Err(e) if budget.charges.iter().all(|c| c.usage) => {
                    // Only run usage: it is a policy input, not a limit, so the decision
                    // stands (design 3.4 denies only calls a limit applies to). The next read
                    // of an unreadable store sees the worst case (see `budget_view`).
                    tracing::error!(error = %e, "run usage could not be charged; deciding anyway");
                    diagnostics.push(format!("run usage could not be charged: {e}"));
                }
                Err(e) => {
                    tracing::error!(error = %e, "budget counters could not be charged; denying");
                    diagnostics.push(format!("budget counters could not be charged: {e}"));
                    (decision, reason, policy_ids) =
                        (Decision::Deny, REASON_BUDGET_ERROR.to_string(), Vec::new());
                }
            }
        }
        // The charge is committed: the run's next decision may read the figures.
        drop(run_guard);
        // An approval is spent only by a call it let through.
        if !decision.is_allow() {
            if let Some(a) = taken.take() {
                self.give_back(&a, decision_id);
            }
        }
        let consumed_approval = taken.as_ref().map(|a| {
            let by = a
                .approver
                .as_ref()
                .map(|p| p.method.by())
                .unwrap_or_default()
                .to_string();
            (Uuid::parse_str(&a.id).unwrap_or_default(), by)
        });

        let mut record =
            DecisionRecord::new(now, decision, reason, chain, call, policy_ids.clone())
                .with_labels(record_labels.clone());
        record.id = decision_id;
        let approval_by_token = consumed_approval.is_some() && ctx.approval_token.is_some();
        if let Some((id, by)) = &consumed_approval {
            let mut info = ApprovalInfo::new(*id);
            info.by = Some(by.clone());
            info.presented = approval_by_token.then(|| "token".to_string());
            record.approval = Some(info);
        }
        record.budget = charged.clone();
        record.usage = budget
            .usage
            .as_ref()
            .map(|u| record_usage(u, &budget.windows));
        // The record moves into the log; the entry hands it back, so it is never cloned. A
        // deferred `sum` charge is durable once this synced append returns, before the call is
        // answered or forwarded; if the append fails, the charge is refunded below.
        let t2 = Instant::now();
        let appended = crate::telemetry::stage_span!("attenuo.audit_append").in_scope(|| {
            let appended = if sync_on_append {
                self.audit.append_synced(record)
            } else {
                self.audit.append(record)
            };
            if let Ok(entry) = &appended {
                tracing::Span::current().record("attenuo.audit.seq", entry.seq);
            }
            appended
        });
        let append_time = t2.elapsed();
        self.metrics.observe_audit_append(append_time);
        self.metrics.audit_append_result(appended.is_ok());
        let lease_time = t1 - t0;
        self.metrics.observe_stage(Stage::LeaseCheck, lease_time);
        if let Some(d) = policy_time {
            self.metrics.observe_stage(Stage::Policy, d);
        }
        self.metrics.observe_stage(Stage::AuditAppend, append_time);
        tracing::debug!(
            lease_check_us = micros(lease_time),
            policy_us = policy_time.map(micros),
            audit_append_us = micros(append_time),
            "decision stages"
        );
        match appended {
            Ok(entry) => {
                let record = entry.record;
                if let Some(hit) = limit
                    .as_ref()
                    .filter(|_| record.reason == REASON_BUDGET_EXHAUSTED)
                {
                    self.metrics.budget_exhausted(hit.kind, exhausted_at);
                    crate::telemetry::record_exhausted(hit.kind, exhausted_at);
                }
                if let Some((_, by)) = &consumed_approval {
                    self.metrics.approval_consumed(by);
                }
                if !record_labels.untrusted_args.is_empty() {
                    self.metrics.taint_match(record.decision.is_allow());
                }
                // Subject, agent, server and tool come from the caller: Debug-format them so
                // a newline cannot forge a log line (SR-18).
                tracing::info!(
                    decision = ?record.decision,
                    reason = ?record.reason,
                    subject = ?self.subject_log.show(&record.originating_subject),
                    agent = ?chain.current_agent().map(|a| a.0.as_str()).unwrap_or(""),
                    server = ?call.server,
                    tool = ?call.tool,
                    seq = entry.seq,
                    "decision"
                );
                let approval = (record.reason == attenuo_policy::REASON_APPROVAL_REQUIRED)
                    .then(|| {
                        self.request_approval(
                            chain,
                            call,
                            ctx.jkt.as_deref(),
                            decision_id,
                            &policy_ids,
                            &record_labels,
                            label_sources,
                            now,
                            &mut diagnostics,
                        )
                    })
                    .flatten();
                PipelineDecision {
                    decision: record.decision,
                    reason: record.reason,
                    decision_id,
                    audit_seq: Some(entry.seq),
                    policy_ids: record.policy_ids,
                    diagnostics,
                    approval,
                    consumed_approval,
                    approval_by_token,
                    budget: budget.context,
                    limit,
                    charged,
                    untrusted_args: record_labels.untrusted_args,
                    usage: budget.usage,
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "audit append failed; denying");
                self.metrics.audit_append_error();
                if let Some(a) = &taken {
                    self.give_back(a, decision_id);
                }
                if any_charged {
                    self.refund_unrecorded(decision_id, now);
                }
                diagnostics.push(format!("audit append failed: {e}"));
                PipelineDecision {
                    decision: Decision::Deny,
                    reason: REASON_AUDIT_ERROR.to_string(),
                    decision_id,
                    audit_seq: None,
                    policy_ids: Vec::new(),
                    diagnostics,
                    approval: None,
                    consumed_approval: None,
                    approval_by_token: false,
                    budget: budget.context,
                    limit: None,
                    charged: None,
                    untrusted_args: record_labels.untrusted_args,
                    usage: budget.usage,
                }
            }
        }
    }

    /// Take a granted approval for `call` by the last hop of `chain` (ADR-0009), marking it
    /// consumed by `decision_id`. A store error means no approval (fail closed) and a
    /// diagnostic.
    fn take_approval(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        decision_id: Uuid,
        now: OffsetDateTime,
        diagnostics: &mut Vec<String>,
    ) -> Option<Approval> {
        let (chain_id, hop) = (chain_id_of(chain)?, chain.hops.last()?);
        match self.leases.take_approval(
            &LeaseId::new(chain_id),
            &hop.lease,
            &call.call_hash(),
            &decision_id.to_string(),
            now,
        ) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!(error = %e, "approval store unreadable; deciding without approval");
                diagnostics.push(format!("approval store unreadable: {e}"));
                None
            }
        }
    }

    /// Take the approval a presented approval token names, after checking the token (see the
    /// module docs, step 3). `Err` is the reason it was refused, for the diagnostics; the
    /// decision is then `approval_invalid`. A store error refuses too (fail closed).
    fn take_presented(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        token: &str,
        jkt: Option<&str>,
        decision_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Approval, String> {
        let verifier = self
            .approval_verifier
            .as_ref()
            .ok_or("approval tokens are not accepted here (no issuer key to check them with)")?;
        let claims = verifier
            .verify_approval(token, now)
            .map_err(|e| format!("approval token refused: {e}"))?;
        let (Some(chain_id), Some(hop)) = (chain_id_of(chain), chain.hops.last()) else {
            return Err("chain has no hops".into());
        };
        let call_hash = call.call_hash();
        claims
            .check_binding(&chain_id, &hop.lease.0, &call_hash, jkt)
            .map_err(|e| e.to_string())?;
        let chain_id = LeaseId::new(chain_id);
        match self.leases.take_approval_by_id(
            &claims.jti,
            &chain_id,
            &hop.lease,
            &call_hash,
            &decision_id.to_string(),
            now,
        ) {
            Ok(Some(a)) => Ok(a),
            Ok(None) => {
                let state = match self.leases.approval(&claims.jti) {
                    Ok(Some(a)) if a.is_expired(now) => {
                        self.metrics.approval_expired();
                        "expired".to_string()
                    }
                    Ok(Some(a)) => a.state.as_str().to_string(),
                    Ok(None) => "unknown".to_string(),
                    Err(_) => "unreadable".to_string(),
                };
                Err(format!(
                    "approval `{}` cannot be used (state: {state}; or its lease is not live)",
                    claims.jti
                ))
            }
            Err(e) => {
                tracing::error!(error = %e, "approval store unreadable; refusing the approval token");
                Err(format!("approval store unreadable: {e}"))
            }
        }
    }

    /// The run limits that match `call` and what their counters hold (ADR-0010), and for a
    /// destructive tool the run's usage of it (design section 3.5; only when the engine tracks
    /// usage, [`PolicyEngine::tracks_usage`]), read without charging
    /// anything. Fails closed: an argument a limit cannot count refuses the call with
    /// `limit_arg_invalid`, counters that cannot be read refuse it with `budget_error` (usage
    /// counters too, when a limit matched; with no limit, unreadable usage is the worst case,
    /// [`UNREADABLE_USAGE`], and the policy decides), and a call that would
    /// take any limit counter past its `max` is refused with `budget_exhausted`. The admin dry
    /// run (`POST /admin/policies/evaluate`) uses this too.
    pub fn budget_view(
        &self,
        engine: &PolicyEngine,
        chain: &DelegationChain,
        call: &ToolCall,
    ) -> BudgetView {
        self.budget_view_from(engine, chain, call, CounterSource::Store)
    }

    /// [`budget_view`](Self::budget_view) with the counters read from `source`: the lease store
    /// ([`CounterSource::Store`], what `budget_view` does), or a stated run
    /// ([`CounterSource::Stated`], the admin dry run's `budget` block), which never touches the
    /// store. The matching limits, the limit check and the figures are the same code either
    /// way, so a stated run is refused with `budget_exhausted` exactly when a stored one
    /// holding the same counters would be.
    pub fn budget_view_from(
        &self,
        engine: &PolicyEngine,
        chain: &DelegationChain,
        call: &ToolCall,
        source: CounterSource<'_>,
    ) -> BudgetView {
        let refused = |limited: bool, reason: &str, detail: String| BudgetContext {
            limited,
            refusal: Some(BudgetRefusal {
                reason: reason.to_string(),
                detail,
            }),
            ..BudgetContext::default()
        };
        let mut charges = match charges_for(chain, call) {
            Ok(c) => c,
            Err(e) => {
                return BudgetView {
                    context: refused(true, REASON_LIMIT_ARG_INVALID, e.to_string()),
                    ..BudgetView::default()
                }
            }
        };
        let limited = !charges.is_empty();
        let keeps_usage = match (usage_inputs(engine, call), chain_id_of(chain)) {
            (Some(inputs), Some(chain_id)) => {
                charges.extend(run_usage_charges(&LeaseId::new(chain_id), call, &inputs));
                true
            }
            _ => false,
        };
        if charges.is_empty() {
            return BudgetView::default();
        }
        let read = match source {
            CounterSource::Store => read_counters(self.leases.as_ref(), &charges),
            CounterSource::Stated(stated) => Ok(stated.counters(&charges)),
        };
        let (used, counts) = match read {
            Ok(u) => u,
            Err(e) if !limited => {
                // Only run usage: no limit to enforce, so the policy decides on the worst case.
                tracing::error!(error = %e, "run usage unreadable; deciding on the worst case");
                return BudgetView {
                    charges,
                    usage: Some(UNREADABLE_USAGE),
                    usage_error: Some(format!("run usage unreadable, worst case assumed: {e}")),
                    ..BudgetView::default()
                };
            }
            Err(e) => {
                tracing::error!(error = %e, "budget counters unreadable; denying the call");
                return BudgetView {
                    context: refused(
                        limited,
                        REASON_BUDGET_ERROR,
                        format!("budget counters unreadable: {e}"),
                    ),
                    charges,
                    usage: None,
                    usage_error: None,
                    hit: None,
                    windows: Vec::new(),
                };
            }
        };
        let left = |c: &Charge, u: u64| i64::try_from(c.max.saturating_sub(u)).unwrap_or(i64::MAX);
        let figure = |u: u64| i64::try_from(u.min(MAX_LIMIT)).unwrap_or(i64::MAX);
        let mut context = BudgetContext {
            limited,
            ..BudgetContext::default()
        };
        let mut usage = keeps_usage.then(UsageContext::default);
        let mut hit = None;
        // `distinct`: values new to a limit earlier in this call, per (hop, capability).
        let mut new_values: Vec<((usize, usize), u64)> = Vec::new();
        for ((c, &u), &count) in charges.iter().zip(&used).zip(&counts) {
            if c.usage {
                let usage = usage.get_or_insert_with(UsageContext::default);
                match c.kind {
                    LimitKind::Calls => usage.calls = figure(u),
                    LimitKind::Sum => usage.amount = figure(u),
                    LimitKind::CallsPer | LimitKind::Distinct => usage.destination_seen |= u > 0,
                }
                continue;
            }
            // What the limit's counter holds and what this charge adds to it. For `distinct`,
            // `u` says whether the value was seen; the counter is the limit's count of values.
            let (held, adds) = match c.kind {
                LimitKind::Distinct => distinct_step(&mut new_values, c, u, count),
                _ => (u, c.amount),
            };
            match c.kind {
                LimitKind::Calls => {
                    context.calls_remaining = context.calls_remaining.min(left(c, u))
                }
                LimitKind::Sum => {
                    context.amount_remaining = context.amount_remaining.min(left(c, u))
                }
                LimitKind::CallsPer | LimitKind::Distinct => context.destination_new &= u == 0,
            }
            if hit.is_none() && held.checked_add(adds).is_none_or(|n| n > c.max) {
                hit = Some(LimitHit::of(c, held));
            }
        }
        if let Some(h) = &hit {
            context.refusal = Some(BudgetRefusal {
                reason: REASON_BUDGET_EXHAUSTED.to_string(),
                detail: h.detail(),
            });
        }
        BudgetView {
            charges,
            usage,
            usage_error: None,
            context,
            hit,
            windows: Vec::new(),
        }
    }

    /// Refund the charge of a decision whose record could not be written, so a budget is spent
    /// exactly when an allowed decision that charged it is in the log. A failed refund leaves
    /// the budget spent (fails closed) and is logged.
    fn refund_unrecorded(&self, decision_id: Uuid, now: OffsetDateTime) {
        match self.leases.refund(&decision_id.to_string(), now) {
            Ok(_) => self.metrics.budget_refunded(RefundSource::AuditError),
            Err(e) => {
                tracing::error!(error = %e, decision = %decision_id, "could not refund an unrecorded charge")
            }
        }
    }

    /// Undo a take for a decision that did not go through.
    fn give_back(&self, approval: &Approval, decision_id: Uuid) {
        if let Err(e) = self
            .leases
            .restore_approval(&approval.id, &decision_id.to_string())
        {
            // The approval stays spent: the user approves again. Fails closed.
            tracing::error!(error = %e, approval = %approval.id, "could not give an approval back");
        }
    }

    /// Store a pending approval for a call the policy gated (or find the pending one for the
    /// same call) and record an `approval_request` for a new one. `None`, with a diagnostic,
    /// when either write fails: the call stays gated, with no approval to grant.
    #[allow(clippy::too_many_arguments)]
    fn request_approval(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        jkt: Option<&str>,
        decision_id: Uuid,
        policy_ids: &[String],
        record_labels: &RecordLabels,
        labels: Vec<ApprovalLabel>,
        now: OffsetDateTime,
        diagnostics: &mut Vec<String>,
    ) -> Option<ApprovalTicket> {
        let (chain_id, hop) = (chain_id_of(chain)?, chain.hops.last()?);
        let call_hash = call.call_hash();
        let wanted = Approval {
            id: Uuid::new_v4().to_string(),
            chain_id: LeaseId::new(chain_id),
            lease: hop.lease.clone(),
            call_hash: call_hash.clone(),
            server: call.server.clone(),
            tool: call.tool.clone(),
            arguments: serde_json::to_value(&call.arguments).unwrap_or_default(),
            labels,
            untrusted_args: record_labels.untrusted_args.clone(),
            decision_id: decision_id.to_string(),
            chain: chain.clone(),
            created_at: now,
            // The store lowers this to the lease's expiry; the token's own expiry bounds it too.
            expires_at: (now + self.approval_ttl).min(hop.expires_at),
            state: ApprovalState::Pending,
            approver: None,
            decided_at: None,
            consumed_by: None,
            jkt: jkt.map(str::to_owned),
        };
        let (stored, created) = match self.leases.create_approval(&wanted) {
            Ok(v) => v,
            // SR-92: the run has as many approvals waiting as an operator is asked to follow.
            Err(e @ attenuo_audit::AuditError::TooManyPendingApprovals { .. }) => {
                tracing::warn!(error = %e, "pending approval refused: too many for this run");
                diagnostics.push(DIAG_TOO_MANY_PENDING_APPROVALS.to_string());
                return None;
            }
            Err(e) => {
                tracing::error!(error = %e, "pending approval could not be stored");
                diagnostics.push(format!("pending approval could not be stored: {e}"));
                return None;
            }
        };
        let approval_id = Uuid::parse_str(&stored.id).ok()?;
        if created {
            let mut record = DecisionRecord::new(
                now,
                Decision::Deny,
                REASON_APPROVAL_REQUESTED,
                chain,
                call,
                policy_ids.to_vec(),
            )
            .with_kind(RecordKind::ApprovalRequest)
            .with_labels(record_labels.clone());
            record.decision_id = Some(decision_id);
            let mut info = ApprovalInfo::new(approval_id);
            info.call_hash = Some(call_hash);
            info.expires_at = Some(stored.expires_at);
            record.approval = Some(info);
            if let Err(e) = self.metrics.time_audit_append(|| self.audit.append(record)) {
                // A request that cannot be recorded is not offered for approval.
                tracing::error!(error = %e, "approval_request append failed; dropping the approval");
                self.metrics.audit_append_error();
                let _ = self.leases.remove_approval(&stored.id);
                diagnostics.push(format!("approval request could not be recorded: {e}"));
                return None;
            }
            self.metrics.approval_created();
            if let Some(n) = &self.approval_notifier {
                n.pending(&stored);
            }
        }
        Some(ApprovalTicket {
            approval_id,
            expires_at: stored.expires_at,
        })
    }

    /// The output labels of `chain`'s delegation run (ADR-0009), read from the lease store by
    /// chain id. Fails closed: a store error, or a chain with no hops, is a tainted run with no
    /// known source.
    pub fn run_labels(&self, chain: &DelegationChain) -> RunLabels {
        let Some(chain_id) = chain_id_of(chain) else {
            return RunLabels {
                session: SessionLabels::unknown(),
                record: RecordLabels::default(),
                sources: Vec::new(),
                error: Some("chain has no hops: no run to read labels for".into()),
            };
        };
        match self.leases.labels(&LeaseId::new(chain_id)) {
            Ok(labels) => RunLabels {
                session: SessionLabels::from_sources(labels.iter().map(|l| l.source.clone())),
                record: RecordLabels {
                    tainted_by: labels.iter().map(|l| l.seq).collect(),
                    untrusted_args: Vec::new(),
                },
                sources: labels
                    .iter()
                    .map(|l| ApprovalLabel {
                        source: l.source.clone(),
                        seq: l.seq,
                    })
                    .collect(),
                error: None,
            },
            Err(e) => {
                tracing::error!(error = %e, "run taint state unreadable; treating the run as tainted");
                RunLabels {
                    session: SessionLabels::unknown(),
                    record: RecordLabels::default(),
                    sources: Vec::new(),
                    error: Some(format!(
                        "taint state unreadable, run treated as tainted: {e}"
                    )),
                }
            }
        }
    }

    /// How the catalog labels the results of `call`'s tool (`output`): untrusted unless the
    /// entry says `trusted`.
    pub fn output_label(&self, call: &ToolCall) -> OutputLabel {
        self.policy
            .snapshot()
            .effective_attrs(&call.server, &call.tool)
            .map(|a| a.output)
            .unwrap_or_default()
    }

    /// Which arguments of `call` carry a verbatim span of an untrusted result of the run
    /// (ADR-0009 phase 2, design section 3.4). Only on a tainted run (`session.tainted`), and
    /// only for a call to a destructive tool unless some loaded policy reads
    /// `context.args_contain_untrusted` or `context.untrusted_args`
    /// ([`PolicyEngine::reads_arg_taint`]), in which case every call is matched (a fetch of a
    /// URL copied from a result, for example); otherwise nothing matches. Arguments pinned by an
    /// `equals` or `one_of` constraint of a hop that permits the call are skipped (the pin
    /// exemption). Every other argument is fingerprinted as results are
    /// ([`attenuo_core::fingerprint::fingerprints`]) and looked up in the run's span index.
    ///
    /// A fingerprint that several arguments carry is looked up once and reported for each of
    /// them. The store returns at most [`MAX_SEQS_PER_PROBE`] results per fingerprint, lowest
    /// `seq` first.
    ///
    /// Fails closed: when the index cannot be read, or the arguments carry more than
    /// [`MAX_ARG_PROBES`] fingerprints in all (no lookup is then made), every unpinned
    /// argument that has a fingerprint counts as untrusted, with kind `unreadable` and no
    /// `seq`, and the diagnostics say why.
    ///
    /// [`MAX_SEQS_PER_PROBE`]: attenuo_audit::MAX_SEQS_PER_PROBE
    pub fn arg_taint(
        &self,
        engine: &PolicyEngine,
        chain: &DelegationChain,
        call: &ToolCall,
        session: &SessionLabels,
    ) -> ArgTaint {
        if !session.tainted || !matches_arguments(engine, call) {
            return ArgTaint::default();
        }
        let Some(chain_id) = chain_id_of(chain) else {
            return ArgTaint::default();
        };
        let pinned = pinned_arguments(chain, call);
        let ArgProbes {
            probes,
            owners,
            fingerprinted,
            pairs,
        } = arg_probes(call, &pinned);
        if fingerprinted.is_empty() {
            return ArgTaint::default();
        }
        let unreadable = |args: &[&str]| -> BTreeSet<UntrustedArg> {
            args.iter()
                .map(|arg| UntrustedArg {
                    arg: arg.to_string(),
                    seq: None,
                    kind: UntrustedKind::Unreadable,
                })
                .collect()
        };
        let (found, error) = if pairs > MAX_ARG_PROBES {
            // Fail closed without a lookup, as for an unreadable index.
            tracing::warn!(
                fingerprints = pairs,
                bound = MAX_ARG_PROBES,
                "too many argument fingerprints; treating the arguments as untrusted"
            );
            (
                unreadable(&fingerprinted),
                Some(format!(
                    "arguments carry more than {MAX_ARG_PROBES} fingerprints; unpinned \
                     arguments treated as untrusted"
                )),
            )
        } else {
            match self.leases.find_spans(&LeaseId::new(chain_id), &probes) {
                Ok(hits) => (
                    hits.iter()
                        .flat_map(|h| {
                            let kind = probes[h.probe].kind.into();
                            owners[h.probe].iter().map(move |arg| UntrustedArg {
                                arg: arg.to_string(),
                                seq: Some(h.seq),
                                kind,
                            })
                        })
                        .collect::<BTreeSet<_>>(),
                    None,
                ),
                Err(e) => {
                    tracing::error!(error = %e, "span index unreadable; treating the arguments as untrusted");
                    (
                        unreadable(&fingerprinted),
                        Some(format!(
                            "span index unreadable, unpinned arguments treated as untrusted: {e}"
                        )),
                    )
                }
            }
        };
        ArgTaint {
            context: ArgLabels::from_args(found.iter().map(|u| u.arg.clone())),
            record: found.into_iter().take(MAX_UNTRUSTED_ARG_ENTRIES).collect(),
            error,
        }
    }

    /// Record the upstream's answer to an allowed mediated call (ADR-0009): append a
    /// `tool_result` record (digest and size from [`result_digest`], the fingerprint count, no
    /// content) and, unless the catalog marks the tool's output trusted ([`output_label`]),
    /// add a label `{source, decision_id, seq, at}` to the run's taint state and `spans` (the
    /// result's fingerprints) to the run's span index under the record's `seq`. A trusted
    /// result's `spans` are dropped and its record says 0. Returns the record's `seq`.
    ///
    /// [`output_label`]: Self::output_label
    /// [`result_digest`]: super::result_digest
    ///
    /// # Errors
    ///
    /// [`REASON_LABEL_ERROR`] when the `tool_result` append fails, when the chain has no first hop
    /// to name the run, or, for an untrusted result, when the run label or the span index cannot be
    /// written; the caller must then withhold the result.
    #[allow(clippy::too_many_arguments)]
    pub fn record_result(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        decision_id: Uuid,
        digest: (String, u64),
        spans: &[Fingerprint],
        is_error: bool,
        now: OffsetDateTime,
    ) -> Result<u64, String> {
        let label = self.output_label(call);
        let spans = if label == OutputLabel::Untrusted {
            spans
        } else {
            &[]
        };
        let (digest, size) = digest;
        let info = ResultInfo {
            digest,
            size,
            error: is_error,
            label,
            fingerprints: spans.len() as u64,
        };
        let record = DecisionRecord::tool_result(now, chain, call, decision_id, info);
        let entry = self
            .metrics
            .time_audit_append(|| self.audit.append(record))
            .map_err(|e| {
                tracing::error!(error = %e, "tool_result append failed; withholding the result");
                self.metrics.audit_append_error();
                REASON_LABEL_ERROR.to_string()
            })?;
        if label == OutputLabel::Untrusted {
            let chain_id = chain_id_of(chain).ok_or_else(|| REASON_LABEL_ERROR.to_string())?;
            let run_label = RunLabel {
                source: format!("{}/{}", call.server, call.tool),
                decision_id: decision_id.to_string(),
                seq: entry.seq,
                at: now,
            };
            let chain_id = LeaseId::new(chain_id);
            self.leases.add_label(&chain_id, &run_label).map_err(|e| {
                tracing::error!(error = %e, "run label write failed; withholding the result");
                REASON_LABEL_ERROR.to_string()
            })?;
            self.leases
                .add_spans(&chain_id, entry.seq, spans)
                .map_err(|e| {
                    tracing::error!(error = %e, "span index write failed; withholding the result");
                    REASON_LABEL_ERROR.to_string()
                })?;
        }
        self.metrics.result_recorded(label);
        // The proxy's `attenuo.record_result` span, carried onto this thread.
        let span = tracing::Span::current();
        span.record("attenuo.result.label", label.as_str());
        span.record("attenuo.audit.seq", entry.seq);
        tracing::debug!(
            server = ?call.server,
            tool = ?call.tool,
            label = label.as_str(),
            seq = entry.seq,
            "result recorded"
        );
        Ok(entry.seq)
    }

    /// Append a `deny` record for a request refused before any decision (the proxy's
    /// `session_mismatch`, `invalid_name` and `tool_not_listed`, or a lease refusal of a
    /// request that has no per-call decision, such as `initialize` on a revoked lease, a
    /// response stream the proxy ended on revocation or expiry, tool `stream.end`, or a
    /// refused token exchange whose subject token verified, tool `token.exchange`, or a
    /// refused lease renewal whose token verified, tool `lease.renew`) and count it in
    /// `decisions_total{decision="deny",reason}`, so every decision record in the log is
    /// counted there. Returns the record id, which is not in the log if the append failed;
    /// [`Pipeline::record_rejection_checked`] says which.
    ///
    /// `reason` comes from a fixed set of codes (the proxy's constants, the lease reasons,
    /// `token_expired`,
    /// [`crate::routes::token::EXCHANGE_REFUSAL_REASONS`] and
    /// [`crate::routes::renew::RENEW_REFUSAL_REASONS`]), so the metric's label set stays
    /// small.
    pub fn record_rejection(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> Uuid {
        self.append_rejection(chain, call, reason, now).0
    }

    /// [`Pipeline::record_rejection`], returning the record id only if the append succeeded
    /// (`None` when it failed and the record is not in the log). The proxy opens a record
    /// window only on a written record (SR-81).
    pub fn record_rejection_checked(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> Option<Uuid> {
        let (id, written) = self.append_rejection(chain, call, reason, now);
        written.then_some(id)
    }

    /// Append the rejection record; its id and whether the append succeeded.
    fn append_rejection(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> (Uuid, bool) {
        self.metrics.decision("deny", reason);
        let record = DecisionRecord::new(now, Decision::Deny, reason, chain, call, Vec::new());
        let id = record.id;
        let written = match self.metrics.time_audit_append(|| self.audit.append(record)) {
            // Caller-controlled strings are Debug-formatted so they cannot forge log lines
            // (SR-18).
            Ok(entry) => {
                tracing::info!(
                    reason = ?reason,
                    subject = ?self.subject_log.show(&chain.originating_user.subject),
                    server = ?call.server,
                    tool = ?call.tool,
                    seq = entry.seq,
                    "request rejected"
                );
                // The proxy's `attenuo.stream_end` span, carried onto this thread; a no-op
                // in any span that does not declare the field.
                tracing::Span::current().record("attenuo.audit.seq", entry.seq);
                true
            }
            Err(e) => {
                tracing::error!(error = %e, reason = ?reason, "audit append failed for a rejection");
                false
            }
        };
        (id, written)
    }

    /// Record that upstream `server` opened the MCP session whose digest is `session` for a
    /// caller of `chain` (`RunState::record_session` with the chain id), so
    /// `POST /admin/leases/revoke` can find the chain by session. Best effort: a failure is
    /// logged and the session stays usable; revoking by chain id still works.
    pub fn record_session(
        &self,
        chain: &DelegationChain,
        server: &str,
        session: &str,
        now: OffsetDateTime,
    ) {
        let Some(root) = chain.hops.first().map(|h| &h.lease) else {
            return;
        };
        let tag = session.get(..12).unwrap_or(session);
        match self.leases.record_session(session, server, root, now) {
            // Server is caller-controlled (the URL path): Debug-format it (SR-18).
            Ok(true) => {
                tracing::debug!(session = %tag, server = ?server, chain_id = ?root.0, "session bound to its chain")
            }
            Ok(false) => {
                tracing::debug!(session = %tag, server = ?server, "session binding already recorded")
            }
            Err(e) => tracing::error!(
                error = %e,
                session = %tag,
                server = ?server,
                "session binding not recorded; this session cannot be revoked by id"
            ),
        }
    }

    /// `Ok` when every lease in the chain is live.
    ///
    /// # Errors
    ///
    /// [`REASON_LEASE_ERROR`] with the store's message when the lease store cannot be read, and
    /// otherwise, in this order of precedence, [`REASON_LEASE_REVOKED`], [`REASON_LEASE_EXPIRED`]
    /// or [`REASON_LEASE_UNKNOWN`] with the ids of the leases concerned.
    pub fn check_leases(
        &self,
        chain: &DelegationChain,
        now: OffsetDateTime,
    ) -> Result<(), (&'static str, Vec<String>)> {
        let status = self
            .leases
            .check_all(&chain.leases(), now)
            .map_err(|e| (REASON_LEASE_ERROR, vec![e.to_string()]))?;
        if status.active {
            return Ok(());
        }
        let ids = |v: &[attenuo_core::LeaseId]| {
            v.iter().map(|l| l.0.as_str()).collect::<Vec<_>>().join(",")
        };
        if !status.revoked.is_empty() {
            Err((
                REASON_LEASE_REVOKED,
                vec![format!("revoked leases: {}", ids(&status.revoked))],
            ))
        } else if !status.expired.is_empty() {
            Err((
                REASON_LEASE_EXPIRED,
                vec![format!("expired leases: {}", ids(&status.expired))],
            ))
        } else {
            Err((
                REASON_LEASE_UNKNOWN,
                vec![format!("unknown leases: {}", ids(&status.unknown))],
            ))
        }
    }
}

/// Run a blocking pipeline step on tokio's blocking pool, so lease lookups and the audit append
/// (SQLite) never occupy an async worker. Appends from concurrent callers serialize on the
/// audit store's lock, so the hash chain stays linear.
/// For a tool that keeps run usage (one the catalog marks destructive, design section 3.5, or
/// gives an `outbound` input, read-side exfiltration design option d): the inputs its catalog
/// entry names as `amount`, `destination` and `outbound`. `None` for any other tool, and for
/// every tool when `engine` does not track usage ([`PolicyEngine::tracks_usage`]: no loaded
/// policy reads `context.usage`, the catalog names no `amount` or `destination`, and
/// `[policy] track_usage` is `"auto"`), so an allowed call then pays no usage write and its
/// record carries no `usage`. A tool the engine knows nothing about counts as destructive with
/// neither input, as [`matches_arguments`] does.
fn usage_inputs(engine: &PolicyEngine, call: &ToolCall) -> Option<UsageInputs> {
    if !engine.tracks_usage() {
        return None;
    }
    match engine.effective_attrs(&call.server, &call.tool) {
        None => Some(UsageInputs::default()),
        Some(a) if a.is_destructive() || a.has_outbound() => Some(UsageInputs {
            amount: a.amount,
            destination: a.destination,
            outbound: a.outbound,
        }),
        Some(_) => None,
    }
}

/// Whether `call` keeps a per-user window: it keeps run usage and some policy of `engine`
/// reads a window kind.
fn keeps_user_window(engine: &PolicyEngine, call: &ToolCall) -> bool {
    usage_inputs(engine, call).is_some() && !engine.user_window_kinds().is_empty()
}

/// Whether [`Pipeline::arg_taint`] matches `call`'s arguments on a tainted run: when some
/// policy of `engine` reads argument taint ([`PolicyEngine::reads_arg_taint`]), or the catalog
/// marks the tool destructive (so the decision record says which arguments were copied even
/// when no policy asks). A tool the engine knows nothing about (its call is denied anyway)
/// counts as destructive.
fn matches_arguments(engine: &PolicyEngine, call: &ToolCall) -> bool {
    engine.reads_arg_taint()
        || engine
            .effective_attrs(&call.server, &call.tool)
            .is_none_or(|a| a.is_destructive())
}

pub(super) async fn on_blocking_pool<R: Send + 'static>(
    pipeline: &Arc<Pipeline>,
    f: impl FnOnce(&Pipeline) -> R + Send + 'static,
) -> R {
    let pipeline = Arc::clone(pipeline);
    // Carry the caller's span and trace context, so the decision's spans and log lines are
    // inside the request that asked for it (otel-export design, section 3.2).
    let carry = crate::telemetry::Carry::capture();
    match tokio::task::spawn_blocking(move || carry.run(|| f(&pipeline))).await {
        Ok(r) => r,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

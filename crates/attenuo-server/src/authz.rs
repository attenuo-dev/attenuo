//! The decision pipeline and the proxy's real [`Authorizer`].
//!
//! [`Pipeline::decide`] is the one place a tool call is decided. Both the MCP proxy (through
//! [`ServerAuthorizer`]) and the AuthZEN endpoint call it, so they cannot disagree:
//!
//! 1. **Leases.** Every lease in the chain must be known, unrevoked and unexpired
//!    (`LeaseStore::check_all`). Otherwise: deny with `lease_revoked`, `lease_expired` or
//!    `lease_unknown` (checked in that order), or `lease_error` if the store fails.
//! 2. **Labels and budgets.** The taint state of the delegation run (`LeaseStore::labels`
//!    for the chain id, ADR-0009); a store that cannot be read counts as tainted. And the
//!    run limits (ADR-0010): every limited capability, in every hop, that matches the call
//!    ([`attenuo_core::limits::charges_for`]) and what its counters hold
//!    (`LeaseStore::budget_used`), as `context.budget` and as the limit check of step 4.
//!    Unreadable counters deny a limited call with `budget_error`; an argument a limit
//!    cannot count denies it with `limit_arg_invalid`.
//! 3. **Approval.** A granted, unexpired approval for this call (same run, same calling hop's
//!    lease, same call hash) is taken from the lease store and marked consumed
//!    (`LeaseStore::take_approval`); Cedar then sees `context.approval.present` and `by`.
//!    When the call presents a signed approval token ([`CallContext::approval_token`]), that
//!    token decides instead: its signature, `typ` and `exp` must verify under the issuer key,
//!    its `chain_id`, `lease`, `ch` and `cnf.jkt` must be the call's run, the calling hop's
//!    lease, the call hash and the hop's key binding, and the approval it names (`jti`) is
//!    taken by id (`LeaseStore::take_approval_by_id`). A token that fails any of this, or
//!    names an approval that is consumed, declined, expired or bound to a dead lease, denies
//!    the call with `approval_invalid` before the policy runs.
//! 4. **Policy.** `PolicyEngine::authorize_labelled`: the capability stage (including the
//!    limit check: a call that would take any matching counter past its `max` is denied with
//!    `budget_exhausted`, before Cedar), then Cedar, with the run's labels as
//!    `context.session` and the budget figures as `context.budget`. A deny through
//!    `@obligation("approval")` forbids only is `approval_required`.
//! 5. **Charge.** For an allowed call that matched limits, every counter is re-checked and
//!    charged in one store transaction (`LeaseStore::charge`), so concurrent calls cannot
//!    overspend: if one spent first, the decision becomes `budget_exhausted`; if the store
//!    fails, `budget_error`. Denied calls are never charged.
//! 6. **Audit.** A [`DecisionRecord`] is appended to the hash-chained log, and its id is the
//!    decision id returned to the caller. If the append fails the call is denied with
//!    `audit_error`: an action that cannot be recorded does not happen. An approval taken in
//!    step 3 is given back when the call is not allowed or its record cannot be written, so
//!    it is spent exactly when an allowed decision that names it is in the log. A charge made
//!    in step 5 is refunded the same way when the append fails (`LeaseStore::refund`).
//! 7. **Pending approval.** For `approval_required`, a pending approval is stored (or the
//!    pending one for the same call reused) and an `approval_request` record appended; the
//!    caller gets its id and expiry ([`PipelineDecision::approval`]).
//!
//! After an allowed mediated call returns, [`Pipeline::record_result`] appends a
//! `tool_result` record and, for an untrusted result, labels the run; if either fails, the
//! proxy withholds the result (`label_error`).
//!
//! The chain is assumed to be verified already (token signature, structure, expiry).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use attenuo_audit::{
    Approval, ApprovalLabel, ApprovalState, AuditSink, ChargeOutcome, LeaseStore, RunLabel,
};
use attenuo_core::limits::{
    charges_for, REASON_BUDGET_ERROR, REASON_BUDGET_EXHAUSTED, REASON_LIMIT_ARG_INVALID,
};
use attenuo_core::{
    chain_id_of, ApprovalInfo, BudgetCharge, Charge, Decision, DecisionRecord, DelegationChain,
    LeaseId, LimitKind, OutputLabel, RecordBudget, RecordKind, RecordLabels, ResultInfo, ToolCall,
    REASON_APPROVAL_INVALID, REASON_APPROVAL_REQUESTED,
};
use attenuo_policy::{
    ApprovalContext, BudgetContext, BudgetRefusal, CallLabels, PolicyEngine, SessionLabels,
};
use attenuo_proxy::{
    ApprovalTicket, AuthDecision, AuthError, Authenticated, Authorizer, CallContext, RequestAuth,
    Stage,
};
use attenuo_token::Verifier;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::metrics::Metrics;

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

/// What [`Pipeline::run_labels`] found for a call's delegation run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunLabels {
    /// What Cedar sees as `context.session`.
    pub session: SessionLabels,
    /// What the decision record carries: the `seq` of the first untrusted result of each
    /// source.
    pub record: RecordLabels,
    /// The same labels with their sources, for a pending approval.
    pub sources: Vec<ApprovalLabel>,
    /// Set when the taint state could not be read (the run then counts as tainted).
    pub error: Option<String>,
}

/// What [`Pipeline::budget_view`] found for a call: the run limits that match it (ADR-0010).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetView {
    /// Every counter the call would be charged against. Empty when no limit matches.
    pub charges: Vec<Charge>,
    /// What Cedar sees as `context.budget`, with the refusal of the limit check, if any.
    pub context: BudgetContext,
    /// For `budget_exhausted`: the limit the call would take past its `max`.
    pub hit: Option<LimitHit>,
}

/// A run limit a call would exceed: the `limit` member of a `budget_exhausted` denial
/// (JSON-RPC `-32003` `data.limit`, AuthZEN `context.limit`). The hop is named by its
/// position, not its lease id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitHit {
    pub hop: usize,
    pub kind: LimitKind,
    pub arg: Option<String>,
    pub max: u64,
    /// What the counter held before the call.
    pub used: u64,
}

impl LimitHit {
    fn of(charge: &Charge, used: u64) -> Self {
        Self {
            hop: charge.hop,
            kind: charge.kind,
            arg: charge.arg.clone(),
            max: charge.max,
            used,
        }
    }

    /// `{hop, kind, arg, max, used}`, `arg` only for `sum` and `calls_per`.
    pub fn to_json(&self) -> Value {
        let mut v = serde_json::json!({
            "hop": self.hop,
            "kind": self.kind.as_str(),
            "max": self.max,
            "used": self.used,
        });
        if let Some(arg) = &self.arg {
            v["arg"] = arg.clone().into();
        }
        v
    }

    fn detail(&self) -> String {
        format!(
            "limit `{}`{} of hop {} would be exceeded: max {}, used {}",
            self.kind,
            self.arg
                .as_ref()
                .map(|a| format!(" on `{a}`"))
                .unwrap_or_default(),
            self.hop,
            self.max,
            self.used
        )
    }
}

/// `context.budget` as JSON: `{limited, calls_remaining, amount_remaining, destination_new}`.
/// What the AuthZEN response and the admin dry run report.
pub fn budget_json(b: &BudgetContext) -> Value {
    serde_json::json!({
        "limited": b.limited,
        "calls_remaining": b.calls_remaining,
        "amount_remaining": b.amount_remaining,
        "destination_new": b.destination_new,
    })
}

/// SHA-256 (hex) and length of the RFC 8785 canonical JSON of an upstream result: what a
/// `tool_result` record stores instead of the result. `Err` for a value with no canonical
/// form (nothing parsed from JSON has one).
pub fn result_digest(result: &Value) -> Result<(String, u64), String> {
    let bytes = attenuo_core::jcs::to_vec(result).map_err(|e| e.to_string())?;
    Ok((
        attenuo_core::digest::sha256_bytes(&bytes),
        bytes.len() as u64,
    ))
}

/// The result of running the pipeline once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineDecision {
    pub decision: Decision,
    pub reason: String,
    /// Id of the audit record. When the append failed this id is not in the log.
    pub decision_id: Uuid,
    /// Audit sequence number of the record, if it was written.
    pub audit_seq: Option<u64>,
    pub policy_ids: Vec<String>,
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
}

impl PipelineDecision {
    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// Lease check, policy evaluation and audit, in that order.
pub struct Pipeline {
    policy: Arc<RwLock<PolicyEngine>>,
    leases: Arc<dyn LeaseStore>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<Metrics>,
    /// `[approvals] ttl_seconds`.
    approval_ttl: time::Duration,
    /// Checks presented approval tokens: the issuer's public keys, `iss` and `aud`. `None`
    /// refuses every presented token (`approval_invalid`).
    approval_verifier: Option<Verifier>,
}

impl Pipeline {
    pub fn new(
        policy: Arc<RwLock<PolicyEngine>>,
        leases: Arc<dyn LeaseStore>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            policy,
            leases,
            audit,
            metrics: Metrics::new(),
            approval_ttl: time::Duration::seconds(
                crate::config::DEFAULT_APPROVAL_TTL_SECONDS as i64,
            ),
            approval_verifier: None,
        }
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
    pub fn policy(&self) -> &Arc<RwLock<PolicyEngine>> {
        &self.policy
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
        let started = Instant::now();
        let out = self.decide_inner(chain, call, ctx, now);
        self.metrics.observe_authorize(started.elapsed());
        self.metrics
            .decision(if out.is_allow() { "allow" } else { "deny" }, &out.reason);
        out
    }

    /// The policy stage alone: `PolicyEngine::authorize_labelled` (the capability stage, the
    /// catalog, then Cedar) on the shared engine, with `labels` as the run's output labels. No
    /// lease check, no audit record, no metrics.
    ///
    /// [`decide`](Self::decide) runs this after the lease check and the label read, and the
    /// admin dry run (`POST /admin/policies/evaluate`) runs it on its own, so the two cannot
    /// disagree about what the policy says. A poisoned engine lock denies with `policy_error`.
    pub fn evaluate_policy(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        labels: &CallLabels,
        now: OffsetDateTime,
    ) -> attenuo_policy::Outcome {
        match self.policy.read() {
            Ok(engine) => engine.authorize_labelled(chain, call, labels, now),
            Err(_) => attenuo_policy::Outcome {
                decision: Decision::Deny,
                reason: attenuo_policy::REASON_POLICY_ERROR.to_string(),
                policy_ids: Vec::new(),
                diagnostics: vec!["policy engine lock poisoned".to_string()],
            },
        }
    }

    fn decide_inner(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        ctx: &CallContext,
        now: OffsetDateTime,
    ) -> PipelineDecision {
        // Stage timings: one `Instant::now()` per boundary (see `Stage`).
        let t0 = Instant::now();
        let leases = self.check_leases(chain, now);
        let t1 = Instant::now();
        let mut policy_time = None;
        let mut record_labels = RecordLabels::default();
        let mut label_sources = Vec::new();
        // The record id is fixed first: a taken approval names the decision that consumed it.
        let decision_id = Uuid::new_v4();
        let mut taken: Option<Approval> = None;
        let mut budget = BudgetView::default();
        let (mut decision, mut reason, mut policy_ids, mut diagnostics) = match leases {
            Err((reason, detail)) => (Decision::Deny, reason.to_string(), Vec::new(), detail),
            Ok(()) => {
                let run = self.run_labels(chain);
                budget = self.budget_view(chain, call);
                let mut diagnostics = Vec::new();
                record_labels = run.record;
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
                            approval: taken
                                .as_ref()
                                .and_then(|a| a.approver.as_ref())
                                .map(|a| ApprovalContext::by(a.method.by()))
                                .unwrap_or_default(),
                            budget: budget.context.clone(),
                        };
                        let o = self.evaluate_policy(chain, call, &labels, now);
                        policy_time = Some(t1.elapsed());
                        diagnostics.extend(o.diagnostics);
                        diagnostics.extend(run.error);
                        (o.decision, o.reason, o.policy_ids, diagnostics)
                    }
                }
            }
        };
        let mut limit = (reason == REASON_BUDGET_EXHAUSTED)
            .then(|| budget.hit.clone())
            .flatten();
        // Charge an allowed call against every matching limit, re-checking in the store's
        // transaction: a concurrent call may have spent the budget since it was read.
        let mut charged: Option<RecordBudget> = None;
        if decision.is_allow() && !budget.charges.is_empty() {
            match self
                .leases
                .charge(&decision_id.to_string(), &budget.charges, now)
            {
                Ok(ChargeOutcome::Charged { used_after }) => {
                    charged = Some(RecordBudget {
                        charged: budget
                            .charges
                            .iter()
                            .zip(used_after)
                            .map(|(c, used_after)| BudgetCharge {
                                hop: c.hop,
                                cap: c.cap,
                                kind: c.kind,
                                arg: c.arg.clone(),
                                used_after,
                                max: c.max,
                            })
                            .collect(),
                    });
                }
                Ok(ChargeOutcome::Exhausted { index, used }) => {
                    let hit = LimitHit::of(&budget.charges[index], used);
                    diagnostics.push(hit.detail());
                    limit = Some(hit);
                    (decision, reason, policy_ids) = (
                        Decision::Deny,
                        REASON_BUDGET_EXHAUSTED.to_string(),
                        Vec::new(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "budget counters could not be charged; denying");
                    diagnostics.push(format!("budget counters could not be charged: {e}"));
                    (decision, reason, policy_ids) =
                        (Decision::Deny, REASON_BUDGET_ERROR.to_string(), Vec::new());
                }
            }
        }
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
        // The record moves into the log; the entry hands it back, so it is never cloned.
        let t2 = Instant::now();
        let appended = self.audit.append(record);
        let append_time = t2.elapsed();
        self.metrics.observe_audit_append(append_time);
        let lease_time = t1 - t0;
        self.metrics.observe_stage(Stage::LeaseCheck, lease_time);
        if let Some(d) = policy_time {
            self.metrics.observe_stage(Stage::Policy, d);
        }
        self.metrics.observe_stage(Stage::AuditAppend, append_time);
        tracing::debug!(
            lease_check_us = lease_time.as_micros() as u64,
            policy_us = policy_time.map(|d| d.as_micros() as u64),
            audit_append_us = append_time.as_micros() as u64,
            "decision stages"
        );
        match appended {
            Ok(entry) => {
                let record = entry.record;
                // Subject, agent, server and tool come from the caller: Debug-format them so
                // a newline cannot forge a log line (SR-18).
                tracing::info!(
                    decision = ?record.decision,
                    reason = ?record.reason,
                    subject = ?record.originating_subject,
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
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "audit append failed; denying");
                self.metrics.audit_append_error();
                if let Some(a) = &taken {
                    self.give_back(a, decision_id);
                }
                if charged.is_some() {
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
                    Ok(Some(a)) if a.is_expired(now) => "expired".to_string(),
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

    /// The run limits that match `call` and what their counters hold (ADR-0010), read without
    /// charging anything. Fails closed: an argument a limit cannot count refuses the call with
    /// `limit_arg_invalid`, counters that cannot be read refuse it with `budget_error`, and a
    /// call that would take any counter past its `max` is refused with `budget_exhausted`.
    /// The admin dry run (`POST /admin/policies/evaluate`) uses this too.
    pub fn budget_view(&self, chain: &DelegationChain, call: &ToolCall) -> BudgetView {
        let refused = |reason: &str, detail: String| BudgetContext {
            limited: true,
            refusal: Some(BudgetRefusal {
                reason: reason.to_string(),
                detail,
            }),
            ..BudgetContext::default()
        };
        let charges = match charges_for(chain, call) {
            Ok(c) => c,
            Err(e) => {
                return BudgetView {
                    context: refused(REASON_LIMIT_ARG_INVALID, e.to_string()),
                    ..BudgetView::default()
                }
            }
        };
        if charges.is_empty() {
            return BudgetView::default();
        }
        let used = match self.leases.budget_used(&charges) {
            Ok(u) => u,
            Err(e) => {
                tracing::error!(error = %e, "budget counters unreadable; denying the limited call");
                return BudgetView {
                    context: refused(
                        REASON_BUDGET_ERROR,
                        format!("budget counters unreadable: {e}"),
                    ),
                    charges,
                    hit: None,
                };
            }
        };
        let left = |c: &Charge, u: u64| i64::try_from(c.max.saturating_sub(u)).unwrap_or(i64::MAX);
        let mut context = BudgetContext {
            limited: true,
            ..BudgetContext::default()
        };
        let mut hit = None;
        for (c, &u) in charges.iter().zip(&used) {
            match c.kind {
                LimitKind::Calls => {
                    context.calls_remaining = context.calls_remaining.min(left(c, u))
                }
                LimitKind::Sum => {
                    context.amount_remaining = context.amount_remaining.min(left(c, u))
                }
                LimitKind::CallsPer => context.destination_new &= u == 0,
            }
            if hit.is_none() && u.checked_add(c.amount).is_none_or(|n| n > c.max) {
                hit = Some(LimitHit::of(c, u));
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
            context,
            hit,
        }
    }

    /// Refund the charge of a decision whose record could not be written, so a budget is spent
    /// exactly when an allowed decision that charged it is in the log. A failed refund leaves
    /// the budget spent (fails closed) and is logged.
    fn refund_unrecorded(&self, decision_id: Uuid, now: OffsetDateTime) {
        if let Err(e) = self.leases.refund(&decision_id.to_string(), now) {
            tracing::error!(error = %e, decision = %decision_id, "could not refund an unrecorded charge");
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

    /// Record the upstream's answer to an allowed mediated call (ADR-0009): append a
    /// `tool_result` record (digest and size from [`result_digest`], no content) and, unless
    /// the catalog marks the tool's output trusted, add a label `{source, decision_id, seq,
    /// at}` to the run's taint state. Returns the record's `seq`. `Err` (reason
    /// `label_error`) when either write fails; the caller must then withhold the result.
    pub fn record_result(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        decision_id: Uuid,
        digest: (String, u64),
        is_error: bool,
        now: OffsetDateTime,
    ) -> Result<u64, String> {
        // A poisoned engine lock cannot say the tool is trusted: label the result untrusted.
        let label = self
            .policy
            .read()
            .ok()
            .and_then(|e| e.effective_attrs(&call.server, &call.tool))
            .map(|a| a.output)
            .unwrap_or_default();
        let (digest, size) = digest;
        let info = ResultInfo {
            digest,
            size,
            error: is_error,
            label,
            fingerprints: 0,
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
            self.leases
                .add_label(&LeaseId::new(chain_id), &run_label)
                .map_err(|e| {
                    tracing::error!(error = %e, "run label write failed; withholding the result");
                    REASON_LABEL_ERROR.to_string()
                })?;
        }
        tracing::debug!(
            server = ?call.server,
            tool = ?call.tool,
            label = label.as_str(),
            seq = entry.seq,
            "result recorded"
        );
        Ok(entry.seq)
    }

    /// Append a `deny` record for a request refused before any decision (for example the
    /// proxy's `session_mismatch`). Returns the record id, which is not in the log if the
    /// append failed.
    pub fn record_rejection(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> Uuid {
        let record = DecisionRecord::new(now, Decision::Deny, reason, chain, call, Vec::new());
        let id = record.id;
        match self.metrics.time_audit_append(|| self.audit.append(record)) {
            // Caller-controlled strings are Debug-formatted so they cannot forge log lines
            // (SR-18).
            Ok(entry) => tracing::info!(
                reason = ?reason,
                subject = ?chain.originating_user.subject,
                server = ?call.server,
                tool = ?call.tool,
                seq = entry.seq,
                "request rejected"
            ),
            Err(e) => {
                tracing::error!(error = %e, reason = ?reason, "audit append failed for a rejection")
            }
        }
        id
    }

    /// `Ok` when every lease in the chain is live; otherwise the reason code and details.
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
async fn on_blocking_pool<R: Send + 'static>(
    pipeline: &Arc<Pipeline>,
    f: impl FnOnce(&Pipeline) -> R + Send + 'static,
) -> R {
    let pipeline = Arc::clone(pipeline);
    match tokio::task::spawn_blocking(move || f(&pipeline)).await {
        Ok(r) => r,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// The proxy's authorizer: token verification, DPoP ([`crate::dpop`]) and
/// [`Pipeline::decide`].
pub struct ServerAuthorizer {
    verifier: Verifier,
    pipeline: Arc<Pipeline>,
    verified: VerifiedTokens,
    dpop: Option<Arc<crate::dpop::Dpop>>,
}

impl ServerAuthorizer {
    pub fn new(verifier: Verifier, pipeline: Arc<Pipeline>) -> Self {
        Self {
            verifier,
            pipeline,
            verified: VerifiedTokens::new(VERIFIED_TOKENS_CAPACITY),
            dpop: None,
        }
    }

    /// Check DPoP proofs with these settings and replay cache (the server's own). Without
    /// this, a bound token is always refused (`dpop_required`): the proof cannot be checked.
    pub fn with_dpop(mut self, dpop: Arc<crate::dpop::Dpop>) -> Self {
        self.dpop = Some(dpop);
        self
    }

    fn verify(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<attenuo_token::VerifiedToken, AuthError> {
        let started = Instant::now();
        let out = self.verify_inner(token, now);
        let elapsed = started.elapsed();
        let (stage, hit) = match &out {
            Ok((_, true)) => (Stage::TokenVerifyHit, true),
            _ => (Stage::TokenVerifyMiss, false),
        };
        self.pipeline.metrics().observe_stage(stage, elapsed);
        tracing::debug!(
            cache_hit = hit,
            token_verify_us = elapsed.as_micros() as u64,
            "token verified"
        );
        out.map(|(v, _)| v)
    }

    /// [`ServerAuthorizer::verify`], and whether the cache answered.
    fn verify_inner(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<(attenuo_token::VerifiedToken, bool), AuthError> {
        let key = VerifiedTokens::key(token);
        if let Some(v) = self.verified.get(&key, now, self.verifier.max_depth()) {
            return Ok((v, true));
        }
        let v = self.verifier.verify(token, now).map_err(|e| {
            if crate::error::is_expiry(&e) {
                AuthError::TokenExpired
            } else {
                AuthError::InvalidToken(e.to_string())
            }
        })?;
        // The cache is bounded by count; a size bound per entry makes it bounded in bytes
        // (SR-46). Larger tokens are verified on every call.
        if token.len() <= VERIFIED_TOKEN_MAX_BYTES {
            self.verified.insert(key, &v, now);
        }
        Ok((v, false))
    }
}

/// Tokens kept by the verified-token cache (`VerifiedTokens`).
pub const VERIFIED_TOKENS_CAPACITY: usize = 4096;

/// Largest token the verified-token cache (`VerifiedTokens`) keeps, in bytes. A token of a few hops with ordinary
/// capabilities is 1 to 4 KiB; a child can carry an arbitrarily long constraint list (a
/// narrowing of its parent), which would make the cache's 4096 entries hundreds of MiB (SR-46).
pub const VERIFIED_TOKEN_MAX_BYTES: usize = 16 * 1024;

/// Chains of tokens that already passed [`Verifier::verify`], keyed by the SHA-256 of the
/// exact token text.
///
/// An agent sends the same bearer token on every call, and verifying it (two Ed25519
/// signatures, JSON decoding, structural checks) costs about 100 us, the largest single stage
/// after the policy. None of that can change while the server runs: the trusted keys are fixed
/// when the verifier is built, and the token's bytes are what was signed. The only
/// time-dependent checks are expiry, so a cache hit re-runs `validate_at(now)` (every hop's
/// expiry, which includes the token's `exp`, the last hop's) and nothing is cached for a token
/// that failed. Lease revocation is unaffected: leases are checked on every call.
///
/// Bounded: when full, expired chains are dropped, and if that frees nothing the map is
/// cleared (the next calls simply verify again).
struct VerifiedTokens {
    chains: Mutex<HashMap<[u8; 32], attenuo_token::VerifiedToken>>,
    capacity: usize,
}

impl VerifiedTokens {
    fn new(capacity: usize) -> Self {
        Self {
            chains: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    fn key(token: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(token.as_bytes()).into()
    }

    /// The cached verified token, if its chain is still valid at `now`.
    fn get(
        &self,
        key: &[u8; 32],
        now: OffsetDateTime,
        max_depth: usize,
    ) -> Option<attenuo_token::VerifiedToken> {
        let chains = self.chains.lock().ok()?;
        let v = chains.get(key)?;
        v.chain.validate_at(now, max_depth).ok()?;
        Some(v.clone())
    }

    fn insert(&self, key: [u8; 32], v: &attenuo_token::VerifiedToken, now: OffsetDateTime) {
        let Ok(mut chains) = self.chains.lock() else {
            return;
        };
        if chains.len() >= self.capacity {
            chains.retain(|_, c| c.chain.hops.iter().all(|h| h.expires_at > now));
            if chains.len() >= self.capacity {
                chains.clear();
            }
        }
        chains.insert(key, v.clone());
    }
}

#[async_trait]
impl Authorizer for ServerAuthorizer {
    /// Without the request there is no DPoP proof to check: a bound token is refused.
    async fn authenticate(
        &self,
        bearer: &str,
        now: OffsetDateTime,
    ) -> Result<DelegationChain, AuthError> {
        let v = self.verify(bearer, now)?;
        if v.claims.cnf.is_some() {
            return Err(AuthError::DpopRequired);
        }
        Ok(v.chain)
    }

    async fn authenticate_request(
        &self,
        req: &RequestAuth<'_>,
        now: OffsetDateTime,
    ) -> Result<Authenticated, AuthError> {
        let v = self.verify(req.token, now)?;
        let dpop_bound = match &self.dpop {
            Some(dpop) => {
                let url = dpop.expected_url(req.host, req.path);
                dpop.check_presented(
                    v.claims.cnf.as_ref(),
                    req.token,
                    req.dpop,
                    req.method,
                    &url,
                    now,
                )?
            }
            None if v.claims.cnf.is_some() => return Err(AuthError::DpopRequired),
            None => false,
        };
        // The key an approval for this hop is bound to: only when the request proved it.
        let jkt = dpop_bound
            .then(|| v.claims.cnf.as_ref().map(|c| c.jkt.clone()))
            .flatten();
        Ok(Authenticated {
            chain: v.chain,
            dpop_bound,
            jkt,
        })
    }

    async fn check_active(
        &self,
        chain: &DelegationChain,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        let chain = chain.clone();
        on_blocking_pool(&self.pipeline, move |p| p.check_leases(&chain, now))
            .await
            .map_err(|(reason, detail)| {
                tracing::warn!(reason, detail = ?detail.join("; "), "lease check failed");
                AuthError::LeaseInactive(reason.to_string())
            })
    }

    async fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> AuthDecision {
        self.authorize_with(chain, call, &CallContext::default(), now)
            .await
    }

    async fn authorize_with(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        ctx: &CallContext,
        now: OffsetDateTime,
    ) -> AuthDecision {
        let (chain, call, ctx) = (chain.clone(), call.clone(), ctx.clone());
        let started = Instant::now();
        let (d, decide_time) = on_blocking_pool(&self.pipeline, move |p| {
            let t = Instant::now();
            let d = p.decide_with(&chain, &call, &ctx, now);
            (d, t.elapsed())
        })
        .await;
        // What the hop to the blocking pool and back cost, beyond the decision itself.
        let hop = started.elapsed().saturating_sub(decide_time);
        self.pipeline
            .metrics()
            .observe_stage(Stage::BlockingPool, hop);
        tracing::debug!(
            blocking_pool_us = hop.as_micros() as u64,
            "decision returned"
        );
        AuthDecision {
            decision: d.decision,
            reason: d.reason,
            decision_id: d.decision_id,
            approval: d.approval,
            limit: d.limit.as_ref().map(LimitHit::to_json),
        }
    }

    async fn record_result(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        decision_id: Uuid,
        result: &Value,
        is_error: bool,
        now: OffsetDateTime,
    ) -> Result<(), String> {
        // The canonical form is computed here, so the result itself is not copied to the
        // blocking pool; only its digest is.
        let digest = result_digest(result).map_err(|e| {
            tracing::error!(error = %e, "result has no canonical form; withholding it");
            REASON_LABEL_ERROR.to_string()
        })?;
        let (chain, call) = (chain.clone(), call.clone());
        on_blocking_pool(&self.pipeline, move |p| {
            p.record_result(&chain, &call, decision_id, digest, is_error, now)
        })
        .await
        .map(|_| ())
    }

    fn observe_tool_hints(
        &self,
        server: &str,
        tool: &str,
        read_only_hint: Option<bool>,
        destructive_hint: Option<bool>,
    ) {
        let Ok(engine) = self.pipeline.policy().read() else {
            return;
        };
        if engine.import_annotations(server, tool, read_only_hint, destructive_hint) {
            // Server and tool come from the upstream: Debug-format them (SR-18).
            tracing::info!(
                server = ?server,
                tool = ?tool,
                read_only_hint = ?read_only_hint,
                destructive_hint = ?destructive_hint,
                "tool annotations narrowed a catalog entry"
            );
        }
    }

    fn knows_tool(&self, server: &str, tool: &str) -> bool {
        // A poisoned lock fails closed: the tool counts as unknown.
        self.pipeline
            .policy()
            .read()
            .map(|engine| engine.catalog().contains(server, tool))
            .unwrap_or(false)
    }

    async fn record_rejection(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> Uuid {
        let (chain, call, reason) = (chain.clone(), call.clone(), reason.to_string());
        on_blocking_pool(&self.pipeline, move |p| {
            p.record_rejection(&chain, &call, &reason, now)
        })
        .await
    }

    fn observe_stage(&self, stage: Stage, elapsed: Duration) {
        self.pipeline.metrics().observe_stage(stage, elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_audit::{MemoryAudit, MemoryLeaseStore};
    use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId, OriginatingUser};
    use attenuo_policy::PolicyEngineBuilder;
    use serde_json::json;
    use time::Duration;

    fn setup() -> (
        Pipeline,
        Arc<MemoryLeaseStore>,
        Arc<MemoryAudit>,
        DelegationChain,
    ) {
        let now = OffsetDateTime::now_utc();
        let engine = PolicyEngineBuilder::new()
            .with_policies_str("permit(principal, action, resource);")
            .with_unknown_tools(attenuo_policy::UnknownTools::Allow)
            .build()
            .unwrap();
        let leases = Arc::new(MemoryLeaseStore::new());
        let audit = Arc::new(MemoryAudit::new());
        let chain = DelegationChain::root(
            OriginatingUser {
                subject: "alice".into(),
                issuer: "idp".into(),
                authenticated_at: now,
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter([Capability::new("github", "read_*")]),
            now,
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        let p = Pipeline::new(Arc::new(RwLock::new(engine)), leases.clone(), audit.clone());
        (p, leases, audit, chain)
    }

    #[test]
    fn unknown_lease_denies_and_is_audited() {
        let (p, _leases, audit, chain) = setup();
        let call = ToolCall::new("github", "read_file", json!({}));
        let d = p.decide(&chain, &call, OffsetDateTime::now_utc());
        assert_eq!(d.reason, REASON_LEASE_UNKNOWN);
        assert_eq!(audit.len().unwrap(), 1);
        assert_eq!(audit.snapshot().unwrap()[0].record.id, d.decision_id);
    }

    #[test]
    fn proxy_rejections_are_audited_as_denials() {
        let (p, _leases, audit, chain) = setup();
        let call = ToolCall::new("github", "http.GET", json!({})).with_session("abc123");
        let id = p.record_rejection(
            &chain,
            &call,
            attenuo_proxy::REASON_SESSION_MISMATCH,
            OffsetDateTime::now_utc(),
        );
        let entries = audit.snapshot().unwrap();
        assert_eq!(entries.len(), 1);
        let r = &entries[0].record;
        assert_eq!(r.id, id);
        assert_eq!(r.decision, Decision::Deny);
        assert_eq!(r.reason, "session_mismatch");
        assert_eq!(r.tool, "http.GET");
        assert_eq!(r.session_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn live_lease_reaches_policy_and_revocation_denies() {
        let (p, leases, _audit, chain) = setup();
        let now = OffsetDateTime::now_utc();
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        let ok = ToolCall::new("github", "read_file", json!({}));
        assert!(p.decide(&chain, &ok, now).is_allow());
        let no = ToolCall::new("github", "delete_repo", json!({}));
        assert_eq!(
            p.decide(&chain, &no, now).reason,
            attenuo_policy::REASON_CAPABILITY_DENIED
        );
        leases.revoke(&LeaseId::new("l1"), "test", now).unwrap();
        assert_eq!(p.decide(&chain, &ok, now).reason, REASON_LEASE_REVOKED);
    }

    #[test]
    fn any_hop_with_an_unrenewed_lease_denies() {
        let (p, leases, _audit, root) = setup();
        let now = OffsetDateTime::now_utc();
        let child = root
            .extend(
                AgentId::new("coder"),
                CapabilitySet::from_iter([Capability::new("github", "read_file")]),
                now,
                Duration::minutes(30),
                LeaseId::new("l2"),
                8,
            )
            .unwrap();
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::minutes(5))
            .unwrap();
        leases
            .register(
                &LeaseId::new("l2"),
                Some(&LeaseId::new("l1")),
                now + Duration::minutes(5),
            )
            .unwrap();
        let call = ToolCall::new("github", "read_file", json!({}));
        assert!(p.decide(&child, &call, now).is_allow());

        // Parent lapses, child's own lease is fine: deny.
        leases
            .renew(&LeaseId::new("l1"), now - Duration::seconds(1), now)
            .unwrap();
        assert_eq!(p.decide(&child, &call, now).reason, REASON_LEASE_EXPIRED);
        // Renewing the parent restores access; the audit trail has all three decisions.
        leases
            .renew(&LeaseId::new("l1"), now + Duration::minutes(5), now)
            .unwrap();
        assert!(p.decide(&child, &call, now).is_allow());
    }

    #[test]
    fn expired_lease_denies() {
        let (p, leases, _audit, chain) = setup();
        let now = OffsetDateTime::now_utc();
        leases
            .register(&LeaseId::new("l1"), None, now - Duration::seconds(1))
            .unwrap();
        let call = ToolCall::new("github", "read_file", json!({}));
        assert_eq!(p.decide(&chain, &call, now).reason, REASON_LEASE_EXPIRED);
    }

    #[test]
    fn decide_returns_the_record_it_appended() {
        let (p, leases, audit, chain) = setup();
        let now = OffsetDateTime::now_utc();
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        let d = p.decide(
            &chain,
            &ToolCall::new("github", "read_file", json!({})),
            now,
        );
        let stored = &audit.snapshot().unwrap()[0];
        assert_eq!(d.audit_seq, Some(stored.seq));
        assert_eq!(d.decision_id, stored.record.id);
        assert_eq!(d.reason, stored.record.reason);
        assert_eq!(d.policy_ids, stored.record.policy_ids);
    }

    #[tokio::test]
    async fn verified_tokens_are_cached_but_expiry_is_rechecked() {
        let (p, _leases, _audit, _chain) = setup();
        let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: Duration::minutes(5),
        });
        let now = OffsetDateTime::now_utc();
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        };
        let caps = CapabilitySet::from_iter([Capability::new("github", "read_*")]);
        let issued = issuer
            .issue_root(user, AgentId::new("planner"), caps, None, now)
            .unwrap();
        let auth = ServerAuthorizer::new(issuer.verifier(), Arc::new(p));

        let first = auth.authenticate(&issued.token, now).await.unwrap();
        assert_eq!(first, issued.chain);
        assert_eq!(auth.verified.chains.lock().unwrap().len(), 1);
        let again = auth.authenticate(&issued.token, now).await.unwrap();
        assert_eq!(again, issued.chain, "served from the cache");

        // Past the token's expiry the cached chain is refused, like a fresh verification.
        let later = issued.expires_at + Duration::seconds(1);
        assert!(auth.authenticate(&issued.token, later).await.is_err());

        // A token that differs in one byte is verified on its own (and fails); failures are
        // not cached.
        let mut forged = issued.token.clone().into_bytes();
        let last = forged.len() - 2;
        forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
        let forged = String::from_utf8(forged).unwrap();
        assert!(auth.authenticate(&forged, now).await.is_err());
        assert_eq!(auth.verified.chains.lock().unwrap().len(), 1);
    }

    /// SR-46: a token over `VERIFIED_TOKEN_MAX_BYTES` is verified, but not kept.
    #[tokio::test]
    async fn oversized_tokens_are_verified_but_not_cached() {
        let (p, _leases, _audit, _chain) = setup();
        let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: Duration::minutes(5),
        });
        let now = OffsetDateTime::now_utc();
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        };
        // A long constraint list, as a child narrowing `github:read_*` could carry.
        let values: Vec<serde_json::Value> = (0..2000)
            .map(|i| json!(format!("acme/repo-{i:05}")))
            .collect();
        let cap = Capability::new("github", "read_*")
            .with_constraint("repo", attenuo_core::ArgConstraint::OneOf(values));
        let issued = issuer
            .issue_root(
                user,
                AgentId::new("planner"),
                CapabilitySet::from_iter([cap]),
                None,
                now,
            )
            .unwrap();
        assert!(issued.token.len() > VERIFIED_TOKEN_MAX_BYTES);
        let auth = ServerAuthorizer::new(issuer.verifier(), Arc::new(p));
        assert_eq!(
            auth.authenticate(&issued.token, now).await.unwrap(),
            issued.chain
        );
        assert_eq!(auth.verified.chains.lock().unwrap().len(), 0);
    }

    #[test]
    fn verified_token_cache_stays_bounded() {
        let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: Duration::minutes(5),
        });
        let now = OffsetDateTime::now_utc();
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        };
        let caps = CapabilitySet::from_iter([Capability::new("github", "read_*")]);
        let issued = issuer
            .issue_root(user, AgentId::new("planner"), caps, None, now)
            .unwrap();
        let v = issuer.verifier().verify(&issued.token, now).unwrap();
        let cache = VerifiedTokens::new(3);
        for i in 0..10 {
            cache.insert(VerifiedTokens::key(&format!("t{i}")), &v, now);
            assert!(cache.chains.lock().unwrap().len() <= 3);
        }
        // Expired entries go first when the cache is full.
        let expired_at = v.chain.hops[0].expires_at;
        let cache = VerifiedTokens::new(2);
        cache.insert(VerifiedTokens::key("a"), &v, now);
        cache.insert(VerifiedTokens::key("b"), &v, now);
        cache.insert(VerifiedTokens::key("c"), &v, expired_at);
        let chains = cache.chains.lock().unwrap();
        assert_eq!(chains.len(), 1);
        assert!(chains.contains_key(&VerifiedTokens::key("c")));
    }
}

/// Run limits in the pipeline (ADR-0010). The multi-hop, concurrent and HTTP-level cases are
/// in `tests/run_limits.rs`; these use the pipeline directly, with a store or a log that can
/// be made to fail.
#[cfg(test)]
mod budget_tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use attenuo_audit::{
        AuditEntry, AuditError, MemoryAudit, MemoryLeaseStore, SqliteLeaseStore, VerifyReport,
    };
    use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId, Limits, OriginatingUser};
    use attenuo_policy::PolicyEngineBuilder;
    use serde_json::json;
    use time::Duration;

    /// A memory log whose appends can be made to fail.
    #[derive(Default)]
    struct FlakyAudit {
        inner: MemoryAudit,
        fail: AtomicBool,
    }

    impl AuditSink for FlakyAudit {
        fn append(&self, record: DecisionRecord) -> Result<AuditEntry, AuditError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuditError::Storage("disk full".into()));
            }
            self.inner.append(record)
        }
        fn head(&self) -> Result<Option<AuditEntry>, AuditError> {
            self.inner.head()
        }
        fn range(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditEntry>, AuditError> {
            self.inner.range(from_seq, limit)
        }
        fn verify_chain(&self) -> Result<VerifyReport, AuditError> {
            self.inner.verify_chain()
        }
    }

    const POLICY: &str = r#"
permit(principal, action, resource);
@id("no_big_payments")
forbid(principal, action == Action::"bank/send", resource)
when { context.input has amount && context.input.amount > 1000 };
"#;

    fn chain(limits: Limits, now: OffsetDateTime) -> DelegationChain {
        DelegationChain::root(
            OriginatingUser {
                subject: "alice".into(),
                issuer: "idp".into(),
                authenticated_at: now,
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter([Capability::new("bank", "send").with_limits(limits)]),
            now,
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap()
    }

    fn pipeline(leases: Arc<dyn LeaseStore>, audit: Arc<dyn AuditSink>) -> Pipeline {
        let engine = PolicyEngineBuilder::new()
            .with_catalog(
                attenuo_policy::ToolCatalog::new().with(
                    "bank",
                    "send",
                    attenuo_policy::ToolAttrs::new()
                        .with_input("amount", attenuo_policy::ArgType::Long),
                ),
            )
            .with_policies_str(POLICY)
            .build()
            .unwrap();
        Pipeline::new(Arc::new(RwLock::new(engine)), leases, audit)
    }

    fn send(amount: Value) -> ToolCall {
        ToolCall::new("bank", "send", json!({ "to": "emma", "amount": amount }))
    }

    #[test]
    fn charges_allowed_calls_and_records_what_was_left() {
        let now = OffsetDateTime::now_utc();
        let leases = Arc::new(MemoryLeaseStore::new());
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        let audit = Arc::new(MemoryAudit::new());
        let p = pipeline(leases, audit.clone());
        let c = chain(Limits::default().with_calls(2).with_sum("amount", 50), now);

        let d = p.decide(&c, &send(json!(40)), now);
        assert!(d.is_allow(), "{d:?}");
        assert_eq!(
            d.budget.calls_remaining, 2,
            "Cedar sees the figures before the call"
        );
        assert_eq!(d.budget.amount_remaining, 50);
        let record = &audit.snapshot().unwrap()[0].record;
        let charged = record.budget.as_ref().unwrap();
        assert_eq!(
            charged
                .charged
                .iter()
                .map(|c| (c.kind, c.used_after, c.max))
                .collect::<Vec<_>>(),
            vec![(LimitKind::Calls, 1, 2), (LimitKind::Sum, 40, 50)]
        );

        // 20 more would take the sum to 60: refused before Cedar, with the limit named.
        let d = p.decide(&c, &send(json!(20)), now);
        assert_eq!(d.reason, REASON_BUDGET_EXHAUSTED);
        let hit = d.limit.unwrap();
        assert_eq!(
            (hit.kind, hit.max, hit.used, hit.hop),
            (LimitKind::Sum, 50, 40, 0)
        );
        assert_eq!(hit.to_json()["arg"], "amount");
        assert!(audit.snapshot().unwrap()[1].record.budget.is_none());
        // 10 still fits.
        assert!(p.decide(&c, &send(json!(10)), now).is_allow());
    }

    #[test]
    fn denied_call_is_not_charged() {
        let now = OffsetDateTime::now_utc();
        let leases = Arc::new(MemoryLeaseStore::new());
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        let p = pipeline(leases.clone(), Arc::new(MemoryAudit::new()));
        let c = chain(Limits::default().with_calls(1), now);
        // Cedar forbids it: nothing is spent, so the next permitted call still has its budget.
        let d = p.decide(&c, &send(json!(5000)), now);
        assert_eq!(d.reason, attenuo_policy::REASON_POLICY_DENY);
        assert!(d.charged.is_none());
        assert!(p.decide(&c, &send(json!(5)), now).is_allow());
        assert_eq!(
            p.decide(&c, &send(json!(5)), now).reason,
            REASON_BUDGET_EXHAUSTED
        );
    }

    #[test]
    fn negative_or_string_amount_is_refused() {
        let now = OffsetDateTime::now_utc();
        let leases = Arc::new(MemoryLeaseStore::new());
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        let p = pipeline(leases, Arc::new(MemoryAudit::new()));
        let c = chain(Limits::default().with_sum("amount", 5000), now);
        for amount in [json!("1500"), json!(-1200), json!(1.5)] {
            let d = p.decide(&c, &send(amount.clone()), now);
            assert_eq!(d.reason, REASON_LIMIT_ARG_INVALID, "{amount}");
            assert!(d.budget.limited);
        }
    }

    #[test]
    fn charge_and_audit_append_commit_together() {
        let now = OffsetDateTime::now_utc();
        let leases = Arc::new(MemoryLeaseStore::new());
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        let audit = Arc::new(FlakyAudit::default());
        let p = pipeline(leases.clone(), audit.clone());
        let c = chain(Limits::default().with_calls(1), now);
        audit.fail.store(true, Ordering::SeqCst);
        let d = p.decide(&c, &send(json!(1)), now);
        assert_eq!(d.reason, REASON_AUDIT_ERROR);
        // The charge was refunded: the call that can be recorded gets the budget.
        audit.fail.store(false, Ordering::SeqCst);
        assert!(p.decide(&c, &send(json!(1)), now).is_allow());
        assert_eq!(
            p.decide(&c, &send(json!(1)), now).reason,
            REASON_BUDGET_EXHAUSTED
        );
    }

    #[test]
    fn unreadable_counters_deny() {
        let now = OffsetDateTime::now_utc();
        let leases = Arc::new(SqliteLeaseStore::open_in_memory().unwrap());
        leases
            .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
            .unwrap();
        leases
            .with_connection(|c| Ok(c.execute_batch("DROP TABLE budget_counters")?))
            .unwrap();
        let p = pipeline(leases, Arc::new(MemoryAudit::new()));
        let d = p.decide(
            &chain(Limits::default().with_calls(5), now),
            &send(json!(1)),
            now,
        );
        assert_eq!(d.reason, REASON_BUDGET_ERROR);
        assert!(
            d.diagnostics.iter().any(|m| m.contains("unreadable")),
            "{d:?}"
        );
        // A call no limit applies to does not read the counters at all.
        let free = chain(Limits::default(), now);
        assert!(p.decide(&free, &send(json!(1)), now).is_allow());
    }
}

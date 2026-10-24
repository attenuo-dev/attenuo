//! The decision pipeline and the proxy's real [`Authorizer`].
//!
//! [`Pipeline::decide`] is the one place a tool call is decided. Both the MCP proxy (through
//! [`ServerAuthorizer`]) and the AuthZEN endpoint call it, so they cannot disagree:
//!
//! 1. **Leases.** Every lease in the chain must be known, unrevoked and unexpired
//!    (`LeaseStore::check_all`). Otherwise: deny with `lease_revoked`, `lease_expired` or
//!    `lease_unknown` (checked in that order), or `lease_error` if the store fails.
//! 2. **Labels.** The taint state of the delegation run (`LeaseStore::labels` for the
//!    chain id, ADR-0009). A store that cannot be read counts as tainted.
//! 3. **Policy.** `PolicyEngine::authorize_labelled`: the capability stage, then Cedar, with
//!    the run's labels as `context.session`. A deny through `@obligation("approval")` forbids
//!    only is `approval_required`.
//! 4. **Audit.** A [`DecisionRecord`] is appended to the hash-chained log, and its id is the
//!    decision id returned to the caller. If the append fails the call is denied with
//!    `audit_error`: an action that cannot be recorded does not happen.
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
use attenuo_audit::{AuditSink, LeaseStore, RunLabel};
use attenuo_core::{
    chain_id_of, Decision, DecisionRecord, DelegationChain, LeaseId, OutputLabel, RecordLabels,
    ResultInfo, ToolCall,
};
use attenuo_policy::{CallLabels, PolicyEngine, SessionLabels};
use attenuo_proxy::{AuthDecision, AuthError, Authenticated, Authorizer, RequestAuth, Stage};
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
    /// Set when the taint state could not be read (the run then counts as tainted).
    pub error: Option<String>,
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
        }
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
        let started = Instant::now();
        let out = self.decide_inner(chain, call, now);
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
        now: OffsetDateTime,
    ) -> PipelineDecision {
        // Stage timings: one `Instant::now()` per boundary (see `Stage`).
        let t0 = Instant::now();
        let leases = self.check_leases(chain, now);
        let t1 = Instant::now();
        let mut policy_time = None;
        let mut record_labels = RecordLabels::default();
        let (decision, reason, policy_ids, diagnostics) = match leases {
            Err((reason, detail)) => (Decision::Deny, reason.to_string(), Vec::new(), detail),
            Ok(()) => {
                let run = self.run_labels(chain);
                let labels = CallLabels {
                    session: run.session,
                };
                let o = self.evaluate_policy(chain, call, &labels, now);
                policy_time = Some(t1.elapsed());
                record_labels = run.record;
                let mut diagnostics = o.diagnostics;
                diagnostics.extend(run.error);
                (o.decision, o.reason, o.policy_ids, diagnostics)
            }
        };

        let record = DecisionRecord::new(now, decision, reason, chain, call, policy_ids)
            .with_labels(record_labels);
        let decision_id = record.id;
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
                PipelineDecision {
                    decision: record.decision,
                    reason: record.reason,
                    decision_id,
                    audit_seq: Some(entry.seq),
                    policy_ids: record.policy_ids,
                    diagnostics,
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "audit append failed; denying");
                self.metrics.audit_append_error();
                let mut diagnostics = diagnostics;
                diagnostics.push(format!("audit append failed: {e}"));
                PipelineDecision {
                    decision: Decision::Deny,
                    reason: REASON_AUDIT_ERROR.to_string(),
                    decision_id,
                    audit_seq: None,
                    policy_ids: Vec::new(),
                    diagnostics,
                }
            }
        }
    }

    /// The output labels of `chain`'s delegation run (ADR-0009), read from the lease store by
    /// chain id. Fails closed: a store error, or a chain with no hops, is a tainted run with no
    /// known source.
    pub fn run_labels(&self, chain: &DelegationChain) -> RunLabels {
        let Some(chain_id) = chain_id_of(chain) else {
            return RunLabels {
                session: SessionLabels::unknown(),
                record: RecordLabels::default(),
                error: Some("chain has no hops: no run to read labels for".into()),
            };
        };
        match self.leases.labels(&LeaseId::new(chain_id)) {
            Ok(labels) => RunLabels {
                session: SessionLabels::from_sources(labels.iter().map(|l| l.source.clone())),
                record: RecordLabels {
                    tainted_by: labels.iter().map(|l| l.seq).collect(),
                },
                error: None,
            },
            Err(e) => {
                tracing::error!(error = %e, "run taint state unreadable; treating the run as tainted");
                RunLabels {
                    session: SessionLabels::unknown(),
                    record: RecordLabels::default(),
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
        Ok(Authenticated {
            chain: v.chain,
            dpop_bound,
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
        let (chain, call) = (chain.clone(), call.clone());
        let started = Instant::now();
        let (d, decide_time) = on_blocking_pool(&self.pipeline, move |p| {
            let t = Instant::now();
            let d = p.decide(&chain, &call, now);
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

//! The decision pipeline and the proxy's real [`Authorizer`].
//!
//! [`Pipeline::decide`] is the one place a tool call is decided. Both the MCP proxy (through
//! [`ServerAuthorizer`]) and the AuthZEN endpoint call it, so they cannot disagree:
//!
//! 1. **Leases.** Every lease in the chain must be known, unrevoked and unexpired
//!    (`LeaseStore::check_all`). Otherwise: deny with `lease_revoked`, `lease_expired` or
//!    `lease_unknown` (checked in that order), or `lease_error` if the store fails.
//! 2. **Policy.** `PolicyEngine::authorize`: the capability stage, then Cedar.
//! 3. **Audit.** A [`DecisionRecord`] is appended to the hash-chained log, and its id is the
//!    decision id returned to the caller. If the append fails the call is denied with
//!    `audit_error`: an action that cannot be recorded does not happen.
//!
//! The chain is assumed to be verified already (token signature, structure, expiry).

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use onbehalf_audit::{AuditSink, LeaseStore};
use onbehalf_core::{Decision, DecisionRecord, DelegationChain, ToolCall};
use onbehalf_policy::PolicyEngine;
use onbehalf_proxy::{AuthDecision, AuthError, Authorizer};
use onbehalf_token::Verifier;
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
        let started = std::time::Instant::now();
        let out = self.decide_inner(chain, call, now);
        self.metrics.observe_authorize(started.elapsed());
        self.metrics
            .decision(if out.is_allow() { "allow" } else { "deny" }, &out.reason);
        out
    }

    fn decide_inner(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> PipelineDecision {
        let (decision, reason, policy_ids, diagnostics) = match self.check_leases(chain, now) {
            Err((reason, detail)) => (Decision::Deny, reason.to_string(), Vec::new(), detail),
            Ok(()) => match self.policy.read() {
                Ok(engine) => {
                    let o = engine.authorize(chain, call, now);
                    (o.decision, o.reason, o.policy_ids, o.diagnostics)
                }
                Err(_) => (
                    Decision::Deny,
                    onbehalf_policy::REASON_POLICY_ERROR.to_string(),
                    Vec::new(),
                    vec!["policy engine lock poisoned".to_string()],
                ),
            },
        };

        let record = DecisionRecord::new(now, decision, reason, chain, call, policy_ids);
        let decision_id = record.id;
        match self.audit.append(record.clone()) {
            Ok(entry) => {
                tracing::info!(
                    decision = ?record.decision,
                    reason = %record.reason,
                    subject = %record.originating_subject,
                    agent = %chain.current_agent().map(|a| a.0.as_str()).unwrap_or(""),
                    server = %call.server,
                    tool = %call.tool,
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
        let ids = |v: &[onbehalf_core::LeaseId]| {
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

/// The proxy's authorizer: token verification plus [`Pipeline::decide`].
pub struct ServerAuthorizer {
    verifier: Verifier,
    pipeline: Arc<Pipeline>,
}

impl ServerAuthorizer {
    pub fn new(verifier: Verifier, pipeline: Arc<Pipeline>) -> Self {
        Self { verifier, pipeline }
    }
}

#[async_trait]
impl Authorizer for ServerAuthorizer {
    async fn authenticate(
        &self,
        bearer: &str,
        now: OffsetDateTime,
    ) -> Result<DelegationChain, AuthError> {
        self.verifier
            .verify(bearer, now)
            .map(|v| v.chain)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    async fn check_active(
        &self,
        chain: &DelegationChain,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        self.pipeline
            .check_leases(chain, now)
            .map_err(|(reason, detail)| {
                tracing::warn!(reason, detail = %detail.join("; "), "lease check failed");
                AuthError::LeaseInactive(reason.to_string())
            })
    }

    async fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> AuthDecision {
        let d = self.pipeline.decide(chain, call, now);
        AuthDecision {
            decision: d.decision,
            reason: d.reason,
            decision_id: d.decision_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onbehalf_audit::{MemoryAudit, MemoryLeaseStore};
    use onbehalf_core::{AgentId, Capability, CapabilitySet, LeaseId, OriginatingUser};
    use onbehalf_policy::PolicyEngineBuilder;
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
            .with_unknown_tools(onbehalf_policy::UnknownTools::Allow)
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
            onbehalf_policy::REASON_CAPABILITY_DENIED
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
}

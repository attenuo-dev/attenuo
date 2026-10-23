//! Authorization decisions and the record the audit log stores for each one.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::call::ToolCall;
use crate::chain::{AgentId, DelegationChain, LeaseId};

/// The outcome of authorizing one tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// What the audit log records for every decision.
///
/// Arguments are stored as a digest, not in clear, because they routinely contain data the
/// log's readers should not see. The chain digest binds the record to the exact delegation
/// chain that was in force, so a later reader can prove which human and which agents were
/// involved without the log storing the full chain each time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    pub decision: Decision,
    /// Short machine-readable reason (e.g. `policy_deny`, `lease_revoked`, `chain_invalid`).
    pub reason: String,
    pub originating_subject: String,
    /// Every agent in the chain, root first. Lets a reader distinguish "the user did this"
    /// from "agent X did this for the user" at a glance.
    pub agents: Vec<AgentId>,
    pub chain_depth: usize,
    pub chain_digest: String,
    pub leases: Vec<LeaseId>,
    pub server: String,
    pub tool: String,
    pub arguments_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Identifiers of the policies that determined the decision, if the engine reports them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_ids: Vec<String>,
    /// The token was sender-constrained (`cnf.jkt`) and the request carried a valid DPoP proof
    /// for it (SR-24). For an issuance record: the new token is bound. Absent (false) in
    /// records written before this field existed, which keeps their hashes unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dpop_bound: bool,
}

impl DecisionRecord {
    pub fn new(
        at: OffsetDateTime,
        decision: Decision,
        reason: impl Into<String>,
        chain: &DelegationChain,
        call: &ToolCall,
        policy_ids: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            at,
            decision,
            reason: reason.into(),
            originating_subject: chain.originating_user.subject.clone(),
            agents: chain.hops.iter().map(|h| h.agent.clone()).collect(),
            chain_depth: chain.depth(),
            chain_digest: chain.digest(),
            leases: chain.leases().into_iter().cloned().collect(),
            server: call.server.clone(),
            tool: call.tool.clone(),
            arguments_digest: call.arguments_digest(),
            session_id: call.session_id.clone(),
            policy_ids,
            dpop_bound: call.dpop_bound,
        }
    }
}

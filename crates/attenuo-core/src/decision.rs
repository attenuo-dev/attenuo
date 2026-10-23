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

/// What sort of event an audit record is. Stored as the record's top-level `kind`, so an
/// export can be filtered or joined without reading anything nested.
///
/// Checkpoints are not records (they are signed separately and appear as `checkpoint` lines in
/// an export), so there is no kind for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// An authorization decision for a tool call (allow, or deny for any reason, including
    /// calls refused before the policy ran).
    Decision,
    /// A token exchange: a new hop was issued (`token.exchange`).
    Exchange,
    /// A root token was issued (IdP login intake, `token.root`).
    RootToken,
    /// A lease was renewed (`lease.renew`).
    LeaseRenew,
    /// A lease (and its subtree) was revoked with the admin bearer (`admin.lease.revoke`).
    LeaseRevoke,
    /// Any other action taken with the admin bearer (`admin.*`: policy reload, dev root mint).
    Admin,
}

impl RecordKind {
    pub const ALL: [RecordKind; 6] = [
        RecordKind::Decision,
        RecordKind::Exchange,
        RecordKind::RootToken,
        RecordKind::LeaseRenew,
        RecordKind::LeaseRevoke,
        RecordKind::Admin,
    ];

    /// The wire string (`decision`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`,
    /// `admin`).
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordKind::Decision => "decision",
            RecordKind::Exchange => "exchange",
            RecordKind::RootToken => "root_token",
            RecordKind::LeaseRenew => "lease_renew",
            RecordKind::LeaseRevoke => "lease_revoke",
            RecordKind::Admin => "admin",
        }
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RecordKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        RecordKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| {
                let all: Vec<_> = RecordKind::ALL.iter().map(RecordKind::as_str).collect();
                format!("unknown record kind `{s}` (one of: {})", all.join(", "))
            })
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
    /// What sort of event this is ([`RecordKind`]).
    pub kind: RecordKind,
    /// Stable id of the delegation chain the event belongs to: the lease id of its first hop,
    /// which every later hop of the same run descends from. Unlike `chain_digest` it does not
    /// change as hops are added. Absent for records with no chain (admin actions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
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

/// The chain id of `chain` (see [`DecisionRecord::chain_id`]).
pub fn chain_id_of(chain: &DelegationChain) -> Option<String> {
    chain.hops.first().map(|h| h.lease.0.clone())
}

impl DecisionRecord {
    /// Set the record's kind (the default from [`new`](Self::new) is [`RecordKind::Decision`]).
    pub fn with_kind(mut self, kind: RecordKind) -> Self {
        self.kind = kind;
        self
    }

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
            kind: RecordKind::Decision,
            chain_id: chain_id_of(chain),
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

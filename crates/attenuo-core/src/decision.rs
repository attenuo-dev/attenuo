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
    /// The call may go ahead.
    Allow,
    /// The call is refused.
    Deny,
}

impl Decision {
    /// Is this [`Decision::Allow`]?
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// The wire form, `"allow"` or `"deny"` (the same string serde writes).
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
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
    /// The upstream's answer to an allowed mediated call, recorded before it was relayed
    /// (output labelling, ADR-0009). Carries [`DecisionRecord::decision_id`] and
    /// [`DecisionRecord::result`]; the content itself is never stored.
    ToolResult,
    /// A call was gated by `@obligation("approval")` and a pending approval was stored for it
    /// (ADR-0009). Carries [`DecisionRecord::decision_id`] (the gated decision) and
    /// [`DecisionRecord::approval`] (id, call hash, expiry).
    ApprovalRequest,
    /// A pending approval was granted or declined by the originating user or an operator.
    /// Carries [`DecisionRecord::approval`] (id, call hash, approver, outcome, expiry). Using a
    /// granted approval is recorded on the decision that consumed it.
    ApprovalGrant,
    /// An AuthZEN action search was answered (`POST /access/v1/search/action`, SR-117): one
    /// record per request, not per candidate, with tool `authzen.search`. Not a decision: it
    /// allows nothing and charges nothing. Carries [`DecisionRecord::search`] (how many
    /// candidates were evaluated and how many were permitted).
    Search,
}

impl RecordKind {
    /// Every kind, in declaration order.
    pub const ALL: [RecordKind; 10] = [
        RecordKind::Decision,
        RecordKind::Exchange,
        RecordKind::RootToken,
        RecordKind::LeaseRenew,
        RecordKind::LeaseRevoke,
        RecordKind::Admin,
        RecordKind::ToolResult,
        RecordKind::ApprovalRequest,
        RecordKind::ApprovalGrant,
        RecordKind::Search,
    ];

    /// The wire string (`decision`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`,
    /// `admin`, `tool_result`, `approval_request`, `approval_grant`, `search`).
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordKind::Decision => "decision",
            RecordKind::Exchange => "exchange",
            RecordKind::RootToken => "root_token",
            RecordKind::LeaseRenew => "lease_renew",
            RecordKind::LeaseRevoke => "lease_revoke",
            RecordKind::Admin => "admin",
            RecordKind::ToolResult => "tool_result",
            RecordKind::ApprovalRequest => "approval_request",
            RecordKind::ApprovalGrant => "approval_grant",
            RecordKind::Search => "search",
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
    /// Unique id of this record.
    pub id: Uuid,
    /// When the event happened.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// What sort of event this is ([`RecordKind`]).
    pub kind: RecordKind,
    /// Stable id of the delegation chain the event belongs to: the lease id of its first hop,
    /// which every later hop of the same run descends from. Unlike `chain_digest` it does not
    /// change as hops are added. Absent for records with no chain (admin actions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// The outcome.
    pub decision: Decision,
    /// Short machine-readable reason (e.g. `policy_deny`, `lease_revoked`, `chain_invalid`).
    pub reason: String,
    /// Subject of the originating user.
    pub originating_subject: String,
    /// Every agent in the chain, root first. Lets a reader distinguish "the user did this"
    /// from "agent X did this for the user" at a glance.
    pub agents: Vec<AgentId>,
    /// Number of hops in the chain.
    pub chain_depth: usize,
    /// [`DelegationChain::digest`] of the chain in force.
    pub chain_digest: String,
    /// The lease of every hop, root first.
    pub leases: Vec<LeaseId>,
    /// Server the call was for.
    pub server: String,
    /// Tool (or call name) the call was for.
    pub tool: String,
    /// [`ToolCall::arguments_digest`] of the call's arguments.
    pub arguments_digest: String,
    /// MCP session the call arrived on, when there was one.
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
    /// The token was bound to a TLS client certificate (`cnf.x5t#S256`) and the request showed
    /// that certificate (RFC 8705 §3). For an issuance record: the new token is bound to one.
    /// Absent (false) on every other record, which keeps their hashes unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cert_bound: bool,
    /// For a [`RecordKind::ToolResult`] record: the id of the decision record of the call the
    /// result answers. Absent on every other kind, which keeps their hashes unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<Uuid>,
    /// For a [`RecordKind::ToolResult`] record: what was recorded about the result. Absent on
    /// every other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultInfo>,
    /// For a decision: the output labels the delegation run carried when the call was decided.
    /// Absent when the run had none, which keeps the hashes of older records unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<RecordLabels>,
    /// The approval this record is about (ADR-0009). On a decision: the approval the call
    /// consumed (`id`, `by`). On an `approval_request` or `approval_grant` record: the
    /// approval's id, call hash, expiry and, for a grant, approver and outcome. Absent on every
    /// other record, which keeps the hashes of older records unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalInfo>,
    /// For an allowed decision that drew on run limits (ADR-0010): every counter it charged
    /// and what each held afterwards. Absent when the call matched no limit, which keeps the
    /// hashes of older records unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<RecordBudget>,
    /// For a decision on a call to a destructive tool: the run usage the policy saw
    /// (`context.usage`, run-limits design section 3.5), before this call. Absent for any other
    /// tool, and when the call was decided before usage was read (a lease denial), which keeps
    /// the hashes of older records unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<RecordUsage>,
    /// For a [`RecordKind::Search`] record: how many candidate tools the search evaluated and
    /// how many it returned as permitted. Absent on every other kind, which keeps the hashes of
    /// older records unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<SearchInfo>,
    /// For a [`RecordKind::RootToken`] record of an IdP intake under `[idps.id_jag_ceiling]`:
    /// which claims of the ID-JAG narrowed the root grant and a digest of their values
    /// (SR-126). Absent on every other record, an ID token's intake and an intake without the
    /// ceiling included, which keeps the hashes of older records unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_jag_ceiling: Option<CeilingInfo>,
}

/// What a [`RecordKind::Search`] record says about one action search (see
/// [`DecisionRecord::search`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SearchInfo {
    /// Candidate tools evaluated on this page.
    pub evaluated: u64,
    /// Of those, the tools returned as permitted (the answer's `page.count`).
    pub permitted: u64,
}

/// What a root token record says about the ID-JAG ceiling (see
/// [`DecisionRecord::id_jag_ceiling`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeilingInfo {
    /// The ID-JAG claims that narrowed the root grant (`resource`, `scope`,
    /// `authorization_details`), in that order: the ones the ID-JAG carried with a value other
    /// than `null`. Empty when the ceiling applied but the ID-JAG carried none of them, so the
    /// root grant was kept as it is.
    pub claims: Vec<String>,
    /// SHA-256 (hex) of the RFC 8785 canonical JSON of an object mapping each name in
    /// `claims` to its full value in the verified ID-JAG ([`crate::digest::sha256_json`], as
    /// for `arguments_digest`). With no claims, the digest of `{}`.
    pub claims_digest: String,
}

impl CeilingInfo {
    /// The ceiling member for the claims `names` of the verified ID-JAG `claims`. A name the
    /// claims do not hold maps to `null`.
    pub fn new<'a>(
        names: impl IntoIterator<Item = &'a str>,
        claims: &serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        let names: Vec<String> = names.into_iter().map(str::to_owned).collect();
        let values: serde_json::Map<String, serde_json::Value> = names
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    claims.get(n).cloned().unwrap_or(serde_json::Value::Null),
                )
            })
            .collect();
        Self {
            claims_digest: crate::digest::sha256_json(&values),
            claims: names,
        }
    }
}

/// What a decision record says about run usage (see [`DecisionRecord::usage`]): the figures
/// Cedar saw as `context.usage`, before the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RecordUsage {
    /// Allowed calls of this server and tool in the run so far, all hops.
    pub calls: u64,
    /// Sum of the catalog's `amount` input over those calls; 0 when the catalog names none.
    pub amount: u64,
    /// The catalog's `destination` input value appeared in an earlier allowed call of this
    /// tool in the run.
    pub destination_seen: bool,
    /// The originating user's per-user windows of this tool (run limits phase 3), for the
    /// kinds a loaded policy reads. Absent when none is kept, so records written without
    /// windows hash as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_window: Option<RecordUserWindow>,
}

/// What a decision record says about the originating user's per-user windows of the called
/// tool (`context.usage.user_window`), before the call. Only the kinds the server keeps are
/// present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RecordUserWindow {
    /// The UTC hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hour: Option<RecordWindow>,
    /// The UTC day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day: Option<RecordWindow>,
}

/// One per-user window as a decision record states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RecordWindow {
    /// The window's start, Unix seconds UTC.
    pub start: i64,
    /// Allowed calls of the tool by any run of the user in the window.
    pub calls: u64,
    /// The sum of the catalog's `amount` input over those calls.
    pub amount: u64,
}

/// What a decision record says about run limits (see [`DecisionRecord::budget`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordBudget {
    /// Every counter the call was charged against, in the order of
    /// [`crate::limits::charges_for`].
    pub charged: Vec<BudgetCharge>,
}

/// One counter a decision charged: which limit, of which capability of which hop, and what it
/// held after the charge. The hop is named by its position, not its lease id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetCharge {
    /// Position of the hop in the chain (0 is the root).
    pub hop: usize,
    /// Index of the capability in the hop's capability set.
    pub cap: usize,
    /// Which limit of the capability was charged.
    pub kind: crate::limits::LimitKind,
    /// The argument a `sum` or `calls_per` limit counts; absent for `calls`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<String>,
    /// What the counter holds after this call.
    pub used_after: u64,
    /// The limit's `max`.
    pub max: u64,
}

/// What a record says about an approval (see [`DecisionRecord::approval`]). Every member but
/// `id` is optional and omitted when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalInfo {
    /// The approval id (`approval_id` in the `-32008` error data).
    pub id: Uuid,
    /// Who stood behind the approval: `user` or `operator`. On a consuming decision and on a
    /// grant record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// SHA-256 of the canonical `{server, tool, arguments}` the approval is bound to
    /// ([`ToolCall::call_hash`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_hash: Option<String>,
    /// When the approval stops being usable.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub expires_at: Option<OffsetDateTime>,
    /// Subject of the approver: the user's `sub`, or `urn:attenuo:admin` for an operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    /// How the approver authenticated: `id_token` or `admin_token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// On a grant record: `grant` or `decline`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// On a consuming decision: `token` when the call presented a signed approval token.
    /// Omitted when the approval was found by the identical-retry lookup, so those records
    /// hash as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented: Option<String>,
}

impl ApprovalInfo {
    /// Only the id; set the other members as needed.
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            by: None,
            call_hash: None,
            expires_at: None,
            approver: None,
            method: None,
            outcome: None,
            presented: None,
        }
    }
}

/// Label of an upstream result (output labelling, ADR-0009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputLabel {
    /// The default for every upstream result: it may carry instructions an attacker placed
    /// there, so it taints the delegation run that read it.
    #[default]
    Untrusted,
    /// The deployment marked the tool's output trusted in the catalog (`output = "trusted"`).
    /// Recorded, but it does not taint the run.
    Trusted,
}

impl OutputLabel {
    /// The wire string, `untrusted` or `trusted`.
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputLabel::Untrusted => "untrusted",
            OutputLabel::Trusted => "trusted",
        }
    }
}

/// What a [`RecordKind::ToolResult`] record says about one upstream result. No content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultInfo {
    /// SHA-256 (hex) of the RFC 8785 canonical JSON of the result: the JSON-RPC `result`
    /// member, or the `error` member for a JSON-RPC error.
    pub digest: String,
    /// Length in bytes of that canonical JSON.
    pub size: u64,
    /// The result was a JSON-RPC error from the upstream.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub error: bool,
    /// The label the result was given.
    pub label: OutputLabel,
    /// How many fingerprints of the result went into the run's span index for argument
    /// matching (ADR-0009 phase 2, [`crate::fingerprint`]). 0 for a trusted result, and in
    /// records written before phase 2.
    pub fingerprints: u64,
}

/// The labels a decision record carries (see [`DecisionRecord::labels`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RecordLabels {
    /// Audit `seq` of the `tool_result` records that tainted the run: the first untrusted
    /// result from each source (`<server>/<tool>`), in ascending order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tainted_by: Vec<u64>,
    /// Arguments of the call that matched an untrusted result of the run (ADR-0009 phase 2):
    /// one entry per argument, result and kind, ordered by argument, then `seq`, then kind.
    /// Omitted when empty, so the hashes of records without matches do not change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub untrusted_args: Vec<UntrustedArg>,
}

impl RecordLabels {
    /// No taint sources and no untrusted arguments.
    pub fn is_empty(&self) -> bool {
        self.tainted_by.is_empty() && self.untrusted_args.is_empty()
    }
}

/// One argument that matched the run's span index: an entry of `labels.untrusted_args`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UntrustedArg {
    /// The top-level argument name.
    pub arg: String,
    /// Audit `seq` of the `tool_result` record whose fingerprints the argument matched.
    /// Absent for [`UntrustedKind::Unreadable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// How the argument came to count as untrusted.
    pub kind: UntrustedKind,
}

/// How an argument came to count as untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrustedKind {
    /// It contains a whole JSON string of the result.
    Leaf,
    /// It contains an entity (URL, host, email, IBAN, digits, path) of the result.
    Entity,
    /// It shares a winnowed k-gram with a long string of the result.
    Kgram,
    /// The span index could not be read, so every unpinned argument with a fingerprint counts
    /// as untrusted (fail closed). No `seq`.
    Unreadable,
}

impl UntrustedKind {
    /// The wire string: `leaf`, `entity`, `kgram` or `unreadable`.
    pub fn as_str(&self) -> &'static str {
        match self {
            UntrustedKind::Leaf => "leaf",
            UntrustedKind::Entity => "entity",
            UntrustedKind::Kgram => "kgram",
            UntrustedKind::Unreadable => "unreadable",
        }
    }
}

impl From<crate::fingerprint::FingerprintKind> for UntrustedKind {
    fn from(k: crate::fingerprint::FingerprintKind) -> Self {
        use crate::fingerprint::FingerprintKind;
        match k {
            FingerprintKind::Leaf => UntrustedKind::Leaf,
            FingerprintKind::Entity => UntrustedKind::Entity,
            FingerprintKind::Kgram => UntrustedKind::Kgram,
        }
    }
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

    /// A [`RecordKind::Decision`] record of `decision` on `call` under `chain`, with a fresh id;
    /// the optional members start empty.
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
            cert_bound: call.cert_bound,
            decision_id: None,
            result: None,
            labels: None,
            approval: None,
            budget: None,
            usage: None,
            search: None,
            id_jag_ceiling: None,
        }
    }

    /// Attach what an action search evaluated and permitted ([`DecisionRecord::search`]).
    pub fn with_search(mut self, search: SearchInfo) -> Self {
        self.search = Some(search);
        self
    }

    /// Attach the ID-JAG ceiling of a root token intake ([`DecisionRecord::id_jag_ceiling`]).
    pub fn with_id_jag_ceiling(mut self, ceiling: CeilingInfo) -> Self {
        self.id_jag_ceiling = Some(ceiling);
        self
    }

    /// Attach the run's labels; empty labels leave the field absent.
    pub fn with_labels(mut self, labels: RecordLabels) -> Self {
        self.labels = (!labels.is_empty()).then_some(labels);
        self
    }

    /// The [`RecordKind::ToolResult`] record for the upstream's answer to `call`, which was
    /// allowed by decision `decision_id`.
    pub fn tool_result(
        at: OffsetDateTime,
        chain: &DelegationChain,
        call: &ToolCall,
        decision_id: Uuid,
        result: ResultInfo,
    ) -> Self {
        let mut r = Self::new(
            at,
            Decision::Allow,
            REASON_TOOL_RESULT,
            chain,
            call,
            Vec::new(),
        )
        .with_kind(RecordKind::ToolResult);
        r.decision_id = Some(decision_id);
        r.result = Some(result);
        r
    }
}

/// `reason` of every [`RecordKind::ApprovalRequest`] record.
pub const REASON_APPROVAL_REQUESTED: &str = "approval_requested";
/// `reason` of an [`RecordKind::ApprovalGrant`] record that granted the approval.
pub const REASON_APPROVAL_GRANTED: &str = "approval_granted";
/// `reason` of an [`RecordKind::ApprovalGrant`] record that declined the approval.
pub const REASON_APPROVAL_DECLINED: &str = "approval_declined";
/// `reason` of a decision that refused a presented approval token (`params._meta
/// ["dev.attenuo/approval"]`, AuthZEN `context.approval_token`): its signature, type or expiry
/// does not verify, it is bound to another run, hop, call or key, or the approval it names is
/// not granted any more (consumed, declined, expired, or its lease revoked). A deny.
pub const REASON_APPROVAL_INVALID: &str = "approval_invalid";

/// `reason` of every [`RecordKind::ToolResult`] record.
pub const REASON_TOOL_RESULT: &str = "tool_result";

/// `reason` of every [`RecordKind::Search`] record: an AuthZEN action search was answered.
pub const REASON_SEARCH_ANSWERED: &str = "search_answered";

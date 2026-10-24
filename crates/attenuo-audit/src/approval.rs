//! Pending approvals (output labelling, ADR-0009).
//!
//! When the policy answers `approval_required` for a call, the server stores an [`Approval`]
//! bound to the delegation run (`chain_id`), the calling hop's lease and the call hash
//! (`ToolCall::call_hash`). The originating user or an operator then grants or declines it, and
//! the agent retries the identical call, which consumes a granted approval once.
//!
//! Approvals live in the lease store, next to the leases they are bound to, so that every
//! state change checks the lease in the same transaction. The life of one approval:
//!
//! ```text
//! pending --grant--> granted --retry of the same call--> consumed
//!    \--decline--> declined
//! ```
//!
//! Expiry is not a state: an approval whose `expires_at` has passed can no longer be granted
//! or consumed, whatever its state says. Nor is revocation: a revoked or expired lease makes
//! every approval bound to it unusable, because grant and consume both check the lease.

use attenuo_core::{DelegationChain, LeaseId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::AuditError;
use crate::lease::LeaseRow;

/// Where an approval is in its life (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Waiting for the user or an operator.
    Pending,
    /// Granted; the next identical call of the run may use it, once.
    Granted,
    /// Declined; it can no longer be granted or used.
    Declined,
    /// Used by a call (single use).
    Consumed,
}

impl ApprovalState {
    /// The wire string: `pending`, `granted`, `declined` or `consumed`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalState::Pending => "pending",
            ApprovalState::Granted => "granted",
            ApprovalState::Declined => "declined",
            ApprovalState::Consumed => "consumed",
        }
    }

    /// Parse the wire string.
    pub fn parse(s: &str) -> Result<Self, AuditError> {
        Ok(match s {
            "pending" => ApprovalState::Pending,
            "granted" => ApprovalState::Granted,
            "declined" => ApprovalState::Declined,
            "consumed" => ApprovalState::Consumed,
            other => {
                return Err(AuditError::Storage(format!(
                    "unknown approval state `{other}`"
                )))
            }
        })
    }
}

impl std::fmt::Display for ApprovalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the approver authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMethod {
    /// An ID token from the originating user's IdP (`POST /approvals/{id}`): `by = "user"`.
    IdToken,
    /// The admin bearer (`POST /admin/approvals/{id}`): `by = "operator"`.
    AdminToken,
}

impl ApprovalMethod {
    /// The wire string: `id_token` or `admin_token`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalMethod::IdToken => "id_token",
            ApprovalMethod::AdminToken => "admin_token",
        }
    }

    /// What Cedar sees as `context.approval.by`: `user` or `operator`.
    pub fn by(&self) -> &'static str {
        match self {
            ApprovalMethod::IdToken => "user",
            ApprovalMethod::AdminToken => "operator",
        }
    }

    /// Parse the wire string.
    pub fn parse(s: &str) -> Result<Self, AuditError> {
        match s {
            "id_token" => Ok(ApprovalMethod::IdToken),
            "admin_token" => Ok(ApprovalMethod::AdminToken),
            other => Err(AuditError::Storage(format!(
                "unknown approval method `{other}`"
            ))),
        }
    }
}

/// Who granted or declined an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    /// The user's `sub`, or `urn:attenuo:admin` for an operator.
    pub subject: String,
    pub method: ApprovalMethod,
}

/// One output label of the run when the approval was requested: what the approver sees next
/// to the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLabel {
    /// `<server>/<tool>` whose result labelled the run.
    pub source: String,
    /// Audit `seq` of that result's `tool_result` record.
    pub seq: u64,
}

/// A stored approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Approval id (a UUID), returned in the `-32008` error data as `approval_id`.
    pub id: String,
    /// The delegation run: the lease of its first hop.
    pub chain_id: LeaseId,
    /// The lease of the hop that made the call. Only that hop's retry can use the approval.
    pub lease: LeaseId,
    /// `ToolCall::call_hash` of the gated call.
    pub call_hash: String,
    /// The gated call, exactly as decided.
    pub server: String,
    pub tool: String,
    pub arguments: Value,
    /// The run's output labels when the call was gated.
    pub labels: Vec<ApprovalLabel>,
    /// Id of the decision record that answered `approval_required`.
    pub decision_id: String,
    /// The delegation chain that made the call: whose run it is (`originating_user`) and what
    /// the audit records of the approval name.
    pub chain: DelegationChain,
    pub created_at: OffsetDateTime,
    /// `min(created_at + [approvals] ttl, lease expiry)`. After this the approval can no
    /// longer be granted or used.
    pub expires_at: OffsetDateTime,
    pub state: ApprovalState,
    /// Set once granted or declined.
    pub approver: Option<Approver>,
    /// When it was granted or declined.
    pub decided_at: Option<OffsetDateTime>,
    /// Id of the decision record that consumed it.
    pub consumed_by: Option<String>,
}

impl Approval {
    /// `expires_at` has passed.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }
}

/// Checks shared by the memory and SQLite stores.
pub(crate) mod rules {
    use super::*;

    /// The lease `lease` must be known and live for an approval bound to it to be created,
    /// granted or used.
    pub(crate) fn live_lease(
        lease: &LeaseId,
        row: Option<&LeaseRow>,
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, AuditError> {
        match row {
            None => Err(AuditError::UnknownLease(lease.0.clone())),
            Some(r) if r.revoked_at.is_some() => Err(AuditError::LeaseRevoked(lease.0.clone())),
            Some(r) if r.expires_at <= now => Err(AuditError::ApprovalExpired(lease.0.clone())),
            Some(r) => Ok(r.expires_at),
        }
    }

    /// May `a` be granted or declined at `now`?
    pub(crate) fn decidable(a: &Approval, now: OffsetDateTime) -> Result<(), AuditError> {
        if a.state != ApprovalState::Pending {
            return Err(AuditError::ApprovalNotPending {
                id: a.id.clone(),
                state: a.state.as_str(),
            });
        }
        if a.is_expired(now) {
            return Err(AuditError::ApprovalExpired(a.id.clone()));
        }
        Ok(())
    }

    /// Is `a` a granted, unexpired approval for this call of this hop?
    pub(crate) fn usable(
        a: &Approval,
        chain_id: &LeaseId,
        lease: &LeaseId,
        call_hash: &str,
        now: OffsetDateTime,
    ) -> bool {
        a.state == ApprovalState::Granted
            && &a.chain_id == chain_id
            && &a.lease == lease
            && a.call_hash == call_hash
            && !a.is_expired(now)
    }

    /// Is `a` a pending, unexpired approval for this call of this hop (one a repeated gated
    /// call should reuse instead of creating another)?
    pub(crate) fn reusable(a: &Approval, new: &Approval, now: OffsetDateTime) -> bool {
        a.state == ApprovalState::Pending
            && a.chain_id == new.chain_id
            && a.lease == new.lease
            && a.call_hash == new.call_hash
            && !a.is_expired(now)
    }
}

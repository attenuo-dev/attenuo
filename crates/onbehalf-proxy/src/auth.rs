//! The decoupling contract between the proxy and the token/policy/audit crates.
//!
//! The proxy never verifies tokens or evaluates policy itself. It hands the bearer token to an
//! [`Authorizer`] to obtain a [`DelegationChain`], and hands each [`ToolCall`] back to it for a
//! decision. The real implementation (token verification + policy engine + audit log) plugs in
//! behind this trait; tests use [`crate::testing::StaticAuthorizer`].

use async_trait::async_trait;
use onbehalf_core::{Decision, DelegationChain, ToolCall};
use time::OffsetDateTime;
use uuid::Uuid;

/// The outcome of authorizing one call, plus the id of the audit record that was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub decision: Decision,
    /// Short machine-readable reason (e.g. `capability_allow`, `policy_deny`, `lease_revoked`).
    pub reason: String,
    /// Id of the [`onbehalf_core::DecisionRecord`] the authorizer stored for this decision.
    pub decision_id: Uuid,
}

impl AuthDecision {
    pub fn allow(reason: impl Into<String>, decision_id: Uuid) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
            decision_id,
        }
    }

    pub fn deny(reason: impl Into<String>, decision_id: Uuid) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
            decision_id,
        }
    }

    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// Why a request could not be authenticated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// The token is valid but a lease in its chain is revoked, expired or unknown.
    #[error("lease inactive: {0}")]
    LeaseInactive(String),
}

/// Authentication and authorization, as the proxy sees it.
#[async_trait]
pub trait Authorizer: Send + Sync {
    /// Resolve the caller from the request's `Authorization: Bearer <token>` header into a
    /// validated delegation chain. `bearer` is the token with the `Bearer ` prefix removed.
    async fn authenticate(
        &self,
        bearer: &str,
        now: OffsetDateTime,
    ) -> Result<DelegationChain, AuthError>;

    /// Is every lease of `chain` live at `now`? Called for requests that are forwarded
    /// without a per-call decision (`tools/list`, `initialize`, `ping`, `GET`/`DELETE` session
    /// requests), so a revoked or lapsed token cannot use them either. `Err` carries the
    /// reason (for example `lease_revoked`). Implementations must fail closed.
    async fn check_active(
        &self,
        chain: &DelegationChain,
        now: OffsetDateTime,
    ) -> Result<(), AuthError>;

    /// Decide one call. Implementations must also record the decision (audit) and return the
    /// record's id in [`AuthDecision::decision_id`].
    async fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> AuthDecision;
}

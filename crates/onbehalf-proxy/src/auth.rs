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

    /// Decide one call. Implementations must also record the decision (audit) and return the
    /// record's id in [`AuthDecision::decision_id`].
    async fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> AuthDecision;
}

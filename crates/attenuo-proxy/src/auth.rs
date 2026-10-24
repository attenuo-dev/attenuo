//! The decoupling contract between the proxy and the token/policy/audit crates.
//!
//! The proxy never verifies tokens or evaluates policy itself. It hands the bearer token to an
//! [`Authorizer`] to obtain a [`DelegationChain`], and hands each [`ToolCall`] back to it for a
//! decision. The real implementation (token verification + policy engine + audit log) plugs in
//! behind this trait; tests use `testing::StaticAuthorizer` (behind the `testing` feature).

use std::time::Duration;

use async_trait::async_trait;
use attenuo_core::{Decision, DelegationChain, ToolCall};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::stage::Stage;

/// The outcome of authorizing one call, plus the id of the audit record that was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub decision: Decision,
    /// Short machine-readable reason (e.g. `capability_allow`, `policy_deny`, `lease_revoked`).
    pub reason: String,
    /// Id of the [`attenuo_core::DecisionRecord`] the authorizer stored for this decision.
    pub decision_id: Uuid,
    /// For an `approval_required` decision: the pending approval the authorizer stored, which
    /// the `-32008` error data names (ADR-0009). `None` otherwise, or when it could not be
    /// stored.
    pub approval: Option<ApprovalTicket>,
    /// For a `budget_exhausted` decision: the run limit that was hit, `{hop, kind, arg, max,
    /// used}` (ADR-0010), which the `-32003` error data carries as `limit`. `None` otherwise.
    pub limit: Option<serde_json::Value>,
}

/// The `params._meta` key that carries a signed approval token (output labelling, ADR-0009).
/// The proxy removes it from every message before the message goes upstream and hands the
/// token to [`Authorizer::authorize_with`] in [`CallContext::approval_token`].
pub const META_APPROVAL_KEY: &str = "dev.attenuo/approval";

/// What the proxy knows about a decided call besides the chain and the call itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallContext {
    /// The signed approval token from `params._meta["dev.attenuo/approval"]`, if the message
    /// carried one.
    pub approval_token: Option<String>,
    /// `cnf.jkt` of the calling hop's token when the request proved possession of its key
    /// ([`Authenticated::jkt`]).
    pub jkt: Option<String>,
}

/// The pending approval behind an `approval_required` decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTicket {
    /// The id to grant or decline at `POST /approvals/{id}`.
    pub approval_id: Uuid,
    /// When the approval can no longer be granted or used.
    pub expires_at: OffsetDateTime,
}

impl AuthDecision {
    pub fn allow(reason: impl Into<String>, decision_id: Uuid) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
            decision_id,
            approval: None,
            limit: None,
        }
    }

    pub fn deny(reason: impl Into<String>, decision_id: Uuid) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
            decision_id,
            approval: None,
            limit: None,
        }
    }

    /// Attach the pending approval of an `approval_required` decision.
    pub fn with_approval(mut self, approval: Option<ApprovalTicket>) -> Self {
        self.approval = approval;
        self
    }

    /// Attach the run limit a `budget_exhausted` decision hit.
    pub fn with_limit(mut self, limit: Option<serde_json::Value>) -> Self {
        self.limit = limit;
        self
    }

    pub fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// Why a request could not be authenticated.
///
/// Only [`AuthError::reason`], a stable code, is sent to the client; the `Display` text (which
/// can name the verifier's exact complaint, such as a wrong audience or an unknown `kid`) is
/// logged at debug level and never returned (SR-17).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingToken,
    /// The token verified but has expired.
    #[error("token has expired")]
    TokenExpired,
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// The token is valid but a lease in its chain is revoked, expired or unknown. The string
    /// is a reason code (`lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`).
    #[error("lease inactive: {0}")]
    LeaseInactive(String),
    /// The token is sender-constrained (`cnf.jkt`, or the server requires DPoP for every
    /// token) and the request carries no DPoP proof (SR-24).
    #[error("a DPoP proof is required with this token")]
    DpopRequired,
    /// The request's DPoP proof is malformed, signed by the wrong key, made for another
    /// method, URL or token, outside the accepted time window, or replayed.
    #[error("invalid DPoP proof: {0}")]
    InvalidDpopProof(String),
    /// The server wants a fresh server-provided nonce in the DPoP proof (RFC 9449 §9) and the
    /// proof has none, or a stale or wrong one. The client retries with the nonce from the
    /// response's `DPoP-Nonce` header, which the server adds to every DPoP response.
    #[error("the DPoP proof needs the server's current nonce: {0}")]
    UseDpopNonce(String),
    /// The request could not be checked because of a server-side limit, not because of
    /// anything wrong with it (a full DPoP replay cache). The string is a reason code. The
    /// proxy answers `503` with `Retry-After`, not `401`, so a client does not discard a
    /// good token or key (SR-47).
    #[error("temporarily unavailable: {0}")]
    Unavailable(String),
}

/// Reason code of [`AuthError::MissingToken`].
pub const REASON_MISSING_TOKEN: &str = "missing_token";
/// Reason code of [`AuthError::InvalidToken`].
pub const REASON_INVALID_TOKEN: &str = "invalid_token";
/// Reason code of [`AuthError::TokenExpired`].
pub const REASON_TOKEN_EXPIRED: &str = "token_expired";
/// Reason code of [`AuthError::DpopRequired`].
pub const REASON_DPOP_REQUIRED: &str = "dpop_required";
/// Reason code of [`AuthError::InvalidDpopProof`].
pub const REASON_INVALID_DPOP_PROOF: &str = "invalid_dpop_proof";
/// Reason code of [`AuthError::UseDpopNonce`] (RFC 9449 §9).
pub const REASON_USE_DPOP_NONCE: &str = "use_dpop_nonce";
/// Reason code (JSON-RPC `data.reason`) for a call whose result was withheld because it could
/// not be labelled: the `tool_result` audit record or the run's taint state could not be
/// written (ADR-0009). The call ran upstream; its result never reaches the agent.
pub const REASON_LABEL_ERROR: &str = "label_error";
/// Reason code of a decision that asks for an approval (`@obligation("approval")`, ADR-0009).
/// The proxy answers it with JSON-RPC `-32008`.
pub const REASON_APPROVAL_REQUIRED: &str = "approval_required";
/// DPoP signature algorithms accepted, for `WWW-Authenticate: DPoP algs="..."` (RFC 9449 §7.1).
pub const DPOP_ALGS: &str = "EdDSA ES256";

impl AuthError {
    /// The stable reason code sent to the client (JSON-RPC `error.data.reason`).
    pub fn reason(&self) -> &str {
        match self {
            AuthError::MissingToken => REASON_MISSING_TOKEN,
            AuthError::TokenExpired => REASON_TOKEN_EXPIRED,
            AuthError::InvalidToken(_) => REASON_INVALID_TOKEN,
            AuthError::LeaseInactive(reason) => reason,
            AuthError::DpopRequired => REASON_DPOP_REQUIRED,
            AuthError::InvalidDpopProof(_) => REASON_INVALID_DPOP_PROOF,
            AuthError::UseDpopNonce(_) => REASON_USE_DPOP_NONCE,
            AuthError::Unavailable(reason) => reason,
        }
    }

    /// The `WWW-Authenticate` challenge for this error: `DPoP` (RFC 9449 §7.1) for a DPoP
    /// failure, `Bearer` otherwise.
    pub fn challenge(&self) -> String {
        match self {
            AuthError::DpopRequired => format!(
                "DPoP error=\"invalid_token\", error_description=\"{REASON_DPOP_REQUIRED}\", algs=\"{DPOP_ALGS}\""
            ),
            AuthError::InvalidDpopProof(_) => format!(
                "DPoP error=\"{REASON_INVALID_DPOP_PROOF}\", algs=\"{DPOP_ALGS}\""
            ),
            AuthError::UseDpopNonce(_) => format!(
                "DPoP error=\"{REASON_USE_DPOP_NONCE}\", error_description=\"Resource server requires nonce in DPoP proof\", algs=\"{DPOP_ALGS}\""
            ),
            _ => "Bearer realm=\"attenuo\"".to_string(),
        }
    }
}

/// What the proxy hands the [`Authorizer`] about a request (SR-24): the token, the DPoP proof
/// if one was sent, and the method and target the proof must name.
#[derive(Debug, Clone, Copy)]
pub struct RequestAuth<'a> {
    /// The token from `Authorization: Bearer <token>` or `Authorization: DPoP <token>`.
    pub token: &'a str,
    /// The single `DPoP` header, if present.
    pub dpop: Option<&'a str>,
    /// HTTP method of the request.
    pub method: &'a str,
    /// Path of the request as received, without the query.
    pub path: &'a str,
    /// The `Host` header, used to rebuild the request URL when no public URL is configured.
    pub host: Option<&'a str>,
}

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// The verified delegation chain.
    pub chain: DelegationChain,
    /// The token is sender-constrained and the request proved possession of its key.
    pub dpop_bound: bool,
    /// The token's `cnf.jkt` when `dpop_bound`: the key an approval for this hop is bound to.
    pub jkt: Option<String>,
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

    /// Authenticate a request: the token, and the DPoP proof that must accompany a
    /// sender-constrained token (SR-24). The default ignores DPoP and calls
    /// [`Authorizer::authenticate`], so authorizers that know nothing of DPoP keep working;
    /// the server's authorizer overrides it.
    async fn authenticate_request(
        &self,
        req: &RequestAuth<'_>,
        now: OffsetDateTime,
    ) -> Result<Authenticated, AuthError> {
        Ok(Authenticated {
            chain: self.authenticate(req.token, now).await?,
            dpop_bound: false,
            jkt: None,
        })
    }

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

    /// [`Authorizer::authorize`] with what the proxy knows about the call besides the chain:
    /// a presented approval token and the calling hop's key binding. The proxy always calls
    /// this. The default ignores the context, so authorizers that know nothing of approval
    /// tokens keep working; the server's authorizer overrides it.
    async fn authorize_with(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        ctx: &CallContext,
        now: OffsetDateTime,
    ) -> AuthDecision {
        let _ = ctx;
        self.authorize(chain, call, now).await
    }

    /// Is `(server, tool)` in the tool catalog behind this authorizer? Used by the proxy's
    /// `require_listed_tools` check (SR-25): a `tools/call` whose name the upstream never listed
    /// is still screened if the catalog knows it. Names are compared exactly. The default knows
    /// nothing, which leaves only the upstream's own `tools/list` results.
    fn knows_tool(&self, server: &str, tool: &str) -> bool {
        let _ = (server, tool);
        false
    }

    /// Record a request the proxy refused on its own, before any per-call decision (for
    /// example `session_mismatch`, SR-11), and return the audit record's id. `call` describes
    /// the HTTP request (`tool` = `http.POST`, `http.GET` or `http.DELETE`). Implementations
    /// that keep an audit log must append a `deny` record; the default records nothing and
    /// returns a fresh id.
    async fn record_rejection(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> Uuid {
        let _ = (chain, call, reason, now);
        Uuid::new_v4()
    }

    /// Record the upstream's answer to an allowed mediated call (`tools/call`,
    /// `resources/read`, `prompts/get`, `completion/complete`) before the proxy relays it
    /// (output labelling, ADR-0009). `result` is the JSON-RPC `result` member, or the `error`
    /// member when `is_error`; `decision_id` is the id the call's decision returned.
    ///
    /// Implementations that keep an audit log must append a `tool_result` record and, for an
    /// untrusted result, add a label to the delegation run's taint state. `Err` carries a
    /// reason code (normally [`REASON_LABEL_ERROR`]) and the proxy then withholds the result:
    /// the agent gets a JSON-RPC error instead. The default records nothing and lets every
    /// result through.
    async fn record_result(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        decision_id: Uuid,
        result: &Value,
        is_error: bool,
        now: OffsetDateTime,
    ) -> Result<(), String> {
        let _ = (chain, call, decision_id, result, is_error, now);
        Ok(())
    }

    /// Report the MCP annotations an upstream gave a tool in a `tools/list` result
    /// (`readOnlyHint`, `destructiveHint`; `None` when absent). Called for every listed tool
    /// that carries either hint, before the list is filtered. The server uses them under
    /// `[policy] import_annotations = "narrowing"`, where they can only make a tool more
    /// restricted. Called on the response path, so it must be cheap. The default ignores them.
    fn observe_tool_hints(
        &self,
        server: &str,
        tool: &str,
        read_only_hint: Option<bool>,
        destructive_hint: Option<bool>,
    ) {
        let _ = (server, tool, read_only_hint, destructive_hint);
    }

    /// Record how long one stage of a proxied request took ([`Stage::Upstream`],
    /// [`Stage::Response`], [`Stage::Total`] come from the proxy). Called on the request path,
    /// so it must be cheap. The default discards it.
    fn observe_stage(&self, stage: Stage, elapsed: Duration) {
        let _ = (stage, elapsed);
    }
}

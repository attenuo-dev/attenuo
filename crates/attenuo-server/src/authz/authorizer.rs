//! [`ServerAuthorizer`]: the proxy's [`Authorizer`], with its verified-token cache.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use attenuo_core::fingerprint::fingerprints;
use attenuo_core::{DelegationChain, OutputLabel, ToolCall};
use attenuo_proxy::{
    AuthDecision, AuthError, Authenticated, Authorizer, CallContext, RequestAuth, Stage,
};
use attenuo_token::Verifier;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::pipeline::on_blocking_pool;
use super::usage::micros;
use super::{
    result_digest, untrusted_args_json, usage_json, LimitHit, Pipeline, REASON_LABEL_ERROR,
};

/// The proxy's authorizer: token verification, DPoP ([`crate::dpop`]) and
/// [`Pipeline::decide`].
pub struct ServerAuthorizer {
    verifier: Verifier,
    pipeline: Arc<Pipeline>,
    pub(super) verified: VerifiedTokens,
    dpop: Option<Arc<crate::dpop::Dpop>>,
    trace: Option<Arc<crate::telemetry::ServerTrace>>,
}

impl ServerAuthorizer {
    /// An authorizer that verifies tokens with `verifier` and decides with `pipeline`. DPoP is
    /// not checked until [`Self::with_dpop`], so a bound token is refused until then.
    pub fn new(verifier: Verifier, pipeline: Arc<Pipeline>) -> Self {
        Self {
            verifier,
            pipeline,
            verified: VerifiedTokens::new(VERIFIED_TOKENS_CAPACITY),
            dpop: None,
            trace: None,
        }
    }

    /// Join the proxy's exported spans to outside traces through `trace` (`[telemetry]`);
    /// `None` leaves tracing off.
    pub fn with_trace(mut self, trace: Option<Arc<crate::telemetry::ServerTrace>>) -> Self {
        self.trace = trace;
        self
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
        // On the proxy's `attenuo.authenticate` span.
        tracing::Span::current().record("attenuo.token.cache", if hit { "hit" } else { "miss" });
        tracing::debug!(
            cache_hit = hit,
            token_verify_us = micros(elapsed),
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
pub(super) struct VerifiedTokens {
    pub(super) chains: Mutex<HashMap<[u8; 32], attenuo_token::VerifiedToken>>,
    capacity: usize,
}

impl VerifiedTokens {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            chains: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub(super) fn key(token: &str) -> [u8; 32] {
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

    pub(super) fn insert(
        &self,
        key: [u8; 32],
        v: &attenuo_token::VerifiedToken,
        now: OffsetDateTime,
    ) {
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
        tracing::debug!(blocking_pool_us = micros(hop), "decision returned");
        AuthDecision {
            decision: d.decision,
            reason: d.reason,
            decision_id: d.decision_id,
            approval: d.approval,
            limit: d.limit.as_ref().map(LimitHit::to_json),
            untrusted_args: (!d.untrusted_args.is_empty())
                .then(|| untrusted_args_json(&d.untrusted_args)),
            usage: d.usage.as_ref().map(usage_json),
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
        // The canonical form and the fingerprints are computed here, so the result itself is
        // not copied to the blocking pool; only its digest and fingerprints are.
        let digest = result_digest(result).map_err(|e| {
            tracing::error!(error = %e, "result has no canonical form; withholding it");
            REASON_LABEL_ERROR.to_string()
        })?;
        let spans = match self.pipeline.output_label(call) {
            OutputLabel::Untrusted => fingerprints(result),
            OutputLabel::Trusted => Vec::new(),
        };
        let (chain, call) = (chain.clone(), call.clone());
        on_blocking_pool(&self.pipeline, move |p| {
            p.record_result(&chain, &call, decision_id, digest, &spans, is_error, now)
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

    async fn screen_tools(
        &self,
        chain: &DelegationChain,
        server: &str,
        tools: &[String],
    ) -> Vec<bool> {
        let (chain, server, tools) = (chain.clone(), server.to_owned(), tools.to_vec());
        // Cedar runs on the blocking pool, as for a decision.
        on_blocking_pool(&self.pipeline, move |p| {
            p.screen_tools(&chain, &server, &tools)
        })
        .await
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

    async fn record_rejection_checked(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> Option<Uuid> {
        let (chain, call, reason) = (chain.clone(), call.clone(), reason.to_string());
        on_blocking_pool(&self.pipeline, move |p| {
            p.record_rejection_checked(&chain, &call, &reason, now)
        })
        .await
    }

    async fn record_session(
        &self,
        chain: &DelegationChain,
        server: &str,
        session_digest: &str,
        now: OffsetDateTime,
    ) {
        let (chain, server, session) = (
            chain.clone(),
            server.to_string(),
            session_digest.to_string(),
        );
        on_blocking_pool(&self.pipeline, move |p| {
            p.record_session(&chain, &server, &session, now)
        })
        .await
    }

    fn trace(&self) -> Option<&dyn attenuo_proxy::TraceHook> {
        self.trace
            .as_deref()
            .map(|t| t as &dyn attenuo_proxy::TraceHook)
    }

    fn observe_stage(&self, stage: Stage, elapsed: Duration) {
        self.pipeline.metrics().observe_stage(stage, elapsed);
    }

    fn observe_stream_end(&self, cause: attenuo_proxy::StreamEndCause) {
        self.pipeline.metrics().stream_ended(cause);
    }

    fn observe_record_suppressed(&self, tool: &'static str, reason: attenuo_proxy::StreamEndCause) {
        self.pipeline.metrics().record_suppressed(tool, reason);
    }
}

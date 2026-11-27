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
use attenuo_token::{Claims, VerifiedToken};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::pipeline::on_blocking_pool;
use super::usage::micros;
use super::{
    result_digest, untrusted_args_json, usage_json, LimitHit, Pipeline, REASON_LABEL_ERROR,
};
use crate::issuer_keys::VerifierSource;

/// The proxy's authorizer: token verification, DPoP ([`crate::dpop`]) and
/// [`Pipeline::decide`].
pub struct ServerAuthorizer {
    verifier: VerifierSource,
    pipeline: Arc<Pipeline>,
    pub(super) verified: VerifiedTokens,
    dpop: Option<Arc<crate::dpop::Dpop>>,
    trace: Option<Arc<crate::telemetry::ServerTrace>>,
    limits: Option<Arc<crate::limits::Limits>>,
    /// The server, for the `[[agents]]` in force: the revocation check of a token bound to a
    /// certificate (`crate::cert_binding::check_revocation`).
    clients: Option<Arc<crate::state::AppState>>,
}

impl ServerAuthorizer {
    /// An authorizer that verifies tokens with `verifier` (a [`attenuo_token::Verifier`], or
    /// the server's [`crate::issuer_keys::SharedKeys`], which a key reload swaps) and decides
    /// with `pipeline`. DPoP is not checked until [`Self::with_dpop`], so a bound token is
    /// refused until then.
    pub fn new(verifier: impl Into<VerifierSource>, pipeline: Arc<Pipeline>) -> Self {
        Self {
            verifier: verifier.into(),
            pipeline,
            verified: VerifiedTokens::new(VERIFIED_TOKENS_CAPACITY),
            dpop: None,
            trace: None,
            limits: None,
            clients: None,
        }
    }

    /// Check a certificate-bound token's certificate against the CRLs of its agents' entries
    /// in `state`'s `[[agents]]` (`crate::cert_binding::check_revocation`). Without this, the
    /// thumbprint alone decides.
    pub(crate) fn with_clients(mut self, state: Arc<crate::state::AppState>) -> Self {
        self.clients = Some(state);
        self
    }

    /// Count each authenticated request against `[limits] mcp_requests_per_minute` of its run
    /// ([`crate::limits`]). Without this nothing is counted.
    pub(crate) fn with_limits(mut self, limits: Arc<crate::limits::Limits>) -> Self {
        self.limits = Some(limits);
        self
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

    fn verify(&self, token: &str, now: OffsetDateTime) -> Result<Verified, AuthError> {
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
    pub(super) fn verify_inner(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<(Verified, bool), AuthError> {
        // One set of keys for the lookup and the verification; the cache entry is tied to it,
        // so a key reload is never answered from an entry the old set verified.
        let verifier = self.verifier.current();
        let key = VerifiedTokens::key(verifier.generation(), token);
        if let Some(claims) = self.verified.get(&key, now, verifier.max_depth()) {
            return Ok((
                Verified {
                    claims,
                    chain: None,
                },
                true,
            ));
        }
        let VerifiedToken { chain, claims } = verifier.verify(token, now).map_err(|e| {
            if crate::error::is_expiry(&e) {
                AuthError::TokenExpired
            } else {
                AuthError::InvalidToken(e.to_string())
            }
        })?;
        // The cache is bounded by count; a size bound per entry makes it bounded in bytes
        // (SR-46). Larger tokens are verified on every call.
        let claims = Arc::new(claims);
        if token.len() <= VERIFIED_TOKEN_MAX_BYTES {
            self.verified.insert(key, Arc::clone(&claims), now);
        }
        Ok((
            Verified {
                claims,
                chain: Some(chain),
            },
            false,
        ))
    }
}

/// A verified token as [`ServerAuthorizer::verify`] returns it.
///
/// [`VerifiedToken`] holds the chain twice, as `chain` and `claims.chain` (the same chain:
/// [`Verifier::verify`] validates `claims.chain` and returns a copy of it beside the claims).
/// The cache keeps only the claims, shared, so an entry holds one chain and a hit copies a
/// pointer; the one chain copy a hit makes is the owned chain the proxy is handed.
pub(super) struct Verified {
    /// The token's claims; `claims.chain` is the verified chain.
    pub(super) claims: Arc<Claims>,
    /// On a miss, the chain `Verifier::verify` already copied out, so a miss does not copy
    /// it again; `None` on a hit.
    chain: Option<DelegationChain>,
}

impl Verified {
    /// The verified chain, owned.
    pub(super) fn into_chain(self) -> DelegationChain {
        match self.chain {
            Some(chain) => chain,
            None => self.claims.chain.clone(),
        }
    }
}

/// Tokens kept by the verified-token cache (`VerifiedTokens`).
pub const VERIFIED_TOKENS_CAPACITY: usize = 4096;

/// Largest token the verified-token cache (`VerifiedTokens`) keeps, in bytes. A token of a few hops with ordinary
/// capabilities is 1 to 4 KiB; a child can carry an arbitrarily long constraint list (a
/// narrowing of its parent), which would make the cache's 4096 entries hundreds of MiB (SR-46).
pub const VERIFIED_TOKEN_MAX_BYTES: usize = 16 * 1024;

/// Claims of tokens that already passed [`attenuo_token::Verifier::verify`], keyed by the
/// SHA-256 of the generation of the keys that verified them and the exact token text. An entry is the claims alone: `claims.chain` is the verified chain, and
/// the copy [`VerifiedToken`] keeps beside it is not stored.
///
/// An agent sends the same bearer token on every call, and verifying it (two Ed25519
/// signatures, JSON decoding, structural checks) costs about 100 us, the largest single stage
/// after the policy. None of that can change for a given set of keys: the trusted keys are fixed
/// within one generation (a key reload starts the next, whose lookups miss every older entry),
/// and the token's bytes are what was signed. The only
/// time-dependent checks are expiry, so a cache hit re-runs `validate_at(now)` (every hop's
/// expiry, which includes the token's `exp`, the last hop's) and nothing is cached for a token
/// that failed. Lease revocation is unaffected: leases are checked on every call.
///
/// Bounded: when full, expired chains are dropped, and if that frees nothing the map is
/// cleared (the next calls simply verify again).
pub(super) struct VerifiedTokens {
    pub(super) chains: Mutex<HashMap<[u8; 32], Arc<Claims>>>,
    capacity: usize,
}

impl VerifiedTokens {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            chains: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// The key of `token` verified by the keys of `generation`
    /// ([`crate::issuer_keys::IssuerKeys::generation`]).
    pub(super) fn key(generation: u64, token: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::new()
            .chain_update(generation.to_be_bytes())
            .chain_update(token.as_bytes())
            .finalize()
            .into()
    }

    /// The cached claims, if their chain is still valid at `now`.
    fn get(&self, key: &[u8; 32], now: OffsetDateTime, max_depth: usize) -> Option<Arc<Claims>> {
        let chains = self.chains.lock().ok()?;
        let claims = chains.get(key)?;
        claims.chain.validate_at(now, max_depth).ok()?;
        Some(Arc::clone(claims))
    }

    pub(super) fn insert(&self, key: [u8; 32], claims: Arc<Claims>, now: OffsetDateTime) {
        let Ok(mut chains) = self.chains.lock() else {
            return;
        };
        if chains.len() >= self.capacity {
            chains.retain(|_, c| c.chain.hops.iter().all(|h| h.expires_at > now));
            if chains.len() >= self.capacity {
                chains.clear();
            }
        }
        chains.insert(key, claims);
    }
}

#[async_trait]
impl Authorizer for ServerAuthorizer {
    /// Without the request there is no DPoP proof and no client certificate to check: a bound
    /// token is refused.
    async fn authenticate(
        &self,
        bearer: &str,
        now: OffsetDateTime,
    ) -> Result<DelegationChain, AuthError> {
        let v = self.verify(bearer, now)?;
        match crate::cert_binding::Binding::of(v.claims.cnf.as_ref()) {
            crate::cert_binding::Binding::None => Ok(v.into_chain()),
            crate::cert_binding::Binding::Dpop => Err(AuthError::DpopRequired),
            crate::cert_binding::Binding::Cert => {
                Err(crate::cert_binding::CertFailure::Required.into())
            }
        }
    }

    async fn authenticate_request(
        &self,
        req: &RequestAuth<'_>,
        now: OffsetDateTime,
    ) -> Result<Authenticated, AuthError> {
        let v = self.verify(req.token, now)?;
        let binding = match &self.dpop {
            Some(dpop) => {
                // An `[[ext_authz]]` entry names the gateway URL the agent's proof is for.
                let url = req
                    .url
                    .map_or_else(|| dpop.expected_url(req.host, req.path), str::to_owned);
                // A token bound to a certificate needs the request's certificate, which the
                // proxy has from the server (`crate::cert_binding::expose_to_proxy`); the
                // gateway route never passes one.
                crate::cert_binding::check_presented(
                    dpop,
                    &crate::cert_binding::Presented {
                        cnf: v.claims.cnf.as_ref(),
                        token: req.token,
                        proof: req.dpop,
                        dpop_scheme: req.dpop_scheme,
                        cert: req.client_cert.as_ref(),
                        method: req.method,
                        url: &url,
                    },
                    now,
                )?
            }
            // Without the DPoP checker (unit tests only), a bound token is refused.
            None => match crate::cert_binding::Binding::of(v.claims.cnf.as_ref()) {
                crate::cert_binding::Binding::None => crate::cert_binding::Binding::None,
                crate::cert_binding::Binding::Dpop => return Err(AuthError::DpopRequired),
                crate::cert_binding::Binding::Cert => {
                    return Err(crate::cert_binding::CertFailure::Required.into())
                }
            },
        };
        // A token bound to the request's certificate: that certificate still passes the check
        // of its agents' entries with CRLs. Only for such a token: nothing more for others.
        if binding.cert() {
            if let Some(state) = &self.clients {
                let cert = crate::cert_binding::request_certificate();
                crate::cert_binding::check_revocation(
                    &state.clients,
                    &v.claims.chain,
                    cert.as_ref(),
                    now,
                )?;
            }
        }
        let dpop_bound = binding.dpop();
        // The key an approval for this hop is bound to: only when the request proved it.
        let jkt = dpop_bound
            .then(|| {
                v.claims
                    .cnf
                    .as_ref()
                    .and_then(|c| c.key_thumbprint().map(str::to_owned))
            })
            .flatten();
        // The per-run rate limit, keyed by the root lease: known from the verified token (a
        // cache hit after the first request), before any lease lookup, decision, audit append
        // or upstream call. Counted only once the token and its DPoP proof verified, so a
        // caller without the token's key cannot use up a run's requests.
        if let Some(limits) = &self.limits {
            if let Some(run) = v.claims.chain.hops.first().map(|h| h.lease.0.as_str()) {
                limits.admit_mcp(run).map_err(AuthError::RateLimited)?;
            }
        }
        Ok(Authenticated {
            chain: v.into_chain(),
            dpop_bound,
            jkt,
            cert_bound: binding.cert(),
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
        // The narrowing is shared by every engine a reload builds from this one, so importing
        // into the snapshot holds for the engine in force whatever is swapped in meanwhile.
        let engine = self.pipeline.policy_snapshot();
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

    fn subject_log(&self) -> &attenuo_proxy::SubjectLog {
        self.pipeline.subject_log()
    }

    fn knows_tool(&self, server: &str, tool: &str) -> bool {
        self.pipeline
            .policy_snapshot()
            .catalog()
            .contains(server, tool)
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

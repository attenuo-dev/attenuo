//! `POST /token/renew`: extend the lease of the token's last hop.
//!
//! The bearer is a delegation token. Only the last hop's lease is renewed: an agent keeps its
//! own lease alive and cannot refresh its parent's. The new expiry is
//!
//! ```text
//! min(now + [issuer] lease_interval_seconds, token exp, parent lease expiry)
//! ```
//!
//! and never earlier than the current expiry. Renewal fails (400 `invalid_grant`, with `code`
//! `lease_revoked`, `lease_expired` or `lease_unknown`) when the lease, or any ancestor lease,
//! is revoked or unknown, or when an ancestor lease has expired: a child cannot outlive a
//! parent that stopped renewing. An expired or invalid *token* is a
//! 401. A token bound to a key (`cnf.jkt`) needs a DPoP proof for `POST /token/renew`
//! ([`crate::dpop`]); a token bound to a TLS client certificate (`cnf.x5t#S256`) needs a
//! request that shows that certificate (`crate::cert_binding`). Every renewal is appended to
//! the audit log (`attenuo` / `lease.renew`, reason `lease_renewed`, with `dpop_bound`, and
//! `cert_bound` for a certificate-bound token).
//!
//! **Audited refusals.** Once the token has verified (signature, audience, expiry, chain) and
//! so has its DPoP proof, a refused renewal is recorded through
//! [`crate::authz::Pipeline::record_rejection`]: one `deny` record of kind `decision` against
//! the token's chain, server `attenuo`, tool `lease.renew` (the tool of a successful renewal,
//! so `--tool lease.renew` finds both), and a reason from [`RENEW_REFUSAL_REASONS`]:
//! `lease_revoked`, `lease_expired` (an ancestor's) or `lease_unknown`. The arguments digest
//! covers `{lease, ancestor, dpop_bound}`, `ancestor` saying whether an ancestor lease or the
//! token's own lease refused. The 400 carries the record id in `X-Attenuo-Decision-Id` and
//! `decision_id`, and the record is counted in `decisions_total{decision="deny",reason}`. Not
//! recorded: a missing token, a token or DPoP proof that does not verify (a log line only,
//! SR-18), and lease store faults (500).
//!
//! Response: `{ "lease": "<id>", "expires_at": "<RFC 3339>", "expires_in": <seconds> }`.

use std::sync::Arc;

use attenuo_audit::{AuditError, LeaseRegistry};
use attenuo_core::{DelegationChain, RecordKind, ToolCall};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::authz::{REASON_LEASE_EXPIRED, REASON_LEASE_REVOKED, REASON_LEASE_UNKNOWN};

use super::{audit_event, bearer_of, no_store};
use crate::client_cert::ClientCertificate;
use crate::error::ApiError;
use crate::state::AppState;

/// `POST /token/renew`: extend the lease of the bearer token's last hop (see the module
/// docs).
///
/// # Errors
///
/// As the module docs say: 401 for a missing, invalid or expired token or a failed DPoP proof; 400
/// `invalid_grant` (audited, with its `decision_id`, and the lease reason as `code`) when the
/// lease or an ancestor lease is revoked or unknown, or an ancestor lease has expired; 500 `server_error` when the lease store fails or
/// the renewal cannot be audited.
pub async fn renew(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
) -> Result<Response, ApiError> {
    // Lease and audit I/O is SQLite: keep it off the async workers.
    state
        .blocking(move |s| renew_sync(s, &headers, &extensions))
        .await
}

fn renew_sync(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> Result<Response, ApiError> {
    let bearer = bearer_of(headers)?.ok_or_else(|| {
        ApiError::unauthorized(
            crate::error::REASON_MISSING_TOKEN,
            "a delegation token bearer is required",
        )
    })?;
    let now = state.now();
    let verified = state
        .keys()
        .verifier
        .verify(bearer, now)
        .map_err(|e| ApiError::bad_token(&e))?;
    // A request on a listener that shows no certificate has none here: a token bound to one
    // is then refused.
    let cert = extensions.get::<ClientCertificate>();
    let binding = crate::cert_binding::check_presented(
        &state.dpop,
        &crate::cert_binding::Presented {
            cnf: verified.claims.cnf.as_ref(),
            token: bearer,
            proof: crate::dpop::header_proof(headers)?,
            dpop_scheme: crate::cert_binding::dpop_scheme(headers),
            cert: cert.map(ClientCertificate::sha256),
            method: "POST",
            url: &state.dpop.expected_url_for(headers, "/token/renew"),
        },
        now,
    )?;
    if binding.cert() {
        crate::cert_binding::check_revocation(&state.clients, cert, now)?;
    }
    let dpop_bound = binding.dpop();
    let chain = verified.chain;
    match renew_verified(state, &chain, binding, now) {
        Ok(resp) => Ok(resp),
        Err(Failure::Other(e)) => Err(e),
        Err(Failure::Refused {
            reason,
            ancestor,
            error,
        }) => {
            // One `deny` record against the verified chain, under the fixed tool name of a
            // renewal. Lease ids are not secret and come from the signed token.
            let mut args = json!({
                "lease": chain.hops.last().map(|h| &h.lease),
                "ancestor": ancestor,
                "dpop_bound": dpop_bound,
            });
            binding.add_to(&mut args);
            let call = ToolCall::new(super::AUDIT_SERVER, RENEW_TOOL, args)
                .with_dpop_bound(dpop_bound)
                .with_cert_bound(binding.cert());
            let id = state.pipeline.record_rejection(&chain, &call, reason, now);
            Err(error.with_decision_id(id))
        }
    }
}

/// Every reason code a refused renewal can be audited with. All are lease reasons: once the
/// token verified, the only refusals the caller causes are a lease (its own, or an ancestor's)
/// that is revoked or unknown, or an ancestor that has expired; the token's own lease may have
/// lapsed, which is what renewal repairs. So there is no `renew_*` code.
pub const RENEW_REFUSAL_REASONS: [&str; 3] = [
    REASON_LEASE_REVOKED,
    REASON_LEASE_EXPIRED,
    REASON_LEASE_UNKNOWN,
];

/// The audit `tool` of a renewal, successful or refused.
const RENEW_TOOL: &str = "lease.renew";

/// Why a renewal failed once its token verified.
enum Failure {
    /// Refused for a lease reason: audited as a `deny` record whose id the response carries.
    /// `ancestor` says whether an ancestor lease or the token's own lease refused.
    Refused {
        reason: &'static str,
        ancestor: bool,
        error: ApiError,
    },
    /// A server fault (lease store, audit append): not audited.
    Other(ApiError),
}

impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        Failure::Other(e)
    }
}

impl From<AuditError> for Failure {
    fn from(e: AuditError) -> Self {
        Failure::Other(e.into())
    }
}

/// A refusal of the token's own lease. `code` is the lease reason (`detail` has carried it
/// since before `code` existed, and still does).
fn own_lease_refused(reason: &'static str) -> Failure {
    Failure::Refused {
        reason,
        ancestor: false,
        error: ApiError::bad_request("invalid_grant", reason).with_code(reason),
    }
}

/// The renewal once the token (and its DPoP proof) verified: every refusal from here on that
/// the caller caused is a [`Failure::Refused`].
fn renew_verified(
    state: &AppState,
    chain: &DelegationChain,
    binding: crate::cert_binding::Binding,
    now: OffsetDateTime,
) -> Result<Response, Failure> {
    let hop = chain
        .hops
        .last()
        .ok_or_else(|| ApiError::internal("token has no hops"))?;

    // Every ancestor must still be live; the hop's own lease is checked by `renew` (it may
    // have lapsed, which is exactly what renewal repairs, but it may not be revoked).
    let leases = chain.leases();
    let ancestors = &leases[..leases.len() - 1];
    let status = state.leases.check_all(ancestors, now)?;
    if !status.active {
        let reason = if !status.revoked.is_empty() {
            REASON_LEASE_REVOKED
        } else if !status.expired.is_empty() {
            REASON_LEASE_EXPIRED
        } else {
            REASON_LEASE_UNKNOWN
        };
        return Err(Failure::Refused {
            reason,
            ancestor: true,
            error: ApiError::bad_request(
                "invalid_grant",
                format!("an ancestor lease is not live: {reason}"),
            )
            .with_code(reason),
        });
    }

    let Some(previous) = state.leases.get(&hop.lease)? else {
        return Err(own_lease_refused(REASON_LEASE_UNKNOWN));
    };
    let mut new_expiry = state.initial_lease_expiry(now, hop.expires_at);
    if chain.hops.len() >= 2 {
        let parent_lease = &chain.hops[chain.hops.len() - 2].lease;
        if let Some(parent) = state.leases.get(parent_lease)? {
            new_expiry = new_expiry.min(parent.expires_at);
        }
    }
    // Renewal extends; it never shortens a lease.
    let new_expiry = new_expiry.max(previous.expires_at);

    state
        .leases
        .renew(&hop.lease, new_expiry, now)
        .map_err(|e| match e {
            AuditError::LeaseRevoked(_) => own_lease_refused(REASON_LEASE_REVOKED),
            AuditError::UnknownLease(_) => own_lease_refused(REASON_LEASE_UNKNOWN),
            other => other.into(),
        })?;

    let mut args = json!({
        "lease": hop.lease,
        "previous_expires_at": previous.expires_at.format(&Rfc3339).unwrap_or_default(),
        "expires_at": new_expiry.format(&Rfc3339).unwrap_or_default(),
    });
    binding.add_to(&mut args);
    if let Err(e) = audit_event(
        state,
        RecordKind::LeaseRenew,
        RENEW_TOOL,
        chain,
        args,
        binding,
        now,
    ) {
        // A renewal we cannot record does not happen.
        let _ = state.leases.renew(&hop.lease, previous.expires_at, now);
        return Err(e.into());
    }
    tracing::info!(lease = %hop.lease.0, expires_at = %new_expiry, "lease renewed");

    let expires_in = (new_expiry - now).whole_seconds().max(0);
    let mut out = Json(json!({
        "lease": hop.lease,
        "expires_at": new_expiry.format(&Rfc3339).map_err(ApiError::internal)?,
        "expires_in": expires_in,
    }))
    .into_response();
    no_store(out.headers_mut());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renew_refusal_reasons_are_the_lease_reasons() {
        // The metric label set stays fixed: every reason is a known lease code, none is
        // `lease_error` (a store fault is a 500, not a refusal).
        for r in RENEW_REFUSAL_REASONS {
            assert!(r.starts_with("lease_"), "{r}");
            assert_ne!(r, crate::authz::REASON_LEASE_ERROR);
        }
        assert_eq!(RENEW_TOOL, "lease.renew");
    }
}

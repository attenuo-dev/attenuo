//! `POST /token/renew`: extend the lease of the token's last hop.
//!
//! The bearer is a delegation token. Only the last hop's lease is renewed: an agent keeps its
//! own lease alive and cannot refresh its parent's. The new expiry is
//!
//! ```text
//! min(now + [issuer] lease_interval_seconds, token exp, parent lease expiry)
//! ```
//!
//! and never earlier than the current expiry. Renewal fails (400 `invalid_grant`) when the
//! lease, or any ancestor lease, is revoked or unknown, or when an ancestor lease has expired:
//! a child cannot outlive a parent that stopped renewing. An expired or invalid *token* is a
//! 401. Every renewal is appended to the audit log (`onbehalf` / `lease.renew`,
//! reason `lease_renewed`).
//!
//! Response: `{ "lease": "<id>", "expires_at": "<RFC 3339>", "expires_in": <seconds> }`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::{AuditError, LeaseStore};
use serde_json::json;
use time::format_description::well_known::Rfc3339;

use super::{audit_event, bearer_of, no_store, now, REASON_LEASE_RENEWED};
use crate::error::ApiError;
use crate::state::AppState;

pub async fn renew(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Lease and audit I/O is SQLite: keep it off the async workers.
    state.blocking(move |s| renew_sync(s, &headers)).await
}

fn renew_sync(state: &AppState, headers: &HeaderMap) -> Result<Response, ApiError> {
    let bearer = bearer_of(headers)?.ok_or_else(|| {
        ApiError::unauthorized(
            crate::error::REASON_MISSING_TOKEN,
            "a delegation token bearer is required",
        )
    })?;
    let now = now();
    let verified = state
        .verifier
        .verify(bearer, now)
        .map_err(|e| ApiError::bad_token(&e))?;
    let chain = verified.chain;
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
            "lease_revoked"
        } else if !status.expired.is_empty() {
            "lease_expired"
        } else {
            "lease_unknown"
        };
        return Err(ApiError::bad_request(
            "invalid_grant",
            format!("an ancestor lease is not live: {reason}"),
        ));
    }

    let previous = state
        .leases
        .get(&hop.lease)?
        .ok_or_else(|| ApiError::bad_request("invalid_grant", "lease_unknown"))?;
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
            AuditError::LeaseRevoked(_) => ApiError::bad_request("invalid_grant", "lease_revoked"),
            AuditError::UnknownLease(_) => ApiError::bad_request("invalid_grant", "lease_unknown"),
            other => other.into(),
        })?;

    let args = json!({
        "lease": hop.lease,
        "previous_expires_at": previous.expires_at.format(&Rfc3339).unwrap_or_default(),
        "expires_at": new_expiry.format(&Rfc3339).unwrap_or_default(),
    });
    if let Err(e) = audit_event(
        state,
        REASON_LEASE_RENEWED,
        "lease.renew",
        &chain,
        args,
        now,
    ) {
        // A renewal we cannot record does not happen.
        let _ = state.leases.renew(&hop.lease, previous.expires_at, now);
        return Err(e);
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

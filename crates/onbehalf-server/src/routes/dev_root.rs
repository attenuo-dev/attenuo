//! `POST /admin/root-token`: mint a hop-0 token directly. **Development only.**
//!
//! RFC-0001 §4 says hop 0 is minted from a verified user credential (an OIDC ID token or an
//! ID-JAG assertion checked against the IdP's JWKS). That intake is not implemented yet. This
//! endpoint stands in for it: an operator holding the admin token asserts who the user is and
//! which agent acts for them. Nothing about the user is verified, so the endpoint sits behind
//! the admin bearer and, when `[[root_grants]]` is configured, is limited to those grants.
//!
//! Body: `{ subject, issuer, agent, capabilities?, ttl_seconds?, attributes? }`, where
//! `capabilities` is a list of `"server:tool"` strings or capability objects. The response has
//! the same shape as a `/token` response.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::LeaseStore;
use onbehalf_core::{AgentId, CapabilitySet, OriginatingUser};
use onbehalf_token::ExchangeResponse;
use serde::Deserialize;
use serde_json::{json, Value};
use time::Duration;

use super::{audit_issuance, no_store, now, parse_json};
use crate::config::{capability_set, CapSpec, RootGrant};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTokenRequest {
    pub subject: String,
    pub issuer: String,
    pub agent: String,
    #[serde(default)]
    pub capabilities: Option<Vec<CapSpec>>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

pub async fn mint_root(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let req: RootTokenRequest = parse_json(&body)?;
    let (capabilities, grant_attributes) = resolve_grant(&state.root_grants, &req)?;
    let attributes = merge_attributes(grant_attributes, &req.attributes)?;

    let now = now();
    let ttl = req
        .ttl_seconds
        .map(|s| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)));
    let user = OriginatingUser {
        subject: req.subject.clone(),
        issuer: req.issuer.clone(),
        authenticated_at: now,
        attributes,
    };
    let issued = state.issuer.issue_root(
        user,
        AgentId::new(req.agent.clone()),
        capabilities,
        ttl,
        now,
    )?;
    state
        .leases
        .register(&issued.lease, None, issued.expires_at)?;
    let args = json!({ "agent": req.agent, "requested": issued.chain.hops[0].capabilities });
    if let Err(e) = audit_issuance(&state, "token.root", &issued.chain, args, now) {
        let _ = state.leases.revoke(&issued.lease, "audit_error", now);
        return Err(e);
    }
    tracing::warn!(
        subject = %req.subject,
        agent = %req.agent,
        lease = %issued.lease.0,
        "dev root token minted (no user credential verified)"
    );
    let mut out = Json(ExchangeResponse::from_issued(&issued, now)).into_response();
    no_store(out.headers_mut());
    Ok(out)
}

/// Apply the `[[root_grants]]` allowlist. Returns the capabilities to grant and the grant's
/// attributes (request attributes are merged over them by the caller).
fn resolve_grant(
    grants: &[RootGrant],
    req: &RootTokenRequest,
) -> Result<(CapabilitySet, BTreeMap<String, Value>), ApiError> {
    let requested = req
        .capabilities
        .as_deref()
        .map(capability_set)
        .transpose()
        .map_err(|e| ApiError::bad_request("invalid_scope", e))?;
    if grants.is_empty() {
        let caps = requested
            .ok_or_else(|| ApiError::bad_request("invalid_request", "capabilities are required"))?;
        return Ok((caps, BTreeMap::new()));
    }
    let grant = grants
        .iter()
        .find(|g| g.subject == req.subject && g.issuer == req.issuer && g.agent == req.agent)
        .ok_or_else(|| {
            ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "no_root_grant",
                format!(
                    "no [[root_grants]] entry for subject `{}` (issuer `{}`) and agent `{}`",
                    req.subject, req.issuer, req.agent
                ),
            )
        })?;
    let ceiling = capability_set(&grant.capabilities).map_err(ApiError::internal)?;
    let caps = match requested {
        None => ceiling,
        Some(r) => ceiling
            .attenuate(&r)
            .map_err(|e| ApiError::bad_request("invalid_scope", e.to_string()))?,
    };
    Ok((caps, grant.attributes.clone()))
}

/// Request attributes may add to a grant's attributes but never replace one: a grant that says
/// `mfa = false` is a ceiling, like its capabilities, and policies key on these attributes.
fn merge_attributes(
    mut grant: BTreeMap<String, Value>,
    requested: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, ApiError> {
    for (k, v) in requested {
        match grant.get(k) {
            Some(fixed) if fixed != v => {
                return Err(ApiError::new(
                    axum::http::StatusCode::FORBIDDEN,
                    "attribute_fixed_by_grant",
                    format!("attribute `{k}` is fixed by the [[root_grants]] entry"),
                ))
            }
            Some(_) => {}
            None => {
                grant.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(caps: Option<Vec<&str>>) -> RootTokenRequest {
        RootTokenRequest {
            subject: "alice".into(),
            issuer: "idp".into(),
            agent: "planner".into(),
            capabilities: caps.map(|v| v.into_iter().map(|s| CapSpec::Short(s.into())).collect()),
            ttl_seconds: None,
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn grants_cap_what_can_be_minted() {
        let grants = vec![RootGrant {
            subject: "alice".into(),
            issuer: "idp".into(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short("github:read_*".into())],
            attributes: BTreeMap::new(),
        }];
        assert_eq!(resolve_grant(&grants, &req(None)).unwrap().0.len(), 1);
        assert!(resolve_grant(&grants, &req(Some(vec!["github:read_file"]))).is_ok());
        let wider = resolve_grant(&grants, &req(Some(vec!["github:*"]))).unwrap_err();
        assert_eq!(wider.code, "invalid_scope");
        let mut other = req(None);
        other.subject = "mallory".into();
        assert_eq!(
            resolve_grant(&grants, &other).unwrap_err().code,
            "no_root_grant"
        );
    }

    /// SR-07: request attributes used to override the grant's (`mfa = false` -> `true`).
    #[test]
    fn request_cannot_override_grant_attributes() {
        let grant = BTreeMap::from([("mfa".to_string(), json!(false))]);
        let lie = BTreeMap::from([("mfa".to_string(), json!(true))]);
        let err = merge_attributes(grant.clone(), &lie).unwrap_err();
        assert_eq!(err.code, "attribute_fixed_by_grant");
        // restating the same value and adding new keys is fine
        let ok = BTreeMap::from([
            ("mfa".to_string(), json!(false)),
            ("tenant".to_string(), json!("acme")),
        ]);
        let merged = merge_attributes(grant, &ok).unwrap();
        assert_eq!(merged["mfa"], json!(false));
        assert_eq!(merged["tenant"], json!("acme"));
    }

    #[test]
    fn without_grants_capabilities_are_required() {
        assert!(resolve_grant(&[], &req(None)).is_err());
        assert!(resolve_grant(&[], &req(Some(vec!["github:*"]))).is_ok());
    }
}

//! `POST /admin/root-token`: mint a hop-0 token directly. **Development only.**
//!
//! Real hop-0 intake verifies a user credential from a trusted IdP (an OIDC ID token or an
//! ID-JAG) at `POST /token`; see `crate::idp`. This endpoint skips that: an operator holding
//! the admin token asserts who the user is and which agent acts for them. Nothing about the
//! user is verified, so the route is mounted only when `[dev] allow_root_mint = true` (the
//! server logs a warning at startup when it is), sits behind the admin bearer and, when
//! `[[root_grants]]` is configured, is limited to those grants.
//!
//! Body: `{ subject, issuer, agent, capabilities?, ttl_seconds?, attributes?, may_act? }`, where
//! `capabilities` is a list of `"server:tool"` strings or capability objects and `may_act` is
//! the RFC 8693 §4.4 claim for the root token (a list of agent ids, or `{"sub": [...]}`;
//! within the grant's `may_act` when it has one). The response has
//! the same shape as a `/token` response.

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_audit::LeaseRegistry;
use attenuo_core::{AgentId, CapabilitySet, OriginatingUser};
use attenuo_token::{ExchangeResponse, IssueOptions, MayAct};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use time::Duration;

use super::extract::Body;
use super::{
    audit_admin, audit_issuance, no_store, parse_json, register_issued, REASON_ADMIN_ACTION,
};
use crate::config::{capability_set, CapSpec, RootGrant};
use crate::error::ApiError;
use crate::state::AppState;
use attenuo_core::Decision;

/// Body of `POST /admin/root-token` (see the module docs).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTokenRequest {
    /// The user's subject, as asserted by the operator and never verified.
    pub subject: String,
    /// The user's IdP issuer, as asserted by the operator.
    pub issuer: String,
    /// The agent acting for the user: the root hop's agent id. `attenuo` is reserved.
    pub agent: String,
    /// `"server:tool"` strings or capability objects. Required when `[[root_grants]]` is
    /// empty; otherwise attenuated against the matching grant, which it defaults to.
    #[serde(default)]
    pub capabilities: Option<Vec<CapSpec>>,
    /// Token lifetime in seconds; `[issuer] default_ttl_seconds` when absent.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// User attributes, merged over the grant's; a request may add an attribute but not change
    /// one the grant sets (403 `attribute_fixed_by_grant`).
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// RFC 8693 §4.4 `may_act` of the root token; within the grant's when it has one.
    #[serde(default)]
    pub may_act: Option<MayAct>,
}

/// `POST /admin/root-token`: mint a hop-0 token for an unverified user. Development only.
///
/// # Errors
///
/// 400 `invalid_request` for a body that is not a [`RootTokenRequest`], a reserved subject or
/// agent, missing capabilities or a `may_act` beyond the grant; 400 `invalid_scope` for
/// capabilities that do not parse or exceed the grant; 403 `no_root_grant` when `[[root_grants]]`
/// has no entry for the request and 403 `attribute_fixed_by_grant` when it changes a granted
/// attribute; 401 for a bad DPoP proof; 500 `server_error` when the token cannot be signed,
/// registered or audited.
pub async fn mint_root(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Body(body): Body,
) -> Result<Response, ApiError> {
    let req: RootTokenRequest = parse_json(&body)?;
    state
        .blocking(move |s| mint_root_sync(s, &headers, req))
        .await
}

fn mint_root_sync(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    req: RootTokenRequest,
) -> Result<Response, ApiError> {
    // The server's own audit records use these names (SR-34).
    if super::is_reserved_subject(&req.subject) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "subject uses a prefix reserved for the server's own records",
        )
        .with_description("reserved_subject"));
    }
    if req.agent == super::AUDIT_SERVER {
        return Err(ApiError::bad_request(
            "invalid_request",
            "agent id `attenuo` is reserved for the server's own records",
        )
        .with_description("reserved_agent"));
    }
    let (capabilities, grant_attributes, may_act) = resolve_grant(&state.root_grants, &req)?;
    let attributes = merge_attributes(grant_attributes, &req.attributes)?;

    let now = state.now();
    // DPoP (SR-24): a `DPoP` header binds the root token to its key, per `[token] dpop`.
    let cnf = state.dpop.bind_new(
        crate::dpop::header_proof(headers)?,
        "POST",
        &state.dpop.expected_url_for(headers, "/admin/root-token"),
        now,
    )?;
    let dpop_bound = cnf.is_some();
    let ttl = req
        .ttl_seconds
        .map(|s| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)));
    let user = OriginatingUser {
        subject: req.subject.clone(),
        issuer: req.issuer.clone(),
        authenticated_at: now,
        attributes,
    };
    let issued = state.issuer.issue_root_with(
        user,
        AgentId::new(req.agent.clone()),
        capabilities,
        ttl,
        now,
        &IssueOptions {
            may_act,
            not_after: None,
            cnf,
        },
    )?;
    register_issued(
        state,
        &issued.token,
        &issued.lease,
        None,
        issued.expires_at,
        now,
    )?;
    let args = json!({ "agent": req.agent, "requested": issued.chain.hops[0].capabilities });
    let admin_args = json!({
        "subject": req.subject,
        "issuer": req.issuer,
        "agent": req.agent,
        "lease": issued.lease,
    });
    let recorded = audit_issuance(state, "token.root", &issued.chain, args, dpop_bound, now)
        .and_then(|_| {
            audit_admin(
                state,
                "admin.root_token",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                vec![issued.lease.clone()],
                admin_args,
                now,
            )
        });
    if let Err(e) = recorded {
        let _ = state.leases.revoke(&issued.lease, "audit_error", now);
        return Err(e);
    }
    tracing::warn!(
        subject = ?state.pipeline.subject_log().show(&req.subject),
        agent = ?req.agent,
        lease = %issued.lease.0,
        "dev root token minted (no user credential verified)"
    );
    let mut out = Json(ExchangeResponse::from_issued(&issued, now)).into_response();
    no_store(out.headers_mut());
    Ok(out)
}

/// What a grant allows: capabilities, attributes, `may_act`.
type Granted = (CapabilitySet, BTreeMap<String, Value>, Option<MayAct>);

/// Apply the `[[root_grants]]` allowlist. Returns the capabilities to grant, the grant's
/// attributes (request attributes are merged over them by the caller) and the `may_act`.
fn resolve_grant(grants: &[RootGrant], req: &RootTokenRequest) -> Result<Granted, ApiError> {
    let requested = req
        .capabilities
        .as_deref()
        .map(capability_set)
        .transpose()
        .map_err(|e| ApiError::bad_request("invalid_scope", e))?;
    if grants.is_empty() {
        let caps = requested
            .ok_or_else(|| ApiError::bad_request("invalid_request", "capabilities are required"))?;
        return Ok((caps, BTreeMap::new(), req.may_act.clone()));
    }
    let grant =
        RootGrant::find(grants, &req.issuer, &req.agent, &req.subject).ok_or_else(|| {
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
    let may_act = grant.may_act_for(req.may_act.clone()).map_err(|e| {
        ApiError::bad_request("invalid_request", e).with_description("may_act_exceeds_grant")
    })?;
    Ok((caps, grant.attributes.clone(), may_act))
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
            may_act: None,
        }
    }

    #[test]
    fn grants_cap_what_can_be_minted() {
        let grants = vec![RootGrant {
            subject: Some("alice".into()),
            issuer: "idp".into(),
            agent: "planner".into(),
            capabilities: vec![CapSpec::Short("github:read_*".into())],
            attributes: BTreeMap::new(),
            may_act: None,
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

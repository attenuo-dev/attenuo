//! The `POST /token` branch that mints hop 0 from an IdP credential.
//!
//! Request fields (form or JSON, as for every `/token` request):
//!
//! | Field | Notes |
//! |---|---|
//! | `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange`, or `urn:ietf:params:oauth:grant-type:jwt-bearer` for an ID-JAG |
//! | `subject_token` | the ID token or ID-JAG (token exchange) |
//! | `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` or `urn:ietf:params:oauth:token-type:id-jag` |
//! | `assertion` | the ID-JAG (jwt-bearer) |
//! | `client_id`, `client_secret` | the agent's credentials from `[[agents]]`; HTTP Basic also accepted (RFC 6749 §2.3.1) |
//! | `actor` | optional; must equal `client_id` when given |
//! | `authorization_details` / `scope` | requested capabilities, as for an exchange |
//! | `requested_ttl_seconds` | optional |
//!
//! Steps, in order: authenticate the agent (`invalid_client`, 401); check `actor` and that
//! capabilities were requested (`invalid_request`); verify the credential
//! ([`IdpRegistry::verify`](super::IdpRegistry::verify), `invalid_grant`); for an ID-JAG,
//! require its `client_id` to be the authenticated agent; build the originating user
//! ([`claims::originating_user`]); find the `[[root_grants]]` entry for (issuer, agent,
//! subject) and attenuate the request against it (`invalid_scope`); then `Issuer::issue_root`,
//! register the lease, and audit as `token.root` / `token_issued`.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::LeaseStore;
use onbehalf_core::{AgentId, CapabilitySet};
use onbehalf_token::{ExchangeResponse, AUTHORIZATION_DETAILS_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};
use serde::Deserialize;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use super::JWT_BEARER_GRANT_TYPE;
use super::{claims, CredentialKind, IntakeError, ID_JAG_TOKEN_TYPE, ID_TOKEN_TYPE};
use crate::clientauth::{self, invalid_request, ClientKind};
use crate::config::{capability_set, AgentConfig, RootGrant};
use crate::error::ApiError;
use crate::routes::{audit_issuance, no_store, register_issued};
use crate::state::AppState;

/// Does this `/token` request carry an IdP credential (rather than an onbehalf token)?
pub fn is_intake(body: &Value) -> bool {
    let s = |k: &str| body.get(k).and_then(Value::as_str);
    matches!(
        s("subject_token_type"),
        Some(ID_TOKEN_TYPE) | Some(ID_JAG_TOKEN_TYPE)
    ) || s("grant_type") == Some(JWT_BEARER_GRANT_TYPE)
}

#[derive(Debug, Deserialize)]
struct Detail {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    capabilities: CapabilitySet,
}

#[derive(Debug, Deserialize)]
struct IntakeRequest {
    grant_type: String,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
    #[serde(default)]
    assertion: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    authorization_details: Vec<Detail>,
    #[serde(default)]
    requested_ttl_seconds: Option<u64>,
}

fn invalid_scope(description: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::bad_request("invalid_scope", detail).with_description(description)
}

/// Handle an intake request whose body has already been parsed to JSON.
pub async fn handle(
    state: &AppState,
    headers: &HeaderMap,
    body: Value,
    now: OffsetDateTime,
) -> Result<Response, ApiError> {
    let req: IntakeRequest = serde_json::from_value(body)
        .map_err(|e| invalid_request("malformed_request", e.to_string()))?;
    let (kind, credential) = credential_of(&req)?;

    let agent = authenticate_client(&state.agents, headers, &req)?;
    if let Some(actor) = &req.actor {
        if *actor != agent {
            return Err(invalid_request(
                "actor_mismatch",
                format!("actor `{actor}` is not the authenticated client `{agent}`"),
            ));
        }
    }
    let requested: CapabilitySet = req
        .authorization_details
        .iter()
        .filter(|d| d.kind == AUTHORIZATION_DETAILS_TYPE)
        .flat_map(|d| d.capabilities.iter().cloned())
        .collect();
    if requested.is_empty() {
        return Err(invalid_request(
            "no_capabilities_requested",
            format!("authorization_details must contain a `{AUTHORIZATION_DETAILS_TYPE}` entry with at least one capability (or use scope)"),
        ));
    }

    let verified = state.idps.verify(credential, kind, now).await?;
    if kind == CredentialKind::IdJag {
        let jag = claims::map_id_jag(&verified.claims)?;
        if jag.client_id != agent {
            return Err(IntakeError::ClientIdMismatch {
                assertion: jag.client_id,
                client: agent,
            }
            .into());
        }
    }
    let user = claims::originating_user(&verified)?;

    let grant = RootGrant::find(
        &state.root_grants,
        &verified.issuer,
        &agent,
        &verified.subject,
    )
    .ok_or_else(|| {
        invalid_scope(
            "no_root_grant",
            format!(
                "no [[root_grants]] entry for agent `{agent}` and users of `{}`",
                verified.issuer
            ),
        )
    })?;
    let ceiling = capability_set(&grant.capabilities).map_err(ApiError::internal)?;
    let capabilities = ceiling
        .attenuate(&requested)
        .map_err(|e| invalid_scope("scope_exceeds_grant", e.to_string()))?;

    let ttl = req
        .requested_ttl_seconds
        .map(|s| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)));
    let issued =
        state
            .issuer
            .issue_root(user, AgentId::new(agent.clone()), capabilities, ttl, now)?;
    register_issued(
        state,
        &issued.token,
        &issued.lease,
        None,
        issued.expires_at,
        now,
    )?;
    let args = json!({
        "agent": agent,
        "requested": issued.chain.hops[0].capabilities,
        "credential": kind.as_str(),
        "idp": verified.issuer,
    });
    if let Err(e) = audit_issuance(state, "token.root", &issued.chain, args, now) {
        let _ = state.leases.revoke(&issued.lease, "audit_error", now);
        return Err(e);
    }
    tracing::info!(
        subject = %verified.subject,
        idp = %verified.issuer,
        credential = kind.as_str(),
        agent = %agent,
        lease = %issued.lease.0,
        "root token issued from IdP credential"
    );
    let mut out = Json(ExchangeResponse::from_issued(&issued, now)).into_response();
    no_store(out.headers_mut());
    Ok(out)
}

/// Which credential the request carries, by grant type and token type.
fn credential_of(req: &IntakeRequest) -> Result<(CredentialKind, &str), ApiError> {
    match req.grant_type.as_str() {
        TOKEN_EXCHANGE_GRANT_TYPE => {
            let kind = match req.subject_token_type.as_deref() {
                Some(ID_TOKEN_TYPE) => CredentialKind::IdToken,
                Some(ID_JAG_TOKEN_TYPE) => CredentialKind::IdJag,
                other => {
                    return Err(invalid_request(
                        "unsupported_token_type",
                        format!("unsupported subject_token_type {other:?}"),
                    ))
                }
            };
            let token = req
                .subject_token
                .as_deref()
                .ok_or_else(|| invalid_request("malformed_request", "subject_token is required"))?;
            Ok((kind, token))
        }
        JWT_BEARER_GRANT_TYPE => req
            .assertion
            .as_deref()
            .map(|a| (CredentialKind::IdJag, a))
            .ok_or_else(|| invalid_request("malformed_request", "assertion is required")),
        other => Err(ApiError::bad_request(
            "unsupported_grant_type",
            format!("unsupported grant_type `{other}`"),
        )),
    }
}

/// Authenticate the agent against `[[agents]]`; returns its id.
fn authenticate_client(
    agents: &[AgentConfig],
    headers: &HeaderMap,
    req: &IntakeRequest,
) -> Result<String, ApiError> {
    clientauth::authenticate(
        ClientKind::Agent,
        agents,
        headers,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
    )
}

/// Validate `[[agents]]` at startup; returns them with the hash lowercased.
pub fn validate_agents(agents: &[AgentConfig]) -> anyhow::Result<Vec<AgentConfig>> {
    clientauth::validate_clients("[[agents]]", agents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderValue};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    fn agents() -> Vec<AgentConfig> {
        validate_agents(&[AgentConfig {
            id: "planner".into(),
            secret_sha256: hex::encode(Sha256::digest(b"s3cret")).to_uppercase(),
        }])
        .unwrap()
    }

    fn req(id: Option<&str>, secret: Option<&str>) -> IntakeRequest {
        IntakeRequest {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE.into(),
            subject_token: Some("x".into()),
            subject_token_type: Some(ID_TOKEN_TYPE.into()),
            assertion: None,
            actor: None,
            client_id: id.map(Into::into),
            client_secret: secret.map(Into::into),
            authorization_details: vec![],
            requested_ttl_seconds: None,
        }
    }

    fn code(r: Result<String, ApiError>) -> &'static str {
        r.unwrap_err().description.unwrap()
    }

    #[test]
    fn client_auth_form_and_basic() {
        let h = HeaderMap::new();
        assert_eq!(
            authenticate_client(&agents(), &h, &req(Some("planner"), Some("s3cret"))).unwrap(),
            "planner"
        );
        assert_eq!(
            code(authenticate_client(
                &agents(),
                &h,
                &req(Some("planner"), Some("nope"))
            )),
            "client_authentication_failed"
        );
        assert_eq!(
            code(authenticate_client(
                &agents(),
                &h,
                &req(Some("ghost"), Some("s3cret"))
            )),
            "client_authentication_failed"
        );
        assert_eq!(
            code(authenticate_client(&agents(), &h, &req(None, None))),
            "client_auth_missing"
        );
        assert_eq!(
            code(authenticate_client(
                &[],
                &h,
                &req(Some("planner"), Some("s3cret"))
            )),
            "no_agents_configured"
        );

        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("planner:s3cret"))).unwrap(),
        );
        assert_eq!(
            authenticate_client(&agents(), &basic, &req(None, None)).unwrap(),
            "planner"
        );
        assert_eq!(
            code(authenticate_client(
                &agents(),
                &basic,
                &req(None, Some("s3cret"))
            )),
            "multiple_client_auth"
        );
    }

    #[test]
    fn agents_config_is_validated() {
        let bad = AgentConfig {
            id: "a".into(),
            secret_sha256: "abc".into(),
        };
        assert!(validate_agents(&[bad]).is_err());
        let a = agents().remove(0);
        assert!(validate_agents(&[a.clone(), a]).is_err());
    }

    #[test]
    fn intake_detection() {
        assert!(is_intake(&json!({"subject_token_type": ID_TOKEN_TYPE})));
        assert!(is_intake(&json!({"subject_token_type": ID_JAG_TOKEN_TYPE})));
        assert!(is_intake(&json!({"grant_type": JWT_BEARER_GRANT_TYPE})));
        assert!(!is_intake(&json!({
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
        })));
    }
}

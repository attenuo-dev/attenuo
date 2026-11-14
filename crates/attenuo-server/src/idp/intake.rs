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
//! | `client_id`, `client_secret` | the agent's credentials from `[[agents]]`; HTTP Basic also accepted (RFC 6749 §2.3.1). With an `actor_token`, `client_id` alone may name the agent |
//! | `client_assertion_type`, `client_assertion` | instead of a secret: a `private_key_jwt` client assertion (RFC 7523 §2.2) signed by one of the agent's `[[agents]] jwks` keys ([`crate::clientauth`]); `client_id`, when sent, must equal its `sub` |
//! | `actor_token`, `actor_token_type` | RFC 8693 §2.1: a workload-identity JWT for the agent from an `[[actor_trust]]` issuer, type `urn:ietf:params:oauth:token-type:jwt` ([`crate::actor`]) |
//! | `actor` | optional; must equal the authenticated agent when given |
//! | `authorization_details` / `scope` | requested capabilities, as for an exchange |
//! | `requested_ttl_seconds` | optional |
//! | `may_act` | optional RFC 8693 §4.4 `may_act` for the root token (agent ids); within the grant's |
//!
//! **Agent authentication** follows `[token] actor_auth`, as for an exchange: client
//! credentials (`"secret"`: the client secret or a `private_key_jwt` assertion, whichever the
//! agent's entry holds), an `actor_token` (`"actor_token"`), or either (`"either"`, the
//! default; when both are sent, both are checked and must name the same agent). A method the
//! mode does not accept is refused (`actor_token_not_accepted`, `client_auth_not_accepted`),
//! and with `"actor_token"` and no token the request fails with 401 `invalid_client` /
//! `actor_token_required`. Hop 0
//! always needs an authenticated agent: `[token] require_actor_auth` does not apply. The agent
//! an actor token maps to must equal `actor` and `client_id` when the request names them
//! (`actor_mismatch`), and is the agent `[[root_grants]]` and the IdP's `client_ids` are looked
//! up for.
//!
//! Steps, in order: check and verify the actor token, if any (`invalid_request` with
//! `actor_token_*` sub-codes); authenticate the agent (`invalid_client`, 401, for client
//! credentials, or for no credential at all); check `actor` and that capabilities were requested (`invalid_request`); verify
//! the credential ([`IdpRegistry::verify`](super::IdpRegistry::verify), `invalid_grant`); for
//! an ID-JAG, require its `client_id` to be the authenticated agent and, when it has a
//! `cnf.jkt`, a DPoP proof by that key (`credential_pop_required`, `credential_pop_mismatch`);
//! build the originating user
//! ([`claims::originating_user`]); find the `[[root_grants]]` entry for (issuer, agent,
//! subject) and attenuate the request against it (`invalid_scope`); for an ID-JAG from an
//! issuer with `[idps.id_jag_ceiling]`, narrow that entry by the ID-JAG's `resource`, `scope`
//! and `authorization_details` ([`super::ceiling`]; `id_jag_ceiling_empty` when nothing is
//! left) and attenuate the request against the result too (`scope_exceeds_id_jag`); cap the TTL at the
//! credential's remaining lifetime (`credential_expired` if none is left) and at the actor
//! token's `exp` (`actor_token_expired`); use the credential and the actor token once
//! ([`crate::replay`], `replayed`); then `Issuer::issue_root`, register the lease, and audit
//! as `token.root` / `token_issued`, with `agent_auth` and the actor token's subject and trust
//! entry in the record's arguments.

use attenuo_audit::LeaseRegistry;
use attenuo_core::{AgentId, CapabilitySet};
use attenuo_token::{ExchangeResponse, AUTHORIZATION_DETAILS_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use super::JWT_BEARER_GRANT_TYPE;
use super::{claims, CredentialKind, IntakeError, ID_JAG_TOKEN_TYPE, ID_TOKEN_TYPE};
use crate::actor::{VerifiedActor, ACTOR_TOKEN_TYPE};
use crate::clientauth::{self, invalid_request, Authenticated, Clients};
use crate::config::{capability_set, ActorAuth, RootGrant};
use crate::error::ApiError;
use crate::routes::token::take_actor_token;
use crate::routes::{audit_issuance, no_store, register_issued};
use crate::state::AppState;

/// Does this `/token` request carry an IdP credential (rather than an attenuo token)?
pub(crate) fn is_intake(body: &Value) -> bool {
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
    #[serde(default)]
    may_act: Option<attenuo_token::MayAct>,
}

fn invalid_scope(description: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::bad_request("invalid_scope", detail).with_description(description)
}

/// Handle an intake request whose body has already been parsed to JSON.
pub(crate) async fn handle(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    body: Value,
    mark: Option<&crate::limits::CallerMark>,
    now: OffsetDateTime,
) -> Result<Response, ApiError> {
    let mut body = body;
    let actor_token = take_actor_token(&mut body, state.actor_auth)?;
    let assertion = match body.as_object_mut() {
        Some(obj) => clientauth::take_client_assertion(obj)?,
        None => None,
    };
    let req: IntakeRequest = serde_json::from_value(body)
        .map_err(|e| invalid_request("malformed_request", e.to_string()))?;
    let (kind, credential) = credential_of(&req)?;

    // The actor token is verified before anything else touches the request: it may need a
    // JWKS fetch, and it decides which agent this is.
    let actor = match actor_token {
        Some(token) => Some((state.actor_trust.verify(&token, now).await?, token)),
        None => None,
    };
    let (agent, agent_auth, client) = authenticate_agent(
        &state.agents,
        state.actor_auth,
        headers,
        &req,
        assertion.as_deref(),
        actor.as_ref().map(|(v, _)| v),
        now,
    )?;
    // A client assertion authenticates this one request, whatever its outcome: its `jti` is
    // recorded now (`crate::clientauth`), unlike the actor token and the IdP credential, which
    // are recorded together once the root token is issued. The rate limit and a DPoP proof
    // that will be refused come first, so that a request the client is told to send again
    // does not use its assertion up (SR-108, SR-111).
    if let Some(client) = client {
        client.check_before_commit(state, headers, mark, now)?;
        state
            .blocking(move |s| client.commit(&s.replay, now))
            .await?;
    }
    // `[limits] token_requests_per_minute`: before the DPoP proof, the IdP credential, the
    // lease registration, signing and the audit append.
    state.limits.admit_agent(mark, &agent)?;
    // DPoP (SR-24): bind the root token to the proof's key, per `[token] dpop`.
    let cnf = state.dpop.bind_new(
        crate::dpop::header_proof(headers)?,
        "POST",
        &state.dpop.expected_url_for(headers, "/token"),
        now,
    )?;
    let dpop_bound = cnf.is_some();
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

    let verified = state.idps.verify(credential, kind, &agent, now).await?;
    if kind == CredentialKind::IdJag {
        let jag = claims::map_id_jag(&verified.claims)?;
        if jag.client_id != agent {
            return Err(IntakeError::ClientIdMismatch {
                assertion: jag.client_id,
                client: agent,
            }
            .into());
        }
        // A sender-constrained ID-JAG (draft -04 §9.8.1.2, -06 §4.4.1): the request must carry
        // a DPoP proof by the key in `cnf.jkt`, and the root token is then bound to that key.
        if let Some(jkt) = &jag.cnf_jkt {
            match &cnf {
                Some(c) if c.jkt == *jkt => {}
                Some(_) => return Err(IntakeError::PopMismatch.into()),
                None => {
                    return Err(IntakeError::PopRequired(
                        if state.dpop.mode() == crate::config::DpopMode::Off {
                            "the ID-JAG is bound to a DPoP key and [token] dpop is off".into()
                        } else {
                            "the ID-JAG is bound to a DPoP key: send a DPoP proof by that key"
                                .into()
                        },
                    )
                    .into())
                }
            }
        }
    }
    let user = claims::originating_user(&verified)?;
    if crate::routes::is_reserved_subject(&user.subject) {
        // Audit records of admin actions use a subject under this prefix (SR-34).
        return Err(ApiError::bad_request(
            "invalid_grant",
            "the credential's subject uses a prefix reserved for the server's own records",
        )
        .with_description("reserved_subject"));
    }

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
    let granted = capability_set(&grant.capabilities).map_err(ApiError::internal)?;
    let capabilities = granted
        .attenuate(&requested)
        .map_err(|e| invalid_scope("scope_exceeds_grant", e.to_string()))?;
    // `[idps.id_jag_ceiling]` (opt-in): the ID-JAG's `resource`, `scope` and
    // `authorization_details` narrow the root grant further (draft -06 §4.4.1). Without the
    // table nothing here runs, and the answer and the audit record are as before.
    let mut ceiling_claims = None;
    let capabilities = match (kind, state.idps.id_jag_ceiling(&verified.issuer)) {
        (CredentialKind::IdJag, Some(ceiling)) => {
            let applied = ceiling.apply(&granted, &verified.claims);
            if applied.capabilities.is_empty() {
                return Err(invalid_scope(
                    "id_jag_ceiling_empty",
                    format!(
                        "the ID-JAG's {} leave nothing of the [[root_grants]] entry for agent `{agent}` \
                         ([idps.id_jag_ceiling] of `{}`)",
                        applied.claims.join(", "),
                        verified.issuer
                    ),
                ));
            }
            let narrowed = applied.capabilities.attenuate(&capabilities).map_err(|_| {
                // Name a refused capability as the request has it: `capabilities` carry
                // the root grant's limits, which the caller was not given (SR-124).
                let refused = requested.iter().find(|r| {
                    let one: CapabilitySet = std::iter::once((*r).clone()).collect();
                    granted
                        .attenuate(&one)
                        .and_then(|c| applied.capabilities.attenuate(&c))
                        .is_err()
                });
                let detail = match refused {
                    Some(r) => attenuo_core::AttenuationError::NotCovered {
                        requested: r.display(),
                    }
                    .to_string(),
                    None => "the request asks for more than the ID-JAG's claims allow".into(),
                };
                invalid_scope("scope_exceeds_id_jag", detail)
            })?;
            tracing::debug!(claims = ?applied.claims, "ID-JAG ceiling applied");
            ceiling_claims = Some(applied.claims);
            narrowed
        }
        _ => capabilities,
    };
    let may_act = grant
        .may_act_for(req.may_act.clone())
        .map_err(|e| invalid_request("may_act_exceeds_grant", e))?;

    // The root token never outlives the credential it was minted from.
    let requested_ttl = req
        .requested_ttl_seconds
        .map(|s| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)))
        .unwrap_or(state.issuer.config().default_ttl);
    let remaining = Duration::seconds(verified.expires_at - now.unix_timestamp());
    if remaining < Duration::seconds(1) {
        return Err(ApiError::bad_request(
            "invalid_grant",
            "the credential expires now; present a fresh one",
        )
        .with_description("credential_expired"));
    }
    let mut ttl = requested_ttl.min(remaining);
    // Nor the actor token that authenticated the agent.
    if let Some((verified_actor, _)) = &actor {
        let left = Duration::seconds(verified_actor.expires_at - now.unix_timestamp());
        if left < Duration::seconds(1) {
            return Err(invalid_request(
                "actor_token_expired",
                "the actor_token expires now; present a fresh one",
            ));
        }
        ttl = ttl.min(left);
    }
    let ttl = Some(ttl);

    let replay_key = verified.replay_key(credential);
    let replay_until = verified
        .expires_at
        .saturating_add(i64::try_from(verified.clock_skew_seconds).unwrap_or(i64::MAX));
    let actor_replay = actor
        .as_ref()
        .map(|(v, token)| (v.replay_key(token), v.replay_until()));
    let actor_info = actor
        .as_ref()
        .map(|(v, _)| (v.subject.clone(), v.trust.clone()));
    let (agent_id, idp, kind_str) = (agent.clone(), verified.issuer.clone(), kind.as_str());
    // Everything from here on touches SQLite; run it on the blocking pool.
    let issued = state
        .blocking(move |state| {
            let issued = state
                .issuer
                .issue_root_with(
                    user,
                    AgentId::new(agent_id.clone()),
                    capabilities,
                    ttl,
                    now,
                    &attenuo_token::IssueOptions {
                        may_act,
                        not_after: None,
                        cnf,
                    },
                )
                .map_err(crate::error::mint_refusal)?;
            // Used once, recorded only after issuance succeeded; a refused token is never
            // registered.
            // The actor token authenticates one request, hop 0 or exchange alike; both are
            // recorded or neither is.
            let mut keys = vec![(replay_key.as_str(), replay_until)];
            if let Some((key, until)) = &actor_replay {
                keys.push((key.as_str(), *until));
            }
            state.replay.use_all_once(&keys, now)?;
            register_issued(
                state,
                &issued.token,
                &issued.lease,
                None,
                issued.expires_at,
                now,
            )?;
            let mut args = json!({
                "agent": agent_id,
                "requested": issued.chain.hops[0].capabilities,
                "credential": kind_str,
                "idp": idp,
                "agent_auth": agent_auth,
                "dpop_bound": dpop_bound,
            });
            // Present only under `[idps.id_jag_ceiling]`, so the digest of every other
            // record is unchanged: the claims that narrowed the root grant (empty when the
            // ID-JAG carried none of them).
            if let Some(claims) = ceiling_claims {
                args["id_jag_ceiling"] = claims.into();
            }
            if let Some((subject, trust)) = actor_info {
                args["actor_subject"] = subject.into();
                args["actor_trust"] = trust.into();
            }
            if let Err(e) =
                audit_issuance(state, "token.root", &issued.chain, args, dpop_bound, now)
            {
                let _ = state.leases.revoke(&issued.lease, "audit_error", now);
                return Err(e);
            }
            Ok::<_, ApiError>(issued)
        })
        .await?;
    tracing::info!(
        // Caller-controlled strings are Debug-formatted (SR-18).
        subject = ?state.pipeline.subject_log().show(&verified.subject),
        idp = ?verified.issuer,
        credential = kind.as_str(),
        agent = ?agent,
        agent_auth,
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

/// Authenticate the agent against `[[agents]]` with its client credentials (secret or
/// assertion).
fn authenticate_client(
    agents: &Clients,
    headers: &HeaderMap,
    req: &IntakeRequest,
    assertion: Option<&str>,
    now: OffsetDateTime,
) -> Result<Authenticated, ApiError> {
    agents.authenticate(
        headers,
        req.client_id.as_deref(),
        req.client_secret.as_deref(),
        assertion,
        now,
    )
}

/// The agent id, how it authenticated, and the client credential whose use the caller must
/// still record ([`Authenticated::commit`]).
type AgentAuth = (String, &'static str, Option<Authenticated>);

/// Authenticate the agent of a hop-0 request under `[token] actor_auth` (see the module
/// docs), and check that `actor` and `client_id` name it. Returns the agent id, how it
/// authenticated (`client_secret`, `private_key_jwt`, `actor_token`,
/// `actor_token+client_secret` or `actor_token+private_key_jwt`) and, for client credentials,
/// the [`Authenticated`] to commit.
fn authenticate_agent(
    agents: &Clients,
    mode: ActorAuth,
    headers: &HeaderMap,
    req: &IntakeRequest,
    assertion: Option<&str>,
    actor: Option<&VerifiedActor>,
    now: OffsetDateTime,
) -> Result<AgentAuth, ApiError> {
    let presented = clientauth::presented(headers, req.client_secret.as_deref(), assertion)?;
    if presented && mode == ActorAuth::ActorToken {
        return Err(invalid_request(
            "client_auth_not_accepted",
            "this server authenticates agents with an actor_token only ([token] actor_auth = \"actor_token\")",
        ));
    }
    let (agent, how, client) = match actor {
        Some(verified) => {
            if let Some(id) = &req.client_id {
                if *id != verified.agent {
                    return Err(invalid_request(
                        "actor_mismatch",
                        format!(
                            "client_id `{id}` is not the agent `{}` the actor_token identifies",
                            verified.agent
                        ),
                    ));
                }
            }
            if presented {
                let client = authenticate_client(agents, headers, req, assertion, now)?;
                let id = client.id().to_owned();
                if id != verified.agent {
                    return Err(invalid_request(
                        "actor_mismatch",
                        format!(
                            "the authenticated client `{id}` is not the agent `{}` the actor_token identifies",
                            verified.agent
                        ),
                    ));
                }
                (id, client.method().with_actor_token(), Some(client))
            } else {
                (verified.agent.clone(), "actor_token", None)
            }
        }
        None if mode == ActorAuth::ActorToken => {
            // No credential at all: `invalid_client` (RFC 6749 §5.2; -06 §4.4 for an ID-JAG),
            // decided before any agent is looked up (SR-110).
            return Err(clientauth::invalid_client(
                "actor_token_required",
                format!("an actor_token (actor_token_type `{ACTOR_TOKEN_TYPE}`) is required"),
            ));
        }
        None => {
            let client = authenticate_client(agents, headers, req, assertion, now)?;
            (
                client.id().to_owned(),
                client.method().as_str(),
                Some(client),
            )
        }
    };
    if let Some(named) = &req.actor {
        if *named != agent {
            return Err(invalid_request(
                "actor_mismatch",
                format!("actor `{named}` is not the authenticated agent `{agent}`"),
            ));
        }
    }
    Ok((agent, how, client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clientauth::AssertionPolicy;
    use crate::config::AgentConfig;
    use axum::http::{header, HeaderValue};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    fn policy() -> AssertionPolicy {
        AssertionPolicy {
            audience: "https://attenuo.example".into(),
            max_lifetime_seconds: 300,
            clock_skew_seconds: 60,
        }
    }

    fn validate_agents(agents: &[AgentConfig]) -> anyhow::Result<Clients> {
        Clients::agents(agents, policy())
    }

    fn agents() -> Clients {
        validate_agents(&[AgentConfig::with_secret_sha256(
            "planner",
            hex::encode(Sha256::digest(b"s3cret")).to_uppercase(),
        )])
        .unwrap()
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_000_000).unwrap()
    }

    /// [`authenticate_client`] with a secret (no assertion), to the client id.
    fn authenticate_secret(
        agents: &Clients,
        h: &HeaderMap,
        r: &IntakeRequest,
    ) -> Result<String, ApiError> {
        authenticate_client(agents, h, r, None, now()).map(|c| c.id().to_owned())
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
            may_act: None,
        }
    }

    fn code(r: Result<String, ApiError>) -> &'static str {
        r.unwrap_err().description.unwrap()
    }

    #[test]
    fn client_auth_form_and_basic() {
        let h = HeaderMap::new();
        assert_eq!(
            authenticate_secret(&agents(), &h, &req(Some("planner"), Some("s3cret"))).unwrap(),
            "planner"
        );
        assert_eq!(
            code(authenticate_secret(
                &agents(),
                &h,
                &req(Some("planner"), Some("nope"))
            )),
            "client_authentication_failed"
        );
        assert_eq!(
            code(authenticate_secret(
                &agents(),
                &h,
                &req(Some("ghost"), Some("s3cret"))
            )),
            "client_authentication_failed"
        );
        assert_eq!(
            code(authenticate_secret(&agents(), &h, &req(None, None))),
            "client_auth_missing"
        );
        assert_eq!(
            code(authenticate_secret(
                &validate_agents(&[]).unwrap(),
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
            authenticate_secret(&agents(), &basic, &req(None, None)).unwrap(),
            "planner"
        );
        assert_eq!(
            code(authenticate_secret(
                &agents(),
                &basic,
                &req(None, Some("s3cret"))
            )),
            "multiple_client_auth"
        );
    }

    #[test]
    fn agents_config_is_validated() {
        let bad = AgentConfig::with_secret_sha256("a", "abc");
        assert!(validate_agents(&[bad]).is_err());
        let a = AgentConfig::with_secret_sha256("a", hex::encode(Sha256::digest(b"x")));
        assert!(validate_agents(&[a.clone(), a]).is_err());
        let neither = AgentConfig {
            id: "a".into(),
            secret_sha256: None,
            jwks: None,
        };
        let e = validate_agents(&[neither]).err().unwrap().to_string();
        assert!(e.contains("set secret_sha256, jwks"), "{e}");
    }

    fn verified(agent: &str) -> VerifiedActor {
        VerifiedActor {
            agent: agent.into(),
            subject: format!("spiffe://example.org/{agent}"),
            trust: "spiffe://example.org".into(),
            expires_at: 2_000_000_000,
            clock_skew_seconds: 0,
            jti: Some("j".into()),
        }
    }

    #[test]
    fn agent_auth_follows_actor_auth_modes() {
        let h = HeaderMap::new();
        let auth = |mode, r: &IntakeRequest, actor: Option<&VerifiedActor>| {
            authenticate_agent(&agents(), mode, &h, r, None, actor, now())
                .map(|(a, how, _)| (a, how))
        };
        let desc = |r: Result<(String, &'static str), ApiError>| r.unwrap_err().description;
        let planner = verified("planner");

        // Actor token alone; `client_id` may name the agent without a secret.
        for r in [req(None, None), req(Some("planner"), None)] {
            assert_eq!(
                auth(ActorAuth::Either, &r, Some(&planner)).unwrap(),
                ("planner".into(), "actor_token")
            );
            assert_eq!(
                auth(ActorAuth::ActorToken, &r, Some(&planner)).unwrap(),
                ("planner".into(), "actor_token")
            );
        }
        // Both: both checked, and they must agree.
        let both = req(Some("planner"), Some("s3cret"));
        assert_eq!(
            auth(ActorAuth::Either, &both, Some(&planner)).unwrap(),
            ("planner".into(), "actor_token+client_secret")
        );
        assert_eq!(
            desc(auth(
                ActorAuth::Either,
                &req(Some("planner"), Some("nope")),
                Some(&planner)
            )),
            Some("client_authentication_failed")
        );
        assert_eq!(
            desc(auth(ActorAuth::Either, &both, Some(&verified("coder")))),
            Some("actor_mismatch")
        );
        // `client_id` or `actor` naming someone else.
        assert_eq!(
            desc(auth(
                ActorAuth::Either,
                &req(Some("coder"), None),
                Some(&planner)
            )),
            Some("actor_mismatch")
        );
        let mut named = req(None, None);
        named.actor = Some("coder".into());
        assert_eq!(
            desc(auth(ActorAuth::Either, &named, Some(&planner))),
            Some("actor_mismatch")
        );
        // Modes.
        assert_eq!(
            desc(auth(ActorAuth::ActorToken, &both, Some(&planner))),
            Some("client_auth_not_accepted")
        );
        assert_eq!(
            desc(auth(ActorAuth::ActorToken, &req(None, None), None)),
            Some("actor_token_required")
        );
        assert_eq!(
            auth(ActorAuth::Secret, &both, None).unwrap(),
            ("planner".into(), "client_secret")
        );
        assert_eq!(
            desc(auth(ActorAuth::Either, &req(Some("planner"), None), None)),
            Some("client_auth_missing")
        );
    }

    /// Hop 0 with a `private_key_jwt` assertion: alone, or with an actor token that must name
    /// the same agent; refused under `actor_auth = "actor_token"`.
    #[test]
    fn agent_auth_with_a_client_assertion() {
        let key = attenuo_token::DpopKey::generate().unwrap();
        let agents = validate_agents(&[
            AgentConfig::with_jwks("planner", json!({ "keys": [key.public_jwk()] }).to_string()),
            AgentConfig::with_jwks("coder", json!({ "keys": [key.public_jwk()] }).to_string()),
        ])
        .unwrap();
        let assertion = |client: &str| {
            attenuo_token::client_assertion::sign(
                &key,
                None,
                client,
                &policy().audience,
                attenuo_token::client_assertion::DEFAULT_LIFETIME,
                now(),
            )
        };
        let h = HeaderMap::new();
        let auth = |mode, a: &str, actor: Option<&VerifiedActor>| {
            authenticate_agent(&agents, mode, &h, &req(None, None), Some(a), actor, now())
                .map(|(a, how, c)| (a, how, c.is_some()))
        };
        let desc = |r: Result<(String, &'static str, bool), ApiError>| r.unwrap_err().description;
        assert_eq!(
            auth(ActorAuth::Either, &assertion("planner"), None).unwrap(),
            ("planner".into(), "private_key_jwt", true)
        );
        assert_eq!(
            auth(ActorAuth::Secret, &assertion("planner"), None).unwrap(),
            ("planner".into(), "private_key_jwt", true)
        );
        assert_eq!(
            auth(
                ActorAuth::Either,
                &assertion("planner"),
                Some(&verified("planner"))
            )
            .unwrap(),
            ("planner".into(), "actor_token+private_key_jwt", true)
        );
        assert_eq!(
            desc(auth(
                ActorAuth::Either,
                &assertion("coder"),
                Some(&verified("planner"))
            )),
            Some("actor_mismatch")
        );
        assert_eq!(
            desc(auth(
                ActorAuth::ActorToken,
                &assertion("planner"),
                Some(&verified("planner"))
            )),
            Some("client_auth_not_accepted")
        );
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

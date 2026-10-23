//! `POST /token`: RFC 8693 token exchange.
//!
//! Two kinds of request share this endpoint:
//!
//! - **Hop 0 (IdP intake).** `subject_token_type` is `...:token-type:id_token` or
//!   `...:token-type:id-jag` (or `grant_type` is `...:grant-type:jwt-bearer`): the subject token
//!   is a user credential from a trusted IdP, and the agent authenticates with its client
//!   credentials or an `actor_token`, under the same `[token] actor_auth` modes as an
//!   exchange. Handled by [`crate::idp::intake`].
//! - **Hop n to n+1.** `subject_token_type` is `...:token-type:jwt` and the subject token is an
//!   onbehalf token. Described below.
//!
//! Accepts `application/x-www-form-urlencoded` (RFC 8693 §2.1) or `application/json`. Fields:
//!
//! | Field | Notes |
//! |---|---|
//! | `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
//! | `subject_token` | the parent onbehalf token |
//! | `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` |
//! | `actor` | the sub-agent's id; the request must authenticate as this agent (below) |
//! | `client_id`, `client_secret` | the actor's `[[agents]]` credentials; HTTP Basic also accepted |
//! | `actor_token`, `actor_token_type` | RFC 8693 §2.1: a workload-identity JWT for the actor, type `urn:ietf:params:oauth:token-type:jwt` ([`crate::actor`]) |
//! | `authorization_details` | RFC 9396 list with one `{"type":"onbehalf_capabilities","capabilities":[...]}`; a JSON string in form encoding |
//! | `scope` | form only, alternative to `authorization_details`: space-separated `server:tool` |
//! | `requested_ttl_seconds` | optional |
//! | `may_act` | optional RFC 8693 §4.4 `may_act` for the child token: agent ids (JSON list or `{"sub": [...]}`; space-separated in form encoding) |
//!
//! **Actor authentication (SR-10).** With `[token] require_actor_auth = true` (the default) the
//! caller must authenticate as `actor`, with whichever methods `[token] actor_auth` accepts
//! (`either` by default):
//!
//! - client credentials from `[[agents]]` (HTTP Basic, or `client_id` / `client_secret`); the
//!   client id must equal `actor`. Failures are 401 `invalid_client` (sub-codes as for intake).
//! - an `actor_token` from an `[[actor_trust]]` issuer (a SPIFFE JWT-SVID, or any JWT with a
//!   JWKS), verified by [`crate::actor::ActorTrustRegistry::verify`]; the agent its `sub` maps
//!   to must equal `actor`. Failures are 400 `invalid_request` with `actor_token_*` sub-codes.
//!
//! When both are sent, both are checked. A method `actor_auth` does not accept is refused
//! (`actor_token_not_accepted`, `client_auth_not_accepted`); with `actor_auth = "actor_token"`
//! and no token, `actor_token_required`. So an agent can only receive a delegation in its own
//! name, and `principal` in Cedar and the agent in the audit log are authenticated, not
//! asserted. A mismatch is 400 `invalid_request` / `actor_mismatch`. An `actor` that already
//! appears in the parent chain is 400 `invalid_request` / `duplicate_actor`.
//!
//! An actor token is used once: a second exchange with the same token (same `jti`, or the same
//! signed content when it has none) is 400 `invalid_grant` / `replayed`. The child token's
//! expiry is also capped at the actor token's `exp`.
//!
//! Besides what `ExchangeRequest::execute` checks (signature, chain validity, attenuation,
//! depth), the parent's leases must all be live: a revoked parent cannot delegate. A parent
//! token delegates to a given actor once; a second exchange of the same parent for the same
//! actor is 400 `invalid_grant` / `replayed` until the parent expires ([`crate::replay`]). The new lease
//! is registered as a child of the parent token's last lease, so revoking the parent cascades.
//!
//! **Sender constraint (SR-24).** A `DPoP` header binds the child to the proof's key; a bound
//! subject token needs a proof by its key (in the header, with `ath`, or in the body field
//! `subject_token_dpop` when the child is bound to another key), and its child is always
//! bound. See [`crate::dpop`] for the rule and `[token] dpop`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use onbehalf_audit::LeaseStore;
use onbehalf_token::{ExchangeRequest, AUTHORIZATION_DETAILS_TYPE};
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use super::{audit_issuance, no_store, now, parse_json, register_issued};
use crate::actor::{VerifiedActor, ACTOR_TOKEN_TYPE};
use crate::clientauth::{self, ClientKind};
use crate::config::{capability_set, ActorAuth, CapSpec};
use crate::error::ApiError;
use crate::state::AppState;

pub async fn exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let value = parse_body(&headers, &body)?;
    let now = now();
    if crate::idp::intake::is_intake(&value) {
        return crate::idp::intake::handle(&state, &headers, value, now).await;
    }
    let mut value = value;
    // The actor token is verified here, on the async side: it may need a JWKS fetch.
    let actor = match take_actor_token(&mut value, state.actor_auth)? {
        Some(token) => Some((state.actor_trust.verify(&token, now).await?, token)),
        None => None,
    };
    // Lease lookups, registration and the audit append are SQLite calls: off the async workers.
    state
        .blocking(move |s| exchange_sync(s, &headers, value, actor, now))
        .await
}

/// Remove `actor_token` / `actor_token_type` from the body and check them: both or neither,
/// the type is the JWT URN, and `[token] actor_auth` accepts actor tokens.
pub(crate) fn take_actor_token(
    value: &mut Value,
    mode: ActorAuth,
) -> Result<Option<String>, ApiError> {
    let Some(obj) = value.as_object_mut() else {
        return Ok(None);
    };
    let take = |obj: &mut Map<String, Value>, k: &str| -> Result<Option<String>, ApiError> {
        match obj.remove(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(clientauth::invalid_request(
                "malformed_request",
                format!("{k} must be a string"),
            )),
        }
    };
    let token = take(obj, "actor_token")?;
    let token_type = take(obj, "actor_token_type")?;
    let token = match (token, token_type) {
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err(clientauth::invalid_request(
                "malformed_request",
                "actor_token_type is required with actor_token (RFC 8693 §2.1)",
            ))
        }
        (None, Some(_)) => {
            return Err(clientauth::invalid_request(
                "malformed_request",
                "actor_token_type without actor_token",
            ))
        }
        (Some(t), Some(ty)) if ty == ACTOR_TOKEN_TYPE => t,
        (Some(_), Some(ty)) => {
            return Err(clientauth::invalid_request(
                "actor_token_type_unsupported",
                format!("unsupported actor_token_type `{ty}`; use `{ACTOR_TOKEN_TYPE}`"),
            ))
        }
    };
    if mode == ActorAuth::Secret {
        return Err(clientauth::invalid_request(
            "actor_token_not_accepted",
            "this server authenticates actors with client credentials only ([token] actor_auth = \"secret\")",
        ));
    }
    Ok(Some(token))
}

fn exchange_sync(
    state: &AppState,
    headers: &HeaderMap,
    value: Value,
    actor: Option<(VerifiedActor, String)>,
    now: OffsetDateTime,
) -> Result<Response, ApiError> {
    let field = |k: &str| value.get(k).and_then(Value::as_str).map(str::to_owned);
    let (client_id, client_secret) = (field("client_id"), field("client_secret"));
    let subject_proof = field("subject_token_dpop");
    let mut value = value;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("client_id");
        obj.remove("client_secret");
        obj.remove("subject_token_dpop");
    }
    let req = parse_request(value)?;
    let presented = client_secret.is_some() || clientauth::basic_credentials(headers)?.is_some();
    if presented && state.actor_auth == ActorAuth::ActorToken {
        return Err(clientauth::invalid_request(
            "client_auth_not_accepted",
            "this server authenticates actors with an actor_token only ([token] actor_auth = \"actor_token\")",
        ));
    }
    let mut actor_auth = "none";
    if let Some((verified, _)) = &actor {
        if verified.agent != req.actor.0 {
            return Err(clientauth::invalid_request(
                "actor_mismatch",
                format!(
                    "actor `{}` is not the agent `{}` the actor_token identifies",
                    req.actor.0, verified.agent
                ),
            ));
        }
        actor_auth = "actor_token";
    }
    if presented || (state.require_actor_auth && actor.is_none()) {
        if state.actor_auth == ActorAuth::ActorToken {
            return Err(clientauth::invalid_request(
                "actor_token_required",
                format!("an actor_token (actor_token_type `{ACTOR_TOKEN_TYPE}`) is required"),
            ));
        }
        let agent = clientauth::authenticate(
            ClientKind::Agent,
            &state.agents,
            headers,
            client_id.as_deref(),
            client_secret.as_deref(),
        )?;
        if agent != req.actor.0 {
            return Err(clientauth::invalid_request(
                "actor_mismatch",
                format!(
                    "actor `{}` is not the authenticated client `{agent}`",
                    req.actor.0
                ),
            ));
        }
        actor_auth = if actor.is_some() {
            "actor_token+client_secret"
        } else {
            "client_secret"
        };
    }
    if req.requested.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            format!("authorization_details must contain a `{AUTHORIZATION_DETAILS_TYPE}` entry with at least one capability"),
        ));
    }
    let parent = state.verifier.verify(&req.subject_token, now)?;
    state
        .pipeline
        .check_leases(&parent.chain, now)
        .map_err(|(reason, detail)| {
            ApiError::bad_request(
                "invalid_grant",
                format!(
                    "subject token cannot delegate: {reason} ({})",
                    detail.join("; ")
                ),
            )
        })?;

    if parent.chain.hops.iter().any(|h| h.agent == req.actor) {
        return Err(clientauth::invalid_request(
            "duplicate_actor",
            format!(
                "agent `{}` already acts in this delegation chain; an agent cannot delegate to \
                 itself or to an agent above it",
                req.actor.0
            ),
        ));
    }
    // The child never outlives the actor token that authenticated the exchange.
    let not_after = match &actor {
        Some((verified, _)) => {
            if verified.expires_at - now.unix_timestamp() < 1 {
                return Err(clientauth::invalid_request(
                    "actor_token_expired",
                    "the actor_token expires now; present a fresh one",
                ));
            }
            Some(
                OffsetDateTime::from_unix_timestamp(verified.expires_at)
                    .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?,
            )
        }
        None => None,
    };
    // DPoP (SR-24): bind the child to the header proof's key; a bound parent needs proof of
    // its key and a bound child.
    let cnf = state.dpop.bind_exchange(
        parent.claims.cnf.as_ref(),
        &req.subject_token,
        crate::dpop::header_proof(headers)?,
        subject_proof.as_deref(),
        &state.dpop.expected_url_for(headers, "/token"),
        now,
    )?;
    let dpop_bound = cnf.is_some();
    let resp = req.execute_with(&state.issuer, now, not_after, cnf)?;
    // An actor token authenticates one exchange (see `crate::replay`), keyed by its `jti`.
    if let Some((verified, token)) = &actor {
        state
            .replay
            .use_once(&verified.replay_key(token), verified.replay_until(), now)?;
    }
    // A parent token delegates to a given actor once (see `crate::replay`). Recorded only once
    // the exchange has succeeded, so a refused request (say `invalid_scope`) does not use up
    // the slot. If this refuses, the token just minted is dropped before its lease is
    // registered, so it could not be used anyway.
    state.replay.use_once(
        &format!("exchange\n{}\n{}", parent.claims.jti, req.actor.0),
        parent.claims.exp,
        now,
    )?;
    // The response carries no chain; read it back from the token we just minted.
    let issued = state.verifier.verify(&resp.access_token, now)?;
    let hop = issued
        .chain
        .hops
        .last()
        .ok_or_else(|| ApiError::internal("issued token has no hops"))?;
    let parent_lease = parent.chain.hops.last().map(|h| &h.lease);
    register_issued(
        state,
        &resp.access_token,
        &resp.lease,
        parent_lease,
        hop.expires_at,
        now,
    )?;

    let mut args = json!({
        "actor": req.actor,
        "requested": req.requested,
        "parent_lease": parent_lease,
        "actor_auth": actor_auth,
        "dpop_bound": dpop_bound,
    });
    if let Some((verified, _)) = &actor {
        args["actor_subject"] = verified.subject.clone().into();
        args["actor_trust"] = verified.trust.clone().into();
    }
    if let Err(e) = audit_issuance(
        state,
        "token.exchange",
        &issued.chain,
        args,
        dpop_bound,
        now,
    ) {
        // An issuance we cannot record must not be usable.
        let _ = state.leases.revoke(&resp.lease, "audit_error", now);
        return Err(e);
    }
    tracing::info!(
        // Caller-controlled strings are Debug-formatted (SR-18).
        subject = ?issued.chain.originating_user.subject,
        actor = ?req.actor,
        actor_auth,
        actor_subject = ?actor.as_ref().map(|(v, _)| v.subject.as_str()),
        lease = %resp.lease.0,
        depth = issued.chain.depth(),
        dpop_bound,
        "token exchanged"
    );
    let mut out = Json(resp).into_response();
    no_store(out.headers_mut());
    Ok(out)
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false)
}

/// The request body as JSON, from either encoding.
fn parse_body(headers: &HeaderMap, body: &Bytes) -> Result<Value, ApiError> {
    if is_form(headers) {
        form_to_json(body)
    } else {
        parse_json::<Value>(body)
    }
}

fn parse_request(value: Value) -> Result<ExchangeRequest, ApiError> {
    serde_json::from_value(value).map_err(|e| {
        let msg = e.to_string();
        let code = if msg.contains("unsupported grant_type") {
            "unsupported_grant_type"
        } else {
            "invalid_request"
        };
        ApiError::bad_request(code, msg)
    })
}

/// Turn RFC 8693 form fields into the JSON shape `ExchangeRequest` deserializes.
fn form_to_json(body: &Bytes) -> Result<Value, ApiError> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    let mut obj = Map::new();
    let mut scope: Option<String> = None;
    for (k, v) in pairs {
        if obj.contains_key(&k) {
            // RFC 6749 §3.1: parameters must not be included more than once.
            return Err(ApiError::bad_request(
                "invalid_request",
                format!("parameter `{k}` repeated"),
            ));
        }
        let value = match k.as_str() {
            "authorization_details" => serde_json::from_str(&v).map_err(|e| {
                ApiError::bad_request(
                    "invalid_request",
                    format!("authorization_details is not JSON: {e}"),
                )
            })?,
            "requested_ttl_seconds" => Value::from(v.parse::<u64>().map_err(|e| {
                ApiError::bad_request("invalid_request", format!("requested_ttl_seconds: {e}"))
            })?),
            "scope" => {
                scope = Some(v);
                continue;
            }
            "may_act" if v.trim_start().starts_with(['[', '{']) => serde_json::from_str(&v)
                .map_err(|e| {
                    ApiError::bad_request("invalid_request", format!("may_act is not JSON: {e}"))
                })?,
            "may_act" => Value::from(v.split_whitespace().collect::<Vec<_>>()),
            _ => Value::String(v),
        };
        obj.insert(k, value);
    }
    if let Some(scope) = scope {
        if obj.contains_key("authorization_details") {
            return Err(ApiError::bad_request(
                "invalid_request",
                "use either scope or authorization_details, not both",
            ));
        }
        let specs: Vec<CapSpec> = scope
            .split_whitespace()
            .map(|s| CapSpec::Short(s.to_string()))
            .collect();
        let caps = capability_set(&specs).map_err(|e| ApiError::bad_request("invalid_scope", e))?;
        obj.insert(
            "authorization_details".into(),
            json!([{ "type": AUTHORIZATION_DETAILS_TYPE, "capabilities": caps }]),
        );
    }
    Ok(Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_scope_becomes_authorization_details() {
        let body = Bytes::from(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
             &subject_token=a.b.c&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
             &actor=coder&scope=github%3Aread_file+github%3Aread_dir&requested_ttl_seconds=60",
        );
        let v = form_to_json(&body).unwrap();
        let req: ExchangeRequest = serde_json::from_value(v).unwrap();
        assert_eq!(req.requested.len(), 2);
        assert_eq!(req.ttl_seconds, Some(60));
        assert_eq!(req.actor.0, "coder");
        assert_eq!(req.may_act, None);
        for may_act in ["reviewer+tester", "%5B%22reviewer%22%2C%22tester%22%5D"] {
            let v = form_to_json(&Bytes::from(format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange\
                 &subject_token=a&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt\
                 &actor=coder&scope=github%3Aread_file&may_act={may_act}"
            )))
            .unwrap();
            let req: ExchangeRequest = serde_json::from_value(v).unwrap();
            assert_eq!(
                req.may_act,
                Some(onbehalf_token::MayAct::new(["reviewer", "tester"]))
            );
        }
    }

    #[test]
    fn actor_token_fields_are_checked_and_removed() {
        let mut v =
            json!({"actor": "c", "actor_token": "a.b.c", "actor_token_type": ACTOR_TOKEN_TYPE});
        assert_eq!(
            take_actor_token(&mut v, ActorAuth::Either)
                .unwrap()
                .as_deref(),
            Some("a.b.c")
        );
        assert_eq!(v, json!({"actor": "c"}));
        let code = |mut v: Value, mode| take_actor_token(&mut v, mode).unwrap_err().description;
        assert_eq!(
            code(json!({"actor_token": "x"}), ActorAuth::Either),
            Some("malformed_request")
        );
        assert_eq!(
            code(
                json!({"actor_token_type": ACTOR_TOKEN_TYPE}),
                ActorAuth::Either
            ),
            Some("malformed_request")
        );
        assert_eq!(
            code(
                json!({"actor_token": "x", "actor_token_type": "urn:ietf:params:oauth:token-type:access_token"}),
                ActorAuth::Either
            ),
            Some("actor_token_type_unsupported")
        );
        assert_eq!(
            code(
                json!({"actor_token": "x", "actor_token_type": ACTOR_TOKEN_TYPE}),
                ActorAuth::Secret
            ),
            Some("actor_token_not_accepted")
        );
        let mut none = json!({"actor": "c"});
        assert_eq!(
            take_actor_token(&mut none, ActorAuth::Secret).unwrap(),
            None
        );
    }

    #[test]
    fn form_rejects_repeats_and_bad_json() {
        assert!(form_to_json(&Bytes::from("actor=a&actor=b")).is_err());
        assert!(form_to_json(&Bytes::from("authorization_details=%5Bnope")).is_err());
        assert!(form_to_json(&Bytes::from("scope=nocolon")).is_err());
    }
}

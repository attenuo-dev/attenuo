//! `/admin/policies*` reads: what is loaded, whether the file on disk would load, and what the
//! loaded policies say about a call. Hot reload itself is `POST /admin/policies/reload` in
//! [`super::admin`].
//!
//! None of these routes changes anything or writes an audit record: they answer questions an
//! operator asks before acting (reloading a file, revoking a lease, editing a policy). Like
//! every `/admin/*` route they sit behind [`super::admin::require_admin`].

use std::sync::Arc;

use attenuo_core::{DelegationChain, ToolCall};
use attenuo_policy::authzen::{self, EvaluationRequest};
use attenuo_policy::{CallLabels, SessionLabels};
use attenuo_token::{TokenError, VerifiedToken, Verifier};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::Digest;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{now, parse_json};
use crate::error::ApiError;
use crate::state::AppState;

/// `lease_check` of every dry run: the lease stage is never run.
pub const LEASE_CHECK_SKIPPED: &str = "skipped";
/// `chain_source` when the chain came from a verified token in the request body.
pub const CHAIN_SOURCE_TOKEN: &str = "token";
/// `chain_source` when the admin supplied the chain itself in `subject.properties.chain`.
pub const CHAIN_SOURCE_ADMIN: &str = "admin_supplied";

fn lock_poisoned() -> ApiError {
    ApiError::internal("policy engine lock poisoned")
}

/// `GET /admin/policies`: the policy set in force.
///
/// `{path, sha256, loaded_at, policy_ids, warnings, policies: [{id, text}]}`. `sha256` and
/// `loaded_at` describe the file text the engine loaded (at startup or by the last successful
/// reload), so after an edit that was not reloaded they still describe the old text. `path`
/// and `sha256` are `null` when no `policy.policies_path` is configured.
pub async fn get_policies(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    // Engine first, then the loaded-policy info: the order reload takes them in, so the pair
    // always describes the same policy set.
    let engine = state
        .pipeline
        .policy()
        .read()
        .map_err(|_| lock_poisoned())?;
    let loaded = state
        .loaded_policies
        .read()
        .map_err(|_| lock_poisoned())?
        .clone();
    let policies: Vec<Value> = engine
        .policy_texts()
        .into_iter()
        .map(|(id, text)| json!({ "id": id, "text": text }))
        .collect();
    Ok(Json(json!({
        "path": state.policies_path,
        "sha256": loaded.sha256,
        "loaded_at": loaded.loaded_at.format(&Rfc3339).map_err(ApiError::internal)?,
        "policy_ids": engine.policy_ids(),
        "warnings": engine.validation_warnings(),
        "policies": policies,
    })))
}

/// `GET /admin/policies/check`: lint `policy.policies_path` as it is on disk now, against the
/// schema of the running engine, without loading it.
///
/// Answers `{path, sha256, loaded_sha256, differs_from_loaded, ok, error_count, warning_count,
/// issues, policy_ids}`, where `issues` and `policy_ids` are an `attenuo_policy::LintReport`
/// (each issue has `severity`, `stage`, `message` and, when known, `policy_id`, `line` and
/// `column`). `ok` is true when there are no errors, which is when a reload would succeed.
/// The loaded set stays in force whatever the file holds, and nothing is audited. 409 when no
/// policy file is configured.
pub async fn check_policies(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let path = state.policies_path.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "check_unavailable",
            "policy.policies_path is not configured; there is no file to check",
        )
    })?;
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::internal(format!("reading {}: {e}", path.display())))?;
    let digest = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    let report = {
        let engine = state
            .pipeline
            .policy()
            .read()
            .map_err(|_| lock_poisoned())?;
        attenuo_policy::lint_with_options(
            &text,
            engine.schema_text(),
            attenuo_policy::LintOptions {
                legacy_bare_actions: engine.legacy_bare_actions(),
                // The engine's schema comes from the real `[policy] catalog`.
                undeclared_catalog: false,
            },
        )
    };
    let loaded = state
        .loaded_policies
        .read()
        .map_err(|_| lock_poisoned())?
        .sha256
        .clone();
    Ok(Json(json!({
        "path": path,
        "sha256": digest,
        "loaded_sha256": loaded,
        "differs_from_loaded": loaded.as_deref() != Some(digest.as_str()),
        "ok": !report.has_errors(),
        "error_count": report.error_count(),
        "warning_count": report.warning_count(),
        "issues": report.issues,
        "policy_ids": report.policy_ids,
    })))
}

/// `POST /admin/policies/evaluate`: what the loaded policies would decide for one call, without
/// checking leases, writing an audit record or counting a decision.
///
/// The body is an AuthZEN evaluation request (as for `POST /access/v1/evaluation`) with one
/// optional extra member, `token`:
///
/// - **With `token`**: a delegation token, verified with the server's verifier. A bad
///   signature, wrong issuer or any other failure is 400 `invalid_token`. An *expired* token
///   is accepted (it is verified as of the last second it was valid) and the answer says
///   `token_expired: true`: the question is what the policy says, not whether the token still
///   works. `subject.id` may be empty and `subject.properties.chain` may be left out; if given
///   it must equal the token's chain. The call counts as DPoP-bound when the token is.
/// - **Without `token`**: `subject.properties.chain` is required and is checked structurally
///   (`validate_at`, as of now) only; 400 `invalid_chain` if that fails. Nothing checks that
///   this server issued it, which is why the answer says `chain_source: "admin_supplied"`.
///
/// The decision is [`Pipeline::evaluate_policy`](crate::authz::Pipeline::evaluate_policy), the
/// same capability stage and Cedar evaluation `POST /access/v1/evaluation` runs after its lease
/// check. Answers `{decision, reason, policy_ids, diagnostics, lease_check: "skipped",
/// chain_source: "token" | "admin_supplied", token_expired, session, approval, budget}`, plus
/// `limit` when a run limit would be exceeded. `budget` is what the run limits matching the
/// call have left, read from the lease store as `context.budget` (ADR-0010); the dry run
/// never charges a counter.
pub async fn evaluate_policies(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let now = now();
    let mut raw: Value = parse_json(&body)?;
    let Some(obj) = raw.as_object_mut() else {
        return Err(ApiError::bad_request(
            "invalid_request",
            "expected a JSON object",
        ));
    };
    let token = match obj.remove("token") {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) => Some(t),
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`token` must be a string",
            ))
        }
    };
    let session = match obj.remove("session") {
        None | Some(Value::Null) => None,
        Some(v) => Some(session_from_json(&v)?),
    };
    // `approval: {"by": "user" | "operator"}`: evaluate as if the call carried a granted
    // approval. The dry run never looks one up or consumes one.
    let approval = match obj.remove("approval") {
        None | Some(Value::Null) => attenuo_policy::ApprovalContext::default(),
        Some(v) => match v.get("by").and_then(Value::as_str) {
            Some(by @ ("user" | "operator" | "policy")) => attenuo_policy::ApprovalContext::by(by),
            _ => {
                return Err(ApiError::bad_request(
                    "invalid_request",
                    "`approval` must be {\"by\": \"user\" | \"operator\" | \"policy\"}",
                ))
            }
        },
    };
    let mut req: EvaluationRequest = serde_json::from_value(raw)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;

    let (chain, call, source, token_expired) = match token {
        Some(token) => {
            let (v, expired) = verify_allowing_expiry(&state.verifier, &token, now)
                .map_err(|e| ApiError::bad_request("invalid_token", e.to_string()))?;
            super::authzen::attach_chain(&mut req, &v.chain)?;
            let (chain, call) = chain_and_call(&req)?;
            let call = call.with_dpop_bound(v.claims.cnf.is_some());
            (chain, call, CHAIN_SOURCE_TOKEN, expired)
        }
        None => {
            let (chain, call) = chain_and_call(&req)?;
            chain
                .validate_at(now, state.verifier.max_depth())
                .map_err(|e| ApiError::bad_request("invalid_chain", e.to_string()))?;
            (chain, call, CHAIN_SOURCE_ADMIN, false)
        }
    };

    // Output labels (ADR-0009): as given, or else the run's current taint state.
    let (session, session_source) = match session {
        Some(s) => (s, "request"),
        None => (state.pipeline.run_labels(&chain).session, "store"),
    };
    // Run limits (ADR-0010): the counters as they are now. Read, never charged.
    let budget = state.pipeline.budget_view(&chain, &call);
    let labels = CallLabels {
        session: session.clone(),
        approval: approval.clone(),
        budget: budget.context.clone(),
    };
    let o = state.pipeline.evaluate_policy(&chain, &call, &labels, now);
    let mut out = json!({
        "decision": o.decision,
        "reason": o.reason,
        "policy_ids": o.policy_ids,
        "diagnostics": o.diagnostics,
        "lease_check": LEASE_CHECK_SKIPPED,
        "chain_source": source,
        "token_expired": token_expired,
        "session": {
            "tainted": session.tainted,
            "tainted_by": session.tainted_by,
            "source": session_source,
        },
        "approval": { "present": approval.present, "by": approval.by },
        "budget": crate::authz::budget_json(&budget.context),
    });
    if let Some(hit) = &budget.hit {
        out["limit"] = hit.to_json();
    }
    Ok(Json(out))
}

/// The optional `session` member of a dry run: `{"tainted_by": ["<server>/<tool>", ...],
/// "tainted": bool}`. `tainted` defaults to whether `tainted_by` is non-empty.
fn session_from_json(v: &Value) -> Result<SessionLabels, ApiError> {
    let bad = |m: &str| ApiError::bad_request("invalid_request", format!("`session`: {m}"));
    let obj = v.as_object().ok_or_else(|| bad("expected an object"))?;
    let mut sources = Vec::new();
    match obj.get("tainted_by") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                sources.push(
                    item.as_str()
                        .ok_or_else(|| bad("`tainted_by` must be a list of strings"))?
                        .to_owned(),
                );
            }
        }
        Some(_) => return Err(bad("`tainted_by` must be a list of strings")),
    }
    let mut session = SessionLabels::from_sources(sources);
    match obj.get("tainted") {
        None | Some(Value::Null) => {}
        Some(Value::Bool(t)) => session.tainted = *t || !session.tainted_by.is_empty(),
        Some(_) => return Err(bad("`tainted` must be a boolean")),
    }
    if let Some(k) = obj.keys().find(|k| *k != "tainted" && *k != "tainted_by") {
        return Err(bad(&format!("unknown member `{k}`")));
    }
    Ok(session)
}

fn chain_and_call(req: &EvaluationRequest) -> Result<(DelegationChain, ToolCall), ApiError> {
    authzen::to_chain_and_call(req)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))
}

/// Verify `token` as of `now`, or, if that fails only because it has expired, as of the last
/// second it was valid. Returns the verified token and whether it had expired.
///
/// The second attempt repeats every check (signature, issuer, audience, chain) at that
/// earlier time, so an expired token is accepted only if it was once a good token. The `exp`
/// read from the unverified payload only picks the time; the signature check then covers it.
pub fn verify_allowing_expiry(
    verifier: &Verifier,
    token: &str,
    now: OffsetDateTime,
) -> Result<(VerifiedToken, bool), TokenError> {
    match verifier.verify(token, now) {
        Ok(v) => Ok((v, false)),
        Err(TokenError::Expired) => {
            let at = unverified_exp(token)
                .and_then(|exp| OffsetDateTime::from_unix_timestamp(exp - 1).ok())
                .ok_or(TokenError::Expired)?;
            verifier.verify(token, at).map(|v| (v, true))
        }
        Err(e) => Err(e),
    }
}

/// The `exp` claim of a JWT, read without checking anything.
fn unverified_exp(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get("exp")?
        .as_i64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
    use attenuo_token::{Issuer, IssuerConfig};
    use time::Duration;

    fn issuer() -> Issuer {
        Issuer::generate(IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo-test".into(),
            max_depth: 4,
            default_ttl: Duration::hours(1),
        })
    }

    fn mint(issuer: &Issuer, at: OffsetDateTime) -> String {
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: at,
            attributes: Default::default(),
        };
        issuer
            .issue_root(
                user,
                AgentId::new("planner"),
                [Capability::new("github", "read_file")]
                    .into_iter()
                    .collect::<CapabilitySet>(),
                Some(Duration::minutes(10)),
                at,
            )
            .unwrap()
            .token
    }

    #[test]
    fn live_and_expired_tokens_verify_and_say_which() {
        let iss = issuer();
        let now = OffsetDateTime::now_utc();
        let live = mint(&iss, now);
        let (_, expired) = verify_allowing_expiry(&iss.verifier(), &live, now).unwrap();
        assert!(!expired);

        let old = mint(&iss, now - Duration::hours(2));
        assert!(matches!(
            iss.verifier().verify(&old, now),
            Err(TokenError::Expired)
        ));
        let (v, expired) = verify_allowing_expiry(&iss.verifier(), &old, now).unwrap();
        assert!(expired);
        assert_eq!(v.chain.originating_user.subject, "alice");
    }

    #[test]
    fn a_token_from_another_key_is_refused_even_when_expired() {
        let now = OffsetDateTime::now_utc();
        let theirs = mint(&issuer(), now - Duration::hours(2));
        assert!(verify_allowing_expiry(&issuer().verifier(), &theirs, now).is_err());
        assert!(verify_allowing_expiry(&issuer().verifier(), "not.a.jwt", now).is_err());
    }

    #[test]
    fn unverified_exp_reads_the_claim() {
        let now = OffsetDateTime::now_utc();
        let t = mint(&issuer(), now);
        let exp = unverified_exp(&t).unwrap();
        assert!((exp - (now + Duration::minutes(10)).unix_timestamp()).abs() <= 1);
        assert_eq!(unverified_exp("x"), None);
        assert_eq!(unverified_exp("x.!!!.y"), None);
    }
}

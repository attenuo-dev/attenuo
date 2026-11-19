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
use attenuo_policy::{ArgLabels, CallLabels, SessionLabels};
use attenuo_token::{TokenError, VerifiedToken, Verifier};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::Digest;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::extract::Body;
use super::parse_json;
use crate::authz::{CounterSource, StatedBudget, StatedLimit, MAX_STATED_LIMITS};
use crate::error::ApiError;
use crate::state::AppState;

/// `lease_check` of every dry run: the lease stage is never run.
pub const LEASE_CHECK_SKIPPED: &str = "skipped";
/// `chain_source` when the chain came from a verified token in the request body.
pub const CHAIN_SOURCE_TOKEN: &str = "token";
/// `chain_source` when the admin supplied the chain itself in `subject.properties.chain`.
pub const CHAIN_SOURCE_ADMIN: &str = "admin_supplied";

fn lock_poisoned() -> ApiError {
    ApiError::internal("loaded policy info lock poisoned")
}

/// `GET /admin/policies`: the policy set in force.
///
/// `{path, sha256, loaded_at, policy_ids, warnings, policies: [{id, text}]}`. `sha256` and
/// `loaded_at` describe the file text the engine loaded (at startup or by the last successful
/// reload), so after an edit that was not reloaded they still describe the old text. `path`
/// and `sha256` are `null` when no `policy.policies_path` is configured.
///
/// # Errors
///
/// 500 `server_error` when the loaded-policy info lock is poisoned (a reload panicked).
pub async fn get_policies(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    // The snapshot is taken while the loaded-policy info is held for reading, and a reload
    // swaps the engine while holding it for writing, so the pair describes one policy set.
    let (engine, loaded) = {
        let loaded = state.loaded_policies.read().map_err(|_| lock_poisoned())?;
        (state.pipeline.policy_snapshot(), loaded.clone())
    };
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
///
/// # Errors
///
/// 409 when no `policy.policies_path` is configured, and 500 `server_error` when the file cannot be
/// read or the loaded policy info lock is poisoned. A file that does not lint is not an error
/// but `ok: false`.
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
        let engine = state.pipeline.policy_snapshot();
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
/// chain_source: "token" | "admin_supplied", token_expired, session, approval, budget, usage}`,
/// plus `limit` when a run limit would be exceeded. `budget` is what the run limits matching
/// the call have left, as `context.budget` (ADR-0010), with `source`: `store` when read from
/// the lease store, `request` when the body states the run's limits in its optional `budget`
/// block (see `budget_from_json`). Either way the counters go through the pipeline's own
/// limit check ([`Pipeline::budget_view_from`](crate::authz::Pipeline::budget_view_from)), so
/// a spent hard limit answers `budget_exhausted` with the live diagnostic; the dry run never
/// charges a counter, and a stated `budget` is never read from or written to the store.
/// `usage` is `context.usage` (run-limits design section 3.5): as given in the request's
/// optional `usage: {calls, amount, destination_seen, user_window}`, or else the run's usage
/// of a destructive tool, with its user's per-user windows (run limits phase 3, the kinds a
/// loaded policy reads), read from the store (all zero for any other tool, and all zero when
/// the body states a `budget`), with `source` saying which: `request`, `store`, or `untracked`
/// when the engine keeps no run usage at all
/// ([`attenuo_policy::PolicyEngine::tracks_usage`]), so the zeros are not a reading of the
/// run.
///
/// # Errors
///
/// 400 `invalid_request` for a body that is not a JSON object or an AuthZEN request, a non-string
/// `token`, a malformed `session`, `approval`, `usage` or `budget` block, or a `budget` that does
/// not match the call's limits; 400 `invalid_token` for a token that does not verify (other than by
/// expiring); 400 `invalid_chain` for a body chain that fails `validate_at`.
pub async fn evaluate_policies(
    State(state): State<Arc<AppState>>,
    Body(body): Body,
) -> Result<Json<Value>, ApiError> {
    let now = state.now();
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
    // `approval: {"by": "user" | "operator" | "policy"}`: evaluate as if the call carried a
    // granted approval. The dry run never looks one up or consumes one.
    let approval = match obj.remove("approval") {
        None | Some(Value::Null) => attenuo_policy::ApprovalContext::default(),
        Some(v) => approval_from_json(&v)?,
    };
    // `usage: {calls, amount, destination_seen}`: evaluate with this run usage instead of the
    // store's. Members left out are 0 or false.
    let usage_given = match obj.remove("usage") {
        None | Some(Value::Null) => None,
        Some(v) => Some(usage_from_json(&v)?),
    };
    // `budget: {calls_remaining, amount_remaining, destination_new, limited, limits}`: the run
    // limits' state the call is decided against, instead of the store's counters.
    let stated = match obj.remove("budget") {
        None | Some(Value::Null) => None,
        Some(v) => Some(budget_from_json(&v, usage_given.unwrap_or_default())?),
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

    // One policy set for every stage of the dry run, as for a decision.
    let engine = state.pipeline.policy_snapshot();
    let engine = engine.as_ref();
    // Output labels (ADR-0009): as given, or else the run's current taint state and, on a
    // tainted run, the arguments that match its span index now (for every call when a policy
    // reads argument taint, else for a destructive call; `Pipeline::arg_taint`).
    let (session, args, session_source) = match session {
        Some((s, args)) => (s, args, "request"),
        None => {
            let s = state.pipeline.run_labels(&chain).session;
            let args = state.pipeline.arg_taint(engine, &chain, &call, &s).context;
            (s, args, "store")
        }
    };
    // Run limits (ADR-0010): the counters as they are now, or as the request states them.
    // Read, never charged.
    let (budget, budget_source) = match &stated {
        None => {
            let mut view = state.pipeline.budget_view(engine, &chain, &call);
            // Per-user windows (run limits phase 3) are read with the run's usage.
            state
                .pipeline
                .add_user_windows(engine, &mut view, &chain, &call, now);
            (view, "store")
        }
        Some(s) => {
            let mut view =
                state
                    .pipeline
                    .budget_view_from(engine, &chain, &call, CounterSource::Stated(s));
            let arg_invalid = view
                .context
                .refusal
                .as_ref()
                .is_some_and(|r| r.reason == attenuo_core::limits::REASON_LIMIT_ARG_INVALID);
            if !arg_invalid {
                if let Some(m) = s.unmatched(&view.charges) {
                    return Err(ApiError::bad_request(
                        "invalid_request",
                        format!("`budget`: {m}"),
                    ));
                }
            }
            if !view.context.limited {
                // No limit to check: Cedar sees the figures as stated, as in `policy test`.
                view.context = s.unlimited_context();
            }
            (view, "request")
        }
    };
    let (usage, usage_source) = match usage_given {
        Some(u) => (u, "request"),
        None if stated.is_some() => (budget.usage.unwrap_or_default(), "request"),
        None => {
            let tracked = engine.tracks_usage();
            let source = if tracked { "store" } else { "untracked" };
            (budget.usage.unwrap_or_default(), source)
        }
    };
    let labels = CallLabels {
        session: session.clone(),
        args: args.clone(),
        approval: approval.clone(),
        budget: budget.context.clone(),
        usage,
    };
    let o = state
        .pipeline
        .evaluate_policy(engine, &chain, &call, &labels, now);
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
            "args_contain_untrusted": args.contain_untrusted,
            "untrusted_args": args.untrusted,
            "source": session_source,
        },
        "approval": { "present": approval.present, "by": approval.by },
        "budget": crate::authz::budget_json(&budget.context),
        "usage": crate::authz::usage_json(&usage),
    });
    out["usage"]["source"] = usage_source.into();
    out["budget"]["source"] = budget_source.into();
    if let Some(hit) = &budget.hit {
        out["limit"] = hit.to_json();
    }
    Ok(Json(out))
}

/// The optional `budget` member of a dry run: the state of the run limits the call is decided
/// against, in the vocabulary of a `policy test` case's `budget`, plus single counters:
///
/// ```json
/// {"calls_remaining": 0, "amount_remaining": 40, "destination_new": false, "limited": true,
///  "limits": [{"hop": 0, "kind": "distinct", "arg": "to", "used": 3, "max": 3}]}
/// ```
///
/// Every member is optional. The figures are non-negative integers (`destination_new` and
/// `limited` booleans); `limits` holds at most [`MAX_STATED_LIMITS`] entries, each with `hop`
/// (non-negative integer), `kind` (`calls`, `sum`, `calls_per` or `distinct`), `arg` (a string,
/// required for every kind but `calls`, refused for `calls`), `used` (required) and `max`
/// (checked against the limit's), no two naming the same limit. Anything else is 400
/// `invalid_request` naming the member. `usage` is the request's `usage` (zero when absent).
fn budget_from_json(
    v: &Value,
    usage: attenuo_policy::UsageContext,
) -> Result<StatedBudget, ApiError> {
    let bad = |m: &str| ApiError::bad_request("invalid_request", format!("`budget`: {m}"));
    let obj = v.as_object().ok_or_else(|| bad("expected an object"))?;
    const KNOWN: [&str; 5] = [
        "limited",
        "calls_remaining",
        "amount_remaining",
        "destination_new",
        "limits",
    ];
    if let Some(k) = obj.keys().find(|k| !KNOWN.contains(&k.as_str())) {
        return Err(bad(&format!("unknown member `{k}`")));
    }
    let count = |o: &serde_json::Map<String, Value>, key: &str, at: &str| match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(n) => n
            .as_i64()
            .and_then(|n| u64::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| bad(&format!("`{at}{key}` must be a non-negative integer"))),
    };
    let flag = |key: &str| match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(bad(&format!("`{key}` must be a boolean"))),
    };
    let entries = match obj.get("limits") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) if items.len() <= MAX_STATED_LIMITS => items.as_slice(),
        Some(Value::Array(items)) => {
            return Err(bad(&format!(
                "`limits` lists {} entries; at most {MAX_STATED_LIMITS}",
                items.len()
            )))
        }
        Some(_) => return Err(bad("`limits` must be a list")),
    };
    let mut limits: Vec<StatedLimit> = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let at = format!("limits[{i}].");
        let o = e
            .as_object()
            .ok_or_else(|| bad(&format!("`limits[{i}]` must be an object")))?;
        if let Some(k) = o
            .keys()
            .find(|k| !matches!(k.as_str(), "hop" | "kind" | "arg" | "used" | "max"))
        {
            return Err(bad(&format!("unknown member `{at}{k}`")));
        }
        let hop = count(o, "hop", &at)?.ok_or_else(|| bad(&format!("`{at}hop` is required")))?;
        let used = count(o, "used", &at)?.ok_or_else(|| bad(&format!("`{at}used` is required")))?;
        let max = count(o, "max", &at)?;
        let kind = match o.get("kind") {
            Some(Value::String(k)) => attenuo_core::LimitKind::parse(k).ok_or_else(|| {
                bad(&format!(
                    "`{at}kind`: unknown limit kind `{k}` (calls, sum, calls_per or distinct)"
                ))
            })?,
            _ => return Err(bad(&format!("`{at}kind` must be a string"))),
        };
        let arg = match o.get("arg") {
            None | Some(Value::Null) => None,
            Some(Value::String(a)) if a.len() <= 256 => Some(a.clone()),
            Some(_) => {
                return Err(bad(&format!(
                    "`{at}arg` must be a string of at most 256 bytes"
                )))
            }
        };
        match (kind, &arg) {
            (attenuo_core::LimitKind::Calls, Some(_)) => {
                return Err(bad(&format!(
                    "`{at}arg`: a `calls` limit counts no argument"
                )))
            }
            (attenuo_core::LimitKind::Calls, None) => {}
            (_, None) => return Err(bad(&format!("`{at}arg` is required for `{kind}`"))),
            (_, Some(_)) => {}
        }
        let entry = StatedLimit {
            hop: usize::try_from(hop).unwrap_or(usize::MAX),
            kind,
            arg,
            max,
            used,
        };
        if limits
            .iter()
            .any(|l| (l.hop, l.kind, &l.arg) == (entry.hop, entry.kind, &entry.arg))
        {
            return Err(bad(&format!(
                "`limits[{i}]` names the same limit as an earlier entry"
            )));
        }
        limits.push(entry);
    }
    Ok(StatedBudget {
        limited: flag("limited")?,
        calls_remaining: count(obj, "calls_remaining", "")?,
        amount_remaining: count(obj, "amount_remaining", "")?,
        destination_new: flag("destination_new")?,
        limits,
        usage,
    })
}

/// The optional `usage` member of a dry run: `{"calls": n, "amount": n, "destination_seen":
/// bool, "user_window": {"hour": {"calls": n, "amount": n}, "day": {...}}}`, each optional (0
/// or false), the figures non-negative integers.
fn usage_from_json(v: &Value) -> Result<attenuo_policy::UsageContext, ApiError> {
    let bad = |m: &str| ApiError::bad_request("invalid_request", format!("`usage`: {m}"));
    let obj = v.as_object().ok_or_else(|| bad("expected an object"))?;
    if let Some(k) = obj.keys().find(|k| {
        !matches!(
            k.as_str(),
            "calls" | "amount" | "destination_seen" | "user_window"
        )
    }) {
        return Err(bad(&format!("unknown member `{k}`")));
    }
    let figure_in = |obj: &serde_json::Map<String, Value>, key: &str| -> Result<i64, ApiError> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(0),
            Some(n) => n
                .as_i64()
                .filter(|n| *n >= 0)
                .ok_or_else(|| bad(&format!("`{key}` must be a non-negative integer"))),
        }
    };
    let figure = |key: &str| figure_in(obj, key);
    let mut user_window = attenuo_policy::UserWindowContext::default();
    if let Some(w) = obj.get("user_window").filter(|w| !w.is_null()) {
        let w = w
            .as_object()
            .ok_or_else(|| bad("`user_window` must be an object"))?;
        for (kind, f) in w {
            let kind = attenuo_core::WindowKind::parse(kind)
                .ok_or_else(|| bad(&format!("`user_window`: unknown kind `{kind}`")))?;
            let f = f
                .as_object()
                .ok_or_else(|| bad(&format!("`user_window.{kind}` must be an object")))?;
            if let Some(k) = f.keys().find(|k| !matches!(k.as_str(), "calls" | "amount")) {
                return Err(bad(&format!("`user_window.{kind}`: unknown member `{k}`")));
            }
            *user_window.get_mut(kind) = attenuo_policy::WindowFigures {
                calls: figure_in(f, "calls")?,
                amount: figure_in(f, "amount")?,
            };
        }
    }
    let destination_seen = match obj.get("destination_seen") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(bad("`destination_seen` must be a boolean")),
    };
    Ok(attenuo_policy::UsageContext {
        calls: figure("calls")?,
        amount: figure("amount")?,
        destination_seen,
        user_window,
    })
}

/// The optional `approval` member of a dry run: `{"by": "user" | "operator" | "policy"}`,
/// evaluated as if the call carried an approval granted by that party. `by` is required (an
/// empty block is not an approval) and no other member is taken: no approval id or token,
/// since the dry run never looks a stored approval up. Anything else is 400 `invalid_request`
/// naming the member, so a misspelt member is not silently read as "no approval".
fn approval_from_json(v: &Value) -> Result<attenuo_policy::ApprovalContext, ApiError> {
    let bad = |m: &str| ApiError::bad_request("invalid_request", format!("`approval`: {m}"));
    let obj = v.as_object().ok_or_else(|| bad("expected an object"))?;
    if let Some(k) = obj.keys().find(|k| k.as_str() != "by") {
        return Err(bad(&format!("unknown member `{k}`")));
    }
    match obj.get("by") {
        Some(Value::String(by)) if matches!(by.as_str(), "user" | "operator" | "policy") => {
            Ok(attenuo_policy::ApprovalContext::by(by))
        }
        None | Some(Value::Null) => Err(bad(
            "`by` is required (\"user\", \"operator\" or \"policy\")",
        )),
        Some(_) => Err(bad("`by` must be \"user\", \"operator\" or \"policy\"")),
    }
}

/// The optional `session` member of a dry run: `{"tainted_by": ["<server>/<tool>", ...],
/// "tainted": bool, "untrusted_args": ["<argument>", ...], "args_contain_untrusted": bool}`.
/// `tainted` defaults to whether `tainted_by` is non-empty, `args_contain_untrusted` to
/// whether `untrusted_args` is (ADR-0009 phase 2); either may be set `true` alone.
fn session_from_json(v: &Value) -> Result<(SessionLabels, ArgLabels), ApiError> {
    let bad = |m: &str| ApiError::bad_request("invalid_request", format!("`session`: {m}"));
    let obj = v.as_object().ok_or_else(|| bad("expected an object"))?;
    const KNOWN: [&str; 4] = [
        "tainted",
        "tainted_by",
        "untrusted_args",
        "args_contain_untrusted",
    ];
    if let Some(k) = obj.keys().find(|k| !KNOWN.contains(&k.as_str())) {
        return Err(bad(&format!("unknown member `{k}`")));
    }
    let strings = |key: &str| -> Result<Vec<String>, ApiError> {
        let msg = format!("`{key}` must be a list of strings");
        match obj.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|i| i.as_str().map(str::to_owned).ok_or_else(|| bad(&msg)))
                .collect(),
            Some(_) => Err(bad(&msg)),
        }
    };
    let flag = |key: &str| -> Result<Option<bool>, ApiError> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(bad(&format!("`{key}` must be a boolean"))),
        }
    };
    let mut session = SessionLabels::from_sources(strings("tainted_by")?);
    if let Some(t) = flag("tainted")? {
        session.tainted = t || !session.tainted_by.is_empty();
    }
    let mut args = ArgLabels::from_args(strings("untrusted_args")?);
    if let Some(c) = flag("args_contain_untrusted")? {
        args.contain_untrusted = c || !args.untrusted.is_empty();
    }
    Ok((session, args))
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
///
/// # Errors
///
/// The [`TokenError`] of the first verification when it fails for any reason other than expiry,
/// [`TokenError::Expired`] when the payload's `exp` cannot be read, and the error of the second
/// verification when the token was not a good token at that earlier time either.
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

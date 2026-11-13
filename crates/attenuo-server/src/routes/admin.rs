//! `/admin/*`: leases, audit log and policy reload. Every route requires an admin
//! credential (`[admin] token` or an `[[admin.operators]]` entry) whose role reaches the
//! route's (see [`require_admin`] and [`crate::operators`]). The read-only policy routes
//! (`GET /admin/policies`, `/check`, `POST /admin/policies/evaluate`) are in
//! [`super::policies`].

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_audit::{
    AuditEntry, AuditError, AuditSink, EntryFilter, LeaseNode, LeaseRegistry, LeaseSelector, Order,
    RunLimits, RunState, SelectorRevocation, SignedVerifyReport,
};
use attenuo_core::{AgentId, LeaseId, RecordKind};
use axum::body::Bytes;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::extract::{Body, Path, Query};
use super::page;
use super::{audit_admin, bearer_of, REASON_ADMIN_ACTION};
use crate::error::ApiError;
use crate::metrics::RefundSource;
use crate::operators::{required_role, AdminIdentity};
use crate::state::AppState;
use attenuo_core::Decision;
use attenuo_proxy::session::{session_digest, session_tag};
use sha2::Digest;

/// Largest page `GET /admin/audit` and `GET /admin/audit/checkpoints` return; a larger
/// `limit` is a 400.
pub const MAX_AUDIT_PAGE: usize = 1000;
/// Page size of `GET /admin/audit` and `GET /admin/audit/checkpoints` without `limit`.
pub const DEFAULT_AUDIT_PAGE: usize = 100;

/// Middleware: the request must carry `Authorization: Bearer <token>` with the token of an
/// admin credential whose role is at least the one the route needs.
///
/// - No credential configured: 403 `admin_disabled` on every route, so a forgotten setting
///   fails closed rather than open.
/// - No bearer, or one that matches no credential: 401 with
///   `WWW-Authenticate: Bearer realm="attenuo-admin"`. The bearer is hashed and compared with
///   every credential in constant time ([`AdminCredentials::authenticate`]).
/// - A role below [`required_role`] of the matched route (a route with no entry in
///   [`crate::operators::ROUTE_ROLES`] needs `admin`): 403 `admin_role_insufficient`, naming
///   the role needed.
///
/// Otherwise the request goes on with an [`AdminIdentity`] in its extensions, which the
/// handlers record as the actor.
///
/// [`AdminCredentials::authenticate`]: crate::operators::AdminCredentials::authenticate
pub async fn require_admin(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    if state.admin_credentials.is_empty() {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "admin_disabled",
            "no admin credential is configured ([admin] token or [[admin.operators]])",
        )
        .into_response();
    }
    let identity = match bearer_of(req.headers()) {
        Ok(Some(token)) => state.admin_credentials.authenticate(token),
        _ => None,
    };
    let Some(identity) = identity else {
        let reason = match bearer_of(req.headers()) {
            Ok(None) => crate::error::REASON_MISSING_TOKEN,
            _ => crate::error::REASON_INVALID_TOKEN,
        };
        let mut resp =
            ApiError::unauthorized(reason, "admin bearer token required").into_response();
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"attenuo-admin\""),
        );
        return resp;
    };
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());
    let needed = required_role(req.method(), route.as_deref());
    if identity.role < needed {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            ROLE_INSUFFICIENT,
            format!(
                "this route needs the `{needed}` role; the credential presented has the `{}` \
                 role",
                identity.role
            ),
        )
        .into_response();
    }
    req.extensions_mut().insert(identity);
    next.run(req).await
}

/// `error` of an admin request whose credential's role is below the route's (403).
pub const ROLE_INSUFFICIENT: &str = "admin_role_insufficient";

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `GET /admin/whoami`: the name and role of the credential that sent the request,
/// `{"name": ..., "role": "viewer" | "operator" | "admin"}`. The operator of `[admin] token`
/// is `{"name": "admin", "role": "admin"}`. Reads nothing else and records nothing.
pub async fn whoami(Extension(who): Extension<AdminIdentity>) -> Json<Value> {
    Json(json!({ "name": who.name, "role": who.role }))
}

/// Body of `POST /admin/leases/{lease_id}/revoke`; an empty body is allowed.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBody {
    /// Why the lease is revoked, stored with it and in the audit record. Default
    /// `revoked by admin`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /admin/leases/{lease_id}/revoke` with `{ "reason": "..." }`: revoke the lease and
/// every lease delegated from it. Returns how many leases changed state.
///
/// # Errors
///
/// 400 `invalid_request` when a non-empty body is not the expected JSON, 404 `not_found` when the
/// registry has no such lease, and 500 `server_error` when the lease store fails. A failure to
/// write the audit record is not an error (`audit_id` is null).
pub async fn revoke_lease(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
    Path(lease_id): Path<String>,
    Body(body): Body,
) -> Result<Json<Value>, ApiError> {
    let body: RevokeBody = if body.is_empty() {
        RevokeBody::default()
    } else {
        super::parse_json(&body)?
    };
    let reason = body
        .reason
        .unwrap_or_else(|| format!("revoked by {}", who.name));
    let lease = LeaseId::new(lease_id);
    let now = state.now();
    state
        .blocking(move |state| {
            let revoked = state.leases.revoke(&lease, &reason, now)?;
            state.metrics.leases_revoked(revoked);
            tracing::warn!(lease = ?lease.0, reason = ?reason, revoked, "lease revoked");
            // The revocation stands even if it cannot be recorded: undoing it would be the
            // unsafe direction. The response says whether it was audited.
            let audit_id = audit_admin(
                state,
                &who,
                "admin.lease.revoke",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                vec![lease.clone()],
                json!({ "lease": lease, "reason": reason, "revoked": revoked }),
                now,
            )
            .inspect_err(|e| tracing::error!(error = ?e.detail, "admin revoke was not audited"))
            .ok();
            Ok(Json(json!({
                "lease_id": lease,
                "revoked": revoked,
                "reason": reason,
                "audit_id": audit_id,
            })))
        })
        .await
}

/// Most lease ids `POST /admin/leases/revoke` lists in its response, per list (`matched`,
/// `revoked`). The counts are always complete; `truncated` says a list was cut.
pub const MAX_SELECTOR_RESPONSE_IDS: usize = 10_000;
/// Most lease ids the audit record of a selector revocation names in `leases`. The record's
/// arguments carry the full count.
pub const MAX_SELECTOR_AUDIT_IDS: usize = 256;

/// Body of `POST /admin/leases/revoke`: exactly one selector, and an optional reason.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorRevokeBody {
    /// The originating user's subject (`sub`).
    #[serde(default)]
    pub user: Option<String>,
    /// A delegation chain id: the lease of the chain's first hop.
    #[serde(default)]
    pub chain_id: Option<String>,
    /// An MCP session id (`Mcp-Session-Id`), as the client or upstream saw it. The server
    /// hashes it and resolves it to the chains that opened it through the proxy.
    #[serde(default)]
    pub session: Option<String>,
    /// Why the leases are revoked, for the audit record. Default `revoked by admin`; ignored
    /// with `?preview=true`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Query of `POST /admin/leases/revoke`.
#[derive(Debug, Default, Deserialize)]
pub struct SelectorRevokeQuery {
    /// Dry run: answer what would be revoked and write nothing.
    #[serde(default)]
    pub preview: bool,
}

/// The selector of a [`SelectorRevokeBody`] and how the response shows it, or 400 unless
/// exactly one non-empty selector is given.
fn selector_of(body: &SelectorRevokeBody) -> Result<(LeaseSelector, Value), ApiError> {
    let given = [
        body.user.is_some(),
        body.chain_id.is_some(),
        body.session.is_some(),
    ];
    if given.iter().filter(|g| **g).count() != 1 {
        return Err(ApiError::bad_request(
            "invalid_request",
            "give exactly one of `user`, `chain_id`, `session`",
        ));
    }
    let non_empty = |field: &str, v: &str| {
        if v.is_empty() {
            Err(ApiError::bad_request(
                "invalid_request",
                format!("`{field}` must not be empty"),
            ))
        } else {
            Ok(())
        }
    };
    if let Some(user) = &body.user {
        non_empty("user", user)?;
        return Ok((
            LeaseSelector::Subject(user.clone()),
            json!({ "user": user }),
        ));
    }
    if let Some(chain) = &body.chain_id {
        non_empty("chain_id", chain)?;
        return Ok((
            LeaseSelector::Chain(LeaseId::new(chain.clone())),
            json!({ "chain_id": chain }),
        ));
    }
    let session = body.session.as_deref().unwrap_or_default();
    non_empty("session", session)?;
    // The raw id is a secret that grants use of the session: only its digest is looked up,
    // and only its audit tag is shown (the resolved chains are added by the caller).
    Ok((
        LeaseSelector::Session(session_digest(session)),
        json!({ "session_tag": session_tag(session) }),
    ))
}

/// For a session selector, add the chains the session resolves to (`chain_ids`, ordered by
/// server, one per upstream the session was opened with) to how the response shows it.
fn resolve_shown(
    state: &AppState,
    selector: &LeaseSelector,
    shown: &mut Value,
) -> Result<(), AuditError> {
    if let LeaseSelector::Session(digest) = selector {
        let chains: Vec<LeaseId> = state
            .leases
            .sessions(digest)?
            .into_iter()
            .map(|b| b.chain_id)
            .collect();
        shown["chain_ids"] = json!(chains);
    }
    Ok(())
}

/// The response of `POST /admin/leases/revoke`, each list cut at
/// [`MAX_SELECTOR_RESPONSE_IDS`].
fn selector_response(
    shown: Value,
    out: &SelectorRevocation,
    reason: Option<&str>,
    audit_id: Option<uuid::Uuid>,
) -> Json<Value> {
    let list = |ids: &[LeaseId]| -> Vec<LeaseId> {
        ids.iter()
            .take(MAX_SELECTOR_RESPONSE_IDS)
            .cloned()
            .collect()
    };
    Json(json!({
        "selector": shown,
        "preview": reason.is_none(),
        "matched": list(&out.matched),
        "revoked": list(&out.revoked),
        "matched_count": out.matched.len(),
        "revoked_count": out.revoked.len(),
        "truncated": out.matched.len() > MAX_SELECTOR_RESPONSE_IDS
            || out.revoked.len() > MAX_SELECTOR_RESPONSE_IDS,
        "reason": reason,
        "audit_id": audit_id,
    }))
}

/// `POST /admin/leases/revoke[?preview=true]` with `{"user": "..."}`, `{"chain_id": "..."}`
/// or `{"session": "..."}` (exactly one) and an optional `"reason"`: revoke every unrevoked
/// lease the selector names, each with the descendant cascade of
/// `POST /admin/leases/{id}/revoke`, in one transaction. An expired lease is matched too,
/// since `POST /token/renew` could bring it back while its token is valid.
///
/// - `user` matches the leases issued for that originating user (`sub`), under any issuer.
///   Leases registered by a server older than this route have no recorded subject and are
///   not matched; revoke them by `chain_id` or by id.
/// - `chain_id` matches that chain's first-hop lease and everything delegated from it. A
///   lease with a parent is not a chain id and matches nothing.
/// - `session` takes a raw MCP session id, hashes it ([`session_digest`]) and matches, as
///   `chain_id` would, the chain of each caller that opened the session through the proxy
///   (`RunState::record_session`, written when the proxy binds a new session for a verified
///   token). The response's `selector` is `{session_tag, chain_ids}`: the session's audit
///   tag and the resolved chains, never the id. A session the server never recorded (unknown,
///   or opened before this route existed) resolves to no chain and matches nothing.
///
/// Answers `{selector, preview, matched, revoked, matched_count, revoked_count, truncated,
/// reason, audit_id}`: `matched` the leases the selector named, `revoked` every lease that
/// changed (the matches first, then the cascade), each list cut at
/// [`MAX_SELECTOR_RESPONSE_IDS`]. Matching nothing is a 200 with empty lists. With
/// `preview=true` nothing is written, not even an audit record, and `revoked` is what a
/// revocation sent now would change (`reason` and `audit_id` are null).
///
/// A revocation appends one `admin.lease.revoke` record (kind `lease_revoke`) whose `leases`
/// holds the first [`MAX_SELECTOR_AUDIT_IDS`] revoked ids and whose arguments (stored as a
/// digest, like every admin record) are the selector, the reason, the count and whether the
/// list was cut. As with a single revocation, the revocation stands if the record cannot be
/// written; `audit_id` is then null.
///
/// # Errors
///
/// 400 `invalid_request` when the body is not the expected JSON, names none or more than one of
/// `user`, `chain_id` and `session`, or gives an empty one, and 500 `server_error` when the lease
/// store fails (nothing is revoked then). Matching nothing and a failed audit append are not
/// errors.
pub async fn revoke_by_selector(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
    Query(q): Query<SelectorRevokeQuery>,
    Body(body): Body,
) -> Result<Json<Value>, ApiError> {
    let body: SelectorRevokeBody = if body.is_empty() {
        SelectorRevokeBody::default()
    } else {
        super::parse_json(&body)?
    };
    let (selector, mut shown) = selector_of(&body)?;
    let reason = body
        .reason
        .unwrap_or_else(|| format!("revoked by {}", who.name));
    let now = state.now();
    state
        .blocking(move |state| {
            resolve_shown(state, &selector, &mut shown)?;
            if q.preview {
                let out = state.leases.preview_selected(&selector)?;
                return Ok(selector_response(shown, &out, None, None));
            }
            let out = state.leases.revoke_selected(&selector, &reason, now)?;
            let revoked = out.revoked.len() as u64;
            state.metrics.leases_revoked(revoked);
            tracing::warn!(
                selector = %shown,
                reason = ?reason,
                matched = out.matched.len(),
                revoked,
                "leases revoked by selector"
            );
            // The revocation stands even if it cannot be recorded (see `revoke_lease`).
            let audited: Vec<LeaseId> = out
                .revoked
                .iter()
                .take(MAX_SELECTOR_AUDIT_IDS)
                .cloned()
                .collect();
            let listed = audited.len();
            let audit_id = audit_admin(
                state,
                &who,
                "admin.lease.revoke",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                audited,
                json!({
                    "selector": shown,
                    "reason": reason,
                    "revoked": revoked,
                    "listed": listed,
                    "truncated": out.revoked.len() > listed,
                }),
                now,
            )
            .inspect_err(|e| tracing::error!(error = ?e.detail, "admin revoke was not audited"))
            .ok();
            Ok(selector_response(shown, &out, Some(&reason), audit_id))
        })
        .await
}

/// Body of `POST /admin/budgets/refund`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundBody {
    /// The decision whose run-limit charge to return: the id of the allowed call's decision
    /// record (the AuthZEN `context.decision_id`).
    pub decision_id: String,
    /// Why the charge is returned, for the audit record. Default `refunded by admin`.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /admin/budgets/refund` with `{"decision_id": "...", "reason": "..."}` (ADR-0010):
/// return to every run-limit counter what that decision charged, at most once, and append an
/// `admin` record (tool `admin.budget.refund`) naming the decision. For an allowed call whose
/// effect an operator knows did not happen; neither the agent nor the upstream can refund.
/// When the charge log has nothing for the decision, the audit log (append-only, every
/// decision kept) tells why (`no_charge_refusal`): 410 `charge_pruned` when its record shows
/// a run-limit charge (the charge-log entry was pruned, `[leases] run_state_retention_seconds`,
/// only once the run's leases are gone), 404 `not_found` naming "charged nothing" or "unknown
/// decision" otherwise. 409 when it was already refunded. The run usage the
/// decision charged (run-limits design section 3.5) is returned too; `refunded` counts only
/// token-limit counters, so it is 0 for a call that charged usage alone.
///
/// As with a revocation, the refund stands if its record cannot be written; the response
/// then carries `audit_id: null` and the failure is logged.
///
/// # Errors
///
/// 400 `invalid_request` when the body is not the expected JSON; 404 `not_found` or 410
/// `charge_pruned` when the charge log has nothing for the decision, as above; 409
/// `already_refunded` when it was refunded before; 500 `server_error` when the lease store or the
/// audit lookup fails.
pub async fn refund_budget(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
    Body(body): Body,
) -> Result<Json<Value>, ApiError> {
    let body: RefundBody = super::parse_json(&body)?;
    let reason = body
        .reason
        .unwrap_or_else(|| format!("refunded by {}", who.name));
    let decision_id = body.decision_id;
    let now = state.now();
    state
        .blocking(move |state| {
            let refunded = state
                .leases
                .refund(&decision_id, now)
                .map_err(|e| match e {
                    // Why there is no charge is in the audit log; the rest is the
                    // central mapping (409 `already_refunded` included).
                    AuditError::UnknownCharge(_) => no_charge_refusal(state, &decision_id),
                    other => other.into(),
                })?;
            state.metrics.budget_refunded(RefundSource::Operator);
            tracing::warn!(decision = ?decision_id, reason = ?reason, refunded, "budget refunded");
            let audit_id = audit_admin(
                state,
                &who,
                "admin.budget.refund",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                Vec::new(),
                json!({ "decision_id": decision_id, "reason": reason, "refunded": refunded }),
                now,
            )
            .inspect_err(|e| tracing::error!(error = ?e.detail, "budget refund was not audited"))
            .ok();
            Ok(Json(json!({
                "decision_id": decision_id,
                "refunded": refunded,
                "reason": reason,
                "audit_id": audit_id,
            })))
        })
        .await
}

/// The refusal of a refund whose decision has no entry in the charge log, told apart by the
/// decision's audit record, which outlives the charge log:
///
/// - the record carries `budget` (the allowed call charged run-limit counters): the entry can
///   only have gone by run-state pruning, so 410 `charge_pruned`;
/// - an allowed decision whose `usage` carries `user_window` charged per-user windows, which
///   go only by their own retention: 410 `charge_pruned`;
/// - an allowed decision with `usage` and no `budget` charged run usage only, which is dropped
///   when its run's root lease is revoked as well as when it is pruned: 404 `not_found` saying
///   so (the two cannot be told apart from the record);
/// - any other record charged nothing: 404 `not_found`, "charged nothing";
/// - no record with that id (or not a UUID): 404 `not_found`, "unknown decision".
///
/// Reads only; nothing is audited for the refusal. A failed audit read is a 500.
fn no_charge_refusal(state: &AppState, decision_id: &str) -> ApiError {
    let record = match uuid::Uuid::parse_str(decision_id) {
        // Records store the hyphenated lower-case form.
        Ok(id) => match state.audit.entry_by_record_id(&id.to_string()) {
            Ok(entry) => entry.map(|e| e.record),
            Err(e) => return ApiError::internal(e),
        },
        Err(_) => None,
    };
    let Some(record) = record else {
        return ApiError::not_found(format!(
            "unknown decision `{decision_id}`: no audit record has this id; nothing to refund"
        ));
    };
    let decided = record.kind == RecordKind::Decision && record.decision.is_allow();
    if decided && record.budget.is_some() {
        ApiError::new(
            StatusCode::GONE,
            CHARGE_PRUNED,
            format!(
                "the charge of decision `{decision_id}` was pruned: its run's leases are gone \
                 and the charge is older than [leases] run_state_retention_seconds, so it can \
                 no longer be refunded (its audit record keeps what it charged)"
            ),
        )
    } else if decided && record.usage.is_some_and(|u| u.user_window.is_some()) {
        // Per-user windows are kept apart from the run and pruned only after their window
        // ended (`[leases] user_window_retention_seconds`), never at revocation.
        ApiError::new(
            StatusCode::GONE,
            CHARGE_PRUNED,
            format!(
                "the per-user window charge of decision `{decision_id}` was pruned: its window \
                 ended longer ago than [leases] user_window_retention_seconds, so it can no \
                 longer be refunded (its audit record keeps what the windows held)"
            ),
        )
    } else if decided && record.usage.is_some() {
        ApiError::not_found(format!(
            "decision `{decision_id}` charged no run limit, only run usage, which is no longer \
             recorded (dropped when its run was revoked, or pruned past [leases] \
             run_state_retention_seconds); nothing to refund"
        ))
    } else {
        ApiError::not_found(format!(
            "decision `{decision_id}` charged nothing: its audit record shows no run limit or \
             run usage charged; nothing to refund"
        ))
    }
}

/// `error` of a refund whose charge was pruned from the charge log (410).
pub const CHARGE_PRUNED: &str = "charge_pruned";

/// `GET /admin/leases/{lease_id}`: the lease's registry row and whether it is active now.
///
/// # Errors
///
/// 404 `not_found` when the registry has no such lease, and 500 `server_error` when the lease store
/// fails.
pub async fn lease_status(
    State(state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let lease = LeaseId::new(lease_id);
    state
        .blocking(move |state| {
            let row = state
                .leases
                .get(&lease)?
                .ok_or_else(|| AuditError::UnknownLease(lease.0.clone()))?;
            let fmt = |t: time::OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
            // Ask the store rather than the row so this agrees with what the pipeline sees.
            let active = state.leases.is_active(&lease, state.now())?;
            Ok(Json(json!({
                "lease_id": lease,
                "active": active,
                "parent": row.parent,
                "expires_at": fmt(row.expires_at),
                "revoked_at": row.revoked_at.map(fmt),
                "revoke_reason": row.revoke_reason,
            })))
        })
        .await
}

/// Leases `GET /admin/leases/{id}/tree` lists when the request names no `max_nodes`.
pub const DEFAULT_TREE_NODES: usize = 1000;
/// Most leases `GET /admin/leases/{id}/tree` lists, whatever `max_nodes` asks for. Bounds the
/// response and the issuance lookup; `would_revoke` still counts the whole subtree.
pub const MAX_TREE_NODES: usize = 10_000;

/// Query of `GET /admin/leases/{lease_id}/tree`.
#[derive(Debug, Deserialize)]
pub struct TreeQuery {
    /// Most nodes to list (default [`DEFAULT_TREE_NODES`], clamped to 1..=[`MAX_TREE_NODES`]).
    pub max_nodes: Option<usize>,
}

/// `GET /admin/leases/{lease_id}/tree?max_nodes=`: a dry-run revocation. Answers
/// `{root, ancestors, nodes, would_revoke, truncated}`:
///
/// - `nodes`: the lease, then everything delegated from it, breadth-first, at most
///   `max_nodes`; `truncated` says the cap cut the list short.
/// - `ancestors`: the leases it was delegated from, nearest first, ending at `root`, the
///   chain's first hop (also the audit `chain_id`).
/// - `would_revoke`: how many leases `POST /admin/leases/{lease_id}/revoke` would revoke if
///   sent now, counted over the whole subtree with the same query the revocation runs.
///
/// Each node carries its registry row, whether it is active now, `chain_id` (the chain's
/// first-hop lease, the same as `root`; the selector `POST /admin/leases/revoke` takes),
/// `subject` (the originating user recorded at issue, [`LeaseRegistry::subject`], read for all
/// nodes in one store call; null for a lease registered before subjects were recorded),
/// `agent`, `issued_at` and `issued_seq` from the audit record that issued it (null when none
/// is found), and `budget`, the hop's run limits and what is left of them (see `hop_budget`;
/// null when the hop has no limits and nothing was charged under its lease). Nothing is
/// written, not even an audit record: this is a read like `GET /admin/leases/{id}`.
///
/// # Errors
///
/// 404 `not_found` when the registry has no such lease, and 500 `server_error` when the lease store
/// or the audit log fails.
pub async fn lease_tree(
    State(state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
    Query(q): Query<TreeQuery>,
) -> Result<Json<Value>, ApiError> {
    let max_nodes = q
        .max_nodes
        .unwrap_or(DEFAULT_TREE_NODES)
        .clamp(1, MAX_TREE_NODES);
    let lease = LeaseId::new(lease_id);
    state
        .blocking(move |state| {
            let tree = state
                .leases
                .subtree(&lease, max_nodes)?
                .ok_or_else(|| AuditError::UnknownLease(lease.0.clone()))?;
            let root = tree.root().clone();
            // Every lease here descends from `root`, so one indexed lookup by `chain_id`
            // finds all their issuance records.
            let wanted: Vec<&LeaseId> = tree
                .ancestors
                .iter()
                .chain(&tree.nodes)
                .map(|n| &n.id)
                .collect();
            let issued: BTreeMap<LeaseId, AuditEntry> = state
                .audit
                .issuance_records(&root.0, &wanted)?
                .into_iter()
                .filter_map(|e| Some((e.record.leases.last()?.clone(), e)))
                .collect();
            // The originating user of every listed lease, in one store call however long
            // the list is. Leases registered before subjects were recorded have none.
            let subjects = state.leases.subjects(&wanted)?;
            let now = state.now();
            let fmt = |t: time::OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
            let budgets: BTreeMap<&LeaseId, Value> = tree
                .ancestors
                .iter()
                .chain(&tree.nodes)
                .map(|n| Ok((&n.id, hop_budget(state.leases.as_ref(), &n.id)?)))
                .collect::<Result<_, ApiError>>()?;
            let node = |n: &LeaseNode| {
                let issuance = issued.get(&n.id);
                json!({
                    "budget": budgets.get(&n.id).cloned().unwrap_or(Value::Null),
                    "lease_id": n.id,
                    "chain_id": root,
                    "subject": subjects.get(&n.id),
                    "parent": n.row.parent,
                    "expires_at": fmt(n.row.expires_at),
                    "revoked_at": n.row.revoked_at.map(fmt),
                    "revoke_reason": n.row.revoke_reason,
                    "active": n.row.is_active(now),
                    "agent": issuance.and_then(|e| e.record.agents.last()),
                    "issued_at": issuance.map(|e| fmt(e.record.at)),
                    "issued_seq": issuance.map(|e| e.seq),
                })
            };
            Ok(Json(json!({
                "root": root,
                "ancestors": tree.ancestors.iter().map(node).collect::<Vec<_>>(),
                "nodes": tree.nodes.iter().map(node).collect::<Vec<_>>(),
                "would_revoke": tree.would_revoke,
                "truncated": tree.truncated,
            })))
        })
        .await
}

/// The `budget` member of a lease tree node (run limits, ADR-0010): `null` when the hop has no
/// recorded limits and nothing was charged under its lease, else
/// `{recorded, limits: [..], usage: [..]}`:
///
/// - `recorded`: the server kept the hop's limits when it issued the token (leases issued by
///   an older version have counters but no recorded limits, so their `max` is null).
/// - `limits`: one entry per limit, `{cap, server, tool, kind, arg, max, used, remaining,
///   values}`. `arg` is null for `calls` and `arg#host` for a derived value. `used` is what
///   the counter holds: calls, the sum, for `distinct` how many values were seen, and for
///   `calls_per` the most calls any one value has had (`values` says how many values were
///   seen). `remaining` is `max - used` (for `calls_per`, what the most used value has left).
/// - `usage`: on a run's root lease, the run's usage per destructive tool, `{tool, calls,
///   amount, destinations}`.
///
/// Read only; value hashes are never shown.
fn hop_budget(leases: &dyn RunLimits, lease: &LeaseId) -> Result<Value, ApiError> {
    let recorded = leases.hop_limits(lease)?;
    let counters = leases.budget_summary(lease)?;
    if recorded.is_none() && counters.is_empty() {
        return Ok(Value::Null);
    }
    let find = |cap: usize, kind: &str, arg: &str| {
        counters
            .iter()
            .find(|c| c.cap == cap && c.kind == kind && c.arg == arg)
    };
    let entry = |cap: usize,
                 server: Option<&str>,
                 tool: Option<&str>,
                 kind: &str,
                 arg: Option<String>,
                 max: Option<u64>| {
        let row = find(cap, kind, arg.as_deref().unwrap_or(""));
        let used = row.map_or(0, |r| r.used);
        let mut v = json!({
            "cap": cap,
            "server": server,
            "tool": tool,
            "kind": kind,
            "arg": arg,
            "max": max,
            "used": used,
            "remaining": max.map(|m| m.saturating_sub(used)),
        });
        if kind == "calls_per" {
            v["values"] = row.map_or(0, |r| r.values).into();
        }
        v
    };
    let mut limits = Vec::new();
    match &recorded {
        Some(hop) => {
            for h in hop {
                let (s, t, l) = (Some(h.server.as_str()), Some(h.tool.as_str()), &h.limits);
                if let Some(max) = l.calls {
                    limits.push(entry(h.cap, s, t, "calls", None, Some(max)));
                }
                for (kind, a) in [
                    ("sum", &l.sum),
                    ("calls_per", &l.calls_per),
                    ("distinct", &l.distinct),
                ] {
                    if let Some(a) = a {
                        limits.push(entry(h.cap, s, t, kind, Some(a.counted()), Some(a.max)));
                    }
                }
            }
        }
        None => {
            for c in counters.iter().filter(|c| !c.kind.starts_with("usage_")) {
                let arg = (!c.arg.is_empty()).then(|| c.arg.clone());
                limits.push(entry(c.cap, None, None, &c.kind, arg, None));
            }
        }
    }
    let mut usage: BTreeMap<&str, Value> = BTreeMap::new();
    for c in counters.iter().filter(|c| c.kind.starts_with("usage_")) {
        let u = usage
            .entry(c.arg.as_str())
            .or_insert_with(|| json!({"tool": c.arg, "calls": 0, "amount": 0, "destinations": 0}));
        match c.kind.as_str() {
            "usage_calls" => u["calls"] = c.used.into(),
            "usage_amount" => u["amount"] = c.used.into(),
            _ => u["destinations"] = c.values.into(),
        }
    }
    Ok(json!({
        "recorded": recorded.is_some(),
        "limits": limits,
        "usage": usage.into_values().collect::<Vec<_>>(),
    }))
}

/// Most seqs one filtered `GET /admin/audit` page reads. `agent`, `lease`, `since` and
/// `until` cannot use an index, so without a bound one request could read the whole log. A
/// page that reaches the bound before it fills comes back short (possibly empty) with
/// `next_cursor` set, and the client keeps paging. Unfiltered pages need no bound: they read
/// exactly the rows they return.
pub const MAX_AUDIT_SCAN: u64 = 50_000;

/// Query string of `GET /admin/audit`. Every field is optional.
#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    /// Lowest seq to return (default 1), as `from` of `GET /admin/audit/export`.
    pub from: Option<u64>,
    /// Highest seq to return (default: the head), as `to` of `GET /admin/audit/export`.
    pub to: Option<u64>,
    /// Removed: refused with a message pointing at `cursor` and `to`.
    pub before: Option<String>,
    /// The `next_cursor` of the previous page ([`super::page`]).
    pub cursor: Option<String>,
    /// Page size (default [`DEFAULT_AUDIT_PAGE`], at most [`MAX_AUDIT_PAGE`]).
    pub limit: Option<usize>,
    /// `asc` (oldest first, the default) or `desc` (newest first).
    pub order: Option<String>,
    /// Record kinds, comma-separated (`decision,exchange`).
    pub kind: Option<String>,
    /// `allow` or `deny`.
    pub decision: Option<String>,
    /// The record's `reason`.
    pub reason: Option<String>,
    /// The record's `originating_subject`.
    pub subject: Option<String>,
    /// An agent in the record's `agents`.
    pub agent: Option<String>,
    /// A lease in the record's `leases`.
    pub lease: Option<String>,
    /// The record's `server`.
    pub server: Option<String>,
    /// The record's `tool`.
    pub tool: Option<String>,
    /// The record's `chain_id`.
    pub chain_id: Option<String>,
    /// Records at or after this RFC 3339 time.
    pub since: Option<String>,
    /// Records strictly before this RFC 3339 time.
    pub until: Option<String>,
}

/// The filter part of an [`AuditQuery`]. 400 `invalid_request` for an unknown kind or
/// decision, a time that is not RFC 3339, or an empty value.
fn entry_filter(q: &AuditQuery) -> Result<EntryFilter, ApiError> {
    let text = |name: &str, v: &Option<String>| -> Result<Option<String>, ApiError> {
        match v.as_deref() {
            Some("") => Err(ApiError::bad_request(
                "invalid_request",
                format!("`{name}` must not be empty"),
            )),
            other => Ok(other.map(str::to_string)),
        }
    };
    let time = |name: &str, v: &Option<String>| -> Result<Option<OffsetDateTime>, ApiError> {
        text(name, v)?
            .map(|s| {
                OffsetDateTime::parse(&s, &Rfc3339).map_err(|_| {
                    ApiError::bad_request(
                        "invalid_request",
                        format!("`{name}` must be an RFC 3339 time"),
                    )
                })
            })
            .transpose()
    };
    let kinds = match text("kind", &q.kind)? {
        None => Vec::new(),
        Some(list) => list
            .split(',')
            .map(|k| k.trim().parse::<RecordKind>())
            .collect::<Result<_, String>>()
            .map_err(|e| ApiError::bad_request("invalid_request", e))?,
    };
    let decision = match text("decision", &q.decision)?.as_deref() {
        None => None,
        Some("allow") => Some(Decision::Allow),
        Some("deny") => Some(Decision::Deny),
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`decision` must be `allow` or `deny`",
            ))
        }
    };
    Ok(EntryFilter {
        kinds,
        decision,
        reason: text("reason", &q.reason)?,
        subject: text("subject", &q.subject)?,
        agent: text("agent", &q.agent)?.map(AgentId::new),
        lease: text("lease", &q.lease)?.map(LeaseId::new),
        server: text("server", &q.server)?,
        tool: text("tool", &q.tool)?,
        chain_id: text("chain_id", &q.chain_id)?,
        since: time("since", &q.since)?,
        until: time("until", &q.until)?,
    })
}

/// `GET /admin/audit`: a page of audit entries, oldest first by default, as
/// `{entries, next_cursor, head}`. Paging is the one style of [`super::page`].
///
/// - `from` and `to` (inclusive seqs, default the whole log) select a range, as on
///   `GET /admin/audit/export`; they are filters, not page links.
/// - `order=asc` (default) returns the range oldest first, `order=desc` newest first.
/// - `cursor` continues where the previous page's `next_cursor` points; `next_cursor` is null
///   once the range has been read (oldest first: up to the head as it was when the page was
///   read; a later request with `from` just above the last seq reads what was appended since).
/// - Filters (`kind`, `decision`, `reason`, `subject`, `agent`, `lease`, `server`, `tool`,
///   `chain_id`, `since`, `until`) keep only matching entries; all are exact matches. A
///   filtered page reads at most [`MAX_AUDIT_SCAN`] seqs, so it can come back short, even
///   empty, with `next_cursor` set: keep paging until it is null.
///
/// The cursor's position is a seq, so entries appended while a client pages never shift the
/// ones it has not read: each is returned once. `head` is the newest seq (0 for an empty log);
/// reading it signs nothing, unlike `/admin/audit/checkpoint`.
///
/// # Errors
///
/// 400 `invalid_cursor` for a cursor that is malformed, of another route or of the other
/// `order`; 400 `invalid_request` for an `order` other than `asc` or `desc`, a `limit` of 0 or
/// above [`MAX_AUDIT_PAGE`], `from` or `to` of 0, `to < from`, the removed `before`, or a
/// filter that is empty or does not parse (an unknown `kind`, a `decision` other than `allow`
/// or `deny`, a `since` or `until` that is not RFC 3339); 500 `server_error` when the audit
/// log fails.
pub async fn audit_range(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Value>, ApiError> {
    if q.before.is_some() {
        return Err(page::removed(
            "before",
            "page with `cursor` (the `next_cursor` of the previous page) and select a range \
             with `from` and `to`",
        ));
    }
    let order = match q.order.as_deref() {
        None | Some("asc") => Order::Ascending,
        Some("desc") => Order::Descending,
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`order` must be `asc` or `desc`",
            ))
        }
    };
    let dir = match order {
        Order::Ascending => page::Direction::Ascending,
        Order::Descending => page::Direction::Descending,
    };
    let filter = entry_filter(&q)?;
    let limit = page::limit(q.limit, DEFAULT_AUDIT_PAGE, MAX_AUDIT_PAGE)?;
    let cursor = page::decode(q.cursor.as_deref(), page::List::Audit, dir)?;
    let (lo, hi) = seq_range(q.from, q.to)?;
    // How many seqs a page may read past where it starts (see MAX_AUDIT_SCAN).
    let span = if filter.is_empty() {
        u64::MAX
    } else {
        MAX_AUDIT_SCAN - 1
    };
    let (entries, next, head) = state
        .blocking(move |s| {
            // Read before the entries: entries appended after it are outside this page.
            let head = s.audit.head()?.map_or(0, |h| h.seq);
            let end = hi.min(head);
            // One more than the page, to tell whether anything follows it.
            let fetch = limit + 1;
            let (mut entries, next) = match order {
                Order::Ascending => {
                    // The cursor is the first seq of this page.
                    let start = cursor.map_or(lo, |c| c.max(lo));
                    if start > end {
                        (Vec::new(), None)
                    } else {
                        let stop = start.saturating_add(span).min(end);
                        let entries = s
                            .audit
                            .entries_matching(start, stop, &filter, order, fetch)?;
                        let next = match entries.get(limit) {
                            Some(_) => Some(entries[limit - 1].seq + 1),
                            None => (stop < end).then_some(stop + 1),
                        };
                        (entries, next)
                    }
                }
                Order::Descending => {
                    // The cursor is the seq every entry of this page is below.
                    let top = cursor.map_or(end, |c| (c - 1).min(end));
                    if top < lo || top == 0 {
                        (Vec::new(), None)
                    } else {
                        let bottom = top.saturating_sub(span).max(lo);
                        let entries = s
                            .audit
                            .entries_matching(bottom, top, &filter, order, fetch)?;
                        let next = match entries.get(limit) {
                            Some(_) => Some(entries[limit - 1].seq),
                            None => (bottom > lo).then_some(bottom),
                        };
                        (entries, next)
                    }
                }
            };
            entries.truncate(limit);
            Ok::<_, attenuo_audit::AuditError>((entries, next, head))
        })
        .await?;
    Ok(Json(json!({
        "entries": entries,
        "next_cursor": next.map(|p| page::encode(page::List::Audit, dir, p)),
        "head": head,
    })))
}

/// `from` and `to` of `GET /admin/audit`, as an inclusive range (`to` defaults to the
/// largest seq).
fn seq_range(from: Option<u64>, to: Option<u64>) -> Result<(u64, u64), ApiError> {
    let bad = |m: &str| Err(ApiError::bad_request("invalid_request", m.to_string()));
    let lo = from.unwrap_or(1);
    let hi = to.unwrap_or(u64::MAX);
    if lo == 0 {
        return bad("`from` must be at least 1");
    }
    if hi == 0 {
        return bad("`to` must be at least 1");
    }
    if hi < lo {
        return bad("`to` must not be below `from`");
    }
    Ok((lo, hi))
}

/// `GET /admin/audit/verify`: walk the whole chain and verify every stored checkpoint
/// signature against the JWKS keys. Besides `entries`, `ok` and `first_bad_seq` the report has
/// `checkpoints`, `last_signed_seq`, `unsigned_tail` and `bad_checkpoints`.
///
/// # Errors
///
/// 500 `server_error` when the audit log cannot be read (a store fault, not a broken chain: a break
/// or a bad checkpoint is reported in the answer).
pub async fn audit_verify(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SignedVerifyReport>, ApiError> {
    Ok(Json(
        state
            .blocking(|s| s.audit.verify_chain_signed(&s.checkpoint_keys))
            .await?,
    ))
}

/// `GET /admin/audit/checkpoint`: the signed checkpoint of the current head,
/// `{seq, head_hash, at, kid, signature}`. Created now if the head has none yet, so the answer
/// can be kept off-host and checked later with only the JWKS. `hash` repeats `head_hash` for
/// clients written against the unsigned v0 response.
///
/// # Errors
///
/// 500 `server_error` when the audit log cannot be read or written, or when a stored checkpoint
/// disagrees with the log at the head. (The audit crate's `NoCheckpointSigner` maps here too,
/// but the server always builds its sink with a signer, so it cannot arise in practice.)
pub async fn audit_checkpoint(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let cp = state
        .blocking(|s| s.audit.checkpoint_signed(s.now()))
        .await?;
    let mut v = serde_json::to_value(&cp).map_err(ApiError::internal)?;
    v["hash"] = Value::String(cp.head_hash.clone());
    Ok(Json(v))
}

/// The tool name `POST /admin/policies/reload` records ([`audit_admin`]).
const POLICY_RELOAD_TOOL: &str = "admin.policies.reload";

/// The body of the single-entry routes; the shape is described on [`audit_entry`].
fn entry_view(state: &AppState, entry: AuditEntry) -> Result<Value, ApiError> {
    let fmt = |t: time::OffsetDateTime| t.format(&Rfc3339).unwrap_or_default();
    let now = state.now();
    let mut lease_states = Vec::with_capacity(entry.record.leases.len());
    for lease in &entry.record.leases {
        let state_of = match state.leases.get(lease)? {
            None => json!({
                "lease_id": lease,
                "known": false,
                "active": false,
                "parent": null,
                "expires_at": null,
                "revoked_at": null,
                "revoke_reason": null,
            }),
            Some(row) => json!({
                "lease_id": lease,
                "known": true,
                "active": state.leases.is_active(lease, now)?,
                "parent": row.parent,
                "expires_at": fmt(row.expires_at),
                "revoked_at": row.revoked_at.map(fmt),
                "revoke_reason": row.revoke_reason,
            }),
        };
        lease_states.push(state_of);
    }
    let covered = state.audit.checkpoint_covering(entry.seq)?;
    let reloaded = state
        .audit
        .first_entry_after(
            entry.seq,
            RecordKind::Admin,
            POLICY_RELOAD_TOOL,
            &Decision::Allow,
        )?
        .map(|e| e.seq);
    Ok(json!({
        "entry": entry,
        "lease_states": lease_states,
        "covered_by_checkpoint": covered,
        "policy_reloaded_after": reloaded,
    }))
}

/// `GET /admin/audit/entries/{seq}`: one entry and its context, as
/// `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}`.
///
/// - `lease_states`: one object per lease in the record's chain, root first, as the lease
///   registry sees it now: `{lease_id, known, active, parent, expires_at, revoked_at,
///   revoke_reason}`. A lease the registry does not hold is `known: false, active: false`.
/// - `covered_by_checkpoint`: the oldest stored checkpoint at or after the entry's seq
///   (`{seq, head_hash, at, kid, signature}`), whose signature covers the entry through the
///   hash chain; null when the entry is newer than every checkpoint. It is read as stored:
///   `GET /admin/audit/verify` checks the signatures.
/// - `policy_reloaded_after`: the seq of the first successful policy reload recorded after
///   the entry, or null. When set, the policy in force now may not be the one that made the
///   decision.
///
/// # Errors
///
/// 404 `not_found` when there is no entry at `seq`, and 500 `server_error` when the audit log or
/// the lease store fails.
pub async fn audit_entry(
    State(state): State<Arc<AppState>>,
    Path(seq): Path<u64>,
) -> Result<Json<Value>, ApiError> {
    state
        .blocking(move |s| {
            let entry = s
                .audit
                .entry_at(seq)?
                .ok_or_else(|| ApiError::not_found(format!("no audit entry at seq {seq}")))?;
            entry_view(s, entry).map(Json)
        })
        .await
}

/// `GET /admin/audit/records/{id}`: the entry whose record id is `id`, the UUID that proxy
/// denials and AuthZEN answers return as `decision_id` (shape as for
/// `/admin/audit/entries/{seq}`).
///
/// # Errors
///
/// 400 `invalid_request` when `id` is not a UUID, 404 `not_found` when no record has it, and 500
/// `server_error` when the audit log or the lease store fails.
pub async fn audit_record(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = uuid::Uuid::parse_str(&id)
        .map_err(|_| ApiError::bad_request("invalid_request", "the record id must be a UUID"))?;
    state
        .blocking(move |s| {
            // Records store the hyphenated lower-case form.
            let entry = s
                .audit
                .entry_by_record_id(&id.to_string())?
                .ok_or_else(|| ApiError::not_found(format!("no audit record with id {id}")))?;
            entry_view(s, entry).map(Json)
        })
        .await
}

/// Query string of `GET /admin/audit/checkpoints`.
#[derive(Debug, Default, Deserialize)]
pub struct CheckpointsQuery {
    /// Removed: refused with a message pointing at `cursor`.
    pub before: Option<String>,
    /// The `next_cursor` of the previous page ([`super::page`]).
    pub cursor: Option<String>,
    /// Page size (default [`DEFAULT_AUDIT_PAGE`], at most [`MAX_AUDIT_PAGE`]).
    pub limit: Option<usize>,
}

/// `GET /admin/audit/checkpoints?cursor=&limit=`: stored checkpoints, newest first, as
/// `{checkpoints, next_cursor}`; `next_cursor` fetches the next (older) page and is null after
/// the oldest. The cursor's position is a checkpoint seq, so checkpoints signed while a client
/// pages do not shift the older ones. Read-only: unlike `GET /admin/audit/checkpoint` it never
/// signs a new checkpoint.
///
/// # Errors
///
/// 400 `invalid_cursor` for a cursor that is malformed or of another route, 400
/// `invalid_request` for a `limit` of 0 or above [`MAX_AUDIT_PAGE`] or the removed `before`,
/// and 500 `server_error` when the audit log fails.
pub async fn audit_checkpoints(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CheckpointsQuery>,
) -> Result<Json<Value>, ApiError> {
    if q.before.is_some() {
        return Err(page::removed(
            "before",
            "page with `cursor` (the `next_cursor` of the previous page)",
        ));
    }
    let dir = page::Direction::Descending;
    let limit = page::limit(q.limit, DEFAULT_AUDIT_PAGE, MAX_AUDIT_PAGE)?;
    let before = page::decode(q.cursor.as_deref(), page::List::Checkpoints, dir)?;
    let mut checkpoints = state
        .blocking(move |s| {
            s.audit
                .checkpoints_before(before.unwrap_or(u64::MAX), limit + 1)
        })
        .await?;
    let next = (checkpoints.len() > limit).then(|| checkpoints[limit - 1].seq);
    checkpoints.truncate(limit);
    Ok(Json(json!({
        "checkpoints": checkpoints,
        "next_cursor": next.map(|p| page::encode(page::List::Checkpoints, dir, p)),
    })))
}

/// Middleware on every `/admin/*` route: `Cache-Control: no-store` (unless the handler chose
/// a cache policy itself) and `X-Content-Type-Options: nosniff`, so an admin answer is never
/// kept by a browser or proxy cache and a browser never renders one as anything but its
/// declared type. It wraps [`require_admin`], so the 401 and 403 answers carry them too.
pub async fn admin_response_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// Entries read per blocking-pool hop while streaming an export.
const EXPORT_PAGE: usize = 500;

/// Query of `GET /admin/audit/export`: the range and the optional filters.
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// First sequence number (default 1).
    pub from: Option<u64>,
    /// Last sequence number, inclusive (default: the head when the export starts).
    pub to: Option<u64>,
    /// Only records of this kind (`decision`, `tool_result`, `exchange`, `root_token`,
    /// `lease_renew`, `lease_revoke`, `admin`).
    pub kind: Option<String>,
    /// Only records of this delegation chain (the `chain_id` field).
    pub chain_id: Option<String>,
    /// Only records for this tool (the `tool` field, for example `token.exchange`).
    pub tool: Option<String>,
    /// Only records with this decision (`allow` or `deny`).
    pub decision: Option<String>,
}

/// Where a streaming export is.
enum ExportPhase {
    Entries { next: u64 },
    Checkpoints,
    Done,
}

/// `GET /admin/audit/export?from=&to=`: entries `from..=to` and the checkpoints inside that
/// range, as `application/x-ndjson` (one JSON object per line, see
/// `attenuo_audit::export`), streamed a page at a time so a large range never sits in memory.
/// Verify the result offline with `attenuo audit verify --file`.
///
/// `kind`, `chain_id`, `tool` and `decision` keep only the matching entries. The header then
/// carries a `filter` member and the file cannot be verified (its chain has gaps); verify an
/// unfiltered export.
///
/// # Errors
///
/// 400 `invalid_request` when `from` is 0, `to` is smaller than `from`, a filter does not parse (as
/// for `GET /admin/audit`) or `kind` names more than one kind, and 500 `server_error` when the head
/// cannot be read. A read failure once the stream has started ends the stream with an error
/// instead.
pub async fn audit_export(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    use futures_util::stream;

    let from = q.from.unwrap_or(1);
    if from == 0 {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`from` must be at least 1",
        ));
    }
    let head = state
        .blocking(|s| s.audit.head())
        .await?
        .map_or(0, |h| h.seq);
    let to = q.to.map_or(head, |t| t.min(head));
    if q.to.is_some_and(|t| t < from) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`to` must not be smaller than `from`",
        ));
    }
    // Same parsing (and the same 400s) as `GET /admin/audit`'s filters of the same names.
    let parsed = entry_filter(&AuditQuery {
        kind: q.kind.clone(),
        chain_id: q.chain_id.clone(),
        tool: q.tool.clone(),
        decision: q.decision.clone(),
        ..AuditQuery::default()
    })?;
    if parsed.kinds.len() > 1 {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`kind` takes a single kind on an export",
        ));
    }
    let filter = attenuo_audit::RecordFilter {
        kind: parsed.kinds.first().copied(),
        chain_id: parsed.chain_id,
        tool: parsed.tool,
        decision: parsed.decision,
    };
    let exported_at = state.now().format(&Rfc3339).map_err(ApiError::internal)?;
    let header = attenuo_audit::header_line(
        &attenuo_audit::ExportHeader::new(from, to, exported_at).with_filter(filter.clone()),
    );

    let first = stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(header)) });
    let rest = stream::unfold(
        (state, ExportPhase::Entries { next: from }),
        move |(state, phase)| {
            let filter = filter.clone();
            async move {
                match phase {
                    ExportPhase::Done => None,
                    ExportPhase::Entries { next } if next > to => {
                        Some((Ok(Bytes::new()), (state, ExportPhase::Checkpoints)))
                    }
                    ExportPhase::Entries { next } => {
                        let want = usize::try_from(to - next + 1)
                            .unwrap_or(EXPORT_PAGE)
                            .min(EXPORT_PAGE);
                        let f = filter.clone();
                        let page = state
                            .blocking(move |s| s.audit.range_filtered(next, to, &f, want))
                            .await;
                        match page {
                            Err(e) => Some((
                                Err(std::io::Error::other(e.to_string())),
                                (state, ExportPhase::Done),
                            )),
                            Ok(entries) if entries.is_empty() => {
                                Some((Ok(Bytes::new()), (state, ExportPhase::Checkpoints)))
                            }
                            Ok(entries) => {
                                let last = entries.last().map_or(next, |e| e.seq);
                                let mut out = String::new();
                                for e in entries.iter().filter(|e| e.seq <= to) {
                                    out.push_str(&attenuo_audit::entry_line(e));
                                }
                                Some((
                                    Ok(Bytes::from(out)),
                                    (state, ExportPhase::Entries { next: last + 1 }),
                                ))
                            }
                        }
                    }
                    ExportPhase::Checkpoints => {
                        let cps = state
                            .blocking(move |s| s.audit.checkpoints_between(from, to))
                            .await;
                        let item = cps
                            .map(|cps| {
                                let out: String =
                                    cps.iter().map(attenuo_audit::checkpoint_line).collect();
                                Bytes::from(out)
                            })
                            .map_err(|e| std::io::Error::other(e.to_string()));
                        Some((item, (state, ExportPhase::Done)))
                    }
                }
            }
        },
    );
    let body = axum::body::Body::from_stream(futures_util::StreamExt::chain(first, rest));
    let mut resp = Response::new(body);
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// `POST /admin/policies/reload`: re-read `policy.policies_path` and swap the policy set if it
/// parses and validates.
///
/// # Errors
///
/// 409 `reload_unavailable` when `policy.policies_path` is not configured, 500 `server_error` when
/// the file cannot be read or the loaded policy info lock is poisoned, and 422 when the file does not parse or
/// validate (the previous set stays in force).
pub async fn reload_policies(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
) -> Result<Json<Value>, ApiError> {
    let path = state.policies_path.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "reload_unavailable",
            "policy.policies_path is not configured; there is nothing to reload",
        )
    })?;
    // One reload at a time, from reading the file to the swap.
    let _reloading = state.policy_reload.lock().await;
    let text = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::internal(format!("reading {}: {e}", path.display())))?;
    let digest = hex::encode(sha2::Sha256::digest(text.as_bytes()));
    let now = state.now();
    // Compile the new set on the blocking pool from a snapshot of the engine in force, with no
    // lock held: decisions go on with the old engine meanwhile (A-7). Then swap it in whole.
    let compiled = state
        .blocking(move |s| s.pipeline.policy_snapshot().with_policies_reloaded(&text))
        .await;
    let reloaded = match compiled {
        Err(e) => Err(e.to_string()),
        Ok(engine) => {
            let engine = Arc::new(engine);
            {
                // The swap happens under the loaded-policy info's write lock, so
                // `GET /admin/policies` never pairs the new policies with the old digest. A
                // failed reload leaves both as they were.
                let mut loaded = state
                    .loaded_policies
                    .write()
                    .map_err(|_| ApiError::internal("loaded policy info lock poisoned"))?;
                state.pipeline.policy().swap(Arc::clone(&engine));
                *loaded = crate::state::LoadedPolicies {
                    sha256: Some(digest.clone()),
                    loaded_at: now,
                };
            }
            tracing::info!(
                run_usage = ?engine.usage_tracking_reasons(),
                "policies reloaded; run usage kept for these reasons (none: not kept)"
            );
            if engine.asks_for_approval() && state.approvals_client_id.is_none() {
                tracing::warn!("{}", crate::config::UNSET_APPROVAL_CLIENT_ID);
            }
            Ok((engine.policy_ids(), engine.validation_warnings().to_vec()))
        }
    };
    let (ids, warnings) = match reloaded {
        Ok(ok) => ok,
        Err(detail) => {
            let (p, d) = (path.clone(), digest.clone());
            let _ = state
                .blocking(move |state| {
                    audit_admin(
                        state,
                        &who,
                        "admin.policies.reload",
                        Decision::Deny,
                        "policy_invalid",
                        Vec::new(),
                        json!({ "path": p, "sha256": d }),
                        now,
                    )
                })
                .await
                .inspect_err(
                    |e| tracing::error!(error = ?e.detail, "failed reload was not audited"),
                );
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "policy_invalid",
                detail,
            ));
        }
    };
    tracing::info!(policies = ?ids, "policies reloaded");
    let (p, d, pids) = (path.clone(), digest.clone(), ids.clone());
    let audit_id = state
        .blocking(move |state| {
            audit_admin(
                state,
                &who,
                "admin.policies.reload",
                Decision::Allow,
                REASON_ADMIN_ACTION,
                Vec::new(),
                json!({ "path": p, "sha256": d, "policy_ids": pids }),
                now,
            )
        })
        .await
        .inspect_err(|e| tracing::error!(error = ?e.detail, "policy reload was not audited"))
        .ok();
    Ok(Json(json!({
        "policy_ids": ids,
        "warnings": warnings,
        "sha256": digest,
        "audit_id": audit_id,
    })))
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn ct_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}

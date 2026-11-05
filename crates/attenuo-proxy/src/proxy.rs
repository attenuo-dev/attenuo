//! The axum router: authentication, `tools/call` interception, list-result filtering
//! (`tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`), and transparent
//! forwarding of everything else.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_core::{chain_id_of, CapabilitySet, DelegationChain, ToolCall};
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use serde_json::Value;
use time::OffsetDateTime;
use tower_http::trace::TraceLayer;
use tracing::Instrument;
use uuid::Uuid;

use crate::auth::{
    AuthError, Authenticated, Authorizer, CallContext, RequestAuth, META_APPROVAL_KEY,
    REASON_APPROVAL_REQUIRED,
};
use crate::config::ProxyConfig;
use crate::filter::{list_kinds_by_shape, ListFilter, ListKind};
use crate::guard::{disown_stream, disown_stream_end, guard_stream, StreamEndCause, StreamGuard};
use crate::jsonrpc::{
    self, approval_required_response, denied_response, denied_response_with, error_response, id_of,
    is_passthrough_method, is_request, method_of, CODE_INVALID_PARAMS, CODE_INVALID_REQUEST,
    CODE_PARSE_ERROR, CODE_TOO_MANY, CODE_UNAUTHORIZED, CODE_UNAVAILABLE, CODE_UNKNOWN_SERVER,
    CODE_UPSTREAM,
};
use crate::label::{
    label_stream, AwaitedResults, Labeller, PendingResult, ResultScope, LABELLED_METHODS,
};
use crate::listed::ListedTools;
use crate::records::{Admission, RecordWindow};
use crate::session::{
    session_digest, session_tag, BindOutcome, SessionCheck, SessionOwner, SessionRegistry,
};
use crate::stage::Stage;

/// Response header carrying the decision record id(s) of every `tools/call` in the request,
/// comma separated in request order.
pub const DECISION_ID_HEADER: &str = "x-attenuo-decision-id";

/// Reason code (audit and JSON-RPC `data.reason`) for a request carrying an `Mcp-Session-Id`
/// bound to another principal (SR-11).
pub const REASON_SESSION_MISMATCH: &str = "session_mismatch";

/// Reason code for a `tools/call` whose name is not a valid tool name
/// ([`attenuo_core::names`]; SR-25).
pub const REASON_INVALID_NAME: &str = "invalid_name";

/// Reason code (JSON-RPC `data.reason`, HTTP 503) when a response would bind a new session but
/// every slot of the session registry holds a live binding (SR-36).
pub const REASON_SESSION_REGISTRY_FULL: &str = "session_registry_full";

/// Reason code (JSON-RPC `data.reason`, HTTP 429) when a response would bind a new session but
/// the caller's principal (root lease) already holds `max_sessions_per_principal` live
/// bindings (SR-49).
pub const REASON_TOO_MANY_SESSIONS: &str = "too_many_sessions";

/// How long the proxy waits for the upstream to acknowledge the `DELETE` of a session it
/// refused to bind (SR-49).
const UPSTREAM_DELETE_TIMEOUT: Duration = Duration::from_secs(5);

/// Reason code (HTTP 413) for a request body over `max_request_body_bytes` (SR-36).
pub const REASON_REQUEST_TOO_LARGE: &str = "request_too_large";

/// Reason code (HTTP 502) for an upstream body over `max_upstream_body_bytes` (SR-36).
pub const REASON_UPSTREAM_BODY_TOO_LARGE: &str = "upstream_body_too_large";

/// Reason code (HTTP 502, JSON-RPC `data.reason`) when the upstream cannot be reached; the
/// transport error itself is only logged (SR-17).
pub const REASON_UPSTREAM_UNREACHABLE: &str = "upstream_unreachable";

/// Reason code (HTTP 502, JSON-RPC `data.reason`) when an upstream answers a `GET` with a
/// success status but not `text/event-stream`. MCP allows only an SSE listen stream or `405`
/// there, and such a body would reach the client without the list filter or result labelling
/// the proxy applies to the listen stream, so it is refused rather than relayed.
pub const REASON_UPSTREAM_NOT_EVENT_STREAM: &str = "upstream_not_event_stream";

/// Reason code for a `tools/call` whose name the upstream never listed and the catalog does not
/// know, with [`ProxyConfig::require_listed_tools`] on (SR-25).
pub const REASON_TOOL_NOT_LISTED: &str = "tool_not_listed";

const HEADER_MCP_SESSION_ID: &str = "mcp-session-id";

/// Request headers forwarded to the upstream. `Authorization` is deliberately absent: the
/// bearer the proxy receives is attenuo's token, not an upstream credential. So is
/// `Mcp-Session-Id`: the proxy inserts the one value it checked ([`session_id_of`],
/// [`with_session_header`]), never the client's headers as sent (SR-27).
const FORWARD_REQUEST_HEADERS: &[&str] = &["accept", "content-type", "last-event-id"];

/// Upstream response headers forwarded back to the client. `Content-Length` and hop-by-hop
/// headers are recomputed by the server.
const FORWARD_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    HEADER_MCP_SESSION_ID,
    "mcp-protocol-version",
    "cache-control",
];

struct AppState {
    upstreams: HashMap<String, String>,
    client: reqwest::Client,
    authorizer: Arc<dyn Authorizer>,
    sessions: SessionRegistry,
    /// [`ProxyConfig::stream_recheck`].
    stream_recheck: Duration,
    /// [`ProxyConfig::require_listed_tools`].
    require_listed_tools: bool,
    /// Tool names each upstream has listed (SR-25).
    listed: Arc<ListedTools>,
    /// [`ProxyConfig::max_upstream_body_bytes`].
    max_upstream_body: usize,
    /// [`ProxyConfig::max_request_body_bytes`].
    max_request_body: usize,
    /// Allowed calls whose answers may arrive on the `GET` listen stream (ADR-0009).
    awaited: Arc<AwaitedResults>,
    /// The bound on `stream.end` records of `GET` listen streams, shared by all of them
    /// ([`ProxyConfig::record_window`], [`ProxyConfig::record_window_max_keys`]).
    stream_end_records: Arc<RecordWindow>,
    /// The bound on lease-refusal records of undecided requests ([`record_lease_refusal`]).
    /// The same window and capacity as `stream_end_records`, in its own table so a flood of
    /// one kind cannot fill the other's.
    lease_refusal_records: RecordWindow,
}

impl AppState {
    /// The re-check (SR-28) for a response streamed to `who` from `server` in `session_id`.
    /// A stream the re-check ends for a lease or token reason is recorded under
    /// [`crate::guard::STREAM_END_TOOL`]. `who` passed full verification, so the record names
    /// a principal attenuo issued a token to (SR-18).
    fn stream_guard(
        &self,
        who: &Authenticated,
        server: &str,
        session_id: Option<&str>,
    ) -> StreamGuard {
        StreamGuard::new(
            self.authorizer.clone(),
            who.chain.clone(),
            self.stream_recheck,
        )
        .recording(server, session_id, who.dpop_bound)
    }
}

/// Build the proxy router. Upstreams are mounted at `/mcp/{name}`.
pub fn router(config: ProxyConfig, authorizer: Arc<dyn Authorizer>) -> Router {
    let stream_recheck = config.stream_recheck;
    let require_listed_tools = config.require_listed_tools;
    let max_upstream_body = config.max_upstream_body_bytes.max(1);
    let max_request_body = config.max_request_body_bytes.max(1);
    let record_window = config.record_window;
    let record_window_max_keys = config.record_window_max_keys;
    let sessions = SessionRegistry::new(config.session_ttl, config.max_sessions)
        .with_max_per_principal(config.max_sessions_per_principal);
    let upstreams = config
        .upstreams
        .into_iter()
        .map(|u| (u.name, u.url))
        .collect();
    let state = Arc::new(AppState {
        upstreams,
        client: upstream_client(),
        authorizer,
        sessions,
        stream_recheck,
        require_listed_tools,
        listed: Arc::new(ListedTools::new()),
        max_upstream_body,
        max_request_body,
        awaited: Arc::new(AwaitedResults::new()),
        stream_end_records: Arc::new(RecordWindow::with_max_keys(
            record_window,
            record_window_max_keys,
        )),
        lease_refusal_records: RecordWindow::with_max_keys(record_window, record_window_max_keys),
    });
    Router::new()
        .route(
            "/mcp/{server}",
            post(handle_post)
                .get(handle_passthrough)
                .delete(handle_passthrough),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// The HTTP client used for upstream requests.
///
/// Redirects are never followed: the upstream is untrusted (threat model, A3), and a followed
/// `307`/`308` would replay an already-authorized `tools/call` body to a host of the upstream's
/// choosing (including internal addresses only the proxy can reach). A redirect response is
/// returned to the client as-is, without its `Location` header.
fn upstream_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client with static configuration builds")
}

/// Bind `config.listen` and serve the proxy until the task is cancelled.
pub async fn serve(config: ProxyConfig, authorizer: Arc<dyn Authorizer>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, "attenuo proxy listening");
    axum::serve(listener, router(config, authorizer)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------

/// The token of `Authorization: Bearer <token>` or `Authorization: DPoP <token>` (RFC 9449
/// §7.1). Whether a proof is needed depends on the token, not on the scheme.
fn bearer_of(headers: &HeaderMap) -> Result<&str, AuthError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidToken("authorization header is not ASCII".into()))?;
    let (scheme, token) = raw
        .split_once(' ')
        .ok_or_else(|| AuthError::InvalidToken("expected `Bearer <token>`".into()))?;
    let known = scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("dpop");
    if !known || token.trim().is_empty() {
        return Err(AuthError::InvalidToken("expected `Bearer <token>`".into()));
    }
    Ok(token.trim())
}

/// The request's `DPoP` header: none, or exactly one ASCII value (RFC 9449 §4.3).
fn dpop_of(headers: &HeaderMap) -> Result<Option<&str>, AuthError> {
    let mut values = headers.get_all("dpop").iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthError::InvalidDpopProof(
            "more than one DPoP header".into(),
        ));
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| AuthError::InvalidDpopProof("DPoP header is not ASCII".into()))
}

async fn authenticate(
    state: &AppState,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<Authenticated, AuthError> {
    let req = RequestAuth {
        token: bearer_of(headers)?,
        dpop: dpop_of(headers)?,
        method: method.as_str(),
        path: uri.path(),
        host: header_str(headers, header::HOST.as_str()),
    };
    state.authorizer.authenticate_request(&req, now).await
}

/// A 401 that names only the stable reason code ([`AuthError::reason`]); the verifier's detail
/// (wrong audience, unknown `kid`, ...) goes to the debug log, never to the client (SR-17).
fn unauthorized(err: AuthError) -> Response {
    unauthorized_recorded(err, None)
}

/// [`unauthorized`] for a refusal recorded in the audit log as `decision_id`, or standing
/// under that earlier record of its window ([`record_lease_refusal`]): the id goes in
/// `X-Attenuo-Decision-Id` and `data.decision_id`.
fn unauthorized_recorded(err: AuthError, decision_id: Option<Uuid>) -> Response {
    let reason = err.reason();
    if let AuthError::Unavailable(_) = &err {
        // A server-side limit, not a bad credential: 503, so the client keeps its token and
        // key and retries (SR-47).
        tracing::warn!(reason = ?reason, "request refused: temporarily unavailable");
        let body = error_response(
            Value::Null,
            CODE_UNAVAILABLE,
            format!("attenuo: temporarily unavailable: {reason}"),
            Some(serde_json::json!({ "reason": reason })),
        );
        let mut resp = json_response(StatusCode::SERVICE_UNAVAILABLE, &body);
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return resp;
    }
    tracing::warn!(reason = ?reason, "request rejected: unauthenticated");
    // The detail can carry attacker-chosen text (an unknown `kid`): Debug-format it (SR-18).
    tracing::debug!(error = ?err.to_string(), "authentication failure detail");
    let body = unauthorized_body(Value::Null, &err, decision_id);
    let mut resp = json_response(StatusCode::UNAUTHORIZED, &body);
    if let Some(id) = decision_id {
        add_decision_header(&mut resp, &[id]);
    }
    if let Ok(challenge) = HeaderValue::from_str(&err.challenge()) {
        resp.headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    resp
}

/// The JSON-RPC `-32001` error for `err`: `message` and `data.reason` carry the reason code,
/// and `data.decision_id` the audit record of a recorded refusal.
fn unauthorized_body(id: Value, err: &AuthError, decision_id: Option<Uuid>) -> Value {
    let reason = err.reason();
    let mut data = serde_json::json!({ "reason": reason });
    if let Some(d) = decision_id {
        data["decision_id"] = Value::String(d.to_string());
    }
    error_response(
        id,
        CODE_UNAUTHORIZED,
        format!("attenuo: unauthorized: {reason}"),
        Some(data),
    )
}

/// Record a request refused because the token's lease chain is no longer live (revoked,
/// expired, unknown, or not checkable), when no per-call decision recorded it already: an
/// `initialize`, `tools/list` or other undecided message, or a `GET`/`DELETE`. A client that
/// opens a session per call (LangChain's MCP adapter) meets revocation here, never at a
/// `tools/call`, and without this record the audit log would not show that it kept trying.
///
/// Only [`AuthError::LeaseInactive`] is recorded: the token verified (signature, audience,
/// expiry, DPoP), so the record names a principal attenuo issued a token to. A token that
/// fails verification stays a log line (SR-18): recording it would let anyone write to the
/// audit log. `tool` is a fixed name (an allowlisted method or `http.<METHOD>`), never text
/// from the request.
///
/// Bounded by [`AppState::lease_refusal_records`]: the first refusal per delegation chain
/// (digest), `tool` and reason in a [`ProxyConfig::record_window`] is
/// recorded; a later one in the window is still refused, but logged and counted through
/// [`Authorizer::observe_record_suppressed`] instead of recorded, and its 401 names the
/// window's first record. Returns the id the 401 names: the new record, the window's first
/// record, or `None` when nothing was recorded (not a lease refusal), the window's record is
/// still being written by a concurrent request, or the record could not be written (then no
/// window opens on it and the next refusal is recorded, SR-81).
async fn record_lease_refusal(
    state: &AppState,
    who: &Authenticated,
    server: &str,
    session_id: Option<&str>,
    tool: &'static str,
    err: &AuthError,
    now: OffsetDateTime,
) -> Option<Uuid> {
    let AuthError::LeaseInactive(reason) = err else {
        return None;
    };
    let key = who.chain.digest();
    let records = &state.lease_refusal_records;
    match records.admit(&key, tool, reason, std::time::Instant::now()) {
        Admission::Suppress { first } => {
            state
                .authorizer
                .observe_record_suppressed(tool, StreamEndCause::of_lease_reason(reason));
            tracing::warn!(
                reason = ?reason,
                tool,
                decision_id = ?first.map(|id| id.to_string()),
                record_suppressed = true,
                "request refused, not recorded: lease inactive, recorded earlier in the window"
            );
            return first;
        }
        Admission::Record { suppressed_before } if suppressed_before > 0 => {
            tracing::info!(
                reason = ?reason,
                tool,
                suppressed = suppressed_before,
                chain_id = ?chain_id_of(&who.chain),
                subject = ?who.chain.originating_user.subject,
                "lease refusal records suppressed in the previous window"
            );
        }
        Admission::Record { .. } => {}
    }
    let mut call =
        ToolCall::new(server, tool, serde_json::json!({})).with_dpop_bound(who.dpop_bound);
    if let Some(sid) = session_id {
        call = call.with_session(session_tag(sid));
    }
    let Some(id) = state
        .authorizer
        .record_rejection_checked(&who.chain, &call, reason, now)
        .await
    else {
        // Not in the log: open no window on it, so the next refusal is recorded (SR-81), and
        // name no decision id.
        records.forget(&key, tool, reason);
        tracing::warn!(reason = ?reason, tool, "request refused, record not written: lease inactive");
        return None;
    };
    records.recorded(&key, tool, reason, id);
    tracing::warn!(reason = ?reason, tool, decision_id = %id, "request refused and recorded: lease inactive");
    Some(id)
}

/// The fixed name a lease refusal of `method` is recorded under: the allowlisted method
/// itself, or `http.POST` for a notification or a message without a method.
fn refused_tool_name(method: Option<&str>) -> &'static str {
    method
        .and_then(|m| {
            jsonrpc::PASSTHROUGH_METHODS
                .iter()
                .copied()
                .find(|p| *p == m)
        })
        .unwrap_or("http.POST")
}

fn unknown_server(server: &str) -> Response {
    tracing::warn!(server = ?server, "request rejected: unknown upstream");
    let body = error_response(
        Value::Null,
        CODE_UNKNOWN_SERVER,
        format!("attenuo: unknown server `{server}`"),
        None,
    );
    json_response(StatusCode::NOT_FOUND, &body)
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        bytes,
    )
        .into_response()
}

fn request_span(server: &str, chain: &DelegationChain, session_id: Option<&str>) -> tracing::Span {
    let agent = chain
        .current_agent()
        .map(ToString::to_string)
        .unwrap_or_default();
    // Server, agent and subject are caller-controlled: Debug-format them (SR-18).
    tracing::info_span!(
        "mcp_request",
        server = ?server,
        agent = ?agent,
        subject = ?chain.originating_user.subject,
        chain_depth = chain.depth(),
        // Session ids grant access to a session: log a hash prefix only (SR-11).
        session = %session_id.map(session_tag).unwrap_or_default(),
    )
}

/// The SR-11 session check, made after authentication. `Ok` carries the caller's
/// [`SessionOwner`], to bind a session id the upstream assigns in its response. A session id
/// bound to someone else is refused with `403` (`session_mismatch`, recorded through
/// [`Authorizer::record_rejection`]); one the proxy does not know gets `404`, the MCP signal
/// to start a new session.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
async fn session_gate(
    state: &AppState,
    server: &str,
    method: &Method,
    who: &Authenticated,
    session_id: Option<&str>,
    now: OffsetDateTime,
) -> Result<Option<SessionOwner>, Response> {
    let chain = &who.chain;
    let owner = SessionOwner::of(chain);
    let Some(sid) = session_id else {
        return Ok(owner);
    };
    let check = match &owner {
        Some(o) => state.sessions.check(sid, o, Instant::now()),
        None => SessionCheck::Mismatch,
    };
    match check {
        SessionCheck::Owned => Ok(owner),
        SessionCheck::Unknown => {
            tracing::warn!(session = %session_tag(sid), "request rejected: unknown session");
            let body = error_response(
                Value::Null,
                CODE_INVALID_REQUEST,
                "attenuo: session not found; start a new session",
                None,
            );
            Err(json_response(StatusCode::NOT_FOUND, &body))
        }
        SessionCheck::Mismatch => {
            let tag = session_tag(sid);
            let call = ToolCall::new(server, format!("http.{method}"), serde_json::json!({}))
                .with_session(tag.clone())
                .with_dpop_bound(who.dpop_bound);
            let id = state
                .authorizer
                .record_rejection(chain, &call, REASON_SESSION_MISMATCH, now)
                .await;
            tracing::warn!(
                session = %tag,
                decision_id = %id,
                "request rejected: session belongs to another principal"
            );
            let body = denied_response(Value::Null, REASON_SESSION_MISMATCH, id);
            let mut resp = json_response(StatusCode::FORBIDDEN, &body);
            add_decision_header(&mut resp, &[id]);
            Err(resp)
        }
    }
}

/// Bind the session id a successful upstream response assigns to the caller. A session id
/// already bound to another principal is removed from the response. When the registry has no
/// free slot, the whole response is replaced by `503` `session_registry_full` (SR-36); when the
/// caller's principal already holds its share, by `429` `too_many_sessions` (SR-49). The
/// client cannot use a session the proxy would not let it back into, and no other user's live
/// binding is given up for it. In both refusals the session the upstream just created is
/// deleted there ([`delete_upstream_session`]), so refused attempts leave nothing open.
async fn adopt_session(
    state: &AppState,
    upstream: &str,
    owner: Option<&SessionOwner>,
    response: &mut Response,
) {
    if !response.status().is_success() {
        return;
    }
    let Some(sid) = header_str(response.headers(), HEADER_MCP_SESSION_ID).map(str::to_owned) else {
        return;
    };
    let outcome = match owner {
        Some(o) => state.sessions.bind(&sid, o, Instant::now()),
        None => BindOutcome::Taken,
    };
    match outcome {
        BindOutcome::Bound => {}
        BindOutcome::Taken => {
            tracing::warn!(
                session = %session_tag(&sid),
                "upstream assigned a session id bound to another principal; header removed"
            );
            response.headers_mut().remove(HEADER_MCP_SESSION_ID);
        }
        BindOutcome::Full => {
            tracing::warn!(
                session = %session_tag(&sid),
                "session registry full; refusing to bind a new session"
            );
            let body = error_response(
                Value::Null,
                CODE_UNAVAILABLE,
                "attenuo: too many open sessions; try again later",
                Some(serde_json::json!({ "reason": REASON_SESSION_REGISTRY_FULL })),
            );
            let mut resp = json_response(StatusCode::SERVICE_UNAVAILABLE, &body);
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
            *response = resp;
            delete_upstream_session(state, upstream, &sid).await;
        }
        BindOutcome::PrincipalFull => {
            tracing::warn!(
                session = %session_tag(&sid),
                "principal holds too many sessions; refusing to bind a new one"
            );
            let body = error_response(
                Value::Null,
                CODE_TOO_MANY,
                "attenuo: too many open sessions for this principal; close one or try again later",
                Some(serde_json::json!({ "reason": REASON_TOO_MANY_SESSIONS })),
            );
            let mut resp = json_response(StatusCode::TOO_MANY_REQUESTS, &body);
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
            *response = resp;
            delete_upstream_session(state, upstream, &sid).await;
        }
    }
}

/// After [`adopt_session`]: the digest of the session id the response still carries when the
/// request did not carry it (an `initialize` the upstream answered with a new session that
/// the proxy bound to the caller), for [`Authorizer::record_session`], so the session can be
/// revoked by id. A session id that was refused has been removed from the response by then,
/// so only a binding the proxy made is recorded, and only for a caller whose token verified.
fn new_session_digest(requested: Option<&str>, response: &Response) -> Option<String> {
    if !response.status().is_success() {
        return None;
    }
    let sid = header_str(response.headers(), HEADER_MCP_SESSION_ID)?;
    (requested != Some(sid)).then(|| session_digest(sid))
}

/// End, at the upstream, a session the proxy refused to bind (SR-49): the MCP `DELETE` with
/// its `Mcp-Session-Id`. Best effort: a failure or a timeout is logged, and the refusal stands.
async fn delete_upstream_session(state: &AppState, upstream: &str, session_id: &str) {
    let tag = session_tag(session_id);
    let req = state
        .client
        .delete(upstream)
        .headers(with_session_header(HeaderMap::new(), Some(session_id)))
        .timeout(UPSTREAM_DELETE_TIMEOUT);
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!(session = %tag, "refused session deleted at the upstream");
        }
        Ok(resp) => tracing::warn!(
            session = %tag,
            status = resp.status().as_u16(),
            "upstream did not accept the DELETE of a refused session"
        ),
        Err(e) => tracing::warn!(
            session = %tag,
            error = ?e.to_string(),
            "DELETE of a refused session at the upstream failed"
        ),
    }
}

/// Read a client request body, at most `limit` bytes. Over the limit is `413` (checked against
/// `Content-Length` first, then while reading); a broken body is `400`.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
async fn read_request_body(
    headers: &HeaderMap,
    body: Body,
    limit: usize,
) -> Result<Bytes, Response> {
    let too_large = || {
        tracing::warn!(limit, "request rejected: body too large");
        let body = error_response(
            Value::Null,
            CODE_INVALID_REQUEST,
            format!("attenuo: request body larger than {limit} bytes"),
            Some(serde_json::json!({ "reason": REASON_REQUEST_TOO_LARGE })),
        );
        json_response(StatusCode::PAYLOAD_TOO_LARGE, &body)
    };
    let declared = header_str(headers, header::CONTENT_LENGTH.as_str())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let mut out = Vec::new();
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::warn!(error = %e, "request body could not be read");
            let body = error_response(
                Value::Null,
                CODE_INVALID_REQUEST,
                "attenuo: request body could not be read",
                None,
            );
            json_response(StatusCode::BAD_REQUEST, &body)
        })?;
        if out.len() + chunk.len() > limit {
            return Err(too_large());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// Why reading an upstream body failed.
enum UpstreamBodyError {
    TooLarge,
    Transport(reqwest::Error),
}

/// Read an upstream body, at most `limit` bytes (checked against `Content-Length` first, then
/// while reading).
async fn read_upstream_body(
    resp: reqwest::Response,
    limit: usize,
) -> Result<Bytes, UpstreamBodyError> {
    if resp.content_length().is_some_and(|n| n > limit as u64) {
        return Err(UpstreamBodyError::TooLarge);
    }
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(UpstreamBodyError::Transport)?;
        if out.len() + chunk.len() > limit {
            return Err(UpstreamBodyError::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

fn upstream_body_too_large(limit: usize) -> Response {
    tracing::error!(limit, "upstream body larger than the proxy buffers");
    let body = error_response(
        Value::Null,
        CODE_UPSTREAM,
        format!("attenuo: upstream response larger than {limit} bytes"),
        Some(serde_json::json!({ "reason": REASON_UPSTREAM_BODY_TOO_LARGE })),
    );
    json_response(StatusCode::BAD_GATEWAY, &body)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Is `value` a session id the MCP specification allows: non-empty, visible ASCII only
/// (`0x21..=0x7E`)?
fn is_valid_session_id(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|b| (0x21..=0x7E).contains(b))
}

/// The request's `Mcp-Session-Id`, checked (SR-27). More than one such header, or a value
/// that is not visible ASCII, is refused with `400`: the session gate and the upstream must
/// act on the same, single value, and the proxy forwards only the value returned here.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
fn session_id_of(headers: &HeaderMap) -> Result<Option<String>, Response> {
    let mut values = headers.get_all(HEADER_MCP_SESSION_ID).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let several = values.next().is_some();
    if several || !is_valid_session_id(first.as_bytes()) {
        tracing::warn!(
            several,
            "request rejected: Mcp-Session-Id header repeated or not visible ASCII"
        );
        let body = error_response(
            Value::Null,
            CODE_INVALID_REQUEST,
            "attenuo: invalid request: exactly one Mcp-Session-Id header, visible ASCII",
            None,
        );
        return Err(json_response(StatusCode::BAD_REQUEST, &body));
    }
    // Visible ASCII is valid UTF-8.
    Ok(Some(String::from_utf8_lossy(first.as_bytes()).into_owned()))
}

/// Add the checked session id to headers bound for the upstream.
fn with_session_header(mut headers: HeaderMap, session_id: Option<&str>) -> HeaderMap {
    if let Some(v) = session_id.and_then(|s| HeaderValue::from_str(s).ok()) {
        headers.insert(HeaderName::from_static(HEADER_MCP_SESSION_ID), v);
    }
    headers
}

/// Drop every `Mcp-Session-Id` of an upstream response unless there is exactly one and it is
/// visible ASCII, so a client never sees two session ids, or one the proxy could not bind
/// (SR-27).
fn sanitize_session_header(headers: &mut HeaderMap) {
    let mut values = headers.get_all(HEADER_MCP_SESSION_ID).iter();
    let Some(first) = values.next() else {
        return;
    };
    let several = values.next().is_some();
    if several || !is_valid_session_id(first.as_bytes()) {
        tracing::warn!(
            several,
            "upstream sent Mcp-Session-Id headers the proxy cannot bind; removed"
        );
        headers.remove(HEADER_MCP_SESSION_ID);
    }
}

fn forward_headers(headers: &HeaderMap, names: &[&'static str]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in names {
        let name = HeaderName::from_static(name);
        for value in headers.get_all(&name) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// GET / DELETE: passthrough (SSE listen stream, its answers labelled; session termination)
// ---------------------------------------------------------------------------------------------

async fn handle_passthrough(
    State(state): State<Arc<AppState>>,
    Path(server): Path<String>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(upstream) = state.upstreams.get(&server).cloned() else {
        return unknown_server(&server);
    };
    let now = OffsetDateTime::now_utc();
    let who = match authenticate(&state, &method, &uri, &headers, now).await {
        Ok(a) => a,
        Err(e) => return unauthorized(e),
    };
    let chain = who.chain.clone();
    if let Err(e) = state.authorizer.check_active(&chain, now).await {
        let tool = if method == Method::DELETE {
            "http.DELETE"
        } else {
            "http.GET"
        };
        let sid = session_id_of(&headers).ok().flatten();
        let id = record_lease_refusal(&state, &who, &server, sid.as_deref(), tool, &e, now).await;
        return unauthorized_recorded(e, id);
    }
    let session_id = match session_id_of(&headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let body = match read_request_body(&headers, body, state.max_request_body).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let span = request_span(&server, &chain, session_id.as_deref());
    async move {
        let owner =
            match session_gate(&state, &server, &method, &who, session_id.as_deref(), now).await {
                Ok(o) => o,
                Err(resp) => return resp,
            };
        tracing::debug!(%method, "forwarding transparently");
        let is_delete = method == Method::DELETE;
        let limit = state.max_upstream_body;
        let req = state
            .client
            .request(method, &upstream)
            .headers(with_session_header(
                forward_headers(&headers, FORWARD_REQUEST_HEADERS),
                session_id.as_deref(),
            ))
            .body(body);
        let mut response = match req.send().await {
            Ok(resp) if is_delete => stream_response(resp, None, None, limit),
            // The listen stream lives as long as the client keeps it open: re-check it
            // (SR-28), count its end, and bound its `stream.end` records per chain and
            // reason. List answers on it (replayed on a resumed stream) are filtered, and
            // responses to allowed calls labelled, like `POST` answers.
            Ok(resp) if is_event_stream(resp.headers()) => {
                let labeller = Labeller::listen(
                    state.authorizer.clone(),
                    state.awaited.clone(),
                    ResultScope::new(&server, session_id.as_deref(), &chain),
                );
                let guard = state
                    .stream_guard(&who, &server, session_id.as_deref())
                    .listen(state.stream_end_records.clone());
                let filter = listen_list_filter(&state, &chain, &server);
                stream_response_sse(resp, None, guard, limit, Some(filter), Some(labeller))
            }
            // Any other success answer to a `GET` is a protocol violation, and the one body
            // that would pass the list filter by: refused. `405` and errors are relayed.
            Ok(resp) if resp.status().is_success() => return upstream_not_event_stream(&resp),
            Ok(resp) => stream_response(
                resp,
                None,
                Some(state.stream_guard(&who, &server, session_id.as_deref())),
                limit,
            ),
            Err(e) => return upstream_error(e),
        };
        match (is_delete, session_id.as_deref()) {
            (true, Some(sid)) if response.status().is_success() => state.sessions.remove(sid),
            (true, _) => {}
            (false, _) => adopt_session(&state, &upstream, owner.as_ref(), &mut response).await,
        }
        response
    }
    .instrument(span)
    .await
}

/// The list filter of a `GET` listen stream. The proxy did not see the requests answered
/// there: an upstream replays the buffered events of a broken `POST` stream when the client
/// resumes with `Last-Event-ID`, and may answer after a `202`. So every response on the stream
/// whose `result` holds a list array ([`list_kinds_by_shape`]) is filtered for `chain`, the
/// holder of the stream, through the same [`ListFilter`] as a `POST` answer, and its tools are
/// recorded for SR-25 the same way ([`observe_listed`]).
fn listen_list_filter(
    state: &AppState,
    chain: &DelegationChain,
    server: &str,
) -> impl FnMut(&mut Value) + Send + 'static {
    let caps = chain.effective_capabilities().cloned().unwrap_or_default();
    let server = server.to_owned();
    let listed = state.listed.clone();
    let authorizer = state.authorizer.clone();
    move |body: &mut Value| {
        let messages: Vec<&mut Value> = match body {
            Value::Array(items) => items.iter_mut().collect(),
            other => vec![other],
        };
        for msg in messages {
            let pending = list_kinds_by_shape(msg);
            if pending.is_empty() {
                continue;
            }
            let filter = ListFilter::new(&pending, &caps, &server);
            observe_listed(&filter, msg, &server, &listed, authorizer.as_ref());
            let removed = filter.apply_message(msg);
            if removed > 0 {
                tracing::debug!(removed, "filtered list result on the listen stream");
            }
        }
    }
}

/// `502` for an upstream that answered a `GET` with a success status and a body that is not
/// SSE ([`REASON_UPSTREAM_NOT_EVENT_STREAM`]). The status and content type are logged; the
/// body is dropped unread, which closes the upstream connection, and no session it may
/// assign is bound.
fn upstream_not_event_stream(resp: &reqwest::Response) -> Response {
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    tracing::error!(
        status = resp.status().as_u16(),
        content_type = ?content_type,
        "upstream answered GET with a success status that is not an SSE stream; refused"
    );
    let body = error_response(
        Value::Null,
        CODE_UPSTREAM,
        "attenuo: upstream answered GET without an event stream",
        Some(serde_json::json!({ "reason": REASON_UPSTREAM_NOT_EVENT_STREAM })),
    );
    json_response(StatusCode::BAD_GATEWAY, &body)
}

/// `502` for a failed upstream request. The `reqwest` error names the internal upstream URL
/// and the transport failure: it is logged, and the client gets only the reason code
/// [`REASON_UPSTREAM_UNREACHABLE`] (SR-17).
fn upstream_error(err: reqwest::Error) -> Response {
    tracing::error!(error = ?err.to_string(), "upstream request failed");
    let body = error_response(
        Value::Null,
        CODE_UPSTREAM,
        "attenuo: upstream unreachable",
        Some(serde_json::json!({ "reason": REASON_UPSTREAM_UNREACHABLE })),
    );
    json_response(StatusCode::BAD_GATEWAY, &body)
}

// ---------------------------------------------------------------------------------------------
// POST: JSON-RPC messages
// ---------------------------------------------------------------------------------------------

/// What the proxy decided about the messages of one HTTP request.
#[derive(Default)]
struct Screened {
    /// Messages to send upstream, in request order.
    forward: Vec<Value>,
    /// Responses the proxy produced itself (denials, invalid params).
    replies: Vec<Value>,
    /// Decision ids of every `tools/call`, in request order.
    decision_ids: Vec<Uuid>,
    /// Ids and kinds of the list requests (`tools/list`, `resources/list`,
    /// `resources/templates/list`, `prompts/list`), whose responses must be filtered.
    list_requests: Vec<(Value, ListKind)>,
    /// Result of the lease check made for messages forwarded without a per-call decision;
    /// made at most once per HTTP request.
    lease_check: Option<Result<(), AuthError>>,
    /// The audit record of a failed lease check ([`record_lease_refusal`]): written for this
    /// HTTP request (at most one), or the earlier record of its window that stands for it.
    lease_refusal: Option<Uuid>,
    /// Allowed mediated calls whose responses must be labelled before they are relayed
    /// (ADR-0009).
    results: Vec<PendingResult>,
}

/// Stage timings of one `POST`, filled in by [`handle_post_inner`] and reported by
/// [`handle_post`] once the response is ready.
#[derive(Default)]
struct PostTiming {
    /// At least one message got a per-call decision.
    decided: bool,
    /// The upstream round trip, up to its response headers.
    upstream: Option<Duration>,
    /// When the upstream's response headers arrived.
    upstream_done: Option<Instant>,
}

async fn handle_post(
    State(state): State<Arc<AppState>>,
    Path(server): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let started = Instant::now();
    let Some(upstream) = state.upstreams.get(&server) else {
        return unknown_server(&server);
    };
    let now = OffsetDateTime::now_utc();
    let who = match authenticate(&state, &Method::POST, &uri, &headers, now).await {
        Ok(a) => a,
        Err(e) => return unauthorized(e),
    };
    let chain = &who.chain;
    let session_id = match session_id_of(&headers) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // Read only after authentication, so an anonymous caller cannot make the proxy buffer.
    let body = match read_request_body(&headers, body, state.max_request_body).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let span = request_span(&server, chain, session_id.as_deref());
    async {
        let owner = match session_gate(
            &state,
            &server,
            &Method::POST,
            &who,
            session_id.as_deref(),
            now,
        )
        .await
        {
            Ok(o) => o,
            Err(resp) => return resp,
        };
        let mut timing = PostTiming::default();
        let mut response = handle_post_inner(
            &state,
            upstream,
            &server,
            &who,
            session_id.as_deref(),
            &headers,
            body,
            now,
            &mut timing,
        )
        .await;
        adopt_session(&state, upstream, owner.as_ref(), &mut response).await;
        if let Some(digest) = new_session_digest(session_id.as_deref(), &response) {
            state
                .authorizer
                .record_session(&who.chain, &server, &digest, now)
                .await;
        }
        if timing.decided {
            report_post_timing(&state, &timing, started);
        }
        response
    }
    .instrument(span)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_post_inner(
    state: &AppState,
    upstream: &str,
    server: &str,
    who: &Authenticated,
    session_id: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    now: OffsetDateTime,
    timing: &mut PostTiming,
) -> Response {
    let chain = &who.chain;
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e.to_string(), "request body is not JSON");
            let body = error_response(
                Value::Null,
                CODE_PARSE_ERROR,
                format!("attenuo: parse error: {e}"),
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };

    let (messages, is_batch) = match parsed {
        Value::Array(items) => (items, true),
        Value::Object(_) => (vec![parsed], false),
        _ => {
            let body = error_response(
                Value::Null,
                CODE_INVALID_REQUEST,
                "attenuo: invalid request: expected a JSON-RPC object or batch",
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };
    if is_batch && messages.is_empty() {
        let body = error_response(
            Value::Null,
            CODE_INVALID_REQUEST,
            "attenuo: invalid request: empty batch",
            None,
        );
        return json_response(StatusCode::BAD_REQUEST, &body);
    }

    let mut screened = Screened::default();
    for msg in messages {
        screen_message(state, who, server, session_id, msg, now, &mut screened).await;
    }
    timing.decided = !screened.decision_ids.is_empty();

    // A single message that was refused only because the token's lease is inactive is an
    // authentication failure for the whole request.
    if !is_batch && screened.forward.is_empty() && screened.decision_ids.is_empty() {
        if let Some(Err(e)) = screened.lease_check.take() {
            return unauthorized_recorded(e, screened.lease_refusal);
        }
    }

    // Nothing left to forward: answer locally.
    if screened.forward.is_empty() {
        let body = if is_batch {
            Value::Array(screened.replies)
        } else {
            screened.replies.pop().unwrap_or(Value::Null)
        };
        let mut resp = json_response(StatusCode::OK, &body);
        if let Some(sid) = session_id.and_then(|s| HeaderValue::from_str(s).ok()) {
            resp.headers_mut()
                .insert(HeaderName::from_static(HEADER_MCP_SESSION_ID), sid);
        }
        add_decision_header(&mut resp, &screened.decision_ids);
        return resp;
    }

    // Forward exactly what was screened, re-encoded. The original bytes are never sent: JSON
    // with duplicate member names parses differently across implementations (serde_json keeps
    // the last, others keep the first), so forwarding the raw body would let a client get
    // `{"method":"ping",...,"method":"tools/call"}`-style messages past screening. A batch also
    // drops the messages the proxy answered itself.
    let encoded = if is_batch {
        serde_json::to_vec(&screened.forward)
    } else {
        serde_json::to_vec(&screened.forward[0])
    };
    let upstream_body = match encoded {
        Ok(v) => Bytes::from(v),
        Err(e) => {
            tracing::error!(error = %e, "re-encoding the screened request failed");
            let body = error_response(
                Value::Null,
                CODE_INVALID_REQUEST,
                "attenuo: invalid request",
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };
    let mut req_headers = with_session_header(
        forward_headers(headers, FORWARD_REQUEST_HEADERS),
        session_id,
    );
    if !req_headers.contains_key(header::CONTENT_TYPE) {
        req_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    // The upstream may answer an allowed call on the `GET` listen stream instead (after a
    // `202`, or on a resumed stream), or in the body of a later `POST` of the session:
    // remember it before the upstream can see it.
    let scope = ResultScope::new(server, session_id, chain);
    if !screened.results.is_empty() {
        state
            .awaited
            .remember(&scope, chain, &screened.results, Instant::now());
    }
    let sent = Instant::now();
    let resp = match state
        .client
        .post(upstream)
        .headers(req_headers)
        .body(upstream_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return upstream_error(e),
    };
    let headers_in = Instant::now();
    timing.upstream = Some(headers_in - sent);
    timing.upstream_done = Some(headers_in);

    let has_lists = !screened.list_requests.is_empty();
    // Clients route a response by its id, whatever body it comes in: an answer to an earlier
    // call of this session and run in this body is labelled too (SR-85), so a `POST` with no
    // allowed call of its own is still read while such calls are awaited. Clients do not read
    // the body of a `POST` that carried no request, so that one is left alone.
    let labeller = if !screened.results.is_empty() {
        Some(
            Labeller::new(
                state.authorizer.clone(),
                chain.clone(),
                std::mem::take(&mut screened.results),
            )
            .striking(state.awaited.clone(), scope),
        )
    } else if screened.forward.iter().any(is_request) && state.awaited.any_in(&scope) {
        Some(Labeller::listen(
            state.authorizer.clone(),
            state.awaited.clone(),
            scope,
        ))
    } else {
        None
    };
    let needs_buffer = has_lists || !screened.replies.is_empty() || labeller.is_some();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().to_ascii_lowercase())
        .unwrap_or_default();
    let is_json = content_type.starts_with("application/json");
    let is_sse = content_type.starts_with("text/event-stream");

    let mut response = if needs_buffer && is_json {
        buffer_and_rewrite(
            state,
            resp,
            chain,
            server,
            &screened,
            labeller.as_ref(),
            is_batch,
        )
        .await
    } else if (has_lists || labeller.is_some()) && is_sse {
        // The list response is an event of the stream, alone or inside a batch: filter each
        // event as it passes; label every response to an allowed call the same way. Replies
        // the proxy generated itself lead the stream.
        let prelude = sse_prelude(&screened.replies);
        let guard = state.stream_guard(who, server, session_id);
        let filter = has_lists.then(|| {
            let pending = screened.list_requests.clone();
            let caps = chain.effective_capabilities().cloned().unwrap_or_default();
            let server = server.to_owned();
            let listed = state.listed.clone();
            let authorizer = state.authorizer.clone();
            move |msg: &mut Value| {
                let filter = ListFilter::new(&pending, &caps, &server);
                observe_listed(&filter, msg, &server, &listed, authorizer.as_ref());
                let removed = filter.apply(msg);
                if removed > 0 {
                    tracing::debug!(removed, "filtered list result in SSE stream");
                }
            }
        });
        stream_response_sse(
            resp,
            prelude,
            guard,
            state.max_upstream_body,
            filter,
            labeller,
        )
    } else if let Some(labeller) = labeller
        .as_ref()
        .filter(|_| !has_lists && !matches!(resp.status().as_u16(), 202 | 204))
    {
        // Neither JSON nor SSE: the proxy cannot find the results in it, so it cannot record
        // them, and an unrecorded result must not reach the agent (ADR-0009). An empty body
        // (a redirect, say) carries nothing and keeps its status; anything else fails closed.
        let status = resp.status();
        let upstream_headers = resp.headers().clone();
        match read_upstream_body(resp, state.max_upstream_body).await {
            Ok(b) if b.is_empty() => build_response(status, &upstream_headers, Body::empty()),
            Ok(_) | Err(UpstreamBodyError::TooLarge) => {
                tracing::error!(
                    content_type = ?content_type,
                    status = %status,
                    "upstream answered a mediated call with a body the proxy cannot label"
                );
                label_failure(&screened, labeller, is_batch)
            }
            Err(UpstreamBodyError::Transport(e)) => upstream_error(e),
        }
    } else if has_lists && !matches!(resp.status().as_u16(), 202 | 204) {
        // Neither JSON nor SSE: the proxy cannot tell what is in it, and a list result must
        // not reach the client unfiltered. Fail closed.
        tracing::error!(
            content_type = ?content_type,
            status = %resp.status(),
            "upstream answered a list request with a body the proxy cannot filter"
        );
        let body = error_response(
            Value::Null,
            CODE_UPSTREAM,
            "attenuo: upstream answered a list request with an unsupported content type",
            None,
        );
        json_response(StatusCode::BAD_GATEWAY, &body)
    } else {
        let prelude = sse_prelude(&screened.replies);
        stream_response(
            resp,
            prelude,
            Some(state.stream_guard(who, server, session_id)),
            state.max_upstream_body,
        )
    };
    add_decision_header(&mut response, &screened.decision_ids);
    response
}

/// Report the proxy's own stages of a `POST` that carried a decided call: to the authorizer
/// ([`Authorizer::observe_stage`]) and as one debug event.
fn report_post_timing(state: &AppState, timing: &PostTiming, started: Instant) {
    let done = Instant::now();
    let total = done - started;
    let response = timing.upstream_done.map(|t| done - t);
    let a = &state.authorizer;
    if let Some(d) = timing.upstream {
        a.observe_stage(Stage::Upstream, d);
    }
    if let Some(d) = response {
        a.observe_stage(Stage::Response, d);
    }
    a.observe_stage(Stage::Total, total);
    tracing::debug!(
        upstream_us = timing.upstream.map(|d| d.as_micros() as u64),
        response_us = response.map(|d| d.as_micros() as u64),
        total_us = total.as_micros() as u64,
        "proxy stages"
    );
}

/// Classify one JSON-RPC message and route it. See the method table in the crate docs.
///
/// - `tools/call`, `resources/read`, `resources/subscribe`, `prompts/get`,
///   `completion/complete` and every unrecognised non-notification method get an
///   authorization decision; only an allow is forwarded.
/// - Allowlisted methods and `notifications/*` are forwarded, after a lease check.
async fn screen_message(
    state: &AppState,
    who: &Authenticated,
    server: &str,
    session_id: Option<&str>,
    mut msg: Value,
    now: OffsetDateTime,
    out: &mut Screened,
) {
    let chain = &who.chain;
    // The approval token is for the decision, never for the upstream (ADR-0009). Removed
    // before anything below reads the params, so it is in no `ToolCall` and no call hash.
    let approval_token = match take_approval_token(&mut msg) {
        Ok(t) => t,
        Err(detail) => {
            if is_request(&msg) {
                out.replies.push(error_response(
                    id_of(&msg),
                    CODE_INVALID_PARAMS,
                    format!("attenuo: invalid params: {detail}"),
                    None,
                ));
            }
            return;
        }
    };
    let method = method_of(&msg).map(str::to_owned);
    let Some(method) = method else {
        // A response to a server-initiated request, or something malformed: the upstream
        // decides. Still requires a live lease.
        if lease_live(state, who, server, session_id, &msg, now, out).await {
            out.forward.push(msg);
        }
        return;
    };

    if is_passthrough_method(&method) {
        if !lease_live(state, who, server, session_id, &msg, now, out).await {
            return;
        }
        if let Some(kind) = ListKind::from_method(&method) {
            if is_request(&msg) {
                out.list_requests.push((id_of(&msg), kind));
            }
        }
        out.forward.push(msg);
        return;
    }

    // Everything else needs a decision. Work out the ToolCall.
    let id = id_of(&msg);
    let params = msg.get("params");
    let str_param = |key: &str| {
        params
            .and_then(|p| p.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let invalid = |detail: &str| {
        tracing::warn!(method = ?method, detail = ?detail, "invalid params");
        error_response(
            id.clone(),
            CODE_INVALID_PARAMS,
            format!("attenuo: invalid params: {detail}"),
            None,
        )
    };
    let (tool, arguments) = match method.as_str() {
        jsonrpc::METHOD_TOOLS_CALL => {
            let Some(name) = str_param("name") else {
                out.replies.push(invalid("tools/call requires params.name"));
                return;
            };
            if let Some(reason) = tool_name_refusal(state, server, &name) {
                refuse_call(state, who, server, session_id, &name, id, reason, now, out).await;
                return;
            }
            let arguments = match params.and_then(|p| p.get("arguments")) {
                None | Some(Value::Null) => Value::Object(Default::default()),
                Some(v @ Value::Object(_)) => v.clone(),
                Some(_) => {
                    // `ToolCall` would read a non-object as "no arguments", so policy would see
                    // something other than what the upstream receives. Refuse it (SR-07).
                    out.replies
                        .push(invalid("tools/call params.arguments must be an object"));
                    return;
                }
            };
            (name, arguments)
        }
        jsonrpc::METHOD_RESOURCES_READ | jsonrpc::METHOD_RESOURCES_SUBSCRIBE => {
            let Some(uri) = str_param("uri") else {
                out.replies
                    .push(invalid(&format!("{method} requires params.uri")));
                return;
            };
            (method.clone(), serde_json::json!({ "uri": uri }))
        }
        jsonrpc::METHOD_PROMPTS_GET => {
            let Some(name) = str_param("name") else {
                out.replies
                    .push(invalid("prompts/get requires params.name"));
                return;
            };
            let arguments = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default()));
            (
                method.clone(),
                serde_json::json!({ "name": name, "arguments": arguments }),
            )
        }
        // `completion/complete` and unknown methods: the whole params object is the input.
        _ => (
            method.clone(),
            params
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default())),
        ),
    };

    let mut call = ToolCall::new(server, tool.clone(), arguments).with_dpop_bound(who.dpop_bound);
    if let Some(sid) = session_id {
        // Policy and the audit log see a stable hash prefix, not the session id (SR-11).
        call = call.with_session(session_tag(sid));
    }
    let ctx = CallContext {
        approval_token,
        jkt: who.jkt.clone(),
    };
    let verdict = state
        .authorizer
        .authorize_with(chain, &call, &ctx, now)
        .await;
    // Method and tool name are the caller's: Debug-format them so a newline cannot forge a
    // log line (SR-18).
    tracing::info!(
        method = ?method,
        tool = ?tool,
        decision = ?verdict.decision,
        reason = ?verdict.reason,
        decision_id = %verdict.decision_id,
        "request authorized"
    );
    out.decision_ids.push(verdict.decision_id);
    if verdict.is_allow() {
        if LABELLED_METHODS.contains(&method.as_str()) && is_request(&msg) {
            out.results.push(PendingResult {
                id,
                call,
                decision_id: verdict.decision_id,
            });
        }
        out.forward.push(msg);
    } else if verdict.reason == REASON_APPROVAL_REQUIRED {
        out.replies.push(jsonrpc::with_usage(
            approval_required_response(
                id,
                verdict.decision_id,
                &call.call_hash(),
                verdict.approval.as_ref(),
                verdict.untrusted_args.as_ref(),
            ),
            verdict.usage.as_ref(),
        ));
    } else {
        out.replies.push(jsonrpc::with_usage(
            denied_response_with(
                id,
                &verdict.reason,
                verdict.decision_id,
                verdict.limit.as_ref(),
                verdict.untrusted_args.as_ref(),
            ),
            verdict.usage.as_ref(),
        ));
    }
}

/// Remove `params._meta["dev.attenuo/approval"]` from `msg` and return it; drop `_meta` when
/// nothing else is left in it, so the message is what it would be without the token. `Err`
/// when the value is not a string.
fn take_approval_token(msg: &mut Value) -> Result<Option<String>, &'static str> {
    let Some(params) = msg.get_mut("params").and_then(Value::as_object_mut) else {
        return Ok(None);
    };
    let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) else {
        return Ok(None);
    };
    let Some(token) = meta.remove(META_APPROVAL_KEY) else {
        return Ok(None);
    };
    if meta.is_empty() {
        params.remove("_meta");
    }
    match token {
        Value::String(t) => Ok(Some(t)),
        _ => Err("params._meta[\"dev.attenuo/approval\"] must be a string"),
    }
}

/// Why a `tools/call` for `name` must be refused before a decision, if it must (SR-25): the
/// name is not a valid tool name, or (with `require_listed_tools`) neither the upstream listed
/// it nor the catalog knows it.
fn tool_name_refusal(state: &AppState, server: &str, name: &str) -> Option<&'static str> {
    if attenuo_core::names::check_tool_name(name).is_err() {
        return Some(REASON_INVALID_NAME);
    }
    if state.require_listed_tools
        && !state.listed.contains(server, name)
        && !state.authorizer.knows_tool(server, name)
    {
        return Some(REASON_TOOL_NOT_LISTED);
    }
    None
}

/// Deny a `tools/call` the proxy refuses on its own: record it through
/// [`Authorizer::record_rejection`] and reply with a denial.
#[allow(clippy::too_many_arguments)]
async fn refuse_call(
    state: &AppState,
    who: &Authenticated,
    server: &str,
    session_id: Option<&str>,
    name: &str,
    id: Value,
    reason: &'static str,
    now: OffsetDateTime,
    out: &mut Screened,
) {
    let mut call =
        ToolCall::new(server, name, serde_json::json!({})).with_dpop_bound(who.dpop_bound);
    if let Some(sid) = session_id {
        call = call.with_session(session_tag(sid));
    }
    let decision_id = state
        .authorizer
        .record_rejection(&who.chain, &call, reason, now)
        .await;
    // `name` is caller-controlled: Debug-format it so it cannot forge log lines.
    tracing::warn!(tool = ?name, reason, %decision_id, "tools/call refused");
    out.decision_ids.push(decision_id);
    out.replies.push(denied_response(id, reason, decision_id));
}

/// Lease check for a message forwarded without a decision. On failure, a request gets a
/// `-32001` reply and a notification is dropped; returns whether to forward. The first failure
/// of an HTTP request is recorded ([`record_lease_refusal`]) under the method of the message
/// that met it.
async fn lease_live(
    state: &AppState,
    who: &Authenticated,
    server: &str,
    session_id: Option<&str>,
    msg: &Value,
    now: OffsetDateTime,
    out: &mut Screened,
) -> bool {
    if out.lease_check.is_none() {
        let check = state.authorizer.check_active(&who.chain, now).await;
        if let Err(e) = &check {
            let tool = refused_tool_name(method_of(msg));
            out.lease_refusal =
                record_lease_refusal(state, who, server, session_id, tool, e, now).await;
        }
        out.lease_check = Some(check);
    }
    match out.lease_check.as_ref() {
        Some(Err(e)) => {
            tracing::warn!(reason = ?e.reason(), "request refused: lease inactive");
            if is_request(msg) {
                out.replies
                    .push(unauthorized_body(id_of(msg), e, out.lease_refusal));
            }
            false
        }
        _ => true,
    }
}

/// Read a JSON upstream response fully, filter list results and merge in the replies
/// the proxy generated for a batch, then re-encode.
async fn buffer_and_rewrite(
    state: &AppState,
    resp: reqwest::Response,
    chain: &DelegationChain,
    server: &str,
    screened: &Screened,
    labeller: Option<&Labeller>,
    is_batch: bool,
) -> Response {
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = match read_upstream_body(resp, state.max_upstream_body).await {
        Ok(b) => b,
        Err(UpstreamBodyError::TooLarge) => {
            return upstream_body_too_large(state.max_upstream_body)
        }
        Err(UpstreamBodyError::Transport(e)) => return upstream_error(e),
    };
    let mut value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        // An empty body answers nothing, so it hides nothing either: relayed as it is when no
        // call or list of this request awaits an answer in it (SR-85 reads the bodies of
        // requests that only might hold an earlier call's answer).
        Err(_)
            if bytes.is_empty()
                && screened.list_requests.is_empty()
                && labeller.is_none_or(|l| l.failure_replies().is_empty()) =>
        {
            return build_response(status, &headers, Body::from(bytes));
        }
        Err(e) => {
            if !screened.list_requests.is_empty() {
                // A list result the proxy cannot parse is one it cannot filter.
                tracing::error!(
                    error = ?e.to_string(),
                    "upstream answered a list request with invalid JSON"
                );
                let body = error_response(
                    Value::Null,
                    CODE_UPSTREAM,
                    "attenuo: upstream answered a list request with invalid JSON",
                    None,
                );
                return json_response(StatusCode::BAD_GATEWAY, &body);
            }
            if let Some(labeller) = labeller {
                // A result the proxy cannot parse is one it cannot record (ADR-0009).
                tracing::error!(
                    error = ?e.to_string(),
                    "upstream answered a mediated call with invalid JSON; withheld"
                );
                return label_failure(screened, labeller, is_batch);
            }
            tracing::warn!(
                error = ?e.to_string(),
                "upstream JSON response did not parse; passing through"
            );
            return build_response(status, &headers, Body::from(bytes));
        }
    };

    // A chain with no hops has no capabilities: list nothing.
    let no_caps = CapabilitySet::new();
    let caps = chain.effective_capabilities().unwrap_or(&no_caps);
    let filter = ListFilter::new(&screened.list_requests, caps, server);
    observe_listed(
        &filter,
        &value,
        server,
        &state.listed,
        state.authorizer.as_ref(),
    );
    let removed = filter.apply(&mut value);
    if removed > 0 {
        tracing::debug!(removed, "filtered list result");
    }
    // An upstream error must not read as the proxy's stream end (`id: null`, `-32001`).
    disown_stream_end(&mut value);
    if let Some(labeller) = labeller {
        let withheld = labeller.label_value(&mut value).await;
        if withheld > 0 {
            tracing::warn!(withheld, "results withheld: they could not be labelled");
        }
    }

    if !screened.replies.is_empty() || (is_batch && !value.is_array()) {
        let mut items = match value {
            Value::Array(items) => items,
            Value::Null => vec![],
            other => vec![other],
        };
        items.extend(screened.replies.iter().cloned());
        value = Value::Array(items);
    }

    let body = serde_json::to_vec(&value).unwrap_or_default();
    build_response(status, &headers, Body::from(body))
}

/// Record the tool names of the `tools/list` results in `body` (SR-25) and report the tools'
/// MCP annotations to the authorizer ([`Authorizer::observe_tool_hints`]). Before filtering,
/// so every tool the upstream lists is seen.
fn observe_listed(
    filter: &ListFilter<'_>,
    body: &Value,
    server: &str,
    listed: &ListedTools,
    authorizer: &dyn Authorizer,
) {
    let names = filter.listed_tool_names(body);
    if !names.is_empty() {
        listed.record(server, names.iter().map(String::as_str));
    }
    for (tool, read_only, destructive) in filter.listed_tool_hints(body) {
        authorizer.observe_tool_hints(server, &tool, read_only, destructive);
    }
}

/// The answer when the upstream's body to a request with allowed mediated calls cannot be
/// read (ADR-0009): the proxy's own replies, then a `label_error` denial for each call, as
/// one JSON body (an array for a batch).
fn label_failure(screened: &Screened, labeller: &Labeller, is_batch: bool) -> Response {
    let mut items = screened.replies.clone();
    items.extend(labeller.failure_replies());
    if items.is_empty() {
        // No call of this request was allowed, but the body may answer an earlier one
        // (SR-85): nothing in it can be relayed.
        let body = error_response(
            Value::Null,
            CODE_UPSTREAM,
            "attenuo: upstream answered with a body the proxy cannot label",
            None,
        );
        return json_response(StatusCode::BAD_GATEWAY, &body);
    }
    let body = if is_batch || items.len() > 1 {
        Value::Array(items)
    } else {
        items.pop().unwrap_or(Value::Null)
    };
    json_response(StatusCode::OK, &body)
}

/// SSE events for locally generated replies, to prepend to an upstream event stream.
fn sse_prelude(replies: &[Value]) -> Option<Bytes> {
    if replies.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for r in replies {
        out.extend_from_slice(b"event: message\ndata: ");
        out.extend_from_slice(&serde_json::to_vec(r).unwrap_or_default());
        out.extend_from_slice(b"\n\n");
    }
    Some(Bytes::from(out))
}

/// Is this an SSE body?
fn is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
}

/// Stream an upstream response back without buffering (SSE passthrough). With a `guard`, the
/// stream is re-checked and ended when the check fails (SR-28); an SSE body is then relayed
/// event by event ([`crate::sse::frame_stream`]), so the proxy's final event never lands
/// inside a partial upstream event, and an upstream event in the shape of that final event is
/// rewritten ([`crate::guard::disown_stream_end`]).
/// `limit` bounds one buffered SSE event (`max_upstream_body_bytes`).
fn stream_response(
    resp: reqwest::Response,
    prelude: Option<Bytes>,
    guard: Option<StreamGuard>,
    limit: usize,
) -> Response {
    let status = resp.status();
    let headers = resp.headers().clone();
    let prelude = futures_util::stream::iter(prelude.map(Ok::<_, std::io::Error>));
    let body = match guard {
        None => {
            let raw = resp
                .bytes_stream()
                .map(|r| r.map_err(std::io::Error::other));
            Body::from_stream(prelude.chain(raw))
        }
        Some(guard) if is_event_stream(&headers) => {
            let framed = disown_stream(crate::sse::frame_stream(resp.bytes_stream(), limit));
            Body::from_stream(guard_stream(prelude.chain(framed), guard, true))
        }
        Some(guard) => {
            let raw = resp
                .bytes_stream()
                .map(|r| r.map_err(std::io::Error::other));
            Body::from_stream(guard_stream(prelude.chain(raw), guard, false))
        }
    };
    build_response(status, &headers, body)
}

/// Like [`stream_response`] for an SSE body, always re-checked: with a `filter`, it runs over
/// every JSON-RPC message in the events (see [`crate::sse`]); with a `labeller`, every
/// response to an allowed call is recorded before its event is relayed ([`crate::label`]).
/// Either way an upstream event in the shape of the proxy's stream-end event is rewritten
/// first ([`crate::guard::disown_stream_end`]).
fn stream_response_sse<F>(
    resp: reqwest::Response,
    prelude: Option<Bytes>,
    guard: StreamGuard,
    limit: usize,
    filter: Option<F>,
    labeller: Option<Labeller>,
) -> Response
where
    F: FnMut(&mut Value) + Send + 'static,
{
    type Events =
        std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send>>;
    let status = resp.status();
    let headers = resp.headers().clone();
    // No upstream event may read as the proxy's own stream end (the guard appends that). With
    // a filter, in the same pass that parses each event; without, on the framed events.
    let events: Events = match filter {
        Some(mut f) => Box::pin(crate::sse::rewrite_stream(
            resp.bytes_stream(),
            limit,
            move |msg: &mut Value| {
                f(msg);
                disown_stream_end(msg);
            },
        )),
        None => Box::pin(disown_stream(crate::sse::frame_stream(
            resp.bytes_stream(),
            limit,
        ))),
    };
    let events: Events = match labeller {
        Some(l) => Box::pin(label_stream(events, l)),
        None => events,
    };
    let prelude = futures_util::stream::iter(prelude.map(Ok::<_, std::io::Error>));
    let body = Body::from_stream(guard_stream(prelude.chain(events), guard, true));
    build_response(status, &headers, body)
}

fn build_response(status: StatusCode, upstream_headers: &HeaderMap, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = forward_headers(upstream_headers, FORWARD_RESPONSE_HEADERS);
    sanitize_session_header(response.headers_mut());
    response
}

fn add_decision_header(response: &mut Response, ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }
    let joined = ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if let Ok(v) = HeaderValue::from_str(&joined) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(DECISION_ID_HEADER), v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn approval_token_is_taken_out_of_meta() {
        let mut msg = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "t", "arguments": {"a": 1},
                       "_meta": {"dev.attenuo/approval": "tok"}}});
        assert_eq!(take_approval_token(&mut msg), Ok(Some("tok".to_string())));
        assert_eq!(
            msg["params"],
            serde_json::json!({"name": "t", "arguments": {"a": 1}})
        );
        let mut msg = serde_json::json!({"method": "tools/call", "params": {"name": "t",
            "_meta": {"progressToken": 7, "dev.attenuo/approval": "tok"}}});
        assert_eq!(take_approval_token(&mut msg), Ok(Some("tok".to_string())));
        assert_eq!(
            msg["params"]["_meta"],
            serde_json::json!({"progressToken": 7})
        );
        let mut msg = serde_json::json!({"method": "tools/call", "params": {"name": "t",
            "_meta": {"progressToken": 7}}});
        let before = msg.clone();
        assert_eq!(take_approval_token(&mut msg), Ok(None));
        assert_eq!(msg, before);
        let mut msg = serde_json::json!({"method": "tools/call", "params": {"name": "t",
            "_meta": {"dev.attenuo/approval": 5}}});
        assert!(take_approval_token(&mut msg).is_err());
        assert_eq!(
            take_approval_token(&mut serde_json::json!({"method": "ping"})),
            Ok(None)
        );
    }

    #[test]
    fn bearer_extraction() {
        assert_eq!(bearer_of(&HeaderMap::new()), Err(AuthError::MissingToken));
        assert_eq!(bearer_of(&headers_with_auth("Bearer abc")), Ok("abc"));
        assert_eq!(bearer_of(&headers_with_auth("bearer abc ")), Ok("abc"));
        assert!(matches!(
            bearer_of(&headers_with_auth("Basic abc")),
            Err(AuthError::InvalidToken(_))
        ));
        assert!(matches!(
            bearer_of(&headers_with_auth("Bearer ")),
            Err(AuthError::InvalidToken(_))
        ));
        assert!(matches!(
            bearer_of(&headers_with_auth("abc")),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn session_header_must_be_single_and_visible_ascii() {
        let with = |values: &[&[u8]]| {
            let mut h = HeaderMap::new();
            for v in values {
                h.append(HEADER_MCP_SESSION_ID, HeaderValue::from_bytes(v).unwrap());
            }
            h
        };
        assert_eq!(session_id_of(&HeaderMap::new()).ok(), Some(None));
        assert_eq!(
            session_id_of(&with(&[b"sess-1"])).ok(),
            Some(Some("sess-1".to_owned()))
        );
        for bad in [
            &[&b"a"[..], &b"b"[..]][..],
            &[&b"a"[..], &b"a"[..]][..],
            &[&b"\x80"[..]][..],
            &[&b"a b"[..]][..],
            &[&b"a\tb"[..]][..],
            &[&b""[..]][..],
        ] {
            let resp = session_id_of(&with(bad)).unwrap_err();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        }
    }

    #[test]
    fn upstream_session_headers_are_dropped_unless_single_and_valid() {
        let mut h = HeaderMap::new();
        h.append(HEADER_MCP_SESSION_ID, HeaderValue::from_static("one"));
        sanitize_session_header(&mut h);
        assert_eq!(h.get(HEADER_MCP_SESSION_ID).unwrap(), "one");
        h.append(HEADER_MCP_SESSION_ID, HeaderValue::from_static("two"));
        sanitize_session_header(&mut h);
        assert!(h.get(HEADER_MCP_SESSION_ID).is_none());
        h.append(
            HEADER_MCP_SESSION_ID,
            HeaderValue::from_bytes(b"\x80").unwrap(),
        );
        sanitize_session_header(&mut h);
        assert!(h.get(HEADER_MCP_SESSION_ID).is_none());
    }

    #[test]
    fn sse_prelude_encodes_each_reply_as_an_event() {
        assert!(sse_prelude(&[]).is_none());
        let p = sse_prelude(&[serde_json::json!({"id": 1}), serde_json::json!({"id": 2})]).unwrap();
        let s = std::str::from_utf8(&p).unwrap();
        assert_eq!(
            s,
            "event: message\ndata: {\"id\":1}\n\nevent: message\ndata: {\"id\":2}\n\n"
        );
    }
}

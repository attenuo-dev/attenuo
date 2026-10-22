//! The axum router: authentication, `tools/call` interception, `tools/list` filtering, and
//! transparent forwarding of everything else.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use onbehalf_core::{DelegationChain, ToolCall};
use serde_json::Value;
use time::OffsetDateTime;
use tower_http::trace::TraceLayer;
use tracing::Instrument;
use uuid::Uuid;

use crate::auth::{AuthError, Authorizer};
use crate::config::ProxyConfig;
use crate::filter::filter_tools_response;
use crate::jsonrpc::{
    self, denied_response, error_response, id_of, is_passthrough_method, is_request, method_of,
    CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_PARSE_ERROR, CODE_UNAUTHORIZED,
    CODE_UNKNOWN_SERVER, CODE_UPSTREAM,
};

/// Response header carrying the decision record id(s) of every `tools/call` in the request,
/// comma separated in request order.
pub const DECISION_ID_HEADER: &str = "x-onbehalf-decision-id";

const HEADER_MCP_SESSION_ID: &str = "mcp-session-id";

/// Request headers forwarded to the upstream. `Authorization` is deliberately absent: the
/// bearer the proxy receives is onbehalf's token, not an upstream credential.
const FORWARD_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "content-type",
    HEADER_MCP_SESSION_ID,
    "mcp-protocol-version",
    "last-event-id",
];

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
}

/// Build the proxy router. Upstreams are mounted at `/mcp/{name}`.
pub fn router(config: ProxyConfig, authorizer: Arc<dyn Authorizer>) -> Router {
    let upstreams = config
        .upstreams
        .into_iter()
        .map(|u| (u.name, u.url))
        .collect();
    let state = Arc::new(AppState {
        upstreams,
        client: upstream_client(),
        authorizer,
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
    tracing::info!(addr = %listener.local_addr()?, "onbehalf proxy listening");
    axum::serve(listener, router(config, authorizer)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------

fn bearer_of(headers: &HeaderMap) -> Result<&str, AuthError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidToken("authorization header is not ASCII".into()))?;
    let (scheme, token) = raw
        .split_once(' ')
        .ok_or_else(|| AuthError::InvalidToken("expected `Bearer <token>`".into()))?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return Err(AuthError::InvalidToken("expected `Bearer <token>`".into()));
    }
    Ok(token.trim())
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<DelegationChain, AuthError> {
    let bearer = bearer_of(headers)?;
    state.authorizer.authenticate(bearer, now).await
}

fn unauthorized(err: AuthError) -> Response {
    tracing::warn!(error = %err, "request rejected: unauthenticated");
    let body = error_response(
        Value::Null,
        CODE_UNAUTHORIZED,
        format!("onbehalf: unauthorized: {err}"),
        None,
    );
    let mut resp = json_response(StatusCode::UNAUTHORIZED, &body);
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"onbehalf\""),
    );
    resp
}

fn unknown_server(server: &str) -> Response {
    tracing::warn!(server, "request rejected: unknown upstream");
    let body = error_response(
        Value::Null,
        CODE_UNKNOWN_SERVER,
        format!("onbehalf: unknown server `{server}`"),
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
    tracing::info_span!(
        "mcp_request",
        server,
        agent = %agent,
        subject = %chain.originating_user.subject,
        chain_depth = chain.depth(),
        session_id = session_id.unwrap_or(""),
    )
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
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
// GET / DELETE: transparent passthrough (SSE listen stream, session termination)
// ---------------------------------------------------------------------------------------------

async fn handle_passthrough(
    State(state): State<Arc<AppState>>,
    Path(server): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(upstream) = state.upstreams.get(&server).cloned() else {
        return unknown_server(&server);
    };
    let now = OffsetDateTime::now_utc();
    let chain = match authenticate(&state, &headers, now).await {
        Ok(c) => c,
        Err(e) => return unauthorized(e),
    };
    if let Err(e) = state.authorizer.check_active(&chain, now).await {
        return unauthorized(e);
    }
    let session_id = header_str(&headers, HEADER_MCP_SESSION_ID).map(str::to_owned);
    let span = request_span(&server, &chain, session_id.as_deref());
    async move {
        tracing::debug!(%method, "forwarding transparently");
        let req = state
            .client
            .request(method, &upstream)
            .headers(forward_headers(&headers, FORWARD_REQUEST_HEADERS))
            .body(body);
        match req.send().await {
            Ok(resp) => stream_response(resp, None, &[]),
            Err(e) => upstream_error(e),
        }
    }
    .instrument(span)
    .await
}

fn upstream_error(err: reqwest::Error) -> Response {
    tracing::error!(error = %err, "upstream request failed");
    let body = error_response(
        Value::Null,
        CODE_UPSTREAM,
        format!("onbehalf: upstream unreachable: {err}"),
        None,
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
    /// Ids of `tools/list` requests, whose responses must be filtered.
    tools_list_ids: Vec<Value>,
    /// Result of the lease check made for messages forwarded without a per-call decision;
    /// made at most once per HTTP request.
    lease_check: Option<Result<(), AuthError>>,
}

async fn handle_post(
    State(state): State<Arc<AppState>>,
    Path(server): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(upstream) = state.upstreams.get(&server) else {
        return unknown_server(&server);
    };
    let now = OffsetDateTime::now_utc();
    let chain = match authenticate(&state, &headers, now).await {
        Ok(c) => c,
        Err(e) => return unauthorized(e),
    };
    let session_id = header_str(&headers, HEADER_MCP_SESSION_ID).map(str::to_owned);
    let span = request_span(&server, &chain, session_id.as_deref());
    handle_post_inner(
        &state,
        upstream,
        &server,
        &chain,
        session_id.as_deref(),
        &headers,
        body,
        now,
    )
    .instrument(span)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_post_inner(
    state: &AppState,
    upstream: &str,
    server: &str,
    chain: &DelegationChain,
    session_id: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    now: OffsetDateTime,
) -> Response {
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "request body is not JSON");
            let body = error_response(
                Value::Null,
                CODE_PARSE_ERROR,
                format!("onbehalf: parse error: {e}"),
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
                "onbehalf: invalid request: expected a JSON-RPC object or batch",
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };
    if is_batch && messages.is_empty() {
        let body = error_response(
            Value::Null,
            CODE_INVALID_REQUEST,
            "onbehalf: invalid request: empty batch",
            None,
        );
        return json_response(StatusCode::BAD_REQUEST, &body);
    }

    let mut screened = Screened::default();
    for msg in messages {
        screen_message(state, chain, server, session_id, msg, now, &mut screened).await;
    }

    // A single message that was refused only because the token's lease is inactive is an
    // authentication failure for the whole request.
    if !is_batch && screened.forward.is_empty() && screened.decision_ids.is_empty() {
        if let Some(Err(e)) = screened.lease_check.take() {
            return unauthorized(e);
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
                "onbehalf: invalid request",
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };
    let mut req_headers = forward_headers(headers, FORWARD_REQUEST_HEADERS);
    if !req_headers.contains_key(header::CONTENT_TYPE) {
        req_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
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

    let needs_buffer = !screened.tools_list_ids.is_empty() || !screened.replies.is_empty();
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.trim_start().starts_with("application/json"))
        .unwrap_or(false);

    let mut response = if needs_buffer && is_json {
        buffer_and_rewrite(resp, chain, server, &screened, is_batch).await
    } else {
        if !screened.tools_list_ids.is_empty() {
            tracing::warn!(
                "upstream answered tools/list over a non-JSON response; passing through \
                 unfiltered (v0 limitation)"
            );
        }
        let prelude = sse_prelude(&screened.replies);
        stream_response(resp, prelude, &[])
    };
    add_decision_header(&mut response, &screened.decision_ids);
    response
}

/// Classify one JSON-RPC message and route it. See the method table in the crate docs.
///
/// - `tools/call`, `resources/read`, `resources/subscribe`, `prompts/get`,
///   `completion/complete` and every unrecognised non-notification method get an
///   authorization decision; only an allow is forwarded.
/// - Allowlisted methods and `notifications/*` are forwarded, after a lease check.
async fn screen_message(
    state: &AppState,
    chain: &DelegationChain,
    server: &str,
    session_id: Option<&str>,
    msg: Value,
    now: OffsetDateTime,
    out: &mut Screened,
) {
    let method = method_of(&msg).map(str::to_owned);
    let Some(method) = method else {
        // A response to a server-initiated request, or something malformed: the upstream
        // decides. Still requires a live lease.
        if lease_live(state, chain, &msg, now, out).await {
            out.forward.push(msg);
        }
        return;
    };

    if is_passthrough_method(&method) {
        if !lease_live(state, chain, &msg, now, out).await {
            return;
        }
        if method == jsonrpc::METHOD_TOOLS_LIST && is_request(&msg) {
            out.tools_list_ids.push(id_of(&msg));
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
        tracing::warn!(%method, "{detail}");
        error_response(
            id.clone(),
            CODE_INVALID_PARAMS,
            format!("onbehalf: invalid params: {detail}"),
            None,
        )
    };
    let (tool, arguments) = match method.as_str() {
        jsonrpc::METHOD_TOOLS_CALL => {
            let Some(name) = str_param("name") else {
                out.replies.push(invalid("tools/call requires params.name"));
                return;
            };
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

    let mut call = ToolCall::new(server, tool.clone(), arguments);
    if let Some(sid) = session_id {
        call = call.with_session(sid);
    }
    let verdict = state.authorizer.authorize(chain, &call, now).await;
    tracing::info!(
        %method,
        tool = %tool,
        decision = ?verdict.decision,
        reason = %verdict.reason,
        decision_id = %verdict.decision_id,
        "request authorized"
    );
    out.decision_ids.push(verdict.decision_id);
    if verdict.is_allow() {
        out.forward.push(msg);
    } else {
        out.replies
            .push(denied_response(id, &verdict.reason, verdict.decision_id));
    }
}

/// Lease check for a message forwarded without a decision. On failure, a request gets a
/// `-32001` reply and a notification is dropped; returns whether to forward.
async fn lease_live(
    state: &AppState,
    chain: &DelegationChain,
    msg: &Value,
    now: OffsetDateTime,
    out: &mut Screened,
) -> bool {
    if out.lease_check.is_none() {
        out.lease_check = Some(state.authorizer.check_active(chain, now).await);
    }
    match out.lease_check.as_ref() {
        Some(Err(e)) => {
            tracing::warn!(error = %e, "request refused: lease inactive");
            if is_request(msg) {
                out.replies.push(error_response(
                    id_of(msg),
                    CODE_UNAUTHORIZED,
                    format!("onbehalf: unauthorized: {e}"),
                    None,
                ));
            }
            false
        }
        _ => true,
    }
}

/// Read a JSON upstream response fully, filter `tools/list` results and merge in the replies
/// the proxy generated for a batch, then re-encode.
async fn buffer_and_rewrite(
    resp: reqwest::Response,
    chain: &DelegationChain,
    server: &str,
    screened: &Screened,
    is_batch: bool,
) -> Response {
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return upstream_error(e),
    };
    let mut value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "upstream JSON response did not parse; passing through");
            return build_response(status, &headers, Body::from(bytes));
        }
    };

    let caps = chain.effective_capabilities();
    let mut filter = |v: &mut Value| {
        if screened.tools_list_ids.contains(&id_of(v)) {
            if let Some(caps) = caps {
                let removed = filter_tools_response(v, caps, server);
                tracing::debug!(removed, "filtered tools/list");
            } else {
                // A chain with no hops has no capabilities: list nothing.
                if let Some(r) = v.get_mut("result") {
                    r["tools"] = Value::Array(vec![]);
                }
            }
        }
    };
    match &mut value {
        Value::Array(items) => items.iter_mut().for_each(&mut filter),
        other => filter(other),
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

/// Stream an upstream response back without buffering (SSE passthrough).
fn stream_response(
    resp: reqwest::Response,
    prelude: Option<Bytes>,
    extra: &[(HeaderName, HeaderValue)],
) -> Response {
    let status = resp.status();
    let headers = resp.headers().clone();
    let upstream = resp.bytes_stream();
    let body = match prelude {
        Some(p) => Body::from_stream(futures_util::stream::once(async { Ok(p) }).chain(upstream)),
        None => Body::from_stream(upstream),
    };
    let mut response = build_response(status, &headers, body);
    for (k, v) in extra {
        response.headers_mut().insert(k.clone(), v.clone());
    }
    response
}

fn build_response(status: StatusCode, upstream_headers: &HeaderMap, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = forward_headers(upstream_headers, FORWARD_RESPONSE_HEADERS);
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

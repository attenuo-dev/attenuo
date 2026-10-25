//! Test doubles: a fake MCP server and a static authorizer.
//!
//! Available in this crate's tests and, behind the `testing` feature, to other crates.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use attenuo_core::{
    AgentId, Capability, CapabilitySet, DecisionRecord, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::StreamExt;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use crate::auth::{AuthDecision, AuthError, Authorizer};
use crate::jsonrpc::{error_response, id_of, is_request, method_of, CODE_INVALID_REQUEST};

// ---------------------------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------------------------

/// A router served on an ephemeral port. The server task is aborted on drop.
pub struct Spawned {
    pub addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl Spawned {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Serve `router` on `127.0.0.1:0` in a background task.
pub async fn spawn_router(router: Router) -> anyhow::Result<Spawned> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(Spawned { addr, handle })
}

// ---------------------------------------------------------------------------------------------
// FakeMcpServer
// ---------------------------------------------------------------------------------------------

/// A `tools/call` the fake upstream received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCall {
    pub name: String,
    pub arguments: Value,
    pub session_id: Option<String>,
    /// The whole `params` member as received (with `_meta`, if any).
    pub params: Value,
}

/// A minimal Streamable HTTP MCP server: `initialize`, `tools/list`, `tools/call`,
/// `resources/list`, `resources/templates/list`, `prompts/list` (all optionally paginated),
/// notifications, batches. Mounted at `POST /mcp`; `DELETE /mcp` ends a session and is recorded
/// ([`FakeMcpServer::deleted_sessions`]). `GET /mcp` answers `405`, as a server without a listen
/// stream does, unless [`FakeMcpServer::with_listen_stream`] or [`FakeMcpServer::with_replay`]
/// turns it on: then it opens a listen stream that stays open, starting with a
/// `notifications/message` event, and a `GET` that resumes with `Last-Event-ID` first replays
/// the messages given to `with_replay`, like a server that buffers the events of a broken
/// stream.
#[derive(Clone)]
pub struct FakeMcpServer {
    tools: Vec<Value>,
    resources: Vec<Value>,
    resource_templates: Vec<Value>,
    prompts: Vec<Value>,
    /// Entries per page for the four list methods; `None` returns everything at once.
    page_size: Option<usize>,
    calls: Arc<Mutex<Vec<RecordedCall>>>,
    methods: Arc<Mutex<Vec<String>>>,
    /// When set, every response is sent as a single `text/event-stream` event instead of JSON.
    sse: bool,
    /// With `sse`: send each response of a batch as its own event, preceded by a server
    /// notification event, like a streaming server does (instead of one event per HTTP reply).
    sse_event_per_response: bool,
    session_id: String,
    /// Resolve `tools/call` names case-insensitively, like some real servers do (SR-25).
    case_insensitive_names: bool,
    /// When set, every `initialize` opens a new session (`{session_id}-{n}`) and other responses
    /// carry no session id, like a real server; otherwise every response carries `session_id`.
    fresh_sessions: bool,
    sessions_opened: Arc<AtomicU64>,
    /// `Mcp-Session-Id` of every `DELETE` received, in order.
    deleted: Arc<Mutex<Vec<String>>>,
    /// `tools/call` names answered with a JSON-RPC error instead of a result.
    failing_tools: Vec<String>,
    /// Serve `GET /mcp` as a listen stream instead of `405`.
    listen: bool,
    /// Messages replayed on a `GET` that carries `Last-Event-ID`.
    replay: Vec<Value>,
    /// `Last-Event-ID` of every `GET` that carried one, in order.
    last_event_ids: Arc<Mutex<Vec<String>>>,
}

impl FakeMcpServer {
    /// A server exposing tools with these names (each with an open object schema).
    pub fn new(tool_names: &[&str]) -> Self {
        Self {
            tools: tool_names
                .iter()
                .map(|n| {
                    json!({
                        "name": n,
                        "description": format!("fake tool {n}"),
                        "inputSchema": {"type": "object"}
                    })
                })
                .collect(),
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            page_size: None,
            calls: Arc::new(Mutex::new(Vec::new())),
            methods: Arc::new(Mutex::new(Vec::new())),
            sse: false,
            sse_event_per_response: false,
            session_id: "fake-session-1".into(),
            case_insensitive_names: false,
            fresh_sessions: false,
            sessions_opened: Arc::new(AtomicU64::new(0)),
            deleted: Arc::new(Mutex::new(Vec::new())),
            failing_tools: Vec::new(),
            listen: false,
            replay: Vec::new(),
            last_event_ids: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Serve a `GET` listen stream (one `notifications/message` event, then open until the
    /// client leaves) instead of answering `GET` with `405`.
    pub fn with_listen_stream(mut self, on: bool) -> Self {
        self.listen = on;
        self
    }

    /// Serve a `GET` listen stream and replay `messages` (one SSE event each, with ids `1`,
    /// `2`, ...) at the start of every one that resumes with `Last-Event-ID`, as a server does
    /// with the buffered events of a stream that broke off.
    pub fn with_replay(mut self, messages: Vec<Value>) -> Self {
        self.listen = true;
        self.replay = messages;
        self
    }

    /// The `Last-Event-ID` of every resumed `GET`, in order.
    pub fn last_event_ids(&self) -> Vec<String> {
        self.last_event_ids
            .lock()
            .expect("last-event-id mutex")
            .clone()
    }

    /// Give tool `name` these MCP `annotations` in `tools/list` (for example
    /// `{"readOnlyHint": true}`).
    pub fn with_tool_annotations(mut self, name: &str, annotations: Value) -> Self {
        for t in &mut self.tools {
            if t["name"] == name {
                t["annotations"] = annotations.clone();
            }
        }
        self
    }

    /// Answer `tools/call` for `name` with a JSON-RPC error (`-32000`, "tool failed").
    pub fn with_failing_tool(mut self, name: &str) -> Self {
        self.failing_tools.push(name.to_owned());
        self
    }

    /// Open a new session on every `initialize` (`{session_id}-1`, `{session_id}-2`, ...), and
    /// send no session id on other responses, as a real server does.
    pub fn with_fresh_session_ids(mut self, on: bool) -> Self {
        self.fresh_sessions = on;
        self
    }

    /// Sessions opened so far with [`with_fresh_session_ids`](Self::with_fresh_session_ids).
    pub fn sessions_opened(&self) -> u64 {
        self.sessions_opened.load(Ordering::SeqCst)
    }

    /// The `Mcp-Session-Id` of every `DELETE` received so far, in order.
    pub fn deleted_sessions(&self) -> Vec<String> {
        self.deleted.lock().expect("deleted mutex").clone()
    }

    /// Resolve `tools/call` names case-insensitively against the tool list (`Delete_Repo` runs
    /// `delete_repo`), the way some servers do. The recorded call carries the resolved name.
    pub fn with_case_insensitive_names(mut self, on: bool) -> Self {
        self.case_insensitive_names = on;
        self
    }

    /// Resources returned by `resources/list`, one per URI.
    pub fn with_resources(mut self, uris: &[&str]) -> Self {
        self.resources = uris
            .iter()
            .map(|u| json!({"uri": u, "name": format!("fake resource {u}")}))
            .collect();
        self
    }

    /// Resource templates returned by `resources/templates/list`, one per URI template.
    pub fn with_resource_templates(mut self, templates: &[&str]) -> Self {
        self.resource_templates = templates
            .iter()
            .map(|t| json!({"uriTemplate": t, "name": format!("fake template {t}")}))
            .collect();
        self
    }

    /// Prompts returned by `prompts/list`, one per name.
    pub fn with_prompts(mut self, names: &[&str]) -> Self {
        self.prompts = names
            .iter()
            .map(|n| json!({"name": n, "description": format!("fake prompt {n}")}))
            .collect();
        self
    }

    /// Paginate `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list`
    /// with this many entries per page. The cursor is the index of the next entry as a string;
    /// the last page has no `nextCursor`.
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = Some(size.max(1));
        self
    }

    /// With SSE on: answer a batch with one event per response, after a
    /// `notifications/message` event, instead of one event holding the whole batch.
    pub fn with_sse_event_per_response(mut self, on: bool) -> Self {
        self.sse_event_per_response = on;
        self
    }

    /// Answer every request over SSE (`text/event-stream`) instead of JSON.
    pub fn with_sse(mut self, sse: bool) -> Self {
        self.sse = sse;
        self
    }

    pub fn with_session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = id.into();
        self
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Every `tools/call` received so far, in order.
    pub fn recorded_calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("calls mutex").clone()
    }

    /// The method of every JSON-RPC message received so far (requests and notifications), in
    /// order. Lets a test assert that a denied request never reached the upstream.
    pub fn recorded_methods(&self) -> Vec<String> {
        self.methods.lock().expect("methods mutex").clone()
    }

    pub fn router(&self) -> Router {
        let routes = post(fake_handle).delete(fake_delete);
        let routes = if self.listen {
            routes.get(fake_listen)
        } else {
            routes
        };
        Router::new().route("/mcp", routes).with_state(self.clone())
    }

    pub async fn spawn(&self) -> anyhow::Result<Spawned> {
        spawn_router(self.router()).await
    }

    fn page(&self, key: &str, entries: &[Value], msg: &Value) -> Value {
        let Some(size) = self.page_size else {
            return json!({ key: entries });
        };
        let start = msg["params"]["cursor"]
            .as_str()
            .and_then(|c| c.parse::<usize>().ok())
            .unwrap_or(0)
            .min(entries.len());
        let end = (start + size).min(entries.len());
        let mut result = json!({ key: &entries[start..end] });
        if end < entries.len() {
            result["nextCursor"] = json!(end.to_string());
        }
        result
    }

    fn respond_one(&self, msg: &Value, session_id: Option<&str>) -> Option<Value> {
        let id = id_of(msg);
        let method = method_of(msg)?;
        self.methods
            .lock()
            .expect("methods mutex")
            .push(method.to_owned());
        if !is_request(msg) {
            // notification: no response
            return None;
        }
        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-mcp", "version": "0.0.0"}
            }),
            "tools/list" => self.page("tools", &self.tools, msg),
            "resources/list" => self.page("resources", &self.resources, msg),
            "resources/templates/list" => {
                self.page("resourceTemplates", &self.resource_templates, msg)
            }
            "prompts/list" => self.page("prompts", &self.prompts, msg),
            "tools/call" => {
                let mut name = msg["params"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if self.case_insensitive_names {
                    if let Some(listed) = self
                        .tools
                        .iter()
                        .filter_map(|t| t["name"].as_str())
                        .find(|t| t.eq_ignore_ascii_case(&name))
                    {
                        name = listed.to_owned();
                    }
                }
                let arguments = msg["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                self.calls.lock().expect("calls mutex").push(RecordedCall {
                    name: name.clone(),
                    arguments: arguments.clone(),
                    session_id: session_id.map(str::to_owned),
                    params: msg["params"].clone(),
                });
                if self.failing_tools.contains(&name) {
                    return Some(error_response(id, -32000, "tool failed", None));
                }
                json!({
                    "content": [{
                        "type": "text",
                        "text": json!({"name": name, "arguments": arguments}).to_string()
                    }],
                    "isError": false
                })
            }
            "ping" => json!({}),
            "resources/read" => json!({
                "contents": [{"uri": msg["params"]["uri"], "text": "fake resource"}]
            }),
            "resources/subscribe" | "resources/unsubscribe" => json!({}),
            "prompts/get" => json!({
                "messages": [{"role": "user", "content": {"type": "text", "text": "fake prompt"}}]
            }),
            "completion/complete" => json!({"completion": {"values": ["a"]}}),
            other => {
                return Some(error_response(
                    id,
                    -32601,
                    format!("method not found: {other}"),
                    None,
                ))
            }
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }
}

async fn fake_handle(
    axum::extract::State(server): axum::extract::State<FakeMcpServer>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                error_response(Value::Null, -32700, e.to_string(), None).to_string(),
            )
                .into_response()
        }
    };
    let reply = match &parsed {
        Value::Array(items) => {
            let replies: Vec<Value> = items
                .iter()
                .filter_map(|m| server.respond_one(m, session_id.as_deref()))
                .collect();
            if replies.is_empty() {
                None
            } else {
                Some(Value::Array(replies))
            }
        }
        Value::Object(_) => server.respond_one(&parsed, session_id.as_deref()),
        _ => Some(error_response(
            Value::Null,
            CODE_INVALID_REQUEST,
            "invalid request",
            None,
        )),
    };
    let mut response = match reply {
        None => StatusCode::ACCEPTED.into_response(),
        Some(v) if server.sse => {
            let body = if server.sse_event_per_response {
                // A streaming server: a progress-style notification first, then one event
                // (with an `id:` field) per response.
                let mut body = format!(
                    "event: message\ndata: {}\n\n",
                    json!({"jsonrpc": "2.0", "method": "notifications/message",
                           "params": {"level": "info", "data": "working"}})
                );
                let items = match &v {
                    Value::Array(items) => items.clone(),
                    other => vec![other.clone()],
                };
                for (n, item) in items.iter().enumerate() {
                    body.push_str(&format!("id: {n}\nevent: message\ndata: {item}\n\n"));
                }
                body
            } else {
                format!("event: message\ndata: {v}\n\n")
            };
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/event-stream")],
                body,
            )
                .into_response()
        }
        Some(v) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            v.to_string(),
        )
            .into_response(),
    };
    let assigned = if !server.fresh_sessions {
        Some(server.session_id.clone())
    } else if method_of(&parsed) == Some("initialize") {
        let n = server.sessions_opened.fetch_add(1, Ordering::SeqCst) + 1;
        Some(format!("{}-{n}", server.session_id))
    } else {
        None
    };
    if let Some(sid) = assigned.and_then(|s| HeaderValue::from_str(&s).ok()) {
        response.headers_mut().insert("mcp-session-id", sid);
    }
    response
}

async fn fake_listen(
    axum::extract::State(server): axum::extract::State<FakeMcpServer>,
    headers: HeaderMap,
) -> Response {
    let resumed = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut events = vec![format!(
        "event: message\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "method": "notifications/message",
               "params": {"level": "info", "data": "listening"}})
    )];
    if let Some(id) = resumed {
        server
            .last_event_ids
            .lock()
            .expect("last-event-id mutex")
            .push(id);
        for (n, msg) in server.replay.iter().enumerate() {
            events.push(format!("id: {}\nevent: message\ndata: {msg}\n\n", n + 1));
        }
    }
    let open = futures_util::stream::iter(
        events
            .into_iter()
            .map(|e| Ok::<_, std::io::Error>(Bytes::from(e))),
    )
    .chain(futures_util::stream::pending());
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/event-stream")],
        axum::body::Body::from_stream(open),
    )
        .into_response()
}

async fn fake_delete(
    axum::extract::State(server): axum::extract::State<FakeMcpServer>,
    headers: HeaderMap,
) -> StatusCode {
    let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) else {
        return StatusCode::BAD_REQUEST;
    };
    server
        .deleted
        .lock()
        .expect("deleted mutex")
        .push(sid.to_owned());
    StatusCode::OK
}

// ---------------------------------------------------------------------------------------------
// StaticAuthorizer
// ---------------------------------------------------------------------------------------------

/// One `observe_tool_hints` report: server, tool, `readOnlyHint`, `destructiveHint`.
pub type ObservedHints = (String, String, Option<bool>, Option<bool>);

/// Maps bearer strings to pre-built chains and decides purely from
/// `chain.effective_capabilities().permits(call)`. Every decision is recorded.
///
/// Without [`with_catalog`](Self::with_catalog) every tool counts as catalogued
/// ([`Authorizer::knows_tool`] is always true), so the proxy's `require_listed_tools` check
/// never refuses anything; with a catalog, only the listed `(server, tool)` pairs are known.
///
/// Results the proxy reports ([`Authorizer::record_result`]) are kept
/// ([`recorded_results`](Self::recorded_results)) and can be made to fail
/// ([`fail_results`](Self::fail_results)); tool annotations are kept too
/// ([`observed_hints`](Self::observed_hints)), and so are new sessions
/// ([`recorded_sessions`](Self::recorded_sessions)), the ends of listen streams
/// ([`stream_ends`](Self::stream_ends)) and suppressed records
/// ([`suppressed_records`](Self::suppressed_records)).
#[derive(Default)]
pub struct StaticAuthorizer {
    chains: HashMap<String, DelegationChain>,
    /// Bearer -> the lease reason `check_active` gives for it.
    revoked: Arc<Mutex<HashMap<String, &'static str>>>,
    stream_ends: Arc<Mutex<Vec<crate::guard::StreamEndCause>>>,
    suppressed: Arc<Mutex<Vec<(String, crate::guard::StreamEndCause)>>>,
    decisions: Arc<Mutex<Vec<DecisionRecord>>>,
    catalog: Option<std::collections::HashSet<(String, String)>>,
    results: Arc<Mutex<Vec<RecordedResult>>>,
    fail_results: Arc<std::sync::atomic::AtomicBool>,
    hints: Arc<Mutex<Vec<ObservedHints>>>,
    ask_for: std::collections::HashSet<String>,
    contexts: Arc<Mutex<Vec<crate::auth::CallContext>>>,
    sessions: Arc<Mutex<Vec<RecordedSession>>>,
}

/// A session reported through [`Authorizer::record_session`] to a [`StaticAuthorizer`]:
/// the root lease of the chain, the server and the session digest.
pub type RecordedSession = (attenuo_core::LeaseId, String, String);

/// A result reported through [`Authorizer::record_result`] to a [`StaticAuthorizer`].
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedResult {
    pub call: ToolCall,
    pub decision_id: uuid::Uuid,
    pub result: Value,
    pub is_error: bool,
}

impl StaticAuthorizer {
    pub const REASON_ALLOW: &'static str = "capability_allow";
    pub const REASON_DENY: &'static str = "capability_denied";

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_chain(mut self, bearer: impl Into<String>, chain: DelegationChain) -> Self {
        self.chains.insert(bearer.into(), chain);
        self
    }

    /// Know only these `(server, tool)` pairs ([`Authorizer::knows_tool`]).
    pub fn with_catalog<'a>(mut self, tools: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        self.catalog = Some(
            tools
                .into_iter()
                .map(|(s, t)| (s.to_owned(), t.to_owned()))
                .collect(),
        );
        self
    }

    pub fn insert(&mut self, bearer: impl Into<String>, chain: DelegationChain) {
        self.chains.insert(bearer.into(), chain);
    }

    /// Mark a bearer's lease revoked: `check_active` fails for it from now on, and so does
    /// `authorize` (reason `lease_revoked`), like the real pipeline.
    pub fn revoke(&self, bearer: &str) {
        self.lapse(bearer, "lease_revoked");
    }

    /// Mark a bearer's lease expired: like [`revoke`](Self::revoke), with reason
    /// `lease_expired`.
    pub fn expire_lease(&self, bearer: &str) {
        self.lapse(bearer, "lease_expired");
    }

    fn lapse(&self, bearer: &str, reason: &'static str) {
        self.revoked
            .lock()
            .expect("revoked mutex")
            .insert(bearer.to_owned(), reason);
    }

    /// The lease reason of `chain`, when a bearer of it was revoked or expired.
    fn lapsed(&self, chain: &DelegationChain) -> Option<&'static str> {
        let revoked = self.revoked.lock().expect("revoked mutex");
        self.chains
            .iter()
            .filter(|(_, c)| *c == chain)
            .find_map(|(bearer, _)| revoked.get(bearer).copied())
    }

    /// Every listen-stream end reported through [`Authorizer::observe_stream_end`], in order.
    pub fn stream_ends(&self) -> Vec<crate::guard::StreamEndCause> {
        self.stream_ends.lock().expect("stream ends mutex").clone()
    }

    /// Every suppressed record reported through [`Authorizer::observe_record_suppressed`],
    /// as `(tool, reason)`, in order.
    pub fn suppressed_records(&self) -> Vec<(String, crate::guard::StreamEndCause)> {
        self.suppressed.lock().expect("suppressed mutex").clone()
    }

    /// Every decision recorded so far, in order.
    pub fn decisions(&self) -> Vec<DecisionRecord> {
        self.decisions.lock().expect("decisions mutex").clone()
    }

    /// Deny calls to `tool` (any server) that the capabilities permit with reason
    /// `approval_required`, as an `@obligation("approval")` forbid would. The decision carries
    /// an approval ticket whose id is the decision id and which expires 120 s later.
    pub fn with_approval_required(mut self, tool: &str) -> Self {
        self.ask_for.insert(tool.to_owned());
        self
    }

    /// The [`CallContext`](crate::auth::CallContext) of every decision made through
    /// [`Authorizer::authorize_with`], in order.
    pub fn contexts(&self) -> Vec<crate::auth::CallContext> {
        self.contexts.lock().expect("contexts mutex").clone()
    }

    /// Every result reported through [`Authorizer::record_result`], in order (failed ones
    /// included).
    pub fn recorded_results(&self) -> Vec<RecordedResult> {
        self.results.lock().expect("results mutex").clone()
    }

    /// Make [`Authorizer::record_result`] fail with `label_error` (or succeed again).
    pub fn fail_results(&self, fail: bool) {
        self.fail_results
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Every session reported through [`Authorizer::record_session`], in order.
    pub fn recorded_sessions(&self) -> Vec<RecordedSession> {
        self.sessions.lock().expect("sessions mutex").clone()
    }

    /// Every tool annotation reported through [`Authorizer::observe_tool_hints`], as
    /// `(server, tool, readOnlyHint, destructiveHint)`.
    pub fn observed_hints(&self) -> Vec<ObservedHints> {
        self.hints.lock().expect("hints mutex").clone()
    }
}

#[async_trait]
impl Authorizer for StaticAuthorizer {
    async fn authenticate(
        &self,
        bearer: &str,
        now: OffsetDateTime,
    ) -> Result<DelegationChain, AuthError> {
        let chain = self
            .chains
            .get(bearer)
            .ok_or_else(|| AuthError::InvalidToken("unknown token".into()))?;
        chain
            .validate_at(now, attenuo_core::chain::DEFAULT_MAX_DEPTH)
            .map_err(|e| match e {
                attenuo_core::ChainError::HopExpired { .. } => AuthError::TokenExpired,
                other => AuthError::InvalidToken(other.to_string()),
            })?;
        Ok(chain.clone())
    }

    async fn check_active(
        &self,
        chain: &DelegationChain,
        _now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        if let Some(reason) = self.lapsed(chain) {
            Err(AuthError::LeaseInactive(reason.into()))
        } else {
            Ok(())
        }
    }

    async fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        now: OffsetDateTime,
    ) -> AuthDecision {
        let lapsed = self.lapsed(chain);
        let revoked = lapsed.is_some();
        let allowed = !revoked
            && chain
                .effective_capabilities()
                .map(|caps| caps.permits(call))
                .unwrap_or(false);
        let (decision, reason) = if allowed && self.ask_for.contains(&call.tool) {
            (
                attenuo_core::Decision::Deny,
                crate::auth::REASON_APPROVAL_REQUIRED,
            )
        } else if allowed {
            (attenuo_core::Decision::Allow, Self::REASON_ALLOW)
        } else if let Some(reason) = lapsed {
            (attenuo_core::Decision::Deny, reason)
        } else {
            (attenuo_core::Decision::Deny, Self::REASON_DENY)
        };
        let record = DecisionRecord::new(now, decision.clone(), reason, chain, call, vec![]);
        let id = record.id;
        self.decisions.lock().expect("decisions mutex").push(record);
        // An approval ticket for `approval_required`, as the server would store one: the
        // approval id is the decision id here, so tests can predict it.
        let approval = (reason == crate::auth::REASON_APPROVAL_REQUIRED).then(|| {
            crate::auth::ApprovalTicket {
                approval_id: id,
                expires_at: now + time::Duration::seconds(120),
            }
        });
        AuthDecision {
            decision,
            reason: reason.into(),
            decision_id: id,
            approval,
            limit: None,
            untrusted_args: None,
            usage: None,
        }
    }

    async fn authorize_with(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        ctx: &crate::auth::CallContext,
        now: OffsetDateTime,
    ) -> AuthDecision {
        self.contexts
            .lock()
            .expect("contexts mutex")
            .push(ctx.clone());
        self.authorize(chain, call, now).await
    }

    fn knows_tool(&self, server: &str, tool: &str) -> bool {
        self.catalog
            .as_ref()
            .is_none_or(|c| c.contains(&(server.to_owned(), tool.to_owned())))
    }

    async fn record_rejection(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        reason: &str,
        now: OffsetDateTime,
    ) -> uuid::Uuid {
        let record = DecisionRecord::new(
            now,
            attenuo_core::Decision::Deny,
            reason,
            chain,
            call,
            vec![],
        );
        let id = record.id;
        self.decisions.lock().expect("decisions mutex").push(record);
        id
    }

    async fn record_session(
        &self,
        chain: &DelegationChain,
        server: &str,
        session_digest: &str,
        _now: OffsetDateTime,
    ) {
        let root = chain
            .hops
            .first()
            .map_or_else(|| attenuo_core::LeaseId::new(""), |h| h.lease.clone());
        self.sessions.lock().expect("sessions mutex").push((
            root,
            server.to_owned(),
            session_digest.to_owned(),
        ));
    }

    async fn record_result(
        &self,
        _chain: &DelegationChain,
        call: &ToolCall,
        decision_id: uuid::Uuid,
        result: &Value,
        is_error: bool,
        _now: OffsetDateTime,
    ) -> Result<(), String> {
        self.results
            .lock()
            .expect("results mutex")
            .push(RecordedResult {
                call: call.clone(),
                decision_id,
                result: result.clone(),
                is_error,
            });
        if self.fail_results.load(std::sync::atomic::Ordering::SeqCst) {
            Err(crate::auth::REASON_LABEL_ERROR.to_owned())
        } else {
            Ok(())
        }
    }

    fn observe_tool_hints(
        &self,
        server: &str,
        tool: &str,
        read_only_hint: Option<bool>,
        destructive_hint: Option<bool>,
    ) {
        self.hints.lock().expect("hints mutex").push((
            server.to_owned(),
            tool.to_owned(),
            read_only_hint,
            destructive_hint,
        ));
    }

    fn observe_stream_end(&self, cause: crate::guard::StreamEndCause) {
        self.stream_ends
            .lock()
            .expect("stream ends mutex")
            .push(cause);
    }

    fn observe_record_suppressed(&self, tool: &'static str, reason: crate::guard::StreamEndCause) {
        self.suppressed
            .lock()
            .expect("suppressed mutex")
            .push((tool.to_owned(), reason));
    }
}

// ---------------------------------------------------------------------------------------------
// Chain builders
// ---------------------------------------------------------------------------------------------

pub fn test_user(subject: &str) -> OriginatingUser {
    OriginatingUser {
        subject: subject.into(),
        issuer: "https://idp.test".into(),
        authenticated_at: OffsetDateTime::now_utc(),
        attributes: BTreeMap::new(),
    }
}

/// A single-hop chain for `agent` on behalf of `subject`, valid for one hour from now.
pub fn test_chain(
    subject: &str,
    agent: &str,
    caps: impl IntoIterator<Item = Capability>,
) -> DelegationChain {
    DelegationChain::root(
        test_user(subject),
        AgentId::new(agent),
        CapabilitySet::from_iter(caps),
        OffsetDateTime::now_utc(),
        Duration::hours(1),
        LeaseId::new(format!("lease-{agent}")),
    )
    .expect("valid test chain")
}

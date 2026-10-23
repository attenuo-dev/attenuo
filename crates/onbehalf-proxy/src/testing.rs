//! Test doubles: a fake MCP server and a static authorizer.
//!
//! Available in this crate's tests and, behind the `testing` feature, to other crates.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use onbehalf_core::{
    AgentId, Capability, CapabilitySet, DecisionRecord, DelegationChain, LeaseId, OriginatingUser,
    ToolCall,
};
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
}

/// A minimal Streamable HTTP MCP server: `initialize`, `tools/list`, `tools/call`,
/// `resources/list`, `resources/templates/list`, `prompts/list` (all optionally paginated),
/// notifications, batches. Mounted at `POST /mcp`.
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
        }
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
        Router::new()
            .route("/mcp", post(fake_handle))
            .with_state(self.clone())
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
                });
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
            "resources/subscribe" => json!({}),
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
    if let Ok(sid) = HeaderValue::from_str(&server.session_id) {
        response.headers_mut().insert("mcp-session-id", sid);
    }
    response
}

// ---------------------------------------------------------------------------------------------
// StaticAuthorizer
// ---------------------------------------------------------------------------------------------

/// Maps bearer strings to pre-built chains and decides purely from
/// `chain.effective_capabilities().permits(call)`. Every decision is recorded.
///
/// Without [`with_catalog`](Self::with_catalog) every tool counts as catalogued
/// ([`Authorizer::knows_tool`] is always true), so the proxy's `require_listed_tools` check
/// never refuses anything; with a catalog, only the listed `(server, tool)` pairs are known.
#[derive(Default)]
pub struct StaticAuthorizer {
    chains: HashMap<String, DelegationChain>,
    revoked: Arc<Mutex<std::collections::HashSet<String>>>,
    decisions: Arc<Mutex<Vec<DecisionRecord>>>,
    catalog: Option<std::collections::HashSet<(String, String)>>,
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
        self.revoked
            .lock()
            .expect("revoked mutex")
            .insert(bearer.to_owned());
    }

    fn is_revoked(&self, chain: &DelegationChain) -> bool {
        let revoked = self.revoked.lock().expect("revoked mutex");
        self.chains
            .iter()
            .any(|(bearer, c)| c == chain && revoked.contains(bearer))
    }

    /// Every decision recorded so far, in order.
    pub fn decisions(&self) -> Vec<DecisionRecord> {
        self.decisions.lock().expect("decisions mutex").clone()
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
            .validate_at(now, onbehalf_core::chain::DEFAULT_MAX_DEPTH)
            .map_err(|e| match e {
                onbehalf_core::ChainError::HopExpired { .. } => AuthError::TokenExpired,
                other => AuthError::InvalidToken(other.to_string()),
            })?;
        Ok(chain.clone())
    }

    async fn check_active(
        &self,
        chain: &DelegationChain,
        _now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        if self.is_revoked(chain) {
            Err(AuthError::LeaseInactive("lease_revoked".into()))
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
        let revoked = self.is_revoked(chain);
        let allowed = !revoked
            && chain
                .effective_capabilities()
                .map(|caps| caps.permits(call))
                .unwrap_or(false);
        let (decision, reason) = if allowed {
            (onbehalf_core::Decision::Allow, Self::REASON_ALLOW)
        } else if revoked {
            (onbehalf_core::Decision::Deny, "lease_revoked")
        } else {
            (onbehalf_core::Decision::Deny, Self::REASON_DENY)
        };
        let record = DecisionRecord::new(now, decision.clone(), reason, chain, call, vec![]);
        let id = record.id;
        self.decisions.lock().expect("decisions mutex").push(record);
        AuthDecision {
            decision,
            reason: reason.into(),
            decision_id: id,
        }
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
            onbehalf_core::Decision::Deny,
            reason,
            chain,
            call,
            vec![],
        );
        let id = record.id;
        self.decisions.lock().expect("decisions mutex").push(record);
        id
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

//! The MCP proxy's request path, end to end through `attenuo_proxy::router`: JSON-RPC body
//! parsing (single messages and batches, non-object `params.arguments` (SR-07), ids of every
//! JSON type), the `Mcp-Session-Id` checks (SR-27), the request body limit (SR-36), and the
//! rewriting of the upstream's answer (JSON or SSE, list filtering).
//!
//! The upstream is a small in-process HTTP server driven by the input: it either echoes a
//! well-formed answer to every request (optionally normalizing numeric ids the way a
//! JavaScript server does) or returns arbitrary bytes. It records every message it receives.
//!
//! Invariants:
//! - nothing reaches the upstream that the chain's capabilities do not permit, judged on the
//!   bytes the upstream actually received;
//! - an oversized body is refused with 413, a malformed `Mcp-Session-Id` with 400;
//! - a `tools/list` answer never reaches the client with a tool the chain cannot call.
#![no_main]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use arbitrary::{Arbitrary, Result, Unstructured};
use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use libfuzzer_sys::fuzz_target;
use attenuo_core::{
    AgentId, ArgConstraint, Capability, CapabilitySet, Decision, DelegationChain, LeaseId,
    OriginatingUser, ToolCall,
};
use attenuo_fuzz::{edge_number, edge_string, json_value};
use attenuo_proxy::jsonrpc::is_passthrough_method;
use attenuo_proxy::{AuthDecision, AuthError, Authorizer, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tower::ServiceExt;

const SERVER: &str = "fuzz";
const TOKEN: &str = "good-token";
const MAX_BODY: usize = 64 * 1024;

fn caps() -> CapabilitySet {
    CapabilitySet::from_iter([
        Capability::new(SERVER, "read_*"),
        Capability::new(SERVER, "create_issue")
            .with_constraint("repo", ArgConstraint::Prefix("acme/".into())),
        Capability::new(SERVER, "completion/complete")
            .with_constraint("ref", ArgConstraint::Equals(json!("ok"))),
        Capability::new(SERVER, "resources/read")
            .with_constraint("uri", ArgConstraint::Prefix("file:///pub/".into())),
    ])
}

fn chain() -> DelegationChain {
    let now = OffsetDateTime::now_utc();
    DelegationChain::root(
        OriginatingUser {
            subject: "user:mudit".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: now,
            attributes: Default::default(),
        },
        AgentId::new("agent:planner"),
        caps(),
        now,
        time::Duration::days(3650),
        LeaseId::new("lease-1"),
    )
    .unwrap()
}

struct FuzzAuth {
    chain: DelegationChain,
}

#[async_trait]
impl Authorizer for FuzzAuth {
    async fn authenticate(
        &self,
        bearer: &str,
        _now: OffsetDateTime,
    ) -> std::result::Result<DelegationChain, AuthError> {
        if bearer == TOKEN {
            Ok(self.chain.clone())
        } else {
            Err(AuthError::InvalidToken("unknown".into()))
        }
    }
    async fn check_active(
        &self,
        _chain: &DelegationChain,
        _now: OffsetDateTime,
    ) -> std::result::Result<(), AuthError> {
        Ok(())
    }
    async fn authorize(
        &self,
        chain: &DelegationChain,
        call: &ToolCall,
        _now: OffsetDateTime,
    ) -> AuthDecision {
        let id = uuid::Uuid::nil();
        if chain
            .effective_capabilities()
            .is_some_and(|c| c.permits(call))
        {
            AuthDecision::allow("capability_allow", id)
        } else {
            AuthDecision {
                decision: Decision::Deny,
                reason: "capability_denied".into(),
                decision_id: id,
                approval: None,
            }
        }
    }
    fn knows_tool(&self, server: &str, tool: &str) -> bool {
        server == SERVER && tool == "read_catalogued"
    }
}

/// What the upstream does with the next request.
#[derive(Debug, Clone)]
enum Upstream {
    /// Answer every request; ids normalized like JavaScript when `js_ids`; as SSE when `sse`.
    Echo {
        js_ids: bool,
        sse: bool,
        per_event: bool,
        session: Option<String>,
    },
    /// Return these bytes.
    Raw {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
}

struct Shared {
    next: Upstream,
    /// Messages the upstream received that the chain does not permit.
    violations: Vec<String>,
}

fn shared() -> &'static Mutex<Shared> {
    static S: OnceLock<Mutex<Shared>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Shared {
            next: Upstream::Raw {
                status: 200,
                content_type: "application/json".into(),
                body: b"{}".to_vec(),
            },
            violations: Vec::new(),
        })
    })
}

/// JavaScript's `JSON.parse` then `JSON.stringify` of a number.
fn js_number(v: &Value) -> Value {
    match v.as_f64() {
        // JavaScript prints an integral double below 1e21 in full ("18446744073709552000");
        // parsing that back gives an integer when it fits and a double otherwise.
        Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => {
            serde_json::from_str(&format!("{f:.0}")).unwrap_or_else(|_| json!(f))
        }
        Some(f) => json!(f),
        None => v.clone(),
    }
}

/// What the proxy derives as the call for a message it authorizes (see `screen_message`).
fn call_of(msg: &Value, method: &str) -> ToolCall {
    let params = msg.get("params");
    let s = |k: &str| params.and_then(|p| p.get(k)).and_then(Value::as_str);
    match method {
        "tools/call" => ToolCall::new(
            SERVER,
            s("name").unwrap_or(""),
            params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(json!({})),
        ),
        "resources/read" | "resources/subscribe" => {
            ToolCall::new(SERVER, method, json!({"uri": s("uri")}))
        }
        "prompts/get" => ToolCall::new(
            SERVER,
            method,
            json!({"name": s("name"), "arguments": params.and_then(|p| p.get("arguments"))}),
        ),
        _ => ToolCall::new(SERVER, method, params.cloned().unwrap_or(json!({}))),
    }
}

fn check_received(msg: &Value, out: &mut Vec<String>) {
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return;
    };
    if is_passthrough_method(method) {
        return;
    }
    if method == "tools/call" {
        let args = msg.get("params").and_then(|p| p.get("arguments"));
        if !matches!(args, None | Some(Value::Null) | Some(Value::Object(_))) {
            out.push(format!("SR-07: non-object arguments forwarded: {msg}"));
        }
    }
    if !caps().permits(&call_of(msg, method)) {
        out.push(format!("unpermitted message forwarded: {msg}"));
    }
}

fn listed_tools() -> Value {
    json!({"tools": [
        {"name": "read_file", "inputSchema": {"type": "object"}},
        {"name": "delete_repo", "inputSchema": {"type": "object"}},
    ]})
}

async fn upstream(headers: HeaderMap, body: Bytes) -> Response {
    let _ = headers;
    let parsed: Option<Value> = serde_json::from_slice(&body).ok();
    let mut sh = shared().lock().unwrap();
    let msgs: Vec<Value> = match &parsed {
        Some(Value::Array(a)) => a.clone(),
        Some(v) => vec![v.clone()],
        None => vec![],
    };
    let mut v = Vec::new();
    for m in &msgs {
        check_received(m, &mut v);
    }
    sh.violations.extend(v);
    match sh.next.clone() {
        Upstream::Raw {
            status,
            content_type,
            body,
        } => {
            let mut r =
                (StatusCode::from_u16(status).unwrap_or(StatusCode::OK), body).into_response();
            if let Ok(ct) = HeaderValue::from_str(&content_type) {
                r.headers_mut().insert("content-type", ct);
            }
            r
        }
        Upstream::Echo {
            js_ids,
            sse,
            per_event,
            session,
        } => {
            let replies: Vec<Value> = msgs
                .iter()
                .filter(|m| m.get("method").is_some() && m.get("id").is_some_and(|i| !i.is_null()))
                .map(|m| {
                    let id = if js_ids {
                        js_number(&m["id"])
                    } else {
                        m["id"].clone()
                    };
                    let result = match m["method"].as_str() {
                        Some("tools/list") => listed_tools(),
                        _ => json!({}),
                    };
                    json!({"jsonrpc": "2.0", "id": id, "result": result})
                })
                .collect();
            if replies.is_empty() {
                return StatusCode::ACCEPTED.into_response();
            }
            let batch = matches!(parsed, Some(Value::Array(_)));
            let whole = if batch {
                Value::Array(replies.clone())
            } else {
                replies[0].clone()
            };
            let mut r = if sse {
                let mut text = String::new();
                if per_event {
                    text.push_str("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n");
                    for rep in &replies {
                        text.push_str(&format!("data: {rep}\n\n"));
                    }
                } else {
                    text.push_str(&format!("data: {whole}\n\n"));
                }
                let mut r = text.into_response();
                r.headers_mut().insert(
                    "content-type",
                    HeaderValue::from_static("text/event-stream"),
                );
                r
            } else {
                axum::Json(whole).into_response()
            };
            if let Some(s) = session.and_then(|s| HeaderValue::from_str(&s).ok()) {
                r.headers_mut().insert("mcp-session-id", s);
            }
            r
        }
    }
}

struct World {
    rt: tokio::runtime::Runtime,
    routers: Vec<Router>,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let addr: SocketAddr = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = Router::new().route("/mcp", axum::routing::post(upstream));
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            addr
        });
        let auth: Arc<dyn Authorizer> = Arc::new(FuzzAuth { chain: chain() });
        let routers = [false, true]
            .into_iter()
            .map(|require_listed| {
                let config = ProxyConfig {
                    upstreams: vec![UpstreamConfig::new(SERVER, format!("http://{addr}/mcp"))],
                    listen: "127.0.0.1:0".parse().unwrap(),
                    stream_recheck: std::time::Duration::from_secs(60),
                    require_listed_tools: require_listed,
                    max_upstream_body_bytes: 1024 * 1024,
                    max_request_body_bytes: MAX_BODY,
                    session_ttl: std::time::Duration::from_secs(60),
                    max_sessions: 64,
                    max_sessions_per_principal: 64,
                };
                attenuo_proxy::router(config, auth.clone())
            })
            .collect();
        World { rt, routers }
    })
}

const METHODS: &[&str] = &[
    "tools/call",
    "tools/call",
    "tools/list",
    "resources/read",
    "resources/list",
    "prompts/get",
    "completion/complete",
    "initialize",
    "ping",
    "notifications/initialized",
    "read_anything",
    "logging/setLevel",
];
const TOOLS: &[&str] = &[
    "read_file",
    "read_catalogued",
    "create_issue",
    "delete_repo",
    "Read_file",
    "read file",
    "read_file\u{0}",
    "resources/read",
];

fn id(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => json!(1),
        1 => json!(1.0),
        2 => json!("1"),
        3 => Value::Null,
        4 => json!(9_007_199_254_740_993u64),
        5 => json!(-0.0),
        6 => edge_number(u)?,
        _ => json_value(u, 1)?,
    })
}

fn message(u: &mut Unstructured<'_>) -> Result<Value> {
    let method = if u.ratio(1u8, 8u8)? {
        json_value(u, 1)?
    } else {
        json!(*u.choose(METHODS)?)
    };
    let mut m = serde_json::Map::new();
    m.insert("jsonrpc".into(), json!("2.0"));
    if u.ratio(7u8, 8u8)? {
        m.insert("method".into(), method);
    }
    if u.ratio(4u8, 5u8)? {
        m.insert("id".into(), id(u)?);
    }
    let params = match u.int_in_range(0u8..=4)? {
        0 => json_value(u, 3)?,
        1 => Value::Null,
        _ => {
            let name = if u.ratio(1u8, 6u8)? {
                Value::String(edge_string(u)?)
            } else {
                json!(*u.choose(TOOLS)?)
            };
            let args = match u.int_in_range(0u8..=5)? {
                0 => json!({"repo": "acme/x"}),
                1 => json!({"repo": "evil/x"}),
                2 => json!(["acme/x"]),
                3 => json!("acme/x"),
                4 => Value::Null,
                _ => json_value(u, 3)?,
            };
            json!({
                "name": name,
                "arguments": args,
                "uri": *u.choose(&["file:///pub/a", "file:///etc/passwd", ""])?,
                "ref": *u.choose(&["ok", "no"])?,
            })
        }
    };
    if u.ratio(9u8, 10u8)? {
        m.insert("params".into(), params);
    }
    if u.ratio(1u8, 10u8)? {
        m.insert("result".into(), listed_tools());
    }
    Ok(Value::Object(m))
}

#[derive(Debug)]
struct Input {
    router: usize,
    body: Vec<u8>,
    auth: Option<String>,
    sessions: Vec<Vec<u8>>,
    content_length: Option<String>,
    upstream: Upstream,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let body = match u.int_in_range(0u8..=5)? {
            0 => u.arbitrary::<Vec<u8>>()?,
            1 => {
                let n = u.int_in_range(0usize..=8)?;
                let msgs = (0..n).map(|_| message(u)).collect::<Result<Vec<_>>>()?;
                serde_json::to_vec(&msgs).unwrap()
            }
            2 => {
                // Duplicate member names: only the last `method` counts.
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_repo"},"method":"ping"}"#
                    .to_vec()
            }
            3 => vec![b' '; MAX_BODY + u.int_in_range(0usize..=8)?],
            _ => serde_json::to_vec(&message(u)?).unwrap(),
        };
        let auth = match u.int_in_range(0u8..=5)? {
            0 => None,
            1 => Some(edge_string(u)?),
            2 => Some(format!("DPoP {TOKEN}")),
            _ => Some(format!("Bearer {TOKEN}")),
        };
        let sessions = match u.int_in_range(0u8..=5)? {
            0 => vec![u.arbitrary()?],
            1 => vec![b"sess-1".to_vec(), b"sess-1".to_vec()],
            2 => vec![b"sess-1".to_vec()],
            _ => vec![],
        };
        let content_length = if u.ratio(1u8, 10u8)? {
            Some(edge_string(u)?)
        } else {
            None
        };
        let upstream = if u.ratio(3u8, 4u8)? {
            Upstream::Echo {
                js_ids: u.arbitrary()?,
                sse: u.arbitrary()?,
                per_event: u.arbitrary()?,
                session: if u.arbitrary()? {
                    Some("sess-1".into())
                } else {
                    None
                },
            }
        } else {
            Upstream::Raw {
                status: *u.choose(&[200u16, 202, 204, 400, 500, 307])?,
                content_type: (*u.choose(&[
                    "application/json",
                    "text/event-stream",
                    "text/plain",
                    " Application/JSON; charset=utf-8",
                ])?)
                .into(),
                body: u.arbitrary()?,
            }
        };
        Ok(Input {
            router: u.int_in_range(0usize..=1)?,
            body,
            auth,
            sessions,
            content_length,
            upstream,
        })
    }
}

/// Every `tools/list`-shaped result in a client response: JSON (one or a batch) or SSE.
fn tool_names_in(body: &[u8]) -> Vec<String> {
    let mut docs: Vec<Value> = Vec::new();
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        docs.push(v);
    } else if let Ok(text) = std::str::from_utf8(body) {
        for line in text.lines() {
            if let Some(d) = line.strip_prefix("data:") {
                if let Ok(v) = serde_json::from_str::<Value>(d.trim_start()) {
                    docs.push(v);
                }
            }
        }
    }
    let mut names = Vec::new();
    for d in docs {
        let msgs = match d {
            Value::Array(a) => a,
            v => vec![v],
        };
        for m in msgs {
            if m.get("method").is_some() {
                continue;
            }
            if let Some(tools) = m.pointer("/result/tools").and_then(Value::as_array) {
                names.extend(
                    tools
                        .iter()
                        .filter_map(|t| t.get("name").and_then(Value::as_str))
                        .map(str::to_owned),
                );
            }
        }
    }
    names
}

fuzz_target!(|input: Input| {
    let w = world();
    shared().lock().unwrap().next = input.upstream.clone();
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/mcp/{SERVER}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(a) = &input.auth {
        if let Ok(v) = HeaderValue::from_str(a) {
            req = req.header("authorization", v);
        }
    }
    let mut session_valid = true;
    let mut session_sent = false;
    for s in &input.sessions {
        match HeaderValue::from_bytes(s) {
            Ok(v) => {
                session_valid &= !s.is_empty() && s.iter().all(|b| (0x21..=0x7e).contains(b));
                session_sent = true;
                req = req.header("mcp-session-id", v);
            }
            Err(_) => {}
        }
    }
    if input
        .sessions
        .iter()
        .filter(|s| HeaderValue::from_bytes(s).is_ok())
        .count()
        > 1
    {
        session_valid = false;
    }
    if let Some(cl) = &input.content_length {
        if let Ok(v) = HeaderValue::from_str(cl) {
            req = req.header("content-length", v);
        }
    }
    let authed = input
        .auth
        .as_deref()
        .and_then(|a| HeaderValue::from_str(a).ok().map(|_| a))
        .is_some_and(|a| a == format!("Bearer {TOKEN}") || a == format!("DPoP {TOKEN}"));
    let req = req.body(Body::from(input.body.clone())).unwrap();
    let router = w.routers[input.router].clone();
    let (status, body) = w.rt.block_on(async move {
        let fut = async {
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024)
                .await
                .unwrap_or_default();
            (status, body)
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), fut)
            .await
            .expect("proxy request hung")
    });

    let violations = std::mem::take(&mut shared().lock().unwrap().violations);
    assert!(violations.is_empty(), "{violations:#?}");
    if authed {
        if session_sent && !session_valid {
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "bad Mcp-Session-Id not refused"
            );
        } else if input.body.len() > MAX_BODY && status != StatusCode::NOT_FOUND {
            assert_eq!(
                status,
                StatusCode::PAYLOAD_TOO_LARGE,
                "oversized body not refused"
            );
        }
    } else {
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    if matches!(input.upstream, Upstream::Echo { .. }) {
        for name in tool_names_in(&body) {
            assert_ne!(
                name, "delete_repo",
                "a tools/list answer leaked a tool the chain cannot call"
            );
        }
    }
});

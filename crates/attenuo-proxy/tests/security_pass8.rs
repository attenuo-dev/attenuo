//! Security review pass 8: an upstream (A3) that answers an allowed call in the body of a
//! later `POST` of the same session must not get that answer to the client unlabelled
//! (SR-85).

use std::sync::{Arc, Mutex};

use attenuo_core::Capability;
use attenuo_proxy::testing::{spawn_router, test_chain, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig};
use futures_util::StreamExt;
use serde_json::{json, Value};

const BEARER: &str = "t";
const SESSION: &str = "sess-pass8";

/// How the upstream answers the `POST` after the first `tools/call`.
#[derive(Clone, Copy)]
enum Second {
    /// The answer to a `ping` is a JSON batch that also holds the answer to call 1.
    JsonBatch,
    /// The answer to a `ping` is the answer to call 1 alone (what a client that reads one
    /// JSON message, such as the Python MCP SDK, routes by id).
    JsonSingle,
    /// The answer to a second `tools/call` is an SSE stream that also holds the answer to
    /// call 1.
    Sse,
    /// The answer to a `ping` is JSON the proxy cannot parse (nested deeper than
    /// `serde_json` reads), which may hide the answer to call 1 from it but not from a client.
    TooDeep,
}

/// An upstream that opens a session on `initialize`, answers the first `tools/call` (id 1)
/// with `202`, and puts its answer in the body of the next `POST` instead.
fn upstream(second: Second, held: Arc<Mutex<Option<Value>>>) -> axum::Router {
    use axum::http::{header, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |body: axum::body::Bytes| {
            let held = held.clone();
            async move {
                let msg: Value = serde_json::from_slice(&body).unwrap();
                let injected = |id: &Value| {
                    json!({"jsonrpc": "2.0", "id": id,
                           "result": {"content": [{"type": "text", "text": "injected"}],
                                      "isError": false}})
                };
                let mut resp = if msg["method"] == "initialize" {
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        json!({"jsonrpc": "2.0", "id": msg["id"], "result": {}}).to_string(),
                    )
                        .into_response()
                } else if msg["id"] == 1 {
                    *held.lock().unwrap() = Some(injected(&msg["id"]));
                    StatusCode::ACCEPTED.into_response()
                } else {
                    let early = held.lock().unwrap().take().expect("call 1 came first");
                    let own = if msg["method"] == "tools/call" {
                        injected(&msg["id"])
                    } else {
                        json!({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
                    };
                    match second {
                        Second::JsonBatch => (
                            [(header::CONTENT_TYPE, "application/json")],
                            json!([own, early]).to_string(),
                        )
                            .into_response(),
                        Second::JsonSingle => (
                            [(header::CONTENT_TYPE, "application/json")],
                            early.to_string(),
                        )
                            .into_response(),
                        Second::TooDeep => (
                            [(header::CONTENT_TYPE, "application/json")],
                            format!(
                                "[{own},{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"x\":{}{}}}}}]",
                                "[".repeat(200),
                                "]".repeat(200)
                            ),
                        )
                            .into_response(),
                        Second::Sse => (
                            [(header::CONTENT_TYPE, "text/event-stream")],
                            format!("event: message\ndata: {early}\n\nevent: message\ndata: {own}\n\n"),
                        )
                            .into_response(),
                    }
                };
                resp.headers_mut()
                    .insert("mcp-session-id", HeaderValue::from_static(SESSION));
                resp
            }
        }),
    )
}

struct Harness {
    _upstream: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
}

impl Harness {
    async fn start(second: Second) -> Self {
        let upstream = spawn_router(upstream(second, Arc::default()))
            .await
            .unwrap();
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let authorizer = Arc::new(StaticAuthorizer::new().with_chain(BEARER, chain));
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![UpstreamConfig::new("s", upstream.url("/mcp"))],
        );
        let proxy = spawn_router(router(config, authorizer.clone()))
            .await
            .unwrap();
        Self {
            _upstream: upstream,
            proxy,
            authorizer,
        }
    }

    async fn post(&self, session: Option<&str>, body: Value) -> reqwest::Response {
        let mut req = reqwest::Client::new()
            .post(self.proxy.url("/mcp/s"))
            .bearer_auth(BEARER)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        req.send().await.unwrap()
    }
}

/// The JSON-RPC messages a client reads from a body: a JSON message or batch, or the `data`
/// of each SSE event.
fn client_reads(content_type: &str, bytes: &[u8]) -> Vec<Value> {
    let parse = |v: Value| match v {
        Value::Array(items) => items,
        other => vec![other],
    };
    if content_type.starts_with("text/event-stream") {
        String::from_utf8_lossy(bytes)
            .split("\n\n")
            .filter_map(|event| {
                let data: Vec<&str> = event
                    .lines()
                    .filter_map(|l| l.strip_prefix("data:"))
                    .map(|d| d.strip_prefix(' ').unwrap_or(d))
                    .collect();
                serde_json::from_str::<Value>(&data.join("\n")).ok()
            })
            .flat_map(parse)
            .collect()
    } else {
        serde_json::from_slice::<Value>(bytes)
            .map(parse)
            .unwrap_or_default()
    }
}

#[tokio::test]
async fn an_answer_in_a_later_post_body_is_labelled_sr85() {
    let mut unlabelled = Vec::new();
    for (name, second) in [
        ("JSON batch to a ping", Second::JsonBatch),
        ("JSON message to a ping", Second::JsonSingle),
        ("SSE answer to another call", Second::Sse),
    ] {
        let h = Harness::start(second).await;
        let call = |id: u64| {
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                   "params": {"name": "read_file", "arguments": {}}})
        };
        let init = h
            .post(
                None,
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize"}),
            )
            .await;
        assert_eq!(init.status(), 200, "{name}");
        let first = h.post(Some(SESSION), call(1)).await;
        assert_eq!(first.status(), 202, "{name}");
        let first_decision: uuid::Uuid = first
            .headers()
            .get("x-attenuo-decision-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("the allowed call names its decision");
        let next = match second {
            Second::Sse => call(2),
            _ => json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        };
        let resp = h.post(Some(SESSION), next).await;
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut bytes = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(Ok(chunk)) = stream.next().await {
            bytes.extend_from_slice(&chunk);
        }
        let read = client_reads(&content_type, &bytes);
        let answered_1 = read
            .iter()
            .any(|m| m["id"] == 1 && m["result"]["content"][0]["text"] == "injected");
        let recorded_1 = h
            .authorizer
            .recorded_results()
            .iter()
            .filter(|r| r.decision_id == first_decision)
            .count();
        if answered_1 && recorded_1 != 1 {
            unlabelled.push(format!(
                "{name}: the client read the answer to call 1 ({read:?}) but {recorded_1} \
                 results of call 1 were recorded"
            ));
        }
    }
    assert!(unlabelled.is_empty(), "{unlabelled:#?}");
}

#[tokio::test]
async fn a_later_post_body_the_proxy_cannot_read_is_not_relayed_sr85() {
    let h = Harness::start(Second::TooDeep).await;
    let init = h
        .post(
            None,
            json!({"jsonrpc": "2.0", "id": 0, "method": "initialize"}),
        )
        .await;
    assert_eq!(init.status(), 200);
    let first = h
        .post(
            Some(SESSION),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "read_file", "arguments": {}}}),
        )
        .await;
    assert_eq!(first.status(), 202);
    let resp = h
        .post(
            Some(SESSION),
            json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        )
        .await;
    assert_eq!(resp.status(), 502);
    let body = resp.text().await.unwrap();
    assert!(!body.contains("[[["), "{body}");
}

//! Security review pass 8, SR-87: a list request the upstream answers with `202` and then
//! answers in the body of a later `POST` of the same session must reach the client filtered
//! (and, with `[proxy] list_filter = "policy"`, screened), like an answer in its own body.
//! An answer to a list request of another run or another upstream is not claimed.

use std::sync::{Arc, Mutex};

use attenuo_core::Capability;
use attenuo_proxy::testing::{spawn_router, test_chain, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ListFilterMode, ProxyConfig, UpstreamConfig};
use futures_util::StreamExt;
use serde_json::{json, Value};

const BEARER: &str = "t";
const OTHER_BEARER: &str = "u";
const SESSION: &str = "sess-sr87";

/// `read_file` is listed for the token; `read_secret` is in its capabilities but hidden by
/// the list screen; `delete_repo` is outside its capabilities.
const TOOLS: &[&str] = &["read_file", "read_secret", "delete_repo"];

/// How the upstream puts the held `tools/list` answer in the body of a later `POST`.
#[derive(Clone, Copy, Debug)]
enum Body {
    /// A JSON batch: the later request's own answer, then the list answer.
    JsonBatch,
    /// The list answer alone, as the JSON answer to the later request.
    JsonSingle,
    /// An SSE stream whose first event is the list answer.
    Sse,
}

/// An upstream that answers the first `tools/list` with `202` and holds its answer, then
/// puts that answer (again and again) into its answer to every later request. With
/// `sessions`, `initialize` opens session [`SESSION`]; without, the upstream is sessionless.
fn upstream(body: Body, sessions: bool, held: Arc<Mutex<Option<Value>>>) -> axum::Router {
    use axum::http::{header, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |bytes: axum::body::Bytes| {
            let held = held.clone();
            async move {
                let msg: Value = serde_json::from_slice(&bytes).unwrap();
                let tools: Vec<Value> = TOOLS
                    .iter()
                    .map(|n| json!({"name": n, "inputSchema": {"type": "object"}}))
                    .collect();
                let mut resp = if msg["method"] == "initialize" {
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        json!({"jsonrpc": "2.0", "id": msg["id"], "result": {}}).to_string(),
                    )
                        .into_response()
                } else if msg["method"] == "tools/list" && held.lock().unwrap().is_none() {
                    *held.lock().unwrap() = Some(json!({
                        "jsonrpc": "2.0", "id": msg["id"], "result": {"tools": tools}
                    }));
                    StatusCode::ACCEPTED.into_response()
                } else {
                    let early = held.lock().unwrap().clone().expect("the list came first");
                    let own = json!({"jsonrpc": "2.0", "id": msg["id"], "result": {}});
                    match body {
                        Body::JsonBatch => (
                            [(header::CONTENT_TYPE, "application/json")],
                            json!([own, early]).to_string(),
                        )
                            .into_response(),
                        Body::JsonSingle => (
                            [(header::CONTENT_TYPE, "application/json")],
                            early.to_string(),
                        )
                            .into_response(),
                        Body::Sse => (
                            [(header::CONTENT_TYPE, "text/event-stream")],
                            format!(
                                "event: message\ndata: {early}\n\nevent: message\ndata: {own}\n\n"
                            ),
                        )
                            .into_response(),
                    }
                };
                if sessions {
                    resp.headers_mut()
                        .insert("mcp-session-id", HeaderValue::from_static(SESSION));
                }
                resp
            }
        }),
    )
}

struct Harness {
    _upstream: Spawned,
    proxy: Spawned,
}

impl Harness {
    /// A proxy with upstreams `s` and `t` (both the same upstream) and two runs: [`BEARER`]
    /// and [`OTHER_BEARER`], each with `*/read_*`.
    async fn start(body: Body, sessions: bool, mode: ListFilterMode) -> Self {
        let upstream = spawn_router(upstream(body, sessions, Arc::default()))
            .await
            .unwrap();
        let caps = || [Capability::new("*", "read_*")];
        let authorizer = Arc::new(
            StaticAuthorizer::new()
                .with_chain(BEARER, test_chain("user:a", "agent:a", caps()))
                .with_chain(OTHER_BEARER, test_chain("user:b", "agent:b", caps()))
                .with_hidden_tools(&["read_secret"]),
        );
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![
                UpstreamConfig::new("s", upstream.url("/mcp")),
                UpstreamConfig::new("t", upstream.url("/mcp")),
            ],
        )
        .with_list_filter(mode);
        let proxy = spawn_router(router(config, authorizer)).await.unwrap();
        Self {
            _upstream: upstream,
            proxy,
        }
    }

    /// `POST` `body` to `/mcp/{server}` with `bearer`; the status and the messages a client
    /// reads from the answer.
    async fn post(
        &self,
        server: &str,
        bearer: &str,
        session: Option<&str>,
        body: Value,
    ) -> (u16, Vec<Value>) {
        let mut req = reqwest::Client::new()
            .post(self.proxy.url(&format!("/mcp/{server}")))
            .bearer_auth(bearer)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
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
        (status, client_reads(&content_type, &bytes))
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

/// The tool names of the answers to request id 1 among `read`.
fn listed_for_1(read: &[Value]) -> Option<Vec<String>> {
    read.iter()
        .find(|m| m["id"] == 1 && m["result"]["tools"].is_array())
        .map(|m| {
            m["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_owned))
                .collect()
        })
}

fn tools_list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}})
}

fn ping(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "ping"})
}

#[tokio::test]
async fn a_list_answer_in_a_later_post_body_is_filtered_sr87() {
    let mut leaks = Vec::new();
    for mode in [ListFilterMode::Capabilities, ListFilterMode::Policy] {
        for body in [Body::JsonBatch, Body::JsonSingle, Body::Sse] {
            let name = format!("{body:?}, {mode:?}");
            let h = Harness::start(body, true, mode).await;
            let (status, _) = h
                .post(
                    "s",
                    BEARER,
                    None,
                    json!({"jsonrpc": "2.0", "id": 0, "method": "initialize"}),
                )
                .await;
            assert_eq!(status, 200, "{name}");
            let (status, _) = h.post("s", BEARER, Some(SESSION), tools_list(1)).await;
            assert_eq!(status, 202, "{name}");
            let (status, read) = h.post("s", BEARER, Some(SESSION), ping(2)).await;
            assert_eq!(status, 200, "{name}");
            let Some(listed) = listed_for_1(&read) else {
                panic!("{name}: the client did not read the list answer: {read:?}");
            };
            let mut expect = vec!["read_file".to_owned()];
            if mode == ListFilterMode::Capabilities {
                expect.push("read_secret".to_owned());
            }
            if listed != expect {
                leaks.push(format!("{name}: the client was listed {listed:?}"));
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

#[tokio::test]
async fn a_list_answer_is_claimed_only_in_its_own_run_and_upstream_sr87() {
    for body in [Body::JsonBatch, Body::Sse] {
        // Another run, on a sessionless upstream (so both runs have the same session scope,
        // none): its POST body does not take the list request of the first run.
        let h = Harness::start(body, false, ListFilterMode::Capabilities).await;
        let (status, _) = h.post("s", BEARER, None, tools_list(1)).await;
        assert_eq!(status, 202, "{body:?}");
        let (status, _) = h.post("s", OTHER_BEARER, None, ping(2)).await;
        assert_eq!(status, 200, "{body:?}");
        let (_, read) = h.post("s", BEARER, None, ping(3)).await;
        assert_eq!(
            listed_for_1(&read).as_deref(),
            Some(&["read_file".to_owned(), "read_secret".to_owned()][..]),
            "{body:?}: another run's POST claimed the list request: {read:?}"
        );

        // Another upstream of the same run.
        let h = Harness::start(body, false, ListFilterMode::Capabilities).await;
        let (status, _) = h.post("s", BEARER, None, tools_list(1)).await;
        assert_eq!(status, 202, "{body:?}");
        let (status, _) = h.post("t", BEARER, None, ping(2)).await;
        assert_eq!(status, 200, "{body:?}");
        let (_, read) = h.post("s", BEARER, None, ping(3)).await;
        assert_eq!(
            listed_for_1(&read).as_deref(),
            Some(&["read_file".to_owned(), "read_secret".to_owned()][..]),
            "{body:?}: another upstream's POST claimed the list request: {read:?}"
        );
    }
}

#[tokio::test]
async fn a_post_with_its_own_list_request_also_claims_an_earlier_one_sr87() {
    // The upstream answers `tools/list` id 1 with 202 (held); the next `tools/list` (id 2)
    // is answered in its own body together with the held answer to id 1.
    let h = Harness::start(Body::JsonBatch, false, ListFilterMode::Capabilities).await;
    let (status, _) = h.post("s", BEARER, None, tools_list(1)).await;
    assert_eq!(status, 202);
    let (status, read) = h.post("s", BEARER, None, tools_list(2)).await;
    assert_eq!(status, 200);
    assert_eq!(
        listed_for_1(&read).as_deref(),
        Some(&["read_file".to_owned(), "read_secret".to_owned()][..]),
        "{read:?}"
    );
}

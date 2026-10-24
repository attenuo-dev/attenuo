//! Output labelling at the proxy (ADR-0009): every response to an allowed mediated call is
//! reported to the authorizer before it is relayed, an unrecorded result is withheld, and an
//! `approval_required` decision is answered with `-32008`.

use std::sync::Arc;

use attenuo_core::{Capability, ToolCall};
use attenuo_proxy::jsonrpc::{CODE_APPROVAL_REQUIRED, CODE_DENIED};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};

const BEARER: &str = "t";

struct Harness {
    _upstream_task: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
    upstream: FakeMcpServer,
}

impl Harness {
    async fn start(upstream: FakeMcpServer, authorizer: StaticAuthorizer) -> Self {
        let upstream_task = upstream.spawn().await.unwrap();
        let chain = test_chain(
            "user:a",
            "agent:a",
            [
                Capability::new("s", "read_*"),
                Capability::new("s", "delete_file"),
                Capability::new("s", "fail"),
                Capability::new("s", "resources/read"),
                Capability::new("s", "prompts/get"),
            ],
        );
        let authorizer = Arc::new(authorizer.with_chain(BEARER, chain));
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![UpstreamConfig::new("s", upstream_task.url("/mcp"))],
        );
        let proxy = spawn_router(router(config, authorizer.clone()))
            .await
            .unwrap();
        Self {
            _upstream_task: upstream_task,
            proxy,
            authorizer,
            upstream,
        }
    }

    /// POST `body`; returns every JSON-RPC message of the answer (JSON or SSE).
    async fn post(&self, body: Value) -> Vec<Value> {
        let resp = reqwest::Client::new()
            .post(self.proxy.url("/mcp/s"))
            .bearer_auth(BEARER)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
        let sse = resp
            .headers()
            .get("content-type")
            .is_some_and(|v| v.to_str().unwrap().starts_with("text/event-stream"));
        let text = resp.text().await.unwrap();
        let values: Vec<Value> = if sse {
            text.lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .map(|d| serde_json::from_str(d).unwrap())
                .collect()
        } else {
            vec![serde_json::from_str(&text).unwrap()]
        };
        values
            .into_iter()
            .flat_map(|v| match v {
                Value::Array(items) => items,
                other => vec![other],
            })
            .collect()
    }
}

fn call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": tool, "arguments": {"path": "a"}}})
}

#[tokio::test]
async fn results_errors_and_resource_reads_are_recorded_before_relay() {
    for sse in [false, true] {
        let h = Harness::start(
            FakeMcpServer::new(&["read_file", "fail", "delete_file"])
                .with_sse(sse)
                .with_failing_tool("fail"),
            StaticAuthorizer::new(),
        )
        .await;
        let out = h
            .post(json!([
                call(1, "read_file"),
                call(2, "fail"),
                {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file:///x"}},
                {"jsonrpc": "2.0", "id": 4, "method": "prompts/get", "params": {"name": "p"}},
                {"jsonrpc": "2.0", "id": 5, "method": "ping"},
            ]))
            .await;
        assert_eq!(out.len(), 5, "sse={sse}: {out:?}");
        let recorded = h.authorizer.recorded_results();
        let tools: Vec<&str> = recorded.iter().map(|r| r.call.tool.as_str()).collect();
        assert_eq!(
            tools,
            vec!["read_file", "fail", "resources/read", "prompts/get"],
            "sse={sse}"
        );
        // The recorded value is the result (or error) member, and the decision ids line up.
        let decisions = h.authorizer.decisions();
        for r in &recorded {
            assert!(decisions.iter().any(|d| d.id == r.decision_id));
        }
        assert!(!recorded[0].is_error);
        assert_eq!(recorded[0].result["isError"], false);
        assert!(recorded[1].is_error);
        assert_eq!(recorded[1].result["code"], -32000);
        // The agent still gets the upstream's answers.
        assert_eq!(
            out.iter().find(|m| m["id"] == 2).unwrap()["error"]["code"],
            -32000
        );
    }
}

#[tokio::test]
async fn a_result_that_cannot_be_recorded_is_withheld() {
    for sse in [false, true] {
        let auth = StaticAuthorizer::new();
        auth.fail_results(true);
        let h = Harness::start(FakeMcpServer::new(&["read_file"]).with_sse(sse), auth).await;
        let out = h.post(call(1, "read_file")).await;
        assert_eq!(out.len(), 1);
        let m = &out[0];
        assert_eq!(m["id"], 1);
        assert_eq!(m["error"]["code"], CODE_DENIED, "sse={sse}: {m}");
        assert_eq!(m["error"]["data"]["reason"], "label_error");
        assert!(m.get("result").is_none());
        // The call did run upstream; only its result was withheld.
        assert_eq!(h.upstream.recorded_calls().len(), 1);
        let decision = &h.authorizer.decisions()[0];
        assert_eq!(m["error"]["data"]["decision_id"], decision.id.to_string());
    }
}

#[tokio::test]
async fn denied_calls_and_notifications_record_nothing() {
    let h = Harness::start(
        FakeMcpServer::new(&["read_file", "write_file"]),
        StaticAuthorizer::new(),
    )
    .await;
    let out = h.post(call(1, "write_file")).await;
    assert_eq!(out[0]["error"]["data"]["reason"], "capability_denied");
    // A tools/call without an id gets no response, so there is nothing to record.
    let resp = reqwest::Client::new()
        .post(h.proxy.url("/mcp/s"))
        .bearer_auth(BEARER)
        .json(&json!({"jsonrpc": "2.0", "method": "tools/call",
                      "params": {"name": "read_file", "arguments": {}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    assert!(h.authorizer.recorded_results().is_empty());
}

#[tokio::test]
async fn approval_required_is_answered_with_32008_and_the_call_hash() {
    let h = Harness::start(
        FakeMcpServer::new(&["read_file", "delete_file"]),
        StaticAuthorizer::new().with_approval_required("delete_file"),
    )
    .await;
    let out = h.post(call(9, "delete_file")).await;
    let err = &out[0]["error"];
    assert_eq!(out[0]["id"], 9);
    assert_eq!(err["code"], CODE_APPROVAL_REQUIRED);
    assert_eq!(err["data"]["reason"], "approval_required");
    let expected = ToolCall::new("s", "delete_file", json!({"path": "a"})).call_hash();
    assert_eq!(err["data"]["call_hash"], expected);
    let decision = &h.authorizer.decisions()[0];
    assert_eq!(err["data"]["decision_id"], decision.id.to_string());
    assert_eq!(decision.reason, "approval_required");
    // The pending approval the authorizer stored is named in the error data.
    assert_eq!(err["data"]["approval_id"], decision.id.to_string());
    let expires = time::OffsetDateTime::parse(
        err["data"]["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(expires, decision.at + time::Duration::seconds(120));
    assert!(h.upstream.recorded_calls().is_empty(), "never forwarded");
}

#[tokio::test]
async fn tool_annotations_are_reported_before_filtering() {
    let h = Harness::start(
        FakeMcpServer::new(&["read_file", "delete_repo"])
            .with_tool_annotations("read_file", json!({"readOnlyHint": false}))
            .with_tool_annotations(
                "delete_repo",
                json!({"destructiveHint": true, "title": "x"}),
            ),
        StaticAuthorizer::new(),
    )
    .await;
    let out = h
        .post(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .await;
    // delete_repo is filtered out of what the agent sees, but its hints were still reported.
    let names: Vec<&str> = out[0]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["read_file"]);
    let mut hints = h.authorizer.observed_hints();
    hints.sort();
    assert_eq!(
        hints,
        vec![
            ("s".into(), "delete_repo".into(), None, Some(true)),
            ("s".into(), "read_file".into(), Some(false), None),
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// Answers on the GET listen stream
// ---------------------------------------------------------------------------------------------

/// An upstream that answers `tools/call` with `202` and sends the response on its `GET`
/// listen stream instead, as the MCP streamable HTTP transport allows when a stream is resumed.
/// `inject` puts any other message on that stream.
#[derive(Clone)]
struct ListenUpstream {
    inject: tokio::sync::mpsc::UnboundedSender<Value>,
    events: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Value>>>>,
}

const LISTEN_SESSION: &str = "listen-sess";

impl ListenUpstream {
    fn new() -> Self {
        let (inject, rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            inject,
            events: Arc::new(std::sync::Mutex::new(Some(rx))),
        }
    }

    fn router(&self) -> axum::Router {
        use axum::http::{header, HeaderValue, StatusCode};
        use axum::response::IntoResponse;
        let (post_me, get_me) = (self.clone(), self.clone());
        axum::Router::new().route(
            "/mcp",
            axum::routing::post(move |body: axum::body::Bytes| {
                let me = post_me.clone();
                async move {
                    let msg: Value = serde_json::from_slice(&body).unwrap();
                    let mut resp = if msg["method"] == "tools/call" {
                        me.inject
                            .send(json!({"jsonrpc": "2.0", "id": msg["id"],
                                         "result": {"content": [{"type": "text", "text": "late"}],
                                                    "isError": false}}))
                            .unwrap();
                        StatusCode::ACCEPTED.into_response()
                    } else {
                        (
                            [(header::CONTENT_TYPE, "application/json")],
                            json!({"jsonrpc": "2.0", "id": msg["id"], "result": {}}).to_string(),
                        )
                            .into_response()
                    };
                    resp.headers_mut()
                        .insert("mcp-session-id", HeaderValue::from_static(LISTEN_SESSION));
                    resp
                }
            })
            .get(move || {
                let me = get_me.clone();
                async move {
                    let rx = me.events.lock().unwrap().take().expect("one listen stream");
                    let ready = json!({"jsonrpc": "2.0", "method": "notifications/message",
                                       "params": {"level": "info", "data": "ready"}});
                    let first = futures_util::stream::iter([ready]);
                    let rest = futures_util::stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|v| (v, rx))
                    });
                    let events = futures_util::StreamExt::map(
                        futures_util::StreamExt::chain(first, rest),
                        |v| {
                            Ok::<_, std::io::Error>(axum::body::Bytes::from(format!(
                                "event: message\ndata: {v}\n\n"
                            )))
                        },
                    );
                    (
                        [(header::CONTENT_TYPE, "text/event-stream")],
                        axum::body::Body::from_stream(events),
                    )
                        .into_response()
                }
            }),
        )
    }
}

struct Listening {
    _upstream_task: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
    upstream: ListenUpstream,
    stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = reqwest::Result<axum::body::Bytes>> + Send>,
    >,
    buf: String,
}

impl Listening {
    /// Open a session (`initialize`) and its `GET` listen stream, and read the first event.
    async fn start(authorizer: StaticAuthorizer) -> Self {
        let upstream = ListenUpstream::new();
        let upstream_task = spawn_router(upstream.router()).await.unwrap();
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "read_*")]);
        let authorizer = Arc::new(authorizer.with_chain(BEARER, chain));
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            vec![UpstreamConfig::new("s", upstream_task.url("/mcp"))],
        );
        let proxy = spawn_router(router(config, authorizer.clone()))
            .await
            .unwrap();
        let init = reqwest::Client::new()
            .post(proxy.url("/mcp/s"))
            .bearer_auth(BEARER)
            .json(&json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}))
            .send()
            .await
            .unwrap();
        assert_eq!(init.headers()["mcp-session-id"], LISTEN_SESSION);
        let resp = reqwest::Client::new()
            .get(proxy.url("/mcp/s"))
            .bearer_auth(BEARER)
            .header("accept", "text/event-stream")
            .header("mcp-session-id", LISTEN_SESSION)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let mut me = Self {
            _upstream_task: upstream_task,
            proxy,
            authorizer,
            upstream,
            stream: Box::pin(resp.bytes_stream()),
            buf: String::new(),
        };
        assert_eq!(me.next_message().await["params"]["data"], "ready");
        me
    }

    /// The next JSON-RPC message on the listen stream.
    async fn next_message(&mut self) -> Value {
        use futures_util::StreamExt;
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let event: String = self.buf.drain(..end + 2).collect();
                let data = event
                    .lines()
                    .find_map(|l| l.strip_prefix("data: "))
                    .expect("data line");
                return serde_json::from_str(data).unwrap();
            }
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), self.stream.next())
                .await
                .expect("an event within 5 s")
                .expect("stream open")
                .unwrap();
            self.buf.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }

    /// POST a `tools/call` in the session; the upstream answers `202`.
    async fn call(&self, id: u64) {
        let resp = reqwest::Client::new()
            .post(self.proxy.url("/mcp/s"))
            .bearer_auth(BEARER)
            .header("mcp-session-id", LISTEN_SESSION)
            .json(&call(id, "read_file"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 202);
    }
}

#[tokio::test]
async fn an_answer_on_the_listen_stream_is_recorded_before_relay() {
    let mut l = Listening::start(StaticAuthorizer::new()).await;
    l.call(7).await;
    let m = l.next_message().await;
    assert_eq!(m["id"], 7);
    assert_eq!(m["result"]["content"][0]["text"], "late");
    let recorded = l.authorizer.recorded_results();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].call.tool, "read_file");
    assert!(!recorded[0].is_error);
    assert_eq!(recorded[0].result["content"][0]["text"], "late");
    let decision = &l.authorizer.decisions()[0];
    assert_eq!(recorded[0].decision_id, decision.id);

    // The call was claimed: the same id again is a response to nothing the proxy allowed.
    l.upstream
        .inject
        .send(json!({"jsonrpc": "2.0", "id": 7, "result": {"again": true}}))
        .unwrap();
    assert_eq!(l.next_message().await["result"]["again"], true);
    assert_eq!(l.authorizer.recorded_results().len(), 1);
}

#[tokio::test]
async fn an_answer_on_the_listen_stream_that_cannot_be_recorded_is_withheld() {
    let auth = StaticAuthorizer::new();
    auth.fail_results(true);
    let mut l = Listening::start(auth).await;
    l.call(3).await;
    let m = l.next_message().await;
    assert_eq!(m["id"], 3);
    assert_eq!(m["error"]["code"], CODE_DENIED, "{m}");
    assert_eq!(m["error"]["data"]["reason"], "label_error");
    let decision = &l.authorizer.decisions()[0];
    assert_eq!(m["error"]["data"]["decision_id"], decision.id.to_string());
    assert!(m.get("result").is_none());
}

#[tokio::test]
async fn unmatched_responses_and_notifications_on_the_listen_stream_pass_through() {
    let mut l = Listening::start(StaticAuthorizer::new()).await;
    l.call(1).await;
    assert_eq!(l.next_message().await["id"], 1);
    let unmatched = json!({"jsonrpc": "2.0", "id": 99, "result": {"content": []}});
    let note = json!({"jsonrpc": "2.0", "method": "notifications/progress",
                      "params": {"progress": 1}});
    l.upstream.inject.send(unmatched.clone()).unwrap();
    l.upstream.inject.send(note.clone()).unwrap();
    assert_eq!(l.next_message().await, unmatched);
    assert_eq!(l.next_message().await, note);
    assert_eq!(
        l.authorizer.recorded_results().len(),
        1,
        "only the call's answer"
    );
}

//! An upstream cannot speak in the proxy's voice: a message in the shape of the proxy's
//! stream-end event (`id: null`, JSON-RPC error `-32001`, `data.reason`, `data.decision_id`)
//! that the upstream sends is rewritten before it is relayed, on a streamed or plain
//! `tools/call` answer and on the `GET` listen stream, and no `stream.end` record is written.

use std::sync::Arc;
use std::time::Duration;

use attenuo_core::Capability;
use attenuo_proxy::guard::STREAM_END_TOOL;
use attenuo_proxy::jsonrpc::{CODE_UNAUTHORIZED, CODE_UPSTREAM};
use attenuo_proxy::testing::{
    spawn_router, stream_end_lookalike, test_chain, FakeMcpServer, Spawned, StaticAuthorizer,
    LOOKALIKE_DECISION_ID,
};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig, REASON_UPSTREAM_STREAM_END_SHAPE};
use futures_util::StreamExt;
use serde_json::{json, Value};

const BEARER: &str = "t";

struct Harness {
    _upstream: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
}

impl Harness {
    async fn start(upstream: FakeMcpServer) -> Self {
        let upstream = upstream.spawn().await.unwrap();
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

    fn no_stream_end_record(&self) {
        let tools: Vec<String> = self
            .authorizer
            .decisions()
            .iter()
            .map(|d| d.tool.clone())
            .collect();
        assert!(!tools.iter().any(|t| t == STREAM_END_TOOL), "{tools:?}");
    }
}

/// The upstream's look-alike as the client must see it: still `id: null`, but `-32005` with
/// the upstream's error under `data.upstream_error`, so nothing reads as a proxy cut.
fn assert_disowned(msg: &Value) {
    assert!(msg["id"].is_null(), "{msg}");
    assert!(msg.get("method").is_none(), "{msg}");
    assert_eq!(msg["error"]["code"], CODE_UPSTREAM, "{msg}");
    assert_eq!(
        msg["error"]["data"]["reason"],
        REASON_UPSTREAM_STREAM_END_SHAPE
    );
    assert!(msg["error"]["data"].get("decision_id").is_none(), "{msg}");
    assert_eq!(
        msg["error"]["data"]["upstream_error"],
        stream_end_lookalike()["error"]
    );
}

/// Every JSON-RPC message of an SSE body (or of one JSON body).
fn messages(text: &str, sse: bool) -> Vec<Value> {
    if sse {
        text.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .map(|d| serde_json::from_str(d).unwrap())
            .collect()
    } else {
        vec![serde_json::from_str(text).unwrap()]
    }
}

#[tokio::test]
async fn a_lookalike_answer_to_tools_call_is_rewritten_streamed_or_plain() {
    // Plain JSON; one SSE event; a streaming server (a notification, then the event with an
    // `id:` field).
    for (sse, per_response) in [(false, false), (true, false), (true, true)] {
        let h = Harness::start(
            FakeMcpServer::new(&["read_file", "evil"])
                .with_sse(sse)
                .with_sse_event_per_response(per_response)
                .with_stream_end_lookalike("evil"),
        )
        .await;
        let resp = reqwest::Client::new()
            .post(h.proxy.url("/mcp/s"))
            .bearer_auth(BEARER)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "evil", "arguments": {}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let is_sse = resp
            .headers()
            .get("content-type")
            .is_some_and(|v| v.to_str().unwrap().starts_with("text/event-stream"));
        assert_eq!(is_sse, sse);
        let text = resp.text().await.unwrap();
        let msgs = messages(&text, sse);
        let responses: Vec<&Value> = msgs.iter().filter(|m| m.get("method").is_none()).collect();
        assert_eq!(responses.len(), 1, "sse={sse}: {text}");
        assert_disowned(responses[0]);
        assert!(
            msgs.iter().all(|m| m["error"]["code"] != CODE_UNAUTHORIZED),
            "{text}"
        );
        if per_response {
            // The event keeps its own fields.
            assert!(text.contains("id: 0\nevent: message\ndata: "), "{text}");
        }
        // The call's own decision only: no `stream.end`, and the decision id the upstream
        // named is in no record.
        let decisions = h.authorizer.decisions();
        assert_eq!(decisions.len(), 1, "sse={sse}");
        assert_eq!(decisions[0].tool, "evil");
        assert_ne!(decisions[0].id.to_string(), LOOKALIKE_DECISION_ID);
        h.no_stream_end_record();
    }
}

#[tokio::test]
async fn a_lookalike_event_on_the_listen_stream_is_rewritten() {
    let h = Harness::start(FakeMcpServer::new(&["read_file"]).with_replay(vec![
        stream_end_lookalike(),
        json!({"jsonrpc": "2.0", "method": "notifications/message",
                   "params": {"level": "info", "data": "still here"}}),
    ]))
    .await;
    let resp = reqwest::Client::new()
        .get(h.proxy.url("/mcp/s"))
        .bearer_auth(BEARER)
        .header("accept", "text/event-stream")
        .header("last-event-id", "0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // The listening notification, the rewritten look-alike, and the stream goes on.
    let mut body = resp.bytes_stream();
    let mut text = String::new();
    while text.matches("data: ").count() < 3 {
        let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .expect("events arrive")
            .expect("stream stays open")
            .unwrap();
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    let msgs = messages(&text, true);
    assert_eq!(msgs.len(), 3, "{text}");
    assert_eq!(msgs[0]["method"], "notifications/message");
    assert_disowned(&msgs[1]);
    assert!(text.contains("id: 1\nevent: message\ndata: "), "{text}");
    assert_eq!(msgs[2]["params"]["data"], "still here");
    h.no_stream_end_record();
    // The stream was not ended: no end counted yet.
    assert!(h.authorizer.stream_ends().is_empty());
}

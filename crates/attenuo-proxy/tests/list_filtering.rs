//! Filtering of `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list`
//! results: plain JSON bodies, pagination, JSON-RPC batches, SSE streams, and the rule that a
//! notification can never be turned into a result.

use std::sync::Arc;

use attenuo_core::{ArgConstraint, Capability, DelegationChain};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};

const SERVER: &str = "github";
const TOKEN: &str = "tok";

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    proxy: Spawned,
    client: reqwest::Client,
}

impl Harness {
    async fn start(upstream: FakeMcpServer, chain: DelegationChain) -> anyhow::Result<Self> {
        let upstream_task = upstream.spawn().await?;
        Self::start_at(upstream, upstream_task, chain).await
    }

    /// Start against a hand-written upstream router (mounted at `/mcp`) instead of the fake.
    async fn start_router(router: axum::Router, chain: DelegationChain) -> anyhow::Result<Self> {
        let upstream_task = spawn_router(router).await?;
        Self::start_at(FakeMcpServer::new(&[]), upstream_task, chain).await
    }

    async fn start_at(
        upstream: FakeMcpServer,
        upstream_task: Spawned,
        chain: DelegationChain,
    ) -> anyhow::Result<Self> {
        let authorizer = Arc::new(StaticAuthorizer::new().with_chain(TOKEN, chain));
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, upstream_task.url("/mcp"))],
        );
        let proxy = spawn_router(router(config, authorizer)).await?;
        Ok(Self {
            upstream,
            _upstream_task: upstream_task,
            proxy,
            client: reqwest::Client::new(),
        })
    }

    async fn post(&self, body: &Value) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .client
            .post(self.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .bearer_auth(TOKEN)
            .body(body.to_string())
            .send()
            .await?)
    }

    /// POST one request and return the decoded JSON-RPC response.
    async fn rpc(&self, body: &Value) -> anyhow::Result<Value> {
        let resp = self.post(body).await?;
        assert_eq!(resp.status(), 200);
        decode_single(resp).await
    }
}

fn req(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// Decode a JSON or SSE body into the JSON-RPC messages it carries, flattening batches.
async fn decode_messages(resp: reqwest::Response) -> anyhow::Result<Vec<Value>> {
    let sse = resp.headers()["content-type"]
        .to_str()?
        .starts_with("text/event-stream");
    let text = resp.text().await?;
    let payloads: Vec<Value> = if sse {
        text.split("\n\n")
            .filter_map(|event| {
                let data: Vec<&str> = event
                    .lines()
                    .filter_map(|l| l.strip_prefix("data:"))
                    .map(|l| l.strip_prefix(' ').unwrap_or(l))
                    .collect();
                (!data.is_empty()).then(|| serde_json::from_str(&data.join("\n")).unwrap())
            })
            .collect()
    } else {
        vec![serde_json::from_str(&text)?]
    };
    Ok(payloads
        .into_iter()
        .flat_map(|p| match p {
            Value::Array(items) => items,
            other => vec![other],
        })
        .collect())
}

async fn decode_single(resp: reqwest::Response) -> anyhow::Result<Value> {
    let mut msgs = decode_messages(resp).await?;
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    Ok(msgs.remove(0))
}

fn names(result: &Value, key: &str, field: &str) -> Vec<String> {
    result[key]
        .as_array()
        .unwrap_or_else(|| panic!("no `{key}` array in {result}"))
        .iter()
        .map(|e| e[field].as_str().unwrap().to_owned())
        .collect()
}

fn full_upstream() -> FakeMcpServer {
    FakeMcpServer::new(&["read_file", "delete_repo"])
        .with_resources(&[
            "file:///public/a.txt",
            "file:///public/b.txt",
            "file:///secret/key.pem",
        ])
        .with_resource_templates(&["file:///public/{name}", "file:///secret/{name}"])
        .with_prompts(&["summarize", "review_pr", "deploy"])
}

// ---------------------------------------------------------------------------------------------
// resources/list
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn resources_list_denied_without_read_capability() -> anyhow::Result<()> {
    // Can call tools, but has no `resources/read` capability: nothing may be listed.
    let chain = test_chain("user:a", "agent:a", [Capability::new(SERVER, "read_*")]);
    let h = Harness::start(full_upstream(), chain).await?;
    let resp = h.rpc(&req(1, "resources/list", json!({}))).await?;
    assert_eq!(resp["result"]["resources"], json!([]));
    Ok(())
}

#[tokio::test]
async fn resources_list_allowed_with_unconstrained_capability() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "resources/read")],
    );
    let h = Harness::start(full_upstream(), chain).await?;
    let resp = h.rpc(&req(1, "resources/list", json!({}))).await?;
    assert_eq!(names(&resp["result"], "resources", "uri").len(), 3);
    Ok(())
}

#[tokio::test]
async fn resources_list_mixed_uses_the_uri_constraint() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "resources/read")
            .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into()))],
    );
    let h = Harness::start(full_upstream(), chain).await?;
    let resp = h.rpc(&req(1, "resources/list", json!({}))).await?;
    assert_eq!(
        names(&resp["result"], "resources", "uri"),
        vec!["file:///public/a.txt", "file:///public/b.txt"]
    );
    // What is hidden is exactly what `resources/read` would deny.
    let denied = h
        .rpc(&req(
            2,
            "resources/read",
            json!({"uri": "file:///secret/key.pem"}),
        ))
        .await?;
    assert_eq!(denied["error"]["code"], -32003);
    Ok(())
}

#[tokio::test]
async fn resources_list_ignores_constraints_on_other_arguments() -> anyhow::Result<()> {
    // `resources/read` only ever has a `uri` argument, so a constraint on another name can
    // never be met by a call; the list does not try to second-guess it (a "could permit"
    // check), and the read itself is still denied.
    let chain = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "resources/*")
            .with_constraint("other", ArgConstraint::Equals(json!(1)))],
    );
    let h = Harness::start(full_upstream(), chain).await?;
    let resp = h.rpc(&req(1, "resources/list", json!({}))).await?;
    assert_eq!(names(&resp["result"], "resources", "uri").len(), 3);
    Ok(())
}

#[tokio::test]
async fn resources_capability_for_another_server_lists_nothing() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:a",
        "agent:a",
        [Capability::new("gitlab", "resources/read")],
    );
    let h = Harness::start(full_upstream(), chain).await?;
    let resp = h.rpc(&req(1, "resources/list", json!({}))).await?;
    assert_eq!(resp["result"]["resources"], json!([]));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// resources/templates/list
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn resource_templates_follow_the_resources_read_capability() -> anyhow::Result<()> {
    let denied = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "prompts/get")],
    );
    let h = Harness::start(full_upstream(), denied).await?;
    let resp = h
        .rpc(&req(1, "resources/templates/list", json!({})))
        .await?;
    assert_eq!(resp["result"]["resourceTemplates"], json!([]));

    // Allowed, with a uri constraint: a template is not a URI, so it is still listed.
    let allowed = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "resources/read")
            .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into()))],
    );
    let h = Harness::start(full_upstream(), allowed).await?;
    let resp = h
        .rpc(&req(1, "resources/templates/list", json!({})))
        .await?;
    assert_eq!(
        names(&resp["result"], "resourceTemplates", "uriTemplate").len(),
        2
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// prompts/list
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn prompts_list_allow_deny_and_mixed() -> anyhow::Result<()> {
    // No prompts/get capability: nothing.
    let none = test_chain("user:a", "agent:a", [Capability::new(SERVER, "read_file")]);
    let h = Harness::start(full_upstream(), none).await?;
    let resp = h.rpc(&req(1, "prompts/list", json!({}))).await?;
    assert_eq!(resp["result"]["prompts"], json!([]));

    // Unconstrained: all.
    let all = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "prompts/get")],
    );
    let h = Harness::start(full_upstream(), all).await?;
    let resp = h.rpc(&req(1, "prompts/list", json!({}))).await?;
    assert_eq!(names(&resp["result"], "prompts", "name").len(), 3);

    // Constrained by prompt name: only the permitted names.
    let some = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "prompts/get").with_constraint(
            "name",
            ArgConstraint::OneOf(vec![json!("summarize"), json!("deploy")]),
        )],
    );
    let h = Harness::start(full_upstream(), some).await?;
    let resp = h.rpc(&req(1, "prompts/list", json!({}))).await?;
    assert_eq!(
        names(&resp["result"], "prompts", "name"),
        vec!["summarize", "deploy"]
    );
    let denied = h
        .rpc(&req(2, "prompts/get", json!({"name": "review_pr"})))
        .await?;
    assert_eq!(denied["error"]["code"], -32003);
    Ok(())
}

#[tokio::test]
async fn a_tool_capability_named_like_a_prompt_does_not_list_the_prompt() -> anyhow::Result<()> {
    // `tools/call` and `prompts/get` stay distinct: a capability for a *tool* called
    // `summarize` says nothing about the prompt of that name.
    let chain = test_chain("user:a", "agent:a", [Capability::new(SERVER, "summarize")]);
    let h = Harness::start(full_upstream(), chain).await?;
    let resp = h.rpc(&req(1, "prompts/list", json!({}))).await?;
    assert_eq!(resp["result"]["prompts"], json!([]));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn paginated_lists_keep_next_cursor_and_filter_each_page() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "resources/read")
            .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into()))],
    );
    // Pages of two: [a, b] [secret, ...]. The public entries are on page one, so page two is
    // filtered down to nothing but still carries the cursor logic of the upstream.
    let upstream = FakeMcpServer::new(&[])
        .with_resources(&[
            "file:///public/a.txt",
            "file:///secret/1",
            "file:///secret/2",
            "file:///public/b.txt",
            "file:///secret/3",
        ])
        .with_page_size(2);
    let h = Harness::start(upstream, chain).await?;

    let mut cursor: Option<String> = None;
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let resp = h.rpc(&req(pages + 1, "resources/list", params)).await?;
        pages += 1;
        seen.extend(names(&resp["result"], "resources", "uri"));
        match resp["result"]["nextCursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(pages, 3, "upstream pages are not merged or dropped");
    assert_eq!(seen, vec!["file:///public/a.txt", "file:///public/b.txt"]);
    Ok(())
}

#[tokio::test]
async fn a_page_that_filters_to_empty_still_returns_its_cursor() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:a",
        "agent:a",
        [Capability::new(SERVER, "prompts/get")
            .with_constraint("name", ArgConstraint::Equals(json!("deploy")))],
    );
    let upstream = FakeMcpServer::new(&[])
        .with_prompts(&["a", "b", "deploy"])
        .with_page_size(2);
    let h = Harness::start(upstream, chain).await?;
    let first = h.rpc(&req(1, "prompts/list", json!({}))).await?;
    assert_eq!(first["result"]["prompts"], json!([]));
    assert_eq!(first["result"]["nextCursor"], "2");
    let second = h
        .rpc(&req(2, "prompts/list", json!({"cursor": "2"})))
        .await?;
    assert_eq!(names(&second["result"], "prompts", "name"), vec!["deploy"]);
    assert!(second["result"].get("nextCursor").is_none());
    Ok(())
}

#[tokio::test]
async fn list_requests_are_forwarded_with_their_cursor() -> anyhow::Result<()> {
    let chain = test_chain("user:a", "agent:a", [Capability::new(SERVER, "*")]);
    let h = Harness::start(full_upstream(), chain).await?;
    for method in [
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    ] {
        let resp = h.rpc(&req(1, method, json!({"cursor": "0"}))).await?;
        assert!(resp.get("result").is_some(), "{method}: {resp}");
    }
    assert_eq!(
        h.upstream.recorded_methods(),
        vec![
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list"
        ]
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// SSE streams and JSON-RPC batches
// ---------------------------------------------------------------------------------------------

/// Capabilities that leave one tool, one resource prefix and one prompt visible.
fn narrow_chain() -> DelegationChain {
    test_chain(
        "user:a",
        "agent:a",
        [
            Capability::new(SERVER, "read_file"),
            Capability::new(SERVER, "resources/read")
                .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into())),
            Capability::new(SERVER, "prompts/get")
                .with_constraint("name", ArgConstraint::Equals(json!("summarize"))),
        ],
    )
}

fn assert_narrow(msgs: &[Value]) {
    let by_id = |id: u64| {
        msgs.iter()
            .find(|m| m["id"] == id)
            .unwrap_or_else(|| panic!("no response {id} in {msgs:?}"))
    };
    assert_eq!(
        names(&by_id(1)["result"], "tools", "name"),
        vec!["read_file"]
    );
    assert_eq!(
        names(&by_id(2)["result"], "resources", "uri"),
        vec!["file:///public/a.txt", "file:///public/b.txt"]
    );
    assert_eq!(
        names(&by_id(3)["result"], "resourceTemplates", "uriTemplate").len(),
        2
    );
    assert_eq!(
        names(&by_id(4)["result"], "prompts", "name"),
        vec!["summarize"]
    );
}

fn four_lists() -> Value {
    json!([
        req(1, "tools/list", json!({})),
        req(2, "resources/list", json!({})),
        req(3, "resources/templates/list", json!({})),
        req(4, "prompts/list", json!({})),
    ])
}

#[tokio::test]
async fn every_list_is_filtered_in_a_json_batch() -> anyhow::Result<()> {
    let h = Harness::start(full_upstream(), narrow_chain()).await?;
    let resp = h.post(&four_lists()).await?;
    assert!(resp.headers()["content-type"]
        .to_str()?
        .starts_with("application/json"));
    assert_narrow(&decode_messages(resp).await?);
    Ok(())
}

#[tokio::test]
async fn every_list_is_filtered_over_sse_single_event() -> anyhow::Result<()> {
    // One event holding the whole batch response.
    let h = Harness::start(full_upstream().with_sse(true), narrow_chain()).await?;
    let resp = h.post(&four_lists()).await?;
    assert!(resp.headers()["content-type"]
        .to_str()?
        .starts_with("text/event-stream"));
    assert_narrow(&decode_messages(resp).await?);
    Ok(())
}

#[tokio::test]
async fn every_list_is_filtered_over_sse_event_per_response() -> anyhow::Result<()> {
    // A notification event first, then one event per response, each with an `id:` field.
    let upstream = full_upstream()
        .with_sse(true)
        .with_sse_event_per_response(true);
    let h = Harness::start(upstream, narrow_chain()).await?;
    let resp = h.post(&four_lists()).await?;
    let msgs = decode_messages(resp).await?;
    assert_eq!(msgs.len(), 5, "{msgs:?}");
    // The notification passes untouched, first.
    assert_eq!(msgs[0]["method"], "notifications/message");
    assert_narrow(&msgs);
    Ok(())
}

#[tokio::test]
async fn single_list_request_over_sse_is_filtered() -> anyhow::Result<()> {
    for per_response in [false, true] {
        let upstream = full_upstream()
            .with_sse(true)
            .with_sse_event_per_response(per_response);
        let h = Harness::start(upstream, narrow_chain()).await?;
        let resp = h.post(&req(1, "tools/list", json!({}))).await?;
        let msgs = decode_messages(resp).await?;
        let list = msgs.iter().find(|m| m["id"] == 1).unwrap();
        assert_eq!(names(&list["result"], "tools", "name"), vec!["read_file"]);
    }
    Ok(())
}

#[tokio::test]
async fn paginated_sse_list_keeps_cursor() -> anyhow::Result<()> {
    let upstream = full_upstream().with_sse(true).with_page_size(1);
    let h = Harness::start(upstream, narrow_chain()).await?;
    let resp = h.post(&req(1, "resources/list", json!({}))).await?;
    let msg = decode_single(resp).await?;
    assert_eq!(
        names(&msg["result"], "resources", "uri"),
        vec!["file:///public/a.txt"]
    );
    assert_eq!(msg["result"]["nextCursor"], "1");
    let resp = h
        .post(&req(2, "resources/list", json!({"cursor": "2"})))
        .await?;
    let msg = decode_single(resp).await?;
    // page three holds only the secret key
    assert_eq!(msg["result"]["resources"], json!([]));
    assert!(msg["result"].get("nextCursor").is_none());
    Ok(())
}

#[tokio::test]
async fn denied_call_and_list_in_one_sse_batch() -> anyhow::Result<()> {
    let upstream = full_upstream()
        .with_sse(true)
        .with_sse_event_per_response(true);
    let h = Harness::start(upstream, narrow_chain()).await?;
    let batch = json!([
        req(1, "tools/list", json!({})),
        json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
               "params":{"name":"delete_repo","arguments":{}}}),
    ]);
    let msgs = decode_messages(h.post(&batch).await?).await?;
    let denial = msgs.iter().find(|m| m["id"] == 9).unwrap();
    assert_eq!(denial["error"]["code"], -32003);
    let list = msgs.iter().find(|m| m["id"] == 1).unwrap();
    assert_eq!(names(&list["result"], "tools", "name"), vec!["read_file"]);
    assert!(h.upstream.recorded_calls().is_empty());
    Ok(())
}

/// An upstream that answers every POST with the given raw `Content-Type` and body chunks,
/// sent as separate stream items so that events are split across reads.
fn raw_upstream(content_type: &'static str, chunks: Vec<String>) -> axum::Router {
    use axum::body::{Body, Bytes};
    use axum::routing::post;
    axum::Router::new().route(
        "/mcp",
        post(move || {
            let chunks = chunks.clone();
            async move {
                let stream = futures_util::stream::iter(
                    chunks
                        .into_iter()
                        .map(|c| Ok::<_, std::io::Error>(Bytes::from(c))),
                );
                axum::response::Response::builder()
                    .header("content-type", content_type)
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
        }),
    )
}

#[tokio::test]
async fn sse_event_split_across_chunks_with_server_request_reusing_the_id() -> anyhow::Result<()> {
    // A server-initiated request that reuses id 1 (and carries a `result` of its own) must
    // not be mistaken for the response, and must not stop the real response being filtered.
    let tools = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[
        {"name":"read_file"},{"name":"delete_repo"}], "nextCursor":"c1"}})
    .to_string();
    let server_request = json!({"jsonrpc":"2.0","id":1,"method":"sampling/createMessage",
        "params":{}, "result":{"tools":[{"name":"delete_repo"}]}})
    .to_string();
    let chunks = vec![
        format!("event: message\ndata: {server_request}\n\nevent: mess"),
        "age\r\nid: 5\r\nda".to_owned(),
        format!("ta: {tools}\r"),
        "\n\r".to_owned(),
        "\n".to_owned(),
    ];
    let h =
        Harness::start_router(raw_upstream("text/event-stream", chunks), narrow_chain()).await?;
    let resp = h.post(&req(1, "tools/list", json!({}))).await?;
    let msgs = decode_messages(resp).await?;
    assert_eq!(msgs.len(), 2, "{msgs:?}");
    // the server's own request is untouched, its `result` member included
    assert_eq!(msgs[0]["method"], "sampling/createMessage");
    assert_eq!(msgs[0]["result"]["tools"][0]["name"], "delete_repo");
    // the response is filtered, cursor intact
    assert_eq!(
        names(&msgs[1]["result"], "tools", "name"),
        vec!["read_file"]
    );
    assert_eq!(msgs[1]["result"]["nextCursor"], "c1");
    Ok(())
}

#[tokio::test]
async fn upstream_body_that_cannot_be_filtered_fails_closed() -> anyhow::Result<()> {
    let tools = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"}]}});
    // wrong content type
    let h = Harness::start_router(
        raw_upstream("text/plain", vec![tools.to_string()]),
        narrow_chain(),
    )
    .await?;
    let resp = h.post(&req(1, "tools/list", json!({}))).await?;
    assert_eq!(resp.status(), 502);
    assert!(!resp.text().await?.contains("delete_repo"));

    // JSON content type, broken body
    let h = Harness::start_router(
        raw_upstream("application/json", vec!["{\"tools\": [delete_repo".into()]),
        narrow_chain(),
    )
    .await?;
    let resp = h.post(&req(1, "resources/list", json!({}))).await?;
    assert_eq!(resp.status(), 502);
    assert!(!resp.text().await?.contains("delete_repo"));
    Ok(())
}

#[tokio::test]
async fn sse_stream_with_unterminated_final_event_does_not_leak_it() -> anyhow::Result<()> {
    let leak = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_repo"}]}});
    let h = Harness::start_router(
        raw_upstream("text/event-stream", vec![format!("data: {leak}\n")]),
        narrow_chain(),
    )
    .await?;
    let resp = h.post(&req(1, "tools/list", json!({}))).await?;
    let text = resp.text().await?;
    assert!(!text.contains("delete_repo"), "{text}");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Notifications carry no data: a `result` smuggled into one changes nothing
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn list_changed_notifications_pass_through_without_a_body() -> anyhow::Result<()> {
    let h = Harness::start(full_upstream(), narrow_chain()).await?;
    for method in [
        "notifications/tools/list_changed",
        "notifications/resources/list_changed",
        "notifications/prompts/list_changed",
        "notifications/resources/updated",
    ] {
        let resp = h.post(&json!({"jsonrpc": "2.0", "method": method})).await?;
        assert_eq!(resp.status(), 202, "{method}");
        assert!(resp.text().await?.is_empty(), "{method}");
    }
    assert_eq!(
        h.upstream.recorded_methods(),
        vec![
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed",
            "notifications/resources/updated",
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_result_smuggled_into_a_notification_is_not_a_list_response() -> anyhow::Result<()> {
    let leak = json!({"tools": [{"name": "delete_repo"}, {"name": "read_file"}]});
    for sse in [false, true] {
        let h = Harness::start(full_upstream().with_sse(sse), narrow_chain()).await?;

        // 1. A bare notification with a `result`: forwarded as the notification it is; nothing
        //    comes back.
        let resp = h
            .post(
                &json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed",
                          "result": leak}),
            )
            .await?;
        assert_eq!(resp.status(), 202);
        assert!(resp.text().await?.is_empty());

        // 2. In a batch with a real `tools/list`, a notification that borrows its id and
        //    carries a `result` cannot replace or widen the filtered response, and neither
        //    can a response-shaped message (no method) for the same id.
        let batch = json!([
            req(1, "tools/list", json!({})),
            {"jsonrpc": "2.0", "id": 1, "method": "notifications/tools/list_changed",
             "result": leak},
            {"jsonrpc": "2.0", "id": 1, "result": leak},
        ]);
        let resp = h.post(&batch).await?;
        let msgs = decode_messages(resp).await?;
        let text = serde_json::to_string(&msgs)?;
        assert!(!text.contains("delete_repo"), "sse={sse}: {text}");
        let list = msgs
            .iter()
            .find(|m| m.get("result").is_some())
            .expect("the filtered list response");
        assert_eq!(names(&list["result"], "tools", "name"), vec!["read_file"]);
    }
    Ok(())
}

#[tokio::test]
async fn an_extra_result_member_does_not_skip_the_deny_path() -> anyhow::Result<()> {
    // A smuggled `result` on a request for a method that needs a decision is still decided.
    let h = Harness::start(full_upstream(), narrow_chain()).await?;
    let resp = h
        .post(&json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                      "params": {"name": "delete_repo", "arguments": {}},
                      "result": {"tools": []}}))
        .await?;
    let msg = decode_single(resp).await?;
    assert_eq!(msg["error"]["code"], -32003);
    assert!(h.upstream.recorded_calls().is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// List answers replayed on a resumed GET stream
// ---------------------------------------------------------------------------------------------

/// Read JSON-RPC messages from an open SSE body until `want` of them have arrived (the stream
/// itself stays open), flattening batches.
async fn read_messages(resp: reqwest::Response, want: usize) -> anyhow::Result<Vec<Value>> {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut out = Vec::new();
    loop {
        while let Some(end) = buf.find("\n\n") {
            let event: String = buf.drain(..end + 2).collect();
            let data: Vec<&str> = event
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(|l| l.strip_prefix(' ').unwrap_or(l))
                .collect();
            if !data.is_empty() {
                match serde_json::from_str(&data.join("\n"))? {
                    Value::Array(items) => out.extend(items),
                    other => out.push(other),
                }
            }
        }
        if out.len() >= want {
            return Ok(out);
        }
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream ended after {out:?}"))??;
        buf.push_str(std::str::from_utf8(&chunk)?);
    }
}

/// The four list answers as a server would have buffered them for a `POST` stream that broke
/// off, unfiltered (two of them in one batch event), plus a server request that reuses an id
/// and carries a `result`.
fn replayed_lists() -> Vec<Value> {
    vec![
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "read_file"}, {"name": "delete_repo"}], "nextCursor": "c1"}}),
        json!({"jsonrpc": "2.0", "id": 9, "method": "sampling/createMessage", "params": {},
               "result": {"tools": [{"name": "delete_repo"}]}}),
        json!([
            {"jsonrpc": "2.0", "id": 2, "result": {"resources": [
                {"uri": "file:///public/a.txt"}, {"uri": "file:///public/b.txt"},
                {"uri": "file:///secret/key.pem"}]}},
            {"jsonrpc": "2.0", "id": 3, "result": {"resourceTemplates": [
                {"uriTemplate": "file:///public/{name}"},
                {"uriTemplate": "file:///secret/{name}"}]}},
        ]),
        json!({"jsonrpc": "2.0", "id": 4, "result": {"prompts": [
            {"name": "summarize"}, {"name": "review_pr"}, {"name": "deploy"}]}}),
    ]
}

/// A client whose `POST` stream broke off resumes it with `GET` and `Last-Event-ID`, and the
/// upstream replays the buffered list answers there. They reach the client filtered exactly
/// like the answers of the `POST` itself, batches included; a server request that carries a
/// `result` is left alone.
#[tokio::test]
async fn list_answers_replayed_on_a_resumed_get_stream_are_filtered() -> anyhow::Result<()> {
    let h = Harness::start(
        full_upstream().with_replay(replayed_lists()),
        narrow_chain(),
    )
    .await?;
    let init = h
        .post(&req(
            0,
            "initialize",
            json!({"protocolVersion": "2025-06-18"}),
        ))
        .await?;
    let sid = init.headers()["mcp-session-id"].to_str()?.to_owned();
    let resp = h
        .client
        .get(h.proxy.url(&format!("/mcp/{SERVER}")))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &sid)
        .header("last-event-id", "0")
        .bearer_auth(TOKEN)
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    // The listening notification, then the five replayed messages.
    let msgs = read_messages(resp, 6).await?;
    assert_eq!(h.upstream.last_event_ids(), vec!["0"]);
    assert_eq!(msgs[0]["method"], "notifications/message");
    let responses: Vec<Value> = msgs
        .iter()
        .filter(|m| m.get("method").is_none())
        .cloned()
        .collect();
    let text = serde_json::to_string(&responses)?;
    for hidden in ["delete_repo", "secret/key.pem", "review_pr", "deploy"] {
        assert!(!text.contains(hidden), "{hidden} in {text}");
    }
    assert_narrow(&responses);
    assert_eq!(responses[0]["result"]["nextCursor"], "c1");
    // The server's own request is untouched, its `result` member included.
    let server_request = msgs.iter().find(|m| m["id"] == 9).unwrap();
    assert_eq!(server_request["result"]["tools"][0]["name"], "delete_repo");
    Ok(())
}

/// An upstream that answers `GET` with `status`, `content_type` and `body`.
fn get_upstream(status: u16, content_type: &'static str, body: String) -> axum::Router {
    axum::Router::new().route(
        "/mcp",
        axum::routing::get(move || {
            let body = body.clone();
            async move {
                axum::response::Response::builder()
                    .status(status)
                    .header("content-type", content_type)
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        }),
    )
}

async fn get_listen(h: &Harness) -> anyhow::Result<reqwest::Response> {
    Ok(h.client
        .get(h.proxy.url(&format!("/mcp/{SERVER}")))
        .header("accept", "text/event-stream")
        .bearer_auth(TOKEN)
        .send()
        .await?)
}

/// MCP answers a `GET` with an SSE stream or `405`. A success answer that is not SSE would
/// reach the client without the list filter (here an unfiltered `tools/list` answer in a JSON
/// body), so the proxy refuses it with `502` `upstream_not_event_stream` and relays none of
/// it, whatever the success status.
#[tokio::test]
async fn a_get_answered_without_an_event_stream_is_refused() -> anyhow::Result<()> {
    let tools = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "read_file"}, {"name": "delete_repo"}]}})
    .to_string();
    for (status, content_type) in [
        (200, "application/json"),
        (200, "text/plain"),
        (202, "application/json"),
    ] {
        let up = get_upstream(status, content_type, tools.clone());
        let h = Harness::start_router(up, narrow_chain()).await?;
        let resp = get_listen(&h).await?;
        assert_eq!(resp.status(), 502, "{status} {content_type}");
        let body: Value = resp.json().await?;
        assert_eq!(body["error"]["code"], -32005, "{body}");
        assert_eq!(
            body["error"]["data"]["reason"],
            attenuo_proxy::REASON_UPSTREAM_NOT_EVENT_STREAM
        );
        assert!(!body.to_string().contains("delete_repo"), "{body}");
    }
    Ok(())
}

/// `405` (no listen stream) and error answers are relayed as before, and an SSE stream whose
/// content type carries parameters is still a listen stream, filtered.
#[tokio::test]
async fn a_get_answered_with_405_or_an_error_is_relayed() -> anyhow::Result<()> {
    for status in [405, 404, 500] {
        let up = get_upstream(status, "text/plain", "no".into());
        let h = Harness::start_router(up, narrow_chain()).await?;
        let resp = get_listen(&h).await?;
        assert_eq!(resp.status(), status);
        assert_eq!(resp.text().await?, "no");
    }
    let tools = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "read_file"}, {"name": "delete_repo"}]}});
    let up = get_upstream(
        200,
        "text/event-stream; charset=utf-8",
        format!("event: message\ndata: {tools}\n\n"),
    );
    let h = Harness::start_router(up, narrow_chain()).await?;
    let resp = get_listen(&h).await?;
    assert_eq!(resp.status(), 200);
    let msgs = read_messages(resp, 1).await?;
    assert_eq!(
        names(&msgs[0]["result"], "tools", "name"),
        vec!["read_file"]
    );
    Ok(())
}

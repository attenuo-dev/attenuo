//! Filtering of `tools/list`, `resources/list`, `resources/templates/list` and `prompts/list`
//! results: plain JSON bodies, pagination, JSON-RPC batches, SSE streams, and the rule that a
//! notification can never be turned into a result.

use std::sync::Arc;

use onbehalf_core::{ArgConstraint, Capability, DelegationChain};
use onbehalf_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use onbehalf_proxy::{router, ProxyConfig, UpstreamConfig};
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

//! `[proxy] list_filter = "policy"` (ADR-0011): after the capability filter, `tools/list`
//! entries go through `Authorizer::screen_tools`, in JSON bodies, batches, SSE answers and on
//! the `GET` listen stream. The default mode never asks. Hidden tools are still learned for
//! `require_listed_tools` and are decided as usual when called.

use std::sync::Arc;

use attenuo_core::{Capability, DelegationChain};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ListFilterMode, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};

const SERVER: &str = "github";
const TOKEN: &str = "tok";
const TOOLS: &[&str] = &["read_file", "create_issue", "update_issue", "delete_repo"];

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    proxy: Spawned,
    client: reqwest::Client,
    auth: Arc<StaticAuthorizer>,
}

impl Harness {
    async fn start(
        upstream: FakeMcpServer,
        chain: DelegationChain,
        mode: ListFilterMode,
    ) -> anyhow::Result<Self> {
        let upstream_task = upstream.spawn().await?;
        let auth = Arc::new(
            StaticAuthorizer::new()
                .with_chain(TOKEN, chain)
                .with_hidden_tools(&["update_issue", "delete_repo"]),
        );
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, upstream_task.url("/mcp"))],
        )
        .with_list_filter(mode);
        let proxy = spawn_router(router(config, auth.clone())).await?;
        Ok(Self {
            upstream,
            _upstream_task: upstream_task,
            proxy,
            client: reqwest::Client::new(),
            auth,
        })
    }

    async fn post(&self, body: &Value) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .client
            .post(self.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .bearer_auth(TOKEN)
            .body(body.to_string())
            .send()
            .await?;
        assert_eq!(resp.status(), 200);
        decode_messages(resp).await
    }
}

fn req(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

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

fn tool_names(msg: &Value) -> Vec<String> {
    msg["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("no tools in {msg}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

fn wide() -> DelegationChain {
    test_chain("user:a", "agent:a", [Capability::new(SERVER, "*")])
}

#[tokio::test]
async fn list_filter_defaults_to_capabilities_and_never_screens() -> anyhow::Result<()> {
    assert_eq!(
        ProxyConfig::new("127.0.0.1:0".parse()?, vec![]).list_filter,
        ListFilterMode::Capabilities
    );
    let h = Harness::start(
        FakeMcpServer::new(TOOLS),
        wide(),
        ListFilterMode::Capabilities,
    )
    .await?;
    let msgs = h.post(&req(1, "tools/list", json!({}))).await?;
    assert_eq!(tool_names(&msgs[0]), TOOLS);
    assert!(h.auth.screens().is_empty());
    Ok(())
}

#[tokio::test]
async fn policy_mode_hides_screened_tools_in_json_and_sse_answers() -> anyhow::Result<()> {
    for sse in [false, true] {
        let h = Harness::start(
            FakeMcpServer::new(TOOLS).with_sse(sse),
            wide(),
            ListFilterMode::Policy,
        )
        .await?;
        let msgs = h.post(&req(1, "tools/list", json!({}))).await?;
        assert_eq!(
            tool_names(&msgs[0]),
            vec!["read_file", "create_issue"],
            "sse {sse}"
        );
        assert_eq!(
            h.auth.screens().len(),
            1,
            "one screen per answer, sse {sse}"
        );
    }
    Ok(())
}

/// The screen sees only what the capability filter kept, and only `tools/list` answers of
/// a batch; the other lists of the batch are untouched by it.
#[tokio::test]
async fn policy_mode_screens_after_the_capability_filter_and_only_tools() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:a",
        "agent:a",
        [
            Capability::new(SERVER, "read_file"),
            Capability::new(SERVER, "update_issue"),
            Capability::new(SERVER, "prompts/get"),
        ],
    );
    for sse in [false, true] {
        let h = Harness::start(
            FakeMcpServer::new(TOOLS)
                .with_prompts(&["update_issue"])
                .with_sse(sse),
            chain.clone(),
            ListFilterMode::Policy,
        )
        .await?;
        let msgs = h
            .post(&json!([
                req(1, "tools/list", json!({})),
                req(2, "prompts/list", json!({}))
            ]))
            .await?;
        let tools = msgs.iter().find(|m| m["id"] == 1).unwrap();
        let prompts = msgs.iter().find(|m| m["id"] == 2).unwrap();
        assert_eq!(tool_names(tools), vec!["read_file"], "sse {sse}");
        assert_eq!(prompts["result"]["prompts"][0]["name"], "update_issue");
        assert_eq!(
            h.auth.screens(),
            vec![vec!["read_file".to_string(), "update_issue".to_string()]],
            "sse {sse}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn policy_mode_screens_replayed_answers_on_the_listen_stream() -> anyhow::Result<()> {
    use futures_util::StreamExt;
    let replay = vec![json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "read_file"}, {"name": "delete_repo"}], "nextCursor": "c1"}})];
    let h = Harness::start(
        FakeMcpServer::new(TOOLS).with_replay(replay),
        wide(),
        ListFilterMode::Policy,
    )
    .await?;
    let init = h
        .client
        .post(h.proxy.url(&format!("/mcp/{SERVER}")))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .bearer_auth(TOKEN)
        .body(req(0, "initialize", json!({"protocolVersion": "2025-06-18"})).to_string())
        .send()
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
    let mut stream = resp.bytes_stream();
    let mut text = String::new();
    while !text.contains("nextCursor") {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream ended: {text}"))??;
        text.push_str(std::str::from_utf8(&chunk)?);
    }
    assert!(text.contains("read_file"), "{text}");
    assert!(!text.contains("delete_repo"), "{text}");
    // The event keeps its `id:` line, so the client can resume after it.
    assert!(text.lines().any(|l| l.starts_with("id:")), "{text}");
    Ok(())
}

/// Hiding is not enforcement: a hidden tool's name was still learned for
/// `require_listed_tools`, and calling it reaches a decision, recorded as any call is.
#[tokio::test]
async fn hidden_tools_are_still_routed_to_a_decision() -> anyhow::Result<()> {
    let h = Harness::start(FakeMcpServer::new(TOOLS), wide(), ListFilterMode::Policy).await?;
    let msgs = h.post(&req(1, "tools/list", json!({}))).await?;
    assert!(!tool_names(&msgs[0]).contains(&"update_issue".to_string()));
    let msgs = h
        .post(&req(
            2,
            "tools/call",
            json!({"name": "update_issue", "arguments": {}}),
        ))
        .await?;
    assert!(msgs[0].get("result").is_some(), "{:?}", msgs[0]);
    let decisions = h.auth.decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].tool, "update_issue");
    assert_eq!(h.upstream.recorded_calls().len(), 1);
    Ok(())
}

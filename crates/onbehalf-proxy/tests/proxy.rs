//! End-to-end tests: a real proxy in front of a real (fake) MCP server, over TCP.

use std::sync::Arc;

use onbehalf_core::{ArgConstraint, Capability, DelegationChain};
use onbehalf_proxy::jsonrpc::{CODE_DENIED, CODE_UNAUTHORIZED, CODE_UNKNOWN_SERVER};
use onbehalf_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use onbehalf_proxy::{router, ProxyConfig, UpstreamConfig, DECISION_ID_HEADER};
use serde_json::{json, Value};

const SERVER: &str = "github";

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
    client: reqwest::Client,
}

impl Harness {
    async fn start(
        tools: &[&str],
        sse: bool,
        chains: Vec<(&str, DelegationChain)>,
    ) -> anyhow::Result<Self> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let upstream = FakeMcpServer::new(tools).with_sse(sse);
        let upstream_task = upstream.spawn().await?;
        let mut authorizer = StaticAuthorizer::new();
        for (bearer, chain) in chains {
            authorizer.insert(bearer, chain);
        }
        let authorizer = Arc::new(authorizer);
        let config = ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, upstream_task.url("/mcp"))],
        );
        let proxy = spawn_router(router(config, authorizer.clone())).await?;
        Ok(Self {
            upstream,
            _upstream_task: upstream_task,
            proxy,
            authorizer,
            client: reqwest::Client::new(),
        })
    }

    async fn post(
        &self,
        server: &str,
        bearer: Option<&str>,
        body: &Value,
    ) -> anyhow::Result<reqwest::Response> {
        let mut req = self
            .client
            .post(self.proxy.url(&format!("/mcp/{server}")))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-session-id", "client-session-42")
            .body(body.to_string());
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        Ok(req.send().await?)
    }

    async fn rpc(&self, bearer: Option<&str>, body: &Value) -> anyhow::Result<reqwest::Response> {
        self.post(SERVER, bearer, body).await
    }
}

fn tools_call(id: u64, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": args}})
}

fn reader_chain() -> DelegationChain {
    test_chain(
        "user:alice",
        "agent:reader",
        [Capability::new(SERVER, "read_*")],
    )
}

#[tokio::test]
async fn allowed_tools_call_is_forwarded_upstream() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    let resp = h
        .rpc(
            Some("tok"),
            &tools_call(1, "read_file", json!({"path": "README.md"})),
        )
        .await?;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key(DECISION_ID_HEADER));
    // session id from the upstream is preserved
    assert_eq!(
        resp.headers()["mcp-session-id"].to_str()?,
        h.upstream.session_id()
    );
    let body: Value = resp.json().await?;
    assert_eq!(body["id"], 1);
    assert!(body.get("error").is_none(), "{body}");
    let echoed: Value =
        serde_json::from_str(body["result"]["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(echoed["name"], "read_file");
    assert_eq!(echoed["arguments"]["path"], "README.md");

    let calls = h.upstream.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, "read_file");
    assert_eq!(calls[0].arguments, json!({"path": "README.md"}));
    // the client's session id reached the upstream
    assert_eq!(calls[0].session_id.as_deref(), Some("client-session-42"));
    Ok(())
}

#[tokio::test]
async fn denied_tools_call_returns_32003_and_never_reaches_upstream() -> anyhow::Result<()> {
    let h = Harness::start(
        &["read_file", "delete_repo"],
        false,
        vec![("tok", reader_chain())],
    )
    .await?;
    let resp = h
        .rpc(
            Some("tok"),
            &tools_call(9, "delete_repo", json!({"repo": "alice/site"})),
        )
        .await?;
    assert_eq!(resp.status(), 200);
    let decision_id = resp.headers()[DECISION_ID_HEADER].to_str()?.to_owned();
    let body: Value = resp.json().await?;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 9);
    assert_eq!(body["error"]["code"], CODE_DENIED);
    assert_eq!(
        body["error"]["message"],
        "onbehalf: denied: capability_denied"
    );
    assert_eq!(body["error"]["data"]["reason"], "capability_denied");
    assert_eq!(body["error"]["data"]["decision_id"], decision_id);
    assert!(h.upstream.recorded_calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn missing_or_invalid_token_is_401() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    let call = tools_call(1, "read_file", json!({}));

    let resp = h.rpc(None, &call).await?;
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("www-authenticate"));
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("missing bearer token"));

    let resp = h.rpc(Some("not-a-token"), &call).await?;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);

    // Even initialize is not forwarded without a token.
    let resp = h
        .rpc(
            None,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        )
        .await?;
    assert_eq!(resp.status(), 401);
    assert!(h.upstream.recorded_calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn tools_list_is_filtered_to_permitted_tool_names() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:alice",
        "agent:reader",
        [
            Capability::new(SERVER, "read_*"),
            // constrained: must still be listed, because some arguments would be permitted
            Capability::new(SERVER, "create_issue")
                .with_constraint("repo", ArgConstraint::Prefix("alice/".into())),
        ],
    );
    let h = Harness::start(
        &[
            "read_file",
            "read_dir",
            "create_issue",
            "delete_repo",
            "write_file",
        ],
        false,
        vec![("tok", chain)],
    )
    .await?;
    let resp = h
        .rpc(
            Some("tok"),
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
        )
        .await?;
    assert_eq!(resp.status(), 200);
    assert!(!resp.headers().contains_key(DECISION_ID_HEADER));
    let body: Value = resp.json().await?;
    let names: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["read_file", "read_dir", "create_issue"]);
    Ok(())
}

#[tokio::test]
async fn batch_with_one_allowed_and_one_denied() -> anyhow::Result<()> {
    let h = Harness::start(
        &["read_file", "delete_repo"],
        false,
        vec![("tok", reader_chain())],
    )
    .await?;
    let batch = json!([
        tools_call(1, "read_file", json!({"path": "a"})),
        tools_call(2, "delete_repo", json!({"repo": "x"})),
        {"jsonrpc":"2.0","method":"notifications/progress","params":{}}
    ]);
    let resp = h.rpc(Some("tok"), &batch).await?;
    assert_eq!(resp.status(), 200);
    let ids: Vec<String> = resp.headers()[DECISION_ID_HEADER]
        .to_str()?
        .split(',')
        .map(str::to_owned)
        .collect();
    assert_eq!(ids.len(), 2);
    let body: Value = resp.json().await?;
    let items = body.as_array().expect("batch response is an array");
    assert_eq!(items.len(), 2, "{body}");
    let by_id = |id: u64| items.iter().find(|r| r["id"] == id).cloned().unwrap();
    assert!(by_id(1).get("result").is_some());
    assert_eq!(by_id(2)["error"]["code"], CODE_DENIED);
    assert_eq!(by_id(2)["error"]["data"]["decision_id"], ids[1]);

    let calls = h.upstream.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, "read_file");
    Ok(())
}

#[tokio::test]
async fn github_leak_scenario_repo_prefix_constraint() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:alice",
        "agent:summarizer",
        [Capability::new(SERVER, "read_file")
            .with_constraint("repo", ArgConstraint::Prefix("alice/public-".into()))],
    );
    let h = Harness::start(&["read_file"], false, vec![("tok", chain)]).await?;

    let denied = h
        .rpc(
            Some("tok"),
            &tools_call(
                1,
                "read_file",
                json!({"repo": "alice/private-salaries", "path": "2026.csv"}),
            ),
        )
        .await?;
    let body: Value = denied.json().await?;
    assert_eq!(body["error"]["code"], CODE_DENIED, "{body}");
    assert!(h.upstream.recorded_calls().is_empty());

    // a call without the constrained argument is also denied
    let denied = h
        .rpc(
            Some("tok"),
            &tools_call(2, "read_file", json!({"path": "x"})),
        )
        .await?;
    let body: Value = denied.json().await?;
    assert_eq!(body["error"]["code"], CODE_DENIED, "{body}");
    assert!(h.upstream.recorded_calls().is_empty());

    let allowed = h
        .rpc(
            Some("tok"),
            &tools_call(
                3,
                "read_file",
                json!({"repo": "alice/public-site", "path": "index.html"}),
            ),
        )
        .await?;
    let body: Value = allowed.json().await?;
    assert!(body.get("error").is_none(), "{body}");
    let calls = h.upstream.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].arguments["repo"], "alice/public-site");
    Ok(())
}

#[tokio::test]
async fn decision_ids_are_returned_in_header_and_recorded() -> anyhow::Result<()> {
    let h = Harness::start(
        &["read_file", "delete_repo"],
        false,
        vec![("tok", reader_chain())],
    )
    .await?;
    let allowed = h
        .rpc(Some("tok"), &tools_call(1, "read_file", json!({})))
        .await?;
    let allowed_id = allowed.headers()[DECISION_ID_HEADER].to_str()?.to_owned();
    let denied = h
        .rpc(Some("tok"), &tools_call(2, "delete_repo", json!({})))
        .await?;
    let denied_id = denied.headers()[DECISION_ID_HEADER].to_str()?.to_owned();
    assert_ne!(allowed_id, denied_id);

    let records = h.authorizer.decisions();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].id.to_string(), allowed_id);
    assert!(records[0].decision.is_allow());
    assert_eq!(records[0].reason, StaticAuthorizer::REASON_ALLOW);
    assert_eq!(records[0].server, SERVER);
    assert_eq!(records[0].tool, "read_file");
    assert_eq!(records[0].originating_subject, "user:alice");
    assert_eq!(records[0].agents[0].0, "agent:reader");
    assert_eq!(records[0].session_id.as_deref(), Some("client-session-42"));
    assert_eq!(records[1].id.to_string(), denied_id);
    assert!(!records[1].decision.is_allow());
    assert_eq!(records[1].reason, StaticAuthorizer::REASON_DENY);
    assert_eq!(records[1].tool, "delete_repo");
    Ok(())
}

#[tokio::test]
async fn initialize_and_notifications_pass_through() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    let resp = h
        .rpc(
            Some("tok"),
            &json!({"jsonrpc":"2.0","id":0,"method":"initialize",
                    "params":{"protocolVersion":"2025-03-26","capabilities":{},
                              "clientInfo":{"name":"t","version":"0"}}}),
        )
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["mcp-session-id"].to_str()?,
        h.upstream.session_id()
    );
    let body: Value = resp.json().await?;
    assert_eq!(body["result"]["serverInfo"]["name"], "fake-mcp");

    let resp = h
        .rpc(
            Some("tok"),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await?;
    assert_eq!(resp.status(), 202);
    Ok(())
}

#[tokio::test]
async fn sse_responses_are_streamed_through() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], true, vec![("tok", reader_chain())]).await?;
    let resp = h
        .rpc(
            Some("tok"),
            &tools_call(1, "read_file", json!({"path": "a"})),
        )
        .await?;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()["content-type"]
        .to_str()?
        .starts_with("text/event-stream"));
    assert!(resp.headers().contains_key(DECISION_ID_HEADER));
    let text = resp.text().await?;
    assert!(text.starts_with("event: message\ndata: "), "{text}");
    let data: Value =
        serde_json::from_str(text.lines().nth(1).unwrap().trim_start_matches("data: "))?;
    assert_eq!(data["id"], 1);
    assert!(data.get("result").is_some());

    // tools/list over SSE: passed through unfiltered (documented v0 limitation)
    let resp = h
        .rpc(
            Some("tok"),
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await?;
    assert!(resp.headers()["content-type"]
        .to_str()?
        .starts_with("text/event-stream"));
    Ok(())
}

#[tokio::test]
async fn batch_partial_denial_over_sse_prepends_denial_events() -> anyhow::Result<()> {
    let h = Harness::start(
        &["read_file", "delete_repo"],
        true,
        vec![("tok", reader_chain())],
    )
    .await?;
    let batch = json!([
        tools_call(1, "read_file", json!({})),
        tools_call(2, "delete_repo", json!({})),
    ]);
    let resp = h.rpc(Some("tok"), &batch).await?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().await?;
    let events: Vec<Value> = text
        .split("\n\n")
        .filter(|e| !e.trim().is_empty())
        .map(|e| {
            let data = e.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
            serde_json::from_str(data).unwrap()
        })
        .collect();
    assert_eq!(events.len(), 2, "{text}");
    assert_eq!(events[0]["id"], 2);
    assert_eq!(events[0]["error"]["code"], CODE_DENIED);
    let upstream_batch = events[1].as_array().unwrap();
    assert_eq!(upstream_batch.len(), 1);
    assert_eq!(upstream_batch[0]["id"], 1);
    assert_eq!(h.upstream.recorded_calls().len(), 1);
    Ok(())
}

#[tokio::test]
async fn unknown_server_is_404_and_bad_json_is_400() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    let resp = h
        .post("nope", Some("tok"), &tools_call(1, "read_file", json!({})))
        .await?;
    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNKNOWN_SERVER);

    let resp = h
        .client
        .post(h.proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("tok")
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await?;
    assert_eq!(resp.status(), 400);

    // tools/call without a name is rejected locally with invalid params
    let resp = h
        .rpc(
            Some("tok"),
            &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}),
        )
        .await?;
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], -32602);
    assert!(h.upstream.recorded_calls().is_empty());
    Ok(())
}

#[tokio::test]
async fn expired_chain_is_rejected_at_authentication() -> anyhow::Result<()> {
    use onbehalf_core::{AgentId, CapabilitySet, LeaseId};
    let expired = DelegationChain::root(
        onbehalf_proxy::testing::test_user("user:alice"),
        AgentId::new("agent:old"),
        CapabilitySet::from_iter([Capability::new(SERVER, "*")]),
        time::OffsetDateTime::now_utc() - time::Duration::hours(2),
        time::Duration::hours(1),
        LeaseId::new("l"),
    )?;
    let h = Harness::start(&["read_file"], false, vec![("tok", expired)]).await?;
    let resp = h
        .rpc(Some("tok"), &tools_call(1, "read_file", json!({})))
        .await?;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await?;
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("expired"));
    Ok(())
}

//! End-to-end tests: a real proxy in front of a real (fake) MCP server, over TCP.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use attenuo_core::{ArgConstraint, Capability, DelegationChain, ManualClock};
use attenuo_proxy::jsonrpc::{CODE_DENIED, CODE_UNAUTHORIZED, CODE_UNKNOWN_SERVER};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{router_with_clock, ProxyConfig, UpstreamConfig, DECISION_ID_HEADER};
use serde_json::{json, Value};

const SERVER: &str = "github";

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
    /// The proxy's clock: [`ManualClock::advance`] steps past a TTL or a window.
    clock: Arc<ManualClock>,
    client: reqwest::Client,
    /// The `Mcp-Session-Id` each bearer was given, sent back on its later requests like an MCP
    /// client would.
    sessions: Mutex<HashMap<String, String>>,
}

impl Harness {
    async fn start(
        tools: &[&str],
        sse: bool,
        chains: Vec<(&str, DelegationChain)>,
    ) -> anyhow::Result<Self> {
        Self::start_with(tools, sse, chains, |c| c).await
    }

    async fn start_with(
        tools: &[&str],
        sse: bool,
        chains: Vec<(&str, DelegationChain)>,
        configure: impl FnOnce(ProxyConfig) -> ProxyConfig,
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
        let config = configure(ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, upstream_task.url("/mcp"))],
        ));
        let clock = ManualClock::new();
        let proxy =
            spawn_router(router_with_clock(config, authorizer.clone(), clock.clone())).await?;
        Ok(Self {
            upstream,
            _upstream_task: upstream_task,
            proxy,
            authorizer,
            clock,
            client: reqwest::Client::new(),
            sessions: Mutex::default(),
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
            .body(body.to_string());
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
            if let Some(sid) = self.sessions.lock().unwrap().get(b) {
                req = req.header("mcp-session-id", sid);
            }
        }
        let resp = req.send().await?;
        if let (Some(b), Some(sid)) = (bearer, resp.headers().get("mcp-session-id")) {
            if resp.status().is_success() {
                self.sessions
                    .lock()
                    .unwrap()
                    .insert(b.to_owned(), sid.to_str()?.to_owned());
            }
        }
        Ok(resp)
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
    assert_eq!(calls[0].session_id, None);

    // The client sends the session id back; it reaches the upstream unchanged.
    let resp = h
        .rpc(Some("tok"), &tools_call(2, "read_file", json!({})))
        .await?;
    assert_eq!(resp.status(), 200);
    let calls = h.upstream.recorded_calls();
    assert_eq!(
        calls[1].session_id.as_deref(),
        Some(h.upstream.session_id())
    );
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
        "attenuo: denied: capability_denied"
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
    assert_eq!(body["error"]["data"]["reason"], "missing_token");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("missing_token"));

    let resp = h.rpc(Some("not-a-token"), &call).await?;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);
    // Only the reason code: the verifier's own words stay in the log (SR-17).
    assert_eq!(body["error"]["data"]["reason"], "invalid_token");
    assert_eq!(
        body["error"]["message"],
        "attenuo: unauthorized: invalid_token"
    );

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
    // The first call had no session; the second carried the one the upstream assigned, and
    // the record holds its hash prefix, never the id itself (SR-11).
    assert_eq!(records[0].session_id, None);
    assert_eq!(
        records[1].session_id.as_deref(),
        Some(attenuo_proxy::session::session_tag(h.upstream.session_id()).as_str())
    );
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

    // tools/list over SSE is still an SSE stream (filtering is covered in list_filtering.rs)
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
    use attenuo_core::{AgentId, CapabilitySet, LeaseId};
    let expired = DelegationChain::root(
        attenuo_proxy::testing::test_user("user:alice"),
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
    assert_eq!(body["error"]["data"]["reason"], "token_expired");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("expired"));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Coverage beyond tools/call
// ---------------------------------------------------------------------------------------------

fn rpc_msg(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn resource_reader_chain() -> DelegationChain {
    test_chain(
        "user:alice",
        "agent:reader",
        [Capability::new(SERVER, "resources/read")
            .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into()))],
    )
}

#[tokio::test]
async fn resources_read_allow_and_deny_by_uri() -> anyhow::Result<()> {
    let h = Harness::start(
        &["read_file"],
        false,
        vec![("tok", resource_reader_chain())],
    )
    .await?;

    let ok = h
        .rpc(
            Some("tok"),
            &rpc_msg(1, "resources/read", json!({"uri": "file:///public/a.txt"})),
        )
        .await?;
    assert_eq!(ok.status(), 200);
    assert!(ok.headers().contains_key(DECISION_ID_HEADER));
    let body: Value = ok.json().await?;
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["result"]["contents"][0]["uri"], "file:///public/a.txt");

    let no = h
        .rpc(
            Some("tok"),
            &rpc_msg(2, "resources/read", json!({"uri": "file:///etc/passwd"})),
        )
        .await?;
    let body: Value = no.json().await?;
    assert_eq!(body["error"]["code"], CODE_DENIED, "{body}");
    assert_eq!(body["error"]["data"]["reason"], "capability_denied");

    // Only the allowed read reached the upstream; both were decided and recorded.
    assert_eq!(h.upstream.recorded_methods(), vec!["resources/read"]);
    let decisions = h.authorizer.decisions();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].tool, "resources/read");
    assert_eq!(decisions[1].tool, "resources/read");
    Ok(())
}

#[tokio::test]
async fn resources_subscribe_is_authorized_and_requires_uri() -> anyhow::Result<()> {
    let chain = test_chain(
        "user:alice",
        "agent:sub",
        [Capability::new(SERVER, "resources/subscribe")],
    );
    let h = Harness::start(&[], false, vec![("tok", chain), ("reader", reader_chain())]).await?;
    let ok = h
        .rpc(
            Some("tok"),
            &rpc_msg(1, "resources/subscribe", json!({"uri": "file:///x"})),
        )
        .await?;
    assert!(ok.json::<Value>().await?.get("error").is_none());
    let no = h
        .rpc(
            Some("reader"),
            &rpc_msg(2, "resources/subscribe", json!({"uri": "file:///x"})),
        )
        .await?;
    assert_eq!(no.json::<Value>().await?["error"]["code"], CODE_DENIED);
    let bad = h
        .rpc(Some("tok"), &rpc_msg(3, "resources/subscribe", json!({})))
        .await?;
    assert_eq!(bad.json::<Value>().await?["error"]["code"], -32602);
    assert_eq!(h.upstream.recorded_methods(), vec!["resources/subscribe"]);
    Ok(())
}

#[tokio::test]
async fn prompts_get_is_denied_without_capability_and_allowed_with_one() -> anyhow::Result<()> {
    let prompter = test_chain(
        "user:alice",
        "agent:prompter",
        [Capability::new(SERVER, "prompts/get")
            .with_constraint("name", ArgConstraint::Prefix("safe-".into()))],
    );
    let h = Harness::start(
        &["read_file"],
        false,
        vec![("reader", reader_chain()), ("prompter", prompter)],
    )
    .await?;
    let call = rpc_msg(
        1,
        "prompts/get",
        json!({"name": "safe-summary", "arguments": {"topic": "x"}}),
    );

    // `read_*` on the server does not cover a prompt.
    let denied = h.rpc(Some("reader"), &call).await?;
    let body: Value = denied.json().await?;
    assert_eq!(body["error"]["code"], CODE_DENIED, "{body}");
    assert!(h.upstream.recorded_methods().is_empty());

    let ok = h.rpc(Some("prompter"), &call).await?;
    assert!(ok.json::<Value>().await?.get("error").is_none());
    let wrong_name = h
        .rpc(
            Some("prompter"),
            &rpc_msg(2, "prompts/get", json!({"name": "admin-reset"})),
        )
        .await?;
    assert_eq!(
        wrong_name.json::<Value>().await?["error"]["code"],
        CODE_DENIED
    );
    assert_eq!(h.upstream.recorded_methods(), vec!["prompts/get"]);

    // The decision saw the mapped tool name and arguments.
    let rec = &h.authorizer.decisions()[0];
    assert_eq!(rec.tool, "prompts/get");
    assert_eq!(
        rec.arguments_digest,
        attenuo_core::ToolCall::new(
            SERVER,
            "prompts/get",
            json!({"name": "safe-summary", "arguments": {"topic": "x"}})
        )
        .arguments_digest()
    );
    Ok(())
}

#[tokio::test]
async fn completion_complete_is_authorized() -> anyhow::Result<()> {
    let h = Harness::start(&[], false, vec![("reader", reader_chain())]).await?;
    let resp = h
        .rpc(
            Some("reader"),
            &rpc_msg(
                1,
                "completion/complete",
                json!({"ref": {"type": "ref/prompt", "name": "p"},
                       "argument": {"name": "a", "value": "x"}}),
            ),
        )
        .await?;
    assert_eq!(resp.json::<Value>().await?["error"]["code"], CODE_DENIED);
    assert!(h.upstream.recorded_methods().is_empty());
    Ok(())
}

#[tokio::test]
async fn unknown_methods_are_denied_by_default() -> anyhow::Result<()> {
    let h = Harness::start(
        &["read_file"],
        false,
        vec![
            ("reader", reader_chain()),
            (
                "sampler",
                test_chain(
                    "user:alice",
                    "agent:sampler",
                    [Capability::new(SERVER, "sampling/createMessage")],
                ),
            ),
        ],
    )
    .await?;
    for method in ["sampling/createMessage", "vendor/exfiltrate", "tools/typo"] {
        let resp = h
            .rpc(Some("reader"), &rpc_msg(1, method, json!({"x": 1})))
            .await?;
        let body: Value = resp.json().await?;
        assert_eq!(body["error"]["code"], CODE_DENIED, "{method}: {body}");
    }
    assert!(h.upstream.recorded_methods().is_empty());
    assert_eq!(h.authorizer.decisions()[0].tool, "sampling/createMessage");

    // An explicit capability opts a method in (the fake upstream then answers -32601).
    let resp = h
        .rpc(
            Some("sampler"),
            &rpc_msg(2, "sampling/createMessage", json!({})),
        )
        .await?;
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], -32601, "{body}");
    assert_eq!(
        h.upstream.recorded_methods(),
        vec!["sampling/createMessage"]
    );
    Ok(())
}

#[tokio::test]
async fn allowlisted_methods_and_notifications_still_pass() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    for (i, method) in ["initialize", "ping", "tools/list"].iter().enumerate() {
        let resp = h
            .rpc(Some("tok"), &rpc_msg(i as u64, method, json!({})))
            .await?;
        assert_eq!(resp.status(), 200, "{method}");
        assert!(resp.json::<Value>().await?.get("error").is_none());
    }
    let resp = h
        .rpc(
            Some("tok"),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await?;
    assert_eq!(resp.status(), 202);
    assert!(h.authorizer.decisions().is_empty(), "no per-call decisions");
    Ok(())
}

#[tokio::test]
async fn revoked_token_cannot_list_tools_or_use_session_requests() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    let list = rpc_msg(1, "tools/list", json!({}));
    assert_eq!(h.rpc(Some("tok"), &list).await?.status(), 200);

    h.authorizer.revoke("tok");

    let resp = h.rpc(Some("tok"), &list).await?;
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("lease_revoked"));

    // Other allowlisted methods too.
    let resp = h.rpc(Some("tok"), &rpc_msg(2, "ping", json!({}))).await?;
    assert_eq!(resp.status(), 401);

    // GET (listen stream) and DELETE (end session) are checked as well.
    for method in [reqwest::Method::GET, reqwest::Method::DELETE] {
        let resp = h
            .client
            .request(method.clone(), h.proxy.url(&format!("/mcp/{SERVER}")))
            .bearer_auth("tok")
            .send()
            .await?;
        assert_eq!(resp.status(), 401, "{method}");
    }

    // A batch mixing a decided call with a list: the call is denied (and recorded), the list
    // is refused, nothing reaches the upstream.
    let batch = json!([
        tools_call(3, "read_file", json!({})),
        rpc_msg(4, "tools/list", json!({}))
    ]);
    let resp = h.rpc(Some("tok"), &batch).await?;
    assert_eq!(resp.status(), 200);
    let items: Vec<Value> = resp.json().await?;
    let by_id = |id: u64| items.iter().find(|m| m["id"] == id).unwrap().clone();
    assert_eq!(by_id(3)["error"]["code"], CODE_DENIED);
    assert_eq!(by_id(4)["error"]["code"], CODE_UNAUTHORIZED);
    assert_eq!(h.upstream.recorded_methods(), vec!["tools/list"]);
    Ok(())
}

/// A client that opens a session per call (LangChain's MCP adapter) meets revocation at
/// `initialize`, not at a `tools/call`. The refusal is recorded once per request under a fixed
/// name, and the 401 names the record; a token that does not verify records nothing.
#[tokio::test]
async fn refused_session_opens_on_a_revoked_lease_are_recorded() -> anyhow::Result<()> {
    let h = Harness::start(&["read_file"], false, vec![("tok", reader_chain())]).await?;
    h.authorizer.revoke("tok");
    let init = rpc_msg(
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "t", "version": "0"}}),
    );

    let resp = h.rpc(Some("tok"), &init).await?;
    assert_eq!(resp.status(), 401);
    let header = resp.headers()[DECISION_ID_HEADER].to_str()?.to_owned();
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);
    assert_eq!(body["error"]["data"]["reason"], "lease_revoked");
    assert_eq!(body["error"]["data"]["decision_id"], header);

    let records = h.authorizer.decisions();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    assert_eq!(r.id.to_string(), header);
    assert_eq!(r.decision, attenuo_core::Decision::Deny);
    assert_eq!(r.reason, "lease_revoked");
    assert_eq!(r.server, SERVER);
    assert_eq!(r.tool, "initialize");
    assert_eq!(r.originating_subject, "user:alice");
    assert_eq!(
        r.agents,
        reader_chain()
            .hops
            .iter()
            .map(|h| h.agent.clone())
            .collect::<Vec<_>>()
    );

    // A batch of undecided messages is one request: one record, named in every reply.
    let batch = json!([
        rpc_msg(2, "ping", json!({})),
        rpc_msg(3, "tools/list", json!({}))
    ]);
    let resp = h.rpc(Some("tok"), &batch).await?;
    let items: Vec<Value> = resp.json().await?;
    assert_eq!(h.authorizer.decisions().len(), 2);
    let batch_id = h.authorizer.decisions()[1].id.to_string();
    assert_eq!(h.authorizer.decisions()[1].tool, "ping");
    for item in &items {
        assert_eq!(item["error"]["data"]["decision_id"], batch_id, "{item}");
    }

    // GET (listen stream) and DELETE (end session) are recorded as `http.<METHOD>`.
    for (method, tool) in [
        (reqwest::Method::GET, "http.GET"),
        (reqwest::Method::DELETE, "http.DELETE"),
    ] {
        let resp = h
            .client
            .request(method.clone(), h.proxy.url(&format!("/mcp/{SERVER}")))
            .bearer_auth("tok")
            .send()
            .await?;
        assert_eq!(resp.status(), 401, "{method}");
        let last = h.authorizer.decisions().last().cloned().unwrap();
        assert_eq!(last.tool, tool);
        assert_eq!(last.reason, "lease_revoked");
        assert_eq!(
            resp.headers()[DECISION_ID_HEADER].to_str()?,
            last.id.to_string()
        );
    }
    assert_eq!(h.authorizer.decisions().len(), 4);

    // A token that does not verify is unauthenticated noise: a 401, a log line, no record.
    for bearer in [
        "garbage",
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyOmFsaWNlIn0.",
    ] {
        let resp = h.rpc(Some(bearer), &init).await?;
        assert_eq!(resp.status(), 401);
        assert!(!resp.headers().contains_key(DECISION_ID_HEADER));
        let body: Value = resp.json().await?;
        assert_eq!(body["error"]["data"]["reason"], "invalid_token");
        assert!(body["error"]["data"].get("decision_id").is_none(), "{body}");
    }
    assert_eq!(h.authorizer.decisions().len(), 4);
    assert!(h.upstream.recorded_methods().is_empty());
    Ok(())
}

fn initialize_msg(id: u64) -> Value {
    rpc_msg(
        id,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "t", "version": "0"}}),
    )
}

/// The decision id a refused request's 401 names, from the header and the body, which agree.
async fn refusal_names(resp: reqwest::Response) -> anyhow::Result<String> {
    assert_eq!(resp.status(), 401);
    let header = resp.headers()[DECISION_ID_HEADER].to_str()?.to_owned();
    let body: Value = resp.json().await?;
    assert_eq!(body["error"]["code"], CODE_UNAUTHORIZED);
    assert_eq!(body["error"]["data"]["decision_id"], header, "{body}");
    Ok(header)
}

/// A client that keeps retrying `initialize` on a revoked lease is refused every time, but
/// only the first refusal per chain, tool and reason in the window is a record; the others are
/// counted as suppressed and their 401 names the first record. Another tool, another reason
/// and another chain each get their own record. Decided requests (`tools/call`) are never
/// bounded.
#[tokio::test]
async fn retried_session_opens_on_a_revoked_lease_leave_one_record_per_window() -> anyhow::Result<()>
{
    use attenuo_proxy::StreamEndCause;
    let bob = test_chain(
        "user:bob",
        "agent:reader",
        [Capability::new(SERVER, "read_*")],
    );
    let h = Harness::start(
        &["read_file"],
        false,
        vec![("tok", reader_chain()), ("bob", bob)],
    )
    .await?;
    h.authorizer.revoke("tok");
    const N: usize = 5;
    let mut named = Vec::new();
    for i in 0..N {
        named.push(refusal_names(h.rpc(Some("tok"), &initialize_msg(i as u64)).await?).await?);
    }
    let records = h.authorizer.decisions();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].tool, "initialize");
    assert_eq!(records[0].reason, "lease_revoked");
    assert!(
        named.iter().all(|id| *id == records[0].id.to_string()),
        "{named:?}"
    );
    assert_eq!(
        h.authorizer.suppressed_records(),
        vec![("initialize".to_owned(), StreamEndCause::LeaseRevoked); N - 1]
    );

    // Another tool of the same chain and reason: its own record, then bounded too.
    let list = rpc_msg(10, "tools/list", json!({}));
    let first_list = refusal_names(h.rpc(Some("tok"), &list).await?).await?;
    assert_eq!(
        refusal_names(h.rpc(Some("tok"), &list).await?).await?,
        first_list
    );
    let get = h
        .client
        .get(h.proxy.url(&format!("/mcp/{SERVER}")))
        .bearer_auth("tok")
        .send()
        .await?;
    let first_get = refusal_names(get).await?;
    let records = h.authorizer.decisions();
    assert_eq!(records.len(), 3, "{records:?}");
    assert_eq!(records[1].tool, "tools/list");
    assert_eq!(records[1].id.to_string(), first_list);
    assert_eq!(records[2].tool, "http.GET");
    assert_eq!(records[2].id.to_string(), first_get);

    // Another chain: its own record.
    h.authorizer.revoke("bob");
    let bob_id = refusal_names(h.rpc(Some("bob"), &initialize_msg(20)).await?).await?;
    assert_ne!(bob_id, named[0]);
    assert_eq!(
        refusal_names(h.rpc(Some("bob"), &initialize_msg(21)).await?).await?,
        bob_id
    );

    // Another reason for the same chain and tool: its own record.
    h.authorizer.expire_lease("tok");
    let expired = h.rpc(Some("tok"), &initialize_msg(30)).await?;
    let expired_id = refusal_names(expired).await?;
    let records = h.authorizer.decisions();
    assert_eq!(records.len(), 5, "{records:?}");
    assert_eq!(records[3].originating_subject, "user:bob");
    assert_eq!(records[3].id.to_string(), bob_id);
    assert_eq!(records[4].reason, "lease_expired");
    assert_eq!(records[4].tool, "initialize");
    assert_eq!(records[4].id.to_string(), expired_id);

    // A refused `tools/call` is a decision: recorded every time.
    for i in 0..3 {
        let resp = h
            .rpc(Some("tok"), &tools_call(40 + i, "read_file", json!({})))
            .await?;
        assert!(resp.headers().contains_key(DECISION_ID_HEADER));
    }
    let calls = h
        .authorizer
        .decisions()
        .into_iter()
        .filter(|r| r.tool == "read_file")
        .count();
    assert_eq!(calls, 3);

    let suppressed = h.authorizer.suppressed_records();
    assert_eq!(suppressed.len(), N - 1 + 2, "{suppressed:?}");
    assert_eq!(
        suppressed[N - 1..],
        [
            ("tools/list".to_owned(), StreamEndCause::LeaseRevoked),
            ("initialize".to_owned(), StreamEndCause::LeaseRevoked),
        ]
    );
    assert!(h.upstream.recorded_methods().is_empty());
    Ok(())
}

/// Once the window has passed, the next refusal is recorded again (the window runs from the
/// first record, so a client that keeps trying leaves one record per window).
#[tokio::test]
async fn a_new_window_records_the_next_lease_refusal() -> anyhow::Result<()> {
    let window = std::time::Duration::from_millis(400);
    let h = Harness::start_with(
        &["read_file"],
        false,
        vec![("tok", reader_chain())],
        |mut c| {
            c.record_window = window;
            c
        },
    )
    .await?;
    h.authorizer.revoke("tok");
    let first = refusal_names(h.rpc(Some("tok"), &initialize_msg(1)).await?).await?;
    assert_eq!(
        refusal_names(h.rpc(Some("tok"), &initialize_msg(2)).await?).await?,
        first
    );
    h.clock
        .advance(window + std::time::Duration::from_millis(100));
    let second = refusal_names(h.rpc(Some("tok"), &initialize_msg(3)).await?).await?;
    assert_ne!(second, first);
    let records = h.authorizer.decisions();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[1].id.to_string(), second);
    assert_eq!(h.authorizer.suppressed_records().len(), 1);
    Ok(())
}

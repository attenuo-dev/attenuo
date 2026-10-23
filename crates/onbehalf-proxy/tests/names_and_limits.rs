//! SR-25 (tool names are checked and must have been listed) and SR-36 (bounded session
//! registry and bodies) at the proxy.

use std::sync::Arc;

use onbehalf_core::Capability;
use onbehalf_proxy::jsonrpc::CODE_DENIED;
use onbehalf_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use onbehalf_proxy::{
    router, ProxyConfig, UpstreamConfig, REASON_INVALID_NAME, REASON_TOOL_NOT_LISTED,
};
use serde_json::{json, Value};

const SERVER: &str = "github";

struct Harness {
    upstream: FakeMcpServer,
    authorizer: Arc<StaticAuthorizer>,
    proxy: Spawned,
    _up: Spawned,
}

impl Harness {
    async fn start(
        upstream: FakeMcpServer,
        authorizer: StaticAuthorizer,
        config: impl FnOnce(ProxyConfig) -> ProxyConfig,
    ) -> anyhow::Result<Self> {
        let up = upstream.spawn().await?;
        let authorizer = Arc::new(authorizer.with_chain(
            "tok",
            test_chain("user:alice", "agent:a", [Capability::new(SERVER, "*")]),
        ));
        let cfg = config(ProxyConfig::new(
            "127.0.0.1:0".parse()?,
            vec![UpstreamConfig::new(SERVER, up.url("/mcp"))],
        ));
        let proxy = spawn_router(router(cfg, authorizer.clone())).await?;
        Ok(Self {
            upstream,
            authorizer,
            proxy,
            _up: up,
        })
    }

    async fn rpc(&self, msg: Value) -> anyhow::Result<Value> {
        let resp = reqwest::Client::new()
            .post(self.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json, text/event-stream")
            .bearer_auth("tok")
            .json(&msg)
            .send()
            .await?;
        let text = resp.text().await?;
        // An SSE answer carries one `data:` line per message here.
        if let Some(data) = text.lines().find_map(|l| l.strip_prefix("data: ")) {
            return Ok(serde_json::from_str(data)?);
        }
        Ok(serde_json::from_str(&text)?)
    }

    async fn call(&self, name: &str) -> anyhow::Result<Value> {
        self.rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": name, "arguments": {}}}))
            .await
    }

    async fn list(&self) -> anyhow::Result<Value> {
        self.rpc(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .await
    }

    fn called(&self) -> Vec<String> {
        self.upstream
            .recorded_calls()
            .into_iter()
            .map(|c| c.name)
            .collect()
    }
}

fn denied_reason(body: &Value) -> Option<&str> {
    (body["error"]["code"] == CODE_DENIED)
        .then(|| body["error"]["data"]["reason"].as_str())
        .flatten()
}

fn case_insensitive_upstream() -> FakeMcpServer {
    FakeMcpServer::new(&["read_file", "delete_repo"]).with_case_insensitive_names(true)
}

/// SR-25: the upstream resolves `Delete_Repo` to `delete_repo`. A `forbid` on
/// `Action::"github/delete_repo"` (or a catalog that only knows `delete_repo`) never sees the
/// call, so the proxy must refuse a name the upstream did not list, whatever the decision.
#[tokio::test]
async fn case_variants_never_reach_a_case_insensitive_upstream_sr25() -> anyhow::Result<()> {
    let h = Harness::start(
        case_insensitive_upstream(),
        StaticAuthorizer::new().with_catalog([(SERVER, "read_file"), (SERVER, "delete_repo")]),
        |c| c,
    )
    .await?;
    for name in ["Delete_Repo", "DELETE_REPO", "delete_Repo"] {
        let body = h.call(name).await?;
        assert_eq!(
            denied_reason(&body),
            Some(REASON_TOOL_NOT_LISTED),
            "{name}: {body}"
        );
    }
    // Listing does not make the variant known: only the exact names listed are.
    h.list().await?;
    let body = h.call("Delete_Repo").await?;
    assert_eq!(denied_reason(&body), Some(REASON_TOOL_NOT_LISTED), "{body}");
    assert!(h.called().is_empty(), "{:?}", h.called());
    // The exact name goes through to the decision (which the static authorizer allows).
    let body = h.call("read_file").await?;
    assert!(body["result"].is_object(), "{body}");
    assert_eq!(h.called(), vec!["read_file"]);
    // Every refusal is on the record.
    let refused: Vec<String> = h
        .authorizer
        .decisions()
        .into_iter()
        .filter(|d| d.reason == REASON_TOOL_NOT_LISTED)
        .map(|d| d.tool)
        .collect();
    assert_eq!(
        refused,
        vec!["Delete_Repo", "DELETE_REPO", "delete_Repo", "Delete_Repo"]
    );
    Ok(())
}

/// A tool the catalog does not know becomes callable once the upstream lists it (JSON or SSE),
/// under exactly the listed name.
#[tokio::test]
async fn listed_names_are_learned_from_json_and_sse_lists_sr25() -> anyhow::Result<()> {
    for sse in [false, true] {
        let h = Harness::start(
            case_insensitive_upstream().with_sse(sse),
            StaticAuthorizer::new().with_catalog([]),
            |c| c,
        )
        .await?;
        let body = h.call("read_file").await?;
        assert_eq!(denied_reason(&body), Some(REASON_TOOL_NOT_LISTED), "{body}");
        let list = h.list().await?;
        assert_eq!(list["result"]["tools"].as_array().map(Vec::len), Some(2));
        let body = h.call("read_file").await?;
        assert!(body["result"].is_object(), "sse={sse}: {body}");
        let body = h.call("Read_File").await?;
        assert_eq!(denied_reason(&body), Some(REASON_TOOL_NOT_LISTED), "{body}");
        assert_eq!(h.called(), vec!["read_file"], "sse={sse}");
    }
    Ok(())
}

/// With the check off, the variant reaches the upstream, which runs the real tool: the hazard
/// `require_listed_tools` closes.
#[tokio::test]
async fn without_require_listed_tools_a_variant_runs_the_real_tool() -> anyhow::Result<()> {
    let h = Harness::start(
        case_insensitive_upstream(),
        StaticAuthorizer::new().with_catalog([]),
        |c| c.with_require_listed_tools(false),
    )
    .await?;
    let body = h.call("Delete_Repo").await?;
    assert!(body["result"].is_object(), "{body}");
    assert_eq!(h.called(), vec!["delete_repo"]);
    Ok(())
}

/// Names outside `[A-Za-z0-9_.-]` (or with `/`, or empty) are refused before any decision, with
/// the check on or off.
#[tokio::test]
async fn invalid_tool_names_are_refused_sr25() -> anyhow::Result<()> {
    for require in [true, false] {
        let h = Harness::start(case_insensitive_upstream(), StaticAuthorizer::new(), |c| {
            c.with_require_listed_tools(require)
        })
        .await?;
        for name in [
            "delete repo",
            "delete_repo\u{200B}",
            "d\u{0435}lete_repo",
            "delete_repo\n",
            "resources/read",
            "prompts/get",
            "",
        ] {
            let body = h.call(name).await?;
            assert_eq!(
                denied_reason(&body),
                Some(REASON_INVALID_NAME),
                "{name:?}: {body}"
            );
        }
        assert!(h.called().is_empty());
        assert!(h
            .authorizer
            .decisions()
            .iter()
            .all(|d| d.reason == REASON_INVALID_NAME));
    }
    Ok(())
}

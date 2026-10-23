//! SR-25 (tool names are checked and must have been listed) and SR-36 (bounded session
//! registry and bodies) at the proxy.

use std::sync::Arc;

use attenuo_core::Capability;
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{
    router, ProxyConfig, UpstreamConfig, REASON_INVALID_NAME, REASON_REQUEST_TOO_LARGE,
    REASON_SESSION_REGISTRY_FULL, REASON_TOOL_NOT_LISTED, REASON_UPSTREAM_BODY_TOO_LARGE,
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

// ---------------------------------------------------------------------------------------------
// SR-36: bounded session registry and bodies
// ---------------------------------------------------------------------------------------------

/// Two upstreams that assign different session ids, behind one proxy whose registry holds
/// `max_sessions` bindings. Bearer `alice` and `bob` are different principals.
async fn two_upstream_proxy(
    max_sessions: usize,
) -> anyhow::Result<(Spawned, Spawned, Spawned, Arc<StaticAuthorizer>)> {
    let a = FakeMcpServer::new(&["read_file"])
        .with_session_id("sess-a")
        .spawn()
        .await?;
    let b = FakeMcpServer::new(&["read_file"])
        .with_session_id("sess-b")
        .spawn()
        .await?;
    let authorizer = Arc::new(
        StaticAuthorizer::new()
            .with_chain(
                "alice",
                test_chain("user:alice", "agent:a", [Capability::new("*", "*")]),
            )
            .with_chain(
                "bob",
                test_chain("user:bob", "agent:b", [Capability::new("*", "*")]),
            ),
    );
    let cfg = ProxyConfig::new(
        "127.0.0.1:0".parse()?,
        vec![
            UpstreamConfig::new("one", a.url("/mcp")),
            UpstreamConfig::new("two", b.url("/mcp")),
        ],
    )
    .with_sessions(std::time::Duration::from_secs(3600), max_sessions);
    let proxy = spawn_router(router(cfg, authorizer.clone())).await?;
    Ok((proxy, a, b, authorizer))
}

async fn post_as(
    proxy: &Spawned,
    server: &str,
    bearer: &str,
    session: Option<&str>,
    msg: &Value,
) -> anyhow::Result<(u16, Option<String>, Value)> {
    let mut req = reqwest::Client::new()
        .post(proxy.url(&format!("/mcp/{server}")))
        .header("accept", "application/json, text/event-stream")
        .bearer_auth(bearer)
        .json(msg);
    if let Some(s) = session {
        req = req.header("mcp-session-id", s);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = resp.json().await.unwrap_or(Value::Null);
    Ok((status, sid, body))
}

fn initialize() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "t", "version": "0"}}})
}

/// SR-36: when every slot is live, a new session is refused with 503; the live binding of
/// another user is not evicted (before the fix, the least recently used one was, and its owner
/// got 404 on the next request).
#[tokio::test]
async fn a_full_session_registry_refuses_new_sessions_without_evicting_sr36() -> anyhow::Result<()>
{
    let (proxy, _a, _b, _auth) = two_upstream_proxy(1).await?;
    let (status, sid, _) = post_as(&proxy, "one", "alice", None, &initialize()).await?;
    assert_eq!((status, sid.as_deref()), (200, Some("sess-a")));

    let (status, sid, body) = post_as(&proxy, "two", "bob", None, &initialize()).await?;
    assert_eq!(status, 503, "{body}");
    assert_eq!(sid, None, "the refused session id is not handed out");
    assert_eq!(
        body["error"]["data"]["reason"],
        REASON_SESSION_REGISTRY_FULL
    );

    // Alice's session still works.
    let ping = json!({"jsonrpc": "2.0", "id": 2, "method": "ping"});
    let (status, _, body) = post_as(&proxy, "one", "alice", Some("sess-a"), &ping).await?;
    assert_eq!(status, 200, "{body}");
    // Re-using a session one already holds needs no new slot.
    let (status, _, _) = post_as(&proxy, "one", "alice", Some("sess-a"), &initialize()).await?;
    assert_eq!(status, 200);
    Ok(())
}

/// SR-36: a JSON body the proxy must buffer (a list result to filter) is bounded; over the
/// limit is 502, not unbounded memory. Over SSE, the oversized event ends the stream.
#[tokio::test]
async fn oversized_upstream_bodies_are_refused_sr36() -> anyhow::Result<()> {
    let names: Vec<String> = (0..200).map(|i| format!("tool_{i}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    for sse in [false, true] {
        let h = Harness::start(
            FakeMcpServer::new(&names).with_sse(sse),
            StaticAuthorizer::new(),
            |c| c.with_max_upstream_body_bytes(1024),
        )
        .await?;
        let sent = reqwest::Client::new()
            .post(h.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json, text/event-stream")
            .bearer_auth("tok")
            .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .send()
            .await;
        if sse {
            // The stream ends with an error instead of the oversized event; depending on
            // timing the connection closes before or after the response head.
            let text = match sent {
                Ok(resp) => resp.text().await.unwrap_or_default(),
                Err(_) => String::new(),
            };
            assert!(!text.contains("tool_199"), "{text}");
        } else {
            let resp = sent?;
            assert_eq!(resp.status(), 502);
            let body: Value = resp.json().await?;
            assert_eq!(
                body["error"]["data"]["reason"],
                REASON_UPSTREAM_BODY_TOO_LARGE
            );
        }
        // A small list still passes.
        let h = Harness::start(
            FakeMcpServer::new(&["read_file"]).with_sse(sse),
            StaticAuthorizer::new(),
            |c| c.with_max_upstream_body_bytes(1024),
        )
        .await?;
        assert_eq!(h.list().await?["result"]["tools"][0]["name"], "read_file");
    }
    Ok(())
}

/// SR-36: request bodies are bounded, with or without `Content-Length`.
#[tokio::test]
async fn oversized_request_bodies_get_413_sr36() -> anyhow::Result<()> {
    let h = Harness::start(case_insensitive_upstream(), StaticAuthorizer::new(), |c| {
        c.with_max_request_body_bytes(1024)
    })
    .await?;
    let big = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "read_file", "arguments": {"pad": "x".repeat(2048)}}})
    .to_string();
    let url = h.proxy.url(&format!("/mcp/{SERVER}"));
    let sized = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .bearer_auth("tok")
        .body(big.clone())
        .send()
        .await?;
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        big.as_bytes().chunks(256).map(|c| Ok(c.to_vec())).collect();
    let chunked = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .bearer_auth("tok")
        .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
            chunks,
        )))
        .send()
        .await?;
    for resp in [sized, chunked] {
        assert_eq!(resp.status(), 413);
        let body: Value = resp.json().await?;
        assert_eq!(body["error"]["data"]["reason"], REASON_REQUEST_TOO_LARGE);
    }
    assert!(h.called().is_empty());
    // Under the limit is fine.
    assert!(h.call("read_file").await?["result"].is_object());
    Ok(())
}

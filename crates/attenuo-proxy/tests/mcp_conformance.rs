//! Conformance-style walk of the MCP method surface.
//!
//! For every method the proxy has an opinion about, the table below says how the proxy must
//! treat it, and the tests check that against a fake upstream that records what reaches it:
//!
//! - **Decided** methods (`tools/call`, `resources/read`, `resources/subscribe`, `prompts/get`,
//!   `completion/complete`, and every method the proxy does not know) reach the upstream only
//!   when a capability permits the `ToolCall` the request maps to; otherwise the client gets
//!   `-32003`, a deny decision is recorded under the mapped tool name, and the upstream sees
//!   nothing.
//! - **Passthrough** methods (`initialize`, `ping`, the four `*/list` methods,
//!   `logging/setLevel`) and **notifications** need a live lease and no capability.
//! - Nothing at all reaches the upstream for a revoked token, and each refused request leaves
//!   one deny record with the lease reason (passthrough methods and notifications included).
//!
//! Mapping and allowlist: `docs/design/server.md`, "MCP method coverage".

use std::sync::Arc;

use attenuo_core::{ArgConstraint, Capability, Decision, DelegationChain};
use attenuo_proxy::jsonrpc::{CODE_DENIED, CODE_INVALID_PARAMS};
use attenuo_proxy::testing::{spawn_router, test_chain, FakeMcpServer, Spawned, StaticAuthorizer};
use attenuo_proxy::{router, ProxyConfig, UpstreamConfig};
use serde_json::{json, Value};

const SERVER: &str = "github";
const TOKEN: &str = "tok";

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    proxy: Spawned,
    authorizer: Arc<StaticAuthorizer>,
    client: reqwest::Client,
}

impl Harness {
    async fn start(chain: DelegationChain) -> anyhow::Result<Self> {
        let upstream = FakeMcpServer::new(&["read_file", "delete_repo"])
            .with_resources(&["file:///public/a"])
            .with_prompts(&["summarize"]);
        let upstream_task = upstream.spawn().await?;
        let authorizer = Arc::new(StaticAuthorizer::new().with_chain(TOKEN, chain));
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

    async fn post(&self, body: &Value) -> anyhow::Result<(u16, Value)> {
        let resp = self
            .client
            .post(self.proxy.url(&format!("/mcp/{SERVER}")))
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .bearer_auth(TOKEN)
            .body(body.to_string())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)?
        };
        Ok((status, body))
    }

    /// How many times the upstream saw `method`.
    fn seen(&self, method: &str) -> usize {
        self.upstream
            .recorded_methods()
            .iter()
            .filter(|m| *m == method)
            .count()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// Forwarded after the lease check; no capability needed.
    Passthrough,
    /// Needs a decision for `ToolCall { tool, arguments }`.
    Decided,
    /// A notification: forwarded after the lease check, never answered.
    Notification,
}

struct Case {
    method: &'static str,
    params: Value,
    class: Class,
    /// The `ToolCall.tool` the request maps to (Decided only).
    tool: &'static str,
    /// Capabilities that permit the request.
    allow: Vec<Capability>,
    /// Capabilities that look related but do not permit it (Decided only).
    deny: Vec<Capability>,
}

fn cap(tool: &str) -> Capability {
    Capability::new(SERVER, tool)
}

/// A valid chain holding `caps`; a chain must hold at least one capability, so "none" is a
/// capability for a tool nothing in this file calls.
fn chain_with(caps: Vec<Capability>) -> DelegationChain {
    let caps = if caps.is_empty() {
        vec![cap("unrelated")]
    } else {
        caps
    };
    test_chain("user:a", "agent:a", caps)
}

fn cases() -> Vec<Case> {
    let passthrough = |method: &'static str, params: Value| Case {
        method,
        params,
        class: Class::Passthrough,
        tool: "",
        allow: vec![],
        deny: vec![],
    };
    let notification = |method: &'static str| Case {
        method,
        params: json!({}),
        class: Class::Notification,
        tool: "",
        allow: vec![],
        deny: vec![],
    };
    let decided =
        |method: &'static str, params: Value, tool: &'static str, allow: Vec<Capability>| Case {
            method,
            params,
            class: Class::Decided,
            tool,
            allow,
            // never the right tool name, never the right server
            deny: vec![cap("something_else"), Capability::new("gitlab", tool)],
        };
    vec![
        passthrough(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "0"}}),
        ),
        passthrough("ping", json!({})),
        passthrough("tools/list", json!({})),
        passthrough("resources/list", json!({})),
        passthrough("resources/templates/list", json!({})),
        passthrough("prompts/list", json!({})),
        passthrough("logging/setLevel", json!({"level": "info"})),
        decided(
            "tools/call",
            json!({"name": "read_file", "arguments": {"path": "a"}}),
            "read_file",
            vec![cap("read_file")],
        ),
        decided(
            "resources/read",
            json!({"uri": "file:///public/a"}),
            "resources/read",
            vec![cap("resources/read")
                .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into()))],
        ),
        decided(
            "resources/subscribe",
            json!({"uri": "file:///public/a"}),
            "resources/subscribe",
            vec![cap("resources/subscribe")],
        ),
        decided(
            "prompts/get",
            json!({"name": "summarize", "arguments": {"x": "1"}}),
            "prompts/get",
            vec![cap("prompts/get")
                .with_constraint("name", ArgConstraint::Equals(json!("summarize")))],
        ),
        decided(
            "completion/complete",
            json!({"ref": {"type": "ref/prompt", "name": "summarize"},
                   "argument": {"name": "x", "value": "a"}}),
            "completion/complete",
            vec![cap("completion/complete")],
        ),
        // Methods the proxy has no mapping for: the method name is the tool.
        decided(
            "resources/unsubscribe",
            json!({"uri": "file:///public/a"}),
            "resources/unsubscribe",
            vec![cap("resources/*")],
        ),
        decided(
            "sampling/createMessage",
            json!({"messages": []}),
            "sampling/createMessage",
            vec![cap("sampling/*")],
        ),
        decided(
            "nonsense/method",
            json!({}),
            "nonsense/method",
            vec![cap("nonsense/*")],
        ),
        // Case and near-miss spellings are different, unknown methods.
        decided(
            "Tools/List",
            json!({}),
            "Tools/List",
            vec![cap("Tools/List")],
        ),
        notification("notifications/initialized"),
        notification("notifications/cancelled"),
        notification("notifications/roots/list_changed"),
        notification("notifications/tools/list_changed"),
        notification("notifications/resources/list_changed"),
        notification("notifications/prompts/list_changed"),
        notification("notifications/resources/updated"),
        notification("notifications/progress"),
    ]
}

fn request(id: u64, case: &Case) -> Value {
    match case.class {
        Class::Notification => json!({"jsonrpc": "2.0", "method": case.method,
                                      "params": case.params}),
        _ => json!({"jsonrpc": "2.0", "id": id, "method": case.method, "params": case.params}),
    }
}

/// The proxy itself refused the request (as opposed to the upstream answering with an error).
fn proxy_refused(status: u16, body: &Value) -> bool {
    status == 401
        || status == 403
        || body["error"]["code"] == CODE_DENIED
        || body["error"]["code"] == -32001
}

#[tokio::test]
async fn permitted_requests_reach_the_upstream() -> anyhow::Result<()> {
    for case in cases() {
        let chain = chain_with(case.allow.clone());
        let h = Harness::start(chain).await?;
        let (status, body) = h.post(&request(1, &case)).await?;
        let label = format!("{} -> {status} {body}", case.method);
        match case.class {
            Class::Notification => assert_eq!(status, 202, "{label}"),
            _ => {
                assert_eq!(status, 200, "{label}");
                assert!(!proxy_refused(status, &body), "{label}");
            }
        }
        assert_eq!(h.seen(case.method), 1, "{label}");
        let decisions = h.authorizer.decisions();
        match case.class {
            Class::Decided => {
                assert_eq!(decisions.len(), 1, "{label}");
                assert_eq!(decisions[0].decision, Decision::Allow, "{label}");
                assert_eq!(decisions[0].tool, case.tool, "{label}");
                assert_eq!(decisions[0].server, SERVER, "{label}");
            }
            // No capability is consulted, so no decision is recorded.
            _ => assert!(decisions.is_empty(), "{label}"),
        }
    }
    Ok(())
}

#[tokio::test]
async fn passthrough_methods_need_no_capability() -> anyhow::Result<()> {
    for case in cases().into_iter().filter(|c| c.class != Class::Decided) {
        // A chain whose only capability is for something unrelated.
        let chain = test_chain("user:a", "agent:a", [cap("unrelated")]);
        let h = Harness::start(chain).await?;
        let (status, body) = h.post(&request(1, &case)).await?;
        assert!(
            !proxy_refused(status, &body),
            "{}: {status} {body}",
            case.method
        );
        assert_eq!(h.seen(case.method), 1, "{}", case.method);
    }
    Ok(())
}

#[tokio::test]
async fn unpermitted_requests_are_denied_and_never_forwarded() -> anyhow::Result<()> {
    for case in cases().into_iter().filter(|c| c.class == Class::Decided) {
        // No capabilities at all, and capabilities that merely look related.
        for caps in [vec![], case.deny.clone()] {
            let chain = chain_with(caps.clone());
            let h = Harness::start(chain).await?;
            let (status, body) = h.post(&request(7, &case)).await?;
            let label = format!("{} with {caps:?} -> {status} {body}", case.method);
            assert_eq!(body["error"]["code"], CODE_DENIED, "{label}");
            assert_eq!(body["id"], 7, "{label}");
            assert!(body["error"]["data"]["decision_id"].is_string(), "{label}");
            assert!(h.upstream.recorded_methods().is_empty(), "{label}");
            let decisions = h.authorizer.decisions();
            assert_eq!(decisions.len(), 1, "{label}");
            assert_eq!(decisions[0].decision, Decision::Deny, "{label}");
            assert_eq!(decisions[0].tool, case.tool, "{label}");
        }
    }
    Ok(())
}

/// SR-25: a method name outside the name rules (`[A-Za-z0-9_.-]` segments joined by `/`) is
/// never permitted, not even by `*`: no capability can name it.
#[tokio::test]
async fn near_miss_method_names_are_never_permitted() -> anyhow::Result<()> {
    for method in ["tools/list ", "tools/call\u{200B}", "resources/re\u{0430}d"] {
        let h = Harness::start(test_chain("user:a", "agent:a", [cap("*")])).await?;
        let (status, body) = h
            .post(&json!({"jsonrpc": "2.0", "id": 3, "method": method, "params": {}}))
            .await?;
        let label = format!("{method:?} -> {status} {body}");
        assert_eq!(body["error"]["code"], CODE_DENIED, "{label}");
        assert!(h.upstream.recorded_methods().is_empty(), "{label}");
        assert!(
            Capability::new(SERVER, method).validate().is_err(),
            "{label}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn argument_constraints_apply_to_the_mapped_arguments() -> anyhow::Result<()> {
    // (method, params, capability, expect allowed)
    let rows: Vec<(&str, Value, Capability, bool)> = vec![
        (
            "resources/read",
            json!({"uri": "file:///secret/key"}),
            cap("resources/read")
                .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into())),
            false,
        ),
        (
            "resources/subscribe",
            json!({"uri": "file:///secret/key"}),
            cap("resources/subscribe")
                .with_constraint("uri", ArgConstraint::Prefix("file:///public/".into())),
            false,
        ),
        (
            "prompts/get",
            json!({"name": "deploy"}),
            cap("prompts/get").with_constraint("name", ArgConstraint::Equals(json!("summarize"))),
            false,
        ),
        (
            "prompts/get",
            json!({"name": "summarize"}),
            cap("prompts/get").with_constraint("name", ArgConstraint::Equals(json!("summarize"))),
            true,
        ),
        (
            // constraint on an argument the call does not have: denied
            "resources/read",
            json!({"uri": "file:///public/a"}),
            cap("resources/read").with_constraint("name", ArgConstraint::Equals(json!("x"))),
            false,
        ),
        (
            "tools/call",
            json!({"name": "read_file", "arguments": {"path": "docs/a"}}),
            cap("read_file").with_constraint("path", ArgConstraint::Prefix("docs/".into())),
            true,
        ),
        (
            "tools/call",
            json!({"name": "read_file", "arguments": {"path": "etc/passwd"}}),
            cap("read_file").with_constraint("path", ArgConstraint::Prefix("docs/".into())),
            false,
        ),
        (
            "completion/complete",
            json!({"ref": {"type": "ref/prompt", "name": "deploy"}, "argument": {"name": "x", "value": ""}}),
            cap("completion/complete").with_constraint(
                "ref",
                ArgConstraint::Equals(json!({"type": "ref/prompt", "name": "summarize"})),
            ),
            false,
        ),
    ];
    for (method, params, capability, allowed) in rows {
        let chain = test_chain("user:a", "agent:a", [capability.clone()]);
        let h = Harness::start(chain).await?;
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let (_, body) = h.post(&msg).await?;
        let label = format!("{method} {params} vs {}", capability.display());
        assert_eq!(
            body["error"]["code"] == CODE_DENIED,
            !allowed,
            "{label}: {body}"
        );
        assert_eq!(h.seen(method), usize::from(allowed), "{label}");
    }
    Ok(())
}

#[tokio::test]
async fn requests_missing_the_field_the_mapping_needs_are_rejected_unforwarded(
) -> anyhow::Result<()> {
    // Even a chain that may do everything cannot send these upstream.
    for (method, params) in [
        ("tools/call", json!({})),
        ("tools/call", json!({"name": 5})),
        ("tools/call", json!({"name": "read_file", "arguments": [1]})),
        ("resources/read", json!({})),
        ("resources/subscribe", json!({"uri": 7})),
        ("prompts/get", json!({})),
    ] {
        let chain = test_chain("user:a", "agent:a", [cap("*")]);
        let h = Harness::start(chain).await?;
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let (_, body) = h.post(&msg).await?;
        assert_eq!(
            body["error"]["code"], CODE_INVALID_PARAMS,
            "{method} {params}: {body}"
        );
        assert!(
            h.upstream.recorded_methods().is_empty(),
            "{method} {params}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn revoked_tokens_reach_nothing() -> anyhow::Result<()> {
    for case in cases() {
        let chain = test_chain("user:a", "agent:a", [cap("*")]);
        let h = Harness::start(chain).await?;
        h.authorizer.revoke(TOKEN);
        let (status, body) = h.post(&request(1, &case)).await?;
        assert!(
            proxy_refused(status, &body),
            "{} should be refused for a revoked lease: {status} {body}",
            case.method
        );
        assert!(
            h.upstream.recorded_methods().is_empty(),
            "{} reached the upstream",
            case.method
        );
        // Every refusal of a verified token leaves exactly one deny record with the lease
        // reason: a decided method under its mapped tool (the decision), anything else under
        // the allowlisted method or `http.POST` (the proxy's own record, so a client that
        // opens a session per call still shows up after revocation).
        let records = h.authorizer.decisions();
        assert_eq!(records.len(), 1, "{}: {records:?}", case.method);
        let r = &records[0];
        assert_eq!(r.decision, Decision::Deny, "{}", case.method);
        assert_eq!(r.reason, "lease_revoked", "{}", case.method);
        assert_eq!(r.server, SERVER, "{}", case.method);
        let tool = match case.class {
            Class::Decided => case.tool,
            Class::Passthrough => case.method,
            Class::Notification => "http.POST",
        };
        assert_eq!(r.tool, tool, "{}", case.method);
    }
    Ok(())
}

#[tokio::test]
async fn whole_surface_in_one_batch() -> anyhow::Result<()> {
    // Everything except `tools/call` and `prompts/get` is permitted; those two are withheld.
    let withheld = ["tools/call", "prompts/get"];
    let all = cases();
    let caps: Vec<Capability> = all
        .iter()
        .filter(|c| c.class == Class::Decided && !withheld.contains(&c.method))
        .flat_map(|c| c.allow.clone())
        .collect();
    let chain = chain_with(caps);
    let h = Harness::start(chain).await?;

    let batch: Vec<Value> = all
        .iter()
        .enumerate()
        .map(|(i, c)| request(i as u64 + 1, c))
        .collect();
    let (status, body) = h.post(&Value::Array(batch)).await?;
    assert_eq!(status, 200);
    let replies = body.as_array().expect("a batch reply");

    let expected_forwarded: Vec<&str> = all
        .iter()
        .filter(|c| !(c.class == Class::Decided && withheld.contains(&c.method)))
        .map(|c| c.method)
        .collect();
    assert_eq!(h.upstream.recorded_methods(), expected_forwarded);

    for (i, c) in all.iter().enumerate() {
        let id = i as u64 + 1;
        let reply = replies
            .iter()
            .find(|r| r["id"] == id && c.class != Class::Notification);
        if withheld.contains(&c.method) {
            let r = reply.unwrap_or_else(|| panic!("no reply for {}", c.method));
            assert_eq!(r["error"]["code"], CODE_DENIED, "{}", c.method);
        } else if let Some(r) = reply {
            assert_ne!(r["error"]["code"], CODE_DENIED, "{}", c.method);
        }
    }
    Ok(())
}

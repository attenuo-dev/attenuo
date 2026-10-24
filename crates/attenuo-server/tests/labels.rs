//! Output labelling through the whole server (ADR-0009): an untrusted result taints its
//! delegation run, a forbid with `@obligation("approval")` then asks for approval with
//! `-32008`, every result is recorded as a `tool_result` audit record before it is relayed,
//! and MCP tool annotations can only narrow the catalog.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_core::ToolCall;
use attenuo_policy::{AnnotationImport, OutputLabel, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "labels-test-admin";

/// Ask before anything destructive once the run has read something untrusted; deny
/// `read_secret` outright; allow everything else the token allows.
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted };

@id("no_secrets")
forbid(principal, action == Action::"github/read_secret", resource);
"#;

/// Deny every tool that is not read-only: what narrowing must not loosen.
const READONLY_POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("reads_only")
forbid(principal, action, resource) unless { resource.readonly };
"#;

const TOOLS: &[&str] = &[
    "read_web",
    "read_balance",
    "read_secret",
    "delete_repo",
    "fetch",
    "wipe",
];

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

fn catalog() -> BTreeMap<String, BTreeMap<String, ToolAttrs>> {
    let read = || ToolAttrs::new().readonly(true);
    BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([
            ("read_web".to_string(), read()),
            (
                "read_balance".to_string(),
                read().output(OutputLabel::Trusted),
            ),
            ("read_secret".to_string(), read()),
            ("delete_repo".to_string(), ToolAttrs::new()),
            ("fetch".to_string(), read()),
            ("wipe".to_string(), ToolAttrs::new().destructive(false)),
        ]),
    )])
}

impl Harness {
    async fn start(policy: &str, upstream: FakeMcpServer, import: AnnotationImport) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let upstream_task = upstream.spawn().await.unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, policy).unwrap();
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.policy.policies_path = Some(policy_path);
        cfg.policy.catalog = catalog();
        cfg.policy.import_annotations = import;
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            server: spawn_router(router).await.unwrap(),
            state,
            upstream,
            _upstream_task: upstream_task,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    async fn default(policy: &str) -> Self {
        Self::start(policy, FakeMcpServer::new(TOOLS), AnnotationImport::Never).await
    }

    /// A root token for alice that allows every tool on `github`: a new delegation run.
    async fn root(&self) -> String {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": "alice",
                "issuer": "https://idp.example",
                "agent": "planner",
                "capabilities": ["github:*"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_string()
    }

    async fn rpc(&self, token: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url("/mcp/github"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn call(&self, token: &str, tool: &str) -> Value {
        self.rpc(
            token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": tool, "arguments": {"repo": "alice/site"}}}),
        )
        .await
    }

    async fn admin_get(&self, path: &str) -> Value {
        let resp = self
            .client
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn evaluate(&self, body: Value) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.server.url("/admin/policies/evaluate"))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap())
    }

    /// Every audit record, with its `seq` folded in.
    async fn records(&self) -> Vec<Value> {
        let v = self.admin_get("/admin/audit?from=1&limit=1000").await;
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let mut r = e["record"].clone();
                r["seq"] = e["seq"].clone();
                r
            })
            .collect()
    }
}

fn allowed(v: &Value) -> bool {
    v.get("result").is_some()
}

#[tokio::test]
async fn untrusted_read_then_destructive_call_requires_approval() {
    let h = Harness::default(POLICY).await;
    let token = h.root().await;
    // Before anything untrusted is read, the destructive call is allowed.
    assert!(allowed(&h.call(&token, "delete_repo").await));

    let token = h.root().await;
    assert!(allowed(&h.call(&token, "read_web").await));
    let v = h.call(&token, "delete_repo").await;
    let err = &v["error"];
    assert_eq!(err["code"], -32008, "{v}");
    assert_eq!(err["data"]["reason"], "approval_required");
    let expected =
        ToolCall::new("github", "delete_repo", json!({"repo": "alice/site"})).call_hash();
    assert_eq!(err["data"]["call_hash"], expected);
    assert_eq!(
        h.upstream
            .recorded_calls()
            .iter()
            .filter(|c| c.name == "delete_repo")
            .count(),
        1,
        "the second delete never went upstream"
    );

    // The audit trail: the read's decision, its tool_result, then the decision that asked.
    let records = h.records().await;
    let result = records
        .iter()
        .find(|r| r["kind"] == "tool_result" && r["tool"] == "read_web")
        .unwrap();
    let read = records
        .iter()
        .find(|r| r["kind"] == "decision" && r["tool"] == "read_web")
        .unwrap();
    assert_eq!(result["decision_id"], read["id"]);
    assert_eq!(result["chain_id"], read["chain_id"]);
    assert_eq!(result["result"]["label"], "untrusted");
    // The echo of the read's arguments is fingerprinted (phase 2): "alice/site" and "read_web".
    assert!(result["result"]["fingerprints"].as_u64().unwrap() > 0);
    assert_eq!(result["result"]["digest"].as_str().unwrap().len(), 64);
    assert!(result["result"]["size"].as_u64().unwrap() > 0);
    let asked = records
        .iter()
        .find(|r| r["reason"] == "approval_required")
        .unwrap();
    assert_eq!(asked["id"], err["data"]["decision_id"]);
    assert_eq!(asked["labels"]["tainted_by"], json!([result["seq"]]));
    assert_eq!(
        asked["policy_ids"],
        json!(["confirm_destructive_after_untrusted_read"])
    );
    // Records of untainted calls carry no labels member.
    assert!(read.get("labels").is_none());
}

/// The value of the `/metrics` sample whose series is exactly `series`.
fn metric(h: &Harness, series: &str) -> u64 {
    let text = h.state.metrics.render();
    attenuo_server::metrics::check_text_format(&text).unwrap();
    let prefix = format!("{series} ");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {series} in:\n{text}"))
        .trim()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn a_trusted_output_read_does_not_taint() {
    let h = Harness::default(POLICY).await;
    let token = h.root().await;
    assert!(allowed(&h.call(&token, "read_balance").await));
    assert!(allowed(&h.call(&token, "delete_repo").await));
    // The result is still recorded, labelled trusted.
    let records = h.records().await;
    let result = records
        .iter()
        .find(|r| r["kind"] == "tool_result" && r["tool"] == "read_balance")
        .unwrap();
    assert_eq!(result["result"]["label"], "trusted");
    assert_eq!(
        metric(&h, "attenuo_results_recorded_total{label=\"trusted\"}"),
        1
    );
}

#[tokio::test]
async fn a_denied_read_taints_nothing() {
    let h = Harness::default(POLICY).await;
    let token = h.root().await;
    let v = h.call(&token, "read_secret").await;
    assert_eq!(v["error"]["data"]["reason"], "policy_deny", "{v}");
    assert!(allowed(&h.call(&token, "delete_repo").await));
    let records = h.records().await;
    assert!(!records
        .iter()
        .any(|r| r["kind"] == "tool_result" && r["tool"] == "read_secret"));
}

#[tokio::test]
async fn taint_belongs_to_one_run() {
    let h = Harness::default(POLICY).await;
    let tainted = h.root().await;
    let clean = h.root().await;
    assert!(allowed(&h.call(&tainted, "read_web").await));
    assert_eq!(
        h.call(&tainted, "delete_repo").await["error"]["code"],
        -32008
    );
    assert!(allowed(&h.call(&clean, "delete_repo").await));
}

#[tokio::test]
async fn a_result_that_cannot_be_recorded_is_withheld_with_label_error() {
    let h = Harness::default(POLICY).await;
    let token = h.root().await;
    // Decisions still append; only tool_result records fail.
    h.state
        .audit
        .with_connection(|c| {
            c.execute_batch(
                "CREATE TRIGGER fail_results BEFORE INSERT ON audit \
                 WHEN NEW.reason = 'tool_result' BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    let v = h.call(&token, "read_web").await;
    assert!(v.get("result").is_none(), "{v}");
    assert_eq!(v["error"]["code"], -32003);
    assert_eq!(v["error"]["data"]["reason"], "label_error");
    assert!(!v.to_string().contains("disk full"), "no store error text");
    // The call ran upstream; its decision is in the log, with its id in the reply.
    assert_eq!(h.upstream.recorded_calls().len(), 1);
    let records = h.records().await;
    let decision = records.iter().find(|r| r["tool"] == "read_web").unwrap();
    assert_eq!(v["error"]["data"]["decision_id"], decision["id"]);
}

#[tokio::test]
async fn narrowing_import_can_restrict_but_never_widen() {
    let upstream = FakeMcpServer::new(TOOLS)
        // Says it writes: `fetch` stops being read-only.
        .with_tool_annotations("fetch", json!({"readOnlyHint": false}))
        // Says it only reads: `wipe` stays not read-only, and becomes destructive.
        .with_tool_annotations(
            "wipe",
            json!({"readOnlyHint": true, "destructiveHint": true}),
        )
        .with_tool_annotations("read_web", json!({"readOnlyHint": true}));
    let h = Harness::start(READONLY_POLICY, upstream, AnnotationImport::Narrowing).await;
    let token = h.root().await;
    // Before tools/list, the catalog alone decides.
    assert!(allowed(&h.call(&token, "fetch").await));
    h.rpc(
        &token,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    let v = h.call(&token, "fetch").await;
    assert_eq!(v["error"]["data"]["reason"], "policy_deny", "{v}");
    assert_eq!(
        h.call(&token, "wipe").await["error"]["data"]["reason"],
        "policy_deny"
    );
    assert!(allowed(&h.call(&token, "read_web").await));
}

#[tokio::test]
async fn annotations_change_nothing_by_default() {
    let upstream =
        FakeMcpServer::new(TOOLS).with_tool_annotations("fetch", json!({"readOnlyHint": false}));
    let h = Harness::start(READONLY_POLICY, upstream, AnnotationImport::Never).await;
    let token = h.root().await;
    h.rpc(
        &token,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert!(allowed(&h.call(&token, "fetch").await));
}

#[tokio::test]
async fn policy_check_and_dry_run_know_the_labelling_attributes() {
    let h = Harness::default(POLICY).await;
    let v = h.admin_get("/admin/policies/check").await;
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["error_count"], 0, "{v}");

    let token = h.root().await;
    let body = |session: Option<Value>| {
        let mut b = json!({
            "token": token,
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "delete_repo"},
            "resource": {"type": "tool", "id": "github/delete_repo",
                         "properties": {"server": "github"}},
            "context": {"input": {"repo": "alice/site"}},
        });
        if let Some(s) = session {
            b["session"] = s;
        }
        b
    };
    // From the store: the run is clean.
    let (status, v) = h.evaluate(body(None)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(v["session"]["source"], "store");
    // As given: a tainted run asks for approval.
    let (_, v) = h
        .evaluate(body(Some(json!({"tainted_by": ["web/fetch"]}))))
        .await;
    assert_eq!(v["reason"], "approval_required", "{v}");
    assert_eq!(v["session"]["tainted"], true);
    assert_eq!(v["session"]["tainted_by"], json!(["web/fetch"]));
    let (status, _) = h.evaluate(body(Some(json!({"tainted": "yes"})))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Option (b) alone (ADR-0009 phase 2): ask only when an argument of a destructive call
/// carries a span of an untrusted result of the run.
const ARGS_POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("confirm_destructive_with_untrusted_args")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.args_contain_untrusted && !context.approval.present };
"#;

fn call_with(tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tool, "arguments": arguments}})
}

#[tokio::test]
async fn an_argument_copied_from_a_result_asks_and_names_the_result() {
    let h = Harness::default(ARGS_POLICY).await;
    let token = h.root().await;
    // The fake upstream echoes the call as JSON text, so the read's result holds the string.
    let read = h
        .rpc(
            &token,
            call_with("read_web", json!({"repo": "attacker/payload-repo"})),
        )
        .await;
    assert!(allowed(&read), "{read}");
    // Tainted, but the agent's own value matches nothing: allowed under option (b).
    let own = h
        .rpc(
            &token,
            call_with("delete_repo", json!({"repo": "alice/site"})),
        )
        .await;
    assert!(allowed(&own), "{own}");
    // Copied from the result: asked, with the argument, the result's seq and the kind.
    let v = h
        .rpc(
            &token,
            call_with("delete_repo", json!({"repo": "attacker/payload-repo"})),
        )
        .await;
    assert_eq!(v["error"]["code"], -32008, "{v}");
    let records = h.records().await;
    let result = records
        .iter()
        .find(|r| r["kind"] == "tool_result" && r["tool"] == "read_web")
        .unwrap();
    assert!(result["result"]["fingerprints"].as_u64().unwrap() > 0);
    let seq = &result["seq"];
    let expected = json!([
        {"arg": "repo", "seq": seq, "kind": "leaf"},
        {"arg": "repo", "seq": seq, "kind": "entity"},
    ]);
    assert_eq!(v["error"]["data"]["untrusted_args"], expected, "{v}");
    let gated = records
        .iter()
        .find(|r| r["id"] == v["error"]["data"]["decision_id"])
        .unwrap();
    assert_eq!(gated["labels"]["untrusted_args"], expected);
    // On /metrics: the untrusted read, and one decision on a destructive call whose argument
    // matched (the agent's own value matched nothing and is not counted).
    assert!(metric(&h, "attenuo_results_recorded_total{label=\"untrusted\"}") >= 1);
    assert_eq!(
        metric(&h, "attenuo_taint_matches_total{decision=\"deny\"}"),
        1
    );
    assert_eq!(
        metric(&h, "attenuo_taint_matches_total{decision=\"allow\"}"),
        0
    );
    // The allowed call's record has the taint but no `untrusted_args` member.
    let own_record = records
        .iter()
        .find(|r| r["kind"] == "decision" && r["tool"] == "delete_repo")
        .unwrap();
    assert!(own_record["labels"].get("untrusted_args").is_none());
    // The approval shows the matched arguments next to the labels.
    let id = v["error"]["data"]["approval_id"].as_str().unwrap();
    let a = h.admin_get(&format!("/admin/approvals/{id}")).await;
    assert_eq!(a["untrusted_args"], expected, "{a}");

    // The dry run reads the same from the store, and takes them as input.
    let body = |session: Option<Value>| {
        let mut b = json!({
            "token": token,
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "delete_repo"},
            "resource": {"type": "tool", "id": "github/delete_repo",
                         "properties": {"server": "github"}},
            "context": {"input": {"repo": "attacker/payload-repo"}},
        });
        if let Some(s) = session {
            b["session"] = s;
        }
        b
    };
    let (status, d) = h.evaluate(body(None)).await;
    assert_eq!(status, StatusCode::OK, "{d}");
    assert_eq!(d["reason"], "approval_required", "{d}");
    assert_eq!(d["session"]["untrusted_args"], json!(["repo"]));
    assert_eq!(d["session"]["args_contain_untrusted"], true);
    let (_, d) = h.evaluate(body(Some(json!({"tainted": true})))).await;
    assert_eq!(d["decision"], "allow", "{d}");
    assert_eq!(d["session"]["untrusted_args"], json!([]));
    let (_, d) = h
        .evaluate(body(Some(json!({"untrusted_args": ["repo"]}))))
        .await;
    assert_eq!(d["reason"], "approval_required", "{d}");
    let (status, _) = h
        .evaluate(body(Some(json!({"untrusted_args": "repo"}))))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

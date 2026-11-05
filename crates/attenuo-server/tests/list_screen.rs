//! `[proxy] list_filter = "policy"` end to end (ADR-0011): the whole server in front of a fake
//! MCP server. `tools/list` hides a tool only when the Cedar policy denies every call to it
//! for the token's chain (approval obligations lifted) or the catalog lacks it under
//! `unknown_tools = "deny"`; a hidden tool that is called anyway is decided and audited as
//! before; a policy reload changes what is hidden; the default mode lists as before.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::{ListFilterMode, UpstreamConfig};
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "test-admin-token";
/// What the upstream lists: the catalog's five tools and one the catalog does not know.
const TOOLS: &[&str] = &[
    "read_file",
    "create_issue",
    "update_issue",
    "delete_repo",
    "merge_pr",
    "not_catalogued",
];

/// Reads for anyone; issues in acme; merges only with an approval; deletes need MFA (the
/// starter policy's forbid); nothing permits `update_issue`.
const POLICY: &str = r#"
@id("reads")
permit(principal, action, resource) when { resource.readonly };

@id("issues_in_acme")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has repo && context.input.repo like "acme/*" };

@id("merges")
permit(principal, action == Action::"github/merge_pr", resource);

@id("ask_before_merging")
@obligation("approval")
forbid(principal, action == Action::"github/merge_pr", resource)
unless { context.approval.present };

@id("deletes")
permit(principal, action == Action::"github/delete_repo", resource);

@id("forbid_sensitive_without_mfa")
forbid(principal, action, resource)
when {
    resource.sensitive &&
    !(context.originating_user.attributes has mfa && context.originating_user.attributes.mfa == true)
};
"#;

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    _server: Spawned,
    state: Arc<AppState>,
    base: String,
    client: reqwest::Client,
    policy_path: PathBuf,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(mode: ListFilterMode) -> Self {
        Self::start_against(FakeMcpServer::new(TOOLS), mode).await
    }

    async fn start_against(upstream: FakeMcpServer, mode: ListFilterMode) -> Self {
        Self::start_with(upstream, mode, &[]).await
    }

    /// As [`start_against`](Self::start_against), with `extra` read-only tools in the catalog.
    async fn start_with(upstream: FakeMcpServer, mode: ListFilterMode, extra: &[String]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let upstream_task = upstream.spawn().await.unwrap();
        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path.clone());
        let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_file".to_string(), repo().readonly(true)),
                ("create_issue".to_string(), repo()),
                ("update_issue".to_string(), repo()),
                ("delete_repo".to_string(), repo().sensitive(true)),
                ("merge_pr".to_string(), repo()),
            ]),
        )]);
        for tool in extra {
            cfg.policy
                .catalog
                .get_mut("github")
                .unwrap()
                .insert(tool.clone(), repo().readonly(true));
        }
        cfg.audit.sqlite_path = ":memory:".into();
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.proxy.list_filter = mode;
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            upstream,
            _upstream_task: upstream_task,
            base: server.url(""),
            _server: server,
            state,
            client: reqwest::Client::new(),
            policy_path,
            _dir: dir,
        }
    }

    async fn admin_post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.base))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn mint(&self, mfa: bool) -> String {
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({
                    "subject": "alice",
                    "issuer": "https://idp.example",
                    "agent": "planner",
                    "capabilities": ["github:*"],
                    "attributes": {"mfa": mfa},
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_owned()
    }

    async fn rpc(&self, token: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(format!("{}/mcp/github", self.base))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sse = resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream");
        let text = resp.text().await.unwrap();
        if !sse {
            return serde_json::from_str(&text).unwrap();
        }
        let data: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|l| l.strip_prefix(' ').unwrap_or(l))
            .collect();
        serde_json::from_str(data[0]).unwrap()
    }

    async fn list(&self, token: &str) -> Vec<String> {
        let v = self
            .rpc(
                token,
                json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}),
            )
            .await;
        v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn call(&self, token: &str, tool: &str, args: Value) -> Value {
        self.rpc(
            token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": tool, "arguments": args}}),
        )
        .await
    }

    async fn audit_entries(&self) -> Vec<Value> {
        let resp = self
            .client
            .get(format!("{}/admin/audit?from=1&limit=1000", self.base))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["entries"].as_array().unwrap().clone()
    }

    async fn reload(&self, policy: &str) {
        std::fs::write(&self.policy_path, policy).unwrap();
        let resp = self.admin_post("/admin/policies/reload", json!({})).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

fn denied_reason(resp: &Value) -> String {
    resp["error"]["data"]["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("not a denial: {resp}"))
        .to_owned()
}

fn hidden_metric(text: &str, reason: &str) -> u64 {
    let prefix = format!("attenuo_proxy_list_entries_hidden_total{{reason=\"{reason}\"}} ");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {prefix}"))
        .trim()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn the_default_mode_lists_what_the_capabilities_allow() {
    let h = Harness::start(ListFilterMode::Capabilities).await;
    let token = h.mint(false).await;
    assert_eq!(h.list(&token).await, TOOLS);
    assert_eq!(hidden_metric(&h.state.metrics.render(), "policy"), 0);
}

#[tokio::test]
async fn policy_mode_hides_tools_no_call_could_use_and_writes_no_record() {
    for sse in [false, true] {
        let h = Harness::start_against(
            FakeMcpServer::new(TOOLS).with_sse(sse),
            ListFilterMode::Policy,
        )
        .await;
        let without_mfa = h.mint(false).await;
        let with_mfa = h.mint(true).await;
        let before = h.audit_entries().await.len();
        // update_issue: no permit. delete_repo: sensitive, no MFA. not_catalogued: not in the
        // catalog under unknown_tools = "deny". merge_pr: approval-gated, so kept.
        assert_eq!(
            h.list(&without_mfa).await,
            vec!["read_file", "create_issue", "merge_pr"],
            "sse {sse}"
        );
        assert_eq!(
            h.list(&with_mfa).await,
            vec!["read_file", "create_issue", "delete_repo", "merge_pr"],
            "sse {sse}"
        );
        // Lists are not decisions: no audit record.
        assert_eq!(h.audit_entries().await.len(), before, "sse {sse}");
        let metrics = h.state.metrics.render();
        assert_eq!(hidden_metric(&metrics, "policy"), 3, "sse {sse}");
        assert_eq!(hidden_metric(&metrics, "not_in_catalog"), 2, "sse {sse}");
        assert!(h.state.pipeline.policy().read().unwrap().screened_tools() > 0);
    }
}

/// A hidden tool called by name is decided by the full pipeline and gets the same denial and
/// the same audit record as with `list_filter = "capabilities"`.
#[tokio::test]
async fn hidden_tools_are_still_decided_when_called() {
    let mut seen = Vec::new();
    for mode in [ListFilterMode::Policy, ListFilterMode::Capabilities] {
        let h = Harness::start(mode).await;
        let token = h.mint(false).await;
        let listed = h.list(&token).await;
        assert_eq!(
            listed.contains(&"update_issue".to_string()),
            mode == ListFilterMode::Capabilities
        );
        let resp = h
            .call(&token, "update_issue", json!({"repo": "acme/x"}))
            .await;
        let reason = denied_reason(&resp);
        let entries = h.audit_entries().await;
        let record = entries
            .iter()
            .rev()
            .find(|e| e["record"]["kind"] == "decision" && e["record"]["tool"] == "update_issue")
            .unwrap_or_else(|| panic!("no decision record in {entries:?}"));
        assert_eq!(record["record"]["decision"], "deny");
        assert_eq!(record["record"]["reason"], reason);
        assert_eq!(
            resp["error"]["data"]["decision_id"], record["record"]["id"],
            "the denial names its record"
        );
        let resp = h
            .call(&token, "delete_repo", json!({"repo": "acme/x"}))
            .await;
        seen.push((reason, denied_reason(&resp)));
        assert!(h.upstream.recorded_calls().is_empty());
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(
        seen[0],
        ("policy_deny".to_string(), "policy_deny".to_string())
    );
}

/// An approval-gated tool stays listed, and calling it starts the approval flow.
#[tokio::test]
async fn approval_gated_tools_stay_listed() {
    let h = Harness::start(ListFilterMode::Policy).await;
    let token = h.mint(false).await;
    assert!(h.list(&token).await.contains(&"merge_pr".to_string()));
    let resp = h.call(&token, "merge_pr", json!({"repo": "acme/x"})).await;
    assert_eq!(denied_reason(&resp), "approval_required");
}

#[tokio::test]
async fn a_policy_reload_changes_the_hidden_set() {
    let h = Harness::start(ListFilterMode::Policy).await;
    let token = h.mint(false).await;
    assert!(!h.list(&token).await.contains(&"update_issue".to_string()));
    let generation = h
        .state
        .pipeline
        .policy()
        .read()
        .unwrap()
        .policy_generation();

    h.reload(&format!(
        "{POLICY}\n@id(\"updates\") permit(principal, action == Action::\"github/update_issue\", resource);\n\
         @id(\"no_reads\") forbid(principal, action == Action::\"github/read_file\", resource);"
    ))
    .await;
    assert_eq!(
        h.state
            .pipeline
            .policy()
            .read()
            .unwrap()
            .policy_generation(),
        generation + 1
    );
    let after = h.list(&token).await;
    assert!(after.contains(&"update_issue".to_string()), "{after:?}");
    assert!(!after.contains(&"read_file".to_string()), "{after:?}");
    assert!(h
        .call(&token, "update_issue", json!({"repo": "acme/x"}))
        .await
        .get("result")
        .is_some());
}

/// The cost of a 200-tool `tools/list` through the whole server, per mode (`#[ignore]`: a
/// measurement, run with `--release --ignored --nocapture`). The catalog holds the five tools
/// above and 194 more read-only ones, all listed under either mode (the policy screen keeps
/// them: `reads` allows them), so both modes return the same 196-tool body and the difference
/// is the screen. Prints the first list and the median of 9 rounds of 50 lists each.
#[tokio::test]
#[ignore]
async fn list_cost_by_mode() {
    let extra: Vec<String> = (0..200 - TOOLS.len())
        .map(|i| format!("tool_{i:03}"))
        .collect();
    let mut names: Vec<String> = TOOLS.iter().map(|t| t.to_string()).collect();
    names.extend(extra.iter().cloned());
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    for mode in [
        ListFilterMode::Capabilities,
        ListFilterMode::Policy,
        ListFilterMode::Capabilities,
        ListFilterMode::Policy,
    ] {
        let h = Harness::start_with(FakeMcpServer::new(&refs), mode, &extra).await;
        let token = h.mint(false).await;
        let first = std::time::Instant::now();
        let listed = h.list(&token).await.len();
        let first = first.elapsed();
        let mut rounds = Vec::new();
        for _ in 0..9 {
            let t = std::time::Instant::now();
            for _ in 0..50 {
                h.list(&token).await;
            }
            rounds.push(t.elapsed().as_secs_f64() * 1e6 / 50.0);
        }
        rounds.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "list_cost {mode:?}: {listed} listed, first {:.0} us, median {:.0} us (min {:.0}, max {:.0})",
            first.as_secs_f64() * 1e6,
            rounds[4],
            rounds[0],
            rounds[8]
        );
    }
}

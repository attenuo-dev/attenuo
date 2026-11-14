//! Per-user windows through the whole server (run limits phase 3): `context.usage.user_window`
//! is kept per originating user across all their runs, so a new run does not reset it and a
//! second user is never charged by the first user's window; it is reported on the decision
//! record and in the `-32003` error data, returned by the operator refund, and not reset by
//! revoking the run. The admin lease tree shows the run's user's windows (phase 3 step 2),
//! read only, to the same roles as the rest of the tree.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "user-windows-test-admin";
/// A `viewer` operator, the lowest role, and an expired one.
const VIEWER: &str = "user-windows-test-viewer";
const EXPIRED: &str = "user-windows-test-expired";

/// A user's agents send at most 100 a UTC day, whatever run they are in.
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("user_daily_spend_cap_100")
forbid (principal, action == Action::"bank/send_money", resource)
when {
  context.input has amount &&
  context.usage.user_window.day.amount + context.input.amount > 100
};
"#;

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    _upstream_task: Spawned,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

struct Minted {
    token: String,
    lease: String,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let upstream = FakeMcpServer::new(&["send_money", "get_balance"]);
        let upstream_task = upstream.spawn().await.unwrap();

        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path);
        cfg.policy.catalog = BTreeMap::from([(
            "bank".to_string(),
            BTreeMap::from([
                (
                    "send_money".to_string(),
                    ToolAttrs::new()
                        .with_input("recipient", ArgType::String)
                        .with_input("amount", ArgType::Long)
                        .with_amount("amount"),
                ),
                ("get_balance".to_string(), ToolAttrs::new().readonly(true)),
            ]),
        )]);
        cfg.audit.sqlite_path = dir.path().join("audit.db").to_string_lossy().into_owned();
        cfg.upstreams = vec![UpstreamConfig::new("bank", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.admin.operators = [
            ("vera", VIEWER, None),
            ("old", EXPIRED, Some(time::OffsetDateTime::UNIX_EPOCH)),
        ]
        .into_iter()
        .map(
            |(name, token, expires_at)| attenuo_server::config::AdminOperator {
                name: name.into(),
                token_sha256: attenuo_server::operators::token_sha256_hex(token),
                role: attenuo_server::operators::AdminRole::Viewer,
                expires_at,
            },
        )
        .collect();
        cfg.dev.allow_root_mint = true;
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            state,
            _upstream_task: upstream_task,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    async fn admin_post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(self.server.url(path))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    /// A new run (root token) of `subject`.
    async fn new_run(&self, subject: &str) -> Minted {
        self.new_run_of("https://idp.example", subject).await
    }

    /// A new run (root token) of `subject` as `issuer` asserts it.
    async fn new_run_of(&self, issuer: &str, subject: &str) -> Minted {
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({"subject": subject, "issuer": issuer,
                       "agent": "planner", "capabilities": ["bank:*"]}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        }
    }

    async fn pay(&self, token: &str, amount: i64) -> Value {
        let resp = self
            .client
            .post(self.server.url("/mcp/bank"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "send_money",
                                     "arguments": {"recipient": "R1", "amount": amount}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    /// `GET /admin/leases/{lease}/tree` with `bearer` (none when `None`).
    async fn tree(&self, lease: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut req = self
            .client
            .get(self.server.url(&format!("/admin/leases/{lease}/tree")));
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn payments(&self) -> Vec<Value> {
        let v: Value = self
            .client
            .get(self.server.url("/admin/audit?from=1&limit=1000"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["record"]["kind"] == "decision" && e["record"]["tool"] == "send_money")
            .map(|e| e["record"].clone())
            .collect()
    }
}

fn allowed(resp: &Value) -> bool {
    resp.get("result").is_some() && resp.get("error").is_none()
}

#[tokio::test]
async fn a_users_window_spans_runs_and_never_charges_another_user() {
    let h = Harness::start().await;
    let alice1 = h.new_run("alice").await;
    assert!(allowed(&h.pay(&alice1.token, 90).await));

    // A second run of alice starts with no run usage, but the day window is hers.
    let alice2 = h.new_run("alice").await;
    let over = h.pay(&alice2.token, 20).await;
    assert_eq!(over["error"]["code"], json!(CODE_DENIED), "{over}");
    assert_eq!(over["error"]["data"]["reason"], "policy_deny");
    let usage = &over["error"]["data"]["usage"];
    assert_eq!(usage["calls"], 0, "{usage}");
    assert_eq!(
        usage["user_window"]["day"],
        json!({"calls": 1, "amount": 90})
    );

    // Bob is not charged by alice's window: his first 90 passes.
    let bob = h.new_run("bob").await;
    assert!(allowed(&h.pay(&bob.token, 90).await));
    // And his window is his own: 20 more takes him past 100.
    let bob_over = h.pay(&bob.token, 20).await;
    assert_eq!(bob_over["error"]["code"], json!(CODE_DENIED), "{bob_over}");
    assert_eq!(
        bob_over["error"]["data"]["usage"]["user_window"]["day"],
        json!({"calls": 1, "amount": 90})
    );

    // Revoking alice's first run does not reset her window.
    let resp = h
        .admin_post(&format!("/admin/leases/{}/revoke", alice1.lease), json!({}))
        .await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    assert_eq!(
        h.pay(&alice2.token, 20).await["error"]["code"],
        json!(CODE_DENIED)
    );

    // The decision record states the window Cedar saw, with its start; only `day` is kept.
    let records = h.payments().await;
    let first = &records[0];
    let day = &first["usage"]["user_window"]["day"];
    assert_eq!(
        (day["calls"].clone(), day["amount"].clone()),
        (json!(0), json!(0))
    );
    let start = day["start"].as_i64().unwrap();
    assert_eq!(start % 86_400, 0, "{first}");
    assert!(
        first["usage"]["user_window"].get("hour").is_none(),
        "{first}"
    );
    assert_eq!(records[1]["usage"]["user_window"]["day"]["amount"], 90);

    // An operator refund of alice's payment returns it to her window.
    let id = first["id"].as_str().unwrap();
    let resp = h
        .admin_post("/admin/budgets/refund", json!({"decision_id": id}))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{}",
        resp.text().await.unwrap()
    );
    assert!(allowed(&h.pay(&alice2.token, 20).await));
}

/// The start of today's UTC day, RFC 3339.
fn today() -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    time::OffsetDateTime::from_unix_timestamp(now - now.rem_euclid(86_400))
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// The lease tree of a run shows its user's windows for the tools the run used, as every run
/// of that user charged them, for the kinds the policies read (only `day` here). The same
/// subject under another issuer is another user. Nothing is shown that the tree did not
/// already show: no issuer, no digest. A run with no usage lists no window, and reading the
/// tree charges nothing.
#[tokio::test]
async fn the_lease_tree_shows_the_run_users_windows() {
    let h = Harness::start().await;
    let alice1 = h.new_run("alice").await;
    assert!(allowed(&h.pay(&alice1.token, 30).await));
    let alice2 = h.new_run("alice").await;
    assert!(allowed(&h.pay(&alice2.token, 40).await));
    // Another IdP's "alice" is someone else.
    let other = h.new_run_of("https://other-idp.example", "alice").await;
    assert!(allowed(&h.pay(&other.token, 5).await));
    let idle = h.new_run("alice").await;

    let day = today();
    let (status, tree) = h.tree(&alice2.lease, Some(ADMIN)).await;
    assert_eq!(status, StatusCode::OK, "{tree}");
    let expected = json!({"truncated": false, "windows": [
        {"tool": "bank/send_money", "kind": "day", "start": day, "calls": 2, "amount": 70}]});
    assert_eq!(tree["user_windows"], expected, "{tree}");
    let text = tree.to_string();
    assert!(!text.contains("idp.example"), "no issuer is shown: {text}");

    let (_, tree) = h.tree(&other.lease, Some(ADMIN)).await;
    assert_eq!(
        tree["user_windows"]["windows"][0],
        json!({"tool": "bank/send_money", "kind": "day", "start": day, "calls": 1, "amount": 5})
    );
    // No usage in the run, so no tool to show a window for.
    let (_, tree) = h.tree(&idle.lease, Some(ADMIN)).await;
    assert_eq!(
        tree["user_windows"],
        json!({"windows": [], "truncated": false})
    );
    // A read twice is the same read: nothing was charged.
    let (_, again) = h.tree(&alice2.lease, Some(ADMIN)).await;
    assert_eq!(again["user_windows"], expected);
}

/// A lease registered before the store kept issuers (schema version 4) has a subject and no
/// issuer: its tree answers `user_windows: null`, and no configured issuer is tried instead.
#[tokio::test]
async fn a_run_without_a_recorded_issuer_shows_no_windows() {
    use attenuo_audit::LeaseRegistry;
    let h = Harness::start().await;
    let run = h.new_run("alice").await;
    assert!(allowed(&h.pay(&run.token, 30).await));
    let old = attenuo_core::LeaseId::new("lease-from-before-v4");
    h.state
        .leases
        .register(
            &old,
            None,
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .unwrap();
    h.state.leases.record_subject(&old, "alice").unwrap();
    let (status, tree) = h.tree(&old.0, Some(ADMIN)).await;
    assert_eq!(status, StatusCode::OK, "{tree}");
    assert_eq!(tree["nodes"][0]["subject"], "alice");
    assert!(tree["user_windows"].is_null(), "{tree}");
}

/// The windows are part of the lease tree, so they need what the tree needs: the `viewer`
/// role, the lowest there is. Without a credential, with a wrong one or with an expired one
/// the tree, windows included, is 401.
#[tokio::test]
async fn the_windows_need_the_trees_role() {
    let h = Harness::start().await;
    let run = h.new_run("alice").await;
    assert!(allowed(&h.pay(&run.token, 30).await));
    assert_eq!(
        attenuo_server::operators::required_role(
            &reqwest::Method::GET,
            Some("/admin/leases/{lease_id}/tree")
        ),
        attenuo_server::operators::AdminRole::Viewer
    );
    let (status, tree) = h.tree(&run.lease, Some(VIEWER)).await;
    assert_eq!(status, StatusCode::OK, "{tree}");
    assert_eq!(tree["user_windows"]["windows"][0]["amount"], 30);
    for bearer in [None, Some("not-a-token"), Some(EXPIRED)] {
        let (status, body) = h.tree(&run.lease, bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{bearer:?}: {body}");
        assert!(body.get("user_windows").is_none(), "{body}");
    }
}

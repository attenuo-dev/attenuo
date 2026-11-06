//! Per-user windows through the whole server (run limits phase 3): `context.usage.user_window`
//! is kept per originating user across all their runs, so a new run does not reset it and a
//! second user is never charged by the first user's window; it is reported on the decision
//! record and in the `-32003` error data, returned by the operator refund, and not reset by
//! revoking the run.

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
    _state: Arc<AppState>,
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
        cfg.dev.allow_root_mint = true;
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            _state: state,
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
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({"subject": subject, "issuer": "https://idp.example",
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

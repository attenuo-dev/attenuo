//! Run usage through the whole server (run-limits design section 3.5, phase 2): per-run usage
//! of destructive tools as `context.usage`, kept in the lease store, charged only by allowed
//! calls of any hop, refunded with the decision, deleted with the run on revocation, reported
//! on the decision record, in the `-32008` / `-32003` error data, AuthZEN and the admin dry
//! run; and a soft limit over it with `@obligation("approval")`, settled by the existing
//! approval flow.

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::jsonrpc::{CODE_APPROVAL_REQUIRED, CODE_DENIED};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "run-usage-test-admin";
const AGENTS: &[&str] = &["helper", "helper2"];

/// The soft rule of the design (ask on the second and later payment), a hard run cap, and a
/// per-destination soft rule for mail.
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("ask_on_repeat_payment")
@obligation("approval")
forbid (principal, action == Action::"bank/send_money", resource)
when { context.usage.calls >= 1 && !context.approval.present };

@id("run_spend_cap_100")
forbid (principal, action == Action::"bank/send_money", resource)
when { context.input has amount && context.usage.amount + context.input.amount > 100 };

@id("ask_on_repeat_mail")
@obligation("approval")
forbid (principal, action == Action::"bank/send_mail", resource)
when { context.usage.destination_seen && !context.approval.present };

@id("ask_on_a_new_host")
@obligation("approval")
forbid (principal, action == Action::"bank/get_webpage", resource)
when { context.usage.calls >= 1 && !context.usage.destination_seen && !context.approval.present };
"#;

fn secret(id: &str) -> String {
    format!("{id}-secret")
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

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
        let upstream =
            FakeMcpServer::new(&["send_money", "send_mail", "get_balance", "get_webpage"]);
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
                        .with_amount("amount")
                        .with_destination("recipient"),
                ),
                (
                    "send_mail".to_string(),
                    ToolAttrs::new()
                        .with_input("to", ArgType::String)
                        .with_destination("to"),
                ),
                ("get_balance".to_string(), ToolAttrs::new().readonly(true)),
                (
                    "get_webpage".to_string(),
                    ToolAttrs::new()
                        .with_input("url", ArgType::String)
                        .with_destination("url#host"),
                ),
            ]),
        )]);
        cfg.audit.sqlite_path = dir.path().join("audit.db").to_string_lossy().into_owned();
        cfg.upstreams = vec![UpstreamConfig::new("bank", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = AGENTS
            .iter()
            .map(|id| attenuo_server::config::AgentConfig {
                id: (*id).into(),
                secret_sha256: sha256_hex(&secret(id)),
            })
            .collect();
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

    async fn mint_root(&self) -> Minted {
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({"subject": "alice", "issuer": "https://idp.example",
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

    async fn exchange(&self, parent: &str, actor: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities",
                    "capabilities": [{"server": "bank", "tool": "*"}]}],
                "client_id": actor,
                "client_secret": secret(actor),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        }
    }

    async fn call(&self, token: &str, tool: &str, args: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url("/mcp/bank"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": tool, "arguments": args}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn pay(&self, token: &str, recipient: &str, amount: i64) -> Value {
        self.call(
            token,
            "send_money",
            json!({"recipient": recipient, "amount": amount}),
        )
        .await
    }

    async fn grant(&self, approval_id: &str) {
        let resp = self
            .admin_post(
                &format!("/admin/approvals/{approval_id}"),
                json!({"decision": "grant"}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn decisions(&self) -> Vec<Value> {
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
            .filter(|e| e["record"]["kind"] == "decision" && e["record"]["server"] == "bank")
            .map(|e| e["record"].clone())
            .collect()
    }

    /// The admin dry run's `usage` for a payment with `token` (never charged).
    async fn dry_run_usage(&self, token: &str) -> Value {
        let v: Value = self
            .admin_post(
                "/admin/policies/evaluate",
                json!({
                    "token": token,
                    "subject": {"type": "agent", "id": ""},
                    "action": {"name": "send_money"},
                    "resource": {"type": "tool", "id": "bank/send_money",
                                 "properties": {"server": "bank"}},
                    "context": {"input": {"recipient": "R1", "amount": 1}},
                }),
            )
            .await
            .json()
            .await
            .unwrap();
        v["usage"].clone()
    }
}

fn allowed(resp: &Value) -> bool {
    resp.get("result").is_some() && resp.get("error").is_none()
}

fn usage(calls: u64, amount: u64, destination_seen: bool) -> Value {
    json!({"calls": calls, "amount": amount, "destination_seen": destination_seen})
}

/// The design's soft limit end to end: the first payment passes, the second gets `-32008`
/// with the run's usage in its data, an operator grants it, the identical retry consumes the
/// approval and is allowed, and usage then counts it, so the third asks again. Every hop of
/// the run shares the count.
#[tokio::test]
async fn soft_limit_on_usage_asks_and_the_approved_call_is_counted() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    let helper = h.exchange(&root.token, "helper").await;

    assert!(allowed(&h.pay(&helper.token, "R1", 10).await));

    let second = h.pay(&helper.token, "R2", 20).await;
    let err = &second["error"];
    assert_eq!(err["code"], json!(CODE_APPROVAL_REQUIRED), "{second}");
    assert_eq!(err["data"]["reason"], "approval_required");
    assert_eq!(err["data"]["usage"], usage(1, 10, false));
    let approval_id = err["data"]["approval_id"].as_str().unwrap().to_string();
    h.grant(&approval_id).await;

    let retry = h.pay(&helper.token, "R2", 20).await;
    assert!(allowed(&retry), "{retry}");

    // A sub-agent of the helper is in the same run: the approved call is counted for it too.
    let helper2 = h.exchange(&helper.token, "helper2").await;
    let third = h.pay(&helper2.token, "R1", 5).await;
    assert_eq!(third["error"]["code"], json!(CODE_APPROVAL_REQUIRED));
    assert_eq!(third["error"]["data"]["usage"], usage(2, 30, true));

    let records = h.decisions().await;
    let payments: Vec<&Value> = records
        .iter()
        .filter(|r| r["tool"] == "send_money")
        .collect();
    assert_eq!(payments.len(), 4);
    assert_eq!(payments[0]["usage"], usage(0, 0, false));
    assert_eq!(payments[1]["reason"], "approval_required");
    assert_eq!(payments[1]["usage"], usage(1, 10, false));
    assert_eq!(payments[2]["decision"], "allow");
    assert_eq!(payments[2]["approval"]["id"], json!(approval_id));
    assert_eq!(payments[2]["usage"], usage(1, 10, false));
    assert_eq!(payments[3]["usage"], usage(2, 30, true));
    // Run usage is not a token limit: no budget member.
    assert!(payments.iter().all(|r| r.get("budget").is_none()));

    // A read keeps no usage and carries none.
    assert!(allowed(
        &h.call(&root.token, "get_balance", json!({})).await
    ));
    let records = h.decisions().await;
    let read = records.iter().find(|r| r["tool"] == "get_balance").unwrap();
    assert!(read.get("usage").is_none(), "{read}");
}

/// Denied calls are never counted: a hard cap over `context.usage.amount` refuses with
/// `-32003` and the usage in its data, and the next call sees the same figures.
#[tokio::test]
async fn hard_limit_on_usage_refuses_and_denied_calls_are_not_counted() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    assert!(allowed(&h.pay(&root.token, "R1", 90).await));
    let over = h.pay(&root.token, "R1", 20).await;
    assert_eq!(over["error"]["code"], json!(CODE_DENIED), "{over}");
    assert_eq!(over["error"]["data"]["reason"], "policy_deny");
    assert_eq!(over["error"]["data"]["usage"], usage(1, 90, true));
    assert_eq!(h.dry_run_usage(&root.token).await["calls"], 1);
    assert_eq!(h.dry_run_usage(&root.token).await["amount"], 90);
}

/// Per destination: mail to a new address passes however many went before; a repeat to the
/// same address asks. The store keeps keyed hashes, so the address is nowhere in it.
#[tokio::test]
async fn destination_seen_is_per_value_and_kept_as_a_hash() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    for to in ["bob@acme.example", "carol@acme.example"] {
        assert!(allowed(
            &h.call(&root.token, "send_mail", json!({"to": to})).await
        ));
    }
    let repeat = h
        .call(&root.token, "send_mail", json!({"to": "bob@acme.example"}))
        .await;
    assert_eq!(repeat["error"]["code"], json!(CODE_APPROVAL_REQUIRED));
    assert_eq!(repeat["error"]["data"]["usage"], usage(2, 0, true));
    let db = std::fs::read(h._dir.path().join("audit.db")).unwrap();
    let needle = b"carol@acme.example";
    assert!(!db.windows(needle.len()).any(|w| w == needle));
}

/// A catalog `destination` of `url#host` (run-limits phase 2) counts sites, not pages: a second
/// page of a site the run already fetched from passes, a new site asks, and so does a value
/// with no host after the first fetch (each such value is a destination of its own, SR-63).
#[tokio::test]
async fn derived_destination_counts_the_host_of_a_url() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    let fetch = |url: &'static str| {
        let token = root.token.clone();
        let h = &h;
        async move { h.call(&token, "get_webpage", json!({ "url": url })).await }
    };
    assert!(allowed(&fetch("https://news.example/article").await));
    assert!(allowed(&fetch("https://News.Example/second?page=2").await));
    let new_site = fetch("https://evil.example/?d=secret").await;
    assert_eq!(new_site["error"]["code"], json!(CODE_APPROVAL_REQUIRED));
    assert_eq!(new_site["error"]["data"]["usage"], usage(2, 0, false));
    let no_host = fetch("not a url").await;
    assert_eq!(no_host["error"]["code"], json!(CODE_APPROVAL_REQUIRED));
}

/// Usage follows the decision's refund, and ends with the run when its root lease is revoked.
#[tokio::test]
async fn usage_is_refunded_with_the_decision_and_deleted_with_the_run() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    assert!(allowed(&h.pay(&root.token, "R1", 10).await));
    assert_eq!(h.dry_run_usage(&root.token).await, {
        let mut u = usage(1, 10, true);
        u["source"] = "store".into();
        u
    });
    let decision_id = h.decisions().await.last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = h
        .admin_post("/admin/budgets/refund", json!({"decision_id": decision_id}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["refunded"], 0, "no token limit was charged: {v}");
    assert_eq!(h.dry_run_usage(&root.token).await["calls"], 0);

    assert!(allowed(&h.pay(&root.token, "R1", 10).await));
    assert_eq!(h.dry_run_usage(&root.token).await["calls"], 1);
    let resp = h
        .admin_post(
            &format!("/admin/leases/{}/revoke", root.lease),
            json!({"reason": "test"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h.dry_run_usage(&root.token).await, {
        let mut u = usage(0, 0, false);
        u["source"] = "store".into();
        u
    });
}

/// AuthZEN charges usage as a proxied call does and reports it; a PEP cannot send its own.
/// The dry run takes `usage` from the request when given.
#[tokio::test]
async fn authzen_and_dry_run_report_usage() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    let ask = |context: Value| {
        let h = &h;
        let token = root.token.clone();
        async move {
            let resp = h
                .client
                .post(h.server.url("/access/v1/evaluation"))
                .bearer_auth(token)
                .json(&json!({
                    "subject": {"type": "agent", "id": ""},
                    "action": {"name": "send_money"},
                    "resource": {"type": "tool", "id": "bank/send_money",
                                 "properties": {"server": "bank"}},
                    "context": context,
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            resp.json::<Value>().await.unwrap()
        }
    };
    let input = json!({"recipient": "R1", "amount": 10});
    let v = ask(json!({"input": input})).await;
    assert_eq!(v["decision"], true, "{v}");
    assert_eq!(v["context"]["usage"], usage(0, 0, false));
    let forged = json!({"input": input, "usage": {"calls": 0}});
    let v = ask(forged).await;
    assert_eq!(v["decision"], false);
    assert_eq!(v["context"]["reason"], "approval_required");
    assert_eq!(v["context"]["usage"], usage(1, 10, true));

    let v: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            json!({
                "token": root.token,
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "send_money"},
                "resource": {"type": "tool", "id": "bank/send_money",
                             "properties": {"server": "bank"}},
                "context": {"input": {"recipient": "R1", "amount": 1}},
                "usage": {"calls": 0, "amount": 0},
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(v["usage"]["source"], "request");
    let resp = h
        .admin_post(
            "/admin/policies/evaluate",
            json!({
                "token": root.token,
                "subject": {"type": "agent", "id": ""},
                "action": {"name": "send_money"},
                "resource": {"type": "tool", "id": "bank/send_money",
                             "properties": {"server": "bank"}},
                "context": {"input": {}},
                "usage": {"calls": -1},
            }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// With a stated `budget`, the dry run reads no usage from the store either: `context.usage`
/// is the request's `usage` (zero when absent), so a soft limit over it is decided on the
/// stated run, and nothing is charged or audited.
#[tokio::test]
async fn dry_run_with_a_stated_budget_decides_soft_limits_on_the_stated_usage() {
    let h = Harness::start().await;
    let root = h.mint_root().await;
    // The real run has paid once: the store says the next payment asks.
    assert!(allowed(&h.pay(&root.token, "R1", 10).await));
    let ask = |extra: Value| {
        let h = &h;
        let mut body = json!({
            "token": root.token,
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "send_money"},
            "resource": {"type": "tool", "id": "bank/send_money",
                         "properties": {"server": "bank"}},
            "context": {"input": {"recipient": "R1", "amount": 10}},
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        async move {
            let resp = h.admin_post("/admin/policies/evaluate", body).await;
            assert_eq!(resp.status(), StatusCode::OK);
            resp.json::<Value>().await.unwrap()
        }
    };
    let audit_before = h.state.audit.len().unwrap();

    let v = ask(json!({})).await;
    assert_eq!(v["reason"], "approval_required", "{v}");
    assert_eq!(v["usage"]["source"], "store");

    // A stated run with no usage: the first payment of the run.
    let v = ask(json!({"budget": {}})).await;
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(
        v["usage"],
        json!({"calls": 0, "amount": 0, "destination_seen": false,
                                  "source": "request"})
    );
    assert_eq!(v["budget"]["source"], "request");

    // The soft rule over `usage.calls` asks; the hard cap over `usage.amount` refuses.
    let v = ask(json!({"budget": {}, "usage": {"calls": 1}})).await;
    assert_eq!(v["reason"], "approval_required", "{v}");
    assert_eq!(v["policy_ids"], json!(["ask_on_repeat_payment"]));
    let v = ask(json!({"budget": {}, "usage": {"amount": 95}})).await;
    assert_eq!(v["reason"], "policy_deny", "{v}");
    assert_eq!(v["policy_ids"], json!(["run_spend_cap_100"]));
    let v = ask(json!({"budget": {}, "usage": {"calls": 1}, "approval": {"by": "user"}})).await;
    assert_eq!(v["decision"], "allow", "{v}");

    // Read-only: the run still holds one payment, and nothing was audited.
    assert_eq!(h.state.audit.len().unwrap(), audit_before);
    assert_eq!(h.dry_run_usage(&root.token).await["calls"], 1);
}

//! Run limits through the whole server (ADR-0010): limits in tokens, inherited and clamped at
//! exchange, every allowed call charged to every hop's counters (so re-delegating does not
//! reset a budget and concurrent siblings cannot overspend), `-32003 budget_exhausted` with
//! the limit in `data.limit`, the decision record's `budget`, AuthZEN, the admin dry run and
//! the operator refund.

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "run-limits-test-admin";
const AGENTS: &[&str] = &["helper", "helper2", "sibling"];

const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);
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
        let upstream =
            FakeMcpServer::new(&["send_money", "get_balance", "flaky_pay", "get_webpage"])
                .with_failing_tool("flaky_pay");
        let upstream_task = upstream.spawn().await.unwrap();

        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path);
        let pay = || {
            ToolAttrs::new()
                .with_input("recipient", ArgType::String)
                .with_input("amount", ArgType::Long)
        };
        cfg.policy.catalog = BTreeMap::from([(
            "bank".to_string(),
            BTreeMap::from([
                ("send_money".to_string(), pay()),
                ("flaky_pay".to_string(), pay()),
                ("get_balance".to_string(), ToolAttrs::new().readonly(true)),
                (
                    "get_webpage".to_string(),
                    ToolAttrs::new().with_input("url", ArgType::String),
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

    async fn mint_root(&self, caps: Value) -> Minted {
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({"subject": "alice", "issuer": "https://idp.example",
                       "agent": "planner", "capabilities": caps}),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        }
    }

    async fn exchange(&self, parent: &str, actor: &str, caps: Value) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities", "capabilities": caps}],
                "client_id": actor,
                "client_secret": secret(actor),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{}",
            resp.text().await.unwrap()
        );
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

    async fn pay(&self, token: &str, amount: i64) -> Value {
        self.call(
            token,
            "send_money",
            json!({"recipient": "FR00EMMA", "amount": amount}),
        )
        .await
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

    async fn authzen(&self, token: &str, tool: &str, args: Value) -> Value {
        self.authzen_with(token, tool, json!({"input": args})).await
    }

    async fn authzen_with(&self, token: &str, tool: &str, context: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url("/access/v1/evaluation"))
            .bearer_auth(token)
            .json(&json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": tool},
                "resource": {"type": "tool", "id": format!("bank/{tool}"),
                             "properties": {"server": "bank"}},
                "context": context,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }
}

fn allowed(resp: &Value) -> bool {
    resp.get("result").is_some() && resp.get("error").is_none()
}

/// The reason and the `limit` member of a `-32003` denial.
fn denial(resp: &Value) -> (String, Value) {
    assert_eq!(resp["error"]["code"], json!(CODE_DENIED), "{resp}");
    (
        resp["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .to_string(),
        resp["error"]["data"]["limit"].clone(),
    )
}

fn send_money(limits: Value) -> Value {
    json!([{"server": "bank", "tool": "send_money", "limits": limits},
           {"server": "bank", "tool": "get_balance"}])
}

#[tokio::test]
async fn call_is_charged_to_every_ancestor_hop_and_redelegation_does_not_reset_budget() {
    let h = Harness::start().await;
    let root = h.mint_root(send_money(json!({"calls": 2}))).await;
    // The helper asks for no limit and inherits the root's figure.
    let helper = h
        .exchange(
            &root.token,
            "helper",
            json!([{"server": "bank", "tool": "send_money"}]),
        )
        .await;
    assert!(allowed(&h.pay(&helper.token, 10).await));

    let records = h.decisions().await;
    let charged = &records.last().unwrap()["budget"]["charged"];
    assert_eq!(
        charged,
        &json!([
            {"hop": 0, "cap": 1, "kind": "calls", "used_after": 1, "max": 2},
            {"hop": 1, "cap": 0, "kind": "calls", "used_after": 1, "max": 2}
        ]),
        "both hops are charged; the root's send_money sorts after get_balance"
    );

    // A fresh sub-agent of the helper is clamped to what is left (1), and its call is still
    // charged to the root: after it, nothing is left for anyone.
    let helper2 = h
        .exchange(
            &helper.token,
            "helper2",
            json!([{"server": "bank", "tool": "send_money"}]),
        )
        .await;
    assert!(allowed(&h.pay(&helper2.token, 10).await));
    for token in [&root.token, &helper.token, &helper2.token] {
        let resp = h.pay(token, 1).await;
        let (reason, limit) = denial(&resp);
        assert_eq!(reason, "budget_exhausted");
        assert_eq!(limit["kind"], "calls");
        assert_eq!(limit["used"], limit["max"], "{limit}");
    }
    // A sub-agent minted now gets a budget of zero, and still cannot spend.
    let late = h
        .exchange(
            &helper2.token,
            "sibling",
            json!([{"server": "bank", "tool": "send_money"}]),
        )
        .await;
    let (reason, _) = denial(&h.pay(&late.token, 1).await);
    assert_eq!(reason, "budget_exhausted");
    // Reads carry no limit and still work for the root.
    assert!(allowed(
        &h.call(&root.token, "get_balance", json!({})).await
    ));
    // The denials are recorded without a budget member.
    let records = h.decisions().await;
    assert!(records
        .iter()
        .filter(|r| r["reason"] == "budget_exhausted")
        .all(|r| r.get("budget").is_none()));
    assert!(!late.lease.is_empty());
}

#[tokio::test]
async fn exchange_clamps_child_budget_to_parent_remaining() {
    let h = Harness::start().await;
    let root = h
        .mint_root(send_money(
            json!({"calls": 3, "sum": {"arg": "amount", "max": 100}}),
        ))
        .await;
    assert!(allowed(&h.pay(&root.token, 70).await));
    // The child asks for more than the root has left; it is clamped, not refused.
    let child = h
        .exchange(
            &root.token,
            "helper",
            json!([{"server": "bank", "tool": "send_money",
                    "limits": {"calls": 9, "sum": {"arg": "amount", "max": 1000}}}]),
        )
        .await;
    let claims = decode_chain(&child.token);
    let limits = &claims["chain"]["hops"][1]["capabilities"][0]["limits"];
    assert_eq!(
        limits,
        &json!({"calls": 2, "sum": {"arg": "amount", "max": 30}})
    );
    // A child that would widen the limit kind is refused as not covered.
    let resp = h
        .client
        .post(h.server.url("/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": root.token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": "sibling",
            "authorization_details": [{"type": "attenuo_capabilities", "capabilities": [
                {"server": "bank", "tool": "send_money", "limits": {"sum": {"arg": "fee", "max": 1}}}
            ]}],
            "client_id": "sibling",
            "client_secret": secret("sibling"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // A limit kind this version does not know is refused, not ignored.
    let resp = h
        .client
        .post(h.server.url("/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": root.token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": "helper2",
            "authorization_details": [{"type": "attenuo_capabilities", "capabilities": [
                {"server": "bank", "tool": "send_money",
                 "limits": {"calls": 1, "window": {"arg": "recipient", "max": 1}}}
            ]}],
            "client_id": "helper2",
            "client_secret": secret("helper2"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request", "{body}");
    // 31 is over what the child (and the root) have left.
    let (reason, limit) = denial(&h.pay(&child.token, 31).await);
    assert_eq!(reason, "budget_exhausted");
    assert_eq!(limit["kind"], "sum");
    assert!(allowed(&h.pay(&child.token, 30).await));
}

fn decode_chain(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn concurrent_siblings_cannot_overspend_parent() {
    let h = Arc::new(Harness::start().await);
    let root = h.mint_root(send_money(json!({"calls": 1}))).await;
    let a = h
        .exchange(
            &root.token,
            "helper",
            json!([{"server": "bank", "tool": "send_money"}]),
        )
        .await;
    let b = h
        .exchange(
            &root.token,
            "sibling",
            json!([{"server": "bank", "tool": "send_money"}]),
        )
        .await;
    let (ra, rb) = tokio::join!(h.pay(&a.token, 1), h.pay(&b.token, 1));
    let wins = [&ra, &rb].iter().filter(|r| allowed(r)).count();
    assert_eq!(wins, 1, "{ra}\n{rb}");
    let loser = if allowed(&ra) { &rb } else { &ra };
    assert_eq!(denial(loser).0, "budget_exhausted");
}

#[tokio::test]
async fn upstream_failure_is_still_charged() {
    let h = Harness::start().await;
    let root = h
        .mint_root(json!([{"server": "bank", "tool": "flaky_pay", "limits": {"calls": 1}}]))
        .await;
    let first = h
        .call(
            &root.token,
            "flaky_pay",
            json!({"recipient": "x", "amount": 1}),
        )
        .await;
    assert!(first.get("error").is_some(), "the upstream failed: {first}");
    assert_ne!(first["error"]["code"], json!(CODE_DENIED));
    let again = h
        .call(
            &root.token,
            "flaky_pay",
            json!({"recipient": "x", "amount": 1}),
        )
        .await;
    assert_eq!(denial(&again).0, "budget_exhausted");
}

#[tokio::test]
async fn calls_per_refuses_a_repeat_payment_to_the_same_payee() {
    let h = Harness::start().await;
    let root = h
        .mint_root(send_money(
            json!({"calls_per": {"arg": "recipient", "max": 1}}),
        ))
        .await;
    let pay = |to: &'static str| {
        let token = root.token.clone();
        let h = &h;
        async move {
            h.call(
                &token,
                "send_money",
                json!({"recipient": to, "amount": 1200}),
            )
            .await
        }
    };
    assert!(allowed(&pay("FR00RENT").await));
    assert!(allowed(&pay("FR00WATER").await));
    let (reason, limit) = denial(&pay("FR00RENT").await);
    assert_eq!(reason, "budget_exhausted");
    assert_eq!(limit["kind"], "calls_per");
    assert_eq!(limit["arg"], "recipient");
    // No recipient: the limit cannot count the call, so it is refused.
    let resp = h
        .call(&root.token, "send_money", json!({"amount": 1}))
        .await;
    assert_eq!(denial(&resp).0, "limit_arg_invalid");
}

#[tokio::test]
async fn authzen_charges_and_reports_the_budget() {
    let h = Harness::start().await;
    let root = h
        .mint_root(send_money(
            json!({"calls": 1, "sum": {"arg": "amount", "max": 40}}),
        ))
        .await;
    let args = json!({"recipient": "FR00EMMA", "amount": 40});
    let v = h.authzen(&root.token, "send_money", args.clone()).await;
    assert_eq!(v["decision"], true, "{v}");
    assert_eq!(
        v["context"]["budget"],
        json!({"limited": true, "calls_remaining": 1, "amount_remaining": 40,
               "destination_new": true})
    );
    assert_eq!(v["context"]["charged"][1]["used_after"], 40);
    // Anything a PEP sends under context.budget is ignored; the server's state decides.
    let forged = json!({"input": args, "budget": {"limited": false, "calls_remaining": 99}});
    let v = h.authzen_with(&root.token, "send_money", forged).await;
    assert_eq!(v["decision"], false);
    assert_eq!(v["context"]["reason"], "budget_exhausted");
    assert_eq!(v["context"]["limit"]["max"], 1);
    // An unlimited call reports no budget.
    let v = h.authzen(&root.token, "get_balance", json!({})).await;
    assert_eq!(v["decision"], true);
    assert!(v["context"].get("budget").is_none(), "{v}");
}

#[tokio::test]
async fn dry_run_reads_counters_and_never_charges() {
    let h = Harness::start().await;
    let root = h.mint_root(send_money(json!({"calls": 1}))).await;
    let body = json!({
        "token": root.token,
        "subject": {"type": "agent", "id": ""},
        "action": {"name": "send_money"},
        "resource": {"type": "tool", "id": "bank/send_money", "properties": {"server": "bank"}},
        "context": {"input": {"recipient": "x", "amount": 1}},
    });
    for _ in 0..3 {
        let v: Value = h
            .admin_post("/admin/policies/evaluate", body.clone())
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(v["decision"], "allow", "{v}");
        assert_eq!(v["budget"]["calls_remaining"], 1);
    }
    assert!(allowed(&h.pay(&root.token, 1).await));
    let v: Value = h
        .admin_post("/admin/policies/evaluate", body)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["reason"], "budget_exhausted");
    assert_eq!(v["budget"]["calls_remaining"], 0);
    assert_eq!(v["limit"]["used"], 1);
}

#[tokio::test]
async fn refund_is_admin_only_and_once_per_decision() {
    let h = Harness::start().await;
    let root = h.mint_root(send_money(json!({"calls": 1}))).await;
    assert!(allowed(&h.pay(&root.token, 1).await));
    let decision_id = h.decisions().await.last().unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(denial(&h.pay(&root.token, 1).await).0, "budget_exhausted");

    // Not without the admin bearer.
    let resp = h
        .client
        .post(h.server.url("/admin/budgets/refund"))
        .json(&json!({"decision_id": decision_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = h
        .admin_post(
            "/admin/budgets/refund",
            json!({"decision_id": decision_id, "reason": "payment bounced"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["refunded"], 1);
    assert!(v["audit_id"].is_string());
    // Once only.
    let resp = h
        .admin_post("/admin/budgets/refund", json!({"decision_id": decision_id}))
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let resp = h
        .admin_post(
            "/admin/budgets/refund",
            json!({"decision_id": "00000000-0000-4000-8000-000000000000"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // The budget is back.
    assert!(allowed(&h.pay(&root.token, 1).await));
    // And the refund is in the log.
    let v: Value = h
        .client
        .get(h.server.url("/admin/audit?from=1&limit=1000"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["record"]["tool"] == "admin.budget.refund" && e["record"]["kind"] == "admin"));
}

/// `distinct` on a derived value (run-limits phase 2): at most two hosts across the run, any
/// number of pages per host, charged to every hop; the denial names the derived argument; a
/// URL without a host cannot be counted; a refund gives a host back; the lease tree shows
/// each hop's limit and what is left.
#[tokio::test]
async fn distinct_hosts_bound_the_sites_a_run_can_reach() {
    let h = Harness::start().await;
    let root = h
        .mint_root(json!([{"server": "bank", "tool": "get_webpage",
            "limits": {"distinct": {"arg": "url", "derive": "host", "max": 2}}}]))
        .await;
    // The child asks for calls only; `calls: 5` does not imply two hosts, so it inherits the
    // parent's `distinct`.
    let child = h
        .exchange(
            &root.token,
            "helper",
            json!([{"server": "bank", "tool": "get_webpage", "limits": {"calls": 5}}]),
        )
        .await;
    let chain = decode_chain(&child.token);
    assert_eq!(
        chain["chain"]["hops"][1]["capabilities"][0]["limits"],
        json!({"calls": 5, "distinct": {"arg": "url", "max": 2, "derive": "host"}})
    );
    let fetch = |url: &'static str| {
        let token = child.token.clone();
        let h = &h;
        async move { h.call(&token, "get_webpage", json!({ "url": url })).await }
    };
    assert!(allowed(&fetch("https://news.example/article").await));
    assert!(allowed(&fetch("https://NEWS.example:443/other?q=1").await));
    assert!(allowed(&fetch("https://docs.example/").await));
    let (reason, limit) = denial(&fetch("https://evil.example/?d=secret").await);
    assert_eq!(reason, "budget_exhausted");
    assert_eq!(
        limit,
        json!({"hop": 0, "kind": "distinct", "arg": "url#host", "max": 2, "used": 2})
    );
    // A page of a site already reached still goes through.
    assert!(allowed(&fetch("https://news.example/third").await));
    // No host to count: refused before Cedar.
    assert_eq!(
        denial(&fetch("news.example/article").await).0,
        "limit_arg_invalid"
    );
    // AuthZEN sees a known host as not new.
    let v = h
        .authzen(
            &child.token,
            "get_webpage",
            json!({"url": "https://docs.example/x"}),
        )
        .await;
    assert_eq!(v["decision"], true, "{v}");
    assert_eq!(v["context"]["budget"]["destination_new"], false, "{v}");

    // The record of the docs.example call charged both hops' counts.
    let decisions = h.decisions().await;
    let docs = decisions
        .iter()
        .filter(|d| d["decision"] == "allow")
        .nth(2)
        .unwrap();
    let charged: Vec<&Value> = docs["budget"]["charged"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "distinct")
        .collect();
    assert_eq!(charged.len(), 2, "{docs}");
    assert!(charged
        .iter()
        .all(|c| c["arg"] == "url#host" && c["used_after"] == 2));

    // The lease tree shows both hops' limits and what is left.
    let tree: Value = h
        .client
        .get(h.server.url(&format!("/admin/leases/{}/tree", root.lease)))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nodes = tree["nodes"].as_array().unwrap();
    let budget_of =
        |lease: &str| nodes.iter().find(|n| n["lease_id"] == lease).unwrap()["budget"].clone();
    let root_budget = budget_of(&root.lease);
    assert_eq!(root_budget["recorded"], true, "{root_budget}");
    assert_eq!(
        root_budget["limits"],
        json!([{"cap": 0, "server": "bank", "tool": "get_webpage", "kind": "distinct",
                "arg": "url#host", "max": 2, "used": 2, "remaining": 0}])
    );
    let child_budget = budget_of(&child.lease);
    let kinds: Vec<(&str, u64)> = child_budget["limits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (l["kind"].as_str().unwrap(), l["used"].as_u64().unwrap()))
        .collect();
    assert_eq!(kinds, vec![("calls", 5), ("distinct", 2)], "{child_budget}");

    // A refund of the docs.example decision gives the host back.
    let resp = h
        .admin_post(
            "/admin/budgets/refund",
            json!({"decision_id": docs["id"], "reason": "test"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(allowed(&fetch("https://evil.example/?d=fine-now").await));
}

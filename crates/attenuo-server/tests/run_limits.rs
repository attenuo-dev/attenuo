//! Run limits through the whole server (ADR-0010): limits in tokens, inherited and clamped at
//! exchange, every allowed call charged to every hop's counters (so re-delegating does not
//! reset a budget and concurrent siblings cannot overspend), `-32003 budget_exhausted` with
//! the limit in `data.limit`, the decision record's `budget`, AuthZEN, the admin dry run and
//! the operator refund.

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

use common::agent_configs;

const ADMIN: &str = "run-limits-test-admin";
const AGENTS: &[&str] = &["helper", "helper2", "sibling"];

const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);
"#;

fn secret(id: &str) -> String {
    format!("{id}-secret")
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
        Self::start_with(|_| {}).await
    }

    async fn start_with(tweak: impl FnOnce(&mut Config)) -> Self {
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
        cfg.agents = agent_configs(AGENTS, secret);
        tweak(&mut cfg);
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

    async fn mint_root(&self, caps: Value) -> Minted {
        let (status, v) = self.try_mint_root(caps).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        }
    }

    async fn try_mint_root(&self, caps: Value) -> (StatusCode, Value) {
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({"subject": "alice", "issuer": "https://idp.example",
                       "agent": "planner", "capabilities": caps}),
            )
            .await;
        (resp.status(), resp.json().await.unwrap())
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
/// URL without a host cannot be counted; a refund gives a host back once no unrefunded
/// decision used it (SR-62); the lease tree shows each hop's limit and what is left.
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
    // A bare host is read as `http://` plus the string: a third site, over the count, not a
    // value without a host.
    let (reason, limit) = denial(&fetch("evil.example/?d=secret").await);
    assert_eq!(reason, "budget_exhausted");
    assert_eq!(limit["arg"], "url#host");
    // A page of a site already reached still goes through.
    assert!(allowed(&fetch("https://news.example/third").await));
    // No host to count: refused before Cedar.
    assert_eq!(
        denial(&fetch("mailto:bob@news.example").await).0,
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

    // A refund of the docs.example decision does not give the host back while the AuthZEN
    // evaluation, which also reached docs.example, stands (SR-62); refunding that one too does.
    let authzen_docs = decisions
        .iter()
        .rev()
        .find(|d| d["decision"] == "allow")
        .unwrap();
    assert_ne!(authzen_docs["id"], docs["id"]);
    let refund = |id: Value| {
        let h = &h;
        async move {
            let resp = h
                .admin_post(
                    "/admin/budgets/refund",
                    json!({"decision_id": id, "reason": "test"}),
                )
                .await;
            assert_eq!(resp.status(), StatusCode::OK);
            resp.json::<Value>().await.unwrap()
        }
    };
    assert_eq!(
        refund(docs["id"].clone()).await["refunded"],
        1,
        "calls only"
    );
    assert_eq!(
        denial(&fetch("https://evil.example/?d=still-not").await).0,
        "budget_exhausted"
    );
    refund(authzen_docs["id"].clone()).await;
    assert!(allowed(&fetch("https://evil.example/?d=fine-now").await));
}

/// The value of the sample whose series is exactly `series` (name and labels).
fn metric(text: &str, series: &str) -> u64 {
    let prefix = format!("{series} ");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {series} in:\n{text}"))
        .trim()
        .parse()
        .unwrap()
}

/// `/metrics` counts run-limit charges by kind, `budget_exhausted` by kind and where, refunds
/// by source, and the run lock: every limited call waits for it once.
#[tokio::test]
async fn metrics_count_charges_exhaustion_refunds_and_the_run_lock() {
    let h = Harness::start().await;
    let root = h
        .mint_root(send_money(json!({
            "calls": 3,
            "sum": {"arg": "amount", "max": 100},
            "calls_per": {"arg": "recipient", "max": 1},
        })))
        .await;
    let render = || h.state.metrics.render();
    let before = render();
    assert_eq!(metric(&before, "attenuo_run_lock_wait_seconds_count"), 0);

    // One allowed call charges each of its three limits once.
    assert!(allowed(&h.pay(&root.token, 60).await));
    let decision_id = h.decisions().await.last().unwrap()["id"].clone();
    // The same payee again: calls_per is hit at the check.
    let (reason, limit) = denial(
        &h.call(
            &root.token,
            "send_money",
            json!({"recipient": "FR00EMMA", "amount": 1}),
        )
        .await,
    );
    assert_eq!(
        (reason.as_str(), limit["kind"].as_str()),
        ("budget_exhausted", Some("calls_per"))
    );
    // Another payee, too much money: sum is hit.
    let (reason, limit) = denial(
        &h.call(
            &root.token,
            "send_money",
            json!({"recipient": "FR00RENT", "amount": 50}),
        )
        .await,
    );
    assert_eq!(
        (reason.as_str(), limit["kind"].as_str()),
        ("budget_exhausted", Some("sum"))
    );
    // A call with no recipient cannot be counted.
    assert_eq!(
        denial(
            &h.call(&root.token, "send_money", json!({"amount": 1}))
                .await
        )
        .0,
        "limit_arg_invalid"
    );
    // A read matches no limit, but the hop is limited, so it still takes the run lock.
    assert!(allowed(
        &h.call(&root.token, "get_balance", json!({})).await
    ));
    let resp = h
        .admin_post(
            "/admin/budgets/refund",
            json!({"decision_id": decision_id, "reason": "bounced"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let text = render();
    attenuo_server::metrics::check_text_format(&text).unwrap();
    for kind in ["calls", "sum", "calls_per"] {
        assert_eq!(
            metric(
                &text,
                &format!("attenuo_budget_charges_total{{kind=\"{kind}\"}}")
            ),
            1,
            "{kind}"
        );
    }
    assert_eq!(
        metric(&text, "attenuo_budget_charges_total{kind=\"distinct\"}"),
        0
    );
    assert_eq!(
        metric(
            &text,
            "attenuo_budget_exhausted_total{kind=\"calls_per\",at=\"check\"}"
        ),
        1
    );
    assert_eq!(
        metric(
            &text,
            "attenuo_budget_exhausted_total{kind=\"sum\",at=\"check\"}"
        ),
        1
    );
    assert_eq!(
        metric(
            &text,
            "attenuo_budget_exhausted_total{kind=\"calls\",at=\"check\"}"
        ),
        0
    );
    assert_eq!(
        metric(
            &text,
            "attenuo_decisions_total{decision=\"deny\",reason=\"budget_exhausted\"}"
        ),
        2
    );
    assert_eq!(
        metric(
            &text,
            "attenuo_decisions_total{decision=\"deny\",reason=\"limit_arg_invalid\"}"
        ),
        1
    );
    assert_eq!(
        metric(&text, "attenuo_budget_refunds_total{source=\"operator\"}"),
        1
    );
    assert_eq!(
        metric(
            &text,
            "attenuo_budget_refunds_total{source=\"audit_error\"}"
        ),
        0
    );
    // Every decision of the limited run took the lock, the `limit_arg_invalid` refusal too (it
    // is decided while the budget is read): five decisions.
    assert_eq!(metric(&text, "attenuo_run_lock_wait_seconds_count"), 5);
    assert_eq!(
        metric(&text, "attenuo_run_lock_wait_seconds_bucket{le=\"+Inf\"}"),
        5
    );
}

/// The admin dry-run body for a payment of `amount` with `token`, plus `extra` members.
fn dry_run_body(token: &str, amount: i64, extra: Value) -> Value {
    let mut body = json!({
        "token": token,
        "subject": {"type": "agent", "id": ""},
        "action": {"name": "send_money"},
        "resource": {"type": "tool", "id": "bank/send_money", "properties": {"server": "bank"}},
        "context": {"input": {"recipient": "FR00EMMA", "amount": amount}},
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// A stated `budget` goes through the pipeline's own limit check: a spent hard limit answers
/// `budget_exhausted` with the same limit and diagnostic as a run whose store holds those
/// counters, and nothing is charged or audited.
#[tokio::test]
async fn dry_run_with_a_stated_budget_refuses_as_the_live_run_does() {
    let h = Harness::start().await;
    let limits = json!({"calls": 3, "sum": {"arg": "amount", "max": 50}});
    // A run that really spent 40 of its 50: the live call and the store-read dry run refuse.
    let spent = h.mint_root(send_money(limits.clone())).await;
    assert!(allowed(&h.pay(&spent.token, 40).await));
    let (reason, live_limit) = denial(&h.pay(&spent.token, 20).await);
    assert_eq!(reason, "budget_exhausted");
    let from_store: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            dry_run_body(&spent.token, 20, json!({})),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(from_store["reason"], "budget_exhausted", "{from_store}");
    assert_eq!(from_store["budget"]["source"], "store");

    // A fresh run, nothing spent, stated as the spent one: the same answer.
    let fresh = h.mint_root(send_money(limits)).await;
    let audit_before = h.state.audit.len().unwrap();
    let stated = json!({"budget": {"calls_remaining": 2, "amount_remaining": 10}});
    let v: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            dry_run_body(&fresh.token, 20, stated),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["decision"], "deny", "{v}");
    assert_eq!(v["reason"], "budget_exhausted");
    assert_eq!(v["limit"], live_limit);
    assert_eq!(v["limit"], from_store["limit"]);
    assert_eq!(v["diagnostics"], from_store["diagnostics"]);
    assert_eq!(v["policy_ids"], json!([]));
    assert_eq!(v["budget"]["source"], "request");
    assert_eq!(v["budget"]["calls_remaining"], 2);
    assert_eq!(v["budget"]["amount_remaining"], 10);
    assert_eq!(v["budget"]["limited"], true);

    // Within the stated figures it is allowed.
    let v: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            dry_run_body(
                &fresh.token,
                10,
                json!({"budget": {"amount_remaining": 10}}),
            ),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(v["budget"]["calls_remaining"], 3);
    assert!(v.get("limit").is_none(), "{v}");

    // A single counter, in the shape of the `limit` member of a refusal.
    let pinned = json!({"budget": {"limits": [{"hop": 0, "kind": "calls", "max": 3, "used": 3}]}});
    let v: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            dry_run_body(&fresh.token, 1, pinned),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["reason"], "budget_exhausted", "{v}");
    assert_eq!(
        v["limit"],
        json!({"hop": 0, "kind": "calls", "max": 3, "used": 3})
    );
    assert_eq!(v["budget"]["calls_remaining"], 0);

    // Nothing was written: no audit record, no counter, and the fresh run's whole budget is
    // still there for a live call.
    assert_eq!(h.state.audit.len().unwrap(), audit_before);
    use attenuo_audit::RunLimits;
    let lease = attenuo_core::LeaseId::new(fresh.lease.clone());
    assert!(h.state.leases.budget_summary(&lease).unwrap().is_empty());
    assert!(allowed(&h.pay(&fresh.token, 50).await));
}

/// With no limit in the chain, the stated figures are what Cedar sees, as `policy test` sets
/// them; there is nothing to refuse.
#[tokio::test]
async fn dry_run_with_a_stated_budget_and_no_limit_passes_the_figures_through() {
    let h = Harness::start().await;
    let root = h
        .mint_root(json!([{"server": "bank", "tool": "send_money"}]))
        .await;
    let v: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            dry_run_body(&root.token, 5, json!({"budget": {"calls_remaining": 0}})),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(
        v["budget"],
        json!({"limited": true, "calls_remaining": 0, "amount_remaining": i64::MAX,
               "destination_new": true, "source": "request"})
    );
    let v: Value = h
        .admin_post(
            "/admin/policies/evaluate",
            dry_run_body(&root.token, 5, json!({"budget": {"limited": false}})),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["budget"]["limited"], false, "{v}");
}

/// A malformed `budget` block is 400 `invalid_request` naming what is wrong.
#[tokio::test]
async fn dry_run_refuses_a_malformed_budget() {
    let h = Harness::start().await;
    let root = h.mint_root(send_money(json!({"calls": 3}))).await;
    let too_many: Vec<Value> = (0..65)
        .map(|i| json!({"hop": i, "kind": "calls", "used": 0}))
        .collect();
    let cases = [
        (json!([1]), "expected an object"),
        (json!({"remaining": 1}), "unknown member `remaining`"),
        (
            json!({"calls_remaining": -1}),
            "`calls_remaining` must be a non-negative integer",
        ),
        (
            json!({"amount_remaining": 1.5}),
            "`amount_remaining` must be a non-negative integer",
        ),
        (
            json!({"destination_new": "no"}),
            "`destination_new` must be a boolean",
        ),
        (json!({"limits": {}}), "`limits` must be a list"),
        (
            json!({ "limits": too_many }),
            "`limits` lists 65 entries; at most 64",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "rate", "used": 1}]}),
            "unknown limit kind `rate`",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "calls", "used": -2}]}),
            "`limits[0].used` must be a non-negative integer",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "calls"}]}),
            "`limits[0].used` is required",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "calls", "used": 1, "lease": "l"}]}),
            "unknown member `limits[0].lease`",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "calls", "arg": "amount", "used": 1}]}),
            "a `calls` limit counts no argument",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "sum", "used": 1}]}),
            "`limits[0].arg` is required for `sum`",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "calls", "used": 1},
                              {"hop": 0, "kind": "calls", "used": 2}]}),
            "`limits[1]` names the same limit as an earlier entry",
        ),
        // Well formed, but naming no limit the call would read.
        (
            json!({"limits": [{"hop": 1, "kind": "calls", "used": 1}]}),
            "`limits[0]` (hop 1, `calls`) names no limit of the chain that matches the call",
        ),
        (
            json!({"limits": [{"hop": 0, "kind": "calls", "max": 9, "used": 1}]}),
            "names no limit of the chain",
        ),
    ];
    let audit_before = h.state.audit.len().unwrap();
    for (budget, want) in cases {
        let resp = h
            .admin_post(
                "/admin/policies/evaluate",
                dry_run_body(&root.token, 1, json!({ "budget": budget })),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{budget}");
        let v: Value = resp.json().await.unwrap();
        let text = v.to_string();
        assert!(text.contains("invalid_request"), "{v}");
        assert!(text.contains("`budget`: "), "{v}");
        assert!(text.contains(want), "{budget}: want {want:?} in {v}");
    }
    assert_eq!(h.state.audit.len().unwrap(), audit_before);
}

/// A harness whose `POST /admin/root-token` is limited to one `[[root_grants]]` entry for
/// planner, with these capabilities.
async fn with_root_grant(caps: Value) -> Harness {
    Harness::start_with(|cfg| {
        cfg.root_grants = vec![attenuo_server::config::RootGrant {
            subject: None,
            issuer: "https://idp.example".into(),
            agent: "planner".into(),
            capabilities: serde_json::from_value(caps).unwrap(),
            attributes: BTreeMap::new(),
            may_act: None,
        }];
    })
    .await
}

fn pay_to(who: &str) -> Value {
    json!({"server": "bank", "tool": "send_money",
           "constraints": {"recipient": {"op": "equals", "value": who}}})
}

/// SR-121: a limit of the root grant is copied into each requested capability it covers, and
/// a call is charged only against the capabilities that match it, so three capabilities, one
/// per recipient, would each carry the grant's `sum` of 100 and the run could send 300. Hop 0
/// refuses that request; one capability with `one_of` gets the budget once.
#[tokio::test]
async fn a_root_grant_limit_is_not_split_across_capabilities_sr121() {
    let h = with_root_grant(json!([{"server": "bank", "tool": "send_money",
        "limits": {"sum": {"arg": "amount", "max": 100}}}]))
    .await;
    let (status, v) = h
        .try_mint_root(json!([pay_to("alice"), pay_to("bob"), pay_to("carol")]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "invalid_scope");
    assert_eq!(v["code"], "limit_split_at_root");
    let detail = v["detail"].as_str().unwrap();
    assert!(detail.contains("one_of"), "says how to ask: {detail}");
    assert!(
        !detail.contains("100") && !detail.contains("limits=") && !detail.contains("max"),
        "{detail}"
    );
    // Its own lower figures do not make it a different request.
    let mut halves = [pay_to("alice"), pay_to("bob")];
    for c in &mut halves {
        c["limits"] = json!({"sum": {"arg": "amount", "max": 50}});
    }
    let (status, v) = h.try_mint_root(json!(halves)).await;
    assert_eq!(
        (status, v["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("limit_split_at_root"))
    );

    // One capability, one budget for the three recipients.
    let root = h
        .mint_root(
            json!([{"server": "bank", "tool": "send_money", "constraints":
            {"recipient": {"op": "one_of", "value": ["alice", "bob", "carol"]}}}]),
        )
        .await;
    let pay = |who: &'static str, amount: i64| {
        let token = root.token.clone();
        let h = &h;
        async move {
            h.call(
                &token,
                "send_money",
                json!({"recipient": who, "amount": amount}),
            )
            .await
        }
    };
    assert!(allowed(&pay("alice", 100).await));
    assert_eq!(denial(&pay("bob", 1).await).0, "budget_exhausted");
    // A single recipient is one capability and still fine.
    h.mint_root(json!([pay_to("alice")])).await;
}

/// SR-121 with `distinct` by host: two capabilities, one per URL prefix, would each carry
/// "one host", so the run could reach two. Refused at hop 0; under an unlimited grant the same
/// split is allowed, as before.
#[tokio::test]
async fn a_root_grant_host_limit_is_not_split_sr121() {
    let fetch = |prefix: &str| {
        json!({"server": "bank", "tool": "get_webpage",
               "constraints": {"url": {"op": "prefix", "value": prefix}}})
    };
    let two = json!([fetch("https://a.example/"), fetch("https://b.example/")]);
    let h = with_root_grant(json!([{"server": "bank", "tool": "get_webpage",
        "limits": {"distinct": {"arg": "url", "derive": "host", "max": 1}}}]))
    .await;
    let (status, v) = h.try_mint_root(two.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "limit_split_at_root");
    let root = h.mint_root(json!([fetch("https://")])).await;
    let get = |url: &'static str| {
        let token = root.token.clone();
        let h = &h;
        async move { h.call(&token, "get_webpage", json!({ "url": url })).await }
    };
    assert!(allowed(&get("https://a.example/x").await));
    assert_eq!(
        denial(&get("https://b.example/x").await).0,
        "budget_exhausted"
    );

    let free = with_root_grant(json!(["bank:*"])).await;
    let root = free.mint_root(two).await;
    assert_eq!(
        decode_chain(&root.token)["chain"]["hops"][0]["capabilities"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// SR-121 does not reach an exchange: a hop's capabilities may split a limited parent
/// capability, because each call is charged against the parent hop too, so the parent's
/// figure still bounds the total.
#[tokio::test]
async fn an_exchange_may_split_a_limited_parent_capability_sr121() {
    let h = with_root_grant(json!([{"server": "bank", "tool": "send_money",
        "limits": {"sum": {"arg": "amount", "max": 100}}}]))
    .await;
    let root = h
        .mint_root(json!([{"server": "bank", "tool": "send_money"}]))
        .await;
    let child = h
        .exchange(
            &root.token,
            "helper",
            json!([pay_to("alice"), pay_to("bob"), pay_to("carol")]),
        )
        .await;
    let hops = &decode_chain(&child.token)["chain"]["hops"];
    let caps = hops[1]["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
    assert!(
        caps.iter().all(|c| c["limits"]["sum"]["max"] == 100),
        "{caps:?}"
    );
    let pay = |who: &'static str, amount: i64| {
        let token = child.token.clone();
        let h = &h;
        async move {
            h.call(
                &token,
                "send_money",
                json!({"recipient": who, "amount": amount}),
            )
            .await
        }
    };
    assert!(allowed(&pay("alice", 60).await));
    assert!(allowed(&pay("bob", 40).await));
    let (reason, limit) = denial(&pay("carol", 1).await);
    assert_eq!(reason, "budget_exhausted");
    assert_eq!(
        limit["hop"], 0,
        "the root hop's capability bounds the total: {limit}"
    );
}

/// `send_money` with `recipient` in `who`, and these limits.
fn pay_any(who: &[&str], limits: Value) -> Value {
    json!({"server": "bank", "tool": "send_money",
           "constraints": {"recipient": {"op": "one_of", "value": who}},
           "limits": limits})
}

/// SR-128: an entry with two limited capabilities, one covering the other's calls ("100 in
/// all, at most 30 of it to alice"). A request for alice and for bob or carol took the alice
/// capability as the first one's parent and the wide one as the second's, so no parent was
/// split and the root token held 30 for alice and 100 for bob or carol: 130 in all. Both
/// requested capabilities are within the wide one, so hop 0 now refuses the split, and alice
/// alone gets both limits (30).
#[tokio::test]
async fn overlapping_root_grant_limits_bound_one_capability_sr128() {
    let mut alice_30 = pay_to("alice");
    alice_30["limits"] = json!({"sum": {"arg": "amount", "max": 30}});
    let h = with_root_grant(json!([
        pay_any(
            &["alice", "bob", "carol"],
            json!({"sum": {"arg": "amount", "max": 100}})
        ),
        alice_30
    ]))
    .await;
    let (status, v) = h
        .try_mint_root(json!([
            pay_to("alice"),
            pay_any(&["bob", "carol"], json!({}))
        ]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "invalid_scope");
    assert_eq!(v["code"], "limit_split_at_root");
    let detail = v["detail"].as_str().unwrap();
    assert!(
        !detail.contains("100") && !detail.contains("30") && !detail.contains("max"),
        "never the grant's limits: {detail}"
    );

    // Alice alone is under both: the lower figure.
    let root = h.mint_root(json!([pay_to("alice")])).await;
    let caps = &decode_chain(&root.token)["chain"]["hops"][0]["capabilities"];
    assert_eq!(caps.as_array().unwrap().len(), 1, "{caps}");
    assert_eq!(caps[0]["limits"]["sum"]["max"], 30, "{caps}");
    let pay = |who: &'static str, amount: i64| {
        let token = root.token.clone();
        let h = &h;
        async move {
            h.call(
                &token,
                "send_money",
                json!({"recipient": who, "amount": amount}),
            )
            .await
        }
    };
    assert!(allowed(&pay("alice", 30).await));
    assert_eq!(denial(&pay("alice", 1).await).0, "budget_exhausted");

    // Bob or carol alone is under the wide one only: 100, as before.
    let root = h
        .mint_root(json!([pay_any(&["bob", "carol"], json!({}))]))
        .await;
    let caps = &decode_chain(&root.token)["chain"]["hops"][0]["capabilities"];
    assert_eq!(caps[0]["limits"]["sum"]["max"], 100, "{caps}");
}

/// SR-128: `bank:*` with `calls` 10 and `bank:send_money` with `calls` 1 ("at most one
/// transfer"). A request for `send_money` took `bank:*` as its parent (it sorts first, and
/// neither covers a request with no limits), so the root token held `send_money` with
/// `calls` 10 and three transfers were allowed. Now it is clamped to both: `calls` 1.
#[tokio::test]
async fn a_nested_root_grant_limit_is_not_skipped_sr128() {
    let h = with_root_grant(json!([
        {"server": "bank", "tool": "*", "limits": {"calls": 10}},
        {"server": "bank", "tool": "send_money", "limits": {"calls": 1}}
    ]))
    .await;
    let root = h
        .mint_root(json!([{"server": "bank", "tool": "send_money"}]))
        .await;
    let caps = &decode_chain(&root.token)["chain"]["hops"][0]["capabilities"];
    assert_eq!(caps.as_array().unwrap().len(), 1, "{caps}");
    assert_eq!(caps[0]["limits"]["calls"], 1, "{caps}");
    let pay = || {
        let token = root.token.clone();
        let h = &h;
        async move {
            h.call(
                &token,
                "send_money",
                json!({"recipient": "alice", "amount": 1}),
            )
            .await
        }
    };
    assert!(allowed(&pay().await));
    assert_eq!(denial(&pay().await).0, "budget_exhausted");
    assert_eq!(denial(&pay().await).0, "budget_exhausted");
}

/// `n` distinct capabilities on the bank server (`get_balance` with one `account` each).
fn many(n: usize) -> Value {
    (0..n)
        .map(|i| {
            json!({"server": "bank", "tool": "get_balance",
                   "constraints": {"account": {"op": "equals", "value": i}}})
        })
        .collect()
}

/// `get_balance` with a `one_of` of `n` accounts.
fn one_of(n: usize) -> Value {
    json!([{"server": "bank", "tool": "get_balance",
            "constraints": {"account": {"op": "one_of", "value": (0..n).collect::<Vec<_>>()}}}])
}

/// SR-123: a request, and so a token, holds at most 1,024 capabilities and a `one_of` at most
/// 1,024 values, at `POST /admin/root-token` (with and without `[[root_grants]]`) and at an
/// exchange, before anything is compared.
#[tokio::test]
async fn requests_are_bounded_in_size_sr123() {
    let refused = |got: &(StatusCode, Value), code: &str| {
        assert_eq!(got.0, StatusCode::BAD_REQUEST, "{}", got.1);
        assert_eq!(got.1["error"], "invalid_scope", "{}", got.1);
        assert_eq!(got.1["code"], code, "{}", got.1);
    };
    for h in [
        Harness::start().await,
        with_root_grant(json!(["bank:*"])).await,
    ] {
        refused(&h.try_mint_root(many(1025)).await, "too_many_capabilities");
        refused(&h.try_mint_root(one_of(1025)).await, "one_of_too_long");
        h.mint_root(one_of(1024)).await;
        let root = h.mint_root(many(1024)).await;
        assert_eq!(
            decode_chain(&root.token)["chain"]["hops"][0]["capabilities"]
                .as_array()
                .unwrap()
                .len(),
            1024
        );
    }

    let h = Harness::start().await;
    let root = h.mint_root(json!(["bank:*"])).await;
    let exchange = |caps: Value, actor: &'static str| {
        let h = &h;
        let parent = root.token.clone();
        async move {
            let resp = h
                .client
                .post(h.server.url("/token"))
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
            (resp.status(), resp.json::<Value>().await.unwrap())
        }
    };
    refused(
        &exchange(many(1025), "helper").await,
        "too_many_capabilities",
    );
    refused(&exchange(one_of(1025), "helper").await, "one_of_too_long");
    let got = exchange(many(1024), "helper").await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
    let got = exchange(one_of(1024), "helper2").await;
    assert_eq!(got.0, StatusCode::OK, "{}", got.1);
}

/// `n` capabilities on the bank server with two constraints each.
fn two_each(n: usize) -> Value {
    (0..n)
        .map(|i| {
            json!({"server": "bank", "tool": "get_balance",
                   "constraints": {"account": {"op": "equals", "value": i},
                                   "currency": {"op": "equals", "value": "EUR"}}})
        })
        .collect()
}

/// `get_balance` and `get_history`, each with a `one_of` of `n` accounts.
fn two_lists(n: usize) -> Value {
    let values: Vec<usize> = (0..n).collect();
    json!([{"server": "bank", "tool": "get_balance",
            "constraints": {"account": {"op": "one_of", "value": values}}},
           {"server": "bank", "tool": "get_history",
            "constraints": {"account": {"op": "one_of", "value": values}}}])
}

/// SR-123, the rest: a request also holds at most 1,024 argument constraints and 1,024
/// `one_of` values over all its capabilities, since attenuation costs each of those times the
/// parent's capabilities. At `POST /admin/root-token` (with and without `[[root_grants]]`)
/// and at an exchange.
#[tokio::test]
async fn requests_are_bounded_in_total_constraints_and_values_sr123() {
    let refused = |got: &(StatusCode, Value), code: &str| {
        assert_eq!(got.0, StatusCode::BAD_REQUEST, "{}", got.1);
        assert_eq!(got.1["error"], "invalid_scope", "{}", got.1);
        assert_eq!(got.1["code"], code, "{}", got.1);
    };
    for h in [
        Harness::start().await,
        with_root_grant(json!(["bank:*"])).await,
    ] {
        refused(
            &h.try_mint_root(two_each(513)).await,
            "too_many_constraints",
        );
        refused(
            &h.try_mint_root(two_lists(513)).await,
            "too_many_one_of_values",
        );
        h.mint_root(two_each(512)).await;
        h.mint_root(two_lists(512)).await;
    }
    let h = Harness::start().await;
    let root = h.mint_root(json!(["bank:*"])).await;
    for (caps, actor, code) in [
        (two_each(513), "helper", Some("too_many_constraints")),
        (two_lists(513), "helper", Some("too_many_one_of_values")),
        (two_each(512), "helper", None),
        (two_lists(512), "helper2", None),
    ] {
        let resp = h
            .client
            .post(h.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": root.token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities", "capabilities": caps}],
                "client_id": actor,
                "client_secret": secret(actor),
            }))
            .send()
            .await
            .unwrap();
        let got = (resp.status(), resp.json::<Value>().await.unwrap());
        match code {
            Some(code) => refused(&got, code),
            None => assert_eq!(got.0, StatusCode::OK, "{}", got.1),
        }
    }
}

/// SR-123 at start: a `[[root_grants]]` entry over any bound does not start.
#[test]
fn a_root_grant_over_the_bounds_does_not_start_sr123() {
    for (caps, says) in [
        (many(1025), "1025 capabilities"),
        (one_of(1025), "1025 values"),
        (two_each(513), "1026 argument constraints"),
        (two_lists(513), "1026 `one_of` values"),
    ] {
        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.agents = agent_configs(AGENTS, secret);
        cfg.root_grants = vec![attenuo_server::config::RootGrant {
            subject: None,
            issuer: "https://idp.example".into(),
            agent: "helper".into(),
            capabilities: serde_json::from_value(caps).unwrap(),
            attributes: BTreeMap::new(),
            may_act: None,
        }];
        let err = cfg.check_server_names().unwrap_err().to_string();
        assert!(attenuo_server::build(&cfg).is_err());
        assert!(
            err.contains(says)
                && err.starts_with(
                    "[[root_grants]] entry 0 (issuer \"https://idp.example\", agent \"helper\", \
                     any subject): "
                ),
            "{err}"
        );
    }
}

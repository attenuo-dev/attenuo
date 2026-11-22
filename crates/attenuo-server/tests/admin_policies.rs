//! The admin console's policy routes: `GET /admin/policies` (what is loaded),
//! `GET /admin/policies/check` (would the file on disk load) and `POST /admin/policies/evaluate`
//! (what the loaded policies say about a call, without leases or audit), driven over HTTP
//! against a real server with real tokens.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use attenuo_audit::LeaseRegistry;
use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId, OriginatingUser, ToolCall};
use attenuo_policy::authzen;
use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

const ADMIN: &str = "test-admin-token";
const AGENTS: &[&str] = &["coder"];

const POLICY: &str = r#"
@id("public_reads")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("no_secrets")
forbid(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "*secret*" };

@id("issues")
permit(principal, action == Action::"github/create_issue", resource);
"#;

const POLICY_V2: &str = r#"
@id("all_reads")
permit(principal, action == Action::"github/read_file", resource);
"#;

/// Line 3 names an attribute the schema does not have; line 5 is cut off.
const BROKEN: &str = "@id(\"ok\")\npermit(principal, action == Action::\"github/read_file\", resource)\nwhen { resource.no_such_attribute };\n\npermit(principal, action,";

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
    policy_path: PathBuf,
    _dir: tempfile::TempDir,
}

struct Minted {
    token: String,
    lease: String,
}

// Not the shared `common::sha256_hex`, on purpose: the tests check the policy hash the server
// reports against this independent computation.
fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://attenuo.test".into();
        cfg.issuer.audience = "attenuo-test".into();
        cfg.policy.policies_path = Some(policy_path.clone());
        let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_file".to_string(), repo().readonly(true)),
                ("create_issue".to_string(), repo()),
            ]),
        )]);
        cfg.audit.sqlite_path = ":memory:".into();
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = AGENTS
            .iter()
            .map(|id| {
                attenuo_server::config::AgentConfig::with_secret_sha256(
                    *id,
                    sha256_hex(&format!("{id}-secret")),
                )
            })
            .collect();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            state,
            client: reqwest::Client::new(),
            policy_path,
            _dir: dir,
        }
    }

    fn url(&self, path: &str) -> String {
        self.server.url(path)
    }

    async fn admin_post(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    async fn admin_get(&self, path: &str) -> Value {
        let resp = self
            .client
            .get(self.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET {path}");
        resp.json().await.unwrap()
    }

    async fn audit_head(&self) -> u64 {
        self.admin_get("/admin/audit?limit=1").await["head"]
            .as_u64()
            .unwrap()
    }

    async fn mint_root(&self, caps: &[&str]) -> Minted {
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

    async fn exchange(&self, parent: &str, actor: &str, caps: &[&str]) -> Minted {
        let caps: Vec<Value> = caps
            .iter()
            .map(|c| {
                let (s, t) = c.split_once(':').unwrap();
                json!({"server": s, "tool": t})
            })
            .collect();
        let resp = self
            .client
            .post(self.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "attenuo_capabilities", "capabilities": caps}],
                "client_id": actor,
                "client_secret": format!("{actor}-secret"),
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

    /// `POST /access/v1/evaluation` with `token` as the bearer.
    async fn authzen(&self, token: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(self.url("/access/v1/evaluation"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn evaluate(&self, body: Value) -> (StatusCode, Value) {
        let resp = self.admin_post("/admin/policies/evaluate", body).await;
        (resp.status(), resp.json().await.unwrap())
    }

    fn chain_of(&self, token: &str) -> attenuo_core::DelegationChain {
        self.state
            .keys()
            .verifier
            .verify(token, OffsetDateTime::now_utc())
            .unwrap()
            .chain
    }

    fn decision_counters(&self) -> Vec<String> {
        self.state
            .metrics
            .render()
            .lines()
            .filter(|l| l.contains("_decisions_total{"))
            .map(str::to_string)
            .collect()
    }
}

/// An AuthZEN body with an empty `subject.id` and no chain, for use with a token.
fn call_body(tool: &str, args: Value) -> Value {
    json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": tool},
        "resource": {"type": "tool", "id": format!("github/{tool}"),
                     "properties": {"server": "github"}},
        "context": {"input": args},
    })
}

fn with_token(mut body: Value, token: &str) -> Value {
    body["token"] = json!(token);
    body
}

#[tokio::test]
async fn get_policies_shows_the_loaded_set_and_follows_only_successful_reloads() {
    let h = Harness::start().await;
    let v = h.admin_get("/admin/policies").await;
    assert_eq!(v["sha256"], sha256_hex(POLICY));
    assert_eq!(v["path"], json!(h.policy_path));
    assert_eq!(
        v["policy_ids"],
        json!(["issues", "no_secrets", "public_reads"])
    );
    assert_eq!(v["warnings"], json!([]));
    let policies = v["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 3);
    assert_eq!(policies[1]["id"], "no_secrets");
    assert!(policies[1]["text"].as_str().unwrap().contains("forbid"));
    let first_loaded_at = v["loaded_at"].as_str().unwrap().to_string();
    OffsetDateTime::parse(
        &first_loaded_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();

    std::fs::write(&h.policy_path, POLICY_V2).unwrap();
    let resp = h.admin_post("/admin/policies/reload", json!({})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = h.admin_get("/admin/policies").await;
    assert_eq!(v["sha256"], sha256_hex(POLICY_V2));
    assert_eq!(v["policy_ids"], json!(["all_reads"]));
    assert_eq!(v["policies"][0]["id"], "all_reads");
    let second_loaded_at = v["loaded_at"].as_str().unwrap().to_string();
    assert!(second_loaded_at >= first_loaded_at);

    // A failed reload changes nothing.
    std::fs::write(&h.policy_path, BROKEN).unwrap();
    let resp = h.admin_post("/admin/policies/reload", json!({})).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let v = h.admin_get("/admin/policies").await;
    assert_eq!(v["sha256"], sha256_hex(POLICY_V2));
    assert_eq!(v["policy_ids"], json!(["all_reads"]));
    assert_eq!(v["loaded_at"], second_loaded_at.as_str());
}

#[tokio::test]
async fn check_reports_issues_with_line_and_column_and_swaps_nothing() {
    let h = Harness::start().await;
    let v = h.admin_get("/admin/policies/check").await;
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["sha256"], sha256_hex(POLICY));
    assert_eq!(v["differs_from_loaded"], false);
    assert_eq!(v["issues"], json!([]));

    std::fs::write(&h.policy_path, BROKEN).unwrap();
    let head = h.audit_head().await;
    let v = h.admin_get("/admin/policies/check").await;
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["sha256"], sha256_hex(BROKEN));
    assert_eq!(v["loaded_sha256"], sha256_hex(POLICY));
    assert_eq!(v["differs_from_loaded"], true);
    let issues = v["issues"].as_array().unwrap();
    assert!(!issues.is_empty());
    assert!(v["error_count"].as_u64().unwrap() >= 1);
    for i in issues {
        assert_eq!(i["severity"], "error", "{i}");
        assert_eq!(i["stage"], "parse", "{i}");
    }
    let located = issues
        .iter()
        .find(|i| i["line"].is_u64() && i["column"].is_u64())
        .unwrap_or_else(|| panic!("no issue has a location: {v}"));
    assert_eq!(located["line"], 5, "{located}");

    // A file that parses but does not validate is reported at the offending policy.
    std::fs::write(
        &h.policy_path,
        "@id(\"ok\")\npermit(principal, action, resource)\nwhen { resource.no_such_attribute };\n",
    )
    .unwrap();
    let v = h.admin_get("/admin/policies/check").await;
    assert_eq!(v["ok"], false, "{v}");
    let i = &v["issues"][0];
    assert_eq!(i["stage"], "validate", "{i}");
    assert_eq!(i["policy_id"], "ok", "{i}");
    assert_eq!(i["line"], 3, "{i}");
    assert!(i["column"].is_u64(), "{i}");

    // Nothing was swapped or audited.
    let loaded = h.admin_get("/admin/policies").await;
    assert_eq!(loaded["sha256"], sha256_hex(POLICY));
    assert_eq!(
        loaded["policy_ids"],
        json!(["issues", "no_secrets", "public_reads"])
    );
    assert_eq!(h.audit_head().await, head);
}

/// The dry run and `POST /access/v1/evaluation` agree on decision, reason and policy ids for
/// chains from real tokens with live leases, whether the dry run gets the token or the chain.
#[tokio::test]
async fn dry_run_agrees_with_authzen() {
    let h = Harness::start().await;
    let root = h.mint_root(&["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;

    let cases = [
        (
            &root,
            "read_file",
            json!({"repo": "alice/public-site"}),
            "policy_allow",
        ),
        (
            &child,
            "read_file",
            json!({"repo": "alice/public-site"}),
            "policy_allow",
        ),
        (
            &root,
            "read_file",
            json!({"repo": "alice/public-secrets"}),
            "policy_deny",
        ),
        (
            &root,
            "read_file",
            json!({"repo": "alice/private"}),
            "policy_deny",
        ),
        (
            &child,
            "create_issue",
            json!({"repo": "alice/public-site"}),
            "capability_denied",
        ),
        (
            &root,
            "delete_org",
            json!({"org": "acme"}),
            "tool_not_in_catalog",
        ),
    ];
    for (minted, tool, args, reason) in &cases {
        let az = h
            .authzen(&minted.token, call_body(tool, args.clone()))
            .await;
        assert_eq!(az["context"]["reason"], *reason, "authzen {tool} {args}");

        let (status, by_token) = h
            .evaluate(with_token(call_body(tool, args.clone()), &minted.token))
            .await;
        assert_eq!(status, StatusCode::OK, "{by_token}");
        let chain = h.chain_of(&minted.token);
        let call = ToolCall::new("github", *tool, args.clone());
        let (status, by_chain) = h
            .evaluate(serde_json::to_value(authzen::to_request(&chain, &call)).unwrap())
            .await;
        assert_eq!(status, StatusCode::OK, "{by_chain}");

        for (dry, source) in [(&by_token, "token"), (&by_chain, "admin_supplied")] {
            assert_eq!(
                dry["decision"] == "allow",
                az["decision"].as_bool().unwrap(),
                "{source} {tool} {args}: {dry}"
            );
            assert_eq!(dry["reason"], az["context"]["reason"], "{source} {tool}");
            assert_eq!(
                dry["policy_ids"], az["context"]["policy_ids"],
                "{source} {tool}"
            );
            assert_eq!(dry["lease_check"], "skipped");
            assert_eq!(dry["chain_source"], source);
            assert_eq!(dry["token_expired"], false);
        }
    }
    // The forbid names itself.
    let (_, v) = h
        .evaluate(with_token(
            call_body("read_file", json!({"repo": "alice/public-secrets"})),
            &root.token,
        ))
        .await;
    assert_eq!(v["policy_ids"], json!(["no_secrets"]));
}

#[tokio::test]
async fn dry_run_writes_no_audit_counts_no_decision_and_skips_revoked_leases() {
    let h = Harness::start().await;
    let root = h.mint_root(&["github:*"]).await;
    let body = with_token(
        call_body("read_file", json!({"repo": "alice/public-site"})),
        &root.token,
    );
    let head = h.audit_head().await;
    let counters = h.decision_counters();

    let (status, v) = h.evaluate(body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["decision"], "allow");
    assert_eq!(h.audit_head().await, head);
    assert_eq!(h.decision_counters(), counters);

    // Revoke the lease: the real endpoint now denies, the dry run still says what policy says.
    let resp = h
        .admin_post(&format!("/admin/leases/{}/revoke", root.lease), json!({}))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!h
        .state
        .leases
        .is_active(&LeaseId::new(&root.lease), OffsetDateTime::now_utc())
        .unwrap());
    let az = h
        .authzen(
            &root.token,
            call_body("read_file", json!({"repo": "alice/public-site"})),
        )
        .await;
    assert_eq!(az["context"]["reason"], "lease_revoked");

    let head = h.audit_head().await;
    let (status, v) = h.evaluate(body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], "allow");
    assert_eq!(v["reason"], "policy_allow");
    assert_eq!(v["policy_ids"], json!(["public_reads"]));
    assert_eq!(v["lease_check"], "skipped");
    assert_eq!(h.audit_head().await, head);
}

fn old_token(h: &Harness) -> (String, attenuo_core::DelegationChain) {
    let then = OffsetDateTime::now_utc() - Duration::hours(2);
    let user = OriginatingUser {
        subject: "alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: then,
        attributes: Default::default(),
    };
    let caps = [Capability::new("github", "read_file")]
        .into_iter()
        .collect::<CapabilitySet>();
    let issued = h
        .state
        .keys()
        .issuer
        .issue_root(
            user,
            AgentId::new("planner"),
            caps,
            Some(Duration::minutes(10)),
            then,
        )
        .unwrap();
    let chain = h
        .state
        .keys()
        .verifier
        .verify(&issued.token, then + Duration::minutes(1))
        .unwrap()
        .chain;
    (issued.token, chain)
}

#[tokio::test]
async fn expired_tokens_are_evaluated_with_a_flag_and_bad_input_is_400() {
    let h = Harness::start().await;
    let call = call_body("read_file", json!({"repo": "alice/public-site"}));

    // Expired but genuine: evaluated, and flagged.
    let (expired, expired_chain) = old_token(&h);
    let (status, v) = h.evaluate(with_token(call.clone(), &expired)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["token_expired"], true);
    assert_eq!(v["decision"], "allow");
    assert_eq!(v["chain_source"], "token");

    // A bad signature.
    let root = h.mint_root(&["github:*"]).await;
    let (head, sig) = root.token.rsplit_once('.').unwrap();
    let mut sig: Vec<char> = sig.chars().collect();
    sig[10] = if sig[10] == 'A' { 'B' } else { 'A' };
    let forged = format!("{head}.{}", sig.into_iter().collect::<String>());
    let (status, v) = h.evaluate(with_token(call.clone(), &forged)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "invalid_token");
    let (status, v) = h.evaluate(with_token(call.clone(), "garbage")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");

    // A bare chain that fails `validate_at` (it has expired).
    let req = authzen::to_request(
        &expired_chain,
        &ToolCall::new("github", "read_file", json!({"repo": "alice/public-site"})),
    );
    let (status, v) = h.evaluate(serde_json::to_value(req).unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "invalid_chain");

    // Neither a token nor a chain.
    let (status, v) = h.evaluate(call.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "invalid_request");

    // A chain that is not the token's.
    let other = h.mint_root(&["github:read_file"]).await;
    let req = authzen::to_request(
        &h.chain_of(&other.token),
        &ToolCall::new("github", "read_file", json!({})),
    );
    let mut body = serde_json::to_value(req).unwrap();
    body["token"] = json!(root.token);
    let (status, v) = h.evaluate(body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "chain_mismatch");
}

#[tokio::test]
async fn policy_routes_need_the_admin_token() {
    let h = Harness::start().await;
    for (method, path) in [
        ("GET", "/admin/policies"),
        ("GET", "/admin/policies/check"),
        ("POST", "/admin/policies/evaluate"),
    ] {
        let req = match method {
            "GET" => h.client.get(h.url(path)),
            _ => h.client.post(h.url(path)).json(&json!({})),
        };
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
        let req = match method {
            "GET" => h.client.get(h.url(path)),
            _ => h.client.post(h.url(path)).json(&json!({})),
        };
        let resp = req.bearer_auth("wrong").send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
    }
}

/// No policy here reads `context.usage` and the catalog names no `amount` or `destination`,
/// so the engine keeps no run usage: the dry run says `untracked` rather than presenting the
/// zeros as the run's usage from the store. Usage given in the request is still `request`.
#[tokio::test]
async fn dry_run_says_untracked_when_the_engine_keeps_no_usage() {
    let h = Harness::start().await;
    assert!(!h.state.pipeline.policy().snapshot().tracks_usage());
    let root = h.mint_root(&["github:*"]).await;
    let body = with_token(
        call_body("create_issue", json!({"repo": "alice/public-site"})),
        &root.token,
    );
    let (status, v) = h.evaluate(body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], "allow", "{v}");
    assert_eq!(
        v["usage"],
        json!({"calls": 0, "amount": 0, "destination_seen": false, "source": "untracked"})
    );
    let mut given = body;
    given["usage"] = json!({"calls": 2});
    let (status, v) = h.evaluate(given).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["usage"]["calls"], 2);
    assert_eq!(v["usage"]["source"], "request");
}

/// The override blocks (`approval`, `session`, `usage`, `budget`) take only their own members:
/// an unknown or misspelt one is 400 `invalid_request` naming it, never ignored, so a typo
/// such as `approved_by` cannot quietly mean "no approval". An `approval` block without `by`
/// (an empty one included) is refused rather than read as granted or as absent; `null` is
/// absent, as for the other blocks.
#[tokio::test]
async fn dry_run_override_blocks_refuse_unknown_members() {
    let h = Harness::start().await;
    let root = h.mint_root(&["github:*"]).await;
    let body = with_token(
        call_body("create_issue", json!({"repo": "alice/public-site"})),
        &root.token,
    );
    let with = |key: &str, block: Value| {
        let mut b = body.clone();
        b[key] = block;
        b
    };

    let (status, v) = h
        .evaluate(with("approval", json!({"by": "operator"})))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["approval"], json!({"present": true, "by": "operator"}));
    let (status, v) = h.evaluate(with("approval", Value::Null)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["approval"]["present"], false, "{v}");

    let refused = [
        (
            "approval",
            json!({"by": "user", "approved_by": "operator"}),
            "`approval`: unknown member `approved_by`",
        ),
        (
            "approval",
            json!({"approved_by": "operator"}),
            "`approval`: unknown member `approved_by`",
        ),
        (
            "approval",
            json!({"by": "user", "id": "a1"}),
            "unknown member `id`",
        ),
        ("approval", json!({}), "`approval`: `by` is required"),
        (
            "approval",
            json!({"by": null}),
            "`approval`: `by` is required",
        ),
        (
            "approval",
            json!({"by": "admin"}),
            "`approval`: `by` must be",
        ),
        ("approval", json!({"by": 1}), "`approval`: `by` must be"),
        (
            "approval",
            json!("operator"),
            "`approval`: expected an object",
        ),
        (
            "session",
            json!({"tainted_by": ["github/read_file"], "taint": true}),
            "`session`: unknown member `taint`",
        ),
        // The unknown member is named even when a known one is malformed too.
        (
            "session",
            json!({"tainted": "yes", "taint": true}),
            "`session`: unknown member `taint`",
        ),
        (
            "usage",
            json!({"calls": 1, "destination": true}),
            "`usage`: unknown member `destination`",
        ),
        (
            "budget",
            json!({"calls_remaining": 1, "remaining": 1}),
            "`budget`: unknown member `remaining`",
        ),
    ];
    for (key, block, msg) in refused {
        let (status, v) = h.evaluate(with(key, block.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{key}: {block}: {v}");
        assert_eq!(v["error"], "invalid_request", "{key}: {block}: {v}");
        let detail = v.to_string();
        assert!(
            detail.contains(msg),
            "{key}: {block}: wanted {msg:?} in {v}"
        );
    }
}

/// Without a policy file there is nothing to check; reading reports an empty set.
#[tokio::test]
async fn no_policy_file_reads_empty_and_check_is_409() {
    let mut cfg = Config::default();
    cfg.admin.token = Some(ADMIN.into());
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let client = reqwest::Client::new();
    let v: Value = client
        .get(server.url("/admin/policies"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["path"], Value::Null);
    assert_eq!(v["sha256"], Value::Null);
    assert_eq!(v["policy_ids"], json!([]));
    let resp = client
        .get(server.url("/admin/policies/check"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

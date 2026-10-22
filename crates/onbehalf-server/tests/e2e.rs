//! End-to-end: the whole server (issuer, policy, audit, leases, proxy) on an ephemeral port in
//! front of a fake MCP server, driven over HTTP the way a client would.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use onbehalf_policy::authzen;
use onbehalf_policy::{ArgType, ToolAttrs};
use onbehalf_proxy::jsonrpc::CODE_DENIED;
use onbehalf_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use onbehalf_proxy::UpstreamConfig;
use onbehalf_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "test-admin-token";
/// Agents registered in `[[agents]]`; each one's secret is [`agent_secret`].
const AGENTS: &[&str] = &["coder", "sneaky", "x", "reviewer"];

fn agent_secret(id: &str) -> String {
    format!("{id}-secret")
}
const TOOLS: &[&str] = &["read_file", "create_issue", "delete_repo"];

const POLICY_PUBLIC_READS: &str = r#"
@id("public_reads")
permit(principal, action == Action::"read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("issues")
permit(principal, action == Action::"create_issue", resource);
"#;

const POLICY_ALL_READS: &str = r#"
@id("all_reads")
permit(principal, action == Action::"read_file", resource);

@id("issues")
permit(principal, action == Action::"create_issue", resource);
"#;

struct Harness {
    upstream: FakeMcpServer,
    _upstream_task: Spawned,
    server: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
    policy_path: PathBuf,
    db_path: Option<PathBuf>,
    _dir: tempfile::TempDir,
}

struct Minted {
    token: String,
    lease: String,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(false).await
    }

    /// `file_db`: back the audit log with a file in a temp dir instead of `:memory:`.
    async fn start_with(file_db: bool) -> Self {
        Self::start_tweaked(file_db, |_| {}).await
    }

    /// As [`start_with`](Self::start_with), with a last chance to change the config.
    async fn start_tweaked(file_db: bool, tweak: impl FnOnce(&mut Config)) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY_PUBLIC_READS).unwrap();
        let db_path = file_db.then(|| dir.path().join("audit.sqlite"));

        let upstream = FakeMcpServer::new(TOOLS);
        let upstream_task = upstream.spawn().await.unwrap();

        let mut cfg = Config::default();
        cfg.issuer.issuer = "https://onbehalf.test".into();
        cfg.issuer.audience = "onbehalf-test".into();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.policy.policies_path = Some(policy_path.clone());
        let repo = || ToolAttrs::new().with_input("repo", ArgType::String);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_file".to_string(), repo().readonly(true)),
                ("create_issue".to_string(), repo()),
                ("delete_repo".to_string(), repo().sensitive(true)),
            ]),
        )]);
        cfg.audit.sqlite_path = match &db_path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => ":memory:".into(),
        };
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = AGENTS
            .iter()
            .map(|id| onbehalf_server::config::AgentConfig {
                id: (*id).into(),
                secret_sha256: sha256_hex(&agent_secret(id)),
            })
            .collect();
        tweak(&mut cfg);

        let (router, state) = onbehalf_server::build(&cfg).unwrap();
        assert!(dir.path().join("keys/issuer.pem").exists());
        let server = spawn_router(router).await.unwrap();
        Self {
            upstream,
            _upstream_task: upstream_task,
            server,
            state,
            client: reqwest::Client::new(),
            policy_path,
            db_path,
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

    async fn mint_root(&self, subject: &str, agent: &str, caps: &[&str]) -> Minted {
        let resp = self
            .admin_post(
                "/admin/root-token",
                json!({
                    "subject": subject,
                    "issuer": "https://idp.example",
                    "agent": agent,
                    "capabilities": caps,
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        }
    }

    /// Exchange, authenticating as `actor` with its client secret.
    async fn exchange_raw(&self, parent: &str, actor: &str, caps: &[&str]) -> reqwest::Response {
        self.exchange_as(parent, actor, caps, Some((actor, &agent_secret(actor))))
            .await
    }

    /// Exchange with explicit client credentials (sent as `client_id` / `client_secret`).
    async fn exchange_as(
        &self,
        parent: &str,
        actor: &str,
        caps: &[&str],
        client: Option<(&str, &str)>,
    ) -> reqwest::Response {
        let caps: Vec<Value> = caps
            .iter()
            .map(|c| {
                let (s, t) = c.split_once(':').unwrap();
                json!({"server": s, "tool": t})
            })
            .collect();
        self.client
            .post(self.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{"type": "onbehalf_capabilities", "capabilities": caps}],
                "client_id": client.map(|c| c.0),
                "client_secret": client.map(|c| c.1),
            }))
            .send()
            .await
            .unwrap()
    }

    async fn exchange(&self, parent: &str, actor: &str, caps: &[&str]) -> Minted {
        let resp = self.exchange_raw(parent, actor, caps).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        }
    }

    async fn rpc(&self, token: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(self.url("/mcp/github"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    async fn call(&self, token: &str, tool: &str, args: Value) -> Value {
        self.rpc(
            token,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": tool, "arguments": args}}),
        )
        .await
    }

    async fn list_tools(&self, token: &str) -> Vec<String> {
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
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    async fn audit_entries(&self) -> Vec<Value> {
        let v = self.admin_get("/admin/audit?from=1&limit=1000").await;
        v["entries"].as_array().unwrap().clone()
    }

    async fn authzen(&self, bearer: Option<&str>, body: Value) -> reqwest::Response {
        let mut req = self
            .client
            .post(self.url("/access/v1/evaluation"))
            .json(&body);
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        req.send().await.unwrap()
    }
}

fn allowed(resp: &Value) -> bool {
    resp.get("result").is_some() && resp.get("error").is_none()
}

/// The denial reason, asserting the response is a -32003 denial.
fn denied_reason(resp: &Value) -> String {
    assert_eq!(resp["error"]["code"], json!(CODE_DENIED), "{resp}");
    resp["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .to_string()
}

fn tool_calls(entries: &[Value]) -> Vec<&Value> {
    entries
        .iter()
        .filter(|e| e["record"]["server"] == "github")
        .collect()
}

fn authzen_body(tool: &str, args: Value) -> Value {
    json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": tool},
        "resource": {"type": "tool", "id": format!("github/{tool}"),
                     "properties": {"server": "github"}},
        "context": {"input": args},
    })
}

// ---------------------------------------------------------------------------------------------
// Scenario 1: argument-level policy through the proxy, with attribution in the audit log.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn policy_restricts_arguments_and_audit_attributes() {
    let h = Harness::start().await;
    let alice = h.mint_root("alice", "planner", &["github:*"]).await;

    let ok = h
        .call(
            &alice.token,
            "read_file",
            json!({"repo": "alice/public-site"}),
        )
        .await;
    assert!(allowed(&ok), "{ok}");

    let no = h
        .call(
            &alice.token,
            "read_file",
            json!({"repo": "alice/private-salaries"}),
        )
        .await;
    assert_eq!(denied_reason(&no), "policy_deny");

    // Only the allowed call reached the upstream.
    let calls = h.upstream.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].arguments["repo"], "alice/public-site");

    let entries = h.audit_entries().await;
    // Issuance is recorded too, under server `onbehalf`.
    assert_eq!(entries[0]["record"]["server"], "onbehalf");
    assert_eq!(entries[0]["record"]["tool"], "token.root");
    assert_eq!(entries[0]["record"]["reason"], "token_issued");
    let calls = tool_calls(&entries);
    assert_eq!(calls.len(), 2);
    for e in &calls {
        assert_eq!(e["record"]["originating_subject"], "alice");
        assert_eq!(e["record"]["agents"], json!(["planner"]));
        assert_eq!(e["record"]["tool"], "read_file");
        assert_eq!(e["record"]["leases"], json!([alice.lease]));
    }
    assert_eq!(calls[0]["record"]["decision"], "allow");
    assert_eq!(calls[0]["record"]["policy_ids"], json!(["public_reads"]));
    assert_eq!(calls[1]["record"]["decision"], "deny");
    assert_eq!(calls[1]["record"]["reason"], "policy_deny");
}

// ---------------------------------------------------------------------------------------------
// Scenario 2: attenuation across an exchange.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn child_is_attenuated_and_cannot_widen() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;

    let ok = h
        .call(
            &child.token,
            "read_file",
            json!({"repo": "alice/public-site"}),
        )
        .await;
    assert!(allowed(&ok), "{ok}");
    let no = h
        .call(
            &child.token,
            "create_issue",
            json!({"repo": "alice/public-site"}),
        )
        .await;
    assert_eq!(denied_reason(&no), "capability_denied");
    // The root could have made that call: the denial is the attenuation, not the policy.
    let root_ok = h
        .call(
            &root.token,
            "create_issue",
            json!({"repo": "alice/public-site"}),
        )
        .await;
    assert!(allowed(&root_ok), "{root_ok}");

    // Exchanging the child back up to github:* fails.
    let resp = h.exchange_raw(&child.token, "sneaky", &["github:*"]).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: Value = resp.json().await.unwrap();
    assert_eq!(err["error"], "invalid_scope");
    assert!(
        err["detail"]
            .as_str()
            .unwrap()
            .contains("delegation chain is invalid"),
        "{err}"
    );

    // The child's audit records name both agents, root first.
    let entries = h.audit_entries().await;
    let exchange = entries
        .iter()
        .find(|e| e["record"]["tool"] == "token.exchange")
        .unwrap();
    assert_eq!(exchange["record"]["agents"], json!(["planner", "coder"]));
    let child_call = tool_calls(&entries)[0];
    assert_eq!(child_call["record"]["agents"], json!(["planner", "coder"]));
    assert_eq!(
        child_call["record"]["leases"],
        json!([root.lease, child.lease])
    );
}

#[tokio::test]
async fn exchange_accepts_rfc8693_form_encoding() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let details = json!([{"type": "onbehalf_capabilities",
                          "capabilities": [{"server": "github", "tool": "read_file"}]}])
    .to_string();
    let form = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("subject_token", root.token.as_str()),
        ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
        ("actor", "coder"),
        ("client_id", "coder"),
        ("client_secret", "coder-secret"),
        ("authorization_details", details.as_str()),
        ("requested_ttl_seconds", "120"),
    ];
    let body = serde_urlencoded_body(&form);
    let resp = h
        .client
        .post(h.url("/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["token_type"], "Bearer");
    assert_eq!(
        v["issued_token_type"],
        "urn:ietf:params:oauth:token-type:jwt"
    );
    assert!(v["expires_in"].as_u64().unwrap() <= 120);
    assert_eq!(
        h.list_tools(v["access_token"].as_str().unwrap()).await,
        vec!["read_file"]
    );

    // Wrong grant type, and a garbage subject token.
    let bad = serde_urlencoded_body(&[("grant_type", "client_credentials")]);
    let resp = h
        .client
        .post(h.url("/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(bad)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = h
        .exchange_raw("not.a.token", "x", &["github:read_file"])
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
}

fn serde_urlencoded_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// SR-10: the actor of an exchange is authenticated, and an agent cannot appear twice.
#[tokio::test]
async fn exchange_actor_must_authenticate_as_itself() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let caps = &["github:read_file"];
    let error = |v: &Value| {
        (
            v["error"].as_str().unwrap_or_default().to_string(),
            v["error_description"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    };

    // No credentials: 401 invalid_client.
    let resp = h.exchange_as(&root.token, "coder", caps, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        error(&resp.json().await.unwrap()),
        ("invalid_client".into(), "client_auth_missing".into())
    );
    // Wrong secret, unknown client.
    for client in [("coder", "nope"), ("ghost", "ghost-secret")] {
        let resp = h
            .exchange_as(&root.token, "coder", caps, Some(client))
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{client:?}");
    }
    // A compromised sub-agent with its own valid credentials cannot name another agent.
    let resp = h
        .exchange_as(
            &root.token,
            "release-bot",
            caps,
            Some(("coder", "coder-secret")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        error(&resp.json().await.unwrap()),
        ("invalid_request".into(), "actor_mismatch".into())
    );
    // HTTP Basic works too.
    let resp = h
        .client
        .post(h.url("/token"))
        .basic_auth("coder", Some("coder-secret"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": root.token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": "coder",
            "authorization_details": [{"type": "onbehalf_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let child: Value = resp.json().await.unwrap();

    // coder -> reviewer -> coder again is refused with a clear error.
    let reviewer = h
        .exchange(child["access_token"].as_str().unwrap(), "reviewer", caps)
        .await;
    let resp = h.exchange_raw(&reviewer.token, "coder", caps).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: Value = resp.json().await.unwrap();
    assert_eq!(
        error(&err),
        ("invalid_request".into(), "duplicate_actor".into())
    );
    assert!(err["detail"].as_str().unwrap().contains("coder"), "{err}");
}

/// SR-10: `[token] require_actor_auth = false` restores asserted actors (with a startup
/// warning), but credentials that are sent are still checked.
#[tokio::test]
async fn actor_auth_can_be_switched_off_explicitly() {
    let h = Harness::start_tweaked(false, |cfg| cfg.token.require_actor_auth = false).await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let resp = h
        .exchange_as(&root.token, "anyone", &["github:read_file"], None)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = h
        .exchange_as(
            &root.token,
            "coder",
            &["github:read_file"],
            Some(("coder", "wrong")),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------------------------
// Scenario 3: revoking the root lease cuts off the child on its next call.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn revoking_root_lease_cascades_to_child() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    let args = json!({"repo": "alice/public-site"});

    assert!(allowed(
        &h.call(&child.token, "read_file", args.clone()).await
    ));

    let resp = h
        .admin_post(
            &format!("/admin/leases/{}/revoke", root.lease),
            json!({"reason": "user logged out"}),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["revoked"], 2, "root and child leases");

    let after = h.call(&child.token, "read_file", args.clone()).await;
    assert_eq!(denied_reason(&after), "lease_revoked");
    assert_eq!(h.upstream.recorded_calls().len(), 1);

    let status = h.admin_get(&format!("/admin/leases/{}", child.lease)).await;
    assert_eq!(status["active"], false);
    assert_eq!(status["parent"], json!(root.lease));
    assert_eq!(status["revoke_reason"], "user logged out");

    // A revoked token cannot delegate further either.
    let resp = h
        .exchange_raw(&child.token, "x", &["github:read_file"])
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: Value = resp.json().await.unwrap();
    assert!(err["detail"].as_str().unwrap().contains("lease_revoked"));

    // Unknown leases are 404, not a silent success.
    let resp = h
        .admin_post("/admin/leases/nope/revoke", json!({"reason": "x"}))
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Scenario 4: the AuthZEN endpoint agrees with the proxy.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn authzen_matches_proxy_decisions() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;

    let cases = [
        ("read_file", json!({"repo": "alice/public-site"})),
        ("read_file", json!({"repo": "alice/private-salaries"})),
        ("create_issue", json!({"repo": "alice/public-site"})),
    ];
    for (tool, args) in &cases {
        let proxy = h.call(&child.token, tool, args.clone()).await;
        let resp = h
            .authzen(Some(&child.token), authzen_body(tool, args.clone()))
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let az: Value = resp.json().await.unwrap();
        assert_eq!(
            az["decision"].as_bool().unwrap(),
            allowed(&proxy),
            "{tool} {args}"
        );
        if !allowed(&proxy) {
            assert_eq!(az["context"]["reason"], proxy["error"]["data"]["reason"]);
        }
        assert!(az["context"]["decision_id"].is_string());
    }

    // Without a bearer the endpoint refuses by default, even for a genuine chain (SR-08).
    let chain = h
        .state
        .verifier
        .verify(&child.token, time::OffsetDateTime::now_utc())
        .unwrap()
        .chain;
    let call =
        onbehalf_core::ToolCall::new("github", "read_file", json!({"repo": "alice/public-site"}));
    let body = serde_json::to_value(authzen::to_request(&chain, &call)).unwrap();
    let resp = h.authzen(None, body).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key("www-authenticate"));

    // A body chain that disagrees with the bearer is rejected.
    let mut forged = chain.clone();
    for (i, hop) in forged.hops.iter_mut().enumerate() {
        hop.lease = onbehalf_core::LeaseId::new(format!("forged-{i}"));
    }
    let body = serde_json::to_value(authzen::to_request(&forged, &call)).unwrap();
    let resp = h.authzen(Some(&child.token), body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "chain_mismatch"
    );

    // No bearer and no chain.
    let resp = h.authzen(None, authzen_body("read_file", json!({}))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // A bad bearer.
    let resp = h
        .authzen(Some("garbage"), authzen_body("read_file", json!({})))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Discovery.
    let cfg: Value = h
        .client
        .get(h.url("/.well-known/authzen-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cfg["access_evaluation_endpoint"],
        h.url("/access/v1/evaluation")
    );
}

const PEP_SECRET: &str = "pep-secret-for-tests";

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

/// SR-08: with `allow_unsigned_chain`, a body chain needs PEP credentials and must match, hop by
/// hop, a chain this server issued. Lease ids alone (they are printed in every token) are not
/// enough to forge a user, attributes or capabilities, and a refused chain leaves no audit
/// record in the victim's name.
#[tokio::test]
async fn unsigned_authzen_chains_need_a_pep_and_an_issued_chain() {
    let h = Harness::start_tweaked(false, |cfg| {
        cfg.authzen.allow_unsigned_chain = true;
        cfg.peps = vec![onbehalf_server::config::PepConfig {
            id: "gateway".into(),
            secret_sha256: sha256_hex(PEP_SECRET),
        }];
    })
    .await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    let chain = h
        .state
        .verifier
        .verify(&child.token, time::OffsetDateTime::now_utc())
        .unwrap()
        .chain;
    let read =
        onbehalf_core::ToolCall::new("github", "read_file", json!({"repo": "alice/public-site"}));
    let with_pep = |chain: &onbehalf_core::DelegationChain,
                    call: &onbehalf_core::ToolCall,
                    secret: Option<&str>| {
        let mut body = serde_json::to_value(authzen::to_request(chain, call)).unwrap();
        if let Some(s) = secret {
            body["pep_id"] = json!("gateway");
            body["pep_secret"] = json!(s);
        }
        body
    };
    let audit_len = |entries: Vec<Value>| entries.len();

    // The genuine chain from an authenticated PEP: decided and audited.
    let before = audit_len(h.audit_entries().await);
    let az: Value = h
        .authzen(None, with_pep(&chain, &read, Some(PEP_SECRET)))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(az["decision"], true, "{az}");
    assert_eq!(audit_len(h.audit_entries().await), before + 1);
    // The root chain alone is a genuine chain too.
    let root_chain = onbehalf_core::DelegationChain {
        originating_user: chain.originating_user.clone(),
        hops: chain.hops[..1].to_vec(),
    };
    let az: Value = h
        .authzen(None, with_pep(&root_chain, &read, Some(PEP_SECRET)))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(az["decision"], true, "{az}");

    // PEP credentials are required: none, wrong, and HTTP Basic.
    let resp = h.authzen(None, with_pep(&chain, &read, None)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "invalid_client"
    );
    let resp = h
        .authzen(None, with_pep(&chain, &read, Some("wrong")))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = h
        .client
        .post(h.url("/access/v1/evaluation"))
        .basic_auth("gateway", Some(PEP_SECRET))
        .json(&with_pep(&chain, &read, None))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Forgeries built from real, live lease ids. None of them is decided or audited.
    let before = audit_len(h.audit_entries().await);
    let mut other_user = chain.clone();
    other_user.originating_user.subject = "bob".into();
    let mut mfa = chain.clone();
    mfa.originating_user
        .attributes
        .insert("mfa".into(), json!(true));
    let mut wider = chain.clone();
    wider.hops[1].capabilities = root_chain.hops[0].capabilities.clone();
    let mut other_agent = chain.clone();
    other_agent.hops[1].agent = onbehalf_core::AgentId::new("release-bot");
    let mut root_lease_twice = chain.clone();
    root_lease_twice.hops[1].lease = chain.hops[0].lease.clone();
    let mut swapped = root_chain.clone();
    swapped.hops[0].lease = chain.hops[1].lease.clone();
    for (name, forged, status) in [
        ("other user", &other_user, StatusCode::FORBIDDEN),
        ("mfa attribute", &mfa, StatusCode::FORBIDDEN),
        ("wider child", &wider, StatusCode::FORBIDDEN),
        ("other agent", &other_agent, StatusCode::FORBIDDEN),
        (
            "child lease on the root hop",
            &swapped,
            StatusCode::FORBIDDEN,
        ),
        (
            "root lease twice",
            &root_lease_twice,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let resp = h
            .authzen(None, with_pep(forged, &read, Some(PEP_SECRET)))
            .await;
        assert_eq!(resp.status(), status, "{name}");
        let err: Value = resp.json().await.unwrap();
        if status == StatusCode::FORBIDDEN {
            assert_eq!(err["error"], "chain_not_issued", "{name}: {err}");
        }
    }
    assert_eq!(
        audit_len(h.audit_entries().await),
        before,
        "refused chains write no audit records"
    );

    // The bearer path still works alongside.
    let resp = h
        .authzen(
            Some(&child.token),
            authzen_body("read_file", json!({"repo": "alice/public-site"})),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------------------------
// Scenario 5: audit verification, and tamper detection on a file-backed log.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn audit_verify_detects_tampering() {
    let h = Harness::start_with(true).await;
    let alice = h.mint_root("alice", "planner", &["github:*"]).await;
    h.call(
        &alice.token,
        "read_file",
        json!({"repo": "alice/public-site"}),
    )
    .await;
    h.call(
        &alice.token,
        "read_file",
        json!({"repo": "alice/private-salaries"}),
    )
    .await;

    let report = h.admin_get("/admin/audit/verify").await;
    assert_eq!(report["ok"], true);
    assert_eq!(report["entries"], 3);
    assert_eq!(report["first_bad_seq"], Value::Null);
    let cp = h.admin_get("/admin/audit/checkpoint").await;
    assert_eq!(cp["seq"], 3);
    assert_eq!(cp["hash"].as_str().unwrap().len(), 64);

    // Turn the recorded denial into an allow behind the server's back.
    let entries = h.audit_entries().await;
    let deny_seq = entries
        .iter()
        .find(|e| e["record"]["decision"] == "deny")
        .unwrap()["seq"]
        .as_u64()
        .unwrap();
    let conn = rusqlite::Connection::open(h.db_path.as_ref().unwrap()).unwrap();
    let changed = conn
        .execute(
            "UPDATE audit SET record_json = replace(record_json, '\"decision\":\"deny\"', \
             '\"decision\":\"allow\"'), decision = 'allow' WHERE seq = ?1",
            [deny_seq as i64],
        )
        .unwrap();
    assert_eq!(changed, 1);
    drop(conn);

    let report = h.admin_get("/admin/audit/verify").await;
    assert_eq!(report["ok"], false);
    assert_eq!(report["first_bad_seq"], deny_seq);
}

// ---------------------------------------------------------------------------------------------
// Scenario 6: tools/list is filtered to what the token could ever call.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn tools_list_is_filtered_for_child() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    let mut all = h.list_tools(&root.token).await;
    all.sort();
    assert_eq!(all, vec!["create_issue", "delete_repo", "read_file"]);
    assert_eq!(h.list_tools(&child.token).await, vec!["read_file"]);
}

// ---------------------------------------------------------------------------------------------
// Scenario 7: policy hot reload.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn policy_reload_changes_decision_without_restart() {
    let h = Harness::start().await;
    let alice = h.mint_root("alice", "planner", &["github:*"]).await;
    let private = json!({"repo": "alice/private-salaries"});

    let before = h.call(&alice.token, "read_file", private.clone()).await;
    assert_eq!(denied_reason(&before), "policy_deny");

    std::fs::write(&h.policy_path, POLICY_ALL_READS).unwrap();
    let resp = h.admin_post("/admin/policies/reload", json!({})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["policy_ids"], json!(["all_reads", "issues"]));

    let after = h.call(&alice.token, "read_file", private.clone()).await;
    assert!(allowed(&after), "{after}");

    // An invalid file is refused and the last good set stays in force.
    std::fs::write(
        &h.policy_path,
        "permit(principal, action == Action::\"no_such_tool\", resource);",
    )
    .unwrap();
    let resp = h.admin_post("/admin/policies/reload", json!({})).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["error"],
        "policy_invalid"
    );
    assert!(allowed(&h.call(&alice.token, "read_file", private).await));
}

// ---------------------------------------------------------------------------------------------
// Admin auth, discovery, health.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn admin_routes_require_the_admin_token() {
    let h = Harness::start().await;
    for (method, path) in [
        ("POST", "/admin/root-token"),
        ("GET", "/admin/audit"),
        ("GET", "/admin/audit/verify"),
        ("POST", "/admin/policies/reload"),
        ("POST", "/admin/leases/x/revoke"),
    ] {
        let req = match method {
            "POST" => h.client.post(h.url(path)).json(&json!({})),
            _ => h.client.get(h.url(path)),
        };
        let resp = req.try_clone().unwrap().send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        let resp = req.bearer_auth("wrong").send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "unauthorized");
    }
    // A delegation token is not an admin token.
    let alice = h.mint_root("alice", "planner", &["github:*"]).await;
    let resp = h
        .client
        .get(h.url("/admin/audit"))
        .bearer_auth(&alice.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwks_verifies_issued_tokens_and_health_is_ok() {
    let h = Harness::start().await;
    let health: Value = h
        .client
        .get(h.url("/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");

    let jwks: Value = h
        .client
        .get(h.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["kid"].as_str().unwrap().len(), 22);

    // Rebuild a PEM from the JWK alone and verify a token with it, as a third party would.
    use base64::Engine;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key["x"].as_str().unwrap())
        .unwrap();
    let mut spki = hex::decode("302a300506032b6570032100").unwrap();
    spki.extend_from_slice(&x);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&spki)
    );
    let verifier = onbehalf_token::Verifier::from_public_pem(
        "https://onbehalf.test",
        "onbehalf-test",
        8,
        &pem,
    )
    .unwrap();
    let alice = h.mint_root("alice", "planner", &["github:read_file"]).await;
    let verified = verifier
        .verify(&alice.token, time::OffsetDateTime::now_utc())
        .unwrap();
    assert_eq!(verified.chain.originating_user.subject, "alice");

    // An unauthenticated proxy call is a 401 with JSON-RPC -32001.
    let resp = h
        .client
        .post(h.url("/mcp/github"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------------------------
// Scenario 7: lease renewal and expiry.
// ---------------------------------------------------------------------------------------------

use onbehalf_audit::LeaseStore;
use onbehalf_core::LeaseId;
use time::{Duration, OffsetDateTime};

impl Harness {
    fn lease_expiry(&self, lease: &str) -> OffsetDateTime {
        self.state
            .leases
            .get(&LeaseId::new(lease))
            .unwrap()
            .unwrap()
            .expires_at
    }

    /// Force a lease's expiry, as if time had passed since the last renewal.
    fn set_lease_expiry(&self, lease: &str, at: OffsetDateTime) {
        self.state
            .leases
            .renew(&LeaseId::new(lease), at, OffsetDateTime::now_utc())
            .unwrap();
    }

    async fn renew_raw(&self, token: Option<&str>) -> reqwest::Response {
        let mut req = self.client.post(self.url("/token/renew"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send().await.unwrap()
    }
}

fn near(a: OffsetDateTime, b: OffsetDateTime) -> bool {
    (a - b).abs() < Duration::seconds(5)
}

#[tokio::test]
async fn leases_are_issued_with_the_lease_interval_not_the_token_ttl() {
    let h = Harness::start().await;
    let now = OffsetDateTime::now_utc();
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    // Default token TTL is 900 s, default lease interval 300 s.
    assert!(near(
        h.lease_expiry(&root.lease),
        now + Duration::seconds(300)
    ));
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    assert!(near(
        h.lease_expiry(&child.lease),
        now + Duration::seconds(300)
    ));
}

#[tokio::test]
async fn renew_extends_by_the_interval_and_is_audited() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let soon = OffsetDateTime::now_utc() + Duration::seconds(20);
    h.set_lease_expiry(&root.lease, soon);

    let resp = h.renew_raw(Some(&root.token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["lease"], json!(root.lease));
    let expires_at = OffsetDateTime::parse(
        v["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(near(
        expires_at,
        OffsetDateTime::now_utc() + Duration::seconds(300)
    ));
    assert_eq!(h.lease_expiry(&root.lease), expires_at);
    assert!((298..=300).contains(&v["expires_in"].as_i64().unwrap()));

    let entries = h.audit_entries().await;
    let last = entries.last().unwrap();
    assert_eq!(last["record"]["tool"], "lease.renew");
    assert_eq!(last["record"]["reason"], "lease_renewed");
    assert_eq!(last["record"]["server"], "onbehalf");
}

#[tokio::test]
async fn renew_never_goes_beyond_token_expiry() {
    let h = Harness::start().await;
    let resp = h
        .admin_post(
            "/admin/root-token",
            json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner",
                   "capabilities": ["github:*"], "ttl_seconds": 100}),
        )
        .await;
    let v: Value = resp.json().await.unwrap();
    let token = v["access_token"].as_str().unwrap();
    let lease = v["lease"].as_str().unwrap();
    // Issued lease is capped by the 100 s token, not the 300 s interval.
    let issued_exp = h.lease_expiry(lease);
    assert!(near(
        issued_exp,
        OffsetDateTime::now_utc() + Duration::seconds(100)
    ));
    h.set_lease_expiry(lease, OffsetDateTime::now_utc() + Duration::seconds(10));

    let resp = h.renew_raw(Some(token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let renewed = h.lease_expiry(lease);
    assert!(
        near(renewed, issued_exp) && renewed <= issued_exp + Duration::seconds(1),
        "{renewed} vs token exp {issued_exp}"
    );
}

#[tokio::test]
async fn renew_never_goes_beyond_the_parent_lease() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    let parent_exp = OffsetDateTime::now_utc() + Duration::seconds(60);
    h.set_lease_expiry(&root.lease, parent_exp);
    h.set_lease_expiry(
        &child.lease,
        OffsetDateTime::now_utc() + Duration::seconds(5),
    );

    let resp = h.renew_raw(Some(&child.token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h.lease_expiry(&child.lease), parent_exp);
    // Renewing the child did not touch the parent.
    assert_eq!(h.lease_expiry(&root.lease), parent_exp);
}

#[tokio::test]
async fn unrenewed_lease_denies_even_though_the_jwt_is_valid() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let args = json!({"repo": "alice/public-site"});
    assert!(allowed(
        &h.call(&root.token, "read_file", args.clone()).await
    ));

    // The agent stops renewing: the lease lapses while the token is still good for minutes.
    h.set_lease_expiry(
        &root.lease,
        OffsetDateTime::now_utc() - Duration::seconds(1),
    );
    let denied = h.call(&root.token, "read_file", args.clone()).await;
    assert_eq!(denied_reason(&denied), "lease_expired");
    assert_eq!(h.upstream.recorded_calls().len(), 1);

    // tools/list needs a live lease as well.
    let resp = h
        .client
        .post(h.url("/mcp/github"))
        .bearer_auth(&root.token)
        .json(&json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Renewing revives it (the lease lapsed but was not revoked).
    assert_eq!(
        h.renew_raw(Some(&root.token)).await.status(),
        StatusCode::OK
    );
    assert!(allowed(&h.call(&root.token, "read_file", args).await));
}

#[tokio::test]
async fn expired_parent_blocks_child_renewal_and_calls() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    h.set_lease_expiry(
        &root.lease,
        OffsetDateTime::now_utc() - Duration::seconds(1),
    );

    let resp = h.renew_raw(Some(&child.token)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: Value = resp.json().await.unwrap();
    assert_eq!(err["error"], "invalid_grant");
    assert!(err["detail"].as_str().unwrap().contains("lease_expired"));

    let denied = h
        .call(&child.token, "read_file", json!({"repo": "alice/public-x"}))
        .await;
    assert_eq!(denied_reason(&denied), "lease_expired");

    // Renewing the parent restores both.
    assert_eq!(
        h.renew_raw(Some(&root.token)).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        h.renew_raw(Some(&child.token)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn revoked_lease_cannot_be_renewed_and_token_problems_are_401() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    let child = h
        .exchange(&root.token, "coder", &["github:read_file"])
        .await;
    h.admin_post(
        &format!("/admin/leases/{}/revoke", root.lease),
        json!({"reason": "logout"}),
    )
    .await;
    let before = h.lease_expiry(&child.lease);

    for token in [&root.token, &child.token] {
        let resp = h.renew_raw(Some(token)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err: Value = resp.json().await.unwrap();
        assert_eq!(err["error"], "invalid_grant");
        assert!(err["detail"].as_str().unwrap().contains("lease_revoked"));
    }
    assert_eq!(h.lease_expiry(&child.lease), before, "no extension");

    assert_eq!(
        h.renew_raw(None).await.status(),
        StatusCode::UNAUTHORIZED,
        "no bearer"
    );
    assert_eq!(
        h.renew_raw(Some("not.a.jwt")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // The admin token is not a delegation token.
    assert_eq!(
        h.renew_raw(Some(ADMIN)).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revoked_token_cannot_list_tools_over_the_proxy() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:*"]).await;
    assert!(!h.list_tools(&root.token).await.is_empty());
    h.admin_post(
        &format!("/admin/leases/{}/revoke", root.lease),
        json!({"reason": "x"}),
    )
    .await;
    let resp = h
        .client
        .post(h.url("/mcp/github"))
        .bearer_auth(&root.token)
        .json(&json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = h
        .client
        .get(h.url("/mcp/github"))
        .bearer_auth(&root.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn resources_and_unknown_methods_are_authorized_through_the_pipeline() {
    let h = Harness::start().await;
    let root = h.mint_root("alice", "planner", &["github:read_file"]).await;
    let denied = h
        .rpc(
            &root.token,
            json!({"jsonrpc": "2.0", "id": 3, "method": "resources/read",
                   "params": {"uri": "file:///etc/passwd"}}),
        )
        .await;
    assert_eq!(denied_reason(&denied), "capability_denied");
    let denied = h
        .rpc(
            &root.token,
            json!({"jsonrpc": "2.0", "id": 4, "method": "vendor/x", "params": {}}),
        )
        .await;
    assert_eq!(denied_reason(&denied), "capability_denied");
    assert!(h.upstream.recorded_methods().is_empty());
    // Both decisions are in the audit log under the method name.
    let entries = h.audit_entries().await;
    let tools: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["record"]["tool"].as_str())
        .collect();
    assert!(tools.contains(&"resources/read") && tools.contains(&"vendor/x"));
}

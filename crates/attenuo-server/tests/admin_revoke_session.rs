//! `POST /admin/leases/revoke` with `session`: a session opened through the proxy with a real
//! token is bound to its chain in the lease store (as a digest, never the raw id), and the
//! admin revokes that chain by the session id, with a dry run and an audit record.

use std::collections::BTreeMap;
use std::sync::Arc;

use attenuo_audit::LeaseStore;
use attenuo_core::{LeaseId, RecordKind, ToolCall};
use attenuo_policy::ToolAttrs;
use attenuo_proxy::jsonrpc::CODE_DENIED;
use attenuo_proxy::session::{session_digest, session_tag};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::Digest;

const ADMIN: &str = "test-admin-token";
const AGENTS: &[&str] = &["coder"];

struct Harness {
    server: Spawned,
    _upstream: Spawned,
    state: Arc<AppState>,
    client: reqwest::Client,
    dir: tempfile::TempDir,
}

struct Minted {
    token: String,
    lease: String,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("policies.cedar");
        std::fs::write(
            &policy,
            "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
        )
        .unwrap();
        let upstream = FakeMcpServer::new(&["read_file"])
            .with_session_id("raw-session-secret")
            .with_fresh_session_ids(true)
            .spawn()
            .await
            .unwrap();
        let mut cfg = Config::default();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.policy.policies_path = Some(policy);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([("read_file".to_string(), ToolAttrs::new().readonly(true))]),
        )]);
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = AGENTS
            .iter()
            .map(|id| attenuo_server::config::AgentConfig {
                id: (*id).into(),
                secret_sha256: hex::encode(sha2::Sha256::digest(format!("{id}-secret"))),
            })
            .collect();
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            _upstream: upstream,
            state,
            client: reqwest::Client::new(),
            dir,
        }
    }

    async fn revoke(&self, query: &str, body: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url(&format!("/admin/leases/revoke{query}")))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{body}");
        resp.json().await.unwrap()
    }

    async fn mint_root(&self, subject: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": subject,
                "issuer": "https://idp.example",
                "agent": "planner",
                "capabilities": ["github:*"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        minted(resp).await
    }

    async fn exchange(&self, parent: &Minted, actor: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent.token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{
                    "type": "attenuo_capabilities",
                    "capabilities": [{"server": "github", "tool": "read_file"}],
                }],
                "client_id": actor,
                "client_secret": format!("{actor}-secret"),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        minted(resp).await
    }

    /// POST one JSON-RPC message through the proxy: status, `Mcp-Session-Id`, body.
    async fn rpc(
        &self,
        token: &str,
        session: Option<&str>,
        msg: Value,
    ) -> (StatusCode, Option<String>, Value) {
        let mut req = self
            .client
            .post(self.server.url("/mcp/github"))
            .header("accept", "application/json, text/event-stream")
            .bearer_auth(token)
            .json(&msg);
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await.unwrap();
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .map(|v| v.to_str().unwrap().to_string());
        let status = resp.status();
        (status, sid, resp.json().await.unwrap_or(Value::Null))
    }

    /// `initialize` as `token`; the new session's id.
    async fn open(&self, token: &str) -> String {
        let (status, sid, body) = self
            .rpc(
                token,
                None,
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "0"}}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        sid.expect("a session id")
    }

    async fn ping(&self, token: &str, session: &str) -> (StatusCode, Value) {
        let (status, _, body) = self
            .rpc(
                token,
                Some(session),
                json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
            )
            .await;
        (status, body)
    }

    async fn read_file(&self, token: &str, session: &str) -> Value {
        self.rpc(
            token,
            Some(session),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "read_file", "arguments": {}}}),
        )
        .await
        .2
    }

    fn active(&self, lease: &str) -> bool {
        self.state
            .leases
            .is_active(&LeaseId::new(lease), time::OffsetDateTime::now_utc())
            .unwrap()
    }

    fn audit_len(&self) -> u64 {
        self.state.audit.len().unwrap()
    }
}

async fn minted(resp: reqwest::Response) -> Minted {
    let v: Value = resp.json().await.unwrap();
    Minted {
        token: v["access_token"].as_str().unwrap().into(),
        lease: v["lease"].as_str().unwrap().into(),
    }
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

/// A session the coder opens is bound to its chain (root > coder). Revoking by the session id
/// previews, then revokes, that chain only; the next request on the session gets 401
/// `lease_revoked`, and the audit record digests the selector with the resolved chain.
#[tokio::test]
async fn revoke_by_session_revokes_the_chain_that_opened_it() {
    let h = Harness::start().await;
    let root = h.mint_root("alice").await;
    let coder = h.exchange(&root, "coder").await;
    let bob = h.mint_root("bob").await;
    let sid = h.open(&coder.token).await;
    let bob_sid = h.open(&bob.token).await;
    assert!(h.read_file(&coder.token, &sid).await["result"].is_object());

    // Bound as a digest, to the chain id (the root's lease), for the proxied server.
    let bindings = h.state.leases.sessions(&session_digest(&sid)).unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].chain_id.0, root.lease);
    assert_eq!(bindings[0].server, "github");

    let mut chain = vec![root.lease.as_str(), coder.lease.as_str()];
    chain.sort();
    let shown = json!({"session_tag": session_tag(&sid), "chain_ids": [root.lease]});

    // The dry run writes nothing.
    let before = h.audit_len();
    let preview = h
        .revoke("?preview=true", json!({"session": sid, "reason": "x"}))
        .await;
    assert_eq!(preview["preview"], true);
    assert_eq!(preview["selector"], shown);
    assert_eq!(strs(&preview["matched"]), chain);
    assert_eq!(strs(&preview["revoked"]), chain);
    assert_eq!(preview["audit_id"], Value::Null);
    assert_eq!(h.audit_len(), before);
    assert!(h.active(&root.lease) && h.active(&coder.lease));
    assert_eq!(h.ping(&coder.token, &sid).await.0, StatusCode::OK);

    // An unknown session resolves to no chain: an empty answer, like an unknown chain id.
    let v = h
        .revoke("?preview=true", json!({"session": "never-seen"}))
        .await;
    assert_eq!(v["matched_count"], 0);
    assert_eq!(v["selector"]["chain_ids"], json!([]));

    let v = h
        .revoke("", json!({"session": sid, "reason": "session hijacked"}))
        .await;
    assert_eq!(v["preview"], false);
    assert_eq!(v["selector"], shown);
    assert_eq!(v["matched"], preview["matched"]);
    assert_eq!(v["revoked"], preview["revoked"]);
    assert_eq!(v["revoked_count"], 2);
    assert!(!h.active(&root.lease) && !h.active(&coder.lease));
    assert!(h.active(&bob.lease));

    // The next request on the session is refused; bob's session still works.
    let (status, body) = h.ping(&coder.token, &sid).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["data"]["reason"], "lease_revoked");
    let denied = h.read_file(&coder.token, &sid).await;
    assert_eq!(denied["error"]["code"], json!(CODE_DENIED), "{denied}");
    assert_eq!(denied["error"]["data"]["reason"], "lease_revoked");
    assert_eq!(h.ping(&bob.token, &bob_sid).await.0, StatusCode::OK);

    // The audit record names the leases and digests the selector with the resolved chain.
    let entry = h
        .state
        .audit
        .entry_by_record_id(v["audit_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let r = &entry.record;
    assert_eq!(r.kind, RecordKind::LeaseRevoke);
    assert_eq!(r.tool, "admin.lease.revoke");
    let audited: Vec<&str> = r.leases.iter().map(|l| l.0.as_str()).collect();
    assert_eq!(audited, chain);
    let args = json!({
        "selector": shown,
        "reason": "session hijacked",
        "revoked": 2,
        "listed": 2,
        "truncated": false,
    });
    assert_eq!(
        r.arguments_digest,
        ToolCall::new("attenuo", "admin.lease.revoke", args).arguments_digest()
    );
}

/// The raw session id is never written to the database file, only its digest; and a session
/// opened by a token that did not verify leaves no binding (SR-18).
#[tokio::test]
async fn the_raw_session_id_is_not_stored() {
    let h = Harness::start().await;
    let root = h.mint_root("alice").await;
    let sid = h.open(&root.token).await;
    let (status, _, _) = h
        .rpc(
            "not-a-token",
            None,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The fake upstream numbers sessions; an unauthenticated initialize never reached it.
    assert_eq!(sid, "raw-session-secret-1");
    assert!(h
        .state
        .leases
        .sessions(&session_digest("raw-session-secret-2"))
        .unwrap()
        .is_empty());

    let digest = session_digest(&sid);
    assert_eq!(h.state.leases.sessions(&digest).unwrap().len(), 1);
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(h.dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            bytes.extend(std::fs::read(&path).unwrap());
        }
    }
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(contains(digest.as_bytes()), "the digest is stored");
    assert!(!contains(sid.as_bytes()), "the raw session id is not");
}

/// `session` must be a non-empty string and comes alone, like the other selectors.
#[tokio::test]
async fn the_session_selector_is_validated() {
    let h = Harness::start().await;
    for body in [
        json!({"session": ""}),
        json!({"session": 7}),
        json!({"session": "s", "chain_id": "c"}),
        json!({"session": "s", "user": "alice"}),
    ] {
        let resp = h
            .client
            .post(h.server.url("/admin/leases/revoke"))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"], "invalid_request", "{body}");
    }
}

/// Session retention on the server: once alice's chain is revoked, a run of the pruner
/// deletes her session's binding, counts it in `lease_sessions_pruned_total`, and leaves
/// bob's (live) binding alone. Revoking by the pruned session then resolves to no chain,
/// exactly as an unknown session does.
#[tokio::test]
async fn bindings_of_revoked_chains_are_pruned() {
    let h = Harness::start().await;
    let root = h.mint_root("alice").await;
    let bob = h.mint_root("bob").await;
    let sid = h.open(&root.token).await;
    let bob_sid = h.open(&bob.token).await;
    assert_eq!(attenuo_server::prune_session_bindings(&h.state).await, 0);

    h.revoke("", json!({"chain_id": root.lease, "reason": "done"}))
        .await;
    assert_eq!(attenuo_server::prune_session_bindings(&h.state).await, 1);
    let digest = |s: &str| session_digest(s);
    assert!(h.state.leases.sessions(&digest(&sid)).unwrap().is_empty());
    assert_eq!(h.state.leases.sessions(&digest(&bob_sid)).unwrap().len(), 1);
    assert!(h
        .state
        .metrics
        .render()
        .contains("attenuo_lease_sessions_pruned_total 1\n"));

    let v = h.revoke("?preview=true", json!({"session": sid})).await;
    assert_eq!(v["matched_count"], 0);
    assert_eq!(v["selector"]["chain_ids"], json!([]));
    assert_eq!(h.ping(&bob.token, &bob_sid).await.0, StatusCode::OK);
}

/// Lease retention on the server: once every lease of alice's chain (root > coder) has been
/// revoked for longer than `[leases] retention_seconds` (default a week, simulated by moving
/// the revocation back), a run of the lease pruner deletes both leases with their subjects
/// and session binding, counts them in `leases_pruned_total`, and leaves bob's live chain
/// alone. The coder's token is then refused as `lease_unknown`, on the session and on a tool
/// call, and the tool call is audited as a `deny` like any unknown lease; revoke-by-user no
/// longer finds alice's chain and the console tree has no such lease.
#[tokio::test]
async fn lease_trees_of_ended_chains_are_pruned() {
    let h = Harness::start().await;
    assert_eq!(
        h.state.lease_retention,
        Some(time::Duration::weeks(1)),
        "the default"
    );
    let root = h.mint_root("alice").await;
    let coder = h.exchange(&root, "coder").await;
    let bob = h.mint_root("bob").await;
    let sid = h.open(&coder.token).await;
    let bob_sid = h.open(&bob.token).await;
    assert_eq!(attenuo_server::prune_lease_registry(&h.state).await, 0);

    h.revoke("", json!({"chain_id": root.lease, "reason": "done"}))
        .await;
    // Revoked, but within the retention: kept, and refused as revoked.
    assert_eq!(attenuo_server::prune_lease_registry(&h.state).await, 0);
    assert_eq!(
        h.read_file(&coder.token, &sid).await["error"]["data"]["reason"],
        "lease_revoked"
    );

    // Eight days later, as far as the store can tell.
    let past = time::OffsetDateTime::now_utc() - time::Duration::days(8);
    let past = past
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    h.state
        .leases
        .with_connection(|c| {
            c.execute(
                "UPDATE leases SET revoked_at = ?1 WHERE revoked_at IS NOT NULL",
                [&past],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(attenuo_server::prune_lease_registry(&h.state).await, 2);
    let metrics = h.state.metrics.render();
    assert!(
        metrics.contains("attenuo_leases_pruned_total 2\n"),
        "{metrics}"
    );
    for lease in [&root.lease, &coder.lease] {
        let l = LeaseId::new(lease);
        assert_eq!(h.state.leases.get(&l).unwrap(), None);
        assert_eq!(h.state.leases.subject(&l).unwrap(), None);
        assert_eq!(h.state.leases.binding(&l).unwrap(), None);
    }
    assert!(h
        .state
        .leases
        .sessions(&session_digest(&sid))
        .unwrap()
        .is_empty());
    assert!(h.active(&bob.lease));
    assert_eq!(h.ping(&bob.token, &bob_sid).await.0, StatusCode::OK);

    // The coder's token (still valid as a JWT) now names leases the store does not know.
    let (status, body) = h.ping(&coder.token, &sid).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["data"]["reason"], "lease_unknown");
    let denied = h.read_file(&coder.token, &sid).await;
    assert_eq!(denied["error"]["code"], json!(CODE_DENIED), "{denied}");
    assert_eq!(denied["error"]["data"]["reason"], "lease_unknown");
    let entry = h
        .state
        .audit
        .entry_by_record_id(denied["error"]["data"]["decision_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.record.decision, attenuo_core::Decision::Deny);
    assert_eq!(entry.record.reason, "lease_unknown");
    assert_eq!(entry.record.tool, "read_file");
    assert_eq!(entry.record.originating_subject, "alice");
    // A renewal is refused and audited the same way.
    let resp = h
        .client
        .post(h.server.url("/token/renew"))
        .bearer_auth(&coder.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v: Value = resp.json().await.unwrap();
    let entry = h
        .state
        .audit
        .entry_by_record_id(v["decision_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.record.reason, "lease_unknown", "{v}");
    assert_eq!(entry.record.tool, "lease.renew");

    // Revoke-by-user and by chain no longer find it; bob's is still there.
    let v = h
        .revoke("?preview=true", json!({"user": "alice", "reason": "x"}))
        .await;
    assert_eq!(v["matched_count"], 0, "{v}");
    let v = h
        .revoke(
            "?preview=true",
            json!({"chain_id": root.lease, "reason": "x"}),
        )
        .await;
    assert_eq!(v["matched_count"], 0, "{v}");
    let v = h
        .revoke("?preview=true", json!({"user": "bob", "reason": "x"}))
        .await;
    assert_eq!(v["matched_count"], 1, "{v}");
    let tree = h
        .client
        .get(h.server.url(&format!("/admin/leases/{}/tree", root.lease)))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(tree.status(), StatusCode::NOT_FOUND);

    // Nothing more to prune; a session pass finds nothing either (the binding went with it).
    assert_eq!(attenuo_server::prune_lease_registry(&h.state).await, 0);
    assert_eq!(attenuo_server::prune_session_bindings(&h.state).await, 0);
}

//! `POST /admin/leases/revoke`: revoke every lease of one originating user or one delegation
//! chain, with the descendant cascade, an audit record and a dry run. Chains are built through
//! real root mints and token exchanges, so the subjects come from the issued tokens.

mod common;

use std::sync::Arc;

use attenuo_audit::LeaseRegistry;
use attenuo_core::{LeaseId, RecordKind, ToolCall};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};

use common::agent_configs;

const ADMIN: &str = "test-admin-token";
/// Agents that may act in an exchange; each one's secret is `<id>-secret`.
const AGENTS: &[&str] = &["coder", "reviewer"];

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
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
        let mut cfg = Config::default();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = agent_configs(AGENTS, |id| format!("{id}-secret"));
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            state,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    /// `POST /admin/leases/revoke{query}` with the admin bearer.
    async fn post(&self, query: &str, body: &Value) -> reqwest::Response {
        self.client
            .post(self.server.url(&format!("/admin/leases/revoke{query}")))
            .bearer_auth(ADMIN)
            .json(body)
            .send()
            .await
            .unwrap()
    }

    async fn revoke(&self, query: &str, body: Value) -> Value {
        let resp = self.post(query, &body).await;
        assert_eq!(resp.status(), StatusCode::OK, "{body}");
        resp.json().await.unwrap()
    }

    async fn mint_root(&self, subject: &str, agent: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": subject,
                "issuer": "https://idp.example",
                "agent": agent,
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

fn sorted(mut v: Vec<&str>) -> Vec<&str> {
    v.sort();
    v
}

/// Alice has two chains (root1 > coder > reviewer, root2 alone), bob one (broot > coder).
struct Fleet {
    root1: Minted,
    coder: Minted,
    reviewer: Minted,
    root2: Minted,
    broot: Minted,
    bcoder: Minted,
}

async fn fleet(h: &Harness) -> Fleet {
    let root1 = h.mint_root("alice", "planner").await;
    let coder = h.exchange(&root1, "coder").await;
    let reviewer = h.exchange(&coder, "reviewer").await;
    let root2 = h.mint_root("alice", "planner").await;
    let broot = h.mint_root("bob", "planner").await;
    let bcoder = h.exchange(&broot, "coder").await;
    Fleet {
        root1,
        coder,
        reviewer,
        root2,
        broot,
        bcoder,
    }
}

#[tokio::test]
async fn issued_leases_record_their_originating_user() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    for (lease, sub) in [
        (&f.root1, "alice"),
        (&f.reviewer, "alice"),
        (&f.bcoder, "bob"),
    ] {
        let got = h.state.leases.subject(&LeaseId::new(&lease.lease)).unwrap();
        assert_eq!(got.as_deref(), Some(sub));
    }
}

/// Every chain of alice goes, with the cascade; bob's chain stays. One `admin.lease.revoke`
/// record names the revoked leases and digests the selector, reason and count.
#[tokio::test]
async fn revoke_by_user_revokes_every_chain_of_that_user_only() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    let alice = [&f.root1, &f.coder, &f.reviewer, &f.root2];
    let v = h
        .revoke("", json!({"user": "alice", "reason": "laptop stolen"}))
        .await;
    let mut want: Vec<&str> = alice.iter().map(|m| m.lease.as_str()).collect();
    want.sort();
    assert_eq!(strs(&v["matched"]), want);
    assert_eq!(strs(&v["revoked"]), want);
    assert_eq!(v["matched_count"], 4);
    assert_eq!(v["revoked_count"], 4);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["preview"], false);
    assert_eq!(v["selector"], json!({"user": "alice"}));
    assert_eq!(v["reason"], "laptop stolen");
    for m in alice {
        assert!(!h.active(&m.lease), "{}", m.lease);
    }
    assert!(h.active(&f.broot.lease) && h.active(&f.bcoder.lease));

    // The audit record.
    let id = v["audit_id"].as_str().unwrap();
    let entry = h.state.audit.entry_by_record_id(id).unwrap().unwrap();
    let r = &entry.record;
    assert_eq!(r.kind, RecordKind::LeaseRevoke);
    assert_eq!(r.tool, "admin.lease.revoke");
    assert_eq!(r.originating_subject, "urn:attenuo:admin");
    let audited: Vec<&str> = r.leases.iter().map(|l| l.0.as_str()).collect();
    assert_eq!(audited, want);
    let args = json!({
        "selector": {"user": "alice"},
        "reason": "laptop stolen",
        "revoked": 4,
        "listed": 4,
        "truncated": false,
    });
    assert_eq!(
        r.arguments_digest,
        ToolCall::new("attenuo", "admin.lease.revoke", args).arguments_digest()
    );

    // The revoked tokens cannot be renewed.
    let resp = h
        .client
        .post(h.server.url("/token/renew"))
        .bearer_auth(&f.coder.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());

    // Again: nothing left, an empty answer, still audited.
    let before = h.audit_len();
    let v = h.revoke("", json!({"user": "alice"})).await;
    assert_eq!(v["revoked_count"], 0);
    assert_eq!(strs(&v["revoked"]), Vec::<&str>::new());
    assert_eq!(v["reason"], "revoked by admin");
    assert_eq!(h.audit_len(), before + 1);
    let v = h.revoke("", json!({"user": "nobody"})).await;
    assert_eq!(v["matched_count"], 0);
}

/// A chain id revokes that chain (the root and everything under it) and nothing else; a lease
/// with a parent is not a chain id and matches nothing.
#[tokio::test]
async fn revoke_by_chain_revokes_that_chain_only() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    let v = h.revoke("", json!({"chain_id": f.coder.lease})).await;
    assert_eq!(v["matched_count"], 0, "the coder's lease has a parent");
    assert!(h.active(&f.coder.lease));

    let v = h.revoke("", json!({"chain_id": f.root1.lease})).await;
    let want = sorted(vec![&f.root1.lease, &f.coder.lease, &f.reviewer.lease]);
    assert_eq!(strs(&v["matched"]), want);
    assert_eq!(strs(&v["revoked"]), want);
    assert_eq!(v["selector"], json!({"chain_id": f.root1.lease}));
    for m in [&f.root1, &f.coder, &f.reviewer] {
        assert!(!h.active(&m.lease));
    }
    for m in [&f.root2, &f.broot, &f.bcoder] {
        assert!(h.active(&m.lease));
    }
    let entry = h
        .state
        .audit
        .entry_by_record_id(v["audit_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.record.kind, RecordKind::LeaseRevoke);
    assert_eq!(entry.record.leases.len(), 3);
}

/// The dry run names exactly what the revocation then changes, and writes nothing: no lease
/// changes and no audit record is appended.
#[tokio::test]
async fn preview_writes_nothing_and_matches_the_revocation() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    let before = h.audit_len();
    let preview = h
        .revoke("?preview=true", json!({"user": "bob", "reason": "x"}))
        .await;
    assert_eq!(preview["preview"], true);
    assert_eq!(preview["audit_id"], Value::Null);
    assert_eq!(preview["reason"], Value::Null);
    assert_eq!(
        strs(&preview["revoked"]),
        sorted(vec![&f.broot.lease, &f.bcoder.lease])
    );
    assert_eq!(h.audit_len(), before);
    assert!(h.active(&f.broot.lease) && h.active(&f.bcoder.lease));

    let v = h.revoke("?preview=false", json!({"user": "bob"})).await;
    assert_eq!(v["preview"], false);
    assert_eq!(v["revoked"], preview["revoked"]);
    assert_eq!(v["matched"], preview["matched"]);
    assert_eq!(h.audit_len(), before + 1);
}

/// Exactly one non-empty selector; anything else is a 400 that changes nothing.
#[tokio::test]
async fn exactly_one_selector_is_required() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    let before = h.audit_len();
    for (body, code) in [
        (json!({}), "invalid_request"),
        (json!({"reason": "x"}), "invalid_request"),
        (
            json!({"user": "alice", "chain_id": f.root1.lease}),
            "invalid_request",
        ),
        (json!({"user": "alice", "session": "s1"}), "invalid_request"),
        (json!({"user": ""}), "invalid_request"),
        (json!({"chain_id": ""}), "invalid_request"),
        (json!({"user": "alice", "lease": "x"}), "invalid_request"),
        (json!({"user": 7}), "invalid_request"),
        (json!({"session": ""}), "invalid_request"),
    ] {
        let resp = h.post("", &body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"], code, "{body}: {v}");
    }
    // An empty body has no selector either.
    let resp = h
        .client
        .post(h.server.url("/admin/leases/revoke"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(h.audit_len(), before);
    assert!(h.active(&f.root1.lease));
}

#[tokio::test]
async fn the_admin_token_is_required() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    let before = h.audit_len();
    for bearer in [None, Some("wrong")] {
        for query in ["", "?preview=true"] {
            let mut req = h
                .client
                .post(h.server.url(&format!("/admin/leases/revoke{query}")))
                .json(&json!({"user": "alice"}));
            if let Some(b) = bearer {
                req = req.bearer_auth(b);
            }
            let resp = req.send().await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{bearer:?} {query}"
            );
        }
    }
    // An agent's own delegation token is not an admin token.
    let resp = h
        .client
        .post(h.server.url("/admin/leases/revoke"))
        .bearer_auth(&f.root1.token)
        .json(&json!({"user": "bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(h.active(&f.root1.lease) && h.active(&f.broot.lease));
    assert_eq!(h.audit_len(), before);
}

/// The audit record lists at most 256 leases; its arguments carry the full count. The
/// response lists them all (below its own cap of 10,000).
#[tokio::test]
async fn the_audit_record_lists_at_most_256_leases() {
    let h = Harness::start().await;
    let exp = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    for i in 0..300 {
        let l = LeaseId::new(format!("bulk-{i:03}"));
        h.state.leases.register(&l, None, exp).unwrap();
        h.state.leases.record_subject(&l, "carol").unwrap();
    }
    let v = h.revoke("", json!({"user": "carol"})).await;
    assert_eq!(v["revoked_count"], 300);
    assert_eq!(v["revoked"].as_array().unwrap().len(), 300);
    assert_eq!(v["truncated"], false);
    let entry = h
        .state
        .audit
        .entry_by_record_id(v["audit_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.record.leases.len(), 256);
    assert_eq!(entry.record.leases[0].0, "bulk-000");
    assert_eq!(entry.record.leases[255].0, "bulk-255");
    let args = json!({
        "selector": {"user": "carol"},
        "reason": "revoked by admin",
        "revoked": 300,
        "listed": 256,
        "truncated": true,
    });
    assert_eq!(
        entry.record.arguments_digest,
        ToolCall::new("attenuo", "admin.lease.revoke", args).arguments_digest()
    );
    assert!(!h.active("bulk-299"));
}

/// The per-lease route still works next to the selector route, and the two agree.
#[tokio::test]
async fn the_per_lease_revoke_is_unchanged() {
    let h = Harness::start().await;
    let f = fleet(&h).await;
    let resp = h
        .client
        .post(
            h.server
                .url(&format!("/admin/leases/{}/revoke", f.coder.lease)),
        )
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "one"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["revoked"], 2);
    // Alice's chain now has root1 and root2 left.
    let v = h.revoke("?preview=true", json!({"user": "alice"})).await;
    assert_eq!(
        strs(&v["matched"]),
        sorted(vec![&f.root1.lease, &f.root2.lease])
    );
}

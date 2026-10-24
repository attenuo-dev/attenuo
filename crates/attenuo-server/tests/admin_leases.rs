//! `GET /admin/leases/{id}/tree`: the lease tree and cascade preview the admin console shows
//! before a revocation. Chains are built through real root mints and token exchanges, so the
//! agents come from the issuance records the server wrote.

use std::sync::Arc;

use attenuo_audit::LeaseStore;
use attenuo_core::LeaseId;
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::Digest;

const ADMIN: &str = "test-admin-token";
/// Agents that may act in an exchange; each one's secret is `<id>-secret`.
const AGENTS: &[&str] = &["coder", "reviewer", "tester"];

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
        // Audit log and lease registry share one file, as in a real deployment.
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
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
            state,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
    }

    async fn tree(&self, lease: &str, query: &str) -> Value {
        let resp = self
            .get(&format!("/admin/leases/{lease}/tree{query}"))
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "tree of {lease}");
        resp.json().await.unwrap()
    }

    /// `POST /admin/leases/{lease}/revoke`, returning the `revoked` count.
    async fn revoke(&self, lease: &str) -> u64 {
        let resp = self
            .client
            .post(self.server.url(&format!("/admin/leases/{lease}/revoke")))
            .bearer_auth(ADMIN)
            .json(&json!({"reason": "test"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["revoked"].as_u64().unwrap()
    }

    async fn mint_root(&self, agent: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": "alice",
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

    /// Exchange `parent` for a token held by `actor`, authenticating as `actor`.
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

    /// Every lease row, straight from the store, for before/after comparisons.
    fn rows(&self, leases: &[&str]) -> Vec<Option<attenuo_audit::lease::LeaseRow>> {
        leases
            .iter()
            .map(|l| self.state.leases.get(&LeaseId::new(*l)).unwrap())
            .collect()
    }
}

async fn minted(resp: reqwest::Response) -> Minted {
    let v: Value = resp.json().await.unwrap();
    Minted {
        token: v["access_token"].as_str().unwrap().into(),
        lease: v["lease"].as_str().unwrap().into(),
    }
}

fn lease_ids(nodes: &Value) -> Vec<&str> {
    nodes
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["lease_id"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn tree_of_a_child_shows_its_root_and_grandchild_with_their_agents() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    let child = h.exchange(&root, "coder").await;
    let grandchild = h.exchange(&child, "reviewer").await;

    let t = h.tree(&child.lease, "").await;
    assert_eq!(t["root"], json!(root.lease));
    assert_eq!(lease_ids(&t["ancestors"]), [root.lease.as_str()]);
    assert_eq!(
        lease_ids(&t["nodes"]),
        [child.lease.as_str(), grandchild.lease.as_str()]
    );
    assert_eq!(t["would_revoke"], 2);
    assert_eq!(t["truncated"], false);

    let anc = &t["ancestors"][0];
    let (c, g) = (&t["nodes"][0], &t["nodes"][1]);
    assert_eq!(anc["agent"], "planner");
    assert_eq!(c["agent"], "coder");
    assert_eq!(g["agent"], "reviewer");
    assert_eq!(anc["parent"], Value::Null);
    assert_eq!(c["parent"], json!(root.lease));
    assert_eq!(g["parent"], json!(child.lease));
    // Issuance order is audit order.
    let seq = |n: &Value| n["issued_seq"].as_u64().unwrap();
    assert!(seq(anc) < seq(c) && seq(c) < seq(g));
    for n in [anc, c, g] {
        assert_eq!(n["active"], true);
        assert_eq!(n["revoked_at"], Value::Null);
        assert_eq!(n["revoke_reason"], Value::Null);
        assert!(n["issued_at"].is_string() && n["expires_at"].is_string());
    }
    // The issued_seq points at the record that issued the lease.
    let entry = h
        .get(&format!("/admin/audit?from={}&limit=1", seq(g)))
        .await
        .json::<Value>()
        .await
        .unwrap();
    let record = &entry["entries"][0]["record"];
    assert_eq!(record["kind"], "exchange");
    assert_eq!(
        record["leases"].as_array().unwrap().last().unwrap(),
        &json!(grandchild.lease)
    );
}

/// The preview is exact: `would_revoke` is the `revoked` count the revocation then returns,
/// for a fresh subtree, a partly revoked one and a fully revoked one.
#[tokio::test]
async fn would_revoke_equals_the_revocation_that_follows() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    let child = h.exchange(&root, "coder").await;
    let grandchild = h.exchange(&child, "reviewer").await;
    let sibling = h.exchange(&root, "tester").await;

    // Fresh.
    let t = h.tree(&child.lease, "").await;
    assert_eq!(t["would_revoke"], 2);
    assert_eq!(h.revoke(&child.lease).await, 2);
    // Partly revoked: only root and sibling are still live.
    let t = h.tree(&root.lease, "").await;
    assert_eq!(t["would_revoke"], 2);
    // Breadth-first: the root, its two children (in id order), then the grandchild.
    let nodes = lease_ids(&t["nodes"]);
    assert_eq!(nodes.len(), 4);
    assert_eq!(nodes[0], root.lease);
    let mut children = [child.lease.as_str(), sibling.lease.as_str()];
    children.sort();
    assert_eq!(nodes[1..3], children[..]);
    assert_eq!(nodes[3], grandchild.lease);
    assert_eq!(h.revoke(&root.lease).await, 2);
    // Fully revoked.
    let t = h.tree(&root.lease, "").await;
    assert_eq!(t["would_revoke"], 0);
    assert_eq!(h.revoke(&root.lease).await, 0);
    for n in t["nodes"].as_array().unwrap() {
        assert_eq!(n["active"], false);
        assert_eq!(n["revoke_reason"], "test");
    }
}

/// The tree is a GET: it changes no lease row and writes no audit record.
#[tokio::test]
async fn the_tree_changes_nothing() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    let child = h.exchange(&root, "coder").await;
    let grandchild = h.exchange(&child, "reviewer").await;
    h.revoke(&grandchild.lease).await;
    let leases = [
        root.lease.as_str(),
        child.lease.as_str(),
        grandchild.lease.as_str(),
    ];

    let rows = h.rows(&leases);
    let audit_len = h.state.audit.len().unwrap();
    for lease in leases {
        h.tree(lease, "").await;
    }
    assert_eq!(
        h.rows(&leases),
        rows,
        "revoked_at and every other column unchanged"
    );
    assert_eq!(h.state.audit.len().unwrap(), audit_len, "nothing audited");
    let t = h.tree(&root.lease, "").await;
    assert_eq!(t["would_revoke"], 2);
    assert!(t["nodes"][2]["revoked_at"].is_string());
}

#[tokio::test]
async fn max_nodes_caps_the_list_and_sets_truncated() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    for agent in AGENTS {
        h.exchange(&root, agent).await;
    }

    let t = h.tree(&root.lease, "?max_nodes=2").await;
    assert_eq!(t["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(
        t["nodes"][0]["lease_id"],
        json!(root.lease),
        "the lease itself first"
    );
    assert_eq!(t["truncated"], true);
    assert_eq!(t["would_revoke"], 4, "counted over the whole subtree");

    let t = h.tree(&root.lease, "?max_nodes=4").await;
    assert_eq!(t["nodes"].as_array().unwrap().len(), 4);
    assert_eq!(t["truncated"], false);
    let t = h.tree(&root.lease, "").await;
    assert_eq!(t["truncated"], false);
    // Zero is raised to one rather than refused.
    let t = h.tree(&root.lease, "?max_nodes=0").await;
    assert_eq!(lease_ids(&t["nodes"]), [root.lease.as_str()]);
    assert_eq!(t["truncated"], true);

    let resp = h
        .get(&format!("/admin/leases/{}/tree?max_nodes=-1", root.lease))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_lease_is_404_and_the_admin_token_is_required() {
    let h = Harness::start().await;
    let resp = h.get("/admin/leases/nope/tree").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let root = h.mint_root("planner").await;
    let resp = h
        .client
        .get(h.server.url(&format!("/admin/leases/{}/tree", root.lease)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = h
        .client
        .get(h.server.url(&format!("/admin/leases/{}/tree", root.lease)))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A lease with no issuance record in the log (registered by hand here) is listed with null
/// `agent`, `issued_at` and `issued_seq` rather than failing the whole tree.
#[tokio::test]
async fn a_lease_without_an_issuance_record_has_null_issuance_fields() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    let exp = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    h.state
        .leases
        .register(
            &LeaseId::new("orphan"),
            Some(&LeaseId::new(&root.lease)),
            exp,
        )
        .unwrap();

    let t = h.tree(&root.lease, "").await;
    assert_eq!(lease_ids(&t["nodes"]), [root.lease.as_str(), "orphan"]);
    assert_eq!(t["nodes"][0]["agent"], "planner");
    let orphan = &t["nodes"][1];
    assert_eq!(orphan["agent"], Value::Null);
    assert_eq!(orphan["issued_at"], Value::Null);
    assert_eq!(orphan["issued_seq"], Value::Null);
    assert_eq!(orphan["active"], true);
}

/// Every node and ancestor carries `chain_id` (the chain's first-hop lease, the selector
/// `POST /admin/leases/revoke` takes) and `subject`, the originating user recorded at issue,
/// so the console can offer "revoke this chain" and "revoke every lease of this user".
#[tokio::test]
async fn nodes_carry_their_chain_id_and_originating_user() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    let child = h.exchange(&root, "coder").await;
    let grandchild = h.exchange(&child, "reviewer").await;

    for of in [&root, &child, &grandchild] {
        let t = h.tree(&of.lease, "").await;
        let all: Vec<&Value> = t["ancestors"]
            .as_array()
            .unwrap()
            .iter()
            .chain(t["nodes"].as_array().unwrap())
            .collect();
        assert_eq!(all.len(), 3, "the tree of {} spans the chain", of.lease);
        for n in all {
            assert_eq!(n["chain_id"], json!(root.lease), "{n}");
            assert_eq!(n["chain_id"], t["root"]);
            assert_eq!(n["subject"], "alice", "{n}");
        }
    }

    // The chain id is what the selector revocation takes: its preview names the tree.
    let preview: Value = h
        .client
        .post(h.server.url("/admin/leases/revoke?preview=true"))
        .bearer_auth(ADMIN)
        .json(&json!({"chain_id": root.lease}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(preview["revoked_count"], 3);
    let preview: Value = h
        .client
        .post(h.server.url("/admin/leases/revoke?preview=true"))
        .bearer_auth(ADMIN)
        .json(&json!({"user": "alice"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(preview["matched_count"], 3);
}

/// A lease registered without a subject (as every lease registered before subjects were
/// recorded) shows `subject: null` next to leases that have one; the store is asked once for
/// all of them, so this also checks the batch keeps leases apart.
#[tokio::test]
async fn a_lease_registered_before_subjects_has_a_null_subject() {
    let h = Harness::start().await;
    let root = h.mint_root("planner").await;
    let exp = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    h.state
        .leases
        .register(
            &LeaseId::new("legacy-child"),
            Some(&LeaseId::new(&root.lease)),
            exp,
        )
        .unwrap();
    h.state
        .leases
        .register(&LeaseId::new("legacy-root"), None, exp)
        .unwrap();

    let t = h.tree(&root.lease, "").await;
    assert_eq!(
        lease_ids(&t["nodes"]),
        [root.lease.as_str(), "legacy-child"]
    );
    assert_eq!(t["nodes"][0]["subject"], "alice");
    assert_eq!(t["nodes"][1]["subject"], Value::Null);
    assert_eq!(t["nodes"][1]["chain_id"], json!(root.lease));

    let t = h.tree("legacy-root", "").await;
    assert_eq!(t["nodes"][0]["subject"], Value::Null);
    assert_eq!(t["nodes"][0]["chain_id"], "legacy-root");
}

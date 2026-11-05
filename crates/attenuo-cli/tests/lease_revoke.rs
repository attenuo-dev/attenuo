//! `attenuo lease revoke --user | --chain-id | --session [--preview]` against a real server.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

use std::process::{Command, Output};

use attenuo_audit::LeaseStore;
use attenuo_core::LeaseId;
use attenuo_proxy::session::{session_digest, session_tag};
use attenuo_proxy::testing::spawn_router;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use serde_json::Value;

const ADMIN: &str = "lease-revoke-test-admin";

fn attenuo() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_attenuo"));
    for var in [
        "ATTENUO_ADMIN_TOKEN",
        "ATTENUO_CLIENT_SECRET",
        "ATTENUO_TOKEN",
        "ATTENUO_SERVER",
        "ATTENUO_DPOP_KEY",
    ] {
        c.env_remove(var);
    }
    c
}

/// Run the CLI off the async runtime (the server runs on it).
async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn ok(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[tokio::test(flavor = "multi_thread")]
async fn lease_revoke_by_user_by_chain_and_by_session() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![AgentConfig {
        id: "coder".into(),
        secret_sha256: {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(b"coder-secret"))
        },
    }];
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    let admin = || {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN).args(["--server", &url]);
        c
    };

    let mut minted = Vec::new();
    for subject in ["alice", "bob", "carol"] {
        let mut c = admin();
        c.args(["--json", "token", "root", "--subject", subject])
            .args(["--agent", "planner", "--cap", "github:*"]);
        let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", root["access_token"].as_str().unwrap())
            .env("ATTENUO_CLIENT_SECRET", "coder-secret")
            .args(["--server", &url, "--json", "token", "exchange"])
            .args(["--actor", "coder", "--cap", "github:*"]);
        let child: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
        minted.push((
            root["lease"].as_str().unwrap().to_string(),
            child["lease"].as_str().unwrap().to_string(),
        ));
    }
    let (alice_root, alice_child) = &minted[0];
    let (bob_root, bob_child) = &minted[1];

    // Preview in text: both of alice's leases, nothing changed, no audit line.
    let mut c = admin();
    c.args(["lease", "revoke", "--user", "alice", "--preview"]);
    let text = ok(&run(c).await);
    assert!(text.starts_with("preview: nothing was changed\n"), "{text}");
    assert!(text.contains("selector  user alice\n"), "{text}");
    assert!(text.contains("would revoke 2 lease(s)\n"), "{text}");
    assert!(text.contains(&format!("  {alice_root}\n")), "{text}");
    assert!(text.contains(&format!("  {alice_child}\n")), "{text}");
    assert!(!text.contains("audit"), "{text}");
    let mut c = admin();
    c.args(["--json", "lease", "show", alice_child]);
    let show: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(show["active"], true, "{show}");

    // The revocation, as JSON.
    let mut c = admin();
    c.args(["--json", "lease", "revoke", "--user", "alice"])
        .args(["--reason", "incident"]);
    let v: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(v["revoked_count"], 2, "{v}");
    assert_eq!(v["reason"], "incident");
    assert!(v["audit_id"].is_string(), "{v}");
    let mut c = admin();
    c.args(["--json", "lease", "show", alice_child]);
    let show: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(show["active"], false, "{show}");

    // By chain, in text: bob's chain.
    let mut c = admin();
    c.args(["lease", "revoke", "--chain-id", bob_root]);
    let text = ok(&run(c).await);
    assert!(
        text.contains(&format!("selector  chain_id {bob_root}\n")),
        "{text}"
    );
    assert!(text.contains("revoked 2 lease(s)\n"), "{text}");
    assert!(text.contains(&format!("  {bob_child}\n")), "{text}");
    assert!(text.contains("reason    revoked by admin\n"), "{text}");
    assert!(text.contains("audit     "), "{text}");

    // By session: carol's chain opened a session through the proxy (bound here as the proxy
    // binds it, by digest). An unknown session resolves to no chain.
    let (carol_root, carol_child) = &minted[2];
    let sid = "cli-test-session-1";
    let bound = state
        .leases
        .record_session(
            &session_digest(sid),
            "github",
            &LeaseId::new(carol_root),
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
    assert!(bound);
    let mut c = admin();
    c.args(["lease", "revoke", "--session", sid, "--preview"]);
    let text = ok(&run(c).await);
    assert!(text.starts_with("preview: nothing was changed\n"), "{text}");
    assert!(
        text.contains(&format!("selector  session {}\n", session_tag(sid))),
        "{text}"
    );
    assert!(
        text.contains(&format!("chains    {carol_root}\n")),
        "{text}"
    );
    assert!(text.contains("would revoke 2 lease(s)\n"), "{text}");
    assert!(
        !text.contains(sid),
        "the raw session id is not echoed: {text}"
    );
    let mut c = admin();
    c.args(["lease", "revoke", "--session", "never-seen", "--preview"]);
    let text = ok(&run(c).await);
    assert!(
        text.contains("chains    none recorded for this session\n"),
        "{text}"
    );
    assert!(text.contains("matched   0 lease(s)\n"), "{text}");
    let mut c = admin();
    c.args(["--json", "lease", "revoke", "--session", sid])
        .args(["--reason", "session hijacked"]);
    let v: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(v["revoked_count"], 2, "{v}");
    assert_eq!(v["selector"]["chain_ids"][0], carol_root.as_str(), "{v}");
    assert!(v["audit_id"].is_string(), "{v}");
    let mut c = admin();
    c.args(["--json", "lease", "show", carol_child]);
    let show: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(show["active"], false, "{show}");

    // The per-lease form still takes an id, and refuses an id with a selector; selectors
    // exclude each other.
    for args in [
        &["lease", "revoke", alice_root, "--user", "alice"][..],
        &["lease", "revoke", alice_root, "--session", sid],
        &["lease", "revoke", "--session", sid, "--chain-id", bob_root],
    ] {
        let mut c = admin();
        c.args(args);
        assert_eq!(
            run(c).await.status.code(),
            Some(1),
            "clap usage error: {args:?}"
        );
    }
    drop(server);
}

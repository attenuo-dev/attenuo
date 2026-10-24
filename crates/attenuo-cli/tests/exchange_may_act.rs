//! `attenuo token exchange --no-delegation | --may-act` against a real server: what the new
//! token's `may_act` says, and who can exchange it next.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

use std::process::{Command, Output};

use attenuo_proxy::testing::spawn_router;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use serde_json::Value;

const ADMIN: &str = "may-act-test-admin";

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

fn agent(id: &str) -> AgentConfig {
    use sha2::Digest;
    AgentConfig {
        id: id.into(),
        secret_sha256: hex::encode(sha2::Sha256::digest(format!("{id}-secret").as_bytes())),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn no_delegation_makes_a_token_nobody_may_exchange() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![agent("coder"), agent("reviewer")];
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();

    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "--json", "token", "root"])
        .args([
            "--subject",
            "alice",
            "--agent",
            "planner",
            "--cap",
            "github:*",
        ]);
    let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let root = root["access_token"].as_str().unwrap().to_string();
    let exchange = |parent: &str, actor: &str, extra: &[&str]| {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", parent)
            .env("ATTENUO_CLIENT_SECRET", format!("{actor}-secret"))
            .args(["--server", &url, "--json", "token", "exchange"])
            .args(["--actor", actor, "--cap", "github:read_file"])
            .args(extra);
        c
    };
    let may_act = |token: &str| {
        state
            .verifier
            .verify(token, time::OffsetDateTime::now_utc())
            .unwrap()
            .claims
            .may_act
            .map(|m| m.sub)
    };

    // --no-delegation: `may_act: []` in the token, and the next exchange is refused (and
    // audited, so the error names the record).
    let child: Value =
        serde_json::from_str(&ok(
            &run(exchange(&root, "coder", &["--no-delegation"])).await
        ))
        .unwrap();
    let child = child["access_token"].as_str().unwrap().to_string();
    assert_eq!(may_act(&child), Some(Vec::new()));
    let out = run(exchange(&child, "reviewer", &[])).await;
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("(may_act)"), "{err}");
    assert!(err.contains("\ndecision "), "{err}");

    // Without either flag the new token carries no `may_act`: anyone authenticated may
    // exchange it (it does not inherit the parent's list).
    let root2 = {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
            .args(["--server", &url, "--json", "token", "root"])
            .args([
                "--subject",
                "bob",
                "--agent",
                "planner",
                "--cap",
                "github:*",
            ])
            .args(["--may-act", "coder"]);
        let v: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
        v["access_token"].as_str().unwrap().to_string()
    };
    assert_eq!(may_act(&root2), Some(vec!["coder".to_string()]));
    let open: Value =
        serde_json::from_str(&ok(&run(exchange(&root2, "coder", &[])).await)).unwrap();
    let open = open["access_token"].as_str().unwrap().to_string();
    assert_eq!(may_act(&open), None);
    ok(&run(exchange(&open, "reviewer", &[])).await);

    // An empty --may-act is refused before anything is sent, and the two flags conflict.
    let out = run(exchange(&root, "reviewer", &["--may-act", ""])).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--no-delegation"));
    let out = run(exchange(
        &root,
        "reviewer",
        &["--no-delegation", "--may-act", "x"],
    ))
    .await;
    assert_eq!(out.status.code(), Some(2), "clap usage error");

    // `token inspect` says who may exchange each token, and `--verify` covers it: the same
    // token with its `may_act` rewritten decodes to the new list but fails verification.
    let inspect = |token: &str, verify: bool| {
        let mut c = attenuo();
        c.args(["--server", &url, "token", "inspect", token]);
        if verify {
            c.arg("--verify");
        }
        c
    };
    let text = ok(&run(inspect(&child, true)).await);
    assert!(
        text.contains("\nmay_act []: no agent may exchange this token\n"),
        "{text}"
    );
    assert!(text.contains("\nverified: "), "{text}");
    let text = ok(&run(inspect(&open, true)).await);
    assert!(
        text.contains("\nmay_act (absent): any authenticated agent may exchange this token\n"),
        "{text}"
    );
    let text = ok(&run(inspect(&root2, false)).await);
    assert!(
        text.contains("\nmay_act coder: only this agent may exchange this token\n"),
        "{text}"
    );
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let parts: Vec<&str> = child.split('.').collect();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    claims["may_act"] = serde_json::json!({"sub": ["reviewer"]});
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
        parts[2]
    );
    let text = ok(&run(inspect(&forged, false)).await);
    assert!(text.contains("\nmay_act reviewer: "), "{text}");
    assert!(text.contains("signature NOT verified"), "{text}");
    let out = run(inspect(&forged, true)).await;
    assert_eq!(out.status.code(), Some(2), "a failed verification exits 2");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("verification FAILED"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    drop(server);
}

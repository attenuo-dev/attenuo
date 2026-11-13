//! `attenuo key gen --client` and `token exchange --client-key` (`private_key_jwt`, RFC 7523)
//! against a real server: the printed `jwks` line, put in the agent's `[[agents]]` entry,
//! authenticates the exchanges the CLI signs with the written key.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::process::{Command, Output};

use attenuo_proxy::testing::spawn_router;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use serde_json::Value;

use common::attenuo;

const ADMIN: &str = "client-key-test-admin";

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
async fn a_generated_client_key_authenticates_exchanges() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("coder.jwk");
    let mut c = attenuo();
    c.args(["key", "gen", "--client"])
        .arg(&key_path)
        .args(["--kid", "coder-1"]);
    let out = ok(&run(c).await);
    assert!(out.contains("kid coder-1"), "{out}");
    let line = out
        .lines()
        .find(|l| l.starts_with("jwks = '''"))
        .unwrap_or_else(|| panic!("no jwks line in {out}"));
    // The printed line, pasted into an `[[agents]]` entry, is valid config; it holds no
    // private member.
    let parsed = Config::from_toml(&format!("[[agents]]\nid = \"coder\"\n{line}\n")).unwrap();
    let jwks = parsed.agents[0].jwks.clone().unwrap();
    assert!(!jwks.contains("\"d\""), "{jwks}");
    let mut c = attenuo();
    c.args(["key", "gen", "--client"]).arg(&key_path);
    let again = run(c).await;
    assert_ne!(
        again.status.code(),
        Some(0),
        "an existing key is never overwritten"
    );

    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![AgentConfig::with_jwks("coder", jwks)];
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();

    let root = || {
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
        c
    };
    let exchange = |parent: &str, extra: &[&str]| {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", parent)
            // Ignored with --client-key, so it is not sent alongside the assertion.
            .env("ATTENUO_CLIENT_SECRET", "unused")
            .args(["--server", &url, "--json", "token", "exchange"])
            .args([
                "--actor",
                "coder",
                "--cap",
                "github:read_file",
                "--client-key",
            ])
            .arg(&key_path)
            .args(extra);
        c
    };
    for extra in [
        &[][..],
        &["--client-assertion-audience", "https://attenuo.test"][..],
    ] {
        let r: Value = serde_json::from_str(&ok(&run(root()).await)).unwrap();
        let parent = r["access_token"].as_str().unwrap().to_owned();
        let child: Value = serde_json::from_str(&ok(&run(exchange(&parent, extra)).await)).unwrap();
        let child = state
            .verifier
            .verify(
                child["access_token"].as_str().unwrap(),
                time::OffsetDateTime::now_utc(),
            )
            .unwrap();
        assert_eq!(child.claims.act.sub, "coder");
    }
    // Another audience is refused by the server.
    let r: Value = serde_json::from_str(&ok(&run(root()).await)).unwrap();
    let parent = r["access_token"].as_str().unwrap().to_owned();
    let out = run(exchange(
        &parent,
        &["--client-assertion-audience", "https://other"],
    ))
    .await;
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("invalid_client") && err.contains("issuer identifier"),
        "{err}"
    );
}

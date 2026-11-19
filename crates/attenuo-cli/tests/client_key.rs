//! `attenuo key gen --client` and `token exchange --client-key` (`private_key_jwt`, RFC 7523)
//! against a real server: the printed `jwks` line, put in the agent's `[[agents]]` entry,
//! authenticates the exchanges the CLI signs with the written key.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use attenuo_proxy::testing::spawn_router;
use attenuo_server::config::{AgentConfig, DpopMode, DpopNonceMode};
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

/// The bytes a [`relay`] saw, client to server and back, over all its connections.
#[derive(Default)]
struct Seen {
    up: Vec<u8>,
    down: Vec<u8>,
}

/// A TCP relay in front of `target` that keeps every byte it passes on, so a test can see each
/// request the CLI sent and each answer it got.
async fn relay(target: std::net::SocketAddr) -> (String, Arc<Mutex<Seen>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let all = seen.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let server = tokio::net::TcpStream::connect(target).await.unwrap();
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = server.into_split();
            let up = all.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n @ 1..) = cr.read(&mut buf).await {
                    up.lock().unwrap().up.extend_from_slice(&buf[..n]);
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = sw.shutdown().await;
            });
            let down = all.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n @ 1..) = sr.read(&mut buf).await {
                    down.lock().unwrap().down.extend_from_slice(&buf[..n]);
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = cw.shutdown().await;
            });
        }
    });
    (url, seen)
}

/// Each value of the JSON string member `name` in `text`, in order.
fn members(text: &str, name: &str) -> Vec<String> {
    let key = format!("\"{name}\":\"");
    text.match_indices(&key)
        .map(|(i, _)| {
            let rest = &text[i + key.len()..];
            rest[..rest.find('"').unwrap()].to_owned()
        })
        .collect()
}

/// SR-111 end to end: against a server that requires its DPoP nonce, `token exchange
/// --client-key --dpop-key` sends its request, is refused `use_dpop_nonce`, and sends the same
/// request (the same client assertion) again with a proof that carries the nonce; the server
/// accepts it. Before the fix the server spent the assertion on the refused request and the
/// retry was refused `client_assertion_replayed`. Each CLI process starts without a nonce, so
/// every exchange goes through the refusal; two in a row show the second is not a special case.
#[tokio::test(flavor = "multi_thread")]
async fn an_exchange_with_a_client_assertion_survives_the_nonce_retry() {
    let dir = tempfile::tempdir().unwrap();
    let client_key = dir.path().join("coder.jwk");
    let mut c = attenuo();
    c.args(["key", "gen", "--client"]).arg(&client_key);
    let out = ok(&run(c).await);
    let line = out.lines().find(|l| l.starts_with("jwks = '''")).unwrap();
    let parsed = Config::from_toml(&format!("[[agents]]\nid = \"coder\"\n{line}\n")).unwrap();
    let dpop_key = dir.path().join("dpop.jwk");
    let mut c = attenuo();
    c.args(["key", "gen", "--dpop"]).arg(&dpop_key);
    ok(&run(c).await);

    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.token.dpop = DpopMode::Optional;
    cfg.token.dpop_nonce = DpopNonceMode::Required;
    cfg.agents = vec![AgentConfig::with_jwks(
        "coder",
        parsed.agents[0].jwks.clone().unwrap(),
    )];
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    let (relay_url, seen) = relay(server.addr).await;

    for round in 1..=2 {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
            .args(["--server", &url, "--json", "token", "root"])
            .args(["--subject", "alice", "--agent", "planner"])
            .args(["--cap", "github:*", "--dpop-key"])
            .arg(&dpop_key);
        let r: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
        let parent = r["access_token"].as_str().unwrap().to_owned();

        let before = {
            let s = seen.lock().unwrap();
            (s.up.len(), s.down.len())
        };
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", &parent)
            .args(["--server", &relay_url, "--json", "token", "exchange"])
            .args(["--actor", "coder", "--cap", "github:read_file"])
            .arg("--client-key")
            .arg(&client_key)
            .arg("--dpop-key")
            .arg(&dpop_key);
        let child: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
        let child = state
            .verifier
            .verify(
                child["access_token"].as_str().unwrap(),
                time::OffsetDateTime::now_utc(),
            )
            .unwrap();
        assert_eq!(child.claims.act.sub, "coder", "round {round}");
        assert!(child.claims.cnf.is_some(), "a DPoP-bound child");

        let s = seen.lock().unwrap();
        let up = String::from_utf8_lossy(&s.up[before.0..]).to_string();
        let down = String::from_utf8_lossy(&s.down[before.1..]).to_string();
        // Two requests: the refused one and its retry, with the same assertion.
        assert_eq!(up.matches("POST /token HTTP/1.1").count(), 2, "{up}");
        let assertions = members(&up, "client_assertion");
        assert_eq!(assertions.len(), 2, "{up}");
        assert_eq!(
            assertions[0], assertions[1],
            "the retry resends the assertion"
        );
        // The first answer is the nonce refusal, the second the token; nothing is a replay.
        // A body has no line end of its own, so the next status line follows it on its line.
        let statuses: Vec<&str> = down
            .match_indices("HTTP/1.1 ")
            .map(|(i, _)| &down[i..i + 12])
            .collect();
        assert_eq!(statuses.len(), 2, "{down}");
        assert!(statuses[0].starts_with("HTTP/1.1 401"), "{down}");
        assert!(statuses[1].starts_with("HTTP/1.1 200"), "{down}");
        assert_eq!(members(&down, "error"), ["use_dpop_nonce"], "{down}");
        assert!(!down.contains("client_assertion_replayed"), "{down}");
    }
}

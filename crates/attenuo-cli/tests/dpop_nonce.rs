//! RFC 9449 §8: the CLI keeps the server's `DPoP-Nonce`, puts it in the next proof and retries
//! a request once when the server answers `use_dpop_nonce`. A scripted listener stands in for
//! the server in the first tests; the last one runs the real server with
//! `[token] dpop_nonce = "required"`.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::{AgentConfig, DpopMode, DpopNonceMode};
use attenuo_server::Config;
use attenuo_token::dpop::{verify_proof, ProofCheck, VerifiedProof};

use common::{attenuo, sha256_hex};

const NONCE: &str = "bm9uY2Utb25lLXNlY3JldA";
const REFUSAL: &str = r#"{"error":"use_dpop_nonce","detail":"retry with the DPoP-Nonce"}"#;
const OK_RPC: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;

/// One scripted reply: status line, extra headers, body.
type Reply = (&'static str, Vec<(&'static str, String)>, &'static str);

fn refusal(nonce: &str) -> Reply {
    (
        "401 Unauthorized",
        vec![
            ("dpop-nonce", nonce.to_string()),
            (
                "www-authenticate",
                "DPoP error=\"use_dpop_nonce\"".to_string(),
            ),
        ],
        REFUSAL,
    )
}

fn ok(body: &'static str) -> Reply {
    ("200 OK", vec![], body)
}

/// Serves `script` in order, one connection per reply, and returns the raw requests.
fn scripted_server(script: Vec<Reply>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for (status, headers, body) in script {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = sock.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req).to_string();
                let Some(split) = text.find("\r\n\r\n") else {
                    if n == 0 {
                        break;
                    }
                    continue;
                };
                let len = text[..split]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::to_owned)
                    })
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if req.len() >= split + 4 + len || n == 0 {
                    break;
                }
            }
            let extra: String = headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect();
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
            seen.push(String::from_utf8_lossy(&req).to_string());
        }
        seen
    });
    (url, handle)
}

fn header<'a>(req: &'a str, name: &str) -> Option<&'a str> {
    req.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn proof_of(req: &str, url: &str, token: Option<&str>) -> VerifiedProof {
    verify_proof(
        header(req, "dpop").expect("a DPoP header"),
        &ProofCheck {
            method: "POST",
            url,
            access_token: token,
            now: time::OffsetDateTime::now_utc(),
            max_age: time::Duration::seconds(60),
        },
    )
    .unwrap()
}

fn key_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("agent.jwk");
    let out = attenuo()
        .args(["key", "gen", "--dpop"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    path
}

/// Neither the nonce nor the token appears in anything the CLI prints.
fn assert_quiet(out: &Output, secrets: &[&str]) {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    for s in secrets {
        assert!(!all.contains(s), "output leaks {s}: {all}");
    }
}

#[test]
fn call_retries_once_with_the_servers_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let key = key_file(dir.path());
    let (url, server) = scripted_server(vec![refusal(NONCE), ok(OK_RPC)]);
    let out = attenuo()
        .env("ATTENUO_TOKEN", "a.b.c")
        .args([
            "--server",
            &url,
            "call",
            "--upstream",
            "github",
            "--tool",
            "t",
        ])
        .arg("--dpop-key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reqs = server.join().unwrap();
    let mcp = format!("{url}/mcp/github");
    assert_eq!(proof_of(&reqs[0], &mcp, Some("a.b.c")).nonce, None);
    let retry = proof_of(&reqs[1], &mcp, Some("a.b.c"));
    assert_eq!(retry.nonce.as_deref(), Some(NONCE));
    // The retry is a fresh proof, not a replay of the first.
    assert_ne!(header(&reqs[0], "dpop"), header(&reqs[1], "dpop"));
    assert_quiet(&out, &[NONCE, "a.b.c"]);
}

#[test]
fn root_and_authzen_retry_with_the_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let key = key_file(dir.path());

    // `token root --dpop-key`: the proof has no token, the admin bearer stays.
    let minted =
        r#"{"access_token":"x.y.z","token_type":"DPoP","expires_in":300,"lease_id":"l-1"}"#;
    let (url, server) = scripted_server(vec![refusal(NONCE), ok(minted)]);
    let out = attenuo()
        .env("ATTENUO_ADMIN_TOKEN", "admin-secret")
        .args(["--server", &url, "token", "root", "--subject", "alice"])
        .args([
            "--agent",
            "planner",
            "--cap",
            "github:read_file",
            "--dpop-key",
        ])
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reqs = server.join().unwrap();
    let root = format!("{url}/admin/root-token");
    assert_eq!(proof_of(&reqs[0], &root, None).nonce, None);
    assert_eq!(
        proof_of(&reqs[1], &root, None).nonce.as_deref(),
        Some(NONCE)
    );
    assert_eq!(
        header(&reqs[1], "authorization"),
        Some("Bearer admin-secret")
    );
    assert_quiet(&out, &[NONCE, "admin-secret"]);

    // `authzen eval`.
    let allow = r#"{"decision":true,"context":{"reason":"ok","decision_id":"d-1"}}"#;
    let (url, server) = scripted_server(vec![refusal(NONCE), ok(allow)]);
    let out = attenuo()
        .env("ATTENUO_TOKEN", "a.b.c")
        .args(["--server", &url, "authzen", "eval", "--upstream", "github"])
        .args(["--tool", "read_file", "--dpop-key"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reqs = server.join().unwrap();
    let eval = format!("{url}/access/v1/evaluation");
    assert_eq!(
        proof_of(&reqs[1], &eval, Some("a.b.c")).nonce.as_deref(),
        Some(NONCE)
    );
    assert_quiet(&out, &[NONCE, "a.b.c"]);
}

#[test]
fn exchange_header_proof_carries_the_nonce_and_the_sign_off_does_not_need_one() {
    let dir = tempfile::tempdir().unwrap();
    let key = key_file(dir.path());
    let minted =
        r#"{"access_token":"x.y.z","token_type":"DPoP","expires_in":300,"lease_id":"l-2"}"#;
    let (url, server) = scripted_server(vec![refusal(NONCE), ok(minted)]);
    let out = attenuo()
        .env("ATTENUO_TOKEN", "a.b.c")
        .env("ATTENUO_CLIENT_SECRET", "coder-secret")
        .args(["--server", &url, "token", "exchange", "--actor", "coder"])
        .args(["--cap", "github:read_file", "--dpop-key"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reqs = server.join().unwrap();
    let token_url = format!("{url}/token");
    assert_eq!(proof_of(&reqs[0], &token_url, None).nonce, None);
    assert_eq!(
        proof_of(&reqs[1], &token_url, None).nonce.as_deref(),
        Some(NONCE)
    );
    assert_quiet(&out, &[NONCE, "a.b.c", "coder-secret"]);
}

#[test]
fn a_second_refusal_is_reported_not_retried_and_a_bearer_is_never_retried() {
    let dir = tempfile::tempdir().unwrap();
    let key = key_file(dir.path());
    // Two refusals: exactly two requests, then the error (the script serves no third).
    let (url, server) = scripted_server(vec![refusal(NONCE), refusal("c2Vjb25kLW5vbmNl")]);
    let out = attenuo()
        .env("ATTENUO_TOKEN", "a.b.c")
        .args([
            "--server",
            &url,
            "call",
            "--upstream",
            "github",
            "--tool",
            "t",
        ])
        .arg("--dpop-key")
        .arg(&key)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(server.join().unwrap().len(), 2);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("use_dpop_nonce"), "{stderr}");
    assert!(!stderr.contains("could not reach"), "{stderr}");
    assert_quiet(&out, &[NONCE, "c2Vjb25kLW5vbmNl", "a.b.c"]);

    // Without a DPoP key a bearer request is not a DPoP request: one attempt.
    let (url, server) = scripted_server(vec![refusal(NONCE)]);
    let out = attenuo()
        .env("ATTENUO_TOKEN", "a.b.c")
        .args([
            "--server",
            &url,
            "call",
            "--upstream",
            "github",
            "--tool",
            "t",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(server.join().unwrap().len(), 1);
}

// -- the real server --

const ADMIN: &str = "nonce-test-admin";

/// The CLI against a server with `[token] dpop_nonce = "required"`: a bound root token, a
/// call through the proxy, an exchange and an AuthZEN evaluation, each in its own process
/// (so each starts without a nonce and learns it from the first refusal).
#[tokio::test(flavor = "multi_thread")]
async fn cli_works_against_a_server_that_requires_nonces() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = FakeMcpServer::new(&["read_file"]);
    let upstream_task = upstream.spawn().await.unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(
        &policy,
        r#"permit(principal, action == Action::"github/read_file", resource);"#,
    )
    .unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.policy.policies_path = Some(policy);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([(
            "read_file".to_string(),
            ToolAttrs::new()
                .with_input("repo", ArgType::String)
                .readonly(true),
        )]),
    )]);
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.token.dpop = DpopMode::Optional;
    cfg.token.dpop_nonce = DpopNonceMode::Required;
    cfg.agents = ["planner", "coder"]
        .iter()
        .map(|id| AgentConfig {
            id: (*id).into(),
            secret_sha256: sha256_hex(&format!("{id}-secret")),
        })
        .collect();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("");
    let url = url.trim_end_matches('/').to_string();

    let key = key_file(dir.path());
    let run = |cmd: Command| tokio::task::spawn_blocking(move || run_ok(cmd));

    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "token", "root", "--subject", "alice"])
        .args([
            "--agent", "planner", "--cap", "github:*", "--print", "token",
        ])
        .args(["--dpop-key"])
        .arg(&key);
    let root = run(c).await.unwrap();
    assert_eq!(root.matches('.').count(), 2, "a JWT: {root}");

    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &root)
        .args([
            "--server",
            &url,
            "tools",
            "--upstream",
            "github",
            "--dpop-key",
        ])
        .arg(&key);
    let tools = run(c).await.unwrap();
    assert!(tools.contains("read_file"), "{tools}");

    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &root)
        .args([
            "--server",
            &url,
            "call",
            "--upstream",
            "github",
            "--tool",
            "read_file",
        ])
        .args(["--arg", "repo=alice/docs", "--dpop-key"])
        .arg(&key);
    run(c).await.unwrap();
    assert_eq!(upstream.recorded_calls().len(), 1);

    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &root)
        .env("ATTENUO_CLIENT_SECRET", "coder-secret")
        .args(["--server", &url, "token", "exchange", "--actor", "coder"])
        .args([
            "--cap",
            "github:read_file",
            "--print",
            "token",
            "--dpop-key",
        ])
        .arg(&key);
    let child = run(c).await.unwrap();

    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &child)
        .args([
            "--server",
            &url,
            "call",
            "--upstream",
            "github",
            "--tool",
            "read_file",
        ])
        .args(["--arg", "repo=alice/docs", "--dpop-key"])
        .arg(&key);
    run(c).await.unwrap();
    assert_eq!(upstream.recorded_calls().len(), 2);

    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &child)
        .args(["--server", &url, "authzen", "eval", "--upstream", "github"])
        .args([
            "--tool",
            "read_file",
            "--arg",
            "repo=alice/docs",
            "--dpop-key",
        ])
        .arg(&key);
    assert!(run(c).await.unwrap().contains("ALLOW"));

    // Without the key the bound token is refused, with or without nonce handling.
    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &child)
        .args(["--server", &url, "tools", "--upstream", "github"]);
    let out = tokio::task::spawn_blocking(move || c.output().unwrap())
        .await
        .unwrap();
    assert!(!out.status.success());
}

fn run_ok(mut cmd: Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "the CLI failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

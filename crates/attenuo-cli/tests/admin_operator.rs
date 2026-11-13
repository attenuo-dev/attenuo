//! `attenuo admin operator new` and `admin operator hash` (ADR-0016): the output shape, that
//! nothing needs a server, and that a server configured with the printed entry accepts the
//! printed token as that operator with that role.

mod common;

use std::io::Write;
use std::process::{Output, Stdio};

use attenuo_proxy::testing::spawn_router;
use attenuo_server::Config;
use serde_json::Value;

use common::{attenuo, sha256_hex};

/// A server URL nothing listens on: the commands must not try it.
const NOWHERE: &str = "http://127.0.0.1:9";

fn new(args: &[&str]) -> Output {
    attenuo()
        .args(["--server", NOWHERE, "admin", "operator", "new"])
        .args(args)
        .output()
        .unwrap()
}

fn hash(stdin: &str, json: bool) -> Output {
    let mut cmd = attenuo();
    cmd.args(["--server", NOWHERE]);
    if json {
        cmd.arg("--json");
    }
    let mut child = cmd
        .args(["admin", "operator", "hash"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

#[tokio::test]
async fn new_prints_a_token_and_an_entry_the_server_accepts() {
    let out = tokio::task::spawn_blocking(|| new(&["--name", "alice", "--role", "operator"]))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let (token, entry) = stdout.split_once("\n\n").unwrap();
    // 32 random bytes, base64url without padding.
    assert_eq!(token.len(), 43, "{token}");
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    assert_eq!(stdout.matches(token).count(), 1);
    assert!(!text(&out.stderr).contains(token));
    assert_eq!(
        entry,
        format!(
            "[[admin.operators]]\nname = \"alice\"\ntoken_sha256 = \"{}\"\nrole = \"operator\"\n",
            sha256_hex(token)
        )
    );

    // A server with that entry takes the token as alice, operator.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::from_toml(entry).unwrap();
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let v: Value = reqwest::Client::new()
        .get(server.url("/admin/whoami"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        v,
        serde_json::json!({"name": "alice", "role": "operator", "expires_at": null})
    );

    // A second run makes another token.
    let again = tokio::task::spawn_blocking(|| new(&["--name", "alice", "--role", "operator"]))
        .await
        .unwrap();
    assert!(!text(&again.stdout).contains(token));
}

#[test]
fn new_with_json_and_refusals() {
    let out = attenuo()
        .args(["--server", NOWHERE, "--json", "admin", "operator", "new"])
        .args(["--name", "ops-1", "--role", "viewer"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let token = v["token"].as_str().unwrap();
    assert_eq!(v["name"], "ops-1");
    assert_eq!(v["role"], "viewer");
    assert_eq!(v["token_sha256"], sha256_hex(token));
    assert!(v["toml"].as_str().unwrap().contains("role = \"viewer\"\n"));

    // The CLI refuses exactly the names the server refuses, and prints nothing on stdout.
    for name in [
        "admin",
        "Alice",
        "a b",
        "",
        "x.y",
        "ok",
        "on_call",
        &"x".repeat(65),
    ] {
        let out = new(&["--name", name, "--role", "admin"]);
        let server_ok = attenuo_server::operators::check_operator_name(name).is_ok();
        assert_eq!(
            out.status.code() == Some(0),
            server_ok,
            "{name:?}: {}",
            text(&out.stderr)
        );
        if !server_ok {
            assert!(out.stdout.is_empty(), "{name:?}");
        }
    }
    let out = new(&["--name", "alice", "--role", "root"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn hash_reads_the_first_line_of_stdin() {
    let out = hash("my-token\n", false);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), format!("{}\n", sha256_hex("my-token")));
    let out = hash("my-token\r\nignored\n", true);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["token_sha256"], sha256_hex("my-token"));
    let out = hash("", false);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

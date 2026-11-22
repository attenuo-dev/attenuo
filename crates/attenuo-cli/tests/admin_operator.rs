//! `attenuo admin operator new` and `admin operator hash` (ADR-0016): the output shape, that
//! nothing needs a server, and that a server configured with the printed entry accepts the
//! printed token as that operator with that role. Also `admin operator reload` and
//! `admin agent reload` against a running server.

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

/// `new --expires-in` writes `expires_at` into the entry; `reload` puts a new entry in force
/// on a running server and prints what changed; a refusal exits non-zero and changes nothing.
#[tokio::test]
async fn new_with_an_expiry_then_reload_puts_it_in_force() {
    const LEGACY: &str = "legacy-admin-token-0123456789abcdef";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.toml");
    let base_file = format!(
        "[issuer]\nprivate_key_pem_path = \"{}\"\n\n[audit]\nsqlite_path = \"{}\"\n\n[admin]\n\
         token = \"{LEGACY}\"\n\n",
        dir.path().join("keys/issuer.pem").display(),
        dir.path().join("audit.sqlite").display(),
    );
    std::fs::write(&path, &base_file).unwrap();
    let cfg = Config::load(&path).unwrap();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("");

    let before = time::OffsetDateTime::now_utc();
    let out = tokio::task::spawn_blocking(|| {
        new(&["--name", "alice", "--role", "viewer", "--expires-in", "2h"])
    })
    .await
    .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("attenuo admin operator reload"));
    let stdout = text(&out.stdout);
    let (token, entry) = stdout.split_once("\n\n").unwrap();
    let token = token.to_string();
    let line = entry
        .lines()
        .find(|l| l.starts_with("expires_at = "))
        .unwrap();
    let at = line
        .trim_start_matches("expires_at = \"")
        .trim_end_matches('"');
    let at =
        time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).unwrap();
    let off = (at - before).whole_seconds();
    assert!((7199..=7300).contains(&off), "{line}");

    let reload = |url: String| {
        attenuo()
            .args(["--server", &url, "admin", "operator", "reload"])
            .env("ATTENUO_ADMIN_TOKEN", LEGACY)
            .output()
            .unwrap()
    };
    // Before the reload, the token is unknown.
    let client = reqwest::Client::new();
    let whoami = |t: String| {
        let (client, url) = (client.clone(), url.clone());
        async move {
            let resp = client
                .get(format!("{url}/admin/whoami"))
                .bearer_auth(t)
                .send()
                .await
                .unwrap();
            (resp.status(), resp.json::<Value>().await.unwrap())
        }
    };
    assert_eq!(whoami(token.clone()).await.0, 401);

    std::fs::write(&path, format!("{base_file}{entry}")).unwrap();
    let u = url.clone();
    let out = tokio::task::spawn_blocking(move || reload(u))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "reloaded operators: 1 added, 0 removed, 0 changed\n  added    alice\n"
    );
    let (status, v) = whoami(token.clone()).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["name"], "alice");
    assert_eq!(
        time::OffsetDateTime::parse(
            v["expires_at"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339
        )
        .unwrap(),
        at
    );

    // A refusal: exit status 1, the code on stderr, nothing changed.
    std::fs::write(&path, format!("{base_file}{entry}{entry}")).unwrap();
    let u = url.clone();
    let out = tokio::task::spawn_blocking(move || reload(u))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("operators_invalid"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(whoami(token).await.0, 200);
}

/// `admin agent reload` puts a changed `[[agents]]` list in force on a running server, prints
/// the ids and the sections that need a restart, `--json` prints the answer, and a refusal
/// exits 1 with the code and changes nothing.
#[tokio::test]
async fn agent_reload_prints_the_changes() {
    const LEGACY: &str = "legacy-admin-token-0123456789abcdef";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.toml");
    let base_file = format!(
        "[issuer]\nprivate_key_pem_path = \"{}\"\n\n[audit]\nsqlite_path = \"{}\"\n\n[admin]\n\
         token = \"{LEGACY}\"\n\n",
        dir.path().join("keys/issuer.pem").display(),
        dir.path().join("audit.sqlite").display(),
    );
    let agent = |id: &str| {
        format!(
            "[[agents]]\nid = \"{id}\"\nsecret_sha256 = \"{}\"\n",
            sha256_hex(&format!("{id}-secret"))
        )
    };
    std::fs::write(&path, format!("{base_file}{}", agent("planner"))).unwrap();
    let cfg = Config::load(&path).unwrap();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("");
    let reload = |url: String, json: bool| {
        let mut cmd = attenuo();
        cmd.args(["--server", &url]);
        if json {
            cmd.arg("--json");
        }
        cmd.args(["admin", "agent", "reload"])
            .env("ATTENUO_ADMIN_TOKEN", LEGACY)
            .output()
            .unwrap()
    };

    std::fs::write(
        &path,
        format!(
            "[server]\nlisten = \"127.0.0.1:9999\"\n\n{base_file}{}",
            agent("coder")
        ),
    )
    .unwrap();
    let u = url.clone();
    let out = tokio::task::spawn_blocking(move || reload(u, false))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "agents: 1 in force, 1 added, 1 removed, 0 changed\n\
         peps: 0 in force, 0 added, 0 removed, 0 changed\n  \
         added    agent coder\n  \
         removed  agent planner\n\
         not reloaded, differ from the running config (restart to apply): [server]\n"
    );
    let u = url.clone();
    let out = tokio::task::spawn_blocking(move || reload(u, true))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agents"]["count"], 1, "{v}");
    assert_eq!(v["agents"]["added"], serde_json::json!([]), "{v}");
    assert_eq!(v["restart_needed"], serde_json::json!(["[server]"]), "{v}");

    // A refusal: exit status 1, the code on stderr, nothing changed.
    std::fs::write(
        &path,
        format!("{base_file}{}{}", agent("coder"), agent("coder")),
    )
    .unwrap();
    let u = url.clone();
    let out = tokio::task::spawn_blocking(move || reload(u, false))
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("agents_invalid"),
        "{}",
        text(&out.stderr)
    );
    std::fs::write(&path, format!("{base_file}{}", agent("coder"))).unwrap();
    let u = url.clone();
    let out = tokio::task::spawn_blocking(move || reload(u, true))
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["agents"]["added"], serde_json::json!([]), "{v}");
    assert_eq!(v["agents"]["removed"], serde_json::json!([]), "{v}");
}

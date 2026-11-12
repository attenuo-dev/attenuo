//! `attenuo approval list|show|grant|decline` against a real server, and how `attenuo call`
//! prints a call that needs an approval (JSON-RPC `-32008`).

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::process::{Command, Output};

use attenuo_policy::ToolAttrs;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::Config;
use serde_json::Value;

use common::attenuo;

const ADMIN: &str = "approvals-cli-test-admin";
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("ask")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

async fn run(cmd: Command) -> Output {
    let mut cmd = cmd;
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn ok(out: &Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        stdout(out),
        String::from_utf8_lossy(&out.stderr)
    );
    stdout(out)
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_lists_shows_grants_and_declines_approvals() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = FakeMcpServer::new(&["read_web", "delete_repo"]);
    let upstream_task = upstream.spawn().await.unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    let mut cfg = Config::default();
    cfg.policy.policies_path = Some(policy);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([
            ("read_web".to_string(), ToolAttrs::new().readonly(true)),
            ("delete_repo".to_string(), ToolAttrs::new()),
        ]),
    )]);
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    let admin = || {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN).args(["--server", &url]);
        c
    };

    let mut c = admin();
    c.args(["--json", "token", "root", "--subject", "alice"])
        .args(["--agent", "planner", "--cap", "github:*"]);
    let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let token = root["access_token"].as_str().unwrap().to_string();
    let chain_id = root["lease"].as_str().unwrap().to_string();
    let call = |tool: &str, repo: &str| {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", &token)
            .args([
                "--server",
                &url,
                "call",
                "--upstream",
                "github",
                "--tool",
                tool,
            ])
            .arg("--arg")
            .arg(format!("repo={repo}"));
        c
    };
    ok(&run(call("read_web", "x")).await);

    // A gated call: exit code 2, and the approval id to hand to the user.
    let out = run(call("delete_repo", "alice/site")).await;
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.starts_with("APPROVAL REQUIRED\n"), "{text}");
    let approval_id = text
        .lines()
        .find_map(|l| l.strip_prefix("approval  "))
        .unwrap()
        .to_string();

    let mut c = admin();
    c.args([
        "--json",
        "approval",
        "list",
        "--chain-id",
        &chain_id,
        "--state",
        "pending",
    ]);
    let list: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(list["approvals"][0]["approval_id"], approval_id.as_str());
    let mut c = admin();
    c.args(["approval", "list"]);
    assert!(ok(&run(c).await).contains(&approval_id));

    let mut c = admin();
    c.args(["approval", "show", &approval_id]);
    let shown = ok(&run(c).await);
    assert!(shown.contains("call       github/delete_repo\n"), "{shown}");
    assert!(shown.contains("github/read_web (audit seq"), "{shown}");

    let mut c = admin();
    c.args(["--json", "approval", "grant", &approval_id]);
    let granted: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(granted["state"], "granted");
    assert_eq!(granted["approver"]["by"], "operator");

    // The grant carries a signed approval token, which `approval verify` checks offline.
    let approval_token = granted["approval_token"].as_str().unwrap().to_string();
    let call_hash = attenuo_core::ToolCall::new(
        "github",
        "delete_repo",
        serde_json::json!({"repo": "alice/site"}),
    )
    .call_hash();
    let verify = |extra: &[&str]| {
        let mut c = attenuo();
        c.args(["--server", &url, "approval", "verify", &approval_token])
            .args(extra);
        c
    };
    let out = ok(&run(verify(&[
        "--call-hash",
        &call_hash,
        "--chain-id",
        &chain_id,
        "--jkt",
        "none",
    ]))
    .await);
    assert!(out.contains(&format!("approval  {approval_id}\n")), "{out}");
    assert!(
        out.contains("by        urn:attenuo:admin (operator)"),
        "{out}"
    );
    assert!(out.contains("VALID"), "{out}");
    // Another call, run or key binding: exit 2.
    for wrong in [
        vec!["--call-hash", "00"],
        vec!["--chain-id", "other-run"],
        vec!["--lease", "other-hop"],
        vec!["--jkt", "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"],
    ] {
        let out = run(verify(&wrong)).await;
        assert_eq!(out.status.code(), Some(2), "{wrong:?}: {}", stdout(&out));
        assert!(stdout(&out).contains("INVALID: "), "{}", stdout(&out));
    }
    // The JWKS from a file or a URL, with --json; and another issuer's JWKS fails.
    let jwks_file = dir.path().join("jwks.json");
    let jwks_url = format!("{url}/.well-known/jwks.json");
    let jwks_text = reqwest::get(&jwks_url).await.unwrap().text().await.unwrap();
    std::fs::write(&jwks_file, &jwks_text).unwrap();
    for source in [jwks_file.to_string_lossy().into_owned(), jwks_url] {
        let mut c = attenuo();
        c.args([
            "--json",
            "approval",
            "verify",
            &approval_token,
            "--jwks",
            &source,
        ]);
        let v: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
        assert_eq!(v["valid"], true, "{v}");
        assert_eq!(v["header"]["typ"], "attenuo-approval+jwt");
        assert_eq!(v["claims"]["jti"], approval_id.as_str());
    }
    let stranger = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
        issuer: "x".into(),
        audience: "y".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    });
    let mut other_jwks: Value = serde_json::from_str(&jwks_text).unwrap();
    let stranger_token = stranger
        .issue_approval(&attenuo_token::ApprovalGrant {
            approval_id: "a",
            approver: "b",
            by: "user",
            chain_id: "c",
            lease: "d",
            call_hash: "e",
            granted_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
            jkt: None,
        })
        .unwrap();
    other_jwks["keys"][0]["kid"] = stranger.key_id().into();
    std::fs::write(&jwks_file, other_jwks.to_string()).unwrap();
    let mut c = attenuo();
    c.args(["approval", "verify", &stranger_token, "--jwks"])
        .arg(&jwks_file);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));

    // The identical retry runs.
    ok(&run(call("delete_repo", "alice/site")).await);
    assert_eq!(
        upstream
            .recorded_calls()
            .iter()
            .filter(|c| c.name == "delete_repo")
            .count(),
        1
    );

    // Decline another; granting it afterwards fails with a clear error.
    let out = run(call("delete_repo", "alice/prod")).await;
    let other = stdout(&out)
        .lines()
        .find_map(|l| l.strip_prefix("approval  "))
        .unwrap()
        .to_string();
    let mut c = admin();
    c.args(["approval", "decline", &other]);
    assert!(ok(&run(c).await).contains("state      declined"));
    let mut c = admin();
    c.args(["approval", "grant", &other]);
    let out = run(c).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("approval_not_pending"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(upstream_task);
}

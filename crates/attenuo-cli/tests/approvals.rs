//! `attenuo approval list|show|grant|decline` against a real server, and how `attenuo call`
//! prints a call that needs an approval (JSON-RPC `-32008`).

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::process::{Command, Output};

use attenuo_policy::ToolAttrs;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::Config;
use serde_json::Value;

const ADMIN: &str = "approvals-cli-test-admin";
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("ask")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

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
                "--server", &url, "call", "--server", "github", "--tool", tool,
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

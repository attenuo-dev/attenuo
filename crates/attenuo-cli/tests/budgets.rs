//! `budget refund` and the budget lines of `lease tree` against a real server: a run whose
//! root and child hops carry `calls` limits makes one allowed call, the tree shows what each
//! hop has left, a refund gives the call back, and a second refund of it exits 3.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::process::{Command, Output};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use serde_json::Value;

use common::{attenuo, sha256_hex};

const ADMIN: &str = "budgets-test-admin";
const POLICY: &str =
    "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n";

/// Run the CLI off the async runtime (the server runs on it).
async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn ok(out: &Output) -> String {
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    text(&out.stdout)
}

fn cap(max: u64) -> String {
    format!(r#"{{"server":"github","tool":"read_file","limits":{{"calls":{max}}}}}"#)
}

#[tokio::test(flavor = "multi_thread")]
async fn refund_and_tree_budgets_against_a_real_server() {
    let upstream = FakeMcpServer::new(&["read_file"]);
    let upstream_task = upstream.spawn().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
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
    cfg.agents = ["planner", "coder"]
        .iter()
        .map(|id| AgentConfig {
            id: (*id).into(),
            secret_sha256: sha256_hex(&format!("{id}-secret")),
        })
        .collect();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    let admin = || {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN).args(["--server", &url]);
        c
    };

    // planner (calls <= 3) > coder (calls <= 2); coder makes one allowed call.
    let mut c = admin();
    c.args(["--json", "token", "root", "--subject", "alice"])
        .args(["--agent", "planner", "--cap", &cap(3)]);
    let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let root_lease = root["lease"].as_str().unwrap().to_string();
    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", root["access_token"].as_str().unwrap())
        .env("ATTENUO_CLIENT_SECRET", "coder-secret")
        .args(["--server", &url, "--json", "token", "exchange"])
        .args(["--actor", "coder", "--cap", &cap(2)]);
    let coder: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", coder["access_token"].as_str().unwrap())
        .args(["--server", &url, "call", "--upstream", "github"])
        .args(["--tool", "read_file", "--arg", "repo=alice/docs"]);
    ok(&run(c).await);
    assert_eq!(upstream.recorded_calls().len(), 1);

    // -- lease tree: each hop's limit, charged once --
    let mut c = admin();
    c.args(["lease", "tree", &root_lease, "--max-nodes", "50"]);
    let tree = ok(&run(c).await);
    assert!(
        tree.contains("│    limit github/read_file calls 1/3 (2 left)\n"),
        "{tree}"
    );
    assert!(
        tree.contains("        limit github/read_file calls 1/2 (1 left)\n"),
        "{tree}"
    );
    assert!(!tree.contains("not recorded"), "{tree}");
    // --json passes the server's answer through.
    let mut c = admin();
    c.args(["--json", "lease", "tree", &root_lease]);
    let v: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(v["nodes"][0]["budget"]["recorded"], true);
    assert_eq!(v["nodes"][0]["budget"]["limits"][0]["remaining"], 2);

    // -- budget refund: the allowed call's decision --
    let mut c = admin();
    c.args(["--json", "audit", "tail", "--tool", "read_file"])
        .args(["--decision", "allow"]);
    let lines = ok(&run(c).await);
    let entries: Vec<Value> = lines
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // The decision, not the `tool_result` record that follows it.
    let decision = entries
        .iter()
        .find(|e| e["record"]["kind"].is_null() || e["record"]["kind"] == "decision")
        .and_then(|e| e["record"]["id"].as_str())
        .unwrap_or_else(|| panic!("no decision in {lines}"))
        .to_string();

    let mut c = admin();
    c.args([
        "budget",
        "refund",
        &decision,
        "--reason",
        "upstream timed out",
    ]);
    let out = ok(&run(c).await);
    assert!(out.starts_with(&format!("decision  {decision}\n")), "{out}");
    assert!(out.contains("refunded  2 limit counter(s)\n"), "{out}");
    assert!(out.contains("reason    upstream timed out\n"), "{out}");
    assert!(
        !out.contains("audit     -"),
        "the refund was audited: {out}"
    );

    let mut c = admin();
    c.args(["lease", "tree", &root_lease]);
    let tree = ok(&run(c).await);
    assert!(tree.contains("calls 0/3 (3 left)"), "{tree}");
    assert!(tree.contains("calls 0/2 (2 left)"), "{tree}");

    // The refund is in the log as an admin record naming the decision.
    let mut c = admin();
    c.args(["--json", "audit", "tail", "--tool", "admin.budget.refund"]);
    let refund: Value = serde_json::from_str(ok(&run(c).await).trim()).unwrap();
    assert_eq!(refund["record"]["kind"], "admin", "{refund}");

    // -- a second refund of the same decision: 409, exit 3, one line --
    let mut c = admin();
    c.args(["budget", "refund", &decision, "--reason", "again"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty());
    assert_eq!(
        text(&out.stderr),
        format!("error: the charge of decision {decision} was already refunded\n")
    );
    // With --json too: nothing on stdout, the same exit status.
    let mut c = admin();
    c.args(["--json", "budget", "refund", &decision, "--reason", "again"]);
    assert_eq!(run(c).await.status.code(), Some(3));

    // -- an unknown decision: 404, exit 2, the server's detail --
    let unknown = "00000000-0000-4000-8000-000000000000";
    let mut c = admin();
    c.args(["budget", "refund", unknown, "--reason", "typo"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stderr),
        format!(
            "error: unknown decision `{unknown}`: no audit record has this id; nothing to \
             refund\n"
        )
    );

    // -- an empty reason is refused before any request --
    let mut c = admin();
    c.args(["budget", "refund", &decision, "--reason", " "]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1), "a usage error, not a no");
    assert!(text(&out.stderr).contains("the reason must not be empty"));
}

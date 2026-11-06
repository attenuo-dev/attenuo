//! `attenuo policy test --via authzen`: a small suite decided by a real server's
//! `POST /access/v1/evaluation`, with the same reporter as the offline run.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::Config;
use serde_json::Value;

use common::attenuo;

const ADMIN: &str = "policy-test-authzen-admin";
const POLICY: &str = r#"@id("public_reads")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("never")
forbid(principal, action, resource) when { context.chain.depth > 5 };
"#;

/// Run the CLI off the async runtime (the server runs on it).
async fn run(cmd: Command) -> Output {
    let mut cmd = cmd;
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

struct Fixture {
    dir: tempfile::TempDir,
    _server: Spawned,
    url: String,
    token_file: std::path::PathBuf,
}

impl Fixture {
    fn suite(&self, name: &str, cases: &str) -> std::path::PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, format!("policies: policies.cedar\ncases:\n{cases}")).unwrap();
        p
    }

    fn test(&self, files: &[&Path], extra: &[&str]) -> Command {
        let mut c = attenuo();
        c.args(["--server", &self.url, "policy", "test", "--via", "authzen"])
            .arg("--token-file")
            .arg(&self.token_file)
            .args(extra)
            .args(files);
        c
    }
}

/// A server with the policy above and a root token for alice's `planner` over `github:*`.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.policy.policies_path = Some(policy);
    let tool = || ToolAttrs::new().with_input("repo", ArgType::String);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([
            ("read_file".to_string(), tool().readonly(true)),
            ("create_issue".to_string(), tool()),
        ]),
    )]);
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();

    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "token", "root", "--print", "token"])
        .args([
            "--subject",
            "alice",
            "--agent",
            "planner",
            "--cap",
            "github:*",
        ]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    Fixture {
        dir,
        _server: server,
        url,
        token_file,
    }
}

const PASSING: &str = r#"  - name: public read
    chain: [planner]
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: allow
    reason: policy_allow
    policy_ids: [public_reads]
  - name: private read
    call: { server: github, tool: read_file, arguments: { repo: alice/private } }
    expect: deny
    reason: policy_deny
    policy_ids: []
"#;

const MIXED: &str = r#"  - name: wrong expectation
    call: { server: github, tool: create_issue, arguments: { repo: alice/public-docs } }
    expect: allow
  - name: other chain
    chain: [assistant, coder]
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: allow
  - name: tainted run
    session: { tainted_by: [web/fetch] }
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: allow
  - name: other user
    user: { subject: bob }
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: allow
"#;

#[tokio::test(flavor = "multi_thread")]
async fn policy_test_runs_a_suite_through_the_authzen_endpoint() {
    let f = fixture().await;

    // Every case the endpoint can express passes against the server.
    let passing = f.suite("passing.yaml", PASSING);
    let out = run(f.test(&[&passing], &[])).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(
        t.contains("\u{2713} public read  (allow: policy_allow [public_reads])"),
        "{t}"
    );
    assert!(t.contains("2 passed, 0 failed (2 cases in 1 file)"), "{t}");
    // The policies come from the local file; `never` decided nothing.
    assert!(t.contains("1 of 2 policies not exercised:"), "{t}");
    assert!(t.contains("policies.cedar:5  never"), "{t}");

    // A wrong expectation fails; cases the endpoint cannot express are skipped, with why.
    let mixed = f.suite("mixed.yaml", MIXED);
    let out = run(f.test(&[&passing, &mixed], &[])).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(
        t.contains("\u{2717} wrong expectation  (deny: policy_deny)"),
        "{t}"
    );
    assert!(t.contains("expected allow, got deny (policy_deny)"), "{t}");
    assert!(
        t.contains("- other chain  (skipped: `chain` assistant > coder differs from the token's chain planner)"),
        "{t}"
    );
    assert!(
        t.contains("- tainted run  (skipped: `session` cannot be sent"),
        "{t}"
    );
    assert!(t.contains("- other user  (skipped: `user` differs from the token's user (alice at https://idp.example))"), "{t}");
    assert!(
        t.contains("2 passed, 1 failed, 3 skipped (6 cases in 2 files)"),
        "{t}"
    );

    // The JSON form carries the server's decision and the counts.
    let out = run(f.test(&[&mixed], &["--json"])).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["failed"], 1);
    assert_eq!(v["skipped"], 3);
    assert_eq!(v["files"][0]["cases"][0]["actual"]["decision"], "deny");
    assert!(v["files"][0]["cases"][1]["skipped"].is_string());
    assert_eq!(v["coverage"]["policies"], 2);
    assert_eq!(v["coverage"]["exercised"], 0);

    // A token the server refuses stops the file with an error (exit 1), not a case failure.
    let good = std::fs::read_to_string(&f.token_file).unwrap();
    let (rest, sig) = good.rsplit_once('.').unwrap();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    std::fs::write(&f.token_file, format!("{rest}.{flipped}{}", &sig[1..])).unwrap();
    let out = run(f.test(&[&passing], &[])).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("case `public read`"), "{t}");
    assert!(!t.contains("passed"), "{t}");

    // So does one that is not a token at all, before anything is sent.
    std::fs::write(&f.token_file, "not-a-token").unwrap();
    let out = run(f.test(&[&passing], &[])).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("--token"), "{}", text(&out));

    // A token only makes sense with --via authzen.
    let mut c = attenuo();
    c.args(["policy", "test", "--token", "x"]).arg(&passing);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("need --via authzen"), "{}", text(&out));
}

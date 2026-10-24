//! `attenuo policy test --via admin-evaluate`: suites decided by a real server's admin dry run
//! (`POST /admin/policies/evaluate`), each case with its own chain and labels, through the same
//! reporter as the offline run.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::Config;
use serde_json::Value;

const ADMIN: &str = "policy-test-admin-evaluate-admin";
const POLICY: &str = r#"@id("public_reads")
permit(principal, action == Action::"github/read_file", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

@id("issues")
permit(principal, action == Action::"github/create_issue", resource);

@id("no_issue_after_taint")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.session.tainted && !context.approval.present };

@id("two_issues_per_run")
forbid(principal, action == Action::"github/create_issue", resource)
when { context.usage.calls >= 2 };

@id("never")
forbid(principal, action, resource) when { context.chain.depth > 5 };
"#;

/// The server's catalog, repeated in the test files so the offline run sees the same tools.
const CATALOG: &str = r#"catalog:
  github:
    read_file: { readonly: true, inputs: { repo: string } }
    create_issue: { inputs: { repo: string } }
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
    state: Arc<attenuo_server::AppState>,
    url: String,
    admin_file: PathBuf,
}

impl Fixture {
    fn suite(&self, name: &str, head: &str, cases: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(
            &p,
            format!("policies: policies.cedar\n{CATALOG}{head}cases:\n{cases}"),
        )
        .unwrap();
        p
    }

    /// `attenuo --server URL policy test --via admin-evaluate --admin-token-file F <files>`.
    fn test(&self, files: &[&Path], extra: &[&str]) -> Command {
        let mut c = attenuo();
        c.args([
            "--server",
            &self.url,
            "policy",
            "test",
            "--via",
            "admin-evaluate",
        ])
        .arg("--admin-token-file")
        .arg(&self.admin_file)
        .args(extra)
        .args(files);
        c
    }

    fn audit_len(&self) -> u64 {
        self.state.audit.len().unwrap()
    }
}

/// A server with the policy above, a chain depth limit of 4 and an admin token in a file.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.max_depth = 4;
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
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    let admin_file = dir.path().join("admin-token");
    std::fs::write(&admin_file, ADMIN).unwrap();
    Fixture {
        dir,
        _server: server,
        state,
        url,
        admin_file,
    }
}

/// Cases the AuthZEN arm would skip (another chain and user, labels, an authentication time,
/// `budget`).
const PASSING: &str = r#"  - name: bob's coder reads a public repo
    user: { subject: bob, attributes: { mfa: true } }
    chain: [assistant, coder]
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: allow
    reason: policy_allow
    policy_ids: [public_reads]
  - name: private read
    call: { server: github, tool: read_file, arguments: { repo: alice/private } }
    expect: deny
    reason: policy_deny
    policy_ids: []
  - name: an issue after an untrusted read
    session: { tainted_by: [web/fetch] }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: deny
    reason: policy_deny
    policy_ids: [no_issue_after_taint]
  - name: the same issue with the user's approval
    session: { tainted_by: [web/fetch] }
    approval: { by: user }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: allow
    reason: policy_allow
    policy_ids: [issues]
  - name: a third issue in the run
    usage: { calls: 2 }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: deny
    reason: policy_deny
    policy_ids: [two_issues_per_run]
  - name: an old authentication is sent too
    user: { subject: alice, authenticated_at_unix: 1759990000 }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: allow
    policy_ids: [issues]
  - name: a delegate without create_issue
    chain:
      - { agent: assistant, capabilities: ["github:*"] }
      - { agent: coder, capabilities: ["github:read_file"] }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: deny
    reason: capability_denied
  - name: with a budget
    budget: { calls_remaining: 1 }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: allow
"#;

const FAILING: &str = r#"  - name: wrong expectation
    call: { server: github, tool: read_file, arguments: { repo: alice/private } }
    expect: allow
  - name: deeper than the server allows
    chain: [a, b, c, d, e, f]
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs } }
    expect: deny
    policy_ids: [never]
  - name: an approver the server does not know
    approval: { by: robot }
    call: { server: github, tool: create_issue, arguments: { repo: alice/x } }
    expect: allow
"#;

#[tokio::test(flavor = "multi_thread")]
async fn policy_test_replays_cases_through_the_admin_dry_run() {
    let f = fixture().await;
    let passing = f.suite("passing.yaml", "now: 1760000000\n", PASSING);
    let before = f.audit_len();

    // Every case replays as written, the budget one too, and passes; nothing is audited.
    let out = run(f.test(&[&passing], &[])).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(
        t.contains(
            "\u{2713} bob's coder reads a public repo  (allow: policy_allow [public_reads])"
        ),
        "{t}"
    );
    assert!(
        t.contains(
            "\u{2713} the same issue with the user's approval  (allow: policy_allow [issues])"
        ),
        "{t}"
    );
    assert!(
        t.contains("\u{2713} a third issue in the run  (deny: policy_deny [two_issues_per_run])"),
        "{t}"
    );
    assert!(
        t.contains("\u{2713} a delegate without create_issue  (deny: capability_denied)"),
        "{t}"
    );
    assert!(
        t.contains("\u{2713} with a budget  (allow: policy_allow [issues])"),
        "{t}"
    );
    assert!(!t.contains("skipped"), "{t}");
    assert!(
        t.contains("note: ") && t.contains("`now` is not sent"),
        "{t}"
    );
    assert!(t.contains("8 passed, 0 failed (8 cases in 1 file)"), "{t}");
    assert_eq!(f.audit_len(), before, "the dry run wrote audit records");

    // The unexercised report runs over the arm's results: `never` decided nothing, and
    // --fail-on-unexercised turns that into exit 2.
    assert!(t.contains("1 of 5 policies not exercised:"), "{t}");
    assert!(t.contains("policies.cedar:16  never"), "{t}");
    let out = run(f.test(&[&passing], &["--fail-on-unexercised"])).await;
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));

    // The offline run of the same file agrees case by case.
    let mut c = attenuo();
    c.args(["policy", "test"]).arg(&passing);
    let out = run(c).await;
    let local = text(&out);
    assert_eq!(out.status.code(), Some(0), "{local}");
    assert!(
        local.contains("8 passed, 0 failed (8 cases in 1 file)"),
        "{local}"
    );

    // A wrong expectation fails; cases the server refuses are that case's error, not the file's.
    let failing = f.suite("failing.yaml", "", FAILING);
    let out = run(f.test(&[&passing, &failing], &[])).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(
        t.contains("\u{2717} wrong expectation  (deny: policy_deny)"),
        "{t}"
    );
    assert!(t.contains("expected allow, got deny (policy_deny)"), "{t}");
    assert!(
        t.contains("\u{2717} deeper than the server allows  (not evaluated)"),
        "{t}"
    );
    assert!(
        t.contains("the server refused the case: server answered 400"),
        "{t}"
    );
    assert!(t.contains("invalid_chain"), "{t}");
    assert!(
        t.contains("\u{2717} an approver the server does not know  (not evaluated)"),
        "{t}"
    );
    assert!(
        t.contains("8 passed, 3 failed (11 cases in 2 files)"),
        "{t}"
    );

    // The JSON form carries the server's answers and the coverage over them.
    let out = run(f.test(&[&passing], &["--json"])).await;
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["passed"], 8);
    assert_eq!(v["skipped"], 0);
    assert_eq!(v["files"][0]["cases"][0]["actual"]["decision"], "allow");
    assert_eq!(v["coverage"]["policies"], 5);
    assert_eq!(v["coverage"]["exercised"], 4);
    assert_eq!(v["coverage"]["unexercised"][0]["id"], "never");
    assert_eq!(f.audit_len(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_test_admin_evaluate_refuses_bad_credentials_and_flags() {
    let f = fixture().await;
    let passing = f.suite("passing.yaml", "", PASSING);

    // A wrong admin token stops the file with an error (exit 1), not a case failure.
    let wrong = f.dir.path().join("wrong-token");
    std::fs::write(&wrong, "not-the-admin-token").unwrap();
    let mut c = attenuo();
    c.args(["--server", &f.url, "--admin-token-file"])
        .arg(&wrong)
        .args(["policy", "test", "--via", "admin-evaluate"])
        .arg(&passing);
    let out = run(c).await;
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("case `bob's coder reads a public repo`"), "{t}");
    assert!(t.contains("401"), "{t}");
    assert!(!t.contains("passed"), "{t}");

    // No admin token at all is refused before anything is sent.
    let mut c = attenuo();
    c.args([
        "--server",
        &f.url,
        "policy",
        "test",
        "--via",
        "admin-evaluate",
    ])
    .arg(&passing);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("--via admin-evaluate needs the admin token"),
        "{}",
        text(&out)
    );

    // The environment variable works as for the other admin commands.
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args([
            "--server",
            &f.url,
            "policy",
            "test",
            "--via",
            "admin-evaluate",
        ])
        .arg(&passing);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // The server validates with its own schema, and the chain is the case's, not a token's.
    let schema = f.dir.path().join("base.cedarschema");
    std::fs::write(&schema, "").unwrap();
    let out = run(f.test(&[&passing], &["--schema-file", schema.to_str().unwrap()])).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("--schema-file has no effect with --via admin-evaluate"),
        "{}",
        text(&out)
    );
    let out = run(f.test(&[&passing], &["--token", "x"])).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("need --via authzen"), "{}", text(&out));
}

/// A server set up as `file` describes: its policies, its catalog, `unknown_tools`,
/// `legacy_bare_actions` and base schema, so the dry run decides what the offline run does.
async fn server_for(
    file: &attenuo_policy::testing::TestFile,
    dir: &Path,
) -> (Spawned, Arc<attenuo_server::AppState>, String) {
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.max_depth = 16;
    cfg.issuer.private_key_pem_path = Some(dir.join("issuer.pem"));
    cfg.policy.policies_path = file.policies_path();
    let mut catalog: BTreeMap<String, BTreeMap<String, ToolAttrs>> = BTreeMap::new();
    for ((server, tool), attrs) in file.load_catalog().unwrap().iter() {
        catalog
            .entry(server.clone())
            .or_default()
            .insert(tool.clone(), attrs.clone());
    }
    cfg.policy.catalog = catalog;
    cfg.policy.unknown_tools = file.load_unknown_tools().unwrap();
    cfg.policy.legacy_bare_actions = file.load_legacy_bare_actions().unwrap();
    cfg.policy.schema_path = file.base_schema_path().unwrap();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some(ADMIN.into());
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    (server, state, url)
}

/// The repository's suites (`config/policies/*_test.yaml` and the two example suites) replay
/// through the admin dry run with nothing skipped, the `budget` cases included, each against a
/// server loaded with that suite's policies and catalog, and nothing is audited.
#[tokio::test(flavor = "multi_thread")]
async fn repository_suites_replay_through_the_admin_dry_run_with_nothing_skipped() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("config/policies"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with("_test.yaml"))
        .collect();
    files.sort();
    assert_eq!(files.len(), 4, "{files:?}");
    files.push(root.join("examples/github-leak-demo/policy_test.yaml"));
    files.push(root.join("examples/multi-hop-demo/policy_test.yaml"));

    let mut budget_cases = 0;
    for path in &files {
        let file = attenuo_policy::testing::TestFile::load(path).unwrap();
        budget_cases += file.cases.iter().filter(|c| c.budget.is_some()).count();
        let dir = tempfile::tempdir().unwrap();
        let (_server, state, url) = server_for(&file, dir.path()).await;
        let admin_file = dir.path().join("admin-token");
        std::fs::write(&admin_file, ADMIN).unwrap();
        let before = state.audit.len().unwrap();

        let mut c = attenuo();
        c.args([
            "--server",
            &url,
            "policy",
            "test",
            "--via",
            "admin-evaluate",
        ])
        .arg("--admin-token-file")
        .arg(&admin_file)
        .args(["--json", "--fail-on-unexercised"])
        .arg(path);
        let out = run(c).await;
        let t = text(&out);
        assert_eq!(out.status.code(), Some(0), "{}: {t}", path.display());
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["passed"], file.cases.len(), "{}: {t}", path.display());
        assert_eq!(v["failed"], 0, "{}: {t}", path.display());
        assert_eq!(v["skipped"], 0, "{}: {t}", path.display());
        assert_eq!(state.audit.len().unwrap(), before, "{}", path.display());
    }
    assert!(
        budget_cases >= 6,
        "the suites have {budget_cases} budget cases"
    );
}

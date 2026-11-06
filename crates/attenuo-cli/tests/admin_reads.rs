//! The CLI's read-only admin commands (`audit tail` filters and paging, `audit show`,
//! `audit checkpoints`, `lease tree`, `policy show`, `policy check`, `policy evaluate`)
//! against a real server, plus one scripted listener for the short-page case, which a real
//! server only produces after 50,000 entries.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};

use attenuo_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser};
use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use serde_json::Value;

use common::{attenuo, sha256_hex};

const ADMIN: &str = "admin-reads-test-admin";
const POLICY: &str =
    "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n";

/// Run the CLI off the async runtime (the server runs on it).
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

/// One JSON object per line (`audit tail --json`).
fn json_lines(text: &str) -> Vec<Value> {
    text.lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

struct Fixture {
    dir: tempfile::TempDir,
    // Both tasks stop when these drop.
    _server: Spawned,
    _upstream: Spawned,
    url: String,
    policy: std::path::PathBuf,
    root_token: String,
    root_lease: String,
    coder_token: String,
    reviewer_lease: String,
}

impl Fixture {
    /// The CLI with the admin token and `--server` set.
    fn admin(&self) -> Command {
        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
            .args(["--server", &self.url]);
        c
    }
}

/// A real server with a checkpoint every 2 entries and a chain planner > coder > reviewer;
/// coder makes one allowed and two denied calls, then the reviewer's lease is revoked.
async fn fixture(upstream: &FakeMcpServer) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let upstream_task = upstream.spawn().await.unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.policy.policies_path = Some(policy.clone());
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
    cfg.audit.checkpoint_every = 2;
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = ["planner", "coder", "reviewer"]
        .iter()
        .map(|id| AgentConfig {
            id: (*id).into(),
            secret_sha256: sha256_hex(&format!("{id}-secret")),
        })
        .collect();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();

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
    let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let root_token = root["access_token"].as_str().unwrap().to_string();

    let exchange = |parent: &str, actor: &str| {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", parent)
            .env("ATTENUO_CLIENT_SECRET", format!("{actor}-secret"))
            .args(["--server", &url, "--json", "token", "exchange"])
            .args(["--actor", actor, "--cap", "github:*"]);
        c
    };
    let coder: Value =
        serde_json::from_str(&ok(&run(exchange(&root_token, "coder")).await)).unwrap();
    let coder_token = coder["access_token"].as_str().unwrap().to_string();
    let reviewer: Value =
        serde_json::from_str(&ok(&run(exchange(&coder_token, "reviewer")).await)).unwrap();

    for (tool, code) in [("read_file", 0), ("create_issue", 2), ("create_issue", 2)] {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", &coder_token)
            .args([
                "--server", &url, "call", "--server", "github", "--tool", tool,
            ])
            .args(["--arg", "repo=alice/docs"]);
        assert_eq!(run(c).await.status.code(), Some(code), "{tool}");
    }

    let f = Fixture {
        dir,
        _server: server,
        _upstream: upstream_task,
        url,
        policy,
        root_token,
        root_lease: root["lease"].as_str().unwrap().to_string(),
        coder_token,
        reviewer_lease: reviewer["lease"].as_str().unwrap().to_string(),
    };
    let mut c = f.admin();
    c.args(["lease", "revoke", &f.reviewer_lease, "--reason", "rotated"]);
    ok(&run(c).await);
    f
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_reads_against_a_real_server() {
    let upstream = FakeMcpServer::new(&["read_file", "create_issue"]);
    let f = fixture(&upstream).await;
    assert_eq!(upstream.recorded_calls().len(), 1);

    // -- audit tail: a filter, then paging back with --before --
    let mut c = f.admin();
    c.args(["--json", "audit", "tail", "--decision", "deny"]);
    let denials = json_lines(&ok(&run(c).await));
    assert_eq!(denials.len(), 2, "{denials:?}");
    assert!(denials.iter().all(|e| e["record"]["decision"] == "deny"));
    assert!(
        denials[0]["seq"].as_u64() < denials[1]["seq"].as_u64(),
        "oldest first"
    );

    let mut c = f.admin();
    c.args(["--json", "audit", "tail", "-n", "100"]);
    let all = json_lines(&ok(&run(c).await));
    let seqs: Vec<u64> = all.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert_eq!(
        seqs,
        (1..=seqs.len() as u64).collect::<Vec<_>>(),
        "the whole log, in order"
    );

    let last_deny = denials[1]["seq"].as_u64().unwrap();
    let mut c = f.admin();
    c.args(["--json", "audit", "tail", "-n", "2", "--before"])
        .arg(last_deny.to_string());
    let page: Vec<u64> = json_lines(&ok(&run(c).await))
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(page, [last_deny - 2, last_deny - 1]);

    let mut c = f.admin();
    c.args([
        "--json", "audit", "tail", "--kind", "exchange", "--agent", "reviewer",
    ]);
    let exchanges = json_lines(&ok(&run(c).await));
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0]["record"]["kind"], "exchange");

    let mut c = f.admin();
    c.args([
        "audit",
        "tail",
        "--decision",
        "deny",
        "--tool",
        "create_issue",
    ]);
    let text = ok(&run(c).await);
    assert_eq!(
        text.matches("DENY  github/create_issue").count(),
        2,
        "{text}"
    );

    // -- audit show by seq and by id, and the 404s --
    let seq = last_deny.to_string();
    let id = denials[1]["record"]["id"].as_str().unwrap().to_string();
    let mut c = f.admin();
    c.args(["audit", "show", &seq]);
    let text = ok(&run(c).await);
    assert!(text.contains("reason=policy_deny"), "{text}");
    assert!(text.contains("kind        decision"), "{text}");
    assert!(
        text.contains(&format!("  {}  active, expires", f.root_lease)),
        "{text}"
    );
    assert!(
        text.contains("policy      not reloaded since this entry"),
        "{text}"
    );

    let mut c = f.admin();
    c.args(["--json", "audit", "show", "--id", &id]);
    let by_id: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(by_id["entry"]["seq"], last_deny);
    assert_eq!(by_id["lease_states"].as_array().unwrap().len(), 2);
    assert!(by_id.get("covered_by_checkpoint").is_some());

    let mut c = f.admin();
    c.args(["audit", "show", "99999"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("404") && err.contains("no audit entry at seq 99999"),
        "{err}"
    );

    let mut c = f.admin();
    c.args([
        "audit",
        "show",
        "--id",
        "0b7c4f1e-0000-4000-8000-000000000001",
    ]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("404"));

    let mut c = f.admin();
    c.args(["audit", "show", "--id", "not-a-uuid"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("400"));

    // -- audit checkpoints: listed, paged, and never signed by listing --
    let mut c = f.admin();
    c.args(["--json", "audit", "checkpoints"]);
    let cps: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let n = cps["checkpoints"].as_array().unwrap().len();
    assert!(n >= 2, "{cps}");
    let newest = cps["checkpoints"][0]["seq"].as_u64().unwrap();
    let mut c = f.admin();
    c.args(["audit", "checkpoints", "--limit", "1"]);
    let text = ok(&run(c).await);
    assert!(text.starts_with(&format!("seq {newest}")), "{text}");
    assert!(
        text.contains(&format!("older: audit checkpoints --before {newest}")),
        "{text}"
    );
    let mut c = f.admin();
    c.args(["--json", "audit", "checkpoints"]);
    let again: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(again["checkpoints"].as_array().unwrap().len(), n);

    // -- lease tree with a revoked grandchild --
    let mut c = f.admin();
    c.args(["lease", "tree", &f.root_lease]);
    let text = ok(&run(c).await);
    assert!(text.starts_with("root lease (no ancestors)\n"), "{text}");
    assert!(
        text.contains(&format!("{}  planner  active", f.root_lease)),
        "{text}"
    );
    assert!(text.contains("└─ "), "{text}");
    assert!(
        text.contains(&format!("   └─ {}  reviewer  REVOKED", f.reviewer_lease)),
        "{text}"
    );
    assert!(text.contains("(rotated)"), "{text}");
    assert!(text.contains("would revoke 2 lease(s)"), "{text}");
    assert!(!text.contains("truncated"), "{text}");

    let mut c = f.admin();
    c.args(["--json", "lease", "tree", &f.reviewer_lease]);
    let tree: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(tree["ancestors"].as_array().unwrap().len(), 2);
    assert_eq!(tree["would_revoke"], 0);

    let mut c = f.admin();
    c.args(["lease", "tree", &f.root_lease, "--max-nodes", "1"]);
    let text = ok(&run(c).await);
    assert!(text.contains("truncated: only 1 leases listed"), "{text}");
    assert!(text.contains("would revoke 2 lease(s)"), "{text}");

    let mut c = f.admin();
    c.args(["lease", "tree", "no-such-lease"]);
    assert_eq!(run(c).await.status.code(), Some(1));

    // -- policy show, evaluate, check --
    let mut c = f.admin();
    c.args(["policy", "show"]);
    let text = ok(&run(c).await);
    assert!(text.contains("policies   1: reads"), "{text}");
    assert!(text.contains("Action::\"github/read_file\""), "{text}");

    let eval = |tool: &str| {
        let mut c = f.admin();
        c.env("ATTENUO_TOKEN", &f.coder_token)
            .args(["policy", "evaluate", "--server", "github", "--tool", tool])
            .args(["--arg", "repo=alice/docs"]);
        c
    };
    let out = run(eval("read_file")).await;
    let text = ok(&out);
    assert!(text.starts_with("ALLOW  policy_allow"), "{text}");
    assert!(text.contains("policies     reads"), "{text}");
    assert!(text.contains("chain from   token\n"), "{text}");
    let out = run(eval("create_issue")).await;
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert!(
        stdout(&out).starts_with("DENY  policy_deny"),
        "{}",
        stdout(&out)
    );

    // The revoked reviewer still gets the policy's answer: the dry run skips the lease check.
    let chain = DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: time::OffsetDateTime::now_utc(),
            attributes: Default::default(),
        },
        AgentId::new("planner"),
        CapabilitySet::from_iter([Capability::new("github", "read_file")]),
        time::OffsetDateTime::now_utc(),
        time::Duration::minutes(5),
        LeaseId::new("L-bare"),
    )
    .unwrap();
    let chain_file = f.dir.path().join("chain.json");
    std::fs::write(&chain_file, serde_json::to_string(&chain).unwrap()).unwrap();
    let mut c = f.admin();
    c.args([
        "--json",
        "policy",
        "evaluate",
        "--server",
        "github",
        "--tool",
        "read_file",
    ])
    .arg("--chain-file")
    .arg(&chain_file);
    let v: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    assert_eq!(v["decision"], "allow");
    assert_eq!(v["chain_source"], "admin_supplied");
    assert_eq!(v["lease_check"], "skipped");

    let mut c = f.admin();
    c.args(["policy", "check"]);
    let text = ok(&run(c).await);
    assert!(text.contains("same as the loaded policy set"), "{text}");
    assert!(text.contains("a reload would succeed"), "{text}");

    std::fs::write(&f.policy, "permit(principal action, resource);\n").unwrap();
    let mut c = f.admin();
    c.args(["policy", "check"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("policies.cedar:1:"), "{text}");
    assert!(text.contains("a reload would FAIL"), "{text}");
    assert!(
        text.contains("differs from the loaded policy set"),
        "{text}"
    );

    // The root token is still good: none of the reads above revoked or changed anything.
    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &f.root_token)
        .args(["--server", &f.url, "tools", "--server", "github"]);
    ok(&run(c).await);
}

/// Answers each request in turn with the next body and returns the request lines.
fn scripted(bodies: Vec<&'static str>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for body in bodies {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&req).contains("\r\n\r\n") {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
            let text = String::from_utf8_lossy(&req).to_string();
            seen.push(text.lines().next().unwrap_or_default().to_string());
        }
        seen
    });
    (url, handle)
}

fn entry(seq: u64) -> String {
    format!(
        r#"{{"seq":{seq},"record":{{"id":"r{seq}","at":"2026-10-23T09:00:00Z","decision":"deny","reason":"policy_deny","originating_subject":"alice","agents":["coder"],"server":"github","tool":"create_issue"}}}}"#
    )
}

/// A filtered page that comes back short with `prev` set (the server stopped scanning) does
/// not end `audit tail`: it keeps paging back until it has `-n` entries.
#[test]
fn tail_keeps_paging_across_a_short_filtered_page() {
    let first: &'static str = Box::leak(
        format!(
            r#"{{"entries":[{}],"next":null,"prev":50,"head":120}}"#,
            entry(110)
        )
        .into_boxed_str(),
    );
    let empty = r#"{"entries":[],"next":51,"prev":20,"head":120}"#;
    let last: &'static str = Box::leak(
        format!(
            r#"{{"entries":[{},{}],"next":21,"prev":7,"head":120}}"#,
            entry(12),
            entry(8)
        )
        .into_boxed_str(),
    );
    let (url, server) = scripted(vec![first, empty, last]);
    let out = attenuo()
        .env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args([
            "--server",
            &url,
            "audit",
            "tail",
            "-n",
            "3",
            "--decision",
            "deny",
        ])
        .output()
        .unwrap();
    let text = ok(&out);
    let reqs = server.join().unwrap();
    assert_eq!(
        reqs,
        [
            "GET /admin/audit?order=desc&limit=3&decision=deny HTTP/1.1",
            "GET /admin/audit?order=desc&limit=2&decision=deny&before=50 HTTP/1.1",
            "GET /admin/audit?order=desc&limit=2&decision=deny&before=20 HTTP/1.1",
        ]
    );
    let shown: Vec<&str> = text.lines().map(|l| &l[..5]).collect();
    assert_eq!(shown, ["#8   ", "#12  ", "#110 "], "{text}");
}

//! `attenuo init` against a fake MCP server, and the configuration it writes loaded by a real
//! attenuo server: the tool the MCP server marks read-only is allowed through the proxy, the
//! others are denied by policy, and nothing reaches the MCP server for a denied call.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use attenuo_proxy::testing::{spawn_router, FakeMcpServer};
use attenuo_server::Config;
use serde_json::json;

use common::attenuo;

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

/// `attenuo init --upstream NAME=URL --dir DIR` plus `extra`.
fn init(upstream: &str, dir: &Path, extra: &[&str]) -> Command {
    let mut c = attenuo();
    c.args(["init", "--upstream", upstream, "--dir"])
        .arg(dir)
        .args(extra);
    c
}

/// The value of `export NAME=value` in `attenuo.env`.
fn env_value(dir: &Path, name: &str) -> String {
    let env = std::fs::read_to_string(dir.join("attenuo.env")).unwrap();
    env.lines()
        .find_map(|l| l.strip_prefix(&format!("export {name}=")))
        .unwrap_or_else(|| panic!("{name} is not in attenuo.env:\n{env}"))
        .to_string()
}

/// The written configuration as the server reads it, with its relative paths (which resolve
/// against the server's working directory) made absolute under `dir`.
fn load(dir: &Path) -> Config {
    let mut cfg = Config::load(&dir.join("attenuo.toml")).unwrap();
    assert_eq!(
        cfg.issuer.private_key_pem_path.as_deref(),
        Some(Path::new("data/issuer.pem"))
    );
    assert_eq!(cfg.audit.sqlite_path, "data/attenuo.sqlite");
    assert_eq!(
        cfg.policy.policies_path.as_deref(),
        Some(Path::new("policy.cedar"))
    );
    cfg.issuer.private_key_pem_path = Some(dir.join("data/issuer.pem"));
    cfg.audit.sqlite_path = dir
        .join("data/attenuo.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.policy.policies_path = Some(dir.join("policy.cedar"));
    cfg
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn fake() -> FakeMcpServer {
    FakeMcpServer::new(&["read_file", "create_issue", "delete_repo", "bad/name"])
        .with_tool_annotations("read_file", json!({"readOnlyHint": true}))
        .with_tool_annotations("delete_repo", json!({"destructiveHint": true}))
}

/// The whole path: discover (paginated, answered as JSON or as SSE), write, load in a real
/// server, mint, exchange, one allowed and one denied call.
async fn init_then_serve(fake: FakeMcpServer) {
    let upstream = fake.spawn().await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("try");

    let spec = format!("github={}", upstream.url("/mcp"));
    let out = ok(&run(init(&spec, &dir, &[])).await);
    assert!(out.contains("3 tools found on `github`."), "{out}");
    assert!(
        out.contains("because the server says they only read (1):\n  read_file\n"),
        "{out}"
    );
    assert!(out.contains("Left out"), "{out}");
    assert!(out.contains("\"bad/name\""), "{out}");
    // No secret on standard output.
    let admin = env_value(&dir, "ATTENUO_ADMIN_TOKEN");
    let secret = env_value(&dir, "ATTENUO_CLIENT_SECRET");
    assert_eq!(admin.len(), 43);
    assert_eq!(secret.len(), 43);
    assert_ne!(admin, secret);
    assert!(!out.contains(&admin) && !out.contains(&secret), "{out}");
    #[cfg(unix)]
    {
        assert_eq!(mode(&dir.join("attenuo.toml")), 0o600);
        assert_eq!(mode(&dir.join("attenuo.env")), 0o600);
        assert_eq!(mode(&dir.join("data")), 0o700);
    }

    // What the MCP server was asked: a handshake and the list, and no tool was called.
    let methods = fake.recorded_methods();
    assert_eq!(methods[0], "initialize", "{methods:?}");
    assert!(
        methods.contains(&"notifications/initialized".to_string()),
        "{methods:?}"
    );
    assert!(methods.contains(&"tools/list".to_string()), "{methods:?}");
    assert!(fake.recorded_calls().is_empty());

    let config = std::fs::read_to_string(dir.join("attenuo.toml")).unwrap();
    assert!(
        config.contains("[policy.catalog.github.read_file]\nreadonly = true\n"),
        "{config}"
    );
    assert!(
        config.contains("[policy.catalog.github.delete_repo]\nsensitive = true\n"),
        "{config}"
    );
    assert!(!config.contains("bad/name"), "{config}");
    assert!(
        !config.contains(&secret),
        "the client secret itself is in the config"
    );

    // A real server accepts the files as written.
    let cfg = load(&dir);
    assert_eq!(cfg.admin.token.as_deref(), Some(admin.as_str()));
    assert!(cfg.dev.allow_root_mint);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();

    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", &admin)
        .args(["--server", &url, "token", "root", "--subject", "alice"])
        .args([
            "--agent", "planner", "--cap", "github:*", "--print", "token",
        ]);
    let root = ok(&run(c).await).trim().to_string();
    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", &root)
        .env("ATTENUO_CLIENT_SECRET", &secret)
        .args(["--server", &url, "token", "exchange", "--actor", "coder"])
        .args(["--cap", "github:*", "--print", "token"]);
    let coder = ok(&run(c).await).trim().to_string();

    let call = |tool: &str| {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", &coder).args([
            "--server",
            &url,
            "call",
            "--upstream",
            "github",
            "--tool",
            tool,
        ]);
        c
    };
    let allowed = ok(&run(call("read_file")).await);
    assert!(allowed.starts_with("ALLOWED"), "{allowed}");
    for tool in ["create_issue", "delete_repo"] {
        let out = run(call(tool)).await;
        assert_eq!(out.status.code(), Some(2), "{tool}: {}", text(&out.stdout));
        assert!(text(&out.stdout).contains("DENIED  policy_deny"), "{tool}");
    }
    // The name the catalog left out cannot be called at all.
    let out = run(call("bad/name")).await;
    assert_ne!(out.status.code(), Some(0));
    let calls = fake.recorded_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].name, "read_file");
}

#[tokio::test(flavor = "multi_thread")]
async fn init_writes_a_configuration_a_server_runs() {
    init_then_serve(fake()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn init_reads_a_paginated_list() {
    init_then_serve(fake().with_page_size(1)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn init_reads_answers_sent_as_sse() {
    init_then_serve(fake().with_sse(true)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_files_are_kept_unless_forced() {
    let upstream = fake().spawn().await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let spec = format!("github={}", upstream.url("/mcp"));
    ok(&run(init(&spec, &dir, &[])).await);
    let before = std::fs::read_to_string(dir.join("attenuo.toml")).unwrap();
    let secret = env_value(&dir, "ATTENUO_CLIENT_SECRET");

    // Each of the three files alone is enough to refuse, and nothing is written.
    for keep in ["attenuo.toml", "policy.cedar", "attenuo.env"] {
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join(keep), "mine").unwrap();
        let out = run(init(&spec, other.path(), &[])).await;
        assert_eq!(out.status.code(), Some(1), "{keep}");
        assert!(text(&out.stderr).contains("already exists"), "{keep}");
        assert_eq!(
            std::fs::read_to_string(other.path().join(keep)).unwrap(),
            "mine"
        );
        assert_eq!(
            std::fs::read_dir(other.path()).unwrap().count(),
            1,
            "{keep}"
        );
    }
    let out = run(init(&spec, &dir, &[])).await;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        std::fs::read_to_string(dir.join("attenuo.toml")).unwrap(),
        before
    );

    // --force replaces them, with new secrets, and a file that was world-readable is not
    // left that way.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("attenuo.env"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    ok(&run(init(&spec, &dir, &["--force"])).await);
    assert_ne!(
        std::fs::read_to_string(dir.join("attenuo.toml")).unwrap(),
        before
    );
    assert_ne!(env_value(&dir, "ATTENUO_CLIENT_SECRET"), secret);
    #[cfg(unix)]
    assert_eq!(mode(&dir.join("attenuo.env")), 0o600);
    load(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn readonly_hints_can_be_ignored() {
    let upstream = fake().spawn().await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let spec = format!("github={}", upstream.url("/mcp"));
    let out = ok(&run(init(&spec, tmp.path(), &["--no-readonly-hints"])).await);
    assert!(out.contains("None is permitted yet"), "{out}");
    let config = std::fs::read_to_string(tmp.path().join("attenuo.toml")).unwrap();
    assert!(!config.contains("\nreadonly = true\n"), "{config}");
    let cfg = load(tmp.path());
    let _built = attenuo_server::build(&cfg).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn without_discovery_the_catalog_is_empty_and_the_server_still_starts() {
    let tmp = tempfile::tempdir().unwrap();
    // Nothing listens there: --no-discover must not try.
    let out = ok(&run(init(
        "files=http://127.0.0.1:9/mcp",
        tmp.path(),
        &["--no-discover", "--listen", "127.0.0.1:8099"],
    ))
    .await);
    assert!(out.contains("The tools were not discovered"), "{out}");
    assert!(out.contains("http://127.0.0.1:8099/mcp/files"), "{out}");
    assert_eq!(
        env_value(tmp.path(), "ATTENUO_SERVER"),
        "http://127.0.0.1:8099"
    );
    let cfg = load(tmp.path());
    assert!(cfg.policy.catalog.is_empty());
    let _built = attenuo_server::build(&cfg).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_write_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("x");
    let cases: [(&[&str], &str, &str); 6] = [
        // The MCP server is not there.
        (&[], "files=http://127.0.0.1:9/mcp", "--no-discover"),
        (
            &["--listen", "0.0.0.0:8080", "--no-discover"],
            "files=http://127.0.0.1:9/mcp",
            "loopback",
        ),
        (&["--no-discover"], "files", "NAME=URL"),
        (
            &["--listen", "127.0.0.1:0", "--no-discover"],
            "files=http://127.0.0.1:9/mcp",
            "fixed port",
        ),
        (
            &["--no-discover"],
            "a/b=http://127.0.0.1:9/mcp",
            "not a valid server name",
        ),
        (
            &["--no-discover"],
            "files=ftp://127.0.0.1/mcp",
            "http:// or https://",
        ),
    ];
    for (extra, spec, expect) in cases {
        let out = run(init(spec, &dir, extra)).await;
        assert_eq!(out.status.code(), Some(1), "{spec} {extra:?}");
        assert!(
            text(&out.stderr).contains(expect),
            "{spec} {extra:?}: {}",
            text(&out.stderr)
        );
        assert!(!dir.exists(), "{spec} {extra:?} left files behind");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_is_not_mcp_is_reported() {
    use axum::routing::post;
    // Answers 200 with something that is not JSON-RPC, then one that needs credentials.
    let not_mcp = spawn_router(axum::Router::new().route("/mcp", post(|| async { "hello" })))
        .await
        .unwrap();
    let locked = spawn_router(axum::Router::new().route(
        "/mcp",
        post(|| async { axum::http::StatusCode::UNAUTHORIZED }),
    ))
    .await
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("x");
    let out = run(init(&format!("a={}", not_mcp.url("/mcp")), &dir, &[])).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("not a JSON-RPC response"),
        "{}",
        text(&out.stderr)
    );
    let out = run(init(&format!("a={}", locked.url("/mcp")), &dir, &[])).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("needs credentials"),
        "{}",
        text(&out.stderr)
    );
    assert!(!dir.exists());
}

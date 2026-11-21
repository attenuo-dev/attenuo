//! `attenuo stdio-bridge` as a process, with the `stdio_mcp` example as its STDIO server:
//! requests and notifications, ids of concurrent callers, the timeout, the child's exit, a
//! stop signal, and the whole path with a real attenuo server and proxy in front.

// Configs are built field by field from `Config::default()`, as in the server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::spawn_router;
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::AgentConfig;
use attenuo_server::Config;
use serde_json::{json, Value};

use common::{attenuo, sha256_hex};

/// The `stdio_mcp` example. `cargo test --workspace` (and `cargo test -p attenuo-cli`)
/// builds examples next to the binaries, and that build is used when it is newer than the
/// example's source. A run of this file alone (`--test stdio_bridge`) does not build
/// examples, so then it is built here, once per test process, in the profile of the
/// `attenuo` binary.
fn stdio_mcp() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let bin = PathBuf::from(env!("CARGO_BIN_EXE_attenuo"));
        let dir = bin.parent().unwrap();
        let built = dir
            .join("examples")
            .join(format!("stdio_mcp{}", std::env::consts::EXE_SUFFIX));
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/stdio_mcp.rs");
        let modified = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        if let (Some(b), Some(s)) = (modified(&built), modified(&source)) {
            if b >= s {
                return built;
            }
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut c = Command::new(cargo);
        c.args(["build", "-p", "attenuo-cli", "--example", "stdio_mcp"])
            .arg("--message-format=json");
        if dir.file_name().is_some_and(|n| n == "release") {
            c.arg("--release");
        }
        let out = c.stderr(Stdio::inherit()).output().unwrap();
        assert!(
            out.status.success(),
            "building the stdio_mcp example failed"
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|m| m["target"]["name"] == "stdio_mcp")
            .find_map(|m| m["executable"].as_str().map(PathBuf::from))
            .expect("cargo named no stdio_mcp executable")
    })
}

/// A running bridge: its URL, everything it (and the child, whose stderr is the bridge's)
/// wrote on stderr so far, and the process, killed on drop.
struct Bridge {
    child: Child,
    url: String,
    stderr: Arc<Mutex<String>>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Bridge {
    fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Wait until stderr holds `needle`.
    fn wait_stderr(&self, needle: &str) {
        let end = Instant::now() + Duration::from_secs(10);
        while !self.stderr().contains(needle) {
            assert!(Instant::now() < end, "no `{needle}` in:\n{}", self.stderr());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for the bridge to exit.
    fn wait_exit(&mut self) -> std::process::ExitStatus {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(
                Instant::now() < end,
                "bridge still running:\n{}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn collect(mut r: impl Read + Send + 'static) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let b = buf.clone();
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = r.read(&mut chunk) {
            if n == 0 {
                break;
            }
            b.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&chunk[..n]));
        }
    });
    buf
}

/// Start `attenuo stdio-bridge --listen 127.0.0.1:0 <flags> -- stdio_mcp`.
fn bridge(flags: &[&str]) -> Bridge {
    bridge_running(flags, &[stdio_mcp().as_os_str()])
}

/// A bridge in front of `command` (the program and its arguments).
fn bridge_running(flags: &[&str], command: &[&std::ffi::OsStr]) -> Bridge {
    let mut child = attenuo()
        .args(["stdio-bridge", "--listen", "127.0.0.1:0"])
        .args(flags)
        .arg("--")
        .args(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = collect(child.stderr.take().unwrap());
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    let url = first
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("first line {first:?}; stderr {}", stderr.lock().unwrap()))
        .to_string();
    Bridge { child, url, stderr }
}

async fn post(url: &str, body: Value) -> (u16, String) {
    let r = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.text().await.unwrap())
}

async fn post_json(url: &str, body: Value) -> (u16, Value) {
    let (s, t) = post(url, body).await;
    (s, serde_json::from_str(&t).unwrap_or(Value::String(t)))
}

fn call(id: Value, tool: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": tool, "arguments": args}})
}

fn text_of(v: &Value) -> &str {
    v["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_notifications_and_what_the_bridge_refuses() {
    let b = bridge(&[]);
    let url = b.url.clone();
    let http = reqwest::Client::new();

    let init = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "0"}}});
    let (s, v) = post_json(&url, init.clone()).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["id"], 0);
    assert_eq!(v["result"]["serverInfo"]["name"], "stdio-mcp");

    // A notification: 202, no body.
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let (s, t) = post(&url, note.clone()).await;
    assert_eq!((s, t.as_str()), (202, ""));

    // A second client's handshake: the first answer, its own id, and nothing more reaches
    // the child.
    let mut again = init.clone();
    again["id"] = json!("second");
    let (s, v2) = post_json(&url, again).await;
    assert_eq!(s, 200);
    assert_eq!(v2["id"], "second");
    assert_eq!(v2["result"], v["result"]);
    assert_eq!(post(&url, note).await.0, 202);

    let (s, v) = post_json(
        &url,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await;
    assert_eq!(s, 200);
    assert!(v["result"]["tools"].as_array().unwrap().len() > 3, "{v}");

    let (s, v) = post_json(&url, call(json!(2), "echo", json!({"text": "a\nb"}))).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["id"], 2);
    assert_eq!(
        serde_json::from_str::<Value>(text_of(&v)).unwrap()["arguments"]["text"],
        "a\nb"
    );
    let (_, v) = post_json(&url, call(json!(3), "stats", json!({}))).await;
    assert_eq!(
        serde_json::from_str::<Value>(text_of(&v)).unwrap(),
        json!({"initialize": 1, "initialized": 1})
    );
    // The child's `ping` (sent before each answer, with the call's id) was answered with an
    // error by the bridge, not taken for the answer.
    b.wait_stderr("stdio-mcp: response ");

    // A response from a caller: accepted and dropped.
    let (s, t) = post(
        &url,
        json!({"jsonrpc": "2.0", "id": "caller-9", "result": {}}),
    )
    .await;
    assert_eq!((s, t.as_str()), (202, ""));
    assert!(!b.stderr().contains("caller-9"));

    // A batch, an invalid id, bad JSON.
    let (s, v) = post_json(&url, json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])).await;
    assert_eq!(s, 400);
    assert_eq!(v["error"]["code"], -32600);
    assert!(v["error"]["message"].as_str().unwrap().contains("batch"));
    let (s, v) = post_json(
        &url,
        json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
    )
    .await;
    assert_eq!((s, v["error"]["code"].clone()), (400, json!(-32600)));
    let r = http
        .post(&url)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    assert_eq!(r.json::<Value>().await.unwrap()["error"]["code"], -32700);

    // Not JSON, an Origin header (a browser), GET and DELETE.
    let r = http
        .post(&url)
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 415);
    let r = http
        .post(&url)
        .header("content-type", "application/json")
        .header("origin", "http://evil.example")
        .body(call(json!(4), "echo", json!({})).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
    assert_eq!(http.get(&url).send().await.unwrap().status().as_u16(), 405);
    assert_eq!(
        http.delete(&url).send().await.unwrap().status().as_u16(),
        405
    );
    let posted_echo = b.stderr().matches("tools/call echo").count();
    assert_eq!(posted_echo, 1, "the refused calls never reached the child");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversize_bodies_and_lines_are_refused() {
    let b = bridge(&[
        "--max-request-bytes",
        "200",
        "--max-line-bytes",
        "300",
        "--timeout",
        "1",
    ]);
    let (s, v) = post_json(
        &b.url,
        call(json!(1), "echo", json!({"t": "x".repeat(300)})),
    )
    .await;
    assert_eq!(s, 413, "{v}");
    assert!(!b.stderr().contains("tools/call"));
    // An answer longer than --max-line-bytes is dropped: the call times out, and the next one
    // is answered.
    let (s, v) = post_json(&b.url, call(json!(2), "big", json!({"bytes": 1000}))).await;
    assert_eq!(s, 504, "{v}");
    assert_eq!(v["id"], 2);
    b.wait_stderr("over --max-line-bytes");
    let (s, v) = post_json(&b.url, call(json!(3), "big", json!({"bytes": 10}))).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(text_of(&v), "x".repeat(10));
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_calls_with_the_same_caller_id_get_their_own_answers() {
    let b = bridge(&[]);
    let mut tasks = Vec::new();
    for n in 0..8u64 {
        let url = b.url.clone();
        // Later calls are faster, so the child answers in reverse order.
        tasks.push(tokio::spawn(async move {
            let args = json!({"ms": (8 - n) * 60, "n": n});
            (n, post_json(&url, call(json!(1), "slow", args)).await)
        }));
    }
    for t in tasks {
        let (n, (s, v)) = t.await.unwrap();
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["id"], 1);
        let echoed: Value = serde_json::from_str(text_of(&v)).unwrap();
        assert_eq!(echoed["arguments"]["n"], n, "{v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_with_no_answer_in_time_is_a_504_and_the_bridge_goes_on() {
    let b = bridge(&["--timeout", "1"]);
    let started = Instant::now();
    let (s, v) = post_json(&b.url, call(json!("slow-1"), "slow", json!({"ms": 3000}))).await;
    assert_eq!(s, 504, "{v}");
    assert_eq!(v["id"], "slow-1");
    assert_eq!(v["error"]["code"], -32603);
    assert!(started.elapsed() < Duration::from_millis(2500));
    let (s, v) = post_json(&b.url, call(json!(2), "echo", json!({}))).await;
    assert_eq!(s, 200, "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_bridge_exits_non_zero_when_the_child_exits() {
    let mut b = bridge(&[]);
    // The child exits while answering. The caller gets a 502, or its connection closes as
    // the bridge exits; either way it does not hang.
    let r = reqwest::Client::new()
        .post(&b.url)
        .header("content-type", "application/json")
        .body(call(json!(1), "exit", json!({})).to_string())
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    if let Ok(r) = r {
        assert_eq!(r.status().as_u16(), 502);
    }
    let status = b.wait_exit();
    assert_eq!(status.code(), Some(1), "{}", b.stderr());
    let err = b.stderr();
    assert!(err.contains("error: the STDIO server"), "{err}");
}

#[test]
fn a_command_that_cannot_start_and_a_public_address_are_refused() {
    let out = attenuo()
        .args(["stdio-bridge", "--listen", "127.0.0.1:0", "--"])
        .arg("/nonexistent/stdio-server")
        .args(["--api-key", "sk-should-not-be-printed"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot start the STDIO server `/nonexistent/stdio-server`"),
        "{err}"
    );
    assert!(!err.contains("sk-should-not-be-printed"), "{err}");

    let out = attenuo()
        .args(["stdio-bridge", "--listen", "0.0.0.0:0", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not a loopback address"), "{err}");
    assert!(err.contains("--allow-non-loopback"), "{err}");

    // No command.
    let out = attenuo()
        .args(["stdio-bridge", "--listen", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn sigterm_stops_the_bridge_and_its_child() {
    let mut b = bridge(&[]);
    let (_, v) = post_json(&b.url, call(json!(1), "pid", json!({}))).await;
    let pid = text_of(&v).to_string();
    assert!(pid.parse::<u32>().is_ok(), "{v}");
    let alive = |pid: &str| {
        Command::new("kill")
            .args(["-0", pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(alive(&pid));
    let status = Command::new("kill")
        .args(["-TERM", &b.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(b.wait_exit().code(), Some(0), "{}", b.stderr());
    // The bridge waited for the child before exiting: it is gone, not orphaned.
    assert!(!alive(&pid), "child {pid} outlived the bridge");
}

/// SR-135: a launcher (`npx`, `uvx`, a shell script) is the bridge's child and the real server
/// is the launcher's child. Stopping the bridge stops that process too: one left behind
/// when the launcher exits on end of input, and one that ignores SIGTERM.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_bridge_stops_what_the_child_started_sr135() {
    use std::ffi::OsStr;
    // Running: not gone and not a zombie. A process that was killed and not yet reaped by
    // its new parent still answers `kill -0`, and it is not running.
    let alive = |pid: &str| {
        #[cfg(target_os = "linux")]
        {
            // The state is the field after the `)` that closes the command name.
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| s.rsplit_once(") ").map(|(_, rest)| rest.to_string()))
                .is_some_and(|rest| !rest.starts_with('Z') && !rest.starts_with('X'))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let out = Command::new("ps")
                .args(["-o", "stat=", "-p", pid])
                .output()
                .unwrap();
            let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
            !state.is_empty() && !state.starts_with('Z')
        }
    };
    // Kills the `sleep` if an assertion fails before the bridge did.
    struct Reap(String);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = Command::new("kill")
                .args(["-KILL", &self.0])
                .stderr(Stdio::null())
                .status();
        }
    }
    // Each script starts a `sleep` in the background, prints its pid on stderr, and then:
    // exits when its input ends; or ignores SIGTERM (the `sleep` inherits that) and stays.
    for script in [
        "sleep 61 & echo \"grandchild $!\" >&2; cat >/dev/null",
        "trap '' TERM; sleep 62 & echo \"grandchild $!\" >&2; wait",
    ] {
        let mut b = bridge_running(
            &[],
            &[OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)],
        );
        let end = Instant::now() + Duration::from_secs(10);
        let pid = loop {
            let err = b.stderr();
            if let Some(pid) = err
                .lines()
                .find_map(|l| l.strip_prefix("grandchild "))
                .map(str::to_string)
            {
                break pid;
            }
            assert!(Instant::now() < end, "no pid from the script: {err}");
            std::thread::sleep(Duration::from_millis(20));
        };
        let _reap = Reap(pid.clone());
        assert!(alive(&pid), "{script}");
        let status = Command::new("kill")
            .args(["-TERM", &b.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(b.wait_exit().code(), Some(0), "{}", b.stderr());
        // A killed process may take a moment to leave the table.
        let end = Instant::now() + Duration::from_secs(2);
        while alive(&pid) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !alive(&pid),
            "the grandchild {pid} outlived the bridge: {script}"
        );
    }
}

/// SR-134: the child gets no `ATTENUO_*` variable of the bridge's environment, the server's
/// secrets and `ATTENUO__*` overrides included; other variables pass.
#[cfg(unix)]
#[test]
fn the_child_gets_no_attenuo_variable_sr134() {
    let out = attenuo()
        .args(["stdio-bridge", "--listen", "127.0.0.1:0", "--"])
        .args(["sh", "-c", "env | sort >&2"])
        .env("ATTENUO_ADMIN_TOKEN", "x")
        .env("ATTENUO_AUDIT_SINK_TOKEN", "x")
        .env("ATTENUO_APPROVAL_NOTIFY_SECRET", "x")
        .env("ATTENUO__ADMIN__TOKEN", "x")
        .env("ATTENUO__AUDIT__SINK__BEARER_TOKEN", "x")
        .env("SR134_KEPT", "kept")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // The child exits at once, and the bridge with it.
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("SR134_KEPT=kept"), "{stderr}");
    let leaked: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("ATTENUO_"))
        .collect();
    assert!(leaked.is_empty(), "{leaked:?}");
}

// -------------------------------------------------------------------------------------------
// End to end: agent -> attenuo proxy -> bridge -> STDIO server
// -------------------------------------------------------------------------------------------

const ADMIN: &str = "stdio-bridge-test-admin";
const POLICY: &str =
    "@id(\"reads\")\npermit(principal, action == Action::\"local/read_file\", resource);\n";

/// Run the CLI off the async runtime (the server runs on it).
async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn ok(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stdio_server_behind_attenuo() {
    let b = bridge(&[]);
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policies.cedar");
    std::fs::write(&policy, POLICY).unwrap();
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.policy.policies_path = Some(policy);
    let tool = || ToolAttrs::new().with_input("path", ArgType::String);
    cfg.policy.catalog = BTreeMap::from([(
        "local".to_string(),
        BTreeMap::from([
            ("read_file".to_string(), tool().readonly(true)),
            ("delete_repo".to_string(), tool()),
        ]),
    )]);
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.upstreams = vec![UpstreamConfig::new("local", b.url.clone())];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![AgentConfig::with_secret_sha256(
        "coder",
        sha256_hex("coder-secret"),
    )];
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
            "local:*",
        ]);
    let root: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let mut c = attenuo();
    c.env("ATTENUO_TOKEN", root["access_token"].as_str().unwrap())
        .env("ATTENUO_CLIENT_SECRET", "coder-secret")
        .args(["--server", &url, "--json", "token", "exchange"])
        .args(["--actor", "coder", "--cap", "local:*"]);
    let coder: Value = serde_json::from_str(&ok(&run(c).await)).unwrap();
    let token = coder["access_token"].as_str().unwrap().to_string();
    let agent = |tool: &str| {
        let mut c = attenuo();
        c.env("ATTENUO_TOKEN", &token)
            .args([
                "--server",
                &url,
                "call",
                "--upstream",
                "local",
                "--tool",
                tool,
            ])
            .args(["--arg", "path=README.md"]);
        c
    };

    // Allowed: reaches the STDIO server and comes back.
    let out = ok(&run(agent("read_file")).await);
    assert!(out.contains("ALLOWED"), "{out}");
    assert!(out.contains("README.md"), "{out}");
    b.wait_stderr("stdio-mcp: tools/call read_file");

    // Denied: never reaches it.
    let out = run(agent("delete_repo")).await;
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!b.stderr().contains("delete_repo"), "{}", b.stderr());

    // The audit chain holds both decisions and verifies.
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "audit", "verify"]);
    let out = ok(&run(c).await);
    assert!(out.contains("audit chain OK"), "{out}");
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", &url, "--json", "audit", "tail", "-n", "100"]);
    let entries: Vec<Value> = ok(&run(c).await)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let decision = |tool: &str| {
        entries
            .iter()
            .map(|e| &e["record"])
            .find(|r| r["server"] == "local" && r["tool"] == tool && r["kind"] == "decision")
            .map(|r| r["decision"].clone())
    };
    assert_eq!(decision("read_file"), Some(json!("allow")), "{entries:?}");
    assert_eq!(decision("delete_repo"), Some(json!("deny")), "{entries:?}");
}

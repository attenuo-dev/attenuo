//! `attenuo connect` driven as a desktop MCP client drives it: the real binary, MCP over its
//! stdin and stdout, in front of a real attenuo server (configured by `attenuo init`) and a
//! fake MCP server. And in front of a canned HTTP server, for the answers a proxy rarely
//! gives: errors without a JSON-RPC body, redirects, a lost session, a 401 that a new token
//! does not fix.

// Configs are changed field by field after loading, as in the other tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_server::Config;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use common::attenuo;

/// How long a test waits for one line before it fails.
const WAIT: Duration = Duration::from_secs(20);

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

/// The value of `export NAME=value` in `attenuo.env`.
fn env_value(dir: &Path, name: &str) -> String {
    let env = std::fs::read_to_string(dir.join("attenuo.env")).unwrap();
    env.lines()
        .find_map(|l| l.strip_prefix(&format!("export {name}=")))
        .unwrap_or_else(|| panic!("{name} is not in attenuo.env:\n{env}"))
        .trim_matches('\'')
        .to_string()
}

/// A real attenuo server in front of `fake`, configured by `attenuo init
/// --trust-readonly-hints`: `read_file` is permitted, `create_issue` is not.
struct Setup {
    fake: FakeMcpServer,
    _upstream: Spawned,
    _server: Spawned,
    url: String,
    admin: String,
    tmp: tempfile::TempDir,
    /// Sessions `attenuo init` ended while it read the tools.
    deleted_by_init: usize,
}

impl Setup {
    /// The sessions ended since `attenuo init` ran.
    fn deleted(&self) -> Vec<String> {
        self.fake.deleted_sessions()[self.deleted_by_init..].to_vec()
    }
}

async fn setup(fake: FakeMcpServer, tweak: impl FnOnce(&mut Config)) -> Setup {
    let fake = fake.with_tool_annotations("read_file", json!({"readOnlyHint": true}));
    let upstream = fake.spawn().await.unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("cfg");
    let mut c = attenuo();
    c.args(["init", "--trust-readonly-hints", "--upstream"])
        .arg(format!("github={}", upstream.url("/mcp")))
        .arg("--dir")
        .arg(&dir);
    ok(&run(c).await);
    let mut cfg = Config::load(&dir.join("attenuo.toml")).unwrap();
    cfg.issuer.private_key_pem_path = Some(dir.join("data/issuer.pem"));
    cfg.audit.sqlite_path = dir
        .join("data/attenuo.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.policy.policies_path = Some(dir.join("policy.cedar"));
    tweak(&mut cfg);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("").trim_end_matches('/').to_string();
    Setup {
        deleted_by_init: fake.deleted_sessions().len(),
        fake,
        _upstream: upstream,
        _server: server,
        url,
        admin: env_value(&dir, "ATTENUO_ADMIN_TOKEN"),
        tmp,
    }
}

/// A token command that counts its runs in `<dir>/count` and mints a root token with the
/// admin token (from the environment), as the guide's example does. With `bad_first`, its
/// first run prints a string that is not a token.
fn mint_script(dir: &Path, bad_first: bool) -> PathBuf {
    let script = dir.join("mint.sh");
    let bad = if bad_first {
        "if [ \"$n\" = 1 ]; then echo not-a-valid-token; exit 0; fi\n"
    } else {
        ""
    };
    std::fs::write(
        &script,
        format!(
            "n=$(( $(cat '{count}' 2>/dev/null || echo 0) + 1 ))\n\
             echo \"$n\" > '{count}'\n\
             {bad}\
             exec \"$ATTENUO_BIN\" token root --subject alice --agent planner --cap 'github:*' --print token\n",
            count = dir.join("count").display()
        ),
    )
    .unwrap();
    script
}

fn runs(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("count"))
        .map(|s| s.trim().parse().unwrap())
        .unwrap_or(0)
}

/// Mint a root token with the CLI.
async fn mint(s: &Setup) -> String {
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", &s.admin)
        .args(["--server", &s.url, "token", "root", "--subject", "alice"])
        .args([
            "--agent", "planner", "--cap", "github:*", "--print", "token",
        ]);
    ok(&run(c).await).trim().to_string()
}

/// The running connector, with its stdin and stdout, and its stderr collected.
struct Connector {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    stderr: tokio::sync::watch::Receiver<String>,
}

impl Connector {
    fn spawn(mut cmd: Command) -> Self {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut err = BufReader::new(child.stderr.take().unwrap()).lines();
        let (tx, stderr) = tokio::sync::watch::channel(String::new());
        tokio::spawn(async move {
            while let Ok(Some(line)) = err.next_line().await {
                tx.send_modify(|s| {
                    s.push_str(&line);
                    s.push('\n');
                });
            }
        });
        Self {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    fn stderr(&self) -> String {
        self.stderr.borrow().clone()
    }

    async fn send_raw(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        stdin.flush().await.unwrap();
    }

    async fn send(&mut self, msg: Value) {
        self.send_raw(&msg.to_string()).await;
    }

    /// The next line of stdout, which must be one JSON-RPC message.
    async fn recv(&mut self) -> Value {
        let line = match tokio::time::timeout(WAIT, self.stdout.next_line()).await {
            Ok(Ok(Some(line))) => line,
            other => panic!("no line on stdout ({other:?}); stderr:\n{}", self.stderr()),
        };
        let v: Value = serde_json::from_str(&line)
            .unwrap_or_else(|_| panic!("stdout carried a line that is not JSON: {line}"));
        assert_eq!(v["jsonrpc"], "2.0", "{line}");
        assert!(!line.contains("eyJ"), "a token reached stdout: {line}");
        v
    }

    async fn request(&mut self, id: Value, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        let v = self.recv().await;
        assert_eq!(v["id"], id, "{v}");
        v
    }

    async fn initialize(&mut self) -> Value {
        let v = self
            .request(
                json!(0),
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}),
            )
            .await;
        assert!(v["result"]["protocolVersion"].is_string(), "{v}");
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        v
    }

    async fn call(&mut self, id: Value, tool: &str) -> Value {
        self.request(
            id,
            "tools/call",
            json!({"name": tool, "arguments": {"path": "README.md"}}),
        )
        .await
    }

    async fn wait_stderr(&mut self, needle: &str) {
        let found = tokio::time::timeout(WAIT, self.stderr.wait_for(|s| s.contains(needle)))
            .await
            .is_ok_and(|r| r.is_ok());
        assert!(
            found,
            "`{needle}` never appeared on stderr:\n{}",
            self.stderr()
        );
    }

    /// Close stdin and wait for the exit: the status, what was left on stdout, and stderr.
    async fn finish(mut self) -> (Option<i32>, Vec<String>, String) {
        drop(self.stdin.take());
        let mut rest = Vec::new();
        while let Ok(Ok(Some(line))) = tokio::time::timeout(WAIT, self.stdout.next_line()).await {
            rest.push(line);
        }
        let status = tokio::time::timeout(WAIT, self.child.wait())
            .await
            .expect("the connector did not exit")
            .unwrap();
        // Let the stderr reader see the last lines.
        let mut stderr = self.stderr.clone();
        let _ = tokio::time::timeout(Duration::from_secs(2), stderr.wait_for(|_| false)).await;
        (status.code(), rest, self.stderr())
    }
}

/// `attenuo connect --upstream github` against `server`, minting with `script`.
fn connect_with_script(s: &Setup, script: &Path) -> Command {
    let mut c = attenuo();
    c.env("ATTENUO_SERVER", &s.url)
        .env("ATTENUO_ADMIN_TOKEN", &s.admin)
        .env("ATTENUO_BIN", env!("CARGO_BIN_EXE_attenuo"))
        .args(["connect", "--upstream", "github", "--token-command"])
        // Quoted, to show the command string is split like a shell would.
        .arg(format!("sh '{}'", script.display()));
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn a_desktop_client_session_from_start_to_end() {
    let s = setup(FakeMcpServer::new(&["read_file", "create_issue"]), |_| {}).await;
    let script = mint_script(s.tmp.path(), false);
    let mut c = Connector::spawn(connect_with_script(&s, &script));

    let init = c.initialize().await;
    assert_eq!(init["result"]["serverInfo"]["name"], "fake-mcp", "{init}");
    let list = c.request(json!("list"), "tools/list", json!({})).await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"read_file"), "{list}");

    // Allowed, then denied by policy: the proxy's JSON-RPC error comes through as it is.
    let allowed = c.call(json!(1), "read_file").await;
    assert_eq!(allowed["result"]["isError"], false, "{allowed}");
    let denied = c.call(json!(2), "create_issue").await;
    assert_eq!(denied["error"]["code"], -32003, "{denied}");
    assert_eq!(denied["error"]["data"]["reason"], "policy_deny", "{denied}");

    // Many at once, without waiting: each answer carries its own id.
    let ids: BTreeSet<i64> = (10..26).collect();
    for id in &ids {
        c.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                      "params": {"name": "read_file", "arguments": {"n": id}}}))
            .await;
    }
    let mut got = BTreeSet::new();
    for _ in &ids {
        let v = c.recv().await;
        let id = v["id"].as_i64().unwrap();
        // The answer to call `n` is the fake's echo of `n`.
        let echoed: Value =
            serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(echoed["arguments"]["n"], id, "{v}");
        got.insert(id);
    }
    assert_eq!(got, ids);

    // Lines that are not one JSON-RPC message.
    c.send_raw("this is not json").await;
    let v = c.recv().await;
    assert_eq!(
        (v["id"].clone(), v["error"]["code"].clone()),
        (Value::Null, json!(-32700))
    );
    c.send_raw(r#"[{"jsonrpc":"2.0","id":5,"method":"ping"}]"#)
        .await;
    let v = c.recv().await;
    assert_eq!(
        (v["id"].clone(), v["error"]["code"].clone()),
        (Value::Null, json!(-32600))
    );
    assert!(
        v["error"]["message"].as_str().unwrap().contains("batch"),
        "{v}"
    );
    c.send_raw("").await;
    let v = c.request(json!("p"), "ping", json!({})).await;
    assert!(v["result"].is_object(), "{v}");

    // End of stdin: the session is ended and the exit status is 0.
    let (code, rest, stderr) = c.finish().await;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(rest.is_empty(), "{rest:?}");
    assert_eq!(s.deleted(), vec![s.fake.session_id().to_string()]);
    // Only the allowed calls reached the MCP server.
    let calls = s.fake.recorded_calls();
    assert_eq!(calls.len(), 1 + ids.len());
    assert!(calls.iter().all(|c| c.name == "read_file"));
    // One token was enough, and neither it nor the command's arguments were logged.
    assert_eq!(runs(s.tmp.path()), 1);
    assert!(!stderr.contains("eyJ"), "{stderr}");
    assert!(!stderr.contains("mint.sh"), "{stderr}");
    assert!(
        stderr.contains("got a token from the token command `sh`"),
        "{stderr}"
    );
    // The upstream has no listen stream (405): that is not worth a line.
    assert!(!stderr.contains("listen stream"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sse_answers_are_written_message_by_message_in_order() {
    let fake = FakeMcpServer::new(&["read_file"])
        .with_sse(true)
        .with_sse_event_per_response(true);
    let s = setup(fake, |_| {}).await;
    let script = mint_script(s.tmp.path(), false);
    let mut c = Connector::spawn(connect_with_script(&s, &script));
    // `initialize` over SSE: a notification first, then the answer.
    c.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "test", "version": "1"}}}))
        .await;
    let first = c.recv().await;
    assert_eq!(first["method"], "notifications/message", "{first}");
    let answer = c.recv().await;
    assert_eq!(answer["id"], 0, "{answer}");
    c.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    c.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "read_file", "arguments": {}}}))
        .await;
    let mut seen = Vec::new();
    loop {
        let v = c.recv().await;
        let done = v["id"] == 1;
        seen.push(v);
        if done {
            break;
        }
    }
    assert_eq!(seen.last().unwrap()["result"]["isError"], false, "{seen:?}");
    assert!(
        seen[..seen.len() - 1]
            .iter()
            .all(|v| v["method"] == "notifications/message"),
        "{seen:?}"
    );
    let (code, _, stderr) = c.finish().await;
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(s.deleted(), vec![s.fake.session_id().to_string()]);
}

/// The first token the command prints is refused (401): the connector runs the command once
/// more and sends the request again with the new token.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_token_is_replaced_and_the_request_sent_once_more() {
    let s = setup(FakeMcpServer::new(&["read_file"]), |_| {}).await;
    let script = mint_script(s.tmp.path(), true);
    let mut c = Connector::spawn(connect_with_script(&s, &script));
    c.initialize().await;
    assert_eq!(runs(s.tmp.path()), 2);
    let v = c.call(json!(1), "read_file").await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(runs(s.tmp.path()), 2);
    let (code, _, stderr) = c.finish().await;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(!stderr.contains("not-a-valid-token"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_command_that_fails_ends_it_before_any_output() {
    let mut c = attenuo();
    c.env("ATTENUO_SERVER", "http://127.0.0.1:9")
        .args(["connect", "--upstream", "github", "--token-command"])
        .arg("sh -c 'echo from-the-command >&2; exit 3' SECRET-ARGUMENT")
        .stdin(Stdio::piped());
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("the token command `sh` failed"), "{stderr}");
    assert!(stderr.contains("from-the-command"), "{stderr}");
    assert!(!stderr.contains("SECRET-ARGUMENT"), "{stderr}");

    // No token source at all, and a command that is not one.
    let mut c = attenuo();
    c.args(["connect", "--upstream", "github"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        text(&out.stderr).contains("--token-command"),
        "{}",
        text(&out.stderr)
    );
    let mut c = attenuo();
    c.args([
        "connect",
        "--upstream",
        "github",
        "--token-command",
        "'open",
    ]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("single quote"),
        "{}",
        text(&out.stderr)
    );
}

/// `--token-file` is read again when the proxy refuses the token it held.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_file_is_read_again_after_a_refusal() {
    let s = setup(FakeMcpServer::new(&["read_file"]), |_| {}).await;
    let file = s.tmp.path().join("token");
    std::fs::write(&file, "stale-token\n").unwrap();
    let mut c = attenuo();
    c.env("ATTENUO_SERVER", &s.url)
        .args(["connect", "--upstream", "github", "--token-file"])
        .arg(&file);
    let mut c = Connector::spawn(c);
    c.wait_stderr("forwarding MCP messages").await;
    std::fs::write(&file, format!("{}\n", mint(&s).await)).unwrap();
    c.initialize().await;
    let v = c.call(json!(1), "read_file").await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    let (code, _, stderr) = c.finish().await;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(!stderr.contains("stale-token"), "{stderr}");
}

/// With a 2-second lease, a call 3.5 seconds in is still allowed because the connector
/// renews; a token minted at the same time and never renewed is refused by then. Then the
/// lease is revoked.
#[tokio::test(flavor = "multi_thread")]
async fn the_lease_is_renewed_in_the_background() {
    let s = setup(FakeMcpServer::new(&["read_file"]), |cfg| {
        cfg.issuer.lease_interval_seconds = 2;
    })
    .await;
    let script = mint_script(s.tmp.path(), false);
    let unrenewed = mint(&s).await;
    let mut c = Connector::spawn(connect_with_script(&s, &script));
    c.initialize().await;
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let v = c.call(json!(1), "read_file").await;
    assert_eq!(v["result"]["isError"], false, "{v}");

    let mut call = attenuo();
    call.env("ATTENUO_TOKEN", &unrenewed).args([
        "--server",
        &s.url,
        "call",
        "--upstream",
        "github",
        "--tool",
        "read_file",
    ]);
    let out = run(call).await;
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stdout));
    assert!(
        text(&out.stdout).contains("lease_expired"),
        "{}",
        text(&out.stdout)
    );

    assert!(
        !c.stderr().contains("renewing the lease failed"),
        "{}",
        c.stderr()
    );

    // A revoked lease is final: renewal stops, and no new token is fetched, not even when
    // the proxy then refuses the token.
    let mut revoke = attenuo();
    revoke
        .env("ATTENUO_ADMIN_TOKEN", &s.admin)
        .args(["--server", &s.url, "lease", "revoke", "--user", "alice"]);
    ok(&run(revoke).await);
    c.wait_stderr("the lease was revoked").await;
    let v = c.request(json!(2), "tools/list", json!({})).await;
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(v["error"]["data"]["reason"], "lease_revoked", "{v}");
    let (code, _, stderr) = c.finish().await;
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(
        stderr.matches("the lease was revoked").count(),
        1,
        "{stderr}"
    );
    assert_eq!(runs(s.tmp.path()), 1);
}

/// The listen stream is opened after `notifications/initialized` and its messages reach
/// stdout; SIGTERM ends the connector with status 0 and the session is ended. The token
/// command is the one of the guide's example.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_listen_stream_is_relayed_and_sigterm_ends_cleanly() {
    let s = setup(
        FakeMcpServer::new(&["read_file"]).with_listen_stream(true),
        |_| {},
    )
    .await;
    // The token command of the guide's worked example, as written there: no shell, so
    // `github:*` needs no quotes.
    let bin = env!("CARGO_BIN_EXE_attenuo");
    let mut cmd = attenuo();
    cmd.env("ATTENUO_ADMIN_TOKEN", &s.admin)
        .args(["--server", &s.url, "connect", "--upstream", "github", "--token-command"])
        .arg(format!(
            "{bin} --server {} token root --subject alice --agent planner --cap github:* --print token",
            s.url
        ));
    let mut c = Connector::spawn(cmd);
    c.initialize().await;
    let v = c.recv().await;
    assert_eq!(v["method"], "notifications/message", "{v}");
    assert_eq!(v["params"]["data"], "listening", "{v}");

    let pid = c.child.id().unwrap().to_string();
    let mut kill = Command::new("kill");
    kill.args(["-TERM", &pid]);
    assert!(run(kill).await.status.success());
    let status = tokio::time::timeout(WAIT, c.child.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.code(), Some(0), "{}", c.stderr());
    assert_eq!(s.deleted(), vec![s.fake.session_id().to_string()]);
}

// ---------------------------------------------------------------------------------------------
// Against a canned server
// ---------------------------------------------------------------------------------------------

/// What the canned server saw.
#[derive(Default)]
struct Seen {
    /// Requests that reached the redirect's target.
    stolen: AtomicUsize,
    /// Released when the test lets the slow request finish.
    release: tokio::sync::Notify,
}

/// A server at `/mcp/github` that answers by method:
/// `initialize` opens session `s-1`; `boom` is HTTP 500 with a text body; `moved` is a 307 to
/// another server; `gone` is the proxy's 404 for an unknown session; `quiet` is 202 for a
/// request; `flood` streams ten 1 KB notifications and no answer; `slow` waits for the
/// test; `locked` is always 401.
async fn canned(seen: Arc<Seen>, thief: String) -> Spawned {
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::post;
    let handler = move |headers: HeaderMap, axum::Json(req): axum::Json<Value>| {
        let seen = seen.clone();
        let thief = thief.clone();
        async move {
            let id = req["id"].clone();
            let json_reply = |status: StatusCode, body: Value| {
                (
                    status,
                    [(header::CONTENT_TYPE, "application/json")],
                    body.to_string(),
                )
                    .into_response()
            };
            match req["method"].as_str().unwrap_or("") {
                "initialize" => {
                    let mut r = json_reply(
                        StatusCode::OK,
                        json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18",
                               "capabilities":{},"serverInfo":{"name":"canned","version":"1"}}}),
                    );
                    r.headers_mut()
                        .insert("mcp-session-id", "s-1".parse().unwrap());
                    r
                }
                "boom" => (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response(),
                "moved" => {
                    (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, thief)]).into_response()
                }
                "gone" => {
                    assert_eq!(headers["mcp-session-id"], "s-1");
                    assert_eq!(headers["mcp-protocol-version"], "2025-06-18");
                    json_reply(
                        StatusCode::NOT_FOUND,
                        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,
                               "message":"attenuo: session not found; start a new session"}}),
                    )
                }
                "quiet" => StatusCode::ACCEPTED.into_response(),
                "flood" => {
                    let note = json!({"jsonrpc":"2.0","method":"notifications/message",
                                      "params":{"data":"x".repeat(900)}});
                    let body = format!("event: message\ndata: {note}\n\n").repeat(10);
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/event-stream")],
                        body,
                    )
                        .into_response()
                }
                "slow" => {
                    seen.release.notified().await;
                    json_reply(StatusCode::OK, json!({"jsonrpc":"2.0","id":id,"result":{}}))
                }
                "locked" => json_reply(
                    StatusCode::UNAUTHORIZED,
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,
                           "message":"attenuo: unauthorized: invalid_token",
                           "data":{"reason":"invalid_token"}}}),
                ),
                _ => StatusCode::ACCEPTED.into_response(),
            }
        }
    };
    spawn_router(axum::Router::new().route("/mcp/github", post(handler)))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_that_are_not_json_rpc_become_errors_with_the_request_id() {
    let seen = Arc::new(Seen::default());
    let thief_seen = seen.clone();
    let thief = spawn_router(axum::Router::new().fallback(move || {
        let s = thief_seen.clone();
        async move {
            s.stolen.fetch_add(1, Ordering::SeqCst);
            "stolen"
        }
    }))
    .await
    .unwrap();
    let server = canned(seen.clone(), thief.url("/steal")).await;
    let tmp = tempfile::tempdir().unwrap();
    // A token command that counts its runs and prints a new string each time.
    let script = tmp.path().join("tok.sh");
    std::fs::write(
        &script,
        format!(
            "n=$(( $(cat '{c}' 2>/dev/null || echo 0) + 1 )); echo \"$n\" > '{c}'; echo \"canned-token-$n\"\n",
            c = tmp.path().join("count").display()
        ),
    )
    .unwrap();
    let mut cmd = attenuo();
    cmd.env("ATTENUO_SERVER", server.url("").trim_end_matches('/'))
        .args(["connect", "--upstream", "github", "--max-in-flight", "1"])
        .args(["--max-message-bytes", "2048", "--max-stream-bytes", "4096"])
        .arg("--token-command")
        .arg(format!("sh {}", script.display()));
    let mut c = Connector::spawn(cmd);
    c.initialize().await;

    let reason = |v: &Value| {
        v["error"]["data"]["reason"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    let v = c.request(json!("b"), "boom", json!({})).await;
    assert_eq!(v["error"]["code"], -32603, "{v}");
    assert_eq!(reason(&v), "http_status");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("HTTP 500"),
        "{v}"
    );

    // A redirect is not followed: the bearer never reaches the other server.
    let v = c.request(json!("m"), "moved", json!({})).await;
    assert_eq!(reason(&v), "redirect", "{v}");
    assert_eq!(seen.stolen.load(Ordering::SeqCst), 0);

    // The session is gone: the proxy's error, with the request's id put in, and no new
    // session is opened behind the client's back.
    let v = c.request(json!("g"), "gone", json!({})).await;
    assert_eq!(v["error"]["code"], -32600, "{v}");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("session not found"));
    c.wait_stderr("does not know the MCP session").await;

    let v = c.request(json!("q"), "quiet", json!({})).await;
    assert_eq!(reason(&v), "no_answer", "{v}");

    // The bounds: a line over --max-message-bytes, a stream over --max-stream-bytes.
    c.send_raw(&format!(
        r#"{{"jsonrpc":"2.0","id":"big","method":"x","params":"{}"}}"#,
        "y".repeat(3000)
    ))
    .await;
    let v = c.recv().await;
    assert_eq!(
        (v["id"].clone(), v["error"]["code"].clone()),
        (Value::Null, json!(-32600))
    );
    c.send(json!({"jsonrpc":"2.0","id":"f","method":"flood"}))
        .await;
    let mut notes = 0;
    let v = loop {
        let v = c.recv().await;
        if v["method"] == "notifications/message" {
            notes += 1;
            continue;
        }
        break v;
    };
    assert_eq!(v["id"], "f", "{v}");
    assert_eq!(reason(&v), "too_large", "{v}");
    assert!(notes < 5, "{notes} notifications were written");

    // One request waits; a second one over --max-in-flight 1 is refused at once.
    c.send(json!({"jsonrpc":"2.0","id":"s1","method":"slow"}))
        .await;
    let v = c.request(json!("s2"), "slow", json!({})).await;
    assert_eq!(reason(&v), "too_many_in_flight", "{v}");
    seen.release.notify_one();
    let v = c.recv().await;
    assert_eq!(v["id"], "s1", "{v}");
    assert!(v["result"].is_object(), "{v}");

    // A 401 that a new token does not fix: one new token, one more try, then the proxy's
    // error with the request's id.
    assert_eq!(runs(tmp.path()), 1);
    let v = c.request(json!("l"), "locked", json!({})).await;
    assert_eq!(v["error"]["code"], -32001, "{v}");
    assert_eq!(runs(tmp.path()), 2);

    let (code, _, stderr) = c.finish().await;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(!stderr.contains("canned-token"), "{stderr}");
    assert!(!stderr.contains("tok.sh"), "{stderr}");
}

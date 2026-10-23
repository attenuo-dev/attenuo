//! SR-35: secrets from stdin, files and the environment reach the server; secrets on the command
//! line still work but warn. A one-shot HTTP listener stands in for the server and records the
//! request, so the tests see what actually goes on the wire.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::thread::{self, JoinHandle};

fn onbehalf() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_onbehalf"));
    for var in [
        "ONBEHALF_ADMIN_TOKEN",
        "ONBEHALF_CLIENT_SECRET",
        "ONBEHALF_TOKEN",
        "ONBEHALF_SERVER",
    ] {
        c.env_remove(var);
    }
    c
}

/// Answers one request with `200 {"ok": true, ...}` and returns the raw request text.
fn fake_server(body: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = sock.read(&mut buf).unwrap();
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req).to_string();
            if let Some(split) = text.find("\r\n\r\n") {
                let len = text[..split]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(str::to_owned)
                    })
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if req.len() >= split + 4 + len || n == 0 {
                    break;
                }
            } else if n == 0 {
                break;
            }
        }
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes()).unwrap();
        String::from_utf8_lossy(&req).to_string()
    });
    (url, handle)
}

fn run_with_stdin(mut cmd: Command, stdin: &str) -> Output {
    let mut child = cmd
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

const LEASE: &str =
    r#"{"lease_id":"L","active":true,"parent":null,"expires_at":"2030-01-01T00:00:00Z"}"#;
const TOKEN: &str = r#"{"access_token":"AT","lease":"L2","expires_in":60}"#;

#[test]
fn admin_token_from_stdin_is_sent_as_the_bearer_without_a_warning() {
    let (url, server) = fake_server(LEASE);
    let mut cmd = onbehalf();
    cmd.args([
        "--server",
        &url,
        "--admin-token-stdin",
        "lease",
        "show",
        "L",
    ]);
    let out = run_with_stdin(cmd, "stdin-admin-secret\nignored\n");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer stdin-admin-secret"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));
}

#[test]
fn admin_token_from_a_file_and_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("admin");
    std::fs::write(&path, "file-admin-secret\n").unwrap();

    let (url, server) = fake_server(LEASE);
    let out = onbehalf()
        .args(["--server", &url, "--admin-token-file"])
        .arg(&path)
        .args(["lease", "show", "L"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer file-admin-secret"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));

    let (url, server) = fake_server(LEASE);
    let out = onbehalf()
        .env("ONBEHALF_ADMIN_TOKEN", "env-admin-secret")
        .args(["--server", &url, "lease", "show", "L"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer env-admin-secret"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));
}

#[test]
fn admin_token_flag_still_works_and_warns_once_on_stderr() {
    let (url, server) = fake_server(LEASE);
    let out = onbehalf()
        .args([
            "--server",
            &url,
            "--admin-token",
            "argv-admin-secret",
            "lease",
            "show",
            "L",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(server.join().unwrap().contains("Bearer argv-admin-secret"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warnings: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("warning:"))
        .collect();
    assert_eq!(warnings.len(), 1, "{stderr}");
    assert!(warnings[0].contains("--admin-token") && warnings[0].contains("ONBEHALF_ADMIN_TOKEN"));
    assert!(
        !stderr.contains("argv-admin-secret"),
        "the secret must not be echoed"
    );
    // Nothing secret-looking on stdout either.
    assert!(!String::from_utf8_lossy(&out.stdout).contains("argv-admin-secret"));
}

#[test]
fn client_secret_from_stdin_and_file_goes_in_the_exchange_body() {
    let exchange = |extra: &[&str]| {
        let mut c = onbehalf();
        c.env("ONBEHALF_TOKEN", "PARENT").args(["--server"]);
        let mut v: Vec<String> = vec![
            "token".into(),
            "exchange".into(),
            "--actor".into(),
            "coder".into(),
            "--cap".into(),
            "github:read_file".into(),
        ];
        v.extend(extra.iter().map(|s| (*s).to_string()));
        (c, v)
    };

    let (url, server) = fake_server(TOKEN);
    let (mut cmd, args) = exchange(&["--client-secret-stdin"]);
    cmd.arg(&url).args(&args);
    let out = run_with_stdin(cmd, "stdin-client-secret\n");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req = server.join().unwrap();
    assert!(
        req.contains(r#""client_secret":"stdin-client-secret""#),
        "{req}"
    );
    assert!(req.contains(r#""client_id":"coder""#), "{req}");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret");
    std::fs::write(&path, "file-client-secret\n").unwrap();
    let (url, server) = fake_server(TOKEN);
    let out = onbehalf()
        .env("ONBEHALF_TOKEN", "PARENT")
        .args([
            "--server",
            &url,
            "token",
            "exchange",
            "--actor",
            "coder",
            "--cap",
            "github:read_file",
            "--client-secret-file",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server
        .join()
        .unwrap()
        .contains(r#""client_secret":"file-client-secret""#));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));
}

#[test]
fn client_secret_flag_warns_and_the_environment_does_not() {
    let (url, server) = fake_server(TOKEN);
    let out = onbehalf()
        .env("ONBEHALF_TOKEN", "PARENT")
        .args([
            "--server",
            &url,
            "token",
            "exchange",
            "--actor",
            "coder",
            "--cap",
            "github:read_file",
            "--client-secret",
            "argv-client-secret",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(server.join().unwrap().contains("argv-client-secret"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("warning: --client-secret on the command line"),
        "{stderr}"
    );
    assert!(!stderr.contains("argv-client-secret"));

    let (url, server) = fake_server(TOKEN);
    let out = onbehalf()
        .env("ONBEHALF_TOKEN", "PARENT")
        .env("ONBEHALF_CLIENT_SECRET", "env-client-secret")
        .args([
            "--server",
            &url,
            "token",
            "exchange",
            "--actor",
            "coder",
            "--cap",
            "github:read_file",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(server.join().unwrap().contains("env-client-secret"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("warning"));
}

#[test]
fn bad_secret_sources_fail_before_any_request() {
    // Empty stdin.
    let mut cmd = onbehalf();
    cmd.args([
        "--server",
        "http://127.0.0.1:1",
        "--admin-token-stdin",
        "lease",
        "show",
        "L",
    ]);
    let out = run_with_stdin(cmd, "\n");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("admin token is empty"));

    // Missing file: the error names the path, not a secret.
    let out = onbehalf()
        .args([
            "--server",
            "http://127.0.0.1:1",
            "--admin-token-file",
            "/nonexistent/onbehalf-admin",
            "lease",
            "show",
            "L",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/onbehalf-admin"));

    // Two stdin consumers.
    let mut cmd = onbehalf();
    cmd.args([
        "--server",
        "http://127.0.0.1:1",
        "--admin-token-stdin",
        "token",
        "exchange",
        "--subject-token",
        "J",
        "--actor",
        "c",
        "--cap",
        "g:t",
        "--client-secret-stdin",
    ]);
    let out = run_with_stdin(cmd, "one\n");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already read"));

    // Flag plus stdin on the command line is a usage error (clap exits 2).
    let out = onbehalf()
        .args([
            "--admin-token",
            "t",
            "--admin-token-stdin",
            "lease",
            "show",
            "L",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

const RPC_OK: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;

fn warnings(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.starts_with("warning:"))
        .map(str::to_owned)
        .collect()
}

/// SR-35 (remaining part): the delegation token of `call` (and `tools`, `authzen eval`) comes
/// from `--token -` (stdin), `--token-file` or `ONBEHALF_TOKEN` without a warning; the plain
/// flag still works and warns once.
#[test]
fn delegation_token_from_stdin_a_file_or_the_environment() {
    let call = |url: &str| {
        let mut c = onbehalf();
        c.args([
            "--server",
            url,
            "call",
            "--server",
            "github",
            "--tool",
            "read_file",
        ]);
        c
    };

    let (url, server) = fake_server(RPC_OK);
    let mut cmd = call(&url);
    cmd.args(["--token", "-"]);
    let out = run_with_stdin(cmd, "stdin.jwt.token\nignored\n");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server
        .join()
        .unwrap()
        .contains("Bearer stdin.jwt.token\r\n"));
    assert!(warnings(&out).is_empty(), "{:?}", warnings(&out));

    // The file wins over the environment, and the two do not conflict.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "file.jwt.token\n").unwrap();
    let (url, server) = fake_server(RPC_OK);
    let out = call(&url)
        .env("ONBEHALF_TOKEN", "env.jwt.token")
        .arg("--token-file")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer file.jwt.token\r\n"));
    assert!(warnings(&out).is_empty());

    let (url, server) = fake_server(RPC_OK);
    let out = call(&url)
        .env("ONBEHALF_TOKEN", "env.jwt.token")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer env.jwt.token\r\n"));
    assert!(warnings(&out).is_empty());

    let (url, server) = fake_server(RPC_OK);
    let out = call(&url)
        .args(["--token", "flag.jwt.token"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer flag.jwt.token\r\n"));
    let w = warnings(&out);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(w[0].contains("--token") && w[0].contains("ONBEHALF_TOKEN"));
    assert!(!w[0].contains("flag.jwt.token"));

    // None of them: an error that names the alternatives, before any request.
    let out = call("http://127.0.0.1:1").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ONBEHALF_TOKEN"));
}

/// SR-35: `--subject-token -` reads the parent token from stdin; the client secret then comes
/// from a file, since stdin can only be read once.
#[test]
fn subject_token_from_stdin_goes_in_the_exchange_body() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "file-client-secret\n").unwrap();
    let (url, server) = fake_server(TOKEN);
    let mut cmd = onbehalf();
    cmd.args([
        "--server",
        &url,
        "token",
        "exchange",
        "--subject-token",
        "-",
        "--actor",
        "coder",
        "--cap",
        "github:read_file",
        "--client-secret-file",
    ])
    .arg(&secret);
    let out = run_with_stdin(cmd, "PARENT.FROM.STDIN\n");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req = server.join().unwrap();
    assert!(
        req.contains(r#""subject_token":"PARENT.FROM.STDIN""#),
        "{req}"
    );
    assert!(warnings(&out).is_empty());

    let path = dir.path().join("parent");
    std::fs::write(&path, "PARENT.FROM.FILE\n").unwrap();
    let (url, server) = fake_server(TOKEN);
    let out = onbehalf()
        .env("ONBEHALF_CLIENT_SECRET", "env-secret")
        .args([
            "--server",
            &url,
            "token",
            "exchange",
            "--subject-token-file",
        ])
        .arg(&path)
        .args(["--actor", "coder", "--cap", "github:read_file"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req = server.join().unwrap();
    assert!(
        req.contains(r#""subject_token":"PARENT.FROM.FILE""#),
        "{req}"
    );
    assert!(req.contains(r#""client_secret":"env-secret""#), "{req}");

    // Parent token and client secret cannot both come from stdin.
    let mut cmd = onbehalf();
    cmd.args([
        "--server",
        "http://127.0.0.1:1",
        "token",
        "exchange",
        "--subject-token",
        "-",
        "--actor",
        "c",
        "--cap",
        "g:t",
        "--client-secret-stdin",
    ]);
    let out = run_with_stdin(cmd, "one\n");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already read"));
}

/// The environment variable and a `--…-file` flag used to be a clap conflict (clap counts an
/// environment value as given); now the file simply wins.
#[test]
fn a_file_flag_overrides_the_environment_instead_of_conflicting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("admin");
    std::fs::write(&path, "file-admin-secret\n").unwrap();
    let (url, server) = fake_server(LEASE);
    let out = onbehalf()
        .env("ONBEHALF_ADMIN_TOKEN", "env-admin-secret")
        .args(["--server", &url, "--admin-token-file"])
        .arg(&path)
        .args(["lease", "show", "L"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(server.join().unwrap().contains("Bearer file-admin-secret"));
}

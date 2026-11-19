//! The commands that answer a question keep their documented exit status when the reader of
//! stdout or stderr has gone before they write (security review pass 20): `audit verify`
//! (0 for an intact chain, 2 for a broken one, 1 for an error), `policy test` (0, 2 for a
//! failed case, 1 for a file that cannot be run), `policy lint` (0, 2 for a policy error) and
//! `health` (0, 1 when the server is not healthy or not there; never 2).
//!
//! Unlike `tests/broken_pipe.rs`, which closes the pipe after the first bytes of a long
//! output, the read end here is closed before the command starts, so the first write of any
//! size meets a closed pipe. A panic would exit 101.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::attenuo;

const ADMIN: &str = "closed-output-test-admin";

/// Which of the command's output streams has no reader.
#[derive(Debug, Clone, Copy)]
enum Closed {
    Stdout,
    Stderr,
    Both,
}

/// A pipe whose read end is already closed.
fn closed_pipe() -> std::io::PipeWriter {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer
}

/// Run `cmd` with `closed` streams readerless; returns the exit code and whatever reached the
/// open stream, if one is open.
fn run_closed(mut cmd: Command, closed: Closed) -> (Option<i32>, String) {
    match closed {
        Closed::Stdout => cmd.stdout(closed_pipe()).stderr(Stdio::piped()),
        Closed::Stderr => cmd.stdout(Stdio::piped()).stderr(closed_pipe()),
        Closed::Both => cmd.stdout(closed_pipe()).stderr(closed_pipe()),
    };
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    let mut open = String::new();
    if let Some(mut s) = child.stdout.take() {
        s.read_to_string(&mut open).unwrap();
    }
    if let Some(mut s) = child.stderr.take() {
        s.read_to_string(&mut open).unwrap();
    }
    let start = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running 30s after start");
        }
        thread::sleep(Duration::from_millis(20));
    };
    (code, open)
}

/// Every closed combination gives `want`, and nothing that reached an open stream is a panic.
fn assert_status(make: impl Fn() -> Command, want: i32, what: &str) {
    for closed in [Closed::Stdout, Closed::Stderr, Closed::Both] {
        let (code, open) = run_closed(make(), closed);
        assert_eq!(code, Some(want), "{what}, {closed:?} closed: {open}");
        assert!(!open.contains("panicked"), "{what}, {closed:?}: {open}");
    }
}

/// Answers every request with `status` and `body` until the test process ends.
fn serve(status: &'static str, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { continue };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&req).contains("\r\n\r\n") {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    url
}

fn against(url: &str, args: &[&str]) -> Command {
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", url])
        .args(args);
    c
}

#[test]
fn audit_verify_keeps_its_status_when_output_is_closed() {
    let intact = serve(
        "200 OK",
        r#"{"ok":true,"entries":3,"first_bad_seq":null,"checkpoints":0}"#,
    );
    let broken = serve(
        "200 OK",
        r#"{"ok":false,"entries":3,"first_bad_seq":2,"checkpoints":0}"#,
    );
    let failing = serve(
        "500 Internal Server Error",
        r#"{"error":"internal","detail":"x"}"#,
    );
    for json in [false, true] {
        let args = |a: &'static [&'static str]| -> Vec<&'static str> {
            if json {
                [&["--json"][..], a].concat()
            } else {
                a.to_vec()
            }
        };
        let verify = args(&["audit", "verify"]);
        assert_status(|| against(&intact, &verify), 0, "an intact chain");
        assert_status(|| against(&broken, &verify), 2, "a broken chain");
        assert_status(|| against(&failing, &verify), 1, "a server error");
    }
}

fn write_policy_case(dir: &Path, expect: &str) -> String {
    std::fs::write(
        dir.join("p.cedar"),
        "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
    )
    .unwrap();
    let cases = dir.join(format!("{expect}_test.yaml"));
    std::fs::write(
        &cases,
        format!(
            "policies: ./p.cedar\ncatalog:\n  github:\n    read_file: {{ readonly: true, inputs: {{ repo: string }} }}\ncases:\n  - name: a read\n    call: {{ server: github, tool: read_file, arguments: {{ repo: alice/x }} }}\n    expect: {expect}\n"
        ),
    )
    .unwrap();
    cases.display().to_string()
}

#[test]
fn policy_test_keeps_its_status_when_output_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let pass = write_policy_case(dir.path(), "allow");
    let fail = write_policy_case(dir.path(), "deny");
    let missing = dir.path().join("missing_test.yaml").display().to_string();
    for json in [false, true] {
        let make = |file: &str| {
            let mut c = attenuo();
            if json {
                c.arg("--json");
            }
            c.args(["policy", "test", file]);
            c
        };
        assert_status(|| make(&pass), 0, "a passing case");
        assert_status(|| make(&fail), 2, "a failing case");
        assert_status(|| make(&missing), 1, "a file that cannot be run");
    }
}

#[test]
fn policy_lint_keeps_its_status_when_output_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.cedar");
    std::fs::write(
        &good,
        "permit(principal, action == Action::\"github/read_file\", resource);\n",
    )
    .unwrap();
    let bad = dir.path().join("bad.cedar");
    std::fs::write(
        &bad,
        "permit(principal, action == Action::\"read_file\", resource);\n",
    )
    .unwrap();
    for json in [false, true] {
        let make = |file: &Path| {
            let mut c = attenuo();
            if json {
                c.arg("--json");
            }
            c.args(["policy", "lint"]).arg(file);
            c
        };
        assert_status(|| make(&good), 0, "a clean policy");
        assert_status(|| make(&bad), 2, "a policy error");
    }
}

#[test]
fn health_keeps_its_status_when_output_is_closed() {
    let healthy = serve("200 OK", r#"{"status":"ok","version":"9.9.9"}"#);
    let ready = serve(
        "200 OK",
        r#"{"ready":true,"checks":{"audit":"ok","leases":"ok"}}"#,
    );
    let not_ready = serve(
        "503 Service Unavailable",
        r#"{"ready":false,"checks":{"audit":"error"}}"#,
    );
    // A port with nothing listening on it.
    let gone = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        url
    };
    for json in [false, true] {
        let make = |url: &str, extra: &[&str]| {
            let mut c = attenuo();
            if json {
                c.arg("--json");
            }
            c.args(["--server", url, "health"]).args(extra);
            c
        };
        assert_status(|| make(&healthy, &[]), 0, "healthy");
        assert_status(|| make(&ready, &["--ready"]), 0, "ready");
        assert_status(|| make(&not_ready, &["--ready"]), 1, "not ready");
        assert_status(|| make(&gone, &["--timeout", "5"]), 1, "not there");
    }
}

//! A reader that closes stdout early (`attenuo audit tail | head -1`) ends the command
//! quietly: no panic and nothing on stderr, and the exit status the command would have had.
//! Streaming commands (`audit tail --follow`, `policy test --watch`) stop at their next write.
//! Any other write error still fails the command with a message.
//!
//! The output here is far larger than a pipe's buffer (64 KiB on Linux), so the CLI is still
//! writing when the test closes the read end, and the write that follows meets a closed pipe.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::attenuo;

const ADMIN: &str = "broken-pipe-test-admin";

/// Entries per page: about 300 KiB of text, and more as JSON.
const ENTRIES: u64 = 1000;

fn entry(seq: u64) -> String {
    format!(
        r#"{{"seq":{seq},"record":{{"id":"r{seq}","at":"2026-10-23T09:00:00Z","decision":"deny","reason":"policy_deny","originating_subject":"alice","agents":["coder"],"server":"github","tool":"create_issue"}}}}"#
    )
}

/// Answers every request with `body` until the test process ends.
fn serve_forever(body: String) -> String {
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
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            // The CLI may hang up mid-body once its reader has gone.
            let _ = sock
                .write_all(head.as_bytes())
                .and_then(|()| sock.write_all(body.as_bytes()));
        }
    });
    url
}

/// A `GET /admin/audit` page of [`ENTRIES`] entries and no next page.
fn audit_server() -> String {
    let entries: Vec<String> = (1..=ENTRIES).rev().map(entry).collect();
    serve_forever(format!(
        r#"{{"entries":[{}],"next_cursor":null,"head":{ENTRIES}}}"#,
        entries.join(",")
    ))
}

/// Spawn `cmd` with stdout on a pipe, read its first bytes, then close the read end, as
/// `head -c` does. Returns the exit code and stderr.
fn close_after_first_bytes(mut cmd: Command, then: impl FnOnce()) -> (Option<i32>, String) {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut first = [0u8; 700];
    let n = stdout.read(&mut first).unwrap();
    assert!(n > 0, "the command printed nothing");
    drop(stdout);
    then();
    let code = wait(&mut child, Duration::from_secs(30));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (code, stderr)
}

/// The exit code, killing the child (and failing) if it outlives `limit`.
fn wait(child: &mut Child, limit: Duration) -> Option<i32> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code();
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running {limit:?} after its reader went away");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn cli(url: &str, args: &[&str]) -> Command {
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(["--server", url])
        .args(args);
    c
}

#[test]
fn audit_tail_json_ends_quietly_when_the_reader_goes() {
    let url = audit_server();
    let (code, stderr) =
        close_after_first_bytes(cli(&url, &["--json", "audit", "tail", "-n", "1000"]), || {});
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "");
}

#[test]
fn audit_tail_text_ends_quietly_when_the_reader_goes() {
    let url = audit_server();
    let (code, stderr) =
        close_after_first_bytes(cli(&url, &["audit", "tail", "-n", "1000"]), || {});
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "");
}

/// `--follow` would poll forever; it stops at its first write after the reader has gone.
#[test]
fn audit_tail_follow_stops_when_the_reader_goes() {
    let url = audit_server();
    let (code, stderr) = close_after_first_bytes(
        cli(
            &url,
            &[
                "audit",
                "tail",
                "-n",
                "1",
                "--follow",
                "--interval-ms",
                "50",
            ],
        ),
        || {},
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "");
}

/// `audit export` streams through its own writer, not `out!`.
#[test]
fn audit_export_ends_quietly_when_the_reader_goes() {
    let mut body = String::from("{\"format\":\"attenuo-audit-export-v2\"}\n");
    for seq in 1..=ENTRIES {
        body.push_str(&entry(seq));
        body.push('\n');
    }
    let url = serve_forever(body);
    let (code, stderr) = close_after_first_bytes(cli(&url, &["audit", "export"]), || {});
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stderr, "");
}

/// `--watch` writes nothing until a file changes; the run after the change meets the closed
/// pipe and ends the command with that run's status, as `policy test` without `--watch`.
#[test]
fn policy_test_watch_stops_when_the_reader_goes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("p.cedar"),
        "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
    )
    .unwrap();
    let cases = dir.path().join("p_test.yaml");
    let yaml = "policies: ./p.cedar\ncatalog:\n  github:\n    read_file: { readonly: true, inputs: { repo: string } }\ncases:\n  - name: a read\n    call: { server: github, tool: read_file, arguments: { repo: alice/x } }\n    expect: allow\n";
    std::fs::write(&cases, yaml).unwrap();
    let mut cmd = attenuo();
    cmd.args(["policy", "test", "--watch"]).arg(&cases);
    let (code, stderr) = close_after_first_bytes(cmd, || {
        // A change of length, so the poll sees it whatever the file system's mtime grain.
        std::fs::write(&cases, format!("{yaml}# changed\n")).unwrap();
    });
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains("Broken pipe"), "{stderr}");
}

/// Another write error is not a closed reader: the command fails with a message.
#[cfg(target_os = "linux")]
#[test]
fn a_full_disk_still_fails_the_command() {
    let url = audit_server();
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let out = cli(&url, &["audit", "tail", "-n", "1000"])
        .stdout(full)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(
        stderr.starts_with("error: writing to standard output: "),
        "{stderr}"
    );
}

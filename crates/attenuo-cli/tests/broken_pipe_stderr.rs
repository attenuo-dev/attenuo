//! A reader that closes stderr early (`attenuo policy test cases.yaml 2>&1 | head -1`) ends
//! the stderr output quietly: no panic, and the exit status the command would have had.
//!
//! As in `tests/broken_pipe.rs`, the output is far larger than a pipe's buffer (64 KiB on
//! Linux), so the CLI is still writing when the test closes the read end, and the write that
//! follows meets a closed pipe. Stdout and stderr share the one pipe, as with `2>&1`.

mod common;

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use common::attenuo;

/// Spawn `cmd` with stdout and stderr on one pipe, read its first bytes, then close the read
/// end, as `2>&1 | head -c` does. Returns the exit code.
fn close_after_first_bytes(mut cmd: Command) -> Option<i32> {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let mut child = cmd
        .stdout(writer.try_clone().unwrap())
        .stderr(writer)
        .spawn()
        .unwrap();
    // The command holds the write ends; only the child's copies may remain.
    drop(cmd);
    let mut first = [0u8; 700];
    let n = reader.read(&mut first).unwrap();
    assert!(n > 0, "the command printed nothing");
    drop(reader);
    wait(&mut child, Duration::from_secs(30))
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

/// Paths of test files that do not exist: each is one `error: ...` line on stderr, about
/// 200 bytes, so 2000 of them are some 400 KiB.
fn missing_files(dir: &Path, n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            dir.join(format!(
                "missing-cases-file-{i:04}-of-a-policy-test-run_test.yaml"
            ))
            .display()
            .to_string()
        })
        .collect()
}

/// Every line goes to stderr; a panic would exit 101 instead of the documented 1 (a file
/// cannot be run).
#[test]
fn policy_test_stderr_ends_quietly_when_the_reader_goes() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = attenuo();
    cmd.args(["policy", "test"])
        .args(missing_files(dir.path(), 2000));
    assert_eq!(close_after_first_bytes(cmd), Some(1));
}

/// Stdout fills the pipe first (many failing cases) and stops quietly; the stderr lines that
/// follow (a file that cannot be run, then `main`'s own `error: ...`) meet the closed pipe.
#[test]
fn policy_test_stdout_then_stderr_ends_quietly_when_the_reader_goes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("p.cedar"),
        "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
    )
    .unwrap();
    let mut yaml = String::from(
        "policies: ./p.cedar\ncatalog:\n  github:\n    read_file: { readonly: true, inputs: { repo: string } }\ncases:\n",
    );
    for i in 0..2000 {
        yaml.push_str(&format!(
            "  - name: a read that the case wrongly expects to be denied, number {i}\n    call: {{ server: github, tool: read_file, arguments: {{ repo: alice/x }} }}\n    expect: deny\n"
        ));
    }
    let cases = dir.path().join("failing_test.yaml");
    std::fs::write(&cases, yaml).unwrap();
    let mut cmd = attenuo();
    cmd.args(["policy", "test"])
        .arg(&cases)
        .args(missing_files(dir.path(), 1));
    assert_eq!(close_after_first_bytes(cmd), Some(1));
}

//! `ATTENUO__<SECTION>__<KEY>` overrides through the real binary (audit O-5): the server
//! applies them before its startup checks, logs the overridden keys by name only, and refuses
//! to start, naming the variable and never the value, on a variable it cannot apply.
//!
//! Each case runs `attenuo-server` as a child process with its own environment, so nothing
//! here touches this test process's environment.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const SECRET: &str = "env-admin-token-that-must-never-appear-0123456789";

fn server(config: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_attenuo-server"));
    cmd.arg("--config")
        .arg(config)
        .env_remove("ATTENUO_ADMIN_TOKEN")
        .env_remove("ATTENUO_LOG_FORMAT")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Variables of the test's own environment must not leak in as overrides.
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("ATTENUO__")
        {
            cmd.env_remove(name);
        }
    }
    cmd
}

fn write_config(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// Run the server to completion (it is expected to refuse to start) and return its output.
fn refused(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(!out.status.success(), "the server started");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn overrides_apply_before_the_checks_and_are_logged_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        dir.path(),
        "[server]\nlisten = \"127.0.0.1:1\"\n\n[admin]\ntoken = \"file-token\"\n",
    );
    let mut child = server(&config)
        // Port 1 in the file would fail to bind; the override moves it.
        .env("ATTENUO__SERVER__LISTEN", "127.0.0.1:0")
        .env("ATTENUO__ADMIN__TOKEN", SECRET)
        .env("ATTENUO__LOGGING__FORMAT", "json")
        // CLI and SDK variables, one underscore: never read as overrides.
        .env("ATTENUO_SERVER", "http://127.0.0.1:9")
        .env("ATTENUO_TOKEN", "not-a-token")
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let found = loop {
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => {
                let listening = line.contains("listening");
                seen.push(line);
                if listening {
                    break true;
                }
            }
            Err(_) => break false,
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut stderr);
    let all = seen.join("\n");
    assert!(found, "the server did not start:\n{all}\n{stderr}");
    let line = seen
        .iter()
        .find(|l| l.contains("config keys overridden from the environment"))
        .unwrap_or_else(|| panic!("no override line:\n{all}"));
    // JSON, so ATTENUO__LOGGING__FORMAT took effect.
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["level"], "INFO");
    let keys = v["keys"].as_str().unwrap();
    assert_eq!(
        keys,
        "[admin] token (ATTENUO__ADMIN__TOKEN), [logging] format (ATTENUO__LOGGING__FORMAT), \
         [server] listen (ATTENUO__SERVER__LISTEN)"
    );
    assert!(!all.contains(SECRET) && !stderr.contains(SECRET));
}

#[test]
fn a_bad_variable_stops_the_server_naming_it_but_not_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "[server]\nlisten = \"127.0.0.1:0\"\n");
    for (var, value, says) in [
        ("ATTENUO__ADMIN__TOKN", SECRET, "[admin] has no key `TOKN`"),
        (
            "ATTENUO__DEV__ALLOW_ROOT_MINT",
            "true",
            "[dev] keys cannot be set from the environment",
        ),
        (
            "ATTENUO__METRICS__ENABLED",
            "not-a-bool-value",
            "expected true or false",
        ),
    ] {
        let out = refused(server(&config).env(var, value));
        assert!(out.contains(var) && out.contains(says), "{var}: {out}");
        assert!(!out.contains(value), "{var} echoed its value: {out}");
    }
}

#[test]
fn the_startup_checks_apply_to_overridden_values() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "[server]\nlisten = \"127.0.0.1:0\"\n");
    // Off loopback without public_url: the same refusal as from the file.
    let out = refused(server(&config).env("ATTENUO__SERVER__LISTEN", "0.0.0.0:0"));
    assert!(
        out.contains("[server] listen = 0.0.0.0:0 is not a loopback address")
            && out.contains("public_url is not set"),
        "{out}"
    );
    // With public_url and an admin listener of its own set too, the weak admin token check.
    let out = refused(
        server(&config)
            .env("ATTENUO__SERVER__LISTEN", "0.0.0.0:0")
            .env("ATTENUO__SERVER__PUBLIC_URL", "https://attenuo.example.com")
            .env("ATTENUO__ADMIN__LISTEN", "127.0.0.1:0")
            .env("ATTENUO__ADMIN__TOKEN", "change-me"),
    );
    assert!(
        out.contains("[admin] token is a published placeholder value"),
        "{out}"
    );
}

#[test]
fn admin_token_from_both_variables_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "[server]\nlisten = \"127.0.0.1:0\"\n");
    let out = refused(
        server(&config)
            .env("ATTENUO__ADMIN__TOKEN", SECRET)
            .env("ATTENUO_ADMIN_TOKEN", SECRET),
    );
    assert!(
        out.contains("ATTENUO__ADMIN__TOKEN: ATTENUO_ADMIN_TOKEN sets [admin] token too"),
        "{out}"
    );
    assert!(!out.contains(SECRET), "{out}");
}

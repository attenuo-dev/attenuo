//! Tiny cells of each new subcommand against the real server (debug builds).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

use attenuo_bench::{run, Opts};
use clap::Parser;
use serde_json::Value;

fn target_debug_dir() -> PathBuf {
    let mut dir = std::env::current_exe().unwrap();
    dir.pop();
    if dir.file_name().is_some_and(|n| n == "deps") {
        dir.pop();
    }
    dir
}

static BUILD: Once = Once::new();

/// The server and the example are other packages' artifacts; build them if cargo test did not.
fn ensure_binaries(dir: &Path) {
    BUILD.call_once(|| {
        if dir.join("attenuo-server").is_file() && dir.join("examples/fake_mcp").is_file() {
            return;
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args([
                "build",
                "-q",
                "-p",
                "attenuo-server",
                "-p",
                "attenuo-proxy",
                "--features",
                "attenuo-proxy/testing",
                "--example",
                "fake_mcp",
            ])
            .status()
            .expect("run cargo build");
        assert!(status.success(), "building the server and fake_mcp failed");
    });
}

fn out_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("attenuo-bench-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

async fn run_args(name: &str, args: &[&str]) -> Value {
    let dir = target_debug_dir();
    ensure_binaries(&dir);
    let out = out_dir(name);
    let json = out.join("r.json");
    let md = out.join("r.md");
    let mut argv: Vec<String> = vec!["attenuo-bench".into()];
    // Top-level flags first, then the subcommand and its own flags.
    argv.extend(args.iter().map(|s| s.to_string()));
    argv.extend([
        "--bin-dir".into(),
        dir.to_str().unwrap().into(),
        "--json".into(),
        json.to_str().unwrap().into(),
        "--markdown".into(),
        md.to_str().unwrap().into(),
    ]);
    // `--bin-dir`, `--json` and `--markdown` exist on the top level and on each subcommand; they
    // are appended last, so they belong to whichever command the arguments end with.
    run(Opts::try_parse_from(argv).unwrap())
        .await
        .expect("bench run");
    assert!(std::fs::read_to_string(&md).unwrap().contains('|'));
    let v: Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&out);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchange_closed_loop_with_fresh_actors() {
    let v = run_args(
        "xc",
        &[
            "exchange",
            "--duration",
            "1",
            "--warmup",
            "0.3",
            "--audit",
            "memory,file",
            "--clients",
            "2",
            "--depths",
            "1,3",
        ],
    )
    .await;
    let rows = v["runs"]["exchange"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "memory and file at 1 and 3 hops");
    for r in rows {
        assert!(r["requests"].as_u64().unwrap() > 0, "{r}");
        assert_eq!(r["unexpected"], 0, "{r}");
        assert_eq!(r["load"], "closed");
        // Server CPU comes from `/proc/<pid>/stat`, so it is only read on Linux.
        if cfg!(target_os = "linux") {
            assert!(
                r["cpu"]["seconds"].as_f64().is_some(),
                "server CPU is read: {r}"
            );
        }
    }
    for c in v["runs"]["exchange"]["audit_checks"].as_array().unwrap() {
        assert_eq!(c["ok"], true, "{c}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exchange_open_loop() {
    let v = run_args(
        "xo",
        &[
            "exchange",
            "--duration",
            "1",
            "--warmup",
            "0.3",
            "--audit",
            "memory",
            "--depths",
            "1",
            "--open-loop",
            "40",
        ],
    )
    .await;
    let r = &v["runs"]["exchange"]["rows"][0];
    assert_eq!(r["load"], "open");
    assert_eq!(r["offered_rps"], 40.0);
    assert!(r["requests"].as_u64().unwrap() > 10, "{r}");
    assert_eq!(r["unexpected"], 0, "{r}");
    assert_eq!(r["shed"], 0, "{r}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_renew_and_cascade() {
    let v = run_args(
        "lr",
        &[
            "lease-renew",
            "--duration",
            "2",
            "--warmup",
            "0.5",
            "--audit",
            "memory",
            "--cells",
            "100:1",
            "--cascade-runs",
            "1",
        ],
    )
    .await;
    let rows = v["runs"]["lease_renew"]["rows"]["renewals"]
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r["leases"], 100);
    assert_eq!(r["errors"], 0, "{r}");
    assert!(
        r["renewals"].as_u64().unwrap() >= 150,
        "100 leases for 2 s at 1 s: {r}"
    );
    let c = &v["runs"]["lease_renew"]["rows"]["cascade"][0];
    assert_eq!(c["revoked"], 101, "{c}");
    assert_eq!(c["descendant_refused"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxied_call_open_loop() {
    let v = run_args(
        "co",
        &[
            "--duration",
            "1",
            "--warmup",
            "0.3",
            "--audit",
            "memory",
            "--depths",
            "1",
            "--outcomes",
            "allow",
            "--open-loop",
            "50",
        ],
    )
    .await;
    let rows = v["runs"]["call_open_loop"]["rows"].as_array().unwrap();
    let paths: Vec<&str> = rows.iter().map(|r| r["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["direct", "allow"]);
    for r in rows {
        assert!(r["requests"].as_u64().unwrap() > 10, "{r}");
        assert_eq!(r["unexpected"], 0, "{r}");
    }
}

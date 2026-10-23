//! Runs a one-second scenario against the real server and fake_mcp (debug builds).

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use onbehalf_bench::{run, Opts};

fn target_debug_dir() -> PathBuf {
    let mut dir = std::env::current_exe().unwrap();
    dir.pop();
    if dir.file_name().is_some_and(|n| n == "deps") {
        dir.pop();
    }
    dir
}

/// The server and the example are other packages' artifacts; build them if cargo test did not.
fn ensure_binaries(dir: &Path) {
    if dir.join("onbehalf-server").is_file() && dir.join("examples/fake_mcp").is_file() {
        return;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .args([
            "build",
            "-q",
            "-p",
            "onbehalf-server",
            "-p",
            "onbehalf-proxy",
            "--features",
            "onbehalf-proxy/testing",
            "--example",
            "fake_mcp",
        ])
        .status()
        .expect("run cargo build");
    assert!(status.success(), "building the server and fake_mcp failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_second_scenario_runs_and_audit_verifies() {
    let dir = target_debug_dir();
    ensure_binaries(&dir);
    let out = std::env::temp_dir().join(format!("onbehalf-bench-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let json = out.join("r.json");
    let opts = Opts::try_parse_from([
        "onbehalf-bench",
        "--bin-dir",
        dir.to_str().unwrap(),
        "--duration",
        "1",
        "--warmup",
        "0.3",
        "--concurrency",
        "2",
        "--depths",
        "3",
        "--audit",
        "memory",
        "--json",
        json.to_str().unwrap(),
    ])
    .unwrap();
    run(opts).await.expect("bench run");

    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 3, "allow, deny_policy, deny_capability");
    for r in results {
        assert!(r["requests"].as_u64().unwrap() > 0, "{r}");
        assert_eq!(r["unexpected"], 0, "{r}");
        assert!(r["p99_us"].as_f64().unwrap() >= r["p50_us"].as_f64().unwrap());
    }
    assert_eq!(v["audit_checks"][0]["ok"], true);
    let _ = std::fs::remove_dir_all(out);
}

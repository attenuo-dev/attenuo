//! `attenuo admin key reload` against a running server: a rotation with an overlap prints the
//! key ids, `--json` prints the answer, a refusal exits 1 with its code and changes nothing,
//! and `--allow-drop-current` drops the current key when asked.

mod common;

use std::process::Output;

use attenuo_proxy::testing::spawn_router;
use attenuo_server::Config;
use attenuo_token::{Issuer, IssuerConfig};
use serde_json::Value;

use common::attenuo;

const LEGACY: &str = "legacy-admin-token-0123456789abcdef";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

/// A fresh Ed25519 key: its private PEM and its `kid`.
fn new_key() -> (String, String) {
    let i = Issuer::generate(IssuerConfig {
        issuer: "i".into(),
        audience: "a".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    });
    (i.private_key_pem(), i.key_id())
}

#[tokio::test]
async fn key_reload_prints_the_kids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.toml");
    let key = |name: &str| dir.path().join(name);
    let (pem1, kid1) = new_key();
    let (pem2, kid2) = new_key();
    let (pem3, kid3) = new_key();
    std::fs::write(key("k1.pem"), &pem1).unwrap();
    std::fs::write(key("k2.pem"), &pem2).unwrap();
    std::fs::write(key("k3.pem"), &pem3).unwrap();
    let file = |signing: &str, previous: &[&str]| {
        let prev: Vec<String> = previous
            .iter()
            .map(|p| format!("\"{}\"", key(p).display()))
            .collect();
        format!(
            "[issuer]\nprivate_key_pem_path = \"{}\"\nprevious_key_paths = [{}]\n\n[audit]\n\
             sqlite_path = \"{}\"\n\n[admin]\ntoken = \"{LEGACY}\"\n",
            key(signing).display(),
            prev.join(", "),
            dir.path().join("audit.sqlite").display(),
        )
    };
    std::fs::write(&path, file("k1.pem", &[])).unwrap();
    let cfg = Config::load(&path).unwrap();
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let url = server.url("");
    let run = move |json: bool, flags: &'static [&'static str]| {
        let url = url.clone();
        async move {
            tokio::task::spawn_blocking(move || -> Output {
                let mut cmd = attenuo();
                cmd.args(["--server", &url]);
                if json {
                    cmd.arg("--json");
                }
                cmd.args(["admin", "key", "reload"])
                    .args(flags)
                    .env("ATTENUO_ADMIN_TOKEN", LEGACY)
                    .output()
                    .unwrap()
            })
            .await
            .unwrap()
        }
    };

    // Rotate to k2 with k1 kept as a retired key.
    std::fs::write(&path, file("k2.pem", &["k1.pem"])).unwrap();
    let out = run(false, &[]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "signing key: {kid1} -> {kid2}\n\
             verifying keys: 2 in force, 1 added, 0 removed\n  \
             added    {kid2}\n\
             audit checkpoints signed by: {kid2}\n"
        )
    );
    assert_eq!(text(&out.stderr), "");
    // No key material is printed.
    assert!(!text(&out.stdout).contains("PRIVATE"));

    // The same file again: nothing changes, and `--json` prints the answer.
    let out = run(true, &[]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["changed"], false, "{v}");
    assert_eq!(v["signing_kid"], kid2.as_str(), "{v}");
    assert_eq!(v["verifying_kids"], serde_json::json!([kid2, kid1]), "{v}");

    // k3 without k2 in previous_key_paths: refused, exit 1, the code on stderr.
    std::fs::write(&path, file("k3.pem", &["k1.pem"])).unwrap();
    let out = run(false, &[]).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    let err = text(&out.stderr);
    assert!(err.contains("keys_reload_drops_current"), "{err}");
    assert!(err.contains("--allow-drop-current"), "{err}");
    let out = run(true, &[]).await;
    assert_eq!(out.status.code(), Some(1));

    // Asked to: k2 is dropped. It signed audit checkpoints too (the reload records above), so
    // that needs its own flag.
    let out = run(false, &["--allow-drop-current"]).await;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("keys_reload_drops_audit_key"),
        "{}",
        text(&out.stderr)
    );
    let out = run(false, &["--allow-drop-current", "--allow-drop-audit-key"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with(&format!(
            "signing key: {kid2} -> {kid3}\n\
             verifying keys: 2 in force, 1 added, 1 removed\n  \
             added    {kid3}\n  \
             removed  {kid2}\n"
        )),
        "{stdout}"
    );
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "warning: tokens signed by kid `{kid2}` no longer verify"
        )),
        "{err}"
    );
}

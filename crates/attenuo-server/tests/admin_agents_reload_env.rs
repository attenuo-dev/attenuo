//! `POST /admin/agents/reload` on a server started the way `attenuo-server` starts, with
//! `ATTENUO__<SECTION>__<KEY>` overrides and `ATTENUO_ADMIN_TOKEN` set: the reload reads the
//! file with the same environment, so an unchanged file needs no restart and is not taken for
//! another server's file. In its own test binary, as it sets variables of the process.

mod common;

use attenuo_proxy::testing::spawn_router;
use attenuo_server::Config;
use reqwest::StatusCode;
use serde_json::{json, Value};

use common::sha256_hex;

const TOKEN: &str = "env-admin-token-0123456789abcdef0123";

#[tokio::test]
async fn an_unchanged_file_under_env_overrides_needs_no_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("attenuo.toml");
    let agent = |id: &str| {
        format!(
            "[[agents]]\nid = \"{id}\"\nsecret_sha256 = \"{}\"\n",
            sha256_hex(&format!("{id}-secret"))
        )
    };
    let text = |lists: &str| {
        format!(
            "[issuer]\nissuer = \"https://attenuo.test\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n{lists}",
            dir.path().join("issuer.pem").display(),
            dir.path().join("audit.sqlite").display(),
        )
    };
    std::fs::write(&path, text(&agent("planner"))).unwrap();
    // Only this test runs in this binary, so setting the process's variables is safe.
    std::env::set_var("ATTENUO_ADMIN_TOKEN", TOKEN);
    std::env::set_var("ATTENUO__ISSUER__DEFAULT_TTL_SECONDS", "600");
    std::env::set_var("ATTENUO__LIMITS__MAX_IN_FLIGHT", "77");

    // As `main.rs` loads it.
    let (mut cfg, overridden) = Config::load_with_env(&path, std::env::vars_os()).unwrap();
    cfg.apply_env();
    assert_eq!(overridden.len(), 2, "{overridden:?}");
    assert_eq!(cfg.issuer.default_ttl_seconds, 600);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let reload = || {
        reqwest::Client::new()
            .post(server.url("/admin/agents/reload"))
            .bearer_auth(TOKEN)
            .json(&json!({}))
            .send()
    };

    let resp = reload().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["restart_needed"], json!([]), "{v}");
    assert_eq!(v["agents"]["count"], 1, "{v}");

    // A list changed in the file, nothing else: still no restart, and the change applies.
    std::fs::write(&path, text(&(agent("planner") + &agent("tester")))).unwrap();
    let resp = reload().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["restart_needed"], json!([]), "{v}");
    assert_eq!(v["agents"]["added"], json!(["tester"]), "{v}");
}

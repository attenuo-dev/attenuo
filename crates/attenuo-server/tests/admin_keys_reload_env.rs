//! `POST /admin/keys/reload` on a server started with `ATTENUO__ISSUER__PRIVATE_KEY_PEM_PATH`
//! set: the variable wins over the file at a reload as at startup, so an edit of that line in
//! the file does nothing, and each answer says where the path came from. In its own test
//! binary, as it sets a variable of the process.

use attenuo_proxy::testing::spawn_router;
use attenuo_server::Config;
use attenuo_token::{Issuer, IssuerConfig};
use reqwest::StatusCode;
use serde_json::{json, Value};

const TOKEN: &str = "env-admin-token-0123456789abcdef0123";

fn new_key() -> Issuer {
    Issuer::generate(IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: time::Duration::minutes(5),
    })
}

#[tokio::test]
async fn an_env_key_path_wins_and_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let p = |n: &str| dir.path().join(n);
    let (from_env, from_file, edited) = (new_key(), new_key(), new_key());
    std::fs::write(p("env.pem"), from_env.private_key_pem()).unwrap();
    std::fs::write(p("file.pem"), from_file.private_key_pem()).unwrap();
    std::fs::write(p("edited.pem"), edited.private_key_pem()).unwrap();
    let path = p("attenuo.toml");
    let text = |signing: &str| {
        format!(
            "[issuer]\nissuer = \"https://attenuo.test\"\nprivate_key_pem_path = \"{}\"\n\n\
             [audit]\nsqlite_path = \"{}\"\n\n[admin]\ntoken = \"{TOKEN}\"\n",
            p(signing).display(),
            p("audit.sqlite").display(),
        )
    };
    std::fs::write(&path, text("file.pem")).unwrap();
    // Only this test runs in this binary, so setting the process's variables is safe.
    std::env::set_var("ATTENUO__ISSUER__PRIVATE_KEY_PEM_PATH", p("env.pem"));

    // As `main.rs` loads it.
    let (mut cfg, overridden) = Config::load_with_env(&path, std::env::vars_os()).unwrap();
    cfg.apply_env();
    assert_eq!(overridden.len(), 1, "{overridden:?}");
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    assert_eq!(state.keys().issuer.key_id(), from_env.key_id());
    let server = spawn_router(router).await.unwrap();
    let reload = || async {
        let resp = reqwest::Client::new()
            .post(server.url("/admin/keys/reload"))
            .bearer_auth(TOKEN)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json::<Value>().await.unwrap()
    };
    let note = "[issuer] private_key_pem_path comes from the environment \
                (ATTENUO__ISSUER__PRIVATE_KEY_PEM_PATH), not from the file: an edit of that \
                line in the file has no effect while the variable is set";

    let v = reload().await;
    assert_eq!(v["changed"], false, "{v}");
    assert_eq!(v["signing_kid"], from_env.key_id().as_str(), "{v}");
    assert_eq!(v["warnings"], json!([note]), "{v}");
    assert_eq!(v["restart_needed"], json!([]), "{v}");

    // The file's line is edited: the variable still decides.
    std::fs::write(&path, text("edited.pem")).unwrap();
    let v = reload().await;
    assert_eq!(v["changed"], false, "{v}");
    assert_eq!(v["signing_kid"], from_env.key_id().as_str(), "{v}");
    assert_eq!(v["warnings"], json!([note]), "{v}");
    assert_eq!(v["restart_needed"], json!([]), "{v}");
}

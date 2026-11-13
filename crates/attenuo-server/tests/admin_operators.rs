//! Per-operator admin credentials (ADR-0016) through the whole server: every admin route,
//! on the main listener and on the console listener, answers each role as
//! `attenuo_server::operators::ROUTE_ROLES` says; `GET /admin/whoami`; the actor recorded for
//! `[admin] token` (unchanged, `urn:attenuo:admin`) and for a named operator
//! (`urn:attenuo:admin:<name>`); and an audit chain written before operators were configured
//! still verifies, checkpoints included, after they are.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::path::Path;

use attenuo_proxy::testing::spawn_router;
use attenuo_server::config::AdminOperator;
use attenuo_server::operators::{token_sha256_hex, AdminRole, ROUTE_ROLES};
use attenuo_server::Config;
use reqwest::StatusCode;
use serde_json::{json, Value};

const LEGACY: &str = "legacy-admin-token-0123456789abcdef";
/// (name, token, role) of the named operators.
const OPERATORS: &[(&str, &str, AdminRole)] = &[
    ("vera", "vera-token", AdminRole::Viewer),
    ("bob", "bob-token", AdminRole::Operator),
    ("ada", "ada-token", AdminRole::Admin),
];

fn config(dir: &Path, operators: bool) -> Config {
    let mut cfg = Config::default();
    cfg.issuer.private_key_pem_path = Some(dir.join("keys/issuer.pem"));
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some(LEGACY.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = common::agent_configs(&["coder"], |id| format!("{id}-secret"));
    if operators {
        cfg.admin.operators = OPERATORS
            .iter()
            .map(|(name, token, role)| AdminOperator {
                name: (*name).into(),
                token_sha256: token_sha256_hex(token),
                role: *role,
                expires_at: None,
            })
            .collect();
    }
    cfg
}

/// A concrete path for a route template.
fn concrete(template: &str) -> String {
    template
        .replace("{lease_id}", "no-such-lease")
        .replace("{seq}", "1")
        .replace("{id}", "no-such-id")
}

async fn send(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let url = format!("{base}{path}");
    let mut req = match method {
        "GET" => client.get(&url),
        "POST" => client
            .post(&url)
            .header("content-type", "application/json")
            .body("{}"),
        other => panic!("no method {other} in the route table"),
    };
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Every route of the table, with each credential: refused with 403 `admin_role_insufficient`
/// exactly when the credential's role is below the route's, and 401 without a credential.
/// Runs against `base`, which mounts the routes `mounted` accepts.
async fn check_every_route(base: &str, mounted: impl Fn(&str, &str) -> bool) {
    let client = reqwest::Client::new();
    let mut creds: Vec<(&str, AdminRole)> = OPERATORS.iter().map(|(_, t, r)| (*t, *r)).collect();
    creds.push((LEGACY, AdminRole::Admin));
    let mut checked = 0;
    for (method, template, needed) in ROUTE_ROLES {
        if !mounted(method, template) {
            continue;
        }
        checked += 1;
        let path = concrete(template);
        let (status, _) = send(&client, base, method, &path, None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} without a bearer"
        );
        let (status, _) = send(&client, base, method, &path, Some("not-a-token")).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} with a wrong bearer"
        );
        for (token, role) in &creds {
            let (status, body) = send(&client, base, method, &path, Some(token)).await;
            let refused = body["code"] == "admin_role_insufficient";
            if role < needed {
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{method} {path} as {role}: {body}"
                );
                assert!(refused, "{method} {path} as {role}: {body}");
                let detail = body["detail"].as_str().unwrap();
                assert!(detail.contains(&format!("`{needed}`")), "{detail}");
                assert!(!body.to_string().contains(token), "{body}");
            } else {
                assert!(!refused, "{method} {path} as {role}: {body}");
                assert_ne!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} as {role}"
                );
            }
        }
    }
    assert!(checked > 10, "only {checked} routes checked");
}

#[tokio::test]
async fn every_route_answers_each_role_as_the_table_says_main_listener() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), true);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    check_every_route(&server.url(""), |_, _| true).await;
}

#[tokio::test]
async fn every_route_answers_each_role_as_the_table_says_console_listener() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), true);
    cfg.admin_ui.allow_write = true;
    let (_router, state) = attenuo_server::build(&cfg).unwrap();
    let console = spawn_router(attenuo_server::admin_ui::router(state, &cfg))
        .await
        .unwrap();
    // The console never mounts the root mint.
    check_every_route(&console.url(""), |_, p| p != "/admin/root-token").await;
}

#[tokio::test]
async fn whoami_names_the_credential() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), true);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let console = spawn_router(attenuo_server::admin_ui::router(state, &cfg))
        .await
        .unwrap();
    let client = reqwest::Client::new();
    for base in [server.url(""), console.url("")] {
        let (status, v) = send(&client, &base, "GET", "/admin/whoami", Some(LEGACY)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            v,
            json!({"name": "admin", "role": "admin", "expires_at": null})
        );
        for (name, token, role) in OPERATORS {
            let (status, v) = send(&client, &base, "GET", "/admin/whoami", Some(token)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                v,
                json!({"name": name, "role": role.as_str(), "expires_at": null})
            );
        }
    }
}

/// A root mint by the admin bearer, then the lease it registered.
async fn mint(client: &reqwest::Client, base: &str, bearer: &str, subject: &str) -> String {
    let resp = client
        .post(format!("{base}/admin/root-token"))
        .bearer_auth(bearer)
        .json(&json!({
            "subject": subject,
            "issuer": "https://idp.example",
            "agent": "coder",
            "capabilities": ["github:*"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    v["lease"].as_str().unwrap().to_string()
}

async fn revoke(client: &reqwest::Client, base: &str, bearer: &str, lease: &str) -> Value {
    let resp = client
        .post(format!("{base}/admin/leases/{lease}/revoke"))
        .bearer_auth(bearer)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.json().await.unwrap()
}

/// `(originating_subject, tool)` of every admin action in the audit log.
async fn actors(client: &reqwest::Client, base: &str, bearer: &str) -> Vec<(String, String)> {
    let (status, v) = send(
        client,
        base,
        "GET",
        "/admin/audit?from=1&limit=1000",
        Some(bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let r = &e["record"];
            (
                r["originating_subject"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                r["tool"].as_str().unwrap_or_default().to_string(),
            )
        })
        .filter(|(_, tool)| tool.starts_with("admin."))
        .collect()
}

async fn verify(client: &reqwest::Client, base: &str, bearer: &str) -> Value {
    let (status, v) = send(client, base, "GET", "/admin/audit/verify", Some(bearer)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["ok"], true, "{v}");
    assert!(
        v["bad_checkpoints"].as_array().is_none_or(Vec::is_empty),
        "{v}"
    );
    v
}

/// The legacy token keeps recording `urn:attenuo:admin`; a log written before
/// `[[admin.operators]]` existed (same record format, no schema change) still verifies with
/// its checkpoint once operators are configured, and the operators' own records extend it.
#[tokio::test]
async fn records_name_the_operator_and_an_older_chain_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let client = reqwest::Client::new();

    // Before: `[admin] token` only, as an existing deployment runs.
    let cfg = config(dir.path(), false);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = common::Running::start(cfg, state.clone(), router).await;
    let base = running.url("");
    let lease = mint(&client, &base, LEGACY, "alice").await;
    let v = revoke(&client, &base, LEGACY, &lease).await;
    assert_eq!(v["revoked"], 1, "{v}");
    // The default reason names the legacy operator as before.
    assert_eq!(v["reason"], "revoked by admin");
    let (status, checkpoint) = send(
        &client,
        &base,
        "GET",
        "/admin/audit/checkpoint",
        Some(LEGACY),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{checkpoint}");
    let before = actors(&client, &base, LEGACY).await;
    assert_eq!(
        before,
        [
            (
                "urn:attenuo:admin".to_string(),
                "admin.root_token".to_string()
            ),
            (
                "urn:attenuo:admin".to_string(),
                "admin.lease.revoke".to_string()
            ),
        ]
    );
    running.stop(state).await;

    // After: the same database, with named operators added.
    let cfg = config(dir.path(), true);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = common::Running::start(cfg, state.clone(), router).await;
    let base = running.url("");
    let v = verify(&client, &base, "vera-token").await;
    // The checkpoint signed before operators existed verifies.
    assert!(v["checkpoints"].as_u64().unwrap() >= 1, "{v}");
    assert_eq!(v["last_signed_seq"], checkpoint["seq"], "{v}");
    let lease = mint(&client, &base, "ada-token", "carol").await;
    revoke(&client, &base, "bob-token", &lease).await;
    let lease = mint(&client, &base, LEGACY, "dave").await;
    revoke(&client, &base, LEGACY, &lease).await;
    let after = actors(&client, &base, "vera-token").await;
    assert_eq!(&after[..2], &before[..]);
    assert_eq!(
        &after[2..],
        [
            (
                "urn:attenuo:admin:ada".to_string(),
                "admin.root_token".to_string()
            ),
            (
                "urn:attenuo:admin:bob".to_string(),
                "admin.lease.revoke".to_string()
            ),
            (
                "urn:attenuo:admin".to_string(),
                "admin.root_token".to_string()
            ),
            (
                "urn:attenuo:admin".to_string(),
                "admin.lease.revoke".to_string()
            ),
        ]
    );
    let (status, _) = send(
        &client,
        &base,
        "GET",
        "/admin/audit/checkpoint",
        Some("vera-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v = verify(&client, &base, "bob-token").await;
    assert_eq!(v["first_bad_seq"], Value::Null, "{v}");
    assert!(v["checkpoints"].as_u64().unwrap() >= 2, "{v}");
    assert_eq!(v["last_signed_seq"], v["entries"], "{v}");
    running.stop(state).await;
}

/// Startup refuses an operator whose digest is that of `[admin] token`, and a duplicate name.
#[test]
fn startup_refuses_a_bad_operator_table() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), true);
    cfg.admin.operators[0].token_sha256 = token_sha256_hex(LEGACY);
    let err = attenuo_server::build(&cfg).err().unwrap().to_string();
    assert!(err.contains("[admin] token"), "{err}");
    assert!(!err.contains(LEGACY), "{err}");
    let mut cfg = config(dir.path(), true);
    cfg.admin.operators[1].name = "vera".into();
    let err = attenuo_server::build(&cfg).err().unwrap().to_string();
    assert!(err.contains("used twice"), "{err}");
}

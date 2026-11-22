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
    // The console never mounts the root mint, and does not mount the audit retention routes.
    let on_console = |p: &str| {
        p != "/admin/root-token"
            && !p.starts_with("/admin/audit/prune")
            && p != "/admin/audit/anchors"
    };
    check_every_route(&console.url(""), |_, p| on_console(p)).await;
    // The routes left out are not there at all, for any credential.
    let client = reqwest::Client::new();
    for (method, path) in [
        ("GET", "/admin/audit/prune/plan"),
        ("POST", "/admin/audit/prune"),
        ("GET", "/admin/audit/anchors"),
    ] {
        for token in [None, Some(LEGACY), Some("vera-token")] {
            let (status, body) = send(&client, &console.url(""), method, path, token).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} {path} on the console with {token:?}: {body}"
            );
        }
    }
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

// --- Expiry and reload (ADR-0016, update of 2026-11-13) ---

/// One `[[admin.operators]]` entry as TOML.
fn entry(name: &str, token: &str, role: &str, expires_at: Option<&str>) -> String {
    let mut s = format!(
        "[[admin.operators]]\nname = \"{name}\"\ntoken_sha256 = \"{}\"\nrole = \"{role}\"\n",
        token_sha256_hex(token)
    );
    if let Some(at) = expires_at {
        s.push_str(&format!("expires_at = \"{at}\"\n"));
    }
    s
}

/// Write `<dir>/attenuo.toml` with `[admin] token` (when `legacy` is set) and `operators`
/// (TOML entries), and return its path. The file is replaced in one rename, so a reload never
/// reads half of it.
fn write_config(dir: &Path, legacy: Option<&str>, operators: &str) -> std::path::PathBuf {
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    let token = legacy.map_or(String::new(), |t| format!("token = \"{t}\"\n"));
    std::fs::write(
        &tmp,
        format!(
            "[issuer]\nprivate_key_pem_path = \"{}\"\n\n[audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\n{token}\n{operators}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
        ),
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

/// A server started from the config file at `path`, as `attenuo-server --config` starts one.
async fn start_from_file(
    path: &Path,
) -> (
    attenuo_proxy::testing::Spawned,
    std::sync::Arc<attenuo_server::AppState>,
) {
    let cfg = Config::load(path).unwrap();
    assert_eq!(cfg.source_path.as_deref(), Some(path));
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    (spawn_router(router).await.unwrap(), state)
}

async fn reload(client: &reqwest::Client, base: &str, bearer: &str) -> (StatusCode, Value) {
    send(
        client,
        base,
        "POST",
        "/admin/operators/reload",
        Some(bearer),
    )
    .await
}

async fn whoami(client: &reqwest::Client, base: &str, bearer: &str) -> (StatusCode, Value) {
    send(client, base, "GET", "/admin/whoami", Some(bearer)).await
}

/// A token that has expired is 401 `admin_credential_expired`, with the same challenge as
/// any admin 401; before its `expires_at` it works and `whoami` shows the expiry. The server's
/// clock is stepped, nothing sleeps.
#[tokio::test]
async fn an_operator_token_stops_working_at_its_expiry() {
    use time::format_description::well_known::Rfc3339;
    let dir = tempfile::tempdir().unwrap();
    let clock = attenuo_core::ManualClock::new();
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::hours(1))
        .replace_nanosecond(0)
        .unwrap();
    let mut cfg = config(dir.path(), true);
    cfg.admin.operators.push(AdminOperator {
        name: "temp".into(),
        token_sha256: token_sha256_hex("temp-token"),
        role: AdminRole::Operator,
        expires_at: Some(expires),
    });
    let (router, _state) = attenuo_server::build_with_clock(&cfg, clock.clone()).unwrap();
    let server = spawn_router(router).await.unwrap();
    let base = server.url("");
    let client = reqwest::Client::new();

    let (status, v) = whoami(&client, &base, "temp-token").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({"name": "temp", "role": "operator", "expires_at": expires.format(&Rfc3339).unwrap()})
    );

    clock.advance(std::time::Duration::from_secs(2 * 3600));
    let resp = client
        .get(format!("{base}/admin/whoami"))
        .bearer_auth("temp-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()["www-authenticate"],
        "Bearer realm=\"attenuo-admin\""
    );
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["code"], "admin_credential_expired", "{v}");
    assert_eq!(v["error"], "unauthorized", "{v}");
    assert!(!v.to_string().contains("temp-token"), "{v}");
    // The other credentials, which do not expire, still work.
    for token in [LEGACY, "vera-token", "bob-token", "ada-token"] {
        assert_eq!(whoami(&client, &base, token).await.0, StatusCode::OK);
    }
    // A wrong token is still `invalid_token`, not the expired code.
    let (status, v) = whoami(&client, &base, "temp-token-x").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(v["code"], "invalid_token");
}

// The warning for an entry that has already expired at startup is checked in
// `admin_operator_expired_at_startup.rs`, a test binary of its own: see there for why.

/// An `expires_at` that is not an RFC 3339 time with an offset refuses the file, naming the
/// key; so does it at a reload (below).
#[test]
fn a_malformed_expiry_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["2026-13-01T00:00:00Z", "2026-12-01T00:00:00", "next week"] {
        let path = write_config(
            dir.path(),
            Some(LEGACY),
            &entry("alice", "alice-token", "viewer", Some(bad)),
        );
        let err = format!("{:#}", Config::load(&path).unwrap_err());
        assert!(err.contains("expires_at"), "{bad}: {err}");
        assert!(!err.contains(LEGACY), "{err}");
    }
}

/// Add, remove, change role, change digest and change expiry in one reload: the answer
/// names each by name, never a digest, and the next requests see the new set. `[admin] token`
/// is not reloaded, even when the file's value changed.
#[tokio::test]
async fn a_reload_adds_removes_and_changes_operators() {
    let dir = tempfile::tempdir().unwrap();
    let before = entry("ada", "ada-token", "admin", None)
        + &entry("bob", "bob-token", "operator", None)
        + &entry("carol", "carol-token", "viewer", None)
        + &entry("dave", "dave-token", "viewer", None)
        + &entry("erin", "erin-token", "viewer", Some("2099-01-01T00:00:00Z"))
        + &entry("vera", "vera-token", "viewer", None);
    let path = write_config(dir.path(), Some(LEGACY), &before);
    let (server, _state) = start_from_file(&path).await;
    let base = server.url("");
    let client = reqwest::Client::new();
    assert_eq!(
        whoami(&client, &base, "bob-token").await.1["role"],
        "operator"
    );

    // Unchanged: ada, vera. bob demoted, carol's digest changed, dave given an expiry that
    // has passed, erin's expiry removed, frank added, and `[admin] token` edited in the file.
    let after = entry("ada", "ada-token", "admin", None)
        + &entry("bob", "bob-token", "viewer", None)
        + &entry("carol", "carol-token-2", "viewer", None)
        + &entry("dave", "dave-token", "viewer", Some("2020-01-01T00:00:00Z"))
        + &entry("erin", "erin-token", "viewer", None)
        + &entry("frank", "frank-token", "operator", None);
    write_config(
        dir.path(),
        Some("an-edited-legacy-token-0123456789abcdef"),
        &after,
    );
    let (status, v) = reload(&client, &base, "ada-token").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["added"], json!(["frank"]));
    assert_eq!(v["removed"], json!(["vera"]));
    assert_eq!(v["changed"], json!(["bob", "carol", "dave", "erin"]));
    assert!(v["audit_id"].is_string(), "{v}");
    for t in ["ada-token", "bob-token", "carol-token", "frank-token"] {
        assert!(!v.to_string().contains(&token_sha256_hex(t)), "{v}");
    }

    let (status, v) = whoami(&client, &base, "vera-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "removed: {v}");
    assert_eq!(v["code"], "invalid_token");
    assert_eq!(
        whoami(&client, &base, "bob-token").await.1["role"],
        "viewer"
    );
    let (status, v) = send(
        &client,
        &base,
        "POST",
        "/admin/leases/x/revoke",
        Some("bob-token"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(v["code"], "admin_role_insufficient");
    assert_eq!(
        whoami(&client, &base, "carol-token").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        whoami(&client, &base, "carol-token-2").await.1["name"],
        "carol"
    );
    let (status, v) = whoami(&client, &base, "dave-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(v["code"], "admin_credential_expired");
    assert_eq!(
        whoami(&client, &base, "erin-token").await.1["expires_at"],
        Value::Null
    );
    assert_eq!(
        whoami(&client, &base, "frank-token").await.1["role"],
        "operator"
    );
    // `[admin] token` is the one the server started with.
    assert_eq!(whoami(&client, &base, LEGACY).await.1["name"], "admin");
    assert_eq!(
        whoami(&client, &base, "an-edited-legacy-token-0123456789abcdef")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // A second reload of the same file changes nothing.
    let (status, v) = reload(&client, &base, LEGACY).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["added"], &v["removed"], &v["changed"]),
        (&json!([]), &json!([]), &json!([]))
    );
}

/// The reload is recorded like any admin action: the actor, and the name lists in the
/// arguments (whose digest the record keeps). A refused reload is recorded as a `deny`.
#[tokio::test]
async fn a_reload_is_audited_with_the_actor_and_the_lists() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        Some(LEGACY),
        &(entry("ada", "ada-token", "admin", None) + &entry("vera", "vera-token", "viewer", None)),
    );
    let (server, _state) = start_from_file(&path).await;
    let base = server.url("");
    let client = reqwest::Client::new();
    write_config(
        dir.path(),
        Some(LEGACY),
        &(entry("ada", "ada-token", "operator", None) + &entry("bob", "bob-token", "viewer", None)),
    );
    // ada demotes herself: the request that does it completes.
    let (status, v) = reload(&client, &base, "ada-token").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let audit_id = v["audit_id"].as_str().unwrap().to_string();
    // ...and her next reload is refused for the role.
    let (status, v) = reload(&client, &base, "ada-token").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(v["code"], "admin_role_insufficient");

    write_config(dir.path(), Some(LEGACY), "this is not toml");
    let (status, v) = reload(&client, &base, LEGACY).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "operators_invalid");

    let (status, v) = send(
        &client,
        &base,
        "GET",
        "/admin/audit?from=1&limit=1000",
        Some(LEGACY),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let records: Vec<&Value> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["record"])
        .filter(|r| r["tool"] == "admin.operators.reload")
        .collect();
    assert_eq!(records.len(), 2, "{records:?}");
    let ok = records[0];
    assert_eq!(ok["id"], audit_id);
    assert_eq!(ok["originating_subject"], "urn:attenuo:admin:ada");
    assert_eq!(ok["decision"], "allow");
    assert_eq!(ok["server"], "attenuo");
    let args = json!({
        "path": path,
        "added": ["bob"],
        "removed": ["vera"],
        "changed": ["ada"],
    });
    let want = attenuo_core::ToolCall::new("attenuo", "admin.operators.reload", args);
    assert_eq!(ok["arguments_digest"], want.arguments_digest());
    let refused = records[1];
    assert_eq!(refused["originating_subject"], "urn:attenuo:admin");
    assert_eq!(refused["decision"], "deny");
    assert_eq!(refused["reason"], "operators_invalid");
}

/// A file that does not parse or breaks a startup rule leaves the set in force as it was.
#[tokio::test]
async fn an_invalid_file_leaves_the_operators_in_force() {
    let dir = tempfile::tempdir().unwrap();
    let ops =
        entry("ada", "ada-token", "admin", None) + &entry("bob", "bob-token", "operator", None);
    let path = write_config(dir.path(), Some(LEGACY), &ops);
    let (server, _state) = start_from_file(&path).await;
    let base = server.url("");
    let client = reqwest::Client::new();
    let good_rest = entry("ada", "ada-token", "admin", None);
    for (operators, want) in [
        ("[[admin.operators]\n".to_string(), "not valid TOML"),
        (
            good_rest.clone() + &entry("ada", "x-token", "viewer", None),
            "used twice",
        ),
        (
            good_rest.clone() + &entry("eve", LEGACY, "viewer", None),
            "[admin] token",
        ),
        (
            good_rest.clone() + &entry("eve", "eve-token", "viewer", Some("soon")),
            "expires_at",
        ),
        (
            good_rest.clone() + "[[admin.operators]]\nname = \"eve\"\ntoken_sha256 = \"abc\"\nrole = \"viewer\"\n",
            "64 lowercase hex",
        ),
        (
            good_rest.clone() + &entry("Eve", "eve-token", "viewer", None),
            "a-z",
        ),
        (
            good_rest.clone() + &entry("eve", "eve-token", "root", None),
            "root",
        ),
    ] {
        write_config(dir.path(), Some(LEGACY), &operators);
        let (status, v) = reload(&client, &base, "ada-token").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{operators}: {v}");
        assert_eq!(v["code"], "operators_invalid", "{v}");
        let detail = v["detail"].as_str().unwrap();
        assert!(detail.contains(want), "{want}: {detail}");
        assert!(!detail.contains(LEGACY), "{detail}");
        assert_eq!(whoami(&client, &base, "bob-token").await.1["role"], "operator");
    }
    // A file that is gone: 500 with its own code, the path in the log only.
    std::fs::remove_file(&path).unwrap();
    let (status, v) = reload(&client, &base, "ada-token").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{v}");
    assert_eq!(v["code"], "config_unreadable");
    assert!(!v.to_string().contains("attenuo.toml"), "{v}");
    assert_eq!(whoami(&client, &base, "bob-token").await.0, StatusCode::OK);
}

/// Without `[admin] token`, a reload that would leave no unexpired admin operator is refused,
/// so that a typo cannot lock everyone out until a restart.
#[tokio::test]
async fn a_reload_that_would_lock_out_every_admin_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ops =
        entry("ada", "ada-token", "admin", None) + &entry("bob", "bob-token", "operator", None);
    let path = write_config(dir.path(), None, &ops);
    let (server, _state) = start_from_file(&path).await;
    let base = server.url("");
    let client = reqwest::Client::new();
    for operators in [
        // ada removed.
        entry("bob", "bob-token", "operator", None),
        // ada demoted.
        entry("ada", "ada-token", "operator", None),
        // ada expired.
        entry("ada", "ada-token", "admin", Some("2020-01-01T00:00:00Z")),
        // Nobody.
        String::new(),
    ] {
        write_config(dir.path(), None, &operators);
        let (status, v) = reload(&client, &base, "ada-token").await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{operators}: {v}");
        assert_eq!(v["code"], "operators_no_admin", "{v}");
        assert_eq!(whoami(&client, &base, "ada-token").await.1["role"], "admin");
    }
    // Handing admin to another operator is fine.
    write_config(
        dir.path(),
        None,
        &(entry("bob", "bob-token", "admin", None) + &entry("ada", "ada-token", "viewer", None)),
    );
    let (status, v) = reload(&client, &base, "ada-token").await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["changed"], json!(["ada", "bob"]));
}

/// A viewer and an operator are refused the reload for their role; a server whose config was
/// not read from a file has nothing to reload.
#[tokio::test]
async fn a_reload_needs_the_admin_role_and_a_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        Some(LEGACY),
        &(entry("vera", "vera-token", "viewer", None)
            + &entry("bob", "bob-token", "operator", None)),
    );
    let (server, _state) = start_from_file(&path).await;
    let client = reqwest::Client::new();
    for token in ["vera-token", "bob-token"] {
        let (status, v) = reload(&client, &server.url(""), token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "admin_role_insufficient");
        assert!(v["detail"].as_str().unwrap().contains("`admin`"), "{v}");
    }

    // Built in code (as `serve(config)` from an embedding program): no file.
    let other = tempfile::tempdir().unwrap();
    let cfg = config(other.path(), true);
    assert_eq!(cfg.source_path, None);
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    let (status, v) = reload(&client, &server.url(""), LEGACY).await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "reload_unavailable");
}

/// Requests keep being answered while reloads swap the set: nothing panics or deadlocks, a
/// credential present in every version always works, and one that comes and goes is either
/// admitted or refused, never anything else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_during_reloads_neither_panic_nor_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let with_bob =
        entry("ada", "ada-token", "admin", None) + &entry("bob", "bob-token", "viewer", None);
    let without_bob = entry("ada", "ada-token", "admin", None);
    let path = write_config(dir.path(), Some(LEGACY), &with_bob);
    let (server, _state) = start_from_file(&path).await;
    let base = server.url("");
    let client = reqwest::Client::new();

    let work = async {
        let mut readers = Vec::new();
        for _ in 0..8 {
            let (client, base) = (client.clone(), base.clone());
            readers.push(tokio::spawn(async move {
                for _ in 0..40 {
                    let (status, _) = whoami(&client, &base, "ada-token").await;
                    assert_eq!(status, StatusCode::OK);
                    let (status, v) = whoami(&client, &base, "bob-token").await;
                    assert!(
                        status == StatusCode::OK || status == StatusCode::UNAUTHORIZED,
                        "{status}: {v}"
                    );
                }
            }));
        }
        let reloader = {
            let (client, base, dir) = (client.clone(), base.clone(), dir.path().to_path_buf());
            tokio::spawn(async move {
                for i in 0..30 {
                    let ops = if i % 2 == 0 { &without_bob } else { &with_bob };
                    write_config(&dir, Some(LEGACY), ops);
                    let (status, v) = reload(&client, &base, "ada-token").await;
                    assert_eq!(status, StatusCode::OK, "{v}");
                }
            })
        };
        // Two reloads at once are serialized, not refused.
        let (a, b) = tokio::join!(
            reload(&client, &base, LEGACY),
            reload(&client, &base, LEGACY)
        );
        assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
        for r in readers {
            r.await.unwrap();
        }
        reloader.await.unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(120), work)
        .await
        .expect("requests during reloads did not finish: deadlock?");
    assert_eq!(whoami(&client, &base, "ada-token").await.0, StatusCode::OK);
}

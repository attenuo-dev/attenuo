//! The admin listener (`[admin] listen`, audit finding S-1): with it, `/admin/*` is served on
//! that address only, behind the same admin bearer, and the main listener answers those paths
//! exactly as it answers a path it does not know. Without it, a loopback server keeps the admin
//! API on the main listener, and a server off loopback refuses to start unless
//! `[admin] serve_on_main_listener = true`.

mod common;

use attenuo_proxy::testing::spawn_router;
use attenuo_server::Config;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

const ADMIN: &str = "admin-listener-test-token-0123456789abcdef";

/// A free loopback address, for a listener `run` binds itself.
fn free_port() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(dir: &std::path::Path) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some(ADMIN.into());
    // On, so that the dev mint is among the paths that must vanish from the main listener.
    cfg.dev.allow_root_mint = true;
    cfg
}

/// Every admin route, with a method it is mounted for, plus a wrong method on one of them (a
/// mounted path answers 405 to that, an unknown one 404, so it must be gone too).
const ADMIN_REQUESTS: &[(&str, &str)] = &[
    ("POST", "/admin/root-token"),
    ("POST", "/admin/leases/revoke"),
    ("POST", "/admin/leases/revoke?preview=true"),
    ("GET", "/admin/leases/l-1"),
    ("POST", "/admin/leases/l-1/revoke"),
    ("GET", "/admin/leases/l-1/tree"),
    ("POST", "/admin/budgets/refund"),
    ("GET", "/admin/audit"),
    ("GET", "/admin/audit/verify"),
    ("GET", "/admin/audit/entries/1"),
    ("GET", "/admin/audit/records/r-1"),
    ("GET", "/admin/audit/checkpoints"),
    ("GET", "/admin/audit/checkpoint"),
    ("GET", "/admin/audit/export?from=1"),
    ("GET", "/admin/policies"),
    ("GET", "/admin/policies/check"),
    ("POST", "/admin/policies/evaluate"),
    ("POST", "/admin/policies/reload"),
    ("POST", "/admin/operators/reload"),
    ("POST", "/admin/agents/reload"),
    ("GET", "/admin/approvals"),
    ("GET", "/admin/approvals/a-1"),
    ("POST", "/admin/approvals/a-1"),
    ("DELETE", "/admin/audit"),
    ("GET", "/admin/"),
    ("GET", "/admin"),
];

/// A response, minus `Date`, which only says when it was sent.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

async fn answer(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
) -> Answer {
    let mut req = client
        .request(
            Method::from_bytes(method.as_bytes()).unwrap(),
            format!("{base}{path}"),
        )
        .header("content-type", "application/json")
        .body(
            json!({"subject": "alice", "issuer": "https://idp.example", "agent": "planner",
                   "capabilities": ["github:*"]})
            .to_string(),
        );
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let mut headers: Vec<(String, Vec<u8>)> = resp
        .headers()
        .iter()
        .filter(|(name, _)| *name != reqwest::header::DATE)
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = resp.bytes().await.unwrap().to_vec();
    Answer {
        status,
        headers,
        body,
    }
}

/// With `[admin] listen` set, every admin path on the main listener gets the very answer an
/// unknown path gets (same status, headers and body; only the path differs), with or without
/// the admin bearer: nothing tells a caller of the agent port that an admin API exists.
#[tokio::test]
async fn admin_paths_on_the_main_listener_answer_as_unknown_paths_do() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.admin.listen = Some(free_port());
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let main = spawn_router(router).await.unwrap();
    let base = main.url("");
    let client = reqwest::Client::new();
    for &(method, path) in ADMIN_REQUESTS {
        // An unknown path of the same shape, outside /admin.
        let unknown = format!("/no-such-route{}", path.trim_start_matches("/admin"));
        for bearer in [None, Some(ADMIN), Some("wrong")] {
            let got = answer(&client, &base, method, path, bearer).await;
            let want = answer(&client, &base, method, &unknown, bearer).await;
            assert_eq!(
                got, want,
                "{method} {path} (bearer {bearer:?}) vs {unknown}"
            );
            assert_eq!(got.status, StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
    // The agent-facing and health routes are still there.
    let r = client.get(main.url("/healthz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = client.get(main.url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = client
        .get(main.url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

/// Without `[admin] listen`, on loopback, the admin API is on the main listener as before:
/// the admin paths are mounted (401 without the bearer, 405 for a wrong method), unlike the
/// unknown paths, and work with the bearer.
#[tokio::test]
async fn on_loopback_the_admin_api_stays_on_the_main_listener_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    assert_eq!(cfg.admin.listen, None);
    assert!(cfg.server.listen.ip().is_loopback());
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let main = spawn_router(router).await.unwrap();
    let base = main.url("");
    let client = reqwest::Client::new();
    let got = answer(&client, &base, "GET", "/admin/audit/verify", None).await;
    assert_eq!(got.status, StatusCode::UNAUTHORIZED);
    let got = answer(&client, &base, "DELETE", "/admin/audit", Some(ADMIN)).await;
    assert_eq!(got.status, StatusCode::METHOD_NOT_ALLOWED);
    let got = answer(&client, &base, "GET", "/admin/audit/verify", Some(ADMIN)).await;
    assert_eq!(got.status, StatusCode::OK);
    let got = answer(&client, &base, "POST", "/admin/root-token", Some(ADMIN)).await;
    assert_eq!(
        got.status,
        StatusCode::OK,
        "{:?}",
        String::from_utf8_lossy(&got.body)
    );
}

/// The admin listener serves the admin routes behind the admin bearer, the dev mint included
/// when it is on, and nothing else: no health, readiness or discovery routes.
#[tokio::test]
async fn the_admin_listener_serves_the_admin_api_behind_the_admin_bearer() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.admin.listen = Some(free_port());
    let (_router, state) = attenuo_server::build(&cfg).unwrap();
    let admin = spawn_router(attenuo_server::admin_router(state))
        .await
        .unwrap();
    let base = admin.url("");
    let client = reqwest::Client::new();
    let got = answer(&client, &base, "GET", "/admin/audit/verify", None).await;
    assert_eq!(got.status, StatusCode::UNAUTHORIZED);
    let www = got
        .headers
        .iter()
        .find(|(n, _)| n == "www-authenticate")
        .map(|(_, v)| v.clone());
    assert_eq!(www.as_deref(), Some(&b"Bearer realm=\"attenuo-admin\""[..]));
    let got = answer(&client, &base, "GET", "/admin/audit/verify", Some("wrong")).await;
    assert_eq!(got.status, StatusCode::UNAUTHORIZED);
    let got = answer(&client, &base, "GET", "/admin/audit/verify", Some(ADMIN)).await;
    assert_eq!(got.status, StatusCode::OK);
    // The admin answers carry the same headers as on the main listener.
    assert!(
        got.headers
            .iter()
            .any(|(n, v)| n == "cache-control" && v == b"no-store"),
        "{:?}",
        got.headers
    );
    let got = answer(&client, &base, "POST", "/admin/root-token", Some(ADMIN)).await;
    assert_eq!(got.status, StatusCode::OK);
    let token: Value = serde_json::from_slice(&got.body).unwrap();
    assert!(token["access_token"].is_string(), "{token}");
    for path in ["/healthz", "/readyz", "/.well-known/jwks.json", "/token"] {
        let got = answer(&client, &base, "GET", path, None).await;
        assert_eq!(got.status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// Through `run`, as `serve` runs it: the admin listener is bound next to the main one and
/// the console, the admin API answers there and not on the main listener, and the console
/// keeps working (it serves the admin API on its own listener, same-origin with the page).
/// Then the stop drains all three and the database is released.
#[tokio::test]
async fn run_serves_the_admin_listener_next_to_the_main_one_and_the_console() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    let admin_addr = free_port();
    let console_addr = free_port();
    cfg.admin.listen = Some(admin_addr);
    cfg.admin_ui.enabled = true;
    cfg.admin_ui.listen = console_addr;
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = common::Running::start(cfg, state.clone(), router).await;
    let client = reqwest::Client::new();
    let verify = |addr: std::net::SocketAddr| format!("http://{addr}/admin/audit/verify");
    // The other listeners are bound inside `run`: wait until the admin one answers.
    let mut tries = 0;
    let resp = loop {
        match client
            .get(verify(admin_addr))
            .bearer_auth(ADMIN)
            .send()
            .await
        {
            Ok(r) => break r,
            Err(e) => {
                tries += 1;
                assert!(tries < 400, "the admin listener never answered: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    };
    assert_eq!(resp.status(), StatusCode::OK);
    let r = client.get(verify(admin_addr)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = client
        .get(running.url("/admin/audit/verify"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = client.get(running.url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // The console: its page and the admin API it calls, both on its own listener.
    let r = client
        .get(format!("http://{console_addr}/admin/ui/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = client
        .get(verify(console_addr))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    running.stop(state).await;
}

/// Off loopback, with no admin listener, the server refuses to start unless the opt-in says to
/// serve the admin API on the main listener; an admin listener of its own needs neither.
#[test]
fn off_loopback_the_admin_api_needs_its_own_listener_or_the_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    // Neither of these is what this test is about.
    cfg.dev.allow_root_mint = false;
    cfg.server.public_url = Some("https://attenuo.example.com".into());
    cfg.server.listen = "0.0.0.0:8080".parse().unwrap();
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    let msg = err.to_string();
    assert!(msg.contains("not a loopback address"), "{msg}");
    assert!(msg.contains("[admin] listen"), "{msg}");
    assert!(msg.contains("serve_on_main_listener = true"), "{msg}");
    cfg.admin.serve_on_main_listener = true;
    let _ = attenuo_server::build(&cfg).unwrap();
    cfg.admin.serve_on_main_listener = false;
    cfg.admin.listen = Some("127.0.0.1:9102".parse().unwrap());
    let _ = attenuo_server::build(&cfg).unwrap();
    // Both at once is a contradiction.
    cfg.admin.serve_on_main_listener = true;
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("contradict"), "{err}");
}

/// Off loopback with the opt-in, the admin API is on the main listener, as before S-1.
#[tokio::test]
async fn the_opt_in_keeps_the_admin_api_on_the_main_listener() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path());
    cfg.dev.allow_root_mint = false;
    cfg.server.public_url = Some("https://attenuo.example.com".into());
    cfg.server.listen = "0.0.0.0:8080".parse().unwrap();
    cfg.admin.serve_on_main_listener = true;
    let (router, _state) = attenuo_server::build(&cfg).unwrap();
    let main = spawn_router(router).await.unwrap();
    let client = reqwest::Client::new();
    let got = answer(
        &client,
        &main.url(""),
        "GET",
        "/admin/audit/verify",
        Some(ADMIN),
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
}

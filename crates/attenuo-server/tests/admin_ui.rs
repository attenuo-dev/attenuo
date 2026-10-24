//! The admin console listener (`[admin_ui]`): assets, headers, which admin routes it mounts,
//! and that `serve` starts it.

use std::sync::Arc;

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::admin_ui::{ASSETS, CSP, SECURITY_HEADERS};
use attenuo_server::{AppState, Config};
use reqwest::header::HeaderMap;
use reqwest::{redirect, StatusCode};
use serde_json::{json, Value};
use sha2::Digest;

const ADMIN: &str = "admin";

struct Harness {
    /// The main listener (for minting a root token to revoke).
    main: Spawned,
    /// The console listener.
    console: Spawned,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(allow_write: bool) -> Self {
        Self::start_with(allow_write, Some(ADMIN)).await
    }

    async fn start_with(allow_write: bool, admin_token: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.admin.token = admin_token.map(Into::into);
        // On, to show the console never mounts the dev mint even so.
        cfg.dev.allow_root_mint = true;
        cfg.admin_ui.enabled = true;
        cfg.admin_ui.allow_write = allow_write;
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let main = spawn_router(router).await.unwrap();
        let console = spawn_router(attenuo_server::admin_ui::router(state.clone(), &cfg))
            .await
            .unwrap();
        Self {
            main,
            console,
            state,
            _dir: dir,
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .unwrap()
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        Self::client()
            .get(self.console.url(path))
            .send()
            .await
            .unwrap()
    }

    async fn mint_root(&self) -> String {
        self.mint_root_full().await["lease"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// The whole answer of the dev mint: `access_token`, `lease`, ...
    async fn mint_root_full(&self) -> Value {
        Self::client()
            .post(self.main.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                          "agent": "planner", "capabilities": ["github:*"]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn admin_get(&self, path: &str) -> reqwest::Response {
        Self::client()
            .get(self.console.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
    }

    async fn head(&self) -> u64 {
        let r: Value = Self::client()
            .get(self.console.url("/admin/audit?order=desc&limit=1"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        r["head"].as_u64().unwrap()
    }
}

fn assert_security_headers(h: &HeaderMap) {
    for (name, value) in SECURITY_HEADERS {
        assert_eq!(
            h.get(*name).and_then(|v| v.to_str().ok()),
            Some(*value),
            "{name}"
        );
    }
    assert_eq!(h["content-security-policy"], CSP);
    assert_no_cors(h);
}

fn assert_no_cors(h: &HeaderMap) {
    let cors: Vec<_> = h
        .keys()
        .filter(|k| k.as_str().starts_with("access-control-"))
        .collect();
    assert!(cors.is_empty(), "{cors:?}");
}

fn assert_no_store(h: &HeaderMap) {
    assert_eq!(h["cache-control"], "no-store");
}

#[tokio::test]
async fn index_is_html_with_the_exact_security_headers() {
    let h = Harness::start(false).await;
    let r = h.get("/admin/ui/").await;
    assert_eq!(r.status(), StatusCode::OK);
    let headers = r.headers().clone();
    assert_eq!(headers["content-type"], "text/html; charset=utf-8");
    assert_eq!(
        headers["content-security-policy"],
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
         connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; \
         require-trusted-types-for 'script'"
    );
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
    assert_eq!(headers["cross-origin-resource-policy"], "same-origin");
    assert_eq!(headers["cache-control"], "no-cache");
    assert!(headers.contains_key("etag"));
    assert_security_headers(&headers);
    let body = r.text().await.unwrap();
    assert!(body.contains("<!doctype html>"), "{body}");
    // The same file under its own name.
    let r = h.get("/admin/ui/index.html").await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.text().await.unwrap(), body);
}

#[tokio::test]
async fn assets_have_their_content_type_and_unknown_ones_404() {
    let h = Harness::start(false).await;
    for (path, ct) in [
        ("app.js", "text/javascript; charset=utf-8"),
        ("app.css", "text/css; charset=utf-8"),
        ("index.html", "text/html; charset=utf-8"),
    ]
    .into_iter()
    .chain(ASSETS.iter().map(|a| (a.path, a.content_type)))
    {
        let path = &format!("/admin/ui/{path}");
        let r = h.get(path).await;
        assert_eq!(r.status(), StatusCode::OK, "{path}");
        assert_eq!(r.headers()["content-type"], ct, "{path}");
        assert_eq!(r.headers()["cache-control"], "no-cache", "{path}");
        assert_security_headers(r.headers());
    }
    for path in [
        "/admin/ui/missing.js",
        "/admin/ui/../Cargo.toml",
        "/admin/ui/%2e%2e%2fCargo.toml",
        "/admin/ui/sub/app.js",
        "/admin/ui/APP.JS",
        "/nope",
    ] {
        let r = h.get(path).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
    }
}

#[tokio::test]
async fn etag_and_if_none_match_give_304() {
    let h = Harness::start(false).await;
    let r = h.get("/admin/ui/app.js").await;
    let etag = r.headers()["etag"].to_str().unwrap().to_string();
    // The SHA-256 of the embedded file.
    let app_js = ASSETS.iter().find(|a| a.path == "app.js").unwrap();
    assert_eq!(
        etag,
        format!("\"{}\"", hex::encode(sha2::Sha256::digest(app_js.bytes)))
    );
    let r = Harness::client()
        .get(h.console.url("/admin/ui/app.js"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(r.headers()["etag"], etag.as_str());
    assert_eq!(r.headers()["cache-control"], "no-cache");
    assert_security_headers(r.headers());
    assert!(r.bytes().await.unwrap().is_empty());
    // A stale tag gets the file.
    let r = Harness::client()
        .get(h.console.url("/admin/ui/app.js"))
        .header("if-none-match", "\"stale\"")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // Different files, different tags.
    let index = h.get("/admin/ui/").await;
    assert_ne!(index.headers()["etag"], etag.as_str());
}

#[tokio::test]
async fn root_and_bare_prefix_redirect_to_the_console() {
    let h = Harness::start(false).await;
    for path in ["/", "/admin/ui"] {
        let r = h.get(path).await;
        assert!(r.status().is_redirection(), "{path}: {}", r.status());
        assert_eq!(r.headers()["location"], "/admin/ui/", "{path}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
    }
}

#[tokio::test]
async fn read_routes_need_the_admin_bearer_and_carry_no_store() {
    let h = Harness::start(false).await;
    for path in [
        "/admin/audit",
        "/admin/audit/verify",
        "/admin/audit/checkpoint",
        "/admin/audit/export",
        "/admin/audit/checkpoints",
        "/admin/audit/entries/1",
        "/admin/audit/records/00000000-0000-0000-0000-000000000000",
        "/admin/leases/nope",
        "/admin/leases/nope/tree",
        "/admin/policies",
        "/admin/policies/check",
    ] {
        let r = h.get(path).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
        assert!(r.headers().contains_key("www-authenticate"), "{path}");
    }
    let r = Harness::client()
        .get(h.console.url("/admin/audit?limit=1"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
    let body: Value = r.json().await.unwrap();
    assert!(body["entries"].is_array());
    let r = Harness::client()
        .get(h.console.url("/admin/leases/nope"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_no_store(r.headers());
}

/// The read routes the console pages use, mounted without `allow_write`, with the bearer.
#[tokio::test]
async fn console_page_routes_are_mounted_without_allow_write() {
    let h = Harness::start(false).await;
    let lease = h.mint_root().await;
    for (path, want) in [
        (
            "/admin/audit/checkpoints?limit=20".to_string(),
            StatusCode::OK,
        ),
        ("/admin/audit/entries/1".to_string(), StatusCode::OK),
        (
            "/admin/audit/entries/999".to_string(),
            StatusCode::NOT_FOUND,
        ),
        (
            "/admin/audit/records/00000000-0000-0000-0000-000000000000".to_string(),
            StatusCode::NOT_FOUND,
        ),
        (
            "/admin/audit/records/nope".to_string(),
            StatusCode::BAD_REQUEST,
        ),
        (format!("/admin/leases/{lease}/tree"), StatusCode::OK),
        ("/admin/policies".to_string(), StatusCode::OK),
        // No policies_path in this config: the check says there is nothing to check.
        ("/admin/policies/check".to_string(), StatusCode::CONFLICT),
    ] {
        let r = h.admin_get(&path).await;
        assert_eq!(r.status(), want, "{path}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
    }
    let tree: Value = h
        .admin_get(&format!("/admin/leases/{lease}/tree"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(tree["root"], lease.as_str());
    assert_eq!(tree["would_revoke"], 1);
    let entry: Value = h
        .admin_get("/admin/audit/entries/1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(entry["entry"]["seq"], 1);
    assert!(entry["lease_states"].is_array());
}

/// Every path a console script fetches by a literal `fetch('/...')` is served on the console
/// listener. The Verify page used to probe `/readyz`, which only the main listener serves, so
/// every visit answered 404 and the browser logged a console error.
#[tokio::test]
async fn console_scripts_fetch_only_paths_the_console_listener_serves() {
    let h = Harness::start(false).await;
    for asset in ASSETS.iter().filter(|a| a.path.ends_with(".js")) {
        let text = std::str::from_utf8(asset.bytes).unwrap();
        for (i, _) in text.match_indices("fetch('/") {
            let rest = &text[i + "fetch('".len()..];
            let path = &rest[..rest.find('\'').unwrap()];
            let r = h.admin_get(path).await;
            assert_ne!(
                r.status(),
                StatusCode::NOT_FOUND,
                "{} fetches {path}, which the console listener does not serve",
                asset.path
            );
        }
    }
    assert_eq!(h.get("/readyz").await.status(), StatusCode::NOT_FOUND);
}

/// The dry run is mounted read-only, needs JSON, and writes nothing.
#[tokio::test]
async fn policy_evaluate_is_a_json_only_dry_run_on_the_console() {
    let h = Harness::start(false).await;
    let token = h.mint_root_full().await["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let url = h.console.url("/admin/policies/evaluate");
    let body = json!({
        "token": token,
        "subject": {"type": "agent", "id": ""},
        "action": {"name": "read_file"},
        "resource": {"type": "tool", "id": "github/read_file", "properties": {"server": "github"}},
        "context": {"input": {"repo": "alice/public-docs"}}
    });
    // No bearer: 401 before anything else.
    let r = Harness::client()
        .post(&url)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // Not JSON: 415, as for the write routes.
    let r = Harness::client()
        .post(&url)
        .bearer_auth(ADMIN)
        .header("content-type", "text/plain")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_security_headers(r.headers());
    let before = h.head().await;
    let r = Harness::client()
        .post(&url)
        .bearer_auth(ADMIN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["lease_check"], "skipped");
    assert_eq!(v["chain_source"], "token");
    assert!(v["decision"] == "allow" || v["decision"] == "deny", "{v}");
    assert_eq!(
        h.head().await,
        before,
        "a dry run must not write an audit record"
    );
}

#[tokio::test]
async fn forbidden_without_a_configured_admin_token_carries_the_headers() {
    let h = Harness::start_with(true, None).await;
    let r = Harness::client()
        .get(h.console.url("/admin/audit"))
        .bearer_auth("anything")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
}

#[tokio::test]
async fn write_routes_are_absent_without_allow_write() {
    let h = Harness::start(false).await;
    for path in [
        "/admin/leases/x/revoke",
        "/admin/policies/reload",
        "/admin/budgets/refund",
    ] {
        let r = Harness::client()
            .post(h.console.url(path))
            .bearer_auth(ADMIN)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
    }
    // The main listener still has revoke.
    let lease = h.mint_root().await;
    let r = Harness::client()
        .post(h.main.url(&format!("/admin/leases/{lease}/revoke")))
        .bearer_auth(ADMIN)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn write_routes_work_with_allow_write() {
    let h = Harness::start(true).await;
    let lease = h.mint_root().await;
    let url = h.console.url(&format!("/admin/leases/{lease}/revoke"));
    // No bearer: 401, even before the content type is looked at.
    let r = Harness::client().post(&url).body("x").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
    // Bearer but not JSON: 415.
    for ct in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        let mut req = Harness::client()
            .post(&url)
            .bearer_auth(ADMIN)
            .body(r#"{"reason":"x"}"#);
        if let Some(ct) = ct {
            req = req.header("content-type", ct);
        }
        let r = req.send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{ct:?}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
    }
    let status: Value = Harness::client()
        .get(h.console.url(&format!("/admin/leases/{lease}")))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["active"], true, "415 must not have revoked anything");
    // A real revoke.
    let r = Harness::client()
        .post(&url)
        .bearer_auth(ADMIN)
        .json(&json!({"reason": "from the console"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["revoked"], 1);
    assert_eq!(body["reason"], "from the console");
    let status: Value = Harness::client()
        .get(h.console.url(&format!("/admin/leases/{lease}")))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["active"], false);
    // Reload is mounted too (no policies_path here, so it says so).
    let r = Harness::client()
        .post(h.console.url("/admin/policies/reload"))
        .bearer_auth(ADMIN)
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn root_token_is_never_mounted_on_the_console() {
    for allow_write in [false, true] {
        let h = Harness::start(allow_write).await;
        let r = Harness::client()
            .post(h.console.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                          "agent": "planner", "capabilities": ["github:*"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::NOT_FOUND,
            "allow_write={allow_write}"
        );
        // While the main listener, with the same config, has it.
        h.mint_root().await;
    }
}

#[tokio::test]
async fn cross_origin_requests_get_no_cors_headers() {
    let h = Harness::start(true).await;
    let client = Harness::client();
    let evil = "https://evil.example";
    let requests = [
        client.get(h.console.url("/admin/ui/")),
        client.get(h.console.url("/admin/audit")),
        client.get(h.console.url("/admin/audit")).bearer_auth(ADMIN),
        client
            .post(h.console.url("/admin/leases/x/revoke"))
            .bearer_auth(ADMIN)
            .json(&json!({})),
        client
            .request(
                reqwest::Method::OPTIONS,
                h.console.url("/admin/leases/x/revoke"),
            )
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization, content-type",
            ),
    ];
    for req in requests {
        let r = req.header("origin", evil).send().await.unwrap();
        assert_no_cors(r.headers());
        assert_security_headers(r.headers());
    }
}

/// `serve` binds `[admin_ui] listen` next to the main listener when enabled.
#[tokio::test]
async fn serve_starts_the_console_listener() {
    let free_port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.path().join("a.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.server.listen = free_port();
    cfg.admin_ui.enabled = true;
    cfg.admin_ui.listen = free_port();
    let console = cfg.admin_ui.listen;
    let main = cfg.server.listen;
    let task = tokio::spawn(attenuo_server::serve(cfg));
    let client = Harness::client();
    let mut ok = None;
    for _ in 0..100 {
        if let Ok(r) = client
            .get(format!("http://{console}/admin/ui/"))
            .send()
            .await
        {
            ok = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let r = ok.expect("console listener never answered");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-security-policy"], CSP);
    // The main listener does not serve the console.
    let r = client
        .get(format!("http://{main}/admin/ui/"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    task.abort();
}

#[tokio::test]
async fn server_refuses_to_start_with_a_public_console_listener() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir.path().join("a.sqlite").to_string_lossy().into_owned();
    cfg.admin.token = Some("0123456789abcdef0123456789abcdef".into());
    cfg.admin_ui.enabled = true;
    cfg.admin_ui.listen = "0.0.0.0:9101".parse().unwrap();
    let err = attenuo_server::build(&cfg).err().expect("must refuse");
    assert!(err.to_string().contains("[admin_ui] listen"), "{err}");
    cfg.admin_ui.allow_public = true;
    let _ = attenuo_server::build(&cfg).unwrap();
}

/// Without `allow_write` the console listener serves the selector revocation's dry run, so the
/// lease page can preview "revoke this chain" and "revoke all for this user", but answers a
/// real revocation with 404 and revokes nothing. A preview, like every console `POST`, needs
/// a JSON `Content-Type`.
#[tokio::test]
async fn selector_preview_is_served_without_allow_write_but_revocation_is_not() {
    let h = Harness::start(false).await;
    let lease = h.mint_root().await;
    let post = |query: &'static str, body: Value| {
        Harness::client()
            .post(h.console.url(&format!("/admin/leases/revoke{query}")))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
    };
    let r = post("?preview=true", json!({"chain_id": lease}))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["preview"], true);
    assert_eq!(body["matched_count"], 1);
    assert_eq!(body["revoked"], json!([lease]));
    let r = post("?preview=true", json!({"user": "alice"}))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // Bad selectors are still the route's own 400.
    let r = post("?preview=true", json!({})).await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    for query in ["", "?preview=false"] {
        let r = post(query, json!({"chain_id": lease, "reason": "x"}))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{query}");
        assert_security_headers(r.headers());
        assert_no_store(r.headers());
    }
    let r = Harness::client()
        .post(h.console.url("/admin/leases/revoke?preview=true"))
        .bearer_auth(ADMIN)
        .header("content-type", "text/plain")
        .body(json!({"chain_id": lease}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let r = Harness::client()
        .post(h.console.url("/admin/leases/revoke?preview=true"))
        .json(&json!({"chain_id": lease}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let status: Value = h
        .admin_get(&format!("/admin/leases/{lease}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(status["active"], true, "nothing was revoked");
}

/// With `allow_write` the console listener revokes by chain and by user, and records it.
#[tokio::test]
async fn selector_revocation_works_on_the_console_with_allow_write() {
    let h = Harness::start(true).await;
    let first = h.mint_root().await;
    let second = h.mint_root().await;
    let before = h.head().await;
    let r = Harness::client()
        .post(h.console.url("/admin/leases/revoke"))
        .bearer_auth(ADMIN)
        .json(&json!({"chain_id": first, "reason": "from the console"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_security_headers(r.headers());
    assert_no_store(r.headers());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["revoked"], json!([first]));
    assert_eq!(body["reason"], "from the console");
    assert!(body["audit_id"].is_string());
    assert_eq!(h.head().await, before + 1);
    let record: Value = h
        .admin_get(&format!(
            "/admin/audit/records/{}",
            body["audit_id"].as_str().unwrap()
        ))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(record["entry"]["record"]["tool"], "admin.lease.revoke");

    // Every other lease of alice: the second root.
    let body: Value = Harness::client()
        .post(h.console.url("/admin/leases/revoke"))
        .bearer_auth(ADMIN)
        .json(&json!({"user": "alice"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["revoked"], json!([second]));
    assert_eq!(body["reason"], "revoked by admin");
}

/// Revoke by session on the console listener: the dry run is served without `allow_write` (an
/// unknown session matches nothing, a bound one resolves to its chain), a revocation is a 404
/// there, and with `allow_write` it revokes the chain. The raw id is never echoed back.
#[tokio::test]
async fn session_revocation_on_the_console_previews_without_allow_write_and_revokes_with_it() {
    use attenuo_audit::LeaseStore;
    use attenuo_proxy::session::{session_digest, session_tag};

    const RAW: &str = "console-raw-session-id";
    for allow_write in [false, true] {
        let h = Harness::start(allow_write).await;
        let lease = h.mint_root().await;
        h.state
            .leases
            .record_session(
                &session_digest(RAW),
                "github",
                &attenuo_core::LeaseId::new(lease.clone()),
                time::OffsetDateTime::now_utc(),
            )
            .unwrap();
        let post = |query: &'static str, body: Value| {
            Harness::client()
                .post(h.console.url(&format!("/admin/leases/revoke{query}")))
                .bearer_auth(ADMIN)
                .json(&body)
                .send()
        };

        let r = post("?preview=true", json!({"session": "never-seen"}))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["selector"]["chain_ids"], json!([]));
        assert_eq!(body["matched_count"], 0);

        let r = post("?preview=true", json!({"session": RAW}))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let text = r.text().await.unwrap();
        assert!(!text.contains(RAW), "{text}");
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            body["selector"],
            json!({"session_tag": session_tag(RAW), "chain_ids": [lease]})
        );
        assert_eq!(body["preview"], true);
        assert_eq!(body["revoked"], json!([lease]));

        let r = post("", json!({"session": RAW, "reason": "hijacked"}))
            .await
            .unwrap();
        let status: Value = h
            .admin_get(&format!("/admin/leases/{lease}"))
            .await
            .json()
            .await
            .unwrap();
        if allow_write {
            assert_eq!(r.status(), StatusCode::OK);
            let text = r.text().await.unwrap();
            assert!(!text.contains(RAW), "{text}");
            let body: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(body["revoked"], json!([lease]));
            assert!(body["audit_id"].is_string());
            assert_eq!(status["active"], false);
        } else {
            assert_eq!(r.status(), StatusCode::NOT_FOUND);
            assert_eq!(status["active"], true, "nothing was revoked");
        }
    }
}

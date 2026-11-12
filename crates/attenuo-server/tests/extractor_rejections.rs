//! K-10: what the server answers when axum's own extractors refuse a request (a query string that
//! does not parse, a path parameter of the wrong type or not UTF-8, a body over the limit, one
//! that is not JSON or is sent with another `Content-Type`). Every REST route answers the JSON
//! error shape of `crates/attenuo-server/src/error.rs`, AuthZEN keeps its own (the same shape),
//! and the MCP proxy keeps JSON-RPC.

#![allow(clippy::field_reassign_with_default)]

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::Config;
use reqwest::{Method, StatusCode};
use serde_json::Value;

const ADMIN: &str = "0123456789abcdef0123456789abcdef-admin";

struct Harness {
    main: Spawned,
    console: Spawned,
    _dir: tempfile::TempDir,
}

async fn start() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.admin_ui.enabled = true;
    cfg.admin_ui.allow_write = true;
    cfg.upstreams = vec![UpstreamConfig::new("github", "http://127.0.0.1:9/mcp")];
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let main = spawn_router(router).await.unwrap();
    let console = spawn_router(attenuo_server::admin_ui::router(state, &cfg))
        .await
        .unwrap();
    Harness {
        main,
        console,
        _dir: dir,
    }
}

struct Answer {
    status: StatusCode,
    content_type: String,
    body: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} {} {:?}",
                self.status, self.content_type, self.body
            )
        })
    }
}

impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}] {}", self.status, self.content_type, self.body)
    }
}

async fn send(
    url: String,
    method: Method,
    content_type: Option<&str>,
    body: Option<Vec<u8>>,
    admin: bool,
) -> Answer {
    let mut req = reqwest::Client::new().request(method, url);
    if admin {
        req = req.bearer_auth(ADMIN);
    }
    if let Some(ct) = content_type {
        req = req.header(reqwest::header::CONTENT_TYPE, ct);
    }
    if let Some(b) = body {
        req = req.body(b);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = resp.text().await.unwrap();
    Answer {
        status,
        content_type,
        body,
    }
}

/// The REST error shape: `application/json`, `{"error": code, "detail": text}`.
#[track_caller]
fn assert_rest(name: &str, a: &Answer, status: StatusCode, code: &str) {
    assert_eq!(a.status, status, "{name}: {a}");
    assert!(
        a.content_type.starts_with("application/json"),
        "{name}: {a}"
    );
    let v = a.json();
    assert_eq!(v["error"], code, "{name}: {a}");
    assert!(v["detail"].is_string(), "{name}: {a}");
    assert!(
        !a.body.contains(MARK),
        "{name}: the answer quotes the request: {a}"
    );
}

/// A value sent in the bad parameters; no answer may repeat it.
const MARK: &str = "zqx";

const JSON: Option<&str> = Some("application/json");

/// One more byte than axum's default body limit (2 MiB).
fn oversized() -> Vec<u8> {
    let mut v = b"{\"x\":\"".to_vec();
    v.resize(2 * 1024 * 1024 + 1, b'a');
    v
}

#[tokio::test]
async fn query_rejections_answer_json() {
    let h = start().await;
    for (name, method, path) in [
        ("audit from", Method::GET, "/admin/audit?from=zqx"),
        ("audit limit", Method::GET, "/admin/audit?limit=-zqx"),
        (
            "tree max_nodes",
            Method::GET,
            "/admin/leases/l1/tree?max_nodes=zqx",
        ),
        ("approvals limit", Method::GET, "/admin/approvals?limit=zqx"),
        (
            "revoke preview",
            Method::POST,
            "/admin/leases/revoke?preview=zqx",
        ),
    ] {
        let a = send(
            h.main.url(path),
            method.clone(),
            JSON,
            Some(b"{\"user\":\"u\"}".to_vec()),
            true,
        )
        .await;
        assert_rest(name, &a, StatusCode::BAD_REQUEST, "invalid_request");
        let a = send(
            h.console.url(path),
            method,
            JSON,
            Some(b"{\"user\":\"u\"}".to_vec()),
            true,
        )
        .await;
        assert_rest(name, &a, StatusCode::BAD_REQUEST, "invalid_request");
    }
}

#[tokio::test]
async fn path_rejections_answer_json() {
    let h = start().await;
    for (name, method, path, admin) in [
        (
            "audit entry seq",
            Method::GET,
            "/admin/audit/entries/zqx",
            true,
        ),
        (
            "audit entry seq overflow",
            Method::GET,
            "/admin/audit/entries/99999999999999999999999",
            true,
        ),
        ("lease not utf-8", Method::GET, "/admin/leases/zqx%FF", true),
        (
            "lease tree not utf-8",
            Method::GET,
            "/admin/leases/zqx%FF/tree",
            true,
        ),
        (
            "revoke not utf-8",
            Method::POST,
            "/admin/leases/zqx%FF/revoke",
            true,
        ),
        (
            "admin approval not utf-8",
            Method::GET,
            "/admin/approvals/zqx%FF",
            true,
        ),
        (
            "audit record not utf-8",
            Method::GET,
            "/admin/audit/records/zqx%FF",
            true,
        ),
        (
            "user approval not utf-8",
            Method::GET,
            "/approvals/zqx%FF",
            false,
        ),
    ] {
        let a = send(h.main.url(path), method, JSON, Some(b"{}".to_vec()), admin).await;
        assert_rest(name, &a, StatusCode::BAD_REQUEST, "invalid_request");
    }
    let a = send(
        h.console.url("/admin/ui/zqx%FF"),
        Method::GET,
        None,
        None,
        false,
    )
    .await;
    assert_rest(
        "console asset",
        &a,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
}

#[tokio::test]
async fn body_rejections_answer_json() {
    let h = start().await;
    let routes: [(&str, &str, bool); 8] = [
        ("root-token", "/admin/root-token", true),
        ("revoke lease", "/admin/leases/l1/revoke", true),
        ("revoke selector", "/admin/leases/revoke", true),
        ("refund", "/admin/budgets/refund", true),
        ("policy evaluate", "/admin/policies/evaluate", true),
        ("admin decide", "/admin/approvals/a1", true),
        ("user decide", "/approvals/a1", false),
        ("token", "/token", false),
    ];
    for (name, path, admin) in routes {
        let a = send(
            h.main.url(path),
            Method::POST,
            JSON,
            Some(b"{not json".to_vec()),
            admin,
        )
        .await;
        assert_rest(name, &a, StatusCode::BAD_REQUEST, "invalid_request");
        let a = send(
            h.main.url(path),
            Method::POST,
            JSON,
            Some(oversized()),
            admin,
        )
        .await;
        assert_rest(name, &a, StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
        let a = send(
            h.main.url(path),
            Method::POST,
            Some("text/plain"),
            Some(b"{not json".to_vec()),
            admin,
        )
        .await;
        assert_rest(name, &a, StatusCode::BAD_REQUEST, "invalid_request");
    }
    for path in ["/access/v1/evaluation", "/access/v1/evaluations"] {
        let a = send(
            h.main.url(path),
            Method::POST,
            JSON,
            Some(b"{not json".to_vec()),
            false,
        )
        .await;
        assert_rest(path, &a, StatusCode::BAD_REQUEST, "invalid_request");
        let a = send(
            h.main.url(path),
            Method::POST,
            JSON,
            Some(oversized()),
            false,
        )
        .await;
        assert_rest(path, &a, StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
        let a = send(
            h.main.url(path),
            Method::POST,
            Some("text/plain"),
            Some(b"{not json".to_vec()),
            false,
        )
        .await;
        assert_rest(path, &a, StatusCode::BAD_REQUEST, "invalid_request");
    }
}

#[tokio::test]
async fn mcp_path_rejection_answers_json_rpc() {
    let h = start().await;
    for method in [Method::POST, Method::GET, Method::DELETE] {
        let a = send(
            h.main.url("/mcp/zqx%FF"),
            method.clone(),
            JSON,
            Some(b"{}".to_vec()),
            false,
        )
        .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST, "{a}");
        assert!(a.content_type.starts_with("application/json"), "{a}");
        let v = a.json();
        assert_eq!(v["jsonrpc"], "2.0", "{a}");
        assert_eq!(v["id"], Value::Null, "{a}");
        assert_eq!(v["error"]["code"], -32600, "{a}");
        assert!(!a.body.contains(MARK), "{a}");
    }
}

/// The main listener reads a JSON body whatever its `Content-Type` (only `POST /token` chooses
/// between form and JSON by it); the console listener requires `application/json` and answers
/// anything else with 415 `unsupported_media_type`, in the same shape.
#[tokio::test]
async fn content_type_of_a_json_body() {
    let h = start().await;
    let path = "/admin/leases/revoke?preview=true";
    let body = br#"{"user":"nobody"}"#.to_vec();
    let a = send(
        h.main.url(path),
        Method::POST,
        Some("text/plain"),
        Some(body.clone()),
        true,
    )
    .await;
    assert_eq!(a.status, StatusCode::OK, "{a}");
    let a = send(
        h.console.url(path),
        Method::POST,
        Some("text/plain"),
        Some(body.clone()),
        true,
    )
    .await;
    assert_rest(
        "console text/plain",
        &a,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    let a = send(h.console.url(path), Method::POST, None, Some(body), true).await;
    assert_rest(
        "console no type",
        &a,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
}

/// `detail` names the parameter and the expected type, from the route and the query struct.
#[tokio::test]
async fn detail_names_the_parameter() {
    let h = start().await;
    for (path, detail) in [
        (
            "/admin/audit/entries/zqx",
            "the path parameter `seq` is not a valid u64",
        ),
        (
            "/admin/leases/zqx%FF",
            "the path parameter `lease_id` is not valid UTF-8",
        ),
        (
            "/admin/audit?from=zqx",
            "the query parameter `from` has an invalid value",
        ),
    ] {
        let a = send(h.main.url(path), Method::GET, None, None, true).await;
        assert_eq!(a.json()["detail"], detail, "{path}: {a}");
    }
    let a = send(
        h.main.url("/token"),
        Method::POST,
        JSON,
        Some(oversized()),
        false,
    )
    .await;
    assert_eq!(
        a.json()["detail"],
        "the request body is over the size limit",
        "{a}"
    );
}

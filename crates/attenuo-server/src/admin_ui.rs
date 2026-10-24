//! The admin console listener (`[admin_ui]`): embedded console assets and the admin API, on a
//! port of their own.
//!
//! The console is not served on the main listener because that origin also serves
//! `/mcp/{server}`, where an upstream chooses the response `Content-Type`; a hostile upstream
//! answering `text/html` must never run script next to the admin token. On its own listener the
//! page and the API it calls are same-origin, so no CORS is needed and none is sent.
//!
//! What this router mounts:
//!
//! - `GET /admin/ui/` and `GET /admin/ui/{file}`: the files of `crates/attenuo-server/ui/`,
//!   compiled in with `include_bytes!` ([`ASSETS`]). `/` and `/admin/ui` redirect to
//!   `/admin/ui/`. Assets carry `Cache-Control: no-cache` and a SHA-256 `ETag`, and answer
//!   `If-None-Match` with 304, so a server upgrade never leaves a stale script running.
//! - The read-only admin routes ([`read_routes`]) behind [`require_admin`]: audit queries,
//!   entries and checkpoints, lease status and tree, the loaded policies, a lint of the policy
//!   file, and the `POST /admin/policies/evaluate` dry run (JSON `Content-Type` required). One
//!   of them, `GET /admin/audit/checkpoint`, signs a checkpoint of the head when it has none;
//!   it is mounted as a read because it changes no recorded fact and the CLI treats it as one.
//! - With `[admin_ui] allow_write = true` only, the routes that change state
//!   ([`write_routes`]), which also require `Content-Type: application/json`. Without it,
//!   `POST /admin/leases/revoke` is still mounted for its dry run (`?preview=true`, JSON
//!   `Content-Type` required) and answers a revocation with 404.
//! - Never `POST /admin/root-token`, whatever `[dev] allow_root_mint` says.
//!
//! Every response, errors and 404s included, carries [`SECURITY_HEADERS`]; every response that
//! is not an asset also carries `Cache-Control: no-store`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use sha2::Digest;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::error::ApiError;
use crate::routes::admin::{self, require_admin};
use crate::routes::{approvals, policies};
use crate::state::AppState;

/// Where the console lives on its listener. Asset paths are relative to it.
pub const UI_PREFIX: &str = "/admin/ui/";

/// The `Content-Security-Policy` of every console-listener response: nothing but same-origin
/// scripts, styles, images and `fetch`, no inline script, no framing, no form posts, and
/// Trusted Types so that a DOM sink cannot take a plain string.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                       connect-src 'self'; form-action 'none'; frame-ancestors 'none'; \
                       base-uri 'none'; require-trusted-types-for 'script'";

/// Headers set on every response of the console listener, overriding any a handler set.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", CSP),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];

/// One embedded console file.
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// Path below [`UI_PREFIX`]; `index.html` is also served at the prefix itself.
    pub path: &'static str,
    /// The `Content-Type` it is served with.
    pub content_type: &'static str,
    /// The file, as compiled in.
    pub bytes: &'static [u8],
}

const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

/// The console files. A fixed table rather than a directory walk, so what ships is exactly
/// what is listed here and reviewed; a new file is one entry. Paths are flat (the asset route
/// takes one path segment), so the views are `view-*.js` rather than a `views/` directory.
pub const ASSETS: &[Asset] = &[
    Asset {
        path: "index.html",
        content_type: HTML,
        bytes: include_bytes!("../ui/index.html"),
    },
    Asset {
        path: "app.css",
        content_type: CSS,
        bytes: include_bytes!("../ui/app.css"),
    },
    Asset {
        path: "app.js",
        content_type: JS,
        bytes: include_bytes!("../ui/app.js"),
    },
    Asset {
        path: "api.js",
        content_type: JS,
        bytes: include_bytes!("../ui/api.js"),
    },
    Asset {
        path: "dom.js",
        content_type: JS,
        bytes: include_bytes!("../ui/dom.js"),
    },
    Asset {
        path: "view-approvals.js",
        content_type: JS,
        bytes: include_bytes!("../ui/view-approvals.js"),
    },
    Asset {
        path: "view-audit.js",
        content_type: JS,
        bytes: include_bytes!("../ui/view-audit.js"),
    },
    Asset {
        path: "view-entry.js",
        content_type: JS,
        bytes: include_bytes!("../ui/view-entry.js"),
    },
    Asset {
        path: "view-lease.js",
        content_type: JS,
        bytes: include_bytes!("../ui/view-lease.js"),
    },
    Asset {
        path: "view-policy.js",
        content_type: JS,
        bytes: include_bytes!("../ui/view-policy.js"),
    },
    Asset {
        path: "view-verify.js",
        content_type: JS,
        bytes: include_bytes!("../ui/view-verify.js"),
    },
];

/// Marks a response as a static asset, so [`security_headers`] leaves its `no-cache` alone.
#[derive(Debug, Clone, Copy)]
struct AssetResponse;

/// An [`Asset`] with its precomputed strong `ETag`.
struct Served {
    asset: Asset,
    etag: HeaderValue,
}

type AssetTable = Arc<Vec<Served>>;

fn asset_table() -> AssetTable {
    Arc::new(
        ASSETS
            .iter()
            .map(|a| Served {
                asset: *a,
                etag: HeaderValue::from_str(&format!(
                    "\"{}\"",
                    hex::encode(sha2::Sha256::digest(a.bytes))
                ))
                .expect("hex is a valid header value"),
            })
            .collect(),
    )
}

/// The admin routes the console listener always mounts: those without side effects on leases
/// or policy. `POST /admin/policies/evaluate` is a dry run (no lease check, no audit record),
/// so it is here too; being a `POST` it requires a JSON `Content-Type` like the write routes.
pub fn read_routes() -> Router<Arc<AppState>> {
    let evaluate = Router::new()
        .route(
            "/admin/policies/evaluate",
            post(policies::evaluate_policies),
        )
        .route_layer(middleware::from_fn(require_json));
    Router::new()
        .route("/admin/audit", get(admin::audit_range))
        .route("/admin/audit/verify", get(admin::audit_verify))
        // Signs a checkpoint of the head when it has none yet; a read for the CLI and here.
        .route("/admin/audit/checkpoint", get(admin::audit_checkpoint))
        .route("/admin/audit/checkpoints", get(admin::audit_checkpoints))
        .route("/admin/audit/entries/{seq}", get(admin::audit_entry))
        .route("/admin/audit/records/{id}", get(admin::audit_record))
        .route("/admin/audit/export", get(admin::audit_export))
        .route("/admin/leases/{lease_id}", get(admin::lease_status))
        .route("/admin/leases/{lease_id}/tree", get(admin::lease_tree))
        .route("/admin/policies", get(policies::get_policies))
        .route("/admin/policies/check", get(policies::check_policies))
        .route("/admin/approvals", get(approvals::admin_list))
        .route("/admin/approvals/{id}", get(approvals::admin_get))
        .merge(evaluate)
}

/// `POST /admin/leases/revoke` on a console listener without `allow_write`: only the dry run
/// (`?preview=true`) is served, so the lease page can show what revoking a chain or a user
/// would change. A revocation is answered 404, as the write routes are when not mounted.
async fn selector_preview_only(
    state: State<Arc<AppState>>,
    q: Query<admin::SelectorRevokeQuery>,
    body: Bytes,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    if !q.preview {
        return Err(ApiError::not_found(
            "writes are disabled on the console listener; only `?preview=true` is served",
        ));
    }
    admin::revoke_by_selector(state, q, body).await
}

/// The admin routes that change state, mounted on the console listener only with
/// `[admin_ui] allow_write = true`. Each requires a JSON `Content-Type` ([`require_json`]).
/// `POST /admin/root-token` is deliberately absent and must never be added.
pub fn write_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/leases/{lease_id}/revoke", post(admin::revoke_lease))
        .route("/admin/leases/revoke", post(admin::revoke_by_selector))
        .route("/admin/budgets/refund", post(admin::refund_budget))
        .route("/admin/policies/reload", post(admin::reload_policies))
        .route("/admin/approvals/{id}", post(approvals::admin_decide))
        .route_layer(middleware::from_fn(require_json))
}

/// The console listener's router over an existing state. See the module docs for what it
/// mounts; `config.admin_ui.allow_write` decides whether [`write_routes`] are included.
pub fn router(state: Arc<AppState>, config: &Config) -> Router {
    let mut api = read_routes();
    if config.admin_ui.allow_write {
        api = api.merge(write_routes());
    } else {
        api = api.merge(
            Router::new()
                .route("/admin/leases/revoke", post(selector_preview_only))
                .route_layer(middleware::from_fn(require_json)),
        );
    }
    // `require_admin` is added last so it runs first: no bearer is 401 before anything else.
    let api = api
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin))
        .with_state(state);

    let assets = Router::new()
        .route("/", get(redirect_to_ui))
        .route("/admin/ui", get(redirect_to_ui))
        .route(UI_PREFIX, get(index))
        .route("/admin/ui/{file}", get(asset))
        .with_state(asset_table());

    api.merge(assets)
        .fallback(not_found)
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http())
}

async fn redirect_to_ui() -> Redirect {
    Redirect::to(UI_PREFIX)
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such route on the console listener")
}

async fn index(State(table): State<AssetTable>, headers: HeaderMap) -> Response {
    serve_asset(&table, "index.html", &headers)
}

async fn asset(
    State(table): State<AssetTable>,
    Path(file): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve_asset(&table, &file, &headers)
}

fn serve_asset(table: &[Served], path: &str, headers: &HeaderMap) -> Response {
    let Some(served) = table.iter().find(|s| s.asset.path == path) else {
        return ApiError::not_found(format!("no console asset `{path}`")).into_response();
    };
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| etag_matches(v, &served.etag));
    let mut resp = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(served.asset.content_type),
            )],
            served.asset.bytes,
        )
            .into_response()
    };
    let h = resp.headers_mut();
    h.insert(header::ETAG, served.etag.clone());
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp.extensions_mut().insert(AssetResponse);
    resp
}

/// `If-None-Match` (RFC 9110 §13.1.2): `*`, or a list of entity tags compared weakly.
fn etag_matches(if_none_match: &str, etag: &HeaderValue) -> bool {
    let ours = etag.as_bytes();
    if_none_match
        .split(',')
        .map(str::trim)
        .any(|tag| tag == "*" || tag.strip_prefix("W/").unwrap_or(tag).as_bytes() == ours)
}

/// Middleware on every console-listener response: [`SECURITY_HEADERS`], plus
/// `Cache-Control: no-store` on everything but static assets (API answers, redirects, 401,
/// 403 and 404 alike), so no admin data is kept in a browser or proxy cache.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let is_asset = resp.extensions().get::<AssetResponse>().is_some();
    let h = resp.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        h.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if !is_asset {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    resp
}

/// Middleware on the console's write routes: a `POST` must say `Content-Type:
/// application/json` (parameters such as `charset` allowed), or it gets 415. A browser cannot
/// send that type cross-site without a CORS preflight, which this listener never grants, so a
/// form or `no-cors` request from another page never reaches a handler.
pub async fn require_json(req: Request, next: Next) -> Response {
    if req.method() == Method::POST && !is_json(req.headers()) {
        return ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "console requests must have Content-Type: application/json",
        )
        .into_response();
    }
    next.run(req).await
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_comparison() {
        let etag = HeaderValue::from_static("\"abc\"");
        assert!(etag_matches("\"abc\"", &etag));
        assert!(etag_matches("W/\"abc\"", &etag));
        assert!(etag_matches("\"x\", \"abc\"", &etag));
        assert!(etag_matches("*", &etag));
        assert!(!etag_matches("\"abd\"", &etag));
        assert!(!etag_matches("abc", &etag));
    }

    #[test]
    fn json_content_type_check() {
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_str(v).unwrap());
            is_json(&h)
        };
        assert!(with("application/json"));
        assert!(with("Application/JSON; charset=utf-8"));
        assert!(!with("text/plain"));
        assert!(!with("application/x-www-form-urlencoded"));
        assert!(!with("application/jsonp"));
        assert!(!is_json(&HeaderMap::new()));
    }

    /// What [`unsafe_markup`] refuses in every script and page: the HTML-parsing sinks,
    /// string-to-code calls and `javascript:` URLs. The console builds every node with
    /// `createElement`/`textContent`, and the CSP's Trusted Types would throw on these anyway;
    /// this test keeps them out of the source so a regression fails CI rather than a browser.
    const FORBIDDEN: &[&str] = &[
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "javascript:",
    ];

    /// Every reason `text` (the asset at `path`) breaks the console's markup rules.
    fn unsafe_markup(path: &str, text: &str) -> Vec<String> {
        let mut found: Vec<String> = FORBIDDEN
            .iter()
            .filter(|f| text.contains(**f))
            .map(|f| format!("{path}: `{f}`"))
            .collect();
        if text.contains("style=") {
            found.push(format!("{path}: `style=`"));
        }
        if !path.ends_with(".html") {
            return found;
        }
        let lower = text.to_ascii_lowercase();
        let b = lower.as_bytes();
        for (i, _) in lower.match_indices("on") {
            // An attribute starts after whitespace: ` onclick=`, `\nonload =`.
            if i == 0 || !b[i - 1].is_ascii_whitespace() {
                continue;
            }
            let name_end = i
                + 2
                + b[i + 2..]
                    .iter()
                    .take_while(|c| c.is_ascii_lowercase())
                    .count();
            let rest = lower[name_end..].trim_start();
            if name_end > i + 2 && rest.starts_with('=') {
                found.push(format!("{path}: inline handler `{}`", &lower[i..name_end]));
            }
        }
        for (i, _) in lower.match_indices("style") {
            let attr = i > 0 && b[i - 1].is_ascii_whitespace();
            if (attr && lower[i + 5..].trim_start().starts_with('=')) || (i > 0 && b[i - 1] == b'<')
            {
                found.push(format!("{path}: inline style at byte {i}"));
            }
        }
        for (i, _) in lower.match_indices("<script") {
            let Some(close) = lower[i..].find('>') else {
                found.push(format!("{path}: unterminated <script"));
                continue;
            };
            let tag = &lower[i..i + close];
            let body_starts = i + close + 1;
            if !tag.contains(" src=") || !lower[body_starts..].starts_with("</script>") {
                found.push(format!("{path}: inline <script> at byte {i}"));
            }
        }
        found
    }

    #[test]
    fn no_asset_contains_an_html_sink_or_inline_code() {
        let mut found = Vec::new();
        for a in ASSETS.iter().filter(|a| !a.path.ends_with(".css")) {
            let text = std::str::from_utf8(a.bytes).expect("console assets are UTF-8");
            found.extend(unsafe_markup(a.path, text));
        }
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn the_markup_scan_catches_each_rule() {
        let bad_js = [
            "el.innerHTML = x",
            "el.outerHTML = x",
            "el.insertAdjacentHTML('beforeend', x)",
            "document.write(x)",
            "eval(x)",
            "new Function('return 1')",
            "a.href = 'javascript:alert(1)'",
        ];
        for js in bad_js {
            assert!(!unsafe_markup("x.js", js).is_empty(), "{js}");
        }
        let bad_html = [
            "<img src=x onerror=alert(1)>",
            "<body\nonload = \"go()\">",
            "<div style=\"color:red\">",
            "<style>p{}</style>",
            "<script>alert(1)</script>",
            "<script src=\"a.js\">alert(1)</script>",
            "<script type=\"module\"></script>",
        ];
        for html in bad_html {
            assert!(!unsafe_markup("x.html", html).is_empty(), "{html}");
        }
        let fine = [
            ("x.html", "<script type=\"module\" src=\"app.js\"></script><button id=\"lock\" hidden>Lock</button>"),
            ("x.html", "<p>Questions on one line</p>"),
            ("x.js", "el.textContent = reason; const done = () => onChain(id);"),
        ];
        for (path, text) in fine {
            assert!(
                unsafe_markup(path, text).is_empty(),
                "{text}: {:?}",
                unsafe_markup(path, text)
            );
        }
    }

    #[test]
    fn every_asset_has_a_known_type_and_unique_path() {
        let mut paths: Vec<_> = ASSETS.iter().map(|a| a.path).collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), ASSETS.len());
        for a in ASSETS {
            let want = match a.path.rsplit_once('.').map(|(_, ext)| ext) {
                Some("html") => HTML,
                Some("js") => JS,
                Some("css") => CSS,
                other => panic!("no content type for {other:?}"),
            };
            assert_eq!(a.content_type, want, "{}", a.path);
        }
    }
}

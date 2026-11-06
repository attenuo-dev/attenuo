//! The span every `TraceLayer` in attenuo opens per HTTP request.
//!
//! tower-http's default `make_span_with` records the full request URI, query string included,
//! so with `RUST_LOG=tower_http=debug` a request such as `GET /admin/audit?subject=...` wrote
//! the subject (or any other query-string filter) to the log, and would hand it to a trace
//! exporter as it is (SR-90). [`request_span`] records the route template instead, the same
//! label the HTTP metrics use, and never the URI.

use axum::extract::MatchedPath;
use axum::http::Request;

/// The route recorded for a request that matched no route. A fixed string, never the path.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// The `request` span for one HTTP request: `method`, `route` and `version`.
///
/// `route` is the template of the matched route (`/admin/audit`, `/mcp/{server}`) from
/// axum's [`MatchedPath`], or [`UNMATCHED_ROUTE`] when no route matched. The URI, its path and
/// its query string are never recorded (SR-90). The span keeps tower-http's name, level
/// (`DEBUG`) and target (`tower_http::trace::make_span`), so existing `RUST_LOG` filters
/// select it as before.
///
/// Use it as `TraceLayer::new_for_http().make_span_with(request_span)`, added with
/// `Router::layer` so that the matched path is already set when the span is made.
pub fn request_span<B>(req: &Request<B>) -> tracing::Span {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNMATCHED_ROUTE, MatchedPath::as_str);
    tracing::debug_span!(
        target: "tower_http::trace::make_span",
        "request",
        method = %req.method(),
        route = %route,
        version = ?req.version(),
    )
}

//! Prometheus metrics: hand-rolled counters and one histogram, plus the text exposition writer.
//!
//! No dependency: a few atomics and two small maps behind mutexes. Label values come from
//! fixed sets (reason codes, route templates, status codes), so cardinality stays bounded.
//! The endpoint lives on its own listener (`[metrics] listen`), never on the proxy port.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

/// Upper bounds (seconds) of the `authorize_duration_seconds` buckets.
pub const BUCKETS: [f64; 11] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];

const PREFIX: &str = "onbehalf";

/// All server metrics. Cheap to share: clone the `Arc`.
#[derive(Debug, Default)]
pub struct Metrics {
    /// (decision, reason) -> count
    decisions: Mutex<BTreeMap<(String, String), u64>>,
    /// (route, status) -> count
    http: Mutex<BTreeMap<(String, u16), u64>>,
    tokens_root: AtomicU64,
    tokens_exchange: AtomicU64,
    leases_revoked: AtomicU64,
    audit_append_errors: AtomicU64,
    audit_checkpoints: AtomicU64,
    /// Time to decide one tool call.
    authorize: Histogram,
    /// Time for one audit append, lock wait and commit included.
    audit_append: Histogram,
}

/// A fixed-bucket histogram over [`BUCKETS`].
#[derive(Debug, Default)]
struct Histogram {
    /// Non-cumulative per-bucket counts; the last slot is `+Inf`.
    buckets: [AtomicU64; BUCKETS.len() + 1],
    nanos: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let i = BUCKETS
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(BUCKETS.len());
        self.buckets[i].fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        header_lines(out, name, help, "histogram");
        let mut cumulative = 0;
        for (i, bound) in BUCKETS.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(out, "{PREFIX}_{name}_bucket{{le=\"{bound}\"}} {cumulative}");
        }
        cumulative += self.buckets[BUCKETS.len()].load(Ordering::Relaxed);
        let _ = writeln!(out, "{PREFIX}_{name}_bucket{{le=\"+Inf\"}} {cumulative}");
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_sum {}",
            self.nanos.load(Ordering::Relaxed) as f64 / 1e9
        );
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_count {}",
            self.count.load(Ordering::Relaxed)
        );
    }
}

/// Which kind of token was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Root,
    Exchange,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Count one pipeline decision (`decision` is `allow` or `deny`).
    pub fn decision(&self, decision: &str, reason: &str) {
        if let Ok(mut m) = self.decisions.lock() {
            *m.entry((decision.to_string(), reason.to_string()))
                .or_default() += 1;
        }
    }

    pub fn token_issued(&self, kind: TokenKind) {
        let c = match kind {
            TokenKind::Root => &self.tokens_root,
            TokenKind::Exchange => &self.tokens_exchange,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Count leases that changed to revoked.
    pub fn leases_revoked(&self, n: u64) {
        self.leases_revoked.fetch_add(n, Ordering::Relaxed);
    }

    pub fn audit_append_error(&self) {
        self.audit_append_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn http_request(&self, route: &str, status: u16) {
        if let Ok(mut m) = self.http.lock() {
            *m.entry((route.to_string(), status)).or_default() += 1;
        }
    }

    /// Record how long one authorization decision took.
    pub fn observe_authorize(&self, d: Duration) {
        self.authorize.observe(d);
    }

    /// Record how long one audit append took, from asking for the store's lock to the commit
    /// (failed appends included).
    pub fn observe_audit_append(&self, d: Duration) {
        self.audit_append.observe(d);
    }

    /// Run an audit append and record its duration.
    pub fn time_audit_append<R>(&self, append: impl FnOnce() -> R) -> R {
        let started = std::time::Instant::now();
        let out = append();
        self.observe_audit_append(started.elapsed());
        out
    }

    /// Count one signed audit checkpoint.
    pub fn audit_checkpoint(&self) {
        self.audit_checkpoints.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text exposition format (version 0.0.4).
    pub fn render(&self) -> String {
        let mut out = String::new();
        header_lines(
            &mut out,
            "decisions_total",
            "Authorization decisions by outcome and reason.",
            "counter",
        );
        if let Ok(m) = self.decisions.lock() {
            for ((decision, reason), n) in m.iter() {
                let _ = writeln!(
                    out,
                    "{PREFIX}_decisions_total{{decision=\"{}\",reason=\"{}\"}} {n}",
                    escape(decision),
                    escape(reason)
                );
            }
        }
        header_lines(
            &mut out,
            "tokens_issued_total",
            "Delegation tokens issued, by kind.",
            "counter",
        );
        for (kind, c) in [
            ("root", &self.tokens_root),
            ("exchange", &self.tokens_exchange),
        ] {
            let _ = writeln!(
                out,
                "{PREFIX}_tokens_issued_total{{kind=\"{kind}\"}} {}",
                c.load(Ordering::Relaxed)
            );
        }
        simple_counter(
            &mut out,
            "leases_revoked_total",
            "Leases moved to revoked, including cascaded descendants.",
            &self.leases_revoked,
        );
        simple_counter(
            &mut out,
            "audit_append_errors_total",
            "Audit log appends that failed.",
            &self.audit_append_errors,
        );
        simple_counter(
            &mut out,
            "audit_checkpoints_total",
            "Signed audit checkpoints written.",
            &self.audit_checkpoints,
        );
        header_lines(
            &mut out,
            "http_requests_total",
            "HTTP requests by route template and status.",
            "counter",
        );
        if let Ok(m) = self.http.lock() {
            for ((route, status), n) in m.iter() {
                let _ = writeln!(
                    out,
                    "{PREFIX}_http_requests_total{{route=\"{}\",status=\"{status}\"}} {n}",
                    escape(route)
                );
            }
        }
        self.authorize.render(
            &mut out,
            "authorize_duration_seconds",
            "Time to decide one tool call (leases, policy, audit append).",
        );
        self.audit_append.render(
            &mut out,
            "audit_append_duration_seconds",
            "Time for one audit log append, including waiting for the store's lock.",
        );
        out
    }
}

fn header_lines(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {PREFIX}_{name} {help}");
    let _ = writeln!(out, "# TYPE {PREFIX}_{name} {kind}");
}

fn simple_counter(out: &mut String, name: &str, help: &str, c: &AtomicU64) {
    header_lines(out, name, help, "counter");
    let _ = writeln!(out, "{PREFIX}_{name} {}", c.load(Ordering::Relaxed));
}

/// Escape a label value: backslash, double quote and newline.
fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// A router serving `GET /metrics` for `metrics`. Mount it on its own listener.
pub fn router(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(handler))
        .with_state(metrics)
}

async fn handler(State(metrics): State<Arc<Metrics>>) -> Response {
    let mut res = metrics.render().into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    res
}

/// Middleware counting every response by matched route template and status.
pub async fn track_http(State(metrics): State<Arc<Metrics>>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_string(), |p| p.as_str().to_string());
    let res = next.run(req).await;
    metrics.http_request(&route, res.status().as_u16());
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_and_histogram() {
        let m = Metrics::new();
        m.decision("allow", "policy_permit");
        m.decision("allow", "policy_permit");
        m.decision("deny", "lease \"x\"");
        m.token_issued(TokenKind::Root);
        m.leases_revoked(3);
        m.audit_append_error();
        m.http_request("/token", 200);
        m.observe_authorize(Duration::from_micros(200));
        m.observe_authorize(Duration::from_millis(30));
        m.observe_authorize(Duration::from_secs(5));
        let text = m.render();
        assert!(text
            .contains("onbehalf_decisions_total{decision=\"allow\",reason=\"policy_permit\"} 2\n"));
        assert!(text.contains("reason=\"lease \\\"x\\\"\"} 1\n"));
        assert!(text.contains("onbehalf_tokens_issued_total{kind=\"root\"} 1\n"));
        assert!(text.contains("onbehalf_tokens_issued_total{kind=\"exchange\"} 0\n"));
        assert!(text.contains("onbehalf_leases_revoked_total 3\n"));
        assert!(text.contains("onbehalf_audit_append_errors_total 1\n"));
        assert!(text.contains("onbehalf_http_requests_total{route=\"/token\",status=\"200\"} 1\n"));
        assert!(text.contains("authorize_duration_seconds_bucket{le=\"0.0005\"} 1\n"));
        assert!(text.contains("authorize_duration_seconds_bucket{le=\"0.05\"} 2\n"));
        assert!(text.contains("authorize_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("authorize_duration_seconds_count 3\n"));
        assert!(text.contains("# TYPE onbehalf_authorize_duration_seconds histogram\n"));
    }

    #[test]
    fn renders_audit_append_histogram_and_checkpoint_counter() {
        let m = Metrics::new();
        let text = m.render();
        assert!(text.contains("# TYPE onbehalf_audit_append_duration_seconds histogram\n"));
        assert!(text.contains("onbehalf_audit_append_duration_seconds_count 0\n"));
        assert!(text.contains("# TYPE onbehalf_audit_checkpoints_total counter\n"));
        assert!(text.contains("onbehalf_audit_checkpoints_total 0\n"));

        m.observe_audit_append(Duration::from_micros(300));
        m.observe_audit_append(Duration::from_millis(7));
        let slow = m.time_audit_append(|| {
            std::thread::sleep(Duration::from_millis(30));
            "done"
        });
        assert_eq!(slow, "done");
        m.audit_checkpoint();
        m.audit_checkpoint();
        let text = m.render();
        assert!(text.contains("audit_append_duration_seconds_bucket{le=\"0.0005\"} 1\n"));
        assert!(text.contains("audit_append_duration_seconds_bucket{le=\"0.01\"} 2\n"));
        assert!(text.contains("audit_append_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("audit_append_duration_seconds_count 3\n"));
        assert!(text.contains("onbehalf_audit_checkpoints_total 2\n"));
        // The two histograms are independent.
        assert!(text.contains("onbehalf_authorize_duration_seconds_count 0\n"));
    }
}

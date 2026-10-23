//! Prometheus metrics: hand-rolled counters and histograms, plus the text exposition writer.
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
use onbehalf_proxy::Stage;

/// Upper bounds (seconds) of the `authorize_duration_seconds` buckets.
pub const BUCKETS: [f64; 11] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];

/// Upper bounds (seconds) of the `proxy_stage_seconds` buckets: 1 us to 1 s, five per decade,
/// fine enough to read a median off stages that take a few microseconds.
pub const STAGE_BUCKETS: [f64; 31] = [
    1e-6, 2e-6, 3e-6, 5e-6, 7e-6, 1e-5, 2e-5, 3e-5, 5e-5, 7e-5, 1e-4, 2e-4, 3e-4, 5e-4, 7e-4, 1e-3,
    2e-3, 3e-3, 5e-3, 7e-3, 1e-2, 2e-2, 3e-2, 5e-2, 7e-2, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0,
];

const PREFIX: &str = "onbehalf";

/// All server metrics. Cheap to share: clone the `Arc`.
#[derive(Debug)]
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
    /// `[audit.sink]` (SR-21): checkpoints delivered, delivery attempts that failed,
    /// checkpoints dropped from a full queue, the queue depth, and when the oldest undelivered
    /// checkpoint was queued (unix seconds, 0 when none).
    audit_sink_delivered: AtomicU64,
    audit_sink_failures: AtomicU64,
    audit_sink_dropped: AtomicU64,
    audit_sink_queue_depth: AtomicU64,
    audit_sink_oldest_unix: AtomicU64,
    /// Time to decide one tool call.
    authorize: Histogram,
    /// Time for one audit append, lock wait and commit included.
    audit_append: Histogram,
    /// Per-stage time of proxied calls, indexed by [`Stage::index`].
    stages: [Histogram; Stage::ALL.len()],
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            decisions: Mutex::default(),
            http: Mutex::default(),
            tokens_root: AtomicU64::default(),
            tokens_exchange: AtomicU64::default(),
            leases_revoked: AtomicU64::default(),
            audit_append_errors: AtomicU64::default(),
            audit_checkpoints: AtomicU64::default(),
            audit_sink_delivered: AtomicU64::default(),
            audit_sink_failures: AtomicU64::default(),
            audit_sink_dropped: AtomicU64::default(),
            audit_sink_queue_depth: AtomicU64::default(),
            audit_sink_oldest_unix: AtomicU64::default(),
            authorize: Histogram::new(&BUCKETS),
            audit_append: Histogram::new(&BUCKETS),
            stages: std::array::from_fn(|_| Histogram::new(&STAGE_BUCKETS)),
        }
    }
}

/// A fixed-bucket histogram.
#[derive(Debug)]
struct Histogram {
    /// Upper bounds, ascending.
    bounds: &'static [f64],
    /// Non-cumulative per-bucket counts; the last slot is `+Inf`.
    buckets: Box<[AtomicU64]>,
    nanos: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new(bounds: &'static [f64]) -> Self {
        Self {
            bounds,
            buckets: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            nanos: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        let i = self
            .bounds
            .iter()
            .position(|b| secs <= *b)
            .unwrap_or(self.bounds.len());
        self.buckets[i].fetch_add(1, Ordering::Relaxed);
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str) {
        header_lines(out, name, help, "histogram");
        self.render_samples(out, name, "");
    }

    /// The `_bucket`, `_sum` and `_count` lines. `labels` is empty or `key="value",` pairs,
    /// each followed by a comma, placed before `le`.
    fn render_samples(&self, out: &mut String, name: &str, labels: &str) {
        let mut cumulative = 0;
        for (i, bound) in self.bounds.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{PREFIX}_{name}_bucket{{{labels}le=\"{bound}\"}} {cumulative}"
            );
        }
        cumulative += self.buckets[self.bounds.len()].load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_bucket{{{labels}le=\"+Inf\"}} {cumulative}"
        );
        let braced = labels
            .strip_suffix(',')
            .map(|l| format!("{{{l}}}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_sum{braced} {}",
            self.nanos.load(Ordering::Relaxed) as f64 / 1e9
        );
        let _ = writeln!(
            out,
            "{PREFIX}_{name}_count{braced} {}",
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

    /// Record how long one stage of a proxied call took (see [`Stage`]).
    pub fn observe_stage(&self, stage: Stage, d: Duration) {
        self.stages[stage.index()].observe(d);
    }

    /// Count one signed audit checkpoint.
    pub fn audit_checkpoint(&self) {
        self.audit_checkpoints.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one checkpoint delivered by `[audit.sink]`.
    pub fn audit_sink_delivered(&self) {
        self.audit_sink_delivered.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one failed delivery attempt (it is retried).
    pub fn audit_sink_failure(&self) {
        self.audit_sink_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one checkpoint dropped from a full sink queue.
    pub fn audit_sink_dropped(&self) {
        self.audit_sink_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the sink queue gauges: queued checkpoints, and when the oldest undelivered one
    /// (queued or in flight) was queued.
    pub fn audit_sink_queue(&self, depth: u64, oldest: Option<std::time::SystemTime>) {
        self.audit_sink_queue_depth.store(depth, Ordering::Relaxed);
        let unix = oldest
            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs().max(1));
        self.audit_sink_oldest_unix.store(unix, Ordering::Relaxed);
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
        simple_counter(
            &mut out,
            "audit_sink_delivered_total",
            "Signed audit checkpoints delivered off the host by [audit.sink].",
            &self.audit_sink_delivered,
        );
        simple_counter(
            &mut out,
            "audit_sink_failures_total",
            "Checkpoint deliveries by [audit.sink] that failed and will be retried.",
            &self.audit_sink_failures,
        );
        simple_counter(
            &mut out,
            "audit_sink_dropped_total",
            "Checkpoints dropped from a full [audit.sink] queue before delivery.",
            &self.audit_sink_dropped,
        );
        simple_gauge(
            &mut out,
            "audit_sink_queue_depth",
            "Checkpoints waiting in the [audit.sink] queue.",
            &self.audit_sink_queue_depth,
        );
        simple_gauge(
            &mut out,
            "audit_sink_oldest_undelivered_timestamp_seconds",
            "Unix time the oldest undelivered checkpoint was queued; 0 when none.",
            &self.audit_sink_oldest_unix,
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
        header_lines(
            &mut out,
            "proxy_stage_seconds",
            "Time spent in each stage of a proxied call (token verification, lease check, \
             policy, audit append, blocking-pool hop, upstream round trip, response handling, \
             total).",
            "histogram",
        );
        for stage in Stage::ALL {
            self.stages[stage.index()].render_samples(
                &mut out,
                "proxy_stage_seconds",
                &format!("stage=\"{}\",", stage.as_str()),
            );
        }
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

fn simple_gauge(out: &mut String, name: &str, help: &str, c: &AtomicU64) {
    header_lines(out, name, help, "gauge");
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

    #[test]
    fn renders_stage_histograms_with_labels() {
        let m = Metrics::new();
        m.observe_stage(Stage::Policy, Duration::from_micros(12));
        m.observe_stage(Stage::Policy, Duration::from_micros(40));
        m.observe_stage(Stage::Upstream, Duration::from_millis(2));
        let text = m.render();
        assert!(text.contains("# TYPE onbehalf_proxy_stage_seconds histogram\n"));
        assert!(text
            .contains("onbehalf_proxy_stage_seconds_bucket{stage=\"policy\",le=\"0.00002\"} 1\n"));
        assert!(
            text.contains("onbehalf_proxy_stage_seconds_bucket{stage=\"policy\",le=\"+Inf\"} 2\n")
        );
        assert!(text.contains("onbehalf_proxy_stage_seconds_count{stage=\"policy\"} 2\n"));
        assert!(text.contains("onbehalf_proxy_stage_seconds_sum{stage=\"policy\"} 0.000052\n"));
        assert!(text.contains("onbehalf_proxy_stage_seconds_count{stage=\"upstream\"} 1\n"));
        // Every stage is rendered, observed or not, and only one TYPE line is written.
        for s in Stage::ALL {
            let line = format!(
                "onbehalf_proxy_stage_seconds_count{{stage=\"{}\"}} ",
                s.as_str()
            );
            assert!(text.contains(&line), "{line}");
        }
        assert_eq!(
            text.matches("# TYPE onbehalf_proxy_stage_seconds").count(),
            1
        );
        // The older histograms keep their label-free form.
        assert!(text.contains("onbehalf_authorize_duration_seconds_bucket{le=\"+Inf\"} 0\n"));
        assert!(text.contains("onbehalf_authorize_duration_seconds_sum 0\n"));
    }
}

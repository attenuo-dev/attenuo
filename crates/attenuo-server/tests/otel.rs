//! OpenTelemetry export (`[telemetry]`, `docs/design/otel-export.md`): one MCP `tools/call`
//! through the proxy, with the spans caught by an in-process exporter, or sent to a tiny
//! OTLP/HTTP receiver on 127.0.0.1, or to a collector that never answers.
//!
//! Each test installs its subscriber with `tracing::subscriber::set_default` on a
//! current-thread runtime, so the server's tasks and the blocking pool (which carries the
//! dispatcher, `telemetry::Carry`) all report to it.
#![cfg(feature = "otel")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::telemetry::{self, TelemetryCounters, TraceSettings};
use attenuo_server::Config;
use axum::http::HeaderMap;
use opentelemetry::trace::SpanKind;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tracing_subscriber::layer::SubscriberExt;

const ADMIN: &str = "test-admin-token";
/// The originating subject: must never leave the process.
const SUBJECT: &str = "alice.secret-subject@example.com";
/// An argument value: must never leave the process.
const ARG_VALUE: &str = "alice/ARGVALUE-do-not-export";
/// A result body: must never leave the process.
const RESULT_TEXT: &str = "RESULTBODY-do-not-export";
/// The caller's trace context (the W3C spec's example).
const INBOUND: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const INBOUND_TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const INBOUND_SPAN: &str = "00f067aa0ba902b7";

/// Every attribute key an exported span may carry (design section 3.3, as built).
const ALLOWED: &[&str] = &[
    "http.request.method",
    "http.route",
    "http.response.status_code",
    "attenuo.server",
    "attenuo.session_tag",
    "attenuo.chain_id",
    "attenuo.chain_depth",
    "attenuo.dpop_bound",
    "attenuo.token.cache",
    "attenuo.reason",
    "attenuo.tool",
    "attenuo.decision",
    "attenuo.decision_id",
    "attenuo.audit.seq",
    "attenuo.policy_ids",
    "attenuo.tainted",
    "attenuo.subject_digest",
    "attenuo.limit.kind",
    "attenuo.budget.exhausted_at",
    "attenuo.result.label",
];

/// An exporter that keeps what it is given.
#[derive(Debug, Clone, Default)]
struct Collect(Arc<Mutex<Vec<SpanData>>>);

impl SpanExporter for Collect {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.0.lock().unwrap().extend(batch);
        Ok(())
    }
}

/// How the fake upstream answers a `tools/call`.
#[derive(Clone, Copy, Debug, Default)]
enum Answer {
    /// A JSON body, read whole by the proxy inside the request.
    #[default]
    Json,
    /// An SSE body whose one event, the result, comes after a pause, so the proxy records it
    /// after the request has returned its headers.
    SseLate,
    /// An SSE body with one progress notification, then open for good, until the proxy ends it.
    SseOpen,
}

/// A fake upstream that answers `tools/call` and remembers each request's headers.
#[derive(Clone, Default)]
struct Upstream {
    headers: Arc<Mutex<Vec<HeaderMap>>>,
    answer: Arc<Mutex<Answer>>,
}

/// One SSE event of `msg`.
fn sse_event(msg: &Value) -> axum::body::Bytes {
    format!("event: message\ndata: {msg}\n\n").into()
}

impl Upstream {
    fn answering(answer: Answer) -> Self {
        Self {
            answer: Arc::new(Mutex::new(answer)),
            ..Self::default()
        }
    }

    async fn spawn(&self) -> Spawned {
        use axum::response::IntoResponse;
        use futures_util::StreamExt;
        let me = self.clone();
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move |headers: HeaderMap, body: axum::Json<Value>| {
                let me = me.clone();
                async move {
                    me.headers.lock().unwrap().push(headers);
                    let result = json!({
                        "jsonrpc": "2.0",
                        "id": body.0["id"].clone(),
                        "result": {"content": [{"type": "text", "text": RESULT_TEXT}]},
                    });
                    let answer = *me.answer.lock().unwrap();
                    let events = match answer {
                        Answer::Json => return axum::Json(result).into_response(),
                        Answer::SseLate => futures_util::stream::once(async move {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                            Ok::<_, std::io::Error>(sse_event(&result))
                        })
                        .boxed(),
                        Answer::SseOpen => {
                            let progress = json!({"jsonrpc": "2.0",
                                "method": "notifications/progress",
                                "params": {"progressToken": 1, "progress": 1}});
                            futures_util::stream::iter([Ok(sse_event(&progress))])
                                .chain(futures_util::stream::pending())
                                .boxed()
                        }
                    };
                    (
                        [("content-type", "text/event-stream")],
                        axum::body::Body::from_stream(events),
                    )
                        .into_response()
                }
            }),
        );
        spawn_router(app).await.unwrap()
    }

    fn last_traceparent(&self) -> Option<String> {
        self.headers
            .lock()
            .unwrap()
            .last()
            .and_then(|h| h.get("traceparent"))
            .map(|v| v.to_str().unwrap().to_owned())
    }
}

struct Harness {
    server: Spawned,
    state: Arc<attenuo_server::AppState>,
    upstream: Upstream,
    _upstream_task: Spawned,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

fn config(dir: &std::path::Path, upstream_url: String, tweak: impl FnOnce(&mut Config)) -> Config {
    let policy = dir.join("policies.cedar");
    std::fs::write(
        &policy,
        "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
    )
    .unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.join("keys/issuer.pem"));
    cfg.policy.policies_path = Some(policy);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([(
            "read_file".to_string(),
            ToolAttrs::new()
                .with_input("repo", ArgType::String)
                .readonly(true),
        )]),
    )]);
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream_url)];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.telemetry.enabled = true;
    cfg.telemetry.traces.sample_ratio = 1.0;
    tweak(&mut cfg);
    cfg
}

impl Harness {
    async fn start(tweak: impl FnOnce(&mut Config)) -> Self {
        Self::start_answering(Answer::Json, tweak).await
    }

    async fn start_answering(answer: Answer, tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let upstream = Upstream::answering(answer);
        let task = upstream.spawn().await;
        let cfg = config(dir.path(), task.url("/mcp"), tweak);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        assert_eq!(
            state.trace.is_some(),
            cfg.telemetry.enabled,
            "[telemetry] enabled builds the trace hook"
        );
        Self {
            server: spawn_router(router).await.unwrap(),
            state,
            upstream,
            _upstream_task: task,
            client: reqwest::Client::new(),
            _dir: dir,
        }
    }

    async fn mint(&self) -> String {
        self.mint_with_lease(None).await.0
    }

    /// A root token for [`SUBJECT`] living `ttl_seconds` (the default when `None`), and its
    /// lease id.
    async fn mint_with_lease(&self, ttl_seconds: Option<u64>) -> (String, String) {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({"subject": SUBJECT, "issuer": "https://idp.example",
                          "agent": "planner", "capabilities": ["github:*"],
                          "ttl_seconds": ttl_seconds}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = resp.json::<Value>().await.unwrap();
        (
            v["access_token"].as_str().unwrap().to_owned(),
            v["lease"].as_str().unwrap().to_owned(),
        )
    }

    /// Send one `tools/call` of `read_file` with `traceparent`, and return the response with
    /// its body unread (an SSE stream).
    async fn call_streamed(&self, token: &str, traceparent: &str) -> reqwest::Response {
        let resp = self
            .client
            .post(self.server.url("/mcp/github"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .header("traceparent", traceparent)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "read_file", "arguments": {"repo": ARG_VALUE}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream"));
        resp
    }

    /// Every audit entry, oldest first.
    async fn audit_entries(&self) -> Vec<Value> {
        self.admin_get("/admin/audit?from=1&limit=1000").await["entries"]
            .as_array()
            .unwrap()
            .clone()
    }

    /// One `tools/call` of `read_file`, with `traceparent` when given. Returns the decision id.
    async fn call(&self, token: &str, traceparent: Option<&str>) -> String {
        let mut req = self
            .client
            .post(self.server.url("/mcp/github"))
            .bearer_auth(token)
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "read_file", "arguments": {"repo": ARG_VALUE}}}));
        if let Some(tp) = traceparent {
            req = req.header("traceparent", tp);
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let id = resp
            .headers()
            .get(attenuo_proxy::DECISION_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["result"]["content"][0]["text"], RESULT_TEXT, "{body}");
        id
    }

    async fn admin_get(&self, path: &str) -> Value {
        let resp = self
            .client
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        resp.json().await.unwrap()
    }
}

fn settings(max_queue: usize, max_batch: usize) -> TraceSettings {
    let mut s = telemetry::TelemetrySection {
        enabled: true,
        ..Default::default()
    };
    s.traces.sample_ratio = 1.0;
    s.traces.max_queue_spans = max_queue;
    s.traces.max_export_batch = max_batch;
    s.resolve_with(&|_| None).unwrap().unwrap()
}

/// A provider exporting into `exporter`, and the subscriber guard that routes this thread's
/// spans to it.
fn install<E: SpanExporter + 'static>(
    settings: &TraceSettings,
    exporter: E,
    counters: Arc<TelemetryCounters>,
) -> (SdkTracerProvider, tracing::subscriber::DefaultGuard) {
    let provider = telemetry::tracer_provider(
        settings,
        exporter,
        counters,
        tokio::runtime::Handle::current(),
    );
    let subscriber = tracing_subscriber::registry().with(telemetry::layer(&provider));
    let guard = tracing::subscriber::set_default(subscriber);
    (provider, guard)
}

/// Flush until a span named `name` has arrived (spans end as the handler returns).
async fn spans_until(provider: &SdkTracerProvider, sink: &Collect, name: &str) -> Vec<SpanData> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        provider.force_flush().unwrap();
        let spans = sink.0.lock().unwrap().clone();
        if spans.iter().any(|s| s.name == name) {
            return spans;
        }
        assert!(
            Instant::now() < deadline,
            "no {name} span: {:?}",
            names(&spans)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn names(spans: &[SpanData]) -> BTreeSet<String> {
    spans.iter().map(|s| s.name.to_string()).collect()
}

fn one<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
    let found: Vec<_> = spans.iter().filter(|s| s.name == name).collect();
    assert_eq!(found.len(), 1, "{name}: {:?}", names(spans));
    found[0]
}

fn attr(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.as_str().into_owned())
}

/// Every attribute of every span is on the allow-list, and no value holds a secret.
fn assert_nothing_forbidden(spans: &[SpanData], secrets: &[&str]) {
    for s in spans {
        for kv in &s.attributes {
            assert!(
                ALLOWED.contains(&kv.key.as_str()),
                "{}: attribute {} is not on the allow-list",
                s.name,
                kv.key
            );
            let v = kv.value.as_str();
            for secret in secrets {
                assert!(!v.contains(secret), "{}: {} holds a secret", s.name, kv.key);
            }
        }
        assert!(
            s.events.is_empty(),
            "{}: no span events are exported",
            s.name
        );
        for l in s.links.iter() {
            assert!(l.attributes.is_empty());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tools_call_exports_the_listed_spans_and_nothing_forbidden() {
    let sink = Collect::default();
    let (provider, _guard) = install(&settings(2048, 512), sink.clone(), Arc::default());
    let h = Harness::start(|_| {}).await;
    let token = h.mint().await;
    let decision_id = h.call(&token, Some(INBOUND)).await;
    let spans = spans_until(&provider, &sink, "mcp.request").await;
    let spans = if spans.iter().any(|s| s.name == "attenuo.record_result") {
        spans
    } else {
        spans_until(&provider, &sink, "attenuo.record_result").await
    };
    let got = names(&spans);
    for want in [
        "mcp.request",
        "attenuo.authenticate",
        "attenuo.session_gate",
        "attenuo.decide",
        "attenuo.lease_check",
        "attenuo.run_state",
        "attenuo.policy",
        "attenuo.audit_append",
        "attenuo.upstream",
        "attenuo.response",
        "attenuo.record_result",
    ] {
        assert!(got.contains(want), "missing {want}: {got:?}");
    }
    // The minted root token came from `/admin/root-token`, which has no exported span.
    assert!(!got.contains("attenuo.token.exchange"), "{got:?}");

    // Nothing that may not leave the process: the token, the subject, the argument value,
    // the result body, the upstream URL.
    let upstream = h._upstream_task.url("/mcp");
    assert_nothing_forbidden(
        &spans,
        &[
            &token,
            SUBJECT,
            "alice.secret",
            ARG_VALUE,
            "ARGVALUE",
            RESULT_TEXT,
            &upstream,
        ],
    );

    // One trace, rooted at `mcp.request` (link mode: a new trace, linked to the caller's).
    let request = one(&spans, "mcp.request");
    assert_eq!(request.span_kind, SpanKind::Server);
    let trace_id = request.span_context.trace_id();
    assert_ne!(
        trace_id.to_string(),
        INBOUND_TRACE,
        "link mode starts a new trace"
    );
    assert_eq!(
        request.parent_span_id,
        opentelemetry::trace::SpanId::INVALID
    );
    let links: Vec<_> = request.links.iter().collect();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].span_context.trace_id().to_string(), INBOUND_TRACE);
    assert_eq!(links[0].span_context.span_id().to_string(), INBOUND_SPAN);
    for s in &spans {
        assert_eq!(
            s.span_context.trace_id(),
            trace_id,
            "{} is in the trace",
            s.name
        );
    }
    assert_eq!(
        attr(request, "http.route").as_deref(),
        Some("/mcp/{server}")
    );
    assert_eq!(
        attr(request, "http.request.method").as_deref(),
        Some("POST")
    );
    assert_eq!(attr(request, "attenuo.server").as_deref(), Some("github"));
    assert_eq!(
        attr(request, "http.response.status_code").as_deref(),
        Some("200")
    );
    assert_eq!(attr(request, "attenuo.chain_depth").as_deref(), Some("1"));
    assert!(attr(request, "attenuo.chain_id").is_some());

    // The decision span: a child of the request through the blocking pool, with the record's
    // id and seq, the tool, the subject as a keyed digest only.
    let decide = one(&spans, "attenuo.decide");
    assert_eq!(decide.parent_span_id, request.span_context.span_id());
    assert_eq!(attr(decide, "attenuo.tool").as_deref(), Some("read_file"));
    assert_eq!(attr(decide, "attenuo.decision").as_deref(), Some("allow"));
    assert_eq!(
        attr(decide, "attenuo.reason").as_deref(),
        Some("policy_allow")
    );
    assert_eq!(attr(decide, "attenuo.policy_ids").as_deref(), Some("reads"));
    assert_eq!(attr(decide, "attenuo.tainted").as_deref(), Some("false"));
    assert_eq!(
        attr(decide, "attenuo.subject_digest").map(|d| d.len()),
        Some(16)
    );
    assert_eq!(
        attr(decide, "attenuo.decision_id").as_deref(),
        Some(decision_id.as_str())
    );
    for stage in [
        "attenuo.lease_check",
        "attenuo.run_state",
        "attenuo.policy",
        "attenuo.audit_append",
    ] {
        assert_eq!(
            one(&spans, stage).parent_span_id,
            decide.span_context.span_id(),
            "{stage}"
        );
    }
    let auth = one(&spans, "attenuo.authenticate");
    assert_eq!(attr(auth, "attenuo.token.cache").as_deref(), Some("miss"));
    assert_eq!(attr(auth, "attenuo.dpop_bound").as_deref(), Some("false"));
    let up = one(&spans, "attenuo.upstream");
    assert_eq!(up.span_kind, SpanKind::Client);
    assert_eq!(
        attr(up, "http.response.status_code").as_deref(),
        Some("200")
    );
    let result = one(&spans, "attenuo.record_result");
    assert_eq!(
        result.parent_span_id,
        one(&spans, "attenuo.response").span_context.span_id()
    );
    assert_eq!(
        attr(result, "attenuo.decision_id").as_deref(),
        Some(decision_id.as_str())
    );
    assert_eq!(
        attr(result, "attenuo.result.label").as_deref(),
        Some("untrusted")
    );

    // Span to signed record: the decision id and seq lead to the entry, which is unchanged
    // (no trace id in the record), and the hash chain verifies.
    let seq: u64 = attr(decide, "attenuo.audit.seq").unwrap().parse().unwrap();
    let entry = h
        .admin_get(&format!("/admin/audit/records/{decision_id}"))
        .await;
    assert_eq!(entry["entry"]["seq"], json!(seq));
    assert_eq!(entry["entry"]["record"]["id"], json!(decision_id));
    let record = entry["entry"]["record"].as_object().unwrap();
    assert!(!record.contains_key("trace_id") && !record.contains_key("span_id"));
    let result_seq: u64 = attr(result, "attenuo.audit.seq").unwrap().parse().unwrap();
    assert!(result_seq > seq);
    assert_eq!(h.admin_get("/admin/audit/verify").await["ok"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn upstream_gets_attenuos_traceparent_and_a_malformed_one_is_ignored() {
    let sink = Collect::default();
    let (provider, _guard) = install(&settings(2048, 512), sink.clone(), Arc::default());
    let h = Harness::start(|_| {}).await;
    let token = h.mint().await;

    // The upstream sees attenuo's `attenuo.upstream` span, never the client's header.
    h.call(&token, Some(INBOUND)).await;
    let sent = h.upstream.last_traceparent().expect("traceparent upstream");
    assert_ne!(sent, INBOUND);
    let tp = attenuo_proxy::TraceParent::parse(&sent).unwrap();
    let spans = spans_until(&provider, &sink, "mcp.request").await;
    let up = one(&spans, "attenuo.upstream");
    assert_eq!(hex(&tp.trace_id), up.span_context.trace_id().to_string());
    assert_eq!(hex(&tp.parent_id), up.span_context.span_id().to_string());
    assert!(tp.sampled());
    sink.0.lock().unwrap().clear();

    // A malformed header: the call goes through, a new trace starts, nothing is linked.
    for bad in [
        "00-garbage",
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01",
    ] {
        h.call(&token, Some(bad)).await;
        let spans = spans_until(&provider, &sink, "mcp.request").await;
        let request = one(&spans, "mcp.request");
        assert!(request.links.is_empty(), "{bad}");
        assert_eq!(
            request.parent_span_id,
            opentelemetry::trace::SpanId::INVALID
        );
        sink.0.lock().unwrap().clear();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn parent_mode_adopts_the_inbound_trace() {
    let sink = Collect::default();
    let (provider, _guard) = install(&settings(2048, 512), sink.clone(), Arc::default());
    let h = Harness::start(|c| {
        c.telemetry.traces.inbound_mcp = telemetry::InboundMode::Parent;
        c.telemetry.traces.propagate_upstream = false;
    })
    .await;
    let token = h.mint().await;
    h.call(&token, Some(INBOUND)).await;
    let spans = spans_until(&provider, &sink, "mcp.request").await;
    let request = one(&spans, "mcp.request");
    assert_eq!(request.span_context.trace_id().to_string(), INBOUND_TRACE);
    assert_eq!(request.parent_span_id.to_string(), INBOUND_SPAN);
    assert!(request.links.is_empty());
    assert_eq!(
        h.upstream.last_traceparent(),
        None,
        "propagate_upstream = false"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tracing_off_inserts_nothing_upstream() {
    let h = Harness::start(|c| c.telemetry.enabled = false).await;
    assert!(h.state.trace.is_none());
    let token = h.mint().await;
    h.call(&token, Some(INBOUND)).await;
    assert_eq!(h.upstream.last_traceparent(), None);
}

/// The spans of the trace `trace_id`.
fn in_trace(spans: &[SpanData], trace_id: opentelemetry::trace::TraceId) -> Vec<&SpanData> {
    spans
        .iter()
        .filter(|s| s.span_context.trace_id() == trace_id)
        .collect()
}

/// `late` is a span recorded after `request` returned: the root of a trace of its own (no
/// parent, and not in the request's trace), with exactly one span link, without attributes,
/// to a span of the request's trace (the one current when the proxy kept the context).
/// Returns the name of the span linked to.
fn assert_linked_not_parented(spans: &[SpanData], late: &SpanData, request: &SpanData) -> String {
    let request_trace = request.span_context.trace_id();
    assert_eq!(
        late.parent_span_id,
        opentelemetry::trace::SpanId::INVALID,
        "{}: a new root span, not a child",
        late.name
    );
    assert_ne!(
        late.span_context.trace_id(),
        request_trace,
        "{}: a trace of its own",
        late.name
    );
    let links: Vec<_> = late.links.iter().collect();
    assert_eq!(links.len(), 1, "{}: one link", late.name);
    let link = &links[0].span_context;
    assert_eq!(
        link.trace_id(),
        request_trace,
        "{}: linked to the request",
        late.name
    );
    assert!(links[0].attributes.is_empty());
    let target = in_trace(spans, request_trace)
        .into_iter()
        .find(|s| s.span_context.span_id() == link.span_id())
        .unwrap_or_else(|| panic!("{}: the link names no span of the request", late.name));
    // Nothing else of the late span's trace but its own children.
    for s in in_trace(spans, late.span_context.trace_id()) {
        assert!(
            s.span_context.span_id() == late.span_context.span_id()
                || s.parent_span_id == late.span_context.span_id(),
            "{} in the trace of {}",
            s.name,
            late.name
        );
    }
    target.name.to_string()
}

/// Read an SSE body to its end, at most `within`.
async fn read_to_end(resp: reqwest::Response, within: Duration) -> String {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut text = String::new();
    tokio::time::timeout(within, async {
        while let Some(chunk) = stream.next().await {
            text.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
        }
    })
    .await
    .expect("the stream ended");
    text
}

/// The JSON-RPC messages of the `data:` lines of an SSE body.
fn sse_messages(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

/// A result streamed back after the response's headers is recorded by the labeller outside
/// `mcp.request`, which has ended: `attenuo.record_result` is a new span linked to the
/// request, with the call's decision id and the seq of its `tool_result` record.
#[tokio::test(flavor = "current_thread")]
async fn a_result_recorded_after_the_response_is_a_linked_span() {
    let sink = Collect::default();
    let (provider, _guard) = install(&settings(2048, 512), sink.clone(), Arc::default());
    let h = Harness::start_answering(Answer::SseLate, |_| {}).await;
    let token = h.mint().await;
    let resp = h.call_streamed(&token, INBOUND).await;
    let header_id = resp
        .headers()
        .get(attenuo_proxy::DECISION_ID_HEADER)
        .map(|v| v.to_str().unwrap().to_owned());
    let text = read_to_end(resp, Duration::from_secs(5)).await;
    let messages = sse_messages(&text);
    assert_eq!(messages.len(), 1, "{text}");
    assert_eq!(
        messages[0]["result"]["content"][0]["text"], RESULT_TEXT,
        "{text}"
    );
    let spans = spans_until(&provider, &sink, "attenuo.record_result").await;
    let spans = if spans.iter().any(|s| s.name == "mcp.request") {
        spans
    } else {
        spans_until(&provider, &sink, "mcp.request").await
    };

    let request = one(&spans, "mcp.request");
    let decide = one(&spans, "attenuo.decide");
    assert_eq!(
        decide.span_context.trace_id(),
        request.span_context.trace_id()
    );
    // The response span ended with the headers: the result is not inside it.
    let response = one(&spans, "attenuo.response");
    let result = one(&spans, "attenuo.record_result");
    assert_ne!(result.parent_span_id, response.span_context.span_id());
    let linked = assert_linked_not_parented(&spans, result, request);
    assert_eq!(linked, "mcp.request");

    // The join to the record: the call's decision id, and the seq of its `tool_result`.
    let decision_id = attr(decide, "attenuo.decision_id").unwrap();
    assert_eq!(
        attr(result, "attenuo.decision_id").as_deref(),
        Some(decision_id.as_str())
    );
    if let Some(id) = header_id {
        assert_eq!(id, decision_id);
    }
    assert_eq!(
        attr(result, "attenuo.result.label").as_deref(),
        Some("untrusted")
    );
    let seq: u64 = attr(result, "attenuo.audit.seq").unwrap().parse().unwrap();
    let entries = h.audit_entries().await;
    let entry = entries
        .iter()
        .find(|e| e["seq"] == json!(seq))
        .expect("the span's seq is in the log");
    assert_eq!(entry["record"]["kind"], "tool_result");
    assert_eq!(entry["record"]["decision_id"], json!(decision_id));
    let decision_seq: u64 = attr(decide, "attenuo.audit.seq").unwrap().parse().unwrap();
    let decision = entries
        .iter()
        .find(|e| e["seq"] == json!(decision_seq))
        .unwrap();
    assert_eq!(decision["record"]["id"], json!(decision_id));

    let upstream = h._upstream_task.url("/mcp");
    assert_nothing_forbidden(
        &spans,
        &[
            &token,
            SUBJECT,
            "alice.secret",
            ARG_VALUE,
            "ARGVALUE",
            RESULT_TEXT,
            "RESULTBODY",
            &upstream,
        ],
    );
    assert_eq!(h.admin_get("/admin/audit/verify").await["ok"], true);
}

/// A streamed answer that the proxy ends because the chain's lease was revoked (`revoke`)
/// or the token expired: `attenuo.stream_end` is a new span linked to the request that
/// opened the stream, with the reason and the decision id and seq of the `stream.end`
/// record, which the final event names.
async fn a_cut_stream_is_a_linked_stream_end_span(revoke: bool) {
    let sink = Collect::default();
    let (provider, _guard) = install(&settings(2048, 512), sink.clone(), Arc::default());
    let h = Harness::start_answering(Answer::SseOpen, |c| c.proxy.stream_recheck_seconds = 1).await;
    let (token, lease) = h.mint_with_lease((!revoke).then_some(2)).await;
    let resp = h.call_streamed(&token, INBOUND).await;
    if revoke {
        let r = h
            .client
            .post(h.server.url(&format!("/admin/leases/{lease}/revoke")))
            .bearer_auth(ADMIN)
            .json(&json!({"reason": "incident"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
    let text = read_to_end(resp, Duration::from_secs(10)).await;
    let messages = sse_messages(&text);
    assert_eq!(messages[0]["method"], "notifications/progress", "{text}");
    let last = messages.last().unwrap();
    let reason = if revoke {
        "lease_revoked"
    } else {
        "token_expired"
    };
    assert_eq!(last["error"]["code"], -32001, "{text}");
    assert_eq!(last["error"]["data"]["reason"], reason);
    let end_id = last["error"]["data"]["decision_id"].as_str().unwrap();

    let spans = spans_until(&provider, &sink, "attenuo.stream_end").await;
    let request = one(&spans, "mcp.request");
    let end = one(&spans, "attenuo.stream_end");
    // The guard is built around the streamed response, inside `attenuo.response`, a child
    // of `mcp.request`: the link names that span.
    let linked = assert_linked_not_parented(&spans, end, request);
    assert_eq!(linked, "attenuo.response");
    assert_eq!(
        one(&spans, "attenuo.response").parent_span_id,
        request.span_context.span_id()
    );
    assert!(
        !names(&spans).contains("attenuo.record_result"),
        "no result came"
    );
    assert_eq!(attr(end, "attenuo.reason").as_deref(), Some(reason));
    assert_eq!(attr(end, "attenuo.decision_id").as_deref(), Some(end_id));
    let seq: u64 = attr(end, "attenuo.audit.seq").unwrap().parse().unwrap();
    let entry = h.admin_get(&format!("/admin/audit/records/{end_id}")).await;
    assert_eq!(entry["entry"]["seq"], json!(seq));
    let record = &entry["entry"]["record"];
    assert_eq!(record["tool"], "stream.end");
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["reason"], reason);
    // The call's own decision is a different record, joined from `attenuo.decide`.
    let decide = one(&spans, "attenuo.decide");
    assert_ne!(attr(decide, "attenuo.decision_id").as_deref(), Some(end_id));

    let upstream = h._upstream_task.url("/mcp");
    assert_nothing_forbidden(
        &spans,
        &[
            &token,
            SUBJECT,
            "alice.secret",
            ARG_VALUE,
            "ARGVALUE",
            RESULT_TEXT,
            &upstream,
        ],
    );
    assert_eq!(h.admin_get("/admin/audit/verify").await["ok"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn a_stream_cut_by_revocation_is_a_linked_stream_end_span() {
    a_cut_stream_is_a_linked_stream_end_span(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_stream_cut_at_token_expiry_is_a_linked_stream_end_span() {
    a_cut_stream_is_a_linked_stream_end_span(false).await;
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A collector that accepts connections and never answers.
async fn dead_collector() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    (addr, task)
}

#[tokio::test(flavor = "current_thread")]
async fn a_dead_collector_never_slows_or_fails_a_decision() {
    let (addr, _collector) = dead_collector().await;
    let mut section = telemetry::TelemetrySection {
        enabled: true,
        otlp_endpoint: format!("http://{addr}"),
        timeout_seconds: 1,
        ..Default::default()
    };
    section.traces.sample_ratio = 1.0;
    section.traces.max_queue_spans = 4;
    section.traces.max_export_batch = 2;
    let settings = section.resolve_with(&|_| None).unwrap().unwrap();
    let exporter = telemetry::otlp_exporter(&settings, tokio::runtime::Handle::current()).unwrap();
    let counters = Arc::new(TelemetryCounters::default());
    let (provider, _guard) = install(&settings, exporter, counters.clone());
    let h = Harness::start(|_| {}).await;
    let token = h.mint().await;

    let started = Instant::now();
    let mut slowest = Duration::ZERO;
    for _ in 0..10 {
        let t = Instant::now();
        h.call(&token, None).await;
        slowest = slowest.max(t.elapsed());
    }
    // Each call makes about a dozen spans against a queue of 4 that a hung collector never
    // drains: most are dropped, none is waited for.
    assert!(
        slowest < Duration::from_millis(900),
        "a call waited on the collector: {slowest:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(counters.dropped() > 0, "drops are counted");
    let metrics = h.state.metrics.render();
    assert!(metrics.contains("# TYPE attenuo_telemetry_spans_dropped_total counter\n"));
    assert!(metrics.contains("# TYPE attenuo_telemetry_export_failures_total counter\n"));
    // The export that hangs times out and is counted; shutdown is bounded.
    let deadline = Instant::now() + Duration::from_secs(5);
    while counters.failures() == 0 {
        assert!(Instant::now() < deadline, "the hung export never timed out");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let t = Instant::now();
    let _ = provider.shutdown_with_timeout(Duration::from_millis(300));
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(h.admin_get("/admin/audit/verify").await["ok"], true);
}

/// The requests a [`receiver`] got: headers and body of each.
type Received = Arc<Mutex<Vec<(HeaderMap, Vec<u8>)>>>;

/// A tiny OTLP/HTTP receiver: keeps the body of every `POST /v1/traces`.
async fn receiver() -> (Spawned, Received) {
    let got: Received = Arc::default();
    let keep = got.clone();
    let app = axum::Router::new().route(
        "/v1/traces",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let keep = keep.clone();
            async move {
                keep.lock().unwrap().push((headers, body.to_vec()));
                StatusCode::OK
            }
        }),
    );
    (spawn_router(app).await.unwrap(), got)
}

#[tokio::test(flavor = "current_thread")]
async fn spans_reach_an_otlp_http_receiver_without_secrets() {
    let (collector, got) = receiver().await;
    let mut section = telemetry::TelemetrySection {
        enabled: true,
        otlp_endpoint: collector.url(""),
        ..Default::default()
    };
    section.traces.sample_ratio = 1.0;
    let settings = section.resolve_with(&|_| None).unwrap().unwrap();
    let exporter = telemetry::otlp_exporter(&settings, tokio::runtime::Handle::current()).unwrap();
    let counters = Arc::new(TelemetryCounters::default());
    let (provider, _guard) = install(&settings, exporter, counters.clone());
    let h = Harness::start(|_| {}).await;
    let token = h.mint().await;
    h.call(&token, Some(INBOUND)).await;
    // Flush from a blocking thread: the export request runs on this runtime.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let p = provider.clone();
        tokio::task::spawn_blocking(move || p.force_flush())
            .await
            .unwrap()
            .unwrap();
        let all: Vec<u8> = got
            .lock()
            .unwrap()
            .iter()
            .flat_map(|(_, b)| b.clone())
            .collect();
        if contains(&all, b"mcp.request") && contains(&all, b"attenuo.record_result") {
            break;
        }
        assert!(Instant::now() < deadline, "nothing reached the receiver");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let bodies = got.lock().unwrap().clone();
    assert_eq!(
        bodies[0].0.get("content-type").unwrap(),
        "application/x-protobuf"
    );
    let all: Vec<u8> = bodies.iter().flat_map(|(_, b)| b.clone()).collect();
    for want in ["attenuo.decide", "attenuo-server", "read_file"] {
        assert!(contains(&all, want.as_bytes()), "{want}");
    }
    for secret in [token.as_str(), SUBJECT, ARG_VALUE, RESULT_TEXT] {
        assert!(
            !contains(&all, secret.as_bytes()),
            "a secret reached the collector"
        );
    }
    assert!(counters.exported() > 0);
    assert_eq!(counters.failures(), 0);
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_bad_endpoint_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(dir.path(), "http://127.0.0.1:1/mcp".into(), |c| {
        c.telemetry.otlp_endpoint = "http://collector.example.com:4318".into();
    });
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(err.contains("plain http"), "{err}");
    cfg.telemetry.otlp_endpoint = "https://collector.example.com:4318".into();
    assert!(attenuo_server::build(&cfg).is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn authzen_and_token_routes_get_one_span_each() {
    let sink = Collect::default();
    let (provider, _guard) = install(&settings(2048, 512), sink.clone(), Arc::default());
    let h = Harness::start(|_| {}).await;
    let token = h.mint().await;
    let resp = h
        .client
        .post(h.server.url("/access/v1/evaluation"))
        .bearer_auth(&token)
        .header("traceparent", INBOUND)
        .json(&json!({
            "subject": {"type": "agent", "id": ""},
            "action": {"name": "read_file"},
            "resource": {"type": "tool", "id": "github/read_file", "properties": {"server": "github"}},
            "context": {"input": {"repo": ARG_VALUE}},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let spans = spans_until(&provider, &sink, "attenuo.authzen.evaluate").await;
    let eval = one(&spans, "attenuo.authzen.evaluate");
    // A bearer caller is not a PEP: linked, not adopted.
    assert_ne!(eval.span_context.trace_id().to_string(), INBOUND_TRACE);
    assert_eq!(eval.links.len(), 1);
    assert_eq!(
        attr(eval, "http.route").as_deref(),
        Some("/access/v1/evaluation")
    );
    let decide = one(&spans, "attenuo.decide");
    assert_eq!(decide.parent_span_id, eval.span_context.span_id());
    assert_nothing_forbidden(&spans, &[&token, SUBJECT, ARG_VALUE]);

    sink.0.lock().unwrap().clear();
    let resp = h
        .client
        .post(h.server.url("/token/renew"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16().to_string();
    let spans = spans_until(&provider, &sink, "attenuo.token.renew").await;
    let renew = one(&spans, "attenuo.token.renew");
    assert_eq!(attr(renew, "http.response.status_code"), Some(status));
    assert_nothing_forbidden(&spans, &[&token, SUBJECT]);
}

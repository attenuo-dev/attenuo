//! OpenTelemetry trace export (`[telemetry]`, `docs/design/otel-export.md`, ADR-0012).
//!
//! Off by default. When `[telemetry] enabled = true`, the subscriber [`init`] installs has two
//! layers: the log (the `fmt` layer under `RUST_LOG`, as before) and an OpenTelemetry layer
//! that sees only spans in the [`OTEL_TARGET`] target. Those spans are built with the fields
//! of the design's allow-list (section 3.3) and nothing else, so nothing a log line carries (a
//! subject, an error string, a verifier detail) can reach the collector: enforcement is by
//! construction, not by scrubbing. No span event and no log record is exported.
//!
//! **What is exported.** One trace per proxied MCP request: `mcp.request` (server kind), with
//! `attenuo.authenticate`, `attenuo.session_gate`, one `attenuo.decide` per decided message
//! with its stages (`attenuo.lease_check`, `attenuo.run_state`, `attenuo.policy`,
//! `attenuo.charge`, `attenuo.audit_append`), `attenuo.upstream` (client kind),
//! `attenuo.response` and `attenuo.record_result`; `attenuo.stream_end` when the proxy cuts a
//! stream. `POST /token`, `POST /token/renew` and the AuthZEN routes get one span each
//! ([`trace_route`]), with an `attenuo.decide` child per evaluation.
//!
//! **Trace context.** An inbound W3C `traceparent` on the proxy and token routes is linked to,
//! not adopted (`[telemetry.traces] inbound_mcp = "link"`): the agent cannot choose attenuo's
//! trace id or force sampling. An AuthZEN caller that authenticated as a `[[peps]]` entry with
//! HTTP Basic is the parent (`inbound_authzen = "parent"`). A malformed header is ignored. The
//! upstream request carries attenuo's own `traceparent`, never the client's
//! (`propagate_upstream`). See [`ServerTrace`].
//!
//! **Span to record.** `attenuo.decide`, `attenuo.record_result` and `attenuo.stream_end`
//! carry `attenuo.decision_id` (the record's id) and `attenuo.audit.seq`; the signed record is
//! unchanged (no trace id in the hash chain).
//!
//! **Failure.** Export fails open and never changes an answer: finished spans go to a bounded
//! queue (`max_queue_spans`) drained by one thread ([`BoundedProcessor`]); a full queue drops
//! the span and counts it in `attenuo_telemetry_spans_dropped_total`, a failed export request
//! counts in `attenuo_telemetry_export_failures_total` ([`TelemetryCounters`]). An unreachable
//! collector does not stop the server; a malformed `[telemetry]` section does
//! ([`TelemetrySection::resolve`]). `/readyz` ignores telemetry. On shutdown the queue gets
//! [`TELEMETRY_SHUTDOWN_GRACE`] to drain.
//!
//! Spans go out as OTLP over HTTP with protobuf (`/v1/traces`), through the workspace's
//! `reqwest`. gRPC is not built.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use attenuo_core::{DelegationChain, ToolCall};
use serde::{Deserialize, Serialize};

pub use attenuo_proxy::OTEL_TARGET;

use crate::authz::PipelineDecision;

/// Default of `[telemetry] otlp_endpoint`: a collector's OTLP/HTTP port on loopback.
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://127.0.0.1:4318";
/// The one `[telemetry] protocol` built: OTLP over HTTP with protobuf bodies.
pub const PROTOCOL_HTTP_PROTOBUF: &str = "http/protobuf";
/// The path the OTLP/HTTP trace exporter posts to, appended to a base endpoint.
pub const TRACES_PATH: &str = "/v1/traces";
/// How long the span queue gets to drain at shutdown, after the request drain (the same grace
/// as `[audit.sink]`, [`crate::SINK_SHUTDOWN_GRACE`]). Exit is never delayed past it.
pub const TELEMETRY_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
/// How often the export thread sends what it holds when the batch is not full.
pub const EXPORT_INTERVAL: Duration = Duration::from_secs(5);

/// `[telemetry]`: OpenTelemetry trace export. Off by default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySection {
    /// Export traces. Default `false`: no exporter is built, no exported span is recorded and
    /// nothing is inserted upstream.
    #[serde(default)]
    pub enabled: bool,
    /// The collector's OTLP/HTTP base URL; [`TRACES_PATH`] is appended. Default
    /// [`DEFAULT_OTLP_ENDPOINT`]. No user name or password in the URL: collector credentials
    /// go in `OTEL_EXPORTER_OTLP_HEADERS`, never in the file.
    #[serde(default = "default_endpoint")]
    pub otlp_endpoint: String,
    /// [`PROTOCOL_HTTP_PROTOBUF`], the only one built. `"grpc"` is refused at start.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Timeout of one export request, 1 to 300 seconds. Default 10.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    /// Accept an `http://` endpoint that is not loopback. Default `false`: a non-loopback
    /// endpoint must be `https://` (as `[metrics] allow_public` guards the metrics listener).
    #[serde(default)]
    pub allow_insecure: bool,
    /// The `service.name` resource attribute. Default `attenuo-server`.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// More resource attributes, such as `deployment.environment`.
    #[serde(default)]
    pub resource_attributes: BTreeMap<String, String>,
    /// `[telemetry.traces]`.
    #[serde(default)]
    pub traces: TracesSection,
    /// `[telemetry.metrics]`: OTLP push of the Prometheus series is not built;
    /// `export = true` is refused at start.
    #[serde(default)]
    pub metrics: TelemetryMetricsSection,
}

impl Default for TelemetrySection {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: default_endpoint(),
            protocol: default_protocol(),
            timeout_seconds: default_timeout_seconds(),
            allow_insecure: false,
            service_name: default_service_name(),
            resource_attributes: BTreeMap::new(),
            traces: TracesSection::default(),
            metrics: TelemetryMetricsSection::default(),
        }
    }
}

/// `[telemetry.traces]`: sampling, trace context and the span queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracesSection {
    /// Head sampling of new traces, 0 to 1. Default 0.1. A trusted parent's sampled flag
    /// decides instead in `parent` mode.
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
    /// What an inbound `traceparent` on `/mcp/{server}`, `POST /token` and
    /// `POST /token/renew` does. Default `link`.
    #[serde(default = "default_inbound_mcp")]
    pub inbound_mcp: InboundMode,
    /// What an inbound `traceparent` on the AuthZEN routes does when the caller authenticated
    /// as a `[[peps]]` entry with HTTP Basic. Default `parent`. Any other AuthZEN caller gets
    /// `inbound_mcp`.
    #[serde(default = "default_inbound_authzen")]
    pub inbound_authzen: InboundMode,
    /// Insert attenuo's own `traceparent` on the upstream request. Default `true`.
    #[serde(default = "default_true")]
    pub propagate_upstream: bool,
    /// Most finished spans waiting for export; one more is dropped and counted. Default 2048.
    #[serde(default = "default_max_queue_spans")]
    pub max_queue_spans: usize,
    /// Most spans in one export request, at most `max_queue_spans`. Default 512.
    #[serde(default = "default_max_export_batch")]
    pub max_export_batch: usize,
}

impl Default for TracesSection {
    fn default() -> Self {
        Self {
            sample_ratio: default_sample_ratio(),
            inbound_mcp: default_inbound_mcp(),
            inbound_authzen: default_inbound_authzen(),
            propagate_upstream: true,
            max_queue_spans: default_max_queue_spans(),
            max_export_batch: default_max_export_batch(),
        }
    }
}

/// `[telemetry.metrics]`. Kept so the design's configuration parses with a clear answer: OTLP
/// push of the `/metrics` series is not built (design section 7, step 5); a collector's
/// Prometheus receiver scrapes `[metrics] listen` instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryMetricsSection {
    /// Must stay `false` (the default).
    #[serde(default)]
    pub export: bool,
    /// Unused while `export` is not built. Default 60.
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
}

impl Default for TelemetryMetricsSection {
    fn default() -> Self {
        Self {
            export: false,
            interval_seconds: default_interval_seconds(),
        }
    }
}

/// What an inbound `traceparent` does to an entry-point span (design section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundMode {
    /// The inbound context is the span's parent, and its sampled flag decides sampling.
    Parent,
    /// The span starts a new trace with a link to the inbound context: the caller cannot
    /// choose attenuo's trace id or force sampling.
    Link,
    /// The header is ignored.
    Ignore,
}

fn default_endpoint() -> String {
    DEFAULT_OTLP_ENDPOINT.to_owned()
}
fn default_protocol() -> String {
    PROTOCOL_HTTP_PROTOBUF.to_owned()
}
fn default_timeout_seconds() -> u64 {
    10
}
fn default_service_name() -> String {
    "attenuo-server".to_owned()
}
fn default_sample_ratio() -> f64 {
    0.1
}
fn default_inbound_mcp() -> InboundMode {
    InboundMode::Link
}
fn default_inbound_authzen() -> InboundMode {
    InboundMode::Parent
}
fn default_true() -> bool {
    true
}
fn default_max_queue_spans() -> usize {
    2048
}
fn default_max_export_batch() -> usize {
    512
}
fn default_interval_seconds() -> u64 {
    60
}

/// `[telemetry]` after the environment overrides and the startup checks: what the exporter is
/// built from.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceSettings {
    /// The full URL spans are posted to (`.../v1/traces`).
    pub endpoint: String,
    /// Timeout of one export request.
    pub timeout: Duration,
    /// `service.name`.
    pub service_name: String,
    /// Resource attributes besides `service.name`.
    pub resource_attributes: BTreeMap<String, String>,
    /// Head sampling ratio of new traces.
    pub sample_ratio: f64,
    /// [`TracesSection::inbound_mcp`].
    pub inbound_mcp: InboundMode,
    /// [`TracesSection::inbound_authzen`].
    pub inbound_authzen: InboundMode,
    /// [`TracesSection::propagate_upstream`].
    pub propagate_upstream: bool,
    /// [`TracesSection::max_queue_spans`].
    pub max_queue_spans: usize,
    /// [`TracesSection::max_export_batch`].
    pub max_export_batch: usize,
}

impl TelemetrySection {
    /// [`resolve_with`](Self::resolve_with) over the process environment.
    pub fn resolve(&self) -> anyhow::Result<Option<TraceSettings>> {
        self.resolve_with(&|k| std::env::var(k).ok())
    }

    /// The settings the exporter is built from, or `None` when export is off (`enabled =
    /// false`, or `OTEL_SDK_DISABLED=true`). The standard variables override the file:
    /// `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (used as is) or `OTEL_EXPORTER_OTLP_ENDPOINT`
    /// (a base, [`TRACES_PATH`] appended), `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` or
    /// `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT` or
    /// `OTEL_EXPORTER_OTLP_TIMEOUT` (milliseconds), `OTEL_SERVICE_NAME`,
    /// `OTEL_RESOURCE_ATTRIBUTES` (`k=v,k=v`, over the file's) and `OTEL_TRACES_SAMPLER_ARG`.
    /// `OTEL_EXPORTER_OTLP_HEADERS` (collector credentials) is read by the exporter itself.
    ///
    /// Errors, which stop the server: a protocol other than `http/protobuf`; an endpoint that
    /// is not an `http` or `https` URL with a host, or that carries a user name, password,
    /// query or fragment; a non-loopback `http://` endpoint without `allow_insecure`; a
    /// timeout outside 1 to 300 seconds; a sample ratio outside 0 to 1; a queue or batch size
    /// of 0, a batch larger than the queue or a queue over 1,000,000; an empty service name;
    /// `[telemetry.metrics] export = true`; and, in a build without the `otel` feature,
    /// `enabled = true`.
    pub fn resolve_with(
        &self,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Option<TraceSettings>> {
        let env = |k: &str| env(k).filter(|v| !v.trim().is_empty());
        if !self.enabled {
            return Ok(None);
        }
        if env("OTEL_SDK_DISABLED").is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
            return Ok(None);
        }
        if !cfg!(feature = "otel") {
            anyhow::bail!(
                "[telemetry] enabled = true, but this attenuo-server was built without the \
                 `otel` feature"
            );
        }
        if self.metrics.export {
            anyhow::bail!(
                "[telemetry.metrics] export = true is not built: scrape [metrics] listen with \
                 the collector's Prometheus receiver instead (see the observability guide)"
            );
        }
        let protocol = env("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
            .or_else(|| env("OTEL_EXPORTER_OTLP_PROTOCOL"))
            .unwrap_or_else(|| self.protocol.clone());
        match protocol.trim() {
            PROTOCOL_HTTP_PROTOBUF => {}
            "grpc" => anyhow::bail!(
                "[telemetry] protocol = \"grpc\" is not built; use \"http/protobuf\" (OTLP over \
                 HTTP, port 4318)"
            ),
            other => anyhow::bail!(
                "[telemetry] protocol = {other:?} is not supported; use \"http/protobuf\""
            ),
        }
        let (endpoint, key) = match env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
            Some(full) => (full, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            None => {
                let (base, key) = match env("OTEL_EXPORTER_OTLP_ENDPOINT") {
                    Some(base) => (base, "OTEL_EXPORTER_OTLP_ENDPOINT"),
                    None => (self.otlp_endpoint.clone(), "[telemetry] otlp_endpoint"),
                };
                (
                    format!("{}{TRACES_PATH}", base.trim().trim_end_matches('/')),
                    key,
                )
            }
        };
        check_endpoint(endpoint.trim(), key, self.allow_insecure)?;
        let timeout = match env("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT")
            .or_else(|| env("OTEL_EXPORTER_OTLP_TIMEOUT"))
        {
            Some(ms) => {
                let ms: u64 = ms.trim().parse().map_err(|_| {
                    anyhow::anyhow!("OTEL_EXPORTER_OTLP_TIMEOUT must be milliseconds, got {ms:?}")
                })?;
                Duration::from_millis(ms)
            }
            None => Duration::from_secs(self.timeout_seconds),
        };
        if timeout < Duration::from_secs(1) || timeout > Duration::from_secs(300) {
            anyhow::bail!("[telemetry] timeout_seconds must be 1 to 300");
        }
        let sample_ratio = match env("OTEL_TRACES_SAMPLER_ARG") {
            Some(v) => v.trim().parse::<f64>().map_err(|_| {
                anyhow::anyhow!("OTEL_TRACES_SAMPLER_ARG must be a number from 0 to 1, got {v:?}")
            })?,
            None => self.traces.sample_ratio,
        };
        if !(0.0..=1.0).contains(&sample_ratio) {
            anyhow::bail!("[telemetry.traces] sample_ratio must be from 0 to 1");
        }
        let t = &self.traces;
        if t.max_queue_spans == 0 || t.max_queue_spans > 1_000_000 {
            anyhow::bail!("[telemetry.traces] max_queue_spans must be 1 to 1000000");
        }
        if t.max_export_batch == 0 || t.max_export_batch > t.max_queue_spans {
            anyhow::bail!("[telemetry.traces] max_export_batch must be 1 to max_queue_spans");
        }
        let service_name = env("OTEL_SERVICE_NAME").unwrap_or_else(|| self.service_name.clone());
        if service_name.trim().is_empty() {
            anyhow::bail!("[telemetry] service_name must not be empty");
        }
        let mut resource_attributes = self.resource_attributes.clone();
        if let Some(list) = env("OTEL_RESOURCE_ATTRIBUTES") {
            for pair in list.split(',').filter(|p| !p.trim().is_empty()) {
                let (k, v) = pair.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("OTEL_RESOURCE_ATTRIBUTES entries must be key=value")
                })?;
                resource_attributes.insert(k.trim().to_owned(), v.trim().to_owned());
            }
        }
        Ok(Some(TraceSettings {
            endpoint: endpoint.trim().to_owned(),
            timeout,
            service_name,
            resource_attributes,
            sample_ratio,
            inbound_mcp: t.inbound_mcp,
            inbound_authzen: t.inbound_authzen,
            propagate_upstream: t.propagate_upstream,
            max_queue_spans: t.max_queue_spans,
            max_export_batch: t.max_export_batch,
        }))
    }
}

/// The startup check of an OTLP endpoint (design section 6).
fn check_endpoint(endpoint: &str, key: &str, allow_insecure: bool) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|e| anyhow::anyhow!("{key} is not a URL ({e}): {endpoint:?}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("{key} must be an http:// or https:// URL");
    }
    let Some(host) = url.host_str().filter(|h| !h.is_empty()) else {
        anyhow::bail!("{key} has no host");
    };
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!(
            "{key} must not carry a user name or password; put collector credentials in \
             OTEL_EXPORTER_OTLP_HEADERS"
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("{key} must not carry a query or fragment");
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() == "http" && !loopback && !allow_insecure {
        anyhow::bail!(
            "{key} is plain http to a host that is not loopback; use https:// or set \
             [telemetry] allow_insecure = true"
        );
    }
    Ok(())
}

/// The export counters `/metrics` serves: `attenuo_telemetry_spans_dropped_total` (spans that
/// never reached the exporter: the queue was full, or export had shut down) and
/// `attenuo_telemetry_export_failures_total` (export requests that failed or timed out).
#[derive(Debug, Default)]
pub struct TelemetryCounters {
    /// Spans dropped before export.
    pub spans_dropped: AtomicU64,
    /// Failed export requests.
    pub export_failures: AtomicU64,
    /// Spans handed to the exporter in requests that succeeded.
    pub spans_exported: AtomicU64,
}

impl TelemetryCounters {
    /// Spans dropped so far.
    pub fn dropped(&self) -> u64 {
        self.spans_dropped.load(Ordering::Relaxed)
    }
    /// Failed export requests so far.
    pub fn failures(&self) -> u64 {
        self.export_failures.load(Ordering::Relaxed)
    }
    /// Spans exported so far.
    pub fn exported(&self) -> u64 {
        self.spans_exported.load(Ordering::Relaxed)
    }
}

static COUNTERS: LazyLock<Arc<TelemetryCounters>> = LazyLock::new(Arc::default);

/// The process's export counters: the exporter [`init`] builds counts into them, and
/// `/metrics` reads them (one tracer provider per process, as one subscriber).
pub fn counters() -> &'static Arc<TelemetryCounters> {
    &COUNTERS
}

/// A keyed digest of the originating subject for the exported `attenuo.decide` span
/// (`attenuo.subject_digest`): HMAC-SHA256 under a key derived from the issuer's private key,
/// truncated to 16 hex digits. A plain hash of an email address is reversed by guessing; this
/// one is not without the key, and an operator finds the user through the audit log, not
/// through the tracing backend. The key changes when the issuer key does, and with it every
/// digest (design open question 5).
#[derive(Clone)]
pub struct SubjectDigest(ring::hmac::Key);

impl SubjectDigest {
    /// Label of the key derivation, so the key is used for nothing else.
    const LABEL: &'static [u8] = b"attenuo/telemetry-subject/v1";

    /// Derive the key from `secret` (the issuer's private key material).
    pub fn derive(secret: &[u8]) -> Self {
        let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let derived = ring::hmac::sign(&k, Self::LABEL);
        Self(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            derived.as_ref(),
        ))
    }

    /// The 16-hex-digit digest of `subject`.
    pub fn digest(&self, subject: &str) -> String {
        hex::encode(&ring::hmac::sign(&self.0, subject.as_bytes()).as_ref()[..8])
    }
}

impl std::fmt::Debug for SubjectDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubjectDigest(..)")
    }
}

/// An exported stage span of a decision, with the optional fields any stage records.
macro_rules! stage_span {
    ($name:literal) => {
        tracing::info_span!(
            target: attenuo_proxy::OTEL_TARGET,
            $name,
            attenuo.reason = tracing::field::Empty,
            attenuo.audit.seq = tracing::field::Empty,
            attenuo.budget.exhausted_at = tracing::field::Empty,
        )
    };
}
pub(crate) use stage_span;

/// The exported `attenuo.decide` span of one decision. The server and tool names go out only
/// when they pass the name rule ([`ToolCall::check_names`]); otherwise both are the fixed
/// string `invalid_name` (design section 3.3).
pub(crate) fn decide_span(call: &ToolCall) -> tracing::Span {
    let span = tracing::info_span!(
        target: OTEL_TARGET,
        "attenuo.decide",
        attenuo.server = tracing::field::Empty,
        attenuo.tool = tracing::field::Empty,
        attenuo.decision = tracing::field::Empty,
        attenuo.reason = tracing::field::Empty,
        attenuo.decision_id = tracing::field::Empty,
        attenuo.audit.seq = tracing::field::Empty,
        attenuo.policy_ids = tracing::field::Empty,
        attenuo.tainted = tracing::field::Empty,
        attenuo.chain_id = tracing::field::Empty,
        attenuo.subject_digest = tracing::field::Empty,
        attenuo.limit.kind = tracing::field::Empty,
        attenuo.budget.exhausted_at = tracing::field::Empty,
    );
    if !span.is_disabled() {
        if call.check_names().is_ok() {
            span.record("attenuo.server", call.server.as_str());
            span.record("attenuo.tool", call.tool.as_str());
        } else {
            span.record("attenuo.server", attenuo_proxy::REASON_INVALID_NAME);
            span.record("attenuo.tool", attenuo_proxy::REASON_INVALID_NAME);
        }
    }
    span
}

/// Fill in the outcome on an `attenuo.decide` span: decision, reason, record id and seq,
/// policy ids, the run's chain id and the subject digest.
pub(crate) fn record_decision(
    span: &tracing::Span,
    out: &PipelineDecision,
    chain: &DelegationChain,
    digest: Option<&SubjectDigest>,
) {
    if span.is_disabled() {
        return;
    }
    span.record("attenuo.decision", out.decision.as_str());
    span.record("attenuo.reason", out.reason.as_str());
    span.record(
        "attenuo.decision_id",
        tracing::field::display(out.decision_id),
    );
    if let Some(seq) = out.audit_seq {
        span.record("attenuo.audit.seq", seq);
    }
    if !out.policy_ids.is_empty() {
        span.record("attenuo.policy_ids", out.policy_ids.join(",").as_str());
    }
    if let Some(chain_id) = attenuo_core::chain_id_of(chain) {
        span.record("attenuo.chain_id", chain_id.as_str());
    }
    if let Some(d) = digest {
        span.record(
            "attenuo.subject_digest",
            d.digest(&chain.originating_user.subject).as_str(),
        );
    }
}

/// Record on the current `attenuo.decide` span which run limit was met and where.
pub(crate) fn record_exhausted(kind: attenuo_core::LimitKind, at: crate::metrics::ExhaustedAt) {
    let span = tracing::Span::current();
    span.record("attenuo.limit.kind", kind.as_str());
    let at = match at {
        crate::metrics::ExhaustedAt::Check => "check",
        crate::metrics::ExhaustedAt::Charge => "charge",
    };
    span.record("attenuo.budget.exhausted_at", at);
}

/// What a blocking-pool closure needs to stay inside the request that queued it: the
/// subscriber, the current span (the log context) and the current trace context (the parent
/// of the spans it opens). `spawn_blocking` carries none of them (design section 3.2,
/// "Blocking pool").
pub(crate) struct Carry {
    dispatch: tracing::Dispatch,
    span: tracing::Span,
    #[cfg(feature = "otel")]
    cx: opentelemetry::Context,
}

impl Carry {
    /// Capture them on the calling thread.
    pub(crate) fn capture() -> Self {
        Self {
            dispatch: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::current(),
            #[cfg(feature = "otel")]
            cx: opentelemetry::Context::current(),
        }
    }

    /// Run `f` under them, on whatever thread this is.
    pub(crate) fn run<R>(self, f: impl FnOnce() -> R) -> R {
        let Self {
            dispatch,
            span,
            #[cfg(feature = "otel")]
            cx,
        } = self;
        tracing::dispatcher::with_default(&dispatch, || {
            #[cfg(feature = "otel")]
            let _attached = cx.attach();
            span.in_scope(f)
        })
    }
}

/// The server's [`attenuo_proxy::TraceHook`]: turns an inbound `traceparent` into a parent or
/// a link as `[telemetry.traces]` says, gives the upstream request attenuo's own context, and
/// links spans recorded after a response to the request that made the call.
#[derive(Debug, Clone)]
pub struct ServerTrace {
    /// `inbound_mcp`: the proxy and token routes, and AuthZEN callers that are not PEPs.
    pub inbound_mcp: InboundMode,
    /// `inbound_authzen`: AuthZEN callers that authenticated as `[[peps]]` with HTTP Basic.
    pub inbound_authzen: InboundMode,
    /// `propagate_upstream`.
    pub propagate_upstream: bool,
}

impl ServerTrace {
    /// The hook for these settings.
    pub fn new(settings: &TraceSettings) -> Self {
        Self {
            inbound_mcp: settings.inbound_mcp,
            inbound_authzen: settings.inbound_authzen,
            propagate_upstream: settings.propagate_upstream,
        }
    }

    /// Apply `mode` to `span` for `inbound`. Before the span is first entered.
    pub fn adopt(
        &self,
        mode: InboundMode,
        span: &tracing::Span,
        inbound: Option<attenuo_proxy::TraceParent>,
    ) {
        #[cfg(feature = "otel")]
        otel::adopt(mode, span, inbound);
        #[cfg(not(feature = "otel"))]
        let _ = (mode, span, inbound);
    }
}

impl attenuo_proxy::TraceHook for ServerTrace {
    fn inbound(&self, span: &tracing::Span, inbound: Option<attenuo_proxy::TraceParent>) {
        self.adopt(self.inbound_mcp, span, inbound);
    }

    fn current(&self) -> Option<attenuo_proxy::TraceParent> {
        #[cfg(feature = "otel")]
        return otel::current();
        #[cfg(not(feature = "otel"))]
        None
    }

    fn outbound(&self, span: &tracing::Span) -> Option<attenuo_proxy::TraceParent> {
        if !self.propagate_upstream {
            return None;
        }
        #[cfg(feature = "otel")]
        return otel::context_of(span);
        #[cfg(not(feature = "otel"))]
        {
            let _ = span;
            None
        }
    }

    fn link_detached(&self, span: &tracing::Span, origin: attenuo_proxy::TraceParent) {
        #[cfg(feature = "otel")]
        otel::link_detached(span, origin);
        #[cfg(not(feature = "otel"))]
        let _ = (span, origin);
    }
}

/// The exported span of a `POST /token`, `POST /token/renew` or AuthZEN request, around the
/// handler: `attenuo.token.exchange` (renamed `attenuo.token.root` by the handler for an IdP
/// intake), `attenuo.token.renew` or `attenuo.authzen.evaluate`, with the method, the route
/// template and the status code. An inbound `traceparent` is the parent only on an AuthZEN
/// route whose caller authenticates as a `[[peps]]` entry with HTTP Basic
/// (`inbound_authzen`); everything else gets `inbound_mcp`. Mounted only when tracing is on.
pub async fn trace_route(
    axum::extract::State(state): axum::extract::State<Arc<crate::AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use tracing::Instrument;
    let Some(trace) = state.trace.clone() else {
        return next.run(req).await;
    };
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or(attenuo_proxy::http_trace::UNMATCHED_ROUTE, |m| m.as_str())
        .to_owned();
    let (name, authzen) = match route.as_str() {
        "/token" => ("attenuo.token.exchange", false),
        "/token/renew" => ("attenuo.token.renew", false),
        "/access/v1/evaluation" | "/access/v1/evaluations" => ("attenuo.authzen.evaluate", true),
        _ => return next.run(req).await,
    };
    let span = tracing::info_span!(
        target: OTEL_TARGET,
        "attenuo.route",
        otel.name = name,
        otel.kind = "server",
        http.request.method = %req.method(),
        http.route = %route,
        http.response.status_code = tracing::field::Empty,
    );
    let inbound = attenuo_proxy::TraceParent::from_headers(req.headers());
    let mode = if authzen
        && inbound.is_some()
        && crate::clientauth::authenticate(
            crate::clientauth::ClientKind::Pep,
            &state.peps,
            req.headers(),
            None,
            None,
        )
        .is_ok()
    {
        trace.inbound_authzen
    } else {
        trace.inbound_mcp
    };
    trace.adopt(mode, &span, inbound);
    let response = next.run(req).instrument(span.clone()).await;
    span.record("http.response.status_code", response.status().as_u16());
    response
}

/// The subscriber's log layer: the `fmt` layer under `RUST_LOG` (default `info`), which never
/// sees spans in [`OTEL_TARGET`], so log lines read as they did without telemetry.
pub fn log_layer<S>() -> impl tracing_subscriber::Layer<S> + Send + Sync
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use tracing_subscriber::filter::FilterExt;
    use tracing_subscriber::Layer;
    let env = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt::layer().with_filter(env.and(tracing_subscriber::filter::filter_fn(
        |m| m.target() != OTEL_TARGET,
    )))
}

/// What [`init`] leaves running: the tracer provider, flushed by [`TelemetryGuard::shutdown`].
#[derive(Debug, Default)]
pub struct TelemetryGuard {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl TelemetryGuard {
    /// Whether spans are being exported.
    pub fn exporting(&self) -> bool {
        #[cfg(feature = "otel")]
        return self.provider.is_some();
        #[cfg(not(feature = "otel"))]
        false
    }

    /// Flush the span queue and stop the exporter, waiting at most `grace`. Never fails: an
    /// error is logged.
    pub fn shutdown(self, grace: Duration) {
        #[cfg(feature = "otel")]
        if let Some(p) = self.provider {
            if let Err(e) = p.shutdown_with_timeout(grace) {
                tracing::warn!(error = %e, "telemetry export did not drain before shutdown");
            }
        }
        #[cfg(not(feature = "otel"))]
        let _ = grace;
    }
}

/// Install the process's subscriber: the log layer, and when `[telemetry]` resolves to
/// [`TraceSettings`], the OpenTelemetry layer with the OTLP/HTTP exporter. Call once, from
/// inside the tokio runtime (the exporter sends its requests on it). An invalid `[telemetry]`
/// section is an error; an unreachable collector is not.
pub fn init(section: &TelemetrySection) -> anyhow::Result<TelemetryGuard> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let settings = section.resolve()?;
    let registry = tracing_subscriber::registry().with(log_layer());
    #[cfg(feature = "otel")]
    if let Some(settings) = settings {
        let exporter = otel::otlp_exporter(&settings, tokio::runtime::Handle::current())?;
        let provider = otel::tracer_provider(
            &settings,
            exporter,
            counters().clone(),
            tokio::runtime::Handle::current(),
        );
        registry.with(otel::layer(&provider)).try_init()?;
        tracing::info!(
            endpoint = %settings.endpoint,
            sample_ratio = settings.sample_ratio,
            "telemetry: exporting traces over OTLP/HTTP"
        );
        return Ok(TelemetryGuard {
            provider: Some(provider),
        });
    }
    let _ = settings;
    registry.try_init()?;
    Ok(TelemetryGuard::default())
}

#[cfg(feature = "otel")]
pub use otel::{layer, otlp_exporter, tracer_provider, BoundedProcessor};

#[cfg(feature = "otel")]
mod otel {
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::{
        self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use attenuo_proxy::TraceParent;
    use axum::body::Bytes;
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState, TracerProvider,
    };
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::trace::{
        Sampler, SdkTracerProvider, Span, SpanData, SpanExporter, SpanProcessor,
    };
    use opentelemetry_sdk::Resource;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    use super::{InboundMode, TelemetryCounters, TraceSettings, EXPORT_INTERVAL, OTEL_TARGET};

    fn span_context(tp: TraceParent) -> SpanContext {
        SpanContext::new(
            TraceId::from_bytes(tp.trace_id),
            SpanId::from_bytes(tp.parent_id),
            TraceFlags::new(tp.flags),
            true,
            TraceState::default(),
        )
    }

    fn trace_parent(sc: &SpanContext) -> Option<TraceParent> {
        sc.is_valid().then(|| TraceParent {
            trace_id: sc.trace_id().to_bytes(),
            parent_id: sc.span_id().to_bytes(),
            flags: sc.trace_flags().to_u8(),
        })
    }

    pub(super) fn adopt(mode: InboundMode, span: &tracing::Span, inbound: Option<TraceParent>) {
        let Some(tp) = inbound else {
            return;
        };
        match mode {
            InboundMode::Parent => {
                let cx = opentelemetry::Context::new().with_remote_span_context(span_context(tp));
                let _ = span.set_parent(cx);
            }
            InboundMode::Link => span.add_link(span_context(tp)),
            InboundMode::Ignore => {}
        }
    }

    pub(super) fn current() -> Option<TraceParent> {
        trace_parent(opentelemetry::Context::current().span().span_context())
    }

    pub(super) fn context_of(span: &tracing::Span) -> Option<TraceParent> {
        trace_parent(span.context().span().span_context())
    }

    pub(super) fn link_detached(span: &tracing::Span, origin: TraceParent) {
        if opentelemetry::Context::current()
            .span()
            .span_context()
            .is_valid()
        {
            return;
        }
        span.add_link(span_context(origin));
    }

    /// The OpenTelemetry layer over `provider`: spans in [`OTEL_TARGET`] only, with no file,
    /// line, module, thread, target or timing attributes of its own.
    pub fn layer<S>(provider: &SdkTracerProvider) -> impl tracing_subscriber::Layer<S>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        use tracing_subscriber::Layer;
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("attenuo"))
            .with_location(false)
            .with_threads(false)
            .with_target(false)
            .with_level(false)
            .with_tracked_inactivity(false)
            .with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target(OTEL_TARGET, tracing::Level::TRACE),
            )
    }

    /// A tracer provider that samples as `settings` say and hands finished spans to
    /// `exporter` through a [`BoundedProcessor`] counting into `counters`. Export requests
    /// run on `rt`.
    pub fn tracer_provider<E: SpanExporter + 'static>(
        settings: &TraceSettings,
        mut exporter: E,
        counters: Arc<TelemetryCounters>,
        rt: tokio::runtime::Handle,
    ) -> SdkTracerProvider {
        let resource = Resource::builder_empty()
            .with_service_name(settings.service_name.clone())
            .with_attributes(
                settings
                    .resource_attributes
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            )
            .build();
        exporter.set_resource(&resource);
        let processor = BoundedProcessor::spawn(
            exporter,
            settings.max_queue_spans,
            settings.max_export_batch,
            EXPORT_INTERVAL,
            counters,
            rt,
        );
        SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                settings.sample_ratio,
            ))))
            .with_resource(resource)
            .build()
    }

    /// The OTLP/HTTP (protobuf) span exporter for `settings`, sending through the workspace's
    /// `reqwest` on `rt`. `OTEL_EXPORTER_OTLP_HEADERS` is read here, by the exporter.
    pub fn otlp_exporter(
        settings: &TraceSettings,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<opentelemetry_otlp::SpanExporter> {
        let client = OtlpClient {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(settings.timeout)
                .build()?,
            rt,
            timeout: settings.timeout,
        };
        Ok(opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(client)
            .with_endpoint(settings.endpoint.clone())
            .with_timeout(settings.timeout)
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .build()?)
    }

    /// Largest collector response read back: the answer to an export is a few bytes.
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;

    /// [`opentelemetry_http::HttpClient`] over the workspace's `reqwest` 0.12. The request runs
    /// as a task on the server's runtime, so the export thread needs no runtime of its own.
    #[derive(Debug, Clone)]
    struct OtlpClient {
        client: reqwest::Client,
        rt: tokio::runtime::Handle,
        timeout: Duration,
    }

    #[async_trait]
    impl opentelemetry_http::HttpClient for OtlpClient {
        async fn send_bytes(
            &self,
            request: axum::http::Request<Bytes>,
        ) -> Result<axum::http::Response<Bytes>, opentelemetry_http::HttpError> {
            let (parts, body) = request.into_parts();
            let req = self
                .client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body);
            let timeout = self.timeout;
            let task = self.rt.spawn(async move {
                tokio::time::timeout(timeout, async move {
                    let mut resp = req.send().await?;
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    let mut body = Vec::new();
                    while let Some(chunk) = resp.chunk().await? {
                        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                            break;
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Ok::<_, reqwest::Error>((status, headers, body))
                })
                .await
            });
            let (status, headers, body) = task
                .await
                .map_err(|e| format!("export task: {e}"))?
                .map_err(|_| "export request timed out".to_string())??;
            let mut resp = axum::http::Response::new(Bytes::from(body));
            *resp.status_mut() = status;
            *resp.headers_mut() = headers;
            Ok(resp)
        }
    }

    enum Control {
        Flush(SyncSender<()>),
        Shutdown(SyncSender<()>),
    }

    /// How often the export thread looks for a flush or a shutdown while idle.
    const CONTROL_POLL: Duration = Duration::from_millis(100);

    /// The span processor in front of the exporter (design section 6): a bounded queue of
    /// `max_queue` finished spans, drained by one thread that exports batches of at most
    /// `max_batch`. A full queue drops the span and counts it; it never blocks the thread
    /// that ended the span, so a slow or dead collector cannot slow a decision. A failed or
    /// timed-out export request is counted and its spans are not retried.
    #[derive(Debug)]
    pub struct BoundedProcessor {
        spans: SyncSender<SpanData>,
        control: Mutex<mpsc::Sender<ControlMsg>>,
        counters: Arc<TelemetryCounters>,
        stopped: std::sync::atomic::AtomicBool,
    }

    /// [`Control`] wrapped so the processor stays `Debug`.
    struct ControlMsg(Control);

    impl std::fmt::Debug for ControlMsg {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ControlMsg")
        }
    }

    impl BoundedProcessor {
        /// Start the export thread.
        pub fn spawn<E: SpanExporter + 'static>(
            exporter: E,
            max_queue: usize,
            max_batch: usize,
            interval: Duration,
            counters: Arc<TelemetryCounters>,
            rt: tokio::runtime::Handle,
        ) -> Self {
            let (spans, rx) = mpsc::sync_channel(max_queue.max(1));
            let (control, ctl_rx) = mpsc::channel();
            let worker_counters = counters.clone();
            let started = std::thread::Builder::new()
                .name("attenuo-otel-export".into())
                .spawn(move || {
                    Worker {
                        exporter,
                        rx,
                        control: ctl_rx,
                        max_batch: max_batch.max(1),
                        interval,
                        counters: worker_counters,
                        rt,
                        failing: false,
                    }
                    .run()
                });
            if let Err(e) = started {
                tracing::error!(error = %e, "telemetry export thread did not start; spans are dropped");
            }
            Self {
                spans,
                control: Mutex::new(control),
                counters,
                stopped: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn ask(&self, make: fn(SyncSender<()>) -> Control, timeout: Duration) -> OTelSdkResult {
            let (ack, done) = mpsc::sync_channel(1);
            let sent = self
                .control
                .lock()
                .map_err(|_| OTelSdkError::InternalFailure("control lock poisoned".into()))?
                .send(ControlMsg(make(ack)));
            if sent.is_err() {
                return Err(OTelSdkError::AlreadyShutdown);
            }
            done.recv_timeout(timeout)
                .map_err(|_| OTelSdkError::Timeout(timeout))
        }
    }

    impl SpanProcessor for BoundedProcessor {
        fn on_start(&self, _span: &mut Span, _cx: &opentelemetry::Context) {}

        fn on_end(&self, span: SpanData) {
            if !span.span_context.is_sampled() {
                return;
            }
            match self.spans.try_send(span) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    self.counters.spans_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        fn force_flush(&self) -> OTelSdkResult {
            self.ask(Control::Flush, super::TELEMETRY_SHUTDOWN_GRACE)
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            if self.stopped.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            self.ask(Control::Shutdown, timeout)
        }
    }

    struct Worker<E> {
        exporter: E,
        rx: Receiver<SpanData>,
        control: mpsc::Receiver<ControlMsg>,
        max_batch: usize,
        interval: Duration,
        counters: Arc<TelemetryCounters>,
        rt: tokio::runtime::Handle,
        /// The last export failed: the next failure is not logged again.
        failing: bool,
    }

    impl<E: SpanExporter> Worker<E> {
        fn run(mut self) {
            let mut batch = Vec::with_capacity(self.max_batch);
            let mut due = Instant::now() + self.interval;
            loop {
                let wait = due
                    .saturating_duration_since(Instant::now())
                    .min(CONTROL_POLL);
                match self.rx.recv_timeout(wait) {
                    Ok(span) => {
                        batch.push(span);
                        if batch.len() >= self.max_batch {
                            self.export(&mut batch);
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        self.export(&mut batch);
                        return;
                    }
                }
                if Instant::now() >= due {
                    self.export(&mut batch);
                    due = Instant::now() + self.interval;
                }
                match self.control.try_recv() {
                    Ok(ControlMsg(Control::Flush(ack))) => {
                        self.drain(&mut batch);
                        let _ = ack.send(());
                    }
                    Ok(ControlMsg(Control::Shutdown(ack))) => {
                        self.drain(&mut batch);
                        let _ = self.exporter.shutdown();
                        let _ = ack.send(());
                        return;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        self.drain(&mut batch);
                        return;
                    }
                }
            }
        }

        /// Export everything queued now.
        fn drain(&mut self, batch: &mut Vec<SpanData>) {
            while let Ok(span) = self.rx.try_recv() {
                batch.push(span);
                if batch.len() >= self.max_batch {
                    self.export(batch);
                }
            }
            self.export(batch);
        }

        fn export(&mut self, batch: &mut Vec<SpanData>) {
            if batch.is_empty() {
                return;
            }
            let spans = std::mem::replace(batch, Vec::with_capacity(self.max_batch));
            let n = spans.len() as u64;
            match self.rt.block_on(self.exporter.export(spans)) {
                Ok(()) => {
                    self.counters.spans_exported.fetch_add(n, Ordering::Relaxed);
                    if self.failing {
                        tracing::info!("telemetry export recovered");
                    }
                    self.failing = false;
                }
                Err(e) => {
                    self.counters
                        .export_failures
                        .fetch_add(1, Ordering::Relaxed);
                    if !self.failing {
                        tracing::warn!(
                            error = %e,
                            spans = n,
                            "telemetry export failed; spans dropped (counted in \
                             attenuo_telemetry_export_failures_total)"
                        );
                    }
                    self.failing = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn section(toml: &str) -> TelemetrySection {
        crate::Config::from_toml(toml).unwrap().telemetry
    }

    fn resolve(
        s: &TelemetrySection,
        env: &[(&str, &str)],
    ) -> anyhow::Result<Option<TraceSettings>> {
        let env: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        s.resolve_with(&|k| env.get(k).cloned())
    }

    #[test]
    fn off_by_default_and_when_disabled() {
        let s = section("");
        assert!(!s.enabled);
        assert_eq!(s, TelemetrySection::default());
        assert_eq!(resolve(&s, &[]).unwrap(), None);
        // An endpoint that would be refused does not matter while export is off.
        let s = section("[telemetry]\notlp_endpoint = \"ftp://x\"\n");
        assert_eq!(resolve(&s, &[]).unwrap(), None);
    }

    #[test]
    fn unknown_keys_are_refused() {
        for bad in [
            "[telemetry]\nendpoint = \"http://127.0.0.1:4318\"\n",
            "[telemetry.traces]\ninbound = \"link\"\n",
            "[telemetry.traces]\ninbound_mcp = \"child\"\n",
            "[telemetry.metrics]\npush = true\n",
        ] {
            assert!(crate::Config::from_toml(bad).is_err(), "{bad}");
        }
    }

    #[cfg(feature = "otel")]
    #[test]
    fn on_with_an_endpoint() {
        let s = section(
            "[telemetry]\nenabled = true\notlp_endpoint = \"https://otel.example.com:4318/\"\n\
             resource_attributes = { \"deployment.environment\" = \"prod\" }\n\
             [telemetry.traces]\nsample_ratio = 1.0\ninbound_mcp = \"ignore\"\n\
             propagate_upstream = false\nmax_queue_spans = 16\nmax_export_batch = 4\n",
        );
        let t = resolve(&s, &[]).unwrap().unwrap();
        assert_eq!(t.endpoint, "https://otel.example.com:4318/v1/traces");
        assert_eq!(t.timeout, Duration::from_secs(10));
        assert_eq!(t.service_name, "attenuo-server");
        assert_eq!(t.resource_attributes["deployment.environment"], "prod");
        assert_eq!(t.sample_ratio, 1.0);
        assert_eq!(t.inbound_mcp, InboundMode::Ignore);
        assert_eq!(t.inbound_authzen, InboundMode::Parent);
        assert!(!t.propagate_upstream);
        assert_eq!((t.max_queue_spans, t.max_export_batch), (16, 4));
        // Defaults: loopback http is fine.
        let d = resolve(&section("[telemetry]\nenabled = true\n"), &[])
            .unwrap()
            .unwrap();
        assert_eq!(d.endpoint, "http://127.0.0.1:4318/v1/traces");
        assert_eq!(d.sample_ratio, 0.1);
        assert_eq!(d.inbound_mcp, InboundMode::Link);
        assert!(d.propagate_upstream);
    }

    #[cfg(feature = "otel")]
    #[test]
    fn environment_overrides_the_file() {
        let s = section("[telemetry]\nenabled = true\n");
        let t = resolve(
            &s,
            &[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:14318"),
                ("OTEL_SERVICE_NAME", "attenuo-eu"),
                ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
                ("OTEL_TRACES_SAMPLER_ARG", "0.5"),
                ("OTEL_RESOURCE_ATTRIBUTES", "a=1, b = 2"),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(t.endpoint, "http://localhost:14318/v1/traces");
        assert_eq!(t.service_name, "attenuo-eu");
        assert_eq!(t.timeout, Duration::from_millis(2500));
        assert_eq!(t.sample_ratio, 0.5);
        assert_eq!(t.resource_attributes["b"], "2");
        let t = resolve(
            &s,
            &[(
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "http://127.0.0.1:9/custom",
            )],
        )
        .unwrap()
        .unwrap();
        assert_eq!(t.endpoint, "http://127.0.0.1:9/custom");
        assert_eq!(resolve(&s, &[("OTEL_SDK_DISABLED", "TRUE")]).unwrap(), None);
    }

    #[cfg(feature = "otel")]
    #[test]
    fn bad_settings_refuse_to_start() {
        for (toml, env, want) in [
            ("otlp_endpoint = \"not a url\"", vec![], "is not a URL"),
            (
                "otlp_endpoint = \"ftp://127.0.0.1:4318\"",
                vec![],
                "http:// or https://",
            ),
            (
                "otlp_endpoint = \"http://user:pw@127.0.0.1:4318\"",
                vec![],
                "user name or password",
            ),
            (
                "otlp_endpoint = \"http://127.0.0.1:4318?x=1\"",
                vec![],
                "query or fragment",
            ),
            (
                "otlp_endpoint = \"http://collector.internal:4318\"",
                vec![],
                "plain http",
            ),
            ("protocol = \"grpc\"", vec![], "not built"),
            ("protocol = \"http/json\"", vec![], "not supported"),
            ("timeout_seconds = 0", vec![], "timeout_seconds"),
            ("service_name = \" \"", vec![], "service_name"),
            (
                "",
                vec![("OTEL_EXPORTER_OTLP_ENDPOINT", "http://10.0.0.5:4318")],
                "OTEL_EXPORTER_OTLP_ENDPOINT is plain http",
            ),
            (
                "",
                vec![("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")],
                "not built",
            ),
            ("", vec![("OTEL_TRACES_SAMPLER_ARG", "2")], "sample_ratio"),
            (
                "",
                vec![("OTEL_EXPORTER_OTLP_TIMEOUT", "soon")],
                "milliseconds",
            ),
        ] {
            let s = section(&format!("[telemetry]\nenabled = true\n{toml}\n"));
            let err = resolve(&s, &env).unwrap_err().to_string();
            assert!(err.contains(want), "{toml} {env:?}: {err}");
        }
        for (traces, want) in [
            ("sample_ratio = 1.5", "sample_ratio"),
            ("sample_ratio = -0.1", "sample_ratio"),
            ("max_queue_spans = 0", "max_queue_spans"),
            ("max_export_batch = 0", "max_export_batch"),
            (
                "max_queue_spans = 8\nmax_export_batch = 9",
                "max_export_batch",
            ),
        ] {
            let s = section(&format!(
                "[telemetry]\nenabled = true\n[telemetry.traces]\n{traces}\n"
            ));
            let err = resolve(&s, &[]).unwrap_err().to_string();
            assert!(err.contains(want), "{traces}: {err}");
        }
        let s = section("[telemetry]\nenabled = true\n[telemetry.metrics]\nexport = true\n");
        assert!(resolve(&s, &[])
            .unwrap_err()
            .to_string()
            .contains("not built"));
        // Plain http to another host is accepted when the operator says so.
        let s = section(
            "[telemetry]\nenabled = true\notlp_endpoint = \"http://collector.internal:4318\"\n\
             allow_insecure = true\n",
        );
        assert!(resolve(&s, &[]).unwrap().is_some());
    }

    #[test]
    fn subject_digest_is_keyed_and_short() {
        let a = SubjectDigest::derive(b"key one");
        let b = SubjectDigest::derive(b"key two");
        let d = a.digest("alice@example.com");
        assert_eq!(d.len(), 16);
        assert!(d.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(d, a.digest("alice@example.com"));
        assert_ne!(d, b.digest("alice@example.com"));
        assert!(!d.contains("alice"));
    }
}

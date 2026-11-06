# OpenTelemetry export: design

- Status: proposed, not accepted. Nothing in this note changes what the server exports today: Prometheus text on the side listener ([HTTP API: metrics](../reference/http-api.md#metrics)), log lines on standard output ([deploy guide: logging](../guides/deploying.md#logging)), and the decision id on every answer.
- Date: 2026-11-06. Base: `main` at 6951476.
- Related: [server pipeline](server.md), [deploy guide: what to monitor](../guides/deploying.md#what-to-monitor), [HTTP API: metrics](../reference/http-api.md#metrics), [performance](performance.md) (the per-stage timing that `proxy_stage_seconds` reports), [multi-replica readiness](multi-replica.md) (per-process metrics), [related work: AgentGateway](../research/related-work.md#agentgateway-linux-foundation), [RFC-0001](../spec/rfc-0001-attenuo.md) section 8 ("Not a general MCP gateway"), [audit log](../concepts/audit-log.md).

Operators who run an OpenTelemetry collector ask for two things: traces of each MCP call through attenuo, and the existing metrics over OTLP instead of a scrape. This note reads what the server and the proxy emit today from the code at 6951476, lists the spans a trace per call would need and which fields may leave the process, proposes how a trace context would travel and how a span links to the signed audit record, and ranks an implementation path. It proposes no code in this change.

## 1. Problem

RFC-0001 section 8 says routing, rate limits, OTel and tool federation belong to gateways such as AgentGateway, which ships OpenTelemetry ([related work](../research/related-work.md#agentgateway-linux-foundation)). That stays true for the gateway's own concerns. Two gaps are left that a gateway cannot fill:

- **The integrated proxy has no gateway in front.** In the common deployment the agent talks to `/mcp/{server}` on attenuo and attenuo talks to the upstream MCP server. The agent's trace ends at attenuo's port and the upstream's trace starts fresh, so the call has no trace across the one component that decided it. The only correlation today is `X-Attenuo-Decision-Id` and the audit log.
- **A gateway sees attenuo as one opaque hop.** When AgentGateway or another PEP asks attenuo through AuthZEN, its span records the latency of the PDP call and the answer. It cannot see which stage took the time (lease check, run state, Cedar, the charge, the audit append), which lease failed, which policies decided, or which signed record holds the decision. Those exist only inside attenuo.

What attenuo's own export would add is therefore narrow: spans for the stages of an authorization decision, carrying ids that lead to the signed record, joined to the caller's and the upstream's traces. What it would not add keeps it out of the gateway role: no routing, retries, rate limits or federation; no request or response bodies; no OTel logs signal; no attributes beyond a fixed allowlist. The audit log stays the record (the deploy guide's "Do not rely on stdout for forensics" applies to traces as well), and an exporter failure never changes a decision.

## 2. What exists today

- **Metrics.** `crates/attenuo-server/src/metrics.rs` is hand-rolled, with no metrics dependency: atomics, two maps behind mutexes, two fixed histogram bucket sets (`BUCKETS` for `authorize_duration_seconds`, `STAGE_BUCKETS` for `proxy_stage_seconds`), and a text writer for Prometheus format 0.0.4. Label values come from fixed sets. `GET /metrics` is served only on `[metrics] listen` (default `127.0.0.1:9100`), unauthenticated, and the server refuses a non-loopback address without `allow_public = true`. HTTP series are labelled by the route template (`MatchedPath`), never the URI.
- **Logs.** `crates/attenuo-server/src/main.rs` installs `tracing_subscriber::fmt()` with an `EnvFilter` from `RUST_LOG` (default `info`). The workspace enables only the `env-filter` feature of `tracing-subscriber` (`Cargo.toml`), so output is the human text format, not JSON. Caller-controlled strings are Debug-formatted so a newline cannot forge a line (SR-18), and session ids appear as their 12-hex-digit tag (`session.rs::session_tag`).
- **Decision ids.** Every authorized answer carries `X-Attenuo-Decision-Id` (`proxy.rs::DECISION_ID_HEADER`), and denials carry `data.decision_id`. `GET /admin/audit/records/{id}` returns the entry for that id ([HTTP API](../reference/http-api.md)). The AuthZEN routes echo `X-Request-ID` (`routes/authzen.rs::echo_request_id`).
- **No trace context.** Nothing reads `traceparent`. The proxy forwards only `accept`, `content-type` and `last-event-id` upstream (`proxy.rs::FORWARD_REQUEST_HEADERS`), so a client's `traceparent` is dropped today.

## 3. Inventory

### 3.1 Spans and events in the code

Counted with `grep` for `tracing::` macros, `#[instrument]`, `info_span!` and `debug_span!` in `crates/attenuo-server/src` and `crates/attenuo-proxy/src`.

| Item | Where | Fields | Notes for export |
|---|---|---|---|
| `mcp_request` span | `crates/attenuo-proxy/src/proxy.rs::request_span`, entered with `.instrument(span)` around the `GET`/`DELETE` and the `POST` handlers | `server`, `agent`, `subject` (Debug, in clear), `chain_depth`, `session` (tag) | The only named span. Carries the originating subject in clear, so it must not reach an exporter as it is. |
| `request` span | `tower_http::trace::TraceLayer::new_for_http().make_span_with(attenuo_proxy::http_trace::request_span)` on the API router (`lib.rs`), the proxy router (`proxy.rs`) and the console listener (`admin_ui.rs`) | `method`, `route` (the route template from `MatchedPath`, or `unmatched`), `version`; same name, level (`DEBUG`) and target as tower-http's default | Before SR-90 this was tower-http's default span, which recorded the full URI with its query string, so `GET /admin/audit?subject=...` put a subject in the debug log and would have exported it. It now carries the route template, the label the metrics already use, and is safe to export. |
| Events | 191 macro calls: 80 `warn!`, 47 `error!`, 38 `info!`, 26 `debug!`; most in `proxy.rs` (45), `authz/` (30, counted before the split in #180), `state.rs` (22) | Mixed | Many carry `subject`, `error = %e` strings or verifier detail (SR-17 moved verifier detail out of answers and into debug lines). Not safe to export wholesale. |
| `decision` event | `crates/attenuo-server/src/authz/pipeline.rs`, `info!`, after the append | `decision`, `reason`, `subject`, `agent`, `server`, `tool`, `seq` | Runs on the blocking pool. `on_blocking_pool` (`authz/pipeline.rs`) and `AppState::blocking` (`state.rs`) call `spawn_blocking` without carrying the current span, so this line is outside `mcp_request` today. |
| `decision stages` event | `authz/pipeline.rs`, `debug!` | `lease_check_us`, `policy_us`, `audit_append_us` | Same timings as `Stage::LeaseCheck`, `Stage::Policy`, `Stage::AuditAppend`. |
| `decision returned` event | `authz/authorizer.rs`, `debug!` | `blocking_pool_us` | `Stage::BlockingPool`. |
| `request authorized` event | `proxy.rs`, `info!` | `method`, `tool`, `decision`, `reason`, `decision_id` | Inside `mcp_request`. |
| `tools/call refused`, lease refusals | `proxy.rs`, `warn!` | `tool`, `reason`, `decision_id` | Inside `mcp_request`. |
| Stage timing | `crates/attenuo-proxy/src/stage.rs::Stage` (nine stages), observed in `metrics.rs` | durations only | Already the boundaries a trace needs; spans should start and end where these measurements do, so a span and the histogram agree. |

So the code has one span per proxied HTTP request, no span per JSON-RPC message, no span per decision stage, and a gap at the blocking pool. A trace per call needs new spans, not only an exporter.

### 3.2 A trace per MCP call

The spans below follow the path of one `POST /mcp/{server}` with one `tools/call`. Each is one span, all in target `attenuo::otel` (section 6), with the attributes listed. Names are proposals.

| Span | Kind | Starts and ends | Attributes |
|---|---|---|---|
| `mcp.request` | server | the proxy's `POST`/`GET`/`DELETE` handler, around `mcp_request` | `http.request.method`, `http.route` (`/mcp/{server}`), `attenuo.server`, `attenuo.session_tag`, `http.response.status_code`, `attenuo.chain_id`, `attenuo.chain_depth` |
| `attenuo.authenticate` | internal | token verification and the DPoP check | `attenuo.token.cache` (`hit`, `miss`), `attenuo.dpop_bound`, `attenuo.reason` on failure (`invalid_token`, `token_expired`, ...) |
| `attenuo.session_gate` | internal | the SR-11 check | `attenuo.reason` on refusal (`session_mismatch`) |
| `attenuo.decide` | internal | one per decided message (`tools/call`, `resources/read`, `prompts/get`, ...) | `attenuo.tool`, `attenuo.decision`, `attenuo.reason`, `attenuo.decision_id`, `attenuo.audit.seq`, `attenuo.policy_ids`, `attenuo.tainted` |
| `attenuo.lease_check` | internal | `Pipeline::check_leases` inside the decision | `attenuo.reason` on failure |
| `attenuo.run_state` | internal | labels, span index and counters read (`run_labels`, `arg_taint`, `budget_view`) | `attenuo.limit.kind` when a limit was met |
| `attenuo.policy` | internal | capability stage and Cedar | none beyond timing |
| `attenuo.charge` | internal | `LeaseStore::charge` and the run lock wait | `attenuo.budget.exhausted_at` (`check`, `charge`) |
| `attenuo.audit_append` | internal | the append, lock wait and commit included | `attenuo.audit.seq` |
| `attenuo.upstream` | client | sending the screened request until response headers | `attenuo.server`, `http.response.status_code`, `attenuo.reason` (`upstream_unreachable`) |
| `attenuo.response` | internal | filtering, list screen, session binding | `attenuo.list.hidden` (count) |
| `attenuo.record_result` | internal | `Pipeline::record_result`: the `tool_result` append and run labels | `attenuo.decision_id` (of the call), `attenuo.result.label` (`trusted`, `untrusted`), `attenuo.audit.seq` |

The other entry points get one span each with the same attribute rules: `POST /token` (`attenuo.token.exchange` or `attenuo.token.root`, with the reason and `decision_id` of a refused exchange), `POST /token/renew`, `POST /access/v1/evaluation` and `/evaluations` (`attenuo.authzen.evaluate`, with an `attenuo.decide` child per evaluation). Admin routes get the `TraceLayer` span with the route template only.

Three cases do not fit a parent-child tree:

- **Blocking pool.** `attenuo.decide` and its children run in `spawn_blocking`. `on_blocking_pool` and `AppState::blocking` must capture `Span::current()` and enter it in the closure; without that the stage spans are new roots. This is a two-line change and is worth making for the log lines alone.
- **Results recorded after the response.** On a streamed answer, and on the listen stream (`label::AwaitedResults`), `record_result` runs after `mcp.request` has returned. The awaited entry would keep the span context of the call, and `attenuo.record_result` would be a new span with a link to it, not a child of an ended span.
- **Long streams.** A listen stream can stay open for an hour. A span that long is a poor fit for most backends. The proposal is no span for the stream itself, and a short `attenuo.stream_end` span when the proxy ends it for a lease or token reason, with the reason and `decision_id` of the `stream.end` record and a link to the request that opened it. Passing re-checks emit nothing, as they write nothing today.

### 3.3 What may leave the process

An OTLP endpoint is usually another host, often another team's or a vendor's. The rules below follow the audit record's own (arguments as a digest, session ids as a tag, verifier detail kept out of answers), with one change: the audit record holds the originating subject in clear because it is the record and its readers are admins, while telemetry gets a digest.

| Class | Fields | Why |
|---|---|---|
| Safe | `decision_id` (record UUID), `chain_id` (root lease id), `session_tag` (12 hex digits of SHA-256 of the session id), `audit.seq`, decision, reason code, record kind, `policy_ids` (operator-authored), chain depth, limit kind, result label, `dpop_bound`, stage durations, route templates, status codes, the upstream's configured name | Opaque ids, fixed sets, or operator configuration. `decision_id` and `chain_id` are the join keys to the record and are not credentials: an admin token is needed to read or revoke with them. |
| Safe after the name rule | tool name, server name from the request | Caller-controlled. Exported only when `ToolCall::check_names` passed; a call refused with `invalid_name` exports the fixed string `invalid_name` instead of the name. |
| Safe with care | agent ids | Names from `[[agents]]`, `[[root_grants]]` and exchanges that pass actor authentication. With `[token] require_actor_auth = false` an exchange can name an actor the operator did not configure; the exporter would then send a digest. |
| Digest only | originating subject | A keyed digest (HMAC-SHA256, truncated to 16 hex digits) under a key the server derives for telemetry. A plain hash of an email address or an employee number is reversed by guessing. The digest lets an operator count calls per user in the backend and find the user through the audit log, not through the backend. Open question 5. |
| Never | bearer tokens, ID tokens, ID-JAGs, actor tokens, approval tokens, DPoP proofs and `jkt` thumbprints, client and PEP secrets, the admin token, the raw `Mcp-Session-Id`, tool arguments and their digests, tool results, list answers, Cedar context, user attributes, policy text, upstream URLs, full request URIs, verifier and store error strings, `baggage` | Credentials, payload, or text that can carry either. Argument digests of low-entropy arguments are guessable and give a backend nothing it needs: the `decision_id` finds the record that holds them. Upstream URLs can carry credentials in the userinfo. |

Enforcement is by construction, not by scrubbing: the exporter sees only spans in the `attenuo::otel` target, through a per-layer filter, and those spans are built with the safe fields only. The existing spans and events keep feeding the log as they do today and never reach the OTel layer. `tracing-opentelemetry` would otherwise export every field of every span, and every event inside a span as a span event, which is how the subject in `mcp_request` and the `decision` line would leak.

## 4. Trace context

### Inbound

The proxy routes (`/mcp/{server}`), the AuthZEN routes, `POST /token` and `POST /token/renew` read one W3C `traceparent` header ([Trace Context](https://www.w3.org/TR/trace-context/)): version `00`, a 32-hex trace id and a 16-hex parent id that are not all zeros, two hex flag digits. A missing, malformed or repeated header starts a new trace and is never a refusal. `tracestate` is read only when the parent is trusted (below); `baggage` is never read.

The header is caller-controlled, and on the MCP port the caller is the agent attenuo is there to constrain. A prompt-injected agent can set any trace id: reuse another run's trace id to blur correlation, or set the sampled flag on every request to force sampling. So the server offers three modes per entry point (`[telemetry.traces] inbound`):

- `parent`: the inbound context is the parent of `mcp.request`, and the sampler honours its sampled flag. The default for AuthZEN callers that authenticated as a `[[peps]]` entry, which the operator configured.
- `link`: `mcp.request` starts a new trace and carries a span link to the inbound context. The backend shows both traces joined, and the client cannot choose attenuo's trace id or sampling. The proposed default on the MCP port.
- `ignore`: no link, as today.

### Upstream

When tracing is on, the proxy inserts its own `traceparent` for the `attenuo.upstream` span on the upstream request. It never copies the client's header, which keeps the rule of SR-27 for `Mcp-Session-Id` (insert the one value attenuo chose) and leaves `FORWARD_REQUEST_HEADERS` as it is. `tracestate` is forwarded only in `parent` mode; `baggage` never. When tracing is off nothing is inserted, so behaviour is unchanged for deployments that do not opt in. The upstream then sees a trace whose parent is attenuo's decision, which is the join the integrated proxy lacks today.

### Server and proxy

`attenuo-proxy` is a library: the server mounts it in the same process (`attenuo_proxy::router_with_clock` in `crates/attenuo-server/src/lib.rs`), and there is no separate proxy binary. Proxy stages and pipeline stages are in one process with one tracer provider, so they are one trace by default once the blocking-pool gap (section 3.2) is closed. The proxy crate needs no OpenTelemetry dependency: it creates `tracing` spans in the `attenuo::otel` target and parses `traceparent` into a small value of its own (about 50 lines, no new crate), and the server, which owns the subscriber, turns that into the span's parent or link. The share-or-link choice that remains is for an external PEP calling AuthZEN, and for the results recorded after a response (open question 3).

### From a span to the signed record, and back

- **Span to record.** `attenuo.decide`, `attenuo.record_result` and `attenuo.stream_end` carry `attenuo.decision_id` and `attenuo.audit.seq`. `GET /admin/audit/records/{id}` and `attenuo audit` find the entry, and `attenuo audit verify` shows it is in the signed chain. This needs no change to the record.
- **Record to span.** With the record as it is, an operator searches the tracing backend for `attenuo.decision_id`. Most backends index span attributes, so this works for every sampled trace.
- **`trace_id` in the record.** A `DecisionRecord` member `trace_id`, optional and skipped when absent, would keep the hashes of older records unchanged, as `dpop_bound`, `labels`, `budget` and `usage` did. It would be inside the hash-chained record, so it is a record schema change that the exports, both SDKs' types and the record reference document. In `link` mode it would hold attenuo's own trace id, not the caller's, so a caller cannot place a chosen value in a signed record. Against it: with head sampling at 10 percent, nine records in ten would name a trace nobody kept, and the record would carry an id from a system it does not control. A side table (`decision_id`, `trace_id`) outside the chain is a third option: not hashed, prunable, and no schema change. Open question 4.

The proposal is the first two, which need no schema change, and to decide the third after operators have used them.

## 5. Metrics: OTLP or Prometheus

Keep `GET /metrics` exactly as it is, and add OTLP push as an opt-in.

- **No code: the collector scrapes.** An OpenTelemetry collector with its Prometheus receiver can scrape the side listener and export OTLP onward. This works today and should be written down in the deploy guide first (step 1). It keeps `/metrics` on loopback, needs no new dependency and keeps one source of truth for every series.
- **Opt-in push.** `[telemetry.metrics] export = true` adds a periodic reader that reads the same `Metrics` struct: counters and gauges as observable instruments whose callbacks read the atomics, with the same names (`attenuo_` prefix dropped in favour of the `attenuo.` namespace, or kept, open question 6) and the same fixed label sets, cumulative temporality as Prometheus has. The two histograms are the hard part: the OpenTelemetry API has no asynchronous histogram, so they are either recorded twice (into the hand-rolled buckets and into an SDK histogram with the same explicit boundaries, `BUCKETS` and `STAGE_BUCKETS`) or exported through a custom producer that hands the SDK the existing bucket counts. The second avoids double cost on the hot path; whether the 0.33 SDK's producer interface accepts pre-aggregated histograms is not verified.
- **Not replacing Prometheus.** Replacing the hand-rolled metrics with the SDK would change every series' exposition (the SDK's Prometheus exporter writes its own names, units and `otel_scope` labels), add a dependency to every build, and break the alert rules in the deploy guide. Nothing in the push path needs that.

Exemplars (a trace id on a histogram bucket, so a slow `authorize_duration_seconds` bucket leads to a trace) need the OpenMetrics text format, not 0.0.4. They are a later step once traces exist. The per-replica caveat of [multi-replica](multi-replica.md) applies to pushed metrics as to scraped ones: gauges read from the shared file report the same global figure from each replica.

## 6. Configuration and failure

```toml
[telemetry]
# Off by default. When off, no exporter is built, no span in `attenuo::otel` is recorded
# beyond what `tracing` does for the log, and nothing is inserted upstream.
enabled = false
# The collector. OTLP over HTTP (protobuf) uses port 4318, gRPC 4317.
otlp_endpoint = "http://127.0.0.1:4318"
protocol = "http/protobuf"      # or "grpc"
timeout_seconds = 10
# A non-loopback endpoint must be https unless this is set (mirrors [metrics] allow_public).
allow_insecure = false
service_name = "attenuo-server"
resource_attributes = { "deployment.environment" = "production" }

[telemetry.traces]
# Head sampling for new traces; a trusted parent's sampled flag applies in `parent` mode.
sample_ratio = 0.1
inbound_mcp = "link"            # "parent" | "link" | "ignore"
inbound_authzen = "parent"      # applies only to callers that authenticated as [[peps]]
propagate_upstream = true
max_queue_spans = 2048
max_export_batch = 512

[telemetry.metrics]
export = false                  # OTLP push of the series /metrics serves; /metrics is unaffected
interval_seconds = 60
```

**Environment.** The standard variables override the file, as `ATTENUO_ADMIN_TOKEN` overrides `[admin] token`: `OTEL_EXPORTER_OTLP_ENDPOINT` (and the per-signal `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `..._METRICS_ENDPOINT`), `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER_ARG`, and `OTEL_SDK_DISABLED=true` to turn export off without editing the file. Collector credentials go in `OTEL_EXPORTER_OTLP_HEADERS` only, never in the file. This is the first set of environment overrides beyond the admin token; the deploy guide's production checklist says there is no other environment-variable substitution today, so it would change that line. Unknown keys under `[telemetry]` are refused at start, as everywhere in the config.

**Fail open, bounded.** Export is the one part of attenuo that fails open, and it must never change an answer:

- Spans go to a bounded queue (`max_queue_spans`) drained by the exporter off the request path. The 0.33 SDK's batch processor already runs on its own thread with a bounded channel and drops when it is full (read from its source). A full queue drops the span, never blocks the call.
- Dropped spans and failed exports are counted on `/metrics`: `telemetry_spans_dropped_total` and `telemetry_export_failures_total`. The SDK counts drops internally but only logs the first and the total at shutdown, with no public counter, so attenuo needs a thin processor of its own in front of the batch processor to count them.
- An unreachable collector at start does not stop the server; a malformed `[telemetry]` section does, like any other config error.
- `/readyz` ignores telemetry. The audit sink marks the server degraded because its checkpoints protect the record; a lost span protects nothing.
- On SIGTERM the exporter gets a bounded flush after the request drain (`DRAIN_TIMEOUT`), like the sink's `SINK_SHUTDOWN_GRACE` of 5 seconds, and exit is never delayed past it.
- No exporter error reaches a client, and none is written to the audit log.

**Sampling.** Head sampling decides when `mcp.request` starts, before the decision is known, so "keep every deny" cannot be a head rule. Two answers: tail sampling in the collector (its job, not attenuo's), or a processor that records every span and exports the sampled ones plus every trace that holds a deny. The second costs the full span volume in memory; the proposal leaves it to the collector.

**Cost.** Unsampled spans are cheap but not free, and a decided call would gain about twelve spans. Cedar takes 12 to 163 microseconds per call (README, "Policy stage"), so span overhead must be measured with `attenuo-bench` at sample ratios 0, 0.1 and 1 before the feature is called done. Not measured.

## 7. Proposed path

Ranked so that each step is useful on its own and the risky decisions come last.

| Step | What | Crates | Effort |
|---|---|---|---|
| 1 | Document the collector's Prometheus receiver scraping `[metrics] listen` and exporting OTLP, in the deploy guide's monitoring section. No code. | docs only | S |
| 2 | Span hygiene with no new dependency: carry the current span into `on_blocking_pool` and `AppState::blocking`; add the spans of section 3.2 in target `attenuo::otel` at the `Stage` boundaries; `TraceLayer` spans use the route template (done: SR-90, `fix/trace-span-route-template`). The log gains request context on the decision lines; nothing is exported. | attenuo-proxy (`proxy.rs`, `label.rs`, `guard.rs`), attenuo-server (`authz.rs`, `state.rs`, `lib.rs`, `admin_ui.rs`) | S |
| 3 | Trace export behind a cargo feature: `[telemetry]` config and env overrides, the subscriber built as a registry with the fmt layer and an OTel layer filtered to `attenuo::otel`, the attribute rules of section 3.3 with a keyed subject digest, the counting processor, the two `telemetry_*` counters, shutdown flush. | attenuo-server (`main.rs`, `config.rs`, new `telemetry.rs`, `metrics.rs`), workspace `Cargo.toml`, `deny.toml` if an exception is needed | M |
| 4 | Propagation: parse `traceparent` (proxy, AuthZEN, token routes), the `parent`/`link`/`ignore` modes, insert attenuo's `traceparent` upstream, keep the call's span context in `AwaitedResults` for later results. | attenuo-proxy (`proxy.rs`, `label.rs`, a new `traceparent.rs`), attenuo-server (`routes/authzen.rs`, `routes/token.rs`, `routes/renew.rs`) | M |
| 5 | OTLP metrics push: observable instruments over `Metrics`, the two histograms through a producer or recorded twice, `[telemetry.metrics]`. | attenuo-server (`metrics.rs`, `telemetry.rs`) | M |
| 6 | Only if open question 4 says so: `trace_id` in `DecisionRecord` (optional, skipped when absent) or a side table, with the record reference, both SDKs' record types and the CLI's display. | attenuo-core (`decision.rs`), attenuo-audit, attenuo-cli, the SDKs, docs | S code, M with the schema review |
| 7 | Exemplars on the two histograms, with OpenMetrics text as an `Accept`-negotiated format next to 0.0.4. | attenuo-server (`metrics.rs`) | S to M |

Steps 1 and 2 are worth doing whatever is decided about export. Step 3 is the one that adds dependencies; steps 4 to 7 build on it.

## 8. Dependencies, size and build time

Resolved against the `Cargo.lock` of 6951476 with a scratch crate that depends on `attenuo-server` plus the OpenTelemetry crates (`cargo tree -e normal`, current crates.io versions on 2026-11-06), and checked with `cargo deny check licenses bans` using the repository's `deny.toml`:

| | gRPC (`grpc-tonic`, `tls-ring`, `tls-webpki-roots`) | HTTP with the crate's client (`http-proto`, `reqwest-client`, `reqwest-rustls`) |
|---|---|---|
| Direct | `opentelemetry` 0.33.1, `opentelemetry_sdk` 0.33.1, `opentelemetry-otlp` 0.33.1, `tracing-opentelemetry` 0.34.0 | the same |
| Packages added to the lock | 25 | 42 |
| Notable | `tonic` 0.14.9, `tonic-prost`, `tonic-types`, `prost` 0.14.4, `prost-types`, `h2` 0.4.20 (hyper is built without HTTP/2 today), `hyper-timeout`, `pin-project`, `tokio-stream`, `rand` 0.9 next to 0.8, a third `getrandom` | `reqwest` 0.13.5 next to the workspace's 0.12.28, `aws-lc-rs` and `aws-lc-sys` (rustls's provider for reqwest 0.13; a C build), `rustls-platform-verifier`, `rustls-native-certs`, `prost`, plus target-only crates (`jni`, `security-framework`, `schannel`) |
| Licences | all within the allow list (Apache-2.0, MIT and dual licences) | all within the allow list (`aws-lc-sys` is ISC, Apache-2.0, MIT and BSD-3-Clause terms) |
| Bans | none hit; no `openssl`, `openssl-sys` or `native-tls` (`openssl-probe` is a different crate) | none hit |
| New duplicate warnings | `getrandom` (3 versions) | `getrandom` (3), `reqwest` (2) |

`multiple-versions` is `warn` in `deny.toml`, so neither variant fails the gate; both add duplicates. The crates' declared MSRVs (1.75, `tonic` 1.88) are below the workspace's 1.89.

The HTTP variant's cost is almost all the second `reqwest`. `opentelemetry-http` defines a one-method `HttpClient` trait (`send_bytes`), so attenuo can implement it over the workspace's `reqwest` 0.12 and drop `reqwest` 0.13, `aws-lc-*` and the platform verifier, leaving the HTTP variant smaller than the gRPC one. Whether the batch processor's dedicated thread can drive an async `reqwest` 0.12 client (which needs a tokio runtime), or the blocking client is needed, is to be confirmed in step 3.

**Size and build time: estimates, not measured.** With the feature compiled out: no change. gRPC variant: 2 to 4 MB more on the release binary (`lto = "thin"`, `codegen-units = 1`) and 20 to 40 seconds more on a clean release build, mostly `tonic`, `h2` and `prost-derive`. HTTP with the crate's client: 3 to 6 MB, and a C toolchain (possibly CMake) plus a minute or more of clean build for `aws-lc-sys`. HTTP over the workspace `reqwest`: 1 to 2 MB and 10 to 20 seconds. None of these figures was measured; step 3 should record them in [performance](performance.md).

## 9. Open questions

1. **Feature flag or always compiled.** A cargo feature (`otel`) keeps the default build and the dependency tree as they are, and the release binaries and container image then need a decision about which features they ship. Always compiled means every build carries 25 or more crates whether or not `[telemetry]` is set. Which, and is the published image built with it?
2. **gRPC or HTTP as the default protocol.** The OTLP crate defaults to `http/protobuf` on 4318, and most collectors accept both. HTTP over the workspace's `reqwest` adds the fewest crates; gRPC adds `tonic` and `h2`. Support one, or both behind sub-features?
3. **One trace or links.** Inside the process, proxy and pipeline spans share one trace (section 4). For an external PEP calling AuthZEN, should attenuo's spans be children of the PEP's span (`parent`, the proposed default for authenticated `[[peps]]`) or a linked trace? And for results recorded after the response, is a link acceptable, or should `mcp.request` stay open until the last awaited result is recorded?
4. **`trace_id` in the hash-chained record.** Join on `decision_id` only (no change), add an optional `trace_id` to `DecisionRecord` (a record schema change, inside the hash, attenuo's own id in `link` mode, mostly pointing at unsampled traces), or keep a side table outside the chain?
5. **The subject in telemetry.** A keyed digest, or nothing (the `chain_id` already groups a run, and the audit log maps runs to users)? If a digest, which key: one derived from the issuer key as the DPoP nonce key is, which changes at rotation and breaks per-user series, or a separate key file?
6. **Names.** OpenTelemetry semantic conventions for the HTTP attributes, and an `attenuo.` namespace for the rest. Should pushed metrics keep the Prometheus names (`attenuo_decisions_total`) so dashboards carry over, or follow OTel naming (`attenuo.decisions`, unit suffixes handled by the exporter)?
7. **Logs.** The proposal exports no logs, because the existing events carry subjects and error strings. Is that acceptable, or should a small allowlisted set of events (decisions, refusals) go out as span events?
8. **Scope against RFC-0001 section 8.** Does the maintainer accept that exporting attenuo's own decision spans is not "OTel belongs to gateways"? If so, section 8 would gain one sentence: attenuo exports spans and metrics for its own decisions, and does not route, rate-limit, federate or export payloads.

# Observability

attenuo gives an operator three views of what it does: Prometheus metrics on a side listener, log lines on standard output, and, with `[telemetry]`, OpenTelemetry traces of each MCP call sent to a collector over OTLP. This guide covers the traces and how to get the metrics into the same collector. The audit log stays the record of what was decided; traces and logs are operational aids.

The design is in [OpenTelemetry export](../design/otel-export.md) and the decision in [ADR-0012](../decisions/0012-opentelemetry-export.md).

## Point attenuo at a collector

Run an OpenTelemetry collector with the OTLP receiver on HTTP (port 4318), then turn export on:

```toml
[telemetry]
enabled = true
otlp_endpoint = "http://127.0.0.1:4318"   # /v1/traces is appended
service_name = "attenuo-server"
resource_attributes = { "deployment.environment" = "staging" }

[telemetry.traces]
sample_ratio = 0.1
```

A collector on another host must be reached over `https://`; the server refuses to start on a plain `http://` URL that is not loopback unless you set `allow_insecure = true`. Collector credentials (an API key header, say) go in the environment, never in the file:

```sh
export OTEL_EXPORTER_OTLP_HEADERS="x-api-key=..."
```

The usual `OTEL_*` variables override the file (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER_ARG`, ...), and `OTEL_SDK_DISABLED=true` turns export off. They never turn it on. The full list is in the [configuration reference](../reference/config.md#telemetry).

Only OTLP over HTTP with protobuf is built. `protocol = "grpc"` refuses to start. A minimal collector configuration:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
  prometheus:
    config:
      scrape_configs:
        - job_name: attenuo
          scrape_interval: 15s
          static_configs:
            - targets: ["127.0.0.1:9100"]   # [metrics] listen
exporters:
  otlp:
    endpoint: your-backend:4317
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp]
    metrics:
      receivers: [prometheus]
      exporters: [otlp]
```

Replace `your-backend:4317` with your tracing backend's OTLP/gRPC address. To see what arrives without a backend, add the collector's `debug` exporter (`debug: { verbosity: detailed }`) to both pipelines: it prints each span and metric to the collector's log.

**What was run.** On 2026-11-14 this configuration, copied from this page, was run against OpenTelemetry Collector **0.165.0** (`otel/opentelemetry-collector-contrib:0.165.0` and the core `otel/opentelemetry-collector:0.165.0`, both with host networking), with the `[telemetry]` block above and `[metrics]` on `127.0.0.1:9100`, by [`scripts/live-collector-smoke.sh`](https://github.com/attenuo-dev/attenuo/blob/main/scripts/live-collector-smoke.sh) (not part of CI; it skips when Docker is absent). What it showed:

- Both images accept the file (`otelcol validate` passes on the contrib image, and both start with it). Version 0.165.0 logs `"otlp" alias is deprecated; use "otlp_grpc" instead` for the exporter: the name still works there; on a collector that has the new name, prefer `otlp_grpc`.
- With a `debug` exporter added, the spans of a proxied call (`mcp.request`, `attenuo.authenticate`, `attenuo.session_gate`, `attenuo.decide` with `attenuo.lease_check`, `attenuo.run_state`, `attenuo.policy` and `attenuo.audit_append`, `attenuo.upstream`, `attenuo.response`, `attenuo.record_result`), for an allow and a deny, and `attenuo.token.exchange` arrive with the attributes listed below and no others, under `service.name` and the `resource_attributes`; a caller's `traceparent` is a span link on `mcp.request`, its trace id is not adopted, and the upstream receives one `traceparent` naming the `attenuo.upstream` span. No token, subject, argument, secret or upstream URL was in any exported span.
- The Prometheus receiver scrapes `[metrics] listen`, the two telemetry series below included.
- The run found that `http.response.status_code`, `attenuo.chain_depth` and `attenuo.audit.seq` reached the collector as strings (`Str(200)`); they are now integers, as the semantic conventions have the status code.
- Not driven in that run: `attenuo.charge` (no run limit), `attenuo.stream_end`, `attenuo.token.root`, `attenuo.token.renew` and the AuthZEN spans, `parent` mode, and `attenuo.session_tag` (no request carried an `Mcp-Session-Id`); the in-process tests cover them. The script sets `OTEL_TRACES_SAMPLER_ARG=1` so that every call is traced; the guide's `sample_ratio = 0.1` itself was not checked against a count of traces. No real tracing backend was used: the `otlp` exporter's target did not resolve, and only the collector's `debug` output was read.

## Metrics

attenuo does not push metrics over OTLP. Enable `[metrics]` and let the collector's Prometheus receiver scrape it, as in the configuration above; the series and the alerts to set are in [Deploying: what to monitor](deploying.md#what-to-monitor). Two series report on the exporter itself:

| Series | Meaning |
|---|---|
| `attenuo_telemetry_spans_dropped_total` | Spans dropped before export, because the queue (`max_queue_spans`) was full or export had shut down. |
| `attenuo_telemetry_export_failures_total` | Export requests that failed or timed out. Their spans are not retried. |

## What is exported

One trace per proxied MCP request:

| Span | Kind | Attributes |
|---|---|---|
| `mcp.request` | server | `http.request.method`, `http.route` (`/mcp/{server}`), `attenuo.server`, `attenuo.session_tag`, `attenuo.chain_id`, `attenuo.chain_depth`, `attenuo.dpop_bound`, `http.response.status_code` |
| `attenuo.authenticate` | internal | `attenuo.token.cache` (`hit`, `miss`), `attenuo.dpop_bound`, `attenuo.reason` on a refusal |
| `attenuo.session_gate` | internal | `attenuo.reason` on a refusal (`session_mismatch`, `session_unknown`) |
| `attenuo.decide` | internal | `attenuo.server`, `attenuo.tool`, `attenuo.decision`, `attenuo.reason`, `attenuo.decision_id`, `attenuo.audit.seq`, `attenuo.policy_ids`, `attenuo.tainted`, `attenuo.chain_id`, `attenuo.subject_digest`, `attenuo.limit.kind` and `attenuo.budget.exhausted_at` when a run limit was met |
| `attenuo.lease_check`, `attenuo.run_state`, `attenuo.policy`, `attenuo.charge`, `attenuo.audit_append` | internal | children of `attenuo.decide`; `attenuo.reason` on a lease failure, `attenuo.audit.seq` on the append |
| `attenuo.upstream` | client | `attenuo.server`, `http.response.status_code`, `attenuo.reason` (`upstream_unreachable`, `upstream_timeout`) |
| `attenuo.response` | internal | none |
| `attenuo.record_result` | internal | `attenuo.decision_id` of the call, `attenuo.result.label`, `attenuo.audit.seq` |
| `attenuo.stream_end` | internal | `attenuo.reason`, `attenuo.decision_id` and `attenuo.audit.seq` of the `stream.end` record |

`POST /token` (`attenuo.token.exchange`, or `attenuo.token.root` for an IdP credential), `POST /token/renew` (`attenuo.token.renew`) and the AuthZEN routes (`attenuo.authzen.evaluate`, with an `attenuo.decide` child per evaluation) get one span each, with the method, the route template and the status code. Admin routes export nothing. The resource carries `service.name` and your `resource_attributes`.

`http.response.status_code`, `attenuo.chain_depth` and `attenuo.audit.seq` are integers, `attenuo.dpop_bound` and `attenuo.tainted` booleans, the rest strings. A tool or server name that breaks the name rule is exported as the fixed string `invalid_name`. The subject is exported only as `attenuo.subject_digest`: 16 hex digits of an HMAC-SHA256 keyed by a key derived from the issuer's private key, so it groups calls per user without naming the user. Rotating the issuer key changes every digest. With `[logging] redact_subjects = true` the server's log lines carry the same digest (`subject=hmac:<16 hex>`), so a log line and a trace of one user match ([config reference](../reference/config.md#logging)).

## What never leaves the process

Bearer tokens, ID tokens, ID-JAGs, actor and approval tokens, DPoP proofs and key thumbprints, client and PEP secrets, the admin token, the raw `Mcp-Session-Id`, tool arguments and their digests, tool results, list answers, the Cedar context, user attributes, policy text, upstream URLs, request URIs, error strings and `baggage`.

This is enforced by construction. The exporter sees only spans in the `attenuo::otel` target, built with the fields above; the log's own spans and events (which carry the subject in clear and error text) never reach it, and no log event is exported as a span event. Logs are unchanged: the exported spans do not appear in them.

## Trace context

- **From the agent.** A W3C `traceparent` on `/mcp/{server}`, `POST /token` or `POST /token/renew` is **linked**, not adopted (`inbound_mcp = "link"`): `mcp.request` starts a new trace with a span link to the caller's. The agent is the party attenuo constrains, so it does not get to pick attenuo's trace id or force sampling. Set `inbound_mcp = "parent"` to join the caller's trace instead, or `"ignore"`.
- **From a PEP.** An AuthZEN caller that authenticates as a `[[peps]]` entry with HTTP Basic is the **parent** (`inbound_authzen = "parent"`). A caller with a bearer token, or with PEP credentials in the body, gets `inbound_mcp`.
- **Malformed headers** (wrong version, uppercase hex, all-zero ids, two headers) are ignored: a new trace starts and the call goes on.
- **To the upstream.** The request to the upstream MCP server carries attenuo's own `traceparent`, naming the `attenuo.upstream` span, so the upstream's trace is a child of attenuo's decision. The client's header is never forwarded. `propagate_upstream = false` turns this off; with telemetry off nothing is inserted. `tracestate` and `baggage` are neither read nor sent.
- **Results after the response.** A result recorded while the response body is buffered is a child of `attenuo.response`. One recorded later, on a stream, is a new span with a link to the request that made the call; so is `attenuo.stream_end`.

## From a span to the signed record, and back

`attenuo.decide`, `attenuo.record_result` and `attenuo.stream_end` carry `attenuo.decision_id`, the id of the audit record, and `attenuo.audit.seq`, its sequence number. From a span, open the record:

```sh
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" \
  http://127.0.0.1:8080/admin/audit/records/<attenuo.decision_id>
attenuo audit verify   # the record is in the signed chain
```

From a record, search the tracing backend for the attribute `attenuo.decision_id` with the record's id (also in the `X-Attenuo-Decision-Id` answer header). Only sampled traces are there. The signed record carries no trace id: nothing outside attenuo's control goes into the hash chain.

## Failure behaviour

Export is the one part of attenuo that fails open, and it never changes an answer. Finished spans go to a bounded queue drained by one thread; a full queue drops the span and counts it, so a slow or dead collector cannot slow a call. Export errors are logged once per outage and counted, never returned to a client or written to the audit log. `/readyz` ignores telemetry. An unreachable collector at start does not stop the server; a malformed `[telemetry]` section does. On shutdown the queue gets 5 seconds to drain after the requests have.

Span overhead, measured on one decision in process ([design note, section 10](../design/otel-export.md#measured)): with `[telemetry]` off, within noise; on at the default ratio 0.1, 2 to 16 %; on at ratio 1, 30 to 95 µs per decision. The whole call through HTTP has not been measured with `attenuo-bench` yet.

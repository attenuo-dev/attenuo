---
status: accepted
date: 2026-11-12
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0012. OpenTelemetry export: allow-listed decision spans over OTLP/HTTP, off by default, linked not adopted, joined to the signed record by decision id

## Context and Problem Statement

Operators who run an OpenTelemetry collector want a trace of each MCP call through attenuo. In the integrated proxy the agent's trace ends at attenuo's port and the upstream's starts fresh, and a gateway in front sees attenuo as one opaque hop; the stages of a decision, the policies that decided it and the signed record that holds it exist only inside attenuo. The existing spans and log events carry the subject in clear and error strings, so they cannot be exported as they are. Should attenuo export traces, of what, with which fields, how should trace context travel, and how does a span lead to the audit record? Design: [design/otel-export.md](../design/otel-export.md).

## Decision Drivers

- An exporter failure must never change, delay or fail a decision, and must never reach a client or the audit log.
- Nothing that may not leave the process does: tokens, DPoP proofs, secrets, the subject in clear, arguments, results, URLs, error text.
- The agent is the party attenuo constrains: it must not choose attenuo's trace id, force sampling or put a value of its choosing into a signed record.
- The audit log stays the record; the hash chain and the record schema do not change for telemetry.
- Small dependency footprint, compatible with the workspace's `tracing`, `reqwest` and `cargo deny` rules.
- Default behaviour stays as it is: no export, nothing inserted upstream.

## Considered Options

- Allow-listed spans in their own `tracing` target, exported over OTLP/HTTP through the workspace's `reqwest`, with a bounded queue (built).
- Export every existing span and event through `tracing-opentelemetry`, scrubbing fields.
- OTLP over gRPC (`tonic`).
- Put the trace id in the signed `DecisionRecord`.
- Do nothing: leave tracing to gateways (RFC-0001 section 8) and correlate by `X-Attenuo-Decision-Id`.

## Decision Outcome

Chosen (built on `feat/otel-export`, see Confirmation): "Allow-listed spans in their own target, over OTLP/HTTP", because it is the only option where what leaves the process is fixed by construction rather than by a scrubber, it adds 17 packages instead of 25 or 42, and it keeps the record unchanged. The choices for the design's eight open questions:

1. A cargo feature `otel` of `attenuo-server`, on by default: the published binary and image carry it, and export is a config switch (`[telemetry] enabled`).
2. OTLP over HTTP with protobuf only; gRPC refuses to start.
3. One trace inside the process. An inbound `traceparent` from the agent (MCP and token routes) is linked, not adopted; from a `[[peps]]` caller authenticated with HTTP Basic on AuthZEN it is the parent. Results recorded after the response, and stream ends, are new spans linked to the request.
4. No trace id in the record; the spans carry `attenuo.decision_id` and `attenuo.audit.seq`.
5. The subject as a keyed digest (HMAC-SHA256 under a key derived from the issuer key, 16 hex digits); agent ids not exported.
6. OpenTelemetry semantic conventions for HTTP attributes, `attenuo.` for the rest.
7. No logs signal and no span events.
8. Left to the maintainer; RFC-0001 is unchanged.

Metrics stay on Prometheus `/metrics`, scraped by the collector; OTLP metrics push is not built.

### Consequences

- Good, because the integrated proxy joins the agent's trace (by link) and the upstream's (as its parent), and a slow call shows which stage took the time, which reason decided it and which record holds it.
- Good, because leaks are prevented by construction: the exporter sees only spans in `attenuo::otel`, built with allow-listed fields, and the test asserts every attribute key against the list and every value against the token, subject, arguments and result.
- Good, because a dead collector costs a dropped, counted span (`telemetry_spans_dropped_total`, `telemetry_export_failures_total`), never a slower decision.
- Bad, because every default build now carries 17 more packages, `prost-derive` among them, and the binary grows (2.5 MB in the development profile; release not measured).
- Bad, because the `OTEL_*` environment variables are the first overrides besides `ATTENUO_ADMIN_TOKEN`.
- Bad, because the subject digest changes at issuer key rotation, which breaks per-user series across a rotation.
- Bad, because sampling every trace costs 30 to 95 µs per decision in the in-process bench (within noise with export off, 2 to 16 % at the default ratio 0.1; [design note, section 10](../design/otel-export.md#measured)); the whole call has not been measured with `attenuo-bench`.
- Neutral, because "keep every deny" needs tail sampling in the collector; attenuo samples at the head.
- Neutral, because linking by default means a backend shows the agent's trace and attenuo's as two traces joined by a link; an operator who trusts the client can set `inbound_mcp = "parent"`.

### Confirmation

Built on branch `feat/otel-export` (2026-11-06) and merged to `main` (#215, #217): the `otel` cargo feature is compiled in by default and export stays off until `[telemetry]` turns it on. The maintainer accepted it on 2026-11-12, with the choices listed above for the design's open questions; export stays off unless configured. Tests in `crates/attenuo-server/tests/otel.rs`: `tools_call_exports_the_listed_spans_and_nothing_forbidden`, `upstream_gets_attenuos_traceparent_and_a_malformed_one_is_ignored`, `parent_mode_adopts_the_inbound_trace`, `tracing_off_inserts_nothing_upstream`, `a_dead_collector_never_slows_or_fails_a_decision`, `spans_reach_an_otlp_http_receiver_without_secrets`, `a_bad_endpoint_refuses_to_start`, `authzen_and_token_routes_get_one_span_each`; configuration and digest unit tests in `crates/attenuo-server/src/telemetry.rs`; `traceparent` parsing tests in `crates/attenuo-proxy/src/traceparent.rs`. The existing audit verification tests pass unchanged. Measurements and what is not verified are in [design section 10](../design/otel-export.md#10-built).

## Pros and Cons of the Options

### Allow-listed spans in their own target, over OTLP/HTTP

- Good, because the allow-list is the code that builds the spans; a new log field cannot leak.
- Good, because it reuses the workspace's `reqwest` 0.12, so no second HTTP client, `aws-lc` or platform verifier.
- Bad, because the SDK's batch processor does not expose its drop count, so attenuo carries its own bounded processor (about 200 lines).

### Export every span and event, scrubbing fields

- Good, because no new spans are needed.
- Bad, because `mcp_request` and the `decision` line carry the subject in clear and error strings carry verifier detail; a scrubber is a deny-list that every new field can slip past.

### OTLP over gRPC

- Good, because some collectors and vendors prefer it.
- Bad, because it adds `tonic`, `h2` and their tree (25 packages), and most collectors accept HTTP on 4318.

### Trace id in the signed record

- Good, because a record would name its trace directly.
- Bad, because it is a record schema change inside the hash, at 10 % sampling nine records in ten would name a trace nobody kept, and the record would carry an id from a system attenuo does not control.

### Do nothing

- Good, because no dependency and no new surface.
- Bad, because the integrated proxy, the common deployment, has no gateway to provide the trace, and a gateway cannot see inside the decision.

## More Information

- Design: [OpenTelemetry export](../design/otel-export.md), with the built choices in section 10.
- Operator guide: [Observability](../guides/observability.md); configuration: [`[telemetry]`](../reference/config.md#telemetry).
- Related: [ADR-0008](0008-admin-console.md) (the console shows nothing of telemetry; its CSP is unchanged), [RFC-0001](../spec/rfc-0001-attenuo.md) section 8, [audit log](../concepts/audit-log.md).
- Revisit when operators have used the `decision_id` join (open question 4), after the span overhead benchmark, and if a user asks for gRPC or OTLP metrics.

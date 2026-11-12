---
status: proposed
date: 2026-11-12
decision-makers: []
consulted: []
informed: []
---

# ADR-0014. Request limits: an in-flight cap and deadlines on by default, per-run and per-agent rate limits in process and off by default

## Context and Problem Statement

attenuo sits inline and fails closed, so anything that swamps the process denies every agent (audit finding S-4). Upstream, audit-append and key-fetch deadlines already exist. The server still had no cap on requests in flight, no header, body or handler deadline, and no per-caller rate limit on `POST /token` or `/mcp/{server}`. What should it bound, keyed on what, and with which defaults, given that denial of service stays outside the threat model and attenuo runs as one replica?

## Decision Drivers

- A limit must never let a request through unchecked, and must not be able to refuse everyone silently (counted, logged, tested at its boundaries).
- Count a caller only on an identity it has proved, so nobody can use up another caller's allowance.
- Count before the expensive work (lease lookups, Cedar, the audit append, the upstream call, signing).
- No change for existing deployments, the tests, the demos or the benchmarks with the defaults.
- No new crate; bounded memory; no subject in logs or metric labels.

## Considered Options

- Keying `/mcp` by run (the chain's root lease), or by user subject.
- Rate limits on by default with a generous figure, or off by default.
- `tower`'s `ConcurrencyLimit` and `tower_http`'s `Timeout`, or small `from_fn` layers of our own.

## Decision Outcome

Chosen: key `/mcp` by run, `POST /token` by authenticated agent with the peer address for requests that authenticate none; rate limits off by default; the in-flight cap (1024) and the deadlines (30 s headers, 30 s body, 60 s handler) on by default; our own layers.

- **Run, not subject.** The root lease id is in the verified token, which the server caches, so the check costs a map lookup before any lease read. It is a random id, safe to log; a subject would need the redaction of `[logging] redact_subjects`. A run is what goes wrong in practice (an agent in a loop), and keying by it leaves the same user's other runs alone. A user who opens many runs is bounded by the `POST /token` limit and by `[proxy] max_sessions_per_principal`.
- **Counted after verification.** `/mcp` counts once the token and its DPoP proof verify, so only a holder of the token (and of its key, when it is bound) can use up a run's minute; `POST /token` counts once the client secret or actor token verified, before the subject token or IdP credential.
- **Off by default.** A legitimate rate spans orders of magnitude (one run makes a few calls a minute, a batch run or the benchmark thousands a second), and a limit set too low is a denial the operator did not choose. The cap and the deadlines protect the process without knowing the workload; the rate limits protect callers from each other and need a figure only the operator has.
- **Fixed window, full table refuses.** Easy to state and to test (N admitted, N+1 refused, N again after the minute; at most 2N across a boundary). Dropping only ended windows means a count is never reset early; refusing new keys when every tracked key is active keeps the bound under a flood of distinct callers, at the price of refusing new callers for at most a minute, counted as `table_full`.
- **Own layers.** `ConcurrencyLimit` queues instead of shedding and cannot exempt the probes; `tower_http`'s timeout answers `408` with no body and would cut the proxy's streams.

### Consequences

- Good, because a burst gets fast `503`s instead of a growing queue, slow clients cannot hold connections forever, and an operator can bound a runaway run or agent with one key.
- Bad, because the limits are per process: a restart forgets them and they do not add up across replicas; behind a reverse proxy the per-peer limit is shared by every caller.
- Neutral, because the server now runs its own accept loop (`listen.rs`) instead of `axum::serve`, the only way to give hyper a timer.

### Confirmation

`limits::tests` (boundaries, churn, full table, peer keys, shedding, deadlines), `listen::tests` (slow headers, idle connections), `tests/limits.rs` (each limit over real connections, streams neither cut nor counted, startup refusals), and the existing stream and idle-timeout tests.

## More Information

Keys and defaults: [configuration reference](../reference/config.md#limits). Design notes: [server design, load limits](../design/server.md#load-limits-limits). Revisit if attenuo ever runs more than one replica ([multi-replica readiness](../design/multi-replica.md)).

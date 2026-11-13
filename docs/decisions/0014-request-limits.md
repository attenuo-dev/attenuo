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

### Update 2026-11-13: a full peer table lets agents authenticate (SR-109)

The decision above stands and is kept as written, except for the per-peer table of `POST /token`. "Fixed window, full table refuses" chose to refuse a new key when every tracked key is inside its minute, so that a flood of distinct callers cannot push out the count of the one being limited. For the per-agent and per-run tables, and for the per-peer table as it was, that refusal fell on the callers the table counts. Security review pass 12 found that it did not for the per-peer table ([SR-109](../research/security-review-2026-11-13-pass12.md#sr-109-a-full-per-peer-table-refuses-every-agent-that-is-not-in-it-info-fixed)): a request that authenticates an agent is never counted against its address, so an agent's address is never in that table, and one unauthenticated request from each of `rate_limit_max_keys` addresses within a minute (10,000 by default) refused every agent at hop 0 and at every exchange, before it could authenticate, for as long as the flood went on. Turning the limit on was what made agents fail.

Now (option 2 of the report): when the per-peer table is full and the address is not in it, the request is not refused before the handler. The handler, before any work, refuses it unless it carries client credentials (a secret, HTTP Basic or a client assertion) and no actor token. A request that goes on is authenticated; if it authenticates an agent it is served as before and not counted in the peer table, and if it does not, its answer is replaced by the `429` it would have got up front, the same body and `Retry-After`, counted as `table_full`. A peer that is in the table and over its limit is still refused before the handler runs. Nothing changes for the per-agent and per-run tables, which hold the callers they refuse.

What this costs, honestly:

- On a full table, an address not in it can make the server do one client authentication per request: a SHA-256 and a constant-time compare for a secret, or parsing the assertion and one signature verification (with the client's key, or the decoy key of SR-110 for an unknown id). The body is read and parsed first, as for any request that reaches the handler. That is the work every request did with the peer limit off; the flood gets no answer past a refusal. It is bounded in concurrency by `max_in_flight`, the body and handler deadlines, and in cost per request by the keys in the config (an RSA key has no maximum size there; the operator chooses it). It is not bounded in rate: from addresses beyond the table's size, the peer limit no longer limits failed client authentications. Floods from many addresses stay with the network in front of the server, as the threat model says; nothing more was added, because a second global counter would be filled by the same flood and lock agents out again.
- Requests without client credentials stay refused up front on a full table: an exchange without actor authentication (with `require_actor_auth = false`) would go on to verify the subject token and read leases without authenticating anyone, and an actor token may need a JWKS fetch from its issuer, both before the request could be told apart from the flood. So an agent that sends an actor token, alone or with client credentials (`actor_auth = "either"`), is still refused while the table is full; an agent that sends client credentials without an actor token is served.
- A request with client credentials that fails authentication and one refused up front get the same answer, so a flood learns nothing from the change but the timing of a failed authentication, which it had with the limit off.

Rejected: letting every request from a new address through uncounted (option 1), which leaves unauthenticated work from new addresses unbounded on every path, including IdP and actor-token key fetches; a second table of addresses that recently authenticated an agent (option 3), which still refuses an agent from a new address during a flood; documenting the behaviour and asking for a larger `rate_limit_max_keys` (option 4), which leaves the limit refusing the callers it was not meant for.

Confirmation: `limits::tests::a_full_peer_table_still_serves_an_authenticated_agent_sr109` (the middleware with a stand-in handler: agent served from a known and a new address, a failed authentication, no credential and an actor token all `429` with one body, the handler not run for a peer over its limit, the metrics) and `tests/limits.rs` `a_full_peer_table_lets_agents_authenticate_sr109` (the server's own handler, at an exchange and at hop 0).

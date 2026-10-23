---
status: proposed
date: 2026-10-22
decision-makers: [7Mudit]
consulted: []
informed: []
---

# ADR-0006. Lease-based in-flight revocation: short leases, renewed by the holder, checked on every request

## Context and Problem Statement

A delegation token is a signed JWT valid for minutes (default 900 s) and cannot be recalled once issued. Principle P4 of [RFC-0001](../spec/rfc-0001-attenuo.md) requires that when a user logs out, an operator kills a session, or an agent is found compromised, the agents acting for that user stop working "within one lease interval", including every sub-agent several hops down. How do we withdraw authority that was already delegated, without making every call depend on a round trip to the IdP and without a token blacklist that grows forever?

## Decision Drivers

- Revocation of a parent must reach all descendants without enumerating tokens (the server does not store tokens).
- The enforcement point must fail closed: a lost row, an unreachable store or a crashed holder must not leave authority alive.
- A holder that dies silently (crashed agent, leaked token whose owner stopped) should lose authority on its own, without anyone noticing.
- Hot-path cost must stay a local lookup; the proxy and the AuthZEN endpoint share one decision pipeline ([design/server.md](../design/server.md)).
- The token is self-contained and verifiable offline by other parties; revocation state must not need to be inside it.

## Considered Options

- Lease per hop in a server-side registry: tree of leases, short expiry, holder renews, cascade on revoke.
- Token blacklist keyed by `jti` (RFC 7009-style revocation list).
- Very short token lifetimes only, with no server-side state.
- Introspection of every token at the IdP (RFC 7662) on each call.

## Decision Outcome

Chosen option: "Lease per hop in a server-side registry", because it is the only option that cascades through the delegation tree with one write, expires on its own when the holder goes quiet, and keeps the hot path to one local lookup.

The mechanism:

1. Every hop of a chain carries a lease id. When a token is issued (root mint or exchange) its lease is registered with `parent` = the previous hop's lease and `expires_at = min(now + lease_interval, token exp)`. `lease_interval` is `[issuer] lease_interval_seconds` (default 300).
2. The holder keeps its authority alive with `POST /token/renew`, bearer = its own delegation token. Only the last hop's lease is extended, to `min(now + lease_interval, token exp, parent lease expiry)`, never earlier than before. A child therefore cannot outlive a parent that stopped renewing, and a token cannot be renewed past its own `exp`.
3. Renewal is refused when the lease or any ancestor is revoked or unknown, or an ancestor has expired. An expired but unrevoked lease of the caller itself can be renewed, as long as the token is still valid and the ancestors are live.
4. Every request is checked against the registry, not only `tools/call`. `Pipeline::decide` checks every lease in the chain (`lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, in that order) before policy. Requests forwarded without a decision (`tools/list`, `initialize`, `ping`, `GET`/`DELETE` session requests) get the same check and are refused with 401.
5. Revocation (`POST /admin/leases/{id}/revoke`) marks the lease and all descendants revoked in one transaction and takes effect on the next request. There is no lease cache in v0, so the "within one interval" bound is a worst case for a stopped holder, and the actual latency for an explicit revoke is one request.
6. Issuance and renewal are appended to the audit log (`token.root`, `token.exchange`, `lease.renew`). A renewal that cannot be recorded is rolled back.

### Consequences

- Good, because one revoke call withdraws a whole subtree, and nothing needs to know which tokens exist.
- Good, because an agent that crashes or is abandoned loses authority after at most one interval, with no operator action.
- Good, because the registry is the only state; losing a row denies (`lease_unknown`) instead of allowing.
- Bad, because every honest long-running agent must call `/token/renew` at an interval shorter than `lease_interval`. A client that forgets sees `lease_expired` while its JWT still verifies, which looks like a bug until the renewal contract is known.
- Bad, because enforcement depends on a store lookup per request; a shared or remote registry would add latency and a new failure mode (which fails closed).
- Neutral, because the cache described in RFC-0001 section 6 (state cached up to one interval) is deliberately not built; it would trade revocation latency for load and needs its own ADR.
- Neutral, because lease renewal is only for the last hop. A parent that wants its sub-agents alive must keep renewing its own lease, which is exactly the cap that makes revocation of a parent effective.

### Confirmation

- `crates/attenuo-audit/tests/leases.rs`: `revoke_cascades_to_descendants_only`, `renew_extends_and_revives_an_expired_lease`, `renew_rejects_unknown_and_revoked` (memory and SQLite stores).
- `crates/attenuo-server/src/authz.rs`: `any_hop_with_an_unrenewed_lease_denies`.
- `crates/attenuo-server/tests/e2e.rs`: `revoking_root_lease_cascades_to_child`, `leases_are_issued_with_the_lease_interval_not_the_token_ttl`, `renew_never_goes_beyond_token_expiry`, `renew_never_goes_beyond_the_parent_lease`, `unrenewed_lease_denies_even_though_the_jwt_is_valid`, `expired_parent_blocks_child_renewal_and_calls`, `revoked_lease_cannot_be_renewed_and_token_problems_are_401`, `revoked_token_cannot_list_tools_over_the_proxy`.
- `crates/attenuo-proxy/tests/proxy.rs`: `revoked_token_cannot_list_tools_or_use_session_requests`.

## Pros and Cons of the Options

### Lease per hop in a server-side registry

- Good, because it matches the delegation tree: revocation is a subtree operation.
- Good, because liveness is tied to the holder's heartbeat, not to the issuer remembering to revoke.
- Neutral, because the lease interval is a dial between revocation latency (short) and renewal traffic (long).
- Bad, because it adds a stateful component to an otherwise stateless token design.

### Token blacklist keyed by `jti`

- Good, because it is simple and standard.
- Bad, because each child token has its own `jti`; revoking a parent means finding and listing every descendant, and tokens not yet issued from a revoked parent still need a separate check.
- Bad, because entries must be kept until the token's `exp`, and nothing revokes an abandoned holder.

### Very short token lifetimes only

- Good, because no revocation state exists.
- Bad, because latency equals the lifetime, so a useful bound (seconds) forces constant re-exchange, which needs the parent token and the issuer on the hot path anyway.
- Bad, because there is no explicit kill at all.

### Introspection of every token at the IdP

- Good, because the IdP stays the single source of truth.
- Bad, because delegated hops are minted by attenuo, not by the IdP, so the IdP cannot answer for them.
- Bad, because it puts a network round trip on every call.

## More Information

- [RFC-0001](../spec/rfc-0001-attenuo.md) principle P4 and section 6.
- [design/server.md](../design/server.md) for the pipeline and the renewal flow.
- Revisit when a push-based revocation channel or a lease cache is proposed, or when renewal load shows up in [design/performance.md](../design/performance.md).

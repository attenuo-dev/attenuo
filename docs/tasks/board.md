# Task board

First 30 days. Technical tasks only. Milestones in [milestones.md](milestones.md); spec in [RFC-0001](../spec/rfc-0001-onbehalf.md).

## Now

- [ ] `onbehalf-core`: `Capability`, `CapabilitySet`, constraint types (set, numeric range, time range), `⊑` predicate.
- [ ] `onbehalf-core`: proptest suite for `⊑` (reflexive, transitive, empty-set minimal, adding a key narrows, removing a value narrows, widening fails).
- [ ] `onbehalf-core`: `DelegationChain`, `Hop`, `OriginatingUser`, canonical JSON (RFC 8785) for hashing.
- [ ] `onbehalf-token`: mint and verify JWT with `act`, `obo`, `cap`, `chain_id`, `depth`, `lease` claims; Ed25519 keys; JWKS endpoint.
- [ ] `onbehalf-token`: RFC 8693 `/token` endpoint for hop n+1 (parent onbehalf token as `subject_token`), rejecting any request where `requested ⋢ parent.cap`, depth or expiry widen, or `obo` is missing.
- [ ] `onbehalf-policy`: Cedar wrapper, schema for `Agent`, `Tool`, `Action`, request builder from (token, `tools/call`), capability match and lease check before evaluation.
- [ ] `onbehalf-proxy`: streamable-HTTP interception of `tools/call` for one upstream server; forward on permit, JSON-RPC error on deny.
- [ ] `onbehalf-audit`: append-only SQLite log, `prev_hash`/`hash` chaining, `onbehalf-audit verify` command.
- [ ] Scenario test: GitHub MCP over-privileged-PAT reproduction, blocked by a `repo` constraint; recorded as an integration test.

## Next

- [ ] Hop 0 from an OIDC ID token (JWKS fetch, `iss`/`aud`/`exp` checks) and from an ID-JAG assertion.
- [ ] Leases: `/lease/{id}/renew`, `/revoke` by user, session, chain (revoke by lease id with descendant cascade is done in the server); proxy cache bounded by TTL.
- [ ] Multi-hop demo: planner agent → coder sub-agent → GitHub tool, three exchanges, attenuated at each.
- [ ] AuthZEN conformance fixtures (the endpoint itself is done).
- [ ] Audit: signed checkpoints every N records; `kind` for `issue`, `decision`, `renew`, `revoke`, `checkpoint`.
- [ ] Server: real admin authentication, `actor_token` verification on exchange, `kid` in token headers, audit failed exchanges.
- [ ] CI: fmt, clippy `-D warnings`, tests, proptest with fixed seed in CI and random locally.
- [ ] AgentDojo / InjecAgent harness: run a no-policy baseline and an onbehalf-enforced run; report attack success and utility.

## Later

- [ ] `RelationResolver` trait and a SpiceDB-backed implementation; projection into Cedar entities; cache bound to lease TTL.
- [ ] Sender-constrained hop tokens (`cnf` with DPoP or SPIFFE JWT-SVID).
- [ ] AgentGateway integration as external PDP.
- [ ] Constraint algebra extensions (globs, nested objects) with decidability notes.
- [ ] Machine-checked statement of the attenuation invariant (Lean or Dafny sketch mirroring the proptest properties).
- [ ] Output labelling: mark tool results as untrusted and forbid flow into destructive tools without approval (design note first).
- [ ] Measurement study of delegation and credential patterns across public MCP servers.
- [ ] Benchmarks: p50/p99 added latency per call, exchange throughput, lease renewal load.

## Done

- [x] Repository skeleton: workspace, CI, licence, docs vault.
- [x] RFC-0001, threat model, ADR-0001 to ADR-0004, research notes (standards, incidents, related work).
- [x] `onbehalf-server`: config, `/token` (RFC 8693), JWKS endpoint, dev root mint, proxy with real authorizer, admin leases/audit endpoints ([design](../design/server.md)).
- [x] AuthZEN `POST /access/v1/evaluation` served by the same pipeline as the proxy; bearer or body chain.
- [x] Lease revocation cascade: integration test that revoking the root lease denies the child's next call (`lease_revoked`).
- [x] Policy hot reload with schema validation (`POST /admin/policies/reload`); invalid set rejected with 422, last good set kept.

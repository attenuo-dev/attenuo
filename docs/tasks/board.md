# Task board

First 30 days. Technical tasks only. Milestones in [milestones.md](milestones.md); spec in [RFC-0001](../spec/rfc-0001-onbehalf.md).

## Now

- [ ] `onbehalf-core`: `Capability`, `CapabilitySet`, constraint types (set, numeric range, time range), `⊑` predicate.
- [ ] `onbehalf-core`: proptest suite for `⊑` (reflexive, transitive, empty-set minimal, adding a key narrows, removing a value narrows, widening fails).
- [ ] `onbehalf-core`: `DelegationChain`, `Hop`, `OriginatingUser`, canonical JSON (RFC 8785) for hashing.
- [ ] `onbehalf-token`: mint and verify JWT with `act`, `chain` (originating user, hops with capabilities and leases), `ou_sig` claims; Ed25519 keys; JWKS endpoint.
- [ ] `onbehalf-token`: RFC 8693 `/token` endpoint for hop n+1 (parent onbehalf token as `subject_token`), rejecting any request where requested capabilities are not covered by the parent's last hop, or depth or expiry widen.
- [ ] `onbehalf-policy`: Cedar wrapper, schema for `Agent`, `Tool`, `Action`, request builder from (token, `tools/call`), capability match and lease check before evaluation.
- [ ] `onbehalf-proxy`: streamable-HTTP interception of `tools/call` for one upstream server; forward on permit, JSON-RPC error on deny.
- [ ] `onbehalf-audit`: append-only SQLite log, `prev_hash`/`hash` chaining, `onbehalf-audit verify` command.
- [ ] Scenario test: GitHub MCP over-privileged-PAT reproduction, blocked by a `repo` constraint; recorded as an integration test.
- [ ] Security SR-09 (high): revoked tokens still pass `authenticate`; check leases on every proxied HTTP request (GET/DELETE, `tools/list`, all methods), not only in `tools/call` decisions. Method coverage is on `feat/leases-and-coverage`.

- [x] Policy test harness: `onbehalf policy test` (YAML cases through the real `PolicyEngine`) and `onbehalf policy lint`; guide in [guides/writing-policies.md](../guides/writing-policies.md).

## Next

- [ ] Security review follow-ups ([review](../research/security-review-2026-10-22.md)): SR-13 server-scoped actions or documented `resource in Server::` pinning (`/` in server names is already rejected); SR-14 domain-separate `ou_sig` and bind it to `iss` and hop 0; SR-17 reason codes only in client-facing errors; SR-18 escape untrusted log fields; SR-19 require `public_url` off loopback; SR-20 RFC 8785 canonicalization (`preserve_order` is on workspace-wide); SR-22 move SQLite off the async workers; SR-23 filter `tools/list` over SSE; SR-24 sender-constrained tokens (credential and exchange replay is already refused, in memory per process); SR-25 name normalization; SR-26 resolve the `cargo deny` licence failure (`webpki-roots`, CDLA-Permissive-2.0) and add `cargo audit` to CI.
- [ ] Token claims: proposed extensions from RFC-0001 section 3.1: `evidence` on the originating user (how the IdP credential was verified), a stable `chain_id`, `may_act` and a verified `actor_token`, numeric and time-range constraints. Reconcile or drop each.
- [ ] Hop-0 hardening: a shared (multi-replica, restart-safe) replay cache for ID tokens and ID-JAGs, `private_key_jwt` client authentication, `evidence` in the user block; track ID-JAG drafts after -04.
- [ ] Leases: `/lease/{id}/renew`, `/revoke` by user, session, chain (revoke by lease id with descendant cascade is done in the server); proxy cache bounded by TTL.
- [ ] Hop 0 from an OIDC ID token (JWKS fetch, `iss`/`aud`/`exp` checks) and from an ID-JAG assertion.
- [ ] Leases: revoke by user, session, chain (revoke by lease id with descendant cascade and `POST /token/renew` are done); optional proxy cache bounded by TTL; audit failed renewals.
- [ ] Proxy: filter `resources/list`, `resources/templates/list` and `prompts/list` results by capability; decide whether `resources/unsubscribe` joins the allowlist.
- [ ] Multi-hop demo: planner agent → coder sub-agent → GitHub tool, three exchanges, attenuated at each.
- [ ] Policy harness follow-ups: report which policies no case exercised, run cases through the AuthZEN endpoint too, a `--schema-file` for custom base schemas, `onbehalf policy test --watch`.
- [ ] AuthZEN conformance fixtures (the endpoint itself is done).
- [ ] Audit: signed checkpoints every N records; `kind` for `issue`, `decision`, `renew`, `revoke`, `checkpoint`.
- [ ] Server: real admin authentication, `actor_token` verification on exchange, audit failed exchanges.
- [ ] CI: fmt, clippy `-D warnings`, tests, proptest with fixed seed in CI and random locally.
- [ ] Server: real admin authentication, `actor_token` verification on exchange, `kid` in token headers, audit failed exchanges.
- [ ] CI: proptest with a fixed seed in CI and random locally. Also: confirm the new workflows on GitHub (MSRV 1.89, musl and macOS release builds, GHCR push, cosign, SBOM) with a `v0.0.0-test` tag on a fork; enable private vulnerability reporting and the DCO app; set the GHCR package public.
- [ ] AgentDojo / InjecAgent harness: run a no-policy baseline and an onbehalf-enforced run; report attack success and utility.
- [ ] Docs follow-ups from the guides: test the Keycloak, Auth0, Okta, Entra ID and Google recipes (and ID-JAG with Okta) against live tenants and drop the "untested" marks; add a CI check that runs the getting-started commands.
- [x] Operations gaps from the deploy guide: SIGTERM graceful shutdown, `/readyz`, `/metrics`, key rotation with overlap (`kid`, `previous_key_paths`). Still open: automatic signed audit checkpoints; audit append latency histogram (only authorize duration exists); `spawn_blocking` for SQLite.
- [x] Policy: `[policy] user_attributes` declares extra `originating_user.attributes`.
- [ ] Operations gaps found while writing the deploy guide: handle SIGTERM for graceful shutdown; a readiness check that touches SQLite; a metrics endpoint (decision counts by reason, audit append latency); automatic signed audit checkpoints.
- [ ] Policy: let operators declare extra `originating_user.attributes` (for example `groups`) in config. Today only `mfa`, `roles`, `tenant` and `email` are in the Cedar schema, and a policy that tests anything else is reported impossible.
- [ ] Python SDK follow-ups: publish to PyPI (name, trusted publishing, release workflow); a token-refresh helper (renew at a third of the interval, re-exchange before `exp`); streaming responses in `call_tool`; test the hop-0 exchange against a live IdP; run the unit suite on Python 3.10 in CI and confirm the workflow; keep the `kid` check in `inspect(verify=True)` aligned with the server's header and JWKS `kid`.

## Later

- [ ] `RelationResolver` trait and a SpiceDB-backed implementation; projection into Cedar entities; cache bound to lease TTL.
- [ ] Sender-constrained hop tokens (`cnf` with DPoP or SPIFFE JWT-SVID).
- [ ] AgentGateway integration as external PDP.
- [ ] Constraint algebra extensions (globs, nested objects) with decidability notes.
- [ ] Machine-checked statement of the attenuation invariant (Lean or Dafny sketch mirroring the proptest properties).
- [ ] Output labelling: mark tool results as untrusted and forbid flow into destructive tools without approval (design note first).
- [ ] Measurement study of delegation and credential patterns across public MCP servers.
- [ ] Benchmarks: p50/p99 added latency per call through the proxy, exchange throughput, lease renewal load (micro-benchmarks for `authorize` and `covers` are done; see [performance](../design/performance.md)).

## Done

- [x] Security review pass 2 (`fix/security-pass-2`): SR-08 AuthZEN needs a bearer (body chains only for authenticated `[[peps]]`, leases bound to chain digests); SR-10 exchange actor authenticated by `[[agents]]` secret, duplicate agents refused; SR-11 `Mcp-Session-Id` bound to user and root lease; SR-12 uncatalogued tools denied by default (`[policy] unknown_tools`), `/` refused in server names; SR-15 weak admin tokens refused off loopback, admin actions audited; SR-16 structural chain checks; one-time use of IdP credentials and (parent, actor) exchanges, root TTL capped by the credential. `actor_token` verification is still open.
- [x] CI and release workflows (fmt, clippy, test matrix, MSRV, deny, audit, demo, policy tests, docs and link checks; musl/macOS archives, signed GHCR image, SBOM, draft release), dev scripts and justfile, repo hygiene files. Workflow YAML parses; none of it has run on GitHub.
- [x] Python SDK (`sdk/python`, package `onbehalf`): sync and async clients, admin client, capability helpers, `onbehalf.mcp`, unit and integration tests, `sdk-python` workflow, [agent example](../../examples/python-agent/agent.py).
- [x] User guides (`docs/guides/`), FAQ and positioning table; wire examples verified against a local build. IdP recipes remain untested against live providers.
- [x] Security review pass 1: SR-01 to SR-07 fixed with regression tests (proxy re-encodes screened messages, no upstream redirects, non-object arguments rejected; Cedar action hierarchy; integral floats as Long; TTL overflow; root-grant attributes).
- [x] Lease renewal: `POST /token/renew`, `LeaseStore::renew`, lease expiry enforced for every hop, ADR-0006.
- [x] Proxy coverage: `resources/read`, `resources/subscribe`, `prompts/get`, `completion/complete` authorized; unknown methods denied by default; `tools/list` and session requests lease-checked.
- [x] Criterion benchmarks for `PolicyEngine::authorize` and `CapabilitySet::covers`.
- [x] Repository skeleton: workspace, CI, licence, docs vault.
- [x] RFC-0001, threat model, ADR-0001 to ADR-0004, research notes (standards, incidents, related work).
- [x] `onbehalf-server`: config, `/token` (RFC 8693), JWKS endpoint, dev root mint, proxy with real authorizer, admin leases/audit endpoints ([design](../design/server.md)).
- [x] AuthZEN `POST /access/v1/evaluation` served by the same pipeline as the proxy; bearer or body chain.
- [x] Lease revocation cascade: integration test that revoking the root lease denies the child's next call (`lease_revoked`).
- [x] Hop 0 from an OIDC ID token and from an ID-JAG: trusted `[[idps]]`, JWKS discovery and cache, `[[agents]]` client auth, root grants; dev root mint off by default ([design](../design/server.md#hop-0-intake-from-an-identity-provider)).
- [x] `onbehalf-cli`: the `onbehalf` binary for tokens, calls, leases, audit and policy, with unit-tested arguments and tree rendering.
- [x] GitHub MCP leak demo: `examples/github-leak-demo/run.sh` with a transcript; the integration-test form of the scenario (first item under Now) is still open.
- [x] Policy hot reload with schema validation (`POST /admin/policies/reload`); invalid set rejected with 422, last good set kept.

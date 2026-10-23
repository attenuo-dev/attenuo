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
- [x] Security SR-27 (medium, [pass 3](../research/security-review-2026-10-23.md)): reject requests with more than one `Mcp-Session-Id` or a non-visible-ASCII one, and forward only the validated value; un-ignore `a_second_session_header_cannot_smuggle_another_principals_session`. Apply after `feat/proxy-list-filtering` merges.
- [x] Security SR-28 (medium, pass 3): re-check leases and token expiry on open SSE streams (GET listen stream, streamed POST responses) and end them; un-ignore `revocation_ends_an_open_sse_stream`. Done on `fix/sr27-sr28-streams`.

- [x] Security SR-13, SR-25, SR-36 (`fix/sr13-sr25-sr36`): actions are `Action::"<server>/<tool>"` (BREAKING; deprecated `[policy] legacy_bare_actions`, lint flags bare actions); one name rule `[A-Za-z0-9_.-]` in core; the proxy refuses invalid and unlisted `tools/call` names (`[proxy] require_listed_tools`); the session registry refuses when full instead of evicting live sessions (503); buffered upstream and request bodies are capped. A per-principal session cap (SR-36's other suggestion) is not done.
- [x] Policy test harness: `onbehalf policy test` (YAML cases through the real `PolicyEngine`) and `onbehalf policy lint`; guide in [guides/writing-policies.md](../guides/writing-policies.md).

## Next

- [ ] Security review follow-ups ([review](../research/security-review-2026-10-22.md)): SR-20 RFC 8785 canonicalization (`preserve_order` is on workspace-wide); SR-22 move SQLite off the async workers; SR-23 filter `tools/list` over SSE; SR-24 sender-constrained tokens (credential and exchange replay is already refused, in memory per process); Pass 3 ([review](../research/security-review-2026-10-23.md)): SR-30 remainder, pin by SHA the tag-referenced actions in `ci.yml`, `docs.yml`, `sdk-*.yml` (listed in the review row; needs API access to resolve SHAs, Docker images are done). Fixed since this item was written: SR-13, SR-14, SR-17, SR-18, SR-19, SR-25, SR-32, SR-33, SR-34, SR-35, SR-36, SR-37, SR-38.
- [ ] Token claims: proposed extensions from RFC-0001 section 3.1: `evidence` on the originating user (how the IdP credential was verified), a stable `chain_id`, numeric and time-range constraints. Reconcile or drop each. (`may_act` and a verified `actor_token` are done.)
- [ ] Actor token follow-ups: test `[[actor_trust]]` against a live SPIRE (bundle endpoint and OIDC discovery provider) and drop the "untested" marks; consider a per-entry opt-out of single use for SPIRE's JWT-SVID cache; record the actor-auth method in the audit record itself (today only in the argument digest and the log line).
- [ ] Hop-0 hardening: a shared (multi-replica, restart-safe) replay cache for ID tokens and ID-JAGs, `private_key_jwt` client authentication, `evidence` in the user block; track ID-JAG drafts after -04.
- [ ] Leases: revoke by user, session, chain (revoke by lease id with descendant cascade and `POST /token/renew` are done); optional proxy cache bounded by TTL; audit failed renewals.
- [x] Proxy: filter `resources/list`, `resources/templates/list` and `prompts/list` results by capability, also over SSE and in batches (`feat/proxy-list-filtering`).
- [ ] Proxy: decide whether `resources/unsubscribe` joins the allowlist; filter list responses replayed on a resumed `GET` stream; consider Cedar-aware list filtering.
- [ ] Multi-hop demo: planner agent → coder sub-agent → GitHub tool, three exchanges, attenuated at each.
- [ ] Policy harness follow-ups: report which policies no case exercised, run cases through the AuthZEN endpoint too, a `--schema-file` for custom base schemas, `onbehalf policy test --watch`.
- [ ] AuthZEN conformance fixtures (the endpoint itself is done).
- [x] Audit: signed checkpoints every N records and every T seconds, verified against the JWKS, with export and offline verify (`feat/audit-hardening`).
- [ ] Audit: `kind` for `issue`, `decision`, `renew`, `revoke`, `checkpoint` and `chain_id` (RFC-0001 section 7); ship checkpoints off the host (no built-in sink yet); RFC 8785 canonical JSON (SR-20).
- [ ] Audit: a dedicated writer thread with group commit if single-writer SQLite throughput becomes the limit (appends now run on the blocking pool behind one lock).
- [ ] Server: real admin authentication, audit failed exchanges.
- [ ] CI: proptest with a fixed seed in CI and random locally. Also: confirm the new workflows on GitHub (MSRV 1.89, musl and macOS release builds, GHCR push, cosign, SBOM) with a `v0.0.0-test` tag on a fork; enable private vulnerability reporting and the DCO app; set the GHCR package public.
- [ ] AgentDojo / InjecAgent harness: run a no-policy baseline and an onbehalf-enforced run; report attack success and utility.
- [ ] Docs follow-ups from the guides: test the Keycloak, Auth0, Okta, Entra ID and Google recipes (and ID-JAG with Okta) against live tenants and drop the "untested" marks; add a CI check that runs the getting-started commands.
- [x] Operations gaps from the deploy guide: SIGTERM graceful shutdown, `/readyz`, `/metrics`, key rotation with overlap (`kid`, `previous_key_paths`). Done in `feat/audit-hardening`: automatic signed audit checkpoints, `audit_append_duration_seconds`, SQLite I/O on the blocking pool.
- [x] Policy: `[policy] user_attributes` declares extra `originating_user.attributes`.
- [ ] SDK follow-ups: offline `audit verify` (export file plus JWKS) in the SDKs; the CLI has it.
- [ ] Python SDK follow-ups: publish to PyPI (name, trusted publishing, release workflow); a token-refresh helper (renew at a third of the interval, re-exchange before `exp`); streaming responses in `call_tool`; test the hop-0 exchange against a live IdP; confirm the Python 3.10 CI job on GitHub (syntax is checked locally by `test_python310_grammar.py`); keep the `kid` check in `inspect(verify=True)` aligned with the server's header and JWKS `kid`.
- [ ] TypeScript SDK follow-ups: publish to npm (scope `@onbehalf`, provenance); a token-refresh helper and a per-request token hook for the MCP transport; streaming in `callTool`; confirm the workflow on GitHub (Node 20 and 22; Ed25519 WebCrypto needs no flag on 20); test hop-0 against a live IdP.

- [ ] Board hygiene (found in the 2026-10-23 docs pass): the "Now" items above (core types, token endpoint, policy wrapper, proxy, audit log, leak scenario) describe work that exists in the tree and appears under Done in other words; confirm each and tick or drop it. "Leases: revoke by user, session, chain" is the only open lease item. The RFC 8785 canonical-JSON part of the `onbehalf-core` item is still open (SR-20).

## Later

- [ ] `RelationResolver` trait and a SpiceDB-backed implementation; projection into Cedar entities; cache bound to lease TTL.
- [ ] Sender-constrained hop tokens (`cnf` with DPoP or SPIFFE JWT-SVID).
- [ ] AgentGateway integration as external PDP.
- [ ] Constraint algebra extensions (globs, nested objects) with decidability notes.
- [ ] Machine-checked statement of the attenuation invariant (Lean or Dafny sketch mirroring the proptest properties).
- [ ] Output labelling: mark tool results as untrusted and forbid flow into destructive tools without approval (design note first).
- [ ] Measurement study of delegation and credential patterns across public MCP servers.
- [ ] Benchmarks, remaining: exchange throughput and lease renewal load; open-loop arrival rates and repeated runs with intervals (RQ2); a per-stage time breakdown of the proxied call; a quiet reference machine.
- [ ] Performance findings from the first end-to-end run ([performance](../design/performance.md#end-to-end-proxy-versus-direct); measurement only, nothing changed): (1) the audit store runs SQLite defaults, so a file-backed log is one synced commit per decision and caps the proxy at roughly 300 to 600 calls per second on this container (memory: about 4,500), denials included; consider WAL with `synchronous=NORMAL` or group commit (see the writer-thread item under Next); (2) end-to-end cost per call roughly doubles from 1 to 3 hops (about 4,500 to 2,200 calls per second) while Cedar alone adds about 20 us per hop, so find the per-hop cost (verification, lease lookups) with tracing spans; (3) the proxied call costs about 0.7 ms at p50 against about 0.12 ms for the Cedar decision, so most of the added latency is outside policy evaluation.

## Done

- [x] SR-14 and hop-0 actor tokens (`fix/sr14-ou-sig-and-hop0-actor`): `ou_sig` v2 bound to `iss` and the root hop with `ou_sig_v`/`ou_kid` (v1 refused, BREAKING); `actor_token` accepted at IdP intake under `[token] actor_auth`; `may_act` on `token root --may-act`, Python `mint_root_dev(may_act=)`, TypeScript `mintRootDev({ mayAct })`.
- [x] Actor authentication (`feat/actor-token`, [ADR-0007](../decisions/0007-actor-authentication.md)): RFC 8693 `actor_token` on exchange verified against `[[actor_trust]]` (SPIFFE trust domain via the SPIRE bundle endpoint, or any JWKS issuer), `[token] actor_auth = "secret" | "actor_token" | "either"`, single-use actor tokens with the child TTL capped by their `exp`, `may_act` on issued tokens (request field and `[[root_grants]] may_act`) enforced as `actor_not_permitted`; CLI `--actor-token`/`--actor-token-file`/`--may-act`, Python `actor_token=`, TypeScript `{ actorToken }`.

- [x] End-to-end benchmark (`feat/e2e-bench`): `onbehalf-bench` crate and `scripts/bench-e2e.sh`, proxy versus direct at 1, 8 and 32 clients, 1 and 3 hops, allow and two denials, memory and file audit, audit chain verified at the end; first results committed in `docs/design/bench/`.
- [x] Security review pass 3 (`review/security-pass-3`): 13 findings (SR-27 to SR-39, no High); fixed SR-29 (ECDSA replay bypass), SR-30 (release actions pinned), SR-31 (Python SDK path encoding), SR-34 (`onbehalf` server name reserved), SR-39; SR-09 and SR-26 verified fixed. SR-27 and SR-28 open in the proxy with ignored tests.
- [x] Security review pass 2 (`fix/security-pass-2`): SR-08 AuthZEN needs a bearer (body chains only for authenticated `[[peps]]`, leases bound to chain digests); SR-10 exchange actor authenticated by `[[agents]]` secret, duplicate agents refused; SR-11 `Mcp-Session-Id` bound to user and root lease; SR-12 uncatalogued tools denied by default (`[policy] unknown_tools`), `/` refused in server names; SR-15 weak admin tokens refused off loopback, admin actions audited; SR-16 structural chain checks; one-time use of IdP credentials and (parent, actor) exchanges, root TTL capped by the credential. `actor_token` verification followed on `feat/actor-token`.
- [x] Documentation site: mdBook build of `docs/` (`book.toml`, `docs/SUMMARY.md`), concept and reference pages, Pages workflow `docs.yml`. Not yet run on GitHub; Pages must be set to "GitHub Actions" as the source in the repo settings.
- [x] CI and release workflows (fmt, clippy, test matrix, MSRV, deny, audit, demo, policy tests, docs and link checks; musl/macOS archives, signed GHCR image, SBOM, draft release), dev scripts and justfile, repo hygiene files. Workflow YAML parses; none of it has run on GitHub.
- [x] Python SDK (`sdk/python`, package `onbehalf`): sync and async clients, admin client, capability helpers, `onbehalf.mcp`, unit and integration tests, `sdk-python` workflow, [agent example](../../examples/python-agent/agent.py).
- [x] TypeScript SDK (`sdk/typescript`, package `@onbehalf/sdk`): `OnbehalfClient`, `AdminClient`, capability builders, `mcpHeaders`/`mcpUrl`, unit and integration tests, `sdk-typescript` workflow, [agent example](../../examples/typescript-agent/agent.ts) and the official MCP client example.
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

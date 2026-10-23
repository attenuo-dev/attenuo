# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, minor versions may contain breaking changes; each one is called out under **Changed** or **Removed** with a `BREAKING:` prefix.

Entries are written by hand. `git cliff --unreleased` (see `cliff.toml`) produces a draft from conventional commits that is edited into this file before a release. Security fixes always go under **Security**, with the advisory identifier once one exists.

## [Unreleased]

### Added

- Workspace skeleton: `onbehalf-core`, `onbehalf-token`, `onbehalf-policy`, `onbehalf-audit`, `onbehalf-proxy`, `onbehalf-server` crates.
- Core model: delegation chains, capability sets, attenuation, decision records.
- Project process files: ADR and RFC process, security policy, code of conduct, governance, contribution guide, release and supply-chain workflows.
- `onbehalf-server` binary: TOML config (`--config` / `ONBEHALF_CONFIG`), RFC 8693 `POST /token` (form and JSON), AuthZEN `POST /access/v1/evaluation` and discovery, `/.well-known/jwks.json`, the MCP proxy at `/mcp/{server}` backed by a real authorizer (lease check, policy, audit), admin endpoints for lease revocation and status, audit range/verify/checkpoint and policy hot reload, and a development-only root-token mint. Example config in `config/example.toml`; design in `docs/design/server.md`.
- Hop-0 intake from an identity provider at `POST /token`: an OIDC ID token (`subject_token_type=urn:ietf:params:oauth:token-type:id_token`) or an ID-JAG (`...:token-type:id-jag`, or `grant_type=...:jwt-bearer`, draft -04) is verified against a trusted issuer's JWKS (discovery or `jwks_url`, cached, refetched once on an unknown `kid`) and exchanged for a root delegation token whose originating user is taken from the verified claims. New config: `[[idps]]`, `[[agents]]` (client authentication), and `[dev]`. Errors carry a stable `error_description`.
- `onbehalf-cli` crate with the `onbehalf` binary: `token root|exchange|inspect` (tree view, `--verify` against the server JWKS), `call`, `tools`, `lease revoke|show`, `audit tail|verify`, `policy reload`, `authzen eval`; human output by default, `--json` for machines.
- `examples/github-leak-demo`: scripted replay of the May 2025 GitHub MCP prompt-injection leak (`run.sh`, config, policy, transcript), with `fake_mcp`, a runnable fake GitHub MCP server in `onbehalf-proxy`'s examples.
- `Dockerfile`, `docker-compose.yml` and `.dockerignore` (untested).

- `POST /token/renew`: the holder of a delegation token extends its last hop's lease by `[issuer] lease_interval_seconds` (new, default 300), never beyond the token's `exp` or the parent lease's expiry. `LeaseStore::renew` on both stores. Renewals are audited as `lease.renew`. See ADR-0006.
- Proxy enforcement coverage: `resources/read`, `resources/subscribe`, `prompts/get` and `completion/complete` are authorized as tool calls, and any other non-notification method outside the allowlist is denied unless a capability and the policy permit a tool named after the method. Mapping documented in `onbehalf-proxy` and `docs/design/server.md`.
- Criterion benchmarks for `PolicyEngine::authorize` and `CapabilitySet::covers`; numbers in `docs/design/performance.md`.
- ADR-0006: lease-based in-flight revocation.
- Policy test harness: `onbehalf_policy::testing` loads YAML test files (user, agent chain, call, expected decision, reason and deciding policy ids), builds real delegation chains, runs them through `PolicyEngine::authorize` and returns a report. `onbehalf policy test <file>... [--json]` runs them offline (exit 0 pass, 1 error, 2 failures). `onbehalf policy lint <policy.cedar> [--config server.toml] [--schema]` parses and validates a policy file against the schema generated from the catalog, with line and column. `onbehalf_policy::lint` exposes the same check as a library. Example: `examples/github-leak-demo/policy_test.yaml`, run by `run.sh`. Guide: `docs/guides/writing-policies.md`.
- Operations hardening: graceful shutdown on SIGTERM and SIGINT with a 10 s drain of in-flight requests; `GET /readyz` (audit store and lease store, 503 with a JSON body on failure; `/healthz` stays liveness-only); Prometheus `GET /metrics` on its own listener (`[metrics] enabled`, `listen`, default `127.0.0.1:9100`) with `decisions_total`, `tokens_issued_total`, `leases_revoked_total`, `audit_append_errors_total`, `http_requests_total` and `authorize_duration_seconds`.
- Key rotation with overlap: tokens carry a `kid`; `Verifier` trusts a set of keys; `[issuer] previous_key_paths` keeps retired keys verify-only and publishes them in the JWKS. `Issuer::trust_previous_key`, `Verifier::with_public_pem`, `TokenError::UnknownKeyId`. Procedure in `docs/guides/deploying.md`.
- `[policy] user_attributes = { groups = "set<string>", ... }` declares extra `originating_user.attributes` in the generated Cedar schema; `onbehalf policy lint --config` and `policy test` read it too.
- Python SDK `onbehalf` in `sdk/python` (Python 3.10+, depends on `httpx`; optional `verify` extra for `cryptography`): `Client` and `AsyncClient` with `exchange`, `renew`, `call_tool` (raises `Denied(reason, decision_id)`; parses JSON and SSE responses), `list_tools`, `authzen_evaluate` and `inspect(verify=True)` (Ed25519 against the JWKS); `AdminClient` with `revoke_lease`, `audit_tail`, `audit_verify`, `policy_reload` and the development root mint; a `Capability(..., repo=Prefix(...))` helper with the same wire shape as the CLI; `onbehalf.mcp` header helpers for MCP clients. Unit tests on `httpx.MockTransport`, an integration test (`ONBEHALF_INTEGRATION=1`) that replays the GitHub leak scenario against the real server, and a separate `sdk-python` workflow. Examples in `examples/python-agent` (planner to coder delegation; the official `mcp` client through the proxy). Not on PyPI.
- TypeScript SDK `@onbehalf/sdk` in `sdk/typescript` (Node 20+, strict TypeScript, ESM and CJS builds, no runtime dependencies, global `fetch`): `OnbehalfClient` with `exchange`, `renew`, `callTool` (throws `DeniedError` with `reason` and `decisionId`; parses JSON and SSE responses), `listTools`, `initialize`, `authzenEvaluate`, `jwks` and `inspect({ verify })` (Ed25519 against the JWKS through WebCrypto); `AdminClient` with `revokeLease`, `leaseStatus`, `audit`, `auditTail`, `auditVerify`, `auditCheckpoint`, `policyReload` and the development root mint; `capability(server, tool, { repo: prefix(...) })` builders with the same wire shape as the CLI; `mcpUrl` and `mcpHeaders` for MCP clients. Unit tests (vitest, mocked `fetch`), an integration test (`ONBEHALF_INTEGRATION=1`) that replays the GitHub leak scenario against the real server and runs the examples, and a separate `sdk-typescript` workflow (Node 20 and 22). Examples in `examples/typescript-agent` (planner to coder delegation; the official `@modelcontextprotocol/sdk` client through the proxy). Not on npm.
- `resources/list`, `resources/templates/list` and `prompts/list` results are filtered like `tools/list`: entries no capability could permit (`resources/read` with the `uri` constraint, `prompts/get` with the `name` constraint) are dropped; `nextCursor` passes through. `onbehalf_proxy::filter` gains `ListKind`, `ListFilter` and `could_permit_resource|resource_template|prompt`, and `onbehalf_proxy::sse` the incremental SSE rewriter. `FakeMcpServer` gains resources, templates, prompts, pagination and an event-per-response SSE mode.
- `tests/mcp_conformance.rs`: a table-driven walk of the MCP method surface (allowed, denied, never forwarded when denied or revoked).

### Changed

- JWKS `kid` is now the first 16 bytes of SHA-256 over the SPKI DER, base64url (22 characters), replacing the 16 hex characters. A token whose `kid` is not trusted is rejected (`UnknownKeyId`); tokens without a `kid` are tried against every trusted key.
- CI split into fmt, clippy, test (ubuntu, macOS), MSRV, cargo-deny, cargo-audit, demo, policy-test and docs (rustdoc and Markdown links) jobs. `.github/workflows/release.yml` builds musl and macOS archives, a signed multi-arch GHCR image with an SBOM, `SHA256SUMS` and a changelog section from the cliff config, and creates a draft release (untested until a tag is pushed).
- `scripts/dev.sh`, `scripts/gen-admin-token.sh`, `scripts/check-links.py` and a `justfile`; `.editorconfig`, `SUPPORT.md`, a commented-out `.github/FUNDING.yml` and an MSRV badge.

### Changed

- MSRV (`rust-version`, `clippy.toml`) raised from 1.85 to 1.89, which the locked dependencies already required. Not tested on 1.89 itself; the CI `msrv` job will.
- BREAKING: `POST /admin/root-token` is mounted only when `[dev] allow_root_mint = true` (default `false`); otherwise it answers 404.
- `[[root_grants]]` entries no longer need a `subject`: without one an entry applies to every user of its `issuer`. The same list now caps IdP intake.
- BREAKING: `LeaseStore` has a new required method `renew`; `onbehalf_proxy::Authorizer` has a new required method `check_active`, and `AuthError` a new variant `LeaseInactive`.
- Leases are registered with `expires_at = min(now + lease_interval, token exp)` instead of the token's expiry, so a holder that stops renewing is denied (`lease_expired`) within one interval while its JWT is still valid.
- `tools/list`, `initialize`, `ping`, the other allowlisted methods and `GET`/`DELETE` session requests are now lease-checked; a revoked token gets 401 instead of being served.
- BREAKING: `POST /access/v1/evaluation` requires the delegation token as bearer. Body-only chains need `[authzen] allow_unsigned_chain = true` and an authenticated `[[peps]]` client (SR-08).
- BREAKING: a hop n+1 token exchange must authenticate as its `actor` with `[[agents]]` client credentials (`[token] require_actor_auth`, default `true`). The CLI takes `--client-id` / `--client-secret` (env `ONBEHALF_CLIENT_SECRET`) on `token exchange` (SR-10).
- BREAKING: tool calls for tools missing from `[policy.catalog]` are denied by default (`[policy] unknown_tools = "deny" | "sensitive" | "allow"`); server names containing `/` are rejected at startup (SR-12, SR-13).
- BREAKING: off a loopback `listen` address the server refuses to start without a strong admin token (at least 32 bytes, not a published placeholder); `ONBEHALF_ADMIN_TOKEN` overrides `[admin] token`, and `config/example.toml` ships no token (SR-15).
- BREAKING: an `Mcp-Session-Id` the proxy did not see the upstream assign gets 404; one bound to another principal gets 403 (SR-11). `onbehalf_proxy::Authorizer` gained `record_rejection` (with a default), and `LeaseStore` gained `bind` and `binding`.
- Policy test files take `unknown_tools`, and pick up `[policy] unknown_tools` from a server config named as `catalog`.
- Python SDK: `exchange(..., client_secret=...)` from a delegation token authenticates the actor (`client_id` defaults to `actor`) and stays a hop n+1 exchange; client credentials only make it hop 0 when the subject token is not an onbehalf token. The examples and the integration test pass the demo agents' secrets; the demo config registers a `tester` agent.

### Deprecated

### Removed

### Fixed

- A rustdoc intra-doc link in `onbehalf-proxy` to the feature-gated `testing` module broke `cargo doc` with `-D warnings`.

### Documentation

- `docs/research/standards.md`: `draft-klrc-aiagent-auth` expired and is replaced by `draft-ietf-wimse-aims` (checked on the IETF datatracker).
- Guides in `docs/guides/`: getting started, deploying (with the v0 limits stated plainly), integrating MCP clients, and identity providers (Keycloak, Auth0, Okta, Entra ID, Google; provider recipes marked untested). Index in `docs/guides/README.md`.
- `docs/faq.md`: fifteen launch-day questions.
- Positioning table in `docs/research/related-work.md`.
- RFC-0001 section 7 now says what the audit log implements today (hash over `(seq, prev_hash, record)`, no automatic checkpoints, no `kind` field) next to the design target.
- Documentation site: the `docs/` tree is built with mdBook (`book.toml`, `docs/SUMMARY.md`) and deployed to GitHub Pages by `.github/workflows/docs.yml` (mdBook 0.4.52, pinned). New concept pages in `docs/concepts/` (delegation chain, capabilities and attenuation, leases and revocation, audit log, enforcement points) and reference pages in `docs/reference/` (CLI commands, config keys, HTTP endpoints). Links from `docs/` to files outside it are now absolute GitHub URLs. Preview steps are in CONTRIBUTING.md.

### Security

- SR-08 (high): AuthZEN evaluated unsigned chains from unauthenticated callers, so anyone who had seen a lease id could get decisions and write audit records for a forged user. The bearer is now required by default; body chains need a PEP credential, and every hop's lease must be bound (at issuance, write-once) to the digest of the chain prefix that created it.
- SR-10 (high): the `actor` of a token exchange was asserted, not authenticated, so any token holder could mint a child naming any agent. The actor now authenticates with its `[[agents]]` secret and must match `actor`; an agent already in the chain is refused (`duplicate_actor`).
- SR-11 (medium): `Mcp-Session-Id` was not bound to the caller, so another user's token could use, listen on or end a session. Session ids are bound to the originating user and root lease; mismatches get 403 `session_mismatch` and an audit record. Logs, policy context and audit records carry a hash prefix of the id, never the id.
- SR-12 (medium): tools missing from the catalog were evaluated as not `sensitive`, so `forbid ... when { resource.sensitive }` failed open for them. They are now denied with `tool_not_in_catalog` unless `[policy] unknown_tools` says otherwise.
- SR-15 (medium): the example config's fixed admin token was accepted on any bind address. Weak or placeholder admin tokens now stop the server off loopback, and admin actions (lease revocation, policy reload, dev root mint) are written to the audit log.
- SR-16 (low): `DelegationChain::validate_at` now rejects empty agent and lease ids, `issued_at` at or after `expires_at` or before the parent's, and repeated leases or agents.
- SR-24 (info, partial): each OIDC ID token or ID-JAG mints at most one root token, a parent token delegates to a given actor at most once (in-memory replay cache, `invalid_grant` / `replayed`), and a root token never outlives the credential it came from.
- Proxy: `tools/list` results delivered over SSE were passed through unfiltered (SR-23). List results are now filtered in JSON bodies, JSON-RPC batches and `text/event-stream` bodies. A list request answered with an unparseable body, or a content type that is neither JSON nor SSE, gets `502` instead of an unfiltered result.
- SR-29 (medium): an ECDSA-signed ID token without `jti` could be redeemed for a second root token by re-encoding its signature (`s` to `n - s`), because the replay cache hashed the whole credential. It now hashes the JWS signing input.
- SR-30 (medium): the release workflow, which can push and sign images and create releases, ran third-party actions from mutable tags and restored a shared cargo cache. Every action in `release.yml` is pinned to a commit SHA and the release build starts without a cache.
- SR-31 (low): the Python SDK put server names and lease ids into URL paths unencoded, so `..`, `?` or `/` in them sent the request (with the admin or delegation bearer) to another endpoint. They are now percent-encoded, and `.` and `..` are refused.
- SR-34 (low): an upstream named `onbehalf` could write tool-call audit records that look like the server's own issuance, renewal and admin records. The name is now reserved.
- SR-39 (info): an IdP credential with a float `exp` was refused as expired.
- Pass 3 of the security review (`docs/research/security-review-2026-10-23.md`) also reports two open proxy findings with ignored regression tests: a second `Mcp-Session-Id` header bypasses session binding (SR-27, medium), and open SSE streams survive revocation and token expiry (SR-28, medium).

[Unreleased]: https://github.com/7Mudit/onbehalf/compare/main...HEAD

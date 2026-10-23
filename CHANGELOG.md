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
- CI split into fmt, clippy, test (ubuntu, macOS), MSRV, cargo-deny, cargo-audit, demo, policy-test and docs (rustdoc and Markdown links) jobs. `.github/workflows/release.yml` builds musl and macOS archives, a signed multi-arch GHCR image with an SBOM, `SHA256SUMS` and a changelog section from the cliff config, and creates a draft release (untested until a tag is pushed).
- `scripts/dev.sh`, `scripts/gen-admin-token.sh`, `scripts/check-links.py` and a `justfile`; `.editorconfig`, `SUPPORT.md`, a commented-out `.github/FUNDING.yml` and an MSRV badge.

### Changed

- MSRV (`rust-version`, `clippy.toml`) raised from 1.85 to 1.89, which the locked dependencies already required. Not tested on 1.89 itself; the CI `msrv` job will.
- BREAKING: `POST /admin/root-token` is mounted only when `[dev] allow_root_mint = true` (default `false`); otherwise it answers 404.
- `[[root_grants]]` entries no longer need a `subject`: without one an entry applies to every user of its `issuer`. The same list now caps IdP intake.
- BREAKING: `LeaseStore` has a new required method `renew`; `onbehalf_proxy::Authorizer` has a new required method `check_active`, and `AuthError` a new variant `LeaseInactive`.
- Leases are registered with `expires_at = min(now + lease_interval, token exp)` instead of the token's expiry, so a holder that stops renewing is denied (`lease_expired`) within one interval while its JWT is still valid.
- `tools/list`, `initialize`, `ping`, the other allowlisted methods and `GET`/`DELETE` session requests are now lease-checked; a revoked token gets 401 instead of being served.

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

### Security

[Unreleased]: https://github.com/7Mudit/onbehalf/compare/main...HEAD

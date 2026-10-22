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

- `POST /token/renew`: the holder of a delegation token extends its last hop's lease by `[issuer] lease_interval_seconds` (new, default 300), never beyond the token's `exp` or the parent lease's expiry. `LeaseStore::renew` on both stores. Renewals are audited as `lease.renew`. See ADR-0006.
- Proxy enforcement coverage: `resources/read`, `resources/subscribe`, `prompts/get` and `completion/complete` are authorized as tool calls, and any other non-notification method outside the allowlist is denied unless a capability and the policy permit a tool named after the method. Mapping documented in `onbehalf-proxy` and `docs/design/server.md`.
- Criterion benchmarks for `PolicyEngine::authorize` and `CapabilitySet::covers`; numbers in `docs/design/performance.md`.
- ADR-0006: lease-based in-flight revocation.

### Changed

- BREAKING: `LeaseStore` has a new required method `renew`; `onbehalf_proxy::Authorizer` has a new required method `check_active`, and `AuthError` a new variant `LeaseInactive`.
- Leases are registered with `expires_at = min(now + lease_interval, token exp)` instead of the token's expiry, so a holder that stops renewing is denied (`lease_expired`) within one interval while its JWT is still valid.
- `tools/list`, `initialize`, `ping`, the other allowlisted methods and `GET`/`DELETE` session requests are now lease-checked; a revoked token gets 401 instead of being served.

### Deprecated

### Removed

### Fixed

### Security

[Unreleased]: https://github.com/7Mudit/onbehalf/compare/main...HEAD

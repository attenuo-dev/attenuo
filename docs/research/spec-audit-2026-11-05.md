# Spec and reference audit, 2026-11-05

An audit of the reference and specification documents against the code at `bd4f8dd`, so that every statement in them is true of that code. Doc errors were fixed in place, one commit per document, on the branch `docs/spec-audit`. Where the code differs from a documented promise, the code was not changed: those cases are listed below for a decision.

## Scope

In order of priority:

1. `docs/reference/config.md` and `config/example.toml`, against `crates/attenuo-server/src/config.rs`, `crates/attenuo-proxy/src/config.rs`, `crates/attenuo-policy/src/catalog.rs` and the startup checks in `crates/attenuo-server/src/state.rs`.
2. `docs/reference/http-api.md`, against the routers in `crates/attenuo-server/src/lib.rs`, `admin_ui.rs`, `metrics.rs` and `crates/attenuo-proxy/src/proxy.rs`, and the handlers under `crates/attenuo-server/src/routes/`.
3. `docs/reference/cli.md`, against the clap definitions in `crates/attenuo-cli/src/cli.rs` and the exit handling in `main.rs`.
4. `docs/reference/authzen.md`, against `crates/attenuo-server/src/routes/authzen.rs` and `crates/attenuo-policy/src/authzen.rs`.
5. `docs/spec/rfc-0001-attenuo.md` sections 3 to 7 and 3.1, the status lines of `docs/decisions/*.md`, and `docs/concepts/*.md`.
6. `sdk/python/README.md`, `sdk/typescript/README.md` and `docs/guides/*.md`: the code samples.

Out of scope: `docs/design/*.md`, the threat model, the report and the brief.

## Method

For each document a list of claims was made and each was checked against the code, with file and line. Some checks were scripted over the whole document rather than read claim by claim:

- every backticked snake_case code in `http-api.md` (error codes, reasons, record kinds) was searched for in the Rust sources; all of them exist;
- the metric series in `http-api.md` were compared both ways with the names registered in `metrics.rs`; the two lists are equal;
- the SDK READMEs' imports, calls and signature tables were compared with the Python sources (by AST) and the TypeScript sources (by pattern), including keyword and option names;
- every `attenuo ...` command line in the guides and READMEs was checked flag by flag against `cli.rs`, every key in a TOML sample against the config structs, and every route named in the guides against the routers.

Nothing was built or run. Behaviour that only a running server shows (timings, the figures of the lease pruning benchmark) was not checked.

## Summary

| Document | Claims checked (about) | Mismatches | Fixed in docs | Open for the lead |
| --- | --- | --- | --- | --- |
| `reference/config.md` | 75 | 14 | 13 | 1 |
| `config/example.toml` | 60 | 3 | 3 | 0 |
| `reference/http-api.md` | 260 (30 routes, 200+ codes scripted, 37 series) | 4 | 3 | 1 |
| `reference/cli.md` | 150 | 4 | 3 | 1 |
| `reference/authzen.md` | 35 | 0 | 0 | 0 |
| `spec/rfc-0001-attenuo.md` (3 to 7, 3.1, 9) | 60 | 9 | 9 | 0 |
| `decisions/*.md` status lines | 12 | 5 | 0 | 1 (five ADRs) |
| `concepts/*.md` | 90 | 3 | 3 | 0 |
| `sdk/python/README.md` | 90 | 1 | 1 | 0 |
| `sdk/typescript/README.md` | 80 | 0 | 0 | 0 |
| `guides/*.md` (samples, routes, keys, one stale list) | 140 | 1 | 1 | 0 |
| Code comments met on the way | | 1 | 0 | 1 |

### Fixed in the docs

- `config.md`: `max_depth` defaults to 8 (`attenuo-core/src/chain.rs:14`), not "library default"; `sqlite_path` defaults to `":memory:"` (`config.rs:890`), not "none"; `default_ttl_seconds` must be positive (`state.rs:326-330`); the `[audit.sink]` limits must be at least 1 and the URLs `http(s)://` (`config.rs:780-865`); `[token] actor_auth` and `[[actor_trust]]` also govern hop 0, which the page denied (`idp/intake.rs:18-26, 352-410`); with no `[[agents]]` only client-credential requests are refused (`no_agents_configured`), an actor-token agent needs no entry; `[[peps]]` was not documented at all (`config.rs:92`); `[admin] token` has an environment override and a strength check that refuses to start off loopback (`config.rs:23-40, 1749-1796`); `[[root_grants]] capabilities` also takes full tables (`config.rs:1593`); the console's `allow_write` also mounts `POST /admin/approvals/{id}` and `POST /admin/budgets/refund`, and its read routes include the approvals (`admin_ui.rs:174-226`); the example ships no admin token.
- `config/example.toml`: the same `[[agents]]` and `allow_write` points, and a refund after run-state pruning answers 410 `charge_pruned` (`routes/admin.rs:369, 429`), not 404.
- `http-api.md`: a reused approval ID token is 400 `invalid_grant` / `replayed` (`replay.rs:77-81`) and a missing bearer is 401 `unauthorized` / `missing_token` (`routes/approvals.rs:263-266`); the proxy refusals the page left out are now in a table (`-32004` unknown server, unknown or malformed session, `session_mismatch`, `request_too_large`, `upstream_body_too_large`, `session_registry_full`, `too_many_sessions`, parse errors; `proxy.rs:424-433, 488-519, 636-650, 703-712, 736-747, 1080-1112`); the `kind` filter accepts `approval_request` and `approval_grant` (`attenuo-core/src/decision.rs:60, 95-106`).
- `cli.md`: an exit status table; `audit export --kind` accepts the approval kinds; the list of commands that run offline.
- RFC-0001: run limits include `distinct` and `"derive": "host"`, and the narrowing rule covers them (`attenuo-core/src/limits.rs:1-40`); `chain_id` is already the revocation handle (`POST /admin/leases/revoke`); the CLI does retry with a DPoP nonce (`attenuo-cli/src/client.rs:83-111`); the Cedar context also carries `session`, `approval`, `budget` and `usage` (`attenuo-policy/src/request.rs:380-531`); the record kinds include `tool_result`, `approval_request` and `approval_grant`; `chain_id` in records is no longer "proposed"; output labelling is no longer "out of scope".
- Concepts: hop 0 accepts an actor token (`delegation-chain.md`); a child `calls` limit satisfies a parent `calls_per` or `distinct` (`capabilities-and-attenuation.md`); the AuthZEN conformance fixtures exist (`enforcement-points.md`).
- Python README: `DpopKey.proof` names its third parameter `access_token`. Guide `admin-console.md`: the full list of routes the read-only console leaves out.

## Open mismatches

### Unknown keys in nested tables

- Doc: `config.md` line 3 and `config/example.toml` line 6, "Unknown keys are rejected at start-up".
- Code: the top-level sections are `#[serde(deny_unknown_fields)]`, but three nested types are not: `UpstreamConfig` (`crates/attenuo-proxy/src/config.rs:9-10`), `ToolAttrs` for `[policy.catalog.<server>.<tool>]` and `catalog_path` (`crates/attenuo-policy/src/catalog.rs:77-78`) and `Capability`, used by the full-table form of `[[root_grants]] capabilities` (`crates/attenuo-core/src/capability.rs:364-365`). A misspelt key there is silently ignored. Two cases fail open: `sensitve = true` in the catalog leaves the tool not sensitive, so a `forbid ... when { resource.sensitive }` does not apply; `constraint = {...}` in a root grant leaves the grant unconstrained.
- Interim doc change: `config.md` now says which tables do not reject unknown keys.
- Recommendation: fix code. Add `deny_unknown_fields` to `UpstreamConfig` and `ToolAttrs`. For `Capability` decide separately, since it is also the token wire format and an old server reading a newer token relies on unknown members being ignored (`capabilities-and-attenuation.md` says servers before 0.1.0 ignore `limits`); a config-only wrapper type with `deny_unknown_fields` would cover `[[root_grants]]` without touching tokens. Then restore the one-sentence claim.
- Status: fixed on `fix/spec-audit-findings`. `UpstreamConfig` and `ToolAttrs` refuse unknown fields; `ToolAttrs` covers the inline catalog, the JSON of `catalog_path` and the catalogs the `attenuo policy` harness reads. The table form of `[[root_grants]] capabilities` is read through a config-only `CapabilityConfig` with `deny_unknown_fields`, so `Capability` and the token format are unchanged. The interim paragraph in `config.md` is removed and the one-sentence claim stands.

### ADR status lines

- Doc: ADR-0005 (`docs/decisions/0005-policy-decision-point.md:3`), ADR-0006 (`0006-lease-based-in-flight-revocation.md:2`), ADR-0007 (`0007-actor-authentication.md:2`), ADR-0008 (`0008-admin-console.md:2`) and ADR-0009 (`0009-output-labelling.md:2`) say `proposed`, as does the index in `docs/decisions/README.md`.
- Code: all five are implemented and documented as shipped (the capability stage and generated schema in `attenuo-policy`; leases in `attenuo-audit/src/lease.rs`; actor tokens in `attenuo-server/src/actor.rs`; the console in `admin_ui.rs`; output labels and approvals in `authz.rs` and `routes/approvals.rs`). ADR-0011 is `proposed` and correctly so: there is no opt-in setting for Cedar-aware list filtering in `[proxy]` (`config.rs:1321-1368`).
- Recommendation: decide. The ADR process (`docs/decisions/README.md`) makes acceptance a maintainer decision, so the audit did not change the lines. If accepted, set `status: accepted` and the date in each file and in the index; ADR-0009's title ("labels every upstream result untrusted") predates the catalog's `output = "trusted"` and may want a note under More Information.

### Approval ID-token errors return the verifier's message

- Doc: `http-api.md` says why a bearer token did not verify "is logged at debug level and never returned" (scoped to `/token/renew`, AuthZEN and `/admin/*`), following SR-17.
- Code: `POST /approvals/{id}` and `GET /approvals/{id}` answer a failed ID token with 401 `invalid_token` whose `detail` is the verifier's `Display` text (`crates/attenuo-server/src/routes/approvals.rs:296-300`), while `error_description` carries the stable sub-code. The other bearer routes use `ApiError::unauthorized`, which returns only the code (`error.rs:76-82`).
- Recommendation: decide, probably fix code. The text names things such as an audience mismatch or an unknown `kid`; that is little, but it is the one place the SR-17 rule is not followed. Returning `e.description()` as the detail would match the rest.

### CLI usage errors exit 2, like a denial

- Doc: `cli.md` gives exit 2 for "the answer was no" on `call`, `policy evaluate`, `policy test` and others, and for "nothing to refund" on `budget refund`; the new exit status table now also says that usage errors exit 2.
- Code: `Cli::parse()` (`crates/attenuo-cli/src/main.rs:50`) exits through clap, which uses status 2 for an unknown flag or a missing argument, the same status `Outcome::No` maps to (`main.rs:56`).
- Recommendation: decide. A script that treats 2 as "denied" will read a typo as a denial. Either parse with `Cli::try_parse()` and exit 1 (or 64) on a usage error, or keep it and leave the documentation as it is now.

### Stale code comments

- `crates/attenuo-server/src/config.rs:1012-1015` (doc comment of `run_state_retention_seconds`) says a refund after run-state pruning "answers 404, as for one that charged nothing"; the route answers 410 `charge_pruned` (`routes/admin.rs:369, 429`), as the docs say.
- Recommendation: fix the comment. It is code, so the audit left it.

## Not verified

- Runtime figures: the pruning benchmark in `concepts/leases-and-revocation.md` and timings elsewhere.
- "Servers older than 0.1.0 accept a `limits` block and ignore it" (`concepts/capabilities-and-attenuation.md`): no older server was at hand.
- The AuthZEN specification text itself was not re-read; `authzen.md` was checked against the code only.
- Guides were checked for their samples, routes and config keys, not every sentence of prose.
- Nothing was compiled or run; every finding is from reading the code at `bd4f8dd`.

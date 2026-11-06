# Code-quality pass, 2026-11-05

- Branch: `chore/code-quality-pass`, from `main` at bd4f8dd
- Scope: the eight Rust crates under `crates/`, the Python SDK (`sdk/python`) and the TypeScript SDK (`sdk/typescript`). The admin console's own code is not reviewed here.
- Standard: [ADR-0004](../decisions/0004-rust-workspace-layout.md) and [the server design](../design/server.md). The goal is consistency and less debt with no change in behaviour.
- File:line references are to bd4f8dd unless a section says otherwise. The fixes made on this branch are listed in [What was fixed](#what-was-fixed-on-this-branch).

## Addendum 2026-11-06: state after the overnight batch

Measured on `main` at 5b85f43 (#190), against the figures above from bd4f8dd. The commands are the ones in [How the numbers were produced](#what-was-fixed-on-this-branch) at the end of the report; source lines are `wc -l` over `crates/<crate>/src/**/*.rs`. The findings below this section keep their 2026-11-05 wording; lines that had become wrong are corrected in place and marked "(updated 2026-11-06)".

The night closed fifteen of the sixteen debt items and most of the sixteenth. The two large files are split (`sqlite.rs` into nine submodules, the largest 1,497 lines; `authz.rs` into ten, the largest 1,314), every library crate now warns on `missing_docs` and `unreachable_pub`, the server and the bench library included (`missing_docs` there since `docs/server-missing-docs`, which documented 121 server and 122 bench items), the three cast lints are on in the six library crates and leave no hit in any library source, and `missing_errors_doc` is on in core, token and policy with no hit left there. The duplicated `Authorization` parser and JSON-RPC codes moved to core, the `AuditError` mapping is one function, the review-pass test files have feature names and the server and CLI share test helpers. What remains: debt item 8's last sleeps (the notifier tests, the 1 s stream re-check in `e2e.rs`, the eight-tick listen-stream test and the audit workload sleeps); `missing_errors_doc` outside the three gateway crates (184, all in audit, server, proxy and bench sources); and the cast lints in test targets and the bench library, which no crate attribute covers (34 hits). The server grew by 2,571 source lines since bd4f8dd, mostly the approval notifier (`notify.rs`, 1,006 lines, and the sink queue made generic for it) and its config; with `authz.rs` split, `config.rs` (2,876) is now the largest file in the workspace.

### Crate sizes (source lines under `src/`)

| Crate | bd4f8dd | 5b85f43 | `.rs` files then / now |
|---|---|---|---|
| `attenuo-server` | 19,616 | 22,187 | 28 / 39 |
| `attenuo-audit` | 9,507 | 10,074 | 13 / 22 |
| `attenuo-proxy` | 8,211 | 9,048 | 14 / 16 |
| `attenuo-policy` | 6,141 | 7,522 | 8 / 9 |
| `attenuo-cli` | 7,219 | 7,224 | 9 / 9 |
| `attenuo-core` | 5,739 | 6,482 | 11 / 14 |
| `attenuo-bench` | 4,928 | 4,933 | 4 / 4 |
| `attenuo-token` | 2,952 | 3,102 | 10 / 10 |
| Total | 64,313 | 70,572 | 97 / 123 |

### Largest files

| bd4f8dd | Lines | 5b85f43 | Lines |
|---|---|---|---|
| `audit/src/sqlite.rs` | 5,237 | `server/src/config.rs` | 2,876 |
| `server/src/authz.rs` | 3,717 | `proxy/src/proxy.rs` | 2,133 |
| `server/src/config.rs` | 2,538 | `audit/src/lease.rs` | 2,111 |
| `audit/src/lease.rs` | 2,102 | `policy/src/testing.rs` | 2,099 |
| `proxy/src/proxy.rs` | 1,993 | `bench/src/exchange.rs` | 1,891 |
| `policy/src/testing.rs` | 1,913 | `cli/src/cli.rs` | 1,748 |
| `bench/src/exchange.rs` | 1,891 | `policy/src/request.rs` | 1,587 |
| `cli/src/cli.rs` | 1,748 | `core/src/limits.rs` | 1,579 |

The split files at 5b85f43: `audit/src/sqlite.rs` 70, and under `sqlite/` `leases.rs` 1,497, `log.rs` 1,418, `tests.rs` 1,003, `wal.rs` 579, `connection.rs` 320, `budgets.rs` 278, `outbox.rs` 270 (the notifier outbox, added after the split), `schema.rs` 187, `approvals.rs` 100. `server/src/authz.rs` 108, and under `authz/` `pipeline.rs` 1,314, `budget_tests.rs` 553, `authorizer.rs` 401, `arg_taint_tests.rs` 363, `run_lock_tests.rs` 355, `budgets.rs` 288, `tests.rs` 285, `usage_tracking_tests.rs` 190, `usage.rs` 51, `labels.rs` 47.

### Crate-level lints and the public surface

From `grep -n 'warn(' crates/*/src/lib.rs` and `cargo clippy --workspace --lib -- -A clippy::all -W missing_docs -W unreachable_pub`:

| Crate | `missing_docs` hits bd4f8dd / 5b85f43 | `#![warn(missing_docs)]` | `#![warn(unreachable_pub)]` | `missing_errors_doc` | cast lints | `unreachable_pub` hits now |
|---|---|---|---|---|---|---|
| `attenuo-core` | 98 / 0 | on | on | on | on | 0 |
| `attenuo-token` | 18 / 0 | on | on | on | on | 0 |
| `attenuo-policy` | 93 / 0 | on | on | on | on | 0 |
| `attenuo-audit` | 62 / 0 | on | on | off | on | 0 |
| `attenuo-proxy` | 41 / 0 | on | on | off | on | 0 |
| `attenuo-server` | 141 / 120 (121 at 2c81944, then 0) | on | on | off | on | 0 |
| `attenuo-bench` (lib) | 122 / 122 (then 0) | on | on | off | off | 0 |

`attenuo-cli` is a binary only and has none of these attributes; turned on, `missing_docs` finds nothing there (a binary exports no item) and `unreachable_pub` 105 `pub` items in its modules, left as they are. Since `docs/server-missing-docs` the server and the bench library warn on `missing_docs` as well, and so does the server's `main.rs` (with `unreachable_pub`; no hit). That branch documented the 121 server items found at 2c81944 (the fields and variants of the `pub` modules the tests reach, the route handlers and request bodies, the sink and notifier methods) and the 122 bench items (the report rows and the subcommand options), and made none `pub(crate)`. ADR-0004 still promises neither crate as an API.

Server surface at 5b85f43 (`crates/attenuo-server/src/lib.rs`): `pub mod` `admin_ui`, `authz`, `config`, `dpop`, `error`, `metrics`, `notify`, `routes` and `sink`, each but `config` with a comment naming its outside user (integration tests, the benches' `result_digest`, the fuzz targets); `pub(crate) mod` `actor`, `clientauth`, `idp`, `issuer_keys`, `replay` and `state`. The root re-exports `Pipeline`, `PipelineDecision` and `ServerAuthorizer` from `authz`, `Config` and `AppState` (so `AppState` is public while its module is not), and has the public functions `build`, `build_with_clock`, `router`, `serve`, `serve_until`, `shutdown_signal`, `spawn_checkpointer`, `spawn_lease_maintenance` and the three `prune_*` passes, with five constants for the maintenance and shutdown periods. `notify` (the approval notifier, #168) is the one `pub` module added since the report. Since #183 the server warns on `unreachable_pub`, so an item inside the six crate-private modules cannot be marked `pub` again without a warning.

### Clippy pedantic

`cargo clippy --workspace --all-targets --message-format=json -- -W clippy::pedantic`, deduplicated by lint, file and line as before: 1,679 at bd4f8dd, 1,636 at 5b85f43. By crate, then / now: server 494 / 503, audit 264 / 259, proxy 232 / 239, core 170 / 143, policy 160 / 151, CLI 135 / 136, bench 122 / 122, token 102 / 83. The total fell less than the fixed lints suggest because the code grew by about 6,000 lines.

| Lint | bd4f8dd | 5b85f43 |
|---|---|---|
| `must_use_candidate` | 339 | 349 |
| `missing_errors_doc` | 253 | 184 |
| `doc_markdown` | 231 | 245 |
| `assert_is_empty` | 99 | 104 |
| `format_push_string` | 92 | 94 |
| `return_self_not_must_use` | 73 | 77 |
| `semicolon_if_nothing_returned` | 57 | 69 |
| `cast_precision_loss` | 58 | 58 |
| `too_many_lines` | 45 | 47 |
| `redundant_closure_for_method_calls` | 36 | 47 |
| `default_trait_access` | 41 | 45 |
| `needless_pass_by_value` | 38 | 40 |
| `unreadable_literal` | 33 | 34 |
| `map_unwrap_or` | 24 | 25 |
| `missing_panics_doc` | 23 | 24 |
| `cast_possible_truncation` | 42 | 21 |
| `cast_possible_wrap` | 27 | 8 |
| `cast_sign_loss` | 20 | 5 |
| `unchecked_time_subtraction` | 3 | 3 |

Where the three adopted lints still fire: `missing_errors_doc` 184, all in library sources of crates that do not enable it (audit 100, server 73, proxy 6, bench 5), none in core, token or policy. The 34 cast hits are in integration tests and benches (audit 19, server 7, core 1, CLI 1) and in the bench library (6), none in the source of a crate that enables the lints: a `#![warn]` in `lib.rs` does not reach a crate's `tests/` and `benches/` targets. `unchecked_time_subtraction` is still 3, at `server/src/sink.rs:173`, `proxy/src/session.rs:356` and `bench/src/exchange.rs:1718`; it was recommended in (g) but not adopted.

### Debt table, state on 2026-11-06

| # | Item | State | Where |
|---|---|---|---|
| 1 | `AuditError` to `ApiError` in one place | Done | `fix/hardening-small`, `chore/audit-error-mapping` (#187) |
| 2 | ADR-0004 up to date | Done | `chore/debt-small`, `docs/adr-0004-refresh` (#186) |
| 3 | One `Authorization` parser | Done | `chore/authz-parser-favicon` (#169) |
| 4 | `missing_docs` on proxy, audit, policy | Done | #171, #172, #173 |
| 5 | Cast lints | Done in the six library crates | `fix/hardening-small` (server, policy), `chore/debt-small` (core, token, audit), `fix/proxy-followups` (proxy). State on 2026-11-06: not on in the bench library (6 hits) or the CLI, and 28 hits remain in test targets |
| 6 | JSON-RPC codes shared | Done | `chore/authz-parser-favicon` (#169) |
| 7 | Split `sqlite.rs` and `authz.rs` | Done | #175, #180 |
| 8 | Injectable clock for TTL and window tests | Done | #170, #188. State on 2026-11-06: left are the notifier tests in `server/tests/approval_notifier.rs` (sleeps of 300 ms to 1.8 s), the 1 s stream re-check in `e2e.rs`, `an_untouched_listen_stream_keeps_flowing`, and the audit sleeps that are the workload under test; 12 integration test files still call `sleep(`. Finished on `chore/notifier-clock-tests`: the notifier reads the server's clock (watcher, outbox times, pruning; `ApprovalNotifier::clock_advanced` wakes the watcher), so the TTL waits are `ManualClock` advances, and the three "nothing else arrives" sleeps are a later notice delivered after any stray one or a stop of the delivery thread; the e2e revoked-stream test and `an_untouched_listen_stream_keeps_flowing` run on paused tokio time, so their re-check ticks pass virtually. `approval_notifier` 3.20-3.26 s to 0.36-0.39 s, `session_and_stream_guard` 0.96 s to 0.44 s, the e2e test 1.07 s to 0.10 s (the `e2e` binary stays about 1.55 s, set by its export tests). The audit sleeps are all workload or condition polls, each now saying so: verifier and checker pacing (`wal.rs:75`, `checkpoints.rs:396`), WAL size sampling (`wal.rs:173`), a probe's phase poll (`wal.rs:389`), a probe's think time (`single_client_outliers.rs:150,153`) and busy-handler backoff (`write_contention.rs:56`, `write_gate.rs:29`); `common::wait_for` polls a condition. What still calls `sleep(` in tests polls a condition with a bound, or paces an upstream's events; no test sleeps for a fixed time before a check |
| 9 | Feature-named test files | Done | #174 |
| 10 | Shared test helpers | Done | #174 |
| 11 | Narrow the server's `pub mod` surface | Done | #172; `unreachable_pub` on the server in #183 |
| 12 | `missing_errors_doc` on core, token, policy | Done | #173 |
| 13 | Python SDK root exports | Done | `chore/debt-small`, #176 |
| 14 | `expect("set above")` and the Cedar type names | Done | #171 |
| 15 | `unreachable_pub` on the library crates | Done | #177, #183 |
| 16 | `JcsError` to `thiserror` | Done | `chore/debt-small` |

Nothing in the table is open as written; item 8 is the one with work left, and item 5's remainder (bench, CLI, test targets) is outside what the row asked.

### Tests

`cargo test --workspace` at 5b85f43, after touching every `lib.rs` and `main.rs`: 1,247 passed, 0 failed, 7 ignored, over 98 result lines (test binaries and doc-test runs), against 1,161 passed and 6 ignored at the report's branch. The seventh ignored test is `list_cost_by_mode` in `server/tests/list_screen.rs`, a measurement added with the list screen; it is the one `#[ignore]` without a reason string (the pedantic run's single `ignore_without_reason`). The other six are the probes section (f) names (three of them in `proxy/tests/listen_stream_cost.rs`).

`#[test]` and `#[tokio::test]` attributes, unit (`src`) / integration (`tests/`), then and now: core 79/32 to 88/32, token 24/31 to 24/31, policy 44/62 to 53/76, audit 28/160 to 29/160, proxy 72/109 to 76/119, server 145/230 to 163/249, CLI 89/29 to 89/32, bench 20/5 to 20/5.

### Duplicated logic (section d)

Both open rows of section (d) closed in #169: the `Authorization` parser is `attenuo_core::authorization::token_of`, called by the proxy's and the server's `bearer_of`, and the JSON-RPC codes are `attenuo_core::jsonrpc`, re-exported by `attenuo_proxy::jsonrpc` and imported by the CLI. The test helpers closed in #174. The two `proptest_seed/mod.rs` copies are still byte-identical by design, and the `[proxy]` `default_*` functions in the server and the proxy still read the same constants.

## (a) Module layout against ADR-0004

The workspace has eight members, not the seven ADR-0004 lists: `attenuo-bench` (load and hot-path measurement) is the extra one. Dependencies all point downward in the ADR's order. Two edges go beyond what the ADR's table names, and two crates have fewer edges than it names.

| Crate | Modules (src) | Depends on (workspace) | Matches ADR-0004? |
|---|---|---|---|
| `attenuo-core` | flat: `call`, `capability`, `chain`, `decision`, `digest`, `error`, `fingerprint`, `jcs`, `limits`, `names` | none | Yes. No I/O, no async; hashing only (`sha2`). It also carries `url` and `unicode-normalization` for fingerprints, which the ADR does not list. The ADR names `Lease` and `AuditRecord`; the code has `LeaseId` and `DecisionRecord`. `#![forbid(unsafe_code)]` was missing (fixed). |
| `attenuo-token` | flat: `approval`, `claims`, `detached`, `dpop`, `error`, `exchange`, `issuer`, `keys` (private), `verifier` | core | Partly. The ADR puts ID-JAG and OIDC intake and JWKS fetching here; they live in `attenuo-server/src/idp/` (`intake.rs`, `jwks.rs`, `claims.rs`). |
| `attenuo-policy` | `authzen` and `testing` public; `catalog`, `lint`, `request`, `schema`, `usage` private; `bench_support` inline in `lib.rs` | core | Partly. The `RelationResolver` trait the ADR names does not exist. Hot reload is driven by the server (`POST /admin/policies/reload`). The only crate with `forbid(unsafe_code)` besides core, which is stricter than the ADR asks. |
| `attenuo-audit` | flat, all `pub mod`: `approval`, `budget`, `checkpoint`, `error`, `export`, `lease`, `log`, `memory`, `query`, `shipped`, `spans`, `sqlite` | core, token | Partly. It depends on `attenuo-token` for `DetachedSigner` (checkpoint signing), which the ADR does not list. The ADR's "verifier is a separate binary entry point" became `attenuo audit verify` in the CLI (the board records that choice). |
| `attenuo-proxy` | flat, all `pub mod`, plus a `testing` module behind a feature and an inline `fuzzing` module | core | Yes, and narrower than the ADR: the proxy talks to the decision side through its `Authorizer` trait, so it does not depend on token, policy or audit. |
| `attenuo-server` | flat modules plus two directories with `mod.rs` (`routes/`, `idp/`); lib and bin | all five | No, as the ADR words it ("no logic beyond wiring and config"). `authz.rs` (3,717 lines, the pipeline), `dpop.rs`, `actor.rs`, `replay.rs`, `sink.rs` and `idp/` hold real logic. The design doc already describes `authz::Pipeline` as the server's one piece of composition; the ADR was not updated. |
| `attenuo-cli` | bin only: `cli`, `client`, `dpop_key`, `jwt`, `policy_cmd`, `render`, `secrets`, `watch` | core, token, audit, policy | Partly. The ADR says core and token. `audit` is used for offline `audit verify --file`; `policy` for `policy test` and `policy lint`, which run the real `PolicyEngine` locally. So "decides nothing" holds only for the online commands. |
| `attenuo-bench` | `lib`, `exchange`, `hotpath`, `main` | none (spawns the binaries) | Not in the ADR. |

Size outliers that a new contributor will notice first: `attenuo-audit/src/sqlite.rs` (5,237 lines), `attenuo-server/src/authz.rs` (3,717), `attenuo-server/src/config.rs` (2,538), `attenuo-audit/src/lease.rs` (2,102), `attenuo-proxy/src/proxy.rs` (1,993), `attenuo-policy/src/testing.rs` (1,913). The two `jwks` modules in the server (`src/jwks.rs` serves the issuer's own keys, `src/idp/jwks.rs` caches IdP keys) differ only by directory. (Renamed: `src/jwks.rs` is now `src/issuer_keys.rs`, debt item 11.) (updated 2026-11-06: `sqlite.rs` and `authz.rs` are split into submodules, debt item 7; the sizes at 5b85f43 are in the addendum.)

## (b) Error handling

**Error enums.** Every library error is a `thiserror` enum: `AttenuationError`, `ChainError`, `NameError`, `RangeError`, `LimitError`, `LimitArgError` (core); `TokenError`, `DpopError` (token); `PolicyError`, `HarnessError` (policy); `AuditError` (audit); `AuthError` and a private `UpstreamBodyError` (proxy); `ActorTokenError`, `JwksError`, `IntakeError` (server). `JcsError` in core is the one hand-written error with no `thiserror` derive (`core/src/jcs.rs:39`). The binaries and the proxy's `serve` use `anyhow`.

**To HTTP.** The server has one response type, `ApiError` (`server/src/error.rs`), with the body `{"error", "detail", "error_description"?, "decision_id"?}`, `Cache-Control: no-store`, and 500 details kept in the log (SR-43). `From` impls exist for `TokenError` (to OAuth `invalid_grant` / `invalid_scope` / `invalid_request` with a sub-code, `Key` to 500, `BindingRequired` to the DPoP 401), `AuditError`, `ActorTokenError`, `IntakeError` and `DpopFailure`. The proxy maps its errors to JSON-RPC codes -32003 to -32008 with HTTP statuses, as the table in the design doc lists.

**To CLI exit codes.** `attenuo-cli/src/main.rs:49-62`: 0 success, 2 for "the server answered no" (`Outcome::No`: a denial, a failed policy test, a failed verification), 3 and 4 for the two refund refusals a script needs to tell apart (`budget_refund`, documented in the CLI reference), 1 for every other error. The CLI does not map HTTP statuses to exit codes; a 4xx or 5xx becomes exit 1 with the server's `error` and `detail` printed.

**Inconsistencies.**

1. `From<AuditError> for ApiError` (`server/src/error.rs:168`) maps only `UnknownLease` (404); every other variant, including the domain refusals, becomes a 500. Each route therefore matches the domain variants itself: `routes/approvals.rs:176-187` (`UnknownApproval`, `ApprovalNotPending`, `ApprovalExpired`, `LeaseRevoked`), `routes/renew.rs:204-205`, `routes/admin.rs:394-395` (`UnknownCharge`, `ChargeRefunded`). A new handler that uses `?` on one of those variants will answer 500 with "internal error". The mapping is correct today; it is a trap for the next route.
2. Two bearer parsers with the same rule and different error types: `proxy/src/proxy.rs:224` (`AuthError`, a missing header is an error) and `server/src/routes/mod.rs:38` (`ApiError`, a missing header is `Ok(None)`). The scheme rule (`Bearer` or `DPoP`, case-insensitive, non-empty token) is written twice.
3. The CLI hard-codes JSON-RPC codes `-32003` and `-32008` (`cli/src/main.rs:36-38`) that the proxy defines as `CODE_DENIED` and `CODE_APPROVAL_REQUIRED` (`proxy/src/jsonrpc.rs:16,33`). The CLI does not depend on the proxy, so they cannot be shared without moving them down.
4. `JcsError` is the only error type in core without `thiserror`; it implements `Display` by hand.

## (c) Public API surface

Counted with `cargo clippy --workspace --lib -- -W missing_docs -W unreachable_pub` (library targets; the CLI is a binary and is not counted).

| Crate | `pub` items without a doc comment (bd4f8dd) | After this branch | `unreachable_pub` hits |
|---|---|---|---|
| `attenuo-core` | 98 | 0, `#![warn(missing_docs)]` on | 0 |
| `attenuo-token` | 18 (all in `approval.rs`) | 0, `#![warn(missing_docs)]` on | 0 |
| `attenuo-policy` | 93 | 0, `#![warn(missing_docs)]` on (`chore/policy-docs-errors-doc`; 95 at dead1ac) | 1 (fixed) |
| `attenuo-audit` | 62 | 0, `#![warn(missing_docs)]` on (`chore/audit-docs-small-debt`; 70 at dead1ac) | 6 (fixed) |
| `attenuo-proxy` | 41 | 0, `#![warn(missing_docs)]` on (`chore/proxy-docs-server-surface`; 60 with the `testing` feature) | 12 (fixed) |
| `attenuo-server` | 141 | 0, `#![warn(missing_docs)]` on (`docs/server-missing-docs`; 121 at 2c81944) | 0 |
| `attenuo-bench` | 122 | 0, `#![warn(missing_docs)]` on (`docs/server-missing-docs`) | 0 |

`#![warn(missing_docs)]` readiness: core and token are now on, audit since `chore/audit-docs-small-debt`, proxy since `chore/proxy-docs-server-surface` and policy since `chore/policy-docs-errors-doc` (the 95 were mostly the AuthZEN wire types and the `testing` harness). Server and bench are not promised stable (ADR-0004), so the lint matters less there than narrowing their surface; it is on in both since `docs/server-missing-docs` (2026-11-06).

Items that should be `pub(crate)`: the 19 `unreachable_pub` hits were methods on crate-private types (`audit/src/budget.rs:172-185`, `audit/src/spans.rs:53-66`, `proxy/src/label.rs` (12), `policy/src/schema.rs:250`); all are now `pub(crate)`. Update (`chore/unreachable-pub`, debt item 15): `#![warn(unreachable_pub)]` is on in core, token, policy, audit and proxy, so new hits fail `clippy -D warnings`; at 39b77ac it found one more, the test-only `AwaitedResults::len` in `proxy/src/label.rs`, now `pub(crate)`. Beyond the lint: every server module is `pub mod` (`server/src/lib.rs:46-59`) so the integration tests can reach `config`, `state` and `authz`. Much of `replay`, `clientauth` and `sink` is used only inside the crate. Narrowing them needs a look at what each test file imports, so it is listed as debt rather than done. Update (`chore/proxy-docs-server-surface`, debt item 11): `actor`, `clientauth`, `idp`, `replay`, `state` and the renamed `issuer_keys` are `pub(crate)`; the modules still `pub` are used by the integration tests, the benches, the fuzz targets, `main.rs` or the CLI, and say which in a comment. `sink` stays `pub` for the SigV4 test in `tests/checkpoint_sink.rs`. (updated 2026-11-06: `config` carries no such comment, `notify` has joined the `pub` modules, and since #183 the server also warns on `unreachable_pub`; the module list at 5b85f43 is in the addendum.)

## (d) Duplicated logic

| What | Copies | Status |
|---|---|---|
| Capability name pattern match (`*`, `prefix*`, exact) | `core/src/capability.rs:350` and `proxy/src/filter.rs:20`, line for line | Fixed: core's is public, the proxy re-exports it |
| `Decision` to `"allow"`/`"deny"` | `audit/src/sqlite.rs:640`, `policy/src/testing.rs:1239`, `cli/src/policy_cmd.rs:449`, `server/src/authz.rs:643` | Fixed: `Decision::as_str` in core |
| `[proxy] stream_recheck_seconds` default | `server/src/config.rs:1423` (literal `2`) and `proxy/src/config.rs:29` (`DEFAULT_STREAM_RECHECK`) | Fixed: the server reads the proxy constant like the other `[proxy]` defaults |
| Bearer and DPoP `Authorization` parsing | `proxy/src/proxy.rs:224`, `server/src/routes/mod.rs:38` | Done (debt item 3, `chore/authz-parser-favicon`: `attenuo_core::authorization::token_of`) |
| JSON-RPC denial and approval codes | `cli/src/main.rs:36-38`, `proxy/src/jsonrpc.rs:16,33` | Done (debt item 6, `chore/authz-parser-favicon`: `attenuo_core::jsonrpc`) |
| `sha256_hex` test helper | 12 test files: `cli/tests/{admin_reads,budgets,dpop_nonce}.rs`, `server/tests/{actor_token,actor_token_hop0,admin_policies,dpop,e2e,oidc,range_constraint,run_limits,run_usage}.rs` | Done (debt item 10, `chore/test-file-hygiene`): one copy in `server/tests/common/mod.rs` and one in `cli/tests/common/mod.rs`. Not folded into `attenuo_core::digest::sha256_bytes`, and `admin_policies.rs` keeps its own copy: it checks the server's policy hash against it, and an independent computation is the point there |
| `fn attenuo()` (path of the CLI binary) | 11 CLI test files | Done (debt item 10, `chore/test-file-hygiene`): `cli/tests/common/mod.rs`; the two copies that left `ATTENUO_DPOP_KEY` set (`secrets.rs`, `audit_shipped.rs`) now clear it too |
| `wait_for` polling helper | `audit/tests/wal.rs:42`, `audit/tests/presync.rs:20`, `server/tests/checkpoint_sink.rs:122` | Done (debt item 10, `chore/test-file-hygiene`): the two blocking copies are one in `audit/tests/common/mod.rs`; the server's async one is in `server/tests/common/mod.rs` |
| `proptest_seed/mod.rs` | `core/tests/` and `audit/tests/`, byte-identical | Deliberate: the module's doc says "an identical copy lives in each crate ... change both" |
| Server and proxy validation of server names | `server/src/config.rs:1686` wraps `core::names::check_server_name` and adds the reserved `attenuo` | Not a duplicate: one rule in core, one server-specific extra |

The `[proxy]` defaults in the server (`server/src/config.rs:1403-1421`) and the proxy (`proxy/src/config.rs:94-118`) are two sets of `default_*` functions. All of them now read the same constants, so the duplication is the serde boilerplate, not the values.

## (e) `TODO`, `FIXME`, `XXX`, `unwrap()`, `expect(`

There is no `TODO`, `FIXME` or `XXX` in any crate or SDK source. The one `XXX` match is the `\uXXXX` escape in a doc comment (`proxy/src/sse.rs:202`).

A scan that skips `#[cfg(test)]` items found 69 `unwrap`, `expect`, `unreachable!` and `panic!` calls. Of those, 7 are in `attenuo-bench`, 26 in `attenuo-proxy/src/testing.rs` (the test upstream's mutexes, behind the `testing` feature) and 3 in `server/src/metrics.rs` tests the scan did not recognise as tests. The rest, with a judgement for each:

| Site | On a request path? | Judgement |
|---|---|---|
| `audit/src/sqlite.rs:1494` `one.pop().expect("one record, one entry")` | Yes, every audit append that falls back to one-by-one commits | Fixed: returns `AuditError::Storage` |
| `audit/src/sqlite.rs:2336` `out.pop().expect("one record, one result")` | Yes, the uncontended append fast path | Fixed: returns `AuditError::Storage` |
| `audit/src/log.rs:63`, `core/src/digest.rs:18`, `core/src/capability.rs:187`, `core/src/limits.rs:707`, `token/src/claims.rs:197,237` (canonical JSON of the crate's own types) | Yes | Keep. `jcs` fails only on non-finite floats, non-string keys or raw JSON, none of which these types can hold; `digest.rs` documents this |
| `core/src/jcs.rs:85` (UTF-8 of canonical output), `core/src/jcs.rs:144` (ryu exponent) | Yes | Keep: output of the crate's own encoder and of `ryu` |
| `token/src/claims.rs:213` (`u32::try_from(len)` for `ou_sig`) | Yes | Keep: request bodies are capped far below 4 GiB |
| `token/src/keys.rs:137` (base64 is ASCII) | Startup and JWKS | Keep |
| `policy/src/request.rs:204` (static Cedar entity type names parse) | Yes | Keep. A `LazyLock` per name would make the invariant visible and save the parse; minor |
| `server/src/admin_ui.rs:165` (hex digest as a header value) | Yes, console asset responses | Keep: hex is always a valid header value |
| `audit/src/checkpoint.rs:57`, `audit/src/shipped.rs:56,74,79` | Checkpoint signing and shipping, background | Keep |
| `audit/src/export.rs:140,142` | `GET /admin/audit/export` | Keep: serialisation of the crate's own export types |
| `audit/src/lease.rs:1134,1152` (`"set above"`) | Charging a run limit | Keep, but `get_or_insert_with` would remove both |
| `audit/src/lease.rs:1619`, `audit/src/sqlite.rs:3712` | Maintenance passes | Keep: local invariants of the loop |
| `audit/src/sqlite.rs:1871` (`Arc::get_mut` in a builder) | Startup | Keep: misuse is a programming error |
| `audit/src/sqlite.rs:4214,4220` (`lock().unwrap()`) | No: `testing` feature only | Keep |
| `proxy/src/proxy.rs:207` (reqwest client builds) | Startup | Keep |
| `token/src/issuer.rs:114` (system RNG) | Startup, key generation | Keep |
| `token/src/dpop.rs:602` (`sign_claims`) | No: a public test helper | Keep; consider `#[doc(hidden)]` or the `testing` feature |
| `policy/src/lib.rs:849` | No: `bench_support` | Keep |
| `cli/src/client.rs:139` (`req.take().expect("sent once")`) | CLI | Keep: the closure runs once when no DPoP retry is possible |
| `cli/src/main.rs:393` (`unreachable!` after clap) | CLI | Keep: clap enforces the group |

## (f) Test organisation

| Crate | Unit tests (`src`) | Integration tests (`tests/`) | Property tests | Benches |
|---|---|---|---|---|
| `attenuo-core` | 79 | 32 | `attenuation_props.rs`, `limits_props.rs` | 1 |
| `attenuo-token` | 24 | 31 | none | 1 |
| `attenuo-policy` | 44 | 62 | none | 2 |
| `attenuo-audit` | 28 | 160 | `budget_props.rs` | 0 |
| `attenuo-proxy` | 72 | 109 | none | 0 |
| `attenuo-server` | 145 | 230 | none | 1 |
| `attenuo-cli` | 89 | 29 | none | 0 |
| `attenuo-bench` | 20 | 5 | none | 0 |

(Counts are `#[test]` and `#[tokio::test]` attributes, so parameterised and proptest cases count once. The full run on this branch is 1,161 tests in 91 binaries, 6 ignored.)

Conventions: unit tests are `#[cfg(test)] mod tests` at the end of the file, except `server/src/lib.rs`, which has `shutdown_tests` and `maintenance_tests`. Integration test files are mostly named after the feature (`leases.rs`, `approvals.rs`, `run_limits.rs`). Seven are named after the security review pass that added them instead: `proxy/tests/security.rs`, `security_pass3.rs`, `security_pass7.rs`, `security_pass7_sr81.rs`, `server/tests/security_pass3.rs`, `security_pass4.rs`, `security_low.rs`. A contributor looking for the tests of a feature has to know which pass found its bug. Only `attenuo-audit` has a shared `tests/common/mod.rs`; the server and CLI test files each build their own harness. Update (`chore/test-file-hygiene`, debt items 9 and 10): the seven, and the two pass 8 files added since (`proxy/tests/security_pass8.rs`, `security_pass8_sr87.rs`), are named after the feature, each with a module doc that lists its SR ids and its old name: proxy `hardening.rs`, `session_and_stream_guard.rs`, `sse_client_view.rs`, `refusal_record_window.rs`, `later_post_answers.rs`, `later_post_list_answers.rs`; server `hardening.rs`, `id_token_intake.rs`, `dpop_exchange.rs`. The two `hardening.rs` files are grab-bags of small findings (SR-01, 02, 03, 11, 17, 18 at the proxy; SR-17, 18, 19, 30, 34 at the server) that would otherwise scatter one test per file. The server and the CLI now have a `tests/common/mod.rs` too. The 6 ignored tests are measurement probes (`proxy/tests/listen_stream_cost.rs`, `audit/tests/{wal,single_client_outliers,write_contention}.rs`), each with a reason string. (updated 2026-11-06: a seventh, `list_cost_by_mode` in `server/tests/list_screen.rs`, has no reason string.)

Tests that sleep or depend on wall-clock timing (the polling `wait_for` loops are left out):

| Test | What it waits for | Risk |
|---|---|---|
| `server/tests/approvals.rs:549` `expired_approval_is_gated` | sleeps 1.3 s for a 1 s approval TTL | Wall-clock margin 300 ms; slow on every run |
| `server/tests/e2e.rs:1938` | sleeps 1.1 s to leave a one-second refusal window | Same pattern |
| `proxy/tests/session_limits.rs:196` | `ttl + 200 ms` for session expiry | Same pattern |
| `proxy/tests/proxy.rs:1068` | `window + 100 ms` for the refusal-record window | Same pattern |
| `proxy/tests/session_and_stream_guard.rs:475,492,494,534,890` (was `security_pass3.rs`) | `RECHECK * 3` or `* 4` for the stream re-check | Margin of one to two re-check periods |
| `audit/tests/presync.rs:136,159` | sleeps 100 ms and 200 ms, then asserts nothing else happened | A negative assertion bounded by a sleep: can pass when it should fail on a slow box |
| `audit/tests/wal.rs:46,83,181,397` | WAL checkpointer timing | Uses `wait_for` for the positive side; the sleeps pace writers |
| `server/tests/ops.rs:299`, `admin_ui.rs:624`, `checkpoint_sink.rs:126`, `e2e.rs:2058,2719` | short polls inside loops | Low |

Only `attenuo-bench` uses tokio's paused clock (`#[tokio::test(start_paused = true)]`). The server's TTL and window checks take `OffsetDateTime::now_utc()` or `Instant::now()` directly, so they cannot use it without an injectable clock.

## (g) Clippy pedantic

One run: `cargo clippy --workspace --all-targets -- -W clippy::pedantic` at bd4f8dd, 1,679 distinct warnings (deduplicated by lint, file and line), by crate: server 494, audit 264, proxy 232, core 170, policy 160, CLI 135, bench 122, token 102.

| Count | Lint |
|---|---|
| 339 | `must_use_candidate` |
| 253 | `missing_errors_doc` |
| 231 | `doc_markdown` |
| 99 | `assert_is_empty` |
| 92 | `format_push_string` |
| 73 | `return_self_not_must_use` |
| 58 | `cast_precision_loss` |
| 57 | `semicolon_if_nothing_returned` |
| 45 | `too_many_lines` |
| 42 | `cast_possible_truncation` |
| 41 | `default_trait_access` |
| 38 | `needless_pass_by_value` |
| 36 | `redundant_closure_for_method_calls` |
| 33 | `unreadable_literal` |
| 27 | `cast_possible_wrap` |
| 24 | `map_unwrap_or` |
| 23 | `missing_panics_doc` |
| 20 | `cast_sign_loss` |
| 19 | `items_after_statements` |
| 14 each | `similar_names`, `needless_raw_string_hashes`, `single_match_else` |
| 8 | `many_single_char_names` |
| 6 | `format_collect` |
| 5 | `match_same_arms` |
| 4 each | `unnested_or_patterns`, `explicit_iter_loop`, `unused_self`, `float_cmp`, `struct_field_names`, `case_sensitive_file_extension_comparisons`, `stable_sort_primitive` |
| 3 each | `assigning_clones`, `ref_option`, `manual_let_else`, `needless_for_each`, `unchecked_time_subtraction` |
| 2 each | `wildcard_imports`, `struct_excessive_bools`, `implicit_clone`, `range_plus_one`, `match_wild_err_arm`, `nonminimal_bool` |
| 1 each | 15 other lints |

The three worth adopting (as `warn` in `[workspace.lints]` or per crate, with the existing hits fixed or allowed where they are deliberate):

1. **`cast_possible_truncation`** (42), with `cast_possible_wrap` (27) and `cast_sign_loss` (20). For a reference monitor these are the casts that can turn a large value into a small one. Most hits are timing fields (`as_micros() as u64`) and are harmless. Two are on untrusted input and deserve a look: `server/src/idp/mod.rs:503` (`f as i64` on an IdP claim: saturates, and NaN becomes 0) and `policy/src/request.rs:57` (`f as i64` when translating an argument for Cedar, after a whole-number check). (updated 2026-11-06: adopted as debt item 5; both casts are now checked conversions.)
2. **`unchecked_time_subtraction`** (3: `server/src/sink.rs:67`, `proxy/src/session.rs:350` in a test, `bench/src/exchange.rs:1718`). `Instant` and `Duration` subtraction panics on underflow. The count is small, so it costs nothing to keep at zero.
3. **`missing_errors_doc`** (253), scoped to core, token and policy, the crates ADR-0004 calls the gateway integration surface. It asks for an `# Errors` section on every public function that returns `Result`, which is what a gateway author needs. It pairs with the `missing_docs` lint now on in core and token. Adopted in all three on `chore/policy-docs-errors-doc` (68 hits there at 439fc28).

Not worth adopting: `must_use_candidate` and `return_self_not_must_use` (412 hits of noise for builders), `doc_markdown` (the docs use backticks already where it matters), `too_many_lines` (the long functions are long for a reason; splitting files is the better fix).

## (h) SDK parity

The client surfaces match closely. Comparing the public methods of each class: `AdminClient` has the same methods in both (Python adds `close`); `Client` and `AttenuoClient` match except Python's `close` and TypeScript's `dpopKey` accessor. `verify_export` / `verifyExport`, `parse_shipped` / `parseShipped`, `cross_check` / `crossCheck`, the DPoP nonce cache, the token refresher and the approval helpers exist in both.

Differences a user will notice:

| Area | Python | TypeScript |
|---|---|---|
| Sync and async | `Client`, `AdminClient`, `TokenRefresher` plus `AsyncClient`, `AsyncAdminClient`, `AsyncTokenRefresher` | async only (idiomatic) |
| Top-level exports | audit verification (`verify_export`, `parse_shipped`, `cross_check`), the MCP helpers (`mcp_url`, `mcp_headers`) and the DPoP helpers (`jwk_thumbprint`, `access_token_hash`, `NonceCache`) are reachable only from their submodules (now exported from the root too, debt item 13) | all exported from the package root (`index.ts:33` and others) |
| Error class names | `Denied`, `Unauthorized`, `ApprovalRequired`, `ApprovalNotGranted` | `DeniedError`, `UnauthorizedError`, `ApprovalRequiredError`, `ApprovalNotGrantedError` |
| Capability builders | classes: `Capability(...)`, `Prefix`, `Equals`, `OneOf`, `Range` | functions: `capability()`, `prefix()`, `equals()`, `oneOf()`, `range()`, plus `parseCapability` / `formatCapability` |
| Canonical JSON | the `rfc8785` package | its own `jcs.ts` with its own test vectors |
| MCP transport | `mcp.py` supplies an `httpx.Auth` flow (`auth_flow`) | `mcpFetch`, a `fetch` wrapper |

None of these is a missing feature. The export gap is the one to close: a Python user reading the TypeScript README will look for `attenuo.verify_export` and not find it. (Closed: debt item 13.)

## (i) Prioritised debt list

Effort: S under a day, M one to three days, L more. Risk is the chance of a behaviour change or a regression.

| # | Item | Effort | Risk |
|---|---|---|---|
| 1 | Centralise `AuditError` to `ApiError`: move the per-route domain mappings (`routes/approvals.rs:176-187`, `renew.rs:204`, `admin.rs:394`) into one function that routes call, so `?` on a domain variant cannot become a 500 | M | Medium: status codes are part of the API; the existing tests pin them. Done (`fix/hardening-small`: one `From<AuditError> for ApiError` in `server/src/error.rs` gives each variant its status, pinned by `every_audit_error_has_one_answer`; `chore/audit-error-mapping`: the approvals routes' unknown-approval 404s and the admin lease reads' unknown-lease 404s are built from it too, renewal keeps only its two lease-refusal arms over it, and `only_store_faults_answer_500` fails when a new variant is not classed as a store fault or a refusal) |
| 2 | Bring ADR-0004 up to date: eight crates (bench), IdP intake and JWKS in the server, audit's dependency on token, the CLI's offline commands depending on audit and policy, no `RelationResolver`, the pipeline living in the server | S | Low (docs only). Done (`docs/adr-0004-refresh`: "Amendment 2026-11-06" in ADR-0004 with the crate graph from `cargo metadata` and the ten points of the original table that no longer hold; index row, server design and README crate row aligned) |
| 3 | One `Authorization` scheme parser for the proxy and the server (`proxy/src/proxy.rs:224`, `server/src/routes/mod.rs:38`), each keeping its own error type | M | Medium: authentication parsing; needs the SR-17 tests to stay green. Done (updated 2026-11-06; `chore/authz-parser-favicon`, #169: `attenuo_core::authorization::token_of`, called by both `bearer_of`, each keeping its error type) |
| 4 | `#![warn(missing_docs)]` for `attenuo-proxy` (41) and `attenuo-audit` (62), then `attenuo-policy` (93) | M | Low. Done: audit (`chore/audit-docs-small-debt`: 70 items, lint on), proxy (`chore/proxy-docs-server-surface`: 60 items with the `testing` feature, 41 without, lint on), policy (`chore/policy-docs-errors-doc`: 95 items, lint on) |
| 5 | Adopt `cast_possible_truncation` (and wrap and sign-loss), starting with the float-to-int casts on untrusted input (`server/src/idp/mod.rs:503`, `policy/src/request.rs:57`) | M | Medium for the two input casts, low elsewhere. Done (updated 2026-11-06): the two input casts are checked conversions and the three lints are on in server and policy (`fix/hardening-small`), core, token and audit (`chore/debt-small`) and proxy (`fix/proxy-followups`); not in the bench library or the CLI |
| 6 | Move the JSON-RPC error codes the CLI needs (`-32003`, `-32008`) to a module both CLI and proxy can use (core, or a small shared constants module), so `cli/src/main.rs:36-38` stops duplicating `proxy/src/jsonrpc.rs` | S | Low. Done (updated 2026-11-06; `chore/authz-parser-favicon`, #169: `attenuo_core::jsonrpc`, re-exported by the proxy, imported by the CLI) |
| 7 | Split `audit/src/sqlite.rs` (5,237 lines) into log, leases, budgets, approvals and maintenance submodules; then `server/src/authz.rs` (3,717) by pipeline stage | L | Medium: merge conflicts with any open branch; no behaviour change. Audit done (`chore/split-audit-sqlite`: `sqlite.rs` is 70 lines of module doc, re-exports and shared helpers; `sqlite/schema.rs`, `connection.rs`, `wal.rs`, `log.rs`, `leases.rs`, `budgets.rs`, `approvals.rs`, `tests.rs`, the largest 1,497 lines; public paths unchanged); server done (`chore/split-server-authz`: `authz.rs` is 108 lines of module doc, module declarations and re-exports; `authz/pipeline.rs`, `authorizer.rs`, `budgets.rs`, `labels.rs`, `usage.rs`, and the five unit test modules in files of the same names, the largest 1,314 lines; public paths and test paths unchanged) |
| 8 | Replace wall-clock sleeps in TTL and window tests (`server/tests/approvals.rs:549`, `e2e.rs:1938`, `proxy/tests/session_limits.rs:196`, `proxy/tests/proxy.rs:1068`, `security_pass3.rs` (now `session_and_stream_guard.rs`) re-check waits) with an injectable clock, and turn the negative sleep in `audit/tests/presync.rs:136,159` into a deterministic check | M | Low; speeds up CI. Mostly done (`chore/injectable-clock`: `ManualClock` in the approval, window and session-TTL tests, a checkpointer barrier in `presync.rs`; `chore/deterministic-time-tests`: the stream guard reads the proxy's clock (`StreamGuard::with_clock`), so the two token-expiry stream tests advance a `ManualClock`, and the six re-check waits in `session_and_stream_guard.rs` are gone, each negative check made exact by waiting until the upstream has seen every guarded stream dropped; that binary 2.84 s to 0.96 s). Left: the notifier tests in `server/tests/approval_notifier.rs` (a 1 s approval TTL waited out, three "nothing else arrives" waits), since the notifier reads the system clock on its own thread; the 1 s stream re-check in `e2e.rs` (`stream_recheck_seconds` takes whole seconds); `an_untouched_listen_stream_keeps_flowing`, which must span eight real re-check ticks; and the audit sleeps that are the workload or the busy-handler backoff under test. (updated 2026-11-06: done on `chore/notifier-clock-tests`; see row 8 of the addendum's debt table) |
| 9 | Rename or fold the seven review-pass test files (`security_pass3.rs` and the rest) into feature-named files, keeping the SR ids in test names or comments. Done (`chore/test-file-hygiene`: nine files renamed, the two pass 8 files included; module docs list the SR ids; the server's SR-30 and SR-34 server-name tests moved to `hardening.rs`; see section (f)) | S | Low |
| 10 | A `tests/common/mod.rs` for the server and the CLI (`fn attenuo()` ×11, `sha256_hex` ×12, `wait_for` ×3, the agent-config builders). Done (`chore/test-file-hygiene`: `attenuo` ×11 and `sha256_hex` ×3 in the CLI's, `sha256_hex` ×8, `agent_configs` ×9 and `wait_for` in the server's, `wait_for` ×2 in the audit crate's; `admin_policies.rs` keeps its own `sha256_hex`) | S | Low |
| 11 | Narrow the server's `pub mod` surface (`server/src/lib.rs:46-59`) to what `main.rs` and the integration tests use, and give `src/jwks.rs` a name that says "issuer keys". Done (`chore/proxy-docs-server-surface`: `actor`, `clientauth`, `idp`, `replay` and `state` are `pub(crate)`; `src/jwks.rs` is `src/issuer_keys.rs`) | M | Low |
| 12 | Adopt `missing_errors_doc` for core, token and policy (an `# Errors` section on each public fallible function) | M | Low. Done (`chore/policy-docs-errors-doc`: `#![warn(clippy::missing_errors_doc)]` on in all three; 68 sections at 439fc28, core 21, token 19, policy 28; the 253 of (g) count every crate) |
| 13 | Python SDK: export audit verification, the MCP helpers and the DPoP helpers from the package root, as TypeScript does | S | Low (additive). Done (`chore/python-sdk-exports`: all of `attenuo.audit.__all__`, the DPoP and MCP helpers, `capabilities_to_json` and `TOKEN_TYPE` are in the root and its `__all__`; `tests/test_root_exports.py` checks each is its submodule's object) |
| 14 | `audit/src/lease.rs:1134,1152`: `get_or_insert_with` instead of `expect("set above")`; `policy/src/request.rs:204`: parse the fixed Cedar entity type names once | S | Low. Done (`chore/audit-docs-small-debt`: `Option::insert` in the memory store, four `LazyLock` type names in `request.rs`) |
| 15 | Turn on `unreachable_pub` for the library crates so the `pub(crate)` cleanup on this branch stays done | S | Low. Done (`chore/unreachable-pub`: `#![warn(unreachable_pub)]` in core, token, policy, audit and proxy; one hit at 39b77ac, the test-only `AwaitedResults::len` in `proxy/src/label.rs`, now `pub(crate)`; server half done in `chore/unreachable-pub-server` at 4ffe725: `#![warn(unreachable_pub)]` in `attenuo-server` and the `attenuo-bench` library, the server's 31 hits, all in the crate-private `actor`, `clientauth`, `idp`, `issuer_keys` and `replay` modules, now `pub(crate)`; the bench library had none, and `attenuo-cli` is a binary only) |
| 16 | `JcsError` to `thiserror` like every other error type in the workspace | S | Low. Done (`chore/debt-small`; messages unchanged) |

## What was fixed on this branch

Each is its own commit; `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` stayed green.

1. `#![forbid(unsafe_code)]` in core and `#![deny(unsafe_code)]` in token, audit, proxy, CLI and bench, as ADR-0004's conventions say.
2. `Decision::as_str` in core, replacing four hand-written conversions (section d).
3. The proxy's list filter reuses core's pattern matcher (section d).
4. The server's `[proxy] stream_recheck_seconds` default reads the proxy's constant (section d).
5. Methods on crate-private types marked `pub(crate)`: 19 `unreachable_pub` hits (section c).
6. The two `expect` calls on the audit append path return `AuditError::Storage` (section e).
7. Every public item of `attenuo-core` documented, `#![warn(missing_docs)]` on.
8. The approval types of `attenuo-token` documented, `#![warn(missing_docs)]` on.

How the numbers were produced: the pedantic count came from one `cargo clippy ... --message-format=json` run, deduplicated by lint, file and line. The missing-docs and `unreachable_pub` counts came from `cargo clippy --workspace --lib -- -A clippy::all -W missing_docs -W unreachable_pub`. The unwrap list came from a script that skips `#[cfg(test)]` items by brace matching, checked by hand; the test counts came from attribute counts. No tool was installed for this pass, and `cargo udeps` was not available. A grep of each crate's declared dependencies against its sources found none unused.

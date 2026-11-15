# Fuzzing

- Status: first campaign 2026-10-23 (`test/fuzz-targets`); second campaign, 10 minutes per target, 2026-10-23 evening (below); round 2 over run limits, budgets, approval tokens, the usage walker and the server routes, 2026-10-24 ([write-up](../research/fuzzing-2026-10-24-round2.md)); round 3 over the pass 7 SSE parsing (`SseFramer`, `SseRewriter`, `parse_data`, the stream-end scan and rewrite), 2026-10-25 ([write-up](../research/fuzz-round-3-2026-10-25.md)); `decimal` and `set<decimal>` inputs in `policy_context`, checked against an exact-digit oracle, 2026-11-06 (`fuzz/policy-context-decimal`, 300 s, 424 k runs, no crash; the order of `Outcome::policy_ids` varies between identical calls); the prepared implication and the hop-0 split rule, `capability_prepared` and `capability_attenuate_root`, 2026-11-15 ([below](#prepared-implication-and-hop-0-2026-11-15)); the ID-JAG ceiling, `idjag_ceiling`, 2026-11-15 ([below](#id-jag-ceiling-2026-11-15))
- Crate: `fuzz/` (cargo-fuzz, libFuzzer), outside the workspace
- Related: [threat model](../spec/threat-model.md), [security review pass 3](../research/security-review-2026-10-23.md)

attenuo parses a lot of input it does not trust: delegation tokens and DPoP proofs from agents, JSON-RPC bodies and headers from MCP clients, SSE streams and list results from upstreams, tool arguments that become Cedar context, and audit exports handed to an offline verifier. Unit tests and proptest cover the cases someone thought of. The fuzz targets cover the rest: each one feeds generated or mutated input to a public API and checks that it never panics and that a security property still holds.

How to run them, and a table of targets, is in [`fuzz/README.md`](https://github.com/attenuo-dev/attenuo/blob/main/fuzz/README.md).

## Design

- **cargo-fuzz on nightly, outside the workspace.** libFuzzer needs `-Zsanitizer` and coverage flags only nightly has, so `fuzz/` is excluded from the root workspace (`exclude = ["fuzz"]`) and has its own `Cargo.lock`. `cargo clippy --workspace`, `cargo test --workspace` and `cargo deny check` do not see it. CI builds it on nightly (job `fuzz-build`), and compiles it on stable with `--cfg fuzzing` and `--locked` on every pull request that can change Rust (job `fuzz-check`), so a library change cannot break a target or leave its lockfile stale unnoticed.
- **Public APIs only, with two exceptions.** Until round 3 no crate exposed anything new for fuzzing. Round 3 reaches the crate-private SSE helpers through `attenuo_proxy::fuzzing`, a `#[doc(hidden)]` module of thin wrappers behind the `fuzzing` cargo feature that only `fuzz/Cargo.toml` turns on; it is not an API. `attenuo_server::fuzzing` does the same for the ID-JAG ceiling (`IdJagCeiling::from_config` and `apply`, and the hop-0 narrowing of `intake::narrow` once the ceiling is looked up). The proxy target drives `attenuo_proxy::router` through `tower::ServiceExt::oneshot` with a small `Authorizer` and an in-process upstream; the DPoP target calls both `attenuo_token::dpop::verify_proof` and the server's `Dpop::verify`.
- **Properties, not only crashes.** "No panic" finds overflow and `expect` bugs. Most targets also assert a property the code is supposed to guarantee: an accepted chain narrows at every hop; `child ⊆ parent` means every call the child permits is permitted by the parent; nothing reaches the upstream that the chain does not permit; a verified audit export has not changed a countersigned entry.
- **Structured inputs.** Random bytes rarely get past a signature check. The token, DPoP and audit targets start from a valid object (a token minted by an issuer with a fixed key, a signed export) and mutate it, re-signing where the attacker model allows: a holder of a second issuer key can re-sign the JWT but not `ou_sig`, a holder of the DPoP key can sign any proof, an attacker without the checkpoint key can re-hash the audit chain but not re-sign checkpoints.
- **Overflow checks on.** cargo-fuzz builds with debug assertions, so integer overflow panics instead of wrapping silently.

## Targets

| Target | Area | Run (s) | Executions |
| --- | --- | ---: | ---: |
| `token_verify_bytes` | token | 120 | 18.5 M |
| `token_verify_mutated` | token | 120 | 7.1 k |
| `chain_validate` | core | 120 | 10.9 M |
| `ou_sig` | token | 120 | 459 k |
| `dpop_proof` | token, server | 120 | 827 k |
| `names` | core | 120 | 20.6 M |
| `capability_attenuation` | core | 120 | 1.67 M |
| `proxy_jsonrpc` | proxy | 180 | 349 k |
| `proxy_sse` | proxy | 120 | 1.08 M |
| `policy_context` | policy | 120 | 140 k |
| `audit_export_bytes` | audit | 120 | 4.74 M |
| `audit_export_mutated` | audit | 120 | 354 k |

Run on a shared 4 vCPU container with other builds going, `-s none` (no AddressSanitizer), one process per target. The run times are the last clean run, after the fixes below. Execution counts vary by an order of magnitude with the target's setup: `token_verify_mutated` signs and parses tokens of up to hundreds of hops per input, and `proxy_jsonrpc` makes a real HTTP round trip to its upstream.

## Findings

| # | Target | Where | What | Status |
| --- | --- | --- | --- | --- |
| F1 | `dpop_proof` | `attenuo-token` `dpop::verify_proof` | `(now - iat).abs()` with a caller-chosen `iat`: overflow panic in debug builds; in release builds `iat = now - 2^63` wrapped to `i64::MIN`, whose `abs()` is negative, so the proof passed the freshness check (and its replay-cache entry expired at once). The attacker needs the DPoP key, so the impact is a proof replayable within that one second, and a panic in debug builds. | Fixed: `abs_diff`; test in `dpop.rs` |
| F2 | `ou_sig` | `attenuo-token` `Issuer::issue_root` | An `authenticated_at` before year 0 (an IdP `auth_time` of about -1e11 seconds, which the server copies unchecked) has no RFC 3339 form, and the `ou_sig` encoding panicked on it (`expect("OriginatingUser serializes")`). Needs an assertion signed by a trusted IdP. | Fixed: `issue_root` refuses such a chain with `TokenError::Malformed`; test in `tests/token_exchange.rs` |
| F3 | `proxy_jsonrpc` | `attenuo-proxy` `filter::ListFilter` | A `tools/list` sent with `"id": 1.0` (or an integer above 2^53) and answered by an upstream that parses ids as doubles (any JavaScript server) comes back as `"id": 1`. The filter matched ids by exact JSON value, so the answer passed through unfiltered and the client saw tools its chain cannot call. A second run found the same with a huge fractional id (`1.866909276318353e230`), whose two spellings `serde_json` parses a unit in the last place apart, and a third with an (invalid) array id holding such numbers. Calls to the hidden tools were still denied. | Fixed: numeric ids compare by value, doubles within a few ULPs, arrays and objects member by member; test in `filter.rs` |
| F4 | `audit_export_mutated` | `attenuo-audit` `log::walk_entries` | An entry with `seq` = 2^64 - 1 and a correct hash makes `expected_seq = entry.seq + 1` overflow: a panic where overflow checks are on (debug builds, the fuzz build), a wrap to 0 in release. Reachable from any export file given to `attenuo audit verify`. | Fixed: `checked_add`, an entry at `u64::MAX` is a bad entry; tests `an_entry_at_u64_max_fails_verification_cleanly_f4`, `an_export_entry_at_u64_max_fails_cleanly_f4`; the skip is gone from both targets |
| F5 | `audit_export_mutated` | `attenuo-audit` `export::verify_export` | Entries after the header's `to` are accepted as an unsigned tail: appending a forged entry 6 to a signed export of `1..=5` (chained and hashed correctly) still verifies `ok`, with `unsigned_tail = 1`. Whether a file that holds more than its header says should fail is a design decision. | Fixed: decided strict. An export needs its header; entries outside `from..=to` fail it (`outside_range`), and so do entries after its last valid checkpoint (`unsigned_tail_rejected`) unless the caller passes `allow_unsigned_tail` (CLI `--allow-unsigned-tail`). Test `entries_after_the_declared_range_fail_the_export_f5`; both targets now check the range and the absence of an unsigned tail on every verified export |

Harness bugs found on the way (fixed in the targets, not product bugs): a random-UUID fixture token compared byte for byte across runs, an out-of-range time offset in the `ou_sig` generator, a JavaScript number model that saturated instead of printing the full integer, edits on hops that were no longer objects, and an audit check that looked at entries after a chain break.

No panic and no property violation was found in `chain_validate`, `names`, `capability_attenuation`, `token_verify_bytes`, `token_verify_mutated`, `proxy_sse` or `policy_context` in these runs.

## Second campaign: 10 minutes per target (2026-10-23 evening)

Same container (4 vCPU, shared with other builds), `-s none`, `-timeout=20`, each target started from `seed_corpus` and run for 600 s on main @ 034fd5c. No crash, no timeout and no property violation in any target. Coverage is libFuzzer's final `cov:` edge count.

| Target | Runs | Edges |
| --- | --- | --- |
| `names` | 117,120,469 | 151 |
| `token_verify_bytes` | 75,053,697 | 2,349 |
| `chain_validate` | 42,208,686 | 3,441 |
| `audit_export_bytes` | 28,972,532 | 2,900 |
| `proxy_sse` | 7,071,736 | 1,862 |
| `dpop_proof` | 4,146,179 | 1,810 |
| `capability_attenuation` | 3,236,332 | 1,431 |
| `ou_sig` | 1,564,866 | 2,366 |
| `proxy_jsonrpc` | 1,369,494 | 8,331 |
| `audit_export_mutated` | 1,253,294 | 3,029 |
| `policy_context` | 462,584 | 6,161 |
| `token_verify_mutated` | 78,851 | 4,233 |

The spread in run counts is the targets' setup cost, as in the first campaign: `token_verify_mutated` signs and parses a whole token per input and `proxy_jsonrpc` makes an HTTP round trip. Ten minutes is still short for the slow targets; a campaign on a dedicated machine should give those an hour or more. Corpora were not kept.

## Prepared implication and hop 0 (2026-11-15)

Two targets over the code merged on 2026-11-14: the prepared implication of SR-123 (#329) and the hop-0 split rule of SR-121 (#328).

- `capability_prepared` asks each question twice. The core compares small constraints and sets pair by pair and larger ones through `capability/prepared.rs`; both are private, so the target reaches them by size. Its reference (`fuzz/src/caps.rs`) splits every `one_of` into its values, so the core only ever answers it on the pairwise path, and each set check runs again with the parent padded by a capability that covers nothing but is too large for the pairwise path. It also checks that `jcs::value_key` is equal exactly when `jcs::value_eq` is, on values `serde_json` parses from generated text, and that `validate_size` refuses exactly at the documented bounds.
- `capability_attenuate_root` checks `attenuate_root` against `attenuate` and against a reference written from its documentation. Since SR-128's fix the rule is checked against every limited grant capability that covers a request's calls: each covers the calls of at most one result capability, whose limits are within it, and `LimitConflict` is answered only when one capability cannot carry their limits. A limited grant capability that only overlaps a request is outside it, by design.

Before the runs, each target was checked against a bug planted in the core for the check and then taken out again, one at a time: a `>` turned into `>=` in the path summary, the `keys.len() == 1` test dropped from the `one_of` against `equals` arm, `MAX_CONSTRAINTS` refused one early, and the split check turned off. Each was caught within three minutes. The first one was missed until the generator was biased towards lists of a single kind (all paths, all strings, all integers), so how well a generator reaches the summaries matters as much as the run time.

Same 4 vCPU container, `-s none`, `-timeout=20`, one target at a time, on `cb99e91a` with the targets added. Each started from the corpus of a short trial run. No crash, no timeout and no property violation.

| Target | Run (s) | Runs | Edges (`cov:`) |
| --- | ---: | ---: | ---: |
| `capability_prepared` | 600 | 1,085,986 | 4,586 |
| `capability_attenuate_root` | 600 | 714,282 | 4,048 |
| `capability_attenuation` (again, the code under it changed) | 300 | 2,103,562 | 1,961 |
| `limits_charges` (again) | 300 | 498,743 | 4,718 |

The slowest input of `capability_prepared` took 10 s. Its `one_of` values come from the shared JSON generator, which can repeat a string of 9 KB 2,000 times in one value, and the reference clones each value once per comparison. That is the size of the generated input, not a cost of the code under test: a request body that large would be over the server's 2 MiB limit. The ID-JAG ceiling (`IdJagCeiling::apply`, the intake narrowing) is not fuzzed. It is crate-private in `attenuo-server`, which has no `fuzzing` feature, and reaching it over HTTP would need an IdP key server and signed ID-JAGs in the harness.

## ID-JAG ceiling (2026-11-15)

`idjag_ceiling` covers the code that #338 left out: `[idps.id_jag_ceiling]` (`idp/ceiling.rs`, `IdJagCeiling::from_config` and `apply`) and the hop-0 narrowing under it (`intake::narrow`). Two security passes found three problems there (SR-121's route through the ceiling, SR-127, SR-129). The code is crate-private, so attenuo-server now has a `fuzzing` feature, off by default and enabled only by `fuzz/Cargo.toml`, with a `#[doc(hidden)]` module `attenuo_server::fuzzing` of three thin wrappers: building the ceiling from its config, `apply`, and the narrowing. The narrowing wrapper calls `intake::narrow_with`, which is `narrow` after the ceiling is looked up. `narrow` itself now only looks the ceiling up and calls it, so the target runs the server's code and has no copy of its logic. `--all-features` builds the module, and clippy and the docs stay clean with it.

Generated inputs: a config whose `resources` and `scopes` map to small capability sets, some with limits; a root grant, some of its capabilities limited; the three claims (`scope` with repeated tokens and odd whitespace, `resource` as a string or an array with repeats and non-strings, `authorization_details` with the right and the wrong `type`, capabilities with and without limits, and malformed members); and a request. Half the inputs are shaped to reach the narrow path: a broad grant, both `scope` and `authorization_details` present, the details built under the `scopes` entries the claim names, and a request with one capability per named one or two per named one. Without that shaping, fewer than one input in a thousand passed every check with a limited step between, and no planted bug in the step check was caught in ten minutes.

The properties are listed in the target's header. In short: an accepted config is built whole; the ceiling and every recorded step are within the grant; a claim with repeated or reordered values gives the same ceiling as its distinct set, and costs at most 80 more heap allocations in `apply` (SR-129 was a cost bug, which equal answers alone do not show); every recorded step holds a limit; a narrowed result is within the grant, the final ceiling and every recorded step, and each limited capability of any of them that covers a result capability's calls covers those of at most one, whose limits are within it (SR-121, SR-127, SR-128); the request's order does not change the answer. The budget property is stronger than the split rule. For the limited capabilities of the grant it is checked on every input since SR-128's fix. For those of the `scopes` entries it holds only in one mode, which a third of the inputs use. In that mode, no two limited capabilities of the grant and of the `scopes` entries overlap, no capability without limits on the same side overlaps a limited one, and `authorization_details` carries no limits. Each limited capability of the grant, and of a `scopes` entry the claim names, is then the only source of limits for the calls it covers. The `calls` figures of the result capabilities whose calls it covers add up to at most its own, and so do their `sum` figures on its argument. `calls_per` and `distinct` are left out because a per-value bound does not add up. Outside the mode the `scopes` property does not hold: a capability without limits that only overlaps a limited one gives its calls without the limit, which is how a grant read as a union has always worked, and `meet` keeps a grant capability that a limited `scopes` capability covers with its limits in place of the `scopes` capability, so two limited grant capabilities under one limited `scopes` capability keep their own figures and the `scopes` figure is in no set the server checks.

Before the run, four bugs were planted one at a time and then taken out. The time is the fuzzing time until the first violation (runs over the run rate), from a fresh corpus, after a build of about two minutes. These runs were made before the 2 MiB skip described below was added; it skips only inputs far larger than any of those.

| Planted bug | Caught by | Runs | About |
| --- | --- | ---: | ---: |
| (a) the per-step loop in `narrow` removed (SR-127 back) | split rule, at a recorded step | 7,111 | 2 s |
| (a) again, with the step clause of the split rule off | budget (a `scopes` `calls` of 3 spent 12 times) | 19,690 | 5 s |
| (b) the de-duplication of SR-129 removed | allocation bound (4,604 against 4,304) | 80,027 | 23 s |
| (c) `meet` keeping the claim's limits instead of the clamped ones | the ceiling not within a recorded step | 8,690 | 3 s |
| (d) the split check against the final ceiling made a no-op | split rule, at the final ceiling | 187,766 | 100 s |

Property 3 alone (equal ceilings) does not see (b): the result is the same set, only slower to build. The allocation count does, because without the de-duplication each repeat clones the capabilities its token maps to. The first version of (d) took longer than five minutes, until the request generator also made pairs of capabilities under one named capability.

The run: same 4 vCPU container, `-s none`, `-timeout=20`, on `8c077d08` with the target added, from an empty corpus. No crash, no timeout and no property violation.

| Target | Run (s) | Runs | Edges (`cov:`) | Features (`ft:`) | Corpus | Crashes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `idjag_ceiling` | 900 | 999,975 | 6,073 | 31,928 | 6,534 | 0 |
| `idjag_ceiling`, an earlier run before the 2 MiB skip | 900 | 840,676 | 5,980 | 31,111 | 6,214 | 0 |

The run rate fell from about 2,900 a second to 1,100 as the corpus grew to longer inputs; peak RSS was 695 MB. libFuzzer reported no input of 10 s or more.

Inputs whose request and claims are over 2 MiB of JSON are skipped. The server refuses a body that large, and the earlier run spent 13 s on one input with a 36 MB request, 2.2 s of it in the narrowing, which grows with the size of the input. Fifteen minutes on one VM shows that the properties hold on what this generator reaches in that time. It does not show that they hold everywhere. The generator decides most of what is reached: the step check was out of reach until the inputs were shaped.

## All targets, 5 minutes each (2026-11-15)

Every target in `cargo fuzz list` (22) was run once on `main` at #339, one at a time, on the 4 vCPU VM used for the runs above: `cargo +nightly fuzz run <target> -s none -- -max_total_time=300 -timeout=20`, each from an empty corpus. No target crashed, timed out or reported a property violation, and no artifact was written. Together they executed 191,805,781 inputs.

| Target | Runs | `cov:` |
|---|---:|---:|
| `approval_token` | 234,490 | 4,531 |
| `audit_export_bytes` | 21,321,638 | 1,125 |
| `audit_export_mutated` | 714,525 | 3,025 |
| `budget_plan` | 104,664 | 3,437 |
| `capability_attenuate_root` | 831,065 | 4,040 |
| `capability_attenuation` | 1,927,373 | 1,953 |
| `capability_prepared` | 565,240 | 4,569 |
| `chain_validate` | 38,409,186 | 1,822 |
| `dpop_proof` | 2,548,945 | 1,767 |
| `idjag_ceiling` | 444,950 | 5,943 |
| `limits_charges` | 261,951 | 4,406 |
| `names` | 57,256,050 | 155 |
| `ou_sig` | 836,829 | 2,478 |
| `policy_context` | 491,738 | 6,904 |
| `policy_usage` | 251,958 | 8,247 |
| `proxy_jsonrpc` | 746,142 | 9,020 |
| `proxy_sse` | 3,829,163 | 1,827 |
| `server_http` | 277,077 | 24,625 |
| `sse_framer_rewriter` | 1,556,131 | 2,218 |
| `sse_parse_data` | 13,857,804 | 1,724 |
| `token_verify_bytes` | 45,294,456 | 1,123 |
| `token_verify_mutated` | 44,406 | 4,127 |

Five minutes from an empty corpus is a smoke run: it shows that nothing shallow broke in the targets' reach after the changes of 14 November, and nothing more. The slow targets (`token_verify_mutated`, `budget_plan`, `approval_token`) got the fewest inputs.

## Limits

- Two minutes per target on a busy machine is a smoke test, not a campaign, and ten minutes (second campaign) is a short one. The corpora are not kept in the repository; a long run should start from `seed_corpus` and keep its corpus.
- `-s none` skips AddressSanitizer, which matters only for the C and assembly in `ring`.
- The proxy target models one JavaScript behaviour of upstreams (number ids). Other upstream quirks (case-insensitive tool names, SR-25) are covered by the integration tests, not here.
- The server's HTTP routes beyond DPoP (token exchange, AuthZEN over HTTP, admin) are not fuzzed; `policy_context` covers the AuthZEN request shape through `PolicyEngine::evaluate`.

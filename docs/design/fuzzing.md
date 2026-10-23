# Fuzzing

- Status: first campaign, 2026-10-23 (`test/fuzz-targets`)
- Crate: `fuzz/` (cargo-fuzz, libFuzzer), outside the workspace
- Related: [threat model](../spec/threat-model.md), [security review pass 3](../research/security-review-2026-10-23.md)

attenuo parses a lot of input it does not trust: delegation tokens and DPoP proofs from agents, JSON-RPC bodies and headers from MCP clients, SSE streams and list results from upstreams, tool arguments that become Cedar context, and audit exports handed to an offline verifier. Unit tests and proptest cover the cases someone thought of. The fuzz targets cover the rest: each one feeds generated or mutated input to a public API and checks that it never panics and that a security property still holds.

How to run them, and a table of targets, is in [`fuzz/README.md`](https://github.com/7Mudit/attenuo/blob/main/fuzz/README.md).

## Design

- **cargo-fuzz on nightly, outside the workspace.** libFuzzer needs `-Zsanitizer` and coverage flags only nightly has, so `fuzz/` is excluded from the root workspace (`exclude = ["fuzz"]`) and has its own `Cargo.lock`. `cargo clippy --workspace`, `cargo test --workspace` and `cargo deny check` do not see it. CI builds it on nightly (job `fuzz-build`).
- **Public APIs only.** No crate exposes anything new for fuzzing. The proxy target drives `attenuo_proxy::router` through `tower::ServiceExt::oneshot` with a small `Authorizer` and an in-process upstream; the DPoP target calls both `attenuo_token::dpop::verify_proof` and the server's `Dpop::verify`.
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

## Limits

- Two minutes per target on a busy machine is a smoke test, not a campaign. The corpora are not kept in the repository; a long run should start from `seed_corpus` and keep its corpus.
- `-s none` skips AddressSanitizer, which matters only for the C and assembly in `ring`.
- The proxy target models one JavaScript behaviour of upstreams (number ids). Other upstream quirks (case-insensitive tool names, SR-25) are covered by the integration tests, not here.
- The server's HTTP routes beyond DPoP (token exchange, AuthZEN over HTTP, admin) are not fuzzed; `policy_context` covers the AuthZEN request shape through `PolicyEngine::evaluate`.

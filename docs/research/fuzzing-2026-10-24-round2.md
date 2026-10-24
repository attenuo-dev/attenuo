# Fuzzing, round 2 (2026-10-24)

- Status: done on `test/fuzz-round-2`, from main @ c3b21fc
- Crate: `fuzz/` (cargo-fuzz, libFuzzer), as in the [first campaign](../design/fuzzing.md)
- Related: [run limits](../design/run-limits.md), [output labelling](../design/output-labelling.md), [security review pass 5](security-review-2026-10-24-pass5.md)

The first campaign covered tokens, DPoP, chains, the proxy, policy context and audit export. Since then attenuo gained run limits and run usage, budget counters with refunds, signed approval tokens, a Cedar walker that decides whether usage is kept, and more request bodies on the server. An attacker reaches all of them with a child token or with the arguments of a call. This round adds five targets over those surfaces, with the same design as the first: public APIs only, structured inputs, properties checked beyond "no panic", overflow checks on. Two property-test files run the same checks on stable in CI.

## Targets

| Target | What it calls | Invariant beyond "no panic" |
| --- | --- | --- |
| `limits_charges` | `Limits` deserialisation and `validate`, `narrows`, `clamp_to`, `charges_for` and `usage_charges` over arbitrary arguments (nested lists, numbers at the edges, floats, control characters, lists of 254 to 258 elements), `Derive::Host` on URL-shaped strings, `jcs` | a valid `Limits` has every `max` at most `MAX_LIMIT` and clean argument names; `clamp_to` is idempotent, never widens a child that already narrows, and narrows the parent when both count the same arguments; every charge carries its limit's `max` and the argument's amount; a limit counts each value once and at most `MAX_COUNTED_VALUES`; a `limit_arg_invalid` names an argument that really is missing or unusable; a derived host of a special scheme is a fixpoint; canonical JSON is a fixpoint and `jcs::value_eq` agrees with byte equality |
| `budget_plan` | `LeaseStore::charge` and `LeaseStore::refund` (so `budget::plan`) on random sequences of charges (calls, sum, `calls_per`, `distinct`, run usage; amounts up to `MAX_LIMIT`) and refunds, against the memory store and the SQLite store in a temporary file, side by side, and a model | both stores give the same outcomes and counters as each other and as the model; a `distinct` count equals its value rows with `used > 0`; no counter exceeds its `max`; a refund never takes a counter below 0; after every decision is refunded every counter is 0 (SR-62: a value is freed only when its last holder is refunded); the two stores summarise each lease the same way |
| `approval_token` | `Verifier::verify_approval` on byte-mutated tokens and on tokens with edited claims or headers re-signed with the issuer key, `ApprovalClaims::check_binding`, cross-type checks, and `take_approval` / `take_approval_by_id` in both stores with mutated retry arguments | a byte-mutated token never verifies with other claims; an accepted token has the approval `typ`, the issuer's `iss` and `aud`, a future `exp` and a well-formed `cnf`; `check_binding` accepts exactly the claims' run, lease, hash and key; an approval and a delegation token are never each other; an approval is taken exactly when the retry's arguments have the same canonical JSON (respelled numbers and reordered members match, anything else does not), only by its hop, and once |
| `policy_usage` | `policies_read_usage` on policies from a small Cedar grammar and on raw text | never "nobody reads usage" for a policy whose AST names `context.usage` (`context.usage`, `context["usage"]`, `context has usage`, nested `has`, unicode escapes), nor for a policy whose answer changes when only `context.usage` changes (evaluation oracle over three usage records) |
| `server_http` | the server's router through `oneshot`: `POST /access/v1/evaluation` and `/access/v1/evaluations` with a valid bearer whose root hop carries run limits (so the bodies reach `charges_for` and run usage), garbage, `Basic`, `DPoP` and admin authorization, valid and invalid approval tokens in `context.approval_token`; `POST /approvals/{id}` and `POST /admin/approvals/{id}` with fuzzed bodies and ids | no 5xx; an allowed evaluation has reason `policy_allow`; a batch answers one result per entry; a decision on an approval that does not exist never succeeds |

The first campaign did not fuzz the server's routes (`policy_context` reached the AuthZEN shape only through `PolicyEngine::evaluate`), so `server_http` covers both AuthZEN request parsing over HTTP and the approval decision bodies.

Property tests in the existing style (`crates/attenuo-core/tests/attenuation_props.rs`):

- `crates/attenuo-core/tests/limits_props.rs`: clamping, charges, the host fixpoint over URL spellings (case, user info, ports, IDNA, IPv4 notations, trailing dots) and canonical JSON, 1024 cases each.
- `crates/attenuo-audit/tests/budget_props.rs`: the `budget_plan` model and differential, 256 sequences against an in-memory SQLite store and 32 against a file store.

## Run

Same container as the first campaign (4 vCPU, shared with builds and the other targets), `-s none`, `-timeout=20`, no seed corpus (the targets build their inputs), 600 s per target, three or four targets at a time. The run counts are libFuzzer's final figures, coverage its final `cov:` edge count.

| Target | Run (s) | Executions | Edges | Corpus at the end | Code |
| --- | ---: | ---: | ---: | --- | --- |
| `limits_charges` | 600 | 1,002,566 | 4,793 | 3,777 inputs, 277 KB | after the fixes |
| `budget_plan` | 600 | 132,256 | 3,321 | 1,173 inputs, 57 KB | after the fixes |
| `approval_token` | 600 | 360,205 | 4,466 | 2,342 inputs, 64 KB | before the fixes (not affected) |
| `policy_usage` | 600 | 351,818 | 8,261 | 2,385 inputs, 109 KB | before the fixes (not affected) |
| `server_http` | 600 | 283,390 | 23,083 | 3,623 inputs, 100 KB | before the fixes |

Earlier runs are not in the table. `limits_charges` stopped three times before the run above: on FZ2-1 within a minute, on FZ2-2, and on the multi-dot IPv4 case of FZ2-1 (`HTTPS://a.example....=.....1.....`), with a clean 120 s run of 333,069 executions between the first two. `budget_plan` ran 600 s clean with one SQLite file per sequence (16,848 executions), then hit FZ2-3 once it kept one file for 2,000 sequences, each under its own lease names and decision ids, which made it about eight times faster. Corpora were not kept, as in the first campaign.

## Findings

| # | Found by | Where | What | Severity | Status |
| --- | --- | --- | --- | --- | --- |
| FZ2-1 | `limits_charges` (host fixpoint) | `attenuo-core` `Derive::Host` | Only one trailing dot was stripped: `https://a.example../` counted as host `a.example.`, apart from `a.example`, and that host used again (`https://a.example./`) counted as `a.example`. Each extra dot was a new value, so a `calls_per` limit on `url#host` gave every spelling its own budget, and run usage saw a fresh `destination_seen`. Whether a client reaches the host through `a.example..` depends on its resolver; many refuse the empty label. `distinct` was not weakened (more values, not fewer). After the first fix the property tests and the fuzzer found that `https://0x7f.1../` then counted as `0x7f.1`, while `https://0x7f.1/` counts as `127.0.0.1` (WHATWG reads a host as IPv4 only with at most one trailing dot). | Low | Fixed: every trailing dot is stripped, and a special-scheme host that lost more than one is parsed again; test `trailing_dots_are_one_host_fz2_1` in `limits.rs`, property `a_derived_host_is_a_fixpoint` |
| FZ2-2 | `limits_charges` (host fixpoint) | `attenuo-core` `Derive::Host` | `Derive::Host` accepts a URL of any scheme. A non-special scheme (`ssh://`, `git://`, `foo://`) has an opaque host, which WHATWG neither percent-decodes nor maps through IDNA: `ssh://a.ex%61mple/` counts as `a.ex%61mple` and `ssh://a.example/` as `a.example`, and `git://βόλος/` as its percent-encoding, not `xn--nxasmm1c`. A tool that decodes the host reaches one destination under several values, so `calls_per` and ask-on-repeat rules can be passed, as with the aliases of SR-65. | Low | Open on the board. Proposed fix: count hosts of special schemes only and treat any other URL as having no host (a limit refuses the call, run usage counts the value raw, as for SR-63), or percent-decode an opaque host and run it through domain-to-ASCII. Both change behaviour for tools that take `ssh://` URLs, so this waits for a decision |
| FZ2-3 | `budget_plan` (differential) | `attenuo-audit` `sqlite::refund_in` | The SQLite refund subtracted `SUM(amount)` of a decision's rows per counter; two rows on one counter adding up past 2^63 - 1 (run usage, up to `MAX_LIMIT` each) overflowed SQLite's integer `SUM`, so the refund failed with a storage error where the memory store succeeded. The pipeline charges each counter once per decision, so this is not reachable through a call today. | Info | Fixed: one saturating `UPDATE` per logged row; test `refund_of_two_large_rows_on_one_counter_fz2_3` in `tests/budgets.rs` |
| FZ2-4 | `budget_props` (model) | `attenuo-audit` refund in both stores | A run-usage counter saturates at `MAX_LIMIT`, but a refund subtracted what the decision logged. After a call with an amount near `MAX_LIMIT` (allowed by any policy that does not bound the amount itself) and a second call of 5, refunding the first left `context.usage.amount` at 0 instead of 5, and refunding the second left it at `MAX_LIMIT - 5`. A refund happens when a charged decision's audit append fails or when an operator refunds it. | Low | Fixed: a refund recomputes each usage counter it touches from the unrefunded charge rows, capped at `MAX_LIMIT`; test `usage_refund_after_saturation_keeps_the_rest_fz2_4` in `tests/budgets.rs`, property `stores_agree_with_the_model` |

The regression tests for FZ2-3 and FZ2-4 failed on the unfixed stores first. `budget_plan` did not hit FZ2-4 in its runs (it needs two saturating amounts and a refund in the right order); the proptest model found it in its first 256 cases.

Also fixed on the way: the existing `proxy_jsonrpc` target no longer compiled (its test authorizer built `AuthDecision` field by field and had not followed the `limit`, `untrusted_args` and `usage` fields), so the CI job `fuzz targets build` would have failed; it uses `AuthDecision::deny` now.

Harness bugs found on the way (fixed in the targets, not product bugs): canonical JSON of generated values nested deeper than `serde_json` parses (tool arguments arrive as text, at most 128 levels, so deeper values are not reachable), an edit on an AuthZEN body whose `context` an earlier edit had replaced with a number, and a `clamp_to` property that expected an already narrowing child to be left exactly as it was (clamping may still lower a figure the child's `calls` already bounds, which only narrows).

No panic and no property violation was found in `approval_token`, `policy_usage` or `server_http`. In particular, the usage walker never missed a read of `context.usage`, and an approval was never taken by a retry whose canonical arguments differed.

## Limits

- Ten minutes per target on a shared machine is a short campaign. `budget_plan` and `server_http` run a few hundred inputs per second; an hour or more on a dedicated machine would be the next step.
- `policy_usage` generates from a grammar of attribute access, `has`, records, sets, conditionals and a few methods. Cedar features outside it (extension functions, entity tags on records) are reached only by the raw-text inputs, which rarely parse.
- `server_http` runs with no IdP configured, so `POST /approvals/{id}` stops at the ID token check; the decision path with a valid ID token is covered by the integration tests, not here. It does not send DPoP proofs.
- The SQLite side of `budget_plan` shares one file between sequences, each under its own lease names; a bug that only shows across leases of one store would need its own target.

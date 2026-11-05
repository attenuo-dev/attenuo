# List screen: Cedar partial evaluation for 200 tools (2026-11-05)

Branch `feat/cedar-list-filter`, base `a2d7a84`. Summary: [performance, List screen](../performance.md#list-screen-partial-evaluation-2026-11-05). Decision this measures: [ADR-0011](../../decisions/0011-cedar-aware-list-filtering.md) (proposed), whose confirmation asked for "a criterion bench of partial evaluation for 200 tools next to `policy_stage`" before acceptance. The ADR's estimate was 2 to 5 ms per warm 200-tool list and about 25 ms on a chain's first list.

## Feasibility

cedar-policy 4.14.0 (the version in `Cargo.lock`), read from the crate source: the `partial-eval` feature gates `Authorizer::is_authorized_partial(&Request, &PolicySet, &Entities) -> PartialResponse`, `RestrictedExpression::new_unknown(name)` and `PartialResponse::decision() -> Option<Decision>`. `Context::from_pairs` accepts unknowns as member values (it partially interprets the record), so `originating_user` and `chain` can stay concrete while `input`, `now_unix`, `session`, `args_contain_untrusted`, `untrusted_args`, `approval`, `budget`, `usage` and `session_id` are unknown. `decision()` is `Some(Deny)` when a forbid is satisfied or no permit is satisfied or residual, `Some(Allow)` when a permit is satisfied and no forbid is satisfied or residual, and `None` otherwise. With the feature on, concrete `is_authorized` runs the same code (`is_authorized_core(...).concretize()`); the evaluator only gains an unknowns mapper that is `None` for every name. The feature adds no crate to the dependency tree.

## Environment

The shared 4-vCPU dev container of the other 2026-10 files (Intel Xeon @ 2.10 GHz), rustc 1.99.1, `cargo bench` (the workspace release profile), `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0`. Load average 2.1 to 2.6 during the screen run, 3.0 to 3.8 during the `policy_stage` A/B. Warm-up 1 s, measurement 3 s (5 s for the A/B), 100 samples.

## Method

`crates/attenuo-policy/benches/list_screen.rs`, group `list_screen_partial`:

- the shipped starter policy (`policies/default.cedar`, `DEFAULT_POLICIES`), and for `screen_approval` the same plus one `@obligation("approval")` forbid on destructive tools in a tainted run, so the screen evaluates the relaxed set;
- a catalog of 200 tools on `github`: `create_issue`, `delete_repo` (sensitive), and 198 more, a third read-only, a third neither, a third read-only and sensitive;
- chains of 1 and 3 hops for a user without MFA. The bench asserts the outcome before timing: 133 of 200 hidden (66 that no permit allows, 66 sensitive read-only tools and `delete_repo`, all under `forbid_sensitive_without_mfa`), 67 kept (`create_issue` as a residual on `context.input`, the 66 read-only tools as an allow).

Rows, each one whole 200-tool list:

| row | what |
|---|---|
| `screen` | `PolicyEngine::screen_tools_uncached`: the per-list parts (principal, `originating_user` and `chain` records, the user, agent and server entities), then per tool the tool and action entities, the partial request and the partial evaluation. What a chain's first list costs; the server memoises the verdicts (commit 2). |
| `screen_memo` | `PolicyEngine::screen_tools` for a chain already screened: every verdict from the memo (chain digest, policy generation, server, tool, attributes). What a repeated list costs. Added with the memo (second commit of the branch); its run is below. |
| `screen_approval` | the same with the approval obligation |
| `prepare` | the first half alone (requests and entity stores for 200 tools) |
| `partial_eval` | the second half alone (200 `is_authorized_partial` calls on prepared requests) |
| `concrete_eval` | for comparison: 200 concrete evaluations of prepared calls, `policy_stage`'s `evaluate` row 200 times |

```
export CARGO_TARGET_DIR=/home/claude/agent-target-list CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
cargo bench -p attenuo-policy --bench list_screen -- --warm-up-time 1 --measurement-time 3
```

## Results (ms per 200-tool list)

| row | 1 hop | 3 hops |
|---|---|---|
| `screen` | **4.94** [4.84, 5.05] | **5.52** [5.46, 5.60] |
| `screen_approval` | 4.95 [4.87, 5.04] | 6.12 [5.90, 6.35] |
| `prepare` | 3.94 [3.84, 4.05] | 4.46 [4.38, 4.54] |
| `partial_eval` | 1.77 [1.72, 1.83] | 1.75 [1.70, 1.80] |
| `concrete_eval` | 1.20 [1.19, 1.21] | 1.40 [1.35, 1.45] |

Per tool: about 25 us for the whole screen (20 us to build the request and entity store, 9 us to evaluate), against 6 us for a concrete evaluation. Partial evaluation costs about 1.3 to 1.5 times concrete evaluation of the same policies. `prepare` and `partial_eval` add up to more than `screen`; the halves are timed with their outputs kept alive (200 entity stores), which `screen` does not do, so read the split as a proportion. The approval obligation costs nothing measurable at 1 hop; at 3 hops the 0.6 ms difference is within this host's run-to-run spread.

Against the ADR's estimate: a chain's first list is 5 to 6 ms, not 25 ms, because the screen builds the user, agent and server entities once per list and adds two entities per tool (`Entities::add_entities`) instead of parsing a whole entity store from JSON per tool (the request cache's 110 to 150 us). A warm list is memo lookups: 80 to 91 us per 200 tools (below), about 0.4 us per tool, most of it the chain digest (RFC 8785 and SHA-256 of the chain, once per list) and the catalog lookups.

Raw criterion output:

```
list_screen_partial/screen/1_hop                time:   [4.8412 ms 4.9361 ms 5.0471 ms]
list_screen_partial/screen_approval/1_hop       time:   [4.8661 ms 4.9464 ms 5.0395 ms]
list_screen_partial/prepare/1_hop               time:   [3.8353 ms 3.9362 ms 4.0467 ms]
list_screen_partial/partial_eval/1_hop          time:   [1.7196 ms 1.7735 ms 1.8283 ms]
list_screen_partial/concrete_eval/1_hop         time:   [1.1939 ms 1.2017 ms 1.2104 ms]
list_screen_partial/screen/3_hop                time:   [5.4613 ms 5.5220 ms 5.5975 ms]
list_screen_partial/screen_approval/3_hop       time:   [5.9041 ms 6.1225 ms 6.3515 ms]
list_screen_partial/prepare/3_hop               time:   [4.3812 ms 4.4554 ms 4.5423 ms]
list_screen_partial/partial_eval/3_hop          time:   [1.7038 ms 1.7471 ms 1.7959 ms]
list_screen_partial/concrete_eval/3_hop         time:   [1.3525 ms 1.4008 ms 1.4543 ms]
```

## With the memo (second run, same day)

The branch's second commit adds the memo and the `screen_memo` row; the whole group was run again (load average 2.5 before, 1.3 after):

```
list_screen_partial/screen/1_hop          [4.8226 ms 4.9283 ms 5.0616 ms]
list_screen_partial/screen_memo/1_hop     [77.262 us 79.548 us 82.191 us]
list_screen_partial/screen_approval/1_hop [4.9611 ms 5.0418 ms 5.1296 ms]
list_screen_partial/prepare/1_hop         [3.7672 ms 3.8555 ms 3.9528 ms]
list_screen_partial/partial_eval/1_hop    [1.5532 ms 1.5731 ms 1.5970 ms]
list_screen_partial/concrete_eval/1_hop   [1.2459 ms 1.2659 ms 1.2879 ms]
list_screen_partial/screen/3_hop          [5.7748 ms 5.8949 ms 6.0297 ms]
list_screen_partial/screen_memo/3_hop     [86.958 us 90.912 us 95.729 us]
list_screen_partial/screen_approval/3_hop [5.6320 ms 5.7218 ms 5.8261 ms]
list_screen_partial/prepare/3_hop         [4.3978 ms 4.4801 ms 4.5730 ms]
list_screen_partial/partial_eval/3_hop    [1.7615 ms 1.8037 ms 1.8492 ms]
list_screen_partial/concrete_eval/3_hop   [1.2052 ms 1.2191 ms 1.2370 ms]
```

## End to end, through the server

An `#[ignore]` test, `list_cost_by_mode` in `crates/attenuo-server/tests/list_screen.rs`, starts the whole server (in-memory audit) in front of the fake MCP server listing 200 tools, mints a 1-hop token for a user without MFA, and times `tools/list` over HTTP on one connection: the first list, then 9 rounds of 50 lists (median of the rounds, min and max in brackets). The catalog has 199 of the 200 tools, 195 of them read-only, so under `"policy"` the screen keeps 197 and hides `update_issue`, `delete_repo` and the uncatalogued one; the bodies differ by those three entries. The modes alternate, two servers each, two runs (load average 2.8 to 3.3):

```
cargo test --release -p attenuo-server --test list_screen list_cost -- --ignored --nocapture
```

| mode | first list (us) | repeated list, median (us) |
|---|---|---|
| `capabilities` | 2587, 2705, 2788, 2709 | 1986 [1710, 2425], 1806 [1701, 1896], 1797 [1528, 2059], 1886 [1642, 2407] |
| `policy` | 8184, 7560, 8357, 10661 | 2421 [1974, 3068], 2468 [2160, 2618], 2226 [2029, 2793], 2700 [2225, 3433] |

So on this host the screen adds about 5 to 8 ms to a chain's first list and 0.4 to 0.8 ms to a repeated one, against 1.8 to 2.0 ms for the list itself. The repeated figure is more than the 0.08 to 0.09 ms of `screen_memo`: the rest is the hop to the blocking pool and back, copying the chain and the 200 names there, and collecting and removing the names in the response. The default mode's path differs from the base commit by one boolean test per list answer and an absent stream stage; it was not timed against the base end to end.

## The decision path with the feature on

`policy_stage` on the base commit and on this branch, alternating in one worktree (`git stash` of the branch's changes for the base), `--measurement-time 5`, rows `authorize` (cache hit) and `evaluate`, two rounds (point estimates, us):

| row | base, round 1 | branch, round 1 | base, round 2 | branch, round 2 |
|---|---|---|---|---|
| `authorize/1_hop` | 18.50 | 19.18 | 17.88 | 18.21 |
| `evaluate/1_hop` | 5.35 | 5.36 | 5.06 | 5.40 |
| `authorize/3_hop` | 18.83 | 18.79 | 18.64 | 18.48 |
| `evaluate/3_hop` | 5.88 | 5.15 | 5.12 | 5.14 |

The differences go both ways and are within 0.7 us, the spread between rounds of the same build on this host. The uncached rows of one earlier pass (`authorize_uncached` 135 against 128 us at 1 hop, 175 against 170 us at 3) also show no direction. No change to the decision path is attributed to the feature or to the shared `fixed_records` helper the branch factors out of `RequestParts::build`.

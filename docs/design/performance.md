# Performance: micro-benchmarks and end to end

- Status: first measurement (v0)
- Crates: `onbehalf-policy` (`benches/authorize.rs`), `onbehalf-core` (`benches/attenuation.rs`), `onbehalf-bench` (end to end)
- Related: [server pipeline](server.md), [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md)

The first part of this page is criterion 0.5 micro-benchmarks of the two pure functions on the hot path. They do not include token verification, the lease lookup, the audit append or the network hop to the upstream, so they are a lower bound on the latency onbehalf adds to a call. The end-to-end figures, measured through the real proxy, are in [End to end: proxy versus direct](#end-to-end-proxy-versus-direct) at the end of the page.

## How to run

```
cargo bench --bench authorize --bench attenuation -- --warm-up-time 1 --measurement-time 3
```

Name the bench targets: a bare `cargo bench -- --warm-up-time ...` also passes the flags to each crate's unit-test harness, which rejects them.

## Measurement environment (dev container, not a reference machine)

Taken in a shared Linux development container while other builds were running on the same host, so treat the numbers as indicative: relative sizes mean more than absolute values, and run-to-run noise of 10 percent or more is expected. Rust release profile (`lto = "thin"`, `codegen-units = 1`), 2026-10-22.

```
$ nproc
4
$ lscpu | head -15
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           52 bits physical, 57 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  4
On-line CPU(s) list:                     0-3
Vendor ID:                               GenuineIntel
Model name:                              Intel(R) Xeon(R) Processor @ 2.10GHz
CPU family:                              6
Model:                                   207
Thread(s) per core:                      1
Core(s) per socket:                      4
Socket(s):                               1
Stepping:                                2
BogoMIPS:                                4200.00
```

Warm-up 1 s, measurement 3 s, criterion's default 100 samples. Each cell is criterion's `[low estimate high]`; the middle value is the point estimate.

## `PolicyEngine::authorize` with the default policies

The shipped `policies/default.cedar` and a catalog with `read_file` (read-only), `create_issue` (argument rule) and `delete_repo` (sensitive). Chain capabilities are wide (`github:*`) so the capability stage passes; the time is chain-to-Cedar translation plus evaluation. Note that `forbid_deep_chains` denies depth greater than 3, so every 4-hop row is a deny; the rows compare the cost of a deeper principal hierarchy, not outcomes.

| Call | 1 hop | 4 hops |
|---|---|---|
| `read_file` (allow at 1 hop) | 123.8 us [118.6, 129.3] | 172.6 us [169.6, 176.0] |
| `create_issue` in `acme/*` (allow at 1 hop) | 112.4 us [110.6, 114.4] | 182.1 us [175.0, 189.7] |
| `delete_repo` (deny: no permit matches) | 114.9 us [110.7, 119.9] | 182.2 us [175.4, 190.1] |

Reading: roughly 110 to 125 us per decision for a single hop and 170 to 190 us for four hops, so about 20 us for each extra hop. Allow and deny cost the same, as expected, since Cedar evaluates the whole policy set either way. At these figures one core sustains on the order of 5,000 to 9,000 decisions per second before the audit append and lease lookup. Whether the per-call cost is dominated by building the Cedar request or by evaluation has not been profiled; request construction is the first suspect, and caching the entity hierarchy per chain digest is the obvious next experiment.

## `CapabilitySet::covers`

Parent: `n` capabilities `srv{i}:tool_*` with a `repo` prefix constraint. Child: `n` narrower ones (`srv{i}:tool_read`, longer prefix), each covered by exactly one parent capability. "covered" is the successful check made at every delegation hop; "rejected" swaps the sets, so the first child capability that the parent cannot cover ends the check.

| Capabilities (n) | covered | rejected (widening) |
|---|---|---|
| 1 | 34.3 ns [33.2, 35.7] | 15.2 ns [14.9, 15.5] |
| 8 | 449 ns [444, 456] | 68.0 ns [67.1, 69.0] |
| 32 | 4.91 us [4.85, 5.00] | 252.8 ns [248.7, 257.7] |

Reading: a successful check is quadratic in the number of capabilities (each child capability scans the parent set), going from 34 ns to 4.9 us between 1 and 32. That is `O(n * m)` by design (see `CapabilitySet::covers`): the conservative single-parent coverage rule keeps it simple and explainable. It is negligible next to a policy decision (4.9 us against about 120 us) at realistic set sizes, and it runs once per exchange, not once per call.

## End to end: proxy versus direct

Harness: `crates/onbehalf-bench` (binary `onbehalf-bench`), driven by `scripts/bench-e2e.sh`. Raw results are committed in [`bench/`](bench/) as `<date>-<host>.json` (every number below, plus the metadata) and `.md` (the tables with the hardware).

### Method

- **What runs.** The release `onbehalf-server` and the `fake_mcp` example (an echo upstream; its stderr goes to `/dev/null`), both started by the harness on free loopback ports, from copies of the binaries. A server is started per audit mode. The load generator runs on the same machine.
- **Tokens.** A root token from the development mint (`POST /admin/root-token`, capability `fake:read_file` only), then `POST /token` exchanges with agent client secrets down to the requested depth. "Hops" counts hops in the token's chain, so 1 is the root token itself and 3 is the root plus two exchanges. Lease lifetime is raised to 24 h so a long run does not outlive its leases.
- **Calls.** `tools/call` over HTTP/1.1 keep-alive, bodies fixed. `allow`: `read_file` on `alice/public-docs`, permitted by the Cedar policy (the leak demo's, three policies). `deny_policy`: `read_file` on `alice/private-salaries`, which the capability stage passes and Cedar denies. `deny_capability`: `delete_repo`, which the token does not carry, denied at the capability stage. Denied calls never reach the upstream.
- **Baseline.** The `allow` call posted straight to `fake_mcp`, at the same concurrency, in the same server group. "Added" is proxy minus direct for the same percentile (p50, p99) or the mean. For denied calls the upstream hop is skipped, so "added" there is the cost of getting the answer, not a hop on top of the upstream call.
- **Load.** N closed-loop clients (1, 8, 32), one request in flight each. 2 s warm-up discarded, then 5 s measured per cell. Latency per request goes into an HdrHistogram (3 significant digits) and is reported as p50, p90, p99, max and mean; throughput is completed measured requests over the 5 s.
- **Checks.** Every answer is classified (result versus JSON-RPC error) and a mismatch fails the run. At the end of each group the harness calls `GET /admin/audit/verify` and fails unless the chain verifies and holds at least one entry per proxied call.
- **Audit modes.** `memory` is `sqlite_path = ":memory:"`; `file` is a SQLite file in the temp directory (a container filesystem here).
- **Limits.** Closed-loop load suffers coordinated omission: a slow response delays the next request, so tail percentiles under overload are understated compared with open-loop load at a fixed arrival rate, which the [evaluation plan](../research/evaluation-plan.md) calls for. One run per cell, no confidence intervals.

### Environment (shared dev container, not a reference machine)

4 vCPU Intel Xeon @ 2.10 GHz, Linux 6.18, rustc 1.97.0, release profile (`lto = "thin"`). Other agents were compiling on the same host during the run (load average 3 to 4 before it started) and the load generator, proxy and upstream share the 4 cores, so the numbers carry a lot of noise and the high-concurrency rows are CPU-saturated: read them as "how it degrades", not as capacity. The full hardware block is in the committed `.md`. Run of 2026-10-23, commit 8ea3d07, file `bench/2026-10-23-vm.json`.

### Headline numbers

Allow call, audit in memory, p50 / p99 in microseconds and requests per second:

| | direct | 1 hop | 3 hops |
|---|---|---|---|
| 1 client | 82 / 184; 11,118 | 756 / 1,343; 1,261 | 1,100 / 4,522; 757 |
| 8 clients | 213 / 858; 31,714 | 1,754 / 4,280; 4,227 | 3,306 / 11,280; 2,099 |
| 32 clients | 567 / 1,994; 48,408 | 6,148 / 18,268; 4,862 | 12,976 / 41,353; 2,238 |

- **Added latency, single client, audit in memory:** about 0.7 ms at p50 and 1.2 ms at p99 for one hop; about 1.0 ms at p50 (4.3 ms at p99, noisy) for three hops. A denial by capability is cheaper (about 0.3 to 0.4 ms) because it stops before Cedar and the upstream.
- **Throughput ceiling:** about 4,200 to 4,900 calls per second at one hop and 2,100 to 2,200 at three hops on these 4 shared cores, against roughly 48,000 for the direct baseline. Throughput stops growing between 8 and 32 clients, so extra clients only add queueing.
- **Hops cost more than the micro-benchmark predicts.** Cedar adds about 20 us per hop (above), yet the end-to-end cost per call roughly doubles from 1 to 3 hops. Where it goes (verifying each hop, lease lookups per hop, request construction) is unprofiled.
- **Most of the added latency is outside Cedar.** The decision is about 120 us; the proxied call costs about 700 us more than a direct one. Token verification, the lease check, the audit append behind a mutex, the blocking-pool hop and the second HTTP round trip account for the rest; there is no breakdown yet.
- **A file-backed audit log is the dominant cost.** With a SQLite file, throughput was about 270 to 590 calls per second regardless of concurrency or outcome (denials are audited too), single-client p50 was 1.6 to 2.5 ms, and p50 rose linearly with clients (about 16 ms at 8, 65 ms at 32): the signature of one serialised append per call. The audit store sets no `synchronous` or `journal_mode` pragma, so it runs SQLite's defaults, which sync to disk on each commit; the figure is specific to this container's filesystem and will differ on other storage. A few file-mode cells have large outliers (for example `deny_policy` at 1 hop with 1 and 8 clients, 70 and 61 req/s) that probably coincide with other builds on the host; rerun before quoting a single cell.
- **Audit integrity under load:** the chain verified after both groups, with 351,679 entries (memory) and 50,495 (file), each at least the number of proxied calls sent.

The complete matrix (every hop count, outcome, concurrency and audit mode, with p90, max and mean) is in `bench/2026-10-23-vm.md`.

### How to run

```
scripts/bench-e2e.sh                       # full matrix, about 6 minutes, writes docs/design/bench/
DURATION=10 scripts/bench-e2e.sh --concurrency 8 --depths 3 --audit memory
cargo run --release -p onbehalf-bench -- --help
```

`onbehalf-bench --print-config DIR` writes the server config and policy it expects, for pointing the harness at an already running server (`--onbehalf-url`, `--upstream-url`). A one-second smoke run is part of `cargo test --workspace` (`crates/onbehalf-bench/tests/smoke.rs`). There is no CI job for the full matrix: it needs a release build and minutes of load, and numbers from shared runners could not be compared.

## Not measured

- `POST /token` exchange throughput and `POST /token/renew` load (the harness only uses exchanges for setup).
- Policy size (the set here has three policies) and catalog size.
- A time breakdown of the proxied call by stage.
- Open-loop load at fixed arrival rates, confidence intervals over repeated runs, and a quiet reference machine.
- Streaming (SSE) responses and `tools/list` filtering.

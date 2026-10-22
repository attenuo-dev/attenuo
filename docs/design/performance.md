# Performance: micro-benchmarks

- Status: first measurement (v0)
- Crates: `onbehalf-policy` (`benches/authorize.rs`), `onbehalf-core` (`benches/attenuation.rs`)
- Related: [server pipeline](server.md), [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md)

These are criterion 0.5 micro-benchmarks of the two pure functions on the hot path. They do not include token verification, the lease lookup, the audit append or the network hop to the upstream, so they are a lower bound on the latency onbehalf adds to a call, not an end-to-end figure. An end-to-end proxy benchmark is still open (see the board).

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

## Not measured

- Token verification (Ed25519 plus JWT parse), lease lookups and the audit append (SQLite, one write per decision).
- The proxy hop and upstream latency.
- `POST /token` throughput and `POST /token/renew` load.
- Behaviour under concurrent callers (the SQLite stores serialize on a mutex).

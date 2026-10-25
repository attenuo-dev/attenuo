# Per-value limits on the hot path: `calls_per`, `distinct`, both, a host `calls_per` and list arguments (2026-10-25)

Branch `perf/per-value-limits-latency`, main `3568ba6`. Release build with `lto = false` and `codegen-units = 16` (as the limit-kinds, usage-write and run-lock runs), rustc 1.99.1. Shared 4-vCPU container with other agents working on it; load average sampled every 15 s: 1.2 to 3.3 during pass 1 (02:06 to 02:16 UTC), 1.5 to 6.8 during pass 2 (02:16 to 02:25, rising at the end as another worker started a build), 1.2 to 5.1 during the list runs (02:25 to 02:38), 1.6 to 3.9 during the criterion runs. File store at `durability = "normal"`, one client, 2-hop token, 2 s warm-up and 10 s measured per cell, 5 interleaved runs per pass, the second pass in reverse order, only the `destructive` call (`create_issue`). See [performance](../performance.md#per-value-limits-on-current-main-2026-10-25).

Why again: the board's run-limits item still listed "`calls_per` and `distinct` latency" as open. The [2026-10-24 limit-kinds run](2026-10-24-vm-limit-kinds.md) measured `calls_per`, `distinct` and a host `distinct` on main `360ba25`. Since then pass 5 added the per-run lock (SR-55), a zero-amount charge-log row for every seen `distinct` value (SR-62) and an index on the charge log (SR-62), so this run measures current main, adds the cells that run did not have (both kinds on one capability, `calls_per` on a URL host, list arguments), and splits the large cells one level down.

## Configurations

Every limit has a `max` no run reaches and sits on `create_issue` in both hops, so none is refused. `create_issue`'s body carries `to` and `url` (declared `string`) in every configuration; `@SEQ@` marks a number the harness makes new on every call. The first seven rows are the 2026-10-24 configurations; the last four are new in `attenuo-bench hot-path`.

| config | limit (both hops) | `to` | `url` | store writes per call (2 hops) |
|---|---|---|---|---|
| `baseline` | none | `r0@example.com` | `https://h0.example/a` | none |
| `limits_calls` | `calls` | as baseline | as baseline | 2 counter updates, 2 charge rows |
| `calls_per_new` | `calls_per` on `to` | `r@SEQ@@example.com` | as baseline | 2 new counter rows, 2 charge rows |
| `calls_per_same` | `calls_per` on `to` | as baseline | as baseline | 2 counter updates, 2 charge rows |
| `distinct_new` | `distinct` on `to` | `r@SEQ@@example.com` | as baseline | 2 new value rows, 2 count updates, 4 charge rows |
| `distinct_same` | `distinct` on `to` | as baseline | as baseline | 2 value-row upserts with the same figure, 2 zero-amount charge rows (SR-62) |
| `calls_per_distinct_new` | `calls_per` and `distinct` on `to` | `r@SEQ@@example.com` | as baseline | the two `_new` rows above together |
| `calls_per_distinct_same` | `calls_per` and `distinct` on `to` | as baseline | as baseline | the two `_same` rows above together |
| `calls_per_host` | `calls_per` on `url`, `derive: host` | as baseline | `https://h0.example/a@SEQ@` (new URL, same host) | 2 counter updates, 2 charge rows, a URL parse per hop |
| `distinct_list` with `--list-values N` | `distinct` on `tos` | as baseline | as baseline | per hop N new value rows, a count update and N + 1 charge rows |

`--list-values N` adds `tos`, a list of N values (`r@SEQ@-0@example.com` and so on, all new on every call, declared as a set of strings), to `create_issue` in every configuration of that invocation, so `baseline` with the same N is `distinct_list`'s control: the same body and the same Cedar input, no limit. N = 256 is `MAX_COUNTED_VALUES`, the most a call may count.

The configuration checks below confirm the charges: 2 counters per call in the single-kind cells, 4 in `calls_per_distinct_*`, 2, 32 and 512 in `distinct_list` at 1, 16 and 256 values; the first charge's `used_after` grows with every call where the value is new and stays at 1 where it is seen.

## Summary

Client figures are medians over the 5 runs; decision, charge and stage figures are means pooled over the runs' measured windows. "charge" is "decide (unstaged)", the decision time outside lease check, policy and audit append: the charge transaction plus about 20 us of record building that `baseline` also has. "run lock wait" is the new `attenuo_run_lock_wait_seconds` mean (SR-55), which sits inside the `policy` stage. Pass 1 / pass 2.

| config | p50 us | p90 us | p99 us | req/s | decide mean | charge mean | run lock wait mean | requests | over 3/5/10 ms |
|---|---|---|---|---|---|---|---|---|---|
| `baseline` | 1,196 / 1,263 | 1,673 / 1,774 | 3,027 / 3,619 | 754 / 724 | 286 / 314 | 20 / 21 | 0.0 / 0.0 | 37,521 / 35,309 | 416 / 145 / 26; 892 / 351 / 40 |
| `limits_calls` | 1,464 / 1,474 | 1,960 / 2,068 | 3,594 / 4,244 | 625 / 592 | 432 / 462 | 109 / 111 | 0.2 / 0.2 | 31,591 / 29,579 | 625 / 222 / 32; 871 / 347 / 44 |
| `calls_per_new` | 1,530 / 1,522 | 2,002 / 2,006 | 3,439 / 6,451 | 613 / 560 | 507 / 542 | 144 / 150 | 0.2 / 0.2 | 29,341 / 28,118 | 636 / 232 / 59; 1072 / 525 / 91 |
| `calls_per_same` | 1,516 / 1,467 | 2,038 / 2,056 | 4,628 / 4,948 | 585 / 588 | 505 / 485 | 131 / 122 | 0.2 / 0.2 | 28,717 / 29,440 | 1052 / 235 / 31; 1078 / 446 / 42 |
| `distinct_new` | 1,652 / 1,675 | 2,198 / 2,216 | 4,346 / 6,083 | 535 / 533 | 644 / 642 | 215 / 212 | 0.2 / 0.2 | 25,800 / 25,857 | 1522 / 306 / 65; 1277 / 562 / 95 |
| `distinct_same` | 1,551 / 1,440 | 2,269 / 1,977 | 4,358 / 3,711 | 571 / 579 | 484 / 471 | 129 / 125 | 0.2 / 0.2 | 28,926 / 29,655 | 923 / 190 / 25; 1040 / 444 / 61 |
| `calls_per_distinct_new` | 1,808 / 1,828 | 2,474 / 2,529 | 6,525 / 7,856 | 462 / 454 | 836 / 817 | 299 / 302 | 0.2 / 0.2 | 23,304 / 23,014 | 1055 / 464 / 123; 1454 / 521 / 128 |
| `calls_per_distinct_same` | 1,691 / 1,640 | 2,156 / 2,140 | 5,427 / 4,035 | 553 / 560 | 559 / 553 | 182 / 182 | 0.2 / 0.2 | 27,511 / 27,317 | 728 / 299 / 66; 778 / 352 / 68 |
| `calls_per_host` | 1,535 / 1,558 | 1,992 / 2,083 | 3,776 / 4,465 | 612 / 584 | 460 / 500 | 122 / 131 | 0.2 / 0.2 | 29,773 / 28,758 | 571 / 204 / 39; 615 / 245 / 38 |

| config | `policy` mean | `audit_append` mean (p50) | handler `total` mean |
|---|---|---|---|
| `baseline` | 122 / 125 | 116 (96) / 138 (102) | 1,115 / 1,193 |
| `limits_calls` | 139 / 144 | 155 (150) / 176 (152) | 1,354 / 1,456 |
| `calls_per_new` | 158 / 159 | 174 (152) / 200 (154) | 1,467 / 1,554 |
| `calls_per_same` | 157 / 148 | 185 (156) / 183 (153) | 1,498 / 1,474 |
| `distinct_new` | 190 / 187 | 208 (157) / 210 (155) | 1,686 / 1,702 |
| `distinct_same` | 155 / 151 | 169 (154) / 163 (152) | 1,479 / 1,467 |
| `calls_per_distinct_new` | 207 / 208 | 297 (161) / 274 (160) | 1,906 / 1,923 |
| `calls_per_distinct_same` | 162 / 160 | 182 (156) / 179 (156) | 1,571 / 1,587 |
| `calls_per_host` | 154 / 156 | 153 (151) / 181 (155) | 1,432 / 1,489 |

Deltas over `baseline`:

| config | client p50 | client p99 | req/s | charge mean | `policy` mean | `audit_append` mean | handler total |
|---|---|---|---|---|---|---|---|
| `limits_calls` | +268 / +211 us | +567 / +625 us | -17 % / -18 % | +89 / +91 us | +17 / +19 us | +39 / +38 us | +239 / +263 us |
| `calls_per_new` | +334 / +259 us | +412 / +2,832 us | -19 % / -23 % | +124 / +129 us | +36 / +34 us | +58 / +62 us | +352 / +361 us |
| `calls_per_same` | +320 / +205 us | +1,602 / +1,329 us | -22 % / -19 % | +111 / +102 us | +34 / +23 us | +69 / +45 us | +383 / +281 us |
| `distinct_new` | +456 / +413 us | +1,319 / +2,464 us | -29 % / -26 % | +195 / +191 us | +67 / +62 us | +92 / +72 us | +571 / +510 us |
| `distinct_same` | +355 / +177 us | +1,331 / +92 us | -24 % / -20 % | +109 / +104 us | +33 / +26 us | +53 / +25 us | +364 / +274 us |
| `calls_per_distinct_new` | +612 / +565 us | +3,498 / +4,237 us | -39 % / -37 % | +279 / +281 us | +85 / +82 us | +181 / +136 us | +791 / +730 us |
| `calls_per_distinct_same` | +495 / +378 us | +2,400 / +416 us | -27 % / -23 % | +162 / +161 us | +40 / +35 us | +66 / +41 us | +456 / +394 us |
| `calls_per_host` | +339 / +295 us | +750 / +846 us | -19 % / -19 % | +102 / +110 us | +32 / +31 us | +37 / +43 us | +317 / +297 us |


Readings:

- **Noise.** `baseline`'s p50 moved by 67 us between the two passes, and by up to 190 us across the six list invocations (1,264 to 1,455 us with a 1- or 16-value list). The load rose to 6.8 at the end of pass 2, and pass 2's deltas are 50 to 180 us lower than pass 1's in five cells. Differences under about 150 us at the client are not resolved here; the charge mean, which does not depend on the host's wake-up latency, agreed within 10 us between the passes in every cell.
- **A `calls` limit now costs about +210 to +270 us at the client p50**, not the +120 to +190 us of #53 (or +99 to +139 us on 2026-10-24). The charge transaction is +89 / +91 us (2026-10-24: about +70), and in process `charge_file/calls` takes 54 to 55 us against 38.5 to 41.5 us then. The likely cause is SR-62's second index on the charge log, one more index entry per charge row; not separated. The rest of the delta is spread over stages outside the decision (`blocking_pool` +20, `upstream` +22, `response` +48 to +59 us), as #53 already saw. `limits_calls`' absolute p50 is the same as on 2026-10-24 (1,464 / 1,474 against 1,464 / 1,475 us); `baseline` is 100 to 170 us faster (its `lease_check` fell from 46 to 49 us to 28 to 30 us), which makes up part of the larger delta.
- **`calls_per` costs what `calls` costs**: +205 to +320 us at p50 with a repeated value and +259 to +334 us with a new one, charge +102 to +129 us against +89 to +91.
- **`distinct` with a new value costs about twice a `calls` limit**: +413 / +456 us at p50, charge +191 / +195 us, 26 to 29 percent of single-client throughput.
- **`distinct` with a seen value is no longer free.** It now costs what a repeated `calls_per` value costs: +177 / +355 us at p50, charge +104 / +109 us, and the decision append grows by 25 to 53 us like every cell that writes. Since SR-62 a seen value logs a zero-amount charge row and upserts its value row with the same figure, so the transaction writes WAL frames again. The 2026-10-24 reading (within noise, an empty transaction of about 25 us) is superseded; in process `charge_file/distinct_same` is 64 to 70 us against 19 us then.
- **Both kinds on one capability cost less than the two separately**, since they share one transaction: with a new value +565 / +612 us at p50 and +279 / +281 us of charge, against +315 to +324 us for `calls_per` and `distinct` charged apart; with a repeated value +378 / +495 us and +161 / +162 us, against +206 to +220 us.
- **`calls_per` on a URL host costs what a repeated `calls_per` value costs**: +295 / +339 us at p50, charge +102 / +110 us. The URL parse is not visible (`charges_for/host` is 1.35 to 1.39 us in process for 2 hops, against 0.58 to 0.60 us without the parse).
- **The run lock** (SR-55) waits 0.2 us on average from one client in every limited cell.
- **p99 deltas** run from +92 us to +4.2 ms and do not agree between the passes, except that the new-value cells and the two-kind cells have the most calls over 10 ms (59 to 128 per pass, against 26 and 40 in `baseline`). `baseline`'s own p99 was 3.0 and 3.6 ms in the two passes.
- **Nothing in these cells is above 1 ms at the median**; the list cells at 16 and 256 values are (next section).


## `distinct` on a list argument: 1, 16 and 256 values

Each N is its own pair of invocations (`--configs baseline,distinct_list`, then reversed), so `baseline` here carries the same N-value list. Pass a / pass b; the deltas are over that invocation's `baseline`.

| N | `baseline` p50 / p99 us | `distinct_list` p50 / p99 us | p50 delta | p99 delta | req/s, `baseline` / `distinct_list` | charge mean | `policy` mean, `baseline` / `distinct_list` | `audit_append` mean (p50), `distinct_list` | calls over 10 ms |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1,391 / 3,580; 1,264 / 3,684 | 1,838 / 5,022; 1,768 / 5,026 | +448 / +505 us | +1,442 / +1,341 us | 646 / 491; 672 / 505 | 212 / 215 us | 136 / 188; 131 / 189 us | 197 (156) / 222 (156) us | 86 of 25,274; 116 of 25,224 |
| 16 | 1,436 / 4,094; 1,455 / 2,843 | 3,850 / 18,252; 3,772 / 20,202 | +2,415 / +2,317 us | +14,158 / +17,359 us | 658 / 175; 657 / 187 | 1,681 / 1,638 us | 148 / 567; 144 / 534 us | 1,536 (243) / 1,472 (231) us | 181 of 8,989; 157 of 9,571 |
| 256 | 2,634 / 4,514; 2,503 / 4,338 | 38,306 / 662,700; 36,536 / 689,439 | +35,672 / +34,034 us | +658 / +685 ms | 363 / 14; 384 / 14 | 28.6 / 28.4 ms | 349 / 5,178; 343 / 4,883 us | 33,678 (892) / 32,684 (885) us | 716 of 716; 724 of 724 |

The list alone, without a limit, costs something too: `baseline` with 256 values is 2.5 to 2.6 ms at p50 against 1.3 to 1.4 ms with one value (Cedar's input carries a 256-element set, `policy` 343 to 349 us against 131 to 136; the upstream and the response carry about 7 KB more). That is not a limit cost and is left out of the deltas.

In the 256 cell every call took longer than 10 ms. The per-run means grew from run to run as the tables filled (`decide` 55 to 75 ms over runs 1 to 5 of pass a, the run p99 from 559 to 752 ms; the value table held about 240,000 rows per hop at the end).

### One level down: where a list call's time goes

In process (`cargo bench -p attenuo-server --bench decide`, new cells `charges_for/distinct_list_N`, `budget_read_{store}/distinct_list_N` and `charge_{store}/distinct_list_N_new`; criterion point estimates, two runs; raw output in [`2026-10-25-vm-criterion-per-value.txt`](2026-10-25-vm-criterion-per-value.txt)):

| cell | N = 1 | N = 16 | N = 256 |
|---|---|---|---|
| `charges_for` (argument read, one RFC 8785 encoding per value, 2 hops) | 0.61 us | 8.0 to 8.1 us | 169 to 172 us |
| `budget_read_file` (the policy stage's counter read, 2N keys) | 5.6 us | 55 to 56 us | 786 to 855 us |
| `charge_file`, every value new | 118 to 159 us | 1.42 to 1.55 ms | 25.3 to 25.8 ms |
| `charge_memory`, every value new | 643 to 652 us | 2.35 to 2.51 ms | 20.5 to 22.4 ms |
| the run lock, uncontended (end to end, `attenuo_run_lock_wait_seconds` mean) | 0.2 us | 0.2 us | 0.3 us |

For comparison on the same runs: `charge_file/calls` 53.7 to 55.2 us, `calls_per_new` 105.6 to 107.7 us, `calls_per_same` 62.6 to 93.8 us, `distinct_new` 143 to 215 us, `distinct_same` 63.6 to 70.5 us (2026-10-24: 38.5 to 41.5, 73.1 to 73.7, 46.6 to 50.2, 106 to 107 and 18.6 to 19.0 us).

WAL bytes per decision, from `strace -e pwrite64` on the server's `-wal` file descriptors for 4 s of a 10 s run (`baseline` and `distinct_list`, calls counted from `attenuo_authorize_duration_seconds_count` before and after; strace slows the server, so the call rates are lower than above, but bytes per call are not affected):

| config | WAL written per decision | WAL page writes per decision |
|---|---|---|
| `baseline`, 1 value | 80 KiB | 40 |
| `baseline`, 256 values | 83 KiB | 41 |
| `distinct_list`, 1 value | 135 KiB | 67 |
| `distinct_list`, 16 values | 522 KiB | 265 |
| `distinct_list`, 256 values | 5,352 KiB | 3,854 |

(The figures include the decision append and the result append of each call, which is why `baseline` writes 80 KiB.)

So, for a 256-value call against a `baseline` with the same body (about +34 to +36 ms at p50):

- **The charge transaction is about 80 percent of it**: 28.4 to 28.6 ms end to end, 25.3 to 25.8 ms in process, which is about 50 to 56 us per new value per hop, linear from N = 1 to N = 256 (2 values: 0.12 to 0.16 ms; 32: 1.4 to 1.7 ms; 512: 25 to 29 ms). Each new value is an insert into the counter table and one into the charge log with its two indexes, all keyed by a keyed hash, so each lands on its own pages: about 7.5 WAL page writes per value, 5.2 MiB of WAL per call. The write gate is held for all of it, so for those 25 to 29 ms no other decision can charge or append.
- **The counter read is about 13 percent**: the `policy` stage grows by 4.5 to 4.8 ms. In process the read of 512 keys takes 0.79 to 0.85 ms on a fresh table; end to end the tables held 30,000 to 240,000 rows per hop and the lookups miss SQLite's page cache, which is the likely reason for the rest (not separated).
- **JCS of the values is under 1 percent**: `charges_for` is 0.17 ms for 512 values, about 0.33 us per value.
- **The per-run lock costs nothing measurable from one client**: 0.2 to 0.3 us of wait.
- **The tail is most likely the WAL checkpointer** (not traced call by call). The decision append's p50 grows only from 0.12 to 0.89 ms (a record with 512 `charged` entries), but its mean is 33 ms, because 42 to 43 of about 720 appends per pass took over 10 ms, up to 0.4 s. At 5.2 MiB of WAL per call the WAL passes the checkpointer's 64 MB locked-pass threshold about every 12 calls and its 128 MB writer backstop soon after; the backstop was measured at 123 to 416 ms in [the backstop section](../performance.md#backstop-pause-measured-2026-10-23). That would explain the 0.66 to 0.69 s p99.

At 16 values the same split holds at a smaller scale: charge 1.6 to 1.7 ms, `policy` +390 to +420 us, decision append p50 +130 us and a mean of 1.5 ms from 73 to 76 appends over 10 ms.

No optimisation was made on this branch: nothing here is a one-line change. The cost is per value in the store; making it cheaper means fewer rows per value (the zero-amount log rows of SR-62 and the counter-log index exist for exact refunds), batching the inserts, or a lower `MAX_COUNTED_VALUES`.

## Rerun

```text
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
cargo build --release -p attenuo-bench -p attenuo-server
cargo build --release -p attenuo-proxy --features testing --example fake_mcp
target/release/attenuo-bench hot-path --runs 5 --cells destructive \
  --configs baseline,limits_calls,calls_per_new,calls_per_same,distinct_new,distinct_same,calls_per_distinct_new,calls_per_distinct_same,calls_per_host \
  --json pass1.json --markdown pass1.md
target/release/attenuo-bench hot-path --runs 5 --cells destructive \
  --configs calls_per_host,calls_per_distinct_same,calls_per_distinct_new,distinct_same,distinct_new,calls_per_same,calls_per_new,limits_calls,baseline \
  --json pass2.json --markdown pass2.md
for n in 1 16 256; do
  target/release/attenuo-bench hot-path --runs 5 --cells destructive --list-values $n --configs baseline,distinct_list
  target/release/attenuo-bench hot-path --runs 5 --cells destructive --list-values $n --configs distinct_list,baseline
done
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 \
  'charges_for/(distinct|calls_per|host)|budget_read_(file|memory)/(calls|distinct_list)|charge_(file|memory)/(calls|calls_per_new|calls_per_same|distinct_new|distinct_same|distinct_list)'
```

The WAL figures came from a throwaway script (not committed) that starts one `hot-path --runs 1 --duration 10` invocation per row, attaches `strace -f -e trace=pwrite64` to the server for 4 s after the warm-up, and sums the bytes written to the descriptors that `/proc/<pid>/fd` shows as `-wal` files.

The raw JSON of every invocation is in [`2026-10-25-vm-per-value-limits.json`](2026-10-25-vm-per-value-limits.json) (`pass1`, `pass2`, `list1_a`, `list1_b`, `list16_a`, `list16_b`, `list256_a`, `list256_b`).

## Pass 1 (`--configs baseline,limits_calls,calls_per_new,calls_per_same,distinct_new,distinct_same,calls_per_distinct_new,calls_per_distinct_same,calls_per_host`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| baseline | destructive | 0 | 0 | false | null |
| limits_calls | destructive | 2 | 0 | false | 37994 |
| calls_per_new | destructive | 2 | 0 | false | 1 |
| calls_per_same | destructive | 2 | 0 | false | 34963 |
| distinct_new | destructive | 2 | 0 | false | 30936 |
| distinct_same | destructive | 2 | 0 | false | 1 |
| calls_per_distinct_new | destructive | 4 | 0 | false | 1 |
| calls_per_distinct_same | destructive | 4 | 0 | false | 33283 |
| calls_per_host | destructive | 2 | 0 | false | 35639 |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| baseline | destructive | 5 | 1196 | 1140.7 to 1397.8 | 1673.2 | 1872.9 | 3026.9 | 754 |
| limits_calls | destructive | 5 | 1464.3 | 1354.8 to 1595.4 | 1959.9 | 2158.6 | 3594.2 | 625 |
| calls_per_new | destructive | 5 | 1529.9 | 1476.6 to 1682.4 | 2001.9 | 2166.8 | 3438.6 | 613 |
| calls_per_same | destructive | 5 | 1515.5 | 1419.3 to 2312.2 | 2037.8 | 2312.2 | 4628.5 | 585 |
| distinct_new | destructive | 5 | 1651.7 | 1536 to 2691.1 | 2197.5 | 2435.1 | 4345.9 | 535 |
| distinct_same | destructive | 5 | 1551.4 | 1437.7 to 1756.2 | 2269.2 | 2533.4 | 4358.1 | 571 |
| calls_per_distinct_new | destructive | 5 | 1808.4 | 1730.6 to 1880.1 | 2474 | 2760.7 | 6524.9 | 462 |
| calls_per_distinct_same | destructive | 5 | 1690.6 | 1554.4 to 1854.5 | 2156.5 | 2502.7 | 5427.2 | 553 |
| calls_per_host | destructive | 5 | 1535 | 1482.8 to 1662 | 1991.7 | 2162.7 | 3776.5 | 612 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| baseline | destructive | 37521 | 416 / 145 / 26 | 25428 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 3 / 1 / 0, audit_append 71 / 27 / 10, blocking_pool 17 / 1 / 0, upstream 23 / 4 / 1, response 83 / 30 / 3, total 327 / 114 / 23 |
| limits_calls | destructive | 31591 | 625 / 222 / 32 | 252969 | token_verify_hit 0 / 0 / 0, lease_check 1 / 1 / 0, policy 5 / 0 / 0, audit_append 78 / 15 / 3, blocking_pool 38 / 4 / 1, upstream 23 / 6 / 1, response 146 / 49 / 9, total 493 / 184 / 29 |
| calls_per_new | destructive | 29341 | 636 / 232 / 59 | 116129.8 | token_verify_hit 1 / 0 / 0, lease_check 6 / 1 / 0, policy 2 / 0 / 0, audit_append 91 / 39 / 14, blocking_pool 24 / 8 / 0, upstream 22 / 7 / 2, response 100 / 57 / 15, total 448 / 202 / 56 |
| calls_per_same | destructive | 28717 | 1052 / 235 / 31 | 198443 | token_verify_hit 0 / 0 / 0, lease_check 3 / 1 / 0, policy 12 / 2 / 0, audit_append 84 / 26 / 4, blocking_pool 14 / 2 / 0, upstream 26 / 5 / 1, response 99 / 45 / 7, total 599 / 193 / 28 |
| distinct_new | destructive | 25800 | 1522 / 306 / 65 | 141426.7 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 4 / 1 / 0, audit_append 96 / 66 / 23, blocking_pool 20 / 2 / 0, upstream 21 / 7 / 1, response 164 / 57 / 19, total 814 / 256 / 62 |
| distinct_same | destructive | 28926 | 923 / 190 / 25 | 114163.7 | token_verify_hit 1 / 0 / 0, lease_check 3 / 1 / 0, policy 4 / 0 / 0, audit_append 79 / 17 / 5, blocking_pool 10 / 4 / 0, upstream 19 / 3 / 1, response 71 / 33 / 6, total 470 / 141 / 23 |
| calls_per_distinct_new | destructive | 23304 | 1055 / 464 / 123 | 222429.2 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 6 / 2 / 1, audit_append 117 / 102 / 52, blocking_pool 68 / 15 / 2, upstream 53 / 14 / 2, response 227 / 86 / 32, total 845 / 409 / 115 |
| calls_per_distinct_same | destructive | 27511 | 728 / 299 / 66 | 141951 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 5 / 3 / 1, audit_append 82 / 42 / 8, blocking_pool 33 / 7 / 2, upstream 32 / 8 / 2, response 156 / 68 / 20, total 545 / 256 / 59 |
| calls_per_host | destructive | 29773 | 571 / 204 / 39 | 103940.1 | token_verify_hit 0 / 0 / 0, lease_check 5 / 2 / 1, policy 4 / 0 / 0, audit_append 63 / 14 / 3, blocking_pool 23 / 9 / 1, upstream 29 / 5 / 1, response 101 / 54 / 8, total 418 / 164 / 34 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | destructive | token_verify_hit | 37516 | 9.7 | 9 | 18.8 |
| baseline | destructive | lease_check | 37518 | 27.8 | 25.2 | 48.6 |
| baseline | destructive | policy | 37518 | 122.3 | 142.3 | 195.9 |
| baseline | destructive | audit_append | 37518 | 116 | 96.5 | 192 |
| baseline | destructive | blocking_pool | 37519 | 95.1 | 80.6 | 192.1 |
| baseline | destructive | upstream | 37520 | 286.1 | 269.7 | 477.4 |
| baseline | destructive | response | 37520 | 394.2 | 375.5 | 656.3 |
| baseline | destructive | total | 37520 | 1115 | 1067 | 1936.3 |
| baseline | destructive | decide (whole, mean) | | 286.1 | | |
| baseline | destructive | decide (unstaged, mean) | | 20 | | |
| baseline | destructive | result append (mean) | 37521 | 121.7 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |
| limits_calls | destructive | token_verify_hit | 31587 | 10.1 | 9.5 | 19.1 |
| limits_calls | destructive | lease_check | 31589 | 28.4 | 25.1 | 48.6 |
| limits_calls | destructive | policy | 31589 | 139.2 | 151.6 | 198 |
| limits_calls | destructive | audit_append | 31589 | 155.2 | 149.8 | 212.3 |
| limits_calls | destructive | blocking_pool | 31589 | 115.3 | 93.7 | 197.1 |
| limits_calls | destructive | upstream | 31590 | 307.5 | 284.2 | 484.4 |
| limits_calls | destructive | response | 31590 | 442.2 | 404.8 | 675.5 |
| limits_calls | destructive | total | 31590 | 1353.7 | 1466.1 | 1982.6 |
| limits_calls | destructive | decide (whole, mean) | | 431.7 | | |
| limits_calls | destructive | decide (unstaged, mean) | | 108.9 | | |
| limits_calls | destructive | result append (mean) | 31590 | 137.1 | | |
| limits_calls | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_new | destructive | token_verify_hit | 29338 | 10.8 | 10.1 | 19.3 |
| calls_per_new | destructive | lease_check | 29338 | 30.2 | 26 | 49.2 |
| calls_per_new | destructive | policy | 29338 | 158.2 | 154.3 | 242.8 |
| calls_per_new | destructive | audit_append | 29338 | 174.2 | 152.1 | 243.7 |
| calls_per_new | destructive | blocking_pool | 29339 | 118.3 | 98.3 | 199.7 |
| calls_per_new | destructive | upstream | 29341 | 317.1 | 293 | 488.9 |
| calls_per_new | destructive | response | 29341 | 465.6 | 418.6 | 693.3 |
| calls_per_new | destructive | total | 29341 | 1466.9 | 1515.1 | 2051.2 |
| calls_per_new | destructive | decide (whole, mean) | | 506.8 | | |
| calls_per_new | destructive | decide (unstaged, mean) | | 144.2 | | |
| calls_per_new | destructive | result append (mean) | 29341 | 147.5 | | |
| calls_per_new | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_same | destructive | token_verify_hit | 28714 | 11.4 | 11.4 | 19.6 |
| calls_per_same | destructive | lease_check | 28716 | 31.8 | 27.1 | 60.5 |
| calls_per_same | destructive | policy | 28716 | 156.7 | 156.6 | 269.2 |
| calls_per_same | destructive | audit_append | 28716 | 184.9 | 156.4 | 279.8 |
| calls_per_same | destructive | blocking_pool | 28716 | 120.9 | 104.3 | 218.6 |
| calls_per_same | destructive | upstream | 28719 | 330.8 | 302.3 | 526.6 |
| calls_per_same | destructive | response | 28719 | 478.8 | 426.4 | 845.7 |
| calls_per_same | destructive | total | 28719 | 1497.8 | 1529.9 | 2628.2 |
| calls_per_same | destructive | decide (whole, mean) | | 504.7 | | |
| calls_per_same | destructive | decide (unstaged, mean) | | 131.2 | | |
| calls_per_same | destructive | result append (mean) | 28718 | 151.2 | | |
| calls_per_same | destructive | run lock wait (mean) | | 0.2 | | |
| distinct_new | destructive | token_verify_hit | 25795 | 11.7 | 11.9 | 19.7 |
| distinct_new | destructive | lease_check | 25799 | 31.3 | 27.5 | 59.7 |
| distinct_new | destructive | policy | 25799 | 189.5 | 168.4 | 301.2 |
| distinct_new | destructive | audit_append | 25799 | 208 | 156.7 | 282.3 |
| distinct_new | destructive | blocking_pool | 25799 | 127.9 | 113.2 | 234.9 |
| distinct_new | destructive | upstream | 25799 | 338.8 | 317.6 | 560.7 |
| distinct_new | destructive | response | 25799 | 509.6 | 439.2 | 902.9 |
| distinct_new | destructive | total | 25799 | 1685.6 | 1594.3 | 2855.4 |
| distinct_new | destructive | decide (whole, mean) | | 644.2 | | |
| distinct_new | destructive | decide (unstaged, mean) | | 215.3 | | |
| distinct_new | destructive | result append (mean) | 25799 | 150 | | |
| distinct_new | destructive | run lock wait (mean) | | 0.2 | | |
| distinct_same | destructive | token_verify_hit | 28921 | 11.5 | 11.6 | 19.6 |
| distinct_same | destructive | lease_check | 28926 | 31.5 | 27.4 | 57.1 |
| distinct_same | destructive | policy | 28926 | 155 | 155.7 | 261.7 |
| distinct_same | destructive | audit_append | 28926 | 168.7 | 153.6 | 269.1 |
| distinct_same | destructive | blocking_pool | 28926 | 122.3 | 109.2 | 231.9 |
| distinct_same | destructive | upstream | 28926 | 333.6 | 316.1 | 509.1 |
| distinct_same | destructive | response | 28926 | 477.2 | 430.4 | 826.7 |
| distinct_same | destructive | total | 28926 | 1479.4 | 1522.6 | 2517.4 |
| distinct_same | destructive | decide (whole, mean) | | 484.1 | | |
| distinct_same | destructive | decide (unstaged, mean) | | 128.9 | | |
| distinct_same | destructive | result append (mean) | 28926 | 145.8 | | |
| distinct_same | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_distinct_new | destructive | token_verify_hit | 23299 | 11.7 | 13 | 19.6 |
| calls_per_distinct_new | destructive | lease_check | 23300 | 33.1 | 29.5 | 55.8 |
| calls_per_distinct_new | destructive | policy | 23300 | 207.3 | 185.6 | 295.6 |
| calls_per_distinct_new | destructive | audit_append | 23300 | 296.8 | 160.7 | 282.6 |
| calls_per_distinct_new | destructive | blocking_pool | 23300 | 128 | 98.8 | 199.8 |
| calls_per_distinct_new | destructive | upstream | 23302 | 327.4 | 297.1 | 490 |
| calls_per_distinct_new | destructive | response | 23302 | 551.9 | 432.8 | 752 |
| calls_per_distinct_new | destructive | total | 23302 | 1906.1 | 1576.2 | 2856.8 |
| calls_per_distinct_new | destructive | decide (whole, mean) | | 835.8 | | |
| calls_per_distinct_new | destructive | decide (unstaged, mean) | | 298.6 | | |
| calls_per_distinct_new | destructive | result append (mean) | 23301 | 194.9 | | |
| calls_per_distinct_new | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_distinct_same | destructive | token_verify_hit | 27507 | 11.6 | 12.8 | 19.6 |
| calls_per_distinct_same | destructive | lease_check | 27511 | 32.4 | 28.2 | 53.7 |
| calls_per_distinct_same | destructive | policy | 27511 | 162.3 | 155.5 | 254.4 |
| calls_per_distinct_same | destructive | audit_append | 27511 | 182.3 | 155.9 | 260.8 |
| calls_per_distinct_same | destructive | blocking_pool | 27511 | 129.5 | 112.6 | 226.3 |
| calls_per_distinct_same | destructive | upstream | 27511 | 331.1 | 317.3 | 491 |
| calls_per_distinct_same | destructive | response | 27511 | 488.6 | 432.6 | 733.2 |
| calls_per_distinct_same | destructive | total | 27511 | 1571 | 1535.4 | 2384.8 |
| calls_per_distinct_same | destructive | decide (whole, mean) | | 558.6 | | |
| calls_per_distinct_same | destructive | decide (unstaged, mean) | | 181.6 | | |
| calls_per_distinct_same | destructive | result append (mean) | 27511 | 141.7 | | |
| calls_per_distinct_same | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_host | destructive | token_verify_hit | 29769 | 11 | 11.5 | 19.4 |
| calls_per_host | destructive | lease_check | 29773 | 30.6 | 26.8 | 49.3 |
| calls_per_host | destructive | policy | 29773 | 153.8 | 153.5 | 226.6 |
| calls_per_host | destructive | audit_append | 29773 | 153.2 | 151.1 | 227 |
| calls_per_host | destructive | blocking_pool | 29773 | 124.3 | 107 | 204.3 |
| calls_per_host | destructive | upstream | 29773 | 327.1 | 313.1 | 489.8 |
| calls_per_host | destructive | response | 29773 | 459.8 | 424.1 | 689.9 |
| calls_per_host | destructive | total | 29773 | 1432.3 | 1506.1 | 1990.5 |
| calls_per_host | destructive | decide (whole, mean) | | 459.8 | | |
| calls_per_host | destructive | decide (unstaged, mean) | | 122.2 | | |
| calls_per_host | destructive | result append (mean) | 29773 | 136.5 | | |
| calls_per_host | destructive | run lock wait (mean) | | 0.2 | | |

## Pass 2 (the same, reversed)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| calls_per_host | destructive | 2 | 0 | false | 34587 |
| calls_per_distinct_same | destructive | 4 | 0 | false | 32685 |
| calls_per_distinct_new | destructive | 4 | 0 | false | 1 |
| distinct_same | destructive | 2 | 0 | false | 1 |
| distinct_new | destructive | 2 | 0 | false | 31415 |
| calls_per_same | destructive | 2 | 0 | false | 35592 |
| calls_per_new | destructive | 2 | 0 | false | 1 |
| limits_calls | destructive | 2 | 0 | false | 35577 |
| baseline | destructive | 0 | 0 | false | null |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| calls_per_host | destructive | 5 | 1557.5 | 1445.9 to 1823.7 | 2082.8 | 2271.2 | 4464.6 | 584 |
| calls_per_distinct_same | destructive | 5 | 1640.4 | 1600.5 to 1765.4 | 2140.2 | 2353.2 | 4034.6 | 560 |
| calls_per_distinct_new | destructive | 5 | 1827.8 | 1675.3 to 2144.3 | 2529.3 | 3377.2 | 7856.1 | 454 |
| distinct_same | destructive | 5 | 1439.7 | 1404.9 to 1672.2 | 1977.3 | 2302 | 3711 | 579 |
| distinct_new | destructive | 5 | 1675.3 | 1588.2 to 1775.6 | 2215.9 | 2553.9 | 6082.6 | 533 |
| calls_per_same | destructive | 5 | 1467.4 | 1430.5 to 1606.7 | 2056.2 | 2328.6 | 4948 | 588 |
| calls_per_new | destructive | 5 | 1521.7 | 1461.2 to 1707 | 2006 | 2455.6 | 6451.2 | 560 |
| limits_calls | destructive | 5 | 1473.5 | 1422.3 to 1646.6 | 2068.5 | 2267.1 | 4243.5 | 592 |
| baseline | destructive | 5 | 1262.6 | 1225.7 to 1268.7 | 1773.6 | 1995.8 | 3618.8 | 724 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| calls_per_host | destructive | 28758 | 615 / 245 / 38 | 135266.3 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 6 / 0 / 0, audit_append 95 / 35 / 10, blocking_pool 34 / 3 / 0, upstream 21 / 6 / 0, response 82 / 39 / 11, total 447 / 197 / 36 |
| calls_per_distinct_same | destructive | 27317 | 778 / 352 / 68 | 155713.5 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 7 / 1 / 0, audit_append 77 / 38 / 9, blocking_pool 47 / 13 / 2, upstream 31 / 8 / 1, response 240 / 81 / 20, total 653 / 306 / 65 |
| calls_per_distinct_new | destructive | 23014 | 1454 / 521 / 128 | 203685.9 | token_verify_hit 0 / 0 / 0, lease_check 3 / 1 / 0, policy 5 / 3 / 1, audit_append 112 / 97 / 44, blocking_pool 60 / 9 / 2, upstream 43 / 10 / 0, response 261 / 84 / 36, total 1035 / 426 / 119 |
| distinct_same | destructive | 29655 | 1040 / 444 / 61 | 123535.4 | token_verify_hit 0 / 0 / 0, lease_check 4 / 3 / 1, policy 9 / 1 / 0, audit_append 92 / 36 / 4, blocking_pool 74 / 16 / 3, upstream 32 / 7 / 3, response 373 / 130 / 23, total 900 / 380 / 54 |
| distinct_new | destructive | 25857 | 1277 / 562 / 95 | 154796 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 11 / 1 / 1, audit_append 106 / 71 / 24, blocking_pool 103 / 20 / 0, upstream 48 / 7 / 1, response 398 / 124 / 34, total 1077 / 477 / 91 |
| calls_per_same | destructive | 29440 | 1078 / 446 / 42 | 147456 | token_verify_hit 0 / 0 / 0, lease_check 2 / 1 / 1, policy 7 / 1 / 0, audit_append 96 / 29 / 11, blocking_pool 78 / 15 / 3, upstream 31 / 4 / 0, response 385 / 81 / 12, total 928 / 350 / 40 |
| calls_per_new | destructive | 28118 | 1072 / 525 / 91 | 161087.5 | token_verify_hit 0 / 0 / 0, lease_check 7 / 4 / 1, policy 6 / 2 / 1, audit_append 102 / 57 / 17, blocking_pool 78 / 16 / 4, upstream 46 / 8 / 1, response 399 / 118 / 31, total 924 / 453 / 84 |
| limits_calls | destructive | 29579 | 871 / 347 / 44 | 318242.8 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 4 / 2 / 0, audit_append 85 / 27 / 8, blocking_pool 65 / 10 / 1, upstream 32 / 7 / 0, response 264 / 102 / 10, total 725 / 298 / 37 |
| baseline | destructive | 35309 | 892 / 351 / 40 | 490209.3 | token_verify_hit 0 / 0 / 0, lease_check 2 / 1 / 0, policy 6 / 0 / 0, audit_append 83 / 29 / 12, blocking_pool 58 / 7 / 0, upstream 62 / 11 / 2, response 273 / 56 / 6, total 702 / 248 / 35 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| calls_per_host | destructive | token_verify_hit | 28753 | 11.3 | 12.3 | 19.5 |
| calls_per_host | destructive | lease_check | 28755 | 31.8 | 28.2 | 52.3 |
| calls_per_host | destructive | policy | 28755 | 156.3 | 153.9 | 235.3 |
| calls_per_host | destructive | audit_append | 28755 | 181.2 | 155 | 255.2 |
| calls_per_host | destructive | blocking_pool | 28755 | 123.8 | 106.1 | 223.9 |
| calls_per_host | destructive | upstream | 28757 | 329.2 | 319.1 | 491.6 |
| calls_per_host | destructive | response | 28757 | 473.7 | 430.6 | 733.2 |
| calls_per_host | destructive | total | 28757 | 1489.4 | 1516.6 | 2107.3 |
| calls_per_host | destructive | decide (whole, mean) | | 500.4 | | |
| calls_per_host | destructive | decide (unstaged, mean) | | 131.1 | | |
| calls_per_host | destructive | result append (mean) | 28757 | 149.9 | | |
| calls_per_host | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_distinct_same | destructive | token_verify_hit | 27314 | 11.8 | 13 | 19.6 |
| calls_per_distinct_same | destructive | lease_check | 27315 | 31.7 | 27.8 | 49.8 |
| calls_per_distinct_same | destructive | policy | 27315 | 160.3 | 154.4 | 242.7 |
| calls_per_distinct_same | destructive | audit_append | 27315 | 179 | 155.7 | 259 |
| calls_per_distinct_same | destructive | blocking_pool | 27315 | 131.2 | 111.5 | 221.1 |
| calls_per_distinct_same | destructive | upstream | 27316 | 330.1 | 320.5 | 490.4 |
| calls_per_distinct_same | destructive | response | 27316 | 510.1 | 432.8 | 764.3 |
| calls_per_distinct_same | destructive | total | 27316 | 1587.2 | 1536.8 | 2427.9 |
| calls_per_distinct_same | destructive | decide (whole, mean) | | 552.9 | | |
| calls_per_distinct_same | destructive | decide (unstaged, mean) | | 182 | | |
| calls_per_distinct_same | destructive | result append (mean) | 27316 | 148.7 | | |
| calls_per_distinct_same | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_distinct_new | destructive | token_verify_hit | 23011 | 12 | 13.1 | 19.7 |
| calls_per_distinct_new | destructive | lease_check | 23012 | 33.6 | 28.6 | 56.3 |
| calls_per_distinct_new | destructive | policy | 23012 | 207.5 | 182 | 297 |
| calls_per_distinct_new | destructive | audit_append | 23012 | 274 | 159.9 | 281.2 |
| calls_per_distinct_new | destructive | blocking_pool | 23012 | 138.4 | 110.4 | 245.5 |
| calls_per_distinct_new | destructive | upstream | 23016 | 335.3 | 306.3 | 497 |
| calls_per_distinct_new | destructive | response | 23016 | 569 | 440.1 | 901.1 |
| calls_per_distinct_new | destructive | total | 23015 | 1922.7 | 1601.4 | 2959.3 |
| calls_per_distinct_new | destructive | decide (whole, mean) | | 816.6 | | |
| calls_per_distinct_new | destructive | decide (unstaged, mean) | | 301.5 | | |
| calls_per_distinct_new | destructive | result append (mean) | 23013 | 188.5 | | |
| calls_per_distinct_new | destructive | run lock wait (mean) | | 0.2 | | |
| distinct_same | destructive | token_verify_hit | 29651 | 10.9 | 9.8 | 19.3 |
| distinct_same | destructive | lease_check | 29653 | 32.9 | 28.2 | 49.6 |
| distinct_same | destructive | policy | 29653 | 151.2 | 152.8 | 204.9 |
| distinct_same | destructive | audit_append | 29653 | 162.8 | 152 | 229 |
| distinct_same | destructive | blocking_pool | 29653 | 126.8 | 94 | 198.6 |
| distinct_same | destructive | upstream | 29654 | 301.5 | 278.6 | 482.3 |
| distinct_same | destructive | response | 29654 | 508.4 | 417 | 747.9 |
| distinct_same | destructive | total | 29654 | 1467.2 | 1508.3 | 2235.3 |
| distinct_same | destructive | decide (whole, mean) | | 471.4 | | |
| distinct_same | destructive | decide (unstaged, mean) | | 124.6 | | |
| distinct_same | destructive | result append (mean) | 29654 | 146.5 | | |
| distinct_same | destructive | run lock wait (mean) | | 0.2 | | |
| distinct_new | destructive | token_verify_hit | 25851 | 11.2 | 11.2 | 19.5 |
| distinct_new | destructive | lease_check | 25854 | 33 | 29.4 | 54.2 |
| distinct_new | destructive | policy | 25854 | 186.9 | 165.1 | 287.2 |
| distinct_new | destructive | audit_append | 25854 | 210 | 155.3 | 261.9 |
| distinct_new | destructive | blocking_pool | 25854 | 134.5 | 97.3 | 217.2 |
| distinct_new | destructive | upstream | 25855 | 317.7 | 289.2 | 488.5 |
| distinct_new | destructive | response | 25855 | 546.2 | 428.6 | 858.4 |
| distinct_new | destructive | total | 25855 | 1702.5 | 1556.5 | 2862.9 |
| distinct_new | destructive | decide (whole, mean) | | 641.7 | | |
| distinct_new | destructive | decide (unstaged, mean) | | 211.8 | | |
| distinct_new | destructive | result append (mean) | 25855 | 161.4 | | |
| distinct_new | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_same | destructive | token_verify_hit | 29435 | 10.9 | 10 | 19.3 |
| calls_per_same | destructive | lease_check | 29437 | 31.7 | 28 | 49.6 |
| calls_per_same | destructive | policy | 29437 | 148.2 | 152.4 | 199.5 |
| calls_per_same | destructive | audit_append | 29437 | 182.7 | 153 | 240.3 |
| calls_per_same | destructive | blocking_pool | 29437 | 125.7 | 94.2 | 198.3 |
| calls_per_same | destructive | upstream | 29439 | 301 | 279.3 | 482.9 |
| calls_per_same | destructive | response | 29439 | 503 | 418.9 | 755.3 |
| calls_per_same | destructive | total | 29439 | 1474.1 | 1511.5 | 2287.1 |
| calls_per_same | destructive | decide (whole, mean) | | 485.1 | | |
| calls_per_same | destructive | decide (unstaged, mean) | | 122.4 | | |
| calls_per_same | destructive | result append (mean) | 29439 | 138.4 | | |
| calls_per_same | destructive | run lock wait (mean) | | 0.2 | | |
| calls_per_new | destructive | token_verify_hit | 28113 | 10.9 | 10.4 | 19.4 |
| calls_per_new | destructive | lease_check | 28115 | 32.6 | 28.1 | 49.6 |
| calls_per_new | destructive | policy | 28115 | 158.6 | 153.6 | 229.1 |
| calls_per_new | destructive | audit_append | 28115 | 200.4 | 154.1 | 244.9 |
| calls_per_new | destructive | blocking_pool | 28115 | 125.7 | 93.1 | 197.9 |
| calls_per_new | destructive | upstream | 28117 | 301.7 | 277.9 | 481.9 |
| calls_per_new | destructive | response | 28117 | 525.8 | 422.2 | 740.9 |
| calls_per_new | destructive | total | 28117 | 1553.9 | 1529.2 | 2350.6 |
| calls_per_new | destructive | decide (whole, mean) | | 541.5 | | |
| calls_per_new | destructive | decide (unstaged, mean) | | 149.9 | | |
| calls_per_new | destructive | result append (mean) | 28117 | 155.9 | | |
| calls_per_new | destructive | run lock wait (mean) | | 0.2 | | |
| limits_calls | destructive | token_verify_hit | 29574 | 10.5 | 9.5 | 19.2 |
| limits_calls | destructive | lease_check | 29577 | 30.6 | 27.5 | 49.4 |
| limits_calls | destructive | policy | 29577 | 143.9 | 152.1 | 199 |
| limits_calls | destructive | audit_append | 29577 | 176.2 | 152.2 | 233.6 |
| limits_calls | destructive | blocking_pool | 29577 | 127.7 | 97.8 | 220.3 |
| limits_calls | destructive | upstream | 29579 | 311.8 | 289 | 486.7 |
| limits_calls | destructive | response | 29579 | 495.5 | 422.3 | 760.4 |
| limits_calls | destructive | total | 29579 | 1455.9 | 1499.6 | 2132.4 |
| limits_calls | destructive | decide (whole, mean) | | 462.1 | | |
| limits_calls | destructive | decide (unstaged, mean) | | 111.4 | | |
| limits_calls | destructive | result append (mean) | 29579 | 140.2 | | |
| limits_calls | destructive | run lock wait (mean) | | 0.2 | | |
| baseline | destructive | token_verify_hit | 35304 | 9.9 | 9 | 18.8 |
| baseline | destructive | lease_check | 35305 | 30.4 | 27.4 | 49.4 |
| baseline | destructive | policy | 35305 | 125 | 145.8 | 196.3 |
| baseline | destructive | audit_append | 35305 | 138.1 | 101.5 | 193.7 |
| baseline | destructive | blocking_pool | 35306 | 99.6 | 75.6 | 193.8 |
| baseline | destructive | upstream | 35309 | 287.3 | 264.3 | 475.4 |
| baseline | destructive | response | 35309 | 437.3 | 389.3 | 683.2 |
| baseline | destructive | total | 35309 | 1192.8 | 1157 | 1971.6 |
| baseline | destructive | decide (whole, mean) | | 314.2 | | |
| baseline | destructive | decide (unstaged, mean) | | 20.7 | | |
| baseline | destructive | result append (mean) | 35310 | 129.3 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |

## `--list-values 1`, pass a (`--configs baseline,distinct_list`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| baseline | destructive | 0 | 0 | false | null |
| distinct_list | destructive | 2 | 0 | false | 30542 |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| baseline | destructive | 5 | 1390.6 | 1269.8 to 1502.2 | 1957.9 | 2189.3 | 3579.9 | 646 |
| distinct_list | destructive | 5 | 1838.1 | 1652.7 to 1889.3 | 2388 | 2582.5 | 5021.7 | 491 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| baseline | destructive | 32880 | 768 / 226 / 25 | 66322.4 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 2 / 1 / 0, audit_append 81 / 26 / 6, blocking_pool 50 / 3 / 1, upstream 37 / 10 / 1, response 146 / 37 / 8, total 578 / 168 / 23 |
| distinct_list | destructive | 25274 | 694 / 276 / 86 | 147849.2 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 5 / 1 / 0, audit_append 90 / 72 / 24, blocking_pool 33 / 6 / 1, upstream 30 / 9 / 2, response 113 / 59 / 32, total 518 / 236 / 82 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | destructive | token_verify_hit | 32876 | 10.3 | 9.6 | 19.2 |
| baseline | destructive | lease_check | 32877 | 31.1 | 27.8 | 50 |
| baseline | destructive | policy | 32877 | 135.6 | 151.1 | 198 |
| baseline | destructive | audit_append | 32877 | 126.3 | 113.2 | 195.3 |
| baseline | destructive | blocking_pool | 32877 | 116.9 | 91.9 | 213.8 |
| baseline | destructive | upstream | 32879 | 324 | 298.3 | 491.6 |
| baseline | destructive | response | 32879 | 466.4 | 418.6 | 753.6 |
| baseline | destructive | total | 32879 | 1282.7 | 1340.3 | 1983.3 |
| baseline | destructive | decide (whole, mean) | | 314.9 | | |
| baseline | destructive | decide (unstaged, mean) | | 21.8 | | |
| baseline | destructive | result append (mean) | 32879 | 132.2 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |
| distinct_list | destructive | token_verify_hit | 25269 | 11.5 | 12.7 | 19.6 |
| distinct_list | destructive | lease_check | 25272 | 31.2 | 27.9 | 50.1 |
| distinct_list | destructive | policy | 25272 | 188 | 168.2 | 286.4 |
| distinct_list | destructive | audit_append | 25272 | 197.2 | 155.6 | 259.8 |
| distinct_list | destructive | blocking_pool | 25272 | 138 | 125.3 | 250.1 |
| distinct_list | destructive | upstream | 25274 | 356 | 361.8 | 495.8 |
| distinct_list | destructive | response | 25274 | 532.7 | 453.2 | 836.1 |
| distinct_list | destructive | total | 25274 | 1721.9 | 1563.2 | 2680.5 |
| distinct_list | destructive | decide (whole, mean) | | 628.7 | | |
| distinct_list | destructive | decide (unstaged, mean) | | 212.4 | | |
| distinct_list | destructive | result append (mean) | 25273 | 170.4 | | |
| distinct_list | destructive | run lock wait (mean) | | 0.2 | | |

## `--list-values 1`, pass b (`--configs distinct_list,baseline`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| distinct_list | destructive | 2 | 0 | false | 30458 |
| baseline | destructive | 0 | 0 | false | null |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| distinct_list | destructive | 5 | 1768.4 | 1569.8 to 1837.1 | 2261 | 2906.1 | 5025.8 | 505 |
| baseline | destructive | 5 | 1263.6 | 1236 to 1446.9 | 1821.7 | 2054.1 | 3684.4 | 672 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| distinct_list | destructive | 25224 | 1199 / 473 / 116 | 192151.6 | token_verify_hit 0 / 0 / 0, lease_check 1 / 1 / 0, policy 11 / 1 / 1, audit_append 99 / 85 / 33, blocking_pool 91 / 11 / 3, upstream 28 / 7 / 1, response 315 / 108 / 38, total 918 / 403 / 110 |
| baseline | destructive | 34044 | 930 / 357 / 32 | 263847.9 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 5 / 1 / 0, audit_append 87 / 33 / 17, blocking_pool 89 / 16 / 1, upstream 35 / 7 / 0, response 346 / 70 / 4, total 787 / 264 / 30 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| distinct_list | destructive | token_verify_hit | 25222 | 11.3 | 11.3 | 19.5 |
| distinct_list | destructive | lease_check | 25223 | 33 | 29 | 55 |
| distinct_list | destructive | policy | 25223 | 189.2 | 166.4 | 286.6 |
| distinct_list | destructive | audit_append | 25223 | 221.5 | 155.5 | 261.1 |
| distinct_list | destructive | blocking_pool | 25223 | 140.8 | 105.5 | 233.5 |
| distinct_list | destructive | upstream | 25226 | 327.9 | 313.7 | 492.8 |
| distinct_list | destructive | response | 25226 | 546.9 | 436.3 | 857.6 |
| distinct_list | destructive | total | 25226 | 1738.3 | 1557.6 | 2797.2 |
| distinct_list | destructive | decide (whole, mean) | | 658.6 | | |
| distinct_list | destructive | decide (unstaged, mean) | | 214.9 | | |
| distinct_list | destructive | result append (mean) | 25224 | 163.8 | | |
| distinct_list | destructive | run lock wait (mean) | | 0.2 | | |
| baseline | destructive | token_verify_hit | 34040 | 10 | 9.1 | 19 |
| baseline | destructive | lease_check | 34041 | 31.2 | 28.6 | 49.7 |
| baseline | destructive | policy | 34041 | 131.3 | 149.9 | 197 |
| baseline | destructive | audit_append | 34041 | 134 | 106.4 | 194.3 |
| baseline | destructive | blocking_pool | 34041 | 110.9 | 84.6 | 196.3 |
| baseline | destructive | upstream | 34044 | 297.8 | 276 | 482.6 |
| baseline | destructive | response | 34044 | 463.8 | 404.6 | 692.4 |
| baseline | destructive | total | 34044 | 1248.7 | 1293.6 | 1981.3 |
| baseline | destructive | decide (whole, mean) | | 317.9 | | |
| baseline | destructive | decide (unstaged, mean) | | 21.4 | | |
| baseline | destructive | result append (mean) | 34044 | 129 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |

## `--list-values 16`, pass a (`--configs baseline,distinct_list`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| baseline | destructive | 0 | 0 | false | null |
| distinct_list | destructive | 32 | 0 | false | 176721 |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| baseline | destructive | 5 | 1435.6 | 1317.9 to 1497.1 | 1926.1 | 2121.7 | 4094 | 658 |
| distinct_list | destructive | 5 | 3850.2 | 3618.8 to 4173.8 | 5623.8 | 7479.3 | 18251.8 | 174 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| baseline | destructive | 31928 | 638 / 176 / 19 | 468975.6 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 1 / 0 / 0, audit_append 76 / 20 / 4, blocking_pool 25 / 3 / 0, upstream 27 / 6 / 0, response 91 / 21 / 5, total 451 / 128 / 18 |
| distinct_list | destructive | 8989 | 8928 / 1185 / 181 | 358613 | token_verify_hit 0 / 0 / 0, lease_check 2 / 0 / 0, policy 15 / 3 / 0, audit_append 81 / 75 / 73, blocking_pool 50 / 10 / 2, upstream 54 / 10 / 2, response 154 / 52 / 13, total 8704 / 908 / 173 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | destructive | token_verify_hit | 31924 | 10.2 | 9.3 | 19 |
| baseline | destructive | lease_check | 31926 | 30.1 | 27.3 | 49.6 |
| baseline | destructive | policy | 31926 | 148.3 | 152.7 | 201.7 |
| baseline | destructive | audit_append | 31925 | 148.7 | 104.2 | 194.7 |
| baseline | destructive | blocking_pool | 31925 | 111.9 | 87.5 | 220.2 |
| baseline | destructive | upstream | 31927 | 344.5 | 335.2 | 498 |
| baseline | destructive | response | 31927 | 456.4 | 418.2 | 775.2 |
| baseline | destructive | total | 31927 | 1332.2 | 1404.9 | 1992.3 |
| baseline | destructive | decide (whole, mean) | | 350.3 | | |
| baseline | destructive | decide (unstaged, mean) | | 23.1 | | |
| baseline | destructive | result append (mean) | 31927 | 127.4 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |
| distinct_list | destructive | token_verify_hit | 8989 | 11.7 | 13.4 | 19.6 |
| distinct_list | destructive | lease_check | 8991 | 36.3 | 30 | 58.3 |
| distinct_list | destructive | policy | 8991 | 566.8 | 563.9 | 848.6 |
| distinct_list | destructive | audit_append | 8991 | 1535.5 | 242.6 | 439.1 |
| distinct_list | destructive | blocking_pool | 8991 | 197.1 | 145.2 | 297.7 |
| distinct_list | destructive | upstream | 8994 | 441.2 | 404.7 | 650.9 |
| distinct_list | destructive | response | 8994 | 754.5 | 584.6 | 1427.7 |
| distinct_list | destructive | total | 8994 | 5294.1 | 4079.3 | 6657.5 |
| distinct_list | destructive | decide (whole, mean) | | 3819.9 | | |
| distinct_list | destructive | decide (unstaged, mean) | | 1681.3 | | |
| distinct_list | destructive | result append (mean) | 8993 | 233.3 | | |
| distinct_list | destructive | run lock wait (mean) | | 0.2 | | |

## `--list-values 16`, pass b (`--configs distinct_list,baseline`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| distinct_list | destructive | 32 | 0 | false | 187489 |
| baseline | destructive | 0 | 0 | false | null |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| distinct_list | destructive | 5 | 3772.4 | 3498 to 3852.3 | 4665.3 | 5058.6 | 20201.5 | 187 |
| baseline | destructive | 5 | 1455.1 | 1327.1 to 1496.1 | 1920 | 2049 | 2842.6 | 657 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| distinct_list | destructive | 9571 | 9535 / 681 / 157 | 330563.6 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 3 / 1 / 0, audit_append 80 / 77 / 76, blocking_pool 8 / 3 / 1, upstream 14 / 3 / 1, response 44 / 31 / 26, total 9091 / 476 / 159 |
| baseline | destructive | 33319 | 305 / 106 / 13 | 40927.2 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 0 / 0 / 0, audit_append 76 / 22 / 4, blocking_pool 5 / 1 / 0, upstream 10 / 3 / 2, response 37 / 17 / 1, total 232 / 84 / 11 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| distinct_list | destructive | token_verify_hit | 9571 | 11.9 | 14 | 19.7 |
| distinct_list | destructive | lease_check | 9576 | 32.6 | 28.2 | 58 |
| distinct_list | destructive | policy | 9576 | 533.7 | 513.3 | 789.1 |
| distinct_list | destructive | audit_append | 9576 | 1471.5 | 230.5 | 398.7 |
| distinct_list | destructive | blocking_pool | 9576 | 162.7 | 152 | 270.3 |
| distinct_list | destructive | upstream | 9576 | 415.9 | 408.9 | 604.1 |
| distinct_list | destructive | response | 9576 | 715.4 | 576.7 | 955 |
| distinct_list | destructive | total | 9576 | 5051.9 | 3999 | 4999.3 |
| distinct_list | destructive | decide (whole, mean) | | 3675.8 | | |
| distinct_list | destructive | decide (unstaged, mean) | | 1638 | | |
| distinct_list | destructive | result append (mean) | 9576 | 273.4 | | |
| distinct_list | destructive | run lock wait (mean) | | 0.2 | | |
| baseline | destructive | token_verify_hit | 33313 | 10 | 9.3 | 19.1 |
| baseline | destructive | lease_check | 33318 | 27.3 | 25.5 | 48.3 |
| baseline | destructive | policy | 33318 | 143.8 | 152 | 198.8 |
| baseline | destructive | audit_append | 33318 | 115.3 | 97.6 | 192 |
| baseline | destructive | blocking_pool | 33318 | 106.6 | 92.7 | 196.5 |
| baseline | destructive | upstream | 33318 | 343.2 | 350.3 | 493.5 |
| baseline | destructive | response | 33318 | 432.6 | 418.1 | 681 |
| baseline | destructive | total | 33318 | 1261.6 | 1401.2 | 1960 |
| baseline | destructive | decide (whole, mean) | | 309 | | |
| baseline | destructive | decide (unstaged, mean) | | 22.6 | | |
| baseline | destructive | result append (mean) | 33318 | 120.4 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |

## `--list-values 256`, pass a (`--configs baseline,distinct_list`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| baseline | destructive | 0 | 0 | false | null |
| distinct_list | destructive | 512 | 0 | false | 238593 |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| baseline | destructive | 5 | 2633.7 | 2469.9 to 2746.4 | 3201 | 3387.4 | 4513.8 | 363 |
| distinct_list | destructive | 5 | 38305.8 | 34340.9 to 38731.8 | 47317 | 543162.4 | 662700 | 14 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| baseline | destructive | 18414 | 3556 / 146 / 3 | 15687.7 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 1 / 0 / 0, audit_append 41 / 2 / 0, blocking_pool 4 / 0 / 0, upstream 26 / 4 / 0, response 34 / 5 / 1, total 978 / 110 / 2 |
| distinct_list | destructive | 716 | 716 / 716 / 716 | 785383.4 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 721 / 304 / 5, audit_append 45 / 45 / 43, blocking_pool 1 / 0 / 0, upstream 3 / 0 / 0, response 3 / 1 / 0, total 721 / 721 / 721 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | destructive | token_verify_hit | 18412 | 11.7 | 13.3 | 19.6 |
| baseline | destructive | lease_check | 18414 | 33.3 | 29.2 | 53.9 |
| baseline | destructive | policy | 18414 | 348.5 | 379.7 | 493.3 |
| baseline | destructive | audit_append | 18414 | 126.8 | 122 | 196.2 |
| baseline | destructive | blocking_pool | 18414 | 151 | 148.1 | 268.1 |
| baseline | destructive | upstream | 18415 | 813.6 | 835.5 | 1143.7 |
| baseline | destructive | response | 18415 | 703.9 | 672.8 | 981.9 |
| baseline | destructive | total | 18415 | 2406.9 | 2480.4 | 3131.9 |
| baseline | destructive | decide (whole, mean) | | 574.1 | | |
| baseline | destructive | decide (unstaged, mean) | | 65.5 | | |
| baseline | destructive | result append (mean) | 18415 | 137.8 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |
| distinct_list | destructive | token_verify_hit | 716 | 19.5 | 16.4 | 29.1 |
| distinct_list | destructive | lease_check | 721 | 51.1 | 47.3 | 76.9 |
| distinct_list | destructive | policy | 721 | 5178 | 4729 | 6984.8 |
| distinct_list | destructive | audit_append | 721 | 33677.6 | 892.1 | 399000 |
| distinct_list | destructive | blocking_pool | 721 | 272.4 | 256.1 | 457.3 |
| distinct_list | destructive | upstream | 721 | 1135 | 1377.9 | 1952.1 |
| distinct_list | destructive | response | 721 | 1124 | 1198.8 | 1990.1 |
| distinct_list | destructive | total | 721 | 70354.8 | 40605.6 | 498000 |
| distinct_list | destructive | decide (whole, mean) | | 67506.3 | | |
| distinct_list | destructive | decide (unstaged, mean) | | 28599.5 | | |
| distinct_list | destructive | result append (mean) | 721 | 234 | | |
| distinct_list | destructive | run lock wait (mean) | | 0.3 | | |

## `--list-values 256`, pass b (`--configs distinct_list,baseline`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| distinct_list | destructive | 512 | 0 | false | 240641 |
| baseline | destructive | 0 | 0 | false | null |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| distinct_list | destructive | 5 | 36536.3 | 33751 to 37224.4 | 48463.9 | 443547.6 | 689438.7 | 14 |
| baseline | destructive | 5 | 2502.7 | 2490.4 to 2684.9 | 3020.8 | 3237.9 | 4337.7 | 384 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| distinct_list | destructive | 724 | 724 / 724 / 724 | 742391.8 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 728 / 178 / 1, audit_append 42 / 42 / 42, blocking_pool 1 / 0 / 0, upstream 3 / 0 / 0, response 6 / 1 / 0, total 729 / 729 / 729 |
| baseline | destructive | 18748 | 2811 / 141 / 6 | 29655 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 0 / 0 / 0, audit_append 38 / 3 / 0, blocking_pool 5 / 3 / 2, upstream 20 / 5 / 2, response 25 / 4 / 0, total 908 / 101 / 6 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| distinct_list | destructive | token_verify_hit | 724 | 18.6 | 16.1 | 29 |
| distinct_list | destructive | lease_check | 728 | 51.6 | 42.5 | 68.6 |
| distinct_list | destructive | policy | 728 | 4883 | 4323.6 | 6803.8 |
| distinct_list | destructive | audit_append | 728 | 32684.2 | 884.5 | 392000 |
| distinct_list | destructive | blocking_pool | 728 | 257.8 | 250.3 | 434.6 |
| distinct_list | destructive | upstream | 729 | 1111.3 | 1394.8 | 1947.1 |
| distinct_list | destructive | response | 729 | 1067.9 | 949.9 | 1982.9 |
| distinct_list | destructive | total | 729 | 68749.4 | 40655.2 | 401111.1 |
| distinct_list | destructive | decide (whole, mean) | | 66067.7 | | |
| distinct_list | destructive | decide (unstaged, mean) | | 28448.9 | | |
| distinct_list | destructive | result append (mean) | 729 | 224.9 | | |
| distinct_list | destructive | run lock wait (mean) | | 0.3 | | |
| baseline | destructive | token_verify_hit | 18747 | 11.5 | 13 | 19.6 |
| baseline | destructive | lease_check | 18747 | 31.6 | 28.1 | 53.2 |
| baseline | destructive | policy | 18747 | 343.3 | 376.2 | 493.1 |
| baseline | destructive | audit_append | 18747 | 124.4 | 117.5 | 195.8 |
| baseline | destructive | blocking_pool | 18747 | 147.8 | 145 | 264.6 |
| baseline | destructive | upstream | 18750 | 802 | 829.4 | 1040.1 |
| baseline | destructive | response | 18750 | 687.5 | 656.1 | 980.8 |
| baseline | destructive | total | 18750 | 2365 | 2465.2 | 2998.1 |
| baseline | destructive | decide (whole, mean) | | 563.7 | | |
| baseline | destructive | decide (unstaged, mean) | | 64.4 | | |
| baseline | destructive | result append (mean) | 18749 | 133.8 | | |
| baseline | destructive | run lock wait (mean) | | 0 | | |

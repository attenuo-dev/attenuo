# Cheaper `distinct` charges on list arguments: batched statements measured, not adopted (2026-10-25)

Branch `perf/distinct-list-charge`, main `4524266`. In-process criterion cells of `cargo bench -p attenuo-server --bench decide`, release build with `lto = false` and `codegen-units = 16` (as #113), `CARGO_INCREMENTAL=0`, rustc 1.99.1, Linux 6.18. Shared 4-vCPU container with other agents working on it; load average 1.0 to 4.5 during the runs (04:02 to 04:31 UTC), sampled before and after each run. See [performance](../performance.md#cheaper-distinct-list-charges-measured-2026-10-25).

Why: the [per-value run](2026-10-25-vm-per-value-limits.md) found that a `distinct` limit on a list argument costs about 50 us per new value per hop in the store, and that a 256-value call (`MAX_COUNTED_VALUES`) holds the write gate for about 28 ms. The board left open whether to make a list charge cheaper or lower the cap. Lowering the cap is the maintainer's decision; this run tried the engineering half: the same rows, written with fewer statements.

**Outcome: no reliable gain, so no store code changed.** The batched charge was 7 to 13 percent faster at 256 values in some runs and not in others, and reproducibly 15 to 20 percent slower at 16 values on the file store. The cost is the B-tree work per row, which statement batching does not reduce. The branch keeps a 64-value bench cell and an SR-62 refund test at full list size; neither changes the store.

## The charge path today

`SqliteLeaseStore::charge_with` computes one counter key per charge (an HMAC-SHA256 of the value, 0.3 to 0.4 ms for 512 charges), takes the write gate and runs `charge_in` in one `IMMEDIATE` transaction:

1. one `SELECT EXISTS` on `budget_charges_decision_idx` (the decision is not charged yet);
2. `budget::plan`, which reads each counter it has not seen yet in this call with one cached `SELECT` per key on the `budget_counters` primary key. A new value reads its value row; the first one per hop also reads the limit's count row;
3. per planned write, one cached `INSERT ... ON CONFLICT DO UPDATE` into `budget_counters` and one cached `INSERT` into `budget_charges`. A new `distinct` value plans two writes (its value row with amount 1, and the count row at count + 1), so a 256-value list in a 2-hop chain is 1,024 upserts (512 new value rows, and the two count rows rewritten 512 times) and 1,024 charge-log rows, plus the `calls` rows;
4. commit.

Every statement was already a cached prepared statement.

## Where the time goes

A throwaway build with timers around each step (not committed), mean over about 330 calls of `charge_{store}/distinct_list_256_new`:

| step | memory store | file store (`normal`) |
|---|---|---|
| begin and the `EXISTS` check | 0.02 ms | 0.04 ms |
| plan, with one counter read per key (514 reads) | 2.06 ms | 2.82 ms |
| counter upserts | 3.46 ms | 6.10 ms |
| charge-log inserts (1,026 rows, two indexes) | 5.62 ms | 11.82 ms |
| commit | 1.35 ms | 2.45 ms |
| **inside `charge_in`** | **12.5 ms** | **23.2 ms** |
| counter keys (HMAC), before the gate | 0.42 ms | 0.32 ms |

Each step costs about 4 to 12 us per row. The value hashes are random, so each new value lands on its own leaf pages of the counter primary key and of `budget_charges_counter_idx`. Statement overhead is small next to that, as the attempts below show.

## What was tried

All three changes together on one build ("after"), and the first two alone ("v1"):

- **The plan's pending counters in a `HashMap`** instead of a `Vec` searched from the end (the search is linear in the counters written so far, about 1,000 at 256 values).
- **Multi-row statements.** The counter upserts deduplicated (each counter once, at the position of its first write with the value of its last, so new rows get their rowids in the same order and only the count row's 255 redundant rewrites per hop go away), then both tables written with `INSERT ... VALUES (...), (...)` in statements of 64, 8 and 1 rows (6 parameters a row, so far below SQLite's 32766-parameter limit; three cached statements per table). The charge log kept its rows in plan order.
- **One read per limit**: `SELECT value, used FROM budget_counters WHERE lease = ? AND cap = ? AND kind = ? AND arg = ? AND value IN (...)` in chunks of 64, 8 and 1, for the keys and the count keys, before the plan, and the plan reading from that map.

The rows written were the same. A unit test that ran the old `charge_in` and the new one on twin stores with the same keys found identical counter tables and charge logs, rowids included, after six decisions (seen and new values, a repeat inside one call, a refused call, a 77-value list for the 64/8/1 split, an all-seen list) and after four refunds. All existing budget tests and `budget_props` passed. Since the change was not adopted, that test is not on the branch.

With the timers, the one-read-per-limit version cut the plan step from 2.06 to 1.92 ms (memory) and from 2.82 to 2.62 ms (file): one cached point query per key was not the cost, the index seek was.

## Results

Criterion point estimates (mean). Baseline: three runs of the main build in a row. Then the main build ("before") and the "after" build, interleaved three times. Then file-store-only extra pairs, and three interleaved pairs of "v1" against "before".

### Baseline on this machine (main build, 04:02 to 04:05 UTC)

| cell | run 1 | run 2 | run 3 | median | spread |
|---|---|---|---|---|---|
| `charge_memory/distinct_list_1_new` | 269 us | 283 us | 278 us | 278 us | 269 to 283 us |
| `charge_memory/distinct_list_16_new` | 1.80 ms | 1.79 ms | 1.84 ms | 1.80 ms | 1.79 to 1.84 ms |
| `charge_memory/distinct_list_64_new` | 5.04 ms | 5.12 ms | 5.22 ms | 5.12 ms | 5.04 to 5.22 ms |
| `charge_memory/distinct_list_256_new` | 19.50 ms | 20.91 ms | 20.16 ms | 20.16 ms | 19.50 to 20.91 ms |
| `charge_file/distinct_list_1_new` | 152 us | 148 us | 167 us | 152 us | 148 to 167 us |
| `charge_file/distinct_list_16_new` | 1.87 ms | 1.63 ms | 1.49 ms | 1.63 ms | 1.49 to 1.87 ms |
| `charge_file/distinct_list_64_new` | 6.06 ms | 5.44 ms | 5.61 ms | 5.61 ms | 5.44 to 6.06 ms |
| `charge_file/distinct_list_256_new` | 31.64 ms | 29.10 ms | 25.51 ms | 29.10 ms | 25.51 to 31.64 ms |

The file store agrees with #113 within noise (there 25.3 to 25.8 ms at 256 values, 1.42 to 1.55 ms at 16), and so does the memory store at 256 values (20.5 to 22.4 ms). The memory store at 16 values is faster here than there (2.35 to 2.51 ms). The 64-value cell is new.

### Before and after, interleaved (04:17 to 04:24 UTC)

| cell | before, 3 runs | median | after, 3 runs | median | change |
|---|---|---|---|---|---|
| `charge_memory/distinct_list_1_new` | 279, 220, 274 us | 274 us | 286, 276, 201 us | 276 us | +1 % |
| `charge_memory/distinct_list_16_new` | 1.88, 1.73, 1.78 ms | 1.78 ms | 1.74, 1.76, 1.80 ms | 1.76 ms | -1 % |
| `charge_memory/distinct_list_64_new` | 4.99, 5.13, 5.14 ms | 5.13 ms | 4.68, 5.04, 4.96 ms | 4.96 ms | -3 % |
| `charge_memory/distinct_list_256_new` | 20.51, 22.25, 21.69 ms | 21.69 ms | 19.06, 18.89, 16.70 ms | 18.89 ms | -13 % |
| `charge_file/distinct_list_1_new` | 151, 139, 144 us | 144 us | 153, 155, 152 us | 153 us | +6 % |
| `charge_file/distinct_list_16_new` | 1.41, 1.62, 1.36 ms | 1.41 ms | 1.67, 2.07, 1.74 ms | 1.74 ms | +23 % |
| `charge_file/distinct_list_64_new` | 6.32, 6.85, 5.60 ms | 6.32 ms | 5.94, 5.92, 6.04 ms | 5.94 ms | -6 % |
| `charge_file/distinct_list_256_new` | 28.92, 31.65, 25.59 ms | 28.92 ms | 24.37, 23.66, 23.68 ms | 23.68 ms | -18 % |

### File store again, four more interleaved pairs (04:24 to 04:27 UTC)

| cell | before | median | after | median | change |
|---|---|---|---|---|---|
| `charge_file/distinct_list_16_new` | 1.47, 1.52, 1.44, 1.59 ms | 1.50 ms | 1.74, 1.75, 1.73, 1.71 ms | 1.73 ms | +16 % |
| `charge_file/distinct_list_256_new` | 24.27, 25.44, 24.72, 26.01 ms | 25.08 ms | 24.76, 22.64, 25.05, 23.80 ms | 24.28 ms | -3 % |

Over all seven pairs, `charge_file` at 256 values has a median of 25.59 ms before and 23.80 ms after (-7 %). At 16 values the after build was slower in all seven pairs.

### The first two changes alone ("v1": map and multi-row statements, per-key reads), three interleaved pairs (04:27 to 04:31 UTC)

| cell | before | v1 |
|---|---|---|
| `charge_memory/distinct_list_16_new` | 1.68, 1.83, 1.77 ms | 1.71, 1.73, 1.46 ms |
| `charge_memory/distinct_list_256_new` | 20.56, 19.31, 20.03 ms | 21.45, 18.57, 18.50 ms |
| `charge_file/distinct_list_16_new` | 1.57, 1.57, 1.49 ms | 1.77, 1.80, 1.64 ms |
| `charge_file/distinct_list_256_new` | 27.02, 31.39, 26.16 ms | 26.68, 29.63, 26.34 ms |

So the file-store slowdown at 16 values comes with the multi-row writes. At 256 values the writes alone change nothing measurable.

## Reading

- **Fewer statements do not make a list charge cheaper.** The gains at 256 values (-3 to -18 % on the file store, -13 % in one memory set and about -3 % in the other) sit inside the spread of the "before" runs. The loss at 16 values on the file store held in all seven pairs. Why a 64- or 8-row statement is slower than the same rows one at a time there was not looked into.
- **The cost is per row in the B-trees**: one primary-key seek per counter read, one primary-key insert and one table insert per new counter row, one table append and two index inserts per charge-log row (the second index, SR-62's `budget_charges_counter_idx`, at a random position). That is what the 5.2 MiB of WAL per call in #113 is. Only writing fewer rows makes it cheaper: for example, no rewrite of a value row whose content does not change, or a cheaper charge-log key. Each of those changes what is recorded for SR-62's exact refunds, so it is a design decision and was not done here. The other option is a lower `MAX_COUNTED_VALUES`, which is the maintainer's call.
- **The write gate hold did not change**: it is the whole of `charge_in`, about 12.5 ms in memory and 23 ms on the file store in process at 256 values.
- **One lever outside the transaction, not taken:** with `PRAGMA cache_size = -65536` (64 MiB, against SQLite's default of about 2 MiB) on the file connection, the 256-value charge took 18.2 ms inside `charge_in` against 23.2 to 23.5 ms (one timed run, about -22 %). The reads and writes fell to memory-store levels (1.89, 3.41 and 5.26 ms), and the commit grew from 2.45 to 7.62 ms because dirty pages no longer spill into the WAL before commit. That costs memory on every connection and affects the whole store, not only budgets, so it is a separate decision; it is listed as open on the board.

## Rerun

```text
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 CARGO_INCREMENTAL=0
cargo bench -p attenuo-server --bench decide --no-run
# from crates/attenuo-server, with the bench binary printed above:
<decide binary> --bench --warm-up-time 1 --measurement-time 3 'charge_(file|memory)/distinct_list'
```

The "before" and "after" binaries were built from `4524266` with the 64-value cell added, the second with the three changes above. Each was copied out of the target directory and run alternately by a script that wrote `uptime` before every run.

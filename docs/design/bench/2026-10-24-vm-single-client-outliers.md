# Single-client outliers on the file store (2026-10-24)

Branch `perf/single-client-outliers`, main `d27c891`. Summary and conclusion: [performance, Single-client outliers](../performance.md#single-client-outliers-2026-10-24).

The question: one client against a file-backed server sees a few calls in a hundred take 3 ms or more, where the median is about 1.3 ms. The write-contention work showed that SQLite's busy handler never runs with one client. This file records what the slow calls are, measured in four ways, and the before and after of the two changes that came out of it.

## Environment

The shared 4-vCPU dev container of the other 2026-10 files (ext4 root, mounted with `discard`, virtio disk, `mq-deadline`), rustc 1.99.1, release builds with `lto = false` and `codegen-units = 16` as in the other 2026-10-24 files. Other agents were building on the host; the load average is given with each run. It was 0.5 to 5.5 over the session.

## Method

1. **Raw host probes** (C, sources at the end of this file): the wake-up latency of a thread that sleeps 500 us (`jitter`), the `fdatasync` of a 4 KiB rewrite (`fsync`), a 64 KiB append plus `fdatasync` with the file truncated to zero every 256 appends (`fsync_append`), and `wal_sim`, which writes 15 frames of 4,120 bytes every 700 us (a WAL commit at `synchronous=NORMAL`, no sync) while a second thread, every 256 commits, does nothing (`none`), `fdatasync`s the same file (`fsync_same`, what a `PASSIVE` checkpoint does to the WAL) or writes and syncs 15 MB of another file (`fsync_other`). With `_reuse` the writer overwrites a preallocated 16 MB file instead of growing one.
2. **In-process probe**, `crates/attenuo-audit/tests/single_client_outliers.rs` (an `#[ignore]` test): one thread makes the store calls of one allowed call in a closed loop (lease check and run-labels read, decision append, a 700 us pause for the upstream, result append, a 350 us pause), and times every append. Configurations: `memory` (in-memory stores), `file` (one file as the server opens it, background checkpointer), `parked` (checkpointer parked by the `testing` hook for each 800-call segment, each segment starting from an empty WAL), `signed` (as `file` plus a signed audit checkpoint every 1,000 entries, the server default), and the `-nopresync` variants of `file` and `signed`, which turn off the two changes below through `testing` hooks, so before and after run on one build. Each slow append is matched against the checkpointer's rounds and locked passes, which the `testing` feature now records (`WalTimings::rounds`). One configuration per process (8 segments, 6,400 calls, 12,800 appends), so its WAL stays large and is overwritten as under steady load; two passes, the second in reverse order.
3. **End to end**, `attenuo-bench hot-path --configs baseline` (one client, file store at `normal`, 2-hop token, 2 s warm-up, 10 s per cell, three runs per invocation). The harness now reports, per cell, the requests over 3, 5 and 10 ms at the client and, per server stage, the samples over 3, 5 and 10 ms (from `attenuo_proxy_stage_seconds`). A new `--audit-set key=value` sets `[audit]` keys, so `checkpoint_every=0` (no signed checkpoints by count) runs on the same binary. Variants alternate per invocation, two passes, the second reversed.
4. `strace -f --seccomp-bpf -e fsync,fdatasync,ftruncate` on the in-process probe, to see which thread syncs which file.

Not measured: tracing and the allocator on their own (the bench runs the server at `RUST_LOG=warn`; the in-memory store, which shares everything but the file I/O, bounds them, see below); the writer thread's hand-off (one client commits inline, so it is not on this path); a quiet reference machine.

## What the slow calls are

| Source | How often, one client | Size before | Size after | In our control |
|---|---|---|---|---|
| Signed audit checkpoint: its commit syncs at `FULL` (SR-50), writing every WAL page since the last WAL sync, up to 256 commits | once per 1,000 entries (2 entries per call, so 1 call in 500) | 13 to 16 ms p50, up to 25 ms (in process) | 3.4 to 3.9 ms p50, up to 9 ms | yes; changed |
| WAL checkpointer's locked pass: its `PASSIVE` finishes and syncs the database file, which holds every page the unlocked passes copied without syncing | once per WAL restart, about 1,800 commits here | holds appends 10 to 23 ms (median), up to 31 ms | 3.0 to 3.4 ms median, up to 4.9 ms | yes; changed |
| Scheduling on the shared host: thread wake-ups, the blocking pool, the client | grows with load: 0.7 to 0.9 % of calls over 3 ms at load 1.5 to 2, 2 to 3.6 % at load 3 to 4.7 | 3 to 10 ms | unchanged | no |
| Appends that grow the WAL file while the checkpointer syncs it | only while the WAL grows (after an idle `TRUNCATE`); the server under steady load overwrites a WAL of about 78 MB | up to 16 ms in `wal_sim` | unchanged | partly; not changed |
| `fsync` tail of the disk | quiet: p99.9 0.4 to 1.1 ms; during another agent's build p50 4 ms, p99 8 ms | magnifies the first two | | no |

## Raw host probes

Two passes (`raw.sh`, below), load 1.6 and 0.8:

| Probe | p50 | p99 | p99.9 | max | over 3 ms |
|---|---|---|---|---|---|
| `jitter`, 10,000 sleeps of 500 us (overshoot) | 98 / 102 us | 210 / 228 us | 0.64 / 1.28 ms | 4.7 / 13.8 ms | 1 / 3 |
| `fsync`, 5,000 rewrites of 4 KiB | 85 / 121 us | 196 / 300 us | 0.38 / 1.11 ms | 0.9 / 1.6 ms | 0 / 0 |
| `fsync_append`, 2,000 (truncate every 256) | 299 / 444 us | 0.75 / 1.38 ms | 11.0 / 14.1 ms | 11.3 / 14.8 ms | 7 / 7 |

Earlier, while this branch's release build ran (load 6.5 to 7.9): `jitter` 29 sleeps in 10,000 over 3 ms (p99.9 5.1 ms, max 12 ms); `fsync` p50 3.98 ms, p99 8.3 ms, max 453 ms. The 7 slow `fsync_append` iterations are the 7 or 8 that follow a truncation: the first sync after freeing the blocks costs 11 to 15 ms on this mount.

`wal_sim`, 8 s per mode (about 9,000 commits), writes over 3 ms, two passes:

| Mode | p50 | p99.9 | max | over 3 ms | the other thread's sync, p50 |
|---|---|---|---|---|---|
| `none` | 34 / 35 us | 290 / 426 us | 0.7 / 3.1 ms | 0 / 1 | |
| `fsync_same` (growing file) | 35 / 33 us | 2.95 / 0.69 ms | 16.3 / 9.1 ms | 8 / 4 | 22 ms |
| `fsync_other` | 32 / 32 us | 294 / 193 us | 3.4 / 1.7 ms | 1 / 0 | 17 ms |
| `none_reuse` | 17 / 17 us | 133 / 158 us | 0.9 / 1.9 ms | 0 / 0 | |
| `fsync_same_reuse` (overwrites) | 19 / 18 us | 165 / 199 us | 1.6 / 2.3 ms | 0 / 0 | 20 ms |

So a plain write at `synchronous=NORMAL` stalls for milliseconds only when it extends a file that is being synced; overwrites do not. Under steady load the server's WAL is overwritten (it stayed at 78.7 to 78.8 MB through a 10 s cell, sampled every 250 ms), so this matters only after an idle `TRUNCATE`.

## In process

Each configuration in its own process, 12,800 appends per pass. "Locked pass" is how long the checkpointer held the store's lock; "signing append" is the append that wrote a signed checkpoint (12 per pass).

| Configuration | appends over 3 ms, pass 1 / 2 | of those, during a locked pass | max append | locked pass, median (range) | signing append, p50 / max |
|---|---|---|---|---|---|
| `memory` | 1 / 0 | | 4.2 / 2.1 ms | | |
| `parked` (no checkpoint runs) | 0 / 0 | | 2.3 / 2.4 ms | | |
| `file-nopresync` (before) | 9 / 11 | 6 / 7 | 33.3 / 13.0 ms | 22.7 ms (10.2 to 31.4) / 10.8 ms (7.7 to 12.7) | |
| `file` (after) | 7 / 6 | 5 / 4 | 20.8 / 9.7 ms | 3.3 ms (2.4 to 4.5) / 3.0 ms (2.4 to 4.9) | |
| `signed-nopresync` (before) | 19 / 21 | 7 / 7 | 25.3 / 155.9 ms | 9.2 / 10.6 ms | 16.2 / 25.3 ms; 15.9 / 155.9 ms |
| `signed` (after) | 18 / 20 | 7 / 6 | 11.7 / 16.7 ms | 3.7 / 3.3 ms | 3.5 / 9.1 ms; 3.9 / 6.9 ms |

Every checkpoint round took 23 to 26 ms at the median, nearly all of it the `PASSIVE` pass's sync of up to 256 commits of WAL (strace: 17 to 31 ms per sync); appends did not wait for it. The first sweep below is the lead of the WAL sync ahead of a signed checkpoint (`signed-leadN`, database-file sync on), signing append p50, two runs each (one for 8 and 16 in a second sweep):

| Lead (entries) | 0 | 8 | 16 | 32 | 64 | 128 |
|---|---|---|---|---|---|---|
| signing append p50 | 16.3, 12.8 ms | 8.6, 9.8 ms | 4.2, 2.9 ms (p90 8 to 9 ms) | 4.4, 4.0, 3.5, 3.4 ms | 6.9, 5.4 ms | 12.3, 11.8 ms |

A short lead leaves the sync still running when the checkpoint commits (that commit then waits for it); a long one leaves more pages for the commit. 32 is kept.

## End to end

`hot-path --configs baseline`, three runs per invocation, read and destructive cells. `before` is main's server (`d27c891`), `after` this branch's, `before, no signed` main's with `--audit-set checkpoint_every=0`. Pooled over the three runs, client side:

| Variant, pass (load) | cell | requests | over 3 ms | over 5 ms | over 10 ms | p99 (per run) | max |
|---|---|---|---|---|---|---|---|
| before, 1 (1.8) | read | 21,147 | 195 (0.92 %) | 104 (0.49 %) | 62 (0.29 %) | 2.6 to 3.0 ms | 41 ms |
| before, 1 | destructive | 21,323 | 153 (0.72 %) | 84 (0.39 %) | 57 (0.27 %) | 2.4 to 2.8 ms | 46 ms |
| after, 1 (1.7) | read | 21,672 | 168 (0.78 %) | 76 (0.35 %) | 19 (0.09 %) | 2.4 to 2.7 ms | 65 ms |
| after, 1 | destructive | 21,589 | 222 (1.03 %) | 82 (0.38 %) | 17 (0.08 %) | 2.8 to 3.1 ms | 19 ms |
| before, no signed, 1 (1.5) | read | 21,802 | 141 (0.65 %) | 57 (0.26 %) | 32 (0.15 %) | 2.3 to 2.6 ms | 52 ms |
| before, no signed, 1 | destructive | 20,760 | 189 (0.91 %) | 70 (0.34 %) | 30 (0.14 %) | 2.7 to 3.4 ms | 51 ms |
| before, no signed, 2 (4.7) | read | 22,219 | 734 (3.30 %) | 282 (1.27 %) | 34 (0.15 %) | 5.1 to 5.4 ms | 53 ms |
| before, no signed, 2 | destructive | 22,233 | 792 (3.56 %) | 310 (1.39 %) | 32 (0.14 %) | 5.2 to 5.3 ms | 56 ms |
| after, 2 (3.7) | read | 21,166 | 575 (2.72 %) | 186 (0.88 %) | 30 (0.14 %) | 4.1 to 5.2 ms | 27 ms |
| after, 2 | destructive | 20,256 | 439 (2.17 %) | 172 (0.85 %) | 29 (0.14 %) | 3.4 to 5.2 ms | 66 ms |
| before, 2 (3.0) | read | 19,544 | 420 (2.15 %) | 137 (0.70 %) | 56 (0.29 %) | 3.9 to 4.6 ms | 48 ms |
| before, 2 | destructive | 19,447 | 376 (1.93 %) | 110 (0.57 %) | 50 (0.26 %) | 3.8 to 4.4 ms | 44 ms |

Server stages over 3 / 5 / 10 ms, same runs (the `audit_append` stage is the decision append; the result append and the run-label write are in `response`; `total` is the handler):

| Variant, pass | cell | `audit_append` | `response` | `blocking_pool` | `upstream` | `total` | client over 3 ms not over 3 ms in `total` |
|---|---|---|---|---|---|---|---|
| before, 1 | read | 55 / 52 / 43 | 20 / 13 / 11 | 11 / 5 / 0 | 13 / 7 / 0 | 152 / 93 / 59 | 43 |
| before, 1 | destructive | 57 / 54 / 45 | 14 / 9 / 8 | 7 / 1 / 0 | 4 / 1 / 0 | 118 / 72 / 55 | 35 |
| after, 1 | read | 53 / 13 / 4 | 16 / 11 / 1 | 7 / 5 / 1 | 13 / 4 / 2 | 129 / 51 / 17 | 39 |
| after, 1 | destructive | 52 / 14 / 5 | 24 / 19 / 5 | 4 / 2 / 0 | 15 / 4 / 0 | 161 / 61 / 15 | 61 |
| before, no signed, 1 | read | 12 / 12 / 10 | 21 / 15 / 13 | 12 / 6 / 2 | 14 / 4 / 0 | 103 / 48 / 30 | 38 |
| before, no signed, 1 | destructive | 15 / 15 / 15 | 20 / 13 / 8 | 11 / 5 / 1 | 16 / 5 / 1 | 133 / 51 / 28 | 56 |
| before, no signed, 2 | read | 21 / 13 / 11 | 233 / 65 / 15 | 171 / 31 / 3 | 34 / 7 / 0 | 654 / 225 / 32 | 80 |
| after, 2 | read | 44 / 18 / 9 | 119 / 31 / 6 | 105 / 26 / 3 | 13 / 6 / 0 | 473 / 141 / 29 | 102 |
| before, 2 | read | 54 / 51 / 42 | 52 / 10 / 6 | 40 / 5 / 1 | 21 / 6 / 2 | 336 / 117 / 56 | 84 |

Three earlier A/B rounds of the same shape agree. Main against `checkpoint_every=0` (2 runs per invocation): 36 to 45 decision appends over 3 ms per cell against 11 to 15. Main against the branch with a 64-entry lead, and then main against both leads (3 runs per invocation): main 40 to 51 decision appends over 10 ms per cell against 3 to 15 for either lead, and over 5 ms 49 to 62 for main, 41 to 51 with a 64-entry lead and 10 to 29 with a 32-entry lead.

Readings:

- **The signed checkpoint is the largest single cause of slow decision appends**: with `checkpoint_every=0` the decision appends over 3 ms fall from 55 to 57 per cell to 12 to 15. It lands on the decision append in these runs (the `response` counts do not move with it).
- **After the change those appends take 3 to 10 ms instead of 10 to 25**: decision appends over 10 ms fall from 43 to 45 to 4 to 5 per cell at load 1.7 to 1.8, and client calls over 10 ms from 0.27 to 0.29 % to 0.08 to 0.09 %, below the run without signed checkpoints (0.14 to 0.15 %), because the locked pass got shorter too. At load 3 to 4.7 the over-10 ms share is 0.14 % against 0.26 to 0.29 %.
- **The count over 3 ms does not change** (0.72 to 1.03 % at load 1.5 to 1.8 for all three variants): the two storage causes now mostly land between 3 and 5 ms, and the rest is the host. It doubles to triples when the load average reaches 3 to 4.7, and the growth is in `blocking_pool`, `response` and outside the handler, stages that wait on a thread being scheduled, not on storage. The time outside the handler (client, hyper, kernel) accounts for 35 to 102 of the slow calls per cell.

## Raw output

In-process probe, both passes (`inproc.sh`, below):

```
== pass 1 memory load 3.63 3.23 2.89
 memory decision append  n   6400  p50    62  p90   109  p99   186  p99.9    483  max   2484 us  >1ms    1  >3ms   0
 memory result append    n   6400  p50    74  p90   127  p99   201  p99.9    589  max   4155 us  >1ms    3  >3ms   1
 memory lease+label read n   6400  p50    34  p90    50  p99    76  p99.9    322  max    828 us  >1ms    0  >3ms   0
 memory rounds 0  took p50 0ns max 0ns  complete 0  truncated 0  first-pass WAL frames min 0 max 0  locked passes 0  backstops 0
 memory appends over 1 ms: 4, of which during a checkpoint round: 0, during its locked pass: 0
 memory appends over 3 ms: 1, of which during a checkpoint round: 0, during its locked pass: 0
== pass 1 file-nopresync load 5.00 3.54 2.99
file-nopresync decision append  n   6400  p50    94  p90   138  p99   200  p99.9   1095  max  26436 us  >1ms    7  >3ms   4
file-nopresync result append    n   6400  p50   112  p90   161  p99   238  p99.9   1481  max  33325 us  >1ms   10  >3ms   5
file-nopresync lease+label read n   6400  p50    48  p90    69  p99   108  p99.9    453  max   4136 us  >1ms    3  >3ms   2
file-nopresync locked passes held the store lock: min 10.240506ms median 22.739521ms max 31.38853ms
file-nopresync rounds 48  took p50 24.996978ms max 519.783374ms  complete 48  truncated 0  first-pass WAL frames min 244 max 19226  locked passes 6  backstops 0
file-nopresync appends over 1 ms: 17, of which during a checkpoint round: 14, during its locked pass: 6
file-nopresync appends over 3 ms: 9, of which during a checkpoint round: 8, during its locked pass: 6
== pass 1 file load 5.46 3.68 3.05
   file decision append  n   6400  p50   102  p90   156  p99   397  p99.9   1192  max  20758 us  >1ms   10  >3ms   3
   file result append    n   6400  p50   120  p90   181  p99   417  p99.9   2480  max   3772 us  >1ms   13  >3ms   4
   file lease+label read n   6400  p50    52  p90    75  p99   249  p99.9    688  max   3995 us  >1ms    4  >3ms   1
   file locked passes held the store lock: min 2.427178ms median 3.306029ms max 4.497918ms
   file rounds 46  took p50 25.490643ms max 784.334726ms  complete 46  truncated 0  first-pass WAL frames min 2012 max 18699  locked passes 7  backstops 0
   file appends over 1 ms: 23, of which during a checkpoint round: 11, during its locked pass: 7
   file appends over 3 ms: 7, of which during a checkpoint round: 5, during its locked pass: 5
== pass 1 parked load 4.85 3.61 3.03
 parked decision append  n   6400  p50   114  p90   166  p99   290  p99.9   1020  max   2347 us  >1ms    7  >3ms   0
 parked result append    n   6400  p50   130  p90   188  p99   285  p99.9    710  max   1606 us  >1ms    2  >3ms   0
 parked lease+label read n   6400  p50    52  p90    75  p99   112  p99.9    352  max    481 us  >1ms    0  >3ms   0
 parked rounds 4  took p50 52.063µs max 59.625µs  complete 4  truncated 0  first-pass WAL frames min 0 max 0  locked passes 0  backstops 0
 parked appends over 1 ms: 9, of which during a checkpoint round: 1, during its locked pass: 0
 parked appends over 3 ms: 0, of which during a checkpoint round: 0, during its locked pass: 0
== pass 1 signed-nopresync load 5.20 3.73 3.08
signed-nopresync decision append  n   6400  p50   104  p90   151  p99   239  p99.9   1295  max  14311 us  >1ms    9  >3ms   3
signed-nopresync result append    n   6400  p50   124  p90   173  p99   317  p99.9  15411  max  25334 us  >1ms   23  >3ms  16
signed-nopresync lease+label read n   6400  p50    58  p90    77  p99   122  p99.9    302  max   2607 us  >1ms    3  >3ms   0
signed-nopresync signing append   n     12  p50 16229  p90 24902  p99 25334  p99.9  25334  max  25334 us  >1ms   12  >3ms  11
signed-nopresync locked passes held the store lock: min 6.866207ms median 9.222443ms max 14.790028ms
signed-nopresync rounds 49  took p50 24.980489ms max 47.61917ms  complete 49  truncated 0  first-pass WAL frames min 2198 max 18167  locked passes 7  backstops 0
signed-nopresync appends over 1 ms: 32, of which during a checkpoint round: 9, during its locked pass: 7
signed-nopresync appends over 3 ms: 19, of which during a checkpoint round: 9, during its locked pass: 7
== pass 1 signed load 4.94 3.73 3.08
 signed decision append  n   6400  p50   101  p90   145  p99   206  p99.9   1509  max  11676 us  >1ms    9  >3ms   5
 signed result append    n   6400  p50   118  p90   168  p99   249  p99.9   3724  max   9128 us  >1ms   16  >3ms  13
 signed lease+label read n   6400  p50    53  p90    76  p99   112  p99.9    442  max   1816 us  >1ms    3  >3ms   0
 signed signing append   n     12  p50  3454  p90  7585  p99  9128  p99.9   9128  max   9128 us  >1ms   12  >3ms  11
 signed locked passes held the store lock: min 3.259412ms median 3.727925ms max 8.083033ms
 signed rounds 49  took p50 24.141297ms max 99.086081ms  complete 49  truncated 0  first-pass WAL frames min 2074 max 18207  locked passes 7  backstops 0
 signed appends over 1 ms: 25, of which during a checkpoint round: 11, during its locked pass: 7
 signed appends over 3 ms: 18, of which during a checkpoint round: 8, during its locked pass: 7
== pass 2 signed load 4.65 3.70 3.08
 signed decision append  n   6400  p50    97  p90   143  p99   222  p99.9   3551  max  16670 us  >1ms    9  >3ms   7
 signed result append    n   6400  p50   113  p90   163  p99   304  p99.9   3904  max   6945 us  >1ms   21  >3ms  13
 signed lease+label read n   6400  p50    49  p90    72  p99   116  p99.9    504  max   2846 us  >1ms    3  >3ms   0
 signed signing append   n     12  p50  3893  p90  5795  p99  6945  p99.9   6945  max   6945 us  >1ms   12  >3ms  10
 signed locked passes held the store lock: min 2.529052ms median 3.30413ms max 8.678392ms
 signed rounds 49  took p50 23.946082ms max 44.829262ms  complete 49  truncated 0  first-pass WAL frames min 2049 max 18111  locked passes 7  backstops 0
 signed appends over 1 ms: 30, of which during a checkpoint round: 11, during its locked pass: 7
 signed appends over 3 ms: 20, of which during a checkpoint round: 8, during its locked pass: 6
== pass 2 signed-nopresync load 4.55 3.71 3.09
signed-nopresync decision append  n   6400  p50    96  p90   141  p99   201  p99.9    663  max  17158 us  >1ms    5  >3ms   4
signed-nopresync result append    n   6400  p50   112  p90   162  p99   257  p99.9  13927  max 155930 us  >1ms   22  >3ms  17
signed-nopresync lease+label read n   6400  p50    49  p90    73  p99   113  p99.9    406  max   1830 us  >1ms    3  >3ms   0
signed-nopresync signing append   n     12  p50 15853  p90 26505  p99 155930  p99.9 155930  max 155930 us  >1ms   12  >3ms  12
signed-nopresync locked passes held the store lock: min 7.083337ms median 10.615779ms max 14.781167ms
signed-nopresync rounds 49  took p50 23.526896ms max 163.764202ms  complete 49  truncated 0  first-pass WAL frames min 2245 max 18159  locked passes 7  backstops 0
signed-nopresync appends over 1 ms: 27, of which during a checkpoint round: 11, during its locked pass: 7
signed-nopresync appends over 3 ms: 21, of which during a checkpoint round: 9, during its locked pass: 7
== pass 2 parked load 4.20 3.68 3.09
 parked decision append  n   6400  p50   114  p90   167  p99   258  p99.9   1031  max   2391 us  >1ms    7  >3ms   0
 parked result append    n   6400  p50   130  p90   187  p99   280  p99.9    762  max   2313 us  >1ms    3  >3ms   0
 parked lease+label read n   6400  p50    52  p90    75  p99   112  p99.9    620  max   3443 us  >1ms    2  >3ms   1
 parked rounds 4  took p50 55.557µs max 2.803652ms  complete 4  truncated 0  first-pass WAL frames min 0 max 0  locked passes 0  backstops 0
 parked appends over 1 ms: 10, of which during a checkpoint round: 1, during its locked pass: 0
 parked appends over 3 ms: 0, of which during a checkpoint round: 0, during its locked pass: 0
== pass 2 file load 3.78 3.60 3.07
   file decision append  n   6400  p50   101  p90   148  p99   216  p99.9    721  max   5404 us  >1ms    4  >3ms   3
   file result append    n   6400  p50   116  p90   168  p99   253  p99.9   1731  max   9651 us  >1ms    7  >3ms   3
   file lease+label read n   6400  p50    51  p90    73  p99   112  p99.9   1187  max   4319 us  >1ms    7  >3ms   1
   file locked passes held the store lock: min 2.386046ms median 3.034649ms max 4.905634ms
   file rounds 49  took p50 23.475757ms max 51.970823ms  complete 49  truncated 0  first-pass WAL frames min 2121 max 18041  locked passes 7  backstops 0
   file appends over 1 ms: 11, of which during a checkpoint round: 8, during its locked pass: 7
   file appends over 3 ms: 6, of which during a checkpoint round: 5, during its locked pass: 4
== pass 2 file-nopresync load 3.20 3.48 3.04
file-nopresync decision append  n   6400  p50   102  p90   150  p99   239  p99.9   1538  max  13020 us  >1ms   11  >3ms   5
file-nopresync result append    n   6400  p50   119  p90   171  p99   281  p99.9   2472  max  12564 us  >1ms    9  >3ms   6
file-nopresync lease+label read n   6400  p50    54  p90    76  p99   123  p99.9    506  max   2701 us  >1ms    3  >3ms   0
file-nopresync locked passes held the store lock: min 7.692883ms median 10.754012ms max 12.682405ms
file-nopresync rounds 49  took p50 24.843183ms max 43.459807ms  complete 49  truncated 0  first-pass WAL frames min 2213 max 18078  locked passes 7  backstops 0
file-nopresync appends over 1 ms: 20, of which during a checkpoint round: 8, during its locked pass: 7
file-nopresync appends over 3 ms: 11, of which during a checkpoint round: 8, during its locked pass: 7
== pass 2 memory load 2.79 3.39 3.01
 memory decision append  n   6400  p50    68  p90   121  p99   192  p99.9    320  max   1623 us  >1ms    1  >3ms   0
 memory result append    n   6400  p50    82  p90   137  p99   224  p99.9    498  max   2067 us  >1ms    3  >3ms   0
 memory lease+label read n   6400  p50    40  p90    61  p99    99  p99.9    299  max    830 us  >1ms    0  >3ms   0
 memory rounds 0  took p50 0ns max 0ns  complete 0  truncated 0  first-pass WAL frames min 0 max 0  locked passes 0  backstops 0
 memory appends over 1 ms: 4, of which during a checkpoint round: 0, during its locked pass: 0
 memory appends over 3 ms: 0, of which during a checkpoint round: 0, during its locked pass: 0
```

End to end, per run (`ab.sh`, below; pooled lines as in the table):

```
== before pass 1 load 1.79 1.71 2.17 1/140 16023
  read        run 1  p50  1334.3  p90  1617.9  p99  2926.6  max   24805.4  n   7242  >3/5/10 ms   70   36   21  rps 724.2
  destructive run 1  p50  1227.8  p90  1599.5  p99  2355.2  max   23625.7  n   7682  >3/5/10 ms   46   26   20  rps 768.2
  read        run 2  p50  1305.6  p90  1633.3  p99  2609.2  max   33013.8  n   7223  >3/5/10 ms   60   39   20  rps 722.3
  destructive run 2  p50  1441.8  p90  1735.7  p99  2752.5  max   39616.5  n   6643  >3/5/10 ms   54   29   18  rps 664.3
  read        run 3  p50  1396.7  p90  1703.9  p99  2992.1  max   41353.2  n   6682  >3/5/10 ms   65   29   21  rps 668.2
  destructive run 3  p50  1356.8  p90  1656.8  p99  2676.7  max   45973.5  n   6998  >3/5/10 ms   53   29   19  rps 699.8
  pooled read        n 21147 >3 195 (0.92%) >5 104 (0.49%) >10 62 (0.29%)
  pooled destructive n 21323 >3 153 (0.72%) >5 84 (0.39%) >10 57 (0.27%)
== before pass 2 load 3.04 2.79 2.48 2/178 21181
  read        run 1  p50  1390.6  p90  1718.3  p99  3932.2  max   34078.7  n   6783  >3/5/10 ms  118   41   19  rps 678.3
  destructive run 1  p50  1423.4  p90  1737.7  p99  3905.5  max   32145.4  n   6552  >3/5/10 ms  113   35   16  rps 655.2
  read        run 2  p50  1433.6  p90  1800.2  p99  4436.0  max   47677.4  n   6379  >3/5/10 ms  152   47   17  rps 637.9
  destructive run 2  p50  1452.0  p90  1788.9  p99  4350.0  max   41123.8  n   6321  >3/5/10 ms  139   37   16  rps 632.1
  read        run 3  p50  1420.3  p90  1791.0  p99  4579.3  max   41713.7  n   6382  >3/5/10 ms  150   49   20  rps 638.2
  destructive run 3  p50  1403.9  p90  1738.8  p99  3760.1  max   44236.8  n   6574  >3/5/10 ms  124   38   18  rps 657.4
  pooled read        n 19544 >3 420 (2.15%) >5 137 (0.70%) >10 56 (0.29%)
  pooled destructive n 19447 >3 376 (1.93%) >5 110 (0.57%) >10 50 (0.26%)
== after pass 1 load 1.67 1.69 2.12 1/140 16192
  read        run 1  p50  1331.2  p90  1637.4  p99  2725.9  max   65044.5  n   7248  >3/5/10 ms   61   28    5  rps 724.8
  destructive run 1  p50  1409.0  p90  1720.3  p99  3051.5  max   13049.9  n   6919  >3/5/10 ms   74   31    2  rps 691.9
  read        run 2  p50  1392.6  p90  1684.5  p99  2738.2  max   28901.4  n   7055  >3/5/10 ms   59   26    5  rps 705.5
  destructive run 2  p50  1385.5  p90  1714.2  p99  3067.9  max   18513.9  n   6967  >3/5/10 ms   73   29    6  rps 696.7
  read        run 3  p50  1333.2  p90  1641.5  p99  2361.3  max   25559.0  n   7369  >3/5/10 ms   48   22    9  rps 736.9
  destructive run 3  p50  1236.0  p90  1625.1  p99  2820.1  max   17678.3  n   7703  >3/5/10 ms   75   22    9  rps 770.3
  pooled read        n 21672 >3 168 (0.78%) >5 76 (0.35%) >10 19 (0.09%)
  pooled destructive n 21589 >3 222 (1.03%) >5 82 (0.38%) >10 17 (0.08%)
== after pass 2 load 3.67 2.79 2.46 2/180 20657
  read        run 1  p50  1232.9  p90  1594.4  p99  4849.7  max   26853.4  n   7370  >3/5/10 ms  159   65   13  rps 737.0
  destructive run 1  p50  1250.3  p90  1545.2  p99  5197.8  max   66027.5  n   7231  >3/5/10 ms  203  100   12  rps 723.1
  read        run 2  p50  1178.6  p90  1601.5  p99  5206.0  max   21266.4  n   7284  >3/5/10 ms  264   89   12  rps 728.4
  destructive run 2  p50  1466.4  p90  1809.4  p99  3395.6  max   15392.8  n   6528  >3/5/10 ms   84   32    8  rps 652.8
  read        run 3  p50  1453.1  p90  1844.2  p99  4141.1  max   15695.9  n   6512  >3/5/10 ms  152   32    5  rps 651.2
  destructive run 3  p50  1453.1  p90  1807.4  p99  4378.6  max   36208.6  n   6497  >3/5/10 ms  152   40    9  rps 649.7
  pooled read        n 21166 >3 575 (2.72%) >5 186 (0.88%) >10 30 (0.14%)
  pooled destructive n 20256 >3 439 (2.17%) >5 172 (0.85%) >10 29 (0.14%)
== before_nosigned pass 1 load 1.50 1.62 2.06 1/137 16406
  read        run 1  p50  1232.9  p90  1548.3  p99  2334.7  max   17678.3  n   7809  >3/5/10 ms   46   22   12  rps 780.9
  destructive run 1  p50  1392.6  p90  1685.5  p99  2670.6  max   50724.9  n   6882  >3/5/10 ms   44   17   10  rps 688.2
  read        run 2  p50  1366.0  p90  1698.8  p99  2582.5  max   32620.5  n   7096  >3/5/10 ms   47   15   10  rps 709.6
  destructive run 2  p50  1410.0  p90  1720.3  p99  3375.1  max   39714.8  n   6685  >3/5/10 ms   83   29   12  rps 668.5
  read        run 3  p50  1369.1  p90  1753.1  p99  2644.0  max   51707.9  n   6897  >3/5/10 ms   48   20   10  rps 689.7
  destructive run 3  p50  1313.8  p90  1649.7  p99  2805.8  max   45744.1  n   7193  >3/5/10 ms   62   24    8  rps 719.3
  pooled read        n 21802 >3 141 (0.65%) >5 57 (0.26%) >10 32 (0.15%)
  pooled destructive n 20760 >3 189 (0.91%) >5 70 (0.34%) >10 30 (0.14%)
== before_nosigned pass 2 load 4.66 2.56 2.36 5/160 19711
  read        run 1  p50  1182.7  p90  1477.6  p99  5103.6  max   25165.8  n   7553  >3/5/10 ms  221   82   13  rps 755.3
  destructive run 1  p50  1183.7  p90  1496.1  p99  5337.1  max   37224.4  n   7261  >3/5/10 ms  305   99   11  rps 726.1
  read        run 2  p50  1163.3  p90  1466.4  p99  5382.1  max   46628.9  n   7369  >3/5/10 ms  250  102   11  rps 736.9
  destructive run 2  p50  1146.9  p90  1470.5  p99  5308.4  max   56066.0  n   7369  >3/5/10 ms  271  115    9  rps 736.9
  read        run 3  p50  1160.2  p90  1461.2  p99  5414.9  max   52559.9  n   7297  >3/5/10 ms  263   98   10  rps 729.7
  destructive run 3  p50  1129.5  p90  1395.7  p99  5222.4  max   51544.1  n   7603  >3/5/10 ms  216   96   12  rps 760.3
  pooled read        n 22219 >3 734 (3.30%) >5 282 (1.27%) >10 34 (0.15%)
  pooled destructive n 22233 >3 792 (3.56%) >5 310 (1.39%) >10 32 (0.14%)
```

Raw host probes, both passes:

```
== pass 1 load 1.59 1.96 2.41
jitter n=10000 p50=98 p90=141 p99=210 p999=640 max=4732 us  >1ms=5 >3ms=1 >4ms=1  (6.1 s)
fsync n=5000 p50=85 p90=117 p99=196 p999=383 max=916 us  >1ms=0 >3ms=0 >4ms=0  (0.5 s)
fsync_append n=2000 p50=299 p90=420 p99=745 p999=10998 max=11334 us  >1ms=14 >3ms=7 >4ms=7  (0.7 s)
none               commits   9314  write p50   34 p99    82 p99.9    290 max    662 us  >1ms   0 >3ms   0 | B ops  36 p50      1 max      2 us
fsync_same         commits   8863  write p50   35 p99    89 p99.9   2951 max  16348 us  >1ms  10 >3ms   8 | B ops  34 p50  21994 max  31844 us
fsync_other        commits   9272  write p50   32 p99    90 p99.9    294 max   3376 us  >1ms   1 >3ms   1 | B ops  36 p50  16729 max  22369 us
none_reuse         commits   9603  write p50   17 p99    49 p99.9    133 max    870 us  >1ms   0 >3ms   0 | B ops  37 p50      2 max      2 us
fsync_same_reuse   commits   9560  write p50   19 p99    52 p99.9    165 max   1553 us  >1ms   2 >3ms   0 | B ops  37 p50  20829 max  23311 us
== pass 2 load 0.81 1.70 2.30
jitter n=10000 p50=102 p90=149 p99=228 p999=1281 max=13814 us  >1ms=12 >3ms=3 >4ms=3  (6.1 s)
fsync n=5000 p50=121 p90=176 p99=300 p999=1114 max=1580 us  >1ms=6 >3ms=0 >4ms=0  (0.7 s)
fsync_append n=2000 p50=444 p90=640 p99=1381 p999=14079 max=14836 us  >1ms=37 >3ms=7 >4ms=7  (1.1 s)
none               commits   9240  write p50   35 p99    89 p99.9    426 max   3058 us  >1ms   3 >3ms   1 | B ops  36 p50      2 max      3 us
fsync_same         commits   9025  write p50   33 p99    82 p99.9    691 max   9110 us  >1ms   5 >3ms   4 | B ops  35 p50  21802 max  25491 us
fsync_other        commits   9358  write p50   32 p99    78 p99.9    193 max   1660 us  >1ms   2 >3ms   0 | B ops  36 p50  16937 max  22930 us
none_reuse         commits   9609  write p50   17 p99    48 p99.9    158 max   1859 us  >1ms   1 >3ms   0 | B ops  37 p50      1 max      2 us
fsync_same_reuse   commits   9600  write p50   18 p99    52 p99.9    199 max   2301 us  >1ms   3 >3ms   0 | B ops  37 p50  20136 max  23858 us
```

## Rerun

```
# Release builds as above (lto and codegen units as in the other 2026-10-24 files).
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
cargo build --release -p attenuo-bench -p attenuo-server
cargo build --release -p attenuo-proxy --features testing --example fake_mcp

# In process: before and after on one build, one configuration per process.
cargo test --release -p attenuo-audit --test single_client_outliers --no-run
for c in memory file-nopresync file parked signed-nopresync signed; do
  PROBE_CONFIGS=$c PROBE_ROUNDS=8 target/release/deps/single_client_outliers-* --ignored --nocapture
done
PROBE_CONFIGS=signed-lead32 PROBE_ROUNDS=8 target/release/deps/single_client_outliers-* --ignored --nocapture

# End to end: a directory per server build (attenuo-server and fake_mcp), variants alternated.
attenuo-bench hot-path --configs baseline --runs 3 --bin-dir BEFORE_DIR
attenuo-bench hot-path --configs baseline --runs 3 --bin-dir AFTER_DIR
attenuo-bench hot-path --configs baseline --runs 3 --bin-dir BEFORE_DIR --audit-set checkpoint_every=0
# (then the same three in reverse order)

# Raw host probes (the two C files below, in one directory; DIR on the disk under test).
gcc -O2 -o fsync_probe fsync_probe.c && gcc -O2 -pthread -o wal_sim wal_sim.c
./fsync_probe jitter 10000; ./fsync_probe fsync 5000 DIR; ./fsync_probe fsync_append 2000 DIR
for m in none fsync_same fsync_other none_reuse fsync_same_reuse; do ./wal_sim $m 8 DIR; done
```

`fsync_probe.c`:

```c
// fsync_probe MODE N DIR
// fsync:        rewrite 4 KiB in a 1 MiB file, then fdatasync; time each.
// fsync_append: append 64 KiB then fdatasync, truncating to 0 every 256 iterations (WAL-like).
// append:       append 60 KiB without sync, 500 us apart, truncate every 512 (WAL at NORMAL).
// jitter:       sleep 500 us; record the overshoot (wake-up latency).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
static double now_us(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e6+t.tv_nsec/1e3;}
static int cmp(const void*a,const void*b){double x=*(const double*)a,y=*(const double*)b;return x<y?-1:x>y;}
static void report(const char*name,double*v,int n,double secs){
  qsort(v,n,sizeof(double),cmp);
  int o1=0,o3=0,o4=0; for(int i=0;i<n;i++){if(v[i]>1000)o1++; if(v[i]>3000)o3++; if(v[i]>4000)o4++;}
  printf("%s n=%d p50=%.0f p90=%.0f p99=%.0f p999=%.0f max=%.0f us  >1ms=%d >3ms=%d >4ms=%d  (%.1f s)\n",name,n,
   v[n/2],v[n*9/10],v[n*99/100],v[n*999/1000],v[n-1],o1,o3,o4,secs);
}
int main(int argc,char**argv){
  if(argc<3){fprintf(stderr,"usage\n");return 2;}
  const char*mode=argv[1]; int n=atoi(argv[2]); const char*dir=argc>3?argv[3]:".";
  double*v=calloc(n,sizeof(double)); char path[4096]; snprintf(path,sizeof path,"%s/probe.dat",dir);
  static char buf[65536]; memset(buf,'x',sizeof buf);
  double t0=now_us();
  if(!strcmp(mode,"fsync")||!strcmp(mode,"write")){
    int fd=open(path,O_RDWR|O_CREAT|O_TRUNC,0644);
    for(int i=0;i<256;i++) if(pwrite(fd,buf,4096,(off_t)i*4096)<0) return 1;
    fsync(fd);
    int sync=!strcmp(mode,"fsync");
    for(int i=0;i<n;i++){double a=now_us(); if(pwrite(fd,buf,4096,(off_t)(i%256)*4096)<0) return 1; if(sync) fdatasync(fd); v[i]=now_us()-a;}
    close(fd);
  } else if(!strcmp(mode,"fsync_append")){
    int fd=open(path,O_RDWR|O_CREAT|O_TRUNC,0644); off_t off=0;
    for(int i=0;i<n;i++){double a=now_us(); if(i%256==0){if(ftruncate(fd,0))return 1;off=0;} if(pwrite(fd,buf,65536,off)<0) return 1; off+=65536; fdatasync(fd); v[i]=now_us()-a;}
    close(fd);
  } else if(!strcmp(mode,"append")){
    int fd=open(path,O_RDWR|O_CREAT|O_TRUNC,0644); off_t off=0;
    for(int i=0;i<n;i++){double a=now_us(); if(pwrite(fd,buf,61440,off)<0) return 1; off+=61440; v[i]=now_us()-a; if(i%512==511){if(ftruncate(fd,0))return 1;off=0;} usleep(500);}
    close(fd);
  } else if(!strcmp(mode,"jitter")){
    for(int i=0;i<n;i++){double a=now_us(); usleep(500); v[i]=now_us()-a-500;}
  } else { fprintf(stderr,"unknown mode\n"); return 2; }
  report(mode,v,n,(now_us()-t0)/1e6);
  unlink(path); return 0;
}
```

`wal_sim.c`:

```c
// wal_sim MODE SECONDS DIR
// Thread A (the "writer"): every 700 us writes 15 frames of 4120 bytes (a WAL commit at
// synchronous=NORMAL, no sync) and times the write. Thread B (the "checkpointer") every
// 256 commits does, by MODE:
//   none        nothing
//   fsync_same  fdatasync the file A writes (the PASSIVE checkpoint's WAL sync)
//   fsync_other writes as many bytes to another file and fdatasyncs that
// A's file either grows (append; truncated to 0 when it passes 64 MB, as a TRUNCATE would)
// or, with suffix _reuse, wraps at 16 MB inside a preallocated file (a restarted WAL).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
static double now_us(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e6+t.tv_nsec/1e3;}
static int cmp(const void*a,const void*b){double x=*(const double*)a,y=*(const double*)b;return x<y?-1:x>y;}
static int fd, ofd; static atomic_long commits; static atomic_int stop; static const char*mode;
static double bsync[100000]; static int nb;
static void* checkpointer(void*arg){
  (void)arg; long last=0; static char big[1<<20]; memset(big,'y',sizeof big);
  while(!stop){
    long c=atomic_load(&commits);
    if(c-last>=256){ last=c; double a=now_us();
      if(strstr(mode,"fsync_same")) fdatasync(fd);
      else if(strstr(mode,"fsync_other")){ for(int i=0;i<15;i++) if(write(ofd,big,sizeof big)<0) break; fdatasync(ofd); lseek(ofd,0,SEEK_SET);}
      if(nb<100000) bsync[nb++]=now_us()-a;
    }
    usleep(1000);
  }
  return 0;
}
int main(int argc,char**argv){
  mode=argv[1]; double secs=atof(argv[2]); const char*dir=argv[3];
  char p[4096]; snprintf(p,sizeof p,"%s/wal_sim.wal",dir); fd=open(p,O_RDWR|O_CREAT|O_TRUNC,0644);
  snprintf(p,sizeof p,"%s/wal_sim.other",dir); ofd=open(p,O_RDWR|O_CREAT|O_TRUNC,0644);
  int reuse=strstr(mode,"_reuse")!=0; off_t wrap=reuse?(16<<20):(64<<20);
  static char frame[15*4120]; memset(frame,'x',sizeof frame);
  if(reuse){ for(off_t o=0;o<wrap;o+=sizeof frame) if(pwrite(fd,frame,sizeof frame,o)<0) return 1; fsync(fd);}
  pthread_t t; pthread_create(&t,0,checkpointer,0);
  int cap=(int)(secs*2000); double*v=calloc(cap,sizeof(double)); int n=0; off_t off=0;
  double end=now_us()+secs*1e6;
  while(now_us()<end && n<cap){
    if(off+(off_t)sizeof frame>wrap){ if(!reuse){ if(ftruncate(fd,0)) return 1;} off=0; }
    double a=now_us(); if(pwrite(fd,frame,sizeof frame,off)<0) return 1; v[n++]=now_us()-a; off+=sizeof frame;
    atomic_fetch_add(&commits,1); usleep(700);
  }
  stop=1; pthread_join(t,0);
  qsort(v,n,sizeof(double),cmp); int o1=0,o3=0; for(int i=0;i<n;i++){if(v[i]>1000)o1++; if(v[i]>3000)o3++;}
  qsort(bsync,nb,sizeof(double),cmp);
  printf("%-18s commits %6d  write p50 %4.0f p99 %5.0f p99.9 %6.0f max %6.0f us  >1ms %3d >3ms %3d | B ops %3d p50 %6.0f max %6.0f us\n",
    mode,n,v[n/2],v[n*99/100],v[n*999/1000],v[n-1],o1,o3,nb,nb?bsync[nb/2]:0,nb?bsync[nb-1]:0);
  snprintf(p,sizeof p,"%s/wal_sim.wal",dir); unlink(p); snprintf(p,sizeof p,"%s/wal_sim.other",dir); unlink(p);
  return 0;
}
```

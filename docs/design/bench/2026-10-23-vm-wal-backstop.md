# WAL backstop pause, 2026-10-23, vm (perf/wal-backstop-pause)

Base `main` @ `034fd5c`, release profile, rustc 1.99.1 (58cf8f9c3 2026-10-13), rusqlite 0.40 with bundled SQLite (`libsqlite3-sys` 0.38.2). `durability = "normal"`, SQLite's default 4 KiB page, temp directory on ext4 (`/dev/vda`).

Shared 4-vCPU development container (Intel Xeon @ 2.10GHz, 15 GB RAM, Linux 6.18.44); nothing else was running during the measurement (load average 0.1 before the first run, 1.2 to 2.8 from these runs themselves). Indicative, not a reference machine. Summary and reading in [performance](../performance.md#backstop-pause-measured-2026-10-23).

## What the test does

`wal_backstop_pause` (ignored) in `crates/attenuo-audit/tests/wal.rs`:

1. **Phase 1.** Opens a file store with WAL checkpoints (5 s interval), parks the background checkpointer with `SqliteAudit::park_wal_checkpointer` (it holds the checkpointer's connection lock, as the unit test `the_writer_checkpoints_itself_when_the_background_thread_cannot` does), and appends the test record one at a time, timing each `append`, until the writer's backstop has fired three times. A fire is seen as the WAL file shrinking by more than half right after an append; that append's latency is the trigger latency. `TRUNCATE ms` is the backstop's own checkpoint time from `SqliteAudit::wal_timings`.
2. **Phase 2.** Drops that store, opens a fresh one with the checkpointer running, and runs eight appending threads (the load of `the_wal_stays_bounded_under_continuous_load`) until the background thread has made three locked passes, timing every append. `store lock held ms` is how long a locked pass held the store's connection (and so every append) for its final `PASSIVE`; `WAL frames` is what that `PASSIVE` reported.

Both hooks are `#[doc(hidden)]` and exist only with `cfg(test)` or the crate's `testing` feature, which the crate's own integration tests enable through a dev-dependency on itself (the pattern `attenuo-proxy` uses). The product build is unchanged.

## How to rerun

```
nproc; uptime
cargo test -p attenuo-audit --release --test wal -- --ignored wal_backstop_pause --nocapture
```

The 2-core check of the backstop under the bounded-WAL test (the `largest WAL` line counts locked passes and writer backstops):

```
cargo test -p attenuo-audit --release --test wal --no-run
taskset -c 0,1 yes > /dev/null & taskset -c 0,1 yes > /dev/null &
for r in 1 2 3 4 5; do
  taskset -c 0,1 cargo test -p attenuo-audit --release --test wal -- the_wal_stays_bounded --nocapture 2>&1 | grep largest
done
kill %1 %2
```

Drop `--release` for the debug figures.

## Raw output, `wal_backstop_pause`, three runs

```
 21:16:27 up  3:39,  0 user,  load average: 2.84, 1.79, 1.38
phase 1, checkpointer parked, 1 writer: 11217 appends in 2.0 s
| fire | WAL before | trigger append ms | TRUNCATE ms |
|---|---|---|---|
| 1 | 128 MB | 358.69 | 358.60 |
| 2 | 128 MB | 384.79 | 384.70 |
| 3 | 128 MB | 356.68 | 356.62 |
the other 11214 appends: p50 0.07 ms, p99 0.18 ms, max 5.28 ms
phase 2, checkpointer running, 8 writers: 12507 appends in 0.9 s, 1 writer backstops
| locked pass | WAL frames | store lock held ms |
|---|---|---|
| 1 | 42 | 2.26 |
| 2 | 29155 | 27.55 |
| 3 | 29155 | 0.00 |
writer backstop: TRUNCATE 123.04 ms
appends: p50 0.38 ms, p99 2.70 ms, max 124.38 ms

 21:16:30 up  3:39,  0 user,  load average: 2.84, 1.79, 1.38
phase 1, checkpointer parked, 1 writer: 11227 appends in 1.8 s
| fire | WAL before | trigger append ms | TRUNCATE ms |
|---|---|---|---|
| 1 | 128 MB | 327.74 | 327.68 |
| 2 | 128 MB | 335.43 | 335.37 |
| 3 | 128 MB | 322.88 | 322.77 |
the other 11224 appends: p50 0.06 ms, p99 0.16 ms, max 2.16 ms
phase 2, checkpointer running, 8 writers: 11580 appends in 0.7 s, 0 writer backstops
| locked pass | WAL frames | store lock held ms |
|---|---|---|
| 1 | 29032 | 23.32 |
| 2 | 29032 | 0.00 |
| 3 | 26579 | 26.04 |
| 4 | 26579 | 0.00 |
appends: p50 0.39 ms, p99 1.20 ms, max 27.04 ms

 21:16:33 up  3:39,  0 user,  load average: 2.77, 1.79, 1.38
phase 1, checkpointer parked, 1 writer: 11252 appends in 1.9 s
| fire | WAL before | trigger append ms | TRUNCATE ms |
|---|---|---|---|
| 1 | 128 MB | 416.47 | 416.41 |
| 2 | 128 MB | 325.56 | 325.47 |
| 3 | 128 MB | 331.60 | 331.54 |
the other 11249 appends: p50 0.06 ms, p99 0.17 ms, max 1.76 ms
phase 2, checkpointer running, 8 writers: 13168 appends in 1.0 s, 1 writer backstops
| locked pass | WAL frames | store lock held ms |
|---|---|---|
| 1 | 31862 | 23.92 |
| 2 | 31862 | 0.00 |
| 3 | 35 | 2.11 |
writer backstop: TRUNCATE 132.39 ms
appends: p50 0.38 ms, p99 1.14 ms, max 177.06 ms
```

A locked pass that reports the same frame count as the one before it and 0.00 ms found the WAL already fully copied (no commit had restarted it yet). Earlier exploratory runs of the same test, before phase 2 got its own store, gave the same picture: trigger appends 348 to 622 ms (the 622 ms was the first fire of the first run on a cold file), backstops under load 133 to 161 ms, locked passes 27 to 42 ms (output not kept).

## Summary

| Pause | Measured |
|---|---|
| Trigger append, backstop with the checkpointer parked | 323 to 416 ms, median 335 ms (9 fires) |
| Other appends, same runs (1 writer) | p50 0.06 to 0.07 ms, p99 0.16 to 0.18 ms, max 1.8 to 5.3 ms |
| Backstop under 8 writers, checkpointer running | 123, 132 ms (fired in 2 of 3 runs) |
| Locked pass at 64 MB, 8 writers | 23.3, 23.9, 26.0, 27.6 ms; 1.4 to 2.8 ms with little left |
| Appends under 8 writers | p50 0.38 to 0.39 ms, p99 1.1 to 2.7 ms, max 27 to 177 ms |

## Does the backstop fire under the bounded-WAL test?

`the_wal_stays_bounded_under_continuous_load` (8 writers, 24,000 appends), one line per run.

| Build | CPUs | Burners | Peak WAL (MB) | Runs with a backstop |
|---|---|---|---|---|
| release | 4 | none | 128.8, 128.8, 128.8 | 3 of 3 (2, 3, 1 fires) |
| release | 2 (`taskset -c 0,1`) | 2 x `yes` on the same CPUs | 109.2, 128.8, 99.9, 116.5, 125.5 | 1 of 5 |
| debug | 4 | none | 86.9, 87.5, 128.8 | 1 of 3 |
| debug | 2 (`taskset -c 0,1`) | 2 x `yes` on the same CPUs | 100.4, 99.7, 85.2, 89.1, 96.0 | 0 of 5 |

```
release, 4 CPUs:
largest WAL: 131900 KiB; locked passes: 4; writer backstops: 2
largest WAL: 131920 KiB; locked passes: 3; writer backstops: 3
largest WAL: 131888 KiB; locked passes: 5; writer backstops: 1
release, 2 CPUs + 2 burners (load average 1.16 at start):
largest WAL: 111827 KiB; locked passes: 7; writer backstops: 0
largest WAL: 131928 KiB; locked passes: 5; writer backstops: 1
largest WAL: 102287 KiB; locked passes: 8; writer backstops: 0
largest WAL: 119290 KiB; locked passes: 5; writer backstops: 0
largest WAL: 128544 KiB; locked passes: 5; writer backstops: 0
debug, 4 CPUs:
largest WAL: 89010 KiB; locked passes: 5; writer backstops: 0
largest WAL: 89634 KiB; locked passes: 5; writer backstops: 0
largest WAL: 131868 KiB; locked passes: 5; writer backstops: 1
debug, 2 CPUs + 2 burners (load average 2.09 at start):
largest WAL: 102859 KiB; locked passes: 5; writer backstops: 0
largest WAL: 102134 KiB; locked passes: 5; writer backstops: 0
largest WAL: 87280 KiB; locked passes: 5; writer backstops: 0
largest WAL: 91191 KiB; locked passes: 6; writer backstops: 0
largest WAL: 98272 KiB; locked passes: 5; writer backstops: 0
```

Fewer CPUs did not make it fire more here: with the burners on the same two CPUs the writers slow down as much as the checkpointer does. What makes it fire is append speed: the release build's writers outrun the background thread's catch-up passes more often than the debug build's.

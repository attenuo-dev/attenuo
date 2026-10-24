# The SR-55 run lock under concurrent clients (2026-10-24)

Branch `perf/run-lock-cost`, main `e04b516`. What `Pipeline::run_guard` (security pass 5, SR-55) costs: one of 64 striped `std::sync::Mutex`es, chosen by the run's `chain_id`, held from the budget read to the end of the charge for every call that matches a limited hop or keeps run usage. See [performance](../performance.md#the-sr-55-run-lock-under-concurrent-clients-2026-10-24).

## Method

- Binaries: **after** is main `e04b516`; **before** is `84b9578`, the parent of `c05674b` (the SR-55 commit), built in a second worktree with its own target dir; **narrow** (second series only) is main with the lock taken later, after the label read, argument taint and approval take, just before the budget read (not kept, see below). All release, `lto = false`, `codegen-units = 16`, rustc 1.99.1, as the earlier runs. The bench binary and `fake_mcp` are the same for all of them (this branch's).
- `attenuo-bench hot-path --runs 1 --duration 10 --warmup 2 --cells destructive --configs baseline,limits_calls,usage --clients C --tokens T --bin-dir <binary>`. File store at `durability = "normal"`, 2-hop token, the `destructive` cell (`create_issue`). `baseline` takes no lock in any binary; `limits_calls` (a `calls` limit in both hops) takes the lock and charges 2 counters; `usage` (`track_usage = true`, no limit) takes the lock and writes run usage.
- `--tokens` is new on this branch: T root tokens, each its own run, client i on run i mod T. C/T = 8/1 and 32/1 put every client on one run; 8/8 and 32/32 give each client its own run.
- Interleaving: each invocation is one run of all three configurations on one binary; the binaries alternate within each run and client count. Pass 1: runs 1 to 5, combinations 8/1, 32/1, 8/8, 32/32, binaries after then before (then narrow then before in series 2), configurations `baseline,limits_calls,usage`. Pass 2: everything reversed. Series 1 (16:42 to 17:34 UTC) compared after and before; series 2 (17:37 to 18:53 UTC) compared after, narrow and before.
- Host: the shared 4-vCPU VM. Another agent's fuzz campaign (four to five fuzzers at full CPU) and builds ran throughout. Load average (1 min, sampled every 15 s): 4.7 to 12.4 in series 1, 3.4 to 12.6 in series 2. The load generator, three servers and their upstreams share the four cores.
- Where the lock wait shows: the lock is taken after the lease check, inside the `policy` stage's timer, so `policy` mean includes it. "unstaged" is the decision time outside lease check, policy and audit append: the charge transaction plus about 27 us of record building.

## How large the noise is

`baseline` takes no lock in any binary, so its difference between binaries is noise: from -17 to +13 percent in req/s between binaries in the same pass (series 2, 8 clients). Differences in throughput under about 15 percent between two binaries are not resolved on this host at this load. The `policy` stage mean resolves the lock wait directly, because it moves by milliseconds.

## Summary

Throughput change, after against before, per pass (pass 1 / pass 2), and the `policy` stage mean (which includes the lock wait):

| clients / runs | config | series 1 req/s | series 2 req/s | `policy` mean before | `policy` mean after |
|---|---|---|---|---|---|
| 8 / 1 | `baseline` (no lock) | -4 / +9 % | -17 / -5 % | 0.52 to 0.58 ms | 0.53 to 0.63 ms |
| 8 / 1 | `limits_calls` | -10 / -11 % | -10 / -14 % | 0.87 to 0.96 ms | 2.8 to 3.9 ms |
| 8 / 1 | `usage` | -4 / -7 % | -3 / -5 % | 0.87 to 0.97 ms | 2.6 to 3.3 ms |
| 32 / 1 | `baseline` (no lock) | -3 / -7 % | +4 / 0 % | 2.3 to 2.4 ms | 2.3 to 2.4 ms |
| 32 / 1 | `limits_calls` | -22 / -15 % | -2 / -4 % | 3.6 to 4.3 ms | 21.9 to 25.6 ms |
| 32 / 1 | `usage` | -15 / -8 % | -4 / +4 % | 3.6 to 4.2 ms | 20.6 to 22.4 ms |
| 8 / 8 | `baseline` (no lock) | +11 / 0 % | -11 / -8 % | 0.57 to 0.59 ms | 0.60 to 0.67 ms |
| 8 / 8 | `limits_calls` | -11 / -9 % | -17 / -11 % | 0.93 to 0.98 ms | 1.10 to 1.18 ms |
| 8 / 8 | `usage` | 0 / -6 % | -12 / +2 % | 0.96 to 0.99 ms | 0.98 to 1.14 ms |
| 32 / 32 | `baseline` (no lock) | -3 / -4 % | 0 / +1 % | 2.6 to 3.0 ms | 2.6 to 2.9 ms |
| 32 / 32 | `limits_calls` | -3 / -3 % | -5 / -5 % | 4.0 to 4.5 ms | 4.3 to 4.9 ms |
| 32 / 32 | `usage` | -5 / +5 % | -4 / -4 % | 3.9 to 4.5 ms | 3.9 to 4.7 ms |

Where the time goes at 32 clients on one run, series 2, means in ms (pass 1 / pass 2):

| | before | after | narrow |
|---|---|---|---|
| `limits_calls` req/s | 1,196 / 1,186 | 1,167 / 1,134 | 1,154 / 1,150 |
| client p50 / p90 | 22.6 / 32.1; 22.1 / 32.0 | 23.4 / 40.3; 23.1 / 43.8 | 22.9 / 41.3; 23.2 / 42.3 |
| whole decision | 16.7 / 16.7 | 23.7 / 24.8 | 23.6 / 23.3 |
| `policy` (lock wait, Cedar) | 4.3 / 4.2 | 21.9 / 22.9 | 20.9 / 20.7 |
| unstaged (the charge) | 4.9 / 4.9 | 0.43 / 0.45 | 0.71 / 0.71 |
| `audit_append` | 7.2 / 7.4 | 1.3 / 1.2 | 1.8 / 1.8 |
| `response` (result append) | 7.3 / 7.0 | 1.9 / 1.7 | 2.2 / 2.4 |
| handler `total` | 25.7 / 25.4 | 26.9 / 27.7 | 26.8 / 26.8 |

## Readings

- **One run, many clients: the lock moves the queue more than it lengthens it.** Before SR-55, 32 clients of one run waited for the file's write gate: 4.9 ms in the charge, 7.2 to 7.4 ms in the decision append and 7.0 to 7.3 ms in the result append. With the lock they wait 18 to 22 ms for it, and then the charge (0.4 ms), the append (1.2 to 1.8 ms) and the result append (1.7 to 1.9 ms) find the gate nearly free. The handler's total grows by 5 to 9 percent for `limits_calls` (25.4 to 25.7 ms against 26.9 to 27.7 ms) and 3 to 7 percent for `usage`.
- **Throughput at 32 clients on one run** changed by +4 to -22 percent over the four passes: median -9.5 percent for `limits_calls` and -6 percent for `usage` (series 1 at the higher load gave the larger losses). The client p90 grew by 24 to 37 percent in series 2 (32 ms to 40 to 44 ms) while p50 stayed within 1 ms; one queue for the lock spreads waits more than the write gate's FIFO did.
- **At 8 clients on one run** the lock wait is 2 to 3 ms per call and `limits_calls` lost 10 to 14 percent in all four passes, `usage` 3 to 7 percent. Both are inside the noise band `baseline` shows.
- **The ceiling for one run** is about one decision per lock hold: 1 / (about 0.85 to 1.0 ms) here, the budget read, Cedar and the charge (the charge waits for the gate behind the audit writer's batch). On this host the whole server saturates near the same rate, so the ceiling costs little; on a larger host one run's limited or usage-tracked calls would stay near it while other runs scale.
- **Many runs do not wait on each other.** With 8 and 32 runs the `policy` stage grows by 0.02 to 0.7 ms against 18 to 22 ms for one run, so no measurable lock wait. Throughput changes of -17 to +5 percent there are the binaries' noise: `baseline`, with no lock, moved by -11 to +11 percent in the same passes, and at 8 runs `limits_calls` lost its time in the charge and the appends, not in `policy`. The before binary also lacks SR-62's new index on the charge log, which every charge writes; that was not separated.
- **Narrowing the guarded region (candidate a) is not a clear win.** With the lock taken after the label read, argument taint and approval take (the approval take is a write transaction, so a wait for the gate), the lock wait falls by about 1 ms at 8 clients and 1 to 2 ms at 32, but the time reappears in the charge, the appends and the approval take: req/s against main moved -1 to +3 percent at 32 clients on one run, and +22 / -3 percent (`limits_calls`) and +13 / -6 percent (`usage`) at 8 clients. A `parking_lot` mutex (b) would change the lock's own cost, which is not where the time is (the hold is), and per-chain locks (c) address collisions, which do not show. None was kept.

## Stripe collisions (analytic, not measured)

With 64 stripes and N runs hashed uniformly, a given run shares its stripe with another with probability 1 - (63/64)^(N-1): 1.6 percent at N = 2, 10 percent at 8, 39 percent at 32, 63 percent at 64. The expected number of colliding pairs is N(N-1)/128: 0.44 at 8 runs and 7.75 at 32. A collision costs a wait only when two runs' budgeted decisions overlap in time, and each holds the lock for about 0.1 to 1 ms. The 32-run cells, where about 39 percent of runs share a stripe, show no lock wait in the `policy` stage, so collisions were not measured separately.

## Rerun

```
cargo build --release -p attenuo-bench -p attenuo-server
cargo build --release -p attenuo-proxy --features testing --example fake_mcp
git worktree add --detach ../pre-sr55 c05674b^   # then build attenuo-server there with its own CARGO_TARGET_DIR
attenuo-bench hot-path --bin-dir <dir with attenuo-server and fake_mcp> --runs 1 --duration 10 --warmup 2 \
    --cells destructive --configs baseline,limits_calls,usage --clients 32 --tokens 1 --json out.json
```

with `--clients 8,32` and `--tokens 1` or equal to `--clients`, alternating binaries per run, then a second pass in reverse order. The committed JSON has, per series, binary, pass, client count, runs and configuration: the medians of the five runs' p50, p90, p99 and req/s, each run's req/s and p50 and load average, and the server stage means pooled over the runs.

## Full tables

Medians of 5 runs' client figures (us, req/s) and pooled server means (us), pass 1 / pass 2. "runs" is `--tokens`.

### Series 1: after against before

| clients | runs | config | binary | p50 | p90 | p99 | req/s | decide | `policy` mean (p50) | unstaged | `audit_append` | `lease_check` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 1 | baseline | before | 4,641 / 3,924 | 7,868 / 6,521 | 18,645 / 19,218 | 1,533 / 1,774 | 1,697 / 1,731 | 575 / 551 (376 / 413) | 29 / 26 | 970 / 1,047 | 123 / 106 |
| 8 | 1 | baseline | after | 4,407 / 3,467 | 8,675 / 5,820 | 21,266 / 19,808 | 1,471 / 1,938 | 1,651 / 1,894 | 550 / 627 (392 / 436) | 29 / 26 | 957 / 1,133 | 117 / 109 |
| 8 | 1 | limits_calls | before | 6,304 / 5,628 | 10,986 / 8,946 | 25,100 / 27,083 | 1,047 / 1,151 | 3,452 / 3,940 | 907 / 962 (683 / 714) | 751 / 907 | 1,649 / 1,939 | 145 / 132 |
| 8 | 1 | limits_calls | after | 6,652 / 5,824 | 12,198 / 10,068 | 29,934 / 26,952 | 942 / 1,030 | 4,606 / 5,504 | 2,794 / 3,936 (2,112 / 2,998) | 474 / 469 | 1,183 / 976 | 156 / 123 |
| 8 | 1 | usage | before | 6,521 / 5,513 | 10,748 / 8,438 | 27,836 / 27,132 | 1,016 / 1,150 | 3,649 / 4,229 | 969 / 964 (732 / 691) | 834 / 901 | 1,698 / 2,231 | 148 / 133 |
| 8 | 1 | usage | after | 6,894 / 6,013 | 11,788 / 10,273 | 26,902 / 24,625 | 975 / 1,071 | 4,234 / 4,720 | 2,579 / 3,303 (1,830 / 2,322) | 453 / 396 | 1,050 / 901 | 153 / 120 |
| 32 | 1 | baseline | before | 15,032 / 12,403 | 23,872 / 19,808 | 58,491 / 61,276 | 1,886 / 2,221 | 6,803 / 6,500 | 2,336 / 2,245 (1,744 / 1,677) | 29 / 28 | 4,272 / 4,074 | 166 / 153 |
| 32 | 1 | baseline | after | 15,532 / 12,771 | 24,494 / 21,529 | 57,672 / 55,574 | 1,836 / 2,070 | 6,825 / 7,024 | 2,313 / 2,268 (1,750 / 1,816) | 28 / 28 | 4,332 / 4,571 | 152 / 158 |
| 32 | 1 | limits_calls | before | 21,168 / 19,923 | 33,686 / 30,917 | 145,490 / 151,781 | 1,232 / 1,319 | 14,063 / 14,943 | 3,569 / 3,839 (2,958 / 2,903) | 3,429 / 4,128 | 6,862 / 6,773 | 202 / 205 |
| 32 | 1 | limits_calls | after | 30,474 / 24,510 | 49,775 / 43,254 | 164,889 / 185,860 | 964 / 1,119 | 27,828 / 24,619 | 25,583 / 22,118 (24,391 / 18,499) | 564 / 507 | 1,489 / 1,810 | 191 / 185 |
| 32 | 1 | usage | before | 22,233 / 21,709 | 33,161 / 31,130 | 150,733 / 149,160 | 1,236 / 1,262 | 14,443 / 15,307 | 3,564 / 3,884 (3,190 / 3,299) | 3,861 / 4,329 | 6,808 / 6,891 | 210 / 203 |
| 32 | 1 | usage | after | 27,984 / 23,724 | 46,006 / 40,862 | 152,830 / 172,491 | 1,048 / 1,161 | 24,768 / 23,049 | 22,414 / 20,640 (22,063 / 17,146) | 512 / 458 | 1,650 / 1,793 | 192 / 158 |
| 8 | 8 | baseline | before | 4,682 / 4,012 | 8,106 / 6,783 | 21,987 / 22,069 | 1,437 / 1,652 | 1,813 / 1,755 | 594 / 590 (387 / 442) | 28 / 27 | 1,065 / 1,023 | 125 / 114 |
| 8 | 8 | baseline | after | 4,387 / 3,459 | 7,201 / 5,620 | 21,873 / 21,905 | 1,600 / 1,650 | 1,741 / 1,943 | 595 / 651 (403 / 447) | 27 / 27 | 1,008 / 1,156 | 111 / 110 |
| 8 | 8 | limits_calls | before | 6,742 / 5,780 | 11,231 / 9,314 | 31,228 / 27,820 | 974 / 1,118 | 3,903 / 3,704 | 977 / 945 (755 / 742) | 853 / 880 | 1,926 / 1,738 | 147 / 141 |
| 8 | 8 | limits_calls | after | 7,090 / 5,812 | 11,796 / 8,675 | 41,878 / 42,467 | 867 / 1,014 | 4,451 / 4,488 | 1,128 / 1,185 (807 / 826) | 998 / 975 | 2,164 / 2,180 | 162 / 149 |
| 8 | 8 | usage | before | 6,353 / 5,304 | 10,732 / 8,659 | 30,802 / 36,209 | 985 / 1,071 | 3,814 / 4,211 | 987 / 990 (753 / 723) | 805 / 1,137 | 1,884 / 1,956 | 138 / 128 |
| 8 | 8 | usage | after | 6,902 / 5,304 | 11,174 / 8,446 | 32,129 / 38,175 | 982 / 1,007 | 4,167 / 4,214 | 1,141 / 1,014 (858 / 764) | 911 / 951 | 1,957 / 2,115 | 158 / 134 |
| 32 | 32 | baseline | before | 14,934 / 14,139 | 27,099 / 23,904 | 81,920 / 81,854 | 1,671 / 1,873 | 7,829 / 7,850 | 2,578 / 2,579 (1,742 / 2,091) | 28 / 28 | 5,065 / 5,084 | 159 / 160 |
| 32 | 32 | baseline | after | 15,581 / 13,574 | 26,558 / 22,708 | 81,527 / 84,541 | 1,625 / 1,795 | 8,056 / 8,331 | 2,640 / 2,841 (1,809 / 2,178) | 28 / 28 | 5,219 / 5,308 | 169 / 154 |
| 32 | 32 | limits_calls | before | 24,298 / 23,265 | 37,650 / 35,750 | 204,997 / 202,768 | 1,053 / 1,091 | 17,053 / 17,598 | 3,974 / 4,196 (3,660 / 3,822) | 4,291 / 4,552 | 8,559 / 8,632 | 229 / 217 |
| 32 | 32 | limits_calls | after | 24,674 / 23,167 | 39,027 / 34,505 | 188,350 / 186,253 | 1,026 / 1,056 | 17,467 / 18,725 | 4,313 / 4,474 (3,471 / 3,955) | 4,054 / 4,565 | 8,869 / 9,467 | 231 / 219 |
| 32 | 32 | usage | before | 22,676 / 21,987 | 38,208 / 32,293 | 194,642 / 185,860 | 1,103 / 1,074 | 16,299 / 18,143 | 3,899 / 4,466 (3,491 / 3,736) | 4,012 / 4,573 | 8,175 / 8,896 | 213 / 210 |
| 32 | 32 | usage | after | 23,298 / 22,364 | 36,798 / 34,275 | 203,686 / 206,438 | 1,049 / 1,126 | 16,772 / 17,362 | 3,927 / 4,062 (3,175 / 3,130) | 3,813 / 4,139 | 8,822 / 8,964 | 211 / 195 |

### Series 2: after, narrow and before

| clients | runs | config | binary | p50 | p90 | p99 | req/s | decide | `policy` mean (p50) | unstaged | `audit_append` | `lease_check` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | 1 | baseline | before | 3,234 / 3,637 | 5,226 / 6,091 | 18,350 / 17,973 | 2,099 / 1,879 | 1,533 / 1,475 | 562 / 515 (434 / 386) | 26 / 26 | 838 / 831 | 107 / 103 |
| 8 | 1 | baseline | after | 3,912 / 3,799 | 6,783 / 6,324 | 18,612 / 17,514 | 1,748 / 1,792 | 1,570 / 1,521 | 549 / 531 (403 / 403) | 27 / 26 | 881 / 857 | 113 / 107 |
| 8 | 1 | baseline | narrow | 3,373 / 3,887 | 5,288 / 6,468 | 19,710 / 18,416 | 1,960 / 1,789 | 1,558 / 1,538 | 548 / 524 (425 / 407) | 26 / 26 | 877 / 879 | 107 / 109 |
| 8 | 1 | limits_calls | before | 5,628 / 5,440 | 9,576 / 8,016 | 26,968 / 23,626 | 1,146 / 1,243 | 3,472 / 3,325 | 874 / 868 (681 / 688) | 820 / 798 | 1,643 / 1,534 | 135 / 125 |
| 8 | 1 | limits_calls | after | 6,259 / 6,029 | 10,781 / 10,084 | 26,444 / 26,313 | 1,036 / 1,075 | 4,742 / 4,588 | 3,267 / 3,046 (2,818 / 2,155) | 431 / 440 | 910 / 971 | 135 / 130 |
| 8 | 1 | limits_calls | narrow | 4,981 / 6,160 | 7,500 / 10,314 | 30,032 / 30,720 | 1,264 / 1,037 | 4,179 / 4,355 | 2,019 / 2,110 (1,540 / 1,600) | 637 / 682 | 1,398 / 1,431 | 125 / 131 |
| 8 | 1 | usage | before | 5,505 / 5,075 | 9,306 / 7,737 | 26,853 / 23,396 | 1,164 / 1,253 | 3,364 / 3,313 | 876 / 872 (667 / 696) | 753 / 790 | 1,602 / 1,525 | 133 / 126 |
| 8 | 1 | usage | after | 5,677 / 5,509 | 9,470 / 9,110 | 24,724 / 24,642 | 1,124 / 1,193 | 4,251 / 4,320 | 2,985 / 2,937 (2,640 / 2,410) | 366 / 395 | 788 / 869 | 113 / 119 |
| 8 | 1 | usage | narrow | 4,760 / 5,714 | 7,090 / 9,536 | 28,885 / 27,623 | 1,269 / 1,120 | 3,875 / 3,985 | 1,905 / 1,938 (1,454 / 1,505) | 586 / 612 | 1,274 / 1,318 | 110 / 117 |
| 32 | 1 | baseline | before | 12,829 / 12,354 | 19,120 / 18,842 | 62,980 / 56,394 | 2,144 / 2,202 | 6,763 / 6,667 | 2,418 / 2,374 (1,976 / 2,140) | 27 / 28 | 4,167 / 4,096 | 151 / 169 |
| 32 | 1 | baseline | after | 12,165 / 11,878 | 17,924 / 18,383 | 61,407 / 60,490 | 2,230 / 2,202 | 6,648 / 6,655 | 2,333 / 2,382 (2,124 / 2,062) | 27 / 27 | 4,122 / 4,085 | 166 / 161 |
| 32 | 1 | baseline | narrow | 11,985 / 12,288 | 17,596 / 19,890 | 63,734 / 58,130 | 2,273 / 2,205 | 6,727 / 6,582 | 2,401 / 2,315 (2,059 / 2,019) | 27 / 27 | 4,141 / 4,082 | 158 / 158 |
| 32 | 1 | limits_calls | before | 22,643 / 22,118 | 32,064 / 31,965 | 132,907 / 145,097 | 1,196 / 1,186 | 16,651 / 16,739 | 4,342 / 4,197 (4,106 / 4,109) | 4,896 / 4,919 | 7,200 / 7,412 | 214 / 211 |
| 32 | 1 | limits_calls | after | 23,380 / 23,052 | 40,272 / 43,811 | 155,320 / 162,267 | 1,167 / 1,134 | 23,710 / 24,778 | 21,860 / 22,929 (17,937 / 19,868) | 428 / 451 | 1,300 / 1,249 | 124 / 149 |
| 32 | 1 | limits_calls | narrow | 22,872 / 23,216 | 41,255 / 42,304 | 161,874 / 152,568 | 1,154 / 1,150 | 23,591 / 23,303 | 20,914 / 20,673 (16,583 / 16,411) | 711 / 714 | 1,839 / 1,772 | 129 / 145 |
| 32 | 1 | usage | before | 21,512 / 22,069 | 30,786 / 31,031 | 156,762 / 136,446 | 1,240 / 1,210 | 16,304 / 16,350 | 4,062 / 4,227 (4,051 / 3,955) | 4,766 / 4,810 | 7,276 / 7,104 | 200 / 209 |
| 32 | 1 | usage | after | 22,512 / 21,643 | 39,354 / 38,601 | 157,548 / 144,310 | 1,196 / 1,255 | 23,244 / 23,070 | 21,310 / 21,386 (18,344 / 16,850) | 403 / 377 | 1,401 / 1,180 | 130 / 127 |
| 32 | 1 | usage | narrow | 22,348 / 21,479 | 38,863 / 39,223 | 151,519 / 161,612 | 1,226 / 1,244 | 22,398 / 22,309 | 19,785 / 19,630 (16,132 / 15,944) | 677 / 666 | 1,799 / 1,871 | 138 / 142 |
| 8 | 8 | baseline | before | 3,373 / 3,498 | 5,231 / 5,857 | 23,101 / 20,185 | 1,967 / 1,832 | 1,663 / 1,619 | 590 / 570 (446 / 432) | 26 / 26 | 941 / 916 | 106 / 107 |
| 8 | 8 | baseline | after | 3,643 / 3,834 | 6,541 / 6,476 | 26,296 / 23,888 | 1,742 / 1,687 | 1,743 / 1,877 | 627 / 665 (441 / 453) | 26 / 27 | 983 / 1,072 | 107 / 112 |
| 8 | 8 | baseline | narrow | 3,418 / 3,697 | 5,173 / 5,808 | 24,379 / 22,806 | 1,963 / 1,894 | 1,737 / 1,657 | 614 / 575 (450 / 452) | 27 / 26 | 984 / 945 | 112 / 110 |
| 8 | 8 | limits_calls | before | 5,222 / 5,636 | 7,967 / 8,233 | 29,360 / 28,082 | 1,205 / 1,172 | 3,713 / 3,715 | 982 / 931 (720 / 743) | 877 / 874 | 1,726 / 1,774 | 129 / 136 |
| 8 | 8 | limits_calls | after | 6,275 / 5,689 | 10,019 / 8,544 | 44,827 / 42,304 | 1,000 / 1,039 | 4,485 / 4,507 | 1,095 / 1,097 (813 / 784) | 1,052 / 1,090 | 2,183 / 2,168 | 156 / 152 |
| 8 | 8 | limits_calls | narrow | 5,636 / 6,013 | 7,868 / 8,856 | 43,909 / 40,206 | 1,124 / 1,079 | 4,346 / 4,282 | 1,030 / 1,017 (798 / 806) | 1,063 / 974 | 2,109 / 2,158 | 144 / 133 |
| 8 | 8 | usage | before | 5,145 / 5,464 | 7,840 / 8,561 | 38,175 / 33,686 | 1,182 / 1,137 | 3,748 / 3,709 | 973 / 957 (730 / 734) | 842 / 859 | 1,809 / 1,767 | 124 / 127 |
| 8 | 8 | usage | after | 5,964 / 5,562 | 10,084 / 8,106 | 35,848 / 38,044 | 1,041 / 1,164 | 3,886 / 4,191 | 982 / 1,030 (738 / 786) | 864 / 959 | 1,905 / 2,080 | 135 / 123 |
| 8 | 8 | usage | narrow | 5,362 / 5,239 | 7,860 / 7,541 | 32,309 / 38,208 | 1,208 / 1,136 | 3,851 / 4,161 | 941 / 997 (761 / 769) | 916 / 986 | 1,868 / 2,050 | 127 / 128 |
| 32 | 32 | baseline | before | 13,615 / 14,082 | 21,840 / 23,282 | 92,864 / 84,935 | 1,755 / 1,855 | 9,057 / 7,900 | 2,969 / 2,666 (2,357 / 1,972) | 28 / 29 | 5,896 / 5,046 | 163 / 159 |
| 32 | 32 | baseline | after | 14,623 / 13,787 | 24,314 / 20,152 | 84,017 / 86,049 | 1,757 / 1,871 | 8,474 / 8,159 | 2,933 / 2,758 (2,361 / 2,349) | 28 / 28 | 5,330 / 5,206 | 181 / 167 |
| 32 | 32 | baseline | narrow | 12,763 / 14,164 | 19,431 / 22,168 | 92,733 / 87,491 | 1,851 / 1,762 | 8,706 / 8,456 | 2,847 / 2,833 (2,321 / 2,293) | 27 / 28 | 5,669 / 5,429 | 162 / 166 |
| 32 | 32 | limits_calls | before | 25,018 / 23,200 | 36,274 / 35,193 | 189,268 / 196,215 | 1,054 / 1,113 | 18,124 / 17,474 | 4,459 / 4,174 (3,760 / 3,292) | 4,878 / 4,447 | 8,556 / 8,642 | 231 / 211 |
| 32 | 32 | limits_calls | after | 25,428 / 23,970 | 36,209 / 33,620 | 182,190 / 169,083 | 1,006 / 1,053 | 19,426 / 19,363 | 4,742 / 4,886 (4,309 / 4,196) | 4,985 / 4,877 | 9,463 / 9,375 | 235 / 225 |
| 32 | 32 | limits_calls | narrow | 25,362 / 24,756 | 36,340 / 33,489 | 182,845 / 168,165 | 942 / 1,025 | 21,249 / 19,867 | 5,017 / 4,680 (4,483 / 4,189) | 5,862 / 5,349 | 10,139 / 9,634 | 230 / 204 |
| 32 | 32 | usage | before | 22,168 / 22,462 | 35,160 / 33,686 | 178,782 / 171,049 | 1,136 / 1,146 | 16,887 / 17,218 | 4,107 / 4,147 (3,526 / 3,146) | 4,360 / 4,585 | 8,207 / 8,286 | 213 / 202 |
| 32 | 32 | usage | after | 23,544 / 22,774 | 31,850 / 34,341 | 177,472 / 190,054 | 1,096 / 1,097 | 18,352 / 18,560 | 4,727 / 4,640 (4,246 / 4,093) | 4,948 / 4,771 | 8,460 / 8,940 | 217 / 210 |
| 32 | 32 | usage | narrow | 24,592 / 23,757 | 33,653 / 33,341 | 183,370 / 181,142 | 1,032 / 1,075 | 19,950 / 18,791 | 4,957 / 4,572 (4,351 / 4,102) | 5,531 / 4,937 | 9,256 / 9,088 | 206 / 194 |

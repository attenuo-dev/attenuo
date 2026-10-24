# Limit kinds on the hot path: `calls_per`, `distinct` and host `distinct` (2026-10-24)

Branch `perf/limit-kinds-latency`, main `360ba25`. Release build with `lto = false` and `codegen-units = 16` (as the usage-write, `sum` follow-up and outlier runs), rustc 1.99.1. Shared 4-vCPU container with other agents building on it: load average 2.3 at the start (14:34 UTC), 1.2 to 5.7 during the runs (sampled every 15 s), 4.7 at the end (14:51 UTC); 0.6 to 3.2 during the criterion runs. File store at `durability = "normal"`, one client, 2-hop token, 2 s warm-up and 10 s measured per cell, 5 interleaved runs per pass, only the `destructive` call (`create_issue`). See [performance](../performance.md#limit-kinds-callsper-and-distinct-2026-10-24).

## Configurations

Every limit has a `max` no run reaches, sits on `create_issue` in both hops, and is the only limit in the token, so each call charges 2 counters (one per hop) and none is refused. `create_issue`'s body carries `to` and `url` (declared `string`) in every configuration; `@SEQ@` marks a number the harness makes new on every call.

| config | limit (both hops) | `to` | `url` | store writes per call |
|---|---|---|---|---|
| `baseline` | none | `r0@example.com` | `https://h0.example/a` | none |
| `limits_calls` | `calls` | as baseline | as baseline | 2 counter updates, 2 charge rows |
| `calls_per_new` | `calls_per` on `to` | `r@SEQ@@example.com` | as baseline | 2 new counter rows, 2 charge rows |
| `calls_per_same` | `calls_per` on `to` | as baseline | as baseline | 2 counter updates, 2 charge rows |
| `distinct_new` | `distinct` on `to` | `r@SEQ@@example.com` | as baseline | 2 new value rows, 2 count updates, 4 charge rows |
| `distinct_same` | `distinct` on `to` | as baseline | as baseline | none (the transaction still runs) |
| `host_new` | `distinct` on `url`, `derive: host` | as baseline | `https://h@SEQ@.example/a` | as `distinct_new` |
| `host_same` | `distinct` on `url`, `derive: host` | as baseline | `https://h0.example/a@SEQ@` (new path, same host) | none |

The configuration check below confirms it: in the `*_new` cells the first charge's `used_after` is the number of values seen (about every call made), in `distinct_same` and `host_same` it stays 1, and for `calls_per_new` it is 1 (each value's first call).

## Summary

Client figures are medians over the 5 runs; decision and charge figures are means pooled over the runs' measured windows. "charge" is the decision time outside lease check, policy and audit append ("decide (unstaged)"), which is the charge transaction plus about 20 us of record building that `baseline` also has. Pass 1 / pass 2.

| config | p50 us | p90 us | p99 us | req/s | decide mean us | charge mean us | requests | over 3 / 5 / 10 ms |
|---|---|---|---|---|---|---|---|---|
| `baseline` | 1,365 / 1,336 | 1,714 / 1,764 | 3,478 / 3,555 | 702 / 713 | 343 / 315 | 22 / 20 | 34,441 / 35,599 | 614 / 220 / 32; 591 / 196 / 21 |
| `limits_calls` | 1,464 / 1,475 | 1,841 / 1,908 | 3,566 / 3,832 | 631 / 621 | 449 / 457 | 91 / 91 | 31,589 / 31,268 | 713 / 249 / 31; 687 / 243 / 30 |
| `calls_per_new` | 1,465 / 1,482 | 1,861 / 1,962 | 4,330 / 4,473 | 610 / 614 | 505 / 536 | 122 / 121 | 30,428 / 29,629 | 867 / 376 / 61; 734 / 322 / 54 |
| `calls_per_same` | 1,467 / 1,505 | 1,878 / 1,923 | 3,469 / 4,682 | 639 / 620 | 463 / 472 | 97 / 96 | 31,702 / 29,968 | 795 / 315 / 38; 1,170 / 395 / 48 |
| `distinct_new` | 1,574 / 1,562 | 1,973 / 2,041 | 3,699 / 5,063 | 595 / 587 | 555 / 568 | 144 / 148 | 29,466 / 29,098 | 879 / 384 / 55; 915 / 355 / 61 |
| `distinct_same` | 1,306 / 1,342 | 1,732 / 1,777 | 3,228 / 4,465 | 697 / 698 | 375 / 391 | 46 / 49 | 34,824 / 33,687 | 757 / 287 / 41; 874 / 275 / 25 |
| `host_new` | 1,553 / 1,574 | 1,968 / 2,183 | 4,538 / 5,874 | 600 / 571 | 583 / 582 | 148 / 153 | 28,613 / 27,626 | 708 / 265 / 59; 1,493 / 524 / 67 |
| `host_same` | 1,403 / 1,406 | 1,789 / 1,836 | 4,014 / 4,674 | 672 / 662 | 401 / 401 | 50 / 51 | 32,461 / 31,823 | 593 / 175 / 24; 904 / 286 / 25 |

Other server stages, means in us, pass 1 / pass 2:

| config | `policy` (counter read, Cedar) | `audit_append` mean (p50) | handler `total` |
|---|---|---|---|
| `baseline` | 131 / 126 | 142 / 123 (113 / 107) | 1,208 / 1,158 |
| `limits_calls` | 147 / 148 | 163 / 168 (153 / 154) | 1,336 / 1,345 |
| `calls_per_new` | 159 / 162 | 174 / 201 (154 / 156) | 1,406 / 1,435 |
| `calls_per_same` | 153 / 152 | 164 / 172 (154 / 155) | 1,341 / 1,411 |
| `distinct_new` | 180 / 178 | 178 / 189 (154 / 155) | 1,462 / 1,478 |
| `distinct_same` | 149 / 157 | 133 / 135 (110 / 121) | 1,208 / 1,248 |
| `host_new` | 187 / 194 | 197 / 178 (154 / 156) | 1,497 / 1,566 |
| `host_same` | 164 / 165 | 136 / 134 (124 / 123) | 1,282 / 1,314 |

## In process (`cargo bench -p attenuo-server --bench decide`)

Criterion point estimates and intervals, `--warm-up-time 1 --measurement-time 3`, two runs (the `file_full` cells once). `charges_for` builds the 2 charges of the call (argument read, canonical JSON, and the URL parse for `host`); `derive_host` is `Derive::Host::apply` on one value; `charge_*` is `LeaseStore::charge` alone, with a new value every iteration or the same value every iteration.

| cell | run 1 | run 2 |
|---|---|---|
| `derive_host/short` (`https://news.example/a`) | 300 ns [285, 317] | 284 ns [274, 297] |
| `derive_host/port_userinfo_case` | 703 ns [684, 729] | 711 ns [689, 737] |
| `derive_host/long` (212 bytes, query and fragment) | 970 ns [929, 1,015] | 1,056 ns [989, 1,125] |
| `derive_host/idn` (`bücher.example`) | 780 ns [735, 831] | 745 ns [709, 791] |
| `charges_for/calls_per` | 605 ns [586, 627] | 816 ns [793, 841] |
| `charges_for/distinct` | 603 ns [590, 618] | 628 ns [618, 638] |
| `charges_for/host` | 1.34 us [1.32, 1.37] | 1.38 us [1.35, 1.42] |
| `charge_file/calls` | 41.5 us [40.0, 43.2] | 38.5 us [37.9, 39.1] |
| `charge_file/calls_per_new` | 73.7 us [70.9, 76.5] | 73.1 us [70.8, 75.7] |
| `charge_file/calls_per_same` | 50.2 us [48.1, 52.7] | 46.6 us [46.1, 47.2] |
| `charge_file/distinct_new` | 106 us [102, 111] | 107 us [104, 110] |
| `charge_file/distinct_same` | 18.6 us [17.7, 19.6] | 19.0 us [18.2, 19.8] |
| `charge_file/host_new` | 95.0 us [91.6, 99.0] | 93.8 us [91.2, 96.6] |
| `charge_file/host_same` | 27.9 us [16.7, 53.9] | 16.5 us [15.9, 17.2] |
| `charge_file_full/calls` | 456 us [433, 481] | |
| `charge_file_full/calls_per_new` | 698 us [651, 744] | |
| `charge_file_full/calls_per_same` | 458 us [443, 474] | |
| `charge_file_full/distinct_new` | 600 us [579, 624] | |
| `charge_file_full/distinct_same` | 15.8 us [15.3, 16.4] | |
| `charge_file_full/host_new` | 357 us [339, 379] | |
| `charge_file_full/host_same` | 16.1 us [15.7, 16.4] | |
| `charge_memory/calls` | 74.5 us [72.6, 76.4] | 95.6 us [90.2, 100.8] |
| `charge_memory/calls_per_new` | 253 us [242, 262] | 205 us [200, 211] |
| `charge_memory/calls_per_same` | 127 us [123, 131] | 121 us [118, 125] |
| `charge_memory/distinct_new` | 415 us [402, 428] | 415 us [405, 426] |
| `charge_memory/distinct_same` | 12.1 us [11.6, 12.6] | 11.7 us [11.2, 12.1] |
| `charge_memory/host_new` | 425 us [415, 437] | 422 us [411, 433] |
| `charge_memory/host_same` | 11.0 us [10.7, 11.3] | 11.2 us [11.0, 11.6] |

## Rerun

```text
export CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
cargo build --release -p attenuo-bench -p attenuo-server
cargo build --release -p attenuo-proxy --features testing --example fake_mcp
target/release/attenuo-bench hot-path --runs 5 --cells destructive \
  --configs baseline,limits_calls,calls_per_new,calls_per_same,distinct_new,distinct_same,host_new,host_same \
  --json pass1.json --markdown pass1.md
target/release/attenuo-bench hot-path --runs 5 --cells destructive \
  --configs host_same,host_new,distinct_same,distinct_new,calls_per_same,calls_per_new,limits_calls,baseline \
  --json pass2.json --markdown pass2.md
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 \
  'derive_host|charges_for/|charge_.*/(calls|calls_per|distinct|host)'
```

The raw JSON of both passes is in [`2026-10-24-vm-limit-kinds.json`](2026-10-24-vm-limit-kinds.json) (`pass1`, `pass2`).

## Pass 1 (`--configs baseline,limits_calls,calls_per_new,calls_per_same,distinct_new,distinct_same,host_new,host_same`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| baseline | destructive | 0 | 0 | false | null |
| limits_calls | destructive | 2 | 0 | false | 37732 |
| calls_per_new | destructive | 2 | 0 | false | 1 |
| calls_per_same | destructive | 2 | 0 | false | 37767 |
| distinct_new | destructive | 2 | 0 | false | 35231 |
| distinct_same | destructive | 2 | 0 | false | 1 |
| host_new | destructive | 2 | 0 | false | 34704 |
| host_same | destructive | 2 | 0 | false | 1 |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| baseline | destructive | 5 | 1365 | 1188.9 to 1481.7 | 1714.2 | 1940.5 | 3477.5 | 702 |
| limits_calls | destructive | 5 | 1464.3 | 1350.7 to 1633.3 | 1841.2 | 2402.3 | 3565.6 | 631 |
| calls_per_new | destructive | 5 | 1465.3 | 1349.6 to 1575.9 | 1860.6 | 2160.6 | 4329.5 | 610 |
| calls_per_same | destructive | 5 | 1467.4 | 1313.8 to 1737.7 | 1878 | 2105.3 | 3469.3 | 639 |
| distinct_new | destructive | 5 | 1573.9 | 1419.3 to 1607.7 | 1973.2 | 2156.5 | 3698.7 | 595 |
| distinct_same | destructive | 5 | 1305.6 | 1239 to 1374.2 | 1731.6 | 1895.4 | 3227.6 | 697 |
| host_new | destructive | 5 | 1553.4 | 1416.2 to 1711.1 | 1968.1 | 2181.1 | 4538.4 | 600 |
| host_same | destructive | 5 | 1402.9 | 1348.6 to 1667.1 | 1788.9 | 2025.5 | 4014.1 | 672 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| baseline | destructive | 34441 | 614 / 220 / 32 | 529793 | token_verify_hit 0 / 0 / 0, lease_check 3 / 1 / 0, policy 2 / 0 / 0, audit_append 69 / 27 / 11, blocking_pool 87 / 18 / 4, upstream 23 / 11 / 1, response 112 / 43 / 10, total 494 / 167 / 30 |
| limits_calls | destructive | 31589 | 713 / 249 / 31 | 100401.2 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 6 / 2 / 0, audit_append 80 / 19 / 7, blocking_pool 72 / 17 / 0, upstream 28 / 11 / 4, response 125 / 45 / 12, total 566 / 201 / 28 |
| calls_per_new | destructive | 30428 | 867 / 376 / 61 | 160825.3 | token_verify_hit 0 / 0 / 0, lease_check 2 / 0 / 0, policy 5 / 1 / 0, audit_append 101 / 48 / 10, blocking_pool 98 / 22 / 4, upstream 39 / 10 / 2, response 191 / 72 / 22, total 730 / 308 / 56 |
| calls_per_same | destructive | 31702 | 795 / 315 / 38 | 46661.6 | token_verify_hit 1 / 0 / 0, lease_check 1 / 0 / 0, policy 3 / 2 / 0, audit_append 76 / 20 / 4, blocking_pool 111 / 19 / 4, upstream 37 / 16 / 2, response 174 / 57 / 14, total 671 / 249 / 36 |
| distinct_new | destructive | 29466 | 879 / 384 / 55 | 153616.4 | token_verify_hit 0 / 0 / 0, lease_check 1 / 1 / 0, policy 2 / 1 / 1, audit_append 91 / 40 / 13, blocking_pool 132 / 29 / 5, upstream 34 / 9 / 1, response 235 / 83 / 22, total 769 / 330 / 52 |
| distinct_same | destructive | 34824 | 757 / 287 / 41 | 276561.9 | token_verify_hit 1 / 0 / 0, lease_check 2 / 1 / 1, policy 11 / 3 / 0, audit_append 62 / 27 / 11, blocking_pool 124 / 27 / 6, upstream 29 / 7 / 1, response 167 / 53 / 12, total 643 / 236 / 37 |
| host_new | destructive | 28613 | 708 / 265 / 59 | 265682.9 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 7 / 2 / 1, audit_append 104 / 50 / 15, blocking_pool 52 / 13 / 4, upstream 34 / 10 / 2, response 94 / 50 / 20, total 542 / 222 / 56 |
| host_same | destructive | 32461 | 593 / 175 / 24 | 79364.1 | token_verify_hit 1 / 0 / 0, lease_check 1 / 0 / 0, policy 3 / 0 / 0, audit_append 60 / 18 / 8, blocking_pool 48 / 13 / 2, upstream 32 / 9 / 0, response 67 / 28 / 7, total 408 / 128 / 21 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | destructive | token_verify_hit | 34434 | 11.5 | 11.8 | 19.5 |
| baseline | destructive | lease_check | 34436 | 49.1 | 45.9 | 82.8 |
| baseline | destructive | policy | 34435 | 130.9 | 145 | 197.5 |
| baseline | destructive | audit_append | 34435 | 141.6 | 112.8 | 196.3 |
| baseline | destructive | blocking_pool | 34436 | 129.9 | 104.1 | 206.4 |
| baseline | destructive | upstream | 34438 | 321.5 | 306 | 493.1 |
| baseline | destructive | response | 34438 | 349.7 | 301.3 | 495.5 |
| baseline | destructive | total | 34438 | 1208.1 | 1233.5 | 1963.6 |
| baseline | destructive | decide (whole, mean) | | 343.2 | | |
| baseline | destructive | decide (unstaged, mean) | | 21.7 | | |
| baseline | destructive | result append (mean) | 34439 | 147.3 | | |
| limits_calls | destructive | token_verify_hit | 31581 | 11.5 | 12 | 19.6 |
| limits_calls | destructive | lease_check | 31583 | 47.8 | 45.4 | 81 |
| limits_calls | destructive | policy | 31583 | 147.4 | 153.2 | 222 |
| limits_calls | destructive | audit_append | 31583 | 162.7 | 152.7 | 256.9 |
| limits_calls | destructive | blocking_pool | 31583 | 133.4 | 112.6 | 220.6 |
| limits_calls | destructive | upstream | 31584 | 333.8 | 320.8 | 495.7 |
| limits_calls | destructive | response | 31584 | 355.4 | 316.5 | 499.3 |
| limits_calls | destructive | total | 31584 | 1335.9 | 1450.2 | 1995 |
| limits_calls | destructive | decide (whole, mean) | | 448.7 | | |
| limits_calls | destructive | decide (unstaged, mean) | | 90.9 | | |
| limits_calls | destructive | result append (mean) | 31583 | 145.3 | | |
| calls_per_new | destructive | token_verify_hit | 30424 | 11.7 | 12.4 | 19.6 |
| calls_per_new | destructive | lease_check | 30429 | 49.7 | 46.7 | 84 |
| calls_per_new | destructive | policy | 30429 | 158.7 | 154.9 | 249.1 |
| calls_per_new | destructive | audit_append | 30429 | 174 | 154 | 257.8 |
| calls_per_new | destructive | blocking_pool | 30429 | 134.7 | 103.4 | 199.7 |
| calls_per_new | destructive | upstream | 30429 | 321.9 | 301.9 | 488.9 |
| calls_per_new | destructive | response | 30429 | 379.1 | 312.9 | 495.9 |
| calls_per_new | destructive | total | 30429 | 1405.5 | 1476.7 | 1990.2 |
| calls_per_new | destructive | decide (whole, mean) | | 504.9 | | |
| calls_per_new | destructive | decide (unstaged, mean) | | 122.4 | | |
| calls_per_new | destructive | result append (mean) | 30429 | 159.4 | | |
| calls_per_same | destructive | token_verify_hit | 31700 | 12 | 13 | 19.6 |
| calls_per_same | destructive | lease_check | 31700 | 49 | 45.9 | 87.7 |
| calls_per_same | destructive | policy | 31700 | 152.8 | 155.5 | 254.8 |
| calls_per_same | destructive | audit_append | 31700 | 163.8 | 153.7 | 267.8 |
| calls_per_same | destructive | blocking_pool | 31700 | 134.6 | 99.5 | 198.6 |
| calls_per_same | destructive | upstream | 31704 | 322.2 | 301.5 | 489.4 |
| calls_per_same | destructive | response | 31704 | 356.2 | 308.1 | 498.1 |
| calls_per_same | destructive | total | 31704 | 1340.7 | 1435.5 | 1990.5 |
| calls_per_same | destructive | decide (whole, mean) | | 462.9 | | |
| calls_per_same | destructive | decide (unstaged, mean) | | 97.3 | | |
| calls_per_same | destructive | result append (mean) | 31703 | 143.2 | | |
| distinct_new | destructive | token_verify_hit | 29460 | 11.8 | 12.8 | 19.6 |
| distinct_new | destructive | lease_check | 29464 | 53.4 | 50.3 | 88.5 |
| distinct_new | destructive | policy | 29464 | 179.7 | 162.3 | 282 |
| distinct_new | destructive | audit_append | 29464 | 177.9 | 153.6 | 255.7 |
| distinct_new | destructive | blocking_pool | 29464 | 145.9 | 112.5 | 220.1 |
| distinct_new | destructive | upstream | 29465 | 315.9 | 298.3 | 487.7 |
| distinct_new | destructive | response | 29465 | 380 | 329.5 | 499.8 |
| distinct_new | destructive | total | 29465 | 1461.6 | 1513.1 | 2061 |
| distinct_new | destructive | decide (whole, mean) | | 555.4 | | |
| distinct_new | destructive | decide (unstaged, mean) | | 144.5 | | |
| distinct_new | destructive | result append (mean) | 29465 | 149.6 | | |
| distinct_same | destructive | token_verify_hit | 34821 | 11.3 | 11.6 | 19.5 |
| distinct_same | destructive | lease_check | 34822 | 47.3 | 43.9 | 75.4 |
| distinct_same | destructive | policy | 34822 | 149.3 | 152.8 | 209.2 |
| distinct_same | destructive | audit_append | 34822 | 132.6 | 110 | 194.8 |
| distinct_same | destructive | blocking_pool | 34822 | 132.6 | 95.5 | 197.9 |
| distinct_same | destructive | upstream | 34825 | 302.9 | 282.3 | 484.8 |
| distinct_same | destructive | response | 34825 | 335.8 | 288.2 | 491.1 |
| distinct_same | destructive | total | 34825 | 1208.4 | 1269 | 1970 |
| distinct_same | destructive | decide (whole, mean) | | 375.4 | | |
| distinct_same | destructive | decide (unstaged, mean) | | 46.2 | | |
| distinct_same | destructive | result append (mean) | 34825 | 127.9 | | |
| host_new | destructive | token_verify_hit | 28609 | 11.8 | 13 | 19.6 |
| host_new | destructive | lease_check | 28611 | 51.3 | 47.7 | 86.7 |
| host_new | destructive | policy | 28611 | 186.7 | 168.6 | 287.9 |
| host_new | destructive | audit_append | 28611 | 196.7 | 154.1 | 264.4 |
| host_new | destructive | blocking_pool | 28611 | 137.5 | 115.8 | 235.6 |
| host_new | destructive | upstream | 28611 | 336.8 | 323 | 493.9 |
| host_new | destructive | response | 28611 | 374.7 | 321.1 | 507.7 |
| host_new | destructive | total | 28611 | 1496.6 | 1512 | 1999.8 |
| host_new | destructive | decide (whole, mean) | | 583 | | |
| host_new | destructive | decide (unstaged, mean) | | 148.3 | | |
| host_new | destructive | result append (mean) | 28611 | 164.6 | | |
| host_same | destructive | token_verify_hit | 32458 | 11.9 | 12.8 | 19.6 |
| host_same | destructive | lease_check | 32459 | 50.6 | 47.3 | 86.4 |
| host_same | destructive | policy | 32459 | 163.8 | 157.4 | 270.7 |
| host_same | destructive | audit_append | 32459 | 136.1 | 123.9 | 198.5 |
| host_same | destructive | blocking_pool | 32460 | 131.3 | 113.5 | 237.5 |
| host_same | destructive | upstream | 32460 | 338 | 328.9 | 497.9 |
| host_same | destructive | response | 32460 | 345.9 | 322.8 | 518.8 |
| host_same | destructive | total | 32460 | 1282.2 | 1393.6 | 1985.5 |
| host_same | destructive | decide (whole, mean) | | 400.7 | | |
| host_same | destructive | decide (unstaged, mean) | | 50.1 | | |
| host_same | destructive | result append (mean) | 32461 | 136.4 | | |

## Pass 2 (the same configurations, reversed)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`), whether it carries run usage (`usage`) in its record, and the first charge's `used_after`.

| config | call | counters charged | tainted_by | usage | used_after |
|---|---|---|---|---|---|
| host_same | destructive | 2 | 0 | false | 1 |
| host_new | destructive | 2 | 0 | false | 33285 |
| distinct_same | destructive | 2 | 0 | false | 1 |
| distinct_new | destructive | 2 | 0 | false | 34971 |
| calls_per_same | destructive | 2 | 0 | false | 35973 |
| calls_per_new | destructive | 2 | 0 | false | 1 |
| limits_calls | destructive | 2 | 0 | false | 37599 |
| baseline | destructive | 0 | 0 | false | null |

#### Client latency per configuration

Medians over the runs of each run's p50, p90, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|---|
| host_same | destructive | 5 | 1406 | 1212.4 to 1946.6 | 1836 | 2179.1 | 4673.5 | 662 |
| host_new | destructive | 5 | 1573.9 | 1421.3 to 1846.3 | 2183.2 | 2977.8 | 5873.7 | 571 |
| distinct_same | destructive | 5 | 1342.5 | 1194 to 1578 | 1776.6 | 2166.8 | 4464.6 | 698 |
| distinct_new | destructive | 5 | 1561.6 | 1362.9 to 1638.4 | 2040.8 | 2455.6 | 5062.7 | 587 |
| calls_per_same | destructive | 5 | 1505.3 | 1312.8 to 1606.7 | 1923.1 | 2717.7 | 4681.7 | 620 |
| calls_per_new | destructive | 5 | 1481.7 | 1443.8 to 1721.3 | 1962 | 2314.2 | 4472.8 | 614 |
| limits_calls | destructive | 5 | 1474.6 | 1446.9 to 1550.3 | 1907.7 | 2121.7 | 3831.8 | 621 |
| baseline | destructive | 5 | 1336.3 | 1230.8 to 1362.9 | 1764.4 | 2057.2 | 3555.3 | 713 |

#### Tail per configuration

Requests over all runs, how many took longer than 3 / 5 / 10 ms at the client, the slowest, and per server stage the samples above 3 / 5 / 10 ms (`attenuo_proxy_stage_seconds`, pooled over the runs' measured windows).

| config | call | requests | over 3 / 5 / 10 ms | max us | stages over 3 / 5 / 10 ms |
|---|---|---|---|---|---|
| host_same | destructive | 31823 | 904 / 286 / 25 | 25575.4 | token_verify_hit 0 / 0 / 0, lease_check 5 / 0 / 0, policy 5 / 1 / 1, audit_append 68 / 25 / 4, blocking_pool 108 / 16 / 1, upstream 52 / 12 / 1, response 129 / 30 / 3, total 676 / 215 / 21 |
| host_new | destructive | 27626 | 1493 / 524 / 67 | 135921.7 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 13 / 2 / 0, audit_append 85 / 41 / 11, blocking_pool 193 / 43 / 4, upstream 107 / 21 / 2, response 262 / 78 / 19, total 1207 / 422 / 58 |
| distinct_same | destructive | 33687 | 874 / 275 / 25 | 26492.9 | token_verify_hit 2 / 1 / 0, lease_check 0 / 0 / 0, policy 5 / 1 / 0, audit_append 70 / 26 / 9, blocking_pool 109 / 17 / 0, upstream 52 / 11 / 1, response 146 / 41 / 4, total 679 / 210 / 23 |
| distinct_new | destructive | 29098 | 915 / 355 / 61 | 131596.3 | token_verify_hit 0 / 0 / 0, lease_check 3 / 1 / 0, policy 4 / 2 / 0, audit_append 100 / 50 / 10, blocking_pool 110 / 22 / 1, upstream 50 / 14 / 3, response 163 / 59 / 13, total 738 / 301 / 59 |
| calls_per_same | destructive | 29968 | 1170 / 395 / 48 | 99680.3 | token_verify_hit 1 / 0 / 0, lease_check 2 / 0 / 0, policy 4 / 1 / 0, audit_append 83 / 21 / 9, blocking_pool 112 / 26 / 5, upstream 81 / 23 / 5, response 169 / 39 / 11, total 856 / 307 / 41 |
| calls_per_new | destructive | 29629 | 734 / 322 / 54 | 805830.7 | token_verify_hit 0 / 0 / 0, lease_check 0 / 0 / 0, policy 6 / 2 / 0, audit_append 93 / 30 / 14, blocking_pool 81 / 15 / 5, upstream 41 / 11 / 3, response 132 / 52 / 21, total 594 / 261 / 50 |
| limits_calls | destructive | 31268 | 687 / 243 / 30 | 46956.5 | token_verify_hit 0 / 0 / 0, lease_check 1 / 0 / 0, policy 9 / 3 / 0, audit_append 75 / 25 / 8, blocking_pool 63 / 11 / 1, upstream 39 / 5 / 0, response 94 / 32 / 7, total 520 / 189 / 26 |
| baseline | destructive | 35599 | 591 / 196 / 21 | 53542.9 | token_verify_hit 0 / 0 / 0, lease_check 1 / 1 / 0, policy 0 / 0 / 0, audit_append 68 / 20 / 4, blocking_pool 53 / 13 / 1, upstream 47 / 15 / 3, response 74 / 32 / 4, total 443 / 143 / 16 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| host_same | destructive | token_verify_hit | 31819 | 11.9 | 12.5 | 19.6 |
| host_same | destructive | lease_check | 31821 | 52 | 47.6 | 88.7 |
| host_same | destructive | policy | 31821 | 164.9 | 157.9 | 271.5 |
| host_same | destructive | audit_append | 31821 | 133.6 | 122.8 | 199.2 |
| host_same | destructive | blocking_pool | 31821 | 145.6 | 107.6 | 261.5 |
| host_same | destructive | upstream | 31822 | 339.5 | 315.5 | 535.6 |
| host_same | destructive | response | 31822 | 361.7 | 319.6 | 603.3 |
| host_same | destructive | total | 31822 | 1314.5 | 1369.4 | 2196.6 |
| host_same | destructive | decide (whole, mean) | | 401 | | |
| host_same | destructive | decide (unstaged, mean) | | 50.6 | | |
| host_same | destructive | result append (mean) | 31822 | 139 | | |
| host_new | destructive | token_verify_hit | 27622 | 11.7 | 11.9 | 19.6 |
| host_new | destructive | lease_check | 27625 | 56.5 | 53.6 | 92.5 |
| host_new | destructive | policy | 27625 | 193.6 | 173.7 | 291.3 |
| host_new | destructive | audit_append | 27625 | 178.5 | 156.5 | 267.5 |
| host_new | destructive | blocking_pool | 27625 | 171.8 | 112.2 | 280.9 |
| host_new | destructive | upstream | 27625 | 338 | 297.3 | 496.8 |
| host_new | destructive | response | 27625 | 409.6 | 338.3 | 620.4 |
| host_new | destructive | total | 27625 | 1566.3 | 1536.5 | 2872.2 |
| host_new | destructive | decide (whole, mean) | | 581.7 | | |
| host_new | destructive | decide (unstaged, mean) | | 153.1 | | |
| host_new | destructive | result append (mean) | 27625 | 161 | | |
| distinct_same | destructive | token_verify_hit | 33683 | 11.8 | 11 | 19.5 |
| distinct_same | destructive | lease_check | 33686 | 50.9 | 47.2 | 87 |
| distinct_same | destructive | policy | 33686 | 156.8 | 154.9 | 253.1 |
| distinct_same | destructive | audit_append | 33686 | 134.7 | 120.7 | 197.9 |
| distinct_same | destructive | blocking_pool | 33686 | 131.3 | 95.4 | 236.9 |
| distinct_same | destructive | upstream | 33687 | 317.3 | 289.5 | 494.3 |
| distinct_same | destructive | response | 33687 | 344.2 | 295 | 543.6 |
| distinct_same | destructive | total | 33687 | 1248.1 | 1302 | 1996.5 |
| distinct_same | destructive | decide (whole, mean) | | 391.1 | | |
| distinct_same | destructive | decide (unstaged, mean) | | 48.6 | | |
| distinct_same | destructive | result append (mean) | 33687 | 135.6 | | |
| distinct_new | destructive | token_verify_hit | 29097 | 11.8 | 12.7 | 19.6 |
| distinct_new | destructive | lease_check | 29098 | 53.3 | 49.3 | 87.3 |
| distinct_new | destructive | policy | 29098 | 178.1 | 161.4 | 279.2 |
| distinct_new | destructive | audit_append | 29098 | 189 | 154.6 | 256.1 |
| distinct_new | destructive | blocking_pool | 29098 | 145.3 | 112.1 | 243 |
| distinct_new | destructive | upstream | 29099 | 330.6 | 316.6 | 492.9 |
| distinct_new | destructive | response | 29099 | 368.2 | 320.4 | 503 |
| distinct_new | destructive | total | 29099 | 1478.2 | 1516.9 | 2221.6 |
| distinct_new | destructive | decide (whole, mean) | | 568 | | |
| distinct_new | destructive | decide (unstaged, mean) | | 147.6 | | |
| distinct_new | destructive | result append (mean) | 29099 | 148.1 | | |
| calls_per_same | destructive | token_verify_hit | 29964 | 12.1 | 12.9 | 19.7 |
| calls_per_same | destructive | lease_check | 29966 | 51.2 | 47.9 | 86.2 |
| calls_per_same | destructive | policy | 29966 | 151.8 | 154.1 | 240.2 |
| calls_per_same | destructive | audit_append | 29966 | 172 | 155.2 | 266.5 |
| calls_per_same | destructive | blocking_pool | 29966 | 151.6 | 107.8 | 267.1 |
| calls_per_same | destructive | upstream | 29966 | 346.7 | 317.7 | 502.2 |
| calls_per_same | destructive | response | 29966 | 373.6 | 317.3 | 588.4 |
| calls_per_same | destructive | total | 29966 | 1410.9 | 1468.1 | 2501.3 |
| calls_per_same | destructive | decide (whole, mean) | | 471.5 | | |
| calls_per_same | destructive | decide (unstaged, mean) | | 96.4 | | |
| calls_per_same | destructive | result append (mean) | 29966 | 149.9 | | |
| calls_per_new | destructive | token_verify_hit | 29626 | 11.9 | 12.9 | 19.6 |
| calls_per_new | destructive | lease_check | 29627 | 51.6 | 48.1 | 88.1 |
| calls_per_new | destructive | policy | 29627 | 162.2 | 155.8 | 258.4 |
| calls_per_new | destructive | audit_append | 29627 | 201.4 | 155.6 | 265.1 |
| calls_per_new | destructive | blocking_pool | 29628 | 138 | 111.7 | 224.4 |
| calls_per_new | destructive | upstream | 29630 | 336.5 | 331.5 | 492.8 |
| calls_per_new | destructive | response | 29630 | 357.7 | 319.6 | 498.7 |
| calls_per_new | destructive | total | 29630 | 1434.9 | 1485.4 | 1993.4 |
| calls_per_new | destructive | decide (whole, mean) | | 535.9 | | |
| calls_per_new | destructive | decide (unstaged, mean) | | 120.7 | | |
| calls_per_new | destructive | result append (mean) | 29631 | 149.5 | | |
| limits_calls | destructive | token_verify_hit | 31264 | 11.4 | 12.2 | 19.5 |
| limits_calls | destructive | lease_check | 31266 | 49.9 | 46.9 | 80.5 |
| limits_calls | destructive | policy | 31266 | 147.6 | 152.3 | 199.5 |
| limits_calls | destructive | audit_append | 31266 | 168.3 | 153.6 | 256.3 |
| limits_calls | destructive | blocking_pool | 31267 | 136.8 | 115 | 245.7 |
| limits_calls | destructive | upstream | 31267 | 338 | 331.6 | 494.9 |
| limits_calls | destructive | response | 31267 | 349.5 | 323 | 499.1 |
| limits_calls | destructive | total | 31267 | 1345.2 | 1459 | 1988 |
| limits_calls | destructive | decide (whole, mean) | | 456.6 | | |
| limits_calls | destructive | decide (unstaged, mean) | | 91 | | |
| limits_calls | destructive | result append (mean) | 31267 | 141.9 | | |
| baseline | destructive | token_verify_hit | 35596 | 10.9 | 10.8 | 19.4 |
| baseline | destructive | lease_check | 35597 | 46.3 | 43.8 | 73.2 |
| baseline | destructive | policy | 35597 | 125.9 | 142 | 196.1 |
| baseline | destructive | audit_append | 35597 | 122.6 | 106.8 | 194.4 |
| baseline | destructive | blocking_pool | 35597 | 126.9 | 97.9 | 223 |
| baseline | destructive | upstream | 35598 | 328.8 | 307.3 | 493 |
| baseline | destructive | response | 35598 | 324 | 289.7 | 494.7 |
| baseline | destructive | total | 35598 | 1157.5 | 1202.9 | 1963.6 |
| baseline | destructive | decide (whole, mean) | | 315.3 | | |
| baseline | destructive | decide (unstaged, mean) | | 20.5 | | |
| baseline | destructive | result append (mean) | 35598 | 130.9 | | |

# Output labelling and run limits on the hot path, 2026-10-24, vm

Commit `77b5e8f` (main) plus the `attenuo-bench hot-path` subcommand of this branch; release profile, rustc 1.99.1 (58cf8f9c3 2026-10-13).
Per cell: 2 s warm-up (discarded), 10 s measured, closed loop, 1 client, 2-hop token, SQLite file store (`durability = "normal"`). 5 interleaved runs of every cell. Approval round: 100 rounds discarded, 2,000 timed.

Command (from the release target dir, binaries built as `scripts/bench-e2e.sh` builds them):

```
attenuo-bench hot-path --runs 5 --duration 10 --warmup 2 \
  --configs baseline,labels,limits,limits_calls,both --approval-loops 2000 --approval-warmup 100 \
  --json docs/design/bench/2026-10-24-vm-labels-limits.json --markdown ...
```

Shared 4-core VM with other agents active. Load average 1.73 / 2.81 / 2.48 at the start (09:17:55 UTC), 4.88 / 2.69 / 2.34 at the end (09:28:17 UTC).

## Hardware

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
$ uname -sr
Linux 6.18.44-fc-v153
```

## Results

### Configuration check

One extra call per configuration and call after the runs: counters its decision charged and label sources (`labels.tainted_by`) in its record.

| config | call | counters charged | tainted_by |
|---|---|---|---|
| baseline | read | 0 | 0 |
| baseline | destructive | 0 | 0 |
| labels | read | 0 | 2 |
| labels | destructive | 0 | 2 |
| limits | read | 4 | 0 |
| limits | destructive | 4 | 0 |
| limits_calls | read | 2 | 0 |
| limits_calls | destructive | 2 | 0 |
| both | read | 4 | 2 |
| both | destructive | 4 | 2 |

### Client latency per configuration

Medians over the runs of each run's p50, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|
| baseline | read | 5 | 1140.7 | 1009.2 to 1356.8 | 1787.9 | 3037.2 | 794 |
| baseline | destructive | 5 | 1178.6 | 1128.4 to 1252.4 | 1778.7 | 2953.2 | 787 |
| labels | read | 5 | 1115.1 | 1019.9 to 1228.8 | 1768.4 | 2877.4 | 810 |
| labels | destructive | 5 | 1203.2 | 1080.3 to 1251.3 | 1761.3 | 2848.8 | 767 |
| limits | read | 5 | 1968.1 | 1857.5 to 2166.8 | 3072 | 4976.6 | 445 |
| limits | destructive | 5 | 2164.7 | 1831.9 to 2357.2 | 3471.4 | 5849.1 | 418 |
| limits_calls | read | 5 | 1262.6 | 1144.8 to 1312.8 | 1893.4 | 2918.4 | 714 |
| limits_calls | destructive | 5 | 1370.1 | 1202.2 to 1415.2 | 2018.3 | 3258.4 | 654 |
| both | read | 5 | 2077.7 | 2019.3 to 2844.7 | 3055.6 | 4550.7 | 451 |
| both | destructive | 5 | 2109.4 | 1958.9 to 3876.9 | 2981.9 | 4468.7 | 440 |

### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | read | token_verify_hit | 38726 | 9.8 | 9 | 18.9 |
| baseline | read | lease_check | 38727 | 44 | 41.1 | 69.9 |
| baseline | read | policy | 38727 | 103.1 | 96.7 | 190.3 |
| baseline | read | audit_append | 38727 | 147.4 | 97.2 | 192.6 |
| baseline | read | blocking_pool | 38729 | 122.1 | 93.3 | 240.6 |
| baseline | read | upstream | 38731 | 277.1 | 255.1 | 480.5 |
| baseline | read | response | 38731 | 307.6 | 262.4 | 486.9 |
| baseline | read | total | 38731 | 1069.7 | 944.8 | 1931.6 |
| baseline | read | decide (whole, mean) | | 311.3 | | |
| baseline | read | decide (unstaged, mean) | | 16.9 | | |
| baseline | read | result append (mean) | 38733 | 137.6 | | |
| baseline | destructive | token_verify_hit | 38626 | 10.1 | 9.1 | 19 |
| baseline | destructive | lease_check | 38629 | 43.8 | 41.1 | 69.7 |
| baseline | destructive | policy | 38629 | 102.4 | 96.9 | 190.3 |
| baseline | destructive | audit_append | 38629 | 155.2 | 99 | 193.7 |
| baseline | destructive | blocking_pool | 38629 | 115.8 | 94.9 | 222.6 |
| baseline | destructive | upstream | 38629 | 277.7 | 260 | 480.4 |
| baseline | destructive | response | 38629 | 306.9 | 267 | 485.6 |
| baseline | destructive | total | 38629 | 1071.5 | 960.9 | 1922.6 |
| baseline | destructive | decide (whole, mean) | | 318.9 | | |
| baseline | destructive | decide (unstaged, mean) | | 17.5 | | |
| baseline | destructive | result append (mean) | 38629 | 140.6 | | |
| labels | read | token_verify_hit | 40277 | 9.7 | 8.9 | 18.9 |
| labels | read | lease_check | 40278 | 27.2 | 23.7 | 48.8 |
| labels | read | policy | 40278 | 104.5 | 98.6 | 190.9 |
| labels | read | audit_append | 40278 | 142 | 94.3 | 191.8 |
| labels | read | blocking_pool | 40278 | 103.7 | 85.8 | 199.1 |
| labels | read | upstream | 40281 | 265.6 | 248 | 472.8 |
| labels | read | response | 40281 | 318.7 | 274.6 | 489.8 |
| labels | read | total | 40281 | 1029 | 920.5 | 1902.3 |
| labels | read | decide (whole, mean) | | 290 | | |
| labels | read | decide (unstaged, mean) | | 16.3 | | |
| labels | read | result append (mean) | 40282 | 134.6 | | |
| labels | destructive | token_verify_hit | 39096 | 9.9 | 9.1 | 19 |
| labels | destructive | lease_check | 39101 | 29.4 | 25.9 | 49.5 |
| labels | destructive | policy | 39101 | 108.9 | 108.1 | 192.2 |
| labels | destructive | audit_append | 39101 | 150.1 | 97.2 | 192.5 |
| labels | destructive | blocking_pool | 39101 | 111.1 | 90.5 | 208.6 |
| labels | destructive | upstream | 39101 | 272.4 | 254.4 | 475.5 |
| labels | destructive | response | 39101 | 321.4 | 286.5 | 492.1 |
| labels | destructive | total | 39101 | 1061.4 | 958.6 | 1916.3 |
| labels | destructive | decide (whole, mean) | | 305.2 | | |
| labels | destructive | decide (unstaged, mean) | | 16.7 | | |
| labels | destructive | result append (mean) | 39101 | 132 | | |
| limits | read | token_verify_hit | 22402 | 11.6 | 13.1 | 19.6 |
| limits | read | lease_check | 22407 | 45.1 | 43.3 | 70.4 |
| limits | read | policy | 22407 | 122 | 137.7 | 195.6 |
| limits | read | audit_append | 22407 | 174.2 | 158.2 | 271 |
| limits | read | blocking_pool | 22407 | 148 | 132.1 | 258.4 |
| limits | read | upstream | 22407 | 316.3 | 294.6 | 487.8 |
| limits | read | response | 22407 | 341 | 286.1 | 491.4 |
| limits | read | total | 22407 | 1989.9 | 1709.6 | 2981 |
| limits | read | decide (whole, mean) | | 1125.6 | | |
| limits | read | decide (unstaged, mean) | | 784.4 | | |
| limits | read | result append (mean) | 22407 | 151.9 | | |
| limits | destructive | token_verify_hit | 20864 | 11.6 | 13.3 | 19.6 |
| limits | destructive | lease_check | 20867 | 50.1 | 46.9 | 80.2 |
| limits | destructive | policy | 20867 | 125.4 | 143 | 195.8 |
| limits | destructive | audit_append | 20867 | 196.3 | 162.3 | 281.1 |
| limits | destructive | blocking_pool | 20867 | 160.6 | 138.6 | 274.6 |
| limits | destructive | upstream | 20869 | 331.5 | 308.8 | 492.3 |
| limits | destructive | response | 20869 | 364.1 | 315.6 | 497.7 |
| limits | destructive | total | 20869 | 2146.1 | 1845.8 | 3764.3 |
| limits | destructive | decide (whole, mean) | | 1229.5 | | |
| limits | destructive | decide (unstaged, mean) | | 857.6 | | |
| limits | destructive | result append (mean) | 20869 | 156.2 | | |
| limits_calls | read | token_verify_hit | 35365 | 10.4 | 9.4 | 19.1 |
| limits_calls | read | lease_check | 35369 | 43.8 | 41.6 | 69.5 |
| limits_calls | read | policy | 35369 | 115.3 | 124.2 | 193.9 |
| limits_calls | read | audit_append | 35368 | 170.5 | 147.9 | 214 |
| limits_calls | read | blocking_pool | 35369 | 123.4 | 95.1 | 214 |
| limits_calls | read | upstream | 35370 | 272.5 | 255.5 | 472.6 |
| limits_calls | read | response | 35370 | 343.3 | 266.5 | 486.3 |
| limits_calls | read | total | 35370 | 1200.2 | 1119.7 | 1954.9 |
| limits_calls | read | decide (whole, mean) | | 408.1 | | |
| limits_calls | read | decide (unstaged, mean) | | 78.5 | | |
| limits_calls | read | result append (mean) | 35371 | 164.5 | | |
| limits_calls | destructive | token_verify_hit | 32465 | 10.5 | 9.4 | 19.2 |
| limits_calls | destructive | lease_check | 32469 | 47.6 | 45.3 | 75.3 |
| limits_calls | destructive | policy | 32469 | 120.5 | 133.5 | 195.2 |
| limits_calls | destructive | audit_append | 32469 | 184.8 | 150.6 | 233.6 |
| limits_calls | destructive | blocking_pool | 32469 | 151.4 | 106.2 | 261.4 |
| limits_calls | destructive | upstream | 32470 | 287.9 | 260.2 | 481.9 |
| limits_calls | destructive | response | 32470 | 384.8 | 286.2 | 497.1 |
| limits_calls | destructive | total | 32470 | 1314.1 | 1279.5 | 1990.2 |
| limits_calls | destructive | decide (whole, mean) | | 435.1 | | |
| limits_calls | destructive | decide (unstaged, mean) | | 82.2 | | |
| limits_calls | destructive | result append (mean) | 32470 | 176.3 | | |
| both | read | token_verify_hit | 20679 | 11.7 | 13.6 | 19.6 |
| both | read | lease_check | 20681 | 31.6 | 28.6 | 49.8 |
| both | read | policy | 20681 | 131.9 | 149.1 | 196.9 |
| both | read | audit_append | 20681 | 179.3 | 159.9 | 275.9 |
| both | read | blocking_pool | 20681 | 149.1 | 131.9 | 256.6 |
| both | read | upstream | 20682 | 317.2 | 291 | 488.1 |
| both | read | response | 20682 | 385.2 | 346.7 | 505.3 |
| both | read | total | 20682 | 2170.9 | 1778.5 | 4288.9 |
| both | read | decide (whole, mean) | | 1259.3 | | |
| both | read | decide (unstaged, mean) | | 916.4 | | |
| both | read | result append (mean) | 20682 | 154.1 | | |
| both | destructive | token_verify_hit | 20724 | 11.7 | 13.5 | 19.6 |
| both | destructive | lease_check | 20726 | 31.9 | 29.1 | 50 |
| both | destructive | policy | 20726 | 134 | 150.8 | 196.9 |
| both | destructive | audit_append | 20726 | 191.7 | 159.8 | 275.5 |
| both | destructive | blocking_pool | 20726 | 145.3 | 132.1 | 250.4 |
| both | destructive | upstream | 20726 | 312 | 291.9 | 486.5 |
| both | destructive | response | 20726 | 384.4 | 350 | 502.9 |
| both | destructive | total | 20726 | 2171 | 1798.1 | 4282.6 |
| both | destructive | decide (whole, mean) | | 1269.8 | | |
| both | destructive | decide (unstaged, mean) | | 912.2 | | |
| both | destructive | result append (mean) | 20726 | 152 | | |

### Approval round (2000 rounds)

| step | count | p50 us | p95 us | p99 us | mean us |
|---|---|---|---|---|---|
| gated_call | 2000 | 995.8 | 1705 | 3792.9 | 1103.1 |
| grant | 2000 | 704 | 1325.1 | 3557.4 | 796.2 |
| retry | 2000 | 1505.3 | 2822.1 | 6459.4 | 1897.1 |
| round | 2000 | 3313.7 | 5939.2 | 9347.1 | 3796.4 |

Server stages over the measured rounds:

| stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|
| token_verify_hit | 4000 | 10.8 | 9.6 | 19.3 |
| lease_check | 4000 | 45.3 | 43 | 72.5 |
| policy | 4000 | 173.7 | 164.3 | 285.3 |
| audit_append | 4000 | 146 | 140.5 | 247.5 |
| blocking_pool | 4000 | 148.7 | 103.7 | 280.1 |
| upstream | 2000 | 332.8 | 276.1 | 495.8 |
| response | 2000 | 626 | 354.5 | 675 |
| total | 4000 | 1203.9 | 969.4 | 1983 |

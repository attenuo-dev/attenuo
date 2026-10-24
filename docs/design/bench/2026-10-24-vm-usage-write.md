# Run usage write: `attenuo-bench hot-path` and `decide` cells (2026-10-24)

Branch `perf/usage-write-elision`, main `8dca83d`. Release build with `lto = false` and `codegen-units = 16`; shared 4-vCPU container, load average 1.0 to 5.9. File store at `durability = "normal"`, one client, 2-hop token, 2 s warm-up and 10 s measured per cell, 5 interleaved runs per pass. `baseline`: no policy reads `context.usage` and no catalog `amount`/`destination`, so usage is elided. `usage`: the same plus `[policy] track_usage = true`, which is what every allowed destructive call did on main since #59. See [performance](../performance.md#run-usage-write-2026-10-24).

## Pass 1 (`--configs baseline,usage`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`) and whether it carries run usage (`usage`) in its record.

| config | call | counters charged | tainted_by | usage |
|---|---|---|---|---|
| baseline | read | 0 | 0 | false |
| baseline | destructive | 0 | 0 | false |
| usage | read | 0 | 0 | false |
| usage | destructive | 0 | 0 | true |

#### Client latency per configuration

Medians over the runs of each run's p50, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|
| baseline | read | 5 | 1208.3 | 1106.9 to 1266.7 | 1688.6 | 3627 | 732 |
| baseline | destructive | 5 | 1228.8 | 1077.2 to 1364 | 1760.3 | 2711.6 | 747 |
| usage | read | 5 | 1254.4 | 1116.2 to 1267.7 | 1720.3 | 2650.1 | 742 |
| usage | destructive | 5 | 1327.1 | 1300.5 to 1531.9 | 1995.8 | 4223 | 666 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| baseline | read | token_verify_hit | 37312 | 9.9 | 9.3 | 18.9 |
| baseline | read | lease_check | 37316 | 46.4 | 44.2 | 69.9 |
| baseline | read | policy | 37316 | 121.7 | 137.7 | 195.6 |
| baseline | read | audit_append | 37316 | 160.3 | 108.9 | 194.5 |
| baseline | read | blocking_pool | 37316 | 108.9 | 87.9 | 192.4 |
| baseline | read | upstream | 37317 | 281.9 | 266.3 | 473.9 |
| baseline | read | response | 37317 | 326.2 | 275.9 | 482.9 |
| baseline | read | total | 37317 | 1120.7 | 984.2 | 1932.5 |
| baseline | read | decide (whole, mean) | | 348.5 | | |
| baseline | read | decide (unstaged, mean) | | 20 | | |
| baseline | read | result append (mean) | 37317 | 145.9 | | |
| baseline | destructive | token_verify_hit | 37109 | 9.8 | 9.2 | 18.9 |
| baseline | destructive | lease_check | 37110 | 44.5 | 42.9 | 69.4 |
| baseline | destructive | policy | 37110 | 120.4 | 135.9 | 195.4 |
| baseline | destructive | audit_append | 37110 | 154.9 | 106.8 | 194.7 |
| baseline | destructive | blocking_pool | 37110 | 114.4 | 91.8 | 195.2 |
| baseline | destructive | upstream | 37110 | 280.1 | 264.4 | 476.1 |
| baseline | destructive | response | 37110 | 336.6 | 280.9 | 486 |
| baseline | destructive | total | 37110 | 1125.8 | 984.2 | 1931.9 |
| baseline | destructive | decide (whole, mean) | | 340 | | |
| baseline | destructive | decide (unstaged, mean) | | 20.3 | | |
| baseline | destructive | result append (mean) | 37110 | 150.9 | | |
| usage | read | token_verify_hit | 37176 | 10.1 | 9.3 | 19 |
| usage | read | lease_check | 37178 | 45.7 | 43.2 | 69.9 |
| usage | read | policy | 37178 | 121.4 | 135.3 | 195.6 |
| usage | read | audit_append | 37178 | 157.4 | 108.1 | 194.7 |
| usage | read | blocking_pool | 37179 | 112.4 | 92.1 | 195.3 |
| usage | read | upstream | 37179 | 287.8 | 272.7 | 478.7 |
| usage | read | response | 37179 | 319.1 | 278.2 | 484 |
| usage | read | total | 37179 | 1119.3 | 1015.5 | 1932.1 |
| usage | read | decide (whole, mean) | | 344.3 | | |
| usage | read | decide (unstaged, mean) | | 19.9 | | |
| usage | read | result append (mean) | 37180 | 141.9 | | |
| usage | destructive | token_verify_hit | 32707 | 10.1 | 9.4 | 19.1 |
| usage | destructive | lease_check | 32707 | 47.4 | 45.4 | 75.4 |
| usage | destructive | policy | 32707 | 135.4 | 150.7 | 198 |
| usage | destructive | audit_append | 32707 | 188.8 | 153.6 | 254.8 |
| usage | destructive | blocking_pool | 32707 | 121 | 98.3 | 198.1 |
| usage | destructive | upstream | 32708 | 300.9 | 283.7 | 483.1 |
| usage | destructive | response | 32708 | 365.3 | 293.2 | 489.1 |
| usage | destructive | total | 32708 | 1294.3 | 1334.2 | 1962.1 |
| usage | destructive | decide (whole, mean) | | 448.4 | | |
| usage | destructive | decide (unstaged, mean) | | 76.9 | | |
| usage | destructive | result append (mean) | 32708 | 179 | | |


## Pass 2 (`--configs usage,baseline`)

#### Configuration check

One extra call per configuration and call after the runs: counters its decision charged, label sources (`labels.tainted_by`) and whether it carries run usage (`usage`) in its record.

| config | call | counters charged | tainted_by | usage |
|---|---|---|---|---|
| usage | read | 0 | 0 | false |
| usage | destructive | 0 | 0 | true |
| baseline | read | 0 | 0 | false |
| baseline | destructive | 0 | 0 | false |

#### Client latency per configuration

Medians over the runs of each run's p50, p95 and p99 (closed loop), and the lowest and highest p50 of the runs.

| config | call | runs | p50 us | p50 range | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|---|
| usage | read | 5 | 1213.4 | 1179.6 to 1351.7 | 1880.1 | 3026.9 | 710 |
| usage | destructive | 5 | 1426.4 | 1206.3 to 1439.7 | 1945.6 | 4247.6 | 659 |
| baseline | read | 5 | 1190.9 | 1121.3 to 1264.6 | 1938.4 | 3827.7 | 741 |
| baseline | destructive | 5 | 1282 | 1115.1 to 1334.3 | 2603 | 5541.9 | 689 |

#### Server stages per configuration

`attenuo_proxy_stage_seconds` pooled over the runs' measured windows; p50 and p95 interpolated inside buckets, mean exact. `decide (unstaged)` is the decision time outside lease check, policy and audit append (the budget charge, among others); `result append` is the mean `tool_result` append. Both are means derived from `attenuo_authorize_duration_seconds` and `attenuo_audit_append_duration_seconds`.

| config | call | stage | count | mean us | p50 us | p95 us |
|---|---|---|---|---|---|---|
| usage | read | token_verify_hit | 34984 | 10.3 | 9.3 | 19 |
| usage | read | lease_check | 34985 | 46.7 | 44.3 | 71.6 |
| usage | read | policy | 34985 | 121 | 137.4 | 195.5 |
| usage | read | audit_append | 34985 | 197.4 | 106 | 194.5 |
| usage | read | blocking_pool | 34985 | 124.3 | 93.5 | 198 |
| usage | read | upstream | 34987 | 292.1 | 271 | 479.5 |
| usage | read | response | 34987 | 342.9 | 284.7 | 489.4 |
| usage | read | total | 34987 | 1200.8 | 1045.3 | 1950.5 |
| usage | read | decide (whole, mean) | | 385.3 | | |
| usage | read | decide (unstaged, mean) | | 20.3 | | |
| usage | read | result append (mean) | 34987 | 147.1 | | |
| usage | destructive | token_verify_hit | 32538 | 10.2 | 9.3 | 19 |
| usage | destructive | lease_check | 32542 | 48.5 | 45.7 | 76.6 |
| usage | destructive | policy | 32542 | 137 | 151.2 | 198.4 |
| usage | destructive | audit_append | 32542 | 184.7 | 153.7 | 255.8 |
| usage | destructive | blocking_pool | 32542 | 130 | 99.3 | 218.7 |
| usage | destructive | upstream | 32543 | 296.5 | 276.8 | 484.1 |
| usage | destructive | response | 32543 | 373.8 | 296.4 | 495.5 |
| usage | destructive | total | 32543 | 1306.1 | 1354.7 | 1976.3 |
| usage | destructive | decide (whole, mean) | | 447.1 | | |
| usage | destructive | decide (unstaged, mean) | | 77 | | |
| usage | destructive | result append (mean) | 32542 | 173.3 | | |
| baseline | read | token_verify_hit | 36648 | 9.8 | 9.1 | 18.8 |
| baseline | read | lease_check | 36651 | 45.1 | 42.8 | 69.6 |
| baseline | read | policy | 36651 | 119.3 | 131.7 | 194.8 |
| baseline | read | audit_append | 36651 | 159.9 | 106 | 194.2 |
| baseline | read | blocking_pool | 36651 | 123.1 | 89.1 | 199.2 |
| baseline | read | upstream | 36651 | 283.2 | 263.3 | 479.6 |
| baseline | read | response | 36651 | 336.9 | 275.3 | 491.5 |
| baseline | read | total | 36651 | 1142.1 | 978.6 | 1954.8 |
| baseline | read | decide (whole, mean) | | 344.2 | | |
| baseline | read | decide (unstaged, mean) | | 20 | | |
| baseline | read | result append (mean) | 36651 | 144.8 | | |
| baseline | destructive | token_verify_hit | 33959 | 10.1 | 9.2 | 18.9 |
| baseline | destructive | lease_check | 33961 | 50.2 | 47 | 77.1 |
| baseline | destructive | policy | 33961 | 125 | 142.3 | 196.1 |
| baseline | destructive | audit_append | 33961 | 164.6 | 119.4 | 196.2 |
| baseline | destructive | blocking_pool | 33961 | 153.8 | 94.3 | 244.7 |
| baseline | destructive | upstream | 33961 | 289.5 | 261.4 | 479.6 |
| baseline | destructive | response | 33961 | 387 | 298.2 | 499.9 |
| baseline | destructive | total | 33961 | 1247.2 | 1088 | 2014.5 |
| baseline | destructive | decide (whole, mean) | | 360.6 | | |
| baseline | destructive | decide (unstaged, mean) | | 20.8 | | |
| baseline | destructive | result append (mean) | 33961 | 160.9 | | |


## `cargo bench -p attenuo-server --bench decide` (criterion, `--warm-up-time 1 --measurement-time 3`)

First run of all cells, in the bench's order:

```text
decide/decide_destructive_memory/tracked time: [149.65 µs 153.50 µs 157.39 µs]
decide/decide_destructive_memory/elided time: [169.92 µs 173.13 µs 176.50 µs]
decide/charge_memory/usage time: [26.529 µs 27.999 µs 29.338 µs]
decide/decide_destructive_file/tracked time: [259.42 µs 289.64 µs 326.69 µs]
decide/decide_destructive_file/elided time: [142.62 µs 153.70 µs 165.99 µs]
decide/charge_file/usage time: [32.007 µs 33.720 µs 36.044 µs]
decide/decide_destructive_file_full/tracked time: [1.1509 ms 1.2188 ms 1.3150 ms]
decide/decide_destructive_file_full/elided time: [454.73 µs 476.16 µs 497.16 µs]
decide/charge_file_full/usage time: [365.53 µs 384.91 µs 406.19 µs]
```

Then `decide_destructive_.*/elided` and `.../tracked` alone, alternating, twice each:

```text
decide_destructive_memory/elided     [135.80 141.77 147.03] us   [138.49 146.68 154.86] us
decide_destructive_file/elided       [146.18 152.92 160.56] us   [134.04 140.06 146.74] us
decide_destructive_file_full/elided  [467.42 485.82 506.64] us   [540.23 565.14 589.58] us
decide_destructive_memory/tracked    [149.24 153.13 156.79] us   [162.47 169.72 176.56] us
decide_destructive_file/tracked      [259.70 308.98 370.39] us   [280.97 323.50 373.95] us
decide_destructive_file_full/tracked [1.3022 1.4494 1.6791] ms   [1.1904 1.2342 1.2803] ms
```

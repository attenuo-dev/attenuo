# End-to-end benchmark, 2026-10-23, vm (upstream hop and blocking pool, rerun)

Commit `5b9d17a` (the reverted `[proxy] inline_decisions` experiment, kept in history for this), release profile, rustc 1.99.1 (58cf8f9c3 2026-10-13).
Per cell: 2 s warm-up (discarded), 8 s measured, closed loop, 1 hop, allow call.

Rerun of the cells quoted in [performance.md, Upstream hop and blocking pool](../performance.md#upstream-hop-and-blocking-pool-2026-10-23-follow-up), whose first run kept no results file. The binaries were built from `git archive 5b9d17a` (crates still named `onbehalf-*` at that commit) into a separate target directory; nothing in the tree changed. `blocking_pool` is the behaviour of main; `when_idle` runs a decision on the async worker when no other decision is in flight (the doc's "inline"). Single client: three runs, the four variants interleaved in each. Eight clients, memory store: two runs, interleaved. The `block_in_place` variant and the always-inline variant the doc quotes at 8 clients are not in that commit and were not rerun. Shared 4 vCPU container; load average 0.5 to 1.6 during the single-client cells and up to 4.5 during the eight-client cells (this run's own load), uptime per cell below.

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

## Summary

Single client, 1 hop, allow call. Median of the three runs, range in brackets; microseconds except calls/s. Stage p50s are from `onbehalf_proxy_stage_seconds` (interpolated inside buckets).

| | memory, `blocking_pool` | memory, `when_idle` | file, `blocking_pool` | file, `when_idle` |
|---|---|---|---|---|
| client p50 | 691 [562-693] | 636 [604-637] | 708 [620-747] | 701 [681-704] |
| client p99 | 1510 [1286-1711] | 1348 [1341-1371] | 1606 [1560-1704] | 1476 [1434-1709] |
| calls/s | 1373 [1351-1648] | 1510 [1506-1570] | 1312 [1272-1451] | 1356 [1339-1379] |
| `blocking_pool` p50 | 69 [58-69] | 1.4 [1.4-1.4] | 69 [61-74] | 1.5 [1.5-1.5] |
| `upstream` p50 | 210 [170-211] | 236 [221-237] | 206 [180-216] | 251 [243-252] |
| `total` (handler) p50 | 460 [386-461] | 405 [390-405] | 484 [435-512] | 456 [443-456] |
| direct p50 (baseline) | 100 [97-100] | 98 [97-102] | 98 [95-102] | 99 [98-99] |

Eight clients, memory store, calls/s per run: `blocking_pool` 5,814 and 5,824; `when_idle` 5,669 and 5,732.

Idle-gap probe (Python `http.client`, one keep-alive connection straight to the `fake_mcp` of the same build, 5,000 calls per pause after 500 discarded; p50 in microseconds, two runs):

| Pause between calls | p50, us (two runs) |
|---|---|
| none | 174, 162 |
| 500 us `sleep` | 391, 351 |
| 500 us busy loop in the client | 274, 280 |

The probe ran right after the eight-client cells, at load average 3.3 to 4.2.

```
# run 1,  20:56:29 up  3:19,  0 user,  load average: 4.18, 2.48, 2.18
none	174
sleep	391
busy	274
# run 2,  20:56:40 up  3:19,  0 user,  load average: 3.76, 2.45, 2.17
none	162
sleep	351
busy	280
# end,  20:56:50 up  3:20,  0 user,  load average: 3.26, 2.38, 2.15
```

The probe, run as `python3 -I probe.py PORT 5000` against `fake_mcp --port PORT`:

```python
"""Idle-gap probe: p50 of one tools/call to fake_mcp over one keep-alive connection,
with no pause, a 500 us sleep, or a 500 us busy loop between calls."""
import http.client, json, statistics, sys, time

port = int(sys.argv[1]); n = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "read_file",
                              "arguments": {"repo": "alice/public-docs", "path": "README.md"}}})
hdr = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
conn = http.client.HTTPConnection("127.0.0.1", port)

def call():
    t = time.perf_counter_ns()
    conn.request("POST", "/mcp", body, hdr)
    r = conn.getresponse(); r.read()
    assert r.status == 200, r.status
    return (time.perf_counter_ns() - t) / 1000

def run(pause):
    xs = []
    for _ in range(n):
        xs.append(call())
        if pause == "sleep":
            time.sleep(0.0005)
        elif pause == "busy":
            end = time.perf_counter_ns() + 500_000
            while time.perf_counter_ns() < end:
                pass
    return statistics.median(xs)

for _ in range(500):
    call()
for pause in ("none", "sleep", "busy"):
    print(f"{pause}\t{run(pause):.0f}")
```

Uptime at the start of each cell:

```
c1 run1 memory blocking_pool  20:50:54 up  3:14,  0 user,  load average: 0.49, 1.46, 1.95
c1 run1 memory when_idle  20:51:15 up  3:14,  0 user,  load average: 0.89, 1.47, 1.94
c1 run1 file blocking_pool  20:51:35 up  3:14,  0 user,  load average: 1.13, 1.49, 1.94
c1 run1 file when_idle  20:51:55 up  3:15,  0 user,  load average: 1.18, 1.47, 1.92
c1 run2 memory blocking_pool  20:52:16 up  3:15,  0 user,  load average: 1.12, 1.44, 1.90
c1 run2 memory when_idle  20:52:36 up  3:15,  0 user,  load average: 1.23, 1.44, 1.90
c1 run2 file blocking_pool  20:52:56 up  3:16,  0 user,  load average: 1.48, 1.48, 1.90
c1 run2 file when_idle  20:53:16 up  3:16,  0 user,  load average: 1.48, 1.48, 1.89
c1 run3 memory blocking_pool  20:53:37 up  3:16,  0 user,  load average: 1.63, 1.52, 1.89
c1 run3 memory when_idle  20:53:57 up  3:17,  0 user,  load average: 1.53, 1.50, 1.88
c1 run3 file blocking_pool  20:54:17 up  3:17,  0 user,  load average: 1.60, 1.52, 1.88
c1 run3 file when_idle  20:54:37 up  3:17,  0 user,  load average: 1.44, 1.48, 1.86
c8 run1 memory blocking_pool  20:54:58 up  3:18,  0 user,  load average: 1.38, 1.47, 1.85
c8 run1 memory when_idle  20:55:18 up  3:18,  0 user,  load average: 2.93, 1.81, 1.95
c8 run2 memory blocking_pool  20:55:39 up  3:18,  0 user,  load average: 3.93, 2.10, 2.04
c8 run2 memory when_idle  20:56:00 up  3:19,  0 user,  load average: 4.44, 2.34, 2.12
end  20:56:20 up  3:19,  0 user,  load average: 4.54, 2.52, 2.19
```

## Results

### 1 client, run 1, audit = memory, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9444 | 97.2 | 131.2 | 238.1 | 5795.8 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1648 | 561.7 | 827.9 | 1286.1 | 9945.1 | 464.5 | 1048 | 500.5 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 13183 | 3.8 | 3.3 | 5.8 |
| 1 | allow | 1 | lease_check | 13183 | 9.8 | 8.2 | 17.6 |
| 1 | allow | 1 | policy | 13183 | 41.8 | 39.4 | 64.1 |
| 1 | allow | 1 | audit_append | 13183 | 53.9 | 45 | 93.6 |
| 1 | allow | 1 | blocking_pool | 13183 | 66 | 57.5 | 96.5 |
| 1 | allow | 1 | upstream | 13184 | 185.1 | 169.6 | 281.3 |
| 1 | allow | 1 | response | 13184 | 7.7 | 6.6 | 15.4 |
| 1 | allow | 1 | total | 13184 | 401.4 | 385.6 | 600.9 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 16091 | 16089 | 16 |

### 1 client, run 1, audit = memory, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9318 | 97.2 | 132.6 | 258.4 | 6836.2 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1570 | 604.2 | 848.9 | 1347.6 | 7487.5 | 507 | 1089.2 | 529.3 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 12558 | 4.7 | 4.4 | 6.5 |
| 1 | allow | 1 | lease_check | 12558 | 11.2 | 10.6 | 18.6 |
| 1 | allow | 1 | policy | 12558 | 44 | 41.7 | 64.6 |
| 1 | allow | 1 | audit_append | 12558 | 57.3 | 48.1 | 93.6 |
| 1 | allow | 1 | blocking_pool | 12558 | 1.4 | 1.4 | 1.9 |
| 1 | allow | 1 | upstream | 12559 | 236 | 220.6 | 395.4 |
| 1 | allow | 1 | response | 12559 | 10.1 | 9.2 | 17.9 |
| 1 | allow | 1 | total | 12559 | 401.5 | 389.9 | 597.7 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 15709 | 15707 | 15 |

### 1 client, run 1, audit = file, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9536 | 95.4 | 127.9 | 242.6 | 4268 |

#### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1451 | 620.5 | 940 | 1605.6 | 29933.6 | 525.1 | 1363 | 584.3 |

#### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 11603 | 4.1 | 3.8 | 6.2 |
| 1 | allow | 1 | lease_check | 11603 | 27.4 | 24.4 | 45.9 |
| 1 | allow | 1 | policy | 11603 | 41.7 | 39.6 | 63.8 |
| 1 | allow | 1 | audit_append | 11603 | 85.5 | 65.1 | 108.7 |
| 1 | allow | 1 | blocking_pool | 11603 | 73.4 | 61 | 129.1 |
| 1 | allow | 1 | upstream | 11604 | 199.9 | 179.6 | 298.2 |
| 1 | allow | 1 | response | 11604 | 8.1 | 7.1 | 16.3 |
| 1 | allow | 1 | total | 11604 | 475.4 | 434.7 | 673.2 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| file | true | 14123 | 14121 | 14 |

### 1 client, run 1, audit = file, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9124 | 99.3 | 139.1 | 257.4 | 4206.6 |

#### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1339 | 703.5 | 950.3 | 1709.1 | 14819.3 | 604.2 | 1451.7 | 636.7 |

#### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 10714 | 5.1 | 4.6 | 6.6 |
| 1 | allow | 1 | lease_check | 10714 | 31.1 | 29.3 | 47.9 |
| 1 | allow | 1 | policy | 10714 | 47.7 | 44 | 66.5 |
| 1 | allow | 1 | audit_append | 10714 | 92.9 | 75.1 | 142.2 |
| 1 | allow | 1 | blocking_pool | 10714 | 1.5 | 1.5 | 2 |
| 1 | allow | 1 | upstream | 10715 | 267.2 | 252.1 | 437.1 |
| 1 | allow | 1 | response | 10715 | 10 | 9.3 | 17.9 |
| 1 | allow | 1 | total | 10715 | 493.9 | 456.5 | 668.3 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| file | true | 13202 | 13200 | 13 |

### 1 client, run 2, audit = memory, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9088 | 100.3 | 138.1 | 248.6 | 6332.4 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1373 | 690.7 | 976.9 | 1510.4 | 8822.8 | 590.4 | 1261.8 | 617.8 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 10986 | 4.5 | 4.2 | 6.5 |
| 1 | allow | 1 | lease_check | 10986 | 12.6 | 11.6 | 19.1 |
| 1 | allow | 1 | policy | 10986 | 49.4 | 48.2 | 68.6 |
| 1 | allow | 1 | audit_append | 10986 | 62.8 | 54.4 | 104.9 |
| 1 | allow | 1 | blocking_pool | 10986 | 82.4 | 69.3 | 153.5 |
| 1 | allow | 1 | upstream | 10986 | 226 | 210.8 | 367.2 |
| 1 | allow | 1 | response | 10986 | 9.5 | 8.6 | 17.6 |
| 1 | allow | 1 | total | 10986 | 487.3 | 460.6 | 682.9 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 13858 | 13856 | 13 |

### 1 client, run 2, audit = memory, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9300 | 98.2 | 134.3 | 240.9 | 5308.4 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1506 | 637.4 | 875 | 1341.4 | 6295.6 | 539.2 | 1100.5 | 556.2 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 12046 | 4.9 | 4.4 | 6.5 |
| 1 | allow | 1 | lease_check | 12046 | 11.8 | 11 | 18.7 |
| 1 | allow | 1 | policy | 12046 | 45.6 | 42.7 | 66 |
| 1 | allow | 1 | audit_append | 12046 | 59.1 | 49.1 | 96.4 |
| 1 | allow | 1 | blocking_pool | 12046 | 1.4 | 1.4 | 1.9 |
| 1 | allow | 1 | upstream | 12047 | 249 | 236.6 | 416.5 |
| 1 | allow | 1 | response | 12047 | 10.2 | 9.3 | 18 |
| 1 | allow | 1 | total | 12047 | 419.8 | 404.9 | 620.3 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 15201 | 15199 | 15 |

### 1 client, run 2, audit = file, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9308 | 97.5 | 133.4 | 262.4 | 3749.9 |

#### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1312 | 708.1 | 1004 | 1703.9 | 13598.7 | 610.6 | 1441.5 | 654.4 |

#### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 10492 | 4.6 | 4.2 | 6.5 |
| 1 | allow | 1 | lease_check | 10493 | 31.2 | 28.8 | 47.8 |
| 1 | allow | 1 | policy | 10493 | 45.5 | 43.1 | 66.3 |
| 1 | allow | 1 | audit_append | 10493 | 89.8 | 72.1 | 133.8 |
| 1 | allow | 1 | blocking_pool | 10493 | 83.2 | 68.9 | 155.8 |
| 1 | allow | 1 | upstream | 10493 | 221.3 | 206.1 | 354.2 |
| 1 | allow | 1 | response | 10493 | 9.2 | 8.6 | 17.6 |
| 1 | allow | 1 | total | 10493 | 523.5 | 483.5 | 697.3 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| file | true | 13080 | 13078 | 13 |

### 1 client, run 2, audit = file, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9230 | 98.8 | 133.8 | 240.1 | 24526.8 |

#### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1379 | 681 | 900.6 | 1475.6 | 54526 | 582.2 | 1235.5 | 616.5 |

#### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 11031 | 4.9 | 4.6 | 6.6 |
| 1 | allow | 1 | lease_check | 11031 | 30.6 | 28.9 | 47.7 |
| 1 | allow | 1 | policy | 11031 | 46.4 | 43.6 | 66 |
| 1 | allow | 1 | audit_append | 11031 | 90.6 | 73.6 | 137.2 |
| 1 | allow | 1 | blocking_pool | 11031 | 1.5 | 1.5 | 1.9 |
| 1 | allow | 1 | upstream | 11031 | 255.8 | 243.4 | 416.7 |
| 1 | allow | 1 | response | 11031 | 9.8 | 9.4 | 18 |
| 1 | allow | 1 | total | 11031 | 476.9 | 442.7 | 652.4 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| file | true | 13720 | 13718 | 13 |

### 1 client, run 3, audit = memory, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9160 | 99.8 | 137.9 | 238.3 | 10321.9 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1351 | 692.7 | 996.4 | 1711.1 | 7262.2 | 592.9 | 1472.8 | 630.6 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 10808 | 4.6 | 4.2 | 6.5 |
| 1 | allow | 1 | lease_check | 10808 | 13 | 12.3 | 19.1 |
| 1 | allow | 1 | policy | 10808 | 50.4 | 49 | 68.5 |
| 1 | allow | 1 | audit_append | 10808 | 63.9 | 54.6 | 105.6 |
| 1 | allow | 1 | blocking_pool | 10808 | 84.1 | 69 | 155.6 |
| 1 | allow | 1 | upstream | 10809 | 229.1 | 209.9 | 378.1 |
| 1 | allow | 1 | response | 10809 | 9.4 | 8.6 | 17.7 |
| 1 | allow | 1 | total | 10809 | 494.4 | 459.6 | 689.5 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 14111 | 14109 | 14 |

### 1 client, run 3, audit = memory, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 8915 | 102.2 | 139.1 | 248.2 | 32129 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1510 | 635.9 | 868.4 | 1371.1 | 6594.6 | 533.7 | 1122.9 | 549.8 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 12079 | 4.7 | 4.4 | 6.5 |
| 1 | allow | 1 | lease_check | 12079 | 12 | 11.4 | 18.8 |
| 1 | allow | 1 | policy | 12079 | 45.7 | 42.6 | 65.8 |
| 1 | allow | 1 | audit_append | 12079 | 59 | 49.4 | 97.2 |
| 1 | allow | 1 | blocking_pool | 12079 | 1.4 | 1.4 | 1.9 |
| 1 | allow | 1 | upstream | 12080 | 249 | 236.3 | 414.6 |
| 1 | allow | 1 | response | 12080 | 9.9 | 9.2 | 17.9 |
| 1 | allow | 1 | total | 12079 | 418.8 | 405.3 | 618.5 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 15184 | 15182 | 15 |

### 1 client, run 3, audit = file, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 8984 | 101.8 | 138 | 262.4 | 3424.3 |

#### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1272 | 747 | 1018.9 | 1559.6 | 16842.8 | 645.2 | 1297.2 | 674.5 |

#### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 10174 | 4.5 | 4.2 | 6.5 |
| 1 | allow | 1 | lease_check | 10174 | 34.4 | 32.6 | 49.1 |
| 1 | allow | 1 | policy | 10174 | 48.7 | 46.1 | 67.9 |
| 1 | allow | 1 | audit_append | 10174 | 91.7 | 76.9 | 147.8 |
| 1 | allow | 1 | blocking_pool | 10174 | 85.6 | 73.9 | 162.1 |
| 1 | allow | 1 | upstream | 10175 | 228.7 | 215.8 | 367.4 |
| 1 | allow | 1 | response | 10175 | 9.4 | 8.8 | 17.8 |
| 1 | allow | 1 | total | 10175 | 543.9 | 512.3 | 740.6 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| file | true | 12797 | 12795 | 12 |

### 1 client, run 3, audit = file, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 9229 | 98.4 | 134.3 | 262.4 | 6377.5 |

#### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1356 | 700.9 | 935.4 | 1433.6 | 17694.7 | 602.5 | 1171.2 | 629 |

#### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 10844 | 4.9 | 4.5 | 6.6 |
| 1 | allow | 1 | lease_check | 10844 | 31.4 | 29.4 | 47.9 |
| 1 | allow | 1 | policy | 10844 | 47 | 43.9 | 66.4 |
| 1 | allow | 1 | audit_append | 10844 | 92.3 | 74.7 | 143.6 |
| 1 | allow | 1 | blocking_pool | 10844 | 1.6 | 1.5 | 2 |
| 1 | allow | 1 | upstream | 10845 | 261.4 | 251.3 | 432 |
| 1 | allow | 1 | response | 10844 | 10.3 | 9.4 | 18 |
| 1 | allow | 1 | total | 10844 | 487.6 | 455.5 | 663.1 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| file | true | 13677 | 13675 | 13 |

### 8 clients, run 1, audit = memory, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 8 | 28127 | 244.9 | 476.4 | 891.9 | 10494 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | 5814 | 1283.1 | 2047 | 3094.5 | 10936.3 | 1038.2 | 2202.6 | 1091.6 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | token_verify_hit | 46501 | 7.4 | 3.9 | 6.3 |
| 1 | allow | 8 | lease_check | 46506 | 58 | 10.1 | 194.1 |
| 1 | allow | 8 | policy | 46506 | 51.8 | 37.8 | 69.1 |
| 1 | allow | 8 | audit_append | 46506 | 298.1 | 211.5 | 684.4 |
| 1 | allow | 8 | blocking_pool | 46506 | 173.3 | 123.5 | 390.1 |
| 1 | allow | 8 | upstream | 46507 | 377.5 | 324.1 | 682.1 |
| 1 | allow | 8 | response | 46507 | 13.6 | 7.7 | 18.1 |
| 1 | allow | 8 | total | 46507 | 1025.2 | 940.3 | 1843.2 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 59254 | 59252 | 59 |

### 8 clients, run 1, audit = memory, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 8 | 28020 | 248.3 | 480.5 | 871.4 | 9502.7 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | 5669 | 1325.1 | 2083.8 | 3055.6 | 35848.2 | 1076.8 | 2184.2 | 1125.3 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | token_verify_hit | 45349 | 7.1 | 4 | 6.5 |
| 1 | allow | 8 | lease_check | 45351 | 56.8 | 11 | 192.6 |
| 1 | allow | 8 | policy | 45351 | 51.7 | 38.8 | 69.1 |
| 1 | allow | 8 | audit_append | 45351 | 278.3 | 195.2 | 656.6 |
| 1 | allow | 8 | blocking_pool | 45351 | 157.1 | 103.2 | 378.3 |
| 1 | allow | 8 | upstream | 45355 | 412.9 | 351.1 | 762.8 |
| 1 | allow | 8 | response | 45355 | 14.5 | 8.4 | 18.7 |
| 1 | allow | 8 | total | 45355 | 1024.4 | 944.9 | 1843.9 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 57935 | 57933 | 57 |

### 8 clients, run 2, audit = memory, `blocking_pool`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 8 | 29555 | 233.9 | 448.5 | 800.8 | 8577 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | 5824 | 1271.8 | 2053.1 | 3176.4 | 15155.2 | 1037.9 | 2375.6 | 1102.5 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | token_verify_hit | 46587 | 7.5 | 3.8 | 6.3 |
| 1 | allow | 8 | lease_check | 46592 | 59.1 | 10.7 | 195.6 |
| 1 | allow | 8 | policy | 46592 | 52.1 | 38 | 69.4 |
| 1 | allow | 8 | audit_append | 46592 | 294.4 | 206.9 | 674.3 |
| 1 | allow | 8 | blocking_pool | 46592 | 175.3 | 124.9 | 394.2 |
| 1 | allow | 8 | upstream | 46594 | 374.5 | 319.8 | 674.2 |
| 1 | allow | 8 | response | 46594 | 13.2 | 7.6 | 18.1 |
| 1 | allow | 8 | total | 46594 | 1021 | 930.1 | 1844.5 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 59775 | 59773 | 59 |

### 8 clients, run 2, audit = memory, `when_idle`

#### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 8 | 28961 | 237.7 | 458.8 | 839.7 | 60293.1 |

#### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | 5732 | 1289.2 | 2105.3 | 3444.7 | 31064.1 | 1051.5 | 2605 | 1119.5 |

#### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 8 | token_verify_hit | 45842 | 7.4 | 3.8 | 6.3 |
| 1 | allow | 8 | lease_check | 45843 | 57.5 | 10.5 | 192.7 |
| 1 | allow | 8 | policy | 45843 | 50.4 | 37.8 | 68.1 |
| 1 | allow | 8 | audit_append | 45843 | 275.5 | 186.5 | 652 |
| 1 | allow | 8 | blocking_pool | 45844 | 148.8 | 95.5 | 363.4 |
| 1 | allow | 8 | upstream | 45848 | 408.6 | 339.4 | 763.6 |
| 1 | allow | 8 | response | 45848 | 13.7 | 8 | 18.4 |
| 1 | allow | 8 | total | 45848 | 1008.1 | 915.7 | 1845.5 |

#### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 58948 | 58946 | 58 |

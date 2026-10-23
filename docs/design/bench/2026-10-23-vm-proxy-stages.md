# End-to-end benchmark, 2026-10-23, vm

Commit `51f0a89`, release profile, rustc 1.97.0 (2d8144b78 2026-07-07).
Per cell: 2 s warm-up (discarded), 10 s measured, closed loop.

Shared 4-core VM, other agents active; stage breakdown run.

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

### Direct to the upstream (baseline, allow call)

| clients | req/s | p50 us | p90 us | p99 us | max us |
|---|---|---|---|---|---|
| 1 | 11949 | 66.7 | 128.1 | 199.6 | 9297.9 |

### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1413 | 661 | 847.9 | 2009.1 | 9035.8 | 594.3 | 1809.5 | 623.6 |
| 1 | deny_policy | 1 | 2308 | 367.4 | 564.7 | 2279.4 | 11059.2 | 300.7 | 2079.8 | 349.4 |
| 3 | allow | 1 | 1106 | 799.7 | 1183.7 | 3481.6 | 11845.6 | 733 | 3282 | 820.2 |
| 3 | deny_policy | 1 | 1963 | 412.9 | 824.8 | 2801.7 | 9379.8 | 346.2 | 2602.1 | 425.6 |

### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1311 | 712.7 | 899.1 | 2079.7 | 21102.6 | 626.3 | 1832.8 | 658.3 |
| 1 | deny_policy | 1 | 2154 | 409.6 | 548.9 | 2181.1 | 25804.8 | 323.2 | 1934.2 | 359.9 |
| 3 | allow | 1 | 1143 | 806.4 | 999.4 | 3158 | 28835.8 | 720 | 2911.1 | 770.7 |
| 3 | deny_policy | 1 | 2130 | 399.6 | 540.7 | 2738.2 | 40009.7 | 313.2 | 2491.3 | 365.2 |

### Time by stage through the proxy, audit = memory

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 14130 | 5.2 | 4.5 | 6.5 |
| 1 | allow | 1 | lease_check | 14130 | 15.6 | 15 | 19.6 |
| 1 | allow | 1 | policy | 14130 | 53.1 | 47.6 | 68.1 |
| 1 | allow | 1 | audit_append | 14130 | 60.6 | 50.6 | 96.7 |
| 1 | allow | 1 | blocking_pool | 14130 | 86 | 69.7 | 110.6 |
| 1 | allow | 1 | upstream | 14131 | 216.3 | 204.7 | 288.2 |
| 1 | allow | 1 | response | 14131 | 10.5 | 9.5 | 18 |
| 1 | allow | 1 | total | 14131 | 484.9 | 436.6 | 640.3 |
| 1 | deny_policy | 1 | token_verify_hit | 23076 | 4.1 | 4 | 5.4 |
| 1 | deny_policy | 1 | lease_check | 23077 | 13.1 | 12.8 | 19 |
| 1 | deny_policy | 1 | policy | 23077 | 46 | 42.8 | 64.3 |
| 1 | deny_policy | 1 | audit_append | 23077 | 74.9 | 52.2 | 150.7 |
| 1 | deny_policy | 1 | blocking_pool | 23077 | 83.6 | 66.3 | 112.7 |
| 1 | deny_policy | 1 | total | 23077 | 261.5 | 230.9 | 395.3 |
| 3 | allow | 1 | token_verify_hit | 11057 | 9.3 | 8.6 | 12.5 |
| 3 | allow | 1 | lease_check | 11058 | 44 | 42 | 63 |
| 3 | allow | 1 | policy | 11058 | 57.4 | 56.5 | 69.6 |
| 3 | allow | 1 | audit_append | 11058 | 111 | 58.6 | 198.8 |
| 3 | allow | 1 | blocking_pool | 11058 | 122 | 85.1 | 170.2 |
| 3 | allow | 1 | upstream | 11058 | 240.7 | 235.1 | 298.8 |
| 3 | allow | 1 | response | 11058 | 22.8 | 21.4 | 29.1 |
| 3 | allow | 1 | total | 11058 | 652.2 | 577.4 | 926.3 |
| 3 | deny_policy | 1 | token_verify_hit | 19626 | 7.5 | 6.7 | 9.5 |
| 3 | deny_policy | 1 | lease_check | 19627 | 38.9 | 36.4 | 64.8 |
| 3 | deny_policy | 1 | policy | 19627 | 46.1 | 42.7 | 64.8 |
| 3 | deny_policy | 1 | audit_append | 19627 | 100.7 | 49.6 | 193.1 |
| 3 | deny_policy | 1 | blocking_pool | 19627 | 115.8 | 77 | 144.3 |
| 3 | deny_policy | 1 | total | 19627 | 352.3 | 266.6 | 600.5 |

### Time by stage through the proxy, audit = file

From the server's `onbehalf_proxy_stage_seconds` over each measured window. p50 and p90 are interpolated inside histogram buckets (estimates); the mean is exact.

| hops | outcome | clients | stage | count | mean us | p50 us | p90 us |
|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | token_verify_hit | 13110 | 5.3 | 4.7 | 6.6 |
| 1 | allow | 1 | lease_check | 13110 | 35.9 | 36.6 | 48.8 |
| 1 | allow | 1 | policy | 13110 | 50.2 | 46.1 | 67.4 |
| 1 | allow | 1 | audit_append | 13110 | 81.2 | 69.4 | 112.8 |
| 1 | allow | 1 | blocking_pool | 13110 | 96.5 | 73.6 | 135.3 |
| 1 | allow | 1 | upstream | 13111 | 217.6 | 214.5 | 289.2 |
| 1 | allow | 1 | response | 13111 | 11.1 | 10.3 | 18.4 |
| 1 | allow | 1 | total | 13111 | 535.9 | 486.1 | 670.2 |
| 1 | deny_policy | 1 | token_verify_hit | 21539 | 4.7 | 4.3 | 6.3 |
| 1 | deny_policy | 1 | lease_check | 21539 | 31.3 | 31.3 | 47.7 |
| 1 | deny_policy | 1 | policy | 21539 | 43.7 | 40.8 | 62.6 |
| 1 | deny_policy | 1 | audit_append | 21539 | 83.8 | 69.8 | 129.7 |
| 1 | deny_policy | 1 | blocking_pool | 21539 | 112.2 | 80 | 158 |
| 1 | deny_policy | 1 | total | 21539 | 317.9 | 270.2 | 452.3 |
| 3 | allow | 1 | token_verify_hit | 11426 | 9.5 | 8.3 | 9.9 |
| 3 | allow | 1 | lease_check | 11426 | 54.3 | 50 | 68.8 |
| 3 | allow | 1 | policy | 11426 | 54.7 | 48.4 | 68.6 |
| 3 | allow | 1 | audit_append | 11426 | 95.1 | 80.8 | 151.5 |
| 3 | allow | 1 | blocking_pool | 11426 | 115.2 | 82 | 165.4 |
| 3 | allow | 1 | upstream | 11426 | 233.2 | 231.4 | 295.5 |
| 3 | allow | 1 | response | 11426 | 22.1 | 20.9 | 28.9 |
| 3 | allow | 1 | total | 11426 | 627.3 | 585.6 | 699.7 |
| 3 | deny_policy | 1 | token_verify_hit | 21297 | 7.2 | 6.6 | 9.4 |
| 3 | deny_policy | 1 | lease_check | 21298 | 41.2 | 38.2 | 61.9 |
| 3 | deny_policy | 1 | policy | 21298 | 42.5 | 40.6 | 61.3 |
| 3 | deny_policy | 1 | audit_append | 21298 | 85.8 | 68.8 | 122.1 |
| 3 | deny_policy | 1 | blocking_pool | 21298 | 106.5 | 76.9 | 125 |
| 3 | deny_policy | 1 | total | 21298 | 326 | 275.5 | 453.3 |

### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 83069 | 83063 | 83 |
| file | true | 81069 | 81063 | 81 |

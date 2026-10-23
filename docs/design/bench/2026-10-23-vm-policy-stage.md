# End-to-end benchmark, 2026-10-23, vm (perf/policy-stage-and-wal-checkpoints)

Commit `238d914`, release profile, rustc 1.97.0 (2d8144b78 2026-07-07).
Per cell: 2 s warm-up (discarded), 5 s measured, closed loop.

Shared development container; other agents were compiling on the same 4 vCPUs (load average 3.8 when the run started, after 7.5 over the previous five minutes, and 6.7 at the end), so read every cell as plus or minus 20 percent, and the memory group, which ran first and under more load, as no faster than the file group that followed it. Branch perf/policy-stage-and-wal-checkpoints: request cache in the policy engine, WAL checkpoints off the writer, inline commit when the writer is idle. Audit modes memory and file only.

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
| 1 | 8084 | 116.1 | 154.6 | 244.7 | 4354 |
| 8 | 23952 | 276.5 | 578 | 1223.7 | 8527.9 |
| 32 | 32262 | 886.8 | 1611.8 | 2914.3 | 20660.2 |

### Through the proxy, audit = memory

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1765 | 540.7 | 732.7 | 1096.7 | 5513.2 | 424.6 | 852 | 442.7 |
| 1 | allow | 8 | 5246 | 1418.2 | 2299.9 | 3575.8 | 16007.2 | 1141.7 | 2352.1 | 1190.8 |
| 1 | allow | 32 | 6646 | 4505.6 | 7028.7 | 10444.8 | 44400.6 | 3618.8 | 7530.5 | 3822.8 |
| 1 | deny_policy | 1 | 2340 | 343.3 | 729.6 | 1418.2 | 11001.9 | 227.2 | 1173.5 | 303.6 |
| 1 | deny_policy | 8 | 4894 | 1486.8 | 2904.1 | 5091.3 | 11026.4 | 1210.3 | 3867.6 | 1300.8 |
| 1 | deny_policy | 32 | 6355 | 4644.9 | 8233 | 12746.8 | 25903.1 | 3758.1 | 9832.5 | 4043.9 |
| 1 | deny_capability | 1 | 1950 | 367.9 | 1300.5 | 2304 | 7266.3 | 251.8 | 2059.3 | 389 |
| 1 | deny_capability | 8 | 3710 | 2081.8 | 4263.9 | 6869 | 29917.2 | 1805.3 | 5645.3 | 1820.2 |
| 1 | deny_capability | 32 | 5516 | 5472.3 | 9502.7 | 14663.7 | 30113.8 | 4585.5 | 11749.4 | 4806 |
| 3 | allow | 1 | 857 | 855 | 2717.7 | 4825.1 | 9142.3 | 738.9 | 4580.4 | 1042.8 |
| 3 | allow | 8 | 2272 | 3176.4 | 6320.1 | 9969.7 | 38567.9 | 2899.9 | 8746 | 3183.9 |
| 3 | allow | 32 | 3460 | 8691.7 | 14663.7 | 21495.8 | 37453.8 | 7804.9 | 18581.5 | 8256.7 |
| 3 | deny_policy | 1 | 1367 | 495.1 | 1297.4 | 3829.8 | 14934 | 379 | 3585.1 | 607.2 |
| 3 | deny_policy | 8 | 2676 | 2838.5 | 5779.5 | 9363.5 | 31096.8 | 2562 | 8139.8 | 2657.2 |
| 3 | deny_policy | 32 | 3724 | 8085.5 | 14483.5 | 22741 | 36306.9 | 7198.7 | 19826.7 | 7599.7 |
| 3 | deny_capability | 1 | 1370 | 435.7 | 1758.2 | 4694 | 11886.6 | 319.6 | 4449.3 | 606.1 |
| 3 | deny_capability | 8 | 3642 | 1793 | 4050.9 | 7917.6 | 29065.2 | 1516.5 | 6693.9 | 1861.3 |
| 3 | deny_capability | 32 | 7118 | 4206.6 | 7028.7 | 10813.4 | 18579.5 | 3319.8 | 7899.1 | 3503.8 |

### Through the proxy, audit = file

| hops | outcome | clients | req/s | p50 us | p90 us | p99 us | max us | added p50 | added p99 | added mean |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | allow | 1 | 1252 | 747.5 | 983.6 | 2261 | 11526.1 | 630.8 | 1919 | 664.6 |
| 1 | allow | 8 | 4049 | 1714.2 | 3106.8 | 5431.3 | 32079.9 | 1423.1 | 3767.3 | 1607.6 |
| 1 | allow | 32 | 6254 | 4587.5 | 7565.3 | 12976.1 | 48398.3 | 3707.9 | 9465.8 | 4088.1 |
| 1 | deny_policy | 1 | 1939 | 457.2 | 651.8 | 1898.5 | 32243.7 | 340.5 | 1556.5 | 382 |
| 1 | deny_policy | 8 | 5958 | 1035.8 | 2211.8 | 4915.2 | 48594.9 | 744.7 | 3251.2 | 975 |
| 1 | deny_policy | 32 | 9613 | 2666.5 | 5070.8 | 9674.8 | 68616.2 | 1786.9 | 6164.5 | 2301.8 |
| 1 | deny_capability | 1 | 2613 | 325.1 | 483.8 | 1517.6 | 42467.3 | 208.4 | 1175.6 | 248.7 |
| 1 | deny_capability | 8 | 6334 | 921.6 | 2022.4 | 4718.6 | 66027.5 | 630.5 | 3054.6 | 900.1 |
| 1 | deny_capability | 32 | 10732 | 2365.4 | 4358.1 | 8376.3 | 91619.3 | 1485.8 | 4866 | 1954.7 |
| 3 | allow | 1 | 1092 | 887.3 | 1119.2 | 1746.9 | 46759.9 | 770.6 | 1404.9 | 781.9 |
| 3 | allow | 8 | 4547 | 1465.3 | 2396.2 | 4993 | 61669.4 | 1174.2 | 3329 | 1391.6 |
| 3 | allow | 32 | 6652 | 4112.4 | 6610.9 | 10870.8 | 86310.9 | 3232.8 | 7360.5 | 3785.2 |
| 3 | deny_policy | 1 | 1840 | 499.5 | 689.2 | 1246.2 | 56066 | 382.8 | 904.2 | 409.5 |
| 3 | deny_policy | 8 | 4776 | 1283.1 | 2519 | 5959.7 | 86573.1 | 992 | 4295.7 | 1296.3 |
| 3 | deny_policy | 32 | 7625 | 3342.3 | 6037.5 | 11558.9 | 131006.5 | 2462.7 | 8048.6 | 3169.8 |
| 3 | deny_capability | 1 | 2541 | 291.8 | 434.4 | 3543 | 61308.9 | 175.1 | 3201 | 258.3 |
| 3 | deny_capability | 8 | 5087 | 1185.8 | 2183.2 | 5767.2 | 111018 | 894.7 | 4103.2 | 1204.9 |
| 3 | deny_capability | 32 | 8247 | 3061.8 | 5378 | 10051.6 | 135397.4 | 2182.2 | 6541.3 | 2855.9 |

### Audit chain after each run

| audit | verified | entries | proxied calls sent | checkpoints |
|---|---|---|---|---|
| memory | true | 456279 | 456273 | 456 |
| file | true | 633468 | 633462 | 633 |

## Same binary, `wal_checkpoint_seconds` on and off

The matrix above cannot separate the WAL change from host load, so the file store was also run
with one binary and only `[audit] wal_checkpoint_seconds` changed, the variants interleaved
(one-hop allow call, 2 s warm-up, 8 s measured, `onbehalf-bench --onbehalf-url`, a fresh
database per run). `0` is SQLite checkpointing on the writer every 1,000 pages, the behaviour
before this branch. "restart at 4,096 pages" is an intermediate version of the checkpointer that
paused appends more often (see the commit history). Load average 8 to 12 during these runs. Raw
results: `2026-10-23-vm-policy-stage-wal-ab.json`.

| run | variant | 8 clients: req/s, p90, p99 | 32 clients: req/s, p90, p99 |
|---|---|---|---|
| 1 | 5 s (as merged) | 5,295, 2.2 ms, 4.0 ms | 8,055, 5.6 ms, 11.4 ms |
| 2 | 5 s, restart at 4,096 pages | 5,047, 2.3 ms, 5.3 ms | 7,061, 6.3 ms, 27.9 ms |
| 3 | 0 (SQLite on the writer) | 2,720, 4.1 ms, 22.9 ms | 3,396, 22.2 ms, 40.8 ms |
| 4 | 5 s (as merged) | 3,617, 3.5 ms, 8.2 ms | 4,629, 10.4 ms, 23.0 ms |
| 5 | 5 s, restart at 4,096 pages | 3,514, 3.6 ms, 10.0 ms | 4,352, 11.1 ms, 30.0 ms |
| 6 | 0 (SQLite on the writer) | 2,694, 4.2 ms, 21.3 ms | 3,754, 20.1 ms, 33.8 ms |

An earlier pair at the first version (runs at load 7 to 10): `0` gave 2,955 and 3,606 req/s with
p99 20.5 and 15.8 ms at 8 clients; 5 s gave 4,359 and 4,510 req/s with p99 8.2 and 5.8 ms.

# Exchange throughput, lease renewal and open-loop arrivals (shared 4-core VM, 2026-10-23)

Run of `onbehalf-bench exchange`, `onbehalf-bench lease-renew` and `onbehalf-bench --open-loop` on branch `perf/exchange-lease-bench` (base def86a9, release build, rustc 1.97.0), results in [`2026-10-23-vm-exchange-lease.json`](2026-10-23-vm-exchange-lease.json). Discussion in [performance.md](../performance.md#exchange-throughput-lease-renewal-and-open-loop-arrivals-2026-10-23).

**Caveats, read first.** A shared 4-core VM (Intel Xeon @ 2.10 GHz, kernel 6.18.44) while other agents were compiling: the load average was 3 to 10 during the runs (9.7 at the end of the lease run). The load generator, the server and (for the call cells) the upstream share those cores. One run per cell, 10 s measured after 2 s of warm-up, so read every figure as plus or minus 20 percent or worse; the file-store cells near saturation moved much more than that between runs (below). Server CPU is `utime + stime` of the server process from `/proc/<pid>/stat` over the measured window, in 10 ms clock ticks. The exchange server runs with `[token] require_actor_auth = false` so each request can name a fresh actor; the actor's client secret (one SHA-256 comparison) is not checked. In open-loop rows, tokio's timer ticks at 1 ms, so the scheduler dispatches an arrival about 1 ms after its scheduled time (column `lag`); the latency columns count that (they run from the scheduled time), the `svc` columns do not.

**Passes.** The closed-loop exchange cells and the lease cells ran once. The open-loop cells ran twice: the first pass lacked the `svc` and `lag` columns and was discarded after they were added. In that first pass the file-store exchange cell at 1,500 arrivals per second reached only 1,023 per second and shed 3,732 arrivals (p50 575 ms), against 1,494 per second and p50 27 ms in the pass reported here, with host load around 8 against 3 to 5. That cell is at the knee of the file store; treat its numbers as a range.

### Token exchange (`POST /token`), closed loop, fresh actor per request

Closed-loop latency runs from send; open-loop latency from the scheduled arrival. `CPU` is the server process over the measured window, in percent of one core and microseconds per request.

| audit | hops in | load | req/s | p50 us | p99 us | max us | shed | server CPU | CPU us/req |
|---|---|---|---|---|---|---|---|---|---|
| memory | 1 | 1 clients | 844 | 1082.4 | 2285.6 | 32325.6 | 0 | 87% | 1026.7 |
| memory | 1 | 8 clients | 2249 | 3203.1 | 9289.7 | 28786.7 | 0 | 261% | 1159.2 |
| memory | 3 | 1 clients | 676 | 1347.6 | 2766.8 | 10231.8 | 0 | 87% | 1282 |
| memory | 3 | 8 clients | 1832 | 3958.8 | 11223 | 27672.6 | 0 | 249% | 1361.1 |
| file | 1 | 1 clients | 649 | 1271.8 | 5705.7 | 26247.2 | 0 | 83% | 1275.1 |
| file | 1 | 8 clients | 1121 | 6086.7 | 23609.3 | 50036.7 | 0 | 130% | 1161.2 |
| file | 3 | 1 clients | 430 | 1398.8 | 11173.9 | 70451.2 | 0 | 59% | 1380.8 |
| file | 3 | 8 clients | 833 | 7786.5 | 44793.9 | 127205.4 | 0 | 117% | 1399.9 |

Audit chain after the run:

| audit | verified | entries | at least |
|---|---|---|---|
| memory | true | 68058 | 56003 |
| file | true | 37332 | 30330 |


### Token exchange, open loop (Poisson arrivals), 1-hop token

Closed-loop latency runs from send; open-loop latency from the scheduled arrival. `CPU` is the server process over the measured window, in percent of one core and microseconds per request. For open-loop rows `svc` is the time from send to answer and `lag` the time the scheduler took to dispatch an arrival (tokio's timer ticks at 1 ms), both of which the latency columns include.

| audit | hops in | load | req/s | p50 us | p99 us | max us | shed | server CPU | CPU us/req | svc p50 / p99 us | lag p50 us |
|---|---|---|---|---|---|---|---|---|---|---|---|
| memory | 1 | open 500/s | 503 | 2533.4 | 7917.6 | 26820.6 | 0 | 56% | 1102.9 | 1311.7 / 5705.7 | 1040.4 |
| memory | 1 | open 1500/s | 1496 | 5636.1 | 33013.8 | 59441.2 | 0 | 166% | 1109.8 | 4169.7 / 30670.8 | 1111 |
| file | 1 | open 500/s | 503 | 3330 | 34570.2 | 83623.9 | 0 | 69% | 1365.3 | 2074.6 / 33439.7 | 1069.1 |
| file | 1 | open 1500/s | 1494 | 27017.2 | 290455.6 | 691011.6 | 0 | 202% | 1344.7 | 25706.5 / 288620.5 | 1071.1 |

Audit chain after the run:

| audit | verified | entries | at least |
|---|---|---|---|
| memory | true | 24015 | 20017 |
| file | true | 24015 | 20017 |


### Lease renewal (`POST /token/renew`)

Each lease renews once per interval, first renewals spread evenly over the first interval. Latency runs from the time the renewal was due (a server that falls behind shows it); service time from the request being sent. `late` counts renewals that finished more than one interval after they were due. Server CPU is over the measured window; idle CPU is the same leases with nothing renewing.

| audit | leases | interval s | offered/s | achieved/s | p50 us | p99 us | max us | svc p50 | svc p99 | late | CPU % of core | CPU us/renewal | idle CPU % | RSS MB before/after |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| memory | 100 | 1 | 100 | 100 | 1501.2 | 4964.4 | 7446.5 | 657.4 | 3422.2 | 0 | 5 | 530 | 0 | 22.2 / 25.5 |
| memory | 1000 | 1 | 1000 | 999.9 | 2033.7 | 56885.2 | 135266.3 | 620.5 | 51118.1 | 0 | 49 | 493 | 0 | 30.1 / 54.4 |
| memory | 5000 | 1 | 5000 | 4985.4 | 23019.5 | 226623.5 | 365428.7 | 15958 | 157286.4 | 0 | 225 | 450.2 | 0 | 68.5 / 206 |
| memory | 5000 | 10 | 500 | 500 | 2209.8 | 6692.9 | 17596.4 | 740.9 | 4341.8 | 0 | 38 | 768 | 0 | 219.6 / 228.6 |
| file | 100 | 1 | 100 | 100 | 2111.5 | 6430.7 | 31457.3 | 849.9 | 4771.8 | 0 | 7 | 740 | 0 | 23 / 24.7 |
| file | 1000 | 1 | 1000 | 999.8 | 2543.6 | 767557.6 | 1141899.3 | 1114.1 | 735576.1 | 4 | 67 | 673 | 0 | 28.5 / 52.7 |
| file | 5000 | 1 | 5000 | 1600.3 | 8271167.5 | 13706985.5 | 14227079.2 | 89849.9 | 396623.9 | 50000 | 113 | 226.6 | 0 | 60.2 / 73.6 |
| file | 5000 | 10 | 500 | 500 | 1874.9 | 75563 | 196476.9 | 952.8 | 74645.5 | 0 | 39 | 788 | 0 | 77 / 77.6 |

### Revoke cascade

Root of a tree of depth 3 (a root, 10 children, 9 grandchildren under each: 100 descendants), revoked through `POST /admin/leases/{id}/revoke`. The time includes the HTTP round trip and the admin audit record.

| audit | runs | revoked leases | min ms | median ms | max ms |
|---|---|---|---|---|---|
| memory | 5 | 101 | 1.04 | 1.2 | 3 |
| file | 5 | 101 | 14.55 | 19.43 | 26.64 |

Audit chain after the run:

| audit | verified | entries | at least |
|---|---|---|---|
| memory | true | 90926 | 66000 |
| file | true | 90926 | 66000 |


### Proxied `tools/call`, open loop (Poisson arrivals)

Latency runs from the scheduled arrival. `achieved` counts correct answers that arrived before the window closed.

| audit | path | hops | offered/s | achieved/s | p50 us | p99 us | max us | shed | server CPU | CPU us/req | svc p50 / p99 us | lag p50 us |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| memory | direct | 0 | 500 | 503 | 1466.4 | 2560 | 16056.3 | 0 | n/a | n/a | 288.8 / 532 | 1097.7 |
| memory | direct | 0 | 2000 | 2014 | 1382.4 | 2922.5 | 12402.7 | 0 | n/a | n/a | 276.2 / 824.8 | 1014.3 |
| memory | allow | 1 | 500 | 503 | 2099.2 | 7082 | 13844.5 | 0 | 26% | 522.7 | 923.1 / 4948 | 1063.9 |
| memory | allow | 1 | 2000 | 2013 | 2054.1 | 6058 | 15458.3 | 0 | 94% | 466.3 | 1028.1 / 4436 | 883.2 |
| file | direct | 0 | 500 | 503 | 1495 | 3287 | 7094.3 | 0 | n/a | n/a | 304.6 / 942.6 | 1101.8 |
| file | direct | 0 | 2000 | 2014 | 1402.9 | 2695.2 | 7045.1 | 0 | n/a | n/a | 301.3 / 754.7 | 999.9 |
| file | allow | 1 | 500 | 503 | 2123.8 | 5427.2 | 21200.9 | 0 | 30% | 606.1 | 974.3 / 2926.6 | 1055.7 |
| file | allow | 1 | 2000 | 2013 | 2060.3 | 17383.4 | 29409.3 | 0 | 106% | 526.9 | 1081.3 / 15614 | 863.2 |

Audit chain after the run:

| audit | verified | entries | at least |
|---|---|---|---|
| memory | true | 30256 | 25170 |
| file | true | 30256 | 25170 |



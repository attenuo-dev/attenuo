# Token verification on a cache miss (2026-10-24)

Branch `perf/ou-sig-kid`, main `e91a139`. What `Verifier::verify` costs when the server's verified-token cache does not answer (the proxy's `token_verify_miss` stage), and what the two ideas of the board's performance follow-up (1) would save: a `kid` on `ou_sig`, and not cloning the chain out of the claims. See [performance](../performance.md#token-verification-on-a-cache-miss-2026-10-24).

## Method

- Machine: the shared 4-vCPU VM (`nproc` 4, Intel Xeon @ 2.10GHz, Linux 6.18.44-fc-v153), rustc 1.99.1. Release builds with the workspace profile (thin LTO, `codegen-units = 1`), not the `lto = false`, `codegen-units = 16` builds of the other 2026-10-24 files, so absolute figures are not comparable with those.
- In process: `cargo bench -p attenuo-token --bench verify -- --warm-up-time 1 --measurement-time 5` (new bench, `crates/attenuo-token/benches/verify.rs`), load average 0.8 to 1.4. Output: [`criterion-verify`](2026-10-24-vm-criterion-verify.txt).
- End to end: `attenuo-bench hot-path --runs 5 --duration 10 --configs baseline --cells read --tokens 5000 --rotate-tokens` (miss) and the same with `--tokens 1` and no `--rotate-tokens` (hit), file store at `durability = "normal"`, one client, 2-hop token, 2 s warm-up and 10 s measured per run. Load average 4.0 to 4.5 during the miss run (21:59 to 22:00 UTC) and 4.0 to 5.3 during the hit run (22:00 to 22:01 UTC). Results: [`verify-miss.json`](2026-10-24-vm-verify-miss.json), [`verify-miss-hit.json`](2026-10-24-vm-verify-miss-hit.json).
- `--rotate-tokens` is new on this branch. `--tokens N` alone cannot make misses: each client keeps one token, and N is at most `--clients`, so every token is verified once and then served from the cache. With `--rotate-tokens` every client sends the next of the N tokens on every call. The cache holds 4,096 tokens and is cleared when full, so cycling through 5,000 makes every call a miss (24,073 misses and 23 hits in the measured windows; each run starts again at the first token, and a few of those can still be cached from the run before). Minting 5,000 two-hop tokens takes about 14 s.
- Each of the 5,000 tokens is its own root, so its own run and its own chain. That also defeats the policy stage's request cache (4,096 `(chain, tool)` entries): `policy` is 410 us p50 in the miss run against 104 us in the hit run. Compare the `token_verify_*` rows between the two runs, not the totals.

## In process (`attenuo-token`, criterion point estimates)

| Cell | 1 hop | 3 hops |
|---|---|---|
| `verify`, one trusted key | 115.7 us | 126.2 us |
| `verify`, three trusted keys, the token's own last | 121.2 us | 133.0 us |
| `DelegationChain::clone` (once per `verify`) | 0.46 us | 1.44 us |
| `ou_sig_message` (the bytes `ou_sig` signs) | 2.06 us | 2.11 us |
| one bare Ed25519 verification (`ring`, 1 KiB) | 53.3 us | |

Two Ed25519 verifications (the outer JWT and `ou_sig`) are 107 us, 92 percent of a 1-hop miss and 84 percent of a 3-hop one. The chain clone is 0.4 and 1.1 percent. Three trusted keys cost the same as one within the noise of this host (the intervals overlap at 1 hop and touch at 3), because the header `kid` and `ou_kid` each pick one key.

## End to end (`attenuo-bench hot-path`, read cell, pooled over 5 runs)

Server stages, microseconds (`attenuo_proxy_stage_seconds`; p50 and p95 interpolated inside buckets, mean exact):

| Stage | hit run: count | mean | p50 | p95 | miss run: count | mean | p50 | p95 |
|---|---|---|---|---|---|---|---|---|
| `token_verify_hit` | 37,446 | 9.4 | 8.8 | 18.4 | 23 | 13.6 | 15 | 19.5 |
| `token_verify_miss` | 0 | | | | 24,073 | 196.1 | 169.5 | 291.2 |
| `lease_check` | 37,447 | 30.4 | 27.3 | 49.4 | 24,097 | 85.9 | 82 | 162.6 |
| `policy` | 37,447 | 108.9 | 103.8 | 192.6 | 24,097 | 421.1 | 410.3 | 603 |
| `audit_append` | 37,447 | 158 | 98 | 193.8 | 24,097 | 146.2 | 145.4 | 228.8 |
| `blocking_pool` | 37,447 | 106.4 | 71.7 | 195.7 | 24,097 | 173.3 | 138 | 264.3 |
| `upstream` | 37,449 | 235.4 | 214.2 | 426.3 | 24,100 | 301.9 | 283.3 | 483 |
| `response` | 37,449 | 454.7 | 372.1 | 856.7 | 24,100 | 444.1 | 380.5 | 622.7 |
| `total` (handler) | 37,449 | 1157.9 | 938.3 | 2046.3 | 24,100 | 1836.3 | 1576.4 | 2891.2 |

Client latency (medians over the runs of each run's figure):

| Run | p50 us | p50 range | p90 us | p95 us | p99 us | req/s |
|---|---|---|---|---|---|---|
| hit (`--tokens 1`) | 1092.6 | 1070.1 to 1230.8 | 1545.2 | 2369.5 | 5054.5 | 739 |
| miss (`--tokens 5000 --rotate-tokens`) | 1933.3 | 1697.8 to 2028.5 | 2371.6 | 2738.2 | 5759 | 482 |

The server's miss is 170 us p50, about 45 us above the in-process `verify` at 2 hops: the cache key (SHA-256 of the token), the cache insert (which clones the verified token, two chains), the timer and this host's load.

## Before and after

| | before (main `e91a139`) | after (this branch) |
|---|---|---|
| `ou_sig` key selection | by `ou_kid`, one key | unchanged (already by `ou_kid` since `ou_sig` v2) |
| chain clone in `verify` | 0.46 / 1.44 us (0.4 / 1.1 % of a miss) | unchanged (kept, below the few-percent bar) |
| `verify`, 1 / 3 hops | 115.7 / 126.2 us | same code; not rerun end to end |
| `token_verify_miss` p50 / mean | 169.5 / 196.1 us | same code; not rerun end to end |

Neither idea applies: the verifier already picks the `ou_sig` key by `ou_kid`, and the clone is about 1 percent. This branch adds the measurements, the `--rotate-tokens` option, a test that a token without `ou_kid` is refused, and the key line of `attenuo token inspect`; the verifier's code is unchanged except for comments, so there is no "after" figure to measure.

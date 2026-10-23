# Performance: micro-benchmarks and end to end

- Status: third measurement, after the policy-stage and WAL work (`perf/policy-stage-and-wal-checkpoints`)
- Crates: `onbehalf-policy` (`benches/authorize.rs`, `benches/policy_stage.rs`), `onbehalf-core` (`benches/attenuation.rs`), `onbehalf-server` (`benches/decide.rs`, the decision path by stage), `onbehalf-bench` (end to end)
- Related: [server pipeline](server.md), [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md)

The first part of this page is criterion 0.5 micro-benchmarks of the two pure functions on the hot path. They do not include token verification, the lease lookup, the audit append or the network hop to the upstream, so they are a lower bound on the latency onbehalf adds to a call. The end-to-end figures, measured through the real proxy, are in [End to end: proxy versus direct](#end-to-end-proxy-versus-direct) at the end of the page, followed by [the audit write path and the per-call cost](#after-the-audit-write-path-work) and [the policy stage and WAL checkpoints](#after-the-policy-stage-and-wal-work), which say what changed and by how much.

## How to run

```
cargo bench --bench authorize --bench attenuation -- --warm-up-time 1 --measurement-time 3
```

Name the bench targets: a bare `cargo bench -- --warm-up-time ...` also passes the flags to each crate's unit-test harness, which rejects them.

## Measurement environment (dev container, not a reference machine)

Taken in a shared Linux development container while other builds were running on the same host, so treat the numbers as indicative: relative sizes mean more than absolute values, and run-to-run noise of 10 percent or more is expected. Rust release profile (`lto = "thin"`, `codegen-units = 1`), 2026-10-22.

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
```

Warm-up 1 s, measurement 3 s, criterion's default 100 samples. Each cell is criterion's `[low estimate high]`; the middle value is the point estimate.

## `PolicyEngine::authorize` with the default policies

The shipped `policies/default.cedar` and a catalog with `read_file` (read-only), `create_issue` (argument rule) and `delete_repo` (sensitive). Chain capabilities are wide (`github:*`) so the capability stage passes; the time is chain-to-Cedar translation plus evaluation. Note that `forbid_deep_chains` denies depth greater than 3, so every 4-hop row is a deny; the rows compare the cost of a deeper principal hierarchy, not outcomes.

| Call | 1 hop | 4 hops |
|---|---|---|
| `read_file` (allow at 1 hop) | 123.8 us [118.6, 129.3] | 172.6 us [169.6, 176.0] |
| `create_issue` in `acme/*` (allow at 1 hop) | 112.4 us [110.6, 114.4] | 182.1 us [175.0, 189.7] |
| `delete_repo` (deny: no permit matches) | 114.9 us [110.7, 119.9] | 182.2 us [175.4, 190.1] |

Reading: roughly 110 to 125 us per decision for a single hop and 170 to 190 us for four hops, so about 20 us for each extra hop. Allow and deny cost the same, as expected, since Cedar evaluates the whole policy set either way. At these figures one core sustains on the order of 5,000 to 9,000 decisions per second before the audit append and lease lookup. These figures predate the request cache. Profiled since: evaluation is about 5 us and the rest was building the Cedar request (Cedar parsing the entity and context JSON). The engine now caches that per chain and tool, and a repeated call costs 11 to 14 us at any depth; see [After the policy-stage and WAL work](#after-the-policy-stage-and-wal-work). This bench repeats one chain and call, so it now measures cache hits.

## `CapabilitySet::covers`

Parent: `n` capabilities `srv{i}:tool_*` with a `repo` prefix constraint. Child: `n` narrower ones (`srv{i}:tool_read`, longer prefix), each covered by exactly one parent capability. "covered" is the successful check made at every delegation hop; "rejected" swaps the sets, so the first child capability that the parent cannot cover ends the check.

| Capabilities (n) | covered | rejected (widening) |
|---|---|---|
| 1 | 34.3 ns [33.2, 35.7] | 15.2 ns [14.9, 15.5] |
| 8 | 449 ns [444, 456] | 68.0 ns [67.1, 69.0] |
| 32 | 4.91 us [4.85, 5.00] | 252.8 ns [248.7, 257.7] |

Reading: a successful check is quadratic in the number of capabilities (each child capability scans the parent set), going from 34 ns to 4.9 us between 1 and 32. That is `O(n * m)` by design (see `CapabilitySet::covers`): the conservative single-parent coverage rule keeps it simple and explainable. It is negligible next to a policy decision (4.9 us against about 120 us) at realistic set sizes, and it runs once per exchange, not once per call.

## End to end: proxy versus direct

Harness: `crates/onbehalf-bench` (binary `onbehalf-bench`), driven by `scripts/bench-e2e.sh`. Raw results are committed in [`bench/`](bench/) as `<date>-<host>.json` (every number below, plus the metadata) and `.md` (the tables with the hardware).

### Method

- **What runs.** The release `onbehalf-server` and the `fake_mcp` example (an echo upstream; its stderr goes to `/dev/null`), both started by the harness on free loopback ports, from copies of the binaries. A server is started per audit mode. The load generator runs on the same machine.
- **Tokens.** A root token from the development mint (`POST /admin/root-token`, capability `fake:read_file` only), then `POST /token` exchanges with agent client secrets down to the requested depth. "Hops" counts hops in the token's chain, so 1 is the root token itself and 3 is the root plus two exchanges. Lease lifetime is raised to 24 h so a long run does not outlive its leases.
- **Calls.** `tools/call` over HTTP/1.1 keep-alive, bodies fixed. `allow`: `read_file` on `alice/public-docs`, permitted by the Cedar policy (the leak demo's, three policies). `deny_policy`: `read_file` on `alice/private-salaries`, which the capability stage passes and Cedar denies. `deny_capability`: `delete_repo`, which the token does not carry, denied at the capability stage. Denied calls never reach the upstream.
- **Baseline.** The `allow` call posted straight to `fake_mcp`, at the same concurrency, in the same server group. "Added" is proxy minus direct for the same percentile (p50, p99) or the mean. For denied calls the upstream hop is skipped, so "added" there is the cost of getting the answer, not a hop on top of the upstream call.
- **Load.** N closed-loop clients (1, 8, 32), one request in flight each. 2 s warm-up discarded, then 5 s measured per cell. Latency per request goes into an HdrHistogram (3 significant digits) and is reported as p50, p90, p99, max and mean; throughput is completed measured requests over the 5 s.
- **Checks.** Every answer is classified (result versus JSON-RPC error) and a mismatch fails the run. At the end of each group the harness calls `GET /admin/audit/verify` and fails unless the chain verifies and holds at least one entry per proxied call.
- **Audit modes.** `memory` is `sqlite_path = ":memory:"`; `file` is a SQLite file in the temp directory (a container filesystem here), and `file_full` the same with `[audit] durability = "full"` (added with the write-path work; the first run predates WAL, so its `file` mode ran SQLite defaults).
- **Limits.** Closed-loop load suffers coordinated omission: a slow response delays the next request, so tail percentiles under overload are understated compared with open-loop load at a fixed arrival rate, which the [evaluation plan](../research/evaluation-plan.md) calls for. One run per cell, no confidence intervals.

### Environment (shared dev container, not a reference machine)

4 vCPU Intel Xeon @ 2.10 GHz, Linux 6.18, rustc 1.97.0, release profile (`lto = "thin"`). Other agents were compiling on the same host during the run (load average 3 to 4 before it started) and the load generator, proxy and upstream share the 4 cores, so the numbers carry a lot of noise and the high-concurrency rows are CPU-saturated: read them as "how it degrades", not as capacity. The full hardware block is in the committed `.md`. Run of 2026-10-23, commit 8ea3d07, file `bench/2026-10-23-vm.json`.

### Headline numbers (first run, before the write-path work)

These are the figures of the first run, at commit 8ea3d07. The audit and decision-path changes that followed are measured in [After the audit write-path work](#after-the-audit-write-path-work).


Allow call, audit in memory, p50 / p99 in microseconds and requests per second:

| | direct | 1 hop | 3 hops |
|---|---|---|---|
| 1 client | 82 / 184; 11,118 | 756 / 1,343; 1,261 | 1,100 / 4,522; 757 |
| 8 clients | 213 / 858; 31,714 | 1,754 / 4,280; 4,227 | 3,306 / 11,280; 2,099 |
| 32 clients | 567 / 1,994; 48,408 | 6,148 / 18,268; 4,862 | 12,976 / 41,353; 2,238 |

- **Added latency, single client, audit in memory:** about 0.7 ms at p50 and 1.2 ms at p99 for one hop; about 1.0 ms at p50 (4.3 ms at p99, noisy) for three hops. A denial by capability is cheaper (about 0.3 to 0.4 ms) because it stops before Cedar and the upstream.
- **Throughput ceiling:** about 4,200 to 4,900 calls per second at one hop and 2,100 to 2,200 at three hops on these 4 shared cores, against roughly 48,000 for the direct baseline. Throughput stops growing between 8 and 32 clients, so extra clients only add queueing.
- **Hops cost more than the micro-benchmark predicts.** Cedar adds about 20 us per hop (above), yet the end-to-end cost per call roughly doubles from 1 to 3 hops. Where it goes (verifying each hop, lease lookups per hop, request construction) is unprofiled.
- **Most of the added latency is outside Cedar.** The decision is about 120 us; the proxied call costs about 700 us more than a direct one. Token verification, the lease check, the audit append behind a mutex, the blocking-pool hop and the second HTTP round trip account for the rest; there is no breakdown yet.
- **A file-backed audit log is the dominant cost.** With a SQLite file, throughput was about 270 to 590 calls per second regardless of concurrency or outcome (denials are audited too), single-client p50 was 1.6 to 2.5 ms, and p50 rose linearly with clients (about 16 ms at 8, 65 ms at 32): the signature of one serialised append per call. The audit store sets no `synchronous` or `journal_mode` pragma, so it runs SQLite's defaults, which sync to disk on each commit; the figure is specific to this container's filesystem and will differ on other storage. A few file-mode cells have large outliers (for example `deny_policy` at 1 hop with 1 and 8 clients, 70 and 61 req/s) that probably coincide with other builds on the host; rerun before quoting a single cell.
- **Audit integrity under load:** the chain verified after both groups, with 351,679 entries (memory) and 50,495 (file), each at least the number of proxied calls sent.

The complete matrix (every hop count, outcome, concurrency and audit mode, with p90, max and mean) is in `bench/2026-10-23-vm.md`.

### After the audit write-path work

Three changes, each its own commit on `perf/audit-write-path`:

1. **SQLite durability settings.** File-backed stores open in WAL mode with `synchronous=NORMAL` by default (`[audit] durability = "full"` syncs every commit), a busy timeout and a prepared-statement cache. At `normal` a power failure can lose the newest decisions but never tear one, and the chain still verifies with an earlier head; lease revocations always sync. See [config](../reference/config.md#audit).
2. **Group commit.** Appends go to one writer thread over a channel. It commits the first waiting record plus everything already queued (up to 256) in one transaction and answers each caller with its entry; checkpoints falling in a batch are signed inside it. A failed batch is retried record by record, so only a record the database refuses fails (and its call is denied with `audit_error`).
3. **Per-call waste.** Found with the stage bench below plus temporary timers inside the audit commit: the server verified the same bearer token on every call (now cached by token hash, with expiry rechecked on every hit), the append decoded and cross-checked the whole head row to learn its hash (now reads `seq, entry_hash`), each record was serialized twice (now once, hashed and stored), the pipeline cloned the record, and the lease check ran one query per hop (now one `IN (...)` query).

**Decision path by stage** (`cargo bench -p onbehalf-server --bench decide`, in process, point estimates in microseconds, 1 hop / 3 hops; same container, about 5 to 10 percent run-to-run noise):

| Stage | before | after |
|---|---|---|
| Token verification as the proxy calls it (`authenticate`) | 97 / 98 | 1.3 / 2.3 (cache hit; a miss is still about 100) |
| Lease check, in-memory store | 0.8 / 2.4 | 1.0 / 4.0 |
| Lease check, file store | 4.1 / 11.1 | 2.1 / 5.3 |
| Policy (`PolicyEngine::authorize`, not changed) | 115 / 153 | 117 / 151 |
| `DecisionRecord::new` | 1.8 / 3.1 | 1.9 / 3.0 |
| Audit append, in memory | 77 / 111 | 91 / 149 |
| Audit append, file, `normal` | 1,055 / 1,054 (SQLite defaults) | 150 / 157 |
| Audit append, file, `full` | (no such setting) | 280 to 1,800 (one `fsync`; varies run to run) |

Readings:

- **Verification was the biggest per-call cost after Cedar**, about 100 us, paid again on every call with the same token. It is now about 1 to 2 us on a hit.
- **The per-hop growth is Cedar's.** Policy grows about 18 us per hop, which matches the micro-benchmark. The audit append also grew with depth because it decoded the previous (larger) record; reading only the head's hash removed that, but the single-threaded append is not faster overall: it now pays a thread handoff to the writer (about 25 us round trip, measured on its own) and the SQLite insert and in-memory commit are about 16 and 13 us. Under concurrency the handoff is shared by a batch.
- **The batched lease query** is faster for a file store and slower for the in-memory one (SQLite builds a small ephemeral table for an `IN` list), and both are a few microseconds against a decision of about 300.

**End to end, before and after** (`onbehalf-bench`, allow call, req/s at 1 / 8 / 32 clients, closed loop; "before" is merged main before this work, 3 s cells; "after" is the full run in [`bench/2026-10-23-vm-audit-write-path.md`](bench/2026-10-23-vm-audit-write-path.md), 5 s cells, commit 38a438d):

| Audit, hops | before | after | single client, added p50 before / after |
|---|---|---|---|
| memory, 1 | 1,131 / 4,266 / 5,275 | 1,209 / 4,958 / 6,601 | 775 / 697 us |
| memory, 3 | 819 / 3,327 / 3,746 | 670 / 2,547 / 3,235 | 1,132 / 1,156 us |
| file (`normal`), 1 | 435 / 488 / 461 | 962 / 3,110 / 4,526 | 2,145 / 851 us |
| file (`normal`), 3 | 290 / 261 / 465 | 720 / 2,846 / 3,873 | 2,580 / 1,176 us |
| file, `full`, 1 | (SQLite defaults are the "before" file row) | 434 / 1,248 / 2,176 (*) | 1,377 us (*) |
| file, `full`, 3 | | 545 / 2,389 / 3,603 | 1,608 us |

(*) Load on the host rose from 3 to 6 during the run, and these cells sit at the end of it; the same cells measured 765 / 3,476 / 5,710 req/s an hour earlier at commit 78e9b14 (before the last merge of main, same code otherwise). The memory, 3-hop row also moved within noise: intermediate runs on the branch measured 934 / 4,038 / 5,479. Read every cell as plus or minus 20 percent on this container.

What this means:

- **The file-backed log is no longer the ceiling.** At `normal` it runs within about 25 percent of the in-memory store (3,100 to 4,500 calls per second at one hop with 8 and 32 clients, from 460 to 490), and single-client latency fell from 2.2 ms to 0.9 ms. At `full` group commit lets one `fsync` cover a batch, so throughput still grows with concurrency instead of staying flat at a few hundred.
- **Tail latency at `normal`** shows periodic stalls (p99 of 15 to 25 ms with 8 or more clients) that `full` does not: SQLite checkpoints the WAL into the database every 1,000 pages on the writer thread, and at `normal` that is where the deferred `fsync` and write-back land. Moving checkpoints off the writer (`wal_autocheckpoint=0` plus a background `PASSIVE` checkpoint) was the next experiment; it is done, see [After the policy-stage and WAL work](#after-the-policy-stage-and-wal-work).
- **Most of the added latency is still outside the decision.** The server's own work is now about 300 us per call (policy about 120 to 150, append 90 to 150, the rest small), against 0.7 to 1.2 ms added end to end; the blocking-pool hop, the proxy's request handling and the second HTTP round trip make up the rest and are not in this branch.

### After the policy-stage and WAL work

Three changes on `perf/policy-stage-and-wal-checkpoints`, each its own commit (the WAL change took three: the first version had a bug the end-to-end run caught, below):

1. **Request cache in the policy engine.** The new bench `cargo bench -p onbehalf-policy --bench policy_stage` splits the Cedar stage into preparing the request and evaluating it. Evaluation was about 5 us; preparation was 115 to 160 us, and nearly all of it was Cedar parsing the JSON built for the entity store (about 50 us) and the context (about 40 us) on every call. The schema and policy set were already parsed once, at load. The engine now keeps what depends only on the chain and the tool (entity store, principal, action, resource, and the `originating_user` and `chain` context records) in a cache of 4,096 entries. An entry is used only when every input it was built from is equal (user, attributes, each hop's agent and lease, server, tool, the tool's catalog attributes), so a hash collision is a miss. A policy reload empties it, and a catalog change builds a new engine. A call then builds only `context.input`, `session_id` and `now_unix`, directly as Cedar values instead of JSON. A test compares the cached request with the old one-pass translation for every argument shape (nulls, decimals, integral floats, big integers, nested sets and records, sessions, legacy actions), and every existing policy test passes unchanged.
2. **WAL checkpoints off the writer.** The writer connection runs with `wal_autocheckpoint=0`, and a background thread with its own connection runs `PRAGMA wal_checkpoint(PASSIVE)` every `[audit] wal_checkpoint_seconds` (default 5) or 256 commits. `PASSIVE` takes no lock the writer needs. It truncates the WAL when no append is in progress, and runs a final `TRUNCATE` at shutdown (and when the store is dropped). Reads go through the store's own connection, so verify and export see every committed row whether or not it has been copied yet. In-memory stores are unchanged.
3. **Inline commit when the writer is idle.** An append that finds nothing queued for the writer and the connection free runs the same one-record transaction on its own thread, without the hand-off. Anything else goes to the writer as before, so group commit is unchanged under load.

**The WAL bug the end-to-end run caught.** SQLite starts a WAL over from its beginning only when a write finds every frame already copied. A `PASSIVE` checkpoint next to a busy writer copies up to where the WAL ended when it started, never further, so under continuous load the first version never let the WAL restart. It grew by about 16 KB per append until the disk was full, and appends then failed with `SQLITE_FULL`. The bench's deny cells accept any JSON-RPC error, so those calls still counted as expected denials. The bench's final check caught it: the chain verified with 476,233 entries for 594,416 calls sent. Now, once the WAL passes 64 MB, a round makes up to four more unlocked passes, each copying what arrived during the one before. It then copies the small remainder while holding the store's connection lock, which pauses appends in this process for that copy and two syncs, and the next commit starts the WAL over. The WAL peaks around 100 MB under sustained load. A test keeps it bounded with eight writers and no idle moment; without the fix that test's WAL passes 400 MB. A first version of the fix paused at 4,096 pages, and those pauses set the p99 at 32 clients (28 to 30 ms, below).

One behaviour change follows from the design. At `durability = "normal"` the WAL is synced when it is checkpointed, so the decisions a power failure can lose are now those since the last background checkpoint: up to one interval (5 s) or 256 commits. Before, the window was about 1,000 pages. Lower `wal_checkpoint_seconds`, or use `"full"`, to narrow it. Decisions are unchanged.

**Decision path by stage** (`cargo bench -p onbehalf-server --bench decide`, point estimates in microseconds, 1 hop / 3 hops; "before" is the column "after" of the previous table, same container, load 2 to 5 during this run):

| Stage | before | after |
|---|---|---|
| Policy (`PolicyEngine::authorize`) | 117 / 151 | 12.9 / 13.6 (cache hit; a miss is still 125 / 175) |
| Audit append, in memory | 91 / 149 | 94 / 142 |
| Audit append, file, `normal` | 150 / 157 | 60 / 68 |
| Audit append, file, `full` | 280 to 1,800 | 256 / 267 |
| Lease check, in memory / file | 1.0 / 4.0, 2.1 / 5.3 | 1.1 / 4.7, 2.5 / 6.2 |
| Token verification (`authenticate`, cache hit) | 1.3 / 2.3 | 1.5 / 2.4 |
| `Pipeline::decide` (leases, policy, record, append), memory / file | not recorded | 139 / 206, 81 / 106 |

The Cedar stage itself (`cargo bench -p onbehalf-policy --bench policy_stage`, same chain and call):

| | before | after, cache hit | after, uncached |
|---|---|---|---|
| `authorize` | 122 / 200 | 11.8 / 12.1 | 129 / 174 |
| prepare (entities, context, `Request::new`) | 121 / 158 | 5.8 / 6.3 | 115 / 168 |
| evaluate | 5.5 / 5.5 | 5.4 / 5.5 | |

Readings:

- **The policy stage is about ten times cheaper and no longer grows with depth.** The per-hop cost was translation, not evaluation: evaluation is 5.5 us at one hop and at three. What remains per call is building `context.input` and the `Request` (about 6 us) and evaluating (about 5.5 us).
- **The file append is now cheaper than the in-memory one** (60 against 94 us at one hop). Part of that is the checkpoints that no longer run on the writer, part is the inline commit; the in-memory store, which journals in memory rather than appending to a WAL, gains only the inline commit. The A/B of the inline commit alone, same host load: in memory 114 / 169 to 92 / 120 us, file 72 / 91 to 70 / 63 us.
- **At `full`** the append is one `fsync`, 250 to 270 us on this run against a range of 280 to 1,800 before; the difference is the host, not the change.

**End to end, before and after** (`onbehalf-bench`, allow call, req/s at 1 / 8 / 32 clients; "before" is the run in [`bench/2026-10-23-vm-audit-write-path.md`](bench/2026-10-23-vm-audit-write-path.md), "after" the run in [`bench/2026-10-23-vm-policy-stage.md`](bench/2026-10-23-vm-policy-stage.md), commit 238d914, memory and file only):

| Audit, hops | before | after | p99 at 8 / 32 clients, before / after | single client, added p50 before / after |
|---|---|---|---|---|
| memory, 1 | 1,209 / 4,958 / 6,601 | 1,765 / 5,246 / 6,646 | 3.5 / 10.6 ms, 3.6 / 10.4 ms | 697 / 425 us |
| memory, 3 | 670 / 2,547 / 3,235 | 857 / 2,272 / 3,460 | 7.6 / 24.3 ms, 10.0 / 21.5 ms | 1,156 / 739 us |
| file (`normal`), 1 | 962 / 3,110 / 4,526 | 1,252 / 4,049 / 6,254 | 15.5 / 23.8 ms, 5.4 / 13.0 ms | 851 / 631 us |
| file (`normal`), 3 | 720 / 2,846 / 3,873 | 1,092 / 4,547 / 6,652 | 17.0 / 26.9 ms, 5.0 / 10.9 ms | 1,176 / 771 us |

Load on the host was 4 to 7 during this run and other agents were compiling; the memory group ran first, under more of that load, which is why its three-hop row looks slower than the file row that followed. Read every cell as plus or minus 20 percent. A same-binary A/B of the WAL change alone, with only `wal_checkpoint_seconds` changed and the variants interleaved, is in the bench file: at 8 clients the p99 went from 21 to 23 ms (SQLite checkpointing on the writer) to 4 to 8 ms and throughput rose 35 to 95 percent; at 32 clients the p99 went from 34 to 41 ms to 11 to 23 ms and the p90 from about 20 ms to 6 to 10 ms.

What this means:

- **Single-client added latency** fell by about 200 us at one hop and about 400 us at three, close to what the policy stage lost (about 105 us, and 140 to 190 us) plus the shorter append. The policy stage is no longer what grows with depth.
- **The file store's tail no longer has the checkpoint stalls.** Its p99 at 8 and 32 clients is now close to the in-memory store's. The worst case remains a catch-up pause each time the WAL passes 64 MB; it shows in the max column (30 to 135 ms on this host) rather than the p99.
- **What is left of the added latency** is mostly outside the server's decision (now about 80 to 140 us at one hop): the blocking-pool hop, the proxy's request handling and the second HTTP round trip. It was not broken down by stage then; see [Time by stage of a proxied call](#time-by-stage-of-a-proxied-call-2026-10-23).

### Time by stage of a proxied call (2026-10-23)

Branch `perf/proxy-stage-timing`, commit 51f0a89. The server now times each stage of a proxied call and serves the result as the histogram `onbehalf_proxy_stage_seconds{stage=...}` on `/metrics` (buckets from 1 us to 1 s, five per decade), with the same figures as `tracing` debug fields. Each stage costs one `Instant::now()` pair. The stages:

| `stage` | What it covers |
|---|---|
| `token_verify_hit`, `token_verify_miss` | Bearer token verification, answered from the verified-token cache or by the verifier |
| `lease_check` | Every hop's lease, inside the decision |
| `policy` | Capability stage and Cedar |
| `audit_append` | Appending the decision record |
| `blocking_pool` | Getting the decision onto a blocking thread and the answer back: the authorizer's wait minus the decision itself |
| `upstream` | The forwarded request, until the upstream's response headers arrive |
| `response` | From those headers to the response the handler returns (filtering, session binding, headers); a streamed body is relayed after this |
| `total` | The proxy's `POST` handler, start to returned response, for requests with at least one decided call |

`lease_check`, `policy` and `audit_append` are recorded in the decision pipeline, so AuthZEN decisions count there too. `onbehalf-bench` reads the histograms when each cell's warm-up ends and when it stops, and prints the difference as a table ([`bench/2026-10-23-vm-proxy-stages.md`](bench/2026-10-23-vm-proxy-stages.md)). The p50 and p90 columns are interpolated inside buckets the way Prometheus' `histogram_quantile` does, so they are estimates. The mean is exact.

The run: one client, 10 s cells after 2 s of warm-up, allow and `deny_policy` at 1 and 3 hops, memory and file (`normal`) stores; 11,000 to 23,000 calls per cell. This is a shared 4-core VM, not a quiet machine. Load average was 4.4 to 6.4 during the run while other agents compiled, and the load generator, proxy and upstream share those cores. Read every figure as plus or minus 20 percent or worse. Absolute figures are 3 to 4 times the in-process `decide` bench (policy 43 to 57 us here, 13 us there), so compare stages within this run, not with the tables above.

Allow call, microseconds, p50 (mean in brackets):

| Stage | memory, 1 hop | memory, 3 hops | file, 1 hop | file, 3 hops |
|---|---|---|---|---|
| `token_verify_hit` | 4.5 (5.2) | 8.6 (9.3) | 4.7 (5.3) | 8.3 (9.5) |
| `lease_check` | 15 (16) | 42 (44) | 37 (36) | 50 (54) |
| `policy` | 48 (53) | 57 (57) | 46 (50) | 48 (55) |
| `audit_append` | 51 (61) | 59 (111) | 69 (81) | 81 (95) |
| `blocking_pool` | 70 (86) | 85 (122) | 74 (97) | 82 (115) |
| `upstream` | 205 (216) | 235 (241) | 215 (218) | 231 (233) |
| `response` | 9.5 (10.5) | 21 (23) | 10 (11) | 21 (22) |
| `total` (handler) | 437 (485) | 577 (652) | 486 (536) | 586 (627) |
| client p50, through the proxy | 661 | 800 | 713 | 806 |
| client p50, direct to the upstream | 67 | 67 | 67 | 67 |

A denied call (`deny_policy`) has no `upstream` or `response`; its handler `total` was 231 to 276 us p50 and its other stages match the allow column within noise.

Readings:

- **The proxy's own upstream round trip is the biggest stage**, 205 to 235 us p50, against 67 us p50 for the same call sent straight to the upstream by the load generator. Most of what the proxy adds to an allowed call is therefore a second HTTP exchange that costs about three times what the client pays for its own. Why it is that much slower from inside the server was not investigated. Candidates are the `reqwest` client on a busy runtime, scheduling across three processes on four cores, and the forwarded request being built and re-encoded.
- **The hop to the blocking pool costs more than the policy stage**: 70 to 85 us p50, which is more than lease check plus policy at one hop. For the in-memory stores, a decision that runs inline (or on a dedicated thread with a cheaper hand-off) is the obvious experiment. The file store still needs to stay off async workers.
- **The decision itself** (lease check, policy, append) is about 115 to 180 us p50 here. Lease check grows with depth (one row per hop) and is two to three times slower on the file store at one hop. The append's mean sits well above its p50 at three hops in memory (111 against 59 us), which shows occasional slow appends.
- **Token verification is negligible on a cache hit** (5 to 9 us), and `response` handling is 10 to 21 us.
- **Inside the handler, about 40 us is in no stage** (the allow-call stage means add up to 447 of a 485 us mean `total` in memory at one hop): reading and parsing the body, screening, building the decision record, the session gate and re-encoding. **Outside the handler**, the client's p50 is about 225 us above the handler's (661 against 437 us). That covers the client-to-proxy HTTP exchange, axum and hyper, and relaying the body. Subtracting medians gives only a rough split.

### How to run

```
scripts/bench-e2e.sh                       # full matrix, about 9 minutes, writes docs/design/bench/
DURATION=10 scripts/bench-e2e.sh --concurrency 8 --depths 3 --audit memory
cargo run --release -p onbehalf-bench -- --help
cargo bench -p onbehalf-policy --bench policy_stage -- --warm-up-time 1 --measurement-time 3
cargo bench -p onbehalf-server --bench decide -- --warm-up-time 1 --measurement-time 3
```

`onbehalf-bench --print-config DIR` writes the server config and policy it expects, for pointing the harness at an already running server (`--onbehalf-url`, `--upstream-url`, and `--metrics-url` for the stage table). Every answer is checked: a denial counts only as the proxy's `-32003` with the expected reason code and a decision id listed in `X-Onbehalf-Decision-Id`, so an `audit_error` denial, a `too_many_sessions` refusal or a `5xx` stops the run after that cell. A one-second smoke run is part of `cargo test --workspace` (`crates/onbehalf-bench/tests/smoke.rs`). There is no CI job for the full matrix: it needs a release build and minutes of load, and numbers from shared runners could not be compared.

## Not measured

- `POST /token` exchange throughput and `POST /token/renew` load (the harness only uses exchanges for setup).
- Policy size (the set here has three policies) and catalog size.
- The time outside the proxy's handler (hyper and axum parsing the client's request, relaying a streamed body). The handler's stages are in `onbehalf_proxy_stage_seconds`; what lies between them and the client's latency is measured only as a difference.
- Open-loop load at fixed arrival rates, confidence intervals over repeated runs, and a quiet reference machine.
- Streaming (SSE) responses and `tools/list` filtering.

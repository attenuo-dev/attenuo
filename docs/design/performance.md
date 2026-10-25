# Performance: micro-benchmarks and end to end

- Status: third measurement, after the policy-stage and WAL work (`perf/policy-stage-and-wal-checkpoints`); exchange, lease renewal and open-loop cells added 2026-10-23 (`perf/exchange-lease-bench`); output labelling and run limits on the hot path added 2026-10-24 (`perf/labels-limits-cost`); the SR-55 run lock under concurrent clients added 2026-10-24 (`perf/run-lock-cost`); per-value limits on current main, two kinds on one capability and list arguments added 2026-10-25 (`perf/per-value-limits-latency`)
- Crates: `attenuo-policy` (`benches/authorize.rs`, `benches/policy_stage.rs`), `attenuo-core` (`benches/attenuation.rs`), `attenuo-server` (`benches/decide.rs`, the decision path by stage), `attenuo-bench` (end to end)
- Related: [server pipeline](server.md), [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md)
- Sources: every figure links the committed file it comes from in [`bench/`](bench/). A figure with no file says "(unrecorded)". Where a rerun of 2026-10-23 gave a different number, the rerun is in the text and the earlier figure is kept in a "quoted earlier, unrecorded" note.

The first part of this page is criterion micro-benchmarks of the two pure functions on the hot path. They do not include token verification, the lease lookup, the audit append or the network hop to the upstream, so they are a lower bound on the latency attenuo adds to a call. The end-to-end figures, measured through the real proxy, are in [End to end: proxy versus direct](#end-to-end-proxy-versus-direct) at the end of the page, followed by [the audit write path and the per-call cost](#after-the-audit-write-path-work) and [the policy stage and WAL checkpoints](#after-the-policy-stage-and-wal-work), which say what changed and by how much.

## How to run

```
cargo bench --bench authorize --bench attenuation -- --warm-up-time 1 --measurement-time 3
```

Name the bench targets: a bare `cargo bench -- --warm-up-time ...` also passes the flags to each crate's unit-test harness, which rejects them.

## Measurement environment (dev container, not a reference machine)

Taken in a shared Linux development container while other builds were running on the same host, so treat the numbers as indicative: relative sizes mean more than absolute values, and run-to-run noise of 10 percent or more is expected. Rust release profile (`lto = "thin"`, `codegen-units = 1`). First run 2026-10-22, with no output kept. Rerun 2026-10-23 at commit 034fd5c with rustc 1.99.1, load average 1 to 3, one bench at a time; the outputs are the `criterion-*.txt` files in [`bench/`](bench/).

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

Rerun 2026-10-23 ([`criterion-authorize`](bench/2026-10-23-vm-criterion-authorize.txt)):

| Call | 1 hop | 4 hops |
|---|---|---|
| `read_file` (allow at 1 hop) | 11.7 us [11.5, 11.8] | 14.1 us [13.6, 14.7] |
| `create_issue` in `acme/*` (allow at 1 hop) | 12.7 us [12.4, 13.1] | 14.4 us [14.0, 14.8] |
| `delete_repo` (deny: no permit matches) | 11.2 us [11.0, 11.5] | 14.3 us [13.8, 14.9] |

Quoted earlier, unrecorded (2026-10-22, before the request cache; no output was kept):

| Call | 1 hop | 4 hops |
|---|---|---|
| `read_file` | 123.8 us [118.6, 129.3] | 172.6 us [169.6, 176.0] |
| `create_issue` | 112.4 us [110.6, 114.4] | 182.1 us [175.0, 189.7] |
| `delete_repo` | 114.9 us [110.7, 119.9] | 182.2 us [175.4, 190.1] |

Reading: this bench repeats one chain and call, so since the request cache every iteration is a cache hit. The rerun is 11 to 13 us at one hop and about 14 us at four. Allow and deny cost the same, as expected, since Cedar evaluates the whole policy set either way. The earlier figures were uncached: 110 to 125 us for one hop and 170 to 190 us for four, about 20 us for each extra hop, or 5,000 to 9,000 decisions per second per core (unrecorded). The uncached cost today is in `policy_stage`: 122 us at one hop and 163 us at three ([`criterion-policy_stage`](bench/2026-10-23-vm-criterion-policy_stage.txt)). Profiled since: evaluation is about 5 us and the rest was building the Cedar request (Cedar parsing the entity and context JSON). The engine now caches that per chain and tool; see [After the policy-stage and WAL work](#after-the-policy-stage-and-wal-work).

## `CapabilitySet::covers`

Parent: `n` capabilities `srv{i}:tool_*` with a `repo` prefix constraint. Child: `n` narrower ones (`srv{i}:tool_read`, longer prefix), each covered by exactly one parent capability. "covered" is the successful check made at every delegation hop; "rejected" swaps the sets, so the first child capability that the parent cannot cover ends the check.

Rerun 2026-10-23 ([`criterion-attenuation`](bench/2026-10-23-vm-criterion-attenuation.txt)):

| Capabilities (n) | covered | rejected (widening) |
|---|---|---|
| 1 | 36.4 ns [35.3, 37.6] | 15.9 ns [15.5, 16.3] |
| 8 | 429 ns [427, 431] | 72.2 ns [70.7, 73.8] |
| 32 | 5.06 us [4.86, 5.30] | 263.3 ns [258.4, 269.3] |

Quoted earlier, unrecorded (2026-10-22): covered 34.3 ns, 449 ns and 4.91 us; rejected 15.2, 68.0 and 252.8 ns. Every cell is within 6 percent of the rerun.

Reading: a successful check is quadratic in the number of capabilities (each child capability scans the parent set), going from 36 ns to 5.1 us between 1 and 32. That is `O(n * m)` by design (see `CapabilitySet::covers`): the conservative single-parent coverage rule keeps it simple and explainable. It is small next to an uncached policy decision (5.1 us against about 120 us) at realistic set sizes, and it runs once per exchange, not once per call.

## End to end: proxy versus direct

Harness: `crates/attenuo-bench` (binary `attenuo-bench`), driven by `scripts/bench-e2e.sh`. Raw results are committed in [`bench/`](bench/) as `<date>-<host>.json` (every number below, plus the metadata) and `.md` (the tables with the hardware).

### Method

- **What runs.** The release `attenuo-server` and the `fake_mcp` example (an echo upstream; its stderr goes to `/dev/null`), both started by the harness on free loopback ports, from copies of the binaries. A server is started per audit mode. The load generator runs on the same machine.
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
- **Hops cost more than the micro-benchmark predicts.** Cedar added about 20 us per hop uncached (the earlier, unrecorded figure above), yet the end-to-end cost per call roughly doubles from 1 to 3 hops. Where it goes (verifying each hop, lease lookups per hop, request construction) is unprofiled.
- **Most of the added latency is outside Cedar.** The decision was about 120 us uncached (unrecorded); the proxied call costs about 700 us more than a direct one. Token verification, the lease check, the audit append behind a mutex, the blocking-pool hop and the second HTTP round trip account for the rest; there is no breakdown yet.
- **A file-backed audit log is the dominant cost.** With a SQLite file, throughput was about 270 to 590 calls per second regardless of concurrency or outcome (denials are audited too), single-client p50 was 1.6 to 2.5 ms, and p50 rose linearly with clients (about 16 ms at 8, 65 ms at 32): the signature of one serialised append per call. The audit store sets no `synchronous` or `journal_mode` pragma, so it runs SQLite's defaults, which sync to disk on each commit; the figure is specific to this container's filesystem and will differ on other storage. A few file-mode cells have large outliers (for example `deny_policy` at 1 hop with 1 and 8 clients, 70 and 61 req/s) that probably coincide with other builds on the host; rerun before quoting a single cell.
- **Audit integrity under load:** the chain verified after both groups, with 351,679 entries (memory) and 50,495 (file), each at least the number of proxied calls sent.

The complete matrix (every hop count, outcome, concurrency and audit mode, with p90, max and mean) is in `bench/2026-10-23-vm.md`.

### After the audit write-path work

Three changes, each its own commit on `perf/audit-write-path`:

1. **SQLite durability settings.** File-backed stores open in WAL mode with `synchronous=NORMAL` by default (`[audit] durability = "full"` syncs every commit), a busy timeout and a prepared-statement cache. At `normal` a power failure can lose the newest decisions but never tear one, and the chain still verifies with an earlier head; lease revocations always sync. See [config](../reference/config.md#audit).
2. **Group commit.** Appends go to one writer thread over a channel. It commits the first waiting record plus everything already queued (up to 256) in one transaction and answers each caller with its entry; checkpoints falling in a batch are signed inside it. A failed batch is retried record by record, so only a record the database refuses fails (and its call is denied with `audit_error`).
3. **Per-call waste.** Found with the stage bench below plus temporary timers inside the audit commit: the server verified the same bearer token on every call (now cached by token hash, with expiry rechecked on every hit), the append decoded and cross-checked the whole head row to learn its hash (now reads `seq, entry_hash`), each record was serialized twice (now once, hashed and stored), the pipeline cloned the record, and the lease check ran one query per hop (now one `IN (...)` query).

**Decision path by stage** (`cargo bench -p attenuo-server --bench decide`, in process, point estimates in microseconds, 1 hop / 3 hops; same container, about 5 to 10 percent run-to-run noise). Both columns are unrecorded: no criterion output was kept, and the code has changed since. Today's rerun is in the decide table of [the next section](#after-the-policy-stage-and-wal-work).

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
- **The per-hop growth is Cedar's.** Policy grows about 18 us per hop, which matches the micro-benchmark. The audit append also grew with depth because it decoded the previous (larger) record; reading only the head's hash removed that, but the single-threaded append is not faster overall: it now pays a thread handoff to the writer (about 25 us round trip, measured on its own) and the SQLite insert and in-memory commit are about 16 and 13 us (temporary timers, unrecorded). Under concurrency the handoff is shared by a batch.
- **The batched lease query** is faster for a file store and slower for the in-memory one (SQLite builds a small ephemeral table for an `IN` list), and both are a few microseconds against a decision of about 300.

**End to end, before and after** (`attenuo-bench`, allow call, req/s at 1 / 8 / 32 clients, closed loop; "before" is merged main before this work, 3 s cells, unrecorded: no results file was kept and that code is gone; "after" is the full run in [`bench/2026-10-23-vm-audit-write-path.md`](bench/2026-10-23-vm-audit-write-path.md), 5 s cells, commit 38a438d):

| Audit, hops | before | after | single client, added p50 before / after |
|---|---|---|---|
| memory, 1 | 1,131 / 4,266 / 5,275 | 1,209 / 4,958 / 6,601 | 775 / 697 us |
| memory, 3 | 819 / 3,327 / 3,746 | 670 / 2,547 / 3,235 | 1,132 / 1,156 us |
| file (`normal`), 1 | 435 / 488 / 461 | 962 / 3,110 / 4,526 | 2,145 / 851 us |
| file (`normal`), 3 | 290 / 261 / 465 | 720 / 2,846 / 3,873 | 2,580 / 1,176 us |
| file, `full`, 1 | (SQLite defaults are the "before" file row) | 434 / 1,248 / 2,176 (*) | 1,377 us (*) |
| file, `full`, 3 | | 545 / 2,389 / 3,603 | 1,608 us |

(*) Load on the host rose from 3 to 6 during the run, and these cells sit at the end of it; the same cells measured 765 / 3,476 / 5,710 req/s an hour earlier at commit 78e9b14 (before the last merge of main, same code otherwise). The memory, 3-hop row also moved within noise: intermediate runs on the branch measured 934 / 4,038 / 5,479 (unrecorded; that branch code has changed since). Read every cell as plus or minus 20 percent on this container.

What this means:

- **The file-backed log is no longer the ceiling.** At `normal` it runs within about 30 to 40 percent of the in-memory store at 8 and 32 clients (3,100 to 4,500 calls per second at one hop with 8 and 32 clients, from 460 to 490), and single-client latency fell from 2.2 ms to 0.9 ms. The "from" figures are the unrecorded "before" column. At `full` group commit lets one `fsync` cover a batch, so throughput still grows with concurrency instead of staying flat at a few hundred.
- **Tail latency at `normal`** shows periodic stalls (p99 of 15.5 to 26.9 ms with 8 or more clients, [audit-write-path](bench/2026-10-23-vm-audit-write-path.md)) that `full` does not: SQLite checkpoints the WAL into the database every 1,000 pages on the writer thread, and at `normal` that is where the deferred `fsync` and write-back land. Moving checkpoints off the writer (`wal_autocheckpoint=0` plus a background `PASSIVE` checkpoint) was the next experiment; it is done, see [After the policy-stage and WAL work](#after-the-policy-stage-and-wal-work).
- **Most of the added latency is still outside the decision.** The server's own work is now about 300 us per call (policy about 120 to 150, append 90 to 150, the rest small), against 0.7 to 1.2 ms added end to end; the blocking-pool hop, the proxy's request handling and the second HTTP round trip make up the rest and are not in this branch.

### After the policy-stage and WAL work

Three changes on `perf/policy-stage-and-wal-checkpoints`, each its own commit (the WAL change took three: the first version had a bug the end-to-end run caught, below):

1. **Request cache in the policy engine.** The new bench `cargo bench -p attenuo-policy --bench policy_stage` splits the Cedar stage into preparing the request and evaluating it. Evaluation was about 5 us; preparation was 115 to 160 us (rerun uncached: 108 and 154 us, [`criterion-policy_stage`](bench/2026-10-23-vm-criterion-policy_stage.txt)), and nearly all of it was Cedar parsing the JSON built for the entity store (about 50 us) and the context (about 40 us) on every call (profiled, unrecorded). The schema and policy set were already parsed once, at load. The engine now keeps what depends only on the chain and the tool (entity store, principal, action, resource, and the `originating_user` and `chain` context records) in a cache of 4,096 entries. An entry is used only when every input it was built from is equal (user, attributes, each hop's agent and lease, server, tool, the tool's catalog attributes), so a hash collision is a miss. A policy reload empties it, and a catalog change builds a new engine. A call then builds only `context.input`, `session_id` and `now_unix`, directly as Cedar values instead of JSON. A test compares the cached request with the old one-pass translation for every argument shape (nulls, decimals, integral floats, big integers, nested sets and records, sessions, legacy actions), and every existing policy test passes unchanged.
2. **WAL checkpoints off the writer.** The writer connection runs with `wal_autocheckpoint=0`, and a background thread with its own connection runs `PRAGMA wal_checkpoint(PASSIVE)` every `[audit] wal_checkpoint_seconds` (default 5) or 256 commits. `PASSIVE` takes no lock the writer needs. It truncates the WAL when no append is in progress, and runs a final `TRUNCATE` at shutdown (and when the store is dropped). Reads go through the store's own connection, so verify and export see every committed row whether or not it has been copied yet. In-memory stores are unchanged.
3. **Inline commit when the writer is idle.** An append that finds nothing queued for the writer and the connection free runs the same one-record transaction on its own thread, without the hand-off. Anything else goes to the writer as before, so group commit is unchanged under load.

**The WAL bug the end-to-end run caught.** SQLite starts a WAL over from its beginning only when a write finds every frame already copied. A `PASSIVE` checkpoint next to a busy writer copies up to where the WAL ended when it started, never further, so under continuous load the first version never let the WAL restart. It grew by about 16 KB per append until the disk was full, and appends then failed with `SQLITE_FULL`. The bench's deny cells accept any JSON-RPC error, so those calls still counted as expected denials. The bench's final check caught it: the chain verified with 476,233 entries for 594,416 calls sent (unrecorded, as is the 16 KB per append: that run's file was not kept). Now, once the WAL passes 64 MB, a round makes up to four more unlocked passes, each copying what arrived during the one before. It then copies the small remainder while holding the store's connection lock, which pauses appends in this process for that copy and two syncs, and the next commit starts the WAL over. The WAL peaks around 100 MB under sustained load (unrecorded for the end-to-end run; the bounded-WAL test peaked at 78 to 104 MB over three runs, [log, 18:05 UTC](../log/2026-10-23.md#1805-utc-the-walkthrough-run-end-to-end)). A test keeps it bounded with eight writers and no idle moment; without the fix that test's WAL passes 400 MB (unrecorded). A first version of the fix paused at 4,096 pages, and those pauses set the p99 at 32 clients (28 to 30 ms, [policy-stage](bench/2026-10-23-vm-policy-stage.md)).

One behaviour change follows from the design. At `durability = "normal"` the WAL is synced when it is checkpointed, so the decisions a power failure can lose are now those since the last background checkpoint: up to one interval (5 s) or 256 commits. Before, the window was about 1,000 pages. Lower `wal_checkpoint_seconds`, or use `"full"`, to narrow it. Decisions are unchanged.

**Decision path by stage** (`cargo bench -p attenuo-server --bench decide`, point estimates in microseconds, 1 hop / 3 hops). "before" is the column "after" of the previous table (unrecorded). "after" is the figure quoted at the time (load 2 to 5, unrecorded). "rerun" is today's run ([`criterion-decide`](bench/2026-10-23-vm-criterion-decide.txt), load average about 1); the file-store rows are the first of its two passes, and the second is in the file.

| Stage | before | after (quoted earlier, unrecorded) | rerun 2026-10-23 |
|---|---|---|---|
| Policy (`PolicyEngine::authorize`) | 117 / 151 | 12.9 / 13.6 (cache hit; a miss is still 125 / 175) | 11.8 / 13.0 (cache hit; a miss is 122 / 163, [`criterion-policy_stage`](bench/2026-10-23-vm-criterion-policy_stage.txt)) |
| Audit append, in memory | 91 / 149 | 94 / 142 | 93 / 163 |
| Audit append, file, `normal` | 150 / 157 | 60 / 68 | 114 / 128 (second pass 142 / 119; intervals up to plus or minus 45 percent) |
| Audit append, file, `full` | 280 to 1,800 | 256 / 267 | 277 / 316 |
| Lease check, in memory / file | 1.0 / 4.0, 2.1 / 5.3 | 1.1 / 4.7, 2.5 / 6.2 | 0.9 / 4.5, 2.4 / 5.9 |
| Token verification (`authenticate`, cache hit) | 1.3 / 2.3 | 1.5 / 2.4 | 1.9 / 3.4 (a miss, `verify`, is 115 / 127) |
| `Pipeline::decide` (leases, policy, record, append), memory / file | not recorded | 139 / 206, 81 / 106 | 156 / 236, 115 / 113 (second pass 130 / 131) |

The Cedar stage itself (`cargo bench -p attenuo-policy --bench policy_stage`, same chain and call). The "before" column is unrecorded. The "after" columns are today's rerun ([`criterion-policy_stage`](bench/2026-10-23-vm-criterion-policy_stage.txt)):

| | before | after, cache hit | after, uncached |
|---|---|---|---|
| `authorize` | 122 / 200 | 12.3 / 12.1 | 122 / 163 |
| prepare (entities, context, `Request::new`) | 121 / 158 | 5.5 / 6.1 | 108 / 154 |
| evaluate | 5.5 / 5.5 | 5.2 / 5.7 | |

Quoted earlier, unrecorded: cache hit 11.8 / 12.1, 5.8 / 6.3 and 5.4 / 5.5; uncached 129 / 174 and 115 / 168. Every cell is within 10 percent of the rerun.

Readings:

- **The policy stage is about ten times cheaper and no longer grows with depth.** The per-hop cost was translation, not evaluation: evaluation is 5.5 us at one hop and at three. What remains per call is building `context.input` and the `Request` (about 6 us) and evaluating (about 5.5 us).
- **The file append was cheaper than the in-memory one when measured** (60 against 94 us at one hop, unrecorded). Part of that was the checkpoints that no longer run on the writer, part the inline commit; the in-memory store, which journals in memory rather than appending to a WAL, gains only the inline commit. The A/B of the inline commit alone, same host load: in memory 114 / 169 to 92 / 120 us, file 72 / 91 to 70 / 63 us (unrecorded). The rerun does not show it: the file append is 114 to 142 us at one hop against 93 in memory, with wide intervals and 8 to 12 percent outliers. Later changes to the writer (the WAL backstop hook) may account for part of it; this was not investigated.
- **At `full`** the append is one `fsync`, 250 to 270 us on that run (unrecorded) and 277 to 316 us in the rerun, against a range of 280 to 1,800 before; the difference is the host, not the change.

**End to end, before and after** (`attenuo-bench`, allow call, req/s at 1 / 8 / 32 clients; "before" is the run in [`bench/2026-10-23-vm-audit-write-path.md`](bench/2026-10-23-vm-audit-write-path.md), "after" the run in [`bench/2026-10-23-vm-policy-stage.md`](bench/2026-10-23-vm-policy-stage.md), commit 238d914, memory and file only):

| Audit, hops | before | after | p99 at 8 / 32 clients, before / after | single client, added p50 before / after |
|---|---|---|---|---|
| memory, 1 | 1,209 / 4,958 / 6,601 | 1,765 / 5,246 / 6,646 | 3.5 / 10.6 ms, 3.6 / 10.4 ms | 697 / 425 us |
| memory, 3 | 670 / 2,547 / 3,235 | 857 / 2,272 / 3,460 | 7.6 / 24.3 ms, 10.0 / 21.5 ms | 1,156 / 739 us |
| file (`normal`), 1 | 962 / 3,110 / 4,526 | 1,252 / 4,049 / 6,254 | 15.5 / 23.8 ms, 5.4 / 13.0 ms | 851 / 631 us |
| file (`normal`), 3 | 720 / 2,846 / 3,873 | 1,092 / 4,547 / 6,652 | 17.0 / 26.9 ms, 5.0 / 10.9 ms | 1,176 / 771 us |

Load on the host was 4 to 7 during this run and other agents were compiling; the memory group ran first, under more of that load, which is why its three-hop row looks slower than the file row that followed. Read every cell as plus or minus 20 percent. A same-binary A/B of the WAL change alone, with only `wal_checkpoint_seconds` changed and the variants interleaved, is in the bench file: at 8 clients the p99 went from 21 to 23 ms (SQLite checkpointing on the writer) to 4 to 8 ms and throughput rose 35 to 95 percent; at 32 clients the p99 went from 34 to 41 ms to 11 to 23 ms and the p90 from about 20 ms to 6 to 10 ms.

What this means:

- **Single-client added latency** fell by about 200 us at one hop and about 400 us at three, close to what the policy stage lost (about 105 us, and 140 to 190 us) plus the shorter append. The policy stage is no longer what grows with depth.
- **The file store's tail no longer has the checkpoint stalls.** Its p99 at 8 and 32 clients is now close to the in-memory store's. The worst case remains a catch-up pause each time the WAL passes 64 MB; it shows in the max column (32 to 131 ms on this host, [policy-stage](bench/2026-10-23-vm-policy-stage.md)) rather than the p99.
- **What is left of the added latency** is mostly outside the server's decision (now about 80 to 140 us at one hop): the blocking-pool hop, the proxy's request handling and the second HTTP round trip. It was not broken down by stage then; see [Time by stage of a proxied call](#time-by-stage-of-a-proxied-call-2026-10-23).

#### Backstop pause, measured (2026-10-23)

Since #21 the writer runs `TRUNCATE` itself when a commit leaves 128 MB in the WAL (`WAL_WRITER_BACKSTOP_FRAMES`). The ignored test `wal_backstop_pause` in `crates/attenuo-audit/tests/wal.rs` times it directly, against the background checkpointer's locked pass, through two test-only hooks behind the crate's `testing` feature (park the checkpointer; read the time each checkpoint held appends up). Three runs, release build, on the 4-vCPU dev container described above (ext4 temp directory, `durability = "normal"`, nothing else running; raw output and the rerun command in [the results file](bench/2026-10-23-vm-wal-backstop.md)):

| Pause | Measured | Notes |
|---|---|---|
| Backstop, checkpointer parked (copies the whole 128 MB) | 323 to 416 ms, median 335 ms (9 fires) | the latency of the append that triggered it; the `TRUNCATE` is all of it |
| Every other append in the same run, one writer | p50 0.06 to 0.07 ms, p99 0.16 to 0.18 ms, max 1.8 to 5.3 ms | about 11,200 appends per run |
| Backstop under load, checkpointer running (8 writers) | 123 and 132 ms | fired in 2 of 3 runs; the background thread had already copied most of the WAL |
| Locked pass at 64 MB, checkpointer running (8 writers) | 23 to 28 ms (4 passes); 1.4 to 2.8 ms when little was left | store lock held for the final `PASSIVE` |
| Appends under that load | p99 1.1 to 2.7 ms, max 27 to 177 ms | the max is the backstop when it fired |

The backstop is not rare on this box once the build is optimised. In release mode the bounded-WAL test (`the_wal_stays_bounded_under_continuous_load`, 8 writers) fired it in 3 of 3 runs on all 4 cores (peak WAL 129 MB) and in 1 of 5 runs pinned to 2 cores with two `yes` burners (peak 100 to 129 MB); in a debug build it fired in 1 of 3 runs on 4 cores and 0 of 5 on 2 cores (peak 85 to 100 MB where it did not fire), which matches the earlier observation of 78 to 104 MB and no fire (its build was not recorded; `cargo test` builds debug). So under sustained full-speed load the backstop, not the locked pass, sets the worst append on the file store: about 130 ms when it fires with the checkpointer working, about 0.35 s if the checkpointer is stuck.

### Time by stage of a proxied call (2026-10-23)

Branch `perf/proxy-stage-timing`, commit 51f0a89. The server now times each stage of a proxied call and serves the result as the histogram `attenuo_proxy_stage_seconds{stage=...}` on `/metrics` (buckets from 1 us to 1 s, five per decade), with the same figures as `tracing` debug fields. Each stage costs one `Instant::now()` pair. The stages:

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

`lease_check`, `policy` and `audit_append` are recorded in the decision pipeline, so AuthZEN decisions count there too. `attenuo-bench` reads the histograms when each cell's warm-up ends and when it stops, and prints the difference as a table ([`bench/2026-10-23-vm-proxy-stages.md`](bench/2026-10-23-vm-proxy-stages.md)). The p50 and p90 columns are interpolated inside buckets the way Prometheus' `histogram_quantile` does, so they are estimates. The mean is exact.

The run: one client, 10 s cells after 2 s of warm-up, allow and `deny_policy` at 1 and 3 hops, memory and file (`normal`) stores; 11,000 to 23,000 calls per cell. This is a shared 4-core VM, not a quiet machine. Load average was 4.4 to 6.4 during the run (unrecorded: the results file has no load line) while other agents compiled, and the load generator, proxy and upstream share those cores. Read every figure as plus or minus 20 percent or worse. Absolute figures are 3 to 4 times the in-process `decide` bench (policy 43 to 57 us here, 13 us there), so compare stages within this run, not with the tables above.

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

- **The proxy's own upstream round trip is the biggest stage**, 205 to 235 us p50, against 67 us p50 for the same call sent straight to the upstream by the load generator. Most of what the proxy adds to an allowed call is therefore a second HTTP exchange that costs about three times what the client pays for its own. The follow-up below traced it to wake-ups from idle on this VM, not to the client code: see [Upstream hop and blocking pool](#upstream-hop-and-blocking-pool-2026-10-23-follow-up).
- **The hop to the blocking pool costs more than the policy stage**: 70 to 85 us p50, which is more than lease check plus policy at one hop. Running the decision inline was tried in the follow-up below; the hop goes, the `upstream` stage grows by about as much, and throughput under load drops, so the pool stays.
- **The decision itself** (lease check, policy, append) is about 115 to 180 us p50 here. Lease check grows with depth (one row per hop) and is two to three times slower on the file store at one hop. The append's mean sits well above its p50 at three hops in memory (111 against 59 us), which shows occasional slow appends.
- **Token verification is negligible on a cache hit** (5 to 9 us), and `response` handling is 10 to 21 us.
- **Inside the handler, about 40 us is in no stage** (the allow-call stage means add up to 447 of a 485 us mean `total` in memory at one hop): reading and parsing the body, screening, building the decision record, the session gate and re-encoding. **Outside the handler**, the client's p50 is about 225 us above the handler's (661 against 437 us). That covers the client-to-proxy HTTP exchange, axum and hyper, and relaying the body. Subtracting medians gives only a rough split.

### Upstream hop and blocking pool (2026-10-23, follow-up)

Branch `perf/proxy-upstream-hop`. This follows the two questions the stage run above left open: why the proxy's upstream round trip (about 205 us p50) costs three times what the load generator pays for the same call (67 us), and whether the `blocking_pool` hop (70 to 85 us) should go. Short answer: neither is a defect in the proxy code, and no change was kept.

**The upstream client is already right.** `AppState` holds one `reqwest::Client`, built once in `router()`, and every request goes through it. During a run, `/proc/net/tcp` showed one established connection from the proxy to `fake_mcp` and no churn, so keep-alive pooling works. The request is HTTP/1.1 with no `Connection: close`, and an `strace` of the server showed it leave as one `writev` (headers and body) and the response come back in one read. The request body is read once. It is parsed and re-encoded on purpose (SR-01: forwarding the raw bytes would let duplicate JSON members past screening), and that happens before the `upstream` timer starts. A `tools/call` response is streamed back, not buffered. Nothing in the upstream path goes through the blocking pool.

**The gap is the cost of waking idle CPUs on this VM.** In the direct baseline the load generator calls `fake_mcp` back to back, about 12,000 times a second, so its threads never sleep. Through the proxy, `fake_mcp` gets one call about every 650 us and sleeps in between, and so does the proxy thread waiting for the answer. A probe that calls `fake_mcp` directly over one keep-alive connection (Python `http.client`, so its absolute figures include Python's own overhead) shows the effect. Rerun 2026-10-23, with the probe's source in the file ([`upstream-hop`](bench/2026-10-23-vm-upstream-hop.md)):

| Pause between calls | p50, us (two runs) |
|---|---|
| none | 174, 162 |
| 500 us `sleep` | 391, 351 |
| 500 us busy loop in the client | 274, 280 |

Quoted earlier, unrecorded (no probe source or output was kept): 145 and 130, 337 and 377, 199 and 349.

An idle gap adds about 200 us to the same call (190 to 215 us in the rerun). That is the same size as the difference between the proxy's `upstream` stage and the direct baseline. The direct baseline in the bench is therefore a lower bound that the proxy cannot reach at one client, not a like-for-like figure.

**The blocking pool hop can be removed, but the time moves elsewhere.** The experiment (commit `5b9d17a`, reverted in the next commit) added `[proxy] inline_decisions`. With it, `ServerAuthorizer` ran the decision on the async worker handling the request when no other decision was in flight, and on the blocking pool otherwise. Decisions, audit records and their order were the same in both paths, and a 48-way concurrent test checked the chain. Rerun 2026-10-23 with binaries built from `5b9d17a` ([`upstream-hop`](bench/2026-10-23-vm-upstream-hop.md)): 1 hop, 1 client, allow call, 8 s cells after 2 s of warm-up, three interleaved runs of each, load average 0.5 to 1.6. "inline" is `inline_decisions = "when_idle"`. The figures are medians of the three runs, with the range in brackets; all in us except calls/s.

| | memory, pool | memory, inline | file, pool | file, inline |
|---|---|---|---|---|
| client p50 | 691 [562-693] | 636 [604-637] | 708 [620-747] | 701 [681-704] |
| client p99 | 1510 | 1348 | 1606 | 1476 |
| calls/s | 1373 | 1510 | 1312 | 1356 |
| `blocking_pool` p50 | 69 | 1.4 | 69 | 1.5 |
| `upstream` p50 | 210 | 236 | 206 | 251 |
| `total` (handler) p50 | 460 | 405 | 484 | 456 |

Quoted earlier, unrecorded (first run, load average 2.6 to 10.8, no results file kept). Its columns were memory pool, memory inline, file pool, file pool again with the same code, and file inline:

| | memory, pool | memory, inline | file, pool | file, pool (rerun) | file, inline |
|---|---|---|---|---|---|
| client p50 | 572 [532-588] | 650 [555-728] | 661 [536-713] | 629 [607-638] | 591 [532-609] |
| client p99 | 1236 | 1392 | 1612 | 2761 | 1207 |
| calls/s | 1637 | 1468 | 1398 | 1386 | 1571 |
| `blocking_pool` p50 | 58 | 1 | 63 | 60 | 2 |
| `upstream` p50 | 170 | 245 | 186 | 171 | 202 |
| `total` (handler) p50 | 396 | 417 | 460 | 438 | 413 |

The hop disappears from `blocking_pool`, and `upstream` grows. In the first run it grew by about as much as the hop. In the rerun it grew by 26 us on memory and 45 us on file, against a hop of 69 us. With the pool, the worker that resumes the request and the pool thread are still awake when the upstream answer arrives. Inline, fewer threads are awake and the answer meets a sleeping CPU. The client sees no consistent gain. In the first run inline was 78 us slower on memory and 38 to 70 us faster on file. In the rerun it was 55 us faster on memory and 7 us faster on file. The pool's own three memory runs spread from 562 to 693 us at p50. That is the noise floor, and every inline difference sits inside it.

Under load, inline did not help. At 8 clients on the memory store, the first run gave 4,929 and 4,606 calls/s with the pool against 3,569 and 2,481 inline (unrecorded; that always-inline variant is not in `5b9d17a`). Running Cedar and the append on async workers takes them away from I/O, and a request that waits for the audit store's lock holds a worker while it waits. The `when_idle` rule (inline only when no other decision is in flight) gave 5,669 and 5,732 calls/s against the pool's 5,814 and 5,824 in the rerun ([`upstream-hop`](bench/2026-10-23-vm-upstream-hop.md)). Quoted earlier, unrecorded: 5,515 and 3,792 against 5,745 and 5,177. `tokio::task::block_in_place` brought the hop down to about 17 us at one client, but at 8 clients it fell to 4,963 and 2,878 calls/s (unrecorded; that variant was never committed).

So the blocking pool stays, for both stores, and SR-22 is unchanged. On this VM a call through the proxy pays a few wake-ups from idle, and moving work between threads changes which stage records them. A quieter machine with less idle-state latency (or more load) would show a smaller `upstream` stage and a smaller hop. The measurement that would settle it is a direct baseline paced at the proxied rate; see the board.
### Exchange throughput, lease renewal and open-loop arrivals (2026-10-23)

Branch `perf/exchange-lease-bench`, base def86a9, new code in `crates/attenuo-bench/src/exchange.rs`. Full tables and the raw rows: [`bench/2026-10-23-vm-exchange-lease.md`](bench/2026-10-23-vm-exchange-lease.md) and `.json`. Three additions to the harness:

- **`exchange`**: N closed-loop clients, each holding its own token (a root, or a chain of three hops), exchange it at `POST /token` for a child delegated to a fresh actor on every request. The server allows one delegation per parent and actor, so the actor ids are generated (`xa-<run>-<client>-<seq>`, never repeated). The server runs with `require_actor_auth = false` for this, which leaves out one SHA-256 comparison per request. Audit store memory or file (`normal`).
- **`lease-renew`**: M live leases (groups of one root and 99 children), every lease renewing at interval T through `POST /token/renew`, first renewals spread evenly over one interval, with a 300 s lease so renewals really move the expiry. Latency is measured from the time a renewal was due. After the cells, the time to revoke the root of a tree of depth 3 with 100 descendants (a root, 10 children, 9 grandchildren under each).
- **`--open-loop RATE[,RATE]`**: Poisson arrivals at a fixed rate instead of a fixed number of clients, on the existing proxied `tools/call` cell (top-level flag, with the call straight at the upstream at the same rate as the baseline) and on `exchange`. Latency runs from the scheduled arrival, so a slow server is not let off by the generator waiting for it. At most 1,024 requests are in flight; further arrivals are dropped and counted as `shed`. The lease cells are scheduled by the clock and need no flag.

Every cell also reads the server's CPU from `/proc/<pid>/stat`. Same environment and caveats as the earlier sections: shared 4-core VM, load average 3 to 10, one run per cell, plus or minus 20 percent. 10 s cells after 2 s of warm-up.

**Exchange**, 1 and 8 clients, req/s (p50 / p99 ms in brackets); "hops" is the length of the token being exchanged:

| Audit, hops | 1 client | 8 clients | server CPU per exchange |
|---|---|---|---|
| memory, 1 | 844 (1.08 / 2.3) | 2,249 (3.2 / 9.3) | 1.0 to 1.2 ms |
| memory, 3 | 676 (1.35 / 2.8) | 1,832 (4.0 / 11.2) | 1.3 to 1.4 ms |
| file, 1 | 649 (1.27 / 5.7) | 1,121 (6.1 / 23.6) | 1.2 to 1.3 ms |
| file, 3 | 430 (1.40 / 11.2) | 833 (7.8 / 44.8) | 1.4 ms |

An exchange costs the server about 1 ms of CPU, two to three times a proxied allow call (470 to 610 us in the open-loop cells below). That is the Ed25519 signing, the verification of the parent and of the token just minted, the lease registration and an audit record. A three-hop parent costs 8 to 25 percent more than a root. At 8 clients the in-memory server used 2.5 cores of the 4 and the generator the rest, so these are rates for this VM, not for the server alone. The file store is about half the in-memory rate at 8 clients and has the longer tail, as for calls. Open loop, 1-hop token: memory held 500 and 1,500 arrivals per second (p99 7.9 and 33 ms); file held 500 (p99 35 ms) and, in this pass, 1,500 (p50 27 ms, p99 290 ms), which is where its closed-loop rate of 1,100 to 1,200 says the knee is; see the note on run-to-run spread in the bench file.

**Lease renewal**, T = 1 s unless stated, latency from the due time (service time from the send in brackets):

| Audit | Leases | Offered / achieved per s | p50 / p99 ms | Server CPU | CPU per renewal |
|---|---|---|---|---|---|
| memory | 100 | 100 / 100 | 1.5 / 5.0 (0.66 / 3.4) | 5% of a core | 530 us |
| memory | 1,000 | 1,000 / 1,000 | 2.0 / 57 (0.62 / 51) | 49% | 490 us |
| memory | 5,000 | 5,000 / 4,985 | 23 / 227 (16 / 157) | 225% | 450 us |
| memory | 5,000, T = 10 s | 500 / 500 | 2.2 / 6.7 (0.74 / 4.3) | 38% | 770 us |
| file | 100 | 100 / 100 | 2.1 / 6.4 (0.85 / 4.8) | 7% | 740 us |
| file | 1,000 | 1,000 / 1,000 | 2.5 / 768 (1.1 / 736) | 67% | 670 us |
| file | 5,000 | 5,000 / 1,600 | 8,271 / 13,707 | saturated | n/a |
| file | 5,000, T = 10 s | 500 / 500 | 1.9 / 76 (0.95 / 75) | 39% | 790 us |

Idle CPU with the leases live and nothing renewing was below the 10 ms tick resolution in every cell: live leases cost nothing until they renew. Server memory (RSS) went from 22 to 25 MB at 100 leases to 68 to 229 MB at 5,000 in the in-memory store; most of the growth is that store keeping every renewal record, not the leases (the file store went 60 to 74 MB).

Revoke cascade, root of a depth-3 tree with 100 descendants, 5 runs per store (revoked 101 leases each time; a descendant's renewal was refused afterwards): memory 1.0 / 1.2 / 3.0 ms (min / median / max), file 14.6 / 19.4 / 26.6 ms, including the HTTP round trip and the admin audit record. About 190 us per lease on the file store, 12 us in memory.

**Open-loop `tools/call`** (allow, 1 hop, direct baseline at the same rate). `svc` is send to answer, without the generator's own 1 ms scheduling lag:

| Audit | Rate per s | svc p50 / p99 ms, proxy | svc p50 / p99 ms, direct | Added svc p50 | Server CPU per call |
|---|---|---|---|---|---|
| memory | 500 | 0.92 / 4.9 | 0.29 / 0.53 | 0.63 ms | 520 us |
| memory | 2,000 | 1.03 / 4.4 | 0.28 / 0.82 | 0.75 ms | 470 us |
| file | 500 | 0.97 / 2.9 | 0.30 / 0.94 | 0.67 ms | 610 us |
| file | 2,000 | 1.08 / 15.6 | 0.30 / 0.75 | 0.78 ms | 530 us |

The achieved rate matched the offered rate in every call cell and nothing was shed. The added p50 (0.63 to 0.78 ms) is larger than the closed-loop single-client figure (0.59 to 0.73 ms in [Time by stage](#time-by-stage-of-a-proxied-call-2026-10-23)) because the open-loop generator opens concurrent requests, and the baseline here is 0.29 ms instead of 0.07 ms for the same reason. The p99 of the file store at 2,000 per second (15.6 ms) shows its tail starting before its throughput limit does.

What this means:

- **Lease renewal is cheap per lease and expensive only at an unrealistic interval.** A renewal costs the server 450 to 790 us of CPU, about as much as a proxied call. With the default 300 s lease and a renewal at half of it, 5,000 live leases are about 33 renewals per second, 2 to 3 percent of one core if the per-renewal cost holds at that rate (extrapolated linearly from the 500 per second cells, not measured). Pushed to 5,000 renewals per second, the in-memory store kept up at 225 percent of a core with a p99 of 227 ms, and the file store did not (1,600 per second, a queue that never drained). So the number to take from this run for sizing is about 2,000 renewals per second per core for in-memory and well under 5,000 per second for the file store on this VM, not the 5,000-lease cells at T = 1 s read as a deployment.
- **The file store's renewal tail is long, and the cause was not found.** At 1,000 per second its p99 was 0.77 s with a median of 2.5 ms. The renewal path makes two writes (the lease row and an audit record); stalls in the writer are the likely cause, but this run has no measurement that separates them from host load (the average was 9.7 at the end of the lease run).
- **Every renewal writes an audit record.** At 500 per second that is 43 million records a day; at the 33 per second above, 2.9 million. This is a growth rate for the audit log to budget for, and a reason to look at whether renewals need a record each (a design question, not made here).
- **Revocation is fast enough to be called immediate** at this size: 101 leases in about a millisecond in memory and 20 ms on file (HTTP round trip included). It scales with the number of descendants, and 100 is small. Larger trees were not tried.
- **Exchange is a once-per-delegation cost**, about 1 ms of server CPU, so an agent that delegates once per task adds that to the task start, not to each call.

What was not measured: renewal traffic and `tools/call` traffic at the same time (so the effect of a renewal load on call latency, which is what RQ2 asks, is inferred from the CPU figures, not observed); renewals with a DPoP-bound token; exchanges with client-secret checking; trees larger than 100 descendants; more than one run per cell. The generator's own cost is in every number: its 1 ms timer lag is shown, its CPU share is not.

### Output labelling: result append (2026-10-24)

Branch `feat/output-labels-phase1`, based on de3cf75. Output labelling adds work to every allowed call that gets an answer: the server hashes the answer (`result_digest`, RFC 8785 JSON and SHA-256), appends a `tool_result` record, and for an untrusted tool adds a label row to the run (`Pipeline::record_result`, two transactions on the store). Every decision also reads the run's labels. The `decide` bench has new cells for these. One run, criterion, 1 s warm-up, 3 s measurement, the same 4-core shared VM, load average 1.5 to 2.1 ([`bench/2026-10-24-vm-criterion-tool-result.txt`](bench/2026-10-24-vm-criterion-tool-result.txt)). Small result (one text item).

| Cell, microseconds (criterion estimate, interval in brackets) | 1 hop | 3 hops |
|---|---|---|
| `result_digest` | 0.68 (0.66 to 0.71) | 0.72 (0.69 to 0.74) |
| `record_result_file` (`durability = normal`) | 147 (115 to 187) | 155 (126 to 189) |
| `append_file`, a decision record, same run | 136 (104 to 173) | 154 (113 to 201) |
| `decide_file`, now including the label read | 143 (123 to 168) | 161 (141 to 184) |
| `record_result_file_full` (`durability = full`) | 329 (316 to 344) | 425 (399 to 451) |
| `record_result_memory` | 136 (129 to 143) | 213 (206 to 221) |

Readings:

- **On the file store, recording a result costs about as much as recording the decision**, roughly 150 us at `normal` durability, so an allowed call now spends about twice as long in the audit log as before. The intervals of `record_result_file` and `append_file` overlap, so the label row adds little on top of the append in this run. The design note's estimate (60 to 140 us for a file append) was about right.
- **Hashing the result is negligible** for a small result (under 1 us). It grows with the size of the result; large results were not measured.
- **The label read did not move `decide_file` measurably** (143 us against 136 us for the bare append in the same run, within noise). The store keeps one label row per source, so the read does not grow with the number of results a run reads.
- **`durability = full` roughly doubles the cost** (two fsyncs, one per transaction).
- The in-memory cells are slower than expected next to the file cells (213 us at 3 hops). Not investigated; one run on a shared VM.

Not measured: results of realistic sizes (tens of kilobytes) and SSE responses with many events. The end-to-end effect is in the next section.

### Output labelling and run limits on the hot path (2026-10-24)

Branch `perf/labels-limits-cost`, main `77b5e8f`. The section above measured the result append in process; this one measures what output labelling (#42, #47) and run limits (#50) add to one proxied call end to end, and on which stage. Results: [`bench/2026-10-24-vm-labels-limits.md`](bench/2026-10-24-vm-labels-limits.md) and `.json`; the in-process charge cells: [`bench/2026-10-24-vm-criterion-charge.txt`](bench/2026-10-24-vm-criterion-charge.txt).

**Method.** New subcommand `attenuo-bench hot-path` (`crates/attenuo-bench/src/hotpath.rs`). It starts one server and one `fake_mcp` per configuration, each with a SQLite file store at `durability = "normal"`, and a 2-hop token (the root and one exchange). It drives two calls through each server: `read` (`read_file` on `alice/public-docs`) and `destructive` (`create_issue` on the same repo, catalog `destructive` by default, allowed by a permit in every configuration). Both bodies carry `n: 1`, declared `long` in every catalog, so the bodies are the same everywhere. One client, closed loop, 2 s warm-up and 10 s measured per cell. Five runs, interleaved: each run measures every configuration's two cells before the next run starts, so drift on the host spreads over all of them. The tables give the median of the five runs' p50, p95 and p99. The p50 of a single run moved by up to 350 us (baseline `read`: 1,009 to 1,357 us; two outlying runs of D at 2.8 and 3.9 ms). The median of runs 1 to 3 and the median of runs 3 to 5 differ by up to 100 us for A, B and C' and by up to 215 us for C. So read client differences under about 100 us as noise. The server's stage figures, pooled over 20,000 to 40,000 calls per cell, are steadier, and the readings below rest on them. After the runs the harness makes one more call of each kind and reads its decision record, to check that each configuration does what it says (counters charged, `labels.tainted_by` entries). Then it verifies each audit chain.

| Configuration | Catalog `output` | Policy beyond the bench's | Token | Check: counters charged / `tainted_by` |
|---|---|---|---|---|
| A, `baseline` | `trusted` on both tools | permit `create_issue` | no limits | 0 / 0 |
| B, `labels` | `untrusted` (the default) | also a forbid on `context.session.tainted` that does not fire for these calls | no limits | 0 / 2 |
| C, `limits` | `trusted` | as A | `calls` and `sum` (on `n`) on both capabilities, in both hops | 4 / 0 |
| C', `limits_calls` | `trusted` | as A | `calls` only | 2 / 0 |
| D, `both` | as B | as B | as C | 4 / 2 |

Two things are true of every configuration, A included, because they are on main for every allowed call. Every answer is recorded with a `tool_result` append (#42; `trusted` only skips the run label). And every decision reads the run's labels and builds `context.session`. So A is the floor today, not "labelling off". What B adds over A is the run-label write after each answer, a label set that is not empty, and `labels.tainted_by` in each decision record. The `read` cell runs first, so in B and D every measured `destructive` call is on a tainted run. C' was added to separate the counter writes from the `synchronous=FULL` commit that a `sum` charge forces.

**Stages.** The charge and the run-label write have no stage of their own in `attenuo_proxy_stage_seconds`, and this branch leaves the server's timers alone. The harness derives two means from histograms the server already exports: **decide (unstaged)**, which is `attenuo_authorize_duration_seconds` minus `lease_check`, `policy` and `audit_append` (the charge, building the record, approval bookkeeping), and **result append**, which is `attenuo_audit_append_duration_seconds` minus the decision appends. The run-label write (`LeaseStore::add_label`) runs inside the `response` stage. The counter read (`budget_view`) and the label read run inside `policy`.

**Environment.** The 4-vCPU shared dev container described at the top of the page, not a reference machine; rustc 1.99.1, release profile. Other agents were working on the host: load average 1.7 at the start (09:18 UTC) and 4.9 at the end (09:28 UTC). The load generator, the servers and the upstreams share the four cores.

Client latency, one client, microseconds, and calls per second (median of 5 runs):

| Configuration | `read` p50 / p95 / p99 | req/s | `destructive` p50 / p95 / p99 | req/s |
|---|---|---|---|---|
| A, baseline | 1,141 / 1,788 / 3,037 | 794 | 1,179 / 1,779 / 2,953 | 787 |
| B, labels | 1,115 / 1,768 / 2,877 | 810 | 1,203 / 1,761 / 2,849 | 767 |
| C, limits (`calls` + `sum`) | 1,968 / 3,072 / 4,977 | 445 | 2,165 / 3,471 / 5,849 | 418 |
| C', limits (`calls` only) | 1,263 / 1,893 / 2,918 | 714 | 1,370 / 2,018 / 3,258 | 654 |
| D, both | 2,078 / 3,056 / 4,551 | 451 | 2,109 / 2,982 / 4,469 | 440 |

Per stage, `read` call, pooled over the five runs (20,000 to 40,000 calls each), p50 / mean in microseconds; "unstaged" and "result append" are means. The `destructive` column moves the same way; both are in the results file.

| Stage | A | B | C | C' | D |
|---|---|---|---|---|---|
| `lease_check` | 41 / 44 | 24 / 27 | 43 / 45 | 42 / 44 | 29 / 32 |
| `policy` (label read, counter read, Cedar) | 97 / 103 | 99 / 105 | 138 / 122 | 124 / 115 | 149 / 132 |
| decide (unstaged): the charge | 17 | 16 | 784 | 79 | 916 |
| `audit_append` (decision record) | 97 / 147 | 94 / 142 | 158 / 174 | 148 / 171 | 160 / 179 |
| whole decision (mean) | 311 | 290 | 1,126 | 408 | 1,259 |
| `blocking_pool` | 93 / 122 | 86 / 104 | 132 / 148 | 95 / 123 | 132 / 149 |
| `upstream` | 255 / 277 | 248 / 266 | 295 / 316 | 256 / 273 | 291 / 317 |
| `response` (result append, label write) | 262 / 308 | 275 / 319 | 286 / 341 | 267 / 343 | 347 / 385 |
| result append (`tool_result`, mean) | 138 | 135 | 152 | 165 | 154 |
| `total` (handler) | 945 / 1,070 | 921 / 1,029 | 1,710 / 1,990 | 1,120 / 1,200 | 1,779 / 2,171 |

Deltas against A, `read` / `destructive`, client p50: B -26 / +25 us; C +827 / +986 us; C' +122 / +192 us; D +937 / +931 us.

In process (`cargo bench -p attenuo-server --bench decide`, new cells; 2-hop chain; criterion point estimate with the interval in brackets; load average 3.4 to 5.9):

| Cell | memory | file, `normal` | file, `full` |
|---|---|---|---|
| `budget_read`, 4 counters | 3.5 us | 4.7 us | 4.6 us |
| `charge`, `calls` only (2 counters) | 78 us [76, 80] | 39 us [37, 41] | 422 us [405, 440] |
| `charge`, `calls` + `sum` (4 counters, commits with `synchronous=FULL`) | 84 us [78, 89] | 623 us [574, 680] | 448 us [426, 471] |

**E: an approval round**, measured separately on its own server (labels as in B, plus `@obligation("approval")` on destructive calls in a tainted run, no limits): the gated call (`-32008` with an `approval_id`), `POST /admin/approvals/{id}` with `{"decision": "grant"}`, and the identical retry, which is allowed and consumes the approval. 100 rounds discarded, then 2,000 timed one after the other, microseconds:

| Step | p50 | p95 | p99 | mean |
|---|---|---|---|---|
| gated call (approval stored, `approval_request` appended) | 996 | 1,705 | 3,793 | 1,103 |
| operator grant | 704 | 1,325 | 3,557 | 796 |
| retry (approval taken, allowed, forwarded, result recorded) | 1,505 | 2,822 | 6,459 | 1,897 |
| whole round | 3,314 | 5,939 | 9,347 | 3,796 |

Over those rounds the `policy` stage averaged 174 us, against 105 in B, because every decision tries to take an approval (a lease-store write when one is granted).

What this means:

- **Labelling an answer untrusted costs nothing measurable at the client.** B is within noise of A in both cells (-26 and +25 us at p50; p95 and p99 a little lower). On the server, the run-label write shows as about 12 to 20 us more at p50 on `response` (`read` and `destructive`), and the session-aware forbid and the non-empty label set add 2 to 11 us at p50 on `policy`. The larger part of what output labelling costs is in every configuration, A included: the `tool_result` append, about 135 to 140 us mean per allowed call on this store, inside `response`. That is the figure of the section above (about 150 us in process), now seen end to end.
- **A `sum` limit costs about 0.8 to 1.0 ms per call and halves single-client throughput.** Almost all of it is the charge transaction (784 to 858 us mean, against 17 us unstaged in A). The cause is the commit with `synchronous=FULL` that every `sum` charge forces (design 3.4), which is one `fsync` on this container's disk. In process, that charge costs 623 us, against 39 us for a `calls`-only charge on the same store.
- **A `calls` limit costs about 120 to 190 us per call at p50** at the client, which is near the noise floor; the handler's `total` agrees (+175 us at p50, +130 us mean). The charge transaction is about 60 to 65 us of it (79 and 82 us unstaged, against 17). The rest is spread out: `policy` grows by 12 to 29 us mean (27 to 52 us at p50), although reading the counters takes only 4 to 5 us in process. The decision append also grows by 23 to 32 us mean (51 to 63 us at p50) whenever limits are on (see the list of anomalies below).
- **Which extra store transaction dominates.** With a `sum` limit, the charge (about 800 us) is five to six times the result append (about 140 us). With `calls` only, the result append is the larger of the two: 135 to 165 us, against a charge of 60 to 65 us. The run-label write is the smallest at about 15 us.
- **Both together cost about the sum of the parts** (D: +931 to +937 us at p50), and D's `response` is the highest of the five (347 us at p50).
- **An approval round costs about 3.3 ms at p50**, about 2.8 times one allowed destructive call in B. It happens once per gated call, not once per call. A human approver adds seconds on top.

Anomalies, measured and not fixed:

- A `sum` charge on a `normal` store costs more than on a `full` store: 623 us [574, 680] against 448 us [426, 471] in process. Switching `synchronous` to `FULL` for one transaction and back (`with_full_sync`) may cost more than the sync itself, or force more than one `fsync`. Not profiled. Profiled since: it is neither (see [`sum` charge follow-up](#sum-charge-follow-up-2026-10-24)).
- With limits on, the decision append grows by about 50 to 60 us at p50, with or without `sum`. The charge commits on the lease store's own connection just before the append commits on the audit connection, on the same file and WAL; a hand-off of the WAL write lock or the shared memory index is the likely cause. Not investigated.
- The in-memory store's charge (78 to 84 us) is slower than the file store's `calls` charge (39 us). The in-memory result append looked the same way in the section above.
- `lease_check` is 15 to 20 us lower on the B and D servers than on A, C and C', with the same chain and store kind. It does not follow any feature, so it is a per-server or per-file effect; it shows how far two identical servers can differ on this host.

Not measured: the memory store end to end (only in process); more than one client, so contention on the store's connection lock between the charge, the label write and the appends under concurrency; `calls_per` limits (their HMAC of the value; measured since: see [Limit kinds](#limit-kinds-callsper-and-distinct-2026-10-24)); results of realistic size (only the small echo answer); `durability = "full"` end to end; and a quiet reference machine.

### `sum` charge follow-up (2026-10-24)

Branch `perf/sum-charge-fsync`, main `422def8`. The section above left two anomalies: a `sum` charge cost more on a `normal` store than on a `full` one (623 against 448 us), which looked like the `synchronous` switch in `with_full_sync` costing more than the sync, and the decision append grew by 50 to 60 us whenever limits were on. This section profiles the charge, changes where its sync happens, and measures again.

**Method.** Same 4-vCPU shared container; other agents were building on it (load average 0.4 to 4.6). All binaries were built with `lto = false` and `codegen-units = 16` (`CARGO_PROFILE_RELEASE_*` overrides, to keep build time and disk down), so the absolute figures are not comparable with the tables above; before and after were built the same way and run interleaved. Three tools: a throwaway probe against `SqliteLeaseStore` and `SqliteAudit` on one file at `normal`, opened as the server opens them (a fresh store per configuration, configurations interleaved; the single-operation loops time 2,000 iterations after 200 discarded, the charge-plus-append runs time every call, 2,000 on one thread or 1,000 per thread on 4 and 8; three to eight rounds); `strace -f` on the same probe to count `fsync` calls and the WAL pages each connection writes; and `attenuo-bench hot-path --configs baseline,limits,limits_calls` with the before and after binaries alternating, 10 runs of each cell per binary (four invocations of 3, 3, 2 and 2 runs). The `decide` bench has a new cell, `decide_limited_{store}/{calls_sum,calls}` (`Pipeline::decide` of a limited call, so the charge and the append in the pipeline's order), but on this host its intervals overlapped from run to run (1.0 to 1.9 ms for `decide_limited_file/calls_sum` with either binary), so the figures below come from the probe.

**What the profile shows.**

- **The `synchronous` switch costs about 2 us** (`PRAGMA synchronous=2` then `=1` without a commit, p50), and every `sum` charge makes exactly one `fsync` in every configuration (strace: one per iteration). A charge-only loop costs the same with the switch (439 to 480 us p50), on a lease connection kept at `FULL` (441 to 452 us), and on a store at `full` (439 to 527 us). Candidate (a), a second connection kept at `FULL`, therefore saves nothing measurable.
- **The 623 against 448 us in the `decide` bench is not the switch.** With fresh stores and interleaved configurations it does not reproduce. What does make a `sum` charge dearer on a `normal` store is what comes between charges in the pipeline: with a decision append after each charge, the charge costs 541 to 854 us p50 on a `normal` store and 425 to 624 us on a `full` one. Its `fsync` also writes out the previous append's WAL frames, which on a `normal` store nothing synced; on a `full` store that append paid for its own `fsync`.
- **One allowed `sum` call writes about 25 to 40 WAL pages before its `fsync`**: 6 to 14 for the charge (four counters and their log rows, with indexes) and 16 to 28 for the decision record (the `audit` table and its indexes). That one `fsync` of 100 to 160 KB is most of the 0.8 to 1.0 ms. The invariant (a `sum` charge is on disk before the call goes on) needs one `fsync` per call from a single client, so no change to how the sync is issued removes it; only fewer pages per call would make it cheaper.
- **The decision append's growth with limits on** did not reproduce cleanly in process: after a `calls` charge the append took 84 to 101 us p50, about what it takes alone, and after a synced `sum` charge 123 to 180 us. It stays open.

**The fix (candidate b, without merging the transactions).** When the lease store and the audit log are the same file, which is how the server opens them, the charge commits at the store's own level and the decision append commits with `synchronous=FULL`. That one `fsync` covers the WAL, so it makes both the charge and the decision durable before the call is answered or forwarded. Concurrent appends join that commit through the existing group commit, so concurrent `sum` calls share one `fsync`. The charge keeps its own `IMMEDIATE` transaction, its re-check and its refund if the append fails. If the process crashes before the synced append returns, the charge can be lost, but then the call was never forwarded. A `calls`-only charge, the memory store, a store at `full`, and a lease store in another file behave as before. Code: `LeaseStore::charge_sync_deferred` and `sync_file`, `AuditSink::append_synced` and `sync_file`, `Pipeline::charge_sync_on_append`. Moving the charge into the audit writer's transaction was not done: the record carries the charge's `used_after`, so the writer would have to run the charge, and the lease store and the log would need one connection. The measurements below show that it would remove one commit, not the `fsync`.

**Before and after.**

| | before | after |
|---|---|---|
| Probe, one thread, charge + append, p50 (median of 7 rounds, range; an eighth, first round on a loaded host discarded) | 717 us (640 to 847) | 637 us (572 to 822) |
| Probe, one thread, charge + append, mean (median of 7 rounds) | 871 us | 705 us |
| Probe, 4 threads, calls per second (3 rounds) | 427, 473, 473 | 685, 610, 736 |
| Probe, 8 threads, calls per second (3 rounds) | 511, 522, 215 | 919, 819, 283 |
| `hot-path`, `limits` `read` / `destructive`, client p50 (median of 10 runs) | 2,405 / 2,339 us | 2,405 / 2,343 us |
| `hot-path`, `limits` `read`, decide mean (median of 10 runs) | 1,245 us | 1,205 us |
| `hot-path`, `limits_calls` `read` / `destructive`, client p50 | 1,489 / 1,504 us | 1,457 / 1,523 us |
| `hot-path`, `baseline` `read` / `destructive`, client p50 | 1,319 / 1,359 us | 1,319 / 1,328 us |

On the server, the cost moved from the charge to the append, as intended: `limits` `read` "decide (unstaged)" fell from 891 to 114 us mean, and `audit_append` rose from 197 to 1,118 us mean (170 to 853 us at p50).

Readings:

- **From one client the change is within noise end to end.** In process it saves about 80 us at p50 (one commit and one lock hand-off between the two connections, about 10 percent of the charge and the append together). At the client, the 10-run medians are equal. The `after` binary also had four runs whose decide mean was 1.5 to 2.9 ms, against at most 1.45 ms for `before`; two of them fell in a load spike on the host, and they were not investigated further. The 0.8 to 1.0 ms a `sum` limit costs is one `fsync` of the call's WAL pages, and the invariant requires it.
- **With concurrent calls it helps**: 1.3 to 1.8 times the calls per second at 4 and 8 threads in process, in all six rounds (the third 8-thread round was slow for both binaries), because the charge no longer holds the lease store's lock and the database write lock through an `fsync`, and concurrent appends share theirs.
- **Multi-client cost is dominated by something else.** Under 4 threads both binaries make about one `clock_nanosleep` per call (strace: 1,256 for 1,200 calls before, 1,101 after). That is SQLite's busy handler: when the lease connection and the audit connection want the write lock at the same time, the loser sleeps 1, 2, 5 ms and so on rather than being woken. It sets the 5 to 35 ms per-call latency seen at 4 to 8 threads, with or without this change, and probably the 4 and 8 ms single-client outliers. Making the two connections queue on a lock in the process instead is the next step for concurrent limited calls (and for any lease-store write that runs alongside appends). It was not attempted here. Done since: see [Write-lock contention between the lease and audit connections](#write-lock-contention-between-the-lease-and-audit-connections-2026-10-24), which removes the sleeps (the single-client outliers turned out not to be the busy handler).

### Write-lock contention between the lease and audit connections (2026-10-24)

Branch `perf/store-write-lock`, main `54aab33`. The section above found that under concurrency SQLite's busy handler sleeps about once per call: the server opens the lease store and the audit log as two connections on one file, SQLite lets one of them write at a time, and the connection that loses the race for `BEGIN IMMEDIATE` sleeps 1, 2, 5 ms and so on instead of being woken when the lock frees. This section measures that directly and removes it.

**Method.** Same shared 4-vCPU container, other agents building on it (load average 1.1 to 5.6 during the runs). Two tools, both run with the before and after builds alternating, built the same way (release, `lto = false`, `codegen-units = 16`, as in the section above, so absolute figures are not comparable with the earlier tables):

- A probe, `crates/attenuo-audit/tests/write_contention.rs` (an `#[ignore]` test, run with `--ignored --nocapture`). It opens `SqliteAudit` and `SqliteLeaseStore` on one file as the server does (WAL checkpointer on, lease autocheckpoint off, `durability = "normal"`), replaces each connection's busy timeout with a handler that counts its calls and otherwise sleeps exactly as SQLite's default one does, and runs 1, 4 and 8 threads of 1,000 calls each. `sum` mode is the pipeline's order for a limited call: a deferred `calls` + `sum` charge on two hops, the synced decision append, and a run label on every fourth call. `calls` mode is a `calls` charge and a plain append. After each run it checks every counter and verifies the chain. Three interleaved rounds per build.
- `attenuo-bench hot-path --configs limits_calls,limits --runs 1 --duration 5 --warmup 1` at `--clients` 1, 4 and 8 (a server per configuration, file store, 2-hop token), two passes, before and after alternating per client count.

**What the probe showed.** Before, the busy handler ran 0.5 to 1.3 times per call at 4 and 8 threads in `sum` mode and 0.1 to 0.8 times in `calls` mode, sleeping 2 to 15 s in total per run, and never at one thread. It is what collapsed concurrent `calls` charges plus appends from about 6,000 calls/s on one thread to 800 to 2,700 calls/s on four.

**The fix: one write gate per file (candidate a).** Every store of the process opened on one file (keyed by its canonical path in a global registry of weak references) shares a `WriteGate`, held across every write transaction: the audit writer's batch commit, the inline append, a signed checkpoint, the WAL backstop's `TRUNCATE`, and every lease-store write (charges, refunds, labels, spans, renewals, revocations, approvals, registrations). Writers on one file queue on it and the next is woken when the commit is done, so SQLite's lock is never contended within the process and its busy handler is not reached; `BUSY_TIMEOUT` still covers another process. The lease store takes the gate before its connection lock, so its reads (the lease check and the budget read on every call) are not held up by a lease write waiting for the gate; the audit log takes it inside its connection lock, which its writer holds for a batch, and releases it before the checkpoint hook. Reads never take it. An in-memory store has no gate and stores in different files have different ones, so those paths are unchanged. Durability is unchanged: the same commits run at the same `synchronous` levels, and the deferred `sum` charge and group commit work as before.

The gate was tried as a plain `std` mutex and as a FIFO ticket lock (a mutex and a condition variable). Both removed every busy-handler call. The ticket lock is kept: it gave lower p99 in five of the six concurrent cells (`sum`, 4 threads: 6.9 against 17.1 ms; `calls`, 8 threads: 7.3 against 10.1 ms, medians of three rounds), with throughput the same within noise. With the plain mutex the audit writer could take the gate back for its next batch while a charge waited. Routing lease writes through the audit writer's connection (candidate b) was not needed, and neither was a shorter busy handler (candidate c).

**Before and after, probe** (medians of three interleaved rounds, range in brackets; per thread count, 1,000 calls per thread):

| mode, threads | busy calls per call | calls/s | p50 | p99 |
|---|---|---|---|---|
| `sum`, 1 | 0 / 0 | 496 (383 to 1,063) / 1,089 (926 to 1,217) | 1,802 / 834 us | 5.4 / 2.2 ms |
| `sum`, 4 | 0.85 (0.78 to 0.96) / 0 | 608 (256 to 693) / 1,163 (687 to 1,341) | 5.3 / 3.2 ms | 26.1 / 6.9 ms |
| `sum`, 8 | 0.69 (0.55 to 0.76) / 0 | 766 (531 to 974) / 1,223 (1,152 to 1,272) | 7.6 / 5.7 ms | 64.4 / 17.4 ms |
| `calls`, 1 | 0 / 0 | 5,875 / 4,167 | 138 / 213 us | 0.54 / 0.75 ms |
| `calls`, 4 | 0.20 (0.10 to 0.25) / 0 | 2,255 (2,056 to 2,677) / 3,056 (2,932 to 4,769) | 336 / 845 us | 13.5 / 5.4 ms |
| `calls`, 8 | 0.10 (0.09 to 0.14) / 0 | 2,842 (2,802 to 3,418) / 3,706 (3,000 to 4,330) | 662 / 1,691 us | 23.0 / 7.3 ms |

Each cell is before / after. An earlier set of four rounds (before against the plain-mutex gate) gave the same picture with more contention before: 0.5 to 1.3 busy calls per call at 4 and 8 threads, and `calls` mode at 4 threads 792 to 1,213 calls/s before against 3,110 to 4,857 after.

**Before and after, end to end** (`hot-path`, two passes per cell, `read` and `destructive` pooled, so four values each):

| config, clients | req/s before | req/s after | p99 before | p99 after | `lease_check` mean before / after |
|---|---|---|---|---|---|
| `limits_calls`, 1 | 578 to 679 | 620 to 687 | 2.9 to 6.7 ms | 3.5 to 5.2 ms | 43 to 61 / 44 to 56 us |
| `limits_calls`, 4 | 835 to 967 | 1,045 to 1,361 | 16.1 to 20.0 ms | 12.6 to 13.4 ms | 604 to 729 / 87 to 118 us |
| `limits_calls`, 8 | 824 to 955 | 965 to 1,103 | 34.0 to 42.2 ms | 32.1 to 42.5 ms | 1,688 to 2,316 / 146 to 162 us |
| `limits`, 1 | 248 to 433 | 254 to 436 | 4.9 to 11.8 ms | 5.1 to 8.9 ms | 48 to 71 / 48 to 60 us |
| `limits`, 4 | 214 to 480 | 104 to 602 | 19.3 to 61.0 ms | 25.7 to 203.6 ms | 1,362 to 3,928 / 65 to 93 us |
| `limits`, 8 | 377 to 511 | 410 to 644 | 47.2 to 86.0 ms | 28.4 to 54.9 ms | 4,858 to 7,252 / 81 to 124 us |

Readings:

- **The busy-handler sleeps are gone**: zero calls in every after run, at every thread count, against 0.1 to 1.3 per call before. The new test `shared_file_writers_never_reach_the_busy_handler` (`crates/attenuo-audit/tests/write_gate.rs`) asserts it and fails without the gate.
- **In process, concurrent tails fall 2.5 to 4 times**: p99 at 4 and 8 threads went from 13 to 64 ms to 5 to 17 ms, and throughput rose 1.3 to 1.9 times. One thread pays nothing for the gate: five more interleaved one-thread `calls` rounds of 3,000 calls gave 3,895 to 6,209 calls/s before and 5,175 to 6,970 after (p50 123 to 155 against 119 to 146 us); the 4,167 in the table is one slow round. With a `calls` charge the p50 rose (336 to 845 us at 4 threads): calls now queue in turn on the gate instead of a few winning outright while others sleep, so the median waits a little longer and the tail much less.
- **End to end, the lease check stops waiting**: under 4 and 8 clients its mean fell from 0.6 to 7 ms to under 0.17 ms, because before the lease connection's lock was held by a write sleeping in the busy handler. With a `calls` limit, 4 clients get about 1.3 times the requests per second (medians of the four values 884 against 1,174) and a lower p99; at 8 clients about 1.14 times (922 against 1,050) and p99 is unchanged (32 to 42 ms either way). On this host 8 clients plus the server saturate the 4 vCPUs, and the remaining tail is scheduling, not SQLite.
- **With a `sum` limit end to end the change is within noise.** Those calls are bound by the one `fsync` per call that the durability rule requires, now paid inside the audit append (whose mean rose as the lease side stopped sleeping). The after cell at 4 clients with 104 req/s and a 204 ms p99 fell in a load spike: its policy stage, which does no I/O, averaged 7.8 ms against 0.4 to 1 ms in the other cells.
- **The single-client outliers are not the busy handler.** It never ran at one thread, before or after. The 4 to 8 ms single-client outliers stay open. Measured since: see [Single-client outliers](#single-client-outliers-2026-10-24).

### Run usage write (2026-10-24)

Branch `perf/usage-write-elision`, main `8dca83d`. Since #59 every allowed call to a destructive tool charged the run-usage counters (`context.usage`) in one lease-store transaction, whether or not anything could read them. The server now keeps usage only when a loaded policy references `context.usage`, the catalog names `amount` or `destination`, or `[policy] track_usage = true` (see [run limits](run-limits.md#usage-kept-only-when-something-can-read-it-2026-10-24)). This section measures that write. Results: [`bench/2026-10-24-vm-usage-write.md`](bench/2026-10-24-vm-usage-write.md).

**Method.** `attenuo-bench hot-path` has a new configuration, `usage`: `baseline` (trusted output, no token limits, the bench's policy, which does not read `context.usage`) plus `track_usage = true`. So `usage` is what every allowed destructive call did on main since #59, and `baseline` is what it does now; the `destructive` cell (`create_issue`) is the one that differs, and `read` is a control. File store at `durability = "normal"`, one client, 2-hop token, 2 s warm-up and 10 s measured per cell, two passes of 5 interleaved runs (`--configs baseline,usage`, then `usage,baseline`). Release build with `lto = false` and `codegen-units = 16`, as in the two sections above, so the absolute figures are not comparable with the #53 tables. Same shared 4-vCPU container, load average 1.0 to 5.9. The configuration check confirms that only `usage`'s destructive call carries a `usage` member. In process, new `decide` cells: `decide_destructive_{store}/{tracked,elided}` (`Pipeline::decide` of `create_issue` on a 2-hop chain with no limits) and `charge_{store}/usage` (the usage charge alone).

| | `baseline` (elided) | `usage` (tracked) | difference |
|---|---|---|---|
| `destructive` client p50, pass 1 / pass 2 (median of 5 runs) | 1,229 / 1,282 us | 1,327 / 1,426 us | +98 / +144 us |
| `destructive` req/s, pass 1 / pass 2 | 747 / 689 | 666 / 659 | -11 / -4 % |
| `destructive` whole decision, mean | 340 / 361 us | 448 / 447 us | +108 / +86 us |
| decide (unstaged): the charge, mean | 20 / 21 us | 77 / 77 us | +56 us |
| `policy` (includes the counter read), mean | 120 / 125 us | 135 / 137 us | +12 to +15 us |
| `audit_append`, mean (p50) | 155 / 165 us (107 / 119) | 189 / 185 us (154 / 154) | +20 to +34 us (+35 to +47) |
| `read` client p50 (control) | 1,208 / 1,191 us | 1,254 / 1,213 us | within noise |

In process (criterion point estimates; three runs of each cell, in [the results](bench/2026-10-24-vm-usage-write.md)):

| Cell | memory | file, `normal` | file, `full` |
|---|---|---|---|
| `decide_destructive`, elided | 142 to 173 us | 140 to 154 us | 476 to 565 us |
| `decide_destructive`, tracked | 153 to 170 us | 290 to 324 us | 1.22 to 1.45 ms |
| `charge`, usage alone (1 counter) | 28 us | 34 us | 385 us |

Readings:

- **The usage write costs about 0.1 ms per allowed destructive call from one client on the file store**: +86 to +108 us on the server's decision mean, +98 to +144 us at the client's p50, and 4 to 11 percent of single-client throughput. Calls that are not destructive are unaffected (the `read` control).
- **Where it goes.** The charge transaction is about 56 us (unstaged mean, 20 to 77 us). The counter read adds 12 to 15 us to `policy`, and the decision append grows by 20 to 34 us mean (35 to 47 us at p50). That growth is the same as the one a `calls` limit causes (the second anomaly of [the labels and limits section](#output-labelling-and-run-limits-on-the-hot-path-2026-10-24)): the charge commits on the lease connection just before the append commits on the audit connection, on the same file.
- **Against the #53 numbers.** #53 put a `calls` limit (two counters in one transaction) at +122 to +192 us over its baseline at p50. The usage write is one counter in the same kind of transaction and costs a little less, as expected. #53's baseline was measured before #59 and so had no usage write, which is why its `destructive` cell was within noise of `read`; on main since #59, the `destructive` cell had about this 0.1 ms on top, and with this change it no longer does unless something reads usage.
- **At `durability = "full"` it costs much more**: every commit syncs, so the usage charge is about 385 us in process and the tracked decision 1.2 to 1.45 ms against about 0.5 ms elided. This is the case where elision matters most. End to end at `full` was not measured.
- In process on the memory store the two cells overlap (142 to 173 against 153 to 170 us); the first elided run, measured right after the tracked one, was the slowest. On the file store the tracked cell's intervals are wide (260 to 374 us), as the `decide_limited` cells were in [the `sum` follow-up](#sum-charge-follow-up-2026-10-24).

### Single-client outliers (2026-10-24)

Branch `perf/single-client-outliers`, main `d27c891`. One client against the file store sees about 1 call in 100 take 3 ms or more, with the median near 1.3 ms; the section above showed that SQLite's busy handler is not involved. Results, raw output, the probe sources and the rerun commands: [`bench/2026-10-24-vm-single-client-outliers.md`](bench/2026-10-24-vm-single-client-outliers.md).

**Method.** Four measurements on the shared 4-vCPU container (load average 0.5 to 5.5): raw host probes in C (thread wake-up after a 500 us sleep, `fdatasync` of a small file, appends next to a sync of the same file); an in-process probe that makes one call's store operations in a loop and times each append (`crates/attenuo-audit/tests/single_client_outliers.rs`), with the background checkpointer's rounds and locked passes now recorded by the `testing` feature so each slow append can be matched to them; `attenuo-bench hot-path --configs baseline`, which now counts requests over 3, 5 and 10 ms at the client and per server stage, and takes `--audit-set key=value` so `checkpoint_every=0` runs on the same binary; and `strace` of the probe. Variants interleaved, two passes, the second reversed.

**What the slow calls are.**

| Source | How often, one client | Before | After | In our control |
|---|---|---|---|---|
| Signed audit checkpoint: the commit syncs at `FULL` (SR-50), writing every WAL page since the WAL was last synced, up to 256 commits | 1 per 1,000 entries (1 call in 500) | 13 to 16 ms p50, up to 25 ms | 3.4 to 3.9 ms p50, up to 9 ms | yes; changed |
| The checkpointer's locked pass syncs the database file, which holds every page the unlocked passes copied but did not sync | 1 per WAL restart (about 1,800 commits in the probe) | appends held 10 to 23 ms (median) | 3.0 to 3.4 ms | yes; changed |
| Scheduling on the shared host (thread wake-ups, blocking pool, the client) | 0.7 to 0.9 % of calls over 3 ms at load 1.5 to 2; 2 to 3.6 % at load 3 to 4.7 | 3 to 10 ms | unchanged | no |
| Appends that extend the WAL while the checkpointer syncs it | only while the WAL grows after an idle `TRUNCATE` | up to 16 ms (raw probe) | unchanged | not changed |
| Disk `fsync` tail | quiet: p99.9 0.4 to 1.1 ms; during another build: p50 4 ms, p99 8 ms | magnifies the first two | | no |

The in-memory store had 0 to 1 append over 3 ms in 12,800, and the file store with the checkpointer parked had none, so allocation, hashing and the commit path itself are not the cause. The background `PASSIVE` pass's own sync takes 17 to 31 ms (strace), but appends do not wait for it while they overwrite the WAL, which is the server's steady state (its WAL stayed at about 78 MB through a 10 s cell). The raw probe shows the exception: a write that extends a file being synced stalls (8 and 4 writes in 9,000 over 3 ms, up to 16 ms), and an overwrite does not (none).

**The two changes.** Neither changes what a commit syncs or at which `synchronous` level; each adds one sync on the checkpointer's thread, off the request path.

1. Before its locked pass, the checkpointer `fsync`s the database file from a descriptor of its own. The locked `PASSIVE` then has only the pages it copies itself to sync while appends wait.
2. When a commit brings the head within `CHECKPOINT_PRESYNC_LEAD` (32) entries of the next signed checkpoint, the writer asks the checkpointer (a new message on its existing channel) to `fsync` the WAL file. The commit that writes the checkpoint still runs at `FULL`, with less left to write. A lead of 8 left that sync running when the checkpoint committed; 64 and 128 left more pages behind (signing append p50 5.4 to 12.3 ms against 3.4 to 4.4 ms at 32). Stores at `durability = "full"`, in memory or without the background checkpointer are unchanged.

**End to end, before and after** (one client, three runs of 10 s per invocation, pooled; load 1.5 to 1.8 for the first pass, 3.0 to 4.7 for the second):

| Variant | calls over 3 ms | over 5 ms | over 10 ms | decision appends over 5 / 10 ms, per cell |
|---|---|---|---|---|
| main, pass 1 | 0.72 to 0.92 % | 0.39 to 0.49 % | 0.27 to 0.29 % | 52 to 54 / 43 to 45 |
| this branch, pass 1 | 0.78 to 1.03 % | 0.35 to 0.38 % | 0.08 to 0.09 % | 13 to 14 / 4 to 5 |
| main with `checkpoint_every=0`, pass 1 | 0.65 to 0.91 % | 0.26 to 0.34 % | 0.14 to 0.15 % | 12 to 15 / 10 to 15 |
| main, pass 2 | 1.93 to 2.15 % | 0.57 to 0.70 % | 0.26 to 0.29 % | 45 to 51 / 33 to 42 |
| this branch, pass 2 | 2.17 to 2.72 % | 0.85 to 0.88 % | 0.14 % | 18 to 25 / 9 to 11 |

Readings:

- **The outliers over 10 ms were storage, and they are about a third of what they were**: client calls over 10 ms fall from 0.27 to 0.29 % to 0.08 to 0.09 % at load below 2, lower than main without signed checkpoints, because the locked pass shrank too. The median and the p99 are unchanged within noise.
- **The 3 to 8 ms outliers are mostly the host, and stay.** The share over 3 ms is the same for all three variants at load below 2 and doubles to triples at load 3 to 4.7; the growth is in `blocking_pool`, `response` and the time outside the handler, stages that wait for a thread to be scheduled. The two storage events now land at 3 to 5 ms, so they still count at 3 ms. On this shared VM that floor is outside the server's control; a quiet machine was not available to measure it.
- **What remains of the storage tail**: the signed checkpoint still syncs on the request path (3 to 5 ms here, once per 1,000 entries), as SR-50 requires; moving that sync off the path would change the commit's level, which this branch does not do. The locked pass still holds appends about 3 ms for its own two syncs. The first commit after an idle `TRUNCATE` grows the WAL from zero, which the raw probe shows can stall next to a sync (and its first sync after freeing blocks cost 11 to 15 ms on this `discard`-mounted ext4); that path was not measured in the server.

### Limit kinds: `calls_per` and `distinct` (2026-10-24)

Branch `perf/limit-kinds-latency`, main `360ba25`. The run-limits sections measured `calls` and `sum`; this one measures the two per-value kinds, `calls_per` (one counter per value, keyed by a keyed hash of the value) and `distinct` (one row per value seen plus a count row; a repeated value writes nothing), and `distinct` on a URL host (`derive: host`, which parses the URL on every call). Results, raw tables and rerun commands: [`bench/2026-10-24-vm-limit-kinds.md`](bench/2026-10-24-vm-limit-kinds.md) and `.json`.

**Method.** `attenuo-bench hot-path` has six new configurations and a `--cells` option. Each puts one limit, with a `max` no run reaches, on `create_issue` in both hops of a 2-hop token, so every call charges 2 counters and none is refused: `calls_per_new` and `calls_per_same` (`calls_per` on argument `to`), `distinct_new` and `distinct_same` (`distinct` on `to`), `host_new` and `host_same` (`distinct` on the host of `url`). In a `_new` cell the value is new on every call (the harness puts a process-wide sequence number into the body); in a `_same` cell it is the same on every call, except that `host_same` sends a new path on the same host, so it parses a new URL every time. `create_issue` now carries `to` and `url` in every configuration, so `baseline` (no limit) and `limits_calls` (`calls` in both hops) differ from the limited cells only by the limit. File store at `durability = "normal"`, one client, only the `destructive` call, 2 s warm-up and 10 s measured per cell, two passes of 5 interleaved runs, the second in reverse order. Release build with `lto = false` and `codegen-units = 16`, as in the three sections above. Same shared 4-vCPU container with other agents building: load average 1.2 to 5.7 during the runs (14:34 to 14:51 UTC), 0.6 to 3.2 during the criterion runs. The configuration check after the runs shows the first charge's `used_after` growing with every call in the `_new` cells (33,000 to 37,000 values per server) and staying at 1 in `distinct_same` and `host_same`. In process, new `decide` cells: `charge_{store}/{calls_per,distinct,host}_{new,same}` (the charge transaction alone), `charges_for/{calls_per,distinct,host}` (building the call's charges, including the URL parse) and `derive_host/{shape}` (`Derive::Host::apply` on one URL).

Pass 1 / pass 2; client figures are medians of 5 runs, the decision and the charge are means over all measured calls. "Charge" is the decision time outside lease check, policy and audit append, so `baseline`'s 20 to 22 us is record building and the rest is the charge transaction.

| config | client p50 us | p90 us | p99 us | req/s | decide mean us | charge mean us | over 3 / 5 / 10 ms (of about 30,000) |
|---|---|---|---|---|---|---|---|
| `baseline` | 1,365 / 1,336 | 1,714 / 1,764 | 3,478 / 3,555 | 702 / 713 | 343 / 315 | 22 / 20 | 614 / 220 / 32; 591 / 196 / 21 |
| `limits_calls` | 1,464 / 1,475 | 1,841 / 1,908 | 3,566 / 3,832 | 631 / 621 | 449 / 457 | 91 / 91 | 713 / 249 / 31; 687 / 243 / 30 |
| `calls_per_new` | 1,465 / 1,482 | 1,861 / 1,962 | 4,330 / 4,473 | 610 / 614 | 505 / 536 | 122 / 121 | 867 / 376 / 61; 734 / 322 / 54 |
| `calls_per_same` | 1,467 / 1,505 | 1,878 / 1,923 | 3,469 / 4,682 | 639 / 620 | 463 / 472 | 97 / 96 | 795 / 315 / 38; 1,170 / 395 / 48 |
| `distinct_new` | 1,574 / 1,562 | 1,973 / 2,041 | 3,699 / 5,063 | 595 / 587 | 555 / 568 | 144 / 148 | 879 / 384 / 55; 915 / 355 / 61 |
| `distinct_same` | 1,306 / 1,342 | 1,732 / 1,777 | 3,228 / 4,465 | 697 / 698 | 375 / 391 | 46 / 49 | 757 / 287 / 41; 874 / 275 / 25 |
| `host_new` | 1,553 / 1,574 | 1,968 / 2,183 | 4,538 / 5,874 | 600 / 571 | 583 / 582 | 148 / 153 | 708 / 265 / 59; 1,493 / 524 / 67 |
| `host_same` | 1,403 / 1,406 | 1,789 / 1,836 | 4,014 / 4,674 | 672 / 662 | 401 / 401 | 50 / 51 | 593 / 175 / 24; 904 / 286 / 25 |

Against `baseline` of the same pass:

| config | client p50 | decide mean | charge transaction | `policy` mean | `audit_append` mean |
|---|---|---|---|---|---|
| `limits_calls` | +99 / +139 us | +106 / +142 us | +69 / +71 us | +16 / +22 us | +21 / +45 us |
| `calls_per_new` | +100 / +146 us | +162 / +221 us | +100 / +101 us | +28 / +36 us | +32 / +78 us |
| `calls_per_same` | +102 / +169 us | +120 / +157 us | +75 / +76 us | +22 / +26 us | +22 / +49 us |
| `distinct_new` | +209 / +226 us | +212 / +253 us | +122 / +128 us | +49 / +52 us | +36 / +66 us |
| `distinct_same` | -59 / +6 us | +32 / +76 us | +24 / +29 us | +18 / +31 us | -9 / +12 us |
| `host_new` | +188 / +238 us | +240 / +267 us | +126 / +133 us | +56 / +68 us | +55 / +55 us |
| `host_same` | +38 / +70 us | +58 / +86 us | +28 / +31 us | +33 / +39 us | -6 / +11 us |

In process (criterion, two runs; `file_full` once):

| cell | memory | file, `normal` | file, `full` |
|---|---|---|---|
| `charge`, `calls` (2 counters, for reference) | 75 to 96 us | 38 to 42 us | 456 us |
| `charge`, `calls_per`, repeated value | 121 to 127 us | 47 to 50 us | 458 us |
| `charge`, `calls_per`, new value | 205 to 253 us | 73 to 74 us | 698 us |
| `charge`, `distinct`, repeated value | 12 us | 19 us | 16 us |
| `charge`, `distinct`, new value | 415 us | 106 to 107 us | 600 us |
| `charge`, host `distinct`, repeated host | 11 us | 16 to 28 us | 16 us |
| `charge`, host `distinct`, new host | 422 to 425 us | 94 to 95 us | 357 us |
| `charges_for`, raw value / host (2 hops) | 0.60 to 0.82 / 1.34 to 1.38 us | | |
| `Derive::Host::apply`, one URL | 0.28 to 0.30 us (short), 0.70 to 0.71 us (port, user info, upper case), 0.74 to 0.78 us (IDN), 0.97 to 1.06 us (212 bytes) | | |

Readings:

- **`calls_per` costs what `calls` costs.** With a repeated value the client p50 is +102 / +169 us against +99 / +139 us for `calls`, and the charge transaction 75 against 70 us. In process the keyed hash and the longer key add about 8 us (47 to 50 against 38 to 42 us). A new value adds about 25 to 30 us to the charge (100 against 75 us end to end, 73 against 47 to 50 in process): the counter row is inserted, at a random place in the index because the key is a hash, instead of updated in place.
- **`distinct` with a new value costs about twice a `calls` limit**: +209 / +226 us at the client p50, +122 / +128 us of charge transaction, 15 to 18 percent of single-client throughput. That is what the design says it writes: per hop a value row and the count row, so four counter writes and four charge rows against two of each for `calls`.
- **`distinct` with a repeated value writes nothing, as designed, and is within noise at the client** (-59 / +6 us p50, 697 / 698 against 702 / 713 req/s). It still runs the charge transaction: the write gate, `BEGIN IMMEDIATE`, the decision check, the counter reads and an empty commit, about 25 us end to end and 19 us in process (16 us at `full`, where a write would cost 360 to 700 us). The decision append does not grow (-9 / +12 us), unlike every cell that writes (+21 to +78 us), which is the WAL hand-off the earlier sections saw; so the empty commit writes no WAL frame. Skipping the transaction when every value is already seen would save those 20 to 25 us, but it would need the counters read outside the write lock, and a concurrent refund can make a seen value new again between that read and the call; not done. Superseded since SR-62, which logs a zero-amount charge row for every seen value: a seen value now costs what a repeated `calls_per` value does (see [Per-value limits on current main](#per-value-limits-on-current-main-2026-10-25)).
- **The URL parse is under 1 percent of a host limit.** `Derive::Host::apply` takes 0.3 to 1.1 us per URL, and a call parses once per limited hop: `charges_for` is 1.34 to 1.38 us for the host limit against 0.60 to 0.63 us for a raw-value `distinct`, so the parse adds about 0.75 us per call on a 2-hop token. A new host costs 126 / 133 us of charge transaction, the same as a new raw value (122 / 128 us); the rest is the store write. `host_same` (a new URL on a seen host every call) costs what `distinct_same` costs in the charge (28 / 31 against 24 / 29 us); its client p50 is 60 to 100 us above `distinct_same`, inside the noise of about 100 us these runs show.
- **The counter read in `policy` grows with the values**: +16 to +22 us for `calls`, +18 to +39 us for the repeated-value cells, +28 to +68 us for the new-value cells. A new value is a lookup of a key that is not in the index; not profiled. It did not grow over the runs as the tables filled (from about 7,000 to 35,000 values per server): the per-run decision means show no trend.
- **The tail.** Calls over 10 ms were 54 to 67 per pass in the three new-value cells against 21 to 32 in `baseline` and `limits_calls` and 24 to 48 in the repeated-value cells (0.18 to 0.24 % against 0.06 to 0.1 %). That suggests more slow commits when each call inserts rows, but with about 30,000 calls per cell and the host's load moving from 1.2 to 5.7 it is not established. `host_new`'s 1,493 calls over 3 ms in pass 2, against 708 in pass 1, fell in a load spike.

Anomaly, measured and not fixed: on the in-memory store a new-value charge costs 205 to 425 us, two to four times the file store's 73 to 107 us, and a repeated `calls_per` value 121 to 127 us against 47 to 50. The memory store's `calls` charge was already slower than the file store's (the second anomaly of [the labels and limits section](#output-labelling-and-run-limits-on-the-hot-path-2026-10-24)); inserting new keys makes the gap larger. The server's default is the file store. Not investigated.

Not measured: these kinds under concurrent clients, at `durability = "full"` end to end (in process only), on the memory store end to end, with list-valued arguments (one charge per element), with more than one limit kind per capability, and with values that are refused (`max` reached, or `limit_arg_invalid`). List arguments and two kinds on one capability are measured since: see [Per-value limits on current main](#per-value-limits-on-current-main-2026-10-25).

### Per-value limits on current main (2026-10-25)

Branch `perf/per-value-limits-latency`, main `3568ba6`. The section above measured `calls_per` and `distinct` before security pass 5. This one measures them again on current main (with the SR-55 run lock, SR-62's zero-amount charge rows for seen `distinct` values and its second index on the charge log), adds both kinds on one capability, `calls_per` on a URL host and `distinct` on a list argument of 1, 16 and 256 values, and splits the large cells one level down. Results, raw tables and rerun commands: [`bench/2026-10-25-vm-per-value-limits.md`](bench/2026-10-25-vm-per-value-limits.md) and `.json`; in process: [`bench/2026-10-25-vm-criterion-per-value.txt`](bench/2026-10-25-vm-criterion-per-value.txt).

**Method.** As in the section above: `attenuo-bench hot-path`, file store at `normal`, one client, 2-hop token, the `destructive` cell, 2 s warm-up and 10 s measured, two passes of 5 interleaved runs, the second reversed, release with `lto = false` and `codegen-units = 16`. New configurations: `calls_per_distinct_new` and `_same` (`calls_per` and `distinct` on `to`), `calls_per_host` (`calls_per` on `url` with `derive: host`, a new URL on one host every call) and `distinct_list`, with a new option `--list-values N` that adds a list argument of N values, all new on every call, to `create_issue` in every configuration, so `baseline` with the same N is the control. The harness now also reports the run lock's wait (`attenuo_run_lock_wait_seconds`). New `decide` cells: `charges_for/distinct_list_N`, `budget_read_{store}/distinct_list_N` and `charge_{store}/distinct_list_N_new`. Shared 4-vCPU container, load average 1.2 to 6.8 (another worker started a build near the end of pass 2), so client differences under about 150 us are not resolved.

| config | client p50, delta over `baseline` | client p99, delta | charge transaction, delta (mean) |
|---|---|---|---|
| `baseline` (absolute) | 1,196 / 1,263 us | 3,027 / 3,619 us | 20 / 21 us |
| `limits_calls` | +268 / +211 us | +567 / +625 us | +89 / +91 us |
| `calls_per`, new / repeated value | +334 / +259; +320 / +205 us | +412 / +2,832; +1,602 / +1,329 us | +124 / +129; +111 / +102 us |
| `distinct`, new / seen value | +456 / +413; +355 / +177 us | +1,319 / +2,464; +1,331 / +92 us | +195 / +191; +109 / +104 us |
| `calls_per` and `distinct`, new / repeated value | +612 / +565; +495 / +378 us | +3,498 / +4,237; +2,400 / +416 us | +279 / +281; +162 / +161 us |
| `calls_per` on a URL host | +339 / +295 us | +750 / +846 us | +102 / +110 us |
| `distinct` on a list of 1 / 16 / 256 values | +448 / +505; +2,415 / +2,317 us; +35.7 / +34.0 ms | +1.4 / +1.3; +14.2 / +17.4; +658 / +685 ms | +191 / +194 us; +1.66 / +1.62 ms; +28.5 / +28.4 ms |

Readings:

- **A `calls` limit costs about +210 to +270 us at p50 on current main, not +120 us.** The charge transaction grew from about 70 to 90 us end to end, and from 38.5 to 41.5 us to 54 to 55 us in process; SR-62's second index on the charge log is the likely cause (one more index entry per charge row), not separated. The rest of the delta sits outside the decision, as in #53, and `baseline` itself got 100 to 170 us faster since 2026-10-24 while `limits_calls`' absolute p50 did not move.
- **`calls_per` costs what `calls` costs**, on a raw value or a URL host alike (the parse is about 0.8 us per call); a new value adds 10 to 30 us of charge. **`distinct` with a new value costs about twice `calls`.** Both kinds on one capability cost less than the two apart, as they share one transaction.
- **A seen `distinct` value is no longer free.** Since SR-62 it logs a zero-amount charge row and rewrites its value row, so it costs what a repeated `calls_per` value does (+104 to +109 us of charge, the decision append grows like every writing cell), where on 2026-10-24 it was within noise.
- **The run lock waits 0.2 to 0.3 us from one client.**
- **A list argument costs about 50 to 56 us per new value per hop, almost all in the store.** At 256 values (the most a call may count), +34 to +36 ms at p50 over a `baseline` with the same body: the charge transaction is 28.4 to 28.6 ms (25.3 to 25.8 ms in process, about 80 percent), the counter read in `policy` +4.5 to +4.8 ms (0.79 to 0.85 ms in process on a fresh table; the end-to-end tables held up to 240,000 rows per hop), and the RFC 8785 encoding of the values 0.17 ms (under 1 percent). Each new value is an insert into the counter table and into the charge log with its two indexes, on hashed keys, so about 7.5 WAL pages per value: 5.2 MiB of WAL per 256-value call against 80 KiB for `baseline`. The write gate is held for the whole charge, so one such call stalls every other decision's charge and append for 25 to 29 ms. The p99 of 0.66 to 0.69 s comes from the decision append (mean 33 ms, p50 0.89 ms, 6 percent over 10 ms), most likely the WAL checkpointer's locked pass and writer backstop, which that much WAL reaches about every dozen calls; not traced call by call. At 16 values: +2.3 to +2.4 ms at p50, 1.6 to 1.7 ms of it the charge.

Not changed here: nothing is a one-line win. Cheaper list charges would need fewer rows per value (the zero-amount log rows and the counter index of the charge log exist for exact refunds, SR-62), batched inserts, or a lower `MAX_COUNTED_VALUES` (SR-57 set 256 so that one call could not stall every decision; at 256 one call holds the write gate for about 28 ms). Not measured: these cells under concurrent clients (a 256-value call's effect on other runs' latency), at `durability = "full"`, on the memory store end to end (in process its list charge is 20.5 to 22.4 ms at 256 values), and lists of repeated values.

### The SR-55 run lock under concurrent clients (2026-10-24)

Branch `perf/run-lock-cost`, main `e04b516`. Security pass 5 (SR-55) added `Pipeline::run_guard`: one of 64 striped `std::sync::Mutex`es, chosen by the run's `chain_id`, held from the budget read to the end of the charge for every call that matches a limited hop or keeps run usage. This section measures what it costs when many clients share one run, the case it serialises, and when each has its own. Results, full tables and the rerun commands: [`bench/2026-10-24-vm-run-lock.md`](bench/2026-10-24-vm-run-lock.md) and `.json`.

**Method.** `attenuo-bench hot-path` has a new option, `--tokens N`: N root tokens, each its own run, with client i on run i mod N. Two server builds: main (after) and `84b9578`, the parent of the SR-55 commit (before), built in a second worktree; the same bench binary drives both. 8 and 32 clients, on one run (`--tokens 1`) and on a run each (`--tokens` equal to `--clients`); configurations `baseline` (no lock in either build), `limits_calls` (lock, `calls` charge) and `usage` (lock, usage write); file store at `durability = "normal"`, 2-hop token, the `destructive` cell, 2 s warm-up and 10 s measured. Each invocation is one run of the three configurations on one build, the builds alternating; 5 runs per pass, the second pass reversed. Two series: before against after, then before, after and a narrowed lock (below). Release build with `lto = false` and `codegen-units = 16`, as the sections above. Same shared 4-vCPU container, with another agent's fuzz campaign at full CPU throughout: load average 3.4 to 12.6. The lock is taken inside the `policy` stage's timer, so that stage's mean includes the wait for it.

**Noise.** `baseline` takes no lock in either build, and its req/s still differed between the builds by -17 to +13 percent within a pass. So throughput differences under about 15 percent between two builds are not resolved here; the `policy` stage resolves the lock wait, because it moves by milliseconds.

| clients / runs | config | req/s, after against before (4 passes) | `policy` mean, before / after |
|---|---|---|---|
| 8 / 1 | `limits_calls` | -10, -11, -10, -14 % | 0.9 / 2.8 to 3.9 ms |
| 8 / 1 | `usage` | -4, -7, -3, -5 % | 0.9 / 2.6 to 3.3 ms |
| 32 / 1 | `limits_calls` | -22, -15, -2, -4 % | 3.6 to 4.3 / 21.9 to 25.6 ms |
| 32 / 1 | `usage` | -15, -8, -4, +4 % | 3.6 to 4.2 / 20.6 to 22.4 ms |
| 32 / 1 | `baseline` (no lock) | -3, -7, +4, 0 % | 2.3 to 2.4 / 2.3 to 2.4 ms |
| 8 / 8 | `limits_calls` | -11, -9, -17, -11 % | 0.93 to 0.98 / 1.10 to 1.18 ms |
| 8 / 8 | `baseline` (no lock) | +11, 0, -11, -8 % | 0.57 to 0.59 / 0.60 to 0.67 ms |
| 32 / 32 | `limits_calls` | -3, -3, -5, -5 % | 4.0 to 4.5 / 4.3 to 4.9 ms |
| 32 / 32 | `usage` | -5, +5, -4, -4 % | 3.9 to 4.5 / 3.9 to 4.7 ms |

Readings:

- **On one run the lock mostly moves the queue.** Before SR-55, 32 clients of one run queued for the file's write gate: 4.9 ms in the charge, 7.2 to 7.4 ms in the decision append and 7.0 to 7.3 ms in the result append (series 2, `limits_calls`). With the lock they wait 18 to 22 ms for it, and the charge (0.4 ms) and both appends (1.2 to 1.9 ms) then find the gate nearly free. The handler's total grew by 5 to 9 percent, throughput fell by a median of 9.5 percent for `limits_calls` and 6 percent for `usage` (22 percent in the worst pass, a 4 percent gain in the best), and the client p90 grew by 24 to 37 percent in series 2 while p50 stayed within 1 ms.
- **At 8 clients on one run** each call waits 2 to 3 ms for the lock; `limits_calls` lost 10 to 14 percent of throughput in all four passes and `usage` 3 to 7 percent, inside the noise `baseline` shows.
- **One run's ceiling is one decision per lock hold**, about 0.85 to 1.0 ms here (the budget read, Cedar, and the charge, which waits for the gate behind the audit writer's batch commit). This 4-vCPU host saturates near that rate anyway; on a larger host one run's limited or usage-tracked calls would stay near it while other runs scale.
- **Runs do not wait on each other.** With a run per client the `policy` stage grows by 0.02 to 0.7 ms, against 18 to 22 ms on one run. The throughput differences there match `baseline`'s noise; at 8 runs `limits_calls` lost its time in the charge and the appends, not in `policy`. The before build also lacks SR-62's index on the charge log; that was not separated.
- **Stripe collisions** were computed, not measured: with 64 stripes a run shares its stripe with another with probability 1 - (63/64)^(N-1), 10 percent at 8 runs and 39 percent at 32, and a shared stripe costs only when two runs' budgeted decisions overlap. The 32-run cells show no lock wait.

**Decision: no server change.** The cost at 32 clients on one run is about the 10 percent line (median 6 to 9.5 percent, worst pass 22), and nothing measurable on separate runs. Candidate (a), taking the lock only after the label read, argument taint and approval take, was built and measured in the second series: the lock wait fell by 1 to 2 ms, but the time reappeared in the approval take (a write transaction), the charge and the appends, and req/s against main moved -1 to +3 percent at 32 clients on one run (8 clients: +22 and -3 percent for `limits_calls`, +13 and -6 for `usage`). Not a clear win, so not kept. A `parking_lot` mutex (b) changes the lock's own cost, but the time is in the hold; per-chain locks (c) remove collisions, which do not show. What would raise one run's ceiling is a shorter hold, which means a cheaper charge transaction or an approval take that skips its write transaction when no approval is granted; neither is in scope here.

Not measured for the run lock: a build of main with the lock removed (the before build differs by the other pass-5 fixes too, SR-62's charge-log index among them), stripe collisions directly, the lock with a `sum` limit or at `durability = "full"` (where the hold includes an `fsync`), runs with approvals granted, the memory store, and a quiet or larger host.

### Token verification on a cache miss (2026-10-24)

Branch `perf/ou-sig-kid`, main `e91a139`. Board follow-up (1) suggested two ways to make a verified-token cache miss cheaper: a `kid` on `ou_sig`, so the verifier stops trying every trusted key, and not cloning the chain out of the claims. Measured first, and neither applies. `ou_kid` has been on every token since `ou_sig` version 2 (SR-14), and the verifier already checks `ou_sig` under that one key and the outer signature under the header `kid`'s. A token without `ou_kid`, or with one that names no trusted key, is refused rather than tried against every key (now also tested with the claim removed). The clone costs 0.46 us at 1 hop and 1.44 us at 3 hops, 0.4 and 1.1 percent of a miss, so it stays: removing it would change `Claims` or `VerifiedToken` for every caller. Nearly all of a miss is the two Ed25519 verifications, about 53 us each with `ring` on this VM, 107 us of `verify`'s 116 us at 1 hop and 126 us at 3; three trusted keys cost what one does. End to end, a new `attenuo-bench hot-path --rotate-tokens` cycles every client through more tokens than the cache holds, so every call misses: `token_verify_miss` is 170 us p50 (196 mean) against 8.8 us p50 for `token_verify_hit` (file store, one client, 2 hops, load average 4 to 5). Each token there is also a new chain, which defeats the policy request cache too (`policy` 410 against 104 us p50), so the 840 us client p50 gap between the two runs is not all verification. Results: [`bench/2026-10-24-vm-verify-miss.md`](bench/2026-10-24-vm-verify-miss.md), [`criterion-verify`](bench/2026-10-24-vm-criterion-verify.txt). What would make a miss cheaper is fewer or faster signature checks. Skipping `ou_sig` when `ou_kid` equals the header `kid` would save about 53 us, since a holder of that key could forge both anyway, but it gives up the check against an exchange bug that edits the user block, so that is a security decision and was not made here. A faster Ed25519 implementation was not tried. On a hit, the cache clones the stored `VerifiedToken`, which holds the chain twice (`chain` and `claims.chain`), about 1 us per copy at 2 hops against a 9 us hit; not changed here.

### Listen-stream list filter (2026-10-24)

Branch `feat/proxy-followups-2`, main `5d86c19`. Since #90 every event of a `GET` listen stream that carries JSON is parsed, checked for a list shape and serialized again (`sse::rewrite_stream` with the list filter), where before it was only framed and relayed (`sse::frame_stream`). An `#[ignore]` test, `crates/attenuo-proxy/tests/listen_stream_cost.rs`, times the SSE stage alone and a whole `GET` through the proxy router against an upstream that writes N events, with "before" measured on the same build with the filter argument set to `None`. A 173-byte progress notification costs 1.54 to 1.59 us more in the stage (1.70 against 0.16 us), against a threshold of 20 us set for a change; end to end the difference does not show, because the relay floor of one HTTP chunk per event is about 40 us here and the runs with the filter were, if anything, faster (bimodal, 10 to 40 us, not explained). An 85 KB `tools/list` answer of 200 tools costs 0.6 to 0.7 ms more in the stage and 1.1 to 1.3 ms end to end, which is the filter doing on the listen stream what it does on a `POST`; a large event that is not a list costs about the same, for the parse and re-serialization alone. **Decision: no change.** Skipping the parse for events without a list key would save at most the 1.5 us on small events, would have to treat `\u` escapes as possible keys, and would let skipped events keep duplicate members that re-serialization removes today. Results and method: [`bench/2026-10-24-vm-listen-stream-filter.md`](bench/2026-10-24-vm-listen-stream-filter.md).

### Stream-end shape check on the unfiltered SSE path (2026-10-25)

Branch `perf/sse-disown-cost`, main `2b495e2`. Since #117 the SSE path without a list filter (a streamed `tools/call` answer, the guarded passthrough) parses every framed event to test whether it has the shape of the proxy's stream-end event (`guard::disown_events`), where before it relayed the framed bytes. A new `#[ignore]` test, `disown` in `crates/attenuo-proxy/tests/listen_stream_cost.rs`, times `SseFramer` alone against `SseFramer` plus the check, one event per chunk, 5 runs of 15 passes each (medians, ranges in the note). The parse added 0.95 us to a 173-byte progress notification (six times the 0.16 us relay floor), 61 us to an 8 KB tool result and 653 us to an 85 KB one, about 7.7 us per KB, past both lines set for a change (0.2 ms per 85 KB, 20 percent of the floor for small events). **Decision: a byte scan before the parse.** `guard::may_hold_stream_end_code` passes an event only if some `-` is followed by a number whose significant digits start with `32001` or `320009`; every spelling of a value that `has_stream_end_shape` matches does (`-32001.0`, `-3.2001E+4`, `-0.32001e5`, a long decimal that rounds to it), which a plain search for `-32001` would not, and the reasoning and a table of spellings are in the code and its tests. A chunk that fails the scan is passed on without a copy (`guard::disown_chunk`). After: 0.06 us added per small event, 1.9 us per 8 KB, 27 us per 85 KB (about 0.3 us per KB, the scan alone). The small-event figure is still 39 percent of the stage floor but 60 ns, about 0.15 percent of the 40 us end-to-end relay floor measured for the listen stream. Output is unchanged: events that fail the scan went out byte for byte before too. Results and method: [`bench/2026-10-25-vm-sse-disown.md`](bench/2026-10-25-vm-sse-disown.md).

### How to run

```
scripts/bench-e2e.sh                       # full matrix, about 9 minutes, writes docs/design/bench/
DURATION=10 scripts/bench-e2e.sh --concurrency 8 --depths 3 --audit memory
cargo run --release -p attenuo-bench -- --help
attenuo-bench exchange --audit memory,file --clients 1,8 --depths 1,3          # exchange throughput
attenuo-bench exchange --audit memory --depths 1 --open-loop 500,1500          # open loop
attenuo-bench lease-renew --cells 100:1,1000:1,5000:1 --cascade-runs 5         # lease renewal and revoke cascade
attenuo-bench --open-loop 500,2000 --depths 1 --outcomes allow --audit memory  # proxied call, open loop
attenuo-bench hot-path --runs 5 --configs baseline,labels,limits,limits_calls,both --approval-loops 2000  # labels and limits
DURATION=10 scripts/bench-e2e.sh hot-path --runs 5 --approval-loops 2000        # the same, built and written to docs/design/bench/
cargo bench -p attenuo-policy --bench policy_stage -- --warm-up-time 1 --measurement-time 3
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 'budget_read_|charge_'  # run-limit counters
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 'decide_limited_'  # a limited call's whole decision
cargo test --release -p attenuo-audit --test write_contention -- --ignored --nocapture  # lease writes against appends on one file, busy-handler count
attenuo-bench hot-path --configs limits_calls,limits --runs 1 --clients 4                # run limits under concurrent clients
attenuo-bench hot-path --runs 5 --configs baseline,usage                                 # the run-usage write (tracked against elided)
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 'decide_destructive_|charge_.*/usage'  # the same in process
cargo test --release -p attenuo-audit --test single_client_outliers -- --ignored --nocapture  # one client's slow appends by cause (PROBE_CONFIGS=...)
attenuo-bench hot-path --configs baseline --runs 3 --audit-set checkpoint_every=0          # counts over 3, 5 and 10 ms per stage; [audit] keys per run
attenuo-bench hot-path --runs 5 --cells destructive --configs baseline,limits_calls,calls_per_new,calls_per_same,distinct_new,distinct_same,host_new,host_same  # per-value limit kinds
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 'derive_host|charges_for/|charge_.*/(calls_per|distinct|host)'  # the same in process, and the URL parse
attenuo-bench hot-path --runs 5 --cells destructive --configs baseline,limits_calls,calls_per_distinct_new,calls_per_distinct_same,calls_per_host  # two kinds on one capability, a host calls_per
attenuo-bench hot-path --runs 5 --cells destructive --list-values 256 --configs baseline,distinct_list  # distinct on a list argument (1 to 256 values)
cargo bench -p attenuo-server --bench decide -- --warm-up-time 1 --measurement-time 3 'distinct_list'  # the same in process: JCS, counter read, charge
attenuo-bench hot-path --runs 1 --cells destructive --configs baseline,limits_calls,usage --clients 32 --tokens 1   # one run under 32 clients (the SR-55 run lock); --bin-dir per build, alternating
attenuo-bench hot-path --runs 1 --cells destructive --configs baseline,limits_calls,usage --clients 32 --tokens 32  # a run per client
cargo bench -p attenuo-token --bench verify -- --warm-up-time 1 --measurement-time 5  # Verifier::verify on a miss, the chain clone, one Ed25519 check
attenuo-bench hot-path --runs 5 --configs baseline --cells read --tokens 5000 --rotate-tokens  # every call a verified-token cache miss (token_verify_miss)
cargo test --release -p attenuo-proxy --test listen_stream_cost -- --ignored --nocapture --test-threads 1  # the listen-stream filter per event, stage and end to end
cargo test --release -p attenuo-proxy --test listen_stream_cost -- --ignored --nocapture --test-threads 1 disown  # the stream-end shape check on the unfiltered SSE path
```

`attenuo-bench --print-config DIR` writes the server config and policy it expects, for pointing the harness at an already running server (`--attenuo-url`, `--upstream-url`, and `--metrics-url` for the stage table). Every answer is checked: a denial counts only as the proxy's `-32003` with the expected reason code and a decision id listed in `X-Attenuo-Decision-Id`, so an `audit_error` denial, a `too_many_sessions` refusal or a `5xx` stops the run after that cell. A one-second smoke run is part of `cargo test --workspace` (`crates/attenuo-bench/tests/smoke.rs`). There is no CI job for the full matrix: it needs a release build and minutes of load, and numbers from shared runners could not be compared.

## Not measured

- Renewal load and `tools/call` load at the same time, `POST /token/renew` with DPoP-bound tokens, and exchanges with the actor's client secret checked (see [Exchange throughput, lease renewal and open-loop arrivals](#exchange-throughput-lease-renewal-and-open-loop-arrivals-2026-10-23)).
- Policy size (the set here has three policies) and catalog size.
- The time outside the proxy's handler (hyper and axum parsing the client's request, relaying a streamed body). The handler's stages are in `attenuo_proxy_stage_seconds`; what lies between them and the client's latency is measured only as a difference.
- Confidence intervals over repeated runs, open-loop load for the deny outcomes and for more than one hop, and a quiet reference machine. (Open-loop arrivals exist now, for the allow call at one hop and for exchange.)
- Streaming (SSE) `POST` answers and `tools/list` filtering on a `POST` (the `GET` listen stream's filter is in [Listen-stream list filter](#listen-stream-list-filter-2026-10-24)).
- The SR-55 run lock with a `sum` limit, at `durability = "full"` and on the memory store; one run's ceiling on a host with more cores (see [the run lock section](#the-sr-55-run-lock-under-concurrent-clients-2026-10-24)).
- Output labelling under concurrency end to end (run limits under 1, 4 and 8 clients are in [Write-lock contention between the lease and audit connections](#write-lock-contention-between-the-lease-and-audit-connections-2026-10-24)), run limits on the memory store end to end and at `durability = "full"` end to end (`calls_per` and `distinct` from one client are in [Limit kinds](#limit-kinds-callsper-and-distinct-2026-10-24)); the charge and the run-label write have no stage of their own in `attenuo_proxy_stage_seconds` (see [Output labelling and run limits on the hot path](#output-labelling-and-run-limits-on-the-hot-path-2026-10-24)).

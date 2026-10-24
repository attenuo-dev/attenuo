# Performance: micro-benchmarks and end to end

- Status: third measurement, after the policy-stage and WAL work (`perf/policy-stage-and-wal-checkpoints`); exchange, lease renewal and open-loop cells added 2026-10-23 (`perf/exchange-lease-bench`); output labelling and run limits on the hot path added 2026-10-24 (`perf/labels-limits-cost`)
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

Not measured: the memory store end to end (only in process); more than one client, so contention on the store's connection lock between the charge, the label write and the appends under concurrency; `calls_per` limits (their HMAC of the value); results of realistic size (only the small echo answer); `durability = "full"` end to end; and a quiet reference machine.

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
- **The single-client outliers are not the busy handler.** It never ran at one thread, before or after. The 4 to 8 ms single-client outliers stay open.

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
```

`attenuo-bench --print-config DIR` writes the server config and policy it expects, for pointing the harness at an already running server (`--attenuo-url`, `--upstream-url`, and `--metrics-url` for the stage table). Every answer is checked: a denial counts only as the proxy's `-32003` with the expected reason code and a decision id listed in `X-Attenuo-Decision-Id`, so an `audit_error` denial, a `too_many_sessions` refusal or a `5xx` stops the run after that cell. A one-second smoke run is part of `cargo test --workspace` (`crates/attenuo-bench/tests/smoke.rs`). There is no CI job for the full matrix: it needs a release build and minutes of load, and numbers from shared runners could not be compared.

## Not measured

- Renewal load and `tools/call` load at the same time, `POST /token/renew` with DPoP-bound tokens, and exchanges with the actor's client secret checked (see [Exchange throughput, lease renewal and open-loop arrivals](#exchange-throughput-lease-renewal-and-open-loop-arrivals-2026-10-23)).
- Policy size (the set here has three policies) and catalog size.
- The time outside the proxy's handler (hyper and axum parsing the client's request, relaying a streamed body). The handler's stages are in `attenuo_proxy_stage_seconds`; what lies between them and the client's latency is measured only as a difference.
- Confidence intervals over repeated runs, open-loop load for the deny outcomes and for more than one hop, and a quiet reference machine. (Open-loop arrivals exist now, for the allow call at one hop and for exchange.)
- Streaming (SSE) responses and `tools/list` filtering.
- Output labelling under concurrency end to end (run limits under 1, 4 and 8 clients are in [Write-lock contention between the lease and audit connections](#write-lock-contention-between-the-lease-and-audit-connections-2026-10-24)), run limits on the memory store end to end, with `calls_per` limits, and at `durability = "full"` end to end; the charge and the run-label write have no stage of their own in `attenuo_proxy_stage_seconds` (see [Output labelling and run limits on the hot path](#output-labelling-and-run-limits-on-the-hot-path-2026-10-24)).

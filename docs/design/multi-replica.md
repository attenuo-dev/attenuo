# Multi-replica readiness: design

- Status: proposed, not accepted. Nothing in this note changes the single-replica guarantees documented today: one server process owns one SQLite file ([deploy guide](../guides/deploying.md#what-v0-is-and-is-not)), and every claim in [server.md](server.md) about replay, budgets and the audit chain holds for that deployment.
- Date: 2026-11-06. Base: `main` at 39b77ac.
- Related: [server pipeline](server.md) ("Known limits": the replay cache is in memory), [run limits](run-limits.md) open questions 8 and 9, [RFC-0001](../spec/rfc-0001-attenuo.md) section 4.1 ("Not covered") and section 9 open question 1, [binding tokens to keys](../guides/binding-tokens-to-keys.md), [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md) (leases), [ADR-0010](../decisions/0010-run-limits.md) (run limits), the task board's "Hop-0 hardening" item.

Several notes say in one line that something is per process and that a second replica would not share it. This note collects those lines into one inventory, read from the code at 39b77ac, says which of them make a replay or an over-spend possible and which only cost a retry, and proposes an order in which to move the correctness-critical ones into a shared store. It proposes no code in this change.

## 1. Problem

The server keeps two kinds of state. The lease store and the audit log are rows in one SQLite file (`[audit] sqlite_path`), and every write to them is an `IMMEDIATE` transaction that reads what it depends on inside the transaction. The rest lives in the process: caches that make a credential single use, locks that serialize one run's budgeted decisions, the proxy's session table, and the notifier's queue. A restart empties the second kind. A second process, on the same file or on a copy, never sees it.

The deploy guide is blunt about the result: "Do not start a second replica against the same file, or against a copy" ([deploying](../guides/deploying.md#what-v0-is-and-is-not)). Operators who need a restart without a replay window, or a second instance for availability, have no path today. Before anyone builds one, the maintainer needs to know what each piece of in-process state protects and what it would cost to share.

## 2. Inventory

Each row names where the state lives, what a second replica changes, and a class:

- **Correctness**: with two replicas (or after a restart), something the documented model forbids becomes possible: a single-use credential used twice, a run spending more than a limit or a policy over run usage allows, a revoked lease still answering, a policy rule enforced on one replica and not another.
- **Availability**: a client gets a refusal it can retry (404, 401 `use_dpop_nonce`, 503), a duplicate webhook, an extra audit record, or a metric that needs summing. Nothing the model forbids is allowed.
- **Safe**: already correct with several processes, because it is stateless, derived from shared configuration, or read from the shared file inside a transaction.

"Shared file" means two processes on one host opening the same SQLite file. "Two files" means each replica has its own database, for example a copy of a volume.

| Item | Where | Shared file | Two files | Class |
|---|---|---|---|---|
| Credential replay cache (ID tokens, ID-JAGs, actor tokens, `(parent jti, actor)` exchanges) | `crates/attenuo-server/src/replay.rs::ReplayCache`, a `Mutex<HashMap<String, i64>>` in `AppState::replay`; used by `idp/intake.rs` and `routes/token.rs` (`use_all_once`) | Each process has its own map, so a credential is single use per process. The same ID token mints one root token on each replica; a parent delegates to one actor once per replica. | Same. | Correctness |
| Approval ID tokens | `routes/approvals.rs::user_decide`, through the same `ReplayCache` (`s.replay.use_once`) | The token is not bound to an approval id (`verify_user` checks issuer, audience, `sub` and `iss` only), so single use is what limits one ID token to one approval. With two replicas it can decide one approval on each. With `[approvals] client_id` unset, the hop-0 ID token an agent redeemed on replica A can approve that agent's own calls on replica B, which is what server.md says single use prevents. | Same. | Correctness |
| DPoP proof `jti` cache | `crates/attenuo-server/src/dpop.rs::ProofReplayCache` (buckets of 16-byte digests behind a `Mutex`), inside `Dpop` | A proof replayed to another replica within `dpop_max_age_seconds` (default 300) is accepted. RFC-0001 section 4.1 and the [binding guide](../guides/binding-tokens-to-keys.md) already say so. | Same. | Correctness |
| DPoP server nonces | `dpop.rs::Nonces`: HMAC-SHA256 of a time bucket under a key derived from the issuer's private key | Stateless. Replicas with the same issuer key accept each other's nonces. With different keys, a nonce from A is refused at B with 401 `use_dpop_nonce` and the client retries once with the nonce from that answer. | Same. | Safe (same key), availability (different keys) |
| Run lock (SR-55) | `crates/attenuo-server/src/authz/pipeline.rs::Pipeline::run_guard`, 64 striped `Mutex<()>` in `Pipeline::run_locks`. Its doc comment says: "In process only: two servers on one store would not share it (not a supported deployment)." | Token limits stay exact: `budgets.rs::charge_in` re-reads the counters in its own `IMMEDIATE` transaction and refuses an exhausted one. A Cedar rule over `context.usage` or `context.budget` is not re-checked by anything: concurrent calls of one run on two replicas read the same figures and are both allowed. That is the over-spend SR-55 closed within one process. | Counters are split too: each file counts its own calls, so a run gets its full budget once per replica. | Correctness |
| Run limit counters, charge log, hop limits | `crates/attenuo-audit/src/sqlite/budgets.rs` (`counter_in`, `charge_in`, `refund_in`), tables `budget_counters`, `budget_charges`, `hop_limits`; the value key in `budget_meta` | Safe for token limits (see the row above): check and write are one transaction, and SQLite's write lock serializes the processes. | Each replica has its own counters. | Safe (shared file), correctness (two files) |
| Run labels and span index | `LeaseStore::add_label`, `add_spans`, `find_spans` in `sqlite/leases.rs`, tables `run_labels`, `run_spans` | Rows in the file, read per decision. | A run tainted on A is clean on B, so an approval the policy would ask for on A is not asked for on B. | Safe (shared file), correctness (two files) |
| Lease registry and revocation | `sqlite/leases.rs::SqliteLeaseStore`; every request reads it (server.md: "No lease cache") | A revocation through either replica is seen by both on their next check. | A revocation on A is never seen by B. This is the case the deploy guide's warning describes. | Safe (shared file), correctness (two files) |
| Approvals | `sqlite/leases.rs` (`decide_approval`, `take_approval`, `take_approval_by_id`: `UPDATE ... WHERE state = 'pending'` or `'granted'` in an `IMMEDIATE` transaction) | Consumed once across processes. | An approval exists only on the replica that asked for it; another replica asks again. | Safe (shared file), availability (two files) |
| Stream re-check | `crates/attenuo-proxy/src/guard.rs` calls `Authorizer::check_active` every `[proxy] stream_recheck_seconds`, which is `Pipeline::check_leases` against the store | Reads the shared registry. | A stream on B outlives a revocation on A. | Safe (shared file), correctness (two files) |
| Proxy session table (SR-11, SR-36, SR-49) | `crates/attenuo-proxy/src/session.rs::SessionRegistry`, in memory | A session bound on A is unknown on B: B answers 404 and the client starts a new session. The per-principal cap (`max_sessions_per_principal`) and the registry size hold per replica, so one principal can hold N times the cap. A hostile upstream that hands one session id to two principals on two replicas gets it bound on both, which one registry would refuse. | Same. | Availability (the cap and the hostile-upstream case are bounds, not grants) |
| Session digests for revocation by session | `LeaseStore::record_session`, table `lease_sessions` | Shared: `POST /admin/leases/revoke` with `{"session"}` finds the chain whichever replica bound it. | Only the replica that bound it. | Safe (shared file), availability (two files) |
| Calls and list requests awaited on the listen stream (SR-85, SR-86, SR-87) | `crates/attenuo-proxy/src/label.rs::AwaitedResults`, keyed by upstream, session and run | An answer that claims no entry passes through unlabelled (module docs). It can only reach a replica through a request carrying the session id, and B refuses that session with 404 (row above), so the session table keeps the two together. Not verified for an upstream that issues no `Mcp-Session-Id`. | Same. | Availability, provided session ids are in use |
| Record windows (`stream.end`, lease refusals) | `crates/attenuo-proxy/src/records.rs::RecordWindow` | One record per chain, tool and reason per window per replica, so up to N records a minute instead of one. The refusal itself is never relaxed. | Same. | Availability |
| Listed tool names (SR-25) | `crates/attenuo-proxy/src/listed.rs::ListedTools` | With `require_listed_tools`, B refuses a call whose name only A has seen listed, until a `tools/list` passes through B. Fails closed. | Same. | Availability |
| MCP annotation narrowing | `crates/attenuo-policy/src/lib.rs::PolicyEngine::narrowed` (`[policy] import_annotations = "narrowing"`) | A tool A has narrowed to destructive stays as the catalog says on B until a `tools/list` passes through B. A forbid keyed on `resource.destructive` applies on A and not on B. A restart has the same effect. | Same. | Correctness (only with `import_annotations = "narrowing"`) |
| Policy set and reload | `AppState::loaded_policies`, `Pipeline::policy` (`Arc<RwLock<PolicyEngine>>`), swapped by `POST /admin/policies/reload` (`routes/admin.rs::reload_policies`) | Each replica reads `policy.policies_path` at start and on its own reload. A reload sent through the load balancer reaches one replica; the others keep the old set until they are reloaded or restarted. A forbid added by the reload is enforced on one replica only. `GET /admin/policies` on each replica shows the digest it holds. | Same. | Correctness (between a reload and the last replica's reload) |
| Policy caches | `attenuo-policy` `request.rs::RequestCache`, `screen.rs::ScreenMemo`; `authz/authorizer.rs::VerifiedTokens` | Pure caches keyed on their inputs and the policy generation; a verified-token hit re-runs `validate_at(now)` and the lease check still reads the store. | Same. | Safe |
| Approval notifier: queue and watch set | `crates/attenuo-server/src/notify.rs` (`Emitter`, `Watch`, `MAX_WATCHED`), delivered on `sink::Queue` | Each replica delivers what it produced. On start, `recover` queues every open outbox row, including rows another live replica is still delivering, so those are sent twice with the same `event_id`. The expiry watch set holds only approvals created by this replica (or found pending at its start): if A stops for good, approvals created on A get no `approval.expired` until some replica restarts. | Each file has its own outbox; nothing is lost or doubled across them. | Availability |
| Notice outbox (#168) | `crates/attenuo-audit/src/sqlite/outbox.rs`, table `notice_outbox` with `event_id ... UNIQUE` and `INSERT OR IGNORE` (`outbox_insert`); settling is `UPDATE ... WHERE id = ?1 AND` open | Already handles the duplicate insert: two replicas that both find one approval expired insert one row, and `Emitter::emit` returns without queueing on `Ok(None)`. A row settled by one replica is not settled again. There is no claim on an open row, so the duplicate delivery above remains; receivers deduplicate by `event_id`, which the design already requires (delivery is at least once). | | Availability (already deduplicated by `event_id`) |
| Audit hash chain | `crates/attenuo-audit/src/sqlite/log.rs::Inner::commit_tx`: `head_link` reads `(seq, entry_hash)` inside the `IMMEDIATE` transaction, `seq INTEGER PRIMARY KEY`, `entry_hash UNIQUE` | The chain stays linear across processes, because each append reads the head under SQLite's write lock. Throughput is one writer for the file, and a process that waits longer than `BUSY_TIMEOUT` (5 s, `connection.rs`) fails its append, which denies the call with `audit_error`. | Two chains, each verifying on its own, neither covering the other's decisions. | Safe (shared file), correctness (two files: no single record of what was decided) |
| Signed checkpoints | `log.rs` (`Checkpointing`, `checkpoint_signed`, `checkpoint_if_new`), signed with the issuer key; shipped by `crates/attenuo-server/src/sink.rs::CheckpointSink` from the `on_created` hook | Whichever process appends the entry at a multiple of `checkpoint_every` signs it, and `checkpoint_signed` returns the existing checkpoint for an unchanged head. Each process ships only the checkpoints it signed, so the off-host copy is the union of the replicas' sinks. With different issuer keys the checkpoints carry different `kid`s and each replica's JWKS lists only its own. | Two independent sets. | Safe (same key, sinks pointing at one destination), availability otherwise |
| Write gate | `crates/attenuo-audit/src/sqlite/connection.rs::WriteGate`: a FIFO ticket lock in a process-wide map keyed by canonical path | In process only. A second process is kept out by SQLite's lock and the busy handler, which sleeps instead of queueing: the contention the gate was built to remove (performance.md, "Write-lock contention") comes back between processes. | Not involved. | Availability |
| WAL checkpointer | `crates/attenuo-audit/src/sqlite/wal.rs::WalCheckpointer`, its locked catch-up pass, and the writer's backstop (`WAL_WRITER_BACKSTOP_FRAMES`) | Each process runs its own. The locked pass pauses only that process's appends, and a `TRUNCATE` needs every reader of every process to finish, so checkpoints come back busy more often and the WAL grows. WAL mode itself needs the processes on one host, sharing the `-shm` file ([SQLite: WAL](https://www.sqlite.org/wal.html)). | Not involved. | Availability |
| Maintenance (pruning) | `crates/attenuo-server/src/lib.rs::spawn_lease_maintenance`; cursors in `SqliteLeaseStore` (`session_cursor`, `lease_prune`, `run_state_cursor`) | Every replica prunes. Each pass is one transaction that re-checks what it deletes, so passes on two processes repeat work without deleting a live row. | Each prunes its own. | Safe |
| Issuer keys | `crates/attenuo-server/src/state.rs::load_issuer`, `issuer_keys.rs::jwks_from_keys` | With one `private_key_pem_path` mounted on every replica (plus the same `previous_key_paths`), tokens, approval tokens, nonces and checkpoints verify everywhere. Without the setting each replica generates an ephemeral key and refuses the others' tokens. Two replicas that start together on a shared volume with no key yet race on `create_new`; the loser fails to start and finds the key on its next start. | Same, if the key files are the same. | Safe (one key), availability otherwise |
| IdP and actor-trust JWKS | `crates/attenuo-server/src/idp/jwks.rs::JwksCache` | Each replica fetches and caches on its own. | Same. | Safe |
| Metrics | `crates/attenuo-server/src/metrics.rs::Metrics` | Per process, scraped per replica. Counters sum. Gauges read from the shared file (`attenuo_approval_notify_outbox_rows`) report the same global figure from each replica, so summing them over-counts. | Gauges are per file. | Availability |

Three things follow from the table.

First, the correctness-critical rows are few and specific: the two replay caches (with approval ID tokens through the first), the run lock, policy divergence after a reload, and annotation narrowing. Everything that is already a row in SQLite is correct with several processes on one file, because the code reads inside `IMMEDIATE` transactions and does not cache lease state.

Second, "two files" is never acceptable: it turns every safe row into a correctness row. The deploy guide's reason ("each process would keep its own idea of which leases are revoked") is the reason for a copy. For a shared file the reason is the in-process rows above.

Third, the proxy's in-memory state is self-protecting. The session table refuses an unknown session with 404, and that refusal keeps the awaited-result map, which would otherwise let an answer through unlabelled, on the replica that holds the session.

## 3. Deployment shapes

### (a) One replica, restart safe

What survives a restart today: leases and revocations (revocations commit with `synchronous=FULL`), counters and the charge log, approvals in every state, run labels and spans, session digests for revocation, the audit log and its checkpoints (checkpoint commits are synced, SR-50), outbox rows, and the issuer key when `private_key_pem_path` is set. The notifier queues the open outbox rows again and watches the pending approvals again (`notify.rs::recover`).

What does not survive:

- The credential replay cache. After a restart, an ID token or ID-JAG that has not expired can mint a second root token, a parent can delegate to the same actor again, and an approval ID token can decide a second approval. The window is the credential's remaining lifetime plus the IdP's clock skew.
- The DPoP `jti` cache. A proof made before the restart can be replayed for up to `dpop_max_age_seconds`.
- The session table. Every client gets 404 and starts a new session, as server.md says.
- Annotation narrowing, until the next `tools/list` from each upstream.
- The checkpoint sink's queue. A checkpoint that was queued and not shipped is lost; the next one covers its entries.
- Record windows, listed tool names, and the policy and token caches, all of which only cost an extra record, a fail-closed refusal or a cache miss.

So the gap for a single replica is the two replay caches. Making them durable in the same SQLite file closes it without touching the deployment model (section 4, step 1).

### (b) Active/passive on a shared volume

The usual form is one instance at a time on a volume that only one host mounts: a Kubernetes Deployment with one replica, `strategy: Recreate` and a `ReadWriteOnce` volume, or a VM pair with a failover script. Failover is then a restart on another host, and (a) applies.

Two things make this shape more fragile than it looks.

- Before the start-up fence (step 2, now built), nothing in the server stopped a second process: there was no lock file and no `locking_mode=EXCLUSIVE`. SQLite's own locking keeps two writers from corrupting the file when both processes are on one host (it needs the shared `-shm` mapping for WAL), and `connection.rs::switch_to_wal` and `BUSY_TIMEOUT` are written for a second process opening the file. But `WriteGate` assumes it is the only writer in the process that matters: the run lock, both replay caches, the outbox recovery and the notifier's watch set are all per process. A rolling update with overlap (`maxSurge` above zero, or a failover script that starts the new instance before the old one is dead) is shape (c) on a shared file for as long as the overlap lasts. `/readyz` passes on both, because it only reads.
- Across hosts, the shared volume must not be a network filesystem (see (d)).

A start-up fence makes (b) safe by construction: refuse to start while another process holds the file. An advisory `flock` on a sibling file (`<sqlite_path>.lock`), held for the life of the process, is enough on one host and on a `ReadWriteOnce` volume. It changes behaviour, since a rolling update with overlap now fails to start the new instance until the old one has exited (open question 7). **Built** (step 2): `attenuo_audit::WriterFence`, taken in `state.rs::open_storage` before the database is opened; see [deploying](../guides/deploying.md#one-process-per-file) and [config](../reference/config.md#single-writer-fence).

### (c) N active replicas behind a load balancer, sticky by token or run

Stickiness routes requests that carry the same key to the same replica. The candidate keys are the `Authorization` header (one token per agent hop), the `Mcp-Session-Id` (absent on the `initialize` that creates it) or a run id (`chain_id`, which a load balancer cannot read without decoding the token).

What stickiness buys: the session table, the awaited-result map, the record windows and the listed tool names behave as on one replica for a client that keeps its token, which is every row marked availability in section 2. Hashing on the `Authorization` header works from the first request; hashing on the session id does not, because `initialize` carries none and the follow-up may land elsewhere and get 404.

What still leaks, whatever the key:

- Replay. Stickiness is chosen by the client, and the replay caches exist to stop a client that is not following the rules. An attacker who holds a replayable credential sends it to whichever replica has not seen it. A router that hashed on the replay key itself (the credential's `jti`, the DPoP proof's `jti`) would put a replay on the same replica, but it must parse the form body of `POST /token` and the proof header, and every change of replica membership moves keys to a replica that has not seen them.
- The run lock. Each hop of a run has its own token, so a run's agents are spread over replicas by a token hash, and concurrent calls of one run under a soft limit are no longer serialized.
- Policy reloads, which reach one replica.
- With separate files per replica, revocations, counters and labels, which makes this shape unsafe without a shared store.

Stickiness is worth having in (d) for availability. It is not a substitute for a shared store in any row marked correctness.

### (d) N active replicas with a shared store

Here every correctness row moves to a store the replicas share. The candidates:

- **Postgres** for the lease store, counters, approvals, labels, outbox and audit log, and possibly the replay caches. Each operation that is an `IMMEDIATE` transaction today becomes a transaction with row locks, and the run lock becomes `pg_advisory_xact_lock` on a hash of the `chain_id`. The README has no stack line that names a Postgres driver: the workspace depends on `rusqlite` only (`Cargo.toml`), so Postgres is a new dependency to clear with `cargo deny`. The store traits are synchronous and run on the blocking pool (`AppState::blocking`), so the synchronous `postgres` crate fits them as they are; `sqlx` is async and would move the store calls off the blocking pool, a larger change (open question 3).
- **Redis** for the replay caches only. `SET key 1 NX PX ttl` is the single-use primitive, and a short Lua script gives the all-or-none of `use_all_once`. Without AOF persistence, a Redis restart reopens the replay window of (a), and it is a second dependency to run (open question 8). Its advantage is the DPoP `jti` volume: one write per proxied request with a proof.
- **SQLite on NFS or another network filesystem: refuse.** WAL mode needs every process on one host, sharing the `-shm` wal-index in memory, and SQLite's documentation says WAL does not work over a network filesystem ([SQLite: WAL](https://www.sqlite.org/wal.html)). Without WAL, SQLite relies on POSIX advisory locks, which are unreliable on many NFS setups ([SQLite: how to corrupt](https://www.sqlite.org/howtocorrupt.html), section 2.1). The failure is not a refusal but two writers that both believe they hold the lock: torn pages or two commits that read the same head. `seq INTEGER PRIMARY KEY` would refuse a second row with the same `seq` only while the file is consistent, which is what broken locking takes away. The server should check the filesystem type of `sqlite_path` at start (on Linux, `statfs` against the NFS, SMB and CIFS magic numbers) and refuse, with an override for operators who know their filesystem.

## 4. Proposed path

Ranked by the correctness column, so that each step closes a row that can today be turned into a replay or an over-spend.

| Step | What | Closes | Effort |
|---|---|---|---|
| 1 | A `ReplayCache` trait with the in-memory implementation of today and a SQLite one (a `replay` table in the lease store's file: key digest, expiry; one `INSERT` per key in an `IMMEDIATE` transaction, refused on conflict with a live row; expired rows pruned by the maintenance task). Credential replay first; DPoP `jti` behind a separate switch, because it costs a write per request. | Restart safety of (a) and the replay rows of (b) | M |
| 2 | A start-up fence: an advisory lock on `<sqlite_path>.lock` held for the life of the process, and a refusal to open `sqlite_path` on a network filesystem. **The lock is built** (`WriterFence`); the network-filesystem refusal is not. | (b) overlap, SQLite on NFS | S |
| 3 | Policy consistency: each replica stores the digest of the set it loaded in the store, and a reload bumps a generation that every replica polls (or the policy text itself lives in the store). Annotation narrowing is recorded in the store, or documented as unsupported with several replicas and replaced by catalog entries. | Policy divergence, annotation narrowing | S to M |
| 4 | A `Counters` trait: the existing `LeaseStore::budget_used`, `charge`, `charge_sync_deferred` and `refund` split out of `LeaseStore`, plus `lock_run(chain_id)`, the run lock of `Pipeline::run_guard`. In process: today's stripes. In Postgres: an advisory transaction lock held from reading the figures to the charge. | The run lock (SR-55) across replicas | M |
| 5 | A Postgres backend for `LeaseStore`, `Counters`, `ReplayCache`, the outbox and `AuditSink`, behind `[store] backend`. | (d) | L |
| 6 | Notifier: an outbox row is claimed before delivery (`claimed_by`, `claimed_until`), and the expiry watcher sweeps the store for pending approvals past their expiry instead of only its own watch set; `event_id` keeps both idempotent. | Duplicate notices, missed expiries | S |

Steps 1 to 3 are worth doing for a single replica on their own: they close the restart window and the overlap during a rolling update. Steps 4 to 6 are only worth doing if N active replicas is a goal (open question 1).

### Interfaces

Both caches already share a shape: a list of keys with expiries, all recorded or none, a replay error, and a fail-closed error when the cache cannot take more (`replay.rs::ReplayCache::use_all_once`, `dpop.rs::ProofReplayCache::use_all_once`). The trait is that shape:

```rust
pub trait ReplayCache: Send + Sync {
    /// Record every key as used until its expiry (Unix seconds), or none of them.
    /// `Replayed` when any key is live or given twice; `Unavailable` when the store is
    /// full or cannot answer, which the routes map to 503 as they map a full cache today.
    fn use_all_once(&self, keys: &[(&str, i64)], now: i64) -> Result<(), ReplayError>;
}
```

`AppState::replay` and the `replay` field of `Dpop` become `Arc<dyn ReplayCache>`. The callers do not change.

`Counters` is mostly a move, not new code. `budgets.rs::charge_in` already re-checks and writes in one transaction, and `LeaseStore` already has `budget_used`, `charge`, `charge_sync_deferred`, `refund` and `budget_summary`. What is missing from any trait is the run lock, which lives in `Pipeline`:

```rust
pub trait Counters: Send + Sync {
    // budget_used, charge, charge_sync_deferred, refund, budget_summary: as on LeaseStore today
    /// Serialize the budgeted decisions of one run, from reading its figures to charging them.
    fn lock_run(&self, chain_id: &str) -> Result<RunGuard<'_>, AuditError>;
}
```

`Pipeline::run_guard` calls `lock_run` instead of indexing `run_locks`. In Postgres the guard holds a transaction with `pg_advisory_xact_lock`. That transaction is open across one Cedar evaluation, about 12 to 163 microseconds (README, "Policy stage"), plus a round trip to the database.

The seam already exists in most of the server: `Pipeline` holds `Arc<dyn LeaseStore>` and `Arc<dyn AuditSink>`, and `MemoryLeaseStore` (`lease.rs`) and `MemoryAudit` (`memory.rs`) are second implementations. It does not exist everywhere. `AppState` holds `Arc<SqliteAudit>` and `Arc<SqliteLeaseStore>`, the notifier holds `Arc<SqliteLeaseStore>` for the outbox methods, which are inherent methods rather than trait methods, and the admin routes call SQLite-only queries (`range_filtered`, `entries_matching`, `checkpoints_between` and others). The two concrete types are named 27 times in `crates/attenuo-server/src` (`authz/`, `notify.rs`, `state.rs`, some of them in tests), and the admin routes reach the SQLite-only queries through `AppState::audit`. That, more than the trait methods, is why step 5 is L.

### The audit chain

The log must stay one chain that `attenuo audit verify`, the exports and both SDKs' verifiers check without change. Two ways to keep that with several writers:

- **One chain, serialized in the store.** This is the algorithm `commit_tx` runs today: read the head inside the write transaction, chain the batch, insert, sign the checkpoints that fall in it, commit. In Postgres the head becomes a one-row `audit_head` table updated in the same transaction, whose row lock serializes the replicas' batches as SQLite's file lock does now. Each replica keeps its writer thread and group commit, so one round trip and one commit cover a batch. Checkpoints are signed by the replica whose batch crosses a multiple of `checkpoint_every`, which requires one issuer key across replicas. Tokens already require that. The cost is that the append rate of all replicas together is that of one serialized writer plus network latency per batch.
- **Per-replica chains with a merge checkpoint.** Each replica appends to its own chain (`replica_id`, `seq`), and a periodic merge checkpoint signs the set of heads. This removes the serialization, but every verifier, the export format, the shipped-checkpoint format and `cross_check` learn about several chains, and "the record before this one" no longer has one answer.

An elected single writer that the other replicas forward appends to is a third option. It adds a network hop to every decision and a failover protocol for the writer, and buys nothing over the first option, whose serialization point is the database's lock.

The proposal is the first: one chain, serialized by a head row in the store, keeping every format as it is. The second is the answer only if measurement shows the serialized append is the bottleneck (open question 4).

### Configuration

```toml
[store]
# "sqlite" (default): today's behaviour; one process per file, enforced by the fence of step 2.
# "postgres": the lease store, counters, approvals, outbox, replay cache and audit log in Postgres.
backend = "sqlite"
# Postgres only. The URL carries a password, so it is read from the environment, as the
# admin token and the sink token are; never from this file.
url_env = "ATTENUO_STORE_URL"
max_connections = 16

[store.replay]
# "memory": today's per-process cache (lost on restart, not shared).
# "store": the [store] backend (step 1 for sqlite, step 5 for postgres).
credentials = "store"
# DPoP proof jtis: one write per request that carries a proof.
dpop = "memory"
```

`[audit] sqlite_path`, `durability` and `wal_checkpoint_seconds` keep their meaning for `backend = "sqlite"`. With `backend = "postgres"`, the server refuses `[store.replay] ... = "memory"` when it cannot tell that it is the only replica (there is no reliable way to tell), or warns and says what is lost: the choice is open question 2.

## 5. Open questions

1. **Is N active replicas a goal for 0.x?** The deploy guide calls one node a design choice ("attenuo fails closed"). If restart safety and active/passive are enough, steps 1 to 3 are the whole plan, and steps 4 to 6 wait for a user who needs them.
2. **Which replay rows to persist.** Credential replay is low volume (one write per hop-0 intake, exchange or approval). DPoP `jti`s are one write per proxied request with a proof, through the same write gate as the audit append. Persist both, persist credentials only and accept a DPoP replay window of `dpop_max_age_seconds` after a restart, or shorten that window with `dpop_nonce = "required"`?
3. **Postgres client.** The synchronous `postgres` crate fits the synchronous store traits on the blocking pool; `sqlx` is async and would change how every store call is made. Is either acceptable as a dependency, and does the async change matter more than the crate?
4. **One chain or several.** Is one chain, serialized by a head row in the store, acceptable as the throughput ceiling of a multi-replica deployment, given that every verifier stays as it is? If not, who owns the format change for per-replica chains (export, shipped checkpoints, both SDKs)?
5. **Run lock across replicas.** Holding a database transaction with an advisory lock across a Cedar evaluation serializes one run's budgeted decisions across the fleet. Is that acceptable, or should soft limits over run usage (`context.usage`) be documented as single-replica only, with token limits (which the store re-checks) as the multi-replica guarantee?
6. **Policy reload across replicas.** Store the loaded digest and a generation in the store and have every replica poll, or keep the policy text itself in the store so that a reload is one write? The second changes where the policy file lives.
7. **Start-up fence.** Should the server refuse to start while another process holds `sqlite_path`, and refuse a network filesystem? It turns a silent overlap in a rolling update into a start-up failure, which operators will notice. Answered for the lock: the server refuses to start, and the deploy guide asks for `strategy: Recreate`. The network-filesystem refusal is still open.
8. **Redis.** Is a second datastore acceptable at all, for the DPoP volume only, or should everything shared go to one store even if it is slower?

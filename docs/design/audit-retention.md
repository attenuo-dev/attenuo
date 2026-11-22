# Audit retention: design

- Status: phase 1a (the server and the store) built on 2026-11-22; see [As built](#11-as-built). Decision record: [ADR-0015](../decisions/0015-audit-retention.md). With the default `prune = "off"` the audit log is never pruned, and every statement elsewhere that it keeps every record holds. Sections 1 to 10 are the design as proposed and keep their code references to the base commit.
- Date: 2026-11-13. Base: `main` at 7493efb. Every code reference below is to that commit.
- Finding: O-4 of the 2026-11-07 audit, "no audit retention or rotation, so the file grows without bound".

## 1. Problem

The audit log is the `audit` table of the server's one SQLite file (`[audit] sqlite_path`), next to the lease registry, the run-state tables and the notice outbox. Rows are inserted by the writer thread and never deleted. The run-state tables have retention of their own (`[leases] retention_seconds`, `run_state_retention_seconds`, `user_window_retention_seconds`); the log has none, and the deploy guide's only advice is to watch free disk space, because a full disk denies every call (`audit_error`).

An operator needs a supported way to keep the file to a bounded size. The log exists so that anyone holding the issuer's JWKS can check that the record is complete and unaltered, offline, without trusting the host. A prune must keep that property for what stays and for what leaves, and must not look like the attack the log is meant to expose (threat model A7: "read the audit log after the fact and attempt to alter or truncate it").

## 2. What a prune must preserve

1. **The retained log verifies.** After a prune through `seq` B, the entries `B + 1 ..= head` verify as a hash chain whose first `prev_hash` is the entry hash at B, and B's hash is vouched for by a signed checkpoint at B that the verifier checks against the JWKS.
2. **The archived prefix verifies on its own.** The removed entries `first ..= B` are an ordinary export file (format `attenuo-audit-export-v2`) that contains the checkpoint at B, so `attenuo audit verify --file` passes on it strictly (no unsigned tail) with the JWKS as the only input. Two consecutive archives, and the last archive with the retained log, link: the last entry hash of one is the first `prev_hash` of the next.
3. **No `seq` is given twice.** The next append after a prune gets `head + 1`, never 1, however much was pruned.
4. **Cursors and ranges keep their meaning.** A cursor or a `from`/`to` that names a pruned `seq` either resumes at the first retained `seq` or is refused with a code that says the range was pruned, never silently answered from other entries.
5. **Nothing live loses its record.** Entries that live state still refers to (a run whose leases are in the registry, its approvals, its run labels and spans, its issuance records) are never pruned.
6. **Verify says what it saw.** `audit verify` on a pruned log reports where the log starts, which anchor vouches for that, and whether the anchor is valid; a log cut without a valid anchor reports a broken chain, as today.
7. **The prune is itself on the record.** An audit record of the prune, a signed checkpoint before and after it, and a signed anchor, all shipped off the host when `[audit.sink]` is set.

## 3. What the code does today

Each fact below is what the design relies on. Line numbers are at 7493efb.

**Storage and sequence numbers**

- `audit.seq` is `INTEGER PRIMARY KEY` without `AUTOINCREMENT` (`crates/attenuo-audit/src/sqlite/schema.rs:13`). The writer computes the next seq itself: `head_link` reads `MAX(seq)` and its hash, and on an empty table returns `(0, GENESIS_HASH)` (`crates/attenuo-audit/src/sqlite/log.rs:161-178`), so the next entry is seq 1 again. Deleting every row would reuse sequence numbers; a prune must always leave at least one row, or `head_link` must fall back to the anchor.
- Six indexes sit on `audit` (`schema.rs:33-37`) plus the record-id expression index (`schema.rs:206-220`). A delete updates each of them.
- Checkpoints are their own table, `checkpoints (seq PRIMARY KEY, head_hash, at, kid, signature)` (`schema.rs:40-48`). There is no table that records where the log starts.
- No connection sets `auto_vacuum`, and nothing runs `VACUUM` (`crates/attenuo-audit/src/sqlite/connection.rs`, no match in the crate). Deleted pages go to SQLite's free list and are reused; the file does not shrink.
- Migration 2 exists because an implicit `rowid` can be renumbered by `VACUUM` and reused after deletes; `approvals` now has `position INTEGER PRIMARY KEY AUTOINCREMENT` (`crates/attenuo-audit/src/sqlite/migrations.rs:210-264`). `audit.seq` is already an `INTEGER PRIMARY KEY`, which `VACUUM` keeps.

**Writes**

- Every append is one `BEGIN IMMEDIATE` transaction taken under the file's write gate, on the writer thread (`Inner::commit_tx`, `log.rs:712-826`). A checkpoint at a multiple of `checkpoint_every` is signed and inserted in the same transaction (`log.rs:760-771`).
- `checkpoint_signed` (`log.rs:1235-1273`) locks the writer connection, holds the gate, opens an `IMMEDIATE` transaction with `synchronous=FULL`, signs the head and inserts the checkpoint, then calls the `on_created` hook that queues it for the sink. A prune transaction can follow the same pattern.
- `checkpoint_if_new` (`log.rs:1284-1300`) signs only when the head moved past the newest checkpoint; the timer is `spawn_checkpointer` (`crates/attenuo-server/src/lib.rs:279-315`).
- `with_connection` (`log.rs:1372-1382`) hands out the writer connection under the log's lock; anything written through it bypasses the chain. Tests use it to tamper.
- The run-state prunes (`prune_leases`, `prune_run_state`, `crates/attenuo-audit/src/sqlite/leases.rs:1488-1640`) hold the gate and run one `IMMEDIATE` transaction per pass of at most `maintenance_batch_rows` rows, driven by the maintenance ticker in passes (`lib.rs:334-368`). A batched audit delete can follow that pattern.

**Verification**

- `walk_entries` (`crates/attenuo-audit/src/log.rs:120-173`) checks seq contiguity, `prev_hash` links and each entry's hash. Anchored (`Start::Genesis`) it expects seq 1 and the genesis `prev_hash` (`log.rs:129-130`); as a window (`Start::Window`, `crates/attenuo-audit/src/checkpoint.rs:207-214`) it takes the first entry's seq and `prev_hash` as given.
- `verify_chain_signed`, the body of `GET /admin/audit/verify` (`crates/attenuo-server/src/routes/admin.rs:996-1004`), always walks with `Start::Genesis` (`crates/attenuo-audit/src/sqlite/log.rs:1350-1361`). On a log whose first row is B + 1 it reports `ok: false, first_bad_seq: B + 1`. Checkpoints at or below B are then silently skipped, because the chain is already reported broken (`checkpoint.rs:268-278`). So today a legitimate prune and an attacker's truncation of the prefix look the same: a broken chain at the first retained seq.
- A checkpoint proves the prefix `1..=seq` hashed to `head_hash` (`checkpoint.rs:11-15`); its signature covers the RFC 8785 JSON of `[seq, head_hash, at, kid]` under the context `attenuo-checkpoint-v1` (`checkpoint.rs:31`, `57-60`).
- `verify_export_with` (`crates/attenuo-audit/src/export.rs:325-397`) verifies a window from its first entry (`export.rs:340-345`), only matches checkpoints inside the entry range and verifies the signatures of the others (`export.rs:346-371`), fails a file that starts or ends short of its header's range (`export.rs:375-378`), and fails entries after the last valid checkpoint unless `allow_unsigned_tail` (`export.rs:384`). An export `first..=B` that contains the checkpoint at B therefore already verifies strictly.
- `ExportHeader` has no `deny_unknown_fields` (`export.rs:84-99`), so a new optional header member is ignored by a verifier that does not know it. (The SDKs' parsers were not checked for this.)
- The shipped-checkpoint cross-check skips shipped checkpoints below the export's `from` without counting them (`crates/attenuo-audit/src/shipped.rs:247-249`). A cross-check of an export of the retained part would not notice a cut prefix today.

**Export and reads**

- `GET /admin/audit/export` defaults `from` to 1 and `to` to the head, and refuses only `from = 0` and `to < from` (`admin.rs:1242-1265`); it streams entries a page at a time and then `checkpoints_between(from, to)` (`admin.rs:1333`), so an export to B includes the checkpoint at B.
- `GET /admin/audit` takes `from` (default 1) and `to` (`seq_range`, `admin.rs:972-986`) and pages by a cursor that is a `seq` (`admin.rs:881-969`). Nothing assumes the first entry is seq 1, so a `from` below the first retained seq simply returns from there.
- `GET /admin/audit/entries/{seq}` answers 404 for a missing seq (`admin.rs:1092-1105`); `GET /admin/audit/records/{id}` looks the record up through the expression index and answers 404 when it is absent (`admin.rs:1115-1131`). Decision ids are random UUIDs (`uuid::Uuid::new_v4()`, `crates/attenuo-server/src/routes/mod.rs:154`), so an id says nothing about when its record was written.

**Live state that refers to audit entries**

- The enforcement path never reads the `audit` table. Every `SELECT ... FROM audit` in the workspace is in `crates/attenuo-audit/src/sqlite/log.rs` (and migration checks); the server calls six lookups from admin routes only: `entry_by_record_id` (refund refusals, `admin.rs:469`; record lookup, `admin.rs:1126`), `issuance_records` (lease tree, `admin.rs:615`), `checkpoint_covering` and `first_entry_after` (entry view, `admin.rs:1056-1066`), `entry_at` (`admin.rs:1100`).
- Refunds: `refund_budget` refunds from the charge log without reading the audit record; only when the charge log has nothing does `no_charge_refusal` read the decision's record to answer 410 `charge_pruned` instead of 404 (`admin.rs:451-515`). Its doc and the threat model rely on "the audit log (append-only, every decision kept)".
- Tables that store an audit `seq` or decision id: `run_labels (chain_id, source, decision_id, seq)` (`schema.rs:91-98`), `approvals.decision_id` (`schema.rs:108`), `budget_charges.decision_id` and `user_window_charges.decision_id` (`schema.rs:133-144`, `184-194`), `run_spans.seq` (`schema.rs:163-169`). None is joined with `audit` by any query. Records also carry `seq`s of earlier records inside them (`labels.tainted_by`, `labels.untrusted_args[].seq`, see the [audit log](../concepts/audit-log.md#tool-results-and-labels) page).
- A run's `run_spans` rows are deleted when the run is revoked (`crates/attenuo-audit/src/sqlite/leases.rs:502-506`), and its `run_labels` and `run_spans` go with the run when the lease registry prunes it (`[leases] retention_seconds` in the [configuration reference](../reference/config.md#leases)).

**Trust and process boundaries**

- Every `/admin/*` route is behind `require_admin` (`admin.rs:45`), the one static admin token.
- An admin record stores a digest of its arguments, not the arguments (`audit_admin`, `routes/mod.rs:143-180`; the digest is `sha256_json` of the arguments, `crates/attenuo-core/src/call.rs:72-74`).
- One server process owns the file: `open_storage` takes the `WriterFence` before opening the database (`crates/attenuo-server/src/state.rs:669`). The CLI never opens the database; `audit verify` and `audit export` go through the admin API or read an export file.
- The checkpoint sink queues in memory, drops the oldest queued checkpoint when full (`crates/attenuo-server/src/sink.rs:363-389`), and reports `queued`, `lag`, `failing_for` and `degraded` (`sink.rs:330-343`) and a count of deliveries (`sink.rs:418-420`). It does not record the highest `seq` it has delivered.

**Schema**

- `SCHEMA_VERSION` is 2 (`migrations.rs:45`); the list is append only (`migrations.rs:57-73`) with a compile-time check that the two agree (`migrations.rs:75-78`). Each step runs in its own `BEGIN IMMEDIATE` transaction that sets `user_version` (`migrations.rs:104-155`). A file above the build's version is refused with `SchemaTooNew` (`migrations.rs:167-172`).

## 4. Design

### 4.1 Terms

- **Boundary B**: the last seq removed. B is always the seq of a stored checkpoint.
- **Archive**: the export `first ..= B`, where `first` is the first retained seq before this prune (1 for the first prune).
- **Prune record**: an `admin` record (tool `admin.audit.prune`, reason `admin_action`, subject `urn:attenuo:admin`) appended at seq P, after the head at the time of the prune. Its arguments are `{through_seq, through_hash, previous_through_seq, archive_sha256}`; as for every admin record only their digest is in the record, and the anchor holds the values.
- **Anchor**: a signed statement, stored in a new table `audit_anchors`, that the log now starts at B + 1. Signed by the issuer key under a new context string `attenuo-audit-anchor-v1`, over the RFC 8785 JSON of `[through_seq, through_hash, prune_seq, prune_entry_hash, previous_through_seq, archive_sha256, at, kid]`. `prune_entry_hash` binds the anchor to the exact prune record; `previous_through_seq` links a series of prunes.

### 4.2 The prune, step by step

Inside the server, on `POST /admin/audit/prune` with `{through, archive_sha256}`:

1. **One short transaction** on the writer connection, under the write gate, `BEGIN IMMEDIATE`, committed with `synchronous=FULL` (as `checkpoint_signed` does):
   1. Check the guards (section 4.3) again inside the transaction.
   2. Sign a checkpoint at the current head H if there is none (the "before" checkpoint).
   3. Append the prune record at P = H + 1, through the same `insert_entry` as any append.
   4. Sign the anchor (it names P and P's entry hash).
   5. Sign a checkpoint at P (the "after" checkpoint).
   6. Insert the anchor row with `state = 'deleting'`.
2. After the commit, the `on_created` hook queues the two checkpoints and the anchor for the sink.
3. **Batched deletes**, each its own short `IMMEDIATE` transaction under the gate: `DELETE FROM audit WHERE seq IN (SELECT seq FROM audit WHERE seq <= B ORDER BY seq LIMIT n)` with `n = [audit.retention] batch_rows`, and once the rows are gone `DELETE FROM checkpoints WHERE seq < B` (the checkpoint at B stays; the anchor refers to it). The last batch sets the anchor's `state = 'done'`. The batches run on the maintenance ticker, so a server restart resumes them.

From the commit in step 1 on, the log starts at B + 1 for every reader, whether or not the rows at or below B have been deleted yet: every read clamps its lower bound to the newest anchor's `through_seq + 1`, and `verify_snapshot` reads the anchor in the same read transaction as the head and the checkpoints. A prune therefore has two states only, before and after, however the deletes are interrupted.

`head_link` falls back to the newest anchor when the table is empty, so that no seq is reused even if every row were removed by hand; the prune itself never empties the table, since P is above B.

### 4.3 Guards: which B is allowed

The server picks or checks B against all of these, and refuses the prune otherwise:

- **At a checkpoint.** A stored checkpoint exists at B and its `head_hash` equals the entry hash at B. The plan route rounds a requested boundary down to the newest such checkpoint (they exist every `checkpoint_every` entries and every `checkpoint_interval_seconds`).
- **Old enough.** The entry at B is older than `[audit.retention] min_age_seconds`. The start-up check refuses a `min_age_seconds` below `[leases] retention_seconds + run_state_retention_seconds` (each term only when it is not 0) or below `user_window_retention_seconds`, so a record is never pruned before the run state that might need it is gone. Entry times come from the wall clock and are not guaranteed to increase with `seq`; the guard reads the time of the entry at B only. What a clock stepped backwards does to this guard has not been analysed.
- **Not live.** B is below the first record of any delegation chain whose root lease is still in the registry: `SELECT MIN(seq) FROM audit WHERE chain_id IN (SELECT id FROM leases WHERE parent IS NULL)`, through `audit_chain_id_idx`. That keeps every issuance record the lease tree reads, every `tool_result` a live run's `run_labels` and `run_spans` point at, and every approval record of a live run.
- **Sink caught up.** When `[audit.sink]` is set, the sink is not degraded and has delivered the checkpoint at B or a later one. This needs a new `last_delivered_seq` in the sink's state (today it counts deliveries but keeps no seq, `sink.rs:418-420`).
- **One at a time.** No anchor is in `state = 'deleting'`.

### 4.4 After a prune

- **Verify.** `verify_chain_signed` walks with a new `Start::Anchored { seq: B, hash }`: the first entry must be B + 1 with `prev_hash` equal to the anchor's `through_hash`. The anchor's signature is checked against the JWKS, the checkpoint at B must verify and match `through_hash`, and the entry at `prune_seq` must exist, be `admin.audit.prune`, hash to `prune_entry_hash` and carry the `arguments_digest` of the anchor's argument values. The report gains `pruned_through` (B, or null), `anchors` (count) and `bad_anchors` (with reasons); `entries` counts retained entries. A log whose first row is not seq 1 and that has no valid anchor naming it reports `ok: false` and `first_bad_seq` at its first row, exactly as today. The CLI prints, for example, `audit chain OK: 41230 entries verified from seq 1000001 (pruned through 1000000 by the record at seq 1041231; anchor signature OK)`.
- **Cursors and ranges.** `GET /admin/audit` keeps working: `from` below the first retained seq returns from there, a cursor below it resumes there (ascending) or ends (descending). The body gains `first` (the first retained seq) next to `head`, so a client can see that it asked for pruned seqs. Nothing is refused, because a listing is not evidence.
- **Single entries.** `GET /admin/audit/entries/{seq}` for `seq <= B` answers 410 `audit_pruned` with `pruned_through` and the prune record's seq, instead of 404. `GET /admin/audit/records/{id}` cannot tell a pruned id from an unknown one (ids carry no time), so it stays 404 and the message says the log is pruned through B, written before a given time, and that the record may be in the archive.
- **Export.** `from` defaults to B + 1. A `from` or `to` at or below B answers 410 `audit_pruned` naming the first retained seq; an export never claims a range it cannot hold. When `from = B + 1` the header carries a new optional member `anchor` (the signed anchor), and `verify --file` then checks that the first entry is `through_seq + 1` with `prev_hash` equal to `through_hash` and reports `from_anchor: true` instead of `from_genesis`. A verifier that does not know the member still verifies the file as a window.
- **Several files.** `attenuo audit verify --file a.jsonl --file b.jsonl ...` verifies each file strictly and checks that they link: each file's last entry hash is the next file's first `prev_hash`, and the archive's last checkpoint is at its last seq. That is how an auditor checks archives plus the retained export as one log from genesis.
- **Cross-check.** The shipped-checkpoint cross-check counts shipped checkpoints below the export's `from` (`below_range`) instead of skipping them, and with an anchor requires the shipped checkpoint at B to equal the anchor's.
- **Refunds.** A refund whose charge is still in the charge log works as before (it does not read the record). When the charge is gone and the record too, the answer is 404 "unknown decision", and the message names the prune boundary; it can no longer be 410 `charge_pruned`. The age guard means this only happens after the run state itself would have been pruned.
- **Records that name pruned seqs.** A `seq` inside a newer record (`labels.tainted_by`) or a table (`run_labels.seq`, `run_spans.seq`) keeps its meaning, because seqs are never reused; the entry it names is in an archive. The live-run guard means no live run points into the pruned range.

## 5. Trust

**Who can prune.** Only the admin, through `POST /admin/audit/prune` behind `require_admin`, and only when the config sets `[audit.retention] prune = "manual"` (or `"auto"` in phase 2). The default `"off"` answers 409 `prune_disabled`. A stolen admin token alone cannot prune a server that was not configured to allow it; changing the config needs a restart, which the operator sees. There is no offline prune tool: the CLI does not open the database, and an offline tool would have to take the fence and duplicate the writer.

**How a prune is recorded.** By four objects, all written in one transaction and, with `[audit.sink]`, all shipped: the "before" checkpoint at H, the prune record at P, the anchor, and the "after" checkpoint at P. The anchor is the only one an attacker without the key cannot make. The server log line and a metric (`audit_pruned_entries_total`) are added too.

**Legitimate prune or truncation.** What each attacker can do, and what the verifier sees:

| Attacker | Can do | What verification shows |
| --- | --- | --- |
| Write access to the file, no key | Delete a prefix; copy a genuine checkpoint into a forged anchor row; append a fake prune record, which the server's timer will then cover with a genuine checkpoint | No valid anchor signature: `audit verify` reports the chain broken at the first retained seq. Reusing an old genuine anchor fails if any row after its `through_seq + 1` was removed (the chain breaks) |
| Write access and a backup | Restore an older file (rows back, no anchor) | The log verifies from genesis but is behind; shipped checkpoints and anchors newer than the file show it, as for any restore today |
| The server process and its key | Prune with a valid anchor, without an archive, or forge an archive; ship forged anchors to an add-only sink | Cryptographically indistinguishable from a legitimate prune. Shipped checkpoints for seqs at or below B catch a forged archive (the archive must hash to them). A missing archive is caught only by the operator's own record of when they pruned and by the time and seq of the shipped anchor |
| The admin token on a server with prune enabled | A legitimate prune, then discard the archive | The anchor, the prune record and the shipped copies show that a prefix of B entries with hash `through_hash` existed and was pruned at a given time; nothing shows what was in it |

What remains undetectable: a prune made with the key (by a compromised server process) is indistinguishable from one the operator made, except through records kept off the host. The contents of a prefix whose archive was destroyed cannot be recovered or proved, only its length and final hash. A prune made while the sink is down leaves its evidence on the host until delivery, the same window as for checkpoints today (the "sink caught up" guard narrows it to the prune's own objects).

## 6. Operator interface

### 6.1 CLI

```sh
attenuo audit prune --before 2026-08-01T00:00:00Z --archive /mnt/archive/attenuo-0001.jsonl
attenuo audit prune --through 1000000 --archive ./a.jsonl --jwks jwks.json
attenuo audit prune --before 2026-08-01T00:00:00Z --dry-run
```

1. `GET /admin/audit/prune/plan?before=...` (or `?through=...`): the server answers `{from, through, entries, checkpoint, at, guards}`, where `through` is the largest B the guards allow at or below the request and `guards` says which one limited it. `--dry-run` prints this and stops.
2. Export `from ..= through` to `--archive` (refusing to overwrite an existing file).
3. Verify the file strictly with the JWKS (`--jwks`, else `GET /.well-known/jwks.json`). Stop if it does not pass.
4. Compute the SHA-256 of the file's bytes.
5. `POST /admin/audit/prune {"through": B, "archive_sha256": "..."}`.
6. Print the prune record's seq, the anchor, both checkpoints, whether the sink has delivered them, and that the rows are being deleted.

The server never sees the archive. `archive_sha256` is the operator's statement, signed into the anchor so that a later reader can check that the archive they hold is the one named; the server cannot check that the file was kept, or kept off the host.

### 6.2 Admin routes

| Route | Answer |
| --- | --- |
| `GET /admin/audit/prune/plan?before=` or `?through=` | 200 the plan; 409 `prune_disabled` |
| `POST /admin/audit/prune` `{through, archive_sha256}` | 200 `{prune_seq, anchor, checkpoint_before, checkpoint_after, pruned_through, deleting, shipped}`. Repeating the same request after it succeeded answers 200 with the existing anchor and `"already": true`; the same `through` with another digest is 409. 409 `prune_disabled`, `prune_not_at_checkpoint`, `prune_too_recent`, `prune_live_run`, `sink_behind`, `prune_in_progress`; 400 for a malformed body |
| `GET /admin/audit/anchors` | the anchors, newest first, paged like `/admin/audit/checkpoints` |

### 6.3 Configuration

```toml
[audit.retention]
prune = "off"              # "off" (default) | "manual" | "auto" (phase 2)
min_age_seconds = 7776000  # 90 days; nothing younger is pruned
batch_rows = 10000         # rows per delete transaction
# phase 2, prune = "auto" only:
# keep_seconds = 15552000      # prune what is older than this, daily
# archive_dir = "/mnt/archive" # the server writes the archive here first
```

Start-up refuses `prune` other than `"off"` with `sqlite_path = ":memory:"`, a `min_age_seconds` below the run-state retentions (section 4.3), and (proposed, open question 2) without `[audit.sink]`. "Explicitly none" is the default: with `prune = "off"` nothing changes and the documents' "the audit log is never pruned" stays true.

### 6.4 Size guidance

Not measured. No committed bench file records the database size or the bytes per entry: the files under `docs/design/bench/` measure latency and, in `2026-10-23-vm-wal-backstop.md`, the size of the WAL, not of the database. Per entry the file stores `record_json` (canonical JSON of the record), the denormalized columns and seven index entries (`schema.rs:12-37`, `216-220`); records with `labels`, `budget` or `usage` are larger than plain decisions. Phase 1 should add a bench that appends N records of each kind and reads `PRAGMA page_count` and `page_size`, and a gauge `audit_db_size_bytes` (page count times page size, with the free-list size beside it) so that operators measure their own rate.

## 7. Failure modes

- **Crash during the CLI's export or verify.** Nothing has changed on the server. Run the command again; a partial archive file is refused by the verify step.
- **Crash during the prune transaction (step 1).** It rolls back entirely: no record, no anchor, no checkpoint. The log is as it was.
- **Crash after the commit, before the CLI gets the answer.** The plan route now reports the anchor; repeating the same `POST` answers with it (`"already": true`).
- **Crash between delete batches.** The anchor is in `state = 'deleting'`; every read already starts at B + 1; the maintenance ticker resumes the deletes after restart. A second prune is refused until the first is done.
- **WAL.** Each delete batch writes the pages it frees and every index page it touches to the WAL. Batches bound what one commit adds; the background WAL checkpointer and the writer's backstop (`WAL_WRITER_BACKSTOP_FRAMES`, `crates/attenuo-audit/src/sqlite/wal.rs:43`) keep the WAL bounded as for appends. The batch size that keeps both the WAL and the pause short is not measured.
- **The write gate and appends.** Each batch holds the gate, so appends wait for it. An append waits at most `[audit] append_timeout_seconds` (10 s) to be taken; a batch must stay far below that, or appends are denied with `audit_error`. The default `batch_rows` must come from a measurement (not done).
- **Single-writer fence.** The prune runs in the server that holds the fence; no second process takes part. A read transaction held open by an outside `sqlite3` keeps the WAL from being checkpointed, as it does today.
- **Sink behind or down.** The prune is refused while the sink is degraded or has not delivered a checkpoint at or after B. After the prune, if the sink fails to deliver the anchor and checkpoints, the answer says `shipped: false` and `/readyz` reports the sink degraded as usual.
- **Restoring a backup taken before a prune.** The rows come back and the anchor is gone; the log verifies from genesis. The shipped anchor, newer than the backup, shows the rewind, as shipped checkpoints do for any restore.
- **Space.** The file stops growing once pruning keeps pace, but does not shrink. Shrinking needs `VACUUM`, which rewrites the file and holds the write lock for the whole run; it is deferred (section 9).

## 8. Schema migration

Migration 4, appended to `MIGRATIONS` with `SCHEMA_VERSION = 4`, plain DDL against version 3 (version 3 is the credential replay table) (no `IF NOT EXISTS`), per the rules in `migrations.rs:27-31`:

```sql
CREATE TABLE audit_anchors (
    through_seq          INTEGER PRIMARY KEY,
    through_hash         TEXT    NOT NULL,
    prune_seq            INTEGER NOT NULL UNIQUE,
    prune_entry_hash     TEXT    NOT NULL,
    previous_through_seq INTEGER NULL,
    archive_sha256       TEXT    NULL,
    at                   TEXT    NOT NULL,
    kid                  TEXT    NOT NULL,
    signature            TEXT    NOT NULL,
    state                TEXT    NOT NULL  -- 'deleting' | 'done'
);
```

No existing row changes, so the chain and its checkpoints are untouched. Every file the new binary opens migrates, pruned or not, so a binary from before refuses it (`SchemaTooNew`) and cannot report a pruned log as broken; going back needs the backup taken before the upgrade, as for every migration ([deploying](../guides/deploying.md#the-database-schema)). The test builds a version 2 file with entries and checkpoints, migrates it, and checks the chain, the checkpoints and that the new table is empty.

## 9. Deferred, and open questions

Deferred:

- Automatic retention (`prune = "auto"`): the server writes the archive to `archive_dir`, verifies it, and prunes on a timer. Needs a decision on where the archive goes and how the server knows it left the host.
- Shrinking the file (`VACUUM`, or `auto_vacuum = INCREMENTAL`, which can only be turned on for an existing file by a `VACUUM`). Until then: stop the server and run `sqlite3 attenuo.sqlite 'VACUUM'` (untested here).
- Rotation to a file per period (option (b) of the ADR).
- The admin console showing the anchor and the first retained seq.
- SDK support: the Python and TypeScript verifiers learning the anchor, the header member and the multi-file link.

Open questions for the owner:

1. Default `min_age_seconds`. 90 days is a placeholder; record-keeping rules usually set it, and the floor from run-state retention is 37 days with today's defaults.
2. Whether `prune = "manual"` requires `[audit.sink]`. Without it the anchor never leaves the host, and an attacker who holds the host can make a prune that nothing off the host contradicts.
3. Whether the server should hold back the prune until the operator proves the archive left the host (for example by echoing a shipped copy), or whether the signed digest is enough.
4. Whether `GET /admin/audit/records/{id}` for an id older than the boundary should keep a small index of pruned record ids (id to seq), so it can answer 410 instead of 404. That keeps a few dozen bytes per pruned record forever.
5. Whether pruning should also drop the checkpoints below B (proposed) or keep them, which costs little and lets `GET /admin/audit/checkpoints` show the full history.
6. Whether the anchor should be its own shipped format (`attenuo-shipped-anchor-v1`) or a new line type in the existing shipped file.

## 10. Test plan

Unit and store tests (`attenuo-audit`):

- A prefix deleted through `with_connection` without an anchor: verify reports `ok: false` at the first retained seq (pins today's behaviour as the attack case).
- A forged anchor row with a genuine copied checkpoint and a bad or missing signature: `bad_anchors` names it and the chain is reported broken.
- A genuine anchor, then one more row deleted after `through_seq + 1`: broken chain at that seq.
- A prune through B: verify passes with `pruned_through = B`; the next append gets `head + 1`; the anchor names P and P's hash; checkpoints at H and P exist.
- `head_link` on an empty table with an anchor continues from the anchor, not from 1.
- Guards: not at a checkpoint, too recent, a live chain below B, a degraded sink, a prune already in progress; each refused with its code and nothing written.
- Crash points: fail the transaction at each of its six steps (probe like `probe_commit`) and check the log is unchanged; stop between delete batches, reopen, and check reads start at B + 1, the deletes resume and the anchor reaches `done`.
- Two prunes in a row: the second anchor's `previous_through_seq` is the first's `through_seq`; the two archives and the retained export link.
- Export: `from <= B` answers `audit_pruned`; `from = B + 1` carries the anchor and verifies with `from_anchor`; the archive `first ..= B` verifies strictly with no unsigned tail.
- Cross-check: a shipped checkpoint below the export's range is counted; with an anchor, a shipped checkpoint at B that differs from the anchor's is a mismatch.
- Migration 4 on a version 3 file with rows in every table.

Server and CLI tests:

- `prune = "off"`: both routes answer `prune_disabled`.
- Start-up refusals: `:memory:`, `min_age_seconds` below the run-state retentions.
- An end-to-end prune through the CLI against a running server with a file sink: archive written and verified, prune committed, shipped file holds both checkpoints and the anchor, `audit verify` passes, `audit verify --file archive --file retained` passes, and flipping one byte in either file is reported at the same seq by the Rust CLI (and, once they learn the anchor, the SDKs).
- Concurrent appends during a prune: every append either lands before H or after P, none is lost or denied under the default batch size (with the batch size taken from the measurement above).
- Refund of a decision whose charge and record were both pruned: 404 naming the boundary.
- `GET /admin/audit/entries/{seq}` for a pruned seq: 410 `audit_pruned`; `GET /admin/audit` with a cursor below the boundary resumes at B + 1.

## 11. As built

Phase 1a, 2026-11-22: the server and the store. The owner's answers to the open questions: 90 days for `min_age_seconds` (1); `prune = "manual"` requires `[audit.sink]` (2); the signed digest is enough (3); no index of pruned record ids, so a pruned id is a 404 whose message names the boundary (4); the checkpoints below B are dropped with the last delete batch (5). For (6) the anchor has its own envelope, `attenuo-shipped-anchor-v1`, sent through the same sink: in a file sink it is one more line of the same file, told apart by its `anchor` member. The shipped file's lines carry no type tag (a checkpoint line is recognised by its members), and an older `parse_shipped` errors on a line it cannot read, so a new line type in the checkpoint format would break older readers anyway; a separate format at least names itself, and `parse_shipped` now skips anchor lines. An older CLI's `--checkpoints` cross-check still errors on a file that holds an anchor line, which only happens once a prune was made. In S3 it is its own object, `<prefix>anchor-<through_seq>-<sha16>.json`.

What was built, against section 4:

- Schema version 5 adds `audit_anchors` as in section 8, with `state` `deleting` or `done`.
- The anchor is signed under `attenuo-audit-anchor-v1` next to the checkpoint signing (`Anchor` in `crates/attenuo-audit/src/checkpoint.rs`). The prune record is an `admin` record of tool `admin.audit.prune` whose arguments are `{through_seq, through_hash, previous_through_seq, archive_sha256}`, built as `audit_admin` builds its record.
- `SqliteAudit::prune_through` writes the "before" checkpoint, the prune record, the anchor, the "after" checkpoint and the anchor row in one `IMMEDIATE` transaction with `synchronous=FULL`; the hooks fire after the commit, so the sink queues both checkpoints and the anchor. `prune_step` deletes `batch_rows` rows per transaction; the maintenance ticker runs it, also when `prune` was turned off after a prune, and a restart resumes it.
- Every read clamps to the newest anchor in SQL, so a prune is visible to reads as soon as it commits. `head_link` on an empty table falls back to the anchor's prune record. Verify walks from the newest anchor (`Start::Anchored`) and reports `pruned_through`, `anchors` and `bad_anchors`; an older anchor is checked for its signature and its `previous_through_seq` link only, since its checkpoint and record may be gone.
- The guards are checked in this order: already pruned (410 `audit_pruned`), a prune still deleting (`prune_in_progress`), the checkpoint at B and its hash (`prune_not_at_checkpoint`), the age of the entry at B (`prune_too_recent`), the first record of a chain whose root lease is still in the registry (`prune_live_run`), and the sink (`sink_behind`: degraded, or `delivered_through` below B, counted from the server's start). One code was added to the design's list: `prune_conflict` (409) for the same `through` with another `archive_sha256`.
- The routes of section 6.2 are admin role only, and not on the console listener. `GET /admin/audit` gained `first`; the export defaults `from` to B + 1 and puts the anchor in its header from there, and the CLI `audit export` no longer sends `from=1` by default.
- Metrics: `audit_pruned_entries_total`, and the gauges `audit_db_size_bytes` and `audit_db_free_bytes`, read at a scrape only when the store's reader is free.
- Measured: one delete batch of 10000 rows on a 200,000-row file (266 MB) took 0.33 to 0.38 s in a release build (1000 rows about 0.06 s, 20000 rows 0.36 to 0.53 s), far below the 10 s append timeout, so `batch_rows` stays 10000. The test is `measure_a_delete_batch` in `crates/attenuo-audit/tests/retention.rs` (ignored by default).

Not built yet: the CLI `attenuo audit prune`, `audit verify` over several files, the SDK verifiers' knowledge of the anchor (they read the header and ignore the member, so a retained export verifies there as a window), the console, `prune = "auto"` and `VACUUM`.


---
status: accepted (2026-11-22)
date: 2026-11-13
decision-makers: []
consulted: []
informed: []
---

# ADR-0015. Audit retention: archive a prefix of the log at a signed checkpoint, prune it in the server behind a signed anchor, off by default

## Context and Problem Statement

The audit log is one table, `audit`, in the same SQLite file as the lease registry (`[audit] sqlite_path`). Nothing ever deletes a row from it, so the file grows for as long as the server takes traffic (audit finding O-4). The run-state tables already have retention (`[leases] retention_seconds`, `run_state_retention_seconds`, `user_window_retention_seconds`); the log does not, and several documents say so as a guarantee ("the audit log, which is not pruned", in the threat model's lease-retention entry). How can an operator bound the log's size without losing the property the log exists for: that anyone holding the issuer's JWKS can tell a complete, unaltered record from one that was cut or rewritten?

The details, each checked against the code at `7493efb`, are in the design note [audit retention](../design/audit-retention.md). This record keeps the decision and the reasons.

## Decision Drivers

- A pruned log must still verify: the retained entries from a signed starting point to the head, and the removed prefix on its own, offline, from an export file and the JWKS, as today.
- A third party must be able to tell a prune the operator made from a truncation by someone who can write the file. Where they cannot (an attacker who holds the server process and its key), the documentation must say so.
- A `seq` is never given twice, and every cursor, `from`/`to` range and stored reference to a `seq` or a decision id keeps one meaning after a prune.
- Nothing the enforcement path reads may disappear. Today the pipeline never reads the `audit` table; some admin routes do, and they must answer truthfully after a prune.
- No change for a deployment that does not opt in: no new behaviour, no new default deletion.
- Work within one server process per file (the single-writer fence), the existing migration mechanism, and the existing export, checkpoint and sink formats where they suffice.

## Considered Options

- (a) Archive and prune in place: export the prefix `first..=B` up to a signed checkpoint at `B`, then delete it from the file, leaving a signed anchor that says the log now starts at `B + 1` and names the checkpoint, the prune record and the archive's digest.
- (b) Rotate: start a new database file per period, linked to the previous one by a cross-file chain link, and delete old files.
- (c) No prune: document external archival (periodic exports), size guidance and the cut-over to a new file.

## Decision Outcome

Chosen: (a), as a manual, admin-only operation in phase 1 (`POST /admin/audit/prune`, driven by `attenuo audit prune`), refused unless `[audit.retention] prune` is set to `"manual"` in the config. Automatic retention is deferred to phase 2 behind the same switch (`"auto"`); the default is `"off"`.

- **Why (a).** It is the only option that keeps one file, one store and one query surface. Every existing read (`GET /admin/audit`, cursors, export, verify, record lookups) keeps working on the retained entries with one more lower bound. The archive is an ordinary `attenuo-audit-export-v2` file, which every verifier (CLI, Python, TypeScript) already checks. The chain needs no new hash construction: an export window that does not start at seq 1 already verifies from its first entry ([`Start::Window`](../design/audit-retention.md#3-what-the-code-does-today)), and a checkpoint at `B` already proves the prefix `1..=B`.
- **Why a signed anchor.** The retained log starting at `B + 1` looks exactly like a log whose prefix an attacker deleted. A checkpoint at `B` does not help on its own, because it is already in the file for anyone to copy into an unsigned "anchor" row, and an entry appended to the log (a fake prune record) is covered by the next checkpoint the server signs on its timer. Only an object that the server signs at prune time, over `B`, the hash at `B`, the prune record's `seq` and the archive digest, under a context string of its own (`attenuo-audit-anchor-v1`), separates a prune made through the server from one made with file access. The anchor is shipped through `[audit.sink]` like a checkpoint.
- **Why in the server.** One process owns the file (the fence), the CLI never opens the database, and the writer thread and the write gate already serialise every write to it. A prune is one more writer, so it goes through them.
- **Why off by default and admin only.** A prune destroys evidence on the host. Requiring a config switch as well as the admin token means that whoever steals the admin token still cannot prune without also changing the config file and restarting.
- **Why not (b).** The log shares its file with the lease registry, the run-state tables and the notice outbox, and the fence, the backup procedure, the migrations and `append_synced` all assume one file. Rotation either copies live state into each new file or splits the audit log into a file of its own, and then still needs the same signed cross-file link that (a) needs. It reclaims space immediately (delete a file), which (a) does not without `VACUUM`; that is its one real advantage, and it is not worth the split.
- **Why not (c).** It is what operators have today, and the only bound it offers is to stop the server and start on a new file, which also drops every lease (every token is then `lease_unknown`) and starts a second chain at seq 1 with nothing linking the two.

### Consequences

- Good, because the file can be kept to a bounded number of entries, with the removed entries still verifiable from the archive and the retained ones verifiable from a signed starting point.
- Good, because an attacker with write access to the file but not the issuer key can no longer pass a cut prefix off as anything but a break: verify reports a broken chain at the first retained seq unless a valid anchor names it.
- Bad, because an attacker who holds the server process (and so the key) can make a prune that verifies, as they can already sign a rewritten history; only copies that left the host (shipped checkpoints and anchors, the archive kept elsewhere) and the operator's own record of when they pruned show it.
- Bad, because a prune by a legitimate admin destroys the entries on the host. If the archive is lost, the record of what was in it is gone; the anchor and shipped checkpoints prove only that a prefix of a stated length and hash existed.
- Bad, because `DELETE` does not shrink a SQLite file: freed pages are reused for new rows, so the file stops growing once pruning keeps pace, but it does not get smaller without `VACUUM`, which rewrites the whole file while holding the write lock. Shrinking is deferred.
- Bad, because answers that read old records change: a refund of a decision whose record was pruned can no longer be told apart from an unknown decision (today's 410 `charge_pruned` versus 404), and `GET /admin/audit/entries/{seq}` for a pruned seq answers 410 `audit_pruned` instead of the entry. The age guard (below) makes this happen only after run state is gone anyway.
- Neutral, because the schema goes to version 4 (one new table, `audit_anchors`), so a binary from before this change refuses the file, as for every migration; that also keeps an old binary from reporting a pruned log as broken. (Note, 2026-11-22: as built it is version 5, since version 4 was taken by another change first.)
- Neutral, because statements that the audit log is never pruned (threat model, configuration reference, concepts page) stay true while `prune = "off"` and must say "unless pruned" once this is built.

### Confirmation

Written for phase 1a (the server and the store), from the design note's [test plan](../design/audit-retention.md#10-test-plan), in `crates/attenuo-audit/tests/retention.rs` and `crates/attenuo-server/tests/audit_retention.rs`. The security-relevant ones: a prefix deleted through `with_connection` without an anchor reports a broken chain at the first retained seq (`a_prefix_deleted_without_an_anchor_is_a_broken_chain_at_the_first_retained_seq`); a hand-written anchor row with a copied checkpoint and no valid anchor signature fails (`a_forged_anchor_row_with_a_copied_checkpoint_fails`, and `an_anchor_by_another_key_fails`); a valid anchor with one more row deleted after `B + 1` fails (`a_genuine_anchor_then_one_more_row_deleted_fails`); a crash at each step of the prune leaves the old log, and a stop between delete batches leaves the anchored log, never a third state (`a_crash_at_each_step_of_the_transaction_leaves_the_old_log`, `a_stop_between_delete_batches_resumes_after_reopen`); the archive and the retained export each verify strictly, and they link (`two_prunes_in_a_row_link_and_their_archives_verify`). Checking the pair as one chain in one command waits for the multi-file `audit verify`, which is not built; the test checks the link itself.

## Pros and Cons of the Options

### (a) Archive and prune at a signed checkpoint, with a signed anchor

- Good, because it reuses the export format, the checkpoint construction, the sink, the migration list and every read route.
- Good, because the prune is one short transaction plus batched deletes that can resume after a crash.
- Bad, because it adds a signed construction (`attenuo-audit-anchor-v1`) and a shipped line type that every verifier must learn.
- Bad, because space is reused, not returned, until a `VACUUM`.

### (b) Rotate to a new database file per period

- Good, because dropping a period frees its space at once and the archive is the file itself.
- Bad, because the lease registry and run state live in the same file; rotation means a split store or copying live state each period.
- Bad, because queries, record-id lookups and exports span files, and the cross-file link needs the same signed anchor as (a).
- Bad, because the CLI cannot read a database file today (`audit verify` reads the admin API or an export), so the "archive is the file" advantage needs new tooling to verify.

### (c) No prune; document external archival and size guidance

- Good, because there is no code and no new trust question.
- Bad, because the file still grows without bound, and the only remedy is a cut-over that loses every lease and starts an unlinked chain.

## More Information

Design note with the code facts, the operator interface, failure modes, the migration and the test plan: [audit retention](../design/audit-retention.md). Related: [ADR-0006](0006-lease-based-in-flight-revocation.md) (leases, whose retention bounds the prune), [ADR-0010](0010-run-limits.md) (refunds read the decision's record), the [audit log](../concepts/audit-log.md) page, [`[audit.sink]`](../reference/config.md#auditsink), [multi-replica readiness](../design/multi-replica.md) (one process per file is assumed throughout).

### Update 2026-11-22: phase 2, the automatic prune

The decision above stands and is kept as written. Phase 2, automatic retention behind `prune = "auto"`, is now built. It was deferred on one open question: where the archive goes, and how the server knows it left the host. The answer has two parts: the sink proves what was pruned, and an optional `archive_dir` keeps what it said.

- **The sink proves what was pruned.** Every prune already needs `[audit.sink]`. The server prunes only what the sink has delivered: a checkpoint at or past the boundary, delivered since the server started, and the anchor of the prune before. These are the guards of a manual prune, run by the same code.
- **`archive_dir` keeps the records.** The sink holds checkpoints and anchors, not records. So with `archive_dir` set, each automatic prune first writes the entries it removes into that directory, as the export file `attenuo audit export` writes (`audit-<from>-<through>.jsonl`). It writes a temporary file, flushes it, links it into place, flushes the directory, reads the file back and verifies it. Only then does it prune, and the anchor carries the file's SHA-256 in `archive_sha256`, as a manual prune with an archive does. A file of that name is never replaced: one that passes the same check, and whose bytes are the export of the range made again with its own `exported_at` (which must be a time in the form the server writes), is used, and its own digest is signed; any other fails the run. Any error means no prune. The shipped anchors name the real archives; a file in `archive_dir` that matches no anchor is not part of the log.
- **The archive stays on the host.** The server does not move it. The operator copies `archive_dir` off the host and deletes old files by their own policy. Someone who controls the host can delete the files. What proves that a kept copy is the real one is the SHA-256 in the shipped anchor.
- **Without `archive_dir`.** The records are deleted and no copy is kept, and the server logs a warning at start that says so. The shipped objects then prove that a prefix of a given length and last hash existed and was pruned at a given time. They do not hold what it said. An operator who must keep the records sets `archive_dir`, or exports them on a schedule of their own.
- **How it runs.** Every `interval_seconds` (default an hour) the server plans as `GET /admin/audit/prune/plan` does, with `keep_seconds` as the age floor (required; at least `min_age_seconds` and a day), at most `max_entries_per_run` entries (default a million). It then verifies the rows it would remove with the signed verify of `GET /admin/audit/verify`, stopped at the boundary, writes and checks the archive when `archive_dir` is set, and prunes through the same transaction as `POST /admin/audit/prune`, which checks the guards again. Any doubt (a guard, a verify that fails, an archive that cannot be written or checked, another prune in between) means no prune.
- **The clock.** A manual prune had a person in the loop; the automatic one trusts the host's clock, and a clock pushed far ahead would make almost everything look old. So the cutoff of a run is `keep_seconds` before the earliest of now, the newest entry that is not a prune record, and the wall time at start plus the monotonic time since. Inside one process, a clock jump cannot speed pruning up: the cutoff moves at most as fast as the monotonic clock, with or without new entries. Across a restart the server cannot tell a jumped clock from real downtime, so after a restart with a wrong clock the cutoff starts from the wrong time. Entries written while the clock was behind carry old timestamps, and once the clock is set right they can be pruned early by up to that error. On an idle server the last `keep_seconds` before the newest entry are kept. `archive_dir` is what protects the content. A run is also skipped (`clock_jump`) when the wall clock moved more than an hour away from the monotonic clock since the last run, forward or back. That is the visible signal; the cutoff does not depend on it. The deploying guide recommends `archive_dir`.
- **How it is recorded.** The same prune record, checkpoints and anchor as a manual prune. The record's subject is `urn:attenuo:retention`, which no operator can have. Verifiers needed no change.
- **Manual and automatic together.** `"auto"` also allows the manual routes. The two cannot both commit, because the prune transaction holds the writer and the write gate and its guards refuse the second.
- **Trust.** The consequence "only copies that left the host ... and the operator's own record of when they pruned show it" weakens with `"auto"`: the operator no longer makes each prune, so a prune made with a stolen key looks like one the timer made. The shipped anchors, with their times, boundaries and archive digests, remain the record.
- **Confirmation.** `crates/attenuo-server/tests/audit_auto_prune.rs`, `an_automatic_prune_and_a_restart_keep_the_files_verifiable_as_one_log` and `two_automatic_prunes_with_archive_dir_leave_files_that_verify_as_one_log` in `crates/attenuo-cli/tests/audit_prune.rs`, and `the_prefix_verify_sees_the_prefix_only` and `an_export_written_by_the_store_verifies_from_the_file` in `crates/attenuo-audit/tests/retention.rs`. The details are in the design note's [As built](../design/audit-retention.md#11-as-built), phase 2.

Not done: shrinking the file in the running server. (Update 2026-11-22: `attenuo audit compact` shrinks it offline, with the server stopped; see the design note's [As built](../design/audit-retention.md#11-as-built), "Compacting".)

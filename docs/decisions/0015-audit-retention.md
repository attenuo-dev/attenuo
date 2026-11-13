---
status: proposed
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
- Neutral, because the schema goes to version 3 (one new table, `audit_anchors`), so a binary from before this change refuses the file, as for every migration; that also keeps an old binary from reporting a pruned log as broken.
- Neutral, because statements that the audit log is never pruned (threat model, configuration reference, concepts page) stay true while `prune = "off"` and must say "unless pruned" once this is built.

### Confirmation

Planned, not written: the tests listed in the design note's [test plan](../design/audit-retention.md#10-test-plan). The security-relevant ones are: a prefix deleted through `with_connection` without an anchor reports a broken chain at the first retained seq; a hand-written anchor row with a copied checkpoint and no valid anchor signature fails; a valid anchor with one more row deleted after `B + 1` fails; a crash at each step of the prune leaves either the old log or the anchored log, never a third state; the archive and the retained export each verify strictly, and the pair verifies as one chain.

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

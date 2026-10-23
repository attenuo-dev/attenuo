# Audit log

onbehalf writes one record for every decision it makes. The records are chained by hash, so changing or removing one is detectable.

## What gets a record

- Every `tools/call` decision, allow or deny. The proxy also treats `resources/read`, `prompts/get` and a few other methods as calls, so they are recorded too.
- Every AuthZEN evaluation.
- Every token issued, at hop 0 and at each exchange.
- Every successful lease renewal.

Requests that carry no decision, such as `tools/list` and `ping`, are not recorded. Failed exchanges and failed renewals are not recorded either in v0.

## What a record holds

A record names the agent chain and the originating user separately. That is the point: most logs cannot tell an agent action from a user action. A record also has:

- a decision id, which the client sees in the `X-Onbehalf-Decision-Id` header or in the error data of a denial,
- the time, and allow or deny,
- a reason code such as `policy_allow`, `capability_denied` or `lease_revoked`,
- the chain depth, a digest of the chain, and the lease ids,
- the server and tool,
- a digest of the arguments,
- the session id and the ids of the policies that decided.

The log stores a digest of the arguments, not the arguments. Secrets and personal data in tool inputs do not end up in the log.

Issuance and renewal use the same record shape. They have `server` set to `onbehalf` and the tool set to `token.root`, `token.exchange` or `lease.renew`.

## The hash chain

Entries are stored in SQLite as `{seq, prev_hash, record, entry_hash}`. The entry hash is SHA-256 over the RFC 8785 canonical JSON of the array `["onbehalf-audit-entry-v2", seq, prev_hash, record]`. Canonical JSON sorts object members and fixes how strings and numbers are written, so the hash depends only on the values: any RFC 8785 implementation, in any language, gets the same bytes. The first entry uses a fixed genesis value for `prev_hash`.

The `v2` in the tag is the hash construction. Logs written before it (plain `serde_json` output, no tag) are refused when the database is opened, with an error that says to start a new file. There is no migration: no logs were released in the old form.

Change a byte in a record and its hash no longer matches. Delete a row in the middle and the next row points at the wrong parent. Reorder rows and the links break. Tests cover each of these cases.

## Failing closed

The audit append is part of the decision. If the log cannot be written, the decision becomes a deny with the reason `audit_error`. An action that cannot be recorded does not happen. The same goes for issuance: if the append fails, the new lease is revoked, so an unrecorded token is unusable.

## Signed checkpoints

A hash chain alone cannot show that the newest entries were deleted, or that someone with write access rebuilt the whole chain. Checkpoints close that gap. A checkpoint is `{seq, head_hash, at, kid, signature}`: the issuer's Ed25519 key signs the head of the chain, under the context string `onbehalf-checkpoint-v1` so the signature is good for nothing else.

- One is written every `[audit] checkpoint_every` entries (default 1000), in the same transaction as the append that reaches it.
- The commit that writes a checkpoint is synced to disk (`synchronous=FULL`) even at `durability = "normal"`, and only then does the checkpoint go to the code that ships it elsewhere. A power failure cannot take back entries that a shipped checkpoint covers.
- One is written every `[audit] checkpoint_interval_seconds` (default 300) if entries arrived since the last one, so the tail of a quiet log is covered too. Whichever trigger fires first wins.
- `GET /admin/audit/checkpoint` signs the current head on demand and returns it. Copy that somewhere the host cannot write.

Verification needs only the public keys the server already publishes at `/.well-known/jwks.json`. A checkpoint fails if its signature is bad, if its `kid` is not in the JWKS, if the entry hash at its `seq` differs from `head_hash` (history was rewritten, even with every later hash recomputed), or if the log is now shorter than its `seq` (truncation). After a key rotation, old checkpoints keep verifying as long as the retired key stays in `[issuer] previous_key_paths`.

What it does not give you: the signing key lives on the same server. Someone who controls the server process can sign a rewritten history. Checkpoints you copied off the host before the compromise still catch it.

## Reading and verifying

- `onbehalf audit tail` shows recent entries. `--follow` keeps polling.
- `onbehalf audit verify` walks the whole chain, checks the checkpoint signatures, and prints the last signed `seq` and how many entries come after it. It exits 2 if the chain is broken or a checkpoint is invalid.
- `onbehalf audit export --from 100 --to 200 --format jsonl` writes a slice of the log with the checkpoints inside it, one canonical JSON object per line, after a header that declares the range (format `onbehalf-audit-export-v2`). `onbehalf audit verify --file export.jsonl --jwks jwks.json` checks that file on any machine, with no admin token and no access to the server: it re-hashes every entry, checks the links, verifies each checkpoint signature and compares its head hash to the entry at that `seq`.
- That check is strict. It fails a file that starts or ends short of the range in its header (truncated), a file that holds entries outside that range, and a file with entries after its last valid checkpoint. Such entries are covered by the hash chain only, and anyone who can write the file can append them. To check an export taken while the log was ahead of its newest checkpoint, pass `--allow-unsigned-tail`; the report still says how many entries are unsigned. Or sign the head first (`GET /admin/audit/checkpoint`) and export up to it.
- `GET /admin/audit`, `/admin/audit/verify`, `/admin/audit/checkpoint` and `/admin/audit/export` are the matching admin endpoints.

## What the chain does not prove

Entries after the last checkpoint are protected by the hash chain only, and the verify report says how many there are (`unsigned_tail`). A signed checkpoint proves what the log looked like when it was signed, not that nothing was deleted afterwards unless you hold a copy of it from somewhere else.


## Not built yet, or uncertain

The RFC describes a `kind` field (`issue`, `decision`, `renew`, `revoke`, `checkpoint`) and a `chain_id`. Neither exists in the code. Checkpoints live in their own table, not as chain entries.

Revocations, policy reloads and dev root mints are appended to the log as admin actions (reason `admin_action`, server `onbehalf`, subject `urn:onbehalf:admin`, which no user can have). To pick out server events, filter on `server = "onbehalf"` and the tool (`token.*`, `lease.renew`, `admin.*`); no upstream or agent can use the name `onbehalf`. The revoke response carries the `audit_id` of that record, or says that the append failed.

More detail: [RFC-0001 section 7](../spec/rfc-0001-onbehalf.md#7-audit-record-and-hash-chaining) and [design/server.md](../design/server.md#audit-convention-for-issuance).

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

Entries are stored in SQLite as `{seq, prev_hash, record, entry_hash}`. The entry hash is SHA-256 over the sequence number, the previous hash and the record. The first entry uses a fixed genesis value for `prev_hash`.

Change a byte in a record and its hash no longer matches. Delete a row in the middle and the next row points at the wrong parent. Reorder rows and the links break. Tests cover each of these cases.

## Failing closed

The audit append is part of the decision. If the log cannot be written, the decision becomes a deny with the reason `audit_error`. An action that cannot be recorded does not happen. The same goes for issuance: if the append fails, the new lease is revoked, so an unrecorded token is unusable.

## Reading and verifying

- `onbehalf audit tail` shows recent entries. `--follow` keeps polling.
- `onbehalf audit verify` walks the whole chain and exits 1 if it is broken.
- `GET /admin/audit`, `/admin/audit/verify` and `/admin/audit/checkpoint` are the matching admin endpoints.

## What the chain does not prove

A hash chain on its own cannot show that the newest entries were deleted. Someone with write access to the file can cut the tail, or rebuild the whole chain. To detect truncation you need to keep the head, which is `{seq, hash}` from the checkpoint endpoint, somewhere the host cannot reach. Compare it later. onbehalf does not emit or sign checkpoints on a schedule yet. The [deploying guide](../guides/deploying.md#sqlite-file-placement-and-backup) says how to handle this by hand.

Also, the hash covers compact JSON with sorted keys. It is not yet RFC 8785 canonical form. The RFC names that as the target.

## Not built yet, or uncertain

The RFC describes a `kind` field (`issue`, `decision`, `renew`, `revoke`, `checkpoint`), signed checkpoints and a `chain_id`. None exist in the code.

The RFC also says revocations are appended to the log. The admin revoke handler does not appear to write an audit entry in v0. Treat revocation as unaudited until you have checked the code for your version.

More detail: [RFC-0001 section 7](../spec/rfc-0001-onbehalf.md#7-audit-record-and-hash-chaining) and [design/server.md](../design/server.md#audit-convention-for-issuance).

# Audit log

attenuo writes one record for every decision it makes. The records are chained by hash, so changing or removing one is detectable.

## What gets a record

- Every `tools/call` decision, allow or deny. The proxy also treats `resources/read`, `prompts/get` and a few other methods as calls, so they are recorded too.
- The upstream's answer to every allowed `tools/call`, `resources/read`, `prompts/get` and `completion/complete`, as a `tool_result` record (a digest, not the content).
- Every AuthZEN evaluation.
- Every token issued, at hop 0 and at each exchange.
- Every successful lease renewal.
- Every approval opened for a gated call, and every grant or decline of one.

Requests that carry no decision, such as `tools/list` and `ping`, are not recorded while the token's leases are live. When they are not, the refusal is a `deny` record with the lease reason (`lease_revoked`, ...) and `tool` set to the method (`initialize`, `tools/list`, or `http.POST`, `http.GET`, `http.DELETE`), so an agent that keeps opening sessions after a revocation shows up. These refusals are bounded: the first per delegation chain, tool and reason within the record window (`[proxy] record_window_seconds`, default 60 s) is recorded, and a retry within that window is still refused (its 401 names the first record) but is only logged and counted in `audit_records_suppressed_total{tool,reason}`. One such record can therefore stand for many refused requests of that chain in the following window; the count is in the metric only. An agent that keeps retrying leaves one record per tool per window (a minute by default). When the proxy ends an open response stream (a `GET` listen stream, or a streamed answer) because the leases are no longer live or the token expired, that is one `deny` record with `tool` `stream.end`, the reason (`lease_revoked`, `token_expired`, ...) and the session's hash tag in `session_id`; the stream's last event carries its id as `data.decision_id`. Only the proxy speaks in that shape (`id: null`, error `-32001`): an upstream message of the same shape, in a stream or a plain JSON answer, reaches the client rewritten as error `-32005` with `data.reason` `upstream_stream_end_shape` and the upstream's error under `data.upstream_error`, so a decision id at `data.decision_id` of a `-32001` always names a record. On the `GET` listen stream these records are bounded: at most one per delegation chain and reason per record window (the same `record_window_seconds`, default 60 s), and it is the first, so the log shows when the condition began. Further listen streams of that chain ended for that reason within the window end the same way (their last event names the window's record) but are not recorded: the proxy logs them and counts them in the metric `audit_records_suppressed_total{tool="stream.end",reason}`. One listen-stream `stream.end` record can therefore stand for many streams; it names the server and session of the first, and has no field for the count, which only the metric holds. Nothing else is bounded this way: every tool-call decision, the `stream.end` of a streamed answer, every refused exchange or renewal and every other refusal is recorded each time. A stream the client drops or the upstream ends leaves no record, so a session with a `stream.end` record was cut by attenuo (or shares its chain's record of that window) and one without was not (`attenuo audit tail --tool stream.end`). An operator who wants to see those endings has the metric `proxy_streams_ended_total{cause}` (`client_disconnect`, `upstream_eof`, `upstream_error`, and the re-check causes such as `token_expired`) and the proxy's log lines, which carry the server, the session's hash tag, the subject and the `chain_id` to match against the session's records. A token that does not verify is never recorded. A refused token exchange is a `deny` record when its subject token verified: tool `token.exchange`, kind `decision`, the parent's chain, and a reason such as `exchange_widening` or `exchange_actor_not_permitted` (the full list is in the [HTTP API reference](../reference/http-api.md#token)). A refused lease renewal is a `deny` record when its token verified: tool `lease.renew` (as for a successful renewal), kind `decision`, the token's chain, and the lease reason (`lease_revoked`, `lease_expired` or `lease_unknown`). Exchanges whose subject token does not verify, and renewals whose token does not, are not recorded. Because refusals are kind `decision`, find them by tool: `attenuo audit tail --tool token.exchange --decision deny` (or `--tool lease.renew`), then `attenuo audit show --id <decision_id>` with the id the error carried. `audit export --kind exchange` lists issued exchanges only; `audit export --tool token.exchange --decision deny` exports the refusals.

## What a record holds

A record names the agent chain and the originating user separately. That is the point: most logs cannot tell an agent action from a user action. A record also has:

- a `kind`, one of `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke` or `admin` (see [Kind and chain id](#kind-and-chain-id)),
- a `chain_id`, the id of the delegation chain it belongs to (absent for admin actions),
- a decision id, which the client sees in the `X-Attenuo-Decision-Id` header or in the error data of a denial,
- the time, and allow or deny,
- a reason code such as `policy_allow`, `capability_denied` or `lease_revoked`,
- the chain depth, a digest of the chain, and the lease ids,
- the server and tool,
- a digest of the arguments,
- the session id and the ids of the policies that decided,
- for an allowed call that matched run limits, `budget.charged`: each counter it was charged against and what it held afterwards,
- for a call to a destructive tool, `usage`: the run's calls, amount and whether the destination was seen before, as the policy saw them (when usage is tracked).

The log stores a digest of the arguments, not the arguments. Secrets and personal data in tool inputs do not end up in the log.

Issuance and renewal use the same record shape. They have `server` set to `attenuo` and the tool set to `token.root`, `token.exchange` or `lease.renew`.

## Kind and chain id

Two top-level fields let you filter and join an export without reading anything nested.

| `kind` | Written when | `tool` |
| --- | --- | --- |
| `decision` | a tool call or AuthZEN evaluation was decided (allow or deny, including refusals before the policy ran), a token exchange or lease renewal was refused, or the proxy ended a response stream on revocation or expiry | the tool called; `token.exchange` for a refused exchange, `lease.renew` for a refused renewal, `stream.end` for an ended stream |
| `tool_result` | the proxy relayed the upstream's answer to an allowed call | the tool called |
| `approval_request` | a gated call opened an approval | the tool called |
| `approval_grant` | the user or the operator granted or declined an approval | the tool called |
| `exchange` | a token exchange issued a new hop (a refused one is a `decision`) | `token.exchange` |
| `root_token` | a root token was issued (IdP login, or the dev mint) | `token.root` |
| `lease_renew` | a lease was renewed (a refused renewal is a `decision`) | `lease.renew` |
| `lease_revoke` | a lease and its subtree were revoked with the admin bearer | `admin.lease.revoke` |
| `admin` | any other admin action (policy reload, budget refund, dev root mint) | `admin.*` |

Checkpoints are not records, so they have no kind: they sit in their own table and appear as `checkpoint` lines in an export.

`chain_id` is the lease id of the chain's first hop. Every hop issued from a root token descends from it, so it is the same for the root token's issuance, each exchange, every call made with any token of the run, and each renewal, and it does not change as hops are added (`chain_digest` does). It is not a new token claim: the lease is already in the token. Admin records have no chain and no `chain_id`.

Both fields are part of the record, so the entry hash covers them, and the SQLite store keeps them in indexed columns that are cross-checked against the stored JSON like the other columns.

## Tool results and labels

A `tool_result` record is written after every allowed mediated call that gets an answer, before the proxy relays it. An SSE response gives one record per answering event, and an upstream JSON-RPC error is recorded too. The record has the call's `chain_id`, server and tool, `arguments_digest` and `decision_id` (the id of the decision record that allowed it), and a `result` member:

| Field | Meaning |
| --- | --- |
| `digest` | SHA-256 (hex) of the RFC 8785 canonical JSON of the answer's `result` member, or of its `error` member |
| `size` | length in bytes of that canonical JSON |
| `error` | `true` when the upstream answered with a JSON-RPC error; absent otherwise |
| `label` | `untrusted`, or `trusted` when the catalog marks the tool's output trusted |
| `fingerprints` | number of span fingerprints kept in the run's index for argument matching; `0` for a trusted result |

The content is not stored. If the record cannot be written, the agent gets a `label_error` denial instead of the answer.

An untrusted result taints the run (see [Writing policies](../guides/writing-policies.md#asking-for-approval-after-untrusted-output)). A decision record of a call on a tainted run has `labels: {tainted_by: [seq, ...]}`, the `seq` of the first `tool_result` record of each source, so an auditor can see what the run had read before a call. When an argument of the call copied a value or span of an untrusted result, `labels.untrusted_args: [{arg, seq, kind}]` names it, the `tool_result` record it matched and how (`leaf`, `entity`, `kgram`, or `unreadable` when the index could not be read; then without `seq`), at most 64 entries. A call charged against run limits records `budget: {charged: [{hop, cap, kind, arg, used_after, max}]}`, one entry per counter (`arg` absent for `calls`). `decision_id`, `result`, `labels`, `approval` and `budget` are omitted when absent, so records without them hash exactly as before.

## Approvals

A call that a policy gates with `@obligation("approval")` gets a `decision` record with reason `approval_required`. Three more records follow its approval:

| Record | `kind` | Decision and reason | `approval` member |
| --- | --- | --- | --- |
| approval opened | `approval_request` | `deny`, `approval_requested`; `decision_id` is the gated decision, `labels` as on it | `id`, `call_hash`, `expires_at` |
| granted or declined | `approval_grant` | `allow`, `approval_granted`, or `deny`, `approval_declined`; `decision_id` is the gated decision | `id`, `by` (`user` or `operator`), `approver` (the user's subject or `urn:attenuo:admin`), `method` (`id_token` or `admin_token`), `outcome` (`grant` or `decline`), `call_hash`, `expires_at` |
| the retry that used it | `decision` | `allow`, the policy's reason | `id`, `by` |

A repeated gated call while its approval is still pending gets a new `decision` record but no new `approval_request`. The record of the retry and the consumption of the grant go together: the grant is given back if the retry is not allowed or its record cannot be written, so every used grant has exactly one allowed decision naming it. A test in `attenuo-audit` pins the hashes of these records and checks that records without them hash as before.

## The hash chain

Entries are stored in SQLite as `{seq, prev_hash, record, entry_hash}`. The entry hash is SHA-256 over the RFC 8785 canonical JSON of the array `["attenuo-audit-entry-v2", seq, prev_hash, record]`. Canonical JSON sorts object members and fixes how strings and numbers are written, so the hash depends only on the values: any RFC 8785 implementation, in any language, gets the same bytes. The first entry uses a fixed genesis value for `prev_hash`.

The `v2` in the tag is the hash construction. `kind` and `chain_id` were added to the record before anything was released, so they are part of v2 and did not bump it; a database created earlier on the same day, without the two columns, is refused at open with a message to start a new file. Logs written before v2 (plain `serde_json` output, no tag) are refused when the database is opened, with an error that says to start a new file. There is no migration: no logs were released in the old form.

Change a byte in a record and its hash no longer matches. Delete a row in the middle and the next row points at the wrong parent. Reorder rows and the links break. Tests cover each of these cases.

## Failing closed

The audit append is part of the decision. If the log cannot be written, the decision becomes a deny with the reason `audit_error`. An action that cannot be recorded does not happen. The same goes for issuance: if the append fails, the new lease is revoked, so an unrecorded token is unusable.

## Signed checkpoints

A hash chain alone cannot show that the newest entries were deleted, or that someone with write access rebuilt the whole chain. Checkpoints close that gap. A checkpoint is `{seq, head_hash, at, kid, signature}`: the issuer's Ed25519 key signs the head of the chain, under the context string `attenuo-checkpoint-v1` so the signature is good for nothing else.

- One is written every `[audit] checkpoint_every` entries (default 1000), in the same transaction as the append that reaches it.
- The commit that writes a checkpoint is synced to disk (`synchronous=FULL`) even at `durability = "normal"`, and only then does the checkpoint go to the code that ships it elsewhere. A power failure cannot take back entries that a shipped checkpoint covers.
- One is written every `[audit] checkpoint_interval_seconds` (default 300) if entries arrived since the last one, so the tail of a quiet log is covered too. Whichever trigger fires first wins.
- `GET /admin/audit/checkpoint` signs the current head on demand and returns it. Copy that somewhere the host cannot write.

Verification needs only the public keys the server already publishes at `/.well-known/jwks.json`. A checkpoint fails if its signature is bad, if its `kid` is not in the JWKS, if the entry hash at its `seq` differs from `head_hash` (history was rewritten, even with every later hash recomputed), or if the log is now shorter than its `seq` (truncation). After a key rotation, old checkpoints keep verifying as long as the retired key stays in `[issuer] previous_key_paths`.

What it does not give you: the signing key lives on the same server. Someone who controls the server process can sign a rewritten history. Checkpoints that left the host before the compromise still catch it, which is what the checkpoint sink is for.

## Shipping checkpoints off the host

`[audit.sink]` sends every checkpoint the log creates somewhere the host cannot rewrite, as soon as the commit that wrote it is on disk ([reference](../reference/config.md#auditsink)). Three kinds:

- `webhook`: `POST` to `url`, `Content-Type: application/json`, optional `Authorization: Bearer`, headers `X-Attenuo-Checkpoint-Seq` and `X-Attenuo-Checkpoint-Sha256`. Any 2xx is delivered; redirects are not followed.
- `file`: append one line to `path` and `fsync` it. For operators who already ship files with their own agent. Put the file on another mount (the server warns at startup when it shares a filesystem with the SQLite file), ideally append-only (`chattr +a`).
- `s3`: `PUT <endpoint>/<bucket>/<prefix><seq, 20 digits>-<first 16 hex of checkpoint_sha256>.json`, signed with AWS Signature Version 4 (implemented in the server on `ring` and `sha2`; no AWS SDK). Requests are path-style (the bucket is the first path segment; there is no virtual-hosted mode). Credentials come from the config or `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`. Run against MinIO on 2026-11-14 (see [Tested against MinIO](#tested-against-minio)); never run against AWS S3.

Each delivery is one canonical JSON object (format `attenuo-shipped-checkpoint-v1`): the checkpoint record, its `kid` and `signature` repeated at the top level, the server's `public_url`, and `checkpoint_sha256`, the hex SHA-256 of the checkpoint's RFC 8785 canonical JSON. The same object is the webhook body, one line of the file, and one S3 object, so the shipped copies of any kind can be collected into one JSON Lines file.

The log's hook only queues; it never waits on the network or the disk. The queue holds `queue_capacity` checkpoints (default 1024). When it is full the oldest queued checkpoint is dropped and `attenuo_audit_sink_dropped_total` counts it: every later checkpoint covers the entries an earlier one does, so the newest are the ones to keep. One background thread delivers in order. A failed delivery is retried, never skipped, with exponential backoff from `initial_backoff_ms` (500) doubling to `max_backoff_seconds` (60), each wait drawn between half and all of that. `/readyz` adds `"degraded": true` and `checks.checkpoint_sink = "degraded"` when the queue is full or the oldest undelivered checkpoint is older than `max_lag_seconds` (300); it stays 200 unless `fail_readiness = true`. Metrics: `audit_sink_delivered_total`, `audit_sink_failures_total`, `audit_sink_dropped_total`, `audit_sink_queue_depth`, `audit_sink_oldest_undelivered_timestamp_seconds`. At shutdown the queue gets five seconds to drain.

The sink's credentials are on the host too, so an attacker who holds the host can also send to the sink. Give the server credentials that can only add: a webhook receiver that never overwrites, an S3 policy with `s3:PutObject` only plus versioning or Object Lock, a file another user owns with the append-only attribute. They can then add a forged checkpoint but not remove the original, and two different checkpoints for one `seq` are themselves reported. With S3, `s3:PutObject` still lets them overwrite an object's key: versioning keeps the original as an older version, but a plain `GET` (or `aws s3 cp`, `mc cp`) of the key returns the newest one. Collect every version of every object (`aws s3api list-object-versions`, `mc ls --versions`) into the file you cross-check against.

### Tested against MinIO

`scripts/live-minio-smoke.sh` (not part of CI) ran the S3 sink on 2026-11-14 against MinIO RELEASE.2025-07-23 (`bitnamilegacy/minio:2025.7.23`, `sha256:8935e75fa5d11295c17171e4aa49efe390a1193cd7f12e4d21b92af9ffef09d7`, on 127.0.0.1 over plain HTTP; the `minio/minio` repository is no longer on Docker Hub). The bucket was created with Object Lock and a default COMPLIANCE retention of one day, and the server's keys were a MinIO user whose only permission was `s3:PutObject` on it. What the run checked, all passing:

- One object per signed checkpoint, at `<prefix><seq, 20 digits>-<16 hex of checkpoint_sha256>.json`, path-style. Each object's bytes are the canonical `attenuo-shipped-checkpoint-v1` envelope of the checkpoint the server signed: field for field the checkpoint in `attenuo audit export`, `checkpoint_sha256` recomputed, `public_url` the server's.
- `attenuo audit verify --file export.jsonl --jwks jwks.json --checkpoints shipped.jsonl` (the objects joined one per line) accepts the export, and exits 2 once one object's `head_hash` is changed.
- The PutObject-only keys can neither read, list nor delete. Overwriting an object with them adds a version and keeps the original, which COMPLIANCE retention keeps even the MinIO root user from deleting; a plain read of the key then returns the overwrite, and a cross-check against every version reports it (exit 2).
- A wrong secret: every PUT is refused with 403, the server logs `[audit.sink] delivery failed; retrying ... S3 answered 403 Forbidden` and keeps retrying, tokens are issued and calls are decided as usual (an allowed call, a `policy_deny`), and `/readyz` stays 200 with `"degraded": true` and `checks.checkpoint_sink = "degraded"` once `max_lag_seconds` has passed.
- Endpoint spellings: `http://LOCALHOST:<port>/` (upper case, trailing `/`) and `http://127.0.0.1:80` (an explicit default port) both deliver. Before the fix that came with this run, neither delivered (`:80` was answered 403): the signed host was the endpoint as written, the host sent was lowercased and without the default port.

Not run: AWS S3 itself (signing region other than `us-east-1`, HTTPS, uploads to an Object Lock bucket with a default retention, for which AWS documents a required `Content-MD5` or checksum header that the sink does not send; MinIO accepted the uploads without one, and whether AWS refuses them was not checked), `session_token` (STS credentials), MinIO over HTTPS, and a bucket with versioning but no Object Lock.

To check a log against what was shipped:

```sh
attenuo audit export --out export.jsonl
attenuo audit verify --file export.jsonl --jwks jwks.json --checkpoints shipped.jsonl
```

For every shipped checkpoint inside the export's range, the export must hold the same checkpoint at that `seq`, field for field, and its entry there must hash to the shipped `head_hash`. A different checkpoint is reported as signed again after shipping (with the fields that differ); a missing one as deleted. A shipped copy whose signature does not verify against the JWKS, or whose envelope disagrees with itself, is reported instead of trusted. Shipped checkpoints past the export's range are counted (`beyond_range`): if the export runs to the head of the log, the log is shorter than what was shipped. Exit status 2 on any mismatch. In code: `attenuo_audit::{parse_shipped, cross_check}`, `attenuo.audit.cross_check` (Python) and `crossCheck` (TypeScript); see [Verifying in code](#verifying-in-code).

## Reading and verifying

- `attenuo audit tail` shows recent entries. `--follow` keeps polling.
- `attenuo audit verify` walks the whole chain, checks the checkpoint signatures, and prints the last signed `seq` and how many entries come after it. It exits 2 if the chain is broken or a checkpoint is invalid.
- `attenuo audit export --from 100 --to 200 --format jsonl` writes a slice of the log with the checkpoints inside it, one canonical JSON object per line, after a header that declares the range (format `attenuo-audit-export-v2`). `attenuo audit verify --file export.jsonl --jwks jwks.json` checks that file on any machine, with no admin token and no access to the server: it re-hashes every entry, checks the links, verifies each checkpoint signature and compares its head hash to the entry at that `seq`.
- That check is strict. It fails a file that starts or ends short of the range in its header (truncated), a file that holds entries outside that range, and a file with entries after its last valid checkpoint. Such entries are covered by the hash chain only, and anyone who can write the file can append them. To check an export taken while the log was ahead of its newest checkpoint, pass `--allow-unsigned-tail`; the report still says how many entries are unsigned. Or sign the head first (`GET /admin/audit/checkpoint`) and export up to it.
- `--checkpoints shipped.jsonl` adds a cross-check against checkpoints shipped off the host; see [Shipping checkpoints off the host](#shipping-checkpoints-off-the-host).
- `GET /admin/audit`, `/admin/audit/verify`, `/admin/audit/checkpoint` and `/admin/audit/export` are the matching admin endpoints. `GET /admin/audit` also filters (by kind, decision, reason, subject, agent, lease, server, tool, chain id and time) and pages newest first; `/admin/audit/entries/{seq}` and `/admin/audit/records/{id}` return one entry with the current state of its leases and the checkpoint that covers it; `/admin/audit/checkpoints` lists stored checkpoints without signing one. See the [HTTP API](../reference/http-api.md#querying-the-audit-log).
- The Python SDK (`attenuo.audit.verify_export`) and the TypeScript SDK (`verifyExport`) run the same strict check in your own code, with the issuer's JWKS as the only input; see [Verifying in code](#verifying-in-code).

### Filtering an export

`attenuo audit export --kind lease_renew`, `--chain-id <lease>`, `--tool <tool>` and `--decision allow|deny` (or `?kind=`, `?chain_id=`, `?tool=` and `?decision=` on the endpoint, alone or together, on top of `from` and `to`) keep only the matching entries. The header then carries a `filter` member that names them, for example `"filter":{"decision":"deny","tool":"token.exchange"}`. `tool` and `decision` were added to `filter` after `kind` and `chain_id`, within the same format `attenuo-audit-export-v2`: a member that is absent means that filter was not used, so a header written before they existed reads the same as it always did, and a verifier from before then still refuses a file filtered on them, since it refuses any header with a `filter`. A filtered file has gaps in its hash chain by construction, so nothing can show that it is complete, and `audit verify --file` refuses it with an error rather than a verdict. Verify an unfiltered export, then filter that, or filter the log and keep the unfiltered export as the evidence. Each entry in a filtered export still carries its own `entry_hash`, so you can recompute it. The SDKs take the same filters (`audit_export(tool="token.exchange", decision="deny")` in Python, `auditExport(1, undefined, { tool: "token.exchange", decision: "deny" })` in TypeScript), and their offline verifiers refuse a filtered file the same way.

### Verifying in code

```python
from attenuo import verify_export

report = verify_export("audit.jsonl", checkpoint_public_keys=jwks)  # jwks: GET /.well-known/jwks.json
if not report.ok:
    print(report.first_bad_seq, report.bad_checkpoints, report.truncated, report.unsigned_tail)
```

```ts
import { verifyExport } from "@attenuo/sdk";

const report = await verifyExport({ path: "audit.jsonl" }, { checkpointPublicKeys: jwks });
```

`cross_check(export, shipped, checkpoint_public_keys=jwks)` in Python and `crossCheck(export, shipped, { checkpointPublicKeys })` in TypeScript run the shipped-checkpoint cross-check above with the same findings: signed again after shipping, deleted, two different shipped copies for one `seq`, and a shipped copy that does not verify, each with the Rust reason text and the line of the shipped file.

Both follow the Rust check rule for rule: the same file gets the same verdict and the same `first_bad_seq`. A file that is not an export at all (no header, wrong format, filtered, not JSON) raises `ExportError`. The cross-language tests in `sdk/python/tests/test_integration.py` export from a real server, flip one byte and check that the Rust CLI, Python and TypeScript all name the same `seq`; a second one runs a server with a file sink and the issuer key in the test's hands, rewrites and re-signs the export, deletes a checkpoint, and tampers with the shipped file, and checks that all three report the same mismatches (`seq`, line and reason). They are a little stricter than Rust in two ways: they hash the record as it appears in the file (Rust decodes it into its record type first and so ignores a member it does not know), and they refuse duplicate object members. TypeScript also refuses integers beyond 2^53 (Python and Rust keep a `u64` seq exact).

## What the chain does not prove

Entries after the last checkpoint are protected by the hash chain only, and the verify report says how many there are (`unsigned_tail`). A signed checkpoint proves what the log looked like when it was signed, not that nothing was deleted afterwards unless you hold a copy of it from somewhere else.


## Not built yet, or uncertain

The checkpoint sink ships what the server signs; entries after the newest checkpoint are not covered until the next one is signed (at most `checkpoint_every` entries or `checkpoint_interval_seconds`).

The log is never pruned and there is no rotation, so it grows without bound. A prune that archives a prefix at a signed checkpoint and leaves a signed anchor is proposed in [ADR-0015](../decisions/0015-audit-retention.md); not built.

Revocations, policy reloads, budget refunds (`admin.budget.refund`, naming the refunded decision) and dev root mints are appended to the log as admin actions (reason `admin_action`, server `attenuo`, subject `urn:attenuo:admin`, which no user can have). To pick out server events, filter on `kind` (anything but `decision`), or on `server = "attenuo"` and the tool (`token.*`, `lease.renew`, `admin.*`); no upstream or agent can use the name `attenuo`. The revoke response carries the `audit_id` of that record, or says that the append failed.

More detail: [RFC-0001 section 7](../spec/rfc-0001-attenuo.md#7-audit-record-and-hash-chaining) and [design/server.md](../design/server.md#audit-convention-for-issuance).

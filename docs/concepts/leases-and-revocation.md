# Leases and revocation

A delegation token is a signed JWT. It stays valid until it expires, and nobody can take it back. That is a problem when a user logs out, an operator kills a run, or an agent turns out to be compromised. Leases solve it.

## What a lease is

Every hop in a chain carries a lease id. The server keeps a small registry of leases in the same SQLite file as the audit log. Each lease has an expiry, a revoked flag and a parent. The parent is the lease of the previous hop. Leases form a tree that matches the delegation chain.

A lease is created when its token is issued. Its expiry is the earlier of "now plus the lease interval" and the token's own expiry. The interval is `[issuer] lease_interval_seconds`, 300 seconds by default.

## Checked on every request

Before policy runs, the server checks every lease in the chain. A lease must be known, not revoked and not expired. If any check fails, the call is denied with one of these reasons: `lease_revoked`, `lease_expired` or `lease_unknown`. The token can still verify as a JWT. It makes no difference.

Requests that carry no decision, such as `initialize`, `tools/list` or a session `GET`, get the same check. They are refused with HTTP 401, and the refusal is a `deny` record with the same reason, so a client that opens a new session for every call still leaves a trace after the revocation.

If the store cannot be read, the answer is deny (`lease_error`). Losing a row denies. It never allows.

## Renewing

The holder keeps its authority alive by calling `POST /token/renew` with its token as the bearer. The lease expiry moves to the earliest of:

- now plus the lease interval,
- the token's expiry,
- the parent lease's expiry.

It never moves earlier. Renewal is refused if the lease or any ancestor is revoked or unknown, or an ancestor has expired. So a child cannot outlive a parent that stopped renewing.

An agent should renew well inside the interval. A third of it is a good rule. A client that forgets sees `lease_expired` while its token still verifies, which can look like a bug.

## Revoking

An operator revokes a lease with `POST /admin/leases/{id}/revoke`, or `attenuo lease revoke <id>`. The server marks that lease and every descendant revoked in one transaction. The next request on any affected hop is denied.

Revoking the root lease of a run stops every sub-agent of every agent in it. You do not need to know which tokens exist. The server never stores tokens.

During an incident you may know the user or the run rather than a lease. `POST /admin/leases/revoke` takes one selector, and `attenuo lease revoke` the matching flag:

- `--user alice@example.com` revokes every lease issued for that originating user, across all of their runs. The server records each lease's user when it issues the token. Leases issued by an older server have no recorded user and are not matched.
- `--chain-id <id>` revokes one run: the root lease named by the `chain_id` of its audit records, and everything below it.
- `--session <id>` revokes the run that opened one MCP session through the proxy. When the proxy binds a new session for a verified token, the server records the session id's SHA-256 with the run's `chain_id`; the admin gives the raw id, the server hashes it and revokes that run as `--chain-id` would. Sessions opened before the server kept these records are not found.

Each match is revoked with its descendants, in one transaction, and expired but unrevoked leases are included, since a renewal could otherwise bring them back. Add `--preview` first to see the list without changing anything. The answer lists every revoked lease, and one `admin.lease.revoke` audit record names them (the first 256, with the full count in its digested arguments, which also name the selector and, for a session, the resolved `chain_id`).

## Two speeds

- An **explicit revoke** takes effect on the next request. There is no lease cache in v0.
- An agent that **stops renewing** loses authority after at most one lease interval, with no operator action.

So "within one lease interval" is the worst case for a silent holder. For a deliberate revoke, it is one request.

## Cost and limits

- Each request does a registry lookup. A shared or remote registry would add latency and a failure mode. It would still fail closed.
- Revocation names leases: by id, or by a selector (user, chain, session) that the server resolves to leases at the time of the call. Leases issued after the call are not covered; a user's next root token is stopped at the IdP, not here.
- A session id resolves only through the server's own record of it, written when the proxy bound the session. A session opened through another server that does not share the store is not found.
- Session records are kept only while the session's run could still be used. Every minute the server deletes the records of runs whose root lease is revoked, or has been expired for longer than `[leases] session_retention_seconds` (a day by default; 0 keeps them all), at most 1,000 per pass and 100 passes per minute, and counts them in `lease_sessions_pruned_total` (the interval, pass size and pass count are `[leases] maintenance_interval_seconds`, `maintenance_batch_rows` and `maintenance_max_passes`). An expired lease can still be renewed while its token is valid, so keep the retention above the longest token lifetime you issue. A pruned session resolves to nothing, as an unknown one does; revoke such a run by `--chain-id` or `--user`, which reach it as long as its leases are kept (next item).
- Leases are kept only while their run could come back, plus a margin. A run here is a root lease and everything delegated from it. Once every lease in it is revoked or expired, and the last of them ended longer ago than `[leases] retention_seconds` (a week by default; 0 keeps every lease), the same background task deletes the whole run: its leases, their recorded users and chain bindings, its session records, hop limits and run labels. It decides on the whole run and never leaves a lease whose parent is gone. One lease still live, or ended within the retention, keeps the whole run. The grace period is there because an expired lease can be renewed while its token is valid: keep the retention above the longest token lifetime you issue. Set too short, it fails closed: the renewal of a pruned run is refused as `lease_unknown`. Revoked runs wait out the retention too, measured from the revocation, so for that long their tokens are still refused as `lease_revoked` and the run still shows in the console. A pass touches at most 1,000 lease rows (`maintenance_batch_rows`): the leases it looks at, the leases it reads to decide a run, and the leases it deletes. A run too wide for one pass is first read to the end, over as many passes as it takes, and only then deleted, children before parents and the root last, again over several passes (and minutes, if it outlasts `maintenance_max_passes`). Every lease of such a run has ended, so its tokens are refused throughout: as `lease_revoked` or `lease_expired` while their rows are there, as `lease_unknown` once they are gone. Once deleting has begun, a renewal of one of its leases is refused as `lease_unknown`, so no part of the run comes back; a revocation or renewal while it is still being read makes the task decide it again later, so a late revocation still restarts the grace period. Deleted leases are counted in `leases_pruned_total`. Measured on a file store with one run of 50,000 leases next to 1,000 runs of two, all past the retention, three runs each: before, the pass that met the wide run held the store for 304 to 330 ms; now the sweep takes 105 passes instead of 4 (0.54 to 0.57 s of passes in all, against 0.33 to 0.35 s), the median pass takes 0.9 ms while reading the wide run and 7.4 to 7.6 ms while deleting, and the slowest pass 31 to 46 ms, a pass that ran a WAL checkpoint (13 to 15 ms with checkpoints off). A hot-path lease check that arrives during a pass waits at most that long.
- After a run is pruned, its token reads as unknown: every request with it is refused as `lease_unknown` and audited as a `deny`, exactly like a token naming a lease the server never issued. What an operator loses is the registry's view of it: `--user` no longer finds its leases, `--chain-id` and `--session` match nothing, and the console's lease tree answers 404. The audit log is not pruned and still has every decision, issuance, renewal and revocation of the run.
- A run's run-limit counters, its charge log and its approvals are kept longer, and only ever deleted after its leases. Nothing of a run whose leases are still in the registry is deleted, however old it is, so a granted approval that has not been used yet, or a counter a live hop still charges, is never touched. Once the run's leases are gone (pruned as above, or never known to the store), the same background task deletes, after the lease pass: a charged decision's entry in the charge log once its charge and any refund are older than `[leases] run_state_retention_seconds` (30 days by default; 0 keeps everything); a counter once no charge under its lease is left; an approval once its creation, decision and expiry are all older than the retention (a pending or granted approval of a pruned run can no longer be used: its lease is unknown). It counts them in `run_state_pruned_total{kind}` with `kind` one of `counters`, `charges`, `approvals`. What an operator loses for such a run: the refund history (an operator refund of one of its decisions answers 404 `not_found`, exactly like a decision that charged nothing, and a second refund cannot be told from a first) and the approval history in `GET /admin/approvals` and the console. The audit log keeps every decision record with its `budget` member, every `admin.budget.refund` record and every `approval_request` and `approval_grant` record, so both histories can still be read there.
- An external enforcement point that uses the AuthZEN endpoint learns about revocation only by asking. There is no push channel. See [Enforcement points](enforcement-points.md).
- A renewal refused after its token verified (a revoked, expired or unknown lease) is a `deny` record of `lease.renew` with the lease reason, and the error carries its `decision_id`. A token that does not verify leaves only a server log line.

More detail: [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md), [RFC-0001 section 6](../spec/rfc-0001-attenuo.md#6-revocation-via-leases) and [design/server.md](../design/server.md#lease-renewal).

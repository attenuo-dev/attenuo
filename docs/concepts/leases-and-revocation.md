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
- An external enforcement point that uses the AuthZEN endpoint learns about revocation only by asking. There is no push channel. See [Enforcement points](enforcement-points.md).
- A renewal refused after its token verified (a revoked, expired or unknown lease) is a `deny` record of `lease.renew` with the lease reason, and the error carries its `decision_id`. A token that does not verify leaves only a server log line.

More detail: [ADR-0006](../decisions/0006-lease-based-in-flight-revocation.md), [RFC-0001 section 6](../spec/rfc-0001-attenuo.md#6-revocation-via-leases) and [design/server.md](../design/server.md#lease-renewal).

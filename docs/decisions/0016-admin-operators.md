---
status: proposed
date: 2026-11-13
decision-makers: []
consulted: []
informed: []
---

# ADR-0016. Admin operators: named admin bearer tokens stored as SHA-256 digests, three fixed roles checked from one route table, and the operator recorded as the actor

## Context and Problem Statement

The admin API (`/admin/*`) accepted one static bearer, `[admin] token`, with no roles, and recorded every admin action with the same actor, `urn:attenuo:admin` (audit finding S-2). Whoever held the token could do everything, several people sharing it could not be told apart, and the audit log could not say which person revoked a lease, reloaded the policy or granted an approval. The threat model had no attacker who is, or holds the credential of, an operator. How should the server tell operators apart and limit what each may do, without breaking the deployments, demos, SDK tests and records that use `[admin] token` today, and without adding a login system?

## Decision Drivers

- Attribution: every admin action and every operator approval names the operator who took it, in the signed audit log.
- Least privilege for the common jobs: looking at the log and leases, revoking and deciding approvals, and changing the server's state are different jobs.
- No breaking change: `[admin] token` keeps working, and keeps producing exactly the records it produced before (`urn:attenuo:admin`), so existing audit chains, checkpoints, docs and tests stay valid. No audit schema change.
- Fail closed: a new admin route that nobody mapped needs the highest role, not the lowest.
- The config file never holds an operator's token.
- No new dependency, no session state, no new listener.

## Considered Options

- Named bearer tokens in `[[admin.operators]]`, each stored as the SHA-256 of the token, with a fixed role (`viewer`, `operator`, `admin`), checked against one route table in the admin middleware.
- The same, with a slow password hash (Argon2, bcrypt) of each token.
- Operator login through the configured IdPs (OIDC), with the role taken from a claim.
- Per-route permissions configured in the file instead of fixed roles.

## Decision Outcome

Chosen option: "named bearer tokens stored as SHA-256 digests, with three fixed roles", because it closes S-2's attribution and least-privilege gaps with a change to one middleware and one config table, works with every client that already sends an admin bearer (CLI, SDKs, console, scripts), and leaves `[admin] token` exactly as it was.

- `[[admin.operators]]` entries have `name` (`[a-z0-9_-]{1,64}`, unique, not `admin`), `token_sha256` (64 lowercase hex characters) and `role`. `[admin] token` is the operator named `admin` with role `admin`; the name is reserved for it. The server refuses to start on a bad or repeated name, a malformed digest, two operators with one digest, and an operator whose digest is that of `[admin] token`. Off loopback it refuses to start without any admin credential, and still refuses a weak `[admin] token` when one is set; operators alone are enough.
- `attenuo admin operator new --name <n> --role <r>` generates a token from 32 random bytes (base64url), prints it once and prints the entry with its digest; it writes nothing to disk and sends nothing to a server. `attenuo admin operator hash` digests a token read from stdin.
- `require_admin` hashes the presented bearer once with SHA-256 and compares the digest with every configured credential in constant time, without stopping at a match, so the time taken does not say which credential matched or whether one did. It then puts the operator's name and role into the request.
- Plain SHA-256 is enough because these tokens are not passwords. A generated token carries 256 bits of entropy, so a stolen digest cannot be reversed by guessing, and a slow hash would only add latency to every admin request. `[admin] token` is still checked for length and published placeholders off loopback, as before. A person who sets a guessable token through `attenuo admin operator hash` defeats this, as a guessable `[admin] token` always has.
- Roles are ordered, each including the ones below: `viewer` may use the read-only routes (lease state and tree, the audit log, its checkpoints and export, the loaded policies and their check, the policy dry run, approvals, `GET /admin/whoami`); `operator` may also revoke leases (by id, user, chain or session, the preview included) and decide approvals; `admin` may use every admin route (policy reload, budget refunds, the dev root mint). The minimum role of each route is in one table, `attenuo_server::operators::ROUTE_ROLES`, keyed by method and route template; a route missing from it needs `admin`. A test reads every admin route the server mounts and fails when one has no entry; another sends every route each role on both listeners. A role too low is answered 403 `admin_role_insufficient`, whose message names the role needed and never the token.
- `GET /admin/audit/checkpoint` is a viewer route although it signs a checkpoint of the head when there is none: the signature records no new fact, and the CLI and console treat it as a read. The selector revoke's `?preview=true` dry run is an operator route because it is the same route as the revocation; a viewer reads the same leases through the lease tree.
- Attribution: audit records of admin actions name the operator as `originating_subject`, and an operator's approval decision has it as the approver subject (also the approval token's `sub`). `[admin] token` keeps `urn:attenuo:admin`; a named operator is `urn:attenuo:admin:<name>`. Both are under the reserved `urn:attenuo:` prefix, which no IdP user can have (SR-34). The default revocation reason names the operator (`revoked by alice`; `revoked by admin` for the legacy token, as before). The audit record format and `SCHEMA_VERSION` are unchanged: the subject was always a string.
- `GET /admin/whoami` answers `{name, role}`. The console uses it to log in, shows the operator and role in its header, and disables the buttons the role cannot use; the server stays the enforcement point.
- Operators are read from the file at startup only. `POST /admin/policies/reload` reloads policies, not the config, so adding, removing or changing an operator takes a restart. `[[admin.operators]]` cannot be set from the environment, as no array of tables can; `ATTENUO_ADMIN_TOKEN` keeps replacing `[admin] token`.

What this does not do:

- No OIDC or other login for operators, no cookie sessions: an operator is whoever presents the token.
- No token expiry and no rotation workflow beyond editing the config and restarting. Withdrawing an operator's access is removing its entry and restarting.
- No per-operator rate limits, and no limit on how many admin requests one operator makes.
- No per-route or per-resource permissions beyond the three roles, and no restriction of an operator to some users or runs.
- Nothing stops whoever can edit the config file, or set `ATTENUO_ADMIN_TOKEN`, from adding an admin. The config file and the server's environment remain part of the trusted base, like the issuer key.

### Consequences

- Good, because every admin action and operator approval in the signed log now says which named operator took it, and a shared token is no longer the only way to give several people access.
- Good, because a person who only needs to read the log, or to revoke and approve, can be given a token that cannot reload the policy, refund budgets or mint roots.
- Good, because nothing changes for a deployment that keeps `[admin] token` alone: same records, same responses, same checks.
- Bad, because the legacy token and a named operator with role `admin` are both all-powerful, and the legacy token's records do not name a person; a deployment gets attribution only by moving its people to named operators.
- Bad, because a leaked operator token stays valid until its entry is removed and the server restarted.
- Neutral, because the roles are fixed in code: a deployment that wants another split has to propose one.

### Confirmation

- `crates/attenuo-server/src/operators.rs` tests: authentication of every credential and of none, the name and digest rules, role order, the fail-closed lookup, a table without duplicates, and that every admin route mounted in `lib.rs` and `admin_ui.rs` has an entry and every entry is mounted.
- `crates/attenuo-server/tests/admin_operators.rs`: every route of the table on the main and on the console listener refuses exactly the roles below its entry with `admin_role_insufficient` and admits the others; `whoami` for each credential; records name `urn:attenuo:admin` for `[admin] token` and `urn:attenuo:admin:<name>` for operators; a log and checkpoint written with only `[admin] token` still verify after operators are configured; startup refusals.
- `crates/attenuo-server/tests/approvals.rs`: a viewer cannot decide an approval; an operator's decision names it in the approval and its audit record.
- Config tests in `crates/attenuo-server/src/config.rs` and `config/overrides.rs`: each startup refusal, the off-loopback rule, and that `ATTENUO__ADMIN__OPERATORS` is refused.
- `crates/attenuo-cli/tests/admin_operator.rs`: the output of `admin operator new` and `hash`, that a server configured with the printed entry accepts the printed token with that name and role, and that the CLI and the server refuse the same names.

## Pros and Cons of the Options

### Named bearer tokens as SHA-256 digests, fixed roles

- Good, because every existing client already sends a bearer, so nothing else changes.
- Good, because the config holds no secret an operator could replay.
- Bad, because tokens do not expire on their own.

### The same with a slow password hash

- Good, because a guessable token's digest would be harder to reverse.
- Bad, because generated tokens are not guessable, so it buys nothing for them, and a slow hash compared against every credential on every admin request costs a noticeable amount of CPU per request and invites a denial of service on the admin port. It would also need a new dependency.

### Operator login through the IdPs

- Good, because people would log in with the identity they already have, with expiry and MFA from the IdP.
- Bad, because it needs a login flow, sessions or short-lived tokens, a role claim mapping and a console redirect, which is far more than S-2 asks for; it can be added later as another way to obtain an `AdminIdentity`.

### Per-route permissions in the file

- Good, because any split is possible.
- Bad, because every deployment would maintain its own route list, a new route would need every config updated, and a typo could open a route; three fixed roles and one table in code keep the failure mode closed.

## More Information

- Audit finding S-2 (one static admin bearer, no roles, every action recorded as `admin`). Related: ADR-0008 (the console holds the token in page memory), ADR-0013 (the admin API's listener), SR-15 (admin actions are audited), SR-34 (reserved subjects).
- Configuration: `docs/reference/config.md#adminoperators`; HTTP: `docs/reference/http-api.md#admin`; CLI: `docs/reference/cli.md`; threat model: attacker A8 in `docs/spec/threat-model.md`.
- Revisit when operators need expiry or rotation without a restart, or OIDC login for the console.

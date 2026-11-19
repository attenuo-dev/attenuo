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
- Operators are read from the file at startup only. `POST /admin/policies/reload` reloads policies, not the config, so adding, removing or changing an operator takes a restart. (Superseded in part by the [update of 2026-11-13](#update-2026-11-13-expiry-and-reload): `POST /admin/operators/reload` re-reads the operators without a restart.) `[[admin.operators]]` cannot be set from the environment, as no array of tables can; `ATTENUO_ADMIN_TOKEN` keeps replacing `[admin] token`.

What this does not do:

- No OIDC or other login for operators, no cookie sessions: an operator is whoever presents the token.
- ~~No token expiry and no rotation workflow beyond editing the config and restarting. Withdrawing an operator's access is removing its entry and restarting.~~ Addressed by the [update of 2026-11-13](#update-2026-11-13-expiry-and-reload): an entry may carry `expires_at`, and removing (or expiring) an entry takes effect with `POST /admin/operators/reload`, without a restart. Rotation is still adding a second entry, reloading, and removing the old one.
- No per-operator rate limits, and no limit on how many admin requests one operator makes.
- No per-route or per-resource permissions beyond the three roles, and no restriction of an operator to some users or runs.
- Nothing stops whoever can edit the config file, or set `ATTENUO_ADMIN_TOKEN`, from adding an admin. The config file and the server's environment remain part of the trusted base, like the issuer key.

### Consequences

- Good, because every admin action and operator approval in the signed log now says which named operator took it, and a shared token is no longer the only way to give several people access.
- Good, because a person who only needs to read the log, or to revoke and approve, can be given a token that cannot reload the policy, refund budgets or mint roots.
- Good, because nothing changes for a deployment that keeps `[admin] token` alone: same records, same responses, same checks.
- Bad, because the legacy token and a named operator with role `admin` are both all-powerful, and the legacy token's records do not name a person; a deployment gets attribution only by moving its people to named operators.
- ~~Bad, because a leaked operator token stays valid until its entry is removed and the server restarted.~~ Addressed by the [update of 2026-11-13](#update-2026-11-13-expiry-and-reload): removing the entry and reloading withdraws it, and an entry can be given an expiry. Still bad: until someone notices the leak, the token works up to its `expires_at`, if it has one.
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
- ~~Bad, because tokens do not expire on their own.~~ Addressed by the [update of 2026-11-13](#update-2026-11-13-expiry-and-reload) (optional `expires_at`).

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
- Revisit when operators need OIDC login for the console. (Expiry, and changes without a restart, are covered by the [update of 2026-11-13](#update-2026-11-13-expiry-and-reload).)

### Update 2026-11-13: expiry and reload

The decision above stands and is kept as written; this closes two of the gaps it listed (a leaked token valid until a restart, and no expiry) without changing the token format, the roles, the route table's rules or the audit record format.

**Expiry.** An `[[admin.operators]]` entry may carry `expires_at`, an RFC 3339 time with an offset (a quoted string or a TOML offset date-time). `AdminCredentials::authenticate(token, now)` still hashes the bearer once and compares the digest with every credential in constant time without stopping at a match; only then does it compare the matched entry's `expires_at` with `now` (the server's clock, so tests step a `ManualClock`). A match that has expired is answered 401 `admin_credential_expired`, with the same `WWW-Authenticate: Bearer realm="attenuo-admin"` as the other admin 401s; the time taken before the comparison ends does not depend on which credential matched. An entry that has already expired when the server starts is accepted, and a warning names it, so that an old entry left in the file does not stop the server; a timestamp that does not parse, or has no offset, refuses the file. `attenuo admin operator new` takes `--expires-in <n>{s,m,h,d}` or `--expires-at <RFC 3339>` (not both) and writes the field into the entry it prints. `GET /admin/whoami` adds `expires_at` (null when none), and the console shows it after the role. `[admin] token` does not expire: it is one string in the file or in `ATTENUO_ADMIN_TOKEN`, with nowhere to put a lifetime.

**Reload.** `POST /admin/operators/reload` (role `admin`, in `ROUTE_ROLES`; `attenuo admin operator reload`; the SDKs' `operators_reload` / `operatorsReload`) re-reads the `[[admin.operators]]` array, and nothing else, from the config file the server was started with (`Config::source_path`, set when the config is loaded from `--config` or `ATTENUO_CONFIG`). It checks the list with the startup rules (`operators::check_operators`, also what `Config::check_admin_operators` calls), against the `[admin] token` in force, which is not reloaded. Then it swaps the credential set in one step: the set is an `RwLock<Arc<AdminCredentials>>` (`SharedAdminCredentials`), the primitive the policy engine already uses for its reload (`SharedPolicy`), held only to copy or replace the pointer. Reloads are serialized by a mutex, from reading the file to the swap. The answer lists the names of the operators added, removed and changed (role, `token_sha256` or `expires_at`), never a digest, and an `admin.operators.reload` audit record names the caller as actor and has `{path, added, removed, changed}` as its arguments. A refusal is recorded as a `deny` with the refusal's code as reason, as a refused policy reload is.

Rules:

- `require_admin` takes one snapshot of the set per request. A request admitted before a swap completes with the identity it was admitted with; the next request is checked against the new set. So the caller may remove or demote its own entry: that reload completes, and the caller's next request is refused or limited.
- A list that would leave no credential with role `admin` that has not expired (no `[admin] token`, and no unexpired operator with role `admin`) is refused with 422 `operators_no_admin`: a typo could otherwise lock everyone out of the admin API until a restart. At startup the rule stays as it was (operators alone, any role, are enough), since a restart is how that is fixed.
- On any error nothing changes: 422 `operators_invalid` for a file that is not TOML or an entry that breaks a rule (the message never quotes the file, whose `[admin] token` line it could otherwise echo), 500 `config_unreadable` for a file that cannot be read (the cause in the log only), 409 `reload_unavailable` when the server was not started from a file (a program that builds its `Config` in code).
- Only the operators are read. The rest of the file is not reloaded, and not checked, though it must still be TOML.

Options considered for the reload, and rejected: a `SIGHUP` handler (no actor to record, and no answer to show what changed or why it was refused); watching the file (an editor's half-written save would be read, and there is no actor); reloading the whole config (most of it, listeners, keys and stores, cannot be swapped in a running server, and a partial reload of "the config" would mislead); a revocation list of token digests next to the entries (a second list to keep in step, where removing the entry already says it). For expiry: a lifetime in the token itself (the token is random bytes, deliberately not a JWT; a lifetime there would need signing and parsing for no gain over the entry).

What this still does not do: no login, no second factor, no per-operator rate limit; no expiry or reload of `[admin] token`; a leaked token works until someone withdraws it or until its `expires_at`; expiry follows the server's clock.

Confirmation: `crates/attenuo-server/src/operators.rs` tests (authentication before, at and after `expires_at` with explicit times, parsing of `expires_at`, the reload's read of the operators alone, `with_operators` and its change lists, the live-admin rule, a snapshot outliving a swap); `crates/attenuo-server/tests/admin_operators.rs` (expiry on a stepped clock, an entry expired at startup warning and refused, a malformed timestamp refused, a reload that adds, removes and changes role, digest and expiry, an invalid or missing file leaving the set in force, the lock-out refusal, role refusals, the audit records, `[admin] token` untouched, reloads racing requests); the refusal-code guard in `crates/attenuo-server/tests/e2e.rs`; `crates/attenuo-cli/tests/admin_operator.rs` (`new --expires-in`, then `reload` against a running server).

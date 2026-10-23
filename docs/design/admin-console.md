# Admin console: design

Status: draft for discussion. Date: 2026-10-23. Base: `main` at 25649d6.
Related: [ADR-0008](../decisions/0008-admin-console.md) (architecture only), RFC-0001 sections 6 and 7, `docs/design/server.md`, ADR-0006.

Attenuo has a CLI and an `/admin/*` REST surface but no UI. This document proposes an admin console for one job: let an operator read the audit log, see and revoke leases, and test policy, without a terminal. The console is a view over the admin API. It adds no authority that the admin bearer does not already have, and it does not grant anything.

## 1. Goal and non-goals

### Goal

One operator who holds the admin token can answer these questions in a browser:

- What did agents do, for which user, and was it allowed?
- Why was this one call allowed or denied?
- Which leases are alive under this run, and what happens if I revoke this one?
- Is the policy file on disk valid, what is loaded now, and would this call be allowed?
- Is the audit log intact, and how far do the signed checkpoints reach?

The console replaces these CLI views: `attenuo audit tail --follow` (`audit_tail` and `fmt_audit_entry` in `crates/attenuo-cli/src/main.rs`), `attenuo lease show` and `lease revoke`, `attenuo audit verify` (`verify_lines`), `attenuo policy reload` and `policy lint`, `attenuo authzen eval`, and the chain tree of `attenuo token inspect` (`render::render_chain_tree`).

### Screens

**Audit explorer.** A table of audit entries, newest first, one row per entry: seq, time, kind, decision, `server/tool`, the agent path (`agents` joined with `>`), originating subject, reason. Filters: kind (several), decision, reason, subject, agent, server, tool, chain id, lease, time range. "Follow" polls for new entries the way `audit tail --follow` does, using `head` from `GET /admin/audit` (which signs nothing). Each row links to the decision view; each chain id links to a filter on that chain; each lease links to the lease tree. "Export this range" downloads the NDJSON export for offline verification.

**Decision view (one entry).** Everything in the `DecisionRecord` (`crates/attenuo-core/src/decision.rs`) plus context:

- The delegation chain as a vertical list, root first: originating subject, then one row per hop with `agents[i]` and `leases[i]` (the two arrays are built from the same hops in `DecisionRecord::new`, so they pair up), and each lease's current state (active, expired, revoked with time and reason).
- Why: the reason code with a one-line explanation from a fixed table in the UI (`policy_allow`, `policy_deny`, `capability_denied`, `lease_revoked`, `lease_expired`, `lease_unknown`, `tool_not_in_catalog`, `tool_not_listed`, `invalid_name`, `dpop_required`, `session_mismatch`, and the rest of the `REASON_*` constants), the `policy_ids` that determined it, and for each id the text of that policy in the set loaded now.
- A warning when the policy set has been reloaded since the record was written (an `admin.policies.reload` record with a higher seq exists), because the policy text shown is then the current one, not the one that decided.
- Hash fields (`seq`, `prev_hash`, `entry_hash`, `chain_digest`, `arguments_digest`) and whether a signed checkpoint covers this seq.
- Other entries of the same chain (`chain_id`), so issuance, renewals, calls and revocation of one run read as a timeline.

What this view cannot show, by design of the log: tool arguments (the log stores `arguments_digest` only, RFC-0001 section 7), and the capabilities of each hop (they live in the token, not in the record). The view says so in plain words and offers "paste the token" to decode the chain locally, the same decode `token inspect` does without `--verify`. The pasted token never leaves the page.

**Lease tree.** Entered from a lease id or a chain id. Shows the path from the root lease down to the selected lease, then the subtree under it, one node per lease: agent (from its issuance record), expiry, state, revoke reason. Per lease, a renewal history (the `lease_renew` records whose last lease is this one) and its issuance and revocation records. Revoke opens a confirmation that shows how many leases would change state (the cascade preview), the list of affected agents, and a required reason. After the revoke the result count from the server is shown next to the preview count.

**Policy page.** The loaded set: file path, SHA-256 of the loaded text, policy ids, validation warnings, and the text of each policy (read-only). A "Check file on disk" button that lints the current file against the server's schema and shows issues with line and column, plus whether the file differs from what is loaded. A "Reload" button, enabled only after a clean check, that calls the existing reload endpoint. An "Evaluate this call" form: a chain (paste a token or build one hop by hop from a recent audit record), a server, a tool, and JSON arguments; the answer shows decision, reason, policy ids and the full diagnostics, without touching leases or the audit log.

**Verify and checkpoints panel.** Head seq, the newest stored checkpoints (seq, time, `kid`, signature status), `last_signed_seq` and `unsigned_tail` from verify, `bad_checkpoints` if any, the JWKS `kid`s that verify them, and readiness (`/readyz`, including `checkpoint_sink` when configured). "Verify now" runs the full walk on demand only. "Sign head now" is a separate, explicit action because it writes a checkpoint.

### Non-goals

- Granting tokens. Agents get tokens through exchange; the dev root mint (`POST /admin/root-token`) is never called by the console.
- Editing policy files in the browser in v1. The console reads, checks, reloads and evaluates; the file is edited where it lives, under review.
- Multi-tenant RBAC or per-operator identity in v1. There is one static admin bearer today (`[admin] token`); the console uses it and adds no roles.
- Replacing the CLI. Every console action stays possible from the CLI, and scripted use stays on the CLI.
- Charts and metrics dashboards. `/metrics` stays a Prometheus endpoint for existing tooling.

## 2. The existing admin API

Routes are registered in `router()` in `crates/attenuo-server/src/lib.rs`. The admin routes share one `route_layer` running `admin::require_admin` (`crates/attenuo-server/src/routes/admin.rs`): `Authorization: Bearer <[admin] token>` (or `DPoP <token>`, parsed by `routes::bearer_of`), compared in constant time; 403 `admin_disabled` when no token is configured; 401 with `WWW-Authenticate: Bearer realm="attenuo-admin"` otherwise. No route sets CORS headers (the workspace enables `tower-http`'s `cors` feature but no `CorsLayer` is used), and no route sets CSP, `X-Frame-Options` or `X-Content-Type-Options`.

| Endpoint | Method | Auth | Handler | Returns | UI use |
|---|---|---|---|---|---|
| `/admin/audit?from&limit` | GET | admin | `admin::audit_range` | `{entries, next, head}`: entries ascending from `from` (default 1), `limit` 1 to 1000 (default 100), `next` when the page was full, `head` = newest seq. Reading signs nothing. | Usable for the unfiltered "latest" view (compute `from = head - n + 1` as `audit_tail` does). **Gap:** no filters, no newest-first paging, no lookup of one entry. |
| `/admin/audit/verify` | GET | admin | `admin::audit_verify` | `SignedVerifyReport`: `entries`, `ok`, `first_bad_seq`, `checkpoints`, `last_signed_seq`, `unsigned_tail`, `bad_checkpoints`. Walks the whole chain. | Usable as is, on demand only (cost grows with the log). |
| `/admin/audit/checkpoint` | GET | admin | `admin::audit_checkpoint` (`SqliteAudit::checkpoint_signed`) | `{seq, head_hash, at, kid, signature, hash}`. **Signs and stores a new checkpoint** when the head has none. | Not a read: use only behind an explicit "Sign head now" button, never on page load or polling. **Gap:** no read-only list of stored checkpoints. |
| `/admin/audit/export?from&to&kind&chain_id` | GET | admin | `admin::audit_export` | `application/x-ndjson` stream, `Cache-Control: no-store`; filtered exports carry a `filter` header member and do not verify. | Usable as is. The UI fetches with the `Authorization` header and saves a Blob (a plain link cannot carry the header). |
| `/admin/leases/{lease_id}` | GET | admin | `admin::lease_status` | `{lease_id, active, parent, expires_at, revoked_at, revoke_reason}`; 404 for an unknown id. | Usable for one node. **Gap:** no children, no agent, no issue time; the `leases` table (`LEASE_SCHEMA` in `crates/attenuo-audit/src/sqlite.rs`) stores only `id, parent, expires_at, revoked_at, revoke_reason`. |
| `/admin/leases/{lease_id}/revoke` | POST | admin | `admin::revoke_lease` | Body `{reason?}` (`RevokeBody`, `deny_unknown_fields`, empty body allowed). `{lease_id, revoked, reason, audit_id}`; audited as `admin.lease.revoke` / kind `lease_revoke`. | Usable as is for the action. **Gap:** no dry run, so no cascade preview. |
| `/admin/policies/reload` | POST | admin | `admin::reload_policies` | `{policy_ids, warnings, sha256, audit_id}`; 409 `reload_unavailable` without `policy.policies_path`; 422 `policy_invalid` (previous set stays; audited as deny). | Usable as is for the action. **Gap:** no read of the loaded set, no check without swapping. |
| `/admin/root-token` | POST | admin, only with `[dev] allow_root_mint` | `dev_root::mint_root` | A root token. | Never used (granting is a non-goal). Not mounted on the console listener. |
| `/access/v1/evaluation`, `/access/v1/evaluations` | POST | delegation token as bearer (with DPoP proof when bound), or a `[[peps]]` credential plus `[authzen] allow_unsigned_chain` and a chain whose lease bindings match what was issued | `authzen::evaluation`, `authzen::evaluations` | AuthZEN `{decision, context{reason, policy_ids, diagnostics, decision_id}}`. Runs the full `Pipeline::decide`: lease check, policy, **and an audit `decision` record per evaluation**. Diagnostics only for PEPs by default. | Not usable for the tester as is: the admin holds no delegation token, an admin-built chain fails `chain_not_issued`, a test would fail on expired leases, and every test would write a `decision` record indistinguishable from a real call. **Gap:** an admin dry-run evaluation. |
| `/readyz` | GET | none | `ops::readyz` | `{ready, checks{audit, leases, checkpoint_sink?}, degraded?}`, 503 when not ready; error text only in the server log (SR-38). | Usable as is for a status line. |
| `/healthz` | GET | none | `wellknown::healthz` | Liveness. | Not needed. |
| `/.well-known/jwks.json` | GET | none | `wellknown::jwks` | Issuer public keys, including `previous_key_paths`. | Usable as is: list the `kid`s that verify checkpoints. |
| `/.well-known/authzen-configuration` | GET | none | `wellknown::authzen_configuration` | AuthZEN metadata. | Not needed. |
| `/metrics` | GET | none, on the separate `[metrics] listen` listener only | `metrics::router` | Prometheus text. | Not used (other port, other origin). Its exposure rule is the precedent for the console listener (below). |
| `/token`, `/token/renew`, `/mcp/{server}` | POST, GET, DELETE | agent credentials or delegation tokens | `token::exchange`, `renew::renew`, `attenuo_proxy::router` | Not admin routes. | Never called by the console. |

### Gaps, as proposed API changes

All new routes sit behind `require_admin`. All are read-only except where stated. None changes the hashed record format.

- **G1. Filtered, two-way audit paging.** Extend `GET /admin/audit` with optional `kind` (comma-separated), `decision`, `reason`, `subject`, `agent`, `lease`, `server`, `tool`, `chain_id`, `since`, `until` (RFC 3339), `order=asc|desc` (default `asc`, so existing callers see no change), and `before` (a seq, for descending pages). The response keeps `{entries, next, head}` and adds `prev`. Implementation: widen `attenuo_audit::RecordFilter` (`crates/attenuo-audit/src/export.rs`) and `SqliteAudit::range_filtered`; `decision`, `reason`, `originating_subject`, `server`, `tool`, `at`, `kind`, `chain_id` are columns already (the last four indexed). `agent` and `lease` match the JSON text with an escaped `LIKE` prefilter and an exact check on the decoded record, the same technique as `SqliteAudit::by_lease`. Because those two scan, the handler caps the seq window it scans per page (for example 50 000 rows) and returns `next` or `prev` so the client keeps paging. The renewal history of a lease is `kind=lease_renew&lease=<id>&chain_id=<root>` with a client-side check that the lease is the last one in `leases`.
- **G2. One entry.** `GET /admin/audit/entries/{seq}` and `GET /admin/audit/records/{id}` (the record UUID that proxy denials and AuthZEN answers return as `decision_id`). The second needs an index; an expression index `ON audit(json_extract(record_json, '$.id'))` created with `IF NOT EXISTS` at open is enough and does not touch hashed data. The response is `{entry, lease_states, covered_by_checkpoint, policy_reloaded_after}` so the decision view needs one request.
- **G3. Stored checkpoints, read-only.** `GET /admin/audit/checkpoints?before&limit` from the `checkpoints` table (newest first; `SqliteAudit::checkpoints_between` and `last_checkpoint` exist). Never signs.
- **G4. Lease tree with cascade preview.** `GET /admin/leases/{lease_id}/tree?max_nodes=` returns `{root, ancestors[], nodes[], would_revoke, truncated}`. `nodes` is the subtree, each `{lease_id, parent, expires_at, revoked_at, revoke_reason, active, agent, issued_at, issued_seq}`. It uses the same recursive CTE over `leases_parent_idx` as `revoke_in`, read-only, capped (default 1000 nodes). `would_revoke` counts unrevoked nodes in the subtree, which is exactly what `revoke_in` would change at that moment. Agent and issue time come from the issuance records (`kind` in `root_token`, `exchange`) of the chain, found through the indexed `chain_id` (the root lease, reached by walking `parent`). This is the "dry-run revoke" as a GET, so the preview needs no CSRF-sensitive request. It needs a new `SqliteLeaseStore::subtree` (and `MemoryLeaseStore` parity for tests); it does not need a `LeaseStore` trait change.
- **G5. Policy read and check.** `GET /admin/policies` returns `{path, sha256, loaded_at, policy_ids, warnings, policies: [{id, text}]}`. The engine does not keep the loaded digest or time today (`reload_policies` computes the digest and drops it), so `AppState` gains a small "loaded policy info" field set at startup and on reload. `GET /admin/policies/check` reads `policies_path`, runs `attenuo_policy::lint::lint` against `PolicyEngine::schema_text()`, and returns the `LintReport` plus `{sha256, differs_from_loaded}`. It swaps nothing and writes no record.
- **G6. Dry-run evaluation.** `POST /admin/policies/evaluate` with an AuthZEN `EvaluationRequest` whose `subject.properties.chain` is required, or `{token}` instead of a chain. A token is signature-checked with the server's `Verifier`; an expired token is accepted with a flag, since the question is "what would policy say". A bare chain is checked with `validate_at` only. The handler calls `PolicyEngine::authorize` (the capability stage and Cedar, as `Pipeline::decide_inner` does after the lease check), and returns `{decision, reason, policy_ids, diagnostics, lease_check: "skipped", chain_source: "token" | "admin_supplied"}`. No lease check, no audit record, no metrics decision counter. A later option `against=file` would evaluate against the on-disk file before reload.
- **G7. Response hardening on admin routes.** Every `/admin/*` JSON response gets `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Today only the export and token responses set `no-store`.

## 3. Architecture

### Options

**(a) Static files embedded in `attenuo-server`, vanilla HTML, JS and CSS, no build step.** A `ui/` directory in the server crate holds `index.html`, `app.js`, `app.css` (and perhaps one JS file per screen). They are compiled in with `include_bytes!` into a fixed table of `(path, content type, bytes)`, served under `/admin/ui/`. A hand-written table of five or so entries needs no new crate; `rust-embed` (proc macro, plus `mime_guess` and a walkdir dependency, and a debug mode that reads from disk) or `include_dir` would save a few lines and add a dependency to audit in `deny.toml`. The ETag is the SHA-256 of the bytes, computed at startup with `sha2` (already a dependency).

**(b) A TypeScript app under `ui/`, built in CI and embedded.** Same serving, but the source is TypeScript with a bundler and probably a component library. CI already runs Node for the TypeScript SDK (`.github/workflows/sdk-typescript.yml`), so the toolchain is not new. But `cargo build` and `cargo install` from source would then depend on either a Node build or a committed `dist/`, the npm tree adds hundreds of transitive packages to the supply chain of a security product, and every UI change becomes a two-toolchain change.

**(c) A separate process.** A standalone console (any stack) that calls the admin API over HTTP. It needs its own deployment and config, it holds the admin token in a second process, and it is cross-origin to the API, so the server needs CORS for `/admin/*` (which it has never had). It would make sense only if the console had to serve several attenuo servers, which is out of scope.

### Weighing

| | (a) embedded vanilla | (b) TS, embedded | (c) separate process |
|---|---|---|---|
| Dependency surface | None new (with `include_bytes!`) | npm tree at build time | New deployable, its own deps |
| CI | One Rust test that scans the assets; curl smoke | Node build before cargo; lint, type check | Separate pipeline |
| CSP | Strict: `script-src 'self'`, no inline, no `eval` | Strict is possible; bundlers sometimes need care with inline chunks | Its own policy, plus CORS on the API |
| Same origin as API | Yes | Yes | No: needs CORS and preflights |
| One maintainer can explain it | Yes, files are read as written | Needs the bundler and framework in their head | Two services to run |
| Cost when the UI grows | JS gets long; no types | Scales better | Scales, at operational cost |

### Where it is served: a dedicated console listener

Serving `/admin/ui/` on the main listener puts the console on the same origin as `/mcp/{server}`. The proxy forwards the upstream `Content-Type` for responses it does not filter (`FORWARD_RESPONSE_HEADERS` in `crates/attenuo-proxy/src/proxy.rs`), so a hostile upstream that answers with `text/html` would run script in the console's origin, if a browser could be made to load it. Today that needs a delegation token in a header, which makes it hard, but the console should not depend on that.

So the recommendation follows the `/metrics` precedent (`MetricsSection` and `check_listen` in `crates/attenuo-server/src/config.rs`, SR-38): a separate, opt-in listener.

```toml
[admin_ui]
enabled = false            # default: no console
listen = "127.0.0.1:9101"  # loopback by default
allow_public = false       # refuse to start off loopback unless set, and warn when set
allow_write = false        # mount revoke and reload on this listener only when true
```

That listener serves the embedded assets under `/admin/ui/` (with `/` redirecting there) and mounts the same admin handlers under `/admin/*` with the same `require_admin` layer. The console and its API are then same-origin, so no CORS is needed and none is added; the console is a different origin from the proxy and from `/token`. The main listener keeps `/admin/*` for the CLI, unchanged. With `allow_write = false` the console listener mounts only read routes, so "read-only by default" is enforced by the server, not only by the page. `POST /admin/policies/evaluate` counts as a read for this purpose (no side effects).

### How the browser holds the admin token

Two candidates:

1. **Header-only, token in page memory.** A login screen takes the token, checks it with `GET /admin/audit?limit=1`, and keeps it in a JS variable in a closure. Every request sends `Authorization: Bearer`. Nothing is written to `localStorage`, `sessionStorage`, cookies or URLs. Reloading the page or opening a new tab asks again. The page forgets the token after an idle timeout (15 minutes) and on "Lock".
2. **Session cookie minted from the admin token.** `POST /admin/session` with the bearer returns a random session id in a `__Host-` cookie with `HttpOnly; Secure; SameSite=Strict; Path=/`, stored server-side with an expiry, plus a CSRF token that writes must echo in a header, and an `Origin` check.

**Recommendation for v1: header-only, in memory.** Reasons:

- It adds no authentication mechanism to the server. `require_admin` stays the one check, which matters while admin auth is still the v0 static bearer.
- Browsers do not attach `Authorization` headers on their own, so there is no ambient credential and CSRF does not arise. A cookie brings CSRF back and needs SameSite, a CSRF token and an Origin check to remove it again.
- No session store, no session expiry logic, no logout endpoint, no cookie `Secure` handling on a plain-HTTP loopback listener (where `__Host-` cookies do not work).

The cost, stated plainly: a script injected into the console could read the static token and send it out, while with an `HttpOnly` cookie it could only act during the session. The mitigations are the strict CSP below (no inline script, `connect-src 'self'`, Trusted Types), rendering by `textContent` only, a short idle timeout, and the fact that the token is already rotatable through `ATTENUO_ADMIN_TOKEN`. When admin authentication becomes per-operator (OIDC or similar, the "replace with real operator authentication" note on `AdminSection::token`), the console should switch to a short-lived server session in a `__Host-`, `HttpOnly`, `SameSite=Strict` cookie with CSRF token and Origin check. Only the console's single `api()` fetch wrapper changes.

### CORS

None. The console listener serves the page and the API from one origin. The server sends no `Access-Control-Allow-Origin` on any admin route, and a test asserts that (a cross-origin `Origin` header gets no CORS headers back). The `cors` feature of `tower-http` can stay unused.

### Headers on the console listener

Every response:

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

API responses also carry `Cache-Control: no-store`. Static assets carry `Cache-Control: no-cache` with an ETag, so a server upgrade never serves a stale script.

### Recommendation and upgrade path

Choose (a), served on the opt-in `[admin_ui]` listener, header-only token in memory. It adds no dependency, keeps one toolchain, allows the strictest CSP, and every file can be read and reviewed as shipped.

Upgrade path: the console talks only to documented JSON endpoints, so the API is the contract. If the vanilla code outgrows one maintainer (rough signal: more than about 2 000 lines of JS, or a need for shared components and types), move to (b) with the same listener, the same paths, the same headers and the same embed mechanism; a superseding ADR records it. Moving to (c) stays possible because nothing in the API assumes the console is embedded.

## 4. Security

### Threat model deltas

The console adds a browser to the admin trust boundary. Before it, the admin token lived in a shell and the audit content was printed as text.

| Threat | Where it comes from | Mitigations (mechanism) |
|---|---|---|
| **XSS from audit content.** Stored strings reach the page. | Caller-controlled strings are stored verbatim: `tool` and `server` (a name that fails `ToolCall::check_names` is still recorded with reason `invalid_name`, and AuthZEN `action.name` becomes `tool`), `session_id` (client header), `originating_subject` (IdP `sub`), `revoke_reason` (admin text), policy ids and policy text, lint messages, error `detail`. Tool arguments are not stored (only `arguments_digest`), which removes the largest vector but not the others. | (1) The page builds DOM with `createElement` and `textContent` only; no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, inline handlers or `javascript:` URLs. (2) CSP `script-src 'self'` with no `'unsafe-inline'` and `require-trusted-types-for 'script'` makes the browser refuse those sinks. (3) A Rust unit test scans the embedded JS for the forbidden sinks and fails the build. (4) API responses are `application/json` with `nosniff`, so opening one directly never renders HTML. (5) Long values are truncated for display with the full value in a copyable field. |
| **CSRF on revoke and reload.** | A page on another origin makes the operator's browser send a write. | (1) Header-only auth: there is no ambient credential, so a cross-site form, image or `fetch` without the token gets 401. (2) No CORS, so a cross-site script cannot read responses or send a preflighted `Authorization` header. (3) On the console listener, admin `POST`s require `Content-Type: application/json`, which a cross-site form cannot send. (4) If a cookie session is ever added, it must come with `SameSite=Strict`, an `Origin` check and a CSRF header token; the ADR records this as a condition. |
| **Clickjacking a revoke.** | The console framed by another page. | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. |
| **Token theft from the browser.** | Storage, history, logs, referrers, extensions. | Token held in a closure variable only; never in `localStorage`, `sessionStorage`, cookies, URLs or query strings (the export download uses `fetch` plus a Blob, not a link with a token). `Referrer-Policy: no-referrer`. `connect-src 'self'` and `img-src 'self'` block the simple ways to send it elsewhere. The login field is `type=password autocomplete=off`. Idle timeout of 15 minutes and a "Lock" button clear it. The server never echoes the token. |
| **Disclosure of audit records to non-admins.** | A console listener reachable from a network; a shared browser's cache. | Console off by default; loopback by default; start refused off loopback without `allow_public` (same rule as `[metrics]`, SR-38), with a startup warning when set. Every data route keeps `require_admin`; only the static assets are public, and they contain no data. `Cache-Control: no-store` on API responses. |
| **Accidental or hurried destructive action.** | A misclick, the wrong lease id. | Server side: `allow_write = false` by default, so revoke and reload are not mounted on the console listener. Page side: the page opens read-only; writes need "Enable changes" for the session; revoke shows the cascade preview (`would_revoke`, affected agents), requires a reason, and requires typing the last 6 characters of the lease id; reload is enabled only after a clean check of the same file digest. Every write is already audited (`audit_admin`). |
| **Admin-supplied chains in the evaluate tester.** | An admin evaluates a chain nobody issued. | `POST /admin/policies/evaluate` writes no audit record and touches no lease, so a made-up chain cannot leave records in a user's name (the concern behind SR-08 and `chain_not_issued`). Its answer is labelled `chain_source: admin_supplied` and `lease_check: skipped`. |
| **Load from expensive reads.** | Full verify walks; `LIKE` scans for agent and lease filters. | Verify runs only on click, with one verify in flight at a time (a server-side guard returns 429 to a second). Filtered queries cap the scanned window per page. Page size stays capped at `MAX_AUDIT_PAGE` (1000). |
| **Guessing the admin token.** | The console listener is one more place to try it. | Unchanged rules: 32-byte minimum and placeholder refusal off loopback (`check_admin_token`), constant-time compare. Not new, but noted: there is no rate limit on failed admin auth on either listener. |

### What does not change

The console adds no authority. Every action it takes is an existing admin action or a read. It holds no state on the server. The dev root mint is never mounted on the console listener, whatever `[dev] allow_root_mint` says.

## 5. v1 scope, in PR-sized steps

Server-side API first, so each step is useful from the CLI and `curl` before any page exists. Each PR keeps `cargo fmt`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo deny` green.

### PR 1: Audit query API (G1, G2, G3, G7)

Changes: filters and descending paging on `GET /admin/audit`; `GET /admin/audit/entries/{seq}`; `GET /admin/audit/records/{id}` with the expression index; `GET /admin/audit/checkpoints`; `no-store` and `nosniff` on admin JSON.

Acceptance:
- Existing calls without new parameters return byte-identical JSON shape (`entries`, `next`, `head`) in ascending order.
- Each filter returns exactly the matching entries; `agent=l1` does not match `l10`; `%` and `_` in a value match literally.
- `order=desc&before=N` pages back to seq 1 with no gaps or repeats.
- `GET /admin/audit/checkpoints` leaves the `checkpoints` row count unchanged.
- Unknown `kind` is 400; missing bearer 401; no admin token configured 403.

Tests: new `crates/attenuo-server/tests/admin_api.rs` (filters, paging both ways, lookup by seq and by id, 404s, auth); unit tests in `crates/attenuo-audit/src/sqlite.rs` for the widened `range_filtered` and the index migration on an existing database.

### PR 2: Lease tree and cascade preview (G4)

Changes: `SqliteLeaseStore::subtree` (and `MemoryLeaseStore` parity); `GET /admin/leases/{lease_id}/tree`.

Acceptance:
- For a root, child and grandchild, the tree of the child lists the root as ancestor and the grandchild as node, with agents from the issuance records.
- `would_revoke` equals the `revoked` count that `POST .../revoke` returns right after, for fresh, partly revoked and fully revoked subtrees.
- The endpoint never changes a row (`revoked_at` unchanged before and after).
- `max_nodes` caps the answer and sets `truncated`.

Tests: in `admin_api.rs`, built through real exchanges as in `tests/e2e.rs`; a store unit test with a parent cycle to show the CTE terminates.

### PR 3: Policy read, check and dry-run evaluate (G5, G6)

Changes: loaded-policy info in `AppState`, set at startup and on reload; `GET /admin/policies`; `GET /admin/policies/check`; `POST /admin/policies/evaluate`.

Acceptance:
- After a reload, `GET /admin/policies` shows the new `sha256` and ids; after a failed reload it still shows the old ones.
- `check` on a broken file returns issues with line and column and leaves the loaded set in force.
- For a chain from a real token with active leases, `evaluate` returns the same decision, reason and policy ids as `POST /access/v1/evaluation` with that token.
- `evaluate` leaves the audit head unchanged and works with a revoked lease (`lease_check: skipped`).
- A token with a bad signature is 400; a bare chain that fails `validate_at` is 400.

Tests: `admin_api.rs` cases for each; a comparison test between the dry run and the AuthZEN route over a small table of calls (allow, `policy_deny`, `capability_denied`, `tool_not_in_catalog`).

### PR 4: Console listener and hardening

Changes: `[admin_ui]` config section with `check_listen` mirroring `MetricsSection`; a second router with the read routes (and write routes when `allow_write`); security-header middleware; JSON content-type requirement on console `POST`s; a placeholder `index.html` served from the embedded table; `serve` starts the listener like the metrics task.

Acceptance:
- Disabled by default; enabled on loopback starts; off loopback without `allow_public` refuses to start with a clear message.
- `GET /admin/ui/` returns 200 HTML with the exact CSP and other headers; unknown asset paths 404; assets have correct `Content-Type`.
- `POST /admin/leases/x/revoke` on the console listener is 404 with `allow_write = false` and works with `true`.
- A request with `Origin: https://evil.example` gets no `Access-Control-*` headers.
- `/admin/root-token` is never mounted on the console listener.

Tests: config unit tests in `config.rs`; router tests in a new `crates/attenuo-server/tests/admin_ui.rs`.

### PR 5: Console pages (v1)

Changes: `crates/attenuo-server/ui/` with `index.html`, `app.js` (hash routes: `#/audit`, `#/entry/{seq}`, `#/lease/{id}`, `#/policy`, `#/verify`), `app.css`; the reason-code explanation table; login and lock; the five screens of section 1.

Acceptance:
- Every screen works against a server started with `config/example.toml` plus `[admin_ui] enabled = true`.
- An audit record whose `tool` is `<img src=x onerror=alert(1)>` shows as literal text and creates no `img` element.
- Reload of the page asks for the token again; nothing appears in Web Storage or cookies.
- Revoke shows the preview count, needs the typed suffix and reason, and shows the server's count after.

Tests: a Rust unit test that scans every embedded `.js` asset for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, `javascript:` and inline `on*=` in the HTML; `scripts/admin-ui-smoke.sh` (start the server, `curl` the page and assert headers, `curl` each admin endpoint with and without the token) run in the `demo` CI job. A Playwright test for the XSS record and the revoke flow, kept outside required CI at first (see question 5).

### PR 6: Docs, threat model, ADR

Changes: `docs/guides/admin-console.md` (enable, reach over SSH tunnel, what each screen shows and cannot show); update the route table in `crates/attenuo-server/src/lib.rs` docs and in `docs/design/server.md` (routes and Known limits); new SR entries in `docs/spec/threat-model.md` for the console listener and the browser token; ADR-0008 moved to `accepted`; `docs/decisions/README.md` index row; CHANGELOG entry.

Acceptance: `mdbook build` and `scripts/check-links.py` pass; the guide's commands run as written.

## 6. Open questions for the owner

1. **Token in the browser: header-only in memory, or a session cookie?** Recommended: header-only for v1, because it adds no auth code and no CSRF surface; switch to a `__Host-`, `HttpOnly`, `SameSite=Strict` session with CSRF token when per-operator admin auth exists.
2. **Separate console listener, or `/admin/ui/` on the main listener?** Recommended: separate, opt-in, loopback by default, like `[metrics]`. It keeps the console off the proxy's origin and lets the server enforce read-only.
3. **Should the dry-run evaluator write an audit record?** Recommended: no. Admin reads are not audited today, and a `decision` record for a call nobody made would blur what the log means. Revisit when admin actions carry an operator identity.
4. **Allow writes from the console in v1 at all?** Recommended: yes, behind `allow_write = true` (default false), with both revoke and reload; revoke is the reason operators will open the console during an incident.
5. **Playwright in CI?** Recommended: not in required CI for v1. The asset scan and the `curl` smoke cover the security properties with no Node dependency in the Rust pipeline; run Playwright locally, or add it later as an optional job next to the TypeScript SDK job.

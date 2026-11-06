# Security review, pass 9

- Date: 2026-11-06
- Branch: `research/security-pass-9` (base: `5b85f43` on main)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [pass 6](security-review-2026-10-25-pass6.md), [pass 7](security-review-2026-10-25-pass7.md), [pass 8](security-review-2026-11-05-pass8.md), [threat model](../spec/threat-model.md), [task board](../tasks/board.md)

## Scope and method

What merged after pass 8 and SR-90, `git log 71d35bd..5b85f43` (89 commits, #166 to #190), plus #164 (argument matching on every call when a policy asks), which merged just before that range and had not been read by a pass. In order of how much was read:

- the approval notifier and its outbox (#168): `attenuo-server` `notify.rs` (`WebhookNotify`, `Emitter`, `OutboxSettle`, `recover`, `watch_expiry`, `signature`, `notice_json`), the generic queue in `sink.rs` (`Queue`, `QueueHandle::push`, `run`, `Settle`), `config.rs` `NotifySection::validate`, `attenuo-audit` `sqlite/outbox.rs`, `routes/ops.rs` (`/readyz`);
- argument matching (#164): `authz/pipeline.rs` `matches_arguments` and `arg_taint`, `attenuo-core` `fingerprint.rs` (`fingerprints`, `collect_strings`, `entities`, `bare_host`, `winnowed_kgrams`), both stores' `find_spans` and `add_spans`;
- the injectable clock (#170, #188): `attenuo_core::clock`, `build_with_clock`, `router_with_clock`, `StreamGuard::with_clock`, every `state.now()` and `state.clock` reader, `main.rs` and `serve`;
- the shared `Authorization` parser and JSON-RPC codes (#169): `attenuo_core::authorization::token_of` against the two parsers it replaced, both `bearer_of` callers and `require_admin`;
- the `decimal` catalog type (#190): `attenuo-policy` `request.rs` `decimal_text`, `typed_cedar_json`, `input_matches`, `check_tool_inputs`, the schema change, the `limits.rs` test of fractional amounts under `sum`, `calls_per` and `distinct`, and the proxy's re-encoding of forwarded arguments;
- SR-90's `http_trace::request_span` and the tower-http defaults for `on_request`, `on_response` and `on_failure`;
- the `authz.rs` split (#180) and the `unreachable_pub` and `missing_docs` changes (#172, #173, #177, #183): module visibility in every crate's `lib.rs` before and after, the `testing` features and who enables them, a line-set comparison of the old `authz.rs` against the new submodules;
- `AuditError` to `ApiError` (#187): `error.rs` and the routes that now use the mapping;
- the Python SDK root exports (#176).

The attacker is as in pass 8: (a) the holder of a narrow child token, (b) a revoked or expired token, (c) a malicious MCP upstream (A3), (d) the admin token on a console listener without `allow_write`; plus, for the notifier, a token holder who wants an operator not to hear about some other run's approval. Costs were measured, not estimated: release build, in-memory SQLite store, this VM (4 vCPU, 15 GiB).

Every fix here has a regression test that fails on `5b85f43` and passes on this branch, except SR-95, which corrects documentation and pins the behaviour it describes. Findings are numbered from SR-91.

## Summary

| Severity | Found | Fixed here | Proposed (lead decides) | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 1 | 0 | 1 | 0 |
| Low | 1 | 0 | 1 | 0 |
| Info | 4 | 3 | 1 | 0 |
| **Total** | **6** | **3** | **3** | **0** |

| ID | Severity | Component | Title | Status |
|---|---|---|---|---|
| SR-91 | Medium | server (`authz/pipeline.rs` `arg_taint`, both stores' `find_spans`) | One call's arguments are looked up with no bound on probes or hits: seconds under the store lock and gigabytes of memory per call | Proposed |
| SR-92 | Low | server (`notify.rs`, `sink.rs` `QueueHandle::push`) | One run can push every other run's approval notices out of the queue and the expiry watcher | Proposed |
| SR-93 | Info | server (`notify.rs` `recover`) | On restart, open outbox rows beyond `queue_capacity` are given up without one attempt | Proposed |
| SR-94 | Info | server (`sink.rs` `WebhookDeliver`, `S3Deliver`) | A failed checkpoint delivery logged the sink URL, query string included | Fixed, test `a_failed_webhook_delivery_does_not_log_the_url_sr94` |
| SR-95 | Info | policy (`request.rs` `decimal_text`), docs | "Never rounded" for `decimal` inputs does not hold for numbers with more digits than a double | Fixed (docs), test `digits_beyond_a_double_are_rounded_by_the_parse_alike_for_cedar_and_upstream_sr95` |
| SR-96 | Info | server (`notify.rs` `ApprovalNotifier::start`) | The plain-http warning missed `HTTP://` and loopback addresses other than `127.0.0.1` | Fixed, test `plain_http_to_another_host_is_detected_in_any_case_sr96` |

## Findings

### SR-91: one call's arguments are looked up with no bound on probes or hits (Medium, proposed)

- **Component.** `attenuo-server` `authz/pipeline.rs` `Pipeline::arg_taint` (lines 1026 to 1087) and `matches_arguments` (1004); `attenuo-audit` `sqlite/leases.rs` `find_spans` (1160) and `lease.rs` `MemoryLeaseStore::find_spans` (1807).
- **Observation.** `fingerprints` caps one value at `MAX_FINGERPRINTS_PER_VALUE` (2,000) fingerprints from its first 1 MiB, and the module docs present that as the bound. `arg_taint` calls it once per argument (`pipeline.rs:1041`), so a call's probe count is the number of arguments times up to 2,000, with no total. Probes are not deduplicated across arguments. `find_spans` then runs one indexed query per probe inside one transaction on the lease store's only connection, holding its mutex, and returns every `(probe, seq)` pair, with no limit on how many results (`seq`) one hash has: a run holds up to `MAX_SPANS_PER_RUN` (20,000) hashes, so one hash can sit under up to 20,000 results. `arg_taint` collects the hits into a `BTreeSet<UntrustedArg>`, one entry per argument name and `seq`, each with its own `String`, before the record keeps 64.
- **Who reaches it.** Any token holder, on a run it has tainted (any untrusted result does it), for any call: `matches_arguments` is true for every call when a loaded policy reads argument taint (#164), and otherwise for a destructive tool or for a tool the engine does not know. The last case needs nothing from the policy: `arg_taint` runs before Cedar and before the capability check, so a `tools/call` of a made-up tool name the token does not cover is fingerprinted and looked up, and then denied.
- **Measured.** Release build, SQLite store in memory, through `Pipeline::decide` (a scratch test, not committed):
  - 190,000 arguments `"k000001": "xxxxxxxx"` (a 4 MB body, under the proxy's default 4 MiB `max_request_body_bytes`), a run with one earlier result `xxxxxxxx`: 0.41 s for one call, decided `capability_denied`. Of that, `find_spans` holds the store mutex for about 0.25 s; every lease check, token exchange and approval of every other client waits on it.
  - The same call after 200 results that each held `xxxxxxxx` (200 reads of any tool that reflects text the agent chose): 13.3 s for one call and a peak resident size of 5.5 GB. `find_spans` alone returned 19 million hits for 100 such results. Memory grows with arguments times results, so about 1,000 results exhaust this host with one call, and a few calls in parallel need far fewer.
  - Distinct probes: 532,000 fingerprints from 3 MB of host-name tokens spread over 266 arguments took 0.31 s to compute and 0.25 s of lookups under the lock, with no earlier results at all.
- **Exploit path.** A compromised or injected agent (or anyone holding a child token) taints its own run with ordinary reads, then sends `tools/call` requests with a few hundred thousand short arguments to a tool name that does not exist. Each call stalls the lease store for the whole server for between a fraction of a second and several seconds, and once the run has a few hundred results holding the same short string, each call allocates gigabytes until the process is killed. Enforcement fails closed while the server is down, so this is availability only: no call is allowed that would not be.
- **Proposed patch** (behaviour changes, so not applied):
  1. In `arg_taint`, bound the probes of one call: deduplicate fingerprints across arguments (keep the owners as a list per fingerprint), and stop at a total of `MAX_ARG_PROBES` (for example `4 * MAX_FINGERPRINTS_PER_VALUE`). Past the bound, fail closed as for an unreadable index: every unpinned argument with a fingerprint counts as untrusted with kind `unreadable`, and the diagnostics say `arguments carry more than N fingerprints; unpinned arguments treated as untrusted`. A legitimate call is nowhere near 8,000 distinct fingerprints.
  2. In `LeaseStore::find_spans` (both stores), return at most a few `seq` per probe (`ORDER BY seq LIMIT 8` in SQLite, `take(8)` in memory). The record keeps 64 entries anyway, and Cedar only needs to know which arguments matched.
  3. Optionally, run `arg_taint` after the capability check, so a call the token cannot make is not fingerprinted at all; today the order is lease check, labels, budgets, `arg_taint`, approvals, policy.

  A regression test: a call with 100,000 arguments sharing one leaf, after 50 results holding it, decided within a fixed time and with every argument named `unreadable`; and a `find_spans` call with one probe whose hash sits under 1,000 results returning at most the bound.

### SR-92: one run can push every other run's approval notices out of the queue (Low, proposed)

- **Component.** `attenuo-server` `notify.rs` `NotifierHandle::pending` (508) and `Watch::add` (428); `sink.rs` `QueueHandle::push` (320).
- **Observation.** Every new pending approval queues an `approval.pending` notice and adds the approval to the expiry watcher. The queue (default 256) drops its oldest item when full, whoever it belongs to, and marks its outbox row given up; the watcher refuses new approvals past `MAX_WATCHED` (10,000), counting a drop. Nothing bounds the pending approvals of one run: `create_approval` reuses a pending approval only for the same call hash, so a run that varies one argument of a gated call creates a new approval, and a new notice, per call. One delivery thread posts the queue in order, so a receiver that takes 50 ms per notice drains 20 a second.
- **Exploit path.** A token holder whose policy gates its calls on approval (for example `confirm_destructive_with_untrusted_args`) sends a few hundred gated calls a second with distinct arguments. The queue fills with its notices and the notices of other runs, queued before them, are dropped: the operator is not told that another user's call is waiting, and that call expires. With 10,000 approvals pending the watcher is full and later approvals of any run get no `approval.expired`. Low: notifications are documented as best effort, every approval stays in the store, the audit log and the console, and nothing is allowed that would not be; the attacker can only make the operator miss someone else's request, as SR-86 could with awaited calls.
- **Proposed patch.** Cap the pending approvals of one run in `create_approval` (both stores), for example 32: past the cap the call is denied with diagnostics `too many pending approvals for this run`, as a failed store would deny it. That bounds the approvals table and the notices together. Alternatively, as SR-86 did, drop the oldest queued notice of the run with the most queued notices when the queue is full (`QueueItem::group`, the chain id for a notice, `None` for a checkpoint), and give the watcher a per-run share.

### SR-93: on restart, open outbox rows beyond `queue_capacity` are given up without one attempt (Info, proposed)

- **Component.** `attenuo-server` `notify.rs` `recover` (679).
- **Observation.** `recover` reads up to `MAX_WATCHED` (10,000) open rows and pushes them all into a queue of `queue_capacity` (default 256), oldest first. Each push past the capacity drops the oldest queued notice, and `OutboxSettle` marks its row given up (`Settled::Dropped`), so after a restart with 1,000 open rows (a receiver that was down while SR-92's flood or ordinary traffic ran) 744 notices are closed without one delivery attempt, logged as `queue full`. Rows beyond 10,000 are left open and are only read at the next restart. The design note says a dropped notice is marked given up, but `recover` reads as if it delivered "the rows still open". No security effect beyond SR-92's: notices are best effort.
- **Proposed patch.** Read at most `queue_capacity` rows in `recover`, and have the delivery thread read the next batch of open rows from the outbox (`outbox_open` after the last row id) when the queue runs empty, so open rows are delivered in order without being dropped for lack of room. Smaller alternative: read only `queue_capacity` rows and leave the rest open until the next restart, which keeps them but delays them indefinitely; not recommended.

### SR-94: a failed checkpoint delivery logged the sink URL, query string included (Info, fixed)

- **Component.** `attenuo-server` `sink.rs` `WebhookDeliver::deliver` (728 on `5b85f43`) and `S3Deliver::deliver` (924).
- **Observation.** Both formatted a transport error as `request failed: {e}`, and `reqwest::Error`'s `Display` ends with `for url (<url>)`. reqwest moves user info into the `Authorization` header, but the path and the query stay, so an `[audit.sink] url` that carries a credential in its query (a pre-signed or tokened ingest URL) was written to the log on every failed attempt (`[audit.sink] delivery failed; retrying`) and on every degraded `/readyz` (`last_error`). The approval notifier added in #168 already strips the URL (`e.without_url()`, "log lines name its host only"); the checkpoint sink it shares the queue with did not. The `/readyz` body itself never had the error. The S3 endpoint has no credential in it (SigV4 is in headers), and is changed for consistency.
- **Fix and evidence.** Both use `e.without_url()`. Test `sink::tests::a_failed_webhook_delivery_does_not_log_the_url_sr94` delivers to `http://127.0.0.1:1/ingest/path-marker?token=secret-marker` and checks that the error names neither marker; it fails on `5b85f43`.

### SR-95: "never rounded" for `decimal` inputs does not hold for numbers with more digits than a double (Info, fixed in the docs)

- **Component.** `attenuo-policy` `request.rs` `decimal_text` (134); `docs/reference/config.md` (`inputs`) and `docs/guides/writing-policies.md` (argument types).
- **Observation.** The docs say a `decimal` argument with more than 4 fractional digits is "refused, never rounded", and the code comment says "the digits are the ones the caller wrote". `decimal_text` does not round, but it sees the number after serde_json parsed it into a double, which already rounded it when it had more digits than a double holds: `0.10000000000000001` arrives as `decimal("0.1")` and `1000000000000.00001` as `decimal("1000000000000.0")`, both accepted, where `12.34567` is refused.
- **Why it is not exploitable.** There is no differential: the proxy forwards the arguments re-encoded from the same parsed value (`proxy.rs:1200`), and serde_json writes a double in its shortest form, the same text `decimal_text` uses, so the upstream is sent exactly the number Cedar compared. Other inputs were checked and are as documented: `-0` and `-0.0` are `0.0`, `1e-7` and `0.00001` are refused, `1e3` is `1000.0`, `9223372036854775807`, `18446744073709551615` and `1e300` are refused, a JSON number cannot be NaN or infinite, sets of decimals go element by element with `null` dropped as for every set, and `sum`, `calls_per`, `distinct` and run usage read the raw JSON number, not the Cedar value (a `sum` refuses a fraction, as the #190 test shows).
- **Fix.** The doc comment, `config.md` and `writing-policies.md` say what the parse rounds and that the upstream is sent the same value. Test `request::tests::digits_beyond_a_double_are_rounded_by_the_parse_alike_for_cedar_and_upstream_sr95` pins it: three such numbers give the same text to `decimal_text` and to the re-encoding, and a fifth fractional digit within a double's precision (`99999999999.99999`, `12345678901.23456`) is still refused. It passes on `5b85f43` as well: the change is the documentation.

### SR-96: the plain-http warning missed `HTTP://` and loopback addresses other than `127.0.0.1` (Info, fixed)

- **Component.** `attenuo-server` `notify.rs` `ApprovalNotifier::start` (578 on `5b85f43`).
- **Observation.** The warning for notices sent unencrypted tested `cfg.url.starts_with("http://")` on the configured string, while `validate` parses the URL, whose scheme is case-insensitive: `HTTP://hooks.example/` is accepted and posted over plain http with no warning. The loopback exemption listed `localhost`, `127.0.0.1` and `[::1]` only, so `127.0.0.2` was warned about. A log line only; the operator chooses the URL.
- **Fix and evidence.** `plain_http_off_loopback` reads the parsed scheme and treats `localhost` (any case) and any loopback IP address as local. Test `notify::tests::plain_http_to_another_host_is_detected_in_any_case_sr96`; it fails on `5b85f43`'s logic.

## Checked and found sound

- **Notifier delivery.** The URL must be `http(s)` with a host, no user info and no fragment; redirects are not followed (`Policy::none()`), so a receiver cannot bounce the request, its headers or the signature to another host. It is operator configuration, so SSRF towards it needs the config file. Header values come from the environment, are marked sensitive, and `content-type`, `content-length`, `host`, `transfer-encoding` and `x-attenuo-*` cannot be set. The secret must be 32 bytes or more; startup errors name variables, never values; `Debug` of `WebhookNotify` shows the host only, and delivery errors use `without_url`. The signature is HMAC-SHA-256 over `<t>.<body>` with `t` taken at each attempt, so a receiver can refuse a replay; the config reference tells receivers to compare in constant time. Backoff is `initial * 2^min(n,31)` saturating and capped at `max_backoff_seconds`, with jitter between half and all of it, and every zero is refused by `validate`; attempts saturate and give up at `max_attempts`.
- **What a notice carries.** Ids, the server and tool names, the call hash, the user's subject and issuer, the last agent, the chain depth, times, the approver's subject and method, and a reason line built from label source names and an argument count. No token, argument value, label content or untrusted text. The outbox row stores that body and nothing more.
- **Outbox and recovery.** `event_id` is a UUIDv8 over a label, the type and the approval id, unique in the table, so a notice of one type is stored once per approval and an expiry found again after a restart inserts nothing. Settling updates only open rows; pruning deletes only settled rows; open rows are never pruned. A row of an unknown type is skipped with a warning, not sent. The watcher reads the approval again at its due time and sends `approval.expired` only if it is still pending and expired by the store's own rule. Nothing in the notifier writes to the approvals or leases, so no failure there changes a decision (SR-92 and SR-93 aside, which are about notices).
- **Injectable clock.** `ManualClock` is public in `attenuo-core` but only constructed in tests: `main.rs` calls `serve`, which calls `build`, which passes `system_clock()`; `router` passes `system_clock()`, and `StreamGuard::new` defaults to it. No config key, environment variable or route selects a clock. `ManualClock` only moves forward, so a misused one would expire sessions and record windows early, never late. An embedder calling `build_with_clock` chooses its own clock, as documented.
- **`token_of` (#169).** The same function as the two it replaced: split at the first space, scheme `Bearer` or `DPoP` in any case, token trimmed and not empty, the scheme not trimmed. The proxy and the server keep their own handling of an absent and a non-ASCII header and their own 401 bodies (`expected \`Bearer <token>\``, `missing_token`/`invalid_token`), so SR-17's reason codes are unchanged; no caller-controlled text reaches a log line through it, so SR-18 is unaffected. `require_admin` still compares in constant time. The JSON-RPC codes moved with the same values (`-32003`, `-32008` and the rest).
- **`http_trace::request_span` (SR-90).** tower-http's default `on_request`, `on_response` and `on_failure` log latency and status or the failure class, never headers or the URI; the span has `method`, `route` (the template or `unmatched`) and `version`. The proxy's own `mcp_request` span records the subject at info level, as before (Debug-formatted, SR-18) and the session as a hash prefix (SR-11).
- **Visibility (#172, #173, #177, #180, #183).** No module or item became more visible: in `attenuo-server`, `actor`, `clientauth`, `idp`, `jwks` (now `issuer_keys`), `replay` and `state` went from `pub` to `pub(crate)`; the only new public modules are `attenuo_core::{authorization, clock, jsonrpc}` and `attenuo_proxy::http_trace`. The `testing` features of `attenuo-proxy` and `attenuo-audit` are enabled only from `[dev-dependencies]`, so the shipped binaries do not contain the fake MCP server or the WAL fault hooks. The split `authz` submodules contain the old file's lines apart from visibility qualifiers and imports; the token cache (`VerifiedTokens`) still revalidates the chain at every hit.
- **`AuditError` to `ApiError` (#187).** The mapping is the one the routes used before, now in one place with a test that every variant is classed; every store fault is a 500 with `INTERNAL_DETAIL` (SR-43). The 4xx details quote only the id the caller sent (`unknown lease \`<id>\``) or a fixed sentence; `ApprovalNotPending` names the state, as before, and the user routes still answer an approval of another run or of a dead token with the same 404 as an unknown one.
- **Python SDK root exports (#176).** Constants (`ENTRY_HASH_VERSION`, `EXPORT_FORMAT`, `GENESIS_HASH`, `PROOF_TYPE`) and pure functions (`entry_hash`, `capabilities_to_json`) were added. Nothing secret, no key material and no new network call; `decode_token`, which verifies nothing, was already exported and says so.

## Standing checks

- `cargo deny check`: see the gate in the log entry for this pass.
- `cargo audit` is not installed here (as in passes 1 to 8); CI runs `rustsec/audit-check`.
- Fuzzing: `policy_context` (which covers `to_cedar_json` and the declared-type check, not yet `decimal`) ran for 120 s on nightly with no crash; the other targets were not run. Adding `ArgType::Decimal` and `Set<decimal>` to that target's catalog is a cheap follow-up.

## Not covered

- The AuthZEN routes, the IdP intake and the CLI were not re-read beyond the lines this range changed.
- The evaluation suite and the bench crate were not run. The SR-91 measurements are from a scratch test against `Pipeline::decide` and `SqliteLeaseStore::find_spans`, not through the proxy over HTTP; the proxy adds JSON parsing and screening of the same body before the pipeline, which only adds time.
- The design notes merged in this range (#178, #181, #182, #189) are proposals and were read only where they describe shipped code.
- Deployments with more than one server process on one store.

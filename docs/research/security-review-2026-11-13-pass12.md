# Security review, pass 12

- Date: 2026-11-13
- Branch: `fix/security-pass-12` (base: `a0712f2` on main, for the review and the fixes)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [pass 6](security-review-2026-10-25-pass6.md), [pass 7](security-review-2026-10-25-pass7.md), [pass 8](security-review-2026-11-05-pass8.md), [pass 9](security-review-2026-11-06-pass9.md), [pass 10](security-review-2026-11-06-pass10.md), [pass 11](security-review-2026-11-12-pass11.md), [threat model](../spec/threat-model.md), task board

## Scope and method

What merged after pass 11, #245 to #298 (`c2bce7f..a0712f2`). In order of how much was read:

- #287 and #292, admin operators: `operators.rs` whole (credentials, the constant-time match, expiry, `ROUTE_ROLES`, the reload parser, `SharedAdminCredentials`), `routes/admin.rs` `require_admin`, `whoami`, `reload_operators` and `audited_refusal`, the `[admin]` config section and its startup checks, the router of the main, admin and console listeners (`lib.rs`, `admin_ui.rs`), and where the operator is recorded (`routes/mod.rs` `audit_admin`, `approvals.rs`, `dev_root.rs`). The console's use of `whoami` was read for DOM sinks only;
- #288, `private_key_jwt`: `clientauth.rs` whole, `replay.rs`, the call sites in `routes/token.rs`, `idp/intake.rs` and `routes/authzen.rs`, `attenuo-token` `client_assertion.rs`, and the order of the DPoP checks in `dpop.rs`;
- #284, #285, #267 and #246, storage: `sqlite/migrations.rs`, `sqlite/replay.rs`, `sqlite/filesystem.rs` and `state.rs` `open_storage` and `filesystem_verdict`;
- #254, #258, #261 and #265: `limits.rs` whole, `config/overrides.rs` whole, `routes/page.rs` whole and the store calls its positions reach, `[admin] listen` and its startup checks;
- #279 and #281, ID-JAG -06: the diff of `idp/mod.rs`, `idp/claims.rs` and `idp/intake.rs`;
- #272, #291 and #294, error codes: the diffs of `error.rs`, `renew.rs`, `token.rs`, `authzen.rs` and `dev_root.rs`, compared with what `detail` said before;
- #256, #257, #259, #266, #270 and #278, demo, Docker, SDK and CLI: `docker-compose.yml`, the IdP demo's script, config and mock IdP, the CLI's `--admin-server` routing, the Python SDK's retry and nonce retry. Read for secrets in argv or logs, binds off loopback, and credentials resent elsewhere.

Documentation, evaluation and test-only pull requests (#245, #249, #250, #252, #253, #260, #262, #264, #268, #269, #271, #273, #275, #276, #277, #282, #283, #286, #289, #290, #293, #295 to #298) were checked for secrets and personal data only, with `scripts/check-public-hygiene.py`. #237 and #263 (a dependency bump and a trait split) were read for behaviour changes only.

The review was done by reading the code. Each finding was labelled "confirmed by reading" (the lines are cited) or "suspected", and then got a test written before any fix, which shows whether it reproduces. All four reproduced. The tests of SR-108 and SR-111 failed before their fix. SR-109 and SR-110 are proposals, not fixed, so their tests pin today's behaviour and will change with the maintainer's choice. The attacker is as in pass 11, plus a sub-agent that holds its own client key (A2 in the threat model) and an unauthenticated caller of `POST /token`. Findings are numbered from SR-108.

Denial of service is out of scope as a security property in the threat model. SR-108 and SR-109 are recorded anyway because each is a case of an opt-in `[limits]` protection not doing what its documentation says.

## Summary

| Severity | Found | Fixed (here) | Proposed (maintainer decides) | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 0 | 0 | 0 | 0 |
| Low | 1 | 1 | 0 | 0 |
| Info | 3 | 3 (SR-111; SR-109, SR-110 after the pass) | 0 | 0 |
| **Total** | **4** | **4** | **0** | **0** |

| ID | Severity | Component | Title | Status |
|---|---|---|---|---|
| SR-108 | Low | server (`routes/token.rs`, `idp/intake.rs`, `limits.rs`) | An agent over `token_requests_per_minute` still had its client assertion recorded, one replay-store write per refused request | Fixed, test `a_rate_limited_agent_does_not_spend_its_assertion_sr108` |
| SR-109 | Info | server (`limits.rs` `token_peer_limit`) | A full per-peer table refuses every new address, so agents with good credentials are refused before they can authenticate | Fixed after the pass (#300, option 2), tests `a_full_peer_table_still_serves_an_authenticated_agent_sr109`, `a_full_peer_table_lets_agents_authenticate_sr109` |
| SR-110 | Info | server (`clientauth.rs` `verify_assertion`) | A refused client assertion tells an unauthenticated caller which client ids have keys, and whether one key or several | Fixed after the pass (#300, option 1), test `an_assertion_refusal_does_not_tell_which_client_ids_have_keys_sr110` |
| SR-111 | Info | server (`routes/token.rs`, `idp/intake.rs`, `dpop.rs`) | With `dpop_nonce = "required"`, the `use_dpop_nonce` retry of a request with a client assertion was refused as a replay | Fixed, test `a_nonce_retry_can_resend_its_assertion_sr111` |

## Findings

### SR-108: a rate-limited agent still used up its client assertion (Low, fixed)

- **Confirmed by reading.** `routes/token.rs` (at `a0712f2`) records the assertion at line 345 (`client.commit(&state.replay, now)`) and checks `[limits] token_requests_per_minute` at line 364 (`state.limits.admit_agent`). `idp/intake.rs` does the same at lines 148 and 153.
- **Attacker.** A sub-agent that holds its own client key (A2), on a server with `token_requests_per_minute` set.
- **Observation.** The rate limit exists so that one agent cannot make the server do unbounded work; the comment at line 363 says it runs "before the subject token, the lease lookups, signing and the audit append". The replay-store write came before it, so an agent over its limit still made one `BEGIN IMMEDIATE` transaction on the database per request, and took one slot of the replay store until the assertion's `exp` plus the skew (up to `client_assertion_max_lifetime_seconds` plus `client_assertion_clock_skew_seconds`, 360 seconds by default). That store is shared by every single-use credential (ID tokens, ID-JAGs, actor tokens, exchanges, approvers' ID tokens). When it holds `DEFAULT_REPLAY_CAPACITY` (100,000) live markers it refuses every new one with `503 replay_cache_full`, so one agent with a key could block hop 0, exchanges and approvals for every user for a few minutes, whatever its limit said. The replay module already says filling the store takes 100,000 live credentials from authenticated agents; the limit was meant to bound that and did not.
- **Second effect.** A client that waited out `Retry-After` and sent the same request again, as the SDKs' opt-in retry does, was refused `client_assertion_replayed`, because the refused request had used the assertion up.
- **Reproduced.** With `token_requests_per_minute = 1`, the second exchange and the second hop-0 request were answered `429` and each added a replay marker (3 instead of 2 after the exchange).
- **Fix.** Both handlers check the limit before the assertion is recorded, without counting (`Limits::check_agent`, over the new `RateLimiter::check`, which is `peek` that also sets the key's first-refusal flag so the warning is still logged once a minute). The request is counted afterwards by `admit_agent`, as before. A request refused by the limit therefore leaves its assertion unused and writes nothing. Requests of one agent that arrive together can all pass the check before any of them is counted, so an agent can write as many markers past its limit as it has requests in flight at that moment; `max_in_flight` bounds that, where nothing did before.
- **Rejected.** Counting the request before the assertion is recorded (`admit_agent` first): a replayed assertion would then count against the agent, so whoever captured one assertion could use up the agent's minute until it expires. With the check first and the count after, a replay is refused at the store and not counted.
- **Test.** `private_key_jwt::a_rate_limited_agent_does_not_spend_its_assertion_sr108` (exchange and hop 0: the `429` adds no marker, and the metric counts two refusals); `limits::tests::check_counts_nothing_and_shares_the_first_refusal`. The first failed before the fix.

### SR-109: a full per-peer table refuses every agent that is not in it (Info, fixed)

- **Confirmed by reading.** `limits.rs` (at `a0712f2`) `token_peer_limit` calls `limiter.peek(&key, ...)` at line 576 and refuses anything but `Admit` at line 577, before the handler runs. A request that authenticated an agent is not counted (line 587), so an agent's address is never a key of the table. `RateLimiter::peek` answers `Full` for a key it does not hold when the table holds `rate_limit_max_keys` keys inside their minute (lines 341 to 345).
- **Attacker.** Anyone who can reach `POST /token` from `rate_limit_max_keys` addresses (10,000 by default, at least 100; an IPv6 address counts by its /64) within one minute, on a server with `token_unauthenticated_requests_per_minute` set (off by default).
- **Observation.** One request from each address, with no or bad credentials, fills the table. From then on every address not in the table is refused `429` (`table_full`) before authentication, and since agents never enter the table, every agent's token request is refused, at hop 0 and at every exchange, for as long as the flood keeps the table full. The flood is light: 10,000 requests a minute. Without the peer limit the same flood is 10,000 failed authentications and agents are not affected, so turning the protection on is what makes them fail. ADR-0014 chose "a full table refuses new callers" so that a flood cannot push out the count of the one being limited; it does not say that callers who would never be counted are refused too. The threat model leaves floods from many addresses to the network in front of the server, hence Info.
- **Reproduced.** In the unit test, an agent from 192.0.2.1 is answered `200`; after one unauthenticated request from each of 100 other addresses (with `rate_limit_max_keys = 100`), the same agent from the same address is answered `429`, counted as `table_full`.
- **Proposed (maintainer decides).** Not fixed, because each option changes what ADR-0014 decided or what a configuration does:
  1. When the table is full, let a request from a new address run, and count it nowhere. Agents keep working; an attacker with more addresses than the table holds gets unlimited unauthenticated attempts from the new ones, which the threat model already leaves to the network.
  2. Keep refusing, but let a request through when it carries client credentials (a secret, an assertion or an actor token) for an id that exists, and refuse it only if it then fails to authenticate. Agents keep working and the limit keeps its bound; the cost is that the refusal of a failing request comes after the authentication work, which the peer limit was meant to spare.
  3. A second, small table for addresses that recently authenticated an agent, checked before the full-table refusal. Agents that were seen keep working; a new agent address during a flood is still refused.
  4. Keep the behaviour and document it in the reference and the deploy guide: with the peer limit on, a flood from many addresses refuses agents too, and `rate_limit_max_keys` should be raised accordingly.

  Option 2 is the closest to what the limit promises; option 4 is the smallest change.
- **Test.** `limits::tests::a_full_peer_table_refuses_an_authenticated_agent_sr109` pins today's behaviour and will change with the option chosen.
- **Fixed after the pass** in #300, with option 2 ([ADR-0014 update](../decisions/0014-request-limits.md#update-2026-11-13-a-full-peer-table-lets-agents-authenticate-sr-109)). A request from an address not in a full peer table is not refused before the handler; the handler refuses it before any work unless it carries client credentials and no actor token, and one that then authenticates no agent gets the same `429` as before, counted as `table_full`. Agents with client credentials are served during the flood; an agent that sends an actor token is still refused, because verifying one may fetch its issuer's keys. A peer in the table over its limit is still refused up front. The cost: on a full table a new address gets one client authentication per request (a digest compare or one signature verification), bounded in concurrency by `max_in_flight` and not in rate. Tests `limits::tests::a_full_peer_table_still_serves_an_authenticated_agent_sr109` and `tests/limits.rs` `a_full_peer_table_lets_agents_authenticate_sr109` (the server's handler, simulated peer addresses).

### SR-110: a refused client assertion tells which client ids have keys (Info, fixed)

- **Confirmed by reading.** `clientauth.rs` (at `a0712f2`) `verify_assertion` looks the client up by the unverified `sub` at line 526 and refuses an unknown id, or one without keys, as `UnknownClient`, whose code is `client_authentication_failed` (line 707). For an id that has keys it goes on to the algorithm (line 533), the `kid` (lines 537 and 543) and the signature (line 556), each with its own code: `client_assertion_unsupported_alg`, `client_assertion_unknown_kid`, `client_assertion_bad_signature` (lines 708 to 710).
- **Attacker.** Anyone who can send `POST /token`, or a body to the AuthZEN endpoints for `[[peps]]`, with no credential.
- **Observation.** An assertion signed with any key of the caller's own and naming a client id is answered `client_authentication_failed` when no entry with keys has that id, and `client_assertion_bad_signature` (one key) or `client_assertion_unknown_kid` (several keys, no `kid`) when one does. Trying `kid` values tells which ones exist too. The secret path takes care not to reveal this: it compares against a dummy digest for unknown ids "so timing does not reveal which ids exist" (module docs, and lines 458 to 460). The early return is also a timing difference, but the codes say it outright. Agent ids are not secrets (they appear in every delegation token's `act`), so the information is small, hence Info; it does help aim a guess at the ids that use keys and at the PEP ids, which appear in no token.
- **Reproduced.** Against the test configuration: `planner` (one key) `client_assertion_bad_signature`, `coder` (two keys) `client_assertion_unknown_kid`, `reviewer` (secret only) and `nobody` `client_authentication_failed`.
- **Proposed (maintainer decides).** Not fixed, because the codes are documented sub-codes in `ERROR_CODES` and the HTTP reference, and clients may already branch on them:
  1. Answer `client_authentication_failed` for an unknown id, a bad algorithm, an unknown `kid` and a bad signature alike, and keep the specific reason in the debug log line (which already records it). RFC 6749 asks for `invalid_client` and nothing more. The three codes stay in the table for the log, or are removed from it.
  2. As 1, but only for the signature-stage codes, and move the algorithm check before the lookup (the allowed algorithms are server-wide, so `client_assertion_unsupported_alg` reveals nothing about a client). `unknown_kid` and `bad_signature` become `client_authentication_failed`.
  3. Keep the codes and say in the HTTP reference that they reveal which client ids have keys.

  Option 1 matches the secret path; option 3 keeps the most help for an operator setting up keys.
- **Test.** `private_key_jwt::an_assertion_refusal_tells_which_client_ids_have_keys_sr110` pins today's behaviour and will change with the option chosen.
- **Fixed after the pass** in #300, with option 1 ([ADR-0017 update](../decisions/0017-private-key-jwt.md#update-2026-11-13-one-answer-until-the-signature-verifies-sr-110)). An unknown id, an entry without keys, an unknown `kid`, a key of another algorithm and a bad signature are one answer, `client_authentication_failed` with one `detail`; the reason is in the debug log. The `alg` allowlist and the `kid` type are checked before the lookup and keep their codes; `client_assertion_bad_signature` and `client_assertion_unknown_kid` are removed. A refusal with no key of the client to verify with verifies against a decoy key of the same algorithm, so an unknown id costs a signature verification too; an RSA key larger than the decoy's 2048 bits still verifies more slowly. Tests `an_assertion_refusal_does_not_tell_which_client_ids_have_keys_sr110` (six cases, byte for byte, at an exchange and at hop 0) and `refusals_after_the_signature_keep_their_codes_sr110`.

### SR-111: the nonce retry of a request with a client assertion was refused as a replay (Info, fixed)

- **Confirmed by reading.** `dpop.rs` module docs: with `dpop_nonce = "required"`, a proof without a current nonce is refused with `use_dpop_nonce` "before its `jti` is recorded, so the client retries once with a new proof carrying the nonce". The proof's check runs in `bind_exchange` and `bind_new`, at `routes/token.rs` line 378 and `idp/intake.rs` line 155 (at `a0712f2`), after the client assertion was recorded (lines 345 and 148).
- **Attacker.** None: this is a failure of a documented combination, recorded because it is how SR-108 was found and has the same cause.
- **Observation.** The Python SDK's `_request` resends the same body with a new proof on `use_dpop_nonce`, and the CLI builds the body, assertion included, once before its nonce retry. So with `[token] dpop_nonce = "required"` and `private_key_jwt`, the first token request of every SDK client (the SDK keeps the nonce afterwards) and every CLI token request failed with `client_assertion_replayed`. Nothing was let through; requests were refused that should have passed.
- **Reproduced.** With `dpop = "optional"` and `dpop_nonce = "required"`, an exchange and a hop-0 request answered `use_dpop_nonce`; the same body with a nonce-carrying proof was answered `401 client_assertion_replayed`.
- **Fix.** Before the assertion is recorded, both handlers run the checks the binding will make on the request's `DPoP` header proof, nonce included, without recording its `jti` (`Dpop::check_header_first`; nothing when there is no header or `dpop = "off"`). A proof the binding would refuse is refused first, so the assertion stays unused and the client's retry goes through. The binding still checks and records the proof. The answer is the same as before for every request but one that was refused for two reasons, which now gets the DPoP refusal first. The HTTP reference says which two refusals leave an assertion unused (this one and SR-108's).
- **Rejected.** Recording the assertion after the binding: the subject token is verified between the two in an exchange, so assertions would also survive refusals that the client is not told to retry, which changes ADR-0017's rule that an assertion authenticates one request whatever its outcome. Making a fresh assertion on every retry in the SDKs and the CLI: it fixes the shipped clients but not others, and the server's nonce design promises that the retry works.
- **Test.** `private_key_jwt::a_nonce_retry_can_resend_its_assertion_sr111` (exchange and hop 0; the assertion is still used once: a third send is `client_assertion_replayed`). It failed before the fix. `dpop::server_nonce_required_through_the_proxy` passes unchanged.

## Checked and found sound

**Admin operators (#287, #292)**

- `authenticate` hashes the bearer once and compares the digest with every credential in a loop that never stops early; the match is selected with `found |= hit.wrapping_neg() & (i + 1)`, without a branch on the comparison. The only branch is on the result after the loop, which the answer reveals anyway. `ct_eq32` folds with OR and compares once. The loop's length is the number of credentials, which is not a secret.
- Expiry is checked after the comparison, with `at <= now` against `state.now()`, the server's clock (the injectable one in tests); `has_live_admin` uses `now < t`, the same boundary.
- Roles: `required_role` falls back to `admin` for a route without an entry and for no `MatchedPath`; `HEAD` is looked up as `GET`. The test that parses `lib.rs` and `admin_ui.rs` covers both listeners: the console's `POST /admin/leases/revoke` (its preview-only handler) is the same template and needs `operator`. Unknown `/admin/...` paths never reach `require_admin` and answer 404.
- Reload: one at a time (`operators_reload` mutex) from reading the file to the swap; a request keeps the snapshot it was admitted with; the file is read once, so there is no check-then-read gap; the new list is checked as at startup against the `[admin] token` in force. A reload that leaves no unexpired `admin` is refused; one whose only `admin` expires a second later passes, which is what the rule promises (no lock-out by a typo, not by time). A reload that removes the caller lets that request finish, as documented.
- What a reload reveals: the TOML error is rebuilt from its message and line, never the quoted line (which could be `[admin] token`); a `token_sha256` that is not 64 lowercase hex is refused without repeating it; the `config_unreadable` cause goes to the log only; the audit record of a refused reload holds the path and the code, not the message. The success answer and record name operators, never digests. `Debug` of the credentials prints names and roles.
- Names are `[a-z0-9_-]{1,64}` and never `admin`, so `urn:attenuo:admin:<name>` cannot hold a colon, a control character or a long string, and cannot be `urn:attenuo:admin`. The operator is the actor of every admin audit record, the approver subject of approvals decided through the admin API, and the default revoke and refund reason.
- `[[admin.operators]]` cannot be set by an environment override (an array of tables), and the digest collision check against `[admin] token` runs after `ATTENUO_ADMIN_TOKEN` and `ATTENUO__ADMIN__TOKEN` are applied. A digest equal to an agent's `secret_sha256` is not refused; that needs an operator to reuse a secret by hand, and is not a finding.
- The console shows `whoami` without an HTML sink.

**`private_key_jwt` (#288), beyond SR-108, SR-110 and SR-111**

- Algorithms: the header `alg` must parse and be in `CLIENT_ASSERTION_ALGS` (`RS256`, `ES256`, `EdDSA`), so `none` and every HMAC are refused, and it must equal the one algorithm the key was bound to at startup from its type and curve; `jsonwebtoken` then verifies with `Validation::new(key.alg)`. An `oct` key and any private member are refused at startup.
- `kid`: no `kid` selects the only key or is refused; a `kid` must match exactly; a non-string `kid` is malformed.
- `aud` is the issuer identifier exactly, as a string or an array whose every element is it; `iss` and `sub` are non-empty, equal, and equal the request's client id when it sends one. The checks on `iss` and `sub` read the unverified payload, but it is the same base64url segment the signature covers, parsed by the same JSON parser.
- Lifetime: `exp` is required; `now >= exp + skew` is expired; `exp > now + max + skew` is too long; `nbf` and `iat` may not be ahead of `now + skew`. All of it is saturating `i64` arithmetic over `numeric_date`, which refuses NaN, infinities and out-of-range floats. `max_lifetime` 0 refuses to start.
- Replay: the key is client kind, client id and `jti` (at most 256 bytes), stored as its SHA-256 until `exp + skew`, in the persisted store; only an assertion whose signature verified reaches the store, so an unauthenticated caller cannot add markers. Secret and assertion together are `multiple_client_auth`.
- Key sets come from the config, so their size, the RSA modulus (2048 bits minimum, no maximum) and the exponent are the operator's.

**Storage (#246, #267, #284, #285)**

- Migrations run one per `BEGIN IMMEDIATE` transaction that also sets `user_version`, so a crash leaves the file at the last completed version; a file above `SCHEMA_VERSION` is refused before anything is read, so an older binary does not downgrade a file. The migration of approvals keeps every row and position.
- `used_credentials`: the `INSERT ... ON CONFLICT DO UPDATE ... WHERE expires_at <= now` is the decision, in one transaction for all of a request's keys; a full store rolls back. Keys are digests, so the table holds no credential.
- Network filesystems: the check reads the filesystem of the database's directory once symbolic links are resolved. An unknown answer (a `statfs` error, an unsupported platform) is logged and allowed, by design: the check stops a known-bad placement and is not a security boundary, and no attacker chooses where the database lives. A single file bind-mounted from a network filesystem into a local directory is not detected, nor are GFS2 and OCFS2, as the module says.

**Admin listener, `[limits]`, environment overrides, cursors (#254, #258, #261, #265)**

- The per-peer key comes from the accepted connection (`ConnectInfo`), never from a header, so it cannot be spoofed; behind a reverse proxy every caller shares the proxy's address, which the reference says. The per-agent key is the authenticated agent and the per-run key the verified root lease. Every table is bounded by `rate_limit_max_keys`, and an unauthenticated caller can reach only the per-peer one (SR-109).
- The handler deadline's exemptions read the raw path; axum does not normalise `..`, so `/admin/../token` does not reach `/token` without its deadline.
- Overrides: `[dev]` keys, lists, name tables and arrays of tables are refused; every error names the variable and never the value (`expected_part` drops any message part that holds the value); applied overrides are logged by key and variable name. A variable can set `[admin] token`, which is then checked for strength and against operator digests like the file's.
- Cursors hold a version, the list, the direction and a position, nothing from the data, and are checked for all four; a position above `i64::MAX` is clamped by the store. As `page.rs` says, forging one only starts a page where the caller could page to anyway.

**ID-JAG -06 (#279, #281)**

- `aud` must be a string or a one-element array; `jti` is required and non-empty; a `cnf` without `jkt` is refused rather than treated as a bearer grant; a bound ID-JAG needs a DPoP proof by that key, and with `dpop = "off"` it is refused. `tenant` must equal `[[idps]] tenant` when one is set, and an empty one refuses to start. Every check runs after the signature, so its message can name the credential's own values. The ID-JAG `typ` with or without `application/` is accepted, and an ID token whose `typ` ends in `+jwt` is still refused.

**Error codes (#272, #291, #294)**

- The new specific codes repeat what `detail` already said (`lease_revoked`, `lease_expired`, `lease_unknown` were the whole `detail` of a refused renewal), or are reached only after a token's signature verified (`token_expired` on an exchange, `invalid_chain` for an authenticated PEP). None tells an unauthenticated caller something it could not learn before. `admin_credential_expired` is answered only to someone who presents that operator's token.

**Demo, Docker, SDK and CLI (#256, #257, #259, #266, #270, #278)**

- Compose publishes only the agent listener, on the host's `127.0.0.1`, keeps the admin listener inside the compose network, and requires `ATTENUO_ADMIN_TOKEN` from the shell. The mock IdP binds `127.0.0.1`. The IdP demo's secrets are fixed demo values on a loopback server and are shown as such.
- The SDK retries only `429 rate_limited` and `503 overloaded`, to the same URL, with new DPoP proofs. The CLI sends `/admin/*` with the admin token to `--admin-server` when given and to `--server` otherwise, as before; the new 404 hint changes no request.

## Not covered

- The review was done by reading; the tests above were added afterwards. Fuzzing was not run beyond the compile check.
- SR-108 and SR-111 were measured with the in-process test server, not with the SDKs or the CLI against a running server; the SDK and CLI behaviour on `use_dpop_nonce` and `429` is from reading their code.
- SR-109 was measured in the limiter's middleware with simulated peer addresses, not with real connections from many hosts.
- The TypeScript SDK's retry was not read; the Python one was.
- The console scripts were read for DOM sinks and the use of `whoami` only.
- `cargo deny` checks the dependency tree; `rustix`, which #285 made a direct dependency of `attenuo-audit` for `statfs`, was not reviewed beyond that.

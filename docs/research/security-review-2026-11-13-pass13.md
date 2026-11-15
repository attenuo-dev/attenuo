# Security review, pass 13

- Date: 2026-11-13
- Branch: `fix/security-pass-13` (base: `c7b796f` on main, for the review and the fixes)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [pass 6](security-review-2026-10-25-pass6.md), [pass 7](security-review-2026-10-25-pass7.md), [pass 8](security-review-2026-11-05-pass8.md), [pass 9](security-review-2026-11-06-pass9.md), [pass 10](security-review-2026-11-06-pass10.md), [pass 11](security-review-2026-11-12-pass11.md), [pass 12](security-review-2026-11-13-pass12.md), [threat model](../spec/threat-model.md), task board

## Scope and method

What merged after pass 12's fixes, #301 to #308 (`5e4de11..c7b796f`), then two areas pass 12 left uncovered, then free hunting. In order of how much was read:

- #303, the SDKs' load retry bounded by the client assertion's `exp`: `_wire.py` `assertion_expiry`, `_retry.py` `left_until` and `RetryPolicy.delay`, `client.py` `_request` and `_retrying` (sync and async); `wire.ts` `assertionExpiry`, `retry.ts`, `client.ts` `post`, `retrying` and `exchange`; and the HTTP layer under both (`_http.py`, `http.ts`), for where a resent request can go. Read as if the assertion came from someone else: huge, negative, fractional and non-finite `exp`, deep nesting, non-UTF-8, and a server that chooses `Retry-After` and the status;
- #305, the verified-token cache holding `Arc<Claims>`: `authz/authorizer.rs` whole, `attenuo-token` `Verifier::verify`, and every reader of the cache;
- #308, `invalid_client` for no credential under `actor_auth = "actor_token"`: the diff of `routes/token.rs` and `idp/intake.rs`, the `exchange` handler from the body to `exchange_sync`, `limits.rs` `token_peer_limit` and `refuse_on_full_table`, `error.rs` (the headers of a 401), `actor.rs` (when an actor token is recorded as used);
- #304 and #307, the Lean model and its CI: `scripts/check-lean.sh`, `scripts/check-lean-differential.sh`, `proofs/lean/lakefile.toml`, `lake-manifest.json` and `lean-toolchain`, the `lean` job of `.github/workflows/ci.yml`, and the elan installer script it runs, at the pinned commit;
- from pass 12's "Not covered": the TypeScript SDK's retry (read whole, above) and the CLI's HTTP client, which pass 12 read for argv and logs only; and #300 (SR-109 and SR-110, fixed after pass 12 and described there but not reviewed by it): `clientauth.rs` `verify_assertion` and the decoy, the full-table path in `routes/token.rs`;
- free hunting: `path_prefix` (`capability.rs` `parse_path`, `path_within`, `implies`) against Unicode and decoding tricks the Lean model also leaves out; the admin route roles (`operators.rs` `ROUTE_ROLES`) against what each read route returns; the console's API calls built from the location hash; the approval notifier's outbound surface (`notify.rs`).

Documentation and evaluation pull requests (#301, #302, #306) were checked for secrets and personal data only, with `scripts/check-public-hygiene.py`.

The review was done by reading the code. Every suspected issue then got a test or a concrete request sequence against the real code; three reproduced and are the findings below, and the ones that did not are listed under "Not confirmed". SR-112 was first recorded as a proposal; the maintainer chose option 1, and it was fixed on this branch. The attacker is as in pass 12: an unauthenticated caller of `POST /token`, a sub-agent with its own client key (A2), and for #303 also whoever supplies the client assertion an SDK is handed or controls what answers at the server URL. Findings are numbered from SR-112.

## Summary

| Severity | Found | Fixed (here) | Proposed (maintainer decides) | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 0 | 0 | 0 | 0 |
| Low | 1 | 1 (SR-112) | 0 | 0 |
| Info | 2 | 2 (SR-113, SR-114) | 0 | 0 |
| **Total** | **3** | **3** | **0** | **0** |

| ID | Severity | Component | Title | Status |
|---|---|---|---|---|
| SR-112 | Low | CLI (`client.rs`), TypeScript SDK (`http.ts`, `mcp.ts`) | A `307` or `308` from the server URL sent the token request body, client secret or assertion included, to another origin | Fixed (option 1): no client follows a redirect, and a 3xx is an error naming its `Location`; tests in `crates/attenuo-cli/tests/redirect.rs`, `sdk/typescript/test/redirect.test.ts`, `sdk/python/tests/test_client.py` |
| SR-113 | Info | Python SDK (`_wire.py` `assertion_expiry`) | A client assertion with an `exp` beyond the float range, or nested deeper than the JSON decoder recurses, made `exchange` raise `OverflowError` or `RecursionError` | Fixed, tests `test_assertion_expiry_of_a_payload_it_cannot_use_is_none_sr113`, `test_an_exchange_with_an_unusable_assertion_exp_gets_the_servers_answer_sr113` |
| SR-114 | Info | CI (`ci.yml`, job `lean`) | The elan installer was pinned to a commit, but downloads whichever elan release is latest, with no checksum | Fixed: the v4.2.4 release binary, checked by sha256 |

## Findings

### SR-112: a redirect from the server URL took the token request body to another origin (Low, fixed)

- **Confirmed by reading.** The CLI built its client with `reqwest::Client::builder().timeout(...)` (`crates/attenuo-cli/src/client.rs` lines 98 to 100 at `c7b796f`), so it followed up to ten redirects, reqwest's default. The TypeScript SDK called `fetch(url, init)` with no `redirect` member (`sdk/typescript/src/http.ts` lines 87 and 109), so it followed them too (`redirect: "follow"`). On a `307` or `308` both sent the same method and body to the new location. Both drop `Authorization` when the origin changes, and neither dropped the body or the `DPoP` header. The Python SDK's `httpx` client did not follow redirects (`follow_redirects` is false), and the server's own outbound clients are all built with `redirect::Policy::none()` (SR-02, S-8).
- **Attacker.** Whoever controls what answers at the configured server URL without being attenuo: a reverse proxy or load balancer in front of it with a redirect rule (for example a host-name or scheme canonicalisation that answers `308`), a compromised one, or an endpoint the client was pointed at by a wrong `ATTENUO_SERVER`. Not a network attacker against `https`, who cannot answer for the server's name.
- **Observation.** A token request carries what authenticates the agent in its body: `client_secret`, or a `client_assertion` that is good for one request until its `exp`, or an `actor_token`; and the `subject_token` (the parent delegation token, or the user's ID token or ID-JAG at hop 0). After a `307` to another origin, all of it, with the `DPoP` proof made for the server's `/token`, goes to that origin. The proof's `jti` is unused (the request never reached attenuo), so whoever receives it can replay the whole request to the real server within the proof's age; a client secret is long-lived and works from anywhere. Pass 11 and pass 8 noted that `fetch` drops `Authorization` on a cross-origin redirect and that `httpx` does not follow redirects, and stopped there; the body was not considered. Admin calls lose their bearer token on the way, so the other origin gets the body only (a revoke selector, an approval decision, a policy evaluation). The same applies to every other request the CLI and the TypeScript SDK make, but only `/token` and the approval decision carry credentials in the body.
- **Severity.** Low: it takes something answering at the server URL that is not attenuo, and on the path an operator chose. The impact was the agent's credential, reusable by the receiver, and the SDKs disagreed with each other on it.
- **Reproduced.** A listener on 127.0.0.1 answering every request with `307 Location: http://127.0.0.1:<other port>/collect`, and a second listener recording what it gets. `attenuo token exchange --client-secret-file` and `AttenuoClient.exchange(..., { clientId, clientSecret })` each delivered the body, with the client secret and the subject token, to `/collect`; `Authorization` did not arrive. `attenuo lease revoke` with `ATTENUO_ADMIN_TOKEN` delivered the selector and not the token.
- **Options considered.** The pass first recorded four, since each changes what a client does against a deployment that redirects today: (1) follow no redirects, as the Python SDK and the server already do, and report a 3xx as an error that names the `Location`; (2) follow redirects only within the server URL's origin; (3) follow them only for requests without credentials in the body; (4) keep the behaviour and document it. The maintainer chose option 1.
- **Fix.** Every request the CLI makes goes through one client built with `redirect::Policy::none()` (`client.rs` `http_client`), the server, the admin listener, `health` and `approval verify --jwks <url>` alike, and a 3xx fails with `refuse_redirect`'s error, exit 1: `error: <url> answered 307 Temporary Redirect (Location <location>); attenuo does not follow redirects, so --server must be the final URL, the one that answers without a redirect` (`--admin-server` or `--jwks` when that is the URL concerned). The TypeScript SDK's `Http.send`, which every `AttenuoClient` and `AdminClient` request goes through (streamed calls and the JWKS fetch included), passes `redirect: "manual"` in `init`, so a `fetch` given in the options gets it too, and throws `ApiError` with `status` the 3xx, `error` and `code` `redirect_not_followed`, and a message naming the request, the status and the `Location`; a browser's opaque redirect (status 0, no readable `Location`) is read as one too. `ApiError` rather than `TransportError`, because the server did answer: a `TransportError` means no answer, and a caller may retry one, while a redirect answers the same every time. `mcpFetch` asks for manual redirects whatever the caller's `init` says and hands the 3xx to the MCP library as it is, since it is a `fetch` and not a client. The Python SDK already followed none; its `HttpClient.send`, which every request goes through, now raises the same `ApiError` `redirect_not_followed` with the same message, so both SDKs answer a 3xx alike. BREAKING for clients: a server URL that redirects (`http://` to `https://`, one host name to another) is now an error instead of a silent second request; give clients the final URL.
- **Server-side clients, checked again.** Every outbound client of the server follows no redirect: the approval notifier (`notify.rs`), IdP and `[[actor_trust]]` key fetches (`idp/jwks.rs` `fetch_client`, used by `actor.rs` too), the checkpoint webhook and S3 sinks (`sink.rs`), and the OTLP exporter (`telemetry.rs`), all `redirect::Policy::none()`; the proxy's upstream client too (`attenuo-proxy` `proxy.rs`, SR-02), which relays a 3xx's status and drops its `Location`. The other `reqwest` clients in the server crates are in test modules. No separate finding.
- **Test.** CLI: `a_307_does_not_send_the_client_secret_to_the_other_origin_sr112`, `a_307_on_an_admin_request_is_refused_sr112` and `health_reports_a_redirect_and_exits_1_sr112` (the other origin gets no request within 500 ms; the error names the status and the `Location`). TypeScript: five tests in `redirect.test.ts` (an exchange and an admin call against real listeners, a `fetch` from the options asked for `"manual"`, a browser's opaque redirect, `mcpFetch` given `redirect: "follow"`). Python: `test_a_redirect_is_an_error_naming_its_location_sr112` (sync and async, real listeners) and `test_no_client_follows_redirects_sr112`. The CLI and TypeScript exchange tests, written first to pin the old behaviour, showed the other origin receiving the client secret.

### SR-113: an assertion `exp` no deadline can hold made the Python SDK raise (Info, fixed)

- **Confirmed by reading.** `_wire.py` `assertion_expiry` (at `c7b796f`, line 409) returns any integer `exp` as it is (line 430) and catches only `AttenuoError` and `ValueError` around `json.loads` (line 424). `_retry.py` `left_until` (line 70) computes `deadline - _now()`, which for an integer beyond the float range raises `OverflowError`. `client.py` `_retrying` evaluates `left_until(resend_until)` on every answer, success included (lines 216 and 671), before deciding whether to retry.
- **Attacker.** None who gains anything: whoever hands the client an assertion it did not mint (a separate signing service, say). Recorded because #303 made the SDK read a part of the assertion it did not read before, and it should not fail differently from the server.
- **Observation.** An assertion whose payload has an `exp` of 309 to 4300 digits made every `exchange` raise `OverflowError` after the request was sent and answered, so the caller saw neither the token nor the server's refusal. A payload nested deeper than Python's JSON decoder recurses raised `RecursionError` before the request was sent. The server refuses both (`numeric_date` and `serde_json`'s depth limit), so nothing was let through; the client raised an exception type it does not document. The TypeScript SDK reads both as no `exp` (`Number.isFinite` and a `catch` around `JSON.parse`).
- **Reproduced.** `assertion_expiry` of `{"exp": 1` followed by 400 zeros `}` returned the integer, and `left_until` of it raised `OverflowError`; of 100,000 nested arrays, `RecursionError`.
- **Fix.** `assertion_expiry` reads an `exp` outside the server's `i64` range, integer or float, as no `exp`, and catches `RecursionError`. An assertion without a readable `exp` is retried as before #303 and left to the server.
- **Test.** `test_assertion_expiry_of_a_payload_it_cannot_use_is_none_sr113` (three payloads) and `test_an_exchange_with_an_unusable_assertion_exp_gets_the_servers_answer_sr113` (sync and async: a `429` then `200` returns the token). Both failed before the fix.

### SR-114: the Lean CI job ran whichever elan release was latest (Info, fixed)

- **Confirmed by reading.** The job downloaded `elan-init.sh` from `raw.githubusercontent.com/leanprover/elan/227caca.../elan-init.sh`, a pinned commit, and the comment above the job said elan's installer was pinned. The script itself downloads `https://github.com/leanprover/elan/releases/latest/download/elan-<arch>.tar.gz` and runs it, with no version and no checksum.
- **Attacker.** Whoever can publish an elan release (a compromise of that project's release process). The job runs with `contents: read`, no secrets, on `pull_request` (not `pull_request_target`) and with `save-if: false` on the Rust cache, so what such a binary could do is limited to that runner and the job's result, which the required `all checks` job depends on.
- **Reproduced.** The pinned script, fetched and read: the download line is `curl -sSfL "$ELAN_UPDATE_ROOT/latest/download/elan-$_arch.tar.gz"`.
- **Fix.** The job downloads `releases/download/v4.2.4/elan-x86_64-unknown-linux-gnu.tar.gz`, checks its sha256 (`42b94d42...1f63`, the binary reports `elan-init 4.2.4 (227caca13 2026-08-25)`, the commit the job had pinned) and runs `elan-init` from it, as the docs workflow does for mdBook. Run locally with a scratch `HOME`: the check passes and elan installs. What remains: elan then downloads the Lean toolchain that `proofs/lean/lean-toolchain` names (`v4.35.0`) from the Lean 4 releases, by name and without a hash pinned in this repository.
- **Test.** None that runs here: it is a workflow change. The step was run by hand as written.

## Not confirmed

- **Win32 trimming of trailing dots and spaces in `path_prefix` values.** On Windows a path segment's trailing `.` and spaces are trimmed after relative segments are evaluated, so `/w/.. ` (with a space) is not a `..` segment to `parse_path` and could become `..` later. From the documented order of Win32 normalisation, the relative segments are resolved first, so the trimmed `..` is a literal name, not a step up; no Windows host was available to check, so this is neither a finding nor ruled out. `path_prefix` does not claim to model Win32 normalisation beyond the separators it lists.
- **NFKC then percent-decode.** `parse_path` accepts `/w/％２ｅ％２ｅ/x` (full-width `％`, `２`, `ｅ`), which NFKC turns into `%2e%2e` and a percent-decode then into `..`. Found no tool that normalises and then decodes a path; a tool that decodes twice is what `%25` is refused for (SR-105). Not a finding without such a tool.
- **Overlong UTF-8 (`%c0%ae`).** One percent-decode gives bytes that only a lenient UTF-8 decoder reads as `.`. Python's `unquote`, Rust's `percent-encoding` with `decode_utf8`, Node's `decodeURIComponent` and the WHATWG URL parser all refuse or replace them. Not a finding.
- **#305, a cached token served after a configuration change.** The issuer keys, the audience and `max_depth` are fixed for the life of the process (no reload path reaches the verifier), and `max_depth` is checked again on every hit. A policy reload, an operator reload or a revocation does not depend on the cache: leases and policy are checked after verification on every call. Nothing to reproduce.
- **#308 and enumeration.** With `actor_auth = "actor_token"`, requests with no credential for a known and an unknown `actor`, at an exchange and at hop 0, get the same status, body and headers; the refusal comes before any lookup, so there is no timing difference from one. The peer limit counts it as unauthenticated (it authenticates no agent), and the per-agent limit does not apply (no agent). Matches the tests #308 added.

## Checked and found sound

**#303, SDK retry bounded by the assertion's `exp`**

- Neither SDK verifies the assertion, and neither needs to: `exp` only shortens the retry, never lengthens it. A negative or past `exp` stops the retry; a huge finite one in TypeScript (`exp * 1000` overflowing to `Infinity`) leaves the retry as it was before #303, bounded by `maxRetries` (at most 10) and `maxRetryDelayMs` (at most 300 s). Non-UTF-8 payloads read as no `exp` in both (`UnicodeDecodeError` is a `ValueError`; `TextDecoder` replaces).
- `Retry-After` cannot make either client send anywhere but the same URL, cannot make it wait longer than its cap (a longer one is raised at once), and cannot loop past `maxRetries`. Only `429 rate_limited` and `503 overloaded` are retried. Clock jumps change when the client gives up, never what the server accepts.

**#305, verified-token cache**

- The cache key is the SHA-256 of the whole token text, and a hit returns the claims of that exact text. `claims.chain` is the chain `Verifier::verify` validated (it returns a clone of it beside the claims), so the hit reads the same chain as before; `validate_at` with the current `max_depth` runs on every hit, so an expired hop is not served. DPoP is checked against `claims.cnf` on hits as on misses. The bound of SR-46 holds: 4096 entries, tokens over 16 KiB never cached, and an entry now holds one chain instead of two.

**#308**

- Under `actor_auth = "actor_token"` an actor token is recorded as used with the exchange (`routes/token.rs`, after `admit_agent`), so an agent over its rate limit does not spend its actor token, which is the SR-108 question for this credential. The `WWW-Authenticate: Basic` that every 401 `invalid_client` carries is also on this refusal, though Basic is refused in this mode (`client_auth_not_accepted`); that is a protocol nit, not a disclosure.

**#300 (SR-109 and SR-110 fixes)**

- Every refusal before the signature verifies calls the decoy with the header's `alg`, which is in the allowlist by then, and the algorithm and `kid` type checks before the lookup depend on nothing per client. A request let through on a full peer table runs only client authentication before it is refused, and the hop-0 path is covered because the check is in the shared handler before intake.

**#304 and #307, Lean**

- `check-lean.sh` splits `find` output unquoted into `grep` arguments, and `check-lean-differential.sh` feeds Rust-written case lines to `awk` as data; a pull request controls both file names and cases, but it also controls the scripts the job runs, so neither is an injection into anything the author could not already change. No secret, no write token and no cache write is available to the job.

**Free hunting**

- `LOOKALIKE_SEPARATORS` matches every code point whose NFKC form is only `.`, `/` and `\` in Unicode 15.1 (checked against Python's `unicodedata`, 15.1.0).
- `implies` for `path_prefix`: a child path prefix is within a parent exactly when its own path satisfies the parent, including the trailing-`/` cases, and a `prefix` never implies a `path_prefix`.
- Admin roles: every read route is `viewer`, and no read route answers differently by role, so a cursor cannot carry data across roles; a route missing from the table needs `admin`. `POST /admin/policies/evaluate` writes nothing.
- The console builds every API path with `encodeURIComponent` on ids from the location hash; a single `..` id collapses to an unknown admin path (404), and every write needs a click.
- The approval notifier posts to one operator-configured URL with no redirects, and the document holds no agent-chosen URL.

## Not covered

- The Lean model and its proofs were not reviewed for whether they say what the design page claims; only the supply chain of the job was.
- Windows path normalisation was reasoned about, not tested.
- The Lean toolchain download is still by name, not by hash (SR-114).
- Fuzzing was not run. `rustix` (pass 12's last item) was not reviewed beyond `cargo deny`.
- The console was read for how it builds API paths and for DOM sinks, not for every view's logic.

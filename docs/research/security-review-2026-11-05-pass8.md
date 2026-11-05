# Security review, pass 8

- Date: 2026-11-05
- Branch: `security/pass8` (base: `bd4f8dd` on main)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [pass 6](security-review-2026-10-25-pass6.md), [pass 7](security-review-2026-10-25-pass7.md), [threat model](../spec/threat-model.md), [task board](../tasks/board.md)

## Scope and method

Two parts. First, what merged after pass 7 (#124), `git log 021e0ac..bd4f8dd`: the SR-81 record window fix (#128: `records.rs` `RecordWindow::forget`, `Authorizer::record_rejection_checked`, `Pipeline::record_rejection_checked`, the callers in `proxy.rs` and `guard.rs`), the SR-82 SDK fixes (#125 Python `_sse.py`, #126 the stream deadline in both SDKs), and the argument type check that landed just before the pass 7 branch was cut and was not read by it (`799350c`, `attenuo-policy` `request.rs` `check_tool_inputs`, `input_matches`). The rest of that range is documentation, CI and dependency bumps.

Second, a fresh read of the places an outside reviewer would try first, with the attacker taken as (a) the holder of a narrow child token, (b) the holder of a revoked or expired token, (c) a malicious MCP upstream that controls tool results (A3), and (d) someone with the admin token on a console listener without `allow_write`:

- `attenuo-proxy`: `handle_post_inner` and `screen_message` end to end, `buffer_and_rewrite`, `stream_response` and `stream_response_sse`, `handle_passthrough` (the `GET` listen stream and `DELETE`), `label.rs` (`Labeller`, `AwaitedResults`), `session.rs`, `filter.rs`, `records.rs`;
- `attenuo-server`: `routes/token.rs` (`exchange_sync`, `exchange_verified`, `clamp_to_remaining`, `form_to_json`), `dpop.rs` `bind_exchange`, `routes/renew.rs`, `authz.rs` `decide_inner` (lease check, approval tokens, charges, give-back), `check_leases`;
- `attenuo-audit`: `sqlite.rs` `register`, `renew`, `revoke`, the prune revival guard callers, `checkpoint.rs` `verify_with_checkpoints`;
- the console listener: `admin_ui.rs` routing, `CSP`, `selector_preview_only`, `require_admin`, and the console's `dom.js` and `api.js`;
- the SDKs: how they read denials, approval-required answers and approval tokens (`_wire.py` `rpc_result`, `approval.py` `verify_approval_token`, `token.py` `_check_ed25519_signature`), and whether they follow redirects.

For A3 the question was the one passes 6 and 7 asked of the SSE reader, asked of the request flow instead: is every message a client acts on seen by the labeller? Client behaviour was taken from the source of the TypeScript MCP SDK (`StreamableHTTPClientTransport`: every message of a JSON or SSE answer to a `POST` that carried a request goes to `onmessage`, and `Protocol` routes a response by its id alone) and the Python MCP SDK (`streamable_http.py`: the answer to a request is one JSON message or an SSE stream, each message goes to the session, which routes a response by its id; `read_timeout_seconds` defaults to none).

Every finding fixed here has a regression test that fails on `bd4f8dd` and passes on this branch. Findings are numbered from SR-85.

## Summary

| Severity | Found | Fixed here | Open | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 1 | 1 | 0 | 0 |
| Low | 3 | 2 (SR-87 after the pass) | 0 | 1 |
| Info | 1 | 1 | 0 | 0 |
| **Total** | **5** | **4** | **0** | **1** |

| ID | Severity | Component | Title | Status |
|---|---|---|---|---|
| SR-85 | Medium | proxy (`proxy.rs`, `label.rs`) | An answer to an earlier call in the body of a later `POST` reached the client unlabelled | Fixed |
| SR-86 | Low | proxy (`label.rs` `AwaitedInner::evict_oldest`) | One run could push every other run's awaited calls out of the map | Fixed |
| SR-87 | Low | proxy (`proxy.rs`, `label.rs`, `screen.rs`) | A list answer to an earlier request, in the body of a later `POST`, was not filtered | Fixed (`fix/proxy-followups`) |
| SR-88 | Info | server (`routes/token.rs` `form_to_json`) | A repeated form `scope` was taken last-wins instead of refused | Fixed |
| SR-89 | Low | proxy (`label.rs` `AWAITED_RESULT_TTL`) | An answer later than ten minutes is relayed unlabelled, and the Python MCP SDK waits that long | Accepted |

SR-85 is the third route, after SR-69 (message shape) and SR-77 to SR-79 (SSE transport), to the same effect: an upstream gets a `tools/call` result to the agent with no `tool_result` record and no `untrusted` label, so `context.session.tainted` stays off and approval rules for destructive calls stay ungated. This time the route is the request flow: the proxy looked for an answer only in the body of the request that carried the call (or on the listen stream), while clients accept it in the body of any request of the session.

## Findings

### SR-85: an answer to an earlier call in the body of a later `POST` reached the client unlabelled (Medium, fixed)

- **Component.** `attenuo-proxy` `proxy.rs` `handle_post_inner` (which `POST`s get a labeller), `label.rs` `Labeller::matches` and `claim` (which answers a `POST` labeller takes).
- **Attack.** A3. The agent calls `read_file` (id 1). The upstream answers that `POST` with `202 Accepted`, which the MCP transport allows, so the call is remembered in `AwaitedResults` for the listen stream. The agent's next request in the session, a `ping` (id 2) or another `tools/call`, gets an answer that also holds the answer to id 1:
  - a JSON batch `[{"id":2,"result":{}}, {"id":1,"result":{...}}]` to the `ping`; the TypeScript MCP SDK hands every message of a JSON answer to `onmessage`, and `Protocol` resolves request 1 with it;
  - the answer to id 1 alone, as the JSON answer to the `ping`; the Python MCP SDK reads one message and routes it by id to request 1 (request 2 then times out);
  - an SSE answer to a second allowed `tools/call` (id 2) whose first event answers id 1.

  In every case the proxy relayed the answer to id 1 without a record. A `POST` with no allowed call of its own had no labeller at all (`proxy.rs:1183` and `1207` on `bd4f8dd` built one only when the request had allowed calls), so a `ping` answer was streamed through untouched; a `POST` with allowed calls had a labeller that matched only its own ids (`label.rs:334`). The awaited entry for id 1 stayed in the map until its TTL, never claimed.
- **Evidence.** `crates/attenuo-proxy/tests/security_pass8.rs` `an_answer_in_a_later_post_body_is_labelled_sr85`, three cases (JSON batch to a `ping`, JSON message to a `ping`, SSE answer to another call). The assertion: if the client reads the answer to call 1, exactly one result was recorded under call 1's decision id. On `bd4f8dd` all three fail with `the client read the answer to call 1 (...) but 0 results of call 1 were recorded`.
- **Fix.** A `POST` labeller also claims an answer to a call remembered in its scope (the same upstream, `Mcp-Session-Id` and run), and records it with that call's chain and decision id, as the listen stream does. A `POST` that forwards a request but has no allowed call of its own gets a listen-style labeller while anything is awaited in its scope, so its JSON body is buffered and its SSE events framed and read. A `POST` that forwarded no request (notifications, client replies) is left alone, since clients do not read its body. When such a body cannot be read (JSON that does not parse, a content type that is neither JSON nor SSE), it is answered `502` with nothing relayed; an empty body is relayed as it is. Second test: `a_later_post_body_the_proxy_cannot_read_is_not_relayed_sr85` (a `ping` answered with JSON nested 200 deep while a call is awaited).
- **Cost.** A `ping` or `tools/list` sent while a call of the session is awaited has its answer parsed. Only sessions with an outstanding allowed call pay this.

### SR-86: one run could push every other run's awaited calls out of the map (Low, fixed)

- **Component.** `attenuo-proxy` `label.rs` `AwaitedInner::evict_oldest`.
- **Attack.** A3 for the victim, plus any token on the same proxy. `AwaitedResults` holds at most 10,000 calls (`MAX_AWAITED_RESULTS`), 256 per session and run, and when full it dropped the oldest call of any run. A call is remembered before it is forwarded and stays until answered or ten minutes pass; a client that drops its connection after sending leaves it there. One principal may hold 64 sessions (`DEFAULT_MAX_SESSIONS_PER_PRINCIPAL`), so one run can hold 16,384 entries, more than the whole map. A run that keeps sending allowed calls whose answers never come therefore pushes out every other run's awaited calls, and an upstream that answers one of those calls on the listen stream after a `202` (or, since SR-85, in a later `POST` body) gets that answer to the victim unlabelled. Low: it needs a malicious upstream for the victim and a second token, and the victim's calls must be awaited outside their `POST` body.
- **Evidence.** Unit test `label::tests::a_run_that_fills_the_map_evicts_its_own_calls_sr86`: a victim run remembers one call, another run fills the map over 41 sessions; with the old eviction the victim's call is gone (`the flooding run pushed out another run's call`).
- **Fix.** When the map is full, the oldest call of the run holding the most calls is dropped, so a run that fills the map evicts its own calls first. The existing `awaited_calls_are_bounded` test (one run) is unchanged. What is left: an attacker with many runs (many root tokens) can still spread its entries so the victim's run is not the largest; each root token is an IdP sign-in or a root grant, which the operator controls.

### SR-87: a list answer to an earlier request, in the body of a later `POST`, was not filtered (Low, fixed)

- **Component.** `attenuo-proxy` `proxy.rs` `buffer_and_rewrite` and the SSE filter of `handle_post_inner`; `filter.rs` `ListFilter`; `screen.rs` `ToolsAnswers::Pending`.
- **Observation.** Found by reading during the pass, reproduced after it. The list filter of a `POST` answer only looked at the ids of that `POST`'s own list requests. A `tools/list` answered with `202`, and then answered in the body of a later `POST` (as in SR-85), reached the client unfiltered and listed tools the token does not cover. The listen stream filters every list answer by shape (`list_kinds_by_shape`), so this was only the later-`POST` route. As with SR-80, the list filter is not an authorization boundary (every call is decided), so this showed the agent tools it cannot call.
- **Evidence.** `crates/attenuo-proxy/tests/security_pass8_sr87.rs`: `a_list_answer_in_a_later_post_body_is_filtered_sr87` (a `tools/list` answered `202`, its answer in the JSON batch, the JSON message or the SSE answer to a later `ping`, with `list_filter` `capabilities` and `policy`; a tool outside the capabilities and one the screen hides) and `a_post_with_its_own_list_request_also_claims_an_earlier_one_sr87`. On `1c0ebdf` the client is listed `delete_repo` in all six cases of the first (and `read_secret` under `policy`), and the second fails the same way. `a_list_answer_is_claimed_only_in_its_own_run_and_upstream_sr87` checks that a later `POST` of another run, or to another upstream, does not take the entry.
- **Fix.** The first sketch: before forwarding, each list request (id and `ListKind`) is remembered in `label::AwaitedResults` next to the awaited calls, under the same scope (upstream, `Mcp-Session-Id`, run), bounds, eviction and ten-minute expiry. A later `POST` that forwards a request claims the list requests its body answers (`label::ListAnswers`, ids matched with `same_id`), and its capability filter and list screen apply to them like to its own. An answer in the request's own body or on the listen stream strikes the entry. Calls and list requests are kept apart, so neither replaces nor claims the other, and a remembered list request does not make the listen stream parse its events for labelling. While a list request of its scope is awaited, a `POST` that forwards a request has its JSON answer buffered or its SSE events framed and filtered, and a body the proxy cannot read is answered `502`, as for its own list requests.
- **What is left.** A claimed entry is gone, so a second answer to the same list request in yet another `POST` body is not filtered there (the same as a second answer to a call, which is not recorded). A list answer for another run's request in a `POST` body, or one after the ten minutes, claims nothing and is relayed as it is.

### SR-88: a repeated form `scope` was taken last-wins instead of refused (Info, fixed)

- **Component.** `attenuo-server` `routes/token.rs` `form_to_json`.
- **Observation.** `form_to_json` refuses a repeated form parameter (RFC 6749 §3.1), but checks repeats against the object it builds, and `scope` is kept aside until the end (`token.rs:657` on `bd4f8dd`). `scope=github:read_file&scope=github:*` was accepted with the last value. No widening past the parent, which the exchange still checks, but a client library that appends a default scope to a narrower one could ask for more than its caller meant, without an error.
- **Evidence and fix.** `form_rejects_repeats_and_bad_json` now asserts a repeated `scope` is refused (it was accepted on `bd4f8dd`); the repeat check covers `scope`.

### SR-89: an answer later than ten minutes is relayed unlabelled (Low, accepted)

- **Component.** `attenuo-proxy` `label.rs` `AWAITED_RESULT_TTL`.
- **Observation.** An allowed call is remembered for ten minutes. An answer to it after that, on the listen stream or (since SR-85) in a later `POST` body, matches nothing and is relayed unlabelled; the module docs and the threat model say so, and pass 6 left it out as "most clients time out well before then". The Python MCP SDK does not: `read_timeout_seconds` is unset by default, so a client session waits for a response indefinitely. An upstream (A3) that answers a call with `202` and sends the answer eleven minutes later on the listen stream gets it to a default Python MCP client unlabelled. The TypeScript MCP SDK times a request out after 60 seconds by default.
- **Reason accepted.** Closing this needs a design decision, not a one-file fix: either keep every forwarded request id for the life of its session (unbounded unless sessions are), or withhold every response on the listen stream and in `POST` bodies that answers nothing the proxy remembers, which also drops legitimate late answers to `ping` or the list methods. The ten-minute bound is documented in the threat model, and an operator can tell agents to set a request timeout below it. Recommended follow-up: name the Python SDK default in the threat model's residual risks, and consider failing closed for unclaimed responses whose result has the shape of a tool result (`content` array).

## Checked and found sound

- **SR-81 fix (#128).** `record_rejection_checked` returns `None` only when the append failed; both callers then call `forget`, which closes only a window whose record was never written. A window that expired and was re-admitted between `admit` and `forget` could be closed by the older admission; that only means one more record, never fewer. The default trait method keeps every other implementor's behaviour.
- **Argument type check (`799350c`).** `input_matches` reads numbers exactly as `to_cedar_json` turns them into Cedar values: an `i64`, or a finite float with no fraction within `DECIMAL_MAX`, is a `Long`; `u64` values above `i64::MAX` and out-of-range floats become strings and so mismatch a `Long`. Null set elements are dropped by both. Only declared arguments of catalogued tools are checked, which the docs say. No differential was found between what is checked and what Cedar sees.
- **Token exchange and narrowing.** Actor authentication is checked before the subject token is used; a mismatch is refused only once the subject token verified, so it is audited (SR-18 holds). The parent's leases are checked, the reserved agent id and duplicate actors are refused, and the child's expiry is capped by the actor token. `clamp_to_remaining` is advisory: two concurrent exchanges can each be clamped to the same remainder, but every allowed call charges every limited capability of every hop (`authz.rs` step 5), so the parent's figure bounds the sum. `may_act` is not inherited, as RFC-0001 section 4 says.
- **DPoP binding on exchange.** A bound parent needs a header proof; with the same key it must cover the subject token (`ath`), with a new key the parent's own sign-off must name the child key and agent (SR-40). Both proofs are used once.
- **Approval tokens.** Bound to run, lease, call hash and key; taken by id under the lease check; given back when the call is not allowed. The SDKs raise `ApprovalRequired` only for a `-32008` whose decision id is in the proxy's `X-Attenuo-Decision-Id` header, so an upstream cannot start an approval flow; `verify_approval_token` requires `alg` `EdDSA` and `typ` `attenuo-approval+jwt`.
- **Revocation and pruning.** `check_leases` checks every lease of the chain, so a child registered after its parent was revoked (the window between `check_leases` and `register_issued`) is still refused at every call. `register` upserts `parent` and `expires_at` but never clears `revoked_at`, and lease ids are only ever the server's own UUIDs. `renew` refuses a revoked lease inside its transaction, and a renewal that cannot be audited is rolled back to the previous expiry (the store's `renew` sets, it does not only extend). The prune revival guard callers are as pass 7 found them.
- **Checkpoints.** Signed over RFC 8785 `[seq, head_hash, at, kid]` with a context string; a checkpoint past the end of a clean chain is reported as truncation; a checkpoint inside a broken chain is not double-reported.
- **Console listener.** No route that changes leases or policy is mounted without `allow_write`: the selector revoke route serves only `?preview=true` (a duplicate `preview` key is a 400 from `serde_urlencoded`), and the preview reads only. `GET /admin/audit/checkpoint` signs a checkpoint, as documented. Every response has the CSP (`script-src 'self'`, no inline script, Trusted Types required); the console builds every node with `createElement` and `textContent`, allowlists attributes, accepts only `#/` and `/admin/` links, and keeps the admin token in a module variable. The admin bearer is compared in constant time.
- **Proxy screening.** Duplicate member names cannot smuggle a method (only the re-encoded screened value is forwarded, SR-01). Non-object `tools/call` arguments are refused; `prompts/get` arguments are passed to policy as they are forwarded, so there is no differential. The upstream's `Location` is not forwarded to the client and redirects are not followed (SR-02), so an SDK using `fetch` cannot be redirected by an upstream.
- **SDK client behaviour.** Neither SDK widens what the server enforces: denials and approval-required answers need the proxy's header (SR-32), path segments are encoded (SR-31), and `httpx` does not follow redirects by default.

## Not covered

- The AuthZEN routes, the IdP intake and the CLI were not re-read in this pass.
- The evaluation suite, the bench crate and the fuzz targets were not re-run.
- Deployments with more than one server process on one store.
- MCP clients other than the Python and TypeScript MCP SDKs and the attenuo SDKs. SR-85 assumes only that a client routes a response by id, which JSON-RPC requires.

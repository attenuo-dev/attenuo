# Security review, pass 7

- Date: 2026-10-25
- Branch: `security/pass7` (base: `ea4d35a` on main)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [pass 6](security-review-2026-10-25-pass6.md), [threat model](../spec/threat-model.md), [task board](../tasks/board.md)

## Scope and method

What merged after pass 6 (#104), `git log aba6275..ea4d35a`. The new or changed surface, read in full:

- the lease-refusal record bound (#107) and its settings (#121): `records.rs` `RecordWindow`, `proxy.rs` `record_lease_refusal`, `lease_live`, `handle_passthrough`, `[proxy] record_window_seconds` and `record_window_max_keys`;
- AuthZEN batch semantics and public discovery (#108): `routes/authzen.rs` `evaluate_batch` and `Semantic`, `routes/wellknown.rs`;
- the strict `approval` block of the admin dry run (#109): `routes/policies.rs` `approval_from_json`;
- wide-run lease pruning with the revival guard (#110): `attenuo-audit` `lease.rs` `prune_pass`, `RunSweep`, `LeasePruneState`, and the callers in both stores;
- the 410 `charge_pruned` refund (#112): `routes/admin.rs` `refund_budget`, `no_charge_refusal`;
- SDK streaming (#115): Python `_sse.py` and `client.py` `_stream`, TypeScript `sse.ts` and `client.ts` `callToolStream`, and `fake_mcp --sse` / `hold_ms`;
- the stream-end look-alike rewrite and its byte scan (#117, #119): `guard.rs` `has_stream_end_shape`, `disown_*`, `may_hold_stream_end_code`, and the SSE reader they rely on (`sse.rs`);
- the SDK publish workflow (#118): `.github/workflows/release-packages.yml`.

The attacker was taken as (a) the holder of a valid but narrow token, (b) the holder of a revoked lease, (c) a malicious or compromised MCP upstream (A3), (d) an unauthenticated network position and (e) someone who can push tags or dispatch workflows. For A3 the review compared, byte for byte, what the proxy reads of an upstream SSE body with what clients read: the WHATWG SSE rules, both attenuo SDKs, the TypeScript MCP SDK (`TextDecoderStream` into `eventsource-parser`, `JSON.parse`) and the Python MCP SDK (`httpx` `iter_text` with `errors="replace"` into `httpx_sse`, pydantic). Each difference was checked against the client by running its decoder or parser on the same input (Node 22, the SDK venv).

Every finding fixed here has a regression test that failed on `ea4d35a` and passes on this branch. Findings are numbered from SR-77.

## Summary

| Severity | Found | Fixed here | Open | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 3 | 3 | 0 | 0 |
| Low | 1 | 1 | 0 | 0 |
| Info | 4 | 2 (SR-81, SR-82, after the pass) | 1 | 1 |
| **Total** | **8** | **6** | **1** | **1** |

| ID | Area | Severity | Status |
|---|---|---|---|
| SR-77 | proxy: SSE byte order mark and non-UTF-8 events (labelling, look-alike rewrite) | Medium | Fixed |
| SR-78 | proxy: lone surrogate escapes in SSE data (labelling, look-alike rewrite) | Medium | Fixed |
| SR-79 | proxy: SSE data nested deeper than `serde_json` parses (labelling, look-alike rewrite) | Medium | Fixed |
| SR-80 | proxy: the same depth differential on the list filter | Low | Fixed |
| SR-81 | proxy: a record window opens on a failed audit append | Info | Fixed |
| SR-82 | SDKs: SSE reader cost and streams that never go idle | Info | Fixed (#125, #126) |
| SR-83 | CI: release workflow build toolchain and install scripts | Info | Open |
| SR-84 | server: AuthZEN batch refused after earlier entries were decided | Info | Accepted |

The three Medium findings have one root: the proxy's reading of an upstream SSE event and a client's reading of it differed, and where the proxy could not read an event it relayed it byte for byte. Output labelling (ADR-0009) and the stream-end rewrite (#117) only act on events the proxy reads, so an upstream (A3) could send a `tools/call` result that a client acts on with no `tool_result` record and no `untrusted` label, which keeps `context.session.tainted` off and the approval rules for destructive calls ungated. That is the same effect as SR-69, reached through the transport instead of the message shape. The fixes make the proxy read what clients read where it can (a leading BOM, lone surrogates), and drop what it still cannot read on a stream it must inspect.

## Findings

### SR-77: a byte order mark or a non-UTF-8 byte hid an SSE event from labelling and from the look-alike rewrite (Medium, fixed)

- **Component.** `attenuo-proxy` `sse.rs` (`SseFramer`, `SseRewriter`, `event_json`), used by `label.rs` `label_events` and `guard.rs` `disown_events`.
- **Attack.** A3. The upstream answers an allowed `tools/call` with an SSE body whose event the proxy cannot read but a client can:
  - a UTF-8 byte order mark before the first `data:` line. The WHATWG rules drop it, and so do `TextDecoderStream` (the TypeScript MCP SDK), the attenuo Python SDK (explicitly) and the attenuo TypeScript SDK (explicitly). The proxy split the line as a field named `\u{feff}data`, found no data, and relayed the event as is;
  - a byte that is not UTF-8 anywhere in the event, for example `\xff` in the result text or in a comment line. `event_json` gave up on the whole event (`from_utf8` failed), and `label_events` relayed it. `TextDecoderStream` and `httpx`'s text decoder replace the byte with U+FFFD, so both MCP SDKs read the result (the attenuo SDKs refuse a non-UTF-8 line).

  In both cases the client acts on a result that has no `tool_result` record and leaves the run untainted. The same bytes in front of a message in the stream-end shape made the attenuo SDKs report a proxy cut with a decision id the upstream chose (BOM), which #117 exists to prevent.
- **Evidence.** `tests/security_pass7.rs` (now `sse_client_view.rs`): `an_sse_answer_a_client_reads_is_labelled_sr77` (three cases: invalid byte in the data, in a comment, BOM; the assertion is "what a lenient WHATWG client reads from the relayed bytes is recorded"), `a_bom_or_invalid_byte_does_not_hide_a_stream_end_lookalike_sr77`. Unit test `sse::tests::a_leading_bom_is_dropped_and_a_non_utf8_event_is_refused_sr77`. On `ea4d35a` the first failed with `the client read [{"id":1,"result":{... "� injected" ...}}] but 0 results were recorded`, the second with the forged cut.
- **Fix.** The framer and the rewriter drop a byte order mark that opens the stream (also when it arrives split across chunks), so the relayed stream no longer has it and both sides read the same lines. The framer ends the stream with an error on a non-UTF-8 event, as the rewriter already did: the call's answer never reaches the client, which is the same outcome as a failed label. A later mark (not at the stream start) is an unknown field name to clients and to the proxy alike, and is left alone.

### SR-78: a lone surrogate escape hid an SSE event from labelling and from the look-alike rewrite (Medium, fixed)

- **Component.** `attenuo-proxy` `sse.rs` (`event_json`, `rewrite_event`).
- **Attack.** A3. `serde_json` refuses a `\u` escape of a UTF-16 surrogate without its pair (`"\ud800"`); `JSON.parse` and Python's `json` accept it (checked: both return the string with the lone surrogate; pydantic refuses it). An upstream that puts `\ud800` in the text of a streamed `tools/call` result gets the event relayed unread: the TypeScript MCP SDK reads the result, unlabelled. In a stream-end look-alike it gets a forged cut past the rewrite, which both attenuo SDKs read (Python `json.loads`, TypeScript `JSON.parse`).
- **Evidence.** `a_lone_surrogate_escape_does_not_hide_an_answer_sr78` (failed on `ea4d35a`: 0 results recorded; the look-alike relayed unrewritten). Unit test `sse::tests::a_lone_surrogate_escape_is_read_as_a_replacement_character_sr78`.
- **Fix.** `sse::parse_data`: data that does not parse is parsed again with each unpaired surrogate escape replaced by `�` (pairs, and an escaped backslash before a `u`, are kept). This is how `JSON.parse` prints such a string, and it gives the proxy the same structure the client sees. Only events whose first parse failed pay for it.

### SR-79: SSE data nested deeper than `serde_json` parses was relayed unread (Medium, fixed)

- **Component.** `attenuo-proxy` `label.rs` `label_events`, `guard.rs` `disown_events`.
- **Attack.** A3. `serde_json` stops at 128 levels of nesting; `JSON.parse` and Python's `json` go far deeper (checked with 200). A `tools/call` result with an extra member `"x": [[[[...]]]]` 200 deep was relayed unlabelled, and the TypeScript MCP SDK's result schema lets the extra member through. A look-alike with the same member passed the rewrite. SR-77 and SR-78 close two specific differentials; this one shows that "relay what the proxy cannot parse" is the problem, since JSON parsers will keep differing.
- **Evidence.** `an_event_the_proxy_cannot_parse_is_not_relayed_sr79` (failed on `ea4d35a`: relayed with 0 records).
- **Fix.** On a labelled stream (every `POST` answer to an allowed mediated call, and the listen stream while a call of its scope is awaited), an event with data the proxy cannot parse is dropped and logged (`bytes` only), not relayed. The stream-end rewrite drops an event that passes the byte scan and has data that does not parse. Events without data (comments, `retry:`) and events that parse are unchanged. The plain JSON path already failed closed (`label_error`, or 502 for a list answer).

### SR-80: the same depth differential skipped the list filter (Low, fixed)

- **Component.** `attenuo-proxy` `sse.rs` `rewrite_event` (the list filter on SSE answers and on the listen stream).
- **Attack.** A3. A streamed `tools/list` answer with a member nested 200 deep reached the client unfiltered, listing tools the token does not cover. The list filter is not an authorization boundary (every call is decided), so this shows the agent tools it cannot call. Low.
- **Evidence.** `a_list_answer_the_proxy_cannot_parse_is_not_relayed_unfiltered_sr80` (failed on `ea4d35a`: `delete_repo` relayed to a `read_*` token). The unit test that pinned the old passthrough of non-JSON data is now `data_less_events_pass_through_and_unparsed_data_is_dropped_sr80`.
- **Fix.** `rewrite_event` drops an event whose data does not parse, instead of emitting it byte for byte. Events without data still pass byte for byte.

### SR-81: a record window opens on a failed audit append (Info, fixed)

Fixed in `fix/sr81-record-window-failed-append`.


- **Component.** `attenuo-proxy` `records.rs` `RecordWindow`, `proxy.rs` `record_lease_refusal`, `guard.rs` `StreamEndRecords`.
- **Observation.** `Authorizer::record_rejection` returns a `Uuid` whatever happens: the server's implementation logs a failed append and returns the id of the record it could not write. `record_lease_refusal` then calls `RecordWindow::recorded` with that id, and for the rest of the window (up to `[proxy] record_window_seconds`, at most 3600) every refusal of that chain, tool and reason is counted, not recorded, and its 401 names a decision id that is in no record. A transient append failure (disk full, a lock timeout) therefore hides up to an hour of retries from the audit log, though not from the proxy log and `audit_records_suppressed_total`. No PoC: `StaticAuthorizer` cannot fail a rejection, and making it able to is a test-API change.
- **Fix sketch.** Have the server's `record_rejection` say whether it wrote (a new default method `record_rejection_checked -> Option<Uuid>` on `Authorizer`, defaulting to `Some(record_rejection(..))`), and on `None` remove the slot (`RecordWindow::forget(key)`) so the next occurrence records. Not done here because it adds to the public `Authorizer` trait.
- **Fixed.** As sketched. `Authorizer::record_rejection_checked` is a default method (`Some(record_rejection(..))`), so existing implementors compile and behave as before; `ServerAuthorizer` overrides it with `Pipeline::record_rejection_checked`, which returns `None` when the append failed (`record_rejection` still returns the id either way). `record_lease_refusal` and the listen-stream `stream.end` record call it, and on `None` call `RecordWindow::forget`, which closes the window unless its record was already written: the next occurrence is recorded and carries the count suppressed meanwhile, and the refusal (or the stream's final event) names no decision id. Regression test `a_failed_append_opens_no_record_window_sr81` (`tests/security_pass7_sr81.rs`, now `refusal_record_window.rs`, with the new `StaticAuthorizer::fail_rejections` and `rejection_attempts`); unit test `records::tests::a_forgotten_record_does_not_open_a_window_sr81`. With the proxy's call site put back to open the window on any id, the regression test fails with one attempt of two.

### SR-82: SDK SSE readers: quadratic rescans in Python, and no idle bound on keep-alive-only streams (Info, open)

Fixed after the pass: part (1) in #125, part (2) in #126.

- **Component.** `sdk/python/src/attenuo/_sse.py` `SseParser.feed`; both SDKs' streamed calls.
- **Observation.** (1) The Python parser keeps the unfinished line as `self._buf += chunk` and searches it again from the start on every chunk, so a long line delivered in many small reads costs time quadratic in its length, up to `max_event_bytes` (16 MiB). The proxy forwards whole events in one write, so a read is usually large, which bounds this in practice. The TypeScript parser keeps the parts in a list and is linear. (2) Both SDKs reset their idle timer on every read, so an upstream that sends `:\n\n` every few seconds keeps a call open with no event until the proxy's stream re-check ends it at token expiry or revocation. A caller can pass its own signal or deadline. Both are denial of service against one client by its upstream, which the threat model leaves out. Hostile `id:` (NUL is ignored as the standard says), CR/LF mixes, CR at a chunk end, UTF-8 split across chunks and oversized `data:` lines were checked in both parsers and behave as specified.
- **Fix sketch** (another branch is editing these files): in `feed`, remember where the last search stopped and search from there, and keep the partial line as a list of chunks joined once per line, as the TypeScript parser does. For (2), an optional total deadline on `call_tool_stream` / `callToolStream`.

### SR-83: the release workflow builds with an unpinned toolchain (Info, open)

- **Component.** `.github/workflows/release-packages.yml`.
- **Observation.** The `python` job runs `pip install -e '.[dev]' build twine` and `python -m build`, which fetches `hatchling>=1.27` in an isolated environment: every tool is resolved at release time without hashes, and the wheel and sdist it builds are what `python-publish` uploads to PyPI under trusted publishing. A compromised release of `build`, `hatchling` or a dev dependency on release day changes the published package without a commit. The `typescript-publish` job runs `npm ci` in a job that holds `id-token: write` and, in a later step, `NPM_TOKEN`; the lockfile pins every package by integrity hash and none of them has an install script today, so this needs a lockfile change, which review sees. What a tag push can do was checked and is sound (see below).
- **Fix sketch.** A hashed `sdk/python/requirements-release.txt` (`pip install --require-hashes`) for `build`, `twine` and `hatchling`, and `python -m build --no-isolation` with that environment; `npm ci --ignore-scripts` in both npm jobs. Not done here: it needs a new file and a CI run to prove, and Actions are blocked.

### SR-84: an AuthZEN batch is refused whole after earlier entries were decided (Info, accepted)

- **Component.** `attenuo-server` `routes/authzen.rs` `evaluate_batch`.
- **Observation.** An entry that fails with 401 or 403 (for example a body chain that does not match the bearer) refuses the whole batch, after the entries before it were decided, audited and charged. The caller does not see those decisions, and the audit log holds decisions that were never answered. This predates #108; the new `deny_on_first_deny` and `permit_on_first_permit` only stop earlier. They reveal nothing about entries after the stop: those are not decided, audited or charged, and the caller could have asked for each one alone. `options` that is not an object is ignored (as `execute_all`); a non-string semantic is 400 before anything is decided.
- **Reason accepted.** Every decided entry is a real decision under the caller's own token and is recorded as one, so nothing is hidden from the log, and a charge for a decision the caller did not see can only make its budget tighter. Answering partial results on an authentication failure would tell a caller with a bad credential what earlier entries decided.

## Verified fixed from earlier passes

- **SR-69.** Still holds: only a string `method` makes a request, on every path including the new SDK streaming paths.
- **SR-74.** The `stream.end` window and the lease-refusal window share `RecordWindow` now (#107, #121); keys are still chain digests, reasons and tools come from fixed sets, and a full table records.

## Checked and found sound

- **The byte scan (#119).** `the_byte_scan_admits_every_spelling_of_the_code_pass7` generates every placement of the point in `32001`, `320010`, `3200100` and with leading zeros, exponents from -12 to 12 in both cases with and without `+`, Rust's and `serde_json`'s formatting of -32001 and its two neighbouring doubles, and 100,000 decimals within 4e-12 of it. Every spelling that `has_stream_end_shape` accepts after `serde_json` parses it passes `may_hold_stream_end_code`. A number cannot be split by an SSE line break (the join puts `\n` inside it, which is not JSON), and the minus sign is always literal. Whole-chunk scanning sees every event's bytes.
- **`has_stream_end_shape` against the SDKs.** It accepts everything the attenuo SDKs' `stream_end_error` / `streamEndError` read as a cut (no `method`, `id` absent or null, code equal to -32001 by value) and more (it does not ask for `data.reason`). Duplicate keys: all three parsers keep the last one.
- **Lease refusals and decided requests.** No decided request goes through the refusal window: `tools/call` and the other mediated methods are decided by `authorize`, which records every lease refusal; the window only sees passthrough methods, notifications, client replies, `GET` and `DELETE`. A batch with a `tools/call` and an `initialize` on a revoked lease records the call's denial every time. A request that fails token verification is a log line, not a record (SR-18), so an unauthenticated caller cannot fill the window table.
- **Window settings (#121).** `record_window_seconds` is 1 to 3600 and `record_window_max_keys` 100 to 1,000,000, checked at startup. A full table of open windows records rather than suppresses, so a small table only means more records. A tiny window means more records. A long window makes one record stand for up to an hour of the same chain, tool and reason, which is the setting's documented trade. Keys hold the chain digest, so one principal cannot suppress another's records. With a table full of open windows each new key costs a `retain` over the table under the lock (at most 1,000,000 entries, only reachable with that many distinct chains).
- **Prune revival guard (#110).** A renewal or registration of a member during the walk abandons the walk (the run is decided again later); during the delete phase it is refused as `lease_unknown`. A child registered under a lease not yet walked is found when the walk reads that lease's children; under one already walked, `after_write` taints the walk. Both stores hold the connection (SQLite) or the rows lock (memory) across the guard and the write, and a pass is one write transaction, so nothing can land between the check and the delete. The delete phase re-reads each row and keeps the rest of the run if one became usable. A child registered under a lease being deleted needs an exchange from a parent that expired more than the retention ago, which the lease check refuses.
- **Refund 410 (#112).** Admin-only. The audit lookup parses the id as a UUID first and binds it; it only tells the admin what the audit log already shows.
- **Strict `approval` (#109).** Only `{"by": "user" | "operator" | "policy"}`; any other member or value is 400. The block exists only in the admin dry run, which writes no record and consumes no approval (SR-76). No non-admin route reads an approval from the request body; AuthZEN takes only a signed `context.approval_token`.
- **AuthZEN discovery (#108).** Public and credential-free like the JWKS; it holds the base URL and two paths, and the `Host` echo is still loopback-only when `public_url` is unset (SR-19).
- **SDK SSE parsing (#115).** CR, LF and CRLF line ends, a CR at the end of a chunk, an `id:` with NUL (ignored), a BOM only at the stream start, UTF-8 split across chunks (lines are decoded whole), and `max_event_bytes` counted over the lines of an event including comments: both parsers behave as the WHATWG rules say. Neither treats a later event after the call's answer as anything.
- **TypeScript idle timer.** The timer is restarted after the response headers and after every read, and cleared in `finally`; an aborted fetch ends the reader. It fires when no read completes within `timeoutMs`; see SR-82 for keep-alive bytes.
- **`fake_mcp --sse` and `hold_ms`.** An example binary for tests and demos, not shipped in a package; `hold_ms` delays its own answer.
- **Release workflow (#118), what a tag push can do.** A tag push is a dry run: the publish jobs run only on `workflow_dispatch` with `dry_run == false`, and they need the check job, whose version step fails unless the ref is a tag named `v<version>`. A dispatch from a branch fails there. Workflow permissions are `contents: read`; only the publish jobs get `id-token: write`, in the `pypi` and `npm` environments, where reviewers can be required. Every action is pinned to a commit SHA, checkouts do not persist credentials, the PyPI upload uses the artifact the check job built, and the npm publish job does not use the shared cache. Who may push a `v*` tag is a repository setting (tag protection), which the release notes should name.

## Not covered

- The DELETE response path relays an upstream body unframed (`stream_response` with no guard); clients do not read SSE answers to `DELETE`, so it was not taken further.
- MCP clients other than the Python and TypeScript SDKs, and JSON parsers other than `serde_json`, `JSON.parse`, Python's `json` and pydantic. SR-79 and SR-80 make the proxy drop what it cannot parse whatever the client's parser accepts, on the streams it inspects.
- The evaluation suite, the bench crate and the fuzz targets (not re-run). A fuzz target for "the proxy relays only events it parsed" on labelled streams would be a good follow-up.
- Deployments with more than one server process on one store.

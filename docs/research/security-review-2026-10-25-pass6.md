# Security review, pass 6

- Date: 2026-10-25
- Branch: `fix/security-pass-6` (base: `9536ec6` on main)
- Related: [pass 1 and 2](security-review-2026-10-22.md), [pass 3](security-review-2026-10-23.md), [pass 4](security-review-2026-10-23-pass4.md), [pass 5](security-review-2026-10-24-pass5.md), [threat model](../spec/threat-model.md), [task board](../tasks/board.md)

## Scope and method

What merged after pass 5, PRs #87 to #102. The new surface, read in full:

- the numeric `range` constraint (`attenuo_core::capability`: the hand-written `RawRange` deserializer, `as_long`, `implies` against `equals` and `one_of`, the `is_empty` shortcut, its canonical JSON in the chain digest, `violation` and `explain_denial`), and how the CLI prints constraints;
- declared input types before Cedar (`check_tool_inputs`, `input_type_mismatch`) and the `like` guards of the starter policy (`default.cedar`);
- revoke by session (`session_digest`, the write-once `lease_sessions`), session binding pruning, lease registry retention and run-state retention (`prune_sessions`, `prune_leases`, `prune_run_state` in both stores), and `lease_unknown` on each path;
- the proxy: list filtering on the listen stream by shape (`list_kinds_by_shape`), `resources/unsubscribe`, the refusal of a non-SSE `GET`, `StreamEndRecords` and `proxy_streams_ended_total`;
- AuthZEN: the `X-Request-ID` echo, a batch without entries answered as a single evaluation, the batch bound;
- the admin dry run's `budget` block (`budget_from_json`, `CounterSource::Stated`);
- the audit export's `tool` and `decision` filters.

The attacker was taken as each of the threat model's roles: a prompt-injected agent that controls arguments (A1), a compromised sub-agent that writes its own exchange requests (A2), a malicious or compromised MCP upstream (A3), a holder of copied or revoked tokens (A4, A6), and a reader of the audit log (A7). For A3 the review checked what MCP client SDKs accept against what the proxy classifies: the Python MCP SDK (`mcp` in a local virtualenv) and the TypeScript SDK (`@modelcontextprotocol/sdk` in `examples/typescript-agent`). For the starter policy it checked how a WHATWG URL parser (Node's `URL`) reads repository names put into a GitHub API path.

Every finding fixed here has a regression test that failed on the base commit and passes on this branch; each was run against the unfixed code first. Findings are numbered from SR-69.

## Summary

| Severity | Found | Fixed here | Open | Accepted |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 0 | 0 |
| Medium | 2 | 2 | 0 | 0 |
| Low | 2 | 2 | 0 | 0 |
| Info | 4 | 0 | 0 | 4 |
| **Total** | **8** | **4** | **0** | **4** |

| ID | Area | Severity | Status |
|---|---|---|---|
| SR-69 | proxy: response classification (list filter, output labelling) | Medium | Fixed |
| SR-70 | policy: starter `default.cedar` `acme/` guards | Medium | Fixed |
| SR-71 | core: `range` implication against `equals` and `one_of` | Low | Fixed |
| SR-72 | CLI: constraint names and dry-run diagnostics | Low | Fixed |
| SR-73 | core: `prefix` constraints and URL parsers | Info | Accepted |
| SR-74 | proxy: `stream.end` record window | Info | Accepted |
| SR-75 | server: AuthZEN `X-Request-ID` and batch checks before authentication | Info | Accepted |
| SR-76 | server: admin dry run with a stated budget | Info | Accepted |

The two Medium findings:

- **SR-69.** The proxy took any message with a `method` member for a request, whatever its value. An upstream that answers an allowed `tools/call` with `"method": null` beside its `result` got that answer past output labelling (no `tool_result` record, no `untrusted` taint), and a list answer past the list filter. The Python MCP SDK reads such a message as the response. Fixed: only a string `method` makes a request.
- **SR-70.** The starter policy's `acme/<name>` guards accepted `acme/..\evil\api`. A tool that puts `repo` into a URL and parses it with a WHATWG parser (Node's `fetch`, Rust's `url` crate) reads the backslash as `/` and calls `/repos/evil/api/...`. Fixed: both repository rules refuse `\`, `%`, `?`, `#`, tab, line feed and carriage return.

## Findings

### SR-69: a non-string `method` hid a response from the list filter and from output labelling (Medium, fixed)

- **Component.** `attenuo-proxy`: `filter.rs` (`list_kinds_by_shape`, `ListFilter::apply_message`, `ListFilter::listed_tools`), `label.rs` (`Labeller::response_id`).
- **Attack.** A3, a malicious or compromised upstream. ADR-0009 labels every response to an allowed mediated call before it is relayed: one `tool_result` record, and an `untrusted` label on the run, which turns on `context.session.tainted` and the approval rules for destructive calls. The proxy found responses as messages "with no `method`", tested with `msg.get("method").is_some()`, so `"method": null` (or `5`, or an object) made a message a request. The upstream answers the allowed call with `{"jsonrpc":"2.0","id":1,"method":null,"result":{"content":[...injected text...]}}`. The proxy relays it unlabelled and unrecorded, and the Python MCP SDK's `JSONRPCMessage` parses it as `JSONRPCResponse` (checked: `method=None` is kept as an extra member). The injected content is now in the agent's context while the run is not tainted, so a later destructive call is not gated. The same message shape got a `tools/list` answer past the list filter, on `POST` bodies and on the listen stream (#90's shape detection), and kept its tool hints out of `observe_tool_hints`. The TypeScript SDK refuses the message (its schemas are strict), so only clients that accept it are affected. Clients built on the Python SDK, the LangChain adapters among them, accept it.
- **Evidence.** `filter::tests::a_null_or_non_string_method_does_not_hide_a_list_answer_sr69` (`null`, a number, an object and a list as `method`: classified as a list answer on the listen stream, tool names observed, filtered on a `POST`), `label::tests::a_null_method_does_not_hide_a_result_from_labelling_sr69` (recorded; withheld as `label_error` when recording fails). Both failed on `9536ec6`.
- **Fix.** The four checks use `jsonrpc::method_of(msg).is_some()`: a message is a request or notification only when its `method` is a string. A message with a non-string `method` is treated as a response, which can only add a record or remove list entries. A message with a string `method` and a `result` is still left alone; clients read it as a request.

### SR-70: the starter policy's `acme/` guards let a URL parser leave the organisation (Medium, fixed)

- **Component.** `config/policies/default.cedar` and its embedded copy `crates/attenuo-policy/policies/default.cedar`: `permit_create_issue_in_acme`, `permit_delete_acme_sandbox_repo`.
- **Attack.** A1, an agent that controls arguments. #84 pinned `repo` to "`acme/<name>`": one `/`, and a name that is not empty, `.` or `..`. Its comment and the writing-policies guide said this rules out "every `..` path that leaves the owner". That holds for the string, not for what a tool does with it. A GitHub tool that builds `https://api.github.com/repos/{repo}/issues` and parses it with a WHATWG URL parser (Node's `fetch` and `URL`, which most JavaScript MCP servers use, or Rust's `url` crate, which `reqwest` uses) reads `\` as `/` in special schemes. It also reads `%2e%2e` as `..` and drops tabs and line breaks. Checked with Node: `acme/..\evil\api` gives `/repos/evil/api/issues`, `acme/sandbox-x\..\..\evil\api` gives the same, and `acme/%2e%2e` and `acme/.<TAB>.` give `/repos/issues`. Some upstreams also decode `%2F` in a path segment. So the injected agent creates issues in any repository the server's credential reaches, and with MFA deletes any repository through the sandbox rule, while the decision log shows a permitted `acme/...` call. This is the same parser differential as SR-56, here in policy instead of in a run limit.
- **Evidence.** Six new cases in `config/policies/default_test.yaml`, marked `(SR-70)`: backslash, `%2e%2e`, `%2F`, tab, `?`/`#`, and the sandbox delete with MFA. All six were allowed on `9536ec6` (`34 passed, 6 failed`). `shipped_default_policy_passes_its_tests` runs the file.
- **Fix.** Both rules add `!(context.input.repo like "*\\*")` and the same for `%`, `?`, `#`, `\t`, `\n` and `\r`. GitHub repository names hold none of them. `acme/api` and `acme/.github` are still allowed. The file comment and the guide's "Patterns and `like`" section say why. Deployments that copied the old rules into their own policy files should add the same guards.

### SR-71: `equals` of a large integer implied a `range` that refuses an equal value (Low, fixed)

- **Component.** `attenuo-core` `ArgConstraint::implies`, cases `(Equals, Range)` and `(OneOf, Range)`.
- **Attack.** A2, a sub-agent that writes its own exchange request. Constraints compare values canonically, so `equals 10000000000000000` is satisfied by the integer and by the float `1e16` (same RFC 8785 form). A `range` admits a float only up to 922337203685477 in magnitude (`as_long`, the policy crate's `DECIMAL_MAX` rule). Under a parent `range {min: 0, max: 20000000000000000}`, a child `equals 10^16` was accepted as narrower, but its token permits `1e16`, which the parent's range refuses. Enforcement checks only the last hop's capabilities, so the child's call carries a value outside what the parent delegated. The value is numerically inside the bounds, so what gets through is the type: a float where the delegator asked for a Cedar `long`. A catalog that declares the argument `long` still refuses it (`input_type_mismatch`), and so does a policy that compares it as a `long`. Low.
- **Evidence.** `capability::tests::equals_a_large_integer_implies_a_range_only_when_every_equal_value_is_a_long_sr71`, which failed on `9536ec6`. It also checks values near the edge (`922337203685477`, `2^53`, `2^53 + 1`, `i64::MAX`, `i64::MIN`): whenever `equals n` implies the range, every value equal to `n` satisfies it. The `range_implication_matches_integer_containment` proptest still passes.
- **Fix.** `range_admits_all_equal`: a member implies a range when the range admits it and either its magnitude is at most 922337203685477, or no float equals it. That is the case exactly when the nearest double is not written with the integer's digits (`jcs::format_f64(n as f64) != n.to_string()`). So `equals 2^53 + 1` and `equals i64::MAX` still imply `range {min: 0}`, and `equals 10^16` no longer implies a range.

### SR-72: constraint names and dry-run diagnostics reached the terminal raw (Low, fixed)

- **Component.** `attenuo-cli` `render.rs`: `fmt_constraint`, used by `token inspect`, `lease tree` and every capability line, and the `diagnostic:` lines of `policy evaluate`.
- **Attack.** A2. A child may add constraints on any argument name: an extra constraint only narrows, so the exchange accepts it. Constraint names, unlike limit names (SR-59), are not checked for control characters. The name is printed as is in `0 <= amount <= 2000`-style lines and, since #96, in the `capability_denied` diagnostic (``argument `<name>` is absent``), which `attenuo policy evaluate` prints raw. An operator who inspects the sub-agent's token during an incident gets a terminal that the name can clear and redraw, as in SR-59. The console builds nodes with `textContent` and is not affected.
- **Evidence.** `render::tests::constraint_names_and_diagnostics_escape_control_characters_sr72`, which failed on `9536ec6`.
- **Fix.** `escape_controls` escapes control characters only (`\u{1b}`) and leaves quotes and everything else as they are. `fmt_constraint` applies it to the name, and `render_evaluation` to each diagnostic. The server side is unchanged: the diagnostic goes to the token's holder, and JSON escapes it.

### SR-73: a `prefix` constraint has the same URL-parser blind spot (Info, accepted)

- **Component.** `attenuo-core` `ArgConstraint::Prefix`.
- **Attack.** A capability `{repo: {op: prefix, value: "acme/"}}` admits `acme/..\evil\api`, which a WHATWG parser resolves outside `acme/` (SR-70).
- **Reason accepted.** A prefix is a plain string prefix, and the writing-policies guide already says it accepts `acme/a/../b` and to prefer `equals` or `one_of` for a whole repository name. What the tool makes of the string is not something a token constraint can know. The guide's paragraph on `like` now names the backslash, and the starter policy refuses it whatever the token says. Threat-model row added.

### SR-74: the `stream.end` window is per chain and reason, not per stream (Info, accepted)

- **Component.** `attenuo-proxy` `guard.rs` `StreamEndRecords`.
- **Attack.** Within one minute of a `stream.end` record, further ends of listen streams of the same chain and reason are counted, not recorded. The server and session of the suppressed ones are in the proxy log, not the audit log. Keys are chain digests, so only someone holding tokens can add keys; the map holds at most 10,000 of them and fails open (records) when full. Reasons and the `cause` label come from fixed sets.
- **Reason accepted.** That is the design of #101. The first record marks when the condition began, which is what the log is for. The suppressed ends are in `audit_records_suppressed_total`.

### SR-75: AuthZEN echoes `X-Request-ID` verbatim and checks a batch's size before authentication (Info, accepted)

- **Component.** `attenuo-server` `routes/authzen.rs` (`echo_request_id`, `evaluate_batch`).
- **Observation.** The first `X-Request-ID` value is copied onto the answer as is: any bytes `hyper` accepts in a header value, up to its header size limit. A header value cannot hold CR or LF, so this does not split a response. Later duplicates are ignored. A batch that is not an object, has a non-array `evaluations`, or is over `max_batch` gets a 400 before the bearer is checked, so an unauthenticated caller learns `max_batch`. A batch without entries is authenticated exactly as a single evaluation is (bearer, then a `[[peps]]` body chain), has `options` removed, and is decided, audited and charged once.
- **Reason accepted.** Nothing reflected reaches a parser that acts on it, and the batch limit is not a secret. Denial of service against attenuo is out of scope.

### SR-76: the admin dry run decides with stated counters and writes no record (Info, accepted)

- **Component.** `attenuo-server` `routes/policies.rs` (`budget_from_json`), `authz.rs` (`CounterSource::Stated`).
- **Observation.** With the admin token, `POST /admin/policies/evaluate` with a `budget` block shows how policy and limits decide any call for any counter state, with no audit record and no lease check, so `lease_unknown` and `lease_revoked` never come up there (`lease_check: "skipped"`). Input is bounded: at most 64 `limits`, non-negative integers up to `i64::MAX`, `arg` up to 256 bytes, no duplicate or unmatched entry, unknown members refused. `CounterSource::Stated` never reads from or writes to the store.
- **Reason accepted.** The admin token is trusted with more than this (it can revoke and refund), and a dry run that wrote records would fill the log with simulations. The console's read-only listener serves it to admin callers only.

## Verified fixed from earlier passes

- **SR-56.** Still holds for run limits. SR-70 is the same differential in the starter policy, now refused there too.
- **SR-59.** Limit names are still refused with control characters and escaped by `fmt_budget`. SR-72 covers the constraint names SR-59 left out.
- **SR-28.** Stream ends are recorded once per chain and reason per window (#101). The cutting of the stream itself is unchanged.

## Checked and found sound

- **`RawRange`.** Refuses a list, a repeated member (also when `value` comes before `op` and serde buffers the content), a misspelt member, a float or string bound (`5.0`, `1e3`), a bound outside `i64` and a missing or inverted range. Every path (tokens, exchange, `--cap`, case files) goes through `TryFrom`, so the unchecked inverted variant cannot arrive on the wire. `is_empty` can only be true for an empty `one_of` from the wire, which permits nothing.
- **`as_long`.** NaN and infinities cannot come from JSON. `-0.0` is `0`, as its canonical form is. Subnormals and fractions are not integers. `1e15` and anything above 922337203685477 is refused, and so is a `u64` past `i64::MAX`. `i64::MIN` and `i64::MAX` as integers are in the bounds of a range that reaches them. `range ⊑ range` is exact interval containment, and `range ⊑ equals/one_of` for a single integer is sound (`5` and `5.0` are equal values; the range admits nothing else).
- **Canonical JSON.** Range bounds are `i64` and written with all their digits. `{max: 5}` and `{min: i64::MIN, max: 5}` have different digests but imply each other, so nothing widens.
- **Diagnostics.** The `capability_denied` text names the constraint's own figures (the prefix as a Debug string, the bounds) and never the value. A denied `31337` is absent (existing test).
- **Input types and `like`.** `check_tool_inputs` only adds denials. Mixed case, Unicode lookalikes, a full-width `／`, NUL and very long names do not match `acme/*` or keep the single-`/` shape. Cedar compares strings exactly, so these all fail closed or stay inside one `acme/` name.
- **Sessions.** `session_digest` is the full SHA-256 and no raw id is stored. A binding is write-once per `(session, server)` and recorded only after the session gate admitted the session. Pruning runs in one write transaction, so a renewal cannot revive a chain between the check and the delete.
- **Retention.** Lease ids are UUIDv4, so a pruned id is never issued again. A child registered after its parent was pruned (possible only with a retention shorter than an exchange) carries a chain that names the missing parent and is refused as `lease_unknown` on every call. Runs are deleted whole, so no live lease has a missing parent row. Run-state rows go only once their leases are gone from the registry. `lease_unknown` refuses `tools/call`, session requests including `GET`, renewal and AuthZEN, which share the pipeline's lease check; an AuthZEN body chain of a pruned run also fails its binding check (403). The admin dry run skips the lease check by design (SR-76).
- **Listen-stream shape detection.** A non-list response with a `tools` (or other list) array loses entries, nothing is added. After SR-69, no message a client reads as a response escapes the check.
- **`resources/unsubscribe`.** Lease-checked, scoped to the run's own session (SR-11), widens nothing.
- **Non-SSE `GET`.** Content types are compared after trimming leading whitespace and lowercasing, by prefix, with parameters ignored. `text/event-stream2` counts as SSE in the proxy, which then filters and labels it as SSE; the Python SDK (`startswith`) reads it the same way and the TypeScript SDK (exact media type essence) refuses it, so no client reads as JSON what the proxy treated as SSE. With duplicate `Content-Type` headers the proxy reads the first; a non-SSE first value fails closed (502, or `label_error` for a mediated call).
- **`proxy_streams_ended_total`.** The label set is fixed (11 causes).
- **Audit export filters.** `tool` and `decision` are bound parameters (`?10`, `?4`) in `range_filtered`, then matched again by `EntryFilter`. The export format stays `attenuo-audit-export-v2`.

## Not covered

- The evaluation suite and its frozen policies, the bench crate and the fuzz targets (not re-run).
- MCP clients other than the Python and TypeScript SDKs for SR-69, and URL parsers other than Node's for SR-70 (Go's `net/url` does not treat `\` as `/`; the fix refuses the characters whatever the parser).
- Output labelling against an upstream that answers an allowed call on the listen stream after `AWAITED_RESULT_TTL` (10 minutes). That answer passes unlabelled by design (module docs of `label.rs`). Most clients time out a request well before then, so it was not taken further here.
- Deployments with more than one server process on one store.
- A flaky property test, unrelated to these fixes: `attenuate_iff_covered_and_nonempty` (`attenuo-core/tests/attenuation_props.rs`) failed once. In its minimal input, the requested capability's `calls: 0` lets `Limits::narrows` accept it under a parent `calls_per` of 0 while its own `calls_per` is 1, and `attenuate` then clamps that to 0, so the result differs from the request. The result is tighter, so nothing widens, but the oracle expects equality. Left for a follow-up (board).

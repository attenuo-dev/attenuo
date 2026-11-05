# Codebase walkthrough

A reading-and-running plan for someone who wants to understand every piece of attenuo himself. It has five parts:

1. [A one-page mental model](#1-the-mental-model): the path of one proxied tool call and one token exchange, by file and function.
2. [Fifteen reading sessions](#2-reading-sessions) of 45 to 60 minutes, each with files in order, a document to read beside them, three to six questions and a block of commands that shows the concept working.
3. [Why it is this way](#3-why-it-is-this-way): every ADR and design document in one line each.
4. [A glossary](#4-glossary).
5. [Things that will surprise you](#5-things-that-will-surprise-you).

Paths are relative to the repository root. Functions are cited by name, not line number, because lines move: find one with `grep -rn "fn name" crates/`. Line counts are rounded and were checked against main @ de3cf75 (2026-10-24); use them to size a session, not as a contract.

Every command below except `cargo bench` and `cargo +nightly fuzz` was run, in this order, on 2026-10-23 against `main` (about 110 commands; the Rust test filters, the Python and TypeScript test suites and the demo included). Where the text quotes output, that is what was printed. Line counts were refreshed the same day; they are rounded, so use them to size a session, not as a contract.

Session 9 (output labelling and approvals) and the labels-arm part of session 10 were added on 2026-10-24, and every command added there was run against `main` @ 1904f70. The same day the commands of sessions 1 to 7 that use the running server, the session 8 quickstart, the demo, and session 10's oracle, pytest and `run.py --out` were run again on that commit. They print what is quoted, except two counts that changed with the new features and were updated here: the demo now verifies 9 audit entries (the allowed call adds a `tool_result` record), and the suite's pytest run passes 24 and skips 7.

Session 11 (run limits) was added for the 0.1.0 documentation refresh, and every command in its block except the benchmarks was run against `main` @ a02bc83 on 2026-10-24, with its line counts checked on the same commit. On that commit the demo was run again (9 entries, as quoted) and the session 9 policy tests, whose count had grown, were updated; session 10's suite commands were run again and their quoted output updated for the new cases and arms.

Session 12 (audited refusals, revocation by user, chain and session, typed inputs, the policy harness, listen-stream list filtering and the new metrics) was added on the evening of 2026-10-24 for the merges #77 to #91. Every command in its block was run against `main` @ 471a319 the same day, and its file pointers were checked against that commit. Sessions 1 to 11 were not re-run for it.

Session 13 (numeric `range` constraints, retention of session records, leases and run state, listen-stream endings and the `stream.end` bound, AuthZEN conformance, and the admin dry run with a stated run state) was added on 2026-10-25 for the merges #95 to #103. Every command in its block was run, in order, against `main` @ 35b2c62 the same night, and its file pointers and line counts were checked against that commit. Sessions 1 to 12 were not re-run for it.

Session 14 (security pass 6, the lease-refusal record bound, the attenuation proptest oracle and the maintenance settings, AuthZEN short-circuit batches and discovery, the strict `approval` block of the dry run, bounded prunes of wide runs, the refund of a pruned charge, the per-value limits figures and the proposed ADR-0011) was added on 2026-10-25 for the merges #104 and #106 to #113. Every command in its block was run, in order, against `main` @ 9d16340 the same night, and its file pointers and line counts were checked against that commit. Sessions 1 to 13 were not re-run for it; where a later merge made session 13 wrong (the refund of a pruned charge, the maintenance constants), its text was corrected in place.

Session 15 (streamed `tools/call` answers in both SDKs and `fake_mcp --sse`, the proxy's rewrite of upstream messages in its stream-end shape and the byte scan in front of it, the property-test seed policy, and the SDK publish workflow) was added on 2026-10-25 for the merges #115 to #119. Every command in its block was run, in order, against `main` @ a2abfdd the same morning, and its file pointers and line counts were checked against that commit. Sessions 1 to 14 were not re-run for it. Where these merges made earlier text wrong, it was corrected in place: session 8's client rows (recounted on that commit), session 14's proptest row, the SDK lines of the open lists of sessions 13 and 14, step 12 of the first table, and section 0.

## 0. Setup you need once

```sh
cargo build -p attenuo-server -p attenuo-cli
cargo build -p attenuo-proxy --features testing --example fake_mcp
export BIN=$PWD/target/debug          # or the directory your CARGO_TARGET_DIR points at
export PATH=$BIN:$PATH                # gives you `attenuo` and `attenuo-server`
```

`fake_mcp` is a stand-in for an MCP server: it has `read_file`, `create_issue` and `delete_repo` tools, echoes calls and does nothing else. It lands in `$BIN/examples/fake_mcp`. With `--sse` it streams every answer as a notification and then the response, and a `tools/call` with a `hold_ms` argument holds the response back that long (session 15). The crate's self dev-dependency turns on `testing`, so `--features testing` can be left out.

Sessions 2, 5, 6, 7, 8, 9, 11, 12, 13, 14 and 15 use a running server (session 9 starts a second one beside it, session 12 restarts it for a clean log, session 13 ends by restarting it on a copy of the config with tiny retentions, session 14 runs on copies with a metrics listener, and session 15 restarts the server and `fake_mcp`, the latter with `--sse`). Start the demo's server and fake upstream once, in a spare terminal or in the background, from the repository root:

```sh
$BIN/examples/fake_mcp --port 13001 > /tmp/ob-fake.log 2>&1 &
RUST_LOG=warn attenuo-server --config examples/github-leak-demo/config.toml > /tmp/ob-server.log 2>&1 &
export ATTENUO_SERVER=http://127.0.0.1:18080 ATTENUO_ADMIN_TOKEN=demo-admin-token
sleep 2 && curl -s $ATTENUO_SERVER/healthz       # {"status":"ok","version":"0.1.0"}
```

Those two variables are read by anything in this shell, the test binaries included: the `attenuo-cli` unit tests expect the default server address and the `attenuo-bench` smoke test mints its own admin token, so with them exported one test in each fails. The `cargo test` lines of sessions 7 and 10 are written with `env -u` for that reason; the other crates' tests do not read them.

The config uses fixed ports (18080 for attenuo, 13001 for the upstream), an in-memory audit log (`sqlite_path = ":memory:"`, so a restart starts a new log) and an ephemeral signing key (so a restart invalidates every token). Stop everything with `pkill -x attenuo-server; pkill -x fake_mcp`.

Two tokens are used again and again. Mint them in the same shell:

```sh
ROOT=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
CODER=$(printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$ROOT" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)
```

`ROOT` is Alice's assistant holding every GitHub tool (hop 0). `CODER` is what the assistant hands a sub-agent: `read_file` only (hop 1). A parent token can be exchanged for a given actor once (see [section 5](#5-things-that-will-surprise-you)), so mint a fresh `ROOT` whenever a block exchanges it again.

If you would rather watch than type, `bash examples/github-leak-demo/run.sh` plays the whole scenario and checks every step. Set `ATTENUO_BIN_DIR=$BIN` to skip its own build.

To run every local check in one command (formatting, clippy, rustdoc, the Rust tests, links, the book, the policy tests, the suite's and both SDKs' tests, and the packaging dry runs), use `scripts/release-check.sh`; `--list` prints its steps and `--from <step>` resumes after a fix. It needs the Python dev dependencies; the setup is in [the 0.1.0 release notes](../release/0.1.0.md#1-run-the-local-checks-on-the-commit-you-will-tag).

## 1. The mental model

attenuo sits between an AI agent and the MCP servers it calls. The agent holds a **token** that says whom it acts for, which agents sit between that person and it (the **chain**) and what each hop may do (**capabilities**). Every call goes through the proxy, which asks a **decision pipeline** three questions in a fixed order (is every lease alive, do the capabilities, the run limits and the Cedar policy allow it, can the decision be written to the audit log) before it forwards anything.

Two flows matter. Read them with the code open.

### One proxied tool call

A client sends `POST /mcp/github` with a JSON-RPC `tools/call` body and `Authorization: Bearer <token>`.

| Step | What happens | Where (crate, file, function) |
| --- | --- | --- |
| 1 | The route exists because the server merges the proxy router into its own. | `attenuo-server/src/lib.rs` `router`; `attenuo-proxy/src/proxy.rs` `router`, which sends `POST` to `handle_post` |
| 2 | The bearer (and DPoP proof, if the token is bound) is authenticated. The proxy asks its `Authorizer` trait; the server implements it. | `proxy.rs` `authenticate` calls `Authorizer::authenticate_request` (trait in `attenuo-proxy/src/auth.rs`); implemented by `ServerAuthorizer` in `attenuo-server/src/authz.rs` |
| 3 | The token is verified, or found in a bounded cache of tokens already verified (expiry and chain validity are re-checked on a hit). Verification checks signature, `typ`, `iss`, `aud`, `exp`, that `sub`/`act` match the chain, `ou_sig`, and the chain's structure. | `ServerAuthorizer::verify_inner` calls `attenuo_token::Verifier::verify` (`attenuo-token/src/verifier.rs`), which ends in `DelegationChain::validate_at` (`attenuo-core/src/chain.rs`) |
| 4 | DPoP: if the token carries `cnf.jkt`, the request needs a proof by that key, and the proof's `jti` is single-use. | `attenuo-server/src/dpop.rs` `Dpop::check_presented`; proof parsing in `attenuo-token/src/dpop.rs` `verify_proof` |
| 5 | An `Mcp-Session-Id`, if present, must belong to this caller. | `proxy.rs` `session_gate`, using `SessionRegistry::check` in `attenuo-proxy/src/session.rs` |
| 6 | The JSON-RPC message becomes a `ToolCall`. The tool name must obey the name rule and, by default, must have been listed by the upstream. | `proxy.rs` `handle_post_inner`, `screen_message`, `tool_name_refusal`; `attenuo_core::names::check_call_name`; `attenuo-proxy/src/listed.rs` `ListedTools` |
| 7 | The decision is requested; the server runs it on a blocking thread because SQLite is synchronous. | `proxy.rs` calls `Authorizer::authorize`; `ServerAuthorizer::authorize` runs `Pipeline::decide` (`authz.rs`) |
| 8 | Leases: every hop's lease must be known, unrevoked and unexpired. | `Pipeline::check_leases` calls `LeaseStore::check_all` (`attenuo-audit/src/lease.rs`, implemented by `SqliteLeaseStore`) |
| 9 | Capabilities, then the tool catalog, then Cedar. A capability miss is `capability_denied` and Cedar never runs. | `PolicyEngine::authorize` (`attenuo-policy/src/lib.rs`): `CapabilitySet::permits` (`attenuo-core/src/capability.rs`), `ToolCatalog`, then the request is translated (cached in `RequestCache`, `attenuo-policy/src/request.rs`) and evaluated by `cedar_policy` |
| 10 | The decision is written to the hash-chained log. If the write fails the answer becomes deny (`audit_error`). The new record's id is the **decision id**. | `DecisionRecord::new` (`attenuo-core/src/decision.rs`), `AuditSink::append` implemented by `SqliteAudit` (`attenuo-audit/src/sqlite.rs`, `log.rs` for the hash) |
| 11 | Deny: a JSON-RPC error `-32003` with `data.reason` and `data.decision_id`; nothing reaches the upstream. Allow: the request is forwarded with `reqwest`. | `proxy.rs` `refuse_call` / `handle_post_inner`; code `CODE_DENIED` in `attenuo-proxy/src/jsonrpc.rs` |
| 12 | The response comes back with `X-Attenuo-Decision-Id`. A `tools/list` (and the other three list methods) result is filtered to what the chain could ever call. A streamed body is re-checked against lease and expiry every couple of seconds. An upstream message in the shape of the proxy's own stream-end event is rewritten to `-32005` before it is relayed (#117, session 15). | `add_decision_header`, `buffer_and_rewrite`, `stream_response_sse`, `ListFilter` in `attenuo-proxy/src/filter.rs`, `StreamGuard` and `disown_stream_end` in `guard.rs` |

The AuthZEN endpoint (`POST /access/v1/evaluation`, `attenuo-server/src/routes/authzen.rs`) enters the same `Pipeline::decide`, so a gateway that asks "may this call happen?" gets the same answer as the proxy, with the same audit record.

Output labelling (ADR-0009, session 9) adds to this table in two places. Between steps 8 and 9, `Pipeline::decide` reads the run's taint (`run_labels`, keyed by `chain_id`, the first hop's lease) and takes a granted approval for this exact call if there is one; Cedar sees both as `context.session` and `context.approval`. A deny that comes only from forbids annotated `@obligation("approval")` has the reason `approval_required`: the proxy answers `-32008` with an approval id instead of `-32003`, and nothing is forwarded. After step 12, before an allowed call's answer is relayed, the proxy reports it and the server appends a `tool_result` record and labels the run (`Pipeline::record_result`); if either write fails, the agent gets `-32003` `label_error` instead of the answer.

Run limits (ADR-0010, session 11) add to it in three places. In the same read between steps 8 and 9, `Pipeline::decide` collects every limited capability in every hop that matches the call (`charges_for`) and what its counters hold, and, when something loaded reads it, the run's usage of a destructive tool. In step 9 a call that would take any of those counters past its `max` is denied with `budget_exhausted` before the catalog and Cedar; Cedar sees what is left as `context.budget` and the usage as `context.usage`. Between steps 9 and 10, an allowed call is charged in one store transaction (`LeaseStore::charge`), which re-checks every counter, so a call that lost a race becomes `budget_exhausted`; if the append in step 10 then fails, the charge is refunded.

### One token exchange

A sub-agent (or its parent on its behalf) sends `POST /token` with the parent token, the new actor and the capabilities it wants (RFC 8693).

| Step | What happens | Where |
| --- | --- | --- |
| 1 | The route. JSON and form bodies are both accepted. | `attenuo-server/src/routes/token.rs` `exchange`, then `exchange_sync` on a blocking thread |
| 2 | The actor proves who it is: a client secret from `[[agents]]`, an RFC 8693 `actor_token` from a trusted workload-identity issuer, or both. | `attenuo-server/src/clientauth.rs`; `attenuo-server/src/actor.rs` `ActorTrustRegistry::verify`; `take_actor_token` in `token.rs` |
| 3 | The parent token is verified exactly as in step 3 above. All its leases must be alive. | `state.verifier.verify`; `Pipeline::check_leases` |
| 4 | Refusals before anything is minted: the reserved agent id `attenuo`; an actor already in the chain (`duplicate_actor`); `may_act` on the parent not naming this actor. | `exchange_sync`; `MayAct::permits` in `attenuo-token/src/claims.rs` |
| 5 | If the parent is key-bound, the child must be bound too, and the parent's holder must have signed off on this child key and this actor. | `Dpop::bind_exchange` in `attenuo-server/src/dpop.rs` |
| 6 | Attenuation: the requested capabilities must be covered by the parent's. This is where widening is refused (`invalid_scope`). The child's expiry is clamped to the parent's. | `ExchangeRequest::execute_with` (`attenuo-token/src/exchange.rs`) calls `Issuer::exchange_with` (`issuer.rs`), which calls `DelegationChain::extend`, which calls `CapabilitySet::attenuate` |
| 7 | The new JWT is signed with the issuer's Ed25519 key. The parent's `ou_sig` is copied unchanged: it signs the user and the root hop, so nobody below the root can alter whom the chain acts for. | `Issuer::exchange_with`; `ou_sig_message` in `claims.rs` |
| 8 | Replay protection: "this parent delegated to this actor" and "this actor token was used" are recorded together or not at all. | `attenuo-server/src/replay.rs` `ReplayCache::use_all_once` |
| 9 | The new lease is registered under the parent's lease, bound to the digest of the chain, and the issuance is audited. | `register_issued` and `audit_issuance` in `routes/mod.rs` |

Renewal (`POST /token/renew`, `routes/renew.rs`) extends a lease, never beyond the token's expiry or the parent lease. Revocation (`POST /admin/leases/{id}/revoke`, `routes/admin.rs` `revoke_lease`) marks a lease and all its descendants; the next call anywhere below it fails step 8 of the first table. `POST /admin/leases/revoke` (`revoke_by_selector`) does the same for every lease of one originating user, one chain or the chains that opened one MCP session (session 12).

A refusal that happens before any pipeline decision (a session opened, an exchange or a renewal refused, a stream cut by the re-check) is also written to the audit log, as a `deny` record with a fixed tool name, through `Pipeline::record_rejection`, but only once the token and its DPoP proof have fully verified (SR-18; session 12).

## 2. Reading sessions

Sixteen sessions: the CLI and the demo get their own, short, session, and output labelling with approvals and run limits, which landed after the others were written, get sessions 9 and 11. Session 12 covers what the evening merges of 2026-10-24 added across the crates, session 13 what the merges of that night (#95 to #103) added, session 14 the follow-ups after it (#104, #106 to #113), session 15 the merges after that (#115 to #119), and session 16 the ones after those (#121 to #126). In order:

1. Core types and attenuation (`attenuo-core`).
2. Tokens, `ou_sig` and DPoP (`attenuo-token`).
3. Cedar policy and the translation cache (`attenuo-policy`).
4. Audit log, WAL, checkpoints and canonical JSON (`attenuo-audit`).
5. Proxy, session registry and list filtering (`attenuo-proxy`).
6. Server routes, exchange, leases, AuthZEN and admin (`attenuo-server`).
7. The CLI and the demo.
8. The SDKs and the refresh helper.
9. Output labelling and approvals: taint, `tool_result`, `-32008`, the approval store.
10. Evaluation suite (with the labels and limits arms), benchmarks and fuzzing.
11. Run limits and budgets: `limits` in the token, the charge transaction, refunds, run usage and soft limits.
12. Refusals you can see, and revocation you can aim: audited refusals of session opens, exchanges, renewals and streams; revoke by user, chain or MCP session; typed inputs before Cedar; the policy harness; list filtering on the resumed listen stream; the new metrics.
13. Number bounds, retention, stream endings, AuthZEN and the stated dry run: the `range` constraint; retention of session records, leases and run state on one ticker; listen-stream endings counted and `stream.end` records bounded; the AuthZEN conformance fixtures; the admin dry run told the run's budget, labels, approval and usage.
14. Security pass 6, bounded refusals, short-circuit batches, wide prunes and the pruned refund: SR-69 to SR-72; lease refusals of undecided requests bounded per chain, tool and reason (`RecordWindow`); the proptest oracle and the maintenance settings; AuthZEN `deny_on_first_deny`, `permit_on_first_permit` and public discovery; the strict `approval` block and the console's Approval section; prune passes bounded for wide runs; 410 `charge_pruned`; the per-value limits figures; ADR-0011 (proposed).
15. Streamed answers, the proxy's voice, reproducible properties and the road to PyPI and npm: `call_tool_stream` and `callToolStream`, `fake_mcp --sse`; upstream messages in the proxy's stream-end shape rewritten to `-32005` `upstream_stream_end_shape`, and the byte scan in front of that check; `PROPTEST_RNG_SEED`, pinned in CI and random locally; `release-packages.yml`, a dry run on a tag and a publish on a dispatch.
16. Record windows you can set, a cost that would not move, cuts the SDKs can trust and security pass 7: `[proxy] record_window_seconds` and `record_window_max_keys`; the `distinct` list charge measured and left as it was; a stream cut read only with one of the proxy's six reasons and a UUID id, else `RpcError -32001`; SR-77 to SR-80 (events the proxy could not parse); the linear Python SSE parser and the optional total deadline on a streamed call (SR-82).

Sessions 9, 11 and 12 cut across sessions 3 to 8 and are easiest after all of them; read 11 after 9, since soft limits use its approvals. Session 12 needs only sessions 5 and 6. Session 13 needs sessions 1, 6 and 11, and session 12 for the refusal records. Session 14 needs session 13 (retention, `stream.end` windows, the dry run) and session 12 (refusal records). Session 15 needs session 8 (the SDKs), session 5 (the proxy's streaming path) and the `stream.end` records of sessions 12 and 13; its seed part follows session 14's proptest row. Session 16 needs session 14 (the refusal record window) and session 15 (streamed calls, the stream-end shape and the byte scan); its #122 row follows session 11's charge transaction. Sessions 7, 8 and 10 are light, so merge them if you have the time.

Each session has four parts. Read the files in the order given, with the "read beside" document open. Answer the questions without looking, then check the run block. Tests are named so that `cargo test -p <crate> <filter>` runs a handful, not the whole suite; add `-- --nocapture` to see output.

### Session 1: core types and attenuation (`attenuo-core`)

This crate has no I/O, no async and no network. If you only understand one crate completely, make it this one: every security claim in the README rests on `covers` and `validate_at`.

Read beside: [Capabilities and attenuation](../concepts/capabilities-and-attenuation.md), and glance at [Delegation chain](../concepts/delegation-chain.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-core/src/lib.rs`, `error.rs` | The module map and the error types (`ChainError`, `AttenuationError`). | 100 |
| 2 | `crates/attenuo-core/src/call.rs` | `ToolCall`: server, tool, arguments, whether the token was key-bound, the session. `arguments_digest`. | 70 |
| 3 | `crates/attenuo-core/src/capability.rs` | `ArgConstraint` (`Eq`, `OneOf`, `Prefix`), `Capability::covers` (is a child no wider than a parent), `permits` (does this call fit), `CapabilitySet::attenuate`. The heart of the project. | 450 |
| 4 | `crates/attenuo-core/src/chain.rs` | `DelegationChain`, `Hop`, `OriginatingUser`; `root`, `extend` (the only way to add a hop), `validate_at` (re-checks everything), `digest`, `prefix_digest`. | 780 |
| 5 | `crates/attenuo-core/src/names.rs` | The one rule for server, tool and method names (ASCII, no `/` or `:` or `*`, at most 128 bytes, never normalized). | 250 |
| 6 | `crates/attenuo-core/src/decision.rs`, `digest.rs` | `Decision`, `DecisionRecord` (what the audit log stores), the SHA-256 helper. | 235 |
| 7 | `crates/attenuo-core/src/jcs.rs` | Skim only; session 4 returns to it. RFC 8785 canonical JSON. | 790 |

Check you understood:

1. A parent holds `github:read_file` with `repo` constrained to a prefix. Which of these children are accepted: no constraint on `repo`; a longer prefix; a `OneOf` of two repos that both match the prefix? Why does the code reject the first one?
2. Why is `DelegationChain::extend` the only way to build a longer chain, and why does `validate_at` still re-check narrowing at every hop?
3. Why does `names.rs` forbid `/` in a server name? (Hint: the Cedar action id is `"<server>/<tool>"`.)

Run it:

```sh
cargo test -p attenuo-core capability::                  # unit tests next to the code
cargo test -p attenuo-core chain::
cargo test -p attenuo-core --test attenuation_props      # property tests: covers is sound, reflexive, transitive
cargo bench -p attenuo-core --bench attenuation          # what `covers` costs (optional)

# The same rule through the server. Widening is refused:
printf '%s\n' demo-tester-secret | ATTENUO_TOKEN="$CODER" \
  attenuo token exchange --actor tester --client-secret-stdin --cap 'github:*'
# error: ... invalid_scope: delegation chain is invalid: hop 2 widens capabilities relative to hop 1 ...

# Narrowing with an argument constraint (a capability as JSON) is accepted. Use a fresh root:
ROOT2=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
CAP='{"server":"github","tool":"read_file","constraints":{"repo":{"op":"prefix","value":"alice/public-"}}}'
T=$(printf '%s\n' demo-tester-secret | ATTENUO_TOKEN="$ROOT2" \
  attenuo token exchange --actor tester --client-secret-stdin --cap "$CAP" --print token)
attenuo token inspect "$T"          # a tree: assistant can github:*, tester can read_file {repo starts with "alice/public-"}
```

### Session 2: tokens, `ou_sig` and DPoP (`attenuo-token`)

How a chain becomes a signed JWT and back, and why a leaked token is not enough.

Read beside: [RFC-0001](../spec/rfc-0001-attenuo.md) section 4 (token exchange) and 4.1 (sender-constrained tokens). Then, for DPoP from the user's side, [Binding tokens to keys](../guides/binding-tokens-to-keys.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-token/src/claims.rs` | The JWT claims (`sub`, nested `act`, `chain`, `ou_sig`, `ou_sig_v`, `cnf`), `MayAct`, and `ou_sig_message`: exactly which bytes `ou_sig` signs. | 325 |
| 2 | `crates/attenuo-token/src/keys.rs`, `detached.rs` | Ed25519 key loading, the `kid`, and `DetachedSigner` (signs with a domain-separation context; used for `ou_sig` and audit checkpoints). | 340 |
| 3 | `crates/attenuo-token/src/issuer.rs` | `Issuer::issue_root_with` and `exchange_with`: build the chain, sign the user block once, sign the JWT. Key rotation via `trust_previous_key`. | 390 |
| 4 | `crates/attenuo-token/src/verifier.rs` | `Verifier::verify`: header `typ`, signature by a trusted `kid`, claims, `ou_sig_v` (only 3), `ou_sig`, `sub`/`act` against the chain, `validate_at`. | 230 |
| 5 | `crates/attenuo-token/src/exchange.rs` | `ExchangeRequest` (RFC 8693 request) and `execute_with`; `ExchangeResponse`. | 270 |
| 6 | `crates/attenuo-token/src/dpop.rs` | `verify_proof` (RFC 9449), `jwk_thumbprint`, `Confirmation` (`cnf.jkt`), `DpopKey` with `proof` and `sign_off`. | 805 |

Check you understood:

1. What does `ou_sig` cover, who can make it, and why does a sub-agent hold a copy it cannot change?
2. A thief copies a DPoP-bound token from a log. What exactly is missing from his request, and what does the server record about each proof so it cannot be replayed?
3. Why does a token carry a `kid` and what happens to tokens signed by a retired key while it is still listed under `previous_key_paths`?

Run it:

```sh
cargo test -p attenuo-token ou_sig            # the ou_sig tests: lifted into another chain, other issuer, v1/unknown versions refused
cargo test -p attenuo-token --lib dpop        # unit tests in dpop.rs, including sign_off_names_the_child_key_and_actor
cargo test -p attenuo-token exchange_cannot_widen_capabilities

attenuo token inspect "$CODER" --verify       # decodes locally, then checks signature, type, issuer, audience, expiry, chain
curl -s $ATTENUO_SERVER/.well-known/jwks.json # the public key and its kid; `inspect --verify` fetches this

# DPoP from the command line: a bound root token, and a sign-off naming the child's key.
mkdir -p /tmp/ob-dpop && cd /tmp/ob-dpop
attenuo key gen --dpop assistant.jwk
CODER_JKT=$(attenuo --json key gen --dpop coder.jwk | python3 -c 'import json,sys; print(json.load(sys.stdin)["jkt"])')
BROOT=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --dpop-key assistant.jwk --print token)
ATTENUO_TOKEN="$BROOT" attenuo token sign-off --dpop-key assistant.jwk \
  --child-jkt "$CODER_JKT" --actor coder > sign-off.txt
BCODER=$(ATTENUO_TOKEN="$BROOT" ATTENUO_CLIENT_SECRET=demo-coder-secret attenuo token exchange \
  --actor coder --cap github:read_file --dpop-key coder.jwk --subject-token-dpop-file sign-off.txt --print token)
ATTENUO_TOKEN="$BCODER" attenuo call --dpop-key coder.jwk --server github --tool read_file \
  --arg repo=alice/public-docs --arg path=README.md      # ALLOWED
ATTENUO_TOKEN="$BCODER" attenuo call --server github --tool read_file \
  --arg repo=alice/public-docs --arg path=README.md      # error -32001 ... dpop_required: a stolen token without the key (exit status 2)
cd - > /dev/null
```

### Session 3: Cedar policy and the translation cache (`attenuo-policy`)

The second gate. Capabilities say what a token may ever do; Cedar says whether this particular call, with these arguments, in this chain, is acceptable.

Read beside: [ADR-0005: Policy decision point](../decisions/0005-policy-decision-point.md). For writing policies, [Writing and testing policies](../guides/writing-policies.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-policy/src/catalog.rs` | `ToolCatalog`, `ToolAttrs` (`readonly`, `sensitive`, typed `inputs`), `UnknownTools` (`deny`, `sensitive`, `allow`). | 215 |
| 2 | `crates/attenuo-policy/src/schema.rs` | Generates the Cedar schema from the catalog; `action_id` makes `Action::"<server>/<tool>"`. | 210 |
| 3 | `crates/attenuo-policy/src/lib.rs` | `PolicyEngineBuilder`, `PolicyEngine::authorize` (the two stages), `reload_policies_str`. Read the crate-level comment first: it documents the request shape. | 670 |
| 4 | `crates/attenuo-policy/src/request.rs` | Turns a chain and a call into Cedar entities and context (`context.chain`, `context.input`, `context.originating_user`). `RequestCache` keeps the part that depends only on the chain and tool. Fails closed on anything it cannot represent. | 880 |
| 5 | `crates/attenuo-policy/src/authzen.rs` | AuthZEN 1.0 request and response types, so any enforcement point can call the engine. | 220 |
| 6 | `crates/attenuo-policy/src/lint.rs`, `testing.rs` | `attenuo policy lint` and `attenuo policy test` (YAML cases). Skim. | 1600 |
| 7 | `config/policies/default.cedar`, `examples/github-leak-demo/policy.cedar`, `policy_test.yaml` | Three real policies and eleven tests to read as examples. | 150 |

Check you understood:

1. In what order do capabilities, the catalog and Cedar run, and which denial reasons does each stage produce?
2. What is cached in `RequestCache`, what is not, and why must the cache be keyed on everything it was built from (chain, tool, attributes)?
3. A `forbid ... when { resource.sensitive }` rule protects `delete_repo`. What happens to a tool that is missing from the catalog under `unknown_tools = "allow"`, and why is that the setting to avoid?

Run it:

```sh
cargo test -p attenuo-policy --test engine                        # 30-odd decision tests
cargo test -p attenuo-policy --test engine cached_translations_decide_like_fresh_ones
cargo test -p attenuo-policy --test engine a_permit_for_one_servers_tool_does_not_match_another_server_sr13
cargo bench -p attenuo-policy --bench policy_stage               # translation versus evaluation (optional)

attenuo policy test examples/github-leak-demo/policy_test.yaml    # 11 passed, 0 failed
attenuo policy lint examples/github-leak-demo/policy.cedar --config examples/github-leak-demo/config.toml
# 3 policies, 0 error(s), 0 warning(s). Without --config lint declares the tools from the policy's own action names and prints a note about what it could not check.

# Ask for a decision without calling the tool (needs the running server):
ATTENUO_TOKEN="$CODER" attenuo authzen eval --server github --tool read_file --arg repo=alice/public-x --arg path=a
# ALLOW  policy_allow, then the decision id and the policy that matched; try repo=bob/x: DENY  policy_deny, exit status 2
# (a token passed as --token works too, with a warning that the command line is visible to other local users)
```

### Session 4: audit log, WAL, checkpoints and canonical JSON (`attenuo-audit`, and `jcs.rs` in core)

Why you can believe the log: each entry's hash covers the previous one, the issuer signs the head every so often, and an export can be checked offline with only the public key.

Read beside: [Audit log](../concepts/audit-log.md), then [RFC-0001](../spec/rfc-0001-attenuo.md) section 7.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-core/src/jcs.rs` (first 100 lines and the tests) | RFC 8785 canonical JSON. Everything hashed or signed as JSON goes through it. | 790 |
| 2 | `crates/attenuo-audit/src/log.rs` | `AuditEntry`, `compute_entry_hash` (SHA-256 over canonical `["attenuo-audit-entry-v2", seq, prev_hash, record]`), `verify_entries`, the `AuditSink` trait. | 185 |
| 3 | `crates/attenuo-audit/src/memory.rs` | An in-memory sink: the smallest implementation to read first. | 60 |
| 4 | `crates/attenuo-audit/src/checkpoint.rs` | `Checkpoint` (seq, head hash, time, `kid`, signature), `CheckpointKeys` from a JWKS, `verify_with_checkpoints`. | 265 |
| 5 | `crates/attenuo-audit/src/export.rs` | The `attenuo-audit-export-v2` JSON Lines format, `parse_export`, strict `verify_export`. | 355 |
| 6 | `crates/attenuo-audit/src/lease.rs` | The `LeaseStore` trait and `MemoryLeaseStore`: register, renew, revoke with cascade, `check_all`. | 375 |
| 7 | `crates/attenuo-audit/src/sqlite.rs` | `SqliteAudit` and `SqliteLeaseStore`. Read the module comment, `Durability`, `append_locked` and the group-commit writer; skim the rest. WAL mode, background WAL checkpoints (and the writer's own backstop), `checkpoint_signed`. | 2900 |

Check you understood:

1. Name three kinds of tampering (edit a record, delete a middle row, truncate the tail) and which mechanism catches each: the hash chain, a signed checkpoint, or the strict export rules.
2. What does `durability = "normal"` risk, what does it never risk, and why are revocations always synced?
3. Why was canonical JSON needed at all, when `serde_json` already produces bytes? (Hint: `preserve_order`, and another language verifying the same log.)

Run it:

```sh
cargo test -p attenuo-audit --test audit tamper
cargo test -p attenuo-audit --test checkpoints forged_checkpoints_are_rejected
cargo test -p attenuo-audit --test export entries_after_the_declared_range_fail_the_export_f5
cargo test -p attenuo-audit --test wal
cargo test -p attenuo-core jcs::                  # includes the RFC 8785 test vectors

# Against the running server (make a few calls first; session 5's block does):
attenuo audit tail -n 5
attenuo audit verify                              # walks the whole chain; "checkpoints: none signed yet" is normal early on
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" $ATTENUO_SERVER/admin/audit/checkpoint   # signs and stores one
attenuo audit export --out /tmp/ob-export.jsonl
attenuo audit verify --file /tmp/ob-export.jsonl  # offline; needs only the JWKS, no admin token

# Break it yourself. Flip one decision in the export:
sed 's/"decision":"deny"/"decision":"allow"/' /tmp/ob-export.jsonl > /tmp/ob-forged.jsonl
attenuo audit verify --file /tmp/ob-forged.jsonl  # audit chain BROKEN at seq N; exit status 2
```

If the export holds entries newer than its last checkpoint, `verify --file` rejects it until you sign the head first (the `curl` above) or pass `--allow-unsigned-tail`. That is the strict behaviour described in [section 5](#5-things-that-will-surprise-you).

### Session 5: proxy, session registry and list filtering (`attenuo-proxy`)

Everything between the agent's HTTP request and the decision: parsing MCP, deciding what counts as a call, and rewriting what comes back. This crate knows nothing about tokens or Cedar; it talks to an `Authorizer` trait.

Read beside: [Server request pipeline](../design/server.md), the "MCP method coverage", "List filtering" and `Mcp-Session-Id` parts (the rest is session 6).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-proxy/src/auth.rs` | The `Authorizer` trait (`authenticate_request`, `authorize`, `check_active`, `record_rejection`, `record_rejection_checked` since #128, `knows_tool`) and `AuthDecision`. This is the seam to the server. | 225 |
| 2 | `crates/attenuo-proxy/src/jsonrpc.rs`, `config.rs`, `lib.rs` | JSON-RPC error codes (`-32003` denied, `-32006`/`-32007` capacity), `ProxyConfig`, crate docs. | 440 |
| 3 | `crates/attenuo-proxy/src/session.rs` | `SessionRegistry`: binds an `Mcp-Session-Id` to the caller's root lease; bounded, idle expiry, per-principal cap (`bind`, `check`). | 410 |
| 4 | `crates/attenuo-proxy/src/listed.rs` | `ListedTools`: names the upstream has returned from `tools/list`. | 95 |
| 5 | `crates/attenuo-proxy/src/filter.rs` | `ListFilter`, `could_permit_*`: drop list entries the chain could never use. | 485 |
| 6 | `crates/attenuo-proxy/src/sse.rs`, `guard.rs` | Incremental SSE parsing; `StreamGuard` ends a stream when its lease dies. | 630 |
| 7 | `crates/attenuo-proxy/src/proxy.rs` | `handle_post`, `handle_post_inner`, `screen_message`, `session_gate`, `buffer_and_rewrite`, `stream_response_filtered`. Read in the order of the table in section 1. Large; do the first pass for shape only. | 1475 |
| 8 | `crates/attenuo-proxy/src/testing.rs`, `examples/fake_mcp.rs` | A fake upstream and a fake authorizer for tests (feature `testing`). | 690 |

Check you understood:

1. A client calls `tools/call` with `params.name = "resources/read"`. Which check stops it from posing as the MCP method, and where?
2. `tools/list` through a token that holds only `github:read_file`: what does the client see, is Cedar consulted, and is anything written to the audit log?
3. One user opens 64 sessions and tries a 65th. What does the client get, and what does the proxy do to the session the upstream just created?

Run it:

```sh
cargo test -p attenuo-proxy --test proxy denied_tools_call_returns_32003_and_never_reaches_upstream
cargo test -p attenuo-proxy --test list_filtering
cargo test -p attenuo-proxy --test session_limits
cargo test -p attenuo-proxy --lib session::          # SessionRegistry unit tests

# An allowed call, with headers so you can see the decision id and the session id:
curl -s -D - -X POST $ATTENUO_SERVER/mcp/github \
  -H "Authorization: Bearer $CODER" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"alice/public-docs","path":"README.md"}}}'
# HTTP/1.1 200 OK ... x-attenuo-decision-id: <uuid>
# No mcp-session-id here, although fake_mcp sends one: it gives every response the same id, fake-session-1, and the
# proxy binds a session id to the first principal that received it (the Session 2 DPoP call, in this order), so for
# CODER the header is removed and the server log says why. Restart the server and repeat the call to see it.

# A denied call (policy: private repo). The upstream never sees it.
curl -s -X POST $ATTENUO_SERVER/mcp/github \
  -H "Authorization: Bearer $CODER" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"alice/private-salaries","path":"x"}}}'
# {"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"attenuo: denied: policy_deny","data":{"reason":"policy_deny","decision_id":"..."}}}

# List filtering: the fake upstream has three tools, the coder's token sees one.
curl -s -X POST $ATTENUO_SERVER/mcp/github -H "Authorization: Bearer $CODER" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}'
# ... "tools":[{"name":"read_file", ...}]  and nothing else

# No token: 401 and a JSON-RPC -32001
curl -s -o /dev/null -w '%{http_code}\n' -X POST $ATTENUO_SERVER/mcp/github -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Session 6: server routes, exchange, leases, AuthZEN and admin (`attenuo-server`)

The wiring crate: it owns no authorization rules, but it owns the order they run in, and most of the security-review findings live here.

Read beside: [ADR-0006: Lease-based in-flight revocation](../decisions/0006-lease-based-in-flight-revocation.md). Keep [HTTP endpoints](../reference/http-api.md) open as a lookup, and read the rest of [Server request pipeline](../design/server.md) (the decision pipeline, blocking I/O, streaming recheck).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-server/src/main.rs`, `lib.rs` | Startup, signal handling, and `router`: every route in one place. | 395 |
| 2 | `crates/attenuo-server/src/state.rs` | `AppState::from_config`: builds the issuer, verifier, policy engine, stores, replay caches. `blocking` and `initial_lease_expiry`. | 625 |
| 3 | `crates/attenuo-server/src/authz.rs` | `Pipeline::decide` (leases, policy, audit), `ServerAuthorizer` (the proxy's `Authorizer`), the verified-token cache. The most important file in the crate. | 810 |
| 4 | `crates/attenuo-server/src/routes/token.rs` | `exchange` / `exchange_sync`: the token exchange table in section 1, line by line. | 540 |
| 5 | `crates/attenuo-server/src/routes/renew.rs`, `dev_root.rs` | Lease renewal; the development root mint. | 420 |
| 6 | `crates/attenuo-server/src/routes/admin.rs` | `require_admin`, revoke, lease status, audit range/verify/checkpoint/export, policy reload. | 875 |
| 7 | `crates/attenuo-server/src/routes/authzen.rs` | AuthZEN single and batch evaluation; `check_issued` rejects a chain the server never issued. | 395 |
| 8 | `crates/attenuo-server/src/dpop.rs`, `replay.rs`, `clientauth.rs`, `actor.rs` | DPoP policy (`bind_new`, `bind_exchange`), single-use caches, client-secret check, actor tokens (SPIFFE). | 2040 |
| 9 | `crates/attenuo-server/src/idp/` (`mod.rs`, `intake.rs`, `jwks.rs`, `claims.rs`) | Hop 0 from a real identity provider: ID tokens and ID-JAG, JWKS cache. Read last, or skip until you wire an IdP. | 1700 |
| 10 | `crates/attenuo-server/src/config.rs`, `metrics.rs`, `routes/ops.rs`, `routes/wellknown.rs` | Config schema with validation (read with `config/example.toml`), Prometheus metrics, `/readyz`, JWKS. | 2430 |

Check you understood:

1. A lease expires because the agent stopped renewing, but its JWT has ten minutes left. What does the next call get, and which function decides?
2. Why does the exchange record the replay key "this parent delegated to this actor" only after the new token is built, and together with the actor token's key?
3. What does `ServerAuthorizer` do on a verified-token cache hit, and why can it not skip `validate_at`?

Run it:

```sh
cargo test -p attenuo-server --test e2e revoking_root_lease_cascades_to_child
cargo test -p attenuo-server --test e2e unrenewed_lease_denies_even_though_the_jwt_is_valid
cargo test -p attenuo-server --test e2e exchanging_the_same_parent_for_the_same_actor_twice_is_refused
cargo test -p attenuo-server --test e2e authzen_matches_proxy_decisions
cargo test -p attenuo-server --test dpop
cargo test -p attenuo-server --lib authz::                 # Pipeline and the token cache

# Leases over HTTP. A fresh root and its lease (one --json call, so both come from the same mint), a child
# under it, then revoke the root and watch the cascade:
ROOTJ=$(attenuo --json token root --subject alice --agent assistant --cap 'github:*')
R=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
L=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lease"])')
printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print lease   # the child's lease
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" $ATTENUO_SERVER/admin/leases/$L
# {"lease_id":"...","active":true,"parent":null,"expires_at":"...","revoked_at":null,"revoke_reason":null}
attenuo lease revoke $L --reason "trying it"      # revoked 2 lease(s): the root and its child
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" $ATTENUO_SERVER/admin/leases/$L     # active false

# The same-parent-same-actor rule:
R2=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
for i in 1 2; do printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R2" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token | wc -c; done
# the second prints: error: ... 400 Bad Request: invalid_grant: this credential was already used; present a fresh one

curl -s $ATTENUO_SERVER/readyz                              # {"ready":true,"checks":{"audit":"ok","leases":"ok"}}
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" "$ATTENUO_SERVER/admin/audit?from=1&limit=2"
attenuo policy reload                                       # re-reads the policy file without a restart
```

### Session 7: the CLI and the demo (`attenuo-cli`, `examples/github-leak-demo`)

The CLI is a thin client; the demo is the project's one-page argument. Read the demo first so you know what the commands are for.

Read beside: [CLI commands](../reference/cli.md), and the demo's own README, `examples/github-leak-demo/README.md`.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `examples/github-leak-demo/run.sh` | The scenario in nine steps, with checks on every exit status. | 150 |
| 2 | `examples/github-leak-demo/config.toml`, `policy.cedar`, `policy_test.yaml` | The server config, policy and policy tests it uses. | 190 |
| 3 | `crates/attenuo-cli/src/cli.rs` | The whole command surface in clap definitions. | 1295 |
| 4 | `crates/attenuo-cli/src/main.rs` | What each command does with the HTTP API. | 1075 |
| 5 | `crates/attenuo-cli/src/client.rs`, `secrets.rs` | The HTTP client; how secrets are read (env, file, stdin, flag with a warning). | 700 |
| 6 | `crates/attenuo-cli/src/jwt.rs`, `render.rs`, `dpop_key.rs`, `policy_cmd.rs` | Local token decoding and display, DPoP key files, `policy test` and `policy lint`. | 1465 |

Check you understood:

1. Which commands work with no server running?
2. The CLI never asks for a client secret as an argument by default. Where does it look first, and why?
3. In the demo, step 6 is denied with `capability_denied` and step 5 with `policy_deny`. What is the difference in what each tells you about the token?

Run it:

```sh
bash examples/github-leak-demo/run.sh            # needs no running server; starts its own on free ports
ATTENUO_BIN_DIR=$BIN bash examples/github-leak-demo/run.sh     # reuse your build

env -u ATTENUO_SERVER -u ATTENUO_ADMIN_TOKEN cargo test -p attenuo-cli   # see section 0 for the env -u
attenuo --help; attenuo token --help
attenuo token inspect "$CODER"                  # offline decode
attenuo tools --server github --token "$CODER" # tools/list through the proxy (--server here is the upstream)
attenuo --json lease show "$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print lease)"
```

Expect the demo to end with `1 tools/call reached upstream. The three denied calls never left attenuo.` and `audit chain OK: 9 entries verified` (8 before output labelling; the ninth is the allowed call's `tool_result` record).

### Session 8: the SDKs and the refresh helper (`sdk/python`, `sdk/typescript`)

How an agent program uses all of this from code. The two SDKs mirror each other; read Python and skim TypeScript for the differences.

Read beside: [Integrating MCP clients](../guides/integrating-mcp-clients.md), then the `sdk/python/README.md` section "Keeping a token alive". Its section "Streaming a call" is the lookup for `call_tool_stream`, which session 15 reads.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `sdk/python/src/attenuo/capability.py` | `Capability`, `Equals`, `OneOf`, `Prefix`; serializes to the server's JSON. | 150 |
| 2 | `sdk/python/src/attenuo/_wire.py` | Request building and response parsing with no I/O, shared by the sync and async clients. | 365 |
| 3 | `sdk/python/src/attenuo/client.py`, `_sse.py` | `Client` / `AsyncClient`: `exchange`, `renew`, `call_tool`, `call_tool_stream` (a streamed answer as an iterator of `StreamEvent`, since #115; session 15), `list_tools`, `authzen_evaluate`, `inspect`. | 1000 |
| 4 | `sdk/python/src/attenuo/errors.py`, `token.py` | `Denied` (trusted only if the decision id is in the response header), `Token` and local decoding. | 360 |
| 5 | `sdk/python/src/attenuo/dpop.py`, `mcp.py` | `DpopKey` (including `sign_off`), `TokenAuth` for `httpx`. | 385 |
| 6 | `sdk/python/src/attenuo/refresh.py` | `TokenRefresher` and `AsyncTokenRefresher`: renew at a third of the lease interval, re-exchange before `exp`, back off, stop on a revoked lease. | 410 |
| 7 | `sdk/python/src/attenuo/admin.py` | `AdminClient`: revoke, lease status, audit, verify, dev root mint. | 935 |
| 8 | `sdk/typescript/src/` (`client.ts`, `refresh.ts`, `dpop.ts`, `wire.ts`, `sse.ts`) | The same, with WebCrypto and `fetch`; `callToolStream` is the streamed call. | 1800 |
| 9 | `examples/python-agent/agent.py` | A planner delegates to a coder with a run limit, the coder meets an injected instruction and the limit, the planner's own `create_issue` waits for an approval, the planner revokes (`mcp_client_example.py` beside it shows the raw client). | 165 |

Check you understood:

1. `ob.call_tool` raises `Denied` only for some `-32003` errors. Which, and why does the SDK care?
2. Why does the refresher's `exchange` function have to bring a fresh parent token every time?
3. `inspect(verify=True)` does not check `ou_sig`. Who does, and when?

Run it:

```sh
python3 -m venv .venv && . .venv/bin/activate && pip install -e 'sdk/python[dev]'   # httpx, rfc8785; [dev] adds pytest, pytest-asyncio, cryptography
PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests -q       # 150+ tests, no server needed (integration ones skip)
# PYTHONPATH alone is enough only once those dependencies are installed; the system Python lacks rfc8785.

PYTHONPATH=sdk/python/src CODER_SECRET=demo-coder-secret python3 - <<'PY'
import os
from attenuo import AdminClient, Capability, Client, Denied, Prefix

URL = "http://127.0.0.1:18080"
admin = AdminClient(URL, "demo-admin-token")
root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
with Client(URL) as ob:
    coder = ob.exchange(root, "coder",
                        [Capability("github", "read_file", repo=Prefix("alice/public-"))],
                        ttl_seconds=600, client_secret=os.environ["CODER_SECRET"])
    print(coder.chain.agents, coder.lease)                    # ('assistant', 'coder') <lease id>
    print(ob.call_tool(coder, "github", "read_file",
                       {"repo": "alice/public-docs", "path": "README.md"}).decision_id)
    try:
        ob.call_tool(coder, "github", "create_issue", {"repo": "alice/public-docs", "title": "x"})
    except Denied as d:
        print("denied:", d.reason, d.decision_id)             # capability_denied <audit record id>
    print(ob.renew(coder))
admin.revoke_lease(root.lease, "done")
print(admin.audit_verify())                                    # VerifyReport(ok=True, entries=..., first_bad_seq=None)
PY

PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests/test_refresh.py -q    # the refresher's schedule, with a fake clock
(cd sdk/typescript && npm ci && npm run build)   # the cross-language tests below run sdk/typescript/dist with node; a stale dist fails two of them
ATTENUO_INTEGRATION=1 ATTENUO_BIN_DIR=$BIN PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests/test_integration.py -q   # builds no Rust; starts its own server
```

The TypeScript SDK: `cd sdk/typescript && npm ci && npm test` (158 passed, 7 skipped without `ATTENUO_INTEGRATION`; main @ de3cf75, 2026-10-24).

### Session 9: output labelling and approvals (ADR-0009)

The attacks the injection suite still gets through use a tool and arguments the task itself needs, so neither the token nor a static policy can tell them from the real thing; what gives them away is that the run read a tool result first. This session follows an upstream answer into the audit log and the run's taint, then a later destructive call from `-32008` through an approval to the one retry that approval allows.

Read beside: [ADR-0009: Output labelling](../decisions/0009-output-labelling.md), then sections 3.6 to 3.8 of the [output-labelling design](../design/output-labelling.md). What was built is in `CHANGELOG.md` under [0.1.0]. Keep [Asking for approval after untrusted output](../guides/writing-policies.md#asking-for-approval-after-untrusted-output) and the Approvals part of [HTTP endpoints](../reference/http-api.md#approvals) open as lookups.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `config/policies/output-labels.cedar`, `output-labels_test.yaml` | The new Cedar attributes listed in the header comment, the two `@obligation("approval")` forbids, and fifteen policy tests that show every rule from the policy author's side. Read these first. | 130 |
| 2 | `crates/attenuo-policy/src/catalog.rs` | `ToolAttrs` gains `destructive` (default `!readonly`, read through `is_destructive`) and `output` (`untrusted` by default, or `trusted`); `AnnotationImport` lets MCP hints narrow a tool, never widen it. | 310 |
| 3 | `crates/attenuo-policy/src/lib.rs` (crate comment, `authorize_labelled`, `REASON_APPROVAL_REQUIRED`), `request.rs` (`context.session`, `context.approval`) | `approval_required` only when every forbid that applied carries the obligation and a permit would otherwise allow the call. Any other forbid still gives `policy_deny`. | 2040 |
| 4 | `crates/attenuo-core/src/call.rs` (`call_hash`), `decision.rs` (`RecordKind::ToolResult`, `ResultInfo`, `RecordLabels`, `chain_id_of`) | The hash an approval is bound to (SHA-256 of the RFC 8785 JSON of server, tool and arguments), the new record kinds and fields, and the run key: the first hop's lease. | 460 |
| 5 | `crates/attenuo-proxy/src/label.rs` | `Labeller`: finds the answers to allowed calls by JSON-RPC id in a JSON body, a batch or SSE events, calls `Authorizer::record_result` before relaying, and replaces an answer it could not record with `-32003` `label_error`. `AwaitedResults`: allowed calls remembered for an answer on the `GET` listen stream, with its bounds. | 655 |
| 6 | `crates/attenuo-proxy/src/jsonrpc.rs` (`approval_required_response`), `proxy.rs` (`screen_message`, where an `approval_required` decision becomes that response, and `handle_passthrough` for the listen stream) | Where `-32008` is written and where the listen stream gets its labeller. | 1840 |
| 7 | `crates/attenuo-server/src/authz.rs` | The crate comment's six steps, then `run_labels`, `take_approval`, `give_back`, `request_approval` and `Pipeline::record_result`. The two places where this session changes section 1's table. | 1220 |
| 8 | `crates/attenuo-audit/src/approval.rs`, `lease.rs` (`add_label`, `labels`, `create_approval`, `take_approval`, `restore_approval`), the `run_labels` and `approvals` tables in `sqlite.rs` | The store. Approvals live beside the leases so that every grant and every use checks the lease in the same transaction. | 830 |
| 9 | `crates/attenuo-server/src/routes/approvals.rs` | `POST /approvals/{id}` with the originating user's ID token (checked as at hop 0, used once), the admin routes, and the order "store first, then the `approval_grant` record, delete on failure". | 395 |
| 10 | `crates/attenuo-cli/src/main.rs` (`Command::Approval`, and `call`'s exit status 2), `crates/attenuo-server/ui/view-approvals.js` | The operator's side: `attenuo approval` with `list`, `show`, `grant` and `decline`, and the console page `#/approvals`. | 1280 |
| 11 | `sdk/python/src/attenuo/errors.py` (`ApprovalRequired`, `ApprovalNotGranted`), `client.py` (`get_approval`, `wait_for_approval`, `call_tool_with_approval`), `admin.py` (`approvals`, `grant_approval`, `decline_approval`); `callToolWithApproval` in `sdk/typescript/src/client.ts` | The agent's side, and the operator's calls in the SDK, the same ones the injection-suite runner makes with raw HTTP. | 1735 |

Check you understood:

1. The coder sub-agent reads a file, and then the assistant, the coder's parent at hop 0, calls `create_issue`. Is the assistant's call gated? What is the key of the taint, and where is it computed?
2. A run is tainted and, besides the approval forbid, a plain `forbid` also matches the call. What does the agent get, and would an approval help?
3. The user grants the approval for `create_issue {"title": "one"}`. The agent then sends that call with title `"two"`, then with `"one"` twice. What does each of the three get, and which function decides?
4. The retry's own decision record cannot be appended. What happens to the approval, and why is that the right order?
5. The upstream has already run an allowed call, and the `tool_result` append fails. What does the agent see, and why not relay the result anyway?
6. Why can the approval not travel through the agent (MCP elicitation, say), and why does `POST /approvals/{id}` refuse the ID token the agent redeemed at hop 0?

Run it:

```sh
cargo test -p attenuo-policy --test labels                # the obligation rule, destructive defaults, the shipped example passing its tests
cargo test -p attenuo-proxy --test labelling              # results recorded before relay, -32008, the listen stream
cargo test -p attenuo-server --test labels                # taint end to end: trusted output, one run only, label_error
cargo test -p attenuo-server --test approvals             # single use, different call hash, revocation, ID token rules
attenuo policy test config/policies/output-labels_test.yaml   # 15 passed, 0 failed

# A second server on port 18081 beside the section 0 one, with the demo policy plus the approval
# forbid. The demo policy already permits create_issue in public repos and asks for an approval
# on every one (ask_before_create_issue); the sed drops that forbid so the taint rule decides
# alone. It uses the same fake upstream.
{ sed '/@id("ask_before_create_issue")/,/};/d' examples/github-leak-demo/policy.cedar; cat; } > /tmp/ob-labels.cedar <<'CEDAR'
@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid (principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
CEDAR
sed -e 's/18080/18081/g' -e 's#examples/github-leak-demo/policy.cedar#/tmp/ob-labels.cedar#' \
  examples/github-leak-demo/config.toml > /tmp/ob-labels.toml
attenuo policy lint /tmp/ob-labels.cedar --config /tmp/ob-labels.toml    # 5 policies, 0 error(s), 0 warning(s)
RUST_LOG=warn attenuo-server --config /tmp/ob-labels.toml > /tmp/ob-labels.log 2>&1 & LABELS_PID=$!
export ATTENUO_SERVER=http://127.0.0.1:18081
sleep 2 && curl -s $ATTENUO_SERVER/healthz

# A fresh run reads, then tries to open an issue. Every result is untrusted unless the catalog says
# output = "trusted", so the read taints the run, and create_issue is destructive (not readonly).
export ATTENUO_TOKEN=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md   # ALLOWED
attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=one
# APPROVAL REQUIRED, then the approval id, its expiry (two minutes), the call hash and the decision id; exit status 2.
# Repeat it: the same approval id comes back, with a new decision id.

# Decide as the operator within the two minutes (the user would use POST /approvals/{id} with an ID token):
attenuo approval list         # <id>  pending  github/create_issue  run <root lease>  expires ...
ID=$(attenuo --json approval list --state pending | python3 -c 'import json,sys; print(json.load(sys.stdin)["approvals"][0]["approval_id"])')
attenuo approval show $ID     # the exact arguments, the call hash, and "labels  github/read_file (audit seq 4)" on a fresh server
attenuo approval grant $ID    # state granted, decided ... by urn:attenuo:admin (operator, admin_token)

attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=two   # APPROVAL REQUIRED, a new id: another call hash
attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=one   # ALLOWED: the identical retry
attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=one   # APPROVAL REQUIRED again: the grant was used up
attenuo approval show $ID     # state consumed, "used by  decision <id of the allowed retry>"

# The same gated call as raw JSON-RPC: -32008, with the decision id in the header as for -32003.
curl -s -D - -X POST $ATTENUO_SERVER/mcp/github \
  -H "Authorization: Bearer $ATTENUO_TOKEN" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_issue","arguments":{"repo":"alice/public-docs","title":"raw"}}}'
# x-attenuo-decision-id: <uuid>
# {"jsonrpc":"2.0","id":7,"error":{"code":-32008,"message":"attenuo: approval required: ask the user to approve <id> (POST /approvals/<id>)",
#  "data":{"reason":"approval_required","decision_id":"<uuid>","call_hash":"...","approval_id":"<id>","expires_at":"..."}}}

# What the log holds. Decisions print ALLOW or DENY; tool_result, approval_request and approval_grant print their
# kind instead, e.g. "#4  <time>  tool_result  github/read_file  assistant for alice  decision=<id>  label=untrusted size=149  id=<id>".
attenuo audit tail -n 12
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" "$ATTENUO_SERVER/admin/audit?kind=tool_result&limit=1"
# "kind":"tool_result", "decision_id" of the read, "result":{"digest":"...","size":149,"label":"untrusted","fingerprints":0}; no content
curl -s -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" "$ATTENUO_SERVER/admin/audit?kind=decision&reason=policy_allow&order=desc&limit=1"
# the allowed retry: "labels":{"tainted_by":[4]} (the seq of the read's tool_result),"approval":{"id":"<id>","by":"operator"}
attenuo audit verify          # audit chain OK

# Question 1, answered: a sub-agent's read taints its parent's run.
R=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
C=$(printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)
ATTENUO_TOKEN="$C" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=x > /dev/null
ATTENUO_TOKEN="$R" attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=x   # APPROVAL REQUIRED

# The SDK's view. The operator grants inside on_approval here; a real agent shows the user the id.
PYTHONPATH=sdk/python/src python3 - <<'PY'
from attenuo import AdminClient, ApprovalRequired, Client

URL = "http://127.0.0.1:18081"
admin = AdminClient(URL, "demo-admin-token")
root = admin.mint_root_dev("alice", "https://idp.example", "assistant", ["github:*"])
with Client(URL) as ob:
    ob.call_tool(root, "github", "read_file", {"repo": "alice/public-docs", "path": "a"})
    args = {"repo": "alice/public-docs", "title": "from python"}
    try:
        ob.call_tool(root, "github", "create_issue", args)
    except ApprovalRequired as e:
        print("gated:", e.reason, e.approval_id is not None)       # gated: approval_required True
    done = ob.call_tool_with_approval(root, "github", "create_issue", args,
                                      on_approval=lambda e: admin.grant_approval(e.approval_id),
                                      interval=0.2)
    print("allowed after approval:", done.decision_id is not None)  # allowed after approval: True
PY

unset ATTENUO_TOKEN; export ATTENUO_SERVER=http://127.0.0.1:18080     # back to the section 0 server
kill $LABELS_PID                                                      # stop the second server
```

The user's own route, `POST /approvals/{id}` with an OIDC ID token, needs a configured `[[idps]]` entry and a real or test identity provider, so it is not in the block; `only_the_originating_users_fresh_id_token_approves` in `crates/attenuo-server/tests/approvals.rs` runs it against a test issuer. An answer on the `GET` listen stream cannot be produced with `fake_mcp`, which always answers in the `POST` body; the three `listen_stream` tests in `crates/attenuo-proxy/tests/labelling.rs` use an upstream that answers `202` and sends the result on its stream.

### Session 10: evaluation suite, benchmarks and fuzzing

The evidence that the design works and what it costs. Read this last; it makes the most sense once you know what the stages are.

Read beside: [Injection suite: results](../evaluation/injection-suite.md). Optional depth: [Evaluation plan](../research/evaluation-plan.md), [Performance](../design/performance.md), [Fuzzing](../design/fuzzing.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `evaluation/injection-suite/README.md` | What a case is, the five base arms (no enforcement, scope only, scope plus constraints, policy only, full attenuo), the arms added since (output labels, argument-level labels, the frozen run-limit rule, soft run usage, URL hosts, recipients, per-task limits), the dev and test splits, and the sections from "The labels arm" to "The per-task arm". | 210 |
| 2 | `evaluation/injection-suite/cases/dev/`, `cases/test/`, `policies/` | The case files and the frozen suite policies (hashes in `cases/test/POLICY_HASHES.json`). | data |
| 3 | `evaluation/injection-suite/label_rules.py` | The labelling oracle: derives each call's expected outcome from the case structure, independent of hand labels. | |
| 4 | `evaluation/injection-suite/harness.py`, `run.py` | Starts real servers, replays every call through each arm, writes results with SHA-256 of every input. | |
| 4a | `evaluation/injection-suite/policies/labels.cedar`; in `harness.py`, `ARMS`, the labels-arm probe, `scripted_approver`, `_settle` and `AFTER_APPROVAL` | The `attenuo_labels` arm: the two approval forbids (hashed under `added_later`), the probe that skips the arm on a server that never answers `-32008`, the scripted approver (grants a call labelled benign, declines one labelled attack, as the operator through `POST /admin/approvals/{id}`) and the one identical retry after a grant, recorded as `after_approval`. | |
| 4b | `evaluation/injection-suite/results/2026-10-24-labels-v2.md`, with [the summary](../evaluation/injection-suite.md#second-run-with-retry-after-approval-2026-10-24) | How to read a labels run: in the arms table the attack column counts calls allowed without an approval; the "Approvals in `attenuo_labels`" tables say what became of each gated call; the approve-all bound is the attack rate if every request were granted (10/60 on the original dev cases, the `attenuo` arm's number). | 230 |
| 4c | `evaluation/injection-suite/policies/limits-rule.json`, `task-limits-dev.md`; `results/2026-10-24-task-limits-v1.md`, with [run limits, section 7](../design/run-limits.md#7-measured) | The limits arms: the frozen `calls: 1` rule, the host and recipient files, and the per-task figures in 47 dev grants. The "Run limits in ..." tables list every call a limit refused, and "Multi-call cases" splits the dev cases into the original 46, the 11 multi-call and the 6 browsing ones. Read section 7 of the design for what the arms do and do not support. | data |
| 5 | `crates/attenuo-bench/src/lib.rs`, `hotpath.rs` | End-to-end load generator: proxy versus direct, by chain depth and concurrency. `attenuo-bench hot-path` measures what output labels and each limit kind add to one call (session 11). | 2800 |
| 6 | `crates/attenuo-core/benches/attenuation.rs`, `crates/attenuo-policy/benches/*.rs`, `crates/attenuo-server/benches/decide.rs` | criterion micro-benchmarks of the hot path; `decide.rs` also times the budget read, each kind of charge, the run-usage write and `record_result`. | 840 |
| 7 | `fuzz/fuzz_targets/` and `fuzz/README.md` | Nineteen libFuzzer targets (twelve from the first campaigns, five from round 2 over run limits, budgets, approval tokens, the usage walker and the server routes, two from round 3 (#130) over the pass 7 SSE parsing, reached through the `fuzzing` feature's `#[doc(hidden)] pub mod fuzzing` wrappers); they assert properties as well as absence of panics. | 19 files |

Check you understood:

1. Why are the suite's policies frozen before the test split was written, and what does `run.py --split test` do if one of them changed?
2. The micro-benchmarks do not include token verification, the lease lookup, the audit append or the network. Why are they still useful, and which benchmark does include them?
3. Pick one fuzz target and say which property it asserts beyond "does not crash".
4. The labels arm allows 1 of 77 dev attack calls without an approval and 0 attack calls were approved. Why is the second number true by construction, and which number in the report tells you what a careless user would let through?
5. The per-task limits arm allows 7 of 77 dev attack calls against 15 for `attenuo`, and refuses 1 benign call by a limit. What does that measure, and what does it not (who wrote the figures, and when)?

Run it:

```sh
python3 evaluation/injection-suite/label_rules.py dev test     # oracle agreement; kappa 1.0, no disagreements
python3 -m pytest evaluation/injection-suite -q                # 47 passed, 12 skipped without ATTENUO_INTEGRATION=1
python3 -m pytest evaluation/injection-suite/test_suite.py -q -k 'approv or labels_arm'   # the approver and report logic: 6 passed, 2 skipped
python3 -m pytest evaluation/injection-suite/test_suite.py -q -k limit   # the limits arms' rules and report: 12 passed, 2 skipped

# The full run starts servers from prebuilt binaries for fifteen arms and takes a few minutes.
# --out keeps the results out of the committed results/ directory:
ATTENUO_BIN_DIR=$BIN \
  python3 evaluation/injection-suite/run.py --split all --out /tmp/ob-inj --tag mine
ls /tmp/ob-inj          # <date>-mine.json and <date>-mine.md; compare with results/2026-10-24-task-limits-v1.md (fifteen arms)

# What became of every gated call in the labels arm, by hand label:
python3 - /tmp/ob-inj/$(date -u +%F)-mine.json <<'PY'
import collections, json, sys
d = json.load(open(sys.argv[1]))
for split in ("dev", "test"):
    gated = [c for c in d["splits"][split]["calls"] if c["outcome"] == "gated" and c["arm"] == "attenuo_labels"]
    print(split, sorted(collections.Counter((c["role"], c["after_approval"]) for c in gated).items()))
PY
# dev [(('attack', 'declined'), 14), (('benign', 'allowed'), 57)]
# test [(('attack', 'declined'), 6), (('benign', 'allowed'), 2)]
grep -m1 -A2 '^| Benign gated' /tmp/ob-inj/$(date -u +%F)-mine.md   # 57/130 (44%) | 57/57 ... | 71 approval requests (the dev labels arm)
grep '^| `attenuo_task_limits` | ' /tmp/ob-inj/$(date -u +%F)-mine.md   # old (46) 6/60, multi-call (11) 0/11, browsing (6) 1/6 attack allowed; 1/22 browsing benign denied

env -u ATTENUO_SERVER -u ATTENUO_ADMIN_TOKEN cargo test -p attenuo-bench   # a short smoke run of the load generator (env -u: section 0)
cargo bench -p attenuo-server --bench decide                  # the decision path by stage (optional, slow)
OUT_DIR=/tmp/ob-bench DURATION=10 WARMUP=2 scripts/bench-e2e.sh   # release build plus the end-to-end matrix; the full run is about 9 minutes, and OUT_DIR keeps it out of docs/design/bench

# Fuzzing needs nightly and cargo-fuzz (see fuzz/README.md):
cargo +nightly fuzz list
cargo +nightly fuzz run dpop_proof -- -max_total_time=60
```

The runner starts its own servers, so it ignores any `ATTENUO_*` variables from section 0 (other than `ATTENUO_BIN_DIR`) and prints one warning. The `cargo +nightly fuzz` commands, the `bench-e2e.sh` run and the Rust benches were not run for this page; the Python oracle, the pytest runs, `run.py --out` and the gated-call count were (with debug binaries from `main` @ a02bc83; the run reproduced the published `task-limits-v1` tables). `run.py` runs the labels, limits, usage, host, recipient and per-task arms only on a server that can; on an older binary it prints why it skipped an arm and records it under `skipped_arms`.

### Session 11: run limits and budgets (ADR-0010)

Session 9 turns the suite's remaining attacks into approval requests. Some of them are a second payment to the right payee, a larger amount under the policy's per-call cap, or a fetch from one more site: nothing in one call gives them away, but the count does. This session follows a `limits` block from the token through the charge transaction to the operator's refund, then run usage, the policy-side soft limit that needs no figure in any token.

Read beside: [ADR-0010: Run limits](../decisions/0010-run-limits.md), then sections 3.1 to 3.5 and 3.7 of the [run-limits design](../design/run-limits.md) and its "As built" parts of section 6. Keep [Run limits](../guides/writing-policies.md#run-limits) and [Limits over run usage](../guides/writing-policies.md#limits-over-run-usage) in the policy guide, and `lease tree` and `budget refund` in the [CLI reference](../reference/cli.md), open as lookups.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `config/policies/run-limits.cedar`, `run-usage.cedar` and their `_test.yaml` files | `context.budget` and `context.usage` as the header comments list them, a soft limit (`@obligation("approval")` forbids such as `ask_on_repeat_payment` and `ask_on_a_new_site`) and a hard one (`run_spend_cap_2000`). Read these first: they show what a policy can and cannot do with a limit. | 330 |
| 2 | `crates/attenuo-core/src/limits.rs` (crate comment, `Limits`, `ArgLimit`, `Derive::Host`, `Limits::narrows`, `Limits::clamp_to`, `Limits::validate`, `Charge`, `charges_for`, `usage_charges`) | The four kinds and the shape in the token; narrowing (a child keeps every parent limit with a `max` no larger, and `calls: m` also satisfies a parent's `calls_per` or `distinct` of `m` or more); one `Charge` per limit of every matching capability in every hop; the run-usage charges, keyed by `chain_id` and tool. `Capability::covers` in `capability.rs` calls `narrows`. | 670 |
| 3 | `crates/attenuo-server/src/routes/token.rs` (`clamp_to_remaining`), `routes/mod.rs` (where `record_hop_limits` is called) | At exchange the child's figures are lowered to what the parent has left, read from the counters; the server keeps a display copy of each hop's limits for the console and `lease tree`. | 510 |
| 4 | `crates/attenuo-audit/src/budget.rs` (crate comment, `ChargeOutcome`, `CounterKey`, `plan`, `summarize`), `lease.rs` (the `LeaseStore` methods `budget_used`, `charge`, `charge_sync_deferred`, `refund`, `record_hop_limits`, `hop_limits`, `budget_summary`) | One counter per (hop lease, capability, kind, argument, value), values kept as a keyed hash. `plan` decides a whole call's charges, all or nothing. A `distinct` limit keeps one `distinct_value` row per value and a count row; a value already seen writes nothing. Every charge is logged under its decision id, so a refund gives back exactly that, once. | 1280 |
| 5 | `crates/attenuo-audit/src/sqlite.rs` (the `budget_counters` and `hop_limits` tables, `charge_in`, `refund_in`, `charge_with`, `WriteGate`) | The SQLite side: an `IMMEDIATE` transaction per charge, a `sum` charge whose sync can ride the decision append, and the in-process write gate that serializes the lease store and the audit log on one file. Large; read only these parts. | 3440 |
| 6 | `crates/attenuo-server/src/authz.rs` (crate comment steps 2, 4, 5 and 6, then `budget_view`, `read_counters`, `distinct_step`, `usage_inputs`, `refund_unrecorded`, `LimitHit`) | Where the pipeline reads the counters before policy, denies `budget_exhausted` before Cedar, charges after an allowed decision, turns a lost race into `budget_exhausted`, and refunds when the audit append fails. Usage is read only when `tracks_usage` says something can read it. | 1700 |
| 7 | `crates/attenuo-policy/src/lib.rs` (crate comment on `budget`, `BudgetContext`, the refusal check in `authorize_labelled`, `tracks_usage`), `request.rs` (`context.budget`, `context.usage`), `usage.rs` (`policies_read_usage`, `TrackUsage`) | What Cedar sees, and the decision, at every policy load, whether usage is kept at all. | 1800 |
| 8 | `crates/attenuo-server/src/routes/admin.rs` (`refund_budget`, `lease_tree`), `crates/attenuo-cli/src/main.rs` (`budget_refund`, `Command::Lease(LeaseCmd::Tree)`), `render.rs` (`fmt_budget`, `render_lease_tree`) | The operator's side: `POST /admin/budgets/refund` (audited as `admin.budget.refund`, exit 2 when nothing was charged and 3 when already refunded) and the budget lines under each lease in `lease tree`. | 2900 |
| 9 | `crates/attenuo-server/ui/view-lease.js` (`limitsPanel`), `view-entry.js` (`budgetPanel`) | The console: each hop's limits and what is left on `#/lease/{id}`, and a decision's charges and the usage the policy saw on its entry page. A refund from the console needs `[admin_ui] allow_write`. | 540 |
| 10 | `sdk/python/src/attenuo/capability.py` (`ArgLimit`, `Limits`, `Capability.with_limits`), `sdk/typescript/src/capability.ts` (`Limits`, `argLimit`, `withLimits`, `checkLimits`) | Typed limits in the SDKs. A kind or derivation the SDK does not know is refused, not passed through. | 610 |
| 11 | `crates/attenuo-bench/src/hotpath.rs` (crate comment, `HotConfig`), `crates/attenuo-server/benches/decide.rs` (crate comment, the `budget_read_*`, `charge_*`, `decide_limited_*`, `decide_destructive_*` and `charges_for/*` benches) | What a limit costs: `attenuo-bench hot-path` runs one server per configuration (`baseline`, `labels`, `limits`, `limits_calls`, `both`, `usage`, and new and repeated values for `calls_per`, `distinct` and host `distinct`); the criterion bench splits the read and the charge. Results are in [performance](../design/performance.md#output-labelling-and-run-limits-on-the-hot-path-2026-10-24). | 1740 |

Check you understood:

1. A root token carries `calls: 3` and has used 2. Its holder exchanges it for a coder with `calls: 5`. What does the coder's token say, which two functions decide it, and what happens to the root's next call after the coder makes one?
2. A call matches a limited capability in hop 0 and another in hop 1, and the hop 1 counter is full. Is the hop 0 counter charged? Where is that decided?
3. Two sub-agents under one parent with `calls: 1` call at the same moment. Both pass the read before policy. Why does only one go through, and what does the other one get?
4. The upstream fails after an allowed, charged call. Is the charge given back by itself? Who can give it back, how many times, and what does that leave in the audit log?
5. A call would take a limit past its `max`, and a policy would ask for an approval for it. What does the agent get, and could any approval pass it?
6. You delete the only policy that reads `context.usage` and reload. What changes on the write path of a destructive call, and why can `[policy] track_usage` not be set to `false`?

Run it:

```sh
cargo test -p attenuo-core --lib limits::                 # narrowing, clamping, charges_for, derived hosts, usage charges: 15 passed
cargo test -p attenuo-audit --test budgets                # all or nothing, distinct value rows, refund once, siblings, both stores: 10 passed
cargo test -p attenuo-server --test run_limits            # every ancestor charged, clamp at exchange, refund, AuthZEN, URL hosts: 9 passed
cargo test -p attenuo-server --test run_usage             # soft and hard limits over context.usage, refunded with the decision: 6 passed
cargo test -p attenuo-policy --lib usage::                # which policies count as reading context.usage: 2 passed
attenuo policy test config/policies/run-limits_test.yaml  # 7 passed, 0 failed
attenuo policy test config/policies/run-usage_test.yaml   # 14 passed, 0 failed

# A root with two limits on read_file: at most three calls, and at most two different repos.
ROOTJ=$(attenuo --json token root --subject alice --agent assistant \
  --cap '{"server":"github","tool":"read_file","limits":{"calls":3,"distinct":{"arg":"repo","max":2}}}')
R=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
L=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lease"])')
export ATTENUO_TOKEN="$R"
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a   # ALLOWED
attenuo call --server github --tool read_file --arg repo=alice/public-blog --arg path=a   # ALLOWED
attenuo --json call --server github --tool read_file --arg repo=alice/public-site --arg path=a
# "code": -32003, "reason": "budget_exhausted", "limit": {"hop": 0, "kind": "distinct", "max": 2, "used": 2, "arg": "repo"}
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=b   # ALLOWED: a repo already seen takes no new slot
attenuo --json call --server github --tool read_file --arg repo=alice/public-docs --arg path=c
# "reason": "budget_exhausted", "limit": {"hop": 0, "kind": "calls", "max": 3, "used": 3}
attenuo lease tree $L
#      limit github/read_file calls 3/3 (0 left)
#      limit github/read_file distinct repo 2/2 (0 left)

# What the last allowed call charged, from its decision record, and a refund of it:
D=$(attenuo --json audit tail -n 20 | python3 -c 'import json,sys
r = [json.loads(l)["record"] for l in sys.stdin if l.strip()]
a = [x for x in r if x["kind"] == "decision" and x["decision"] == "allow"][-1]
print(json.dumps(a["budget"]), file=sys.stderr); print(a["id"])')
# {"charged": [{"hop": 0, "cap": 0, "kind": "calls", "used_after": 3, "max": 3}, {"hop": 0, "cap": 0, "kind": "distinct", "arg": "repo", "used_after": 2, "max": 2}]}
attenuo budget refund $D --reason "upstream timed out"   # refunded  1 limit counter(s): the seen repo wrote no distinct row
attenuo budget refund $D --reason again                  # error: the charge of decision ... was already refunded; exit status 3
attenuo lease tree $L                                    # calls 2/3 (1 left)

# A child that asks for more than its parent has left gets what is left, and its calls are charged to both:
C=$(printf '%s\n' demo-coder-secret | attenuo token exchange --actor coder --client-secret-stdin \
  --cap '{"server":"github","tool":"read_file","limits":{"calls":5}}' --print token)
attenuo token inspect "$C"        # coder: can github:read_file [calls <= 1, distinct repo <= 2]
ATTENUO_TOKEN="$C" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=f   # ALLOWED
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=g   # DENIED  budget_exhausted
attenuo lease tree $L
# │    limit github/read_file calls 3/3 (0 left)          the root
# └─ <lease>  coder ...
#         limit github/read_file calls 1/1 (0 left)
#         limit github/read_file distinct repo 1/2 (1 left)   the coder's own counter saw docs as new
unset ATTENUO_TOKEN
```

The soft limits over `context.usage` need a destructive tool with an `amount` or `destination` in the catalog and a policy that reads them; the demo config has neither, so they are shown by the policy tests above and by `soft_limit_on_usage_asks_and_the_approved_call_is_counted` in `crates/attenuo-server/tests/run_usage.rs`. The race in question 3 is `concurrent_siblings_cannot_overspend_parent`, in both `run_limits.rs` and `crates/attenuo-audit/tests/budgets.rs`, and `crates/attenuo-audit/tests/write_gate.rs` runs it with the audit writer and WAL checkpointer going. The latency of each limit kind is measured with `target/release/attenuo-bench hot-path` (the command is in the `hotpath.rs` crate comment) and `cargo bench -p attenuo-server --bench decide`; neither was run for this page.

### Session 12: refusals you can see, and revocation you can aim

Sessions 5 and 6 left two gaps that an operator meets on the first bad day. Refusals that happened before any decision (a session opened on a revoked lease, a refused exchange or renewal, a stream the re-check cut) were log lines, so the audit log could not show an agent that kept trying. And revocation took one lease id, while an incident report names a person, a run or an MCP session. This session follows what the merges of 2026-10-24 evening (#77 to #91) did about both, then the policy stage's new typed-input check, the policy harness, list filtering on the resumed listen stream and the metrics.

Read beside: [What gets a record](../concepts/audit-log.md#what-gets-a-record) in the audit-log concept, [Revoke by user or chain](../reference/http-api.md#revoke-by-user-or-chain) and [Revoke by session](../reference/http-api.md#revoke-by-session) in the HTTP API reference, then [Revoking during an incident](../guides/deploying.md#revoking-during-an-incident) and [What to monitor](../guides/deploying.md#what-to-monitor) in the deploy guide. Keep [Patterns and `like`](../guides/writing-policies.md#patterns-and-like) and [Unexercised policies](../guides/writing-policies.md#unexercised-policies) in the policy guide open as lookups. The day's log entries from 19:12 to 21:55 UTC in [the 2026-10-24 log](../log/2026-10-24.md) give the reasoning behind each change.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-server/src/authz.rs` (`Pipeline::record_rejection`, near line 1390, and its `Authorizer` impl near line 1805) | The one funnel for every refusal that is not a pipeline decision. It counts the reason in `decisions_total{decision="deny",reason}`, builds an ordinary `DecisionRecord` (kind `decision`, `deny`, the verified chain, a `ToolCall` with a fixed tool name) and appends it. The doc comment lists every caller and every reason set. Read this first: everything in rows 2 to 5 ends here. | 60 |
| 2 | `crates/attenuo-proxy/src/proxy.rs` (`record_lease_refusal` near line 320, `refused_tool_name`, `handle_passthrough`), `jsonrpc.rs` (`PASSTHROUGH_METHODS`) | #80. A request with no per-call decision (`initialize`, `ping`, the four list methods, `resources/unsubscribe`, `logging/setLevel`, notifications, client replies, `GET`, `DELETE`) whose lease check fails becomes one `deny` record per HTTP request. Only `AuthError::LeaseInactive` is recorded; the tool is the allowlisted method or `http.<METHOD>`, never request text. The 401 carries the id in `X-Attenuo-Decision-Id` and `data.decision_id`. | 120 |
| 3 | `crates/attenuo-server/src/routes/token.rs` (crate comment "Audited refusals", `EXCHANGE_REFUSAL_REASONS` near line 198, `EXCHANGE_TOOL`, `refusal_reason`, the `record_rejection` call in `exchange_sync`) | #86. A refused exchange whose subject token and DPoP proof verified is a `deny` of `attenuo/token.exchange` against the parent's chain, with one of thirteen reasons (`exchange_widening`, `exchange_actor_not_permitted`, ..., or the parent's lease reason). Note the order change: an actor mismatch is now decided after the parent verified, so it can be audited. A refused exchange still uses up nothing but its DPoP proof. | 380 |
| 4 | `crates/attenuo-server/src/routes/renew.rs` (crate comment, `RENEW_REFUSAL_REASONS` near line 108, `RENEW_TOOL`, `Failure`) | #87. A refused renewal is a `deny` of `attenuo/lease.renew`, the same tool as a successful one, with a lease reason only: once the token verified, a revoked, expired or unknown lease (its own or an ancestor's) is the only refusal the caller can cause. | 250 |
| 5 | `crates/attenuo-proxy/src/guard.rs` (crate comment, `STREAM_END_TOOL`, `StreamGuard::recording`, `record_end`, `end_event_recorded`), `proxy.rs` (`AppState::stream_guard`) | #90, SR-28. When the re-check cuts a stream because the lease is no longer live or the token expired, the guard writes one `stream.end` record (reason, server, session tag) and puts its id in the final SSE event. `stream_guard` takes the `Authenticated` caller, so only a token that verified when the stream opened can cause a record. A client disconnect or an upstream EOF is a log line, not a record. | 340 |
| 6 | `crates/attenuo-cli/src/cli.rs` (`AuditFilter`, near line 686), `crates/attenuo-server/src/routes/admin.rs` (`entry_filter`), `crates/attenuo-audit/src/export.rs` (`RecordFilter`) | How the refusals are found. `audit tail --tool X --decision deny` filters on the server; since #91 `audit export` takes `--tool` and `--decision` too, and the export header names them, so `audit verify --file` refuses a filtered export as it refuses one filtered by kind. | 200 |
| 7 | `crates/attenuo-audit/src/lease.rs` (`LeaseSelector` near line 334, `SessionBinding`, the trait methods `record_subject`, `subjects`, `record_session`, `sessions`, `preview_selected`, `revoke_selected`), `sqlite.rs` (the `lease_subjects` and `lease_sessions` tables near line 105) | #81 and #89. Three selectors: `Subject` (the originating user's `sub`, recorded at issuance), `Chain` (the first hop's lease, found through the parent links, so it matches leases from before the tables), `Session` (a session digest, resolved to the chains that opened it). Each matches unrevoked leases, expired ones included because a renewal could bring them back, and revokes them with the usual cascade in one `IMMEDIATE` transaction. Both tables are created at open, so there is no migration step. | 300 |
| 8 | `crates/attenuo-server/src/routes/mod.rs` (`register_issued`), `crates/attenuo-proxy/src/proxy.rs` (`new_session_digest`, the `record_session` call in `handle_post` after `adopt_session`), `auth.rs` (`Authorizer::record_session`), `session.rs` (`session_digest`, `session_tag`), `authz.rs` (`Pipeline::record_session`) | Where the selectors' data is written. The subject is written with the lease and a failure fails the issuance. The session binding is written only after the proxy adopted a session the upstream assigned for a verified, live caller (SR-18), keyed by `(session, server)`, write-once, and best effort: a failure is logged and the session still works. | 150 |
| 9 | `crates/attenuo-server/src/routes/admin.rs` (`SelectorRevokeBody`, `selector_of` near line 168, `resolve_shown`, `selector_response`, `revoke_by_selector` near line 291, `MAX_SELECTOR_AUDIT_IDS`) | `POST /admin/leases/revoke[?preview=true]` with exactly one of `user`, `chain_id`, `session`. The raw session id is hashed on arrival and never echoed: the answer's `selector` is `{session_tag, chain_ids}`. A preview writes nothing, not even an audit record; a revocation writes one `admin.lease.revoke` record listing at most 256 leases, with the full count in its digested arguments. | 200 |
| 10 | `crates/attenuo-cli/src/cli.rs` (`LeaseCmd::Revoke` near line 432), `crates/attenuo-server/ui/view-lease.js` (`openSelectorRevoke`, `openSessionRevoke`, `confirmForm`, `resultView`), `crates/attenuo-server/src/admin_ui.rs` (crate comment) | The two front ends. `attenuo lease revoke --user SUB | --chain-id ID | --session ID [--preview]` (a clap group, so exactly one). The console (#85, #91) always previews first and then asks for a typed confirmation: the chain id's last six characters, or for a user or session the number of leases that would change. The session id is typed into a field that is cleared on submit and never reaches a URL. Without `[admin_ui] allow_write` the console listener serves the preview and refuses the revocation. | 560 |
| 11 | `crates/attenuo-policy/src/request.rs` (`check_tool_inputs` near line 183, `input_matches`), `lib.rs` (`REASON_INPUT_TYPE_MISMATCH`, the "Stage 1d" comment in `authorize_labelled` near line 984) | #88. A declared catalog input that is present and not `null` must have its type as Cedar would see it, or the call is denied `input_type_mismatch` with a fixed diagnostic and no policy ids. It runs after the user-attribute check (1c) and before the request cache and Cedar, on every path: proxy, AuthZEN, admin dry run and `policy test`. | 120 |
| 12 | `config/policies/default.cedar`, `default_test.yaml`; `crates/attenuo-policy/tests/engine.rs` (`shipped_default_policy_passes_its_tests`) | #84 and #88. The starter policy: `like` has one wildcard that also matches `/` and the empty string, so `permit_create_issue_in_acme` pins `acme/<name>` with `!(like "acme/*/*")`, guards against the characters URL parsers act on (SR-70) and three `!=` guards; `permit_delete_acme_sandbox_repo` gives `forbid_sensitive_without_mfa` a decision it changes. 40 cases, all five policies exercised. The crate's embedded copy must stay byte-identical, which the engine test checks. | 450 |
| 13 | `crates/attenuo-policy/src/testing.rs` (`policy_refs`, `TestReport::unexercised`, `TestCase::check`, `authzen_skip_reason`), `crates/attenuo-cli/src/cli.rs` (`TestArgs`, `Via`), `policy_cmd.rs` | #82 and #84. `policy test` lists the policies no case's decision depended on, `--fail-on-unexercised` makes that exit 2, and `--via authzen` or `--via admin-evaluate` sends the same cases to a running server through one loader, checker and reporter. AuthZEN takes the chain from the bearer, so cases that need another chain are skipped; the admin dry run takes the case's chain and, since `feat/admin-evaluate-budget`, its `budget` too, so it skips nothing. | 900 |
| 14 | `crates/attenuo-proxy/src/filter.rs` (`list_kinds_by_shape` near line 229, `ListFilter::apply_message`), `proxy.rs` (`listen_list_filter`, `observe_listed`) | #90. An upstream that replays buffered events on a resumed `GET` stream (`Last-Event-ID`) used to send list answers unfiltered, because `ListFilter` matched request ids of the HTTP request it served and a `GET` has none. Now a response whose `result` holds a `tools`, `resources`, `resourceTemplates` or `prompts` array is a list answer by its shape, and goes through the same filter and SR-25 recording as on a `POST`. | 120 |
| 15 | `crates/attenuo-server/src/metrics.rs` (`ExhaustedAt`, `budget_exhausted`, `observe_run_lock_wait`, `render_limits_approvals_labels`, `render_wal`, `check_text_format`), `crates/attenuo-audit/src/sqlite.rs` (`wal_stats`) | #77. Series for run limits, approvals, output labels, the SR-55 run lock and the WAL checkpointer, labels from fixed sets only. `check_text_format` is a test helper that checks the page against the text format. The three example alert rules are in the deploy guide. | 500 |

Why each piece is shaped this way:

- **One rule for every refusal record: full verification first (SR-18).** Every caller in rows 2 to 5 records only after the token's signature, audience, expiry, chain and DPoP proof verified. Garbage, forged or expired tokens stay log lines. A record names a principal attenuo issued a token to; anything else would let an anonymous caller write to a log that is meant to be evidence. The cost is that a stranger's probing is visible only in the server log.
- **Ordinary decision records, not a new kind.** A refusal is kind `decision`, `deny`, with a fixed tool name (`initialize`, `http.GET`, `token.exchange`, `lease.renew`, `stream.end`). The schema, the hash input and every reader stay as they were, and `--tool` and `--decision` find them. The price: `audit export --kind exchange` lists issued exchanges only, and a refused one is found by tool and decision.
- **Fixed reason sets.** `EXCHANGE_REFUSAL_REASONS` and `RENEW_REFUSAL_REASONS` exist so that the metric's label set stays small and a unit test (`refusal_reasons_come_from_the_listed_set`, `renew_refusal_reasons_are_the_lease_reasons`) catches a new code that was not listed.
- **The session binding stores the full SHA-256, the audit tag is 12 characters.** The tag (`session_tag`) is 48 bits, fine for correlating log lines but not for deciding whose leases to revoke: two sessions sharing a tag would let one revocation hit another user's chain. So the store keys on `session_digest` (the full 64 hex characters), and the tag is defined as its prefix, so a tag in an audit record is still a prefix of the stored value. No raw id is stored, logged or echoed, because a session id grants use of the session.
- **Preview, then a typed confirmation.** A selector can match far more than the operator expects (every lease a user ever had, expired ones included). The preview runs the same match without writing; the console then asks the operator to type something that comes from the preview (a count, or the end of the chain id), so a stale or mistaken click cannot revoke.
- **Typed inputs before Cedar.** Before #88 a number in a declared string reached Cedar. Where a policy read it, `like` raised a type error and the call ended as `policy_error`, which the client guide tells clients to retry. Where no policy read it, the call went to the upstream unchecked. A fixed reason before Cedar makes the outcome independent of which policies happen to read the argument, and names the caller's mistake.
- **Shape beats remembered ids on the listen stream.** Remembering list request ids per session would need state with a TTL, would be lost on a proxy restart, and would miss an answer to an id the proxy never saw. Filtering by shape needs no state. The trade-off is that a non-list response carrying such an array also loses the entries the chain could not use. That only removes entries, never adds one.
- **`resources/unsubscribe` is allowlisted.** Giving up a subscription in the run's own session cannot widen anything, and requiring a capability only stopped an agent that had lost `subscribe` from cleaning up. It is still lease-checked, and a refusal is recorded under its own name. Capabilities and policies that name it no longer have any effect (CHANGELOG, Changed).

Check you understood:

1. An agent sends `POST /token` with a forged subject token, then with a valid token asking for a tool its parent does not hold. Which of the two leaves an audit record, under which tool and reason, and where does the caller find its id?
2. LangChain's MCP adapter opens a session per call. After a revocation, what does the audit log show for its next attempt, and why is there one record per HTTP request rather than one per token?
3. `POST /admin/leases/revoke {"session": "..."}` names a session that two upstreams each assigned to a different chain. What is revoked? What would go wrong if the store were keyed on the 12-character audit tag instead?
4. A catalog declares `repo = "string"` and an agent sends `repo: 42` to a tool whose policy never reads `repo`. What happened before #88, what happens now, and at which stage?
5. A test file's suite passes offline with every policy exercised, but `--via authzen --fail-on-unexercised` exits 2 on the same file. Why, and which arm would run every case?
6. An upstream replays a `tools/list` answer on a resumed `GET` stream. Which function decides that it is a list answer, and what else runs on it besides removing entries?

Run it (against the section 0 setup; the restart gives a clean log, so the sequence numbers below are the ones you will see, and it kills every earlier token):

```sh
pkill -x attenuo-server; sleep 1
RUST_LOG=warn attenuo-server --config examples/github-leak-demo/config.toml > /tmp/ob-server.log 2>&1 &
sleep 2
ROOT=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
CODER=$(printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$ROOT" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)

# 1. A refused exchange is a deny record against the parent's chain; an unverifiable token leaves nothing.
printf '%s\n' demo-tester-secret | ATTENUO_TOKEN="$CODER" \
  attenuo token exchange --actor tester --client-secret-stdin --cap github:create_issue
# error: server answered 400 Bad Request: invalid_scope: delegation chain is invalid: hop 2 widens capabilities ...
# decision <uuid>
printf '%s\n' demo-tester-secret | ATTENUO_TOKEN=not-a-token \
  attenuo token exchange --actor tester --client-secret-stdin --cap github:read_file
# error: server answered 400 Bad Request: invalid_grant: malformed token: InvalidToken   (no decision line)
attenuo audit tail --tool token.exchange --decision deny
# #4  <time>  DENY  attenuo/token.exchange  assistant > coder for alice  reason=exchange_widening  id=<uuid>

# 2. A declared input of the wrong type is refused before Cedar (the demo catalog declares path as a string).
ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path:=7
# DENIED  input_type_mismatch, then the decision id; exit status 2
ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path:='"7"'   # ALLOWED

# 3. Revoke by MCP session. fake_mcp gives every response the session id fake-session-1, so the coder's
#    first call since the restart bound it to this run (the call above did). Preview, then revoke.
attenuo lease revoke --session fake-session-1 --preview
# preview: nothing was changed
# selector  session 79a43975a64b          the first 12 hex characters of SHA-256("fake-session-1")
# chains    <root lease>
# matched   2 lease(s)
# would revoke 2 lease(s)
attenuo lease revoke --session fake-session-1 --reason "session drill"
# ... revoked 2 lease(s), reason    session drill, audit     <uuid>
attenuo lease revoke --session no-such-session --preview    # chains    none recorded for this session; 0 lease(s)

# 4. What the coder meets next, each one audited.
curl -s -i -X POST $ATTENUO_SERVER/mcp/github -H "Authorization: Bearer $CODER" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}' \
  | grep -i -E '^HTTP|^x-attenuo-decision-id|^\{'
# HTTP/1.1 401 Unauthorized
# x-attenuo-decision-id: <uuid>
# {"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"attenuo: unauthorized: lease_revoked","data":{"reason":"lease_revoked","decision_id":"<uuid>"}}}
curl -s -i -X POST $ATTENUO_SERVER/token/renew -H "Authorization: Bearer $CODER" | grep -i -E '^HTTP|^x-attenuo-decision-id|^\{'
# HTTP/1.1 400 Bad Request ... {"error":"invalid_grant","detail":"an ancestor lease is not live: lease_revoked","decision_id":"<uuid>"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST $ATTENUO_SERVER/token/renew -H "Authorization: Bearer not-a-token"   # 401, nothing recorded
attenuo audit tail --decision deny
# #4   ... DENY  attenuo/token.exchange  ...  reason=exchange_widening
# #5   ... DENY  github/read_file        ...  reason=input_type_mismatch
# #11  ... DENY  github/initialize       ...  reason=lease_revoked
# #12  ... DENY  attenuo/lease.renew     ...  reason=lease_revoked
attenuo audit verify          # audit chain OK: 12 entries verified

# 5. The policy harness: coverage, and the same cases through a running server.
attenuo policy test --fail-on-unexercised config/policies/default_test.yaml   # 40 passed, 0 failed ... all 5 policies exercised
attenuo policy test --via admin-evaluate examples/github-leak-demo/policy_test.yaml   # 11 passed ... all 5 policies exercised
R=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
printf '%s' "$R" > /tmp/ob-root.tok
attenuo policy test --via authzen --token-file /tmp/ob-root.tok --fail-on-unexercised examples/github-leak-demo/policy_test.yaml
# 2 passed, 0 failed, 9 skipped (11 cases in 1 file), then "3 of 5 policies not exercised:" with file:line and id; exit status 2
```

Every command in the block was run against `main` @ 471a319 on 2026-10-24 with debug binaries, and prints what is quoted. Two things cannot be shown with `fake_mcp`, which answers `GET` with `405`. One is a `stream.end` record: `a_listen_stream_cut_by_revocation_is_audited` in `crates/attenuo-server/tests/e2e.rs` cuts a real listen stream with an admin revocation. The other is list filtering on a resumed stream: `list_answers_replayed_on_a_resumed_get_stream_are_filtered` in `crates/attenuo-proxy/tests/list_filtering.rs` replays four list answers, and it failed before the fix. The other server-side proofs are `refused_exchanges_are_audited_against_the_parent_chain`, `refused_renewals_are_audited_against_the_token_chain`, `initialize_on_a_revoked_lease_is_audited`, `unverified_exchanges_leave_no_record` and `unverified_renewals_leave_no_record` (all in `e2e.rs`), `crates/attenuo-server/tests/admin_revoke_session.rs` and `mistyped_declared_input_denies_before_cedar_not_as_policy_error` in `crates/attenuo-policy/tests/engine.rs`. The demo config has no `[metrics]` listener; add `[metrics] enabled = true` with a loopback `listen` to a copy of it to read `/metrics`.

What is still open (from the [task board](../tasks/board.md) and the day's log):

- Revocation: revoking by the audit `session_tag` (48 bits, so the server would have to list every match); a lost session binding is only a log line.
- Proxy: Cedar-aware list filtering. (Listen-stream endings are counted in `proxy_streams_ended_total` and their `stream.end` records bounded per chain and reason since `feat/proxy-stream-endings`; the `http.GET` refusals of a client reopening a stream on a revoked lease are still one record per request.)
- Policy harness: the admin dry run cannot be given a `budget`, so those cases are skipped.
- Injection suite: `stage_of` in `evaluation/injection-suite/harness.py` does not know `input_type_mismatch`, so `t-banking-02` and `t-workspace-03` will score their mistyped attack calls as stage `other` (still denied) on the next run.
- SDKs: done after this session on `feat/sdk-export-revoke-selectors`: `audit_export` / `auditExport` take `tool` and `decision`, and `revoke_by_selector` / `revokeBySelector` wrap `POST /admin/leases/revoke`.
- Metrics: soft-limit asks are not told apart from other `approval_required` decisions (that would need policy ids as labels).

Session 13 closes the listen-stream, policy-harness and SDK items above; [its open list](#session-13-number-bounds-retention-stream-endings-authzen-and-the-stated-dry-run) supersedes this one.

### Session 13: number bounds, retention, stream endings, AuthZEN and the stated dry run

The merges of the night of 2026-10-24 to 25 (#95 to #103) close a run of open items from sessions 11 and 12. A capability can now bound a number. The lease store finally forgets: session records, then whole runs, then their counters and approvals. The listen stream's endings are counted and their records bounded. AuthZEN has fixtures that pin the specification's shapes. The admin dry run can be told the whole run state, from the CLI, both SDKs and the console. This session reads them in that order.

Read beside: the `range` paragraphs of [Capabilities and attenuation](../concepts/capabilities-and-attenuation.md) (constraint kinds and the attenuation rules), [Bounding a number](../guides/writing-policies.md#bounding-a-number-range-cedar-or-sum) in the policy guide, the retention items under [Cost and limits](../concepts/leases-and-revocation.md#cost-and-limits) in the leases concept with [`[leases]`](../reference/config.md#leases) in the configuration reference, [What gets a record](../concepts/audit-log.md#what-gets-a-record) in the audit-log concept for the `stream.end` bound, [AuthZEN conformance](../reference/authzen.md), and [Policies: read, check, dry run](../reference/http-api.md#policies-read-check-dry-run) in the HTTP API reference. The section "Admin: a dry run with a stated budget" in `sdk/python/README.md` and in `sdk/typescript/README.md` is the lookup for the SDK side. The reasoning behind each change is in [the 2026-10-24 log](../log/2026-10-24.md): the entries from 22:44 to 23:58 UTC, then the three after midnight, which sit at the top of the file.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-core/src/capability.rs` (`ArgConstraint::Range`, `RawRange` and its visitor, `RangeError`, `ArgConstraint::range`, `as_long` with `WHOLE_FLOAT_MAX`, `satisfied_by`, `violation`, `implies`, `Capability::explain_denial`) | #96. The fourth constraint kind. The wire form `{"op": "range", "value": {"min": 0, "max": 2000}}` is inclusive, either bound may be left out but not both, `min <= max`, bounds are JSON integers in `i64`. The visitor is hand-written so that a misspelt `maximum`, a repeated member, a float bound and a list (`[0, 5]`, which a derived struct takes as a tuple) are refused instead of read as "no bound". `as_long` reads a value as Cedar would: an `i64`, or a whole float up to 922337203685477, so `5.0` is `5` and `"5"`, `5.5` and `null` satisfy no range. `implies` is interval containment, a missing bound being the end of `i64`; `equals` or `one_of` sits in a range when every member is an integer inside it, a range sits in them only when it holds one integer, and `prefix` and `range` never relate. | 970 |
| 2 | `crates/attenuo-policy/src/lib.rs` (the capability check at the top of `authorize_labelled`, near line 930) | Where a range is enforced: the capability stage, before the catalog's type check (`input_type_mismatch`, session 12) and Cedar. So a fraction under a range is `capability_denied` even where the catalog declares the argument `long`. The diagnostic lists the effective capabilities and now appends, per capability whose patterns match, the first constraint the call fails: ``argument `amount` is above the maximum 2000``, `is below the minimum`, `is not an integer`, `is absent`, and for the other kinds `does not start with "acme/"` or `is not one of the permitted values`. It never prints the call's value. The proxy's `-32003` carries only the reason and decision id; the diagnostic is in the dry run and in AuthZEN answers when `[authzen] diagnostics` allows the caller. | 1310 |
| 3 | `crates/attenuo-core/src/limits.rs` (the `Range` arm in the `sum` check), `crates/attenuo-core/tests/attenuation_props.rs`, `crates/attenuo-server/tests/range_constraint.rs`, `crates/attenuo-policy/tests/range_cases.rs` | A `sum` limit over an argument needs a constraint that admits a non-negative integer; a range does when its `max` is at least 0. The proptests now generate ranges and whole and fractional floats, and check `implies` against integer containment. The server test refuses a higher max, a lower min, a dropped bound and a dropped constraint at exchange, each audited as `exchange_widening`. | 2440 |
| 4 | `crates/attenuo-cli/src/render.rs` (`fmt_constraint`), `sdk/python/src/attenuo/capability.py` (`Range`), `sdk/typescript/src/capability.ts` (`range`, `RangeBounds`) | The surfaces. `token inspect` prints `1 <= max_lines <= 100`, `amount <= 2000` or `amount >= 0`. There is no `--constraint` flag: a range goes in as `--cap` JSON, as every constraint always has. The SDK builders refuse what the server refuses. A range does not pin an argument against output-labelling fingerprints (only `equals` and `one_of` do), and time ranges are deferred, with the reasons in [RFC-0001 §3.1](../spec/rfc-0001-attenuo.md#31-not-yet-implemented--proposed). | 2010 |
| 5 | `crates/attenuo-server/src/config.rs` (`LeasesConfig` near line 987, `retention`, `session_retention`, `run_state_retention`), `crates/attenuo-server/src/state.rs` (the startup warning) | #97, #100, #102. Three keys under `[leases]`, each in seconds with 0 meaning off: `session_retention_seconds` 86400, `retention_seconds` 604800, `run_state_retention_seconds` 2592000. The server warns at startup when `retention_seconds` is below `[issuer] default_ttl_seconds`, because a run can then be pruned while its token could still renew it. It warns rather than refuses: too short a value fails closed, as `lease_unknown`. | 3030 |
| 6 | `crates/attenuo-audit/src/lease.rs` (the trait methods `prune_sessions`, `prune_leases`, `prune_run_state` near line 134; `SessionPrune`, `LeasePrune`, `lease_end`, `tree_prunable`, `RunStatePrune`, `run_state_prunable`, `approval_last_touched` near line 420; the memory store's versions near line 1134) | The three rules, written once as pure functions and used by both stores. `lease_end` is when a lease was revoked, or when it expired if it never was; `tree_prunable` asks it of every lease of a run. Each prune takes `(now, retention, max_rows)`, looks at a bounded window in insertion order, resumes after the last row it saw and reports `wrapped` at the end of the table. | 1780 |
| 7 | `crates/attenuo-audit/src/sqlite.rs` (`prune_sessions`, `prune_leases`, `prune_run_state` near line 3378) | One `IMMEDIATE` transaction per pass under the write gate, with a `rowid` cursor. The lease pass classifies each row of its window as a top lease or not by a `NOT EXISTS` on its parent, skips a top whose own row is still live without walking its tree, and deletes the rest of each prunable run with the revocation's recursive query. The run-state pass walks the charge log, then the counters, then the approvals, with one cursor, and parses timestamps in Rust, since RFC 3339 strings with and without fractional seconds do not sort as text. | 5170 |
| 8 | `crates/attenuo-server/src/lib.rs` (`LEASE_MAINTENANCE_PERIOD`, `LEASE_PRUNE_BATCH`, `LEASE_PRUNE_MAX_PASSES`, `prune_in_passes`, `prune_session_bindings`, `prune_lease_registry`, `prune_run_state`, `spawn_lease_maintenance`, and where `serve` starts it) | The single ticker. Every 60 s it runs the session pass, then the lease pass, then the run-state pass, each as passes of 1,000 rows on the blocking pool until one wraps or 100 have run (since #106 these three figures are the defaults of `[leases] maintenance_*`; session 14). Sessions go first, so a binding whose run is about to go is counted as a session; run state goes last, since it waits for the leases. The task starts only when at least one retention is on. Its first tick is skipped, so the first run is one period after startup. The three counters are `lease_sessions_pruned_total`, `leases_pruned_total` and `run_state_pruned_total{kind}`, in `metrics.rs`. | 540 |
| 9 | `crates/attenuo-server/src/routes/admin.rs` (`refund_budget`), `crates/attenuo-cli/src/main.rs` (`budget_refund`) | What a pruned charge looks like to an operator. At #102 a refund answered 404 `not_found`, exactly as for a decision that charged nothing (exit 2). Since #112 it answers 410 `charge_pruned` (CLI exit 4), and the 404 detail says which of three cases it is; see session 14, row 12. | 2800 |
| 10 | `crates/attenuo-proxy/src/guard.rs` (crate comment, `StreamEndCause`, `of_lease_reason`, the record window (`STREAM_END_RECORD_KEYS` and `StreamEndRecords::admit` at 35b2c62, `RecordWindow` in `records.rs` since #107), `StreamGuard::listen`, `impl Drop for State` near line 501), `auth.rs` (`observe_stream_end`, `observe_record_suppressed`) | #101. Every `GET` listen stream is counted once when it ends, in `proxy_streams_ended_total{cause}`. The count happens in the `Drop` of the stream's state, which runs exactly once whatever ended it, a body never polled included. A missing cause means the client went away. `StreamEndRecords` bounds the `stream.end` records of listen streams: one per (chain digest, reason) per window (60 s at 35b2c62; `[proxy] record_window_seconds` since #121, default 60), the first; later ends in the window keep their final event, which names the window's record, and are counted in `audit_records_suppressed_total{tool="stream.end",reason}`. | 1340 |
| 11 | `crates/attenuo-proxy/src/proxy.rs` (`REASON_UPSTREAM_NOT_EVENT_STREAM`, `upstream_not_event_stream` near line 865) | #97. A `GET` the upstream answers with a `2xx` that is not `text/event-stream` is refused: 502, `-32005`, reason `upstream_not_event_stream`, the body dropped unread and no session adopted. It was the one path on which a list answer reached the client unfiltered and an allowed call's answer unlabelled. `405` and errors are relayed as before. | 1920 |
| 12 | `crates/attenuo-server/tests/authzen_conformance.rs` (crate comment, `run_fixture`, `normalise`, `matches`, `comparator_is_exact_where_it_should_be`), `crates/attenuo-server/tests/fixtures/authzen/` | #99. 27 JSON fixtures, each a `_note` naming the specification section, an optional `token` (capabilities, `revoke`) and steps of request and exact expected answer. Every fixture gets a fresh root token through the dev mint, so budgets and approvals never leak between them. Only random or clock-bound values are normalised (`decision_id`, `approval_id`, `call_hash`, `expires_at`, `approval.id`, the base URL); `"<any>"` is for free-text error details; a member the fixture does not list fails. | 2160 |
| 13 | `crates/attenuo-server/src/routes/authzen.rs` (`evaluations` near line 87, `echo_request_id` near line 192) | The two gaps the fixtures found. `X-Request-ID` is copied onto every answer of both evaluation routes, errors included, by a `route_layer` (section 10.1.3 makes it a MUST). A batch with no `evaluations`, or an empty one, is decided and answered as a single evaluation (section 7.1), where it used to be a 400. | 490 |
| 14 | `crates/attenuo-server/src/authz.rs` (`CounterSource` and `StatedBudget` near line 232, `StatedBudget::counters`, `Pipeline::budget_view_from` near line 1071), `routes/policies.rs` (`evaluate_policies`, `budget_from_json`, `usage_from_json`, `session_from_json`) | #95. The dry run's run state. `budget_view_from(chain, call, CounterSource::Store)` is the live path (`budget_view` calls it); `CounterSource::Stated` answers each charge from the request and never touches the lease store. The answer's `budget`, `session` and `usage` each carry `source`: `store` or `request`, and `untracked` for usage when nothing reads it. With a stated `budget` and no `usage`, usage is zero and reported as `request`. | 4290 |
| 15 | `crates/attenuo-cli/src/policy_cmd.rs` (`admin_evaluate_body` near line 267), `sdk/python/src/attenuo/admin.py` (`StatedBudget`, `BudgetLimit`, `StatedSession`, `StatedApproval`, `StatedUsage`, `policy_evaluate`), `sdk/typescript/src/admin.ts` (the same types, `policyEvaluate`), `crates/attenuo-server/ui/view-policy.js` | #95, #98, #103. `policy test --via admin-evaluate` sends each case's `session` and `usage` always (so nothing is read from the store), `approval` when the case has one and `budget` with only the members the case sets. `policy evaluate` has no flags for these blocks and reads the store. The SDKs send only what is set, under the server's names, and validate nothing beyond types; an unlimited figure is `2**63 - 1` in Python and `Infinity` in TypeScript. The console has "Budget", "Run labels" and "Run usage" sections and no approval field. | 4090 |

The three retention rules side by side:

| | Session records (#97) | Lease registry (#100) | Run state (#102) |
| --- | --- | --- | --- |
| Key, default | `session_retention_seconds`, 86400 (a day) | `retention_seconds`, 604800 (a week) | `run_state_retention_seconds`, 2592000 (30 days) |
| What is deleted | `lease_sessions` rows (revoke by session) | a whole run, root lease and subtree: `leases`, `lease_subjects`, `lease_bindings`, `lease_sessions`, `hop_limits`, `run_labels`, `run_spans` | `budget_charges` entries (per decision), `budget_counters`, `approvals` |
| When | the run's root lease is revoked (at once, whatever the setting), has been expired longer than the retention, or is unknown | every lease of the run has ended (revoked, or expired if never revoked) and the last ended longer ago than the retention; a revoked run waits too, counted from the revocation | only once the leases they belong to are gone from the registry; a charge entry when its charge and any refund are older than the retention, a counter when no charge under its lease is left, an approval when its creation, decision and expiry are all older |
| What an operator loses | `lease revoke --session` finds the run no more; `--chain-id` and `--user` still reach it while its leases are kept | the run's token reads `lease_unknown` (audited as a `deny`, renewals included); `--user`, `--chain-id` and `--session` match nothing; the console's lease tree answers 404 | a refund of one of its decisions answers 410 `charge_pruned` since #112 (404 `not_found`, as for a decision that charged nothing, when this session was written; a late refund cannot be honoured either way); its approvals leave `GET /admin/approvals` and the console |
| What the audit log keeps | everything | every decision, issuance, renewal and revocation of the run | every decision record with its `budget` member, every `admin.budget.refund`, every `approval_request` and `approval_grant` |
| Metric | `lease_sessions_pruned_total` | `leases_pruned_total` (deleted leases) | `run_state_pruned_total{kind}`, `kind` one of `counters`, `charges`, `approvals` |

Why each piece is shaped this way:

- **One constraint per argument, so `range` does not combine.** A capability maps an argument name to one `ArgConstraint`, as before. "1 to 100 but not 13" is a Cedar rule. Combining kinds would have changed the shape of every token and the `covers` rule for every pair, for a case nobody has.
- **A range is checked before Cedar, as the delegated bound.** The policy guide's table says when to use which: `range` when the bound is part of what was delegated (chosen per token, narrowed per hop, passed by no policy or approval), a Cedar rule over `context.input` for a deployment-wide ceiling that nobody has to put in a token, and `sum` or `context.usage.amount` for a total per run. A `range` and a `sum` together stop one large payment and many small ones.
- **`as_long` repeats the policy crate's rule.** `attenuo-core` cannot depend on `attenuo-policy`, so the 922337203685477 bound for whole floats is a repeated constant with a comment. If the two disagreed, a value could pass the capability stage and be refused or misread by Cedar, or the reverse.
- **A range covers a `one_of` only when the range holds one integer.** `[1, 3]` does not cover `one_of [1, 2, 3]`. That is sound and keeps the rule to one line; it is open until a real exchange needs more.
- **The diagnostic names the bound, never the value.** The value of a refused argument is what an injected agent tried to send; echoing it into logs and answers would copy attacker text into places that are read by people and tools. A test checks that a denied `31337` appears nowhere.
- **Retention exists because nothing in the store was ever deleted.** Before #97 every issued token left a lease row, a subject and a binding forever, and every charged or gated call left counters and approval rows. The rules all keep anything a renewal could still bring back. An expired but unrevoked lease is renewable while its token is valid, so every grace period must outlast the longest token lifetime. That is why the defaults are a day and a week against a 900 s default token.
- **Whole runs, never part of one.** Deleting a run whole keeps `ancestors_of`, `classify` and the revoke cascade honest: no surviving lease has a parent row that is gone, so the hot path never sees a known child under an unknown parent because of pruning.
- **Revoked runs wait out the retention, counted from the revocation.** Pruning them at once was allowed and would change nothing a caller can do. Waiting keeps the run in the console tree, in revoke-by-user previews and in `lease_revoked` (rather than `lease_unknown`) refusals for a week, which is what an operator in an incident wants. Counting from the revocation matters for a lease that a user-wide revocation reached after it expired: it was renewable until then (`a_late_revocation_restarts_the_grace_period`). The session record of a revoked run goes at once all the same, since it only serves revoke-by-session and a revoked chain needs no more revoking.
- **Run state goes per lease, and only after the leases.** Counters and charges are keyed by lease id and never joined with `leases` (ADR-0010). Once the lease rows are gone there is no way back to the run, and since runs go whole, "this lease is unknown" means "its run is gone". Deleting a counter cannot reopen a budget: every hop it counted is unknown, so their calls are refused as `lease_unknown` before any limit is read. The 30 days sit on top of the week because refunds follow billing and incident processes.
- **One ticker, constants for cadence and batch.** No other part of the store ran periodically, so the server got one task rather than three. A pass is bounded in what it reads as well as what it deletes; measured on a file store of 100,000 leases, a deleting pass of 1,000 took 5.6 ms median and a pass over live rows 0.77 ms. A hot-path lease check that arrives during a deleting pass waits for it. The constants are open as configuration.
- **One `stream.end` record may stand for many streams.** The volume that prompted #101 turned out to be concurrent listen streams of one token cut at the same moment (several sessions, or more than one stream), not reconnects: reopening with an expired token is refused at authentication and was never recorded (SR-18). So the bound is per chain digest and reason, the digest rather than `chain_id` so that a sub-agent's ends are not hidden behind its parent's. The first end of a window is recorded, so the log shows when the condition began. Decision records have no free-text field, so the count of suppressed ends lives only in `audit_records_suppressed_total` and in the log line of the next record. The window is a constant: no `[proxy]` or `[audit]` key fits a knob on record suppression. A table full of open windows records rather than suppresses. Tool-call decisions, other refusals and the `stream.end` of a streamed `POST` answer are never bounded.
- **The non-SSE `GET` is refused, not filtered.** MCP allows only an event stream or `405` on `GET`. A JSON body there skipped both the list filter and output labelling, and the safe answer is 502.
- **Fixtures compare whole answers.** A suite that checked only `decision` would notice neither a new member leaking into answers nor a header the specification requires going missing. The fixtures list the expected headers and the whole body, with a short list of normalised fields, so every change to the answer shape is a test change. A mutation check (the route layer removed) made `evaluation-request-id.json` fail.
- **The stated dry run goes through the live limit check.** A stated `budget` is turned into counters and checked by the same loop a live call uses, so a spent hard limit answers `budget_exhausted` with the live `limit` member and diagnostic, and a refusal's `limit` can be pasted back as a `limits` entry. The one divergence left is offline: `attenuo policy test` without `--via` keeps no limit check, so a case whose chain carries a limit and whose `budget` says it is spent only sets `context.budget` there. The run block shows it.

Check you understood:

1. A parent holds `amount` in `0..2000`. Which of these children does the exchange accept: `10..500`; `equals 300`; `one_of [100, 2500]`; `{"min": 0}`; `prefix "1"`? Which function decides, and what reason does the audit record carry for a refusal?
2. An agent holding `amount` in `1..100` sends `amount: 5.0`, then `amount: 5.5`, then `amount: "5"`, to a tool whose catalog declares `amount = "long"`. What does each get, at which stage, and why is the second not `input_type_mismatch`?
3. Alice's run was revoked six days ago. With the defaults, what does a call with her coder's token get today, and what would it get two days from now if the token were still valid then? Which table rows are gone by then, and which follow thirty days later?
4. An operator refunds a decision of a run pruned forty days ago, and then one that charged nothing. What did each answer when this session was written, and where did the operator tell them apart? (Since #112 the first is 410 `charge_pruned`; session 14 has the table.)
5. Three listen streams of one chain and one of another chain are open when the first chain is revoked. How many `stream.end` records are written, what do the other streams' final events say, and where is the count of the ones not recorded?
6. A fixture expects `{"decision": true, "context": {"reason": "policy_allow", "policy_ids": [...], "diagnostics": [], "decision_id": "<decision_id>"}}` and the server starts adding `"budget"` to every answer. What happens to the suite, and what would have happened with a comparator that checked only `decision`?
7. A case's chain carries `calls: 2` on `read_file` and its `budget` says `calls_remaining: 0`. What do `attenuo policy test` and `attenuo policy test --via admin-evaluate` say, and why do they differ?

Run it. Start from the section 0 setup with a freshly started demo server. The last block restarts the server on a copy of the demo config with tiny retentions and a metrics listener, so run it last.

```sh
cargo test -p attenuo-core --lib range                   # serde, satisfaction, the violation text, implication, attenuation: 5 passed
cargo test -p attenuo-core --test attenuation_props range # the two range proptests: 2 passed
cargo test -p attenuo-policy --test range_cases           # range cases in policy test files: 3 passed
cargo test -p attenuo-server --test range_constraint      # widening refused and audited, narrower child enforced: 2 passed

# 1. A range in a token, a narrower child, a widening refused, a call above the max denied.
#    fake_mcp echoes any argument, so read_file takes an extra one, max_lines, that the demo catalog does not declare.
CAP='{"server":"github","tool":"read_file","constraints":{"max_lines":{"op":"range","value":{"min":1,"max":500}}}}'
ROOTR=$(attenuo token root --subject alice --agent assistant --cap "$CAP" --print token)
attenuo token inspect "$ROOTR"          # assistant  can github:read_file {1 <= max_lines <= 500}
NARROW='{"server":"github","tool":"read_file","constraints":{"max_lines":{"op":"range","value":{"min":1,"max":100}}}}'
C=$(printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$ROOTR" \
  attenuo token exchange --actor coder --client-secret-stdin --cap "$NARROW" --print token)
attenuo token inspect "$C"              # coder  can github:read_file {1 <= max_lines <= 100}
WIDE='{"server":"github","tool":"read_file","constraints":{"max_lines":{"op":"range","value":{"min":1,"max":1000}}}}'
printf '%s\n' demo-tester-secret | ATTENUO_TOKEN="$ROOTR" \
  attenuo token exchange --actor tester --client-secret-stdin --cap "$WIDE"
# error: server answered 400 Bad Request: invalid_scope: delegation chain is invalid: hop 1 widens capabilities
#   relative to hop 0: requested capability `github:read_file{max_lines={"op":"range","value":{"min":1,"max":1000}}}` ...
# decision <uuid>
NOMAX='{"server":"github","tool":"read_file","constraints":{"max_lines":{"op":"range","value":{"min":1}}}}'
printf '%s\n' demo-tester-secret | ATTENUO_TOKEN="$C" \
  attenuo token exchange --actor tester --client-secret-stdin --cap "$NOMAX"
# error: ... hop 2 widens capabilities relative to hop 1 ...    dropping the upper bound is widening too
attenuo token root --subject alice --agent assistant \
  --cap '{"server":"github","tool":"read_file","constraints":{"max_lines":{"op":"range","value":{"min":10,"maximum":5}}}}'
# error: invalid capability JSON ...: unknown field `maximum`, expected `min` or `max` ...   refused before anything is sent

export ATTENUO_TOKEN="$C"
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a --arg max_lines:=50     # ALLOWED
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a --arg max_lines:=50.0   # ALLOWED: a whole float is 50
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a --arg max_lines:=150
# DENIED  capability_denied, then the decision id; exit status 2. The -32003 carries only the reason and the id.
attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a --arg max_lines:='"50"'  # DENIED  capability_denied
attenuo policy evaluate --server github --tool read_file --arg repo=alice/public-docs --arg path=a --arg max_lines:=150
# DENY  capability_denied ...
# diagnostic: call github:read_file is not permitted by the effective capabilities
#   [github:read_file{max_lines={"op":"range","value":{"min":1,"max":100}}}]; github:read_file: argument `max_lines` is above the maximum 100
attenuo policy evaluate --server github --tool read_file --arg repo=alice/public-docs --arg path=a --arg max_lines:=7.5
# ... argument `max_lines` is not an integer          (also: is below the minimum 1, for 0; is absent, without it)
unset ATTENUO_TOKEN
attenuo audit tail --decision deny
# ... DENY  attenuo/token.exchange  assistant for alice           reason=exchange_widening ...
# ... DENY  attenuo/token.exchange  assistant > coder for alice   reason=exchange_widening ...
# ... DENY  github/read_file        assistant > coder for alice   reason=capability_denied ...   (twice)

# 2. Listen-stream endings and the stream.end bound need an upstream with a listen stream (fake_mcp answers GET with 405).
cargo test -p attenuo-proxy --lib guard::                       # the window, the cause labels, each way a stream ends: 10 passed
cargo test -p attenuo-proxy --test security_pass3 leave_one_record   # one record for several streams of a chain: 2 passed
cargo test -p attenuo-proxy --test list_filtering a_get_answered     # the non-SSE GET refused (502), 405 and errors relayed: 2 passed

# 3. AuthZEN conformance: the fixtures, then the two fixed gaps by hand.
cargo test -p attenuo-server --test authzen_conformance         # every fixture, and the comparator's own test: 2 passed
ls crates/attenuo-server/tests/fixtures/authzen/ | wc -l        # 27
R=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
Q='{"subject":{"type":"agent","id":""},"action":{"name":"read_file"},"resource":{"type":"tool","id":"github/read_file"},"context":{"input":{"repo":"alice/public-docs","path":"a"}}}'
curl -s -i $ATTENUO_SERVER/access/v1/evaluation -H "Authorization: Bearer $R" -H 'X-Request-ID: drill-42' \
  -H 'Content-Type: application/json' -d "$Q" | grep -i -E '^HTTP|^x-request-id'
# HTTP/1.1 200 OK
# x-request-id: drill-42
curl -s -i $ATTENUO_SERVER/access/v1/evaluation -H "Authorization: Bearer garbage" -H 'X-Request-ID: drill-43' \
  -H 'Content-Type: application/json' -d "$Q" | grep -i -E '^HTTP|^x-request-id'
# HTTP/1.1 401 Unauthorized
# x-request-id: drill-43                                         echoed on errors too
curl -s $ATTENUO_SERVER/access/v1/evaluations -H "Authorization: Bearer $R" \
  -H 'Content-Type: application/json' -d "${Q%\}},\"evaluations\":[]}"; echo
# {"decision":true,"context":{"reason":"policy_allow",...}}      an empty batch is one evaluation, answered as one
curl -s $ATTENUO_SERVER/access/v1/evaluations -H "Authorization: Bearer $R" \
  -H 'Content-Type: application/json' -d "${Q%\}},\"evaluations\":[{}],\"options\":{\"evaluations_semantic\":\"deny_on_first_deny\"}}"; echo
# {"error":"invalid_request","detail":"evaluations_semantic `deny_on_first_deny` is not supported; use `execute_all`"}
#   (that was the answer when this block was run; since `feat/authzen-semantics-discovery` merged, `deny_on_first_deny`
#   and `permit_on_first_permit` are honoured: the batch stops at the first deny or permit and answers only the
#   entries it decided, each with its own audit record; see "Batch semantics" on the AuthZEN reference page)

# 4. The dry run with a stated run state, from the CLI: the same cases offline and through the server.
cat > /tmp/ob-dry_test.yaml <<EOF
policies: $PWD/examples/github-leak-demo/policy.cedar
catalog: $PWD/examples/github-leak-demo/config.toml
cases:
  - name: one call left of two, so the read goes through
    chain:
      - agent: assistant
        capabilities: [{server: github, tool: read_file, limits: {calls: 2}}]
    budget: { calls_remaining: 1 }
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs, path: a } }
    expect: allow
    reason: policy_allow
  - name: none left, so the server's own limit check refuses it before Cedar
    chain:
      - agent: assistant
        capabilities: [{server: github, tool: read_file, limits: {calls: 2}}]
    budget: { calls_remaining: 0 }
    call: { server: github, tool: read_file, arguments: { repo: alice/public-docs, path: a } }
    expect: deny
    reason: budget_exhausted
  - name: a tainted run that already used the tool, and an approval by the user
    chain: [{ agent: assistant, capabilities: ["github:*"] }]
    session: { tainted_by: [github/read_file] }
    usage: { calls: 3 }
    approval: { by: user }
    call: { server: github, tool: create_issue, arguments: { repo: alice/public-docs, title: hi } }
    expect: allow
    reason: policy_allow
EOF
attenuo policy test /tmp/ob-dry_test.yaml
# ✗ none left, so the server's own limit check refuses it before Cedar  (allow: policy_allow ...)
# 2 passed, 1 failed ...; exit status 2: offline, budget only sets context.budget (the documented divergence)
attenuo policy test --via admin-evaluate /tmp/ob-dry_test.yaml
# ✓ none left, ...  (deny: budget_exhausted)
# 3 passed, 0 failed (3 cases in 1 file); nothing audited, nothing charged
# The CLI prints the decision, not the answer's sources. The route itself, with a stated budget and session:
R=$(attenuo token root --subject alice --agent assistant \
  --cap '{"server":"github","tool":"read_file","limits":{"calls":2}}' --print token)
curl -s $ATTENUO_SERVER/admin/policies/evaluate -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d @- <<EOF | python3 -m json.tool
{"token": "$R",
 "subject": {"type": "agent", "id": ""},
 "action": {"name": "read_file"},
 "resource": {"type": "tool", "id": "github/read_file", "properties": {"server": "github"}},
 "context": {"input": {"repo": "alice/public-docs", "path": "a"}},
 "budget": {"calls_remaining": 0},
 "session": {"tainted_by": ["github/read_file"]}}
EOF
# "reason": "budget_exhausted", "diagnostics": ["limit `calls` of hop 0 would be exceeded: max 2, used 2"],
# "session": {"tainted": true, ..., "source": "request"}, "budget": {..., "calls_remaining": 0, ..., "source": "request"},
# "usage": {"calls": 0, ..., "source": "request"}, "limit": {"hop": 0, "kind": "calls", "max": 2, "used": 2}

# 5. The same from Python (the section 8 venv, or PYTHONPATH as below).
PYTHONPATH=sdk/python/src python3 - <<'PY'
from attenuo import (AdminClient, Capability, StatedApproval, StatedBudget,
                     StatedSession, StatedUsage)

admin = AdminClient("http://127.0.0.1:18080", "demo-admin-token")
root = admin.mint_root_dev("alice", "https://idp.example", "assistant",
                           [Capability("github", "read_file").with_limits(calls=2), "github:create_issue"])
read = {"repo": "alice/public-docs", "path": "a"}
ev = admin.policy_evaluate("github", "read_file", read, token=root)
print(ev.reason, ev.budget.calls_remaining, ev.budget.source, ev.labels.source, ev.usage.source)
# policy_allow 2 store store untracked
ev = admin.policy_evaluate("github", "read_file", read, token=root, budget=StatedBudget(calls_remaining=0))
print(ev.reason, ev.limit, ev.budget.source, ev.usage.source)
# budget_exhausted BudgetLimit(hop=0, kind='calls', used=2, arg=None, max=2) request request
issue = {"repo": "alice/public-docs", "title": "hi"}
print(admin.policy_evaluate("github", "create_issue", issue, token=root).reason)
# approval_required
ev = admin.policy_evaluate("github", "create_issue", issue, token=root,
                           session=StatedSession(tainted_by=["github/read_file"]),
                           usage=StatedUsage(calls=3), approval=StatedApproval(by="user"))
print(ev.reason, ev.approval_by, ev.labels.tainted_by, ev.labels.source, ev.usage.calls, ev.usage.source)
# policy_allow user ['github/read_file'] request 3 request
PY

# 6. And from TypeScript, against the built package (npm ci && npm run build in sdk/typescript, as in section 8).
node --input-type=module - <<'JS'
import { AdminClient, capability, withLimits } from "./sdk/typescript/dist/index.js";
const admin = new AdminClient("http://127.0.0.1:18080", "demo-admin-token");
const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
  capabilities: [withLimits(capability("github", "read_file"), { calls: 2 }), "github:create_issue"],
});
const read = { repo: "alice/public-docs", path: "a" };
let ev = await admin.policyEvaluate("github", "read_file", read, { token: root });
console.log(ev.reason, ev.budget?.callsRemaining, ev.budget?.source, ev.labels?.source, ev.usage?.source);
// policy_allow 2 store store untracked
ev = await admin.policyEvaluate("github", "read_file", read, { token: root, budget: { callsRemaining: 0 } });
console.log(ev.reason, ev.limit, ev.budget?.source, ev.usage?.source);
// budget_exhausted { hop: 0, kind: 'calls', used: 2, max: 2 } request request
ev = await admin.policyEvaluate("github", "create_issue", { repo: "alice/public-docs", title: "hi" }, {
  token: root, session: { taintedBy: ["github/read_file"] }, usage: { calls: 3 }, approval: { by: "user" },
});
console.log(ev.reason, ev.approvalBy, ev.labels?.taintedBy, ev.labels?.source, ev.usage?.calls, ev.usage?.source);
// policy_allow user [ 'github/read_file' ] request 3 request
JS
attenuo audit verify            # audit chain OK: 21 entries verified, on a server that ran only this block so far; the dry-run route never appends

# 7. Retention: tiny retentions, one revoked run, one maintenance period. There is no route or flag that runs a
#    pass on demand, so the block waits for the ticker (60 s after startup, then every 60 s) and watches /metrics.
cargo test -p attenuo-audit --test run_state                    # run state kept while the leases are there, pruned after: 5 passed
cargo test -p attenuo-audit --test leases prune                 # session and lease passes, bounded and resuming: 6 passed
pkill -x attenuo-server; sleep 1
cp examples/github-leak-demo/config.toml /tmp/ob-retention.toml
cat >> /tmp/ob-retention.toml <<'EOF'

[leases]
retention_seconds = 1
session_retention_seconds = 1
run_state_retention_seconds = 1

[metrics]
enabled = true
listen = "127.0.0.1:19100"
EOF
RUST_LOG=warn attenuo-server --config /tmp/ob-retention.toml > /tmp/ob-server.log 2>&1 &
sleep 2
grep -o '\[leases\] retention_seconds is below.*lease_unknown' /tmp/ob-server.log
# [leases] retention_seconds is below [issuer] default_ttl_seconds: a chain can be pruned while its token is still
#   valid, and its renewal then fails as lease_unknown
ROOTJ=$(attenuo --json token root --subject alice --agent assistant \
  --cap '{"server":"github","tool":"read_file","limits":{"calls":5}}')
R=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
L=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lease"])')
C=$(printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)
ATTENUO_TOKEN="$C" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a   # ALLOWED, charged
D=$(attenuo --json audit tail -n 5 | python3 -c 'import json,sys
r = [json.loads(l)["record"] for l in sys.stdin if l.strip()]
print([x for x in r if x["kind"] == "decision" and x["decision"] == "allow"][-1]["id"])')
attenuo lease revoke --session fake-session-1 --preview          # chains <root lease>, matched 2 lease(s): the binding exists
attenuo lease revoke --chain-id "$L" --reason "retention drill"  # revoked 2 lease(s)
ATTENUO_TOKEN="$C" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=b   # DENIED  lease_revoked
curl -s http://127.0.0.1:19100/metrics | grep -E '^attenuo_(lease_sessions_pruned|leases_pruned|run_state_pruned)_total'
# attenuo_lease_sessions_pruned_total 0
# attenuo_leases_pruned_total 0
# attenuo_run_state_pruned_total{kind="counters"} 0     (and charges 0, approvals 0)
until curl -s http://127.0.0.1:19100/metrics | grep -q '^attenuo_leases_pruned_total [1-9]'; do sleep 5; done   # about a minute
curl -s http://127.0.0.1:19100/metrics | grep -E '^attenuo_(lease_sessions_pruned|leases_pruned|run_state_pruned)_total'
# attenuo_lease_sessions_pruned_total 1
# attenuo_leases_pruned_total 2
# attenuo_run_state_pruned_total{kind="counters"} 2     the root's and the coder's counters
# attenuo_run_state_pruned_total{kind="charges"} 1      the one charged decision
# attenuo_run_state_pruned_total{kind="approvals"} 0
ATTENUO_TOKEN="$C" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=c   # DENIED  lease_unknown
curl -s -X POST $ATTENUO_SERVER/token/renew -H "Authorization: Bearer $C"; echo
# {"error":"invalid_grant","detail":"an ancestor lease is not live: lease_unknown","decision_id":"<uuid>"}
attenuo lease tree "$L"                     # error: server answered 404 Not Found: not_found: unknown lease `<root lease>`
attenuo lease revoke --chain-id "$L" --preview       # matched 0 lease(s)
attenuo lease revoke --session fake-session-1 --preview   # chains none recorded for this session
attenuo budget refund "$D" --reason late
# error: no charge is recorded for decision <uuid> (it charged no run limit or run usage, or its charge log was pruned);
#   nothing to refund                       exit status 2 (on 35b2c62; since #112 a pruned charge is 410
#   charge_pruned, exit 4: session 14, part 6)
attenuo audit tail -n 4
# #6  ... ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action ...
# #7  ... DENY  github/read_file      assistant > coder for alice  reason=lease_revoked ...
# #8  ... DENY  github/read_file      assistant > coder for alice  reason=lease_unknown ...
# #9  ... DENY  attenuo/lease.renew   assistant > coder for alice  reason=lease_unknown ...
attenuo audit verify                        # audit chain OK: 9 entries verified: the log kept everything
pkill -x attenuo-server; sleep 1            # back to the demo config for the other sessions:
RUST_LOG=warn attenuo-server --config examples/github-leak-demo/config.toml > /tmp/ob-server.log 2>&1 &
```

Every command in the block was run in this order against `main` @ 35b2c62 on 2026-10-25, with debug binaries, on a freshly started demo server and `fake_mcp`, and prints what is quoted, the test counts included; ids, leases and times differ on every run. The Python block ran the repository's sources through `PYTHONPATH` in a virtual environment with the SDK's dependencies, and the TypeScript block the package built by `npm run build`. Three things are not shown live. One is a `stream.end` record and its bound, since `fake_mcp` answers `GET` with `405`: the `guard::` and `leave_one_record` tests above cut real listen streams, and `a_listen_stream_cut_by_revocation_is_audited` in `crates/attenuo-server/tests/e2e.rs` checks `proxy_streams_ended_total{cause="lease_revoked"} 1` end to end. Another is the console's "Budget", "Run labels" and "Run usage" sections, which `scripts/console-smoke.sh` exercises in a browser (not run for this page). The last is the startup timing of retention: the ticker skips its first tick, so the wait in block 7 is about a minute after the server started, whatever the retentions say; the server-side proofs with a clock moved days back are `lease_trees_of_ended_chains_are_pruned` and `bindings_of_revoked_chains_are_pruned` in `crates/attenuo-server/tests/admin_revoke_session.rs` and `run_state_of_pruned_runs_is_pruned_past_its_retention` in `crates/attenuo-server/tests/approvals.rs` (all three pass on that commit).

What is still open after this session (from the [task board](../tasks/board.md) and the logs of these merges; this list supersedes session 12's):

- Release: 0.1.0 waits on the maintainer (Actions billing, the tag, making the repository public, the package names, the manual publishes).
- Constraints: time ranges, deferred until a tool argument needs one; no `--constraint` shorthand on the CLI (it would be the first non-JSON constraint syntax, so it should cover every kind); a range covering a small `one_of` is refused; the fuzz targets that now generate ranges were type-checked, not run. In the token claims, `evidence` on the originating user and a stable `chain_id` are still to be reconciled or dropped.
- Revocation and leases: revoking by the audit `session_tag`; the optional proxy lease cache; a lost session binding is only a log line.
- Retention: a refund of a pruned charge cannot be told from one of a decision that charged nothing (both 404 `not_found`, exit 2) without the audit log (410 `charge_pruned` since #112); the maintenance cadence and batch are constants (`[leases] maintenance_*` since #106); a lease pass reads the subtree of every prunable run on top of its 1,000-row window, so a very wide run makes that pass longer (bounded since #110); the run-state pass's per-row lookups were not measured.
- Proxy: Cedar-aware list filtering; a client that keeps reopening a listen stream (or sends any undecided request) on a revoked lease still adds one `http.GET` `deny` per request, unbounded; the `stream.end` window is a constant (a setting since #121) and the suppressed count is in the metric and log only; a large non-list event on the listen stream costs about 0.7 ms per 85 KB to parse and re-serialize.
- AuthZEN: the Search APIs and discovery `capabilities` and `signed_metadata` are not implemented (`deny_on_first_deny`, `permit_on_first_permit` and the `Content-Type` check landed on `feat/authzen-semantics-discovery`); error bodies stay JSON objects ([AuthZEN conformance](../reference/authzen.md#not-implemented)).
- Dry run: offline `policy test` does not enforce chain limits. (The console's Approval section and the strict `approval` block, which used to ignore members other than `by`, landed on `feat/console-approval-strict-route`.)
- Server and identity: real admin authentication; actor tokens against a live SPIRE; hop-0 hardening (a shared replay cache, `private_key_jwt`, ID-JAG drafts).
- SDKs: publishing to PyPI and npm (prepared since #118, with the publish itself the maintainer's step), streaming responses (`call_tool_stream` and `callToolStream` since #115; both in session 15), hop-0 against a live IdP; one intermittent Python integration failure (`test_dpop_server_nonce`, suspected) is still being watched.
- Evaluation and performance: the remaining test-split cases and a model in the loop; the injection suite's `stage_of` in `evaluation/injection-suite/harness.py` still does not know `input_type_mismatch`, so two held-out cases will score their mistyped attack calls as stage `other` (still denied); run limits phase 3; the open benchmark and performance items on the board (a quiet reference machine above all).
- Metrics: soft-limit asks are not told apart from other `approval_required` decisions (that would need policy ids as labels).

Session 14 closes the proxy (the `http.GET` refusals), retention, AuthZEN and dry-run items above; [its open list](#session-14-security-pass-6-bounded-refusals-short-circuit-batches-wide-prunes-and-the-pruned-refund) supersedes this one.

### Session 14: security pass 6, bounded refusals, short-circuit batches, wide prunes and the pruned refund

The merges after Session 13, in the small hours of 2026-10-25 (#104 and #106 to #113), are mostly follow-ups: a security review found four things to fix, and most of session 13's open list got an answer. Lease refusals of undecided requests are now bounded like `stream.end` records. The flaky attenuation proptest had a wrong oracle, not a wrong `attenuate`. The maintenance cadence is configuration. AuthZEN batches can stop early, and the discovery document is public by decision. The dry run's `approval` block is strict and the console has a field for it. A very wide run is pruned over many short passes. A refund of a pruned charge says so. The per-value limits were measured again, and Cedar-aware list filtering has a proposed ADR. This session reads them in that order.

Read beside: [the pass 6 report](../research/security-review-2026-10-25-pass6.md) (each finding has an attack, the evidence and the fix; read the summary and SR-69 to SR-72), then [What gets a record](../concepts/audit-log.md#what-gets-a-record) in the audit-log concept for the refusal bound, [Batch semantics](../reference/authzen.md#batch-semantics) and [Discovery](../reference/authzen.md#discovery) on the AuthZEN page, [Policies: read, check, dry run](../reference/http-api.md#policies-read-check-dry-run) for the `approval` block, [Cost and limits](../concepts/leases-and-revocation.md#cost-and-limits) in the leases concept with [`[leases]`](../reference/config.md#leases) in the configuration reference, and [Budget refund](../reference/http-api.md#budget-refund) in the HTTP API reference. Keep [the per-value limits bench note](../design/bench/2026-10-25-vm-per-value-limits.md) and [ADR-0011](../decisions/0011-cedar-aware-list-filtering.md) for the end. The reasoning behind each change is in [the 2026-10-24 log](../log/2026-10-24.md), the post-midnight entries from 00:58 to 02:55 UTC at the top of the file.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-proxy/src/jsonrpc.rs` (`method_of`), `filter.rs` (`list_kinds_by_shape` near line 229, `ListFilter::apply_message`, `ListFilter::listed_tools`), `label.rs` (`Labeller::response_id` near line 321) | SR-69 (Medium, #104). Four places told a response from a request with `msg.get("method").is_some()`, so an upstream answer with `"method": null` beside its `result` skipped output labelling (no `tool_result`, no taint) and a list answer skipped the filter, while the Python MCP SDK reads such a message as the response. All four now ask `method_of(msg).is_some()`, which is `Some` only for a string `method`. A message with any other `method` is treated as a response, which can only add a record or remove list entries. | 1530 |
| 2 | `config/policies/default.cedar` (the file comment, `permit_create_issue_in_acme` near line 42, `permit_delete_acme_sandbox_repo`), `default_test.yaml` (the six cases marked `(SR-70)`) | SR-70 (Medium). `acme/..\evil\api` kept the `acme/<name>` shape, and a WHATWG URL parser (Node's `fetch`, Rust's `url`) reads `\` as `/`, `%2e%2e` as `..` and drops tabs and line breaks, so a tool building `/repos/{repo}/issues` left the organisation. Both repository rules now also refuse `\`, `%`, `?`, `#`, tab, LF and CR with `!(... like "*\\*")`-style guards. The crate's embedded copy is the same file (session 12, row 12). SR-73 accepts the same blind spot in a `prefix` constraint, which cannot know what a tool does with the string. | 500 |
| 3 | `crates/attenuo-core/src/capability.rs` (`range_admits_all_equal` near line 166, its two callers in `implies` near line 252) | SR-71 (Low). Constraints compare values canonically, so `equals 10^16` is also satisfied by the float `1e16`, which no `range` admits (`as_long` stops at 922337203685477). A child `equals 10^16` under a parent range up to `2*10^16` was accepted and let through a value the parent refuses. A member above that magnitude now implies a range only when no float equals it: when `jcs::format_f64(n as f64)` is not written with `n`'s digits. `2^53 + 1` and `i64::MAX` still imply `range {min: 0}`. | 1060 |
| 4 | `crates/attenuo-cli/src/render.rs` (`escape_controls` near line 35, `fmt_constraint`, `render_evaluation` near line 752) | SR-72 (Low). A child chooses the argument names of the constraints it adds, and `token inspect`, `lease tree` and the dry run's `capability_denied` diagnostic printed them raw. Control characters are now escaped (`\u{1b}`), and nothing else is touched. Limit names were already refused with control characters (SR-59); constraint names are still accepted, only printed safely. The console uses `textContent` and was not affected. | 1340 |
| 5 | `crates/attenuo-proxy/src/records.rs` (crate comment, `RecordWindow`, `Admission`, `DEFAULT_RECORD_WINDOW_MAX_KEYS` and `DEFAULT_RECORD_WINDOW` (`RECORD_WINDOW_MAX_KEYS` and `LEASE_REFUSAL_RECORD_WINDOW` until #121), `LEASE_REFUSAL_HTTP_TOOLS`, `is_lease_refusal_tool`) | #107. The `StreamEndRecords` of session 13 moved here as `RecordWindow`, keyed by (chain digest, fixed tool name, reason) instead of (chain digest, reason). Same rules: the window opens at the first record, the first is never replaced, concurrent occurrences admit exactly one, and a poisoned lock or a table full of open windows (`[proxy] record_window_max_keys`, default 10,000, since #121) records rather than suppresses. `Admission::Suppress { first }` carries the window's first record id, `None` only while that record is still being written. | 280 |
| 6 | `crates/attenuo-proxy/src/proxy.rs` (the two `RecordWindow` fields of `AppState` near line 126, `record_lease_refusal` near line 343, `refused_tool_name`), `guard.rs` (the stream-end table's use of the same window), `auth.rs` (`Authorizer::observe_record_suppressed`), `crates/attenuo-server/src/metrics.rs` (`record_suppressed` near line 1022) | Two tables, so a flood of one kind cannot fill the other's capacity: `stream_end_records` (unchanged behaviour) and `lease_refusal_records`, both 60 s by default and both built in `router` from `ProxyConfig::record_window` and `record_window_max_keys` since #121 (`[proxy] record_window_seconds`, 1 to 3600, and `record_window_max_keys`, 100 to 1,000,000; one setting for both tables). The first `LeaseInactive` refusal per key and window is recorded as in session 12. A later one is still a 401 with the same reason, but is a `warn` log line with `record_suppressed = true` and a count in `audit_records_suppressed_total{tool,reason}`, and its 401 names the window's first record in `X-Attenuo-Decision-Id` and `data.decision_id`. The eleven refusal tool names (`PASSTHROUGH_METHODS` plus `http.POST`, `http.GET`, `http.DELETE`) are a fixed set; their series appear once counted, so a dashboard must read a missing series as 0. Refused exchanges and renewals go through the server's routes and `tools/call` refusals are pipeline decisions: all three stay one record each. | 4510 |
| 7 | `crates/attenuo-core/tests/attenuation_props.rs` (`config` near line 31 since #116, `effect_free_clamp` near line 280, `covered_request_with_calls_below_parent_per_value_limit_is_clamped_without_effect` near line 671), `crates/attenuo-core/src/limits.rs` (`Limits::clamp_to` near line 358), `capability.rs` (the doc comment of `attenuate_with` near line 555) | #106. `attenuate_iff_covered_and_nonempty` failed about once in tens of thousands of cases. Its minimal input: a parent `distinct` of 0 on `y`, a request with `calls: 0` and `distinct` of 1 on `y`. `covers` accepts it because the request's `calls` is no larger than the parent's `max`, and `attenuate` lowers the request's per-value figure to the parent's. The bound in force per value, `min(calls, max)`, is the same before and after, so nothing widens. The oracle now accepts exactly that difference (`effect_free_clamp`) and nothing else. `PROPTEST_CASES` now reaches this file, which had hard-coded 512 cases; since #116 it does so through the shared `proptest_config` helper, which also takes `PROPTEST_RNG_SEED` (session 15). | 2200 |
| 8 | `crates/attenuo-server/src/config.rs` (`LeasesSection` near line 1018, `LeaseMaintenance` near line 1036, `LeasesSection::maintenance` near line 1136), `crates/attenuo-server/src/lib.rs` (`prune_in_passes` near line 210, `spawn_lease_maintenance` near line 334) | #106. `[leases] maintenance_interval_seconds` (default 60, at least 1), `maintenance_batch_rows` (1000, 1 to 100000) and `maintenance_max_passes` (100, 1 to 10000) replace session 13's three constants, which stay as the defaults. They are checked at startup whether or not a retention is on, with an error naming the key and the range, and read only at startup, not on reload. The rules of the passes did not change. | 3010 |
| 9 | `crates/attenuo-server/src/routes/authzen.rs` (`evaluate_batch` near line 105, `Semantic` near line 187, `Semantic::stops_at`), `routes/wellknown.rs`, `tests/fixtures/authzen/evaluations-deny-on-first-deny.json`, `evaluations-permit-on-first-permit.json`, `metadata.json`, `tests/authzen_conformance.rs` (`stopped_batch_audits_only_what_it_ran`) | #108. `options.evaluations_semantic` is parsed after the `max_batch` check and before authentication; an unknown value or a non-string is 400 `invalid_request`. Entries are decided in order. `deny_on_first_deny` stops after the first `decision: false` or failed entry, `permit_on_first_permit` after the first `decision: true` (a failure is not a permit). The entries after the stop are left out of the answer, as in the specification's examples, not answered as denied, and are never decided: no audit record, no charge, no approval used. The deciding entry keeps attenuo's own `reason`, so the answer matches its audit record. Discovery (`GET /.well-known/authzen-configuration`) is public like the JWKS and ignores an `Authorization` header. | 620 |
| 10 | `crates/attenuo-server/src/routes/policies.rs` (`approval_from_json` near line 482, `session_from_json` near line 503), `crates/attenuo-server/ui/view-policy.js` (`approvalFields` near line 360, `approvalResult` near line 444) | #109. The dry run's `approval` block takes only `by`; any other member is a 400 naming it, checked before `by`, so `{"approved_by": ...}` names the typo instead of saying `by` is missing. `{}` and `by: null` are "`by` is required", as an empty block was already refused before. `session` now checks unknown members first too. The console's "Approval" section is a select of `user`, `operator` and `policy`, closed by default; "not stated" sends no block, and the answer's Approval block says "stated in the request" or "none stated" (the dry run never reads a stored approval). | 1130 |
| 11 | `crates/attenuo-audit/src/lease.rs` (`LeasePrune::walked` near line 461, `PruneOps` near line 511, `LeasePruneState::before_revival` and `after_write` near line 564, `RunSweep` near line 596 and `RunSweep::advance` near line 671, `prune_pass` near line 749), `sqlite.rs` (`SqlitePrune` near line 2760, `prune_leases` near line 3566, the `before_revival` calls in renew and register) | #110. A lease pass spends at most `max_rows` rows in all: those its window examined, those it walked and those it deleted. One engine (`prune_pass`) serves both stores through `PruneOps`. A top that ended past the retention starts a `RunSweep`: walk the run breadth-first, a page of children at a time; the first lease that is live or ended within the retention ends the sweep with nothing deleted. Only once the whole run has been walked is it deleted, children before parents, the top last. A run that does not fit in a pass is continued first by the next one, held in memory beside the window cursor. Between passes, a write to a walked lease abandons the walk, and once deleting has begun a renewal or re-registration of the run is refused as `UnknownLease` (the revival guard). | 7340 |
| 12 | `crates/attenuo-server/src/routes/admin.rs` (`refund_budget` near line 378, `no_charge_refusal` near line 437, `CHARGE_PRUNED`), `crates/attenuo-cli/src/main.rs` (`budget_refund` near line 819, `refund_refusal`, `EXIT_CHARGE_PRUNED`) | #112. No tombstone table: when the store answers `UnknownCharge`, the route reads the decision's audit record (`entry_by_record_id`) and tells four cases apart (table below). Only the refusal path reads the log; the happy path and the 409 are unchanged, and the refusal writes nothing. The CLI gives 410 exit 4 and prints a 404's detail after `error:` (still exit 2). The SDKs have no refund helper, so a raw request sees the 410 as their generic `ApiError` with `code == "charge_pruned"`. | 2910 |
| 13 | `docs/design/bench/2026-10-25-vm-per-value-limits.md`, the section [Per-value limits on current main](../design/performance.md#per-value-limits-on-current-main-2026-10-25) of the performance page | #113. `calls_per` and `distinct` measured again on current main (after pass 5's run lock and SR-62's zero-amount charge rows and second charge-log index), with both kinds on one capability, a host `calls_per` and `distinct` on a list. Read the summary, the deltas table and "One level down". | 850 |
| 14 | `docs/decisions/0011-cedar-aware-list-filtering.md`, `docs/design/cedar-aware-list-filtering.md` | #111, docs only and **proposed**: the maintainer decides. The recommendation is an opt-in `[proxy] list_filter = "policy"` that hides a tool only when the catalog stage denies it or Cedar's experimental partial evaluation returns a deny for every possible call, with call-time context unknown and approval forbids lifted, so approval-gated tools stay listed. Nothing is built; the costs (2 to 5 ms per warm 200-tool list) are estimates from existing figures. | 180 |

What a refund of a decision with no charge left in the store answers since #112 (`no_charge_refusal`):

| The decision's audit record | Answer | CLI line and exit status |
| --- | --- | --- |
| an allowed `decision` with a `budget` member: it charged run-limit counters, and only run-state pruning removes such a charge log entry | 410 `charge_pruned`, detail naming the decision and `run_state_retention_seconds` | "the charge of decision ... was pruned ...; it can no longer be refunded", exit 4 |
| an allowed `decision` with `usage` and no `budget`: run usage only, which a revocation of the run drops as well as pruning, so the record cannot say which | 404 `not_found`, "charged no run limit, only run usage, which is no longer recorded ..." | the detail, exit 2 |
| any other record (a denial, an allowed call with neither member, another kind) | 404 `not_found`, "charged nothing ..." | the detail, exit 2 |
| no record with that id, or not a UUID | 404 `not_found`, "unknown decision ..." | the detail, exit 2 |

None of the four carries a `decision_id` or `X-Attenuo-Decision-Id`, since nothing new was audited. A refunded and then pruned charge also answers 410, not 409; its refund is in the `admin.budget.refund` records.

What a retrying revoked client leaves in the log, before and after #107 (one chain, one minute):

| Request | Before | After |
| --- | --- | --- |
| `initialize` five times | five `deny` records of `github/initialize` | one record; the other four 401s name it and count in `audit_records_suppressed_total{tool="initialize",reason="lease_revoked"}` |
| a `tools/list` and a `GET` next | one record each | one record each: another tool name is another window |
| the same chain, now `lease_expired` | one record per request | one record: another reason is another window |
| another chain of the same run (a sub-agent) | one record per request | its own window: the key is the chain digest, not `chain_id` |
| `POST /token/renew` or `/token` refused, or a `tools/call` refused | one record each | one record each: decided requests are never bounded |

Why each piece is shaped this way:

- **A non-string `method` makes a response, not a request.** The choice that fails safe is the one that runs more checks. Treating a doubtful message as a response can add a `tool_result` record or remove list entries; treating it as a request skipped both. A message with a string `method` and a `result` is still left alone, because clients read it as a request.
- **The starter policy refuses characters, not parsers.** The policy cannot know which URL parser a tool uses, and GitHub names never hold `\`, `%`, `?`, `#` or control characters. Refusing them holds whatever the parser (Go's `net/url` does not read `\` as `/`, Node's does). A `prefix` constraint keeps the blind spot (SR-73): it is a plain string prefix, and the guide already prefers `equals` or `one_of` for a whole name.
- **SR-71 is about the type, not the bounds.** `1e16` is numerically inside the parent's range; what gets through is a float the range refuses. The fix compares canonical forms because that is how constraints compare values everywhere else.
- **One window type, two tables.** Lease refusals of undecided requests and listen-stream ends are the same problem: a client or a set of streams repeating one condition. One type keeps the rules identical; two tables keep a refusal flood from evicting stream windows or the reverse. The tool name is in the key so that a `GET` after an `initialize` still leaves a record of its own: the log shows every kind of request the client tried.
- **The 401 still names a record.** A suppressed refusal points at the window's first record, so a client that logs decision ids still has one it can give an operator. Only in the moment between a concurrent first refusal's admission and its write is the id unknown, and then it is left out rather than invented; since #128 (SR-81) it is also left out, and no window opens, when the audit append itself failed (`record_rejection_checked` returned `None`, `RecordWindow::forget`).
- **The oracle was wrong, not `attenuate`.** RFC-0001's rule 3 lets a request with a `calls` below the parent's per-value `max` through, and `clamp_to` then lowers its per-value figure to the parent's; nothing the token permits changes. The test now encodes that, with a deterministic case for the shape and its near misses, rather than making `attenuate` return the request unchanged.
- **Maintenance knobs, checked at startup.** The constants were open as configuration since session 13. A bad value refuses to start (a zero batch would never prune); a value is not reloaded, because the ticker is started once.
- **Omit, do not deny.** Section 7.1.2.1's text only says "short-circuiting"; its examples answer three requests with two entries and with one. Answering the rest as denied would invent decisions that were never made and have no audit record behind them. So the answer is shorter than the request, and each entry in it has the `decision_id` of a real record.
- **Discovery stays public.** A PEP needs the document before it knows where to send credentials, the specification's example request has none, and the document holds only the base URL and two fixed paths. An invalid bearer therefore gets the document, not a 401.
- **Strict override blocks.** A typo in a dry run's `approval` used to be ignored, so `approved_by` read as "no approval" and the dry run quietly answered a different question. Every override block now refuses unknown members before reading known ones.
- **Walk the whole run, then delete children first.** Nothing in a pruned run is live, before, during or after: every lease in it has ended, and the top stays until the last pass, so a check sees `lease_revoked` or `lease_expired` while rows remain and `lease_unknown` once they are gone, never a child without its parent row. Deleting top-first would orphan children mid-prune, and hiding the whole run at once would have needed every reader to filter rows. Deleting nothing until the walk ends means a run kept because one lease is live loses nothing. Measured on a run of 50,000 leases, the longest pass went from about 320 ms to tens of ms (bounded by WAL checkpoints), at the price of more passes.
- **The revival guard.** Once deletion began, the run was found prunable as a whole; letting a renewal bring back part of it would leave a live lease whose ancestors are being deleted. Before deletion, a write simply abandons the walk and the run is decided again later, as a renewal inside one transaction would have kept it.
- **The refund reads the audit log, which already keeps everything.** A tombstone table would be one more thing to prune. The record's `budget` member is set exactly when a call charged run-limit counters, and such a charge leaves the log only by run-state pruning, so "budget present, charge gone" means pruned. Run usage cannot be told apart that way, and the route says so rather than guessing.
- **The `calls` figure moved, and nobody changed `calls`.** The charge transaction grew from about 70 to 90 us, most likely from SR-62's second charge-log index, and `baseline` itself got faster, which widens the delta. So the README and these pages now quote +210 to +270 us at the client p50, not the +120 to +190 us measured on 2026-10-24 (#53).

Check you understood:

1. An upstream answers an allowed `read_file` with `{"jsonrpc":"2.0","id":1,"method":null,"result":{...}}`. Before SR-69, what did the proxy skip and what would a Python MCP client do with the answer? What does it do now, and why is that the safe direction?
2. Under a parent `range {min: 0, max: 20000000000000000}`, which of these children does the exchange accept: `equals 10000000000000000`, `equals 9007199254740993`, `equals 2000`? Which function decides?
3. A client keeps calling `initialize` on a revoked lease for three minutes, once a second, then tries `tools/list` once. How many audit records are written, what decision id does each 401 carry, and where is the rest counted? What changes if it calls `POST /token/renew` instead?
4. A batch of three under `deny_on_first_deny` has a deny in the middle. How many entries are in the answer, how many audit records are written, and what would answering the third as "denied" have got wrong? What does `permit_on_first_permit` answer for the same batch?
5. A run of 50,000 leases ended a month ago, and an operator renews its root token's lease (the token is still valid) while the maintenance task is walking it, then again once deleting has begun. What does each renewal get, and what does a call with a leaf's token get during the walk, during deletion and after?
6. An operator refunds four decisions: a charged call of a pruned run, a denial, a usage-only call of a revoked run, and a mistyped id. What does each answer, with which CLI exit status, and which one cannot say whether its run was pruned?
7. A token carries `distinct` on a list argument and the agent sends 256 new values in one call. About how long does the call take, where does the time go, and what does it hold up for others meanwhile?

Run it. Start from the section 0 setup with `fake_mcp` running and `ATTENUO_SERVER` and `ATTENUO_ADMIN_TOKEN` exported. The block starts its own server on a copy of the demo config with a metrics listener (port 19100), restarts it with tiny retentions in part 6, and ends on the plain demo config.

```sh
pkill -x attenuo-server; sleep 1
T=$(mktemp -d)
cp examples/github-leak-demo/config.toml $T/walk14.toml
printf '\n[metrics]\nenabled = true\nlisten = "127.0.0.1:19100"\n' >> $T/walk14.toml
RUST_LOG=warn attenuo-server --config $T/walk14.toml > $T/server.log 2>&1 &
sleep 2

# 1. Security pass 6: the four fixes by their regression tests, then three of them live.
cargo test -p attenuo-proxy --lib sr69     # a null method hides neither a list answer nor a result: 2 passed
cargo test -p attenuo-core --lib sr71      # equals_a_large_integer_implies_a_range_only_when_...: 1 passed
cargo test -p attenuo-cli sr72             # constraint_names_and_diagnostics_escape_control_characters_sr72: 1 passed
P='{"server":"github","tool":"read_file","constraints":{"n":{"op":"range","value":{"min":0,"max":20000000000000000}}}}'
R=$(attenuo token root --subject alice --agent assistant --cap "$P" --print token)
printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R" attenuo token exchange --actor coder --client-secret-stdin \
  --cap '{"server":"github","tool":"read_file","constraints":{"n":{"op":"equals","value":10000000000000000}}}'
# error: server answered 400 Bad Request: invalid_scope: delegation chain is invalid: hop 1 widens capabilities
#   relative to hop 0: requested capability `github:read_file{n={"op":"equals","value":10000000000000000}}` is not
#   covered by the parent capability set
# decision <uuid>                                    (1e16 equals it, and no range admits that float)
printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R" attenuo token exchange --actor coder --client-secret-stdin \
  --cap '{"server":"github","tool":"read_file","constraints":{"n":{"op":"equals","value":2000}}}' --print token | cut -c1-20
# eyJ0eXAiOiJhdHRlbnVv                               (a small integer is still narrower)
R=$(attenuo token root --subject alice --agent assistant \
  --cap '{"server":"github","tool":"read_file","constraints":{"x\u001b[2Jy":{"op":"equals","value":1}}}' --print token)
attenuo token inspect "$R" | grep ' can '
#      can   github:read_file {x\u{1b}[2Jy == 1}       (the escape sequence that would clear the screen, printed escaped)
attenuo policy test config/policies/default_test.yaml | grep -E 'SR-70|passed'
#   ✓ a backslash path that climbs out of the acme organisation is denied (SR-70)  (deny: policy_deny)
#   ✓ a percent-encoded dot segment is denied (SR-70)  (deny: policy_deny)
#   ... a percent-encoded slash, a tab inside the name, a query or fragment, and with MFA a backslash out of the sandbox
# 40 passed, 0 failed (40 cases in 1 file)

# 2. A revoked client retrying: one record per chain, tool and reason a minute; decided requests are not bounded.
cargo test -p attenuo-proxy --lib records::                  # the window's rules: 5 passed
cargo test -p attenuo-proxy --test proxy window              # retried opens leave one record; a new window records: 2 passed
ROOTJ=$(attenuo --json token root --subject alice --agent assistant --cap 'github:*')
R=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
L=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lease"])')
C=$(printf '%s\n' demo-coder-secret | ATTENUO_TOKEN="$R" \
  attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)
attenuo lease revoke --chain-id "$L" --reason "retry drill" | grep revoked      # revoked 2 lease(s)
open() { curl -s -i -X POST $ATTENUO_SERVER/mcp/github -H "Authorization: Bearer $C" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$1" \
  | grep -i -E '^HTTP|^x-attenuo-decision-id' | tr -d '\r' | paste -sd' '; }
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}'
for i in 1 2 3 4; do open "$INIT"; done
# HTTP/1.1 401 Unauthorized x-attenuo-decision-id: 01a07589-...      four times, the same id
open '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
# HTTP/1.1 401 Unauthorized x-attenuo-decision-id: ab9caf02-...      another tool, its own record
for i in 1 2; do curl -s -X POST $ATTENUO_SERVER/token/renew -H "Authorization: Bearer $C"; echo; done
# {"error":"invalid_grant","detail":"an ancestor lease is not live: lease_revoked","decision_id":"941eada0-..."}
# {"error":"invalid_grant","detail":"an ancestor lease is not live: lease_revoked","decision_id":"f03912ac-..."}
attenuo audit tail --decision deny
# #3   ... DENY  attenuo/token.exchange  assistant for alice          reason=exchange_widening  (part 1)
# #11  ... DENY  github/initialize       assistant > coder for alice  reason=lease_revoked  id=01a07589-...
# #12  ... DENY  github/tools/list       assistant > coder for alice  reason=lease_revoked  id=ab9caf02-...
# #13  ... DENY  attenuo/lease.renew     assistant > coder for alice  reason=lease_revoked
# #14  ... DENY  attenuo/lease.renew     assistant > coder for alice  reason=lease_revoked
curl -s http://127.0.0.1:19100/metrics | grep -E '^attenuo_audit_records_suppressed_total\{tool="(initialize|tools/list|lease.renew)"'
# attenuo_audit_records_suppressed_total{tool="initialize",reason="lease_revoked"} 3      (no series for the others)

# 3. The proptest oracle, and the maintenance settings.
cargo test -p attenuo-core --test attenuation_props covered_request     # the clamp shape and its near misses: 1 passed
PROPTEST_CASES=20000 cargo test -p attenuo-core --test attenuation_props attenuate_iff   # 1 passed in about 8 s
cargo test -p attenuo-server --lib maintenance   # defaults and bounds, refusal at startup, smaller batches: 3 passed

# 4. AuthZEN: a batch that stops early, and discovery.
cargo test -p attenuo-server --test authzen_conformance   # fixtures, comparator, stopped_batch_audits_only_what_it_ran: 3 passed
ls crates/attenuo-server/tests/fixtures/authzen/ | wc -l  # 29
R=$(attenuo token root --subject alice --agent assistant --cap 'github:read_file' --print token)
B='{"subject":{"type":"agent","id":""},"action":{"name":"read_file"},"resource":{"type":"tool","id":"github/read_file"},
 "context":{"input":{"repo":"alice/public-docs","path":"a"}},
 "evaluations":[{},{"context":{"input":{"repo":"bob/private","path":"a"}}},{}]'
show() { python3 -c 'import json,sys; print([(e["decision"], e["context"]["reason"]) for e in json.load(sys.stdin)["evaluations"]])'; }
for s in execute_all deny_on_first_deny permit_on_first_permit; do
  curl -s $ATTENUO_SERVER/access/v1/evaluations -H "Authorization: Bearer $R" -H 'Content-Type: application/json' \
    -d "$B,\"options\":{\"evaluations_semantic\":\"$s\"}}" | show
done
# [(True, 'policy_allow'), (False, 'policy_deny'), (True, 'policy_allow')]
# [(True, 'policy_allow'), (False, 'policy_deny')]
# [(True, 'policy_allow')]
attenuo audit tail -n 50 | grep -c 'github/read_file'     # 6: three, two and one; the entries not reached left nothing
curl -s $ATTENUO_SERVER/access/v1/evaluations -H "Authorization: Bearer $R" -H 'Content-Type: application/json' \
  -d "$B,\"options\":{\"evaluations_semantic\":\"first_deny\"}}"; echo
# {"error":"invalid_request","detail":"evaluations_semantic `first_deny` is not supported; use `execute_all`,
#   `deny_on_first_deny` or `permit_on_first_permit`"}
curl -s -i $ATTENUO_SERVER/.well-known/authzen-configuration -H 'Authorization: Bearer garbage' \
  | grep -i -E '^HTTP|^content-type|^\{'
# HTTP/1.1 200 OK
# content-type: application/json
# {"policy_decision_point":"http://127.0.0.1:18080","access_evaluation_endpoint":"http://127.0.0.1:18080/access/v1/evaluation",
#  "access_evaluations_endpoint":"http://127.0.0.1:18080/access/v1/evaluations"}      (the bearer is ignored)

# 5. The dry run's strict approval block.
cargo test -p attenuo-server --test admin_policies dry_run_override   # every override block refuses unknown members: 1 passed
ev() { curl -s $ATTENUO_SERVER/admin/policies/evaluate -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d "{\"token\":\"$R\",\"subject\":{\"type\":\"agent\",\"id\":\"\"},
  \"action\":{\"name\":\"create_issue\"},\"resource\":{\"type\":\"tool\",\"id\":\"github/create_issue\",\"properties\":{\"server\":\"github\"}},
  \"context\":{\"input\":{\"repo\":\"alice/public-docs\",\"title\":\"hi\"}}$1}"; echo; }
R=$(attenuo token root --subject alice --agent assistant --cap 'github:*' --print token)
ev ',"approval":{"approved_by":"operator"}'
# {"error":"invalid_request","detail":"`approval`: unknown member `approved_by`"}
ev ',"approval":{}'
# {"error":"invalid_request","detail":"`approval`: `by` is required (\"user\", \"operator\" or \"policy\")"}
ev ',"approval":{"by":"operator"}' | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a["reason"], a["approval"])'
# policy_allow {'present': True, 'by': 'operator'}
ev '' | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a["reason"], a["approval"])'
# approval_required {'present': False, 'by': ''}

# 6. Wide prunes by their tests; then a pruned charge refunded, with the maintenance interval at 2 s.
cargo test -p attenuo-audit --test leases wide_run   # over several passes never partly live; writes during the walk;
                                                     # cannot be revived once deleting: 3 passed
pkill -x attenuo-server; sleep 1
cp $T/walk14.toml $T/bad.toml
printf '\n[leases]\nmaintenance_batch_rows = 0\n' >> $T/bad.toml
attenuo-server --config $T/bad.toml 2>&1 | grep -m1 maintenance_batch_rows; echo "exit ${PIPESTATUS[0]}"
# Error: [leases] maintenance_batch_rows must be between 1 and 100000, not 0
# exit 1
cp $T/walk14.toml $T/prune.toml
cat >> $T/prune.toml <<'EOF'

[leases]
retention_seconds = 1
session_retention_seconds = 1
run_state_retention_seconds = 1
maintenance_interval_seconds = 2
EOF
RUST_LOG=warn attenuo-server --config $T/prune.toml > $T/server.log 2>&1 &
sleep 2
ROOTJ=$(attenuo --json token root --subject alice --agent assistant \
  --cap '{"server":"github","tool":"read_file","limits":{"calls":5}}')
R=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
L=$(printf '%s' "$ROOTJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lease"])')
ATTENUO_TOKEN="$R" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=a | head -1  # ALLOWED
ATTENUO_TOKEN="$R" attenuo call --server github --tool read_file --arg repo=bob/private --arg path=a | head -1  # DENIED  policy_deny
ids() { attenuo --json audit tail -n 5 | python3 -c 'import json,sys
r = [json.loads(l)["record"] for l in sys.stdin if l.strip()]
print([x for x in r if x["kind"] == "decision" and x["decision"] == sys.argv[1]][-1]["id"])' "$1"; }
D=$(ids allow); X=$(ids deny)
attenuo lease revoke --chain-id "$L" --reason "refund drill" | grep revoked     # revoked 1 lease(s)
until curl -s http://127.0.0.1:19100/metrics | grep -q '^attenuo_run_state_pruned_total{kind="charges"} [1-9]'; do sleep 1; done
curl -s http://127.0.0.1:19100/metrics | grep -E '^attenuo_(leases_pruned|run_state_pruned)_total'
# attenuo_leases_pruned_total 1
# attenuo_run_state_pruned_total{kind="counters"} 1
# attenuo_run_state_pruned_total{kind="charges"} 1
# attenuo_run_state_pruned_total{kind="approvals"} 0              (a few seconds, not a minute: the interval is 2 s)
attenuo budget refund "$D" --reason late; echo "exit $?"
# error: the charge of decision <D> was pruned ([leases] run_state_retention_seconds after its run ended); it can no
#   longer be refunded
# exit 4
attenuo budget refund "$X" --reason late; echo "exit $?"
# error: decision `<X>` charged nothing: its audit record shows no run limit or run usage charged; nothing to refund
# exit 2
attenuo budget refund 3f2a8c1e-0000-4000-8000-000000000000 --reason late; echo "exit $?"
# error: unknown decision `3f2a8c1e-0000-4000-8000-000000000000`: no audit record has this id; nothing to refund
# exit 2
curl -s -i $ATTENUO_SERVER/admin/budgets/refund -H "Authorization: Bearer $ATTENUO_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d "{\"decision_id\":\"$D\",\"reason\":\"late\"}" | grep -E '^HTTP|^\{'
# HTTP/1.1 410 Gone
# {"error":"charge_pruned","detail":"the charge of decision `<D>` was pruned: its run's leases are gone and the charge
#   is older than [leases] run_state_retention_seconds, so it can no longer be refunded (its audit record keeps what it charged)"}
attenuo audit verify            # audit chain OK: 6 entries verified; the refusals wrote nothing
pkill -x attenuo-server; sleep 1            # back to the demo config for the other sessions:
RUST_LOG=warn attenuo-server --config examples/github-leak-demo/config.toml > /tmp/ob-server.log 2>&1 &
```

Every command in the block was run in this order against `main` @ 9d16340 on 2026-10-25, with debug binaries, on a freshly started server and `fake_mcp`, and prints what is quoted, the test counts included; ids, leases and times differ on every run. Two lines differ from the first run in a harmless way: the server with the bad batch size was first run with `| tail -1`, which in a shell with `RUST_BACKTRACE=1` printed the last line of a backtrace, so it was run again with the `grep` shown (the server refuses to start either way and changes nothing); and the audit count in part 4 was first run as `audit tail -n 6 | grep -c`, which counts six lines whatever they hold, so it was run again as shown on the same log, to which nothing had been appended since. Not shown live, and where to look instead:

- The 60 s window closing: `a_new_window_records_the_next_lease_refusal` in `crates/attenuo-proxy/tests/proxy.rs` runs with a 400 ms window (set through `ProxyConfig::record_window` since #121). The server-side count, with refused renewals and exchanges still one record each, is `retried_initialize_on_a_revoked_lease_leaves_one_record` in `crates/attenuo-server/tests/e2e.rs`.
- A wide run being pruned, what a check sees mid-prune and the revival guard: the three `wide_run` tests in part 6 (passes of 7 over a run of 111 leases; a lease pass on the demo store has nothing wide to walk). The figures for 50,000 leases come from a throwaway release test, not committed, quoted in the log entry.
- SR-69 needs an upstream that answers with a non-string `method`, which `fake_mcp` does not: the two `sr69` tests.
- The usage-only 404: the demo policy reads no `context.usage`, so nothing is tracked. `usage_is_refunded_with_the_decision_and_deleted_with_the_run` in `crates/attenuo-server/tests/run_usage.rs` refunds one after its run was revoked. `run_state_of_pruned_runs_is_pruned_past_its_retention` in `tests/approvals.rs` checks the 410 and both other 404s with a clock moved back.
- The console's Approval section: `policy page: a dry run with a stated approval` in `tests/console/console.test.cjs`, run by `scripts/console-smoke.sh` (not run for this page).
- The per-value limits figures: `attenuo-bench hot-path` and `cargo bench`, with the rerun commands at the end of the bench note (not run for this page, as for the other benchmarks).

The figures of row 13, in short (client p50 over no limit, one client, file store, two passes): a `calls` limit now costs +210 to +270 us (it was +120 to +190 us when #53 measured it on 2026-10-24), `calls_per` +205 to +334 us, `distinct` with a new value +413 to +456 us and with a seen value +177 to +355 us (no longer free: SR-62 makes it write), both on one capability +565 to +612 us with new values. `distinct` on a list costs about 50 to 56 us per new value per hop in the charge transaction: +2.3 to +2.4 ms at 16 values and +34 to +36 ms at 256 (`MAX_COUNTED_VALUES`), with a p99 of 0.66 to 0.69 s, most likely the WAL checkpointer behind 5.2 MiB of WAL per call. For those 25 to 29 ms the write gate is held, so no other decision can charge or append.

What is still open after this session (from the [task board](../tasks/board.md) and the logs of these merges; this list supersedes session 13's):

- Release: 0.1.0 waits on the maintainer (Actions billing, the tag, making the repository public, the package names, the manual publishes).
- Constraints: time ranges; no `--constraint` shorthand on the CLI; a range covering a small `one_of` is refused; the fuzz targets that generate ranges were type-checked, not run; a `prefix` constraint keeps the URL-parser blind spot of SR-70 (SR-73, accepted). In the token claims, `evidence` on the originating user and a stable `chain_id` are still to be reconciled or dropped.
- Revocation and leases: revoking by the audit `session_tag`; the optional proxy lease cache; a lost session binding is only a log line. The maintenance settings are read at startup, not on reload. A wide run's sweep state lives in the store value, so a second process writing the same file is covered only by the re-read before each delete; a run kept because one lease is live is walked again on every sweep.
- Refunds: a usage-only decision whose usage is gone stays 404, since revoked and pruned cannot be told apart from the record; a duplicate refund of a pruned decision is told from a first only by reading the `admin.budget.refund` records, whose decision id is in the argument digest. The SDKs have no refund helper.
- Proxy: Cedar-aware list filtering waits on a decision about [ADR-0011](../decisions/0011-cedar-aware-list-filtering.md) (whether an experimental Cedar feature is acceptable, whether a spent hard limit should hide a tool, `notifications/tools/list_changed` after a reload, a bench of partial evaluation). Both record windows are constants (settings since #121: `[proxy] record_window_seconds` and `record_window_max_keys`, read at startup only); a suppressed record's count is in the metric and the log only; the lease-refusal series appear only once counted. A large non-list event on the listen stream costs about 0.7 ms per 85 KB to parse and re-serialize.
- AuthZEN: the Search APIs and discovery `capabilities` and `signed_metadata` are not implemented; error bodies stay JSON objects ([AuthZEN conformance](../reference/authzen.md#not-implemented)).
- Dry run: offline `policy test` does not enforce chain limits; the route ignores unknown top-level members, as the AuthZEN request it extends does.
- Run limits: a `distinct` list of 256 new values holds the write gate for about 28 ms (fewer rows per value, batched inserts or a lower `MAX_COUNTED_VALUES` are open); the per-value kinds are not measured under concurrent clients, at `durability = "full"` end to end or on the memory store end to end.
- Server and identity: real admin authentication; actor tokens against a live SPIRE; hop-0 hardening (a shared replay cache, `private_key_jwt`, ID-JAG drafts).
- SDKs: publishing to PyPI and npm (prepared since #118, with the publish itself the maintainer's step), streaming responses (`call_tool_stream` and `callToolStream` since #115; both in session 15), hop-0 against a live IdP; one intermittent Python integration failure (`test_dpop_server_nonce`, suspected) is still being watched.
- Evaluation and performance: the remaining test-split cases and a model in the loop; the injection suite's `stage_of` in `evaluation/injection-suite/harness.py` still does not know `input_type_mismatch`; run limits phase 3; the open benchmark and performance items on the board (a quiet reference machine above all).
- Metrics: soft-limit asks are not told apart from other `approval_required` decisions (that would need policy ids as labels).

Session 15 closes the SDK streaming item above and prepares the publishing; [its open list](#session-15-streamed-answers-the-proxys-voice-reproducible-properties-and-the-road-to-pypi-and-npm) supersedes this one.

### Session 15: streamed answers, the proxy's voice, reproducible properties and the road to PyPI and npm

The five merges after Session 14, early on 2026-10-25 (#115 to #119), finish things the earlier sessions left half done. Both SDKs can now read a `tools/call` answer as it streams, and `fake_mcp --sse` streams one for them to read. Streaming showed a gap: the SDKs read the proxy's stream-end event as a cut, and an upstream could send that same shape. So the proxy now rewrites any upstream message in its own stream-end shape (#117), and a byte scan keeps that check off most events (#119). Property tests take one seed policy: pinned in CI, random and printed locally (#116). The Python and npm packages are ready to publish from one workflow, which publishes nothing until the maintainer asks it to (#118). This session reads them in that order.

Read beside: "Streaming a call" in `sdk/python/README.md` and in `sdk/typescript/README.md`, and the "Streamed answers" paragraph under [Handling `DENIED` responses](../guides/integrating-mcp-clients.md#handling-denied-responses) in the integration guide. Then the `stream.end` paragraph of [What gets a record](../concepts/audit-log.md#what-gets-a-record) in the audit-log concept, which now ends on the rewrite, and the "Look-alike stream ends" item under [Residual risks to track](../spec/threat-model.md#residual-risks-to-track) in the threat model. Then [the stream-end shape bench note](../design/bench/2026-10-25-vm-sse-disown.md) (the method, "The change" and "Readings"), the "Property tests" subsection of `CONTRIBUTING.md`, and [step 6 of the 0.1.0 release](../release/0.1.0.md#6-publish-the-sdks). The reasoning behind each change is in [the 2026-10-24 log](../log/2026-10-24.md), in the entries from 03:20 to 03:57 UTC near the top of the file.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `sdk/python/src/attenuo/_sse.py` (`_STREAM_END_REASONS` near line 32, `_UUID` near line 43, `SseParser` near line 57, `SseParser.feed` near line 79, `StreamEvent` near line 174, `_is_stream_end` near line 202, `stream_end_error` near line 216, `CallStream` near line 242 and `CallStream._message` near line 296) | #115. An incremental SSE parser with no I/O. It handles LF, CRLF and CR line ends (a CR at the end of a read waits for the next byte), joins `data:` lines with `\n`, ignores comments, `event:` and `retry:`, and keeps `id:` across events for `Last-Event-ID`. It strips an opening BOM, decodes strict UTF-8 and drops a final event that has no blank line after it. Since #125 (SR-82) each read is searched for line ends once and an unfinished line is kept as a list of chunks joined when its end arrives, so a long line in small reads is linear, as in TypeScript (1 MiB in 1 KiB reads: 4 s to 10 ms). One bound, `DEFAULT_MAX_EVENT_BYTES` (16 MiB, the proxy's `max_upstream_body_bytes` default), covers an event and an unfinished line. `CallStream` turns events into `StreamEvent`s. A message with a `method` is passed on. So is a response with another id. A response in the proxy's stream-end shape (no `method`, `id` null or absent, `error.code` `-32001`) raises `Denied` only when `data.reason` is one of the six reasons the proxy sends (`token_expired`, `lease_revoked`, `lease_expired`, `lease_unknown`, `lease_error`, `unauthorized`) and `data.decision_id` is absent or a hyphenated UUID; anything else of that shape raises `RpcError` `-32001`, which ends the call but is not a decision (#123). The response to the call goes through the same `rpc_result` as `call_tool` and ends the stream. | 240 |
| 2 | `sdk/python/src/attenuo/client.py` (`Client.call_tool_stream` near line 229, `Client._stream` near line 277, `AsyncClient.call_tool_stream` near line 586 and `AsyncClient._stream` near line 617), `_wire.py` (`rpc_result` near line 415) | The same `POST`, headers and DPoP proof as `call_tool`, sent with `httpx` `stream=True`. A 400 or 401 body is read so that `NonceCache` can see `use_dpop_nonce`, and the request is retried once. A response that is not SSE, or is an error status, is read whole (up to the bound) and becomes one final event or the exception `call_tool` raises. Argument errors are raised at the call; the request goes out on the first `next`. The response is closed in a `finally`, so leaving the loop early closes the connection once the generator is closed or collected. The client's `timeout` is per read, so a stream that keeps sending is never cut by it; since #126 (SR-82) the keyword-only `deadline=` seconds bounds the whole stream from the request start, checked between reads, and ends it with `AttenuoError` naming the deadline. The async variant is an async generator (`async for`, no `await`). | 760 |
| 3 | `sdk/typescript/src/sse.ts` (`STREAM_END_REASONS` near line 27, `UUID` near line 37, `SseParser` near line 62, `StreamEvent` near line 170, `streamEndError` near line 202, `callStream` near line 244) | The same parser and the same rules, including the reason-and-UUID test for a cut (#123). An unfinished line is kept as a list of chunks and joined once, so a long line arriving in small reads is not quadratic. `callStream` reads the body with a reader and calls `onChunk` after each read. A `finally` cancels the reader whenever iteration stops early (a `break`, a refusal, an error). | 280 |
| 4 | `sdk/typescript/src/client.ts` (`CallToolStreamOptions` near line 56, `callToolStream` near line 276, the private `stream` near line 299), `http.ts` (`timeoutMs` near line 22, the `signal` option of `Http.request` near line 39) | `callToolStream` returns an `AsyncIterable`, and the request goes out when iteration starts. `Http.request` takes a `signal` that replaces its whole-request `AbortSignal.timeout`. `stream` makes one `AbortController` for the caller's `signal` and for an idle timer of `timeoutMs`, restarted on every read. A stream that keeps sending is therefore never cut at 30 s, and one that goes quiet for 30 s is; since #126 (SR-82) `deadlineMs` arms a second timer on the same controller that aborts the fetch and throws `AttenuoError` naming the deadline, whatever the upstream sends. `Http.timeoutMs` is now public and read-only. | 510 |
| 5 | `crates/attenuo-proxy/examples/fake_mcp.rs` (the crate comment, `held_sse` near line 94, `log_calls` near line 109 reading `hold_ms` near line 121, `--sse` in `main` near line 192), `testing.rs` (`with_sse_event_per_response` near line 262, `with_sse` near line 268) | `FakeMcpServer` could already stream; the example could not. `--sse` answers every request as `text/event-stream`: a `notifications/message` event, then the response with an `id:` field. A `tools/call` whose arguments hold `"hold_ms": N` gets the first event at once and the rest N ms later (`held_sse` cuts the body at the first blank line), so a test can revoke the lease while the stream is open. Without `--sse` the demo, the bench and the injection suite see the same upstream as before. | 220 |
| 6 | `crates/attenuo-proxy/src/guard.rs` (`end_event_recorded` near line 360, `REASON_UPSTREAM_STREAM_END_SHAPE` near line 376, `has_stream_end_shape` near line 386, `disown_stream_end` near line 407; tests `the_proxys_own_end_event_has_the_protected_shape` and `stream_end_shape_is_null_id_minus_32001_and_no_method` near lines 716 and 725) | #117. The protected shape is a response (no `method` member) whose `id` is `null` or absent and whose `error.code` is `-32001` by value (`as_f64`, so `-32001.0` counts, as it does in Python and JavaScript). That is the SDKs' own test without its check of `data.reason`, so nothing they would read as a cut gets through. A unit test checks that the proxy's own `end_event_recorded` has the shape, which ties the rule to the event. `disown_stream_end` rewrites each matching message, alone or in a batch. Its `error` becomes `-32005` (`CODE_UPSTREAM`) with `data.reason` `upstream_stream_end_shape` and the upstream's whole error object under `data.upstream_error`. The `id` stays `null`, and each rewrite is a `warn` line without the upstream's text. A `-32001` that answers the request by its id is left alone. | 1120 |
| 7 | `crates/attenuo-proxy/src/proxy.rs` (`buffer_and_rewrite` near line 1614, its `disown_stream_end` call near line 1681; `stream_response` near line 1768, its guarded SSE branch near line 1785; `stream_response_sse` near line 1803, the filter closure near line 1826 and the framed branch near line 1829), `sse.rs` (`rewrite_event` near line 186, now `pub(crate)`) | The three rewrite points, all places that already parse upstream messages. (1) A buffered JSON answer (every `POST` with a mediated call or a list request): after the list filter, before labelling. (2) A labelled `POST` answer or the `GET` listen stream (`stream_response_sse`): inside the list filter's closure when there is one, so each event is still parsed once, and otherwise over the framed events (`disown_stream`). Both run before the labeller and before the guard appends its own final event. (3) The guarded SSE branch of `stream_response` (other `POST` answers, error statuses on `GET`) runs the framed events through the same function. A rewritten event keeps its `id:` and `event:` fields; every other event goes out byte for byte. | 1980 |
| 8 | `crates/attenuo-proxy/src/testing.rs` (`with_stream_end_lookalike` near line 196, `LOOKALIKE_DECISION_ID` and `stream_end_lookalike` near line 409), `tests/stream_end_lookalike.rs` (`assert_disowned` near line 60, `a_lookalike_answer_to_tools_call_is_rewritten_streamed_or_plain` near line 88, `a_lookalike_event_on_the_listen_stream_is_rewritten` near line 138), `sdk/python/tests/test_stream.py` (`test_stream_upstream_lookalike_rewritten_by_the_proxy_is_not_a_cut` near line 292; `sdk/typescript/test/stream.test.ts`, `an upstream look-alike the proxy rewrote is not a cut` near line 248, added in #123) | The hostile upstream is a switch on the test server, not on `fake_mcp`. The integration test sends the look-alike as plain JSON, as one SSE event and from a streaming server, and replays it on a resumed listen stream. Each time it checks that the client gets `-32005` with the original under `data.upstream_error` and no `decision_id`, that only the call's own decision is recorded, and that there is no `stream.end` record. On the listen stream it also checks that the event keeps `id: 1` and the stream goes on. The Python test feeds the rewritten message to `call_tool_stream`: in a stream it is an ordinary event and the call ends with `AttenuoError` ("ended before"), and as a plain body it is an `RpcError` `-32005`. No SDK source changed in #117; #123 added the TypeScript twin of the Python test. | 1130 |
| 9 | `guard.rs` (`may_hold_stream_end_code` near line 457, `disown_events` near line 486, `disown_chunk` near line 513, `disown_stream` near line 522; the scan tests near lines 830, 845 and 895), `tests/listen_stream_cost.rs` (`disown` near line 170), `docs/design/bench/2026-10-25-vm-sse-disown.md` | #119. After #117 the unfiltered SSE path parsed every event: 0.95 us added to a small notification and 653 us to an 85 KB result. Now a byte scan runs first. It accepts an event when some `-` is followed by a run of digits and points whose significant digits (points and leading zeros dropped) start with `32001`, or with `320009` for a value just under it. `disown_chunk` scans the whole chunk and passes it on with no copy when nothing matches. After the change, 0.06 us per small event and 27 us per 85 KB, the scan alone. Output is unchanged. | 540 |
| 10 | `crates/attenuo-core/tests/proptest_seed/mod.rs` (`proptest_config` near line 27, `parse_cases` near line 43, `parse_seed` near line 52, four tests from line 61), its identical copy in `crates/attenuo-audit/tests/proptest_seed/mod.rs`, the callers (`attenuation_props.rs` `config` near line 31, `limits_props.rs` near line 185, `budget_props.rs` near lines 369 and 380), `.github/workflows/ci.yml` (the `test` job's `env` near line 118), `CONTRIBUTING.md` ("Property tests" near line 34) | #116. One helper per crate. `PROPTEST_CASES` overrides each test's count, and `PROPTEST_RNG_SEED` fixes the seed (`RngSeed::Fixed`). With no seed set, the helper draws a random u64 from std `RandomState`, uses it as the fixed seed and prints `proptest: random seed, replay with PROPTEST_RNG_SEED=<n>` into the captured output, which libtest shows on failure. A bad value of either variable panics, naming it. Persistence stays off, and `proptest-regressions/` is gitignored. CI pins `20261024` and 1024 cases. Two side effects of an explicit count: `max_global_rejects` scales with the cases, and the file-store budget test runs an eighth of the in-memory count. | 190 |
| 11 | `.github/workflows/release-packages.yml` (the header comment, `PUBLISH` near line 54, the `python` job near line 57, `python-publish` near line 104, `typescript` near line 121, `typescript-publish` near line 155), `docs/release/0.1.0.md` (step 6 near line 131) | #118. A `v*` tag push builds, tests and checks both packages and uploads nothing. Python runs ruff, `mypy --strict src`, pytest, `python -m build`, `twine check --strict` and a check that the wheel holds only `attenuo/`. npm runs `npm ci`, lint, build, test and `npm pack --dry-run`. Only a `workflow_dispatch` with `dry_run=false` publishes, and its check jobs then fail unless the ref is the tag `v<version>`. `python-publish` (environment `pypi`, `id-token: write` only, no checkout) uploads the checked files by trusted publishing. `typescript-publish` (environment `npm`) runs `npm publish --provenance` with the environment's `NPM_TOKEN`. Step 6 has the one-time setup and the manual fallback. | 220 |
| 12 | `sdk/python/pyproject.toml`, `sdk/typescript/package.json`, `.gitignore` | `authors`, `Development Status :: 3 - Alpha`, Python 3.10 to 3.13, `3 :: Only` and topic classifiers, and a Homepage URL. There is no `License ::` classifier, because hatchling refuses one beside the SPDX `license` expression. npm gains `publishConfig.provenance: true` and `prepack: npm run build`: without a prior build, `npm pack` packed only the README, LICENSE and `package.json`. `.gitignore` adds `*.tgz` and `dist-py/` (`dist/` was already there). | 150 |

What a streamed call's client sees, by what arrives (Python `call_tool_stream`, TypeScript `callToolStream`; both SDKs test every row since #123):

| What arrives | Python | TypeScript |
| --- | --- | --- |
| A notification or a server request (string `method`) | a `StreamEvent` with `method`, `last_event_id` and the header's `decision_id`; the loop goes on | a `StreamEvent` with `method`, `lastEventId` and `decisionId`; the loop goes on |
| A response with another id | a `StreamEvent` with `method` `None`; the loop goes on | the same, `method` undefined |
| The response to the call, a result | the final event: `is_final` true, `result` the `ToolResult` that `call_tool` returns; nothing after it | the final event: `isFinal` true, `result`; nothing after it |
| The response to the call, an error | what `call_tool` raises: `Denied` (a `-32003` whose `data.decision_id` the header names), `ApprovalRequired` (`-32008`, the same proof), else `RpcError` | `DeniedError`, `ApprovalRequiredError`, else `RpcError` |
| The proxy's cut: `id: null`, `-32001`, `data.reason` one of the six the proxy sends, `data.decision_id` absent or a UUID | raises `Denied(reason, decision_id)`; the id is the `stream.end` record's, which the header (sent before the cut) cannot vouch for | throws `DeniedError` the same way |
| That shape with another reason, a non-UUID or null id, or no `data` (since #123) | raises `RpcError` `-32001`; the call ends, but not as a decision. Before #123: `Denied` with whatever reason and id arrived | throws `RpcError` the same way |
| An upstream message in that shape, since #117 | it arrives rewritten (`id: null`, `-32005`, `data.reason` `upstream_stream_end_shape`, the original under `data.upstream_error`), which is a response with another id, so it is an ordinary event; if the upstream sends nothing more, the call ends with `AttenuoError` ("stream ended before the tools/call response"). Before #117: `Denied` with the made-up id | the same: an ordinary event, then `AttenuoError` |
| A plain JSON answer (not SSE, or an error status) | one final event, `last_event_id` `None`, or what `call_tool` raises; a rewritten look-alike there is `RpcError` `-32005` | one final event, `lastEventId` undefined, or what `callTool` throws |
| The stream ends without the response | `AttenuoError` | `AttenuoError` |
| An event (or a plain body) over the bound | `AttenuoError` | `AttenuoError` |

Why each piece is shaped this way:

- **A separate method, not a flag.** `call_tool(stream=True)` would return an iterator for one value of the flag and a `ToolResult` for the other. Keeping mypy and tsc exact would then need overloads on a `Literal`. A second method keeps both return types plain and leaves `call_tool` exactly as it was, so nobody's code changes meaning.
- **Omit nothing, but nest the upstream's error.** The rewrite keeps the message, keeps `id: null` and keeps every byte the upstream sent, under `data.upstream_error`. It moves them out of the places a client or a person reads as the proxy's word: the top-level `code`, `data.reason` and `data.decision_id`. A client still learns that the upstream failed and what it said. It no longer reads `lease_revoked` and a decision id that no record has.
- **Rewrite, do not drop.** Dropping the message would hide an upstream failure and leave the client waiting for an answer that will never come. `-32005` already means "the upstream answered with something the proxy will not relay as is", and both SDKs surface it as `RpcError`.
- **The rule is the SDKs' rule, minus `data.reason`.** If the proxy matched less than the SDKs read as a cut, some look-alike would still pass. Matching on `id` and `code` alone covers everything the SDKs act on, and costs only a rewrite of an upstream error that nobody should be sending anyway. An upstream `-32001` with the request's id is left alone: it is a plain answer, and the proxy's only other `-32001` bodies are its HTTP 401s, which never pass through the relay.
- **The scan reads significant digits, not `-32001`.** The shape test compares `error.code` by value. `-3.2001e4`, `-0.32001e5`, `-320010e-1` and `-32000.99999999999999999` are all `-32001` as an `f64`, and none of them contains the text `-32001`. A JSON number cannot be escaped and starts with a literal `-`, so every spelling shares its significant digits: `32001`, or `320009` when it rounds up to it. The scan never reads the exponent. A wrong magnitude (`-3.2001`) is a false positive, and the parse then rejects it, so the scan can only cost a parse, never let a look-alike through.
- **`PROPTEST_RNG_SEED`, not `PROPTEST_SEED`.** `PROPTEST_RNG_SEED` is proptest's own variable. `ProptestConfig::default()` prints "Ignoring unknown env-var" for any other `PROPTEST_*` name, so a made-up one would put a misleading line into every failing test's output. The helper also parses the value strictly and panics on a bad one, where proptest would warn and fall back to a random seed, and a typo would quietly stop replaying.
- **Random locally, pinned in CI.** A pinned CI seed makes a red run reproducible and a green one not a matter of luck. A random local seed keeps exploring, and printing it makes any local failure replayable. Failures are kept as their seed and then as a deterministic test (as session 14's `covered_request_...` was), not as a regressions file.
- **A tag push is a dry run; publishing needs a dispatch.** An upload to PyPI or npm cannot be taken back: a version, once uploaded, can never be uploaded again, even after deleting it. Tagging is also how the binaries and the image are released. So the tag only proves that both packages build and pass. A publish takes a deliberate `dry_run=false` dispatch from the tag whose version matches, in a GitHub environment that can require a reviewer's click. PyPI uses trusted publishing (OIDC, no stored token). npm uses a token for now, because npm's trusted publishing could not be confirmed from where this was built.

Check you understood:

1. A streamed `read_file` has yielded one progress notification when the operator revokes the lease. What does the Python loop see next, about how long after the revocation, and which audit record does `d.decision_id` name? Why can the `X-Attenuo-Decision-Id` header not vouch for that id the way it does for a `-32003`?
2. An upstream answers a `tools/call` over SSE with `{"jsonrpc":"2.0","id":null,"error":{"code":-3.2001e4,"message":"x","data":{"reason":"lease_revoked","decision_id":"..."}}}` and then closes the stream. What reaches the client, what does `call_tool_stream` raise, and which function let the event be parsed at all? What changes if the same error carries the call's `id`?
3. Why does `may_hold_stream_end_code` accept a run starting `320009`? An event holds a stack trace with `line -32001` inside a string. What does the scan cost there, and what reaches the client?
4. CI is green at seed 20261024 with 1024 cases, and a contributor's local run of `attenuation_props` fails. How do they replay it, what do they commit once they understand it, and why is no `proptest-regressions/` file added? Why can CI not find that failure on its own?
5. The maintainer pushes `v0.1.0`. What does `release-packages.yml` do, and what is uploaded? What must already be set up before `gh workflow run release-packages.yml --ref v0.1.0 -f package=python -f dry_run=false` uploads anything, and what happens to the same dispatch without `--ref`?
6. A TypeScript client has the default 30 s `timeoutMs`. A tool sends progress every 10 s for five minutes. What happens with `callTool` and with `callToolStream`? What happens with `callToolStream` if the tool is then quiet for 40 s?

Run it. Start from the section 0 setup, with `ATTENUO_SERVER` and `ATTENUO_ADMIN_TOKEN` exported. You also need the section 8 venv active, with `build` and `twine` added (`pip install build twine`), and the TypeScript package built (`npm ci && npm run build` in `sdk/typescript`, as in section 8). The block restarts the server on a copy of the demo config, with `fake_mcp --sse` as the upstream, and ends on the section 0 setup.

```sh
pkill -x attenuo-server; pkill -x fake_mcp; sleep 1
T=$(mktemp -d)
cp examples/github-leak-demo/config.toml $T/walk15.toml
$BIN/examples/fake_mcp --port 13001 --sse > $T/fake.log 2>&1 &
RUST_LOG=warn attenuo-server --config $T/walk15.toml > $T/server.log 2>&1 &
sleep 2

# 1. A streamed answer: on the wire, then from Python and from TypeScript.
R=$(attenuo token root --subject alice --agent assistant --cap github:read_file --print token)
curl -s -N $ATTENUO_SERVER/mcp/github -H "Authorization: Bearer $R" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"alice/public-docs","path":"README.md"}}}'
# event: message
# data: {"jsonrpc":"2.0","method":"notifications/message","params":{"data":"working","level":"info"}}
#
# id: 0
# event: message
# data: {"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"{\"arguments\":{...},\"name\":\"read_file\"}","type":"text"}],"isError":false}}
PYTHONPATH=sdk/python/src python3 - <<'PY'
from attenuo import AdminClient, Client

URL = "http://127.0.0.1:18080"
root = AdminClient(URL, "demo-admin-token").mint_root_dev(
    "alice", "https://idp.example", "assistant", ["github:read_file"])
with Client(URL) as ob:
    for ev in ob.call_tool_stream(root, "github", "read_file",
                                  {"repo": "alice/public-docs", "path": "README.md"}):
        print(ev.method, ev.last_event_id, ev.is_final, ev.decision_id)
        if ev.is_final:
            print(ev.result.content[0]["text"])
PY
# notifications/message None False 739a3cb6-...     the header's decision id, on every event
# None 0 True 739a3cb6-...                          the response: final, SSE id "0"
# {"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}
node --input-type=module - <<'JS'
import { AdminClient, AttenuoClient } from "./sdk/typescript/dist/index.js";
const URL = "http://127.0.0.1:18080";
const root = await new AdminClient(URL, "demo-admin-token").mintRootDev(
  "alice", "https://idp.example", "assistant", { capabilities: ["github:read_file"] });
const ob = new AttenuoClient(URL);
for await (const ev of ob.callToolStream(root, "github", "read_file", { repo: "alice/public-docs", path: "a" })) {
  console.log(ev.method, ev.lastEventId, ev.isFinal, ev.decisionId, ev.result?.content.length);
}
JS
# notifications/message undefined false 538689a8-... undefined
# undefined 0 true 538689a8-... 1
attenuo audit tail -n 6 | cut -c1-110
# #7  ... ALLOW github/read_file  assistant for alice  reason=policy_allow  id=739...
# #8  ... tool_result  github/read_file  assistant for alice  decision=739a3cb6-...   a streamed answer is labelled too
# #9  ... ALLOW attenuo/token.root ...   #10 ... ALLOW attenuo/admin.root_token ...      (the TypeScript mint)
# #11 ... ALLOW github/read_file ... id=5386...   #12 ... tool_result ... decision=538689a8-...

# 2. The same call held open by the upstream (hold_ms), and its lease revoked after the first event.
PYTHONPATH=sdk/python/src python3 - <<'PY'
import subprocess, time
from attenuo import AdminClient, Client, Denied

URL = "http://127.0.0.1:18080"
root = AdminClient(URL, "demo-admin-token").mint_root_dev(
    "alice", "https://idp.example", "assistant", ["github:read_file"])
t0 = time.monotonic()
with Client(URL) as ob:
    try:
        for ev in ob.call_tool_stream(root, "github", "read_file",
                                      {"repo": "alice/public-docs", "path": "a", "hold_ms": 20000}):
            print(f"{time.monotonic() - t0:.1f}s", ev.method)
            subprocess.run(["attenuo", "lease", "revoke", root.lease, "--reason", "cut mid-stream"], check=True)
    except Denied as d:
        print(f"{time.monotonic() - t0:.1f}s denied:", d.reason, d.decision_id)
PY
# 0.1s notifications/message
# revoked 1 lease(s) starting at dad0806d-... (reason: cut mid-stream)
# 2.1s denied: lease_revoked f49e431b-...         within one re-check ([proxy] stream_recheck_seconds, default 2)
attenuo audit tail -n 3 | cut -c1-140
# #15 ... ALLOW github/read_file  assistant for alice  reason=policy_allow  id=c3af5e6a-...
# #16 ... ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action ...
# #17 ... DENY  github/stream.end  assistant for alice  reason=lease_revoked  id=f49e431b-...   the id Denied carried
grep -c 'tools/call read_file' $T/fake.log       # 4: the curl, Python, TypeScript and the held call reached the upstream

# 3. An upstream speaking in the proxy's voice. fake_mcp has no switch for it; the test server does.
cargo test -p attenuo-proxy --lib --locked -- stream_end_shape lookalike protected_shape
# the_proxys_own_end_event_has_the_protected_shape, stream_end_shape_is_null_id_minus_32001_and_no_method,
# a_lookalike_plain_body_is_rewritten_..., a_lookalike_sse_event_is_rewritten_with_its_fields_...: 4 passed
cargo test -p attenuo-proxy --test stream_end_lookalike --locked
# a_lookalike_answer_to_tools_call_is_rewritten_streamed_or_plain, a_lookalike_event_on_the_listen_stream_is_rewritten: 2 passed
PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests/test_stream.py -q -k lookalike
# 2 passed, 33 deselected     (the sync and async runs of the rewritten-message test)

# 4. The byte scan in front of the parse.
cargo test -p attenuo-proxy --lib may_hold --locked
# running 0 tests ... 66 filtered out: the scan's tests are named for what they check, not for the function
cargo test -p attenuo-proxy --lib --locked -- byte_scan not_parsed
# every_encoding_serde_json_writes_for_the_code_passes_the_byte_scan, hand_written_spellings_of_the_code_pass_the_byte_scan,
# events_without_the_codes_digits_are_not_parsed: 3 passed

# 5. Seeds: pinned, replayed, random and printed, refused when malformed.
PROPTEST_RNG_SEED=20261024 PROPTEST_CASES=16 cargo test -p attenuo-core --test attenuation_props --locked
# 28 passed (24 properties and cases, and the helper's 4 tests, which run in every property-test binary)
PROPTEST_RNG_SEED=20261024 PROPTEST_CASES=16 PROPTEST_VERBOSE=1 cargo test -p attenuo-core --test attenuation_props \
  --locked -- --test-threads=1 --nocapture 2>&1 | grep -c 'Next test input'
# 0: level 1 prints only failures, so the traces below need level 2
for seed in 20261024 20261024 7; do
  PROPTEST_RNG_SEED=$seed PROPTEST_CASES=16 PROPTEST_VERBOSE=2 cargo test -p attenuo-core --test attenuation_props \
    --locked -- --test-threads=1 --nocapture 2>&1 | grep 'Next test input' > $T/trace
  echo "seed $seed: $(wc -l < $T/trace) inputs, md5 $(md5sum < $T/trace | cut -c1-12), first $(head -1 $T/trace | cut -c60-140)"
done
# seed 20261024: 414 inputs, md5 e95f10996ae9, first input: parent = CapabilitySet({Capability { server: "a", tool: "a*", constraints:
# seed 20261024: 414 inputs, md5 e95f10996ae9, first input: parent = CapabilitySet({Capability { server: "a", tool: "a*", constraints:
# seed 7: 402 inputs, md5 27625c0bf54d, first input: parent = CapabilitySet({Capability { server: "a", tool: "*", constraints:
cargo test -p attenuo-core --test attenuation_props --locked attenuate_iff -- --nocapture | grep 'random seed'
# proptest: random seed, replay with PROPTEST_RNG_SEED=7773806230261193916     (another number every run)
PROPTEST_RNG_SEED=0xbeef cargo test -p attenuo-core --test attenuation_props --locked attenuate_iff 2>&1 | grep -m1 'must be'
# PROPTEST_RNG_SEED must be a decimal u64, got "0xbeef"
grep -m1 -A2 PROPTEST_RNG_SEED .github/workflows/ci.yml
#       PROPTEST_RNG_SEED: "20261024"
#       PROPTEST_CASES: "1024"

# 6. The packages, as the tag's dry run builds them (nothing is uploaded).
(cd sdk/typescript && npm pack --dry-run 2>&1 | grep -E 'Tarball Contents|kB|total files|name:|version:')
# npm notice Tarball Contents
# npm notice 11.4kB LICENSE   53.7kB README.md   109.5kB dist/index.cjs   266.8kB dist/index.cjs.map
# npm notice 73.8kB dist/index.d.cts   73.8kB dist/index.d.ts   106.2kB dist/index.js   262.7kB dist/index.js.map
# npm notice 1.8kB package.json
# npm notice name: @attenuo/sdk   version: 0.1.0   package size: 267.3 kB   unpacked size: 959.7 kB   total files: 9
(cd sdk/python && python3 -m build > /dev/null 2>&1 && twine check --strict dist/*)
# Checking dist/attenuo-0.1.0-py3-none-any.whl: PASSED
# Checking dist/attenuo-0.1.0.tar.gz: PASSED
unzip -l sdk/python/dist/attenuo-0.1.0-py3-none-any.whl | awk '{print $4}' | cut -d/ -f1 | sort -u | grep .
# ----  Name  attenuo  attenuo-0.1.0.dist-info      (the listing's header, then the only two top-level entries)
tar tzf sdk/python/dist/attenuo-0.1.0.tar.gz | grep -c '/tests/'
# 15: the sdist carries the test suite (open below)
git status --short --ignored sdk/ | grep -v node_modules
# !! sdk/python/.pytest_cache/
# !! sdk/python/dist/
# !! sdk/python/src/attenuo/__pycache__/
# !! sdk/python/tests/__pycache__/
# !! sdk/typescript/dist/                           all ignored: nothing to commit
rm -rf sdk/python/dist sdk/typescript/dist
grep -n -E '^  (push|workflow_dispatch):|PUBLISH:|id-token: write|environment:' .github/workflows/release-packages.yml
# 30:  push:   33:  workflow_dispatch:
# 54:  PUBLISH: ${{ github.event_name == 'workflow_dispatch' && inputs.dry_run == false }}
# 109:    environment:   113:      id-token: write # PyPI trusted publishing
# 160:    environment:   165:      id-token: write # npm provenance   (and the comment on line 20)

pkill -x attenuo-server; pkill -x fake_mcp; sleep 1        # back to the section 0 setup:
$BIN/examples/fake_mcp --port 13001 > /tmp/ob-fake.log 2>&1 &
RUST_LOG=warn attenuo-server --config examples/github-leak-demo/config.toml > /tmp/ob-server.log 2>&1 &
```

Every command in the block was run in this order against `main` @ a2abfdd on 2026-10-25. The binaries were debug builds (`cargo build -p attenuo-server -p attenuo-cli` and `cargo build -p attenuo-proxy --example fake_mcp`; the self dev-dependency turns on `testing`, so the example builds without `--features`). The server and `fake_mcp --sse` were freshly started, and every command prints what is quoted, the test counts included; ids, leases and times differ on every run. Some outputs are folded onto fewer lines. The Python parts ran the repository's sources through `PYTHONPATH` in a virtual environment with the SDK's dependencies, `build` and `twine`; the TypeScript part ran the package built by `npm run build`. The block was run twice: the first run piped the trace through `tee` into `head -1`, which cut the trace short when `head` exited. The loop above, which writes the file first, is the second run, on a freshly restarted server. Not shown live, and where to look instead:

- A look-alike from an upstream. `fake_mcp` has no switch for it, and none was added for this page. `FakeMcpServer::with_stream_end_lookalike` serves it in `crates/attenuo-proxy/tests/stream_end_lookalike.rs` (part 3).
- What `callToolStream` does with the rewritten message. It is read from `sse.ts` (it is a response whose id is not the call's, so it is yielded). No TypeScript test feeds it, and #117 changed no SDK source.
- The TypeScript cut by revocation: "relays events in order and throws DeniedError when revocation cuts the stream" in `sdk/typescript/test/integration.test.ts` (with `ATTENUO_INTEGRATION=1`; not run for this page), and `test_call_tool_stream_relays_events_and_raises_on_revocation` in `sdk/python/tests/test_integration.py` for Python.
- The cost of the check and of the scan: the `#[ignore]` test `disown` in `crates/attenuo-proxy/tests/listen_stream_cost.rs`, run in release with the command at the end of the bench note (not run for this page, as for the other benchmarks).
- The workflow itself, and any upload. Actions are blocked on billing, and nothing was uploaded to PyPI, TestPyPI or npm. Part 6 runs what its check jobs run, locally.

What is still open after this session (from the [task board](../tasks/board.md) and the logs of these merges; this list supersedes session 14's):

- Release: 0.1.0 waits on the maintainer (Actions billing, the tag, making the repository public, the package names, `cargo publish`). For the SDKs it now means the one-time setup of step 6 (the `pypi` and `npm` environments, the PyPI trusted publisher, the `@attenuo` npm organisation and its token) and the two dispatches. The workflow has never run.
- SDKs: the SDK half of the look-alike item closed in #123: a cut needs one of the six reasons the proxy sends and a UUID decision id, which since #117 is defence in depth only. A custom `Authorizer` reason outside the six surfaces as `RpcError -32001`, not `Denied`. Neither SDK answers server requests (sampling, elicitation) on a stream or resumes one with `Last-Event-ID`. The sdist carries the test suite (15 files under `tests/` in part 6; the wheel holds only the package). npm trusted publishing is untried, so npm publishes with a token. Hop-0 against a live IdP is still to test, and one intermittent Python integration failure (`test_dpop_server_nonce`, suspected) is still being watched.
- Proxy: pass 7 (#124, SR-77 to SR-80) closed the parse gap: an upstream SSE event the proxy could not parse (a leading BOM, bytes that are not UTF-8, a lone surrogate escape, nesting past 128 levels) used to pass to the client unlabelled and unrewritten; now the BOM is stripped, a non-UTF-8 event ends the stream, lone surrogates read as U+FFFD, and an event whose data still does not parse is dropped on labelled, list-filtered and may-hold-the-code streams (`parse_data`, `has_data` in `crates/attenuo-proxy/src/sse.rs`; tests in `crates/attenuo-proxy/tests/security_pass7.rs`). From pass 7: SR-81 fixed in #128 (`Authorizer::record_rejection_checked`, a default method, so third-party implementors are unaffected; a failed append opens no window and names no id), SR-82 fixed in #125 and #126, SR-83 (publish workflow tools not hash-pinned) open. Three look-alike residuals remain. A plain JSON answer to a method the proxy neither filters nor labels (`initialize`, `ping`, a notification-only `POST`) is relayed unread, so a look-alike there is not rewritten; no SDK reads those as a cut. An upstream `-32001` that answers by the request's id still surfaces as `Unauthorized`. The scan is not measured end to end. Cedar-aware list filtering waits on a decision about [ADR-0011](../decisions/0011-cedar-aware-list-filtering.md). Both record windows are constants (settings since #121: `[proxy] record_window_seconds` and `record_window_max_keys`, read at startup only); a suppressed record's count is in the metric and the log only; the lease-refusal series appear only once counted. A large non-list event on the filtered listen stream costs about 0.7 ms per 85 KB to parse and re-serialize.
- CI and tests: the pinned seed means CI replays one sequence and never explores. Rotating it now and then, or a scheduled job with a random printed seed, is a separate decision. The two `proptest_seed` copies must be kept identical by hand. The other CI items on the board are unchanged (the new workflows confirmed on a fork, private vulnerability reporting, the DCO app).
- Run limits: a `distinct` list of 256 new values holds the write gate for about 28 ms, and whether to lower `MAX_COUNTED_VALUES`, write fewer rows per value or batch the inserts is undecided. A `perf/distinct-list-charge` branch is in flight and may land after this session; its results are not covered here. The per-value kinds are not measured under concurrent clients, at `durability = "full"` end to end or on the memory store end to end.
- Constraints: time ranges; no `--constraint` shorthand on the CLI; a range covering a small `one_of` is refused; the fuzz targets that generate ranges were type-checked, not run; a `prefix` constraint keeps the URL-parser blind spot of SR-70 (SR-73, accepted). In the token claims, `evidence` on the originating user and a stable `chain_id` are still to be reconciled or dropped.
- Revocation and leases: revoking by the audit `session_tag`; the optional proxy lease cache; a lost session binding is only a log line. The maintenance settings are read at startup, not on reload. A wide run's sweep state lives in the store value, and a run kept because one lease is live is walked again on every sweep.
- Refunds: a usage-only decision whose usage is gone stays 404; a duplicate refund of a pruned decision is told from a first only by reading the `admin.budget.refund` records. The SDKs have no refund helper.
- AuthZEN: the Search APIs and discovery `capabilities` and `signed_metadata` are not implemented; error bodies stay JSON objects ([AuthZEN conformance](../reference/authzen.md#not-implemented)).
- Dry run: offline `policy test` does not enforce chain limits; the route ignores unknown top-level members, as the AuthZEN request it extends does.
- Server and identity: real admin authentication; actor tokens against a live SPIRE; hop-0 hardening (a shared replay cache, `private_key_jwt`, ID-JAG drafts).
- Evaluation and performance: the remaining test-split cases and a model in the loop; the injection suite's `stage_of` in `evaluation/injection-suite/harness.py` still does not know `input_type_mismatch`; run limits phase 3; the open benchmark and performance items on the board (a quiet reference machine above all).
- Metrics: soft-limit asks are not told apart from other `approval_required` decisions (that would need policy ids as labels).

### Session 16: record windows you can set, a cost that would not move, cuts the SDKs can trust and security pass 7

The six merges after Session 15, on the morning of 2026-10-25 (#121 to #126), close loose ends that Sessions 14 and 15 left open. The two record windows (lease refusals and listen-stream ends) become settings (#121). A try at making a wide `distinct` charge cheaper measured no reliable gain and changed no store code; it leaves one test and a bench note behind (#122). The SDKs stop reading every message of the stream-end shape as a cut: they want one of the six reasons the proxy sends and a UUID decision id (#123). Security pass 7 found the proxy relaying SSE events it could not parse, unlabelled and unrewritten, and fixed that in four ways (#124, SR-77 to SR-80). Its SR-82 was fixed in two parts: the Python SSE parser became linear (#125), and both SDKs gained an optional total deadline on a streamed call (#126). This session reads them in that order.

Read beside: the `[proxy]` rows `record_window_seconds` and `record_window_max_keys` in [the config reference](../reference/config.md#proxy) and the matching comment in `config/example.toml` (near line 285). Then [the distinct list-charge bench note](../design/bench/2026-10-25-vm-distinct-list-charge.md) ("Where the time goes" and "Reading") and the [performance section](../design/performance.md#cheaper-distinct-list-charges-measured-2026-10-25) that summarises it. Then [security review pass 7](../research/security-review-2026-10-25-pass7.md) whole (it is short: the summary table, SR-77 to SR-84, and "Checked and found sound"). Last, "Streaming a call" in `sdk/python/README.md` and in `sdk/typescript/README.md`, which now name the six reasons and the deadline. The reasoning behind each change is in [the 2026-10-24 log](../log/2026-10-24.md), in the entries from 04:32 to 05:26 UTC.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/attenuo-proxy/src/records.rs` (`DEFAULT_RECORD_WINDOW_MAX_KEYS` near line 28, `DEFAULT_RECORD_WINDOW` near line 40, `RecordWindow::with_max_keys` near line 92; tests `a_short_window_closes_sooner` near line 253 and `a_full_table_at_the_smallest_configurable_size_records` near line 297), `config.rs` (`ProxyConfig::record_window` near line 82, `record_window_max_keys` near line 87, `with_record_window` near line 144), `proxy.rs` (`router` reading both near line 160, the lease-refusal table near line 184) | #121, the proxy half. The two constants keep their values (60 s, 10,000 windows) and become the defaults of two `ProxyConfig` fields. `router` builds both `RecordWindow`s from them, the lease-refusal table and the guard's `stream.end` table, each its own table of the same size. The hidden test hook that set only the refusal window is gone. A full table still records rather than suppresses, so a smaller `max_keys` can only mean more records, never fewer. | 360 |
| 2 | `crates/attenuo-server/src/config.rs` (`ProxySection` near line 1322, its fields near lines 1361 and 1366, `MAX_RECORD_WINDOW_SECONDS` and the two key bounds near lines 1371 to 1377, `ProxySection::record_window` near line 1460, `apply` near line 1486; test `proxy_record_window_defaults_and_bounds` near line 1879), `state.rs` (the startup check near line 101), `tests/e2e.rs` (`record_window_seconds_sets_the_lease_refusal_window` near line 1906) | #121, the server half. `[proxy] record_window_seconds` (default 60, 1 to 3600) and `record_window_max_keys` (default 10000, 100 to 1000000) are read as `u64`. `record_window()` validates both and returns `(Duration, usize)`; startup calls it and refuses a value out of range with `[proxy] record_window_seconds must be between 1 and 3600, not 0`. `apply` passes the pair to `with_record_window`. One window for both kinds, because two would ask the operator a question nobody has asked; the doc comment on the field says so. Read at startup only. | 2540 |
| 3 | `docs/design/bench/2026-10-25-vm-distinct-list-charge.md` ("Where the time goes" near line 20, the per-row figure near line 34, "Reading" near line 100), `crates/attenuo-audit/tests/budgets.rs` (`a_refund_after_a_wide_list_charge_frees_only_unshared_values_sr62` near line 687) | #122, a negative result. A 256-value `distinct` list charge holds the write gate for about 28 ms (#113). Batching the same rows (a map for pending counters, deduplicated upserts, multi-row `INSERT`s of 64, 8 and 1, one `IN` read per limit) moved the medians inside the old build's spread, so the store code is unchanged. The cost is per row in the B-trees, about 4 to 12 us each, since the value hashes are random and every new value lands on its own leaf pages. Only writing fewer rows would help, and each way of doing that changes what SR-62's exact refunds rely on. What stays is a 64-value bench cell and this test: two 256-value decisions in two hops share values, and refunds free only the unshared ones, on both stores. Whether to lower `MAX_COUNTED_VALUES` (256) is the maintainer's decision, on the board. | 120 |
| 4 | `crates/attenuo-proxy/src/guard.rs` (`StreamEndCause::of_lease_reason` near line 150, `check_detail` near line 254 and its `check_active` call near line 272, `"unauthorized"` near line 289, `end_event_recorded` near line 353) | Where the six reasons come from (#123 read them here, it changed nothing in the crate). The event carries the reason the re-check failed with, not the metric label. `check_active` returning `LeaseInactive(reason)` passes the server authorizer's reason through: `lease_revoked`, `lease_expired`, `lease_unknown` or `lease_error`. An expired token is `token_expired`, and a token refused for any other reason is `unauthorized` (not recorded, so no id). `end_event_recorded` writes the decision id with `Uuid::to_string()` or leaves the member out. `lease_other`, `recheck_unavailable` and `recheck_failed` are metric labels and never appear in the event. | 1200 |
| 5 | `sdk/python/src/attenuo/_sse.py` (`_STREAM_END_REASONS` near line 34, `_UUID` near line 45, `_is_stream_end` near line 227, `stream_end_error` near line 241), `sdk/python/tests/test_stream.py` (`test_stream_cut_with_each_reason_the_proxy_sends_is_denied` near line 243, `test_stream_end_shape_the_proxy_never_sends_is_not_denied` near line 267) | #123 in Python. The shape test is unchanged: no `method`, `id` null or absent, `error.code` `-32001`. A message of that shape is now `Denied` only when `_is_stream_end(data)` holds: `data.reason` is one of the six and `data.decision_id` is absent or matches `_UUID` in full. Anything else of that shape is `RpcError(-32001, message, data)`, which still ends the call but is not a decision. An explicit `null` id or an empty string is not a cut. The set and the pattern are private; the package exports no reason constants. The docstring says why this is defence in depth: since #117 the proxy rewrites any upstream message of that shape, and its header went out before the cut, so it cannot vouch for the id. | 330 |
| 6 | `sdk/typescript/src/sse.ts` (`STREAM_END_REASONS` near line 27, `UUID` near line 37, `streamEndError` near line 202, the reason-and-id test near line 215), `sdk/typescript/test/stream.test.ts` (the two `it.each` tables near lines 207 and 228) | The same rule in TypeScript: `streamEndError` returns `DeniedError`, `RpcError` or `undefined`. The tests are the Python ones as `it.each` tables: the six reasons, then an unknown reason, a non-UUID id, a null id and no `data`. #123 also added the TypeScript twin of the rewritten look-alike test that Session 15 noted was missing. | 320 |
| 7 | `crates/attenuo-proxy/src/sse.rs` (`strip_leading_bom` near line 35, `event_json` near line 178, `parse_data` near line 192, `replace_lone_surrogates` near line 205, `has_data` near line 242, `SseFramer` near line 325 and `SseFramer::push` near line 354 with its non-UTF-8 error near line 370; tests near lines 496, 542 and 578) | #124, SR-77, SR-78 and SR-80. Labelling and the look-alike rewrite act only on events the proxy parses, and the MCP SDKs parse more leniently than `serde_json`. Now the proxy reads the way they do. A UTF-8 BOM that opens the stream is dropped, as clients drop it (SR-77). An event that is not UTF-8 ends the stream with an `InvalidData` error rather than being passed on (SR-77). `parse_data` retries a failed parse with every unpaired `\uD800`-range escape replaced by `�`, since `JSON.parse` and Python's `json` accept such an escape and `serde_json` does not (SR-78). The list filter's rewriter drops an event whose data does not parse instead of passing it on (SR-80). `has_data` tells an event with data the proxy could not read from a data-less one (a comment, a bare `id:`), which still passes. | 630 |
| 8 | `crates/attenuo-proxy/src/label.rs` (`label_events` near line 428, the withheld branch near line 448), `guard.rs` (`disown_events` near line 480, the drop near line 495; `the_byte_scan_admits_every_spelling_of_the_code_pass7` near line 1135) | #124, SR-79. Nesting deeper than `serde_json`'s 128 levels is the case no rewrite fixes, so an unparseable event with data is dropped where it matters. `label_events` withholds it while an answer is awaited, since it may be the answer, and a client may read it unlabelled. `disown_events` drops one that passes the byte scan (it may hold `-32001`) and does not parse, with a `warn` line that gives only its size. The pass also checked #119's byte scan against generated spellings of `-32001` and found it sound; that test stays. | 690 |
| 9 | `crates/attenuo-proxy/tests/security_pass7.rs` (`raw_sse_upstream` near line 17, `lenient_client_reads` near line 88, the five tests from line 117 to line 223), `docs/research/security-review-2026-10-25-pass7.md` (the summary table near line 24, SR-81 near line 82) | The regression tests, each failing on the pre-fix commit first. A raw upstream sends exact bytes, and `lenient_client_reads` parses the client's side as a lenient SDK would (lossy UTF-8, a leading BOM dropped, the `data:` lines joined and parsed), so each test asserts what a real client would act on. The report's open items: SR-81 (a record window opened even when its first audit append failed, so up to `record_window_seconds` of retries named an id no record had; fixed after this session in #128 by `Authorizer::record_rejection_checked` and `RecordWindow::forget`), SR-83 (the release workflow resolves `build`, `twine` and `hatchling` without hashes) and SR-84 (accepted: an AuthZEN batch refused by a 401 or 403 entry after earlier entries were decided). SR-82 was open when the report was written and is fixed by rows 10 and 11. | 250 |
| 10 | `sdk/python/src/attenuo/_sse.py` (`SseParser` near line 82, its state near lines 96 to 99: `_head`, `_parts`, `_parts_len`, `_cr`; `SseParser.feed` near line 104, `_pending` near line 163), `sdk/python/tests/test_stream.py` (`test_parser_reads_a_long_line_in_small_reads_in_linear_time_sr82` near line 144) | #125, SR-82 part 1. `feed` used to append each read to one buffer and search it from the start, so a long line in small reads cost time quadratic in its length. Now each read is searched once from its own start. The unfinished line is a list of chunks with a byte count, joined once when its line end arrives, as the TypeScript parser already did. A CR at the end of a read is held in `_cr` and settled by the next read's first byte (LF makes it CRLF). `_head` holds the first bytes while they may still be a BOM split across reads. The bound now counts `_parts_len`. A 1 MiB line in 1 KiB reads took about 4 s and now takes about 10 to 20 ms. A throwaway differential check (300,000 random bodies, old parser against new) found no difference and was not committed. | 330 |
| 11 | `_sse.py` (`check_deadline` near line 51, `Deadline` near line 57), `client.py` (`Client.call_tool_stream` near line 229 with `deadline` near line 239, `Deadline(deadline)` in `_stream` near line 294, `expires.check()` near lines 305 and 312; async twins near lines 586, 634, 645 and 653), `sdk/typescript/src/client.ts` (`CallToolStreamOptions.deadlineMs` near line 71, `MAX_TIMER_MS` near line 75, the check in `callToolStream` near line 287, the `AbortController` in `stream` near line 313 and the deadline timer near line 329), the `*_sr82` tests in `sdk/python/tests/test_stream.py` (near lines 523, 537 and 554) and `sdk/typescript/test/stream.test.ts` (near lines 523, 543 and 553) | #126, SR-82 part 2. Both SDKs restart their idle timer on every read, so an upstream sending `:\n\n` every few seconds kept a call open with no event, until the proxy's re-check ended it at token expiry or revocation. Now there is an optional total deadline, counted from the request's start and never restarted. Python checks a monotonic deadline between reads, so a silent upstream is still ended by the per-read `timeout`. On expiry it raises `AttenuoError("stream deadline of 3s elapsed")`, and the `finally` closes the response. TypeScript arms a second timer on the same `AbortController` as the idle timer: it aborts the fetch, and `onChunk` throws if a read still completes after it. `check_deadline` refuses zero, negative, NaN and infinity with `ValueError`; TypeScript throws `RangeError` for those and for anything above 2,147,483,647 ms, since a longer `setTimeout` fires at once. | 780 |

Why each piece is shaped this way:

- **One window for both bounded kinds.** The listen-stream ends and the lease refusals are the same problem, one condition seen many times. Two knobs would ask the operator to choose between values nobody has a reason to set apart, so there is one, and each kind keeps its own table. The bounds are wide (1 s to an hour, 100 to a million windows), and a value outside them stops startup instead of being clamped, so a typo is not quietly turned into some other value.
- **A full table records.** If the table is full of open windows, the next condition is recorded, not counted. The bound can therefore fail towards more records, never towards fewer, and `record_window_max_keys` is a memory knob, not an audit knob.
- **A measurement that changed nothing is still merged.** #122 kept its bench note, a bench cell and the SR-62 test at full list size. The next person who wants to batch these inserts can read why the same rows in fewer statements do not help, and the test guards the refunds any later change to what is written per value would have to keep.
- **The SDKs check the reason and the id, although the proxy already rewrites.** After #117 nothing of the stream-end shape should reach a client from an upstream. The SDK check is the second wall. Behind a proxy too old to rewrite, or behind some other relay, a made-up `lease_revoked` with an id no record has now surfaces as `RpcError -32001`, which ends the call but does not claim a decision. The cost is that a custom `Authorizer` reason outside the six also surfaces as `RpcError`.
- **Read the way the client reads.** The pass-7 bugs share one cause: the proxy's parser was stricter than the clients'. An event the proxy could not read went past labelling and the rewrite, and the client then read it. The fixes move the proxy towards what clients do (drop the BOM, accept lone surrogates), and where that cannot work (nesting past 128 levels, bytes that are not UTF-8) they stop relaying instead of passing the event on.
- **A deadline, not a smaller idle timeout.** A keep-alive is a read, and the idle timer exists to restart on reads. Only a timer that never restarts can end a stream that keeps sending nothing useful. It is opt-in because a tool may honestly run for an hour, and a default would cut it.

Check you understood:

1. An operator sets `record_window_seconds = 0` in `[proxy]`. What happens at startup, and which function says so? With `= 2`, a client retries `initialize` on a revoked lease at 0 s, 0.1 s and 2.3 s: how many `deny` records are written, and what `X-Attenuo-Decision-Id` does each 401 carry? Which table does `record_window_max_keys` size, and what happens when it is full?
2. Why does `[proxy]` have one window for both bounded kinds and not two? What does SR-81 say goes wrong with that window when the first audit append fails, and why was it not fixed in pass 7?
3. #122 batched the inserts of a 256-value `distinct` charge and the medians barely moved. Where does the time go, per the bench note, and what would make the charge cheaper? Why is that a design decision and not a performance fix?
4. A streamed Python call receives `{"id":null,"error":{"code":-32001,"message":"x","data":{"reason":"quota_exceeded","decision_id":"<a UUID>"}}}`. What does `call_tool_stream` raise, and what did it raise before #123? Where in `guard.rs` would you look to check the list of six?
5. An upstream answers a labelled `tools/call` over SSE with an event whose data is the answer nested 200 arrays deep. What did the client get before #124, and what does it get now? What if the same event opens with a UTF-8 BOM, or holds a lone `\ud800` escape?
6. A tool sends one progress event and then a keep-alive comment every 0.5 s. What ends the Python call with `timeout=1` and no deadline, and what ends it with `deadline=3`? What does TypeScript do with `deadlineMs: 3_000_000_000`?

Run it. Start from the section 0 setup. No server is needed: every part runs tests or the SDK sources against a fake transport. You also need the section 8 venv active and the TypeScript dependencies installed (`npm ci` in `sdk/typescript`).

```sh
# 1. Record windows: the proxy's tests, then the server's settings.
cargo test -p attenuo-proxy --locked record_window 2>&1 | grep -c '^test result: ok. 0 passed'
# 13: the count of `test result: ok. 0 passed` lines (every test binary plus the doc-tests), none with a test of that name; the window's tests live in records::
cargo test -p attenuo-proxy --lib --locked records:: 2>&1 | grep 'test result'
# test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 64 filtered out
# (a_short_window_closes_sooner and a_full_table_at_the_smallest_configurable_size_records among them)
cargo test -p attenuo-server --locked record_window 2>&1 | grep '^test '
# test config::tests::proxy_record_window_defaults_and_bounds ... ok
# test record_window_seconds_sets_the_lease_refusal_window ... ok
grep -n '^record_window' config/example.toml
# 290:record_window_seconds = 60
# 291:record_window_max_keys = 10000

# 2. The distinct list charge: the one test #122 kept.
cargo test -p attenuo-audit --test budgets --locked sr62 2>&1 | grep -E '^test |test result'
# test a_distinct_refund_keeps_a_value_a_later_call_used_sr62 ... ok
# test a_refund_after_a_wide_list_charge_frees_only_unshared_values_sr62 ... ok
# test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out

# 3. What the SDK reads as a cut, since #123.
PYTHONPATH=sdk/python/src python3 - <<'PY'
from attenuo._sse import stream_end_error
def cut(data): return {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "stream ended", "data": data}}
for d in [{"reason": "lease_revoked", "decision_id": "f49e431b-1c2d-4e5f-8a9b-0c1d2e3f4a5b"},
          {"reason": "lease_revoked"},
          {"reason": "quota_exceeded", "decision_id": "f49e431b-1c2d-4e5f-8a9b-0c1d2e3f4a5b"},
          {"reason": "lease_revoked", "decision_id": "not-a-uuid"},
          None]:
    e = stream_end_error(cut(d))
    print(type(e).__name__, getattr(e, "reason", None) or getattr(e, "code", None), getattr(e, "decision_id", ""))
print(stream_end_error({"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "x"}}))
PY
# Denied lease_revoked f49e431b-1c2d-4e5f-8a9b-0c1d2e3f4a5b    a known reason and a UUID: the proxy's cut
# Denied lease_revoked None                                   no id (an end that was not recorded) is still a cut
# RpcError -32001                                             a reason the proxy never sends
# RpcError -32001                                             an id that is not a UUID
# RpcError -32001                                             no data at all
# None                                                        an answer by the call's id is not the stream-end shape

# 4. Pass 7: the proxy's regression tests.
cargo test -p attenuo-proxy --test security_pass7 --locked 2>&1 | grep -E '^test |test result'
# test a_list_answer_the_proxy_cannot_parse_is_not_relayed_unfiltered_sr80 ... ok
# test a_bom_or_invalid_byte_does_not_hide_a_stream_end_lookalike_sr77 ... ok
# test a_lone_surrogate_escape_does_not_hide_an_answer_sr78 ... ok
# test an_event_the_proxy_cannot_parse_is_not_relayed_sr79 ... ok
# test an_sse_answer_a_client_reads_is_labelled_sr77 ... ok
# test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
cargo test -p attenuo-proxy --lib --locked -- sr77 sr78 sr80 pass7 2>&1 | grep 'test result'
# test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 67 filtered out
# (the BOM and non-UTF-8 test, the lone-surrogate test, the SR-80 rewriter test and the byte-scan check)

# 5. SR-82 part 1: a 1 MiB line in 1 KiB reads.
PYTHONPATH=sdk/python/src python3 - <<'PY'
import time
from attenuo._sse import SseParser
line = b"data: " + b"x" * (1 << 20) + b"\n\n"
p = SseParser(); t = time.monotonic(); n = 0
for i in range(0, len(line), 1024):
    n += len(list(p.feed(line[i:i + 1024])))
print(f"{n} event, {len(line)} bytes in 1 KiB reads: {(time.monotonic() - t) * 1000:.0f} ms")
PY
# 1 event, 1048584 bytes in 1 KiB reads: 17 ms             (about 4 s before #125)

# 6. SR-82 part 2: keep-alives every 0.5 s, a 1 s idle timeout, a 3 s deadline.
PYTHONPATH=sdk/python/src python3 - <<'PY'
import time, httpx
from attenuo import Client, AttenuoError

def body():
    yield b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n\n'
    while True:
        yield b":\n\n"
        time.sleep(0.5)

class Body(httpx.SyncByteStream):
    def __iter__(self): return body()

handler = lambda r: httpx.Response(200, stream=Body(), headers={"content-type": "text/event-stream"})
t0 = time.monotonic()
with Client("http://127.0.0.1:1", timeout=1, transport=httpx.MockTransport(handler)) as ob:
    try:
        for ev in ob.call_tool_stream("TOK", "srv", "t", deadline=3):
            print(f"{time.monotonic() - t0:.1f}s", ev.method)
    except AttenuoError as e:
        print(f"{time.monotonic() - t0:.1f}s", type(e).__name__, e)
PY
# 0.0s notifications/progress
# 3.0s AttenuoError stream deadline of 3s elapsed          the 1 s idle timeout never fired: every 0.5 s brought a read
PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests/test_stream.py -q -k sr82 2>&1 | tail -1
# 10 passed, 55 deselected in 1.26s
(cd sdk/typescript && npx vitest run test/stream.test.ts -t sr82 2>&1 | grep 'Tests ')
#       Tests  3 passed | 33 skipped (36)
```

Every command in the block was run in this order against `main` @ fabb60a on 2026-10-25, from a clean worktree with `ATTENUO_TOKEN`, `ATTENUO_SERVER` and `ATTENUO_ADMIN_TOKEN` unset, and prints what is quoted, the test counts included. The cargo commands ran as debug builds without debug info (`CARGO_PROFILE_DEV_DEBUG=0`, a separate `CARGO_TARGET_DIR`). The three Python snippets were run from files with exactly the contents shown, in a virtual environment with the SDK's dependencies. The TypeScript part ran against the installed `node_modules`; it needs no build, since vitest reads the sources. The parser timing differs on every run (the log of #125 has 9.5 to 12.8 ms on the machine that measured it). Not shown live, and where to look instead:

- The startup refusal of an out-of-range window. `proxy_record_window_defaults_and_bounds` checks the exact text of five refusals, and the 04:32 log entry records the server exiting with `Error: [proxy] record_window_seconds must be between 1 and 3600, not 0`. Not rerun for this page.
- The criterion runs behind #122. The commands are at the end of the bench note; like the other benchmarks they were not rerun.
- A deadline against a real server. `fake_mcp --sse` sends no keep-alive comments, so a live run would show nothing the fake transport does not. The TypeScript deadline is shown by its three tests only.
- SR-79 at the byte level. `an_event_the_proxy_cannot_parse_is_not_relayed_sr79` builds the 200-deep nesting; read it beside `disown_events`.

What is still open after this session (from the [task board](../tasks/board.md), [pass 7](../research/security-review-2026-10-25-pass7.md) and the logs of these merges; items of session 15's list not named here stand as written there):

- Proxy: SR-81 was fixed in #128, after this session was written: `Authorizer::record_rejection_checked` (a default method, `Some(record_rejection(..))`, overridden by `ServerAuthorizer` to return `None` on a failed append) and `RecordWindow::forget`, so a failed append opens no window and names no id; regression test `a_failed_append_opens_no_record_window_sr81` in `crates/attenuo-proxy/tests/security_pass7_sr81.rs`. The window settings are read at startup only, not on reload, and a suppressed occurrence's count is still only in the metric and the log. The three look-alike residuals of session 15 stand (relayed unread answers to `initialize`, `ping` and notification-only `POST`s; an upstream `-32001` by the request's id; the scan not measured end to end).
- SDKs: SR-82 is closed. The deadline is opt-in, so a caller who passes none can still be held by keep-alives until the proxy's re-check ends the stream. Neither SDK can tell that a stream-end id is the proxy's, since the header went out before the cut. A custom `Authorizer` reason outside the six surfaces as `RpcError -32001`. The other SDK items of session 15 (server requests on a stream, `Last-Event-ID` resumption, the sdist test suite, npm trusted publishing) are unchanged.
- Release and CI: SR-83 is open (`build`, `twine` and `hatchling` resolved without hashes in the publish job, `npm ci` running install scripts in a job that holds `id-token: write`). It needs a hashed requirements file and a CI run, and Actions are blocked on billing. SR-84 is accepted.
- Run limits: whether to lower `MAX_COUNTED_VALUES`, or write fewer rows per value, is the maintainer's decision. #122 showed that batching the same rows does not help. A 64 MiB SQLite page cache cut the 256-value charge by about 22 % in one timed run, at a memory cost for the whole store; that is a separate, unmeasured decision on the board.

## 3. Why it is this way

One line per decision. The ADRs record a decision and what was rejected; the design pages record how something works and why it was built that way.

### ADRs

| Document | Decision | Rejected alternative |
| --- | --- | --- |
| [ADR-0001: Separate enforcement layer](../decisions/0001-separate-enforcement-layer.md) | Enforce delegation and per-call authorization in a separate proxy and policy decision point that both the agent and the MCP server are treated as untrusted by. | Changing the MCP protocol, in-server checks, in-client checks, or only a gateway plugin. |
| [ADR-0002: Cedar for policy](../decisions/0002-cedar-for-policy.md) | Cedar is the only policy language authors see; delegation and attenuation are enforced in Rust code before policy runs. | Rego (sidecar or WASM), CEL only, a custom delegation DSL, Cedar plus a second language. |
| [ADR-0003: Apache License 2.0](../decisions/0003-apache-2-license.md) | The whole repository is Apache-2.0, inbound equals outbound, no CLA. | AGPL, MIT/BSD, source-available licences, MPL. |
| [ADR-0004: Rust workspace layout](../decisions/0004-rust-workspace-layout.md) | A Cargo workspace of small crates with dependencies pointing only downward, so the proxy cannot reach token minting. | One crate with modules, a lib plus bin pair, one crate per standard, a Go implementation. |
| [ADR-0005: Policy decision point](../decisions/0005-policy-decision-point.md) | Two stages, capabilities first and Cedar second; requests are built from the chain and a typed tool catalog; fail closed on any error; AuthZEN types so other enforcement points can call it. | No validation, or a hand-maintained full schema; namespaced actions per server were deferred and later replaced by `Action::"<server>/<tool>"`. |
| [ADR-0006: Lease-based in-flight revocation](../decisions/0006-lease-based-in-flight-revocation.md) | One lease per hop in a server-side tree; holders renew; revoking a lease cascades to descendants with one write. | A `jti` blacklist, very short token lifetimes only, per-call introspection at the IdP. |
| [ADR-0007: Actor authentication](../decisions/0007-actor-authentication.md) | Authenticate the agent in an exchange with an RFC 8693 `actor_token` from configured workload-identity issuers, or a client secret, plus `may_act` on the parent. | Client secrets only, mTLS with X.509-SVIDs at `/token`, `private_key_jwt` per agent. |
| [ADR-0008: Admin console](../decisions/0008-admin-console.md) (proposed) | Vanilla static files embedded in the server, on a separate opt-in listener, with the admin token held in page memory. | A TypeScript app built with Node in CI, or a separate console process calling the admin API across origins; `/admin/ui/` on the main listener and a cookie session were the rejected sub-options. |
| [ADR-0009: Output labelling](../decisions/0009-output-labelling.md) (proposed; phase 1 built, session 9) | The proxy labels every upstream result untrusted, taints the delegation run by `chain_id`, and policy can require an approval bound to one call (`@obligation("approval")`, `-32008`). | Argument-level taint only, SDK-side labelled values only, no labelling. Argument matching (phase 2) is on `main` too (#55). |
| [ADR-0010: Run limits](../decisions/0010-run-limits.md) (accepted; phases 1 and 2 built, session 11) | Count, amount and destination budgets declared per token hop, charged against every hop of the chain in the decision's transaction, exposed to Cedar as `context.budget`; run usage as `context.usage` for soft limits in policy. | Per-run budgets in configuration or policy only, reservation carved out of the parent at exchange, per-user rate windows, or no new mechanism (pin amounts and rely on approvals). |
| [ADR-0011: Cedar-aware list filtering](../decisions/0011-cedar-aware-list-filtering.md) (proposed; nothing built, session 14) | Opt in with `[proxy] list_filter = "policy"`; hide a tool only when the catalog stage denies it or Cedar partial evaluation denies it for every possible call, approval-gated tools always kept. | Evaluating with an empty input (hides gated tools), a `_meta` hint instead of hiding, the status quo. |
| [ADR template](../decisions/0000-adr-template.md), [how ADRs are written](../decisions/README.md) | MADR 4 format; one file per decision, numbered. | |

### Specification and design

| Document | Decision or content | Alternative or caveat |
| --- | --- | --- |
| [RFC-0001](../spec/rfc-0001-attenuo.md) | The properties P1 to P4, the chain data model, token exchange, per-call authorization, leases, audit chaining. Section 10 says what is implemented. | Section 8 lists non-goals; section 9 the open questions. |
| [Threat model](../spec/threat-model.md) | Assume the agent is compromised and bound the damage; attenuo does not detect prompt injection. | Out-of-scope threats are listed, including loss of audit records on a power failure at `durability = "normal"`. |
| [Server request pipeline](../design/server.md) | The server is wiring around one `Pipeline::decide` used by both the proxy and AuthZEN; SQLite on a blocking pool; MCP method coverage and list filtering. | Deferred: a lease cache (v0 looks every lease up on every request, so revocation reaches the next one). |
| [Performance](../design/performance.md) | Measure the hot path in pieces; group commit, a verified-token cache and a policy request cache came from the measurements. | A per-call Cedar translation and one commit per audit append were the first versions. Numbers are from a shared VM and indicative only. |
| [Benchmark runs](../design/bench/2026-10-23-vm.md) | Four dated end-to-end runs (this one, plus `-proxy-stages`, `-policy-stage` and `-audit-write-path` in the same folder) that back the figures in Performance. | Not a reference machine. |
| [Output labelling](../design/output-labelling.md) | Why provenance, not the token or the policy, separates the suite's remaining attacks; the Cedar attributes, the approval flow and the audit records; the phased plan with the measured phase 1 numbers. | Phase 1, approvals and option (b), argument-level taint (#55), are built. Option (c), SDK-side labelled values, is not. |
| [Run limits](../design/run-limits.md) | Budgets per hop for the repetition and amount attacks that labelling only turns into approval requests; section 7 has every limits arm of the suite and what an operator should set. | Phases 1 and 2 built; phase 3 (per-user windows, reservation) is not. No uniform figure measured there is free of benign loss. |
| [Fuzzing](../design/fuzzing.md) | cargo-fuzz targets outside the workspace, public APIs only until round 3 (#130), which reaches crate-private SSE helpers through a `fuzzing` feature, with properties asserted, from valid mutated inputs. | In-workspace fuzzing was rejected: it needs nightly and its own lockfile. |
| [Rename plan](../design/rename-plan.md) | A script (`scripts/rename.py`) does one case-aware rename; history files keep the old name. | The name is not decided. |
| [Standards](../research/standards.md), [Incidents](../research/incidents-2025-2026.md), [Related work](../research/related-work.md), [Comparison](../comparison.md) | Background: which standards attenuo follows, the incidents it is built against, and how it differs from gateways, policy engines and IdP features. | |
| [Evaluation plan](../research/evaluation-plan.md), [Injection suite](../evaluation/injection-suite.md) | Ask a bounded question: if the agent is already injected, how many harmful calls get through and how many benign ones are refused. No LLM in the first slice. | Live-model evaluation is planned, not done. |
| Security reviews: [pass 1 and 2](../research/security-review-2026-10-22.md), [pass 3](../research/security-review-2026-10-23.md), [pass 4](../research/security-review-2026-10-23-pass4.md), [pass 5](../research/security-review-2026-10-24-pass5.md), [pass 6](../research/security-review-2026-10-25-pass6.md), [pass 7](../research/security-review-2026-10-25-pass7.md) | The numbered findings (SR-n) that explain most of the odd-looking rules in the code. Grep a code comment's `SR-` number here. | |
| [Concepts](../concepts/README.md) | Five short explainers: chain, capabilities, leases, audit, enforcement points. | |

## 4. Glossary

| Term | Meaning in this project |
| --- | --- |
| **Hop** | One link in a delegation chain: an agent, the capabilities it was given, its lease id and its times. Hop 0 is the root; hop n+1 is made by exchanging a hop-n token. |
| **Chain** | The originating user plus the hops from the root agent down to the token's holder (`DelegationChain`). Each hop's capabilities are a subset of the one above. |
| **Originating user** | The human the whole chain acts for: subject, issuer, attributes. Fixed at the root and covered by `ou_sig`. |
| **Capability** | A `server:tool` pattern with optional argument constraints (`Eq`, `OneOf`, `Prefix`, and since #96 `Range`) and optional run limits. What a hop may ever do. |
| **Attenuation** | Handing a sub-agent a subset of your own capabilities, never more. Enforced by `Capability::covers` and `CapabilitySet::attenuate` when a hop is added and again on every validation. |
| **Lease** | A server-side record per hop with an expiry. A call is allowed only if every lease in the chain is unrevoked and unexpired. Holders renew; revoking one lease kills its descendants. |
| **Actor token** | An RFC 8693 credential (for example a SPIFFE JWT-SVID) that proves which agent is asking for a delegation. Single use. Alternative to a client secret. Not the same as the delegation token the exchange returns. |
| **`may_act`** | An RFC 8693 claim on a parent token that names the only agents allowed to exchange it. |
| **`ou_sig`** | The issuer's signature over the issuer, the originating user and the root hop. Copied unchanged into every child token, so a sub-agent cannot change whom the chain acts for. Version 3 is current. |
| **Decision id** | The UUID of the audit record for one decision. Returned in `X-Attenuo-Decision-Id`, in a denial's `data.decision_id` and in AuthZEN `context.decision_id`; the key for finding a decision in the log. |
| **Reason** | The short code on a decision: `policy_allow`, `policy_deny`, `approval_required`, `capability_denied`, `lease_revoked`, `lease_expired`, `lease_unknown`, `tool_not_in_catalog`, `tool_not_listed`, `invalid_name`, `audit_error`, `label_error`, `budget_exhausted`, `budget_error`, `limit_arg_invalid`, `approval_invalid`, `input_type_mismatch`, `attribute_type_mismatch`, `token_expired` (a stream the re-check ended), the `exchange_*` codes of a refused exchange (`EXCHANGE_REFUSAL_REASONS`), and others. |
| **Catalog** | The `[policy.catalog]` table declaring every tool Cedar may name, with `readonly`, `sensitive`, `destructive` (default: not `readonly`), `output` (`untrusted` by default, or `trusted`) and typed inputs. A tool not in it is denied by default. |
| **Server-scoped action** | The Cedar action id `Action::"<server>/<tool>"` (for example `github/read_file`). A permit for one upstream's tool cannot match another's (SR-13). The older bare form needs `legacy_bare_actions`. |
| **Canonical name** | The one accepted spelling of a server or tool name: ASCII letters, digits, `_`, `.`, `-`, at most 128 bytes, compared byte for byte, never case-folded or normalized (`names.rs`). Not to be confused with canonical JSON below. |
| **Canonical JSON (JCS)** | RFC 8785: the byte-exact JSON form that anything hashed or signed uses, so another language computes the same bytes (`attenuo_core::jcs`). |
| **Hash chain** | Each audit entry's hash covers its sequence number, the previous hash and the record, so an edit anywhere breaks every later hash. |
| **Checkpoint** | A signed statement by the issuer key of the log's head (sequence number and hash) at a moment. Catches truncation and history rewrites that a bare chain cannot. |
| **Durability** | The `[audit] durability` setting, `normal` or `full`: whether each audit commit is synced to disk. `normal` can lose the newest records on a power failure; revocations are always synced. |
| **WAL** | SQLite's write-ahead log, used by the file-backed audit and lease stores; a background thread checkpoints it into the database file. Unrelated to audit checkpoints. |
| **DPoP** | RFC 9449 proof of possession. A token with `cnf.jkt` is usable only with a fresh proof signed by the key with that thumbprint. |
| **Sign-off** | A DPoP proof by the parent's key that consents to one exchange: it names the child key's thumbprint (`child_jkt`) and the actor (`child_actor`). |
| **PEP / PDP** | Policy enforcement point (the proxy, or a gateway) and policy decision point (`Pipeline::decide`, reachable over AuthZEN). |
| **AuthZEN** | The OpenID AuthZEN 1.0 evaluation API (`/access/v1/evaluation`) for asking the PDP a yes or no question without calling the tool. |
| **Root grant** | A `[[root_grants]]` entry: the most a root token may carry for a given user, issuer and agent. |
| **Session binding** | The proxy's record that an `Mcp-Session-Id` belongs to one principal (the chain's root lease), so another user cannot ride it. Since #89 the server also keeps, in `lease_sessions`, the full SHA-256 of each id the proxy bound with the chain that opened it, so the session can be revoked. |
| **Session tag, session digest** | `session_digest` is the SHA-256 of an `Mcp-Session-Id` in hex, what `lease_sessions` stores; `session_tag` is its first 12 characters, what audit records and logs carry. The raw id is stored nowhere. |
| **Refusal record** | A `deny` record of kind `decision` written through `Pipeline::record_rejection` for a refusal that had no pipeline decision: a lease refusal of `initialize` or another undecided request, a refused exchange (`token.exchange`) or renewal (`lease.renew`), a stream ended by the re-check (`stream.end`). Only for tokens that fully verified (SR-18). |
| **Lease selector** | What `POST /admin/leases/revoke` revokes by instead of a lease id: `user` (the originating `sub`, from `lease_subjects`), `chain_id` (the first hop's lease) or `session` (resolved through `lease_sessions`). `LeaseSelector` in `attenuo-audit`. |
| **Dev / test split** | In the injection suite, 63 development cases (the 46 whose policies were written alongside them, then 11 multi-call and 6 browsing cases written against the frozen policies), and 26 held-out test cases written afterwards against frozen policies. Do not confuse with `[dev] allow_root_mint`, the development-only token mint, or with `cargo test`. |
| **Run taint** | The output labels of one delegation run, stored by `chain_id` (the first hop's lease) in `run_labels`: one `{source, decision_id, seq}` per tool whose untrusted result the run has read. Every agent of the run shares it, so a sub-agent's read taints its parent. Cedar sees it as `context.session.tainted` and `tainted_by`; a store that cannot be read counts as tainted. |
| **`tool_result`** | The audit record kind appended after an allowed call's answer and before it is relayed: the call's `decision_id`, the SHA-256 and size of the RFC 8785 JSON of the answer, its label and a fingerprint count. Never the content. |
| **`approval_required`, `-32008`** | The reason when Cedar denies only through forbids annotated `@obligation("approval")` and a permit would otherwise allow the call, and the JSON-RPC code the proxy answers it with (`data`: `reason`, `decision_id`, `call_hash`, `approval_id`, `expires_at`). The call is not forwarded. |
| **Approval** | A record in the lease store's `approvals` table for one gated call: run, calling hop's lease, `call_hash`, the call, the run's labels, `expires_at` (default two minutes, never past the token or lease). Pending, then granted or declined by the user (`POST /approvals/{id}` with an ID token) or an operator (`/admin/approvals`), then consumed by the first identical retry from the same hop. Audit kinds `approval_request` and `approval_grant`; the consuming decision carries `approval: {id, by}`. |
| **`call_hash`** | SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}` (`ToolCall::call_hash`). What an approval is bound to: any change to an argument is a different call. |
| **Scripted approver** | The injection-suite runner's stand-in for the user in the `attenuo_labels` arm: it grants a gated call labelled benign and declines one labelled attack, through the operator endpoint, and retries a granted call once. It knows the labels, so it never makes a wrong decision. |
| **Listen stream, `AwaitedResults`** | The MCP `GET` stream on which an upstream may send messages, including the answer to a `POST` it answered with `202`. `AwaitedResults` in `label.rs` remembers each allowed call (by upstream, session, run and request id; ten minutes, 256 per session, 10,000 in all) so that such an answer is recorded and labelled like one in the `POST` body. |
| **Taint** | Two levels. Run taint (above): the run has read an untrusted result. Argument-level taint (ADR-0009 phase 2): an argument of a destructive call on a tainted run matches a fingerprint of an earlier untrusted result in the run's span index; Cedar sees `context.args_contain_untrusted` and `context.untrusted_args`. |
| **Run limit, budget** | A capability's `limits` (ADR-0010): `calls`, `sum` over one integer argument, `calls_per` value of one argument, or `distinct` values of one argument (optionally the URL host, `derive: host`). The maxima are in the signed token; the budget is what is left, kept by the server per hop lease. Cedar sees it as `context.budget`. |
| **Charge** | What an allowed call adds to every counter it matches, in every hop, in one store transaction (`LeaseStore::charge`): all or none, re-checked against `max`, logged under the decision id. The decision record lists them in `budget.charged`. Denied calls are never charged. |
| **Refund** | `LeaseStore::refund`: give back exactly what one decision charged, once. The pipeline does it when a charged decision's audit append fails; an operator does it with `attenuo budget refund` (`POST /admin/budgets/refund`, audited as `admin.budget.refund`) for a call whose effect did not happen. |
| **`distinct`** | The limit kind that counts different values of an argument. One `distinct_value` row per value seen (a keyed hash) and one count row; a value already seen adds nothing, and a refund removes the value rows its decision added. |
| **Run usage, soft limit** | Run usage: per run (`chain_id`) and destructive tool, the calls allowed, the catalog's `amount` input summed and whether its `destination` was seen, kept with no figure in any token and shown to Cedar as `context.usage`. A soft limit is a policy over it marked `@obligation("approval")` (such as `ask_on_repeat_payment`): it asks instead of refusing, and the approved call is counted, so the next one asks again. Token limits are always hard. |
| **`range`** | The constraint kind that bounds an integer argument, both ends inclusive: `{"op": "range", "value": {"min": 0, "max": 2000}}`, one bound optional. Read as Cedar reads a number (`as_long`), checked at the capability stage, narrowed by interval containment at exchange. Session 13. |
| **Retention, lease maintenance** | The three `[leases]` rules that delete what can no longer be used (session records, whole ended runs, then their counters, charge log and approvals), run by one background task every minute (`spawn_lease_maintenance`) in bounded passes. The audit log is never pruned. Session 13. |
| **`stream.end` bound** | At most one `stream.end` record per delegation chain (digest) and reason per window (`[proxy] record_window_seconds`, default 60 s) for `GET` listen streams (a `RecordWindow`); later ends in the window name that record in their final event and are counted in `audit_records_suppressed_total`. Every listen stream's end is counted in `proxy_streams_ended_total{cause}`. |
| **`RecordWindow`** | The bound on repeated refusal records in the proxy (`records.rs`): at most one record per delegation chain digest, fixed tool name and reason per window (`[proxy] record_window_seconds`, default 60 s; the table holds `record_window_max_keys` keys, default 10,000), the first; later occurrences are counted in `audit_records_suppressed_total` and name the first record. Two tables: `stream.end` of listen streams, and lease refusals of undecided requests (#107). Session 14. |
| **`charge_pruned`** | The 410 a refund answers when the decision's audit record shows a run-limit charge whose charge log entry was pruned (`no_charge_refusal`, #112; CLI exit 4). The three 404 `not_found` cases are an unknown decision, one that charged nothing, and one that charged run usage only. Session 14. |
| **Evaluations semantic** | `options.evaluations_semantic` of an AuthZEN batch (`Semantic` in `routes/authzen.rs`): `execute_all` (the default), `deny_on_first_deny` or `permit_on_first_permit`. A short-circuit batch answers, and audits, only the entries it decided. Session 14. |
| **Effect-free clamp** | What `attenuate` may change in a covered request (`effect_free_clamp` in the attenuation proptests): a `calls_per` or `distinct` `max` lowered to the parent's when the request's own `calls` is no larger, so the bound in force per value is the same. Session 14. |
| **Run sweep** | A prunable run being pruned across lease passes (`RunSweep`): walked whole from its top first, then deleted children before parents, the top last, each pass within `[leases] maintenance_batch_rows` rows; a renewal once deleting began is refused (#110). Session 14. |
| **`StreamEvent`** | One JSON-RPC message of a streamed `tools/call` answer, as `call_tool_stream` (Python) and `callToolStream` (TypeScript) yield it: `message`, `method` (for a notification or server request), `last_event_id` / `lastEventId`, the call's `decision_id` / `decisionId`, and on the last event only `result` with `is_final` / `isFinal` true (#115). Session 15. |
| **Look-alike stream end, `upstream_stream_end_shape`** | An upstream message in the shape of the proxy's stream-end event: a response with `id` `null` or absent and `error.code` `-32001` by value (`has_stream_end_shape`). Since #117 the proxy rewrites each one it relays to `-32005` with `data.reason` `upstream_stream_end_shape` and the upstream's error under `data.upstream_error`, so only the proxy's own `-32001` with `id: null` reads as a cut. Session 15. |
| **`PROPTEST_RNG_SEED`** | proptest's own variable for a fixed seed (a decimal u64), read by the `proptest_config` helper in each crate's `tests/proptest_seed/mod.rs`. CI pins `20261024`; without it the seed is random and printed as `proptest: random seed, replay with PROPTEST_RNG_SEED=<n>`. A made-up `PROPTEST_SEED` only draws proptest's "Ignoring unknown env-var" warning (#116). Session 15. |
| **Trusted publishing** | PyPI's upload by OIDC: the PyPI project names this repository, workflow `release-packages.yml` and environment `pypi`, and the publish job's `id-token: write` token is accepted instead of an API token. The npm package uses a token for now; npm's trusted publishing is untried (#118). Session 15. |
| **SR-n, F-n** | Finding numbers from the security reviews (SR) and the fuzzing campaign (F). Comments and changelog entries cite them. |

## 5. Things that will surprise you

Each of these is deliberate, and most were found by a review or the fuzzers. Where a command shows it, it is one you can run against the setup in section 0.

- **A parent token delegates to a given actor once.** Exchanging the same parent for the same actor a second time fails with `invalid_grant` ("this credential was already used"), because the replay key is the parent's `jti` plus the actor. A long-running agent needs a fresh parent token for every re-exchange; this is why the SDK refresher takes an `exchange` callable instead of a token. An agent also cannot appear twice in one chain (`duplicate_actor`). See `exchanging_the_same_parent_for_the_same_actor_twice_is_refused` and session 6.
- **A DPoP sign-off names the child's key and the child's agent.** The parent's holder consents to one specific delegation, not "any exchange by anyone holding my token" (SR-40). A plain proof by the parent's key is refused with 401 `invalid_dpop_proof`, and every proof's `jti` is single-use, so replaying a sign-off fails too. Session 2 shows it.
- **`ou_sig` is version 3 and the verifier refuses version 2.** Moving to canonical JSON (SR-20) changed the signed bytes, so older tokens must be re-issued from the root. The audit entry hash, the export format (`attenuo-audit-export-v2`) and the database were bumped the same way; an old audit database is refused at startup, with no migration.
- **Export verification is strict.** `attenuo audit verify --file` fails if the export has no header, holds entries outside the range the header declares, or ends with entries after its last signed checkpoint (fuzz finding F5). Sign the head with `GET /admin/audit/checkpoint` before exporting, or pass `--allow-unsigned-tail` knowingly.
- **A valid JWT is not enough.** Every call also needs every lease alive, so a token whose holder stopped renewing is denied while its signature and `exp` are fine. There is no lease cache in v0; revocation reaches the next request.
- **`tools/list` shows less than the upstream has, and is not audited.** The filter uses capabilities only (no Cedar, no audit record), and it applies in JSON, batches and SSE. A listed tool can still be denied when called.
- **Unknown tools are denied.** A tool absent from `[policy.catalog]` gets `tool_not_in_catalog`, and a `tools/call` name the upstream never listed gets `tool_not_listed`. Names are never normalized, so `Delete_Repo` is not `delete_repo`.
- **`policy lint` without `--config` checks less.** It declares the tools from the policy's own `<server>/<tool>` action names, so a correct policy passes, but it cannot know `resource.readonly`, `resource.sensitive`, input types or user attributes. It prints a `note:` saying so. Pass `--config` for the full check.
- **`--server` means two things.** Before the subcommand it is the attenuo server's URL; after `call`, `tools` or `authzen eval` it is the MCP upstream name.
- **The agent id `attenuo` is reserved.** The server uses it for its own audit records, so no exchange may name it as the actor (SR-34, SR-45).
- **`-32003` is only attenuo's denial if the decision id is in the response header.** An upstream can send its own `-32003`; the SDKs and the examples raise `Denied` only when `data.decision_id` matches `X-Attenuo-Decision-Id` (SR-32, SR-53).
- **The default audit durability can lose the newest records on a power failure.** The surviving log is a clean prefix and still verifies; use `durability = "full"` if every executed call must be on disk (SR-48).
- **A restart forgets things.** The session registry is in memory, so every MCP session ends; the demo config also uses an in-memory audit log and a fresh signing key, so all tokens die.
- **A 500 never explains itself.** The body says "the details are in the server log" (SR-43); look in the log, not the response.
- **A shared `CARGO_TARGET_DIR` can run the wrong server.** If several checkouts build into one target directory, `target/debug/attenuo-server` is whichever built last. Pin binaries with `ATTENUO_BIN_DIR` (the demo and the integration tests honour it).
- **The SDK's local `inspect` is not verification of the user block.** It checks signature, `typ`, `exp` and that `sub`/`act` match the chain, not `ou_sig`; the server checks that on every request.

- **Every result is untrusted unless the catalog says otherwise.** That includes the answer of a destructive call and the answers a sub-agent reads: the taint belongs to the run, keyed by the root hop's lease, so a coder's read makes its parent's next `create_issue` ask for an approval. Mark a tool `output = "trusted"` only when its answers cannot carry text from outside. Session 9 shows the parent case.
- **A grant is used by the identical retry only, once.** The approval is bound to the `call_hash` and the calling hop's lease. A retry with any argument changed gets `-32008` with a new approval; the second identical retry after the grant gets a new approval too; another agent of the same run cannot use it. If the retry's decision cannot be written, the approval is given back (`give_back`), so a grant is spent exactly when an allowed decision naming it is in the log.
- **`-32008` never appears on the `GET` listen stream, but `label_error` can, without a decision header.** A gated call is decided on its `POST` and never forwarded, so there is nothing for the upstream to answer later. An allowed call answered on the listen stream is labelled there, and if that fails the answer is replaced by `-32003` `label_error` with no `X-Attenuo-Decision-Id` (the stream's headers went out when it opened), so the SDKs see an upstream `RpcError`, not `Denied`. An answer that arrives after its ten minutes, or after its entry was evicted, is relayed unrecorded ([server design](../design/server.md), "Limits").
- **The approver in the injection suite is a script that knows the labels.** "0 attack calls approved" in the labels results is true by construction. The number that measures attenuo is "attack allowed without approval" (1/77 dev, 1/38 test); the approve-all bound (15/77, 7/38) is what a user who grants everything would get. Run limits (session 11) aim at the gap between the two.
- **No approval passes a token limit.** `budget_exhausted` is decided before Cedar, so an approval forbid never gets a say and a granted approval does not help; the run needs a new token, and a parent can only hand on what it has left. Only limits written as policy over `context.usage` can ask.
- **Every hop pays.** A call is charged to every matching limited capability in every hop above it, so a sub-agent that re-delegates cannot reset its parent's budget, and a child token can show figures larger than what its parent still has between exchange and call. `lease tree` shows each hop's counters; the smallest figure left along a branch is what its lowest lease can spend. A child's own `distinct` counter starts empty, so it counts as new a value its parent has already seen.
- **A repeated `distinct` value adds nothing to the count, but is not free.** The charge transaction still runs, and since SR-62 it logs a zero-amount charge row and upserts the value row, so it costs about what a repeated `calls_per` value costs (+177 to +355 us at the client p50 on 2026-10-25; see [per-value limits](../design/performance.md#per-value-limits-on-current-main-2026-10-25)). Skipping it would mean reading counters outside the write lock, which races a refund. A refund of such a call restores only its other counters (`refunded 1 limit counter(s)` in session 11).
- **Usage is kept only when something can read it.** At every load and reload the engine decides whether any policy reads `context.usage` (or the catalog names `amount` or `destination`, or `[policy] track_usage = true`). If not, a destructive call writes no usage, Cedar sees zeros, and records carry no `usage`. A policy loaded mid-run starts from what was counted while usage was tracked, so it misses the calls in between. `track_usage = false` is refused, since a policy that reads usage must get it.
- **The upstream's failure is still charged.** The charge happens before forwarding, so a call that times out upstream has spent its budget (`upstream_failure_is_still_charged`). Giving it back is an operator's decision (`attenuo budget refund`), once per decision.
- **Older servers ignore limits.** A server before 0.1.0, or an external PEP that does not read `limits`, accepts a token with a `limits` block and enforces nothing, without an error or a log line. Until every replica and PEP runs 0.1.0, back a limit with a Cedar `forbid` or an approval. A `decision` record without a `budget` member for a limited capability came from such a server.

- **A forged token cannot write to the audit log, and a revoked one writes once a minute per request kind.** Refusals are recorded only after full verification (SR-18), so a stranger's garbage is a log line. A client that keeps sending `initialize`, `tools/list`, a `GET` or another undecided request with a revoked token leaves one `deny` record per chain, tool and reason a minute (#107); the other 401s name that record and are counted in `audit_records_suppressed_total`. Refused renewals, exchanges and `tools/call` are still one record each. Session 14 shows it.
- **A session revocation follows whoever opened the session first.** The binding in `lease_sessions` is write-once per session and upstream, so with `fake_mcp`, which gives every response `fake-session-1`, revoking that session revokes the first run that called after the server started. A real upstream assigns a new id per session.
- **`resources/unsubscribe` needs no capability.** It is on the passthrough allowlist (#90), so a capability or policy that names it has no effect any more; `resources/subscribe` is still decided.
- **A number in a declared string is no longer `policy_error`.** It is `input_type_mismatch`, decided before Cedar, even when no policy reads the argument. An undeclared argument, or any argument of a tool missing from the catalog, is still passed to Cedar as it is.

- **A fraction under a `range` is `capability_denied`, not `input_type_mismatch`.** The capability stage runs before the catalog's type check, so `5.5`, `"5"` or a missing argument under a range never reaches it, even where the catalog declares the argument `long`. A whole float such as `5.0` passes as `5`. The `-32003` names only the reason; the bound that was missed is in the dry run's diagnostic.
- **A pruned run reads as if it never existed.** After the lease retention, its token is `lease_unknown` (not `lease_revoked`), its lease tree is a 404, and after the run-state retention an operator refund of its decisions can no longer be honoured: since #112 it answers 410 `charge_pruned` (CLI exit 4), which the route reads from the audit log, except for a decision that charged run usage only, which stays a 404 that cannot say whether its run was pruned or revoked. Only the audit log still knows what the run did. Set the retentions above the longest token lifetime and refund window you have.
- **Nothing is pruned in the first maintenance interval, and nothing prunes on demand.** The maintenance ticker skips its first tick and has no route or flag; a retention of one second still waits for the next tick, a minute by default (`[leases] maintenance_interval_seconds`, session 14).
- **One `stream.end` record can stand for many streams.** Concurrent listen streams of one chain cut for the same reason within one window (60 s by default) leave one record, naming the first stream's server and session; the count is only in a metric and the log. Reopening on a revoked lease is bounded the same way since #107, in a table of its own: one `http.GET` record per chain and reason a minute.
- **A 401 can name a record written a window ago (a minute by default).** A lease refusal suppressed by the window carries the window's first record id in `X-Attenuo-Decision-Id` and `data.decision_id`, not a new one; looking it up shows the first refusal's time. Only when a concurrent first refusal is still being written, or when the record's append failed (#128, SR-81), is the id left out.
- **A short-circuit AuthZEN batch answers fewer entries than it was sent.** Under `deny_on_first_deny` or `permit_on_first_permit` the entries after the stop are left out, not denied, and leave no audit record. Count the answers, do not index them by request position past the stop.
- **AuthZEN discovery ignores the bearer.** `GET /.well-known/authzen-configuration` is public by decision, so an invalid token gets the document, not a 401.
- **A constraint name can hold a control character.** The exchange accepts any argument name a child adds (an extra constraint only narrows); the CLI escapes control characters when it prints one (SR-72), so `token inspect` shows `\u{1b}` rather than acting on it.
- **An empty AuthZEN batch is not an empty list.** `POST /access/v1/evaluations` with no `evaluations`, or `[]`, is decided as a single evaluation and answered as `{decision, context}`, as the specification says (section 7.1), not as `{"evaluations": []}`.

- **A streamed call cut by revocation names a record its own header never mentioned.** `call_tool_stream` raises `Denied` whose `decision_id` is the `stream.end` record written when the proxy cut the stream. The `X-Attenuo-Decision-Id` header, and the `decision_id` on every event before the cut, name the call's earlier `allow` record. The header went out before the cut, so it cannot vouch for the second id. Since #117 nothing but the proxy can send that shape. Session 15 shows the two ids.
- **An upstream's honest `-32001` with `id: null` reaches you as `-32005`.** The proxy cannot tell a hostile look-alike from an upstream that answers that way by mistake, so it rewrites both. The original is under `data.upstream_error`. On a streamed call the rewritten message is an ordinary event (its id is not the call's), and the call then ends with `AttenuoError` ("stream ended before the tools/call response"), not `RpcError`. A `-32001` that answers by the request's id is not rewritten and stays `Unauthorized`.
- **`PROPTEST_VERBOSE=1` prints nothing for a passing run, and CI never finds a new case.** Level 1 reports failures only; use level 2 to see the inputs. CI replays one pinned sequence on every run, so new cases come only from local runs, which use a random seed and print it.
- **Pushing the release tag publishes no SDK.** On a `v*` tag, `release-packages.yml` only builds and checks the packages. A publish needs a dispatch from that tag with `dry_run=false`, and a dispatch from `main` refuses to publish. A version uploaded once can never be uploaded again, so a mistake means a new version number.

When something in the code looks over-cautious, grep its `SR-` or `F` number in the three security reviews, the [fuzzing page](../design/fuzzing.md) and `CHANGELOG.md`; the reason is almost always written down there.

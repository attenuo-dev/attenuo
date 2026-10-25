# Codebase walkthrough

A reading-and-running plan for someone who wants to understand every piece of attenuo himself. It has five parts:

1. [A one-page mental model](#1-the-mental-model): the path of one proxied tool call and one token exchange, by file and function.
2. [Twelve reading sessions](#2-reading-sessions) of 45 to 60 minutes, each with files in order, a document to read beside them, three to six questions and a block of commands that shows the concept working.
3. [Why it is this way](#3-why-it-is-this-way): every ADR and design document in one line each.
4. [A glossary](#4-glossary).
5. [Things that will surprise you](#5-things-that-will-surprise-you).

Paths are relative to the repository root. Functions are cited by name, not line number, because lines move: find one with `grep -rn "fn name" crates/`. Line counts are rounded and were checked against main @ de3cf75 (2026-10-24); use them to size a session, not as a contract.

Every command below except `cargo bench` and `cargo +nightly fuzz` was run, in this order, on 2026-10-23 against `main` (about 110 commands; the Rust test filters, the Python and TypeScript test suites and the demo included). Where the text quotes output, that is what was printed. Line counts were refreshed the same day; they are rounded, so use them to size a session, not as a contract.

Session 9 (output labelling and approvals) and the labels-arm part of session 10 were added on 2026-10-24, and every command added there was run against `main` @ 1904f70. The same day the commands of sessions 1 to 7 that use the running server, the session 8 quickstart, the demo, and session 10's oracle, pytest and `run.py --out` were run again on that commit. They print what is quoted, except two counts that changed with the new features and were updated here: the demo now verifies 9 audit entries (the allowed call adds a `tool_result` record), and the suite's pytest run passes 24 and skips 7.

Session 11 (run limits) was added for the 0.1.0 documentation refresh, and every command in its block except the benchmarks was run against `main` @ a02bc83 on 2026-10-24, with its line counts checked on the same commit. On that commit the demo was run again (9 entries, as quoted) and the session 9 policy tests, whose count had grown, were updated; session 10's suite commands were run again and their quoted output updated for the new cases and arms.

Session 12 (audited refusals, revocation by user, chain and session, typed inputs, the policy harness, listen-stream list filtering and the new metrics) was added on the evening of 2026-10-24 for the merges #77 to #91. Every command in its block was run against `main` @ 471a319 the same day, and its file pointers were checked against that commit. Sessions 1 to 11 were not re-run for it.

## 0. Setup you need once

```sh
cargo build -p attenuo-server -p attenuo-cli
cargo build -p attenuo-proxy --features testing --example fake_mcp
export BIN=$PWD/target/debug          # or the directory your CARGO_TARGET_DIR points at
export PATH=$BIN:$PATH                # gives you `attenuo` and `attenuo-server`
```

`fake_mcp` is a stand-in for an MCP server: it has `read_file`, `create_issue` and `delete_repo` tools, echoes calls and does nothing else. It lands in `$BIN/examples/fake_mcp`.

Sessions 2, 5, 6, 7, 8, 9, 11 and 12 use a running server (session 9 starts a second one beside it, and session 12 restarts it for a clean log). Start the demo's server and fake upstream once, in a spare terminal or in the background, from the repository root:

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
| 12 | The response comes back with `X-Attenuo-Decision-Id`. A `tools/list` (and the other three list methods) result is filtered to what the chain could ever call. A streamed body is re-checked against lease and expiry every couple of seconds. | `add_decision_header`, `buffer_and_rewrite`, `stream_response_filtered`, `ListFilter` in `attenuo-proxy/src/filter.rs`, `StreamGuard` in `guard.rs` |

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

Twelve sessions: the CLI and the demo get their own, short, session, and output labelling with approvals and run limits, which landed after the others were written, get sessions 9 and 11. Session 12 covers what the evening merges of 2026-10-24 added across the crates. In order:

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

Sessions 9, 11 and 12 cut across sessions 3 to 8 and are easiest after all of them; read 11 after 9, since soft limits use its approvals. Session 12 needs only sessions 5 and 6. Sessions 7, 8 and 10 are light, so merge them if you have the time.

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
| 1 | `crates/attenuo-proxy/src/auth.rs` | The `Authorizer` trait (`authenticate_request`, `authorize`, `check_active`, `record_rejection`, `knows_tool`) and `AuthDecision`. This is the seam to the server. | 225 |
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

Read beside: [Integrating MCP clients](../guides/integrating-mcp-clients.md), then the `sdk/python/README.md` section "Keeping a token alive".

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `sdk/python/src/attenuo/capability.py` | `Capability`, `Equals`, `OneOf`, `Prefix`; serializes to the server's JSON. | 150 |
| 2 | `sdk/python/src/attenuo/_wire.py` | Request building and response parsing with no I/O, shared by the sync and async clients. | 365 |
| 3 | `sdk/python/src/attenuo/client.py` | `Client` / `AsyncClient`: `exchange`, `renew`, `call_tool`, `list_tools`, `authzen_evaluate`, `inspect`. | 430 |
| 4 | `sdk/python/src/attenuo/errors.py`, `token.py` | `Denied` (trusted only if the decision id is in the response header), `Token` and local decoding. | 360 |
| 5 | `sdk/python/src/attenuo/dpop.py`, `mcp.py` | `DpopKey` (including `sign_off`), `TokenAuth` for `httpx`. | 385 |
| 6 | `sdk/python/src/attenuo/refresh.py` | `TokenRefresher` and `AsyncTokenRefresher`: renew at a third of the lease interval, re-exchange before `exp`, back off, stop on a revoked lease. | 410 |
| 7 | `sdk/python/src/attenuo/admin.py` | `AdminClient`: revoke, lease status, audit, verify, dev root mint. | 935 |
| 8 | `sdk/typescript/src/` (`client.ts`, `refresh.ts`, `dpop.ts`, `wire.ts`) | The same, with WebCrypto and `fetch`. | 1100 |
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
| 7 | `fuzz/fuzz_targets/` and `fuzz/README.md` | Seventeen libFuzzer targets (twelve from the first campaigns, five from round 2 over run limits, budgets, approval tokens, the usage walker and the server routes); they assert properties as well as absence of panics. | 17 files |

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
| 12 | `config/policies/default.cedar`, `default_test.yaml`; `crates/attenuo-policy/tests/engine.rs` (`shipped_default_policy_passes_its_tests`) | #84 and #88. The starter policy: `like` has one wildcard that also matches `/` and the empty string, so `permit_create_issue_in_acme` pins `acme/<name>` with `!(like "acme/*/*")` and three `!=` guards; `permit_delete_acme_sandbox_repo` gives `forbid_sensitive_without_mfa` a decision it changes. 34 cases, all five policies exercised. The crate's embedded copy must stay byte-identical, which the engine test checks. | 450 |
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
attenuo policy test --fail-on-unexercised config/policies/default_test.yaml   # 34 passed, 0 failed ... all 5 policies exercised
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
| [Fuzzing](../design/fuzzing.md) | cargo-fuzz targets outside the workspace, public APIs only, with properties asserted, from valid mutated inputs. | In-workspace fuzzing was rejected: it needs nightly and its own lockfile. |
| [Rename plan](../design/rename-plan.md) | A script (`scripts/rename.py`) does one case-aware rename; history files keep the old name. | The name is not decided. |
| [Standards](../research/standards.md), [Incidents](../research/incidents-2025-2026.md), [Related work](../research/related-work.md), [Comparison](../comparison.md) | Background: which standards attenuo follows, the incidents it is built against, and how it differs from gateways, policy engines and IdP features. | |
| [Evaluation plan](../research/evaluation-plan.md), [Injection suite](../evaluation/injection-suite.md) | Ask a bounded question: if the agent is already injected, how many harmful calls get through and how many benign ones are refused. No LLM in the first slice. | Live-model evaluation is planned, not done. |
| Security reviews: [pass 1 and 2](../research/security-review-2026-10-22.md), [pass 3](../research/security-review-2026-10-23.md), [pass 4](../research/security-review-2026-10-23-pass4.md) | The numbered findings (SR-n) that explain most of the odd-looking rules in the code. Grep a code comment's `SR-` number here. | |
| [Concepts](../concepts/README.md) | Five short explainers: chain, capabilities, leases, audit, enforcement points. | |

## 4. Glossary

| Term | Meaning in this project |
| --- | --- |
| **Hop** | One link in a delegation chain: an agent, the capabilities it was given, its lease id and its times. Hop 0 is the root; hop n+1 is made by exchanging a hop-n token. |
| **Chain** | The originating user plus the hops from the root agent down to the token's holder (`DelegationChain`). Each hop's capabilities are a subset of the one above. |
| **Originating user** | The human the whole chain acts for: subject, issuer, attributes. Fixed at the root and covered by `ou_sig`. |
| **Capability** | A `server:tool` pattern with optional argument constraints (`Eq`, `OneOf`, `Prefix`) and optional run limits. What a hop may ever do. |
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
- **A repeated `distinct` value is free but not skipped.** It writes nothing and adds nothing to the count, yet the charge transaction still runs (about 25 microseconds on the file store; see [performance](../design/performance.md#limit-kinds-callsper-and-distinct-2026-10-24)). Skipping it would mean reading counters outside the write lock, which races a refund. A refund of such a call restores only its other counters (`refunded 1 limit counter(s)` in session 11).
- **Usage is kept only when something can read it.** At every load and reload the engine decides whether any policy reads `context.usage` (or the catalog names `amount` or `destination`, or `[policy] track_usage = true`). If not, a destructive call writes no usage, Cedar sees zeros, and records carry no `usage`. A policy loaded mid-run starts from what was counted while usage was tracked, so it misses the calls in between. `track_usage = false` is refused, since a policy that reads usage must get it.
- **The upstream's failure is still charged.** The charge happens before forwarding, so a call that times out upstream has spent its budget (`upstream_failure_is_still_charged`). Giving it back is an operator's decision (`attenuo budget refund`), once per decision.
- **Older servers ignore limits.** A server before 0.1.0, or an external PEP that does not read `limits`, accepts a token with a `limits` block and enforces nothing, without an error or a log line. Until every replica and PEP runs 0.1.0, back a limit with a Cedar `forbid` or an approval. A `decision` record without a `budget` member for a limited capability came from such a server.

- **A forged token cannot write to the audit log, but a revoked one can, once per request.** Refusals are recorded only after full verification (SR-18), so a stranger's garbage is a log line, while a client that keeps calling with a revoked token adds one `deny` record per HTTP request until its `exp`. There is no per-token cache to collapse them.
- **A session revocation follows whoever opened the session first.** The binding in `lease_sessions` is write-once per session and upstream, so with `fake_mcp`, which gives every response `fake-session-1`, revoking that session revokes the first run that called after the server started. A real upstream assigns a new id per session.
- **`resources/unsubscribe` needs no capability.** It is on the passthrough allowlist (#90), so a capability or policy that names it has no effect any more; `resources/subscribe` is still decided.
- **A number in a declared string is no longer `policy_error`.** It is `input_type_mismatch`, decided before Cedar, even when no policy reads the argument. An undeclared argument, or any argument of a tool missing from the catalog, is still passed to Cedar as it is.

When something in the code looks over-cautious, grep its `SR-` or `F` number in the three security reviews, the [fuzzing page](../design/fuzzing.md) and `CHANGELOG.md`; the reason is almost always written down there.

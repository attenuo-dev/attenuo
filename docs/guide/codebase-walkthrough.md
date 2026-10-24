# Codebase walkthrough

A reading-and-running plan for someone who wants to understand every piece of attenuo himself. It has five parts:

1. [A one-page mental model](#1-the-mental-model): the path of one proxied tool call and one token exchange, by file and function.
2. [Ten reading sessions](#2-reading-sessions) of 45 to 60 minutes, each with files in order, a document to read beside them, three to six questions and a block of commands that shows the concept working.
3. [Why it is this way](#3-why-it-is-this-way): every ADR and design document in one line each.
4. [A glossary](#4-glossary).
5. [Things that will surprise you](#5-things-that-will-surprise-you).

Paths are relative to the repository root. Functions are cited by name, not line number, because lines move: find one with `grep -rn "fn name" crates/`. Line counts are rounded and were checked against main @ de3cf75 (2026-10-24); use them to size a session, not as a contract.

Every command below except `cargo bench` and `cargo +nightly fuzz` was run, in this order, on 2026-10-23 against `main` (about 110 commands; the Rust test filters, the Python and TypeScript test suites and the demo included). Where the text quotes output, that is what was printed. Line counts were refreshed the same day; they are rounded, so use them to size a session, not as a contract.

Session 9 (output labelling and approvals) and the labels-arm part of session 10 were added on 2026-10-24, and every command added there was run against `main` @ 1904f70. The same day the commands of sessions 1 to 7 that use the running server, the session 8 quickstart, the demo, and session 10's oracle, pytest and `run.py --out` were run again on that commit. They print what is quoted, except two counts that changed with the new features and were updated here: the demo now verifies 9 audit entries (the allowed call adds a `tool_result` record), and the suite's pytest run passes 24 and skips 7.

## 0. Setup you need once

```sh
cargo build -p attenuo-server -p attenuo-cli
cargo build -p attenuo-proxy --features testing --example fake_mcp
export BIN=$PWD/target/debug          # or the directory your CARGO_TARGET_DIR points at
export PATH=$BIN:$PATH                # gives you `attenuo` and `attenuo-server`
```

`fake_mcp` is a stand-in for an MCP server: it has `read_file`, `create_issue` and `delete_repo` tools, echoes calls and does nothing else. It lands in `$BIN/examples/fake_mcp`.

Sessions 2, 5, 6, 7, 8 and 9 use a running server (session 9 starts a second one beside it). Start the demo's server and fake upstream once, in a spare terminal or in the background, from the repository root:

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

## 1. The mental model

attenuo sits between an AI agent and the MCP servers it calls. The agent holds a **token** that says whom it acts for, which agents sit between that person and it (the **chain**) and what each hop may do (**capabilities**). Every call goes through the proxy, which asks a **decision pipeline** three questions in a fixed order (is every lease alive, do the capabilities and the Cedar policy allow it, can the decision be written to the audit log) before it forwards anything.

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

Renewal (`POST /token/renew`, `routes/renew.rs`) extends a lease, never beyond the token's expiry or the parent lease. Revocation (`POST /admin/leases/{id}/revoke`, `routes/admin.rs` `revoke_lease`) marks a lease and all its descendants; the next call anywhere below it fails step 8 of the first table.

## 2. Reading sessions

Ten sessions: the CLI and the demo get their own, short, session, and output labelling and approvals, which landed after the others were written, get session 9. In order:

1. Core types and attenuation (`attenuo-core`).
2. Tokens, `ou_sig` and DPoP (`attenuo-token`).
3. Cedar policy and the translation cache (`attenuo-policy`).
4. Audit log, WAL, checkpoints and canonical JSON (`attenuo-audit`).
5. Proxy, session registry and list filtering (`attenuo-proxy`).
6. Server routes, exchange, leases, AuthZEN and admin (`attenuo-server`).
7. The CLI and the demo.
8. The SDKs and the refresh helper.
9. Output labelling and approvals: taint, `tool_result`, `-32008`, the approval store.
10. Evaluation suite (with the labels arm), benchmarks and fuzzing.

Session 9 cuts across sessions 3 to 8 and is easiest after all of them. Sessions 7, 8 and 10 are light, so merge them if you have the time.

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
| 7 | `config/policies/default.cedar`, `examples/github-leak-demo/policy.cedar`, `policy_test.yaml` | Three real policies and nine tests to read as examples. | 150 |

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

attenuo policy test examples/github-leak-demo/policy_test.yaml    # 9 passed, 0 failed
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
| 9 | `examples/python-agent/agent.py` | A planner delegates to a coder, the coder meets an injected instruction, the planner revokes (`mcp_client_example.py` beside it shows the raw client). | 130 |

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

Read beside: [ADR-0009: Output labelling](../decisions/0009-output-labelling.md), then sections 3.6 to 3.8 of the [output-labelling design](../design/output-labelling.md). Its status line still says nothing is implemented; phase 1 as built is described in `CHANGELOG.md` under [Unreleased]. Keep [Asking for approval after untrusted output](../guides/writing-policies.md#asking-for-approval-after-untrusted-output) and the Approvals part of [HTTP endpoints](../reference/http-api.md#approvals) open as lookups.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `config/policies/output-labels.cedar`, `output-labels_test.yaml` | The new Cedar attributes listed in the header comment, the two `@obligation("approval")` forbids, and ten policy tests that show every rule from the policy author's side. Read these first. | 130 |
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
attenuo policy test config/policies/output-labels_test.yaml   # 10 passed, 0 failed

# A second server on port 18081 beside the section 0 one, with the demo policy plus a permit for
# create_issue and the approval forbid. It uses the same fake upstream.
cat examples/github-leak-demo/policy.cedar - > /tmp/ob-labels.cedar <<'CEDAR'
@id("issues_in_public_repos")
permit(principal, action == Action::"github/create_issue", resource)
when { context.input has repo && context.input.repo like "alice/public-*" };

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

# What the log holds. tail prints no kind: a tool_result shows as "ALLOW ... reason=tool_result", an
# approval_request as "DENY ... reason=approval_requested" and an approval_grant as "ALLOW ... reason=approval_granted".
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
| 1 | `evaluation/injection-suite/README.md` | What a case is, the six arms (no enforcement, scope only, scope plus constraints, policy only, full attenuo, and full attenuo plus output labels), the dev and test splits, and "The labels arm" section. | 150 |
| 2 | `evaluation/injection-suite/cases/dev/`, `cases/test/`, `policies/` | The case files and the frozen suite policies (hashes in `cases/test/POLICY_HASHES.json`). | data |
| 3 | `evaluation/injection-suite/label_rules.py` | The labelling oracle: derives each call's expected outcome from the case structure, independent of hand labels. | |
| 4 | `evaluation/injection-suite/harness.py`, `run.py` | Starts real servers, replays every call through each arm, writes results with SHA-256 of every input. | |
| 4a | `evaluation/injection-suite/policies/labels.cedar`; in `harness.py`, `ARMS`, the labels-arm probe, `scripted_approver`, `_settle` and `AFTER_APPROVAL` | The `attenuo_labels` arm: the two approval forbids (hashed under `added_later`), the probe that skips the arm on a server that never answers `-32008`, the scripted approver (grants a call labelled benign, declines one labelled attack, as the operator through `POST /admin/approvals/{id}`) and the one identical retry after a grant, recorded as `after_approval`. | |
| 4b | `evaluation/injection-suite/results/2026-10-24-labels-v2.md`, with [the summary](../evaluation/injection-suite.md#second-run-with-retry-after-approval-2026-10-24) | How to read a labels run: in the arms table the attack column counts calls allowed without an approval; the "Approvals in `attenuo_labels`" tables say what became of each gated call; the approve-all bound is the attack rate if every request were granted (10/60, the `attenuo` arm's number). | 230 |
| 5 | `crates/attenuo-bench/src/lib.rs` | End-to-end load generator: proxy versus direct, by chain depth and concurrency. | 1432 |
| 6 | `crates/attenuo-core/benches/attenuation.rs`, `crates/attenuo-policy/benches/*.rs`, `crates/attenuo-server/benches/decide.rs` | criterion micro-benchmarks of the hot path. | 575 |
| 7 | `fuzz/fuzz_targets/` and `fuzz/README.md` | Twelve libFuzzer targets; they assert properties as well as absence of panics. | 12 files |

Check you understood:

1. Why are the suite's policies frozen before the test split was written, and what does `run.py --split test` do if one of them changed?
2. The micro-benchmarks do not include token verification, the lease lookup, the audit append or the network. Why are they still useful, and which benchmark does include them?
3. Pick one fuzz target and say which property it asserts beyond "does not crash".
4. The labels arm allows 1 of 60 dev attack calls without an approval and 0 attack calls were approved. Why is the second number true by construction, and which number in the report tells you what a careless user would let through?

Run it:

```sh
python3 evaluation/injection-suite/label_rules.py dev test     # oracle agreement; kappa 1.0, no disagreements
python3 -m pytest evaluation/injection-suite -q                # 24 passed, 7 skipped without ATTENUO_INTEGRATION=1
python3 -m pytest evaluation/injection-suite/test_suite.py -q -k 'approv or labels_arm'   # the approver and report logic: 6 passed, 2 skipped

# The full run starts servers from prebuilt binaries and takes about half a minute.
# --out keeps the results out of the committed results/ directory:
ATTENUO_BIN_DIR=$BIN \
  python3 evaluation/injection-suite/run.py --split all --out /tmp/ob-inj --tag mine
ls /tmp/ob-inj          # <date>-mine.json and <date>-mine.md; compare with results/2026-10-24-labels-v2.md (six arms)

# What became of every gated call in the labels arm, by hand label:
python3 - /tmp/ob-inj/$(date -u +%F)-mine.json <<'PY'
import collections, json, sys
d = json.load(open(sys.argv[1]))
for split in ("dev", "test"):
    gated = [c for c in d["splits"][split]["calls"] if c["outcome"] == "gated"]
    print(split, sorted(collections.Counter((c["role"], c["after_approval"]) for c in gated).items()))
PY
# dev [(('attack', 'declined'), 9), (('benign', 'allowed'), 18)]
# test [(('attack', 'declined'), 6), (('benign', 'allowed'), 2)]
grep -A2 '^| Benign gated' /tmp/ob-inj/$(date -u +%F)-mine.md   # 18/69 (26%) | 18/18 ... | 27 approval requests (dev); 2/29 | 2/2 ... | 8 (test)

env -u ATTENUO_SERVER -u ATTENUO_ADMIN_TOKEN cargo test -p attenuo-bench   # a short smoke run of the load generator (env -u: section 0)
cargo bench -p attenuo-server --bench decide                  # the decision path by stage (optional, slow)
OUT_DIR=/tmp/ob-bench DURATION=10 WARMUP=2 scripts/bench-e2e.sh   # release build plus the end-to-end matrix; the full run is about 9 minutes, and OUT_DIR keeps it out of docs/design/bench

# Fuzzing needs nightly and cargo-fuzz (see fuzz/README.md):
cargo +nightly fuzz list
cargo +nightly fuzz run dpop_proof -- -max_total_time=60
```

The runner starts its own servers, so it ignores any `ATTENUO_*` variables from section 0 (other than `ATTENUO_BIN_DIR`) and prints one warning. The `cargo +nightly fuzz` commands, the `bench-e2e.sh` run and the Rust benches were not run for this page; the Python oracle, the pytest runs, `run.py --out` and the gated-call count were. `run.py` runs the labels arm only on a server with the approvals API; on an older binary it prints why it skipped the arm and records it under `skipped_arms`.

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
| [ADR-0009: Output labelling](../decisions/0009-output-labelling.md) (proposed; phase 1 built, session 9) | The proxy labels every upstream result untrusted, taints the delegation run by `chain_id`, and policy can require an approval bound to one call (`@obligation("approval")`, `-32008`). | Argument-level taint only, SDK-side labelled values only, no labelling. Argument matching is phase 2. |
| [ADR-0010: Run limits](../decisions/0010-run-limits.md) (proposed; implementation in progress on another branch) | Count and amount budgets declared per token hop, charged against every hop of the chain in the decision's transaction, exposed to Cedar as `context.budget`. | Per-run budgets in configuration or policy only, reservation carved out of the parent at exchange, per-user rate windows, or no new mechanism (pin amounts and rely on approvals). |
| [ADR template](../decisions/0000-adr-template.md), [how ADRs are written](../decisions/README.md) | MADR 4 format; one file per decision, numbered. | |

### Specification and design

| Document | Decision or content | Alternative or caveat |
| --- | --- | --- |
| [RFC-0001](../spec/rfc-0001-attenuo.md) | The properties P1 to P4, the chain data model, token exchange, per-call authorization, leases, audit chaining. Section 10 says what is implemented. | Section 8 lists non-goals; section 9 the open questions. |
| [Threat model](../spec/threat-model.md) | Assume the agent is compromised and bound the damage; attenuo does not detect prompt injection. | Out-of-scope threats are listed, including loss of audit records on a power failure at `durability = "normal"`. |
| [Server request pipeline](../design/server.md) | The server is wiring around one `Pipeline::decide` used by both the proxy and AuthZEN; SQLite on a blocking pool; MCP method coverage and list filtering. | Deferred: a lease cache (v0 looks every lease up on every request, so revocation reaches the next one). |
| [Performance](../design/performance.md) | Measure the hot path in pieces; group commit, a verified-token cache and a policy request cache came from the measurements. | A per-call Cedar translation and one commit per audit append were the first versions. Numbers are from a shared VM and indicative only. |
| [Benchmark runs](../design/bench/2026-10-23-vm.md) | Four dated end-to-end runs (this one, plus `-proxy-stages`, `-policy-stage` and `-audit-write-path` in the same folder) that back the figures in Performance. | Not a reference machine. |
| [Output labelling](../design/output-labelling.md) | Why provenance, not the token or the policy, separates the suite's remaining attacks; the Cedar attributes, the approval flow and the audit records; the phased plan with the measured phase 1 numbers. | Its status line predates the code; phase 1 is built. Options (b) and (c) are later phases. |
| [Run limits](../design/run-limits.md) | Budgets per hop for the repetition and amount attacks that labelling only turns into approval requests. | Proposed; implementation in progress. |
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
| **Capability** | A `server:tool` pattern with optional argument constraints (`Eq`, `OneOf`, `Prefix`). What a hop may ever do. |
| **Attenuation** | Handing a sub-agent a subset of your own capabilities, never more. Enforced by `Capability::covers` and `CapabilitySet::attenuate` when a hop is added and again on every validation. |
| **Lease** | A server-side record per hop with an expiry. A call is allowed only if every lease in the chain is unrevoked and unexpired. Holders renew; revoking one lease kills its descendants. |
| **Actor token** | An RFC 8693 credential (for example a SPIFFE JWT-SVID) that proves which agent is asking for a delegation. Single use. Alternative to a client secret. Not the same as the delegation token the exchange returns. |
| **`may_act`** | An RFC 8693 claim on a parent token that names the only agents allowed to exchange it. |
| **`ou_sig`** | The issuer's signature over the issuer, the originating user and the root hop. Copied unchanged into every child token, so a sub-agent cannot change whom the chain acts for. Version 3 is current. |
| **Decision id** | The UUID of the audit record for one decision. Returned in `X-Attenuo-Decision-Id`, in a denial's `data.decision_id` and in AuthZEN `context.decision_id`; the key for finding a decision in the log. |
| **Reason** | The short code on a decision: `policy_allow`, `policy_deny`, `approval_required`, `capability_denied`, `lease_revoked`, `lease_expired`, `lease_unknown`, `tool_not_in_catalog`, `tool_not_listed`, `invalid_name`, `audit_error`, `label_error`, and others. |
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
| **Session binding** | The proxy's record that an `Mcp-Session-Id` belongs to one principal (the chain's root lease), so another user cannot ride it. |
| **Dev / test split** | In the injection suite, 46 development cases whose policies were written alongside them, and 26 held-out test cases written afterwards against frozen policies. Do not confuse with `[dev] allow_root_mint`, the development-only token mint, or with `cargo test`. |
| **Run taint** | The output labels of one delegation run, stored by `chain_id` (the first hop's lease) in `run_labels`: one `{source, decision_id, seq}` per tool whose untrusted result the run has read. Every agent of the run shares it, so a sub-agent's read taints its parent. Cedar sees it as `context.session.tainted` and `tainted_by`; a store that cannot be read counts as tainted. |
| **`tool_result`** | The audit record kind appended after an allowed call's answer and before it is relayed: the call's `decision_id`, the SHA-256 and size of the RFC 8785 JSON of the answer, its label and a fingerprint count. Never the content. |
| **`approval_required`, `-32008`** | The reason when Cedar denies only through forbids annotated `@obligation("approval")` and a permit would otherwise allow the call, and the JSON-RPC code the proxy answers it with (`data`: `reason`, `decision_id`, `call_hash`, `approval_id`, `expires_at`). The call is not forwarded. |
| **Approval** | A record in the lease store's `approvals` table for one gated call: run, calling hop's lease, `call_hash`, the call, the run's labels, `expires_at` (default two minutes, never past the token or lease). Pending, then granted or declined by the user (`POST /approvals/{id}` with an ID token) or an operator (`/admin/approvals`), then consumed by the first identical retry from the same hop. Audit kinds `approval_request` and `approval_grant`; the consuming decision carries `approval: {id, by}`. |
| **`call_hash`** | SHA-256 of the RFC 8785 JSON of `{server, tool, arguments}` (`ToolCall::call_hash`). What an approval is bound to: any change to an argument is a different call. |
| **Scripted approver** | The injection-suite runner's stand-in for the user in the `attenuo_labels` arm: it grants a gated call labelled benign and declines one labelled attack, through the operator endpoint, and retries a granted call once. It knows the labels, so it never makes a wrong decision. |
| **Listen stream, `AwaitedResults`** | The MCP `GET` stream on which an upstream may send messages, including the answer to a `POST` it answered with `202`. `AwaitedResults` in `label.rs` remembers each allowed call (by upstream, session, run and request id; ten minutes, 256 per session, 10,000 in all) so that such an answer is recorded and labelled like one in the `POST` body. |
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
- **The approver in the injection suite is a script that knows the labels.** "0 attack calls approved" in the labels results is true by construction. The number that measures attenuo is "attack allowed without approval" (1/60 dev, 1/38 test); the approve-all bound (10/60, 7/38) is what a user who grants everything would get. ADR-0010's run limits aim at the gap between the two.
- **`attenuo audit tail` does not print the record kind.** A `tool_result` reads as `ALLOW ... reason=tool_result`, an `approval_request` as `DENY ... reason=approval_requested` and an `approval_grant` as `ALLOW ... reason=approval_granted`, next to the decisions. Filter with `GET /admin/audit?kind=decision` when you want decisions only.

When something in the code looks over-cautious, grep its `SR-` or `F` number in the three security reviews, the [fuzzing page](../design/fuzzing.md) and `CHANGELOG.md`; the reason is almost always written down there.

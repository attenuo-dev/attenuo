# Codebase walkthrough

A reading-and-running plan for someone who wants to understand every piece of onbehalf himself. It has five parts:

1. [A one-page mental model](#1-the-mental-model): the path of one proxied tool call and one token exchange, by file and function.
2. [Nine reading sessions](#2-reading-sessions) of 45 to 60 minutes, each with files in order, a document to read beside them, three questions and a block of commands that shows the concept working.
3. [Why it is this way](#3-why-it-is-this-way): every ADR and design document in one line each.
4. [A glossary](#4-glossary).
5. [Things that will surprise you](#5-things-that-will-surprise-you).

Paths are relative to the repository root. Functions are cited by name, not line number, because lines move: find one with `grep -rn "fn name" crates/`. Line counts are rounded and were taken at the commit this page was written against; use them to size a session, not as a contract.

Every non-cargo command below (the CLI, `curl`, the Python SDK, the demo, the evaluation oracle and runner) was run on 2026-10-23 against prebuilt binaries of this repository's `main`. The `cargo test` and `cargo bench` lines were not run for this page, which was written without building; their filters were checked against the test names in the source with `grep`, so a filter that matches nothing means a test was renamed since. TypeScript and fuzzing commands are marked where they appear.

## 0. Setup you need once

```sh
cargo build -p onbehalf-server -p onbehalf-cli
cargo build -p onbehalf-proxy --features testing --example fake_mcp
export BIN=$PWD/target/debug          # or the directory your CARGO_TARGET_DIR points at
export PATH=$BIN:$PATH                # gives you `onbehalf` and `onbehalf-server`
```

`fake_mcp` is a stand-in for an MCP server: it has `read_file`, `create_issue` and `delete_repo` tools, echoes calls and does nothing else. It lands in `$BIN/examples/fake_mcp`.

Sessions 2, 5, 6, 7, 8 and 9 use a running server. Start the demo's server and fake upstream once, in a spare terminal or in the background, from the repository root:

```sh
$BIN/examples/fake_mcp --port 13001 > /tmp/ob-fake.log 2>&1 &
RUST_LOG=warn onbehalf-server --config examples/github-leak-demo/config.toml > /tmp/ob-server.log 2>&1 &
export ONBEHALF_SERVER=http://127.0.0.1:18080 ONBEHALF_ADMIN_TOKEN=demo-admin-token
sleep 2 && curl -s $ONBEHALF_SERVER/healthz       # {"status":"ok","version":"0.1.0"}
```

The config uses fixed ports (18080 for onbehalf, 13001 for the upstream), an in-memory audit log (`sqlite_path = ":memory:"`, so a restart starts a new log) and an ephemeral signing key (so a restart invalidates every token). Stop everything with `pkill -x onbehalf-server; pkill -x fake_mcp`.

Two tokens are used again and again. Mint them in the same shell:

```sh
ROOT=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --print token)
CODER=$(printf '%s\n' demo-coder-secret | ONBEHALF_TOKEN="$ROOT" \
  onbehalf token exchange --actor coder --client-secret-stdin --cap github:read_file --print token)
```

`ROOT` is Alice's assistant holding every GitHub tool (hop 0). `CODER` is what the assistant hands a sub-agent: `read_file` only (hop 1). A parent token can be exchanged for a given actor once (see [section 5](#5-things-that-will-surprise-you)), so mint a fresh `ROOT` whenever a block exchanges it again.

If you would rather watch than type, `bash examples/github-leak-demo/run.sh` plays the whole scenario and checks every step. Set `ONBEHALF_BIN_DIR=$BIN` to skip its own build.

## 1. The mental model

onbehalf sits between an AI agent and the MCP servers it calls. The agent holds a **token** that says whom it acts for, which agents sit between that person and it (the **chain**) and what each hop may do (**capabilities**). Every call goes through the proxy, which asks a **decision pipeline** three questions in a fixed order (is every lease alive, do the capabilities and the Cedar policy allow it, can the decision be written to the audit log) before it forwards anything.

Two flows matter. Read them with the code open.

### One proxied tool call

A client sends `POST /mcp/github` with a JSON-RPC `tools/call` body and `Authorization: Bearer <token>`.

| Step | What happens | Where (crate, file, function) |
| --- | --- | --- |
| 1 | The route exists because the server merges the proxy router into its own. | `onbehalf-server/src/lib.rs` `router`; `onbehalf-proxy/src/proxy.rs` `router`, which sends `POST` to `handle_post` |
| 2 | The bearer (and DPoP proof, if the token is bound) is authenticated. The proxy asks its `Authorizer` trait; the server implements it. | `proxy.rs` `authenticate` calls `Authorizer::authenticate_request` (trait in `onbehalf-proxy/src/auth.rs`); implemented by `ServerAuthorizer` in `onbehalf-server/src/authz.rs` |
| 3 | The token is verified, or found in a bounded cache of tokens already verified (expiry and chain validity are re-checked on a hit). Verification checks signature, `typ`, `iss`, `aud`, `exp`, that `sub`/`act` match the chain, `ou_sig`, and the chain's structure. | `ServerAuthorizer::verify_inner` calls `onbehalf_token::Verifier::verify` (`onbehalf-token/src/verifier.rs`), which ends in `DelegationChain::validate_at` (`onbehalf-core/src/chain.rs`) |
| 4 | DPoP: if the token carries `cnf.jkt`, the request needs a proof by that key, and the proof's `jti` is single-use. | `onbehalf-server/src/dpop.rs` `Dpop::check_presented`; proof parsing in `onbehalf-token/src/dpop.rs` `verify_proof` |
| 5 | An `Mcp-Session-Id`, if present, must belong to this caller. | `proxy.rs` `session_gate`, using `SessionRegistry::check` in `onbehalf-proxy/src/session.rs` |
| 6 | The JSON-RPC message becomes a `ToolCall`. The tool name must obey the name rule and, by default, must have been listed by the upstream. | `proxy.rs` `handle_post_inner`, `screen_message`, `tool_name_refusal`; `onbehalf_core::names::check_call_name`; `onbehalf-proxy/src/listed.rs` `ListedTools` |
| 7 | The decision is requested; the server runs it on a blocking thread because SQLite is synchronous. | `proxy.rs` calls `Authorizer::authorize`; `ServerAuthorizer::authorize` runs `Pipeline::decide` (`authz.rs`) |
| 8 | Leases: every hop's lease must be known, unrevoked and unexpired. | `Pipeline::check_leases` calls `LeaseStore::check_all` (`onbehalf-audit/src/lease.rs`, implemented by `SqliteLeaseStore`) |
| 9 | Capabilities, then the tool catalog, then Cedar. A capability miss is `capability_denied` and Cedar never runs. | `PolicyEngine::authorize` (`onbehalf-policy/src/lib.rs`): `CapabilitySet::permits` (`onbehalf-core/src/capability.rs`), `ToolCatalog`, then the request is translated (cached in `RequestCache`, `onbehalf-policy/src/request.rs`) and evaluated by `cedar_policy` |
| 10 | The decision is written to the hash-chained log. If the write fails the answer becomes deny (`audit_error`). The new record's id is the **decision id**. | `DecisionRecord::new` (`onbehalf-core/src/decision.rs`), `AuditSink::append` implemented by `SqliteAudit` (`onbehalf-audit/src/sqlite.rs`, `log.rs` for the hash) |
| 11 | Deny: a JSON-RPC error `-32003` with `data.reason` and `data.decision_id`; nothing reaches the upstream. Allow: the request is forwarded with `reqwest`. | `proxy.rs` `refuse_call` / `handle_post_inner`; code `CODE_DENIED` in `onbehalf-proxy/src/jsonrpc.rs` |
| 12 | The response comes back with `X-Onbehalf-Decision-Id`. A `tools/list` (and the other three list methods) result is filtered to what the chain could ever call. A streamed body is re-checked against lease and expiry every couple of seconds. | `add_decision_header`, `buffer_and_rewrite`, `stream_response_filtered`, `ListFilter` in `onbehalf-proxy/src/filter.rs`, `StreamGuard` in `guard.rs` |

The AuthZEN endpoint (`POST /access/v1/evaluation`, `onbehalf-server/src/routes/authzen.rs`) enters the same `Pipeline::decide`, so a gateway that asks "may this call happen?" gets the same answer as the proxy, with the same audit record.

### One token exchange

A sub-agent (or its parent on its behalf) sends `POST /token` with the parent token, the new actor and the capabilities it wants (RFC 8693).

| Step | What happens | Where |
| --- | --- | --- |
| 1 | The route. JSON and form bodies are both accepted. | `onbehalf-server/src/routes/token.rs` `exchange`, then `exchange_sync` on a blocking thread |
| 2 | The actor proves who it is: a client secret from `[[agents]]`, an RFC 8693 `actor_token` from a trusted workload-identity issuer, or both. | `onbehalf-server/src/clientauth.rs`; `onbehalf-server/src/actor.rs` `ActorTrustRegistry::verify`; `take_actor_token` in `token.rs` |
| 3 | The parent token is verified exactly as in step 3 above. All its leases must be alive. | `state.verifier.verify`; `Pipeline::check_leases` |
| 4 | Refusals before anything is minted: the reserved agent id `onbehalf`; an actor already in the chain (`duplicate_actor`); `may_act` on the parent not naming this actor. | `exchange_sync`; `MayAct::permits` in `onbehalf-token/src/claims.rs` |
| 5 | If the parent is key-bound, the child must be bound too, and the parent's holder must have signed off on this child key and this actor. | `Dpop::bind_exchange` in `onbehalf-server/src/dpop.rs` |
| 6 | Attenuation: the requested capabilities must be covered by the parent's. This is where widening is refused (`invalid_scope`). The child's expiry is clamped to the parent's. | `ExchangeRequest::execute_with` (`onbehalf-token/src/exchange.rs`) calls `Issuer::exchange_with` (`issuer.rs`), which calls `DelegationChain::extend`, which calls `CapabilitySet::attenuate` |
| 7 | The new JWT is signed with the issuer's Ed25519 key. The parent's `ou_sig` is copied unchanged: it signs the user and the root hop, so nobody below the root can alter whom the chain acts for. | `Issuer::exchange_with`; `ou_sig_message` in `claims.rs` |
| 8 | Replay protection: "this parent delegated to this actor" and "this actor token was used" are recorded together or not at all. | `onbehalf-server/src/replay.rs` `ReplayCache::use_all_once` |
| 9 | The new lease is registered under the parent's lease, bound to the digest of the chain, and the issuance is audited. | `register_issued` and `audit_issuance` in `routes/mod.rs` |

Renewal (`POST /token/renew`, `routes/renew.rs`) extends a lease, never beyond the token's expiry or the parent lease. Revocation (`POST /admin/leases/{id}/revoke`, `routes/admin.rs` `revoke_lease`) marks a lease and all its descendants; the next call anywhere below it fails step 8 of the first table.

## 2. Reading sessions

Nine sessions instead of eight: the CLI and the demo get their own, short, session. Sessions 7 to 9 are light, so merge them if you have the time.

Each session has four parts. Read the files in the order given, with the "read beside" document open. Answer the questions without looking, then check the run block. Tests are named so that `cargo test -p <crate> <filter>` runs a handful, not the whole suite; add `-- --nocapture` to see output.

### Session 1: core types and attenuation (`onbehalf-core`)

This crate has no I/O, no async and no network. If you only understand one crate completely, make it this one: every security claim in the README rests on `covers` and `validate_at`.

Read beside: [Capabilities and attenuation](../concepts/capabilities-and-attenuation.md), and glance at [Delegation chain](../concepts/delegation-chain.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/onbehalf-core/src/lib.rs`, `error.rs` | The module map and the error types (`ChainError`, `AttenuationError`). | 100 |
| 2 | `crates/onbehalf-core/src/call.rs` | `ToolCall`: server, tool, arguments, whether the token was key-bound, the session. `arguments_digest`. | 70 |
| 3 | `crates/onbehalf-core/src/capability.rs` | `ArgConstraint` (`Eq`, `OneOf`, `Prefix`), `Capability::covers` (is a child no wider than a parent), `permits` (does this call fit), `CapabilitySet::attenuate`. The heart of the project. | 450 |
| 4 | `crates/onbehalf-core/src/chain.rs` | `DelegationChain`, `Hop`, `OriginatingUser`; `root`, `extend` (the only way to add a hop), `validate_at` (re-checks everything), `digest`, `prefix_digest`. | 780 |
| 5 | `crates/onbehalf-core/src/names.rs` | The one rule for server, tool and method names (ASCII, no `/` or `:` or `*`, at most 128 bytes, never normalized). | 250 |
| 6 | `crates/onbehalf-core/src/decision.rs`, `digest.rs` | `Decision`, `DecisionRecord` (what the audit log stores), the SHA-256 helper. | 150 |
| 7 | `crates/onbehalf-core/src/jcs.rs` | Skim only; session 4 returns to it. RFC 8785 canonical JSON. | 790 |

Check you understood:

1. A parent holds `github:read_file` with `repo` constrained to a prefix. Which of these children are accepted: no constraint on `repo`; a longer prefix; a `OneOf` of two repos that both match the prefix? Why does the code reject the first one?
2. Why is `DelegationChain::extend` the only way to build a longer chain, and why does `validate_at` still re-check narrowing at every hop?
3. Why does `names.rs` forbid `/` in a server name? (Hint: the Cedar action id is `"<server>/<tool>"`.)

Run it:

```sh
cargo test -p onbehalf-core capability::                  # unit tests next to the code
cargo test -p onbehalf-core chain::
cargo test -p onbehalf-core --test attenuation_props      # property tests: covers is sound, reflexive, transitive
cargo bench -p onbehalf-core --bench attenuation          # what `covers` costs (optional)

# The same rule through the server. Widening is refused:
printf '%s\n' demo-tester-secret | ONBEHALF_TOKEN="$CODER" \
  onbehalf token exchange --actor tester --client-secret-stdin --cap 'github:*'
# error: ... invalid_scope: delegation chain is invalid: hop 2 widens capabilities relative to hop 1 ...

# Narrowing with an argument constraint (a capability as JSON) is accepted. Use a fresh root:
ROOT2=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --print token)
CAP='{"server":"github","tool":"read_file","constraints":{"repo":{"op":"prefix","value":"alice/public-"}}}'
T=$(printf '%s\n' demo-tester-secret | ONBEHALF_TOKEN="$ROOT2" \
  onbehalf token exchange --actor tester --client-secret-stdin --cap "$CAP" --print token)
onbehalf token inspect "$T"          # a tree: assistant can github:*, tester can read_file {repo starts with "alice/public-"}
```

### Session 2: tokens, `ou_sig` and DPoP (`onbehalf-token`)

How a chain becomes a signed JWT and back, and why a leaked token is not enough.

Read beside: [RFC-0001](../spec/rfc-0001-onbehalf.md) section 4 (token exchange) and 4.1 (sender-constrained tokens). Then, for DPoP from the user's side, [Binding tokens to keys](../guides/binding-tokens-to-keys.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/onbehalf-token/src/claims.rs` | The JWT claims (`sub`, nested `act`, `chain`, `ou_sig`, `ou_sig_v`, `cnf`), `MayAct`, and `ou_sig_message`: exactly which bytes `ou_sig` signs. | 325 |
| 2 | `crates/onbehalf-token/src/keys.rs`, `detached.rs` | Ed25519 key loading, the `kid`, and `DetachedSigner` (signs with a domain-separation context; used for `ou_sig` and audit checkpoints). | 340 |
| 3 | `crates/onbehalf-token/src/issuer.rs` | `Issuer::issue_root_with` and `exchange_with`: build the chain, sign the user block once, sign the JWT. Key rotation via `trust_previous_key`. | 390 |
| 4 | `crates/onbehalf-token/src/verifier.rs` | `Verifier::verify`: header `typ`, signature by a trusted `kid`, claims, `ou_sig_v` (only 3), `ou_sig`, `sub`/`act` against the chain, `validate_at`. | 230 |
| 5 | `crates/onbehalf-token/src/exchange.rs` | `ExchangeRequest` (RFC 8693 request) and `execute_with`; `ExchangeResponse`. | 270 |
| 6 | `crates/onbehalf-token/src/dpop.rs` | `verify_proof` (RFC 9449), `jwk_thumbprint`, `Confirmation` (`cnf.jkt`), `DpopKey` with `proof` and `sign_off`. | 805 |

Check you understood:

1. What does `ou_sig` cover, who can make it, and why does a sub-agent hold a copy it cannot change?
2. A thief copies a DPoP-bound token from a log. What exactly is missing from his request, and what does the server record about each proof so it cannot be replayed?
3. Why does a token carry a `kid` and what happens to tokens signed by a retired key while it is still listed under `previous_key_paths`?

Run it:

```sh
cargo test -p onbehalf-token ou_sig            # the ou_sig tests: lifted into another chain, other issuer, v1/unknown versions refused
cargo test -p onbehalf-token --lib dpop        # unit tests in dpop.rs, including sign_off_names_the_child_key_and_actor
cargo test -p onbehalf-token exchange_cannot_widen_capabilities

onbehalf token inspect "$CODER" --verify       # decodes locally, then checks signature, type, issuer, audience, expiry, chain
curl -s $ONBEHALF_SERVER/.well-known/jwks.json # the public key and its kid; `inspect --verify` fetches this

# DPoP from the command line: a bound root token, and a sign-off naming the child's key.
mkdir -p /tmp/ob-dpop && cd /tmp/ob-dpop
onbehalf key gen --dpop assistant.jwk
CODER_JKT=$(onbehalf --json key gen --dpop coder.jwk | python3 -c 'import json,sys; print(json.load(sys.stdin)["jkt"])')
BROOT=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --dpop-key assistant.jwk --print token)
onbehalf token sign-off --subject-token "$BROOT" --dpop-key assistant.jwk \
  --child-jkt "$CODER_JKT" --actor coder > sign-off.txt
BCODER=$(ONBEHALF_TOKEN="$BROOT" ONBEHALF_CLIENT_SECRET=demo-coder-secret onbehalf token exchange \
  --actor coder --cap github:read_file --dpop-key coder.jwk --subject-token-dpop-file sign-off.txt --print token)
ONBEHALF_TOKEN="$BCODER" onbehalf call --dpop-key coder.jwk --server github --tool read_file \
  --arg repo=alice/public-docs --arg path=README.md      # ALLOWED
ONBEHALF_TOKEN="$BCODER" onbehalf call --server github --tool read_file \
  --arg repo=alice/public-docs --arg path=README.md      # error -32001 ... dpop_required: a stolen token without the key
cd - > /dev/null
```

### Session 3: Cedar policy and the translation cache (`onbehalf-policy`)

The second gate. Capabilities say what a token may ever do; Cedar says whether this particular call, with these arguments, in this chain, is acceptable.

Read beside: [ADR-0005: Policy decision point](../decisions/0005-policy-decision-point.md). For writing policies, [Writing and testing policies](../guides/writing-policies.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/onbehalf-policy/src/catalog.rs` | `ToolCatalog`, `ToolAttrs` (`readonly`, `sensitive`, typed `inputs`), `UnknownTools` (`deny`, `sensitive`, `allow`). | 215 |
| 2 | `crates/onbehalf-policy/src/schema.rs` | Generates the Cedar schema from the catalog; `action_id` makes `Action::"<server>/<tool>"`. | 210 |
| 3 | `crates/onbehalf-policy/src/lib.rs` | `PolicyEngineBuilder`, `PolicyEngine::authorize` (the two stages), `reload_policies_str`. Read the crate-level comment first: it documents the request shape. | 670 |
| 4 | `crates/onbehalf-policy/src/request.rs` | Turns a chain and a call into Cedar entities and context (`context.chain`, `context.input`, `context.originating_user`). `RequestCache` keeps the part that depends only on the chain and tool. Fails closed on anything it cannot represent. | 880 |
| 5 | `crates/onbehalf-policy/src/authzen.rs` | AuthZEN 1.0 request and response types, so any enforcement point can call the engine. | 220 |
| 6 | `crates/onbehalf-policy/src/lint.rs`, `testing.rs` | `onbehalf policy lint` and `onbehalf policy test` (YAML cases). Skim. | 1600 |
| 7 | `config/policies/default.cedar`, `examples/github-leak-demo/policy.cedar`, `policy_test.yaml` | Three real policies and nine tests to read as examples. | 150 |

Check you understood:

1. In what order do capabilities, the catalog and Cedar run, and which denial reasons does each stage produce?
2. What is cached in `RequestCache`, what is not, and why must the cache be keyed on everything it was built from (chain, tool, attributes)?
3. A `forbid ... when { resource.sensitive }` rule protects `delete_repo`. What happens to a tool that is missing from the catalog under `unknown_tools = "allow"`, and why is that the setting to avoid?

Run it:

```sh
cargo test -p onbehalf-policy --test engine                        # 30-odd decision tests
cargo test -p onbehalf-policy --test engine cached_translations_decide_like_fresh_ones
cargo test -p onbehalf-policy --test engine a_permit_for_one_servers_tool_does_not_match_another_server_sr13
cargo bench -p onbehalf-policy --bench policy_stage               # translation versus evaluation (optional)

onbehalf policy test examples/github-leak-demo/policy_test.yaml    # 9 passed, 0 failed
onbehalf policy lint examples/github-leak-demo/policy.cedar --config examples/github-leak-demo/config.toml
# 3 policies, 0 error(s), 0 warning(s). Without --config the catalog is empty and lint reports a false error.

# Ask for a decision without calling the tool (needs the running server):
onbehalf authzen eval --server github --tool read_file --arg repo=alice/public-x --arg path=a --token "$CODER"
# ALLOW policy_allow ... then try repo=bob/x: DENIED
```

### Session 4: audit log, WAL, checkpoints and canonical JSON (`onbehalf-audit`, and `jcs.rs` in core)

Why you can believe the log: each entry's hash covers the previous one, the issuer signs the head every so often, and an export can be checked offline with only the public key.

Read beside: [Audit log](../concepts/audit-log.md), then [RFC-0001](../spec/rfc-0001-onbehalf.md) section 7.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/onbehalf-core/src/jcs.rs` (first 100 lines and the tests) | RFC 8785 canonical JSON. Everything hashed or signed as JSON goes through it. | 790 |
| 2 | `crates/onbehalf-audit/src/log.rs` | `AuditEntry`, `compute_entry_hash` (SHA-256 over canonical `["onbehalf-audit-entry-v2", seq, prev_hash, record]`), `verify_entries`, the `AuditSink` trait. | 185 |
| 3 | `crates/onbehalf-audit/src/memory.rs` | An in-memory sink: the smallest implementation to read first. | 60 |
| 4 | `crates/onbehalf-audit/src/checkpoint.rs` | `Checkpoint` (seq, head hash, time, `kid`, signature), `CheckpointKeys` from a JWKS, `verify_with_checkpoints`. | 265 |
| 5 | `crates/onbehalf-audit/src/export.rs` | The `onbehalf-audit-export-v2` JSON Lines format, `parse_export`, strict `verify_export`. | 305 |
| 6 | `crates/onbehalf-audit/src/lease.rs` | The `LeaseStore` trait and `MemoryLeaseStore`: register, renew, revoke with cascade, `check_all`. | 240 |
| 7 | `crates/onbehalf-audit/src/sqlite.rs` | `SqliteAudit` and `SqliteLeaseStore`. Read the module comment, `Durability`, `append_locked` and the group-commit writer; skim the rest. WAL mode, background WAL checkpoints, `checkpoint_signed`. | 1930 |

Check you understood:

1. Name three kinds of tampering (edit a record, delete a middle row, truncate the tail) and which mechanism catches each: the hash chain, a signed checkpoint, or the strict export rules.
2. What does `durability = "normal"` risk, what does it never risk, and why are revocations always synced?
3. Why was canonical JSON needed at all, when `serde_json` already produces bytes? (Hint: `preserve_order`, and another language verifying the same log.)

Run it:

```sh
cargo test -p onbehalf-audit --test audit tamper
cargo test -p onbehalf-audit --test checkpoints forged_checkpoints_are_rejected
cargo test -p onbehalf-audit --test export entries_after_the_declared_range_fail_the_export_f5
cargo test -p onbehalf-audit --test wal
cargo test -p onbehalf-core jcs::                  # includes the RFC 8785 test vectors

# Against the running server (make a few calls first; session 5's block does):
onbehalf audit tail -n 5
onbehalf audit verify                              # walks the whole chain; "checkpoints: none signed yet" is normal early on
curl -s -H "Authorization: Bearer $ONBEHALF_ADMIN_TOKEN" $ONBEHALF_SERVER/admin/audit/checkpoint   # signs and stores one
onbehalf audit export --out /tmp/ob-export.jsonl
onbehalf audit verify --file /tmp/ob-export.jsonl  # offline; needs only the JWKS, no admin token

# Break it yourself. Flip one decision in the export:
sed 's/"decision":"deny"/"decision":"allow"/' /tmp/ob-export.jsonl > /tmp/ob-forged.jsonl
onbehalf audit verify --file /tmp/ob-forged.jsonl  # audit chain BROKEN at seq N; exit status 2
```

If the export holds entries newer than its last checkpoint, `verify --file` rejects it until you sign the head first (the `curl` above) or pass `--allow-unsigned-tail`. That is the strict behaviour described in [section 5](#5-things-that-will-surprise-you).

### Session 5: proxy, session registry and list filtering (`onbehalf-proxy`)

Everything between the agent's HTTP request and the decision: parsing MCP, deciding what counts as a call, and rewriting what comes back. This crate knows nothing about tokens or Cedar; it talks to an `Authorizer` trait.

Read beside: [Server request pipeline](../design/server.md), the "MCP method coverage", "List filtering" and `Mcp-Session-Id` parts (the rest is session 6).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/onbehalf-proxy/src/auth.rs` | The `Authorizer` trait (`authenticate_request`, `authorize`, `check_active`, `record_rejection`, `knows_tool`) and `AuthDecision`. This is the seam to the server. | 225 |
| 2 | `crates/onbehalf-proxy/src/jsonrpc.rs`, `config.rs`, `lib.rs` | JSON-RPC error codes (`-32003` denied, `-32006`/`-32007` capacity), `ProxyConfig`, crate docs. | 440 |
| 3 | `crates/onbehalf-proxy/src/session.rs` | `SessionRegistry`: binds an `Mcp-Session-Id` to the caller's root lease; bounded, idle expiry, per-principal cap (`bind`, `check`). | 410 |
| 4 | `crates/onbehalf-proxy/src/listed.rs` | `ListedTools`: names the upstream has returned from `tools/list`. | 95 |
| 5 | `crates/onbehalf-proxy/src/filter.rs` | `ListFilter`, `could_permit_*`: drop list entries the chain could never use. | 485 |
| 6 | `crates/onbehalf-proxy/src/sse.rs`, `guard.rs` | Incremental SSE parsing; `StreamGuard` ends a stream when its lease dies. | 630 |
| 7 | `crates/onbehalf-proxy/src/proxy.rs` | `handle_post`, `handle_post_inner`, `screen_message`, `session_gate`, `buffer_and_rewrite`, `stream_response_filtered`. Read in the order of the table in section 1. Large; do the first pass for shape only. | 1475 |
| 8 | `crates/onbehalf-proxy/src/testing.rs`, `examples/fake_mcp.rs` | A fake upstream and a fake authorizer for tests (feature `testing`). | 690 |

Check you understood:

1. A client calls `tools/call` with `params.name = "resources/read"`. Which check stops it from posing as the MCP method, and where?
2. `tools/list` through a token that holds only `github:read_file`: what does the client see, is Cedar consulted, and is anything written to the audit log?
3. One user opens 64 sessions and tries a 65th. What does the client get, and what does the proxy do to the session the upstream just created?

Run it:

```sh
cargo test -p onbehalf-proxy --test proxy denied_tools_call_returns_32003_and_never_reaches_upstream
cargo test -p onbehalf-proxy --test list_filtering
cargo test -p onbehalf-proxy --test session_limits
cargo test -p onbehalf-proxy --lib session::          # SessionRegistry unit tests

# An allowed call, with headers so you can see the decision id and the session id:
curl -s -D - -X POST $ONBEHALF_SERVER/mcp/github \
  -H "Authorization: Bearer $CODER" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"alice/public-docs","path":"README.md"}}}'
# HTTP/1.1 200 OK ... x-onbehalf-decision-id: <uuid> ... mcp-session-id: fake-session-1

# A denied call (policy: private repo). The upstream never sees it.
curl -s -X POST $ONBEHALF_SERVER/mcp/github \
  -H "Authorization: Bearer $CODER" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"repo":"alice/private-salaries","path":"x"}}}'
# {"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"onbehalf: denied: policy_deny","data":{"reason":"policy_deny","decision_id":"..."}}}

# List filtering: the fake upstream has three tools, the coder's token sees one.
curl -s -X POST $ONBEHALF_SERVER/mcp/github -H "Authorization: Bearer $CODER" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}'
# ... "tools":[{"name":"read_file", ...}]  and nothing else

# No token: 401 and a JSON-RPC -32001
curl -s -o /dev/null -w '%{http_code}\n' -X POST $ONBEHALF_SERVER/mcp/github -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Session 6: server routes, exchange, leases, AuthZEN and admin (`onbehalf-server`)

The wiring crate: it owns no authorization rules, but it owns the order they run in, and most of the security-review findings live here.

Read beside: [ADR-0006: Lease-based in-flight revocation](../decisions/0006-lease-based-in-flight-revocation.md). Keep [HTTP endpoints](../reference/http-api.md) open as a lookup, and read the rest of [Server request pipeline](../design/server.md) (the decision pipeline, blocking I/O, streaming recheck).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `crates/onbehalf-server/src/main.rs`, `lib.rs` | Startup, signal handling, and `router`: every route in one place. | 330 |
| 2 | `crates/onbehalf-server/src/state.rs` | `AppState::from_config`: builds the issuer, verifier, policy engine, stores, replay caches. `blocking` and `initial_lease_expiry`. | 525 |
| 3 | `crates/onbehalf-server/src/authz.rs` | `Pipeline::decide` (leases, policy, audit), `ServerAuthorizer` (the proxy's `Authorizer`), the verified-token cache. The most important file in the crate. | 810 |
| 4 | `crates/onbehalf-server/src/routes/token.rs` | `exchange` / `exchange_sync`: the token exchange table in section 1, line by line. | 540 |
| 5 | `crates/onbehalf-server/src/routes/renew.rs`, `dev_root.rs` | Lease renewal; the development root mint. | 420 |
| 6 | `crates/onbehalf-server/src/routes/admin.rs` | `require_admin`, revoke, lease status, audit range/verify/checkpoint/export, policy reload. | 410 |
| 7 | `crates/onbehalf-server/src/routes/authzen.rs` | AuthZEN single and batch evaluation; `check_issued` rejects a chain the server never issued. | 395 |
| 8 | `crates/onbehalf-server/src/dpop.rs`, `replay.rs`, `clientauth.rs`, `actor.rs` | DPoP policy (`bind_new`, `bind_exchange`), single-use caches, client-secret check, actor tokens (SPIFFE). | 1770 |
| 9 | `crates/onbehalf-server/src/idp/` (`mod.rs`, `intake.rs`, `jwks.rs`, `claims.rs`) | Hop 0 from a real identity provider: ID tokens and ID-JAG, JWKS cache. Read last, or skip until you wire an IdP. | 1700 |
| 10 | `crates/onbehalf-server/src/config.rs`, `metrics.rs`, `routes/ops.rs`, `routes/wellknown.rs` | Config schema with validation (read with `config/example.toml`), Prometheus metrics, `/readyz`, JWKS. | 2100 |

Check you understood:

1. A lease expires because the agent stopped renewing, but its JWT has ten minutes left. What does the next call get, and which function decides?
2. Why does the exchange record the replay key "this parent delegated to this actor" only after the new token is built, and together with the actor token's key?
3. What does `ServerAuthorizer` do on a verified-token cache hit, and why can it not skip `validate_at`?

Run it:

```sh
cargo test -p onbehalf-server --test e2e revoking_root_lease_cascades_to_child
cargo test -p onbehalf-server --test e2e unrenewed_lease_denies_even_though_the_jwt_is_valid
cargo test -p onbehalf-server --test e2e exchanging_the_same_parent_for_the_same_actor_twice_is_refused
cargo test -p onbehalf-server --test e2e authzen_matches_proxy_decisions
cargo test -p onbehalf-server --test dpop
cargo test -p onbehalf-server --lib authz::                 # Pipeline and the token cache

# Leases over HTTP. A fresh root, its lease, a child, then revoke the root:
R=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --print token)
L=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --print lease)
curl -s -H "Authorization: Bearer $ONBEHALF_ADMIN_TOKEN" $ONBEHALF_SERVER/admin/leases/$L
# {"lease_id":"...","active":true,"parent":null,"expires_at":"...","revoked_at":null,"revoke_reason":null}
onbehalf lease revoke $L --reason "trying it"
curl -s -H "Authorization: Bearer $ONBEHALF_ADMIN_TOKEN" $ONBEHALF_SERVER/admin/leases/$L     # active false

# The same-parent-same-actor rule:
R2=$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --print token)
for i in 1 2; do printf '%s\n' demo-coder-secret | ONBEHALF_TOKEN="$R2" \
  onbehalf token exchange --actor coder --client-secret-stdin --cap github:read_file --print token | wc -c; done
# the second prints: error: ... 400 Bad Request: invalid_grant: this credential was already used; present a fresh one

curl -s $ONBEHALF_SERVER/readyz                              # {"ready":true,"checks":{"audit":"ok","leases":"ok"}}
curl -s -H "Authorization: Bearer $ONBEHALF_ADMIN_TOKEN" "$ONBEHALF_SERVER/admin/audit?from=1&limit=2"
onbehalf policy reload                                       # re-reads the policy file without a restart
```

### Session 7: the CLI and the demo (`onbehalf-cli`, `examples/github-leak-demo`)

The CLI is a thin client; the demo is the project's one-page argument. Read the demo first so you know what the commands are for.

Read beside: [CLI commands](../reference/cli.md), and the demo's own README, `examples/github-leak-demo/README.md`.

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `examples/github-leak-demo/run.sh` | The scenario in nine steps, with checks on every exit status. | 200 |
| 2 | `examples/github-leak-demo/config.toml`, `policy.cedar`, `policy_test.yaml` | The server config, policy and policy tests it uses. | 190 |
| 3 | `crates/onbehalf-cli/src/cli.rs` | The whole command surface in clap definitions. | 910 |
| 4 | `crates/onbehalf-cli/src/main.rs` | What each command does with the HTTP API. | 845 |
| 5 | `crates/onbehalf-cli/src/client.rs`, `secrets.rs` | The HTTP client; how secrets are read (env, file, stdin, flag with a warning). | 550 |
| 6 | `crates/onbehalf-cli/src/jwt.rs`, `render.rs`, `dpop_key.rs`, `policy_cmd.rs` | Local token decoding and display, DPoP key files, `policy test` and `policy lint`. | 1040 |

Check you understood:

1. Which commands work with no server running?
2. The CLI never asks for a client secret as an argument by default. Where does it look first, and why?
3. In the demo, step 6 is denied with `capability_denied` and step 5 with `policy_deny`. What is the difference in what each tells you about the token?

Run it:

```sh
bash examples/github-leak-demo/run.sh            # needs no running server; starts its own on free ports
ONBEHALF_BIN_DIR=$BIN bash examples/github-leak-demo/run.sh     # reuse your build

cargo test -p onbehalf-cli
onbehalf --help; onbehalf token --help
onbehalf token inspect "$CODER"                  # offline decode
onbehalf tools --server github --token "$CODER" # tools/list through the proxy (--server here is the upstream)
onbehalf --json lease show "$(onbehalf token root --subject alice --agent assistant --cap 'github:*' --print lease)"
```

Expect the demo to end with `1 tools/call reached upstream. The three denied calls never left onbehalf.` and `audit chain OK: 8 entries verified`.

### Session 8: the SDKs and the refresh helper (`sdk/python`, `sdk/typescript`)

How an agent program uses all of this from code. The two SDKs mirror each other; read Python and skim TypeScript for the differences.

Read beside: [Integrating MCP clients](../guides/integrating-mcp-clients.md), then the `sdk/python/README.md` section "Keeping a token alive".

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `sdk/python/src/onbehalf/capability.py` | `Capability`, `Equals`, `OneOf`, `Prefix`; serializes to the server's JSON. | 150 |
| 2 | `sdk/python/src/onbehalf/_wire.py` | Request building and response parsing with no I/O, shared by the sync and async clients. | 365 |
| 3 | `sdk/python/src/onbehalf/client.py` | `Client` / `AsyncClient`: `exchange`, `renew`, `call_tool`, `list_tools`, `authzen_evaluate`, `inspect`. | 430 |
| 4 | `sdk/python/src/onbehalf/errors.py`, `token.py` | `Denied` (trusted only if the decision id is in the response header), `Token` and local decoding. | 360 |
| 5 | `sdk/python/src/onbehalf/dpop.py`, `mcp.py` | `DpopKey` (including `sign_off`), `TokenAuth` for `httpx`. | 320 |
| 6 | `sdk/python/src/onbehalf/refresh.py` | `TokenRefresher` and `AsyncTokenRefresher`: renew at a third of the lease interval, re-exchange before `exp`, back off, stop on a revoked lease. | 410 |
| 7 | `sdk/python/src/onbehalf/admin.py` | `AdminClient`: revoke, lease status, audit, verify, dev root mint. | 405 |
| 8 | `sdk/typescript/src/` (`client.ts`, `refresh.ts`, `dpop.ts`, `wire.ts`) | The same, with WebCrypto and `fetch`. | 1100 |
| 9 | `examples/python-agent/agent.py` | A planner delegates to a coder, the coder meets an injected instruction, the planner revokes. | 200 |

Check you understood:

1. `ob.call_tool` raises `Denied` only for some `-32003` errors. Which, and why does the SDK care?
2. Why does the refresher's `exchange` function have to bring a fresh parent token every time?
3. `inspect(verify=True)` does not check `ou_sig`. Who does, and when?

Run it:

```sh
PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests -q       # 100+ tests, no server needed (integration ones skip)
pip install -e sdk/python                                              # or keep using PYTHONPATH=sdk/python/src

PYTHONPATH=sdk/python/src CODER_SECRET=demo-coder-secret python3 - <<'PY'
import os
from onbehalf import AdminClient, Capability, Client, Denied, Prefix

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
ONBEHALF_INTEGRATION=1 ONBEHALF_BIN_DIR=$BIN PYTHONPATH=sdk/python/src python3 -m pytest sdk/python/tests/test_integration.py -q   # builds nothing; starts its own server
```

The TypeScript SDK needs `cd sdk/typescript && npm install && npm test`. That was not run for this page (no `node_modules` in the environment it was written in), so treat the TypeScript commands as unverified.

### Session 9: evaluation suite, benchmarks and fuzzing

The evidence that the design works and what it costs. Read this last; it makes the most sense once you know what the stages are.

Read beside: [Injection suite: results](../evaluation/injection-suite.md). Optional depth: [Evaluation plan](../research/evaluation-plan.md), [Performance](../design/performance.md), [Fuzzing](../design/fuzzing.md).

| Order | File | What it does | Lines |
| --- | --- | --- | --- |
| 1 | `evaluation/injection-suite/README.md` | What a case is, the five arms (no enforcement, scope only, scope plus constraints, policy only, full onbehalf), the dev and test splits. | 130 |
| 2 | `evaluation/injection-suite/cases/dev/`, `cases/test/`, `policies/` | The case files and the frozen suite policies (hashes in `cases/test/POLICY_HASHES.json`). | data |
| 3 | `evaluation/injection-suite/label_rules.py` | The labelling oracle: derives each call's expected outcome from the case structure, independent of hand labels. | |
| 4 | `evaluation/injection-suite/harness.py`, `run.py` | Starts real servers, replays every call through each arm, writes results with SHA-256 of every input. | |
| 5 | `crates/onbehalf-bench/src/lib.rs` | End-to-end load generator: proxy versus direct, by chain depth and concurrency. | 1410 |
| 6 | `crates/onbehalf-core/benches/attenuation.rs`, `crates/onbehalf-policy/benches/*.rs`, `crates/onbehalf-server/benches/decide.rs` | criterion micro-benchmarks of the hot path. | 580 |
| 7 | `fuzz/fuzz_targets/` and `fuzz/README.md` | Twelve libFuzzer targets; they assert properties as well as absence of panics. | 12 files |

Check you understood:

1. Why are the suite's policies frozen before the test split was written, and what does `run.py --split test` do if one of them changed?
2. The micro-benchmarks do not include token verification, the lease lookup, the audit append or the network. Why are they still useful, and which benchmark does include them?
3. Pick one fuzz target and say which property it asserts beyond "does not crash".

Run it:

```sh
python3 evaluation/injection-suite/label_rules.py dev test     # oracle agreement; kappa 1.0, no disagreements
python3 -m pytest evaluation/injection-suite -q                # 14 passed, 3 skipped without ONBEHALF_INTEGRATION=1

# The full run starts servers from prebuilt binaries and takes about half a minute.
# --out keeps the results out of the committed results/ directory:
env -u ONBEHALF_ADMIN_TOKEN -u ONBEHALF_SERVER ONBEHALF_BIN_DIR=$BIN \
  python3 evaluation/injection-suite/run.py --split all --out /tmp/ob-inj --tag mine
ls /tmp/ob-inj          # <date>-mine.json and <date>-mine.md; compare with results/2026-10-23-v2.md

cargo test -p onbehalf-bench                                   # a short smoke run of the load generator
cargo bench -p onbehalf-server --bench decide                  # the decision path by stage (optional, slow)
OUT_DIR=/tmp/ob-bench DURATION=10 WARMUP=2 scripts/bench-e2e.sh   # release build plus the end-to-end matrix; the full run is about 9 minutes, and OUT_DIR keeps it out of docs/design/bench

# Fuzzing needs nightly and cargo-fuzz (see fuzz/README.md):
cargo +nightly fuzz list
cargo +nightly fuzz run dpop_proof -- -max_total_time=60
```

The `env -u` is there because the runner starts its own servers and would otherwise pick up the `ONBEHALF_*` variables from section 0. The `cargo +nightly fuzz` commands, the `bench-e2e.sh` run and the Rust benches were not run for this page; the Python oracle, the pytest run and `run.py --out` were.

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
| [ADR template](../decisions/0000-adr-template.md), [how ADRs are written](../decisions/README.md) | MADR 4 format; one file per decision, numbered. | |

### Specification and design

| Document | Decision or content | Alternative or caveat |
| --- | --- | --- |
| [RFC-0001](../spec/rfc-0001-onbehalf.md) | The properties P1 to P4, the chain data model, token exchange, per-call authorization, leases, audit chaining. Section 10 says what is implemented. | Section 8 lists non-goals; section 9 the open questions. |
| [Threat model](../spec/threat-model.md) | Assume the agent is compromised and bound the damage; onbehalf does not detect prompt injection. | Out-of-scope threats are listed, including loss of audit records on a power failure at `durability = "normal"`. |
| [Server request pipeline](../design/server.md) | The server is wiring around one `Pipeline::decide` used by both the proxy and AuthZEN; SQLite on a blocking pool; MCP method coverage and list filtering. | Deferred: a lease cache (v0 looks every lease up on every request, so revocation reaches the next one). |
| [Performance](../design/performance.md) | Measure the hot path in pieces; group commit, a verified-token cache and a policy request cache came from the measurements. | A per-call Cedar translation and one commit per audit append were the first versions. Numbers are from a shared VM and indicative only. |
| [Benchmark runs](../design/bench/2026-10-23-vm.md) | Four dated end-to-end runs (this one, plus `-proxy-stages`, `-policy-stage` and `-audit-write-path` in the same folder) that back the figures in Performance. | Not a reference machine. |
| [Fuzzing](../design/fuzzing.md) | cargo-fuzz targets outside the workspace, public APIs only, with properties asserted, from valid mutated inputs. | In-workspace fuzzing was rejected: it needs nightly and its own lockfile. |
| [Rename plan](../design/rename-plan.md) | A script (`scripts/rename.py`) does one case-aware rename; history files keep the old name. | The name is not decided. |
| [Standards](../research/standards.md), [Incidents](../research/incidents-2025-2026.md), [Related work](../research/related-work.md), [Comparison](../comparison.md) | Background: which standards onbehalf follows, the incidents it is built against, and how it differs from gateways, policy engines and IdP features. | |
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
| **Decision id** | The UUID of the audit record for one decision. Returned in `X-Onbehalf-Decision-Id`, in a denial's `data.decision_id` and in AuthZEN `context.decision_id`; the key for finding a decision in the log. |
| **Reason** | The short code on a decision: `policy_allow`, `policy_deny`, `capability_denied`, `lease_revoked`, `lease_expired`, `lease_unknown`, `tool_not_in_catalog`, `tool_not_listed`, `invalid_name`, `audit_error`, and others. |
| **Catalog** | The `[policy.catalog]` table declaring every tool Cedar may name, with `readonly`, `sensitive` and typed inputs. A tool not in it is denied by default. |
| **Server-scoped action** | The Cedar action id `Action::"<server>/<tool>"` (for example `github/read_file`). A permit for one upstream's tool cannot match another's (SR-13). The older bare form needs `legacy_bare_actions`. |
| **Canonical name** | The one accepted spelling of a server or tool name: ASCII letters, digits, `_`, `.`, `-`, at most 128 bytes, compared byte for byte, never case-folded or normalized (`names.rs`). Not to be confused with canonical JSON below. |
| **Canonical JSON (JCS)** | RFC 8785: the byte-exact JSON form that anything hashed or signed uses, so another language computes the same bytes (`onbehalf_core::jcs`). |
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
| **SR-n, F-n** | Finding numbers from the security reviews (SR) and the fuzzing campaign (F). Comments and changelog entries cite them. |

## 5. Things that will surprise you

Each of these is deliberate, and most were found by a review or the fuzzers. Where a command shows it, it is one you can run against the setup in section 0.

- **A parent token delegates to a given actor once.** Exchanging the same parent for the same actor a second time fails with `invalid_grant` ("this credential was already used"), because the replay key is the parent's `jti` plus the actor. A long-running agent needs a fresh parent token for every re-exchange; this is why the SDK refresher takes an `exchange` callable instead of a token. An agent also cannot appear twice in one chain (`duplicate_actor`). See `exchanging_the_same_parent_for_the_same_actor_twice_is_refused` and session 6.
- **A DPoP sign-off names the child's key and the child's agent.** The parent's holder consents to one specific delegation, not "any exchange by anyone holding my token" (SR-40). A plain proof by the parent's key is refused with 401 `invalid_dpop_proof`, and every proof's `jti` is single-use, so replaying a sign-off fails too. Session 2 shows it.
- **`ou_sig` is version 3 and the verifier refuses version 2.** Moving to canonical JSON (SR-20) changed the signed bytes, so older tokens must be re-issued from the root. The audit entry hash, the export format (`onbehalf-audit-export-v2`) and the database were bumped the same way; an old audit database is refused at startup, with no migration.
- **Export verification is strict.** `onbehalf audit verify --file` fails if the export has no header, holds entries outside the range the header declares, or ends with entries after its last signed checkpoint (fuzz finding F5). Sign the head with `GET /admin/audit/checkpoint` before exporting, or pass `--allow-unsigned-tail` knowingly.
- **A valid JWT is not enough.** Every call also needs every lease alive, so a token whose holder stopped renewing is denied while its signature and `exp` are fine. There is no lease cache in v0; revocation reaches the next request.
- **`tools/list` shows less than the upstream has, and is not audited.** The filter uses capabilities only (no Cedar, no audit record), and it applies in JSON, batches and SSE. A listed tool can still be denied when called.
- **Unknown tools are denied.** A tool absent from `[policy.catalog]` gets `tool_not_in_catalog`, and a `tools/call` name the upstream never listed gets `tool_not_listed`. Names are never normalized, so `Delete_Repo` is not `delete_repo`.
- **`policy lint` without `--config` lies.** With no catalog the generated schema has no actions, so a correct server-scoped policy is reported as an error. Pass `--config`.
- **`--server` means two things.** Before the subcommand it is the onbehalf server's URL; after `call`, `tools` or `authzen eval` it is the MCP upstream name.
- **The agent id `onbehalf` is reserved.** The server uses it for its own audit records, so no exchange may name it as the actor (SR-34, SR-45).
- **`-32003` is only onbehalf's denial if the decision id is in the response header.** An upstream can send its own `-32003`; the SDKs and the examples raise `Denied` only when `data.decision_id` matches `X-Onbehalf-Decision-Id` (SR-32, SR-53).
- **The default audit durability can lose the newest records on a power failure.** The surviving log is a clean prefix and still verifies; use `durability = "full"` if every executed call must be on disk (SR-48).
- **A restart forgets things.** The session registry is in memory, so every MCP session ends; the demo config also uses an in-memory audit log and a fresh signing key, so all tokens die.
- **A 500 never explains itself.** The body says "the details are in the server log" (SR-43); look in the log, not the response.
- **A shared `CARGO_TARGET_DIR` can run the wrong server.** If several checkouts build into one target directory, `target/debug/onbehalf-server` is whichever built last. Pin binaries with `ONBEHALF_BIN_DIR` (the demo and the integration tests honour it).
- **The SDK's local `inspect` is not verification of the user block.** It checks signature, `typ`, `exp` and that `sub`/`act` match the chain, not `ou_sig`; the server checks that on every request.

When something in the code looks over-cautious, grep its `SR-` or `F` number in the three security reviews, the [fuzzing page](../design/fuzzing.md) and `CHANGELOG.md`; the reason is almost always written down there.

# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the parsers and
checks an attacker can reach: tokens, DPoP proofs, names and capabilities, the MCP proxy's
JSON-RPC and SSE handling, the policy engine's context building, and audit export
verification. Each target calls public APIs only. Why, how they are built and what they found:
[docs/design/fuzzing.md](../docs/design/fuzzing.md) and, for the second round, [docs/research/fuzzing-2026-10-24-round2.md](../docs/research/fuzzing-2026-10-24-round2.md).

This crate is not a member of the main workspace (the root `Cargo.toml` excludes it): it
needs a nightly toolchain and has its own `Cargo.lock`.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked

# Optional: seed inputs (a valid token, its chain, a signed audit export, SSE events).
cargo +nightly run --manifest-path fuzz/Cargo.toml --example seed_corpus

cargo +nightly fuzz list
cargo +nightly fuzz run dpop_proof -- -max_total_time=120
```

`-s none` turns off AddressSanitizer: faster, and much smaller builds (useful on a small
disk). The code under test is safe Rust, so ASan mostly adds value for `ring`'s C and
assembly. Debug assertions, and so integer-overflow checks, stay on either way.

Corpora grow in `fuzz/corpus/<target>/` and crashes land in `fuzz/artifacts/<target>/`; both
are ignored by git. To replay or shrink a crash:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
cargo +nightly fuzz fmt <target> fuzz/artifacts/<target>/crash-<hash>   # Debug-print the input
```

A crash that is a real bug gets a regression test in the crate that owns the code, so the
artifact itself is not kept.

## Targets

| Target | What it calls | Invariant beyond "no panic" |
| --- | --- | --- |
| `token_verify_bytes` | `Verifier::verify` on arbitrary bytes | whatever verifies came from the fixed issuer and has a sound chain |
| `token_verify_mutated` | `Verifier::verify` on a valid token: byte flips; claims edits re-signed with the issuer key (deep `act`, hundreds of hops, widened capabilities, unicode, edge numbers, odd headers); and with `ou_sig` re-signed too | byte-mutated tokens never verify with other claims; without a new `ou_sig`, the user block and root hop cannot change; anything accepted has a sound chain and consistent `sub`/`act`/`exp` |
| `chain_validate` | `DelegationChain` from JSON, `validate_at`, digests | an accepted chain narrows at every hop (checked independently) and round-trips |
| `ou_sig` | `claims::ou_sig_message`, `Issuer::issue_root`, `verify_detached` | the encoding is injective; a signature never verifies for another triple; arbitrary times never panic the issuer |
| `dpop_proof` | `dpop::verify_proof` and the server's `Dpop::verify` (replay cache) with fuzzed `htm`, `htu`, `iat`, `ath`, `jti`, header and `jwk`, raw or correctly signed | an accepted proof matches the request, is within `max_age`, and is refused the second time |
| `names` | `attenuo_core::names` checks | the name sets nest as documented; `<server>/<call>` splits back into one pair |
| `capability_attenuation` | `Capability::covers`, `CapabilitySet::{covers, attenuate, permits}` over small alphabets | if `parent ⊇ child` then every call `child` permits, `parent` permits; `attenuate` agrees with `covers`; coverage is reflexive and transitive |
| `proxy_jsonrpc` | `attenuo_proxy::router` end to end, with a fuzz-driven upstream | nothing unpermitted reaches the upstream (SR-07 included); 413 over the body limit; 400 for a bad `Mcp-Session-Id`; no unfiltered `tools/list` entry reaches the client |
| `proxy_sse` | `SseFramer`, `SseRewriter`, `ListFilter` on chunked bytes | framing is the input cut at event ends; rewriting does not depend on chunking; filtered answers hold only permitted tools |
| `policy_context` | `PolicyEngine::authorize` with arbitrary arguments and user attributes, `decimal` and `set<decimal>` inputs among them; `PolicyEngine::evaluate` (AuthZEN) on arbitrary JSON | a documented reason every time; an allow passed the capability stage; deterministic up to the order of `policy_ids`; on `create_issue`, the stage that denies and the `dec_` policies that decide match an exact-digit oracle on the number as the upstream is sent it (SR-95) |
| `audit_export_bytes` | `parse_export` + `verify_export` on arbitrary text | countersigned entries are the original ones |
| `audit_export_mutated` | `verify_export` on edits of a signed export (entries, checkpoints, header, bytes; with or without re-hashing) | a verified export never alters an entry at or below the last good checkpoint |
| `limits_charges` | `Limits` deserialisation and `validate`, `narrows`, `clamp_to`, `charges_for`, `usage_charges`, `Derive::Host`, `jcs` | clamping is idempotent and narrows; each value counted once, at most `MAX_COUNTED_VALUES`; a `limit_arg_invalid` has a cause; a derived host comes from a special scheme only and is a fixpoint; canonical JSON is a fixpoint and agrees with `value_eq` |
| `budget_plan` | `LeaseStore::charge` and `refund` (`budget::plan`) on random sequences, memory and SQLite (temp file) side by side | both stores agree with each other and a model; `distinct` counts equal their value rows; no counter over `max` or below 0; all 0 after every refund |
| `approval_token` | `Verifier::verify_approval` on mutated and re-signed tokens, `check_binding`, `take_approval` and `take_approval_by_id` with mutated arguments | byte-mutated tokens never verify with other claims; accepted tokens are well formed; an approval is taken exactly when the canonical arguments match, once |
| `policy_usage` | `policies_read_usage` on generated and raw Cedar | never "nobody reads usage" for a policy naming `context.usage`, or one whose answer changes with `context.usage` |
| `server_http` | the server router: `POST /access/v1/evaluation(s)`, `POST /approvals/{id}`, `POST /admin/approvals/{id}` | no 5xx; an allow has `policy_allow`; one result per batch entry; no decision on a missing approval |
| `sse_framer_rewriter` | the pass 7 SSE code: BOM strip, `SseFramer`, `SseRewriter`, `rewrite_event`, `has_data`, `may_hold_stream_end_code`, `disown_events` (crate-private, via the `fuzzing` feature) | BOM strip and framing independent of chunking; framed output is whole UTF-8 events; rewriter output bounded; the scan never misses a number equal to -32001; no stream-end shape survives `disown_events` |
| `sse_parse_data` | `parse_data`, `replace_lone_surrogates` (via the `fuzzing` feature) | same value as `serde_json` whenever it parses; text without `\u` unchanged; length kept; idempotent |

`src/lib.rs` holds the shared pieces: JSON and string generators biased to edge cases, a token
issuer with a fixed key (so targets can re-sign mutated tokens) and a signed audit export.

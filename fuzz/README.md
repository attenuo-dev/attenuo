# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the parsers and
checks an attacker can reach: tokens, DPoP proofs, names and capabilities, the MCP proxy's
JSON-RPC and SSE handling, the policy engine's context building, and audit export
verification. Each target calls public APIs only. Why, how they are built and what they found:
[docs/design/fuzzing.md](../docs/design/fuzzing.md).

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
| `names` | `onbehalf_core::names` checks | the name sets nest as documented; `<server>/<call>` splits back into one pair |
| `capability_attenuation` | `Capability::covers`, `CapabilitySet::{covers, attenuate, permits}` over small alphabets | if `parent ⊇ child` then every call `child` permits, `parent` permits; `attenuate` agrees with `covers`; coverage is reflexive and transitive |
| `proxy_jsonrpc` | `onbehalf_proxy::router` end to end, with a fuzz-driven upstream | nothing unpermitted reaches the upstream (SR-07 included); 413 over the body limit; 400 for a bad `Mcp-Session-Id`; no unfiltered `tools/list` entry reaches the client |
| `proxy_sse` | `SseFramer`, `SseRewriter`, `ListFilter` on chunked bytes | framing is the input cut at event ends; rewriting does not depend on chunking; filtered answers hold only permitted tools |
| `policy_context` | `PolicyEngine::authorize` with arbitrary arguments and user attributes; `PolicyEngine::evaluate` (AuthZEN) on arbitrary JSON | a documented reason every time; an allow passed the capability stage; deterministic |
| `audit_export_bytes` | `parse_export` + `verify_export` on arbitrary text | countersigned entries are the original ones |
| `audit_export_mutated` | `verify_export` on edits of a signed export (entries, checkpoints, header, bytes; with or without re-hashing) | a verified export never alters an entry at or below the last good checkpoint |

`src/lib.rs` holds the shared pieces: JSON and string generators biased to edge cases, a token
issuer with a fixed key (so targets can re-sign mutated tokens) and a signed audit export.

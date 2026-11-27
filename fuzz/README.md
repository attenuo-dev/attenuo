# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets for the parsers and
checks an attacker can reach: tokens, DPoP proofs, names and capabilities, the MCP proxy's
JSON-RPC and SSE handling, the policy engine's context building, and audit export
verification. Each target calls public APIs only, except those that go through a `fuzzing` feature (attenuo-proxy's SSE helpers, attenuo-server's ID-JAG ceiling), which is not an API. Why, how they are built and what they found:
[docs/design/fuzzing.md](../docs/design/fuzzing.md) and, for the second round, [docs/research/fuzzing-2026-10-24-round2.md](../docs/research/fuzzing-2026-10-24-round2.md).

This crate is not a member of the main workspace (the root `Cargo.toml` excludes it): it
needs a nightly toolchain and has its own `Cargo.lock`.

## Checking that the targets compile

No nightly needed: this is what CI's `fuzz-check` job runs on every pull request that can
change Rust (also `just fuzz-check` or `scripts/dev.sh fuzz`).

```sh
RUSTFLAGS="--cfg fuzzing -D warnings" cargo check --manifest-path fuzz/Cargo.toml --bins --examples --locked
```

It fails when a library change breaks a target, makes one warn, or leaves `fuzz/Cargo.lock` stale. cargo-fuzz
has no `--locked` and rewrites the lockfile silently, so after a dependency change in the
workspace refresh it with `cargo update --manifest-path fuzz/Cargo.toml --workspace` (or
`-p <crate> --precise <version>` to match the root `Cargo.lock`) and commit the result.

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
| `capability_prepared` | `ArgConstraint::implies`, `CapabilitySet::{covers, covered, attenuate, attenuate_each, attenuate_root, validate_size}`, `jcs::{value_key, value_eq, to_vec}`, with `one_of` lists long enough for the prepared implication (SR-123) | the prepared implication gives the pairwise answer (a reference that only ever hands the core lists of one value, and each set check again with the parent padded onto the prepared path); `value_key` equal exactly when `value_eq`, on values parsed from text with other number spellings, escapes, NFC/NFD and duplicate keys; `validate_size` refuses exactly when a documented count is over its bound, and attenuation then answers `TooLarge` first |
| `capability_attenuate_root` | `CapabilitySet::attenuate_root` (hop 0, SR-121) against `attenuate` on grants and requests that share limited parents | refuses whenever `attenuate` does; the result is covered by the grant; each limited grant capability that covers a result capability's calls (SR-128) covers those of at most one, whose limits are within it, with `LimitSplit` and `LimitConflict` exactly when the documented rule says; the answer does not depend on the order the request lists its capabilities; pairwise and prepared paths agree. Not covered, by design: a limited grant capability that only overlaps a request bounds nothing at hop 0 |
| `idjag_ceiling` | `[idps.id_jag_ceiling]`: `IdJagCeiling::from_config` and `apply`, and the hop-0 narrowing of `intake::narrow` (crate-private, via attenuo-server's `fuzzing` feature), on generated configs, grants, claims (repeats, odd whitespace, wrong types, malformed `authorization_details`) and requests | an accepted config is built whole; the ceiling and every recorded step are within the grant; repeated or reordered claim values give the same ceiling at no more than a few extra allocations (SR-129); every recorded step holds a limit; a narrowed result is within the grant, the ceiling, every step and what every claim with limits named, and each limited capability of any of them that covers a result capability's calls covers those of at most one, whose limits are within it (SR-121, SR-127, SR-128, SR-131); on every input, the result's `calls` and `sum` under each limited capability of the grant and of a named `scopes` entry add up to at most its figure; the request's order does not matter |
| `client_pki_der` | the DER reads of the `tls_client_auth` check (crate-private, via attenuo-server's `fuzzing` feature): `is_ca`, `uri_name_count`, the issuer, subject and `notAfter` reads, and `useful_intermediates`, on raw bytes and on the bytes placed in a certificate skeleton | a malformed `basicConstraints` is never a CA; the URI count fits the bytes; a `notAfter` that reads gives back its digits; the intermediates kept are the first readable one per subject, never the leaf or a self-issued one |
| `client_crl_check` | the CRL check of ADR-0024 (crate-private, via attenuo-server's `fuzzing` feature): `client_crl::load` (signers, signatures, dates, the issuer file's checks, the trust anchors' issuers), `CrlSet::status`, `CrlSet::anchor_status`, `client_pki::verify` (`path_status` on each path rustls-webpki builds) and `verify_signature`, on a root, an intermediate, a client certificate and two CRLs signed in the target with fixed Ed25519 keys, whose serial numbers, lists, placement and rules come from the input | the files load or are refused as a model says; a serial number is listed exactly when it equals a listed one without leading zero bytes; a self-signed root is never refused; the intermediate as a trust anchor, and the whole path, are refused exactly as the model says; a signature verifies only under the right key and unchanged |
| `client_crl_der` | the CRL file reads of ADR-0024 (crate-private, via attenuo-server's `fuzzing` feature): `parse` (PEM or DER, rustls-webpki's parser and the server's own reads), `facts`, `signed_data` and the `cRLSign` read, on raw bytes and on CRL and certificate skeletons | a parsed CRL has no `issuingDistributionPoint`, at most 100,000 entries and the dates and number the field reads give; DER and PEM parse alike, never with a private key; a skeleton reads back its fields; `cRLSign` only from a well-formed `BIT STRING` |
| `forwarded_client_cert` | the RFC 9440 header reads of `[server.forwarded_client_cert]` (crate-private, via attenuo-server's `fuzzing` feature): `parse_values` on raw values and on values built from bytes with spaces and tabs, and `parse` on header maps | what is accepted is within the caps (4 chain certificates, 16 KiB each, 64 KiB in all) and never a chain without a leaf; it reads back the same in its canonical spelling; built values read back exactly; a repeated line is always refused |
| `proxy_jsonrpc` | `attenuo_proxy::router` end to end, with a fuzz-driven upstream | nothing unpermitted reaches the upstream (SR-07 included); 413 over the body limit; 400 for a bad `Mcp-Session-Id`; no unfiltered `tools/list` entry reaches the client |
| `proxy_sse` | `SseFramer`, `SseRewriter`, `ListFilter` on chunked bytes | framing is the input cut at event ends; rewriting does not depend on chunking; filtered answers hold only permitted tools |
| `policy_context` | `PolicyEngine::authorize` with arbitrary arguments and user attributes, `decimal` and `set<decimal>` inputs among them; `PolicyEngine::evaluate` (AuthZEN) on arbitrary JSON | a documented reason every time; an allow passed the capability stage; deterministic up to the order of `policy_ids`; on `create_issue`, the stage that denies and the `dec_` policies that decide match an exact-digit oracle on the number as the upstream is sent it (SR-95) |
| `audit_export_bytes` | `parse_export` + `verify_export` on arbitrary text | countersigned entries are the original ones |
| `audit_export_mutated` | `verify_export` on edits of a signed export (entries, checkpoints, header, bytes; with or without re-hashing) | a verified export never alters an entry at or below the last good checkpoint |
| `limits_charges` | `Limits` deserialisation and `validate`, `narrows`, `clamp_to`, `charges_for`, `usage_charges`, `Derive::Host`, `jcs` | clamping is idempotent and narrows; each value counted once, at most `MAX_COUNTED_VALUES`; a `limit_arg_invalid` has a cause; a derived host comes from a special scheme only and is a fixpoint; canonical JSON is a fixpoint and agrees with `value_eq` |
| `budget_plan` | `RunLimits::charge` and `refund` (`budget::plan`) on random sequences, memory and SQLite (temp file) side by side | both stores agree with each other and a model; `distinct` counts equal their value rows; no counter over `max` or below 0; all 0 after every refund |
| `approval_token` | `Verifier::verify_approval` on mutated and re-signed tokens, `check_binding`, `take_approval` and `take_approval_by_id` with mutated arguments | byte-mutated tokens never verify with other claims; accepted tokens are well formed; an approval is taken exactly when the canonical arguments match, once |
| `policy_usage` | `policies_read_usage` on generated and raw Cedar | never "nobody reads usage" for a policy naming `context.usage`, or one whose answer changes with `context.usage` |
| `server_http` | the server router: `POST /access/v1/evaluation(s)`, `POST /approvals/{id}`, `POST /admin/approvals/{id}` | no 5xx; an allow has `policy_allow`; one result per batch entry; no decision on a missing approval |
| `sse_framer_rewriter` | the pass 7 SSE code: BOM strip, `SseFramer`, `SseRewriter`, `rewrite_event`, `has_data`, `may_hold_stream_end_code`, `disown_events` (crate-private, via the `fuzzing` feature) | BOM strip and framing independent of chunking; framed output is whole UTF-8 events; rewriter output bounded; the scan never misses a number equal to -32001; no stream-end shape survives `disown_events` |
| `sse_parse_data` | `parse_data`, `replace_lone_surrogates` (via the `fuzzing` feature) | same value as `serde_json` whenever it parses; text without `\u` unchanged; length kept; idempotent |

`src/lib.rs` holds the shared pieces: JSON and string generators biased to edge cases, a token
issuer with a fixed key (so targets can re-sign mutated tokens) and a signed audit export.

# ADR-0004: Rust workspace layout

- Status: accepted (amended 2026-11-05 and 2026-11-06, see [More Information](#more-information))
- Date: 2026-10-22

## Context

The guarantees in [RFC-0001](../spec/rfc-0001-attenuo.md) have different trust and change profiles. The attenuation rule and audit chain are the trusted base and should be small, dependency-light and property-tested. The MCP proxy and HTTP server change with transports and framework versions. Gateways should be able to use the PDP without pulling in the proxy. One crate would blur those lines; too many would slow a small team.

Rust is the implementation language because the pieces being composed are Rust (Cedar's evaluator, AgentGateway, Firecracker-class VMMs for a later sandbox layer) and because a reference monitor benefits from memory safety without a GC pause in the call path ([arXiv 2403.04651](https://arxiv.org/abs/2403.04651v2), [agentgateway](https://github.com/agentgateway/agentgateway)).

## Decision

A Cargo workspace with seven crates, dependencies pointing only downward in this list.

| Crate | Responsibility | Key dependencies | Notes |
|---|---|---|---|
| `attenuo-core` | Domain types: `OriginatingUser`, `Capability`, `CapabilitySet`, `DelegationChain`, `Hop`, `Lease`, `Decision`, `AuditRecord`. The attenuation predicate `⊑` and canonical JSON. | `serde`, `serde_json`, `thiserror`, `time` | No I/O, no async, no crypto beyond hashing. The attenuation rule lives here and nowhere else. Property tests with `proptest` for `⊑` (reflexive, transitive, empty set minimal, adding a constraint narrows). |
| `attenuo-token` | RFC 8693 token exchange, JWT mint/verify, `act`, `chain` and `ou_sig` claims (`may_act` proposed), ID-JAG and OIDC ID-token intake, JWKS fetching and caching, key management. | `core`, `jsonwebtoken` or `josekit`, `reqwest` | Verifies `requested ⊑ parent` by calling `core`; never reimplements it. |
| `attenuo-policy` | Cedar engine wrapper, AuthZEN request/response types, request builder (token + MCP call to Cedar request), `RelationResolver` trait, policy store with hot reload and schema validation. | `core`, `cedar-policy` 4.x | Capability match and lease liveness run here before Cedar; a `forbid`-by-default result when any input is missing. |
| `attenuo-audit` | Hash-chained append-only log, checkpoints, verifier, SQLite backend behind a `LogSink` trait. | `core`, `rusqlite` (bundled), `sha2` | Verifier is a separate binary entry point so an auditor can run it without the server. |
| `attenuo-proxy` | MCP streamable-HTTP interception: parse JSON-RPC, extract `tools/call`, enforce decision, forward or reject, propagate session ids; lease renewal client. | `core`, `token`, `policy`, `audit`, `axum`/`hyper`, `tower` | Only crate that understands MCP framing. Must not interpret tool results. |
| `attenuo-server` | The binary: config, wiring, `/token`, `/access/v1/evaluation`, `/lease/*`, `/revoke`, health, metrics, the proxy routes. | all of the above, `axum`, `tokio`, `clap`, `tracing` | No logic beyond wiring and config. |
| `attenuo-cli` | The `attenuo` binary: a thin HTTP client for a running server (token root/exchange/inspect, call, lease, audit, policy, AuthZEN eval). | `core`, `token`, `reqwest`, `clap` | Holds no keys and decides nothing; `token inspect` decodes locally and `--verify` uses the server's JWKS. |

Conventions:

- `attenuo-core` has `#![forbid(unsafe_code)]` and no async; the others `#![deny(unsafe_code)]`.
- Security invariants (attenuation, lease revocation reaching the next call, audit chain verification) get property or integration tests in the crate that owns them, per [CONTRIBUTING](https://github.com/attenuo-dev/attenuo/blob/main/CONTRIBUTING.md).
- Shared `rustfmt.toml`, `clippy.toml` with `-D warnings` in CI, pinned toolchain in `rust-toolchain.toml`.
- Public APIs in `core`, `token` and `policy` are the integration surface for gateways; `proxy` and `server` are not promised stable.

## Consequences

- Positive: the trusted base (`core` + `audit`) is auditable in an afternoon; gateways can depend on `policy` + `token` as a library or call the server's AuthZEN endpoint.
- Positive: attenuation has one implementation and one test suite.
- Negative: seven crates means some type duplication at boundaries (AuthZEN JSON vs. core types) and more `Cargo.toml` upkeep.
- Negative: `proxy` depends on MCP framing details that will change with spec revisions; it is isolated for that reason.

## Alternatives considered

- **Single crate with modules**: faster at first, but no compile-time enforcement that the proxy cannot reach into token minting, and library users would pull the whole server.
- **Two crates (lib + bin)**: does not separate the trusted base from transport code, and forces gateways to take the proxy with the PDP.
- **Separate crate per standard** (`rfc8693`, `authzen`, `idjag`): premature; the standards are drafts and are revised together.
- **A Go implementation to match most gateways**: rejected; Cedar and the VMM layer are Rust, and in-process Cedar from Go would need CGo.

## More Information

### Update 2026-11-05

The decision stands: a Cargo workspace, dependencies pointing only downward, status accepted. The layout above has drifted from the code in the ways below, checked against the `Cargo.toml` files and the sources at this date. The table in Decision is kept as written; read it with these corrections.

- **Eight crates, not seven.** `attenuo-bench` (load and hot-path measurement) was added. It has no workspace dependencies: it spawns the built binaries.
- **IdP intake and JWKS fetching are in `attenuo-server`, not `attenuo-token`.** ID-JAG and OIDC intake and the IdP key cache live in `attenuo-server/src/idp/` (`intake.rs`, `jwks.rs`, `claims.rs`). `attenuo-token` has no HTTP client code for them.
- **`attenuo-audit` depends on `attenuo-token`**, for `DetachedSigner` and `verify_detached` (checkpoint signing). The verifier became the `attenuo audit verify` command in the CLI rather than a separate binary.
- **`attenuo-cli` depends on `attenuo-audit` and `attenuo-policy`** as well as core and token. `audit verify --file` and `policy test` / `policy lint` run locally, the latter against the real `PolicyEngine`. "Decides nothing" holds only for the online commands.
- **`attenuo-proxy` depends only on `attenuo-core`**, narrower than the table. It reaches the decision side through its `Authorizer` trait.
- **The `RelationResolver` trait was never built** in `attenuo-policy`. Hot reload is driven by the server (`POST /admin/policies/reload`).
- **`attenuo-server` holds real logic**, not only wiring: `authz.rs` (the authorization pipeline), `dpop.rs`, `actor.rs`, `replay.rs`, `sink.rs` and `idp/`. The [server design](../design/server.md) describes `authz::Pipeline` as the server's piece of composition.
- **Names in core:** the code has `LeaseId` and `DecisionRecord` where the table says `Lease` and `AuditRecord`.
- **Unsafe code:** `attenuo-core` and `attenuo-policy` use `#![forbid(unsafe_code)]`; the other crates use `#![deny(unsafe_code)]`.

Workspace dependencies between crates, from the manifests (`[dependencies]` only; "x" means the row depends on the column):

| Crate | core | token | policy | audit | proxy | server |
|---|---|---|---|---|---|---|
| `attenuo-core` | | | | | | |
| `attenuo-token` | x | | | | | |
| `attenuo-policy` | x | | | | | |
| `attenuo-audit` | x | x | | | | |
| `attenuo-proxy` | x | | | | | |
| `attenuo-server` | x | x | x | x | x | |
| `attenuo-cli` | x | x | x | x | | |
| `attenuo-bench` | | | | | | |

`attenuo-cli` has `attenuo-server` and `attenuo-proxy` as dev-dependencies only (integration tests). Source: [code-quality pass, 2026-11-05](../research/code-quality-2026-11-05.md).

### Amendment 2026-11-06

The decision still stands and Decision is still kept as written. This amendment records the workspace as it is on `main` at `82905d0`, corrects two lines of the update above that were overtaken the same night, and lists in one place every statement of the original table that no longer holds. Facts come from `cargo metadata --no-deps` and the sources at that commit.

Crate graph (normal dependencies only; `──►` lists the crates a crate depends on):

```text
top      attenuo-cli     ──► core, token, policy, audit
         attenuo-server  ──► core, token, policy, audit, proxy
middle   attenuo-proxy   ──► core
         attenuo-audit   ──► token, core
         attenuo-policy  ──► core
         attenuo-token   ──► core
base     attenuo-core        (no workspace dependencies)
outside  attenuo-bench       (no workspace dependencies; spawns the built binaries)
```

The same edges as a table, with the workspace dev-dependencies:

| Crate | Depends on (workspace, `[dependencies]`) | Dev-dependencies (workspace) |
|---|---|---|
| `attenuo-core` | none | none |
| `attenuo-token` | core | none |
| `attenuo-policy` | core | none |
| `attenuo-audit` | core, token | itself, with `testing` |
| `attenuo-proxy` | core | itself, with `testing` |
| `attenuo-server` | core, token, policy, audit, proxy | proxy |
| `attenuo-cli` | core, token, policy, audit | core, proxy, server |
| `attenuo-bench` | none | none |

Every edge still points downward in the order core, token, policy, audit, proxy, server, cli; bench sits outside the order. The rule of the Decision holds.

Corrections to the update of 2026-11-05:

- **The pipeline is `authz/`, not `authz.rs` alone.** `e40e3ee` (2026-11-06, #180) split it by stage: `authz.rs` keeps the module documentation and re-exports, and the stages live in `authz/pipeline.rs`, `authorizer.rs`, `labels.rs`, `budgets.rs` and `usage.rs`. The [server design](../design/server.md) already names `authz/pipeline.rs`.
- **Two files named for keys.** `9023ce5` (2026-11-06) renamed the server's `src/jwks.rs`, which builds the issuer's own JWK Set for `GET /.well-known/jwks.json`, to `src/issuer_keys.rs`, so that it no longer shares a name with the IdP key cache in `src/idp/jwks.rs`. The same commit made `actor`, `clientauth`, `idp`, `replay` and `state` `pub(crate)`.

What the original table says that is no longer true, with the reason where the log, a commit or an ADR gives one:

1. **Seven crates.** There are eight; `attenuo-bench` (end-to-end latency and throughput, `scripts/bench-e2e.sh`) was added on 2026-10-23 (`75b8625`, the end-to-end latency harness) and drives the release binaries over HTTP, so it needs no workspace dependency.
2. **`attenuo-token` does ID-JAG and OIDC intake and JWKS fetching.** Both are in `attenuo-server/src/idp/` (`intake.rs`, `jwks.rs`, `claims.rs`), next to the `[[idps]]` configuration and the HTTP client they use; `attenuo-token` keeps minting, verification and detached signatures and has no HTTP client. No log entry records it as a decision: intake was written in the server from its first commit (`4692f75`, 2026-10-22, "feat(server): hop-0 intake from OIDC ID tokens and ID-JAG").
3. **`attenuo-policy` has a `RelationResolver` trait.** It was never built (`git grep RelationResolver` finds only docs). ReBAC composition stays planned under [ADR-0002](0002-cedar-for-policy.md) and is an open item on the board; policy reload is driven by the server (`POST /admin/policies/reload`).
4. **`attenuo-audit` is the log and depends only on core.** It depends on `attenuo-token` for `DetachedSigner` and `verify_detached`, which sign and check audit checkpoints with the issuer key (audit hardening, 2026-10-23). It also holds the lease store (`lease`, `approval`, `budget`, `spans`: leases, approvals, run counters and the span index), so the SQLite state of a deployment sits in one crate.
5. **The verifier is a separate binary entry point.** It is `attenuo audit verify` in the CLI; `--file` checks an export offline with only the JWKS (2026-10-23).
6. **`attenuo-cli` depends on core and token only and decides nothing.** It also depends on audit (offline `audit verify --file`) and policy (`policy test` and `policy lint`, which run the real `PolicyEngineBuilder` locally). It holds no keys of the server and its online commands decide nothing; the offline commands evaluate policy and verify logs on the operator's machine.
7. **`attenuo-proxy` depends on core, token, policy and audit.** It depends on core only and reaches decisions through its `Authorizer` trait, which the server implements (`ServerAuthorizer` in `authz/authorizer.rs`).
8. **`attenuo-server` is wiring with no logic.** It holds the decision pipeline (`authz/`), IdP intake (`idp/`), the issuer JWKS (`issuer_keys.rs`), DPoP (`dpop.rs`), actor-token authentication (`actor.rs`), client authentication (`clientauth.rs`), replay protection (`replay.rs`), the checkpoint sink (`sink.rs`), the approval notifier (`notify.rs`, ADR-0009 approvals), the admin console listener (`admin_ui.rs`, [ADR-0008](0008-admin-console.md)) and metrics. Putting the pipeline here lets the proxy and the AuthZEN endpoint share one `Pipeline::decide`, so they cannot disagree ([server design](../design/server.md)).
9. **Core type names.** The code has `LeaseId` and `DecisionRecord` where the table says `Lease` and `AuditRecord`.
10. **Unsafe code.** `attenuo-policy` uses `#![forbid(unsafe_code)]` like core, stricter than the convention; the rest use `#![deny(unsafe_code)]`.

The Consequences hold with "seven crates" read as eight. Source: debt item 2 of the [code-quality pass](../research/code-quality-2026-11-05.md).

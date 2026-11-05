# ADR-0004: Rust workspace layout

- Status: accepted
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

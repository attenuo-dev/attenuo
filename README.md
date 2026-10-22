# onbehalf

[![CI](https://github.com/7Mudit/onbehalf/actions/workflows/ci.yml/badge.svg)](https://github.com/7Mudit/onbehalf/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](docs/spec/rfc-0001-onbehalf.md)
<!-- TODO once published: crates.io and docs.rs badges for onbehalf-core -->

Delegated authorization for software agents. onbehalf lets a principal hand an agent a scoped, attenuable, revocable capability to act on their behalf, checks every call against policy, and writes a tamper-evident audit record of each decision. It is written in Rust and ships as a set of crates plus a standalone server.

**Status: pre-alpha.** The design is in [RFC-0001](docs/spec/rfc-0001-onbehalf.md) and is still open for comment. Nothing here is ready for production use and formats will change before 1.0.

## Where to look

- [RFC-0001: onbehalf](docs/spec/rfc-0001-onbehalf.md): what the system is, the token model, the policy and audit design.
- [docs/](docs/README.md): specifications, architecture decisions, research notes, task board and engineering log.
- [CONTRIBUTING.md](CONTRIBUTING.md): how to build, test and submit changes.
- [SECURITY.md](SECURITY.md): how to report a vulnerability. Please do not file security issues publicly.
- [CHANGELOG.md](CHANGELOG.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Crates

| Crate | Purpose |
| --- | --- |
| `onbehalf-core` | Delegation chains, capability sets, attenuation, decision records |
| `onbehalf-token` | Token encoding, signing and verification |
| `onbehalf-policy` | Policy evaluation |
| `onbehalf-audit` | Append-only, hash-chained audit log |
| `onbehalf-proxy` | Enforcement in front of upstream services |
| `onbehalf-server` | The standalone server binary |

## Building

```sh
cargo build --workspace
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full set of checks CI runs.

## License

Apache-2.0. See [LICENSE](LICENSE).

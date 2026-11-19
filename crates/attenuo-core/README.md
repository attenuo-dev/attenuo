# attenuo-core

Core types for attenuo: delegation chains, capability sets with argument constraints, the attenuation rule, run limits, RFC 8785 canonical JSON, and the decision record that the audit log stores.

The crate does no I/O and no async. Everything that signs, stores or evaluates lives in the sibling crates. The attenuation rule (a child capability set is covered by its parent's) is defined here and nowhere else.

## In the workspace

It is the bottom of the workspace: every other attenuo crate depends on it, and it depends on none of them. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [Capabilities and attenuation](https://github.com/attenuo-dev/attenuo/blob/main/docs/concepts/capabilities-and-attenuation.md)
- [Delegation chain](https://github.com/attenuo-dev/attenuo/blob/main/docs/concepts/delegation-chain.md)
- [RFC-0001, section 3](https://github.com/attenuo-dev/attenuo/blob/main/docs/spec/rfc-0001-attenuo.md#3-delegation-chain-data-model)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

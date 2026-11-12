# attenuo-token

Delegation tokens for attenuo: RFC 8693-style token exchange carrying a signed delegation chain.

An `Issuer` holds an Ed25519 key and mints short-lived JWTs (`alg` EdDSA, `typ` `attenuo+jwt`); a `Verifier` holds only public keys and checks tokens strictly. The originating-user block is signed once at root issuance (`ou_sig`) and copied unchanged through every exchange, exchanges only narrow the chain, and verification takes the clock from the caller. The crate also holds DPoP proofs (RFC 9449), approval tokens and detached signatures.

## In the workspace

It depends on `attenuo-core`. `attenuo-audit`, `attenuo-server` and `attenuo-cli` depend on it. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [RFC-0001, section 4](https://github.com/attenuo-dev/attenuo/blob/main/docs/spec/rfc-0001-attenuo.md#4-token-exchange)
- [Binding tokens to keys](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/binding-tokens-to-keys.md)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

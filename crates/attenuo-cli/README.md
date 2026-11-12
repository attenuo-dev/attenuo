# attenuo-cli

The `attenuo` command line for a running attenuo server: mint, exchange and inspect delegation tokens, call tools through the proxy, manage leases and approvals, read and verify the audit log, and test and lint policies.

Exit status is 0 on success, 1 on an error (including a usage error) and 2 when the server answered but said no (a denied call, a negative AuthZEN decision, a broken audit chain). The online commands hold no keys and decide nothing; `audit verify --file` and `policy test` / `policy lint` run locally.

## In the workspace

It depends on `attenuo-core`, `attenuo-token`, `attenuo-audit` and `attenuo-policy`. The crate builds the `attenuo` binary. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [CLI commands](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/cli.md)
- [Getting started](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/getting-started.md)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

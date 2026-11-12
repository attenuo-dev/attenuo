# attenuo-server

The attenuo server: one HTTP service that wires the token issuer, the policy engine, the audit log, the lease registry and the MCP proxy together. It serves RFC 8693 token exchange (`POST /token`, including hop 0 from an OIDC ID token or ID-JAG), lease renewal, the AuthZEN evaluation endpoints, the MCP proxy, the `/admin/*` routes, and an optional embedded admin console on a separate listener.

All decisions go through one pipeline, `authz::Pipeline::decide`. The crate builds the `attenuo-server` binary.

## In the workspace

It depends on `attenuo-core`, `attenuo-token`, `attenuo-policy`, `attenuo-audit` and `attenuo-proxy`. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [Getting started](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/getting-started.md)
- [Deploying](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/deploying.md)
- [Configuration keys](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/config.md)
- [HTTP endpoints](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/http-api.md)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

# attenuo-proxy

The policy enforcement point for attenuo: an HTTP reverse proxy in front of MCP servers that speak the Streamable HTTP transport, each mounted at `/mcp/{server}`.

For every request it resolves the caller's token into a delegation chain through the pluggable `Authorizer` trait, asks for a decision on every request that can read data or cause an effect, forwards allowed ones upstream and answers denied ones with JSON-RPC error `-32003`. It filters list results down to what the caller's capabilities could permit, binds MCP session ids to the principal they were assigned to, and labels upstream results for output labelling.

## In the workspace

It depends only on `attenuo-core` and reaches the decision side through its `Authorizer` trait. `attenuo-server` provides that implementation. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [Enforcement points](https://github.com/attenuo-dev/attenuo/blob/main/docs/concepts/enforcement-points.md)
- [Integrating MCP clients](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/integrating-mcp-clients.md)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

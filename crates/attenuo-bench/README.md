# attenuo-bench

End-to-end latency and throughput benchmark for attenuo. It starts `attenuo-server` and the `fake_mcp` example (or is pointed at running ones), builds a delegation chain of the requested depth, and drives `tools/call` with closed-loop clients through the proxy and straight at `fake_mcp`, so the added latency is the difference at the same concurrency. At the end it asks the server to verify the audit chain.

## In the workspace

It is a workspace tool and is not published (`publish = false`). The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [Performance](https://github.com/attenuo-dev/attenuo/blob/main/docs/design/performance.md)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

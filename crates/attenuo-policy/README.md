# attenuo-policy

The policy decision point for attenuo. `PolicyEngine::authorize` decides a tool call for a verified delegation chain in two stages: a capability stage (the call must be permitted by the chain's effective capabilities, so no policy can grant what was not delegated), then the loaded [Cedar](https://www.cedarpolicy.com) policies. The engine fails closed: a request that cannot be translated into Cedar, or a policy that raises an evaluation error, is a deny with reason `policy_error`.

The Cedar request mirrors the shape of AWS Bedrock AgentCore policies (`Action::"<server>/<tool>"`, arguments in `context.input`). The crate also holds the tool catalog, the AuthZEN request and response types, and the list screen behind `[proxy] list_filter = "policy"`.

## In the workspace

It depends on `attenuo-core`. `attenuo-server` and `attenuo-cli` (`attenuo policy test`, `attenuo policy lint`) depend on it. The workspace layout and the dependency rules between crates are in [ADR-0004](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0004-rust-workspace-layout.md).

The API is not stable before 1.0; see [API compatibility](https://github.com/attenuo-dev/attenuo/blob/main/docs/reference/api-compatibility.md).

## Documentation

- [attenuo repository](https://github.com/attenuo-dev/attenuo) and its [README](https://github.com/attenuo-dev/attenuo#readme)
- [Writing and testing policies](https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/writing-policies.md)
- [RFC-0001, section 5](https://github.com/attenuo-dev/attenuo/blob/main/docs/spec/rfc-0001-attenuo.md#5-per-call-authorization)
- [ADR-0005](https://github.com/attenuo-dev/attenuo/blob/main/docs/decisions/0005-policy-decision-point.md)

## Licence

Apache License 2.0. See [LICENSE](https://github.com/attenuo-dev/attenuo/blob/main/LICENSE).

# GitHub MCP leak demo

> The demo config sets `[dev] allow_root_mint = true` so step 1 can mint Alice's root token without an identity provider. Real deployments leave that off and mint root tokens from an OIDC ID token or ID-JAG (see the top-level README).

In May 2025 researchers showed that an AI assistant wired to the official GitHub MCP server could be turned against its user. A malicious issue in a public repository carried instructions; the assistant read them while triaging issues, followed them, pulled files out of the user's private repositories with the user's broad access token, and published the contents in a public pull request ([Invariant Labs write-up](https://invariantlabs.ai/blog/mcp-github-vulnerability)). Nothing was exploited in GitHub or in the MCP server. The agent held more authority than the task needed, and nothing checked each call against what the user had actually delegated.

This demo replays that shape against onbehalf, with a fake GitHub MCP server so it runs offline.

## Run it

```sh
examples/github-leak-demo/run.sh
```

It needs a Rust toolchain, `curl` and `python3`. The first run compiles the workspace. Ports are picked at random, everything lives in a temp directory, and an exit trap stops both servers and removes the directory (`KEEP=1` keeps it for the logs). The script exits non-zero if any step does not come out as described below, so it can also run in CI. A real run is in [transcript.md](transcript.md).

The policy has its own tests, which need no server (`run.sh` runs them first):

```sh
cargo run -q -p onbehalf-cli -- policy test examples/github-leak-demo/policy_test.yaml
cargo run -q -p onbehalf-cli -- policy lint examples/github-leak-demo/policy.cedar --config examples/github-leak-demo/config.toml
```

See [writing-policies](../../docs/guides/writing-policies.md#testing-policies).

## What happens

| Step | Call | Result | Why |
| --- | --- | --- | --- |
| 1 | `token root` for alice's `assistant`, `github:*` | token | The broad grant, like the over-privileged PAT. |
| 2 | `token exchange` to `coder`, `github:read_file`, authenticated with coder's client secret | token | The sub-agent gets one tool, not all of them, and only an agent that proves it is `coder` can receive it. |
| 3 | `token inspect --verify` | tree: alice, assistant, coder | The chain and capabilities are in the token and can be checked against the server's JWKS. |
| 4 | `read_file alice/public-docs` | allowed, reaches upstream | Intended use. |
| 5 | `read_file alice/private-salaries` (the injected call) | denied, `policy_deny` | The token allows `read_file`, but `policy.cedar` only permits repos matching `alice/public-*`. This is the leak, stopped. |
| 6 | `create_issue` on the public repo (the exfiltration path) | denied, `capability_denied` | `coder` was never delegated it. |
| 7 | `lease revoke` on the assistant's lease | 2 leases revoked | Alice pulls the plug; the revocation cascades to `coder`. |
| 8 | the legitimate `read_file` again | denied, `lease_revoked` | The next call after revocation is refused. |
| 9 | `audit tail`, `audit verify` | eight entries, chain OK | Every issuance and decision is recorded, denials included, and so are the two admin actions (the dev root mint and the revocation). |

At the end the script prints what the fake GitHub server received: one `tools/call`, the legitimate one.

## Files

- `config.toml`: server config with the catalog, the upstream, the admin token and alice's root grant. `run.sh` rewrites the ports and the policy path in a copy.
- `policy.cedar`: the one permit rule, `read_file` only when `repo like "alice/public-*"`, plus two guard-rail forbids (sensitive tools without MFA, chains deeper than three).
- `policy_test.yaml`: nine cases for that policy, run by `onbehalf policy test`.
- `config.docker.toml`: the same, for `docker-compose.yml` at the repository root (untested).
- `run.sh`, `transcript.md`.

The fake server is `crates/onbehalf-proxy/examples/fake_mcp.rs`: the proxy crate's `FakeMcpServer` test double with `read_file`, `create_issue` and `delete_repo`, which echoes calls instead of doing anything.

## What this does not show

The root token comes from the server's development endpoint, which trusts the admin to say who alice is. Real deployments mint it from an OIDC ID token or ID-JAG instead. The `actor` of the exchange authenticates with a client secret from `[[agents]]`; workload identity (an `actor_token` such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) is supported but not used here. See [identity providers](../../docs/guides/identity-providers.md) and the [task board](../../docs/tasks/board.md).

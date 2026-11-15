# GitHub MCP leak demo

> The demo config sets `[dev] allow_root_mint = true` so step 1 can mint Alice's root token without an identity provider. Real deployments leave that off and mint root tokens from an OIDC ID token or ID-JAG (see the top-level README).

In May 2025 researchers showed that an AI assistant wired to the official GitHub MCP server could be turned against its user. A malicious issue in a public repository carried instructions; the assistant read them while triaging issues, followed them, pulled files out of the user's private repositories with the user's broad access token, and published the contents in a public pull request ([Invariant Labs write-up](https://invariantlabs.ai/blog/mcp-github-vulnerability)). Nothing was exploited in GitHub or in the MCP server. The agent held more authority than the task needed, and nothing checked each call against what the user had actually delegated.

This demo replays that shape against attenuo, with a fake GitHub MCP server so it runs offline.

## Run it

```sh
examples/github-leak-demo/run.sh
```

It needs a Rust toolchain, `curl` and `python3`. The first run compiles the workspace (about a minute and a half on 4 cores, see [How long it takes](#how-long-it-takes)). Ports are picked at random, everything lives in a temp directory, and an exit trap stops both servers and removes the directory (`KEEP=1` keeps it for the logs). The script exits non-zero if any step does not come out as described below, so it can also run in CI. A real run is in [transcript.md](transcript.md).

The policy has its own tests, which need no server (`run.sh` runs them first):

```sh
cargo run -q -p attenuo-cli -- policy test examples/github-leak-demo/policy_test.yaml
cargo run -q -p attenuo-cli -- policy lint examples/github-leak-demo/policy.cedar --config examples/github-leak-demo/config.toml
```

See [writing-policies](../../docs/guides/writing-policies.md#testing-policies).

### Run it in Docker

`docker-compose.yml` at the repository root runs the same pair in containers: the server from the release image (`attenuo:dev`, which has no fake server and no `curl`) and the fake GitHub server from the `demo` build target (`attenuo:demo`).

```sh
export ATTENUO_ADMIN_TOKEN=$(openssl rand -hex 32)
docker compose up --build --wait     # returns once `attenuo health` passes in the server's container
# admin commands: in the container, on the admin listener (port 9102, not published)
docker compose exec attenuo attenuo --server http://127.0.0.1:9102 token root --subject alice --agent assistant --cap 'github:*'
curl -s http://127.0.0.1:8080/healthz             # the main listener, from the host
docker compose down
```

The main port answers `/admin/*` with 404, so `token root`, `lease`, `audit` and `approval` go to port 9102 from inside the container; `token exchange`, `call` and `tools` go to 8080, from the container or from the host (`ATTENUO_SERVER=http://127.0.0.1:8080`). `scripts/compose-smoke.sh` builds both images, checks what the release image holds, and plays steps 1 to 9 this way, failing on any step that does not come out as below. It needs Docker with the compose plugin and a free `127.0.0.1:8080`; the first build compiles the workspace in release mode.

### How long it takes

Measured 2026-10-24 at commit `de3cf75` on a 4-vCPU container (Intel Xeon @ 2.10GHz, 15 GB RAM, rustc 1.99.1), with an empty target directory and crates already downloaded:

- cold, cargo defaults: 1 min 31 s wall clock, nearly all of it compiling;
- cold, debug info and incremental off (`CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`): 1 min 22 s;
- warm: 0.9 s, of which the nine steps take about 0.2 s and the rest is cargo checking that nothing changed.

Downloading crates on a machine with an empty cargo cache comes on top and was not measured. Raw output: [2026-10-24-vm-demo-cold-timing.md](../../docs/design/bench/2026-10-24-vm-demo-cold-timing.md).

## What happens

| Step | Call | Result | Why |
| --- | --- | --- | --- |
| 1 | `token root` for alice's `assistant`, `github:*` | token | The broad grant, like the over-privileged PAT. |
| 2 | `token exchange` to `coder`, `github:read_file`, authenticated with coder's client secret | token | The sub-agent gets one tool, not all of them, and only an agent that proves it is `coder` can receive it. |
| 3 | `token inspect --verify` | tree: alice, assistant, coder | The chain and capabilities are in the token and can be checked against the server's JWKS. |
| 4 | `read_file alice/public-docs` | allowed, reaches upstream | Intended use. |
| 5 | `read_file alice/private-salaries` (the injected call) | denied, `policy_deny` | The token allows `read_file`, but `policy.cedar` only permits repos matching `alice/public-*`. This is the leak, stopped. |
| 6 | `create_issue` on the public repo (the exfiltration path) | denied, `capability_denied` | `coder` was never delegated it. A token that does hold it would still wait for a person's approval: `policy.cedar` asks before every `create_issue`. |
| 7 | `lease revoke` on the assistant's lease | 2 leases revoked | Alice pulls the plug; the revocation cascades to `coder`. |
| 8 | the legitimate `read_file` again | denied, `lease_revoked` | The next call after revocation is refused. |
| 9 | `audit tail`, `audit verify` | nine entries, chain OK | Every issuance and decision is recorded, denials included, and so are the two admin actions (the dev root mint and the revocation) and the `tool_result` record of the allowed read. |

At the end the script prints what the fake GitHub server received: one `tools/call`, the legitimate one.

## Files

- `config.toml`: server config with the catalog, the upstream, the admin token, alice's root grant and the `[approvals]` client id. `run.sh` rewrites the ports and the policy path in a copy.
- `policy.cedar`: two permits, `read_file` and `create_issue` only when `repo like "alice/public-*"`; a forbid with `@obligation("approval")` that holds every `create_issue` until a person approves it (the Python, TypeScript and Claude Agent SDK examples use it); and two guard-rail forbids (sensitive tools without MFA, chains deeper than three).
- `policy_test.yaml`: eleven cases for that policy, run by `attenuo policy test`.
- `config.docker.toml`: the same, for `docker-compose.yml` at the repository root (run by `scripts/compose-smoke.sh`). It binds `0.0.0.0` inside the container, so the admin API gets a listener of its own (`[admin] listen = "0.0.0.0:9102"`, not published by compose), and, since that listener is not loopback either, it sets the demo-only `[dev] allow_root_mint_off_loopback`, without which the dev mint refuses to start. Never copy that line into a deployment.
- `run.sh`, `transcript.md`.

The fake server is `crates/attenuo-proxy/examples/fake_mcp.rs`: the proxy crate's `FakeMcpServer` test double with `read_file`, `create_issue` and `delete_repo`, which echoes calls instead of doing anything.

## What this does not show

The root token comes from the server's development endpoint, which trusts the admin to say who alice is. Real deployments mint it from an OIDC ID token or ID-JAG instead. The `actor` of the exchange authenticates with a client secret from `[[agents]]`; workload identity (an `actor_token` such as a SPIFFE JWT-SVID from an `[[actor_trust]]` issuer) is supported but not used here. See [identity providers](../../docs/guides/identity-providers.md).

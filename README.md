<p align="center"><img src="assets/brand/header.png" alt="attenuo: delegated authority that can only narrow, enforced on every tool call" width="100%"></p>

# attenuo

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV: 1.89](https://img.shields.io/badge/MSRV-1.89-blue.svg)](Cargo.toml)
[![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](docs/spec/rfc-0001-attenuo.md)
<!-- TODO once published: crates.io and docs.rs badges for attenuo-core -->

When you give an AI agent access to your GitHub, your mail or your bank, it usually gets one broad token, and every tool call it makes after that is allowed. If a poisoned issue or web page talks the agent into something, nothing stands between the instruction and your data. attenuo is a self-hosted server and proxy for that gap. A user's login becomes a token for an agent, and the agent can hand a narrower token to each sub-agent it uses. Every tool call goes through attenuo, which checks it against what was delegated and against a Cedar policy that sees the call's arguments. You can revoke a running session, and every decision is written to a hash-chained audit log. It works with any OIDC identity provider and is written in Rust, with Python and TypeScript SDKs.

**Status: pre-alpha.** The design is in [RFC-0001](docs/spec/rfc-0001-attenuo.md) and is still open for comment. Nothing here is ready for production use and formats will change before 1.0. See [Status](#status) for what has and has not been tested.

## See it block the GitHub MCP leak

In May 2025 researchers showed that a malicious issue in a public repository could steer an AI assistant. Through the official GitHub MCP server it read the user's private repositories and published them ([write-up](https://invariantlabs.ai/blog/mcp-github-vulnerability)). The demo replays that against a fake GitHub MCP server, so it runs offline.

You need a Rust toolchain, `curl` and `python3`.

```sh
git clone https://github.com/attenuo-dev/attenuo.git
cd attenuo
examples/github-leak-demo/run.sh
```

No Rust toolchain? With Docker, the same scenario runs from the published image and compiles nothing:

```sh
git clone https://github.com/attenuo-dev/attenuo.git
cd attenuo
examples/github-leak-demo/run-docker.sh
```

It pulls `ghcr.io/attenuo-dev/attenuo:0.1.0` and the stock Python image, which runs a small fake GitHub server ([details](examples/github-leak-demo/README.md#run-it-without-rust)).

With the Rust toolchain, the first run compiles the workspace: about a minute and a half on a 4-core machine, nearly all of it compiling (plus crate downloads if your cargo cache is empty). After that the script takes about a second ([measured](docs/design/bench/2026-10-24-vm-demo-cold-timing.md)). It starts attenuo and the fake server on free ports, plays nine steps with the `attenuo` CLI, and exits non-zero if any step comes out differently. In short:

- Alice's assistant gets a broad `github:*` token and hands its `coder` sub-agent `github:read_file` only.
- `coder` reads `alice/public-docs`: allowed.
- The injected call reads `alice/private-salaries`: `DENIED policy_deny`. The token allows `read_file`, but the policy only permits repos matching `alice/public-*`.
- The injected `create_issue` that would copy the data out: `DENIED capability_denied`, because it was never delegated.
- Alice revokes the assistant's lease. `coder`'s next call, even the legitimate one, is `DENIED lease_revoked`.
- The audit chain verifies (9 entries, one of them the `tool_result` record of the allowed read), and the fake GitHub server received exactly one call.

![The GitHub leak demo in a terminal: the coder reads the public repository, is refused the private one and create_issue, and is cut off by the revocation](docs/demo/github-leak-demo.gif)

A recorded run is in [transcript.md](examples/github-leak-demo/transcript.md) (the recording above is [docs/demo](docs/demo/README.md), paced for reading), and the step table is in the [demo README](examples/github-leak-demo/README.md). The demo mints Alice's root token through a development-only endpoint. A real deployment mints it from an OIDC ID token, as shown in [getting started](docs/guides/getting-started.md) and [identity providers](docs/guides/identity-providers.md).

## Install

Prebuilt binaries for Linux (x86_64, aarch64) and macOS (Intel, Apple silicon):

```sh
curl -fsSL https://raw.githubusercontent.com/attenuo-dev/attenuo/main/scripts/install.sh | sh
```

The script downloads the latest release's archive for your machine, checks its SHA-256 against the release's `SHA256SUMS`, and puts `attenuo` (the CLI) and `attenuo-server` in `~/.local/bin`. It does not use `sudo`. Set `ATTENUO_VERSION=v0.1.0` to pin a release and `ATTENUO_INSTALL_DIR` to choose the directory; [read the script](scripts/install.sh) first if you prefer. There is also a container image, `ghcr.io/attenuo-dev/attenuo`, and you can [build from source](CONTRIBUTING.md).

## Try it

- **Quickest:** the demo at the top of this page.
- **Step by step:** [Getting started](docs/guides/getting-started.md) writes a small config, runs the server in front of a fake MCP server, and makes allowed and denied calls.
- **By hand:** the [walkthrough](docs/guides/walkthrough.md) runs the example config and does one delegation with `curl`, then with the `attenuo` CLI and the Python and TypeScript SDKs.
- **Your own MCP client:** [Integrating MCP clients](docs/guides/integrating-mcp-clients.md).
- **A real deployment:** [Deploying](docs/guides/deploying.md) and [Identity providers](docs/guides/identity-providers.md).

The `attenuo` command line is documented in the [CLI reference](docs/reference/cli.md). The SDKs have their own pages: [Python](sdk/python/README.md) and [TypeScript](sdk/typescript/README.md). Neither is published to a package registry yet.

## How it works

```text
 user --login--> IdP --ID token--> orchestrator --exchange--> sub-agent
                                        |                        |
                       RFC 8693 token exchange at attenuo:      |
                       each hop gets a narrower token            |
                                        v                        v
                                  +---------------------------------+
     tools/call + bearer token    |        attenuo proxy           |
     ---------------------------> |  1. token and chain verify      |
                                  |  2. leases of every hop         |
                                  |  3. capability (tool, args)     |
                                  |  4. run limits of every hop     |
                                  |  5. Cedar policy, approvals     |
                                  |  6. audit record, then answer   |
                                  +----------------+----------------+
                                                   | allowed calls only
                                                   v
                                              MCP server
```

The user's ID token is exchanged once for a root token (RFC 8693) held by the orchestrator. The orchestrator exchanges that token again for each sub-agent. Each exchange can only shrink what the token allows: fewer tools, tighter argument constraints, a shorter lifetime, no more than the maximum depth. The whole chain, from the verified user to the current agent, is inside the token.

On every `tools/call`, attenuo verifies the token and its chain, then runs the checks below in order. The first failure denies the call, and the proxy answers with a JSON-RPC error carrying the reason and a decision id.

1. **Lease.** Every hop's lease must be live. Revoking any ancestor lease denies all of its descendants on their next call.
2. **Capability.** The tool and arguments must be covered by every hop's capability set.
3. **Run limits.** A capability can cap how many calls, how much in total, or how many destinations a run may use; a call that would go over any hop's limit is denied with `budget_exhausted` before policy runs. See [run limits](docs/design/run-limits.md) and [ADR-0010](docs/decisions/0010-run-limits.md).
4. **Policy.** A Cedar policy sees the originating user, the chain, the arguments, the run's remaining budget and whether the run has read untrusted tool output, and must explicitly permit the call. Deny is the default.
5. **Approval.** A policy can ask for a person instead of denying: the proxy answers `-32008` with an approval id, and once the user or an operator grants it, one identical retry goes through. See [output labelling](docs/design/output-labelling.md) and [ADR-0009](docs/decisions/0009-output-labelling.md).
6. **Audit.** The decision, allow or deny, is appended to a hash-chained log before the answer goes out.

Only allowed calls reach the MCP server, and an allowed call is charged against the run limits it matched in the same store transaction. More detail: [delegation chains](docs/concepts/delegation-chain.md), [capabilities and attenuation](docs/concepts/capabilities-and-attenuation.md), [leases](docs/concepts/leases-and-revocation.md), [the audit log](docs/concepts/audit-log.md), and [how it compares with the alternatives](docs/comparison.md).

## What it is not

- **Not a replacement for your API gateway.** It does not do routing or general traffic management. Its `[limits]` (an in-flight cap, request deadlines and optional per-caller rate limits) protect one attenuo process, not the services behind it, and run limits count calls per delegation run, not requests per second. It can sit behind a gateway as the decision point through its AuthZEN endpoint. One gateway adapter exists, for [agentgateway's external authorization](docs/guides/agentgateway.md); it has been run once against agentgateway v1.7.0, on one machine, on loopback.
- **Not a prompt-injection detector.** It never reads prompts or model output. It limits what an agent that has already been fooled can do with the authority it was given. In the [injection suite](docs/evaluation/injection-suite.md), 15 of 77 attack calls in the development split still went through the base configuration, because they used a tool and arguments the task legitimately needed. Output labelling and run limits narrow that, but only by asking a person or by a limit someone has to choose for the task.
- **Not a sandbox.** It only sees calls that go through it. If the agent also holds a direct API key or network path to the tool, attenuo sees nothing. See [what attenuo does not prevent](docs/spec/threat-model.md#what-attenuo-does-not-prevent).

**Not affiliated with Tenuo.** [Tenuo](https://github.com/tenuo-ai/tenuo) is a separate open-source project with a similar name and a related goal. The two are unrelated. In Tenuo the holder of a warrant narrows it offline; in attenuo every narrowing is a token exchange at a server you run (RFC 8693), so a running chain can be revoked at once. attenuo also applies a Cedar policy to each call and keeps a hash-chained log of every decision. The [comparison](docs/comparison.md) puts the two side by side.

## Numbers

All measured on a shared 4-core development container, so read them as indicative. Every figure, its caveats and its run are in [docs/numbers.md](docs/numbers.md).

- **With a model that follows attacks** (AgentDojo, local `qwen2.5:14b`, grants written by a planner model): 207 of 936 attacks landed alone and 25 of 936 behind attenuo. The cost: with no attack, 38 instead of 49 of 96 tasks finished. One model, one run per case ([details](docs/evaluation/agentdojo-local-model.md)).
- **Replay with no model** (AgentDojo's own attack calls): 592 of 609 attacks landed without attenuo, 13 of 609 with planner-written grants and the suite policy, keeping 75 of 97 benign tasks ([details](docs/evaluation/agentdojo-planner-grants.md)).
- **Own injection suite, held-out split:** 7 of 38 attack calls got through and 3 of 29 benign calls were refused. The cases and the policies have the same author, so this checks the corpus against the code and does not measure effectiveness ([details](docs/evaluation/injection-suite.md)).
- **Latency added:** about 0.4 to 0.8 ms at the median per proxied call with one client; a Cedar decision takes about 12 to 13 microseconds on a cache hit ([performance](docs/design/performance.md)).
- **Throughput:** 1,252 to 6,254 allowed calls per second at 1 to 32 clients, one hop, file-backed audit log at `durability = "normal"`.

## Status

attenuo is pre-alpha and has not been used in production. Release 0.1.0, the first, was tagged on 2026-11-19 ([release notes](docs/release/0.1.0.md)). The full account is in [docs/status.md](docs/status.md).

- **Tests and fuzzing.** Unit, property and integration tests in Rust and in both SDKs, the SDKs against a real server, and 22 fuzz targets with no open crash.
- **Proof.** A Lean model of the covering rule proves that delegation never widens authority in the model. The Rust code is not verified against it; a differential test finds the two in agreement on 31,500 generated cases.
- **Security review.** Twenty review passes recorded 138 findings; none is open, each is fixed or accepted with reasons. All passes were done by the project itself. There has been no outside audit.
- **Not tested.** Hosted identity providers (Auth0, Okta, Entra ID, Google), AWS S3, a production SPIRE or Keycloak, and the release workflow. No load test on reference hardware.

## Where to look

- [Guides](docs/guides/README.md): getting started, the walkthrough, integrating MCP clients, writing policies, deploying, identity providers.
- [FAQ](docs/faq.md) and [comparison](docs/comparison.md) with OAuth scopes, gateways, policy engines and SPIFFE.
- [RFC-0001](docs/spec/rfc-0001-attenuo.md): the token model, the policy and audit design. The rest of the specifications, decisions and research notes are under [docs/](docs/README.md).
- [Numbers](docs/numbers.md) and [status](docs/status.md) in full.
- [Examples](examples/README.md): the leak demo, a multi-hop delegation, a chain that starts at an identity provider, and agents in the Claude Agent SDK and LangChain.
- SDKs: [Python](sdk/python/README.md) and [TypeScript](sdk/typescript/README.md).
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) (please report vulnerabilities privately), [CHANGELOG.md](CHANGELOG.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Crates

| Crate | Purpose |
| --- | --- |
| `attenuo-core` | Delegation chains, capability sets, attenuation, decision records |
| `attenuo-token` | Token encoding, signing and verification |
| `attenuo-policy` | Policy evaluation |
| `attenuo-audit` | Append-only, hash-chained audit log |
| `attenuo-proxy` | Enforcement in front of upstream services |
| `attenuo-server` | The standalone server binary |
| `attenuo-cli` | The `attenuo` command line: a client for a running server, plus offline `audit verify --file` and `policy test` / `policy lint` |
| `attenuo-bench` | End-to-end latency and throughput benchmark (`scripts/bench-e2e.sh`, results in `docs/design/bench/`) |

## Building

```sh
cargo build --workspace
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full set of checks CI runs.

## How this project is built

attenuo is written by one maintainer working with AI coding agents (Claude Code), and the git history shows it: most commits carry a `Co-Authored-By` trailer for the model that wrote them. Every change went through a branch, local tests and review before it was merged, and the maintainer decides what the project does. Some parts of the evaluation were also written by AI agents, including the injection-suite cases, their policies and the scripted approver; the [technical report](docs/report/attenuo-2026-11.md) treats that as a threat to validity. The security review passes in `docs/research/` were done the same way, which is one more reason they are not a substitute for an outside audit. Rules for AI-assisted contributions are in [CONTRIBUTING](CONTRIBUTING.md#ai-assisted-contributions).

## License

Apache-2.0. See [LICENSE](LICENSE).

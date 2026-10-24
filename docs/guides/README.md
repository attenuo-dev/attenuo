# Guides

Task-oriented guides for people who want to run attenuo or build on it. They describe what the code does today. attenuo is pre-alpha, so read the limits in each guide.

| Guide | Read it when you want to |
| --- | --- |
| [Getting started](getting-started.md) | Build attenuo, run it in front of an MCP server, mint a token, make allowed and denied calls, revoke, and read the audit log |
| [Writing and testing policies](writing-policies.md) | Write Cedar policies for agents (server-scoped `Action::"<server>/<tool>"`), test them offline with `attenuo policy test`, lint them, and run both in CI |
| [Deploying](deploying.md) | Put it somewhere other than your laptop: bind address, TLS, admin token, key rotation, SQLite backup, lease tuning, logs, Docker, monitoring, and the v0 limits |
| [Integrating MCP clients](integrating-mcp-clients.md) | Write the agent side: send the bearer, exchange tokens hop to hop, handle denials, renew leases, call the AuthZEN endpoint from a non-MCP enforcement point |
| [Codebase walkthrough](../guide/codebase-walkthrough.md) | Read and run the whole codebase yourself: twelve sessions of reading order, questions and commands, a "why it is this way" index, a glossary and the things that surprise people |
| [Binding tokens to keys](binding-tokens-to-keys.md) | Make a leaked token useless: bind tokens to agent keys with DPoP, from the CLI, the SDKs or raw HTTP, and what the server refuses |
| [Identity providers](identity-providers.md) | Connect Keycloak, Auth0, Okta, Entra ID or Google, set up agents and root grants, and use ID-JAG. Provider recipes are untested |
| [Admin console](admin-console.md) | Look at the audit log, a decision, a lease tree, the loaded policies and the chain's signatures in a browser; revoke or reload from it if you allow writes |

Suggested order: Getting started, then Identity providers and Integrating MCP clients, then Deploying.

Other places to look:

- [FAQ](../faq.md): why a proxy, how it differs from gateways and policy engines, what happens when it is down.
- [design/server.md](../design/server.md): how a request is decided, with sequence diagrams and error codes.
- [config/example.toml](https://github.com/attenuo-dev/attenuo/blob/main/config/example.toml): every config key, annotated.
- [examples/github-leak-demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/github-leak-demo/README.md): a scripted replay of a real incident.
- [examples/multi-hop-demo](https://github.com/attenuo-dev/attenuo/blob/main/examples/multi-hop-demo/README.md): a planner delegating to a coder, narrowed at each hop, ended by one revocation of the chain.
- [examples/claude-agent-sdk](https://github.com/attenuo-dev/attenuo/blob/main/examples/claude-agent-sdk/README.md) and [examples/langchain-agent](https://github.com/attenuo-dev/attenuo/blob/main/examples/langchain-agent/README.md): agent frameworks talking to MCP servers through attenuo, a token per hop.
- [RFC-0001](../spec/rfc-0001-attenuo.md) and the [threat model](../spec/threat-model.md): what the system promises and what it does not.

## Conventions in these guides

- Commands are meant to be run as written. Where one has not been run, the guide says **untested**.
- `$OB` is your checkout of the repository. `$ATTENUO_ADMIN_TOKEN` is the admin bearer.
- A guide never uses the example admin token or agent secret from `config/example.toml` for anything real.

If a command in a guide does not work as written, that is a bug in the guide. Please open an issue.

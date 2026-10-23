# Guides

Task-oriented guides for people who want to run onbehalf or build on it. They describe what the code does today. onbehalf is pre-alpha, so read the limits in each guide.

| Guide | Read it when you want to |
| --- | --- |
| [Getting started](getting-started.md) | Build onbehalf, run it in front of an MCP server, mint a token, make allowed and denied calls, revoke, and read the audit log |
| [Deploying](deploying.md) | Put it somewhere other than your laptop: bind address, TLS, admin token, key rotation, SQLite backup, lease tuning, logs, Docker, monitoring, and the v0 limits |
| [Integrating MCP clients](integrating-mcp-clients.md) | Write the agent side: send the bearer, exchange tokens hop to hop, handle denials, renew leases, call the AuthZEN endpoint from a non-MCP enforcement point |
| [Identity providers](identity-providers.md) | Connect Keycloak, Auth0, Okta, Entra ID or Google, set up agents and root grants, and use ID-JAG. Provider recipes are untested |

Suggested order: Getting started, then Identity providers and Integrating MCP clients, then Deploying.

Other places to look:

- [FAQ](../faq.md): why a proxy, how it differs from gateways and policy engines, what happens when it is down.
- [design/server.md](../design/server.md): how a request is decided, with sequence diagrams and error codes.
- [config/example.toml](https://github.com/7Mudit/onbehalf/blob/main/config/example.toml): every config key, annotated.
- [examples/github-leak-demo](https://github.com/7Mudit/onbehalf/blob/main/examples/github-leak-demo/README.md): a scripted replay of a real incident.
- [RFC-0001](../spec/rfc-0001-onbehalf.md) and the [threat model](../spec/threat-model.md): what the system promises and what it does not.

## Conventions in these guides

- Commands are meant to be run as written. Where one has not been run, the guide says **untested**.
- `$OB` is your checkout of the repository. `$ONBEHALF_ADMIN_TOKEN` is the admin bearer.
- A guide never uses the example admin token or agent secret from `config/example.toml` for anything real.

If a command in a guide does not work as written, that is a bug in the guide. Please open an issue.

# Claude Agent SDK through onbehalf

An orchestrator agent hands a GitHub task to a `coder` sub-agent. Both are [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview) agents, the GitHub MCP server is reachable only through onbehalf's proxy, and each agent hop carries its own delegation token. A malicious issue tries to get the coder to read a private repository and copy it out; onbehalf refuses both calls.

This is the scenario of [github-leak-demo](../github-leak-demo/README.md) with a real agent framework on the client side. It reuses that demo's `config.toml` and `policy.cedar` unchanged.

## Run it

```sh
examples/claude-agent-sdk/run.sh
```

No API key needed: that is the **dry-run**, which makes the tool calls the coder would make, in a fixed order, with no model involved. It needs `curl`, `python3` (3.10 or newer) and a Rust toolchain (or `ONBEHALF_BIN_DIR=DIR` with prebuilt `onbehalf-server` and `fake_mcp`). The script creates a venv, installs `requirements.txt` and `sdk/python`, starts onbehalf-server and the fake GitHub MCP server on free ports, mints the orchestrator's root token through the dev endpoint (`[dev] allow_root_mint`, which a real deployment replaces with an IdP login), runs `agent.py --dry-run`, and fails if any call comes out differently than expected. `PYTHON=/path/to/python` skips the venv; `KEEP=1` keeps the logs.

The test is `test_example.py`, gated like the SDK's integration tests:

```sh
pip install -e sdk/python -r examples/claude-agent-sdk/requirements.txt pytest
ONBEHALF_INTEGRATION=1 ONBEHALF_BIN_DIR=target/debug pytest examples/claude-agent-sdk
```

### With a model

```sh
export ANTHROPIC_API_KEY=sk-ant-...
LIVE=1 examples/claude-agent-sdk/run.sh
```

`agent.py --live` runs `claude_agent_sdk.query()` with the orchestrator and the `coder` sub-agent, the model being `claude-opus-5-5` (override with `EXAMPLE_MODEL`). The prompt contains the simulated malicious issue. What the model does is up to it, so the output differs between runs; the denials come from onbehalf either way. **This path is not tested in CI and was not run with a key when the example was written**; the objects it builds (`ClaudeAgentOptions`, `AgentDefinition`) are constructed and checked against `claude-agent-sdk` 0.2.173, nothing more.

## The hops

```
 alice (user)
    |  root token: alice, via "assistant", github:*          (dev mint; an IdP login in production)
    v
 orchestrator ------------------------------------------------ no MCP server of its own
    |  token exchange, authenticated with the coder's client secret
    |  asks for: github:read_file where repo starts with "alice/public-"
    v
 coder sub-agent ---- Authorization: Bearer <narrowed token> ---> onbehalf /mcp/github ---> GitHub MCP
   (AgentDefinition.mcpServers)                                   checks the chain, the           (fake_mcp)
                                                                  constraint, Cedar, the lease
```

The orchestrator's agent id in the demo config is `assistant`; that is the name that shows in the chain (`assistant > coder`). The one place the token is handed over is `AgentDefinition(mcpServers=[{"github": {"type": "http", "url": ".../mcp/github", "headers": {"Authorization": "Bearer ..."}}}])`, see `agent_options()` in `agent.py`. The token is in an HTTP header, never in a prompt or a tool argument, so the model cannot repeat it.

## What each token may do

| Token | Held by | May | Cannot |
| --- | --- | --- | --- |
| root | orchestrator | `github:*` (anything the policy allows) | Nothing is given to the model: the orchestrator has no MCP server configured. |
| exchanged | coder | `github:read_file` with `repo` starting `alice/public-`, 10 minutes | Any other tool, or any other repo. |

The coder's token is the only thing the model can reach. The Cedar policy (`../github-leak-demo/policy.cedar`) is a second layer that applies to every call whatever the token says: `read_file` only on `alice/public-*`, no deep chains, no sensitive tools without MFA.

## What gets denied, and where to see it

The dry-run output (shortened):

```
[coder] tools/list through onbehalf shows: ['read_file']
  ALLOWED read_file {'repo': 'alice/public-docs', 'path': 'README.md'}
  DENIED  read_file {'repo': 'alice/private-salaries', ...}  reason=capability_denied decision=94801347-...
  DENIED  create_issue {'repo': 'alice/public-docs', ...}    reason=capability_denied decision=9aef3152-...
[orchestrator] the session looks compromised: revoking its lease
  DENIED  read_file {'repo': 'alice/public-docs', ...}       reason=lease_revoked decision=c4fc5999-...
[audit] chain ok=True, 8 entries
```

| Call | Result | Why |
| --- | --- | --- |
| `tools/list` | only `read_file` | The proxy filters the list to what the token may call. In live mode the model never sees `create_issue`, so the denial below only happens if it calls the tool anyway (a hallucination or an injected name). |
| `read_file alice/public-docs` | allowed, reaches the upstream | The intended use. |
| `read_file alice/private-salaries` | denied, `capability_denied` | The coder's token constrains `repo` to `alice/public-`. Had the token been broader, `policy_deny` from `policy.cedar` would stop it; the leak demo shows that layer. |
| `create_issue` | denied, `capability_denied` | The coder was never delegated it: the exfiltration path is closed. |
| `read_file` after the orchestrator's lease is revoked | denied, `lease_revoked` | Revocation cascades from the orchestrator's lease to the coder's. |

Every one of these is in the audit log, with the same `decision` id the denial carried. In the script the log is printed at the end (`#5 deny github/read_file reason=capability_denied` and so on). Against your own server:

```sh
onbehalf audit tail -n 10
onbehalf audit verify          # the hash chain checks out
curl -s "$ONBEHALF_SERVER/admin/audit?from=1&limit=20" -H "Authorization: Bearer $ONBEHALF_ADMIN_TOKEN"
```

`run.sh` also checks that the fake GitHub server saw exactly one `tools/call`, the legitimate one.

## How the dry-run relates to the live run

The dry-run does not call the Agent SDK. It reads the MCP server config that `coder_mcp_server()` produces (the same function live mode puts into `AgentDefinition`), opens an MCP Streamable HTTP session with the `mcp` client using that URL and header, and makes the calls. So the token, the URL and the headers are exercised for real; the model's choice of tool calls is the only thing replaced.

## Things to know

- **Which server name the tools get.** The inline MCP server is called `github`, so the coder's tools are `mcp__github__read_file` and `mcp__github__create_issue`. Both are listed in `tools`/`allowed_tools` on purpose: onbehalf, not the SDK's permission list, is what decides.
- **Refresh.** The token lasts ten minutes here. A long-running agent has to re-exchange before it expires and give the SDK a new header (new session or `TokenAuth` in the `mcp` client). Not shown.
- **Revoked sessions.** In the dry-run the coder's MCP session was open when the lease was revoked, so the denial arrives as JSON-RPC `-32003`. A client that opens a new session after the revocation gets HTTP 401 instead (see the [LangChain example](../langchain-agent/README.md)).
- **Telling onbehalf's denials from the upstream's errors.** The upstream is untrusted and can answer with its own `-32003` and any `reason`. The dry-run counts a `-32003` as onbehalf's only when its `data.decision_id` is in the `X-Onbehalf-Decision-Id` header of the proxy's response, which only the proxy sets (the SDKs' SR-32 check; SR-53 here). The `mcp` client raises `McpError` without the response, so the dry-run's HTTP client has a response hook (`ProxyDecisions`) that collects the decision ids the proxy sends, and `_denial` checks against them; any other `-32003` is printed as `UPSTREAM ERROR`. `test_example.py` checks both cases without servers. In live mode the Agent SDK runs the MCP client itself and hands the model the error text, so neither the model nor this script can make that check: what the model reads as a refusal may come from the upstream, and only the audit log (`onbehalf audit tail`) says what onbehalf decided.
- **The root token comes from the dev endpoint** and `alice` is asserted, not verified. See [what the leak demo does not show](../github-leak-demo/README.md#what-this-does-not-show).

## Files

- `agent.py`: the example (`--dry-run`, `--live`).
- `run.sh`: starts the servers, mints the root token, runs the dry-run.
- `requirements.txt`: `claude-agent-sdk==0.2.173`, `mcp==1.30.0` (run with Python 3.13; the `onbehalf` SDK is installed from the checkout).
- `test_example.py`: runs `run.sh` end to end.

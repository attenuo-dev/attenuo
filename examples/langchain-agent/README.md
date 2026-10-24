# LangChain through attenuo

The same scenario as the [Claude Agent SDK example](../claude-agent-sdk/README.md), with LangChain: an orchestrator agent hands a GitHub task to a `coder` agent, the coder's tools come from [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters) pointed at attenuo's proxy, and the coder's delegation token is the bearer. A malicious issue tries to get the coder to read a private repository and copy it out; attenuo refuses both calls. The orchestrator's own `create_issue` is held until a person approves it, and goes through after the grant. It reuses the [github-leak-demo](../github-leak-demo/README.md) `config.toml` and `policy.cedar` unchanged.

## Run it

```sh
examples/langchain-agent/run.sh
```

No API key needed: that is the **dry-run**, which invokes the coder's LangChain tools in a fixed order with no model involved. It needs `curl`, `python3` (3.10 or newer) and a Rust toolchain (or `ATTENUO_BIN_DIR=DIR` with prebuilt `attenuo-server` and `fake_mcp`). The script creates a venv, installs `requirements.txt` and `sdk/python`, starts attenuo-server and the fake GitHub MCP server on free ports, mints the orchestrator's root token through the dev endpoint (`[dev] allow_root_mint`, which a real deployment replaces with an IdP login), runs `agent.py --dry-run`, and fails if any call comes out differently than expected. `PYTHON=/path/to/python` skips the venv; `KEEP=1` keeps the logs.

The test is `test_example.py`:

```sh
pip install -e sdk/python -r examples/langchain-agent/requirements.txt pytest
ATTENUO_INTEGRATION=1 ATTENUO_BIN_DIR=target/debug pytest examples/langchain-agent
```

### With a model

```sh
export ANTHROPIC_API_KEY=sk-ant-...
LIVE=1 examples/langchain-agent/run.sh
```

`agent.py --live` builds two `langchain.agents.create_agent` agents on `ChatAnthropic(model="claude-opus-5-5")` (override with `EXAMPLE_MODEL`). The orchestrator's only tool is `ask_coder`, which runs the coder agent; the coder's tools are the MCP tools. **This path is not tested in CI and was not run with a key when the example was written.** Only the pieces that need no model were run: the MCP client, the interceptor and the tool loading.

## The hops

```
 alice (user)
    |  root token: alice, via "assistant", github:*          (dev mint; an IdP login in production)
    v
 orchestrator agent ---- tool: ask_coder ------------------- no MCP tools of its own
    |  token exchange, authenticated with the coder's client secret
    |  asks for: github:read_file where repo starts with "alice/public-"
    v
 coder agent ---- MultiServerMCPClient, Authorization: Bearer <narrowed token> ---> attenuo /mcp/github ---> GitHub MCP
                                                                                    checks the chain, the           (fake_mcp)
                                                                                    constraint, Cedar, the lease
```

The orchestrator's agent id in the demo config is `assistant`; that is the name in the chain (`assistant > coder`). The token goes in the connection config (`connections()` in `agent.py`): `{"transport": "http", "url": ".../mcp/github", "headers": {"Authorization": "Bearer ..."}}`. It is an HTTP header, never in a prompt or a tool argument.

## What each token may do

| Token | Held by | May | Cannot |
| --- | --- | --- | --- |
| root | orchestrator | `github:*` (anything the policy allows) | Nothing is given to the model: the orchestrator has no MCP tools. The dry-run uses it once, outside the agent graph, to open an issue that needs approval. |
| exchanged | coder | `github:read_file` with `repo` starting `alice/public-`, 10 minutes | Any other tool, or any other repo. |

The Cedar policy (`../github-leak-demo/policy.cedar`) is a second layer that applies to every call whatever the token says: `read_file` only on `alice/public-*`, `create_issue` only on `alice/public-*` and only after a person approves the call, no deep chains, no sensitive tools without MFA.

## What gets denied, and where to see it

The dry-run output (shortened):

```
[coder] tools/list through attenuo shows: ['read_file']
  ALLOWED read_file {'repo': 'alice/public-docs', 'path': 'README.md'}
  DENIED  read_file {'repo': 'alice/private-salaries', ...}  reason=capability_denied decision=90fed943-...
  the model sees: read_file is not allowed for this agent (capability_denied). Do not retry it.
  DENIED  create_issue {'repo': 'alice/public-docs', ...}    reason=capability_denied decision=0bdab038-...
[orchestrator] reports the typo itself: create_issue with its own token
  HELD    create_issue {'repo': 'alice/public-docs', 'title': 'README: fix typo'}  approval=b89c31a2-... decision=3aaeb05b-...
  [operator] approval b89c31a2-...: granted
  ALLOWED create_issue {'repo': 'alice/public-docs', 'title': 'README: fix typo'}  after approval b89c31a2-... (one retry)
[orchestrator] the session looks compromised: revoking its lease
  DENIED  read_file {'repo': 'alice/public-docs', ...}       HTTP 401 (lease gone)
[audit] chain ok=True, 13 entries
```

| Call | Result | Why |
| --- | --- | --- |
| `tools/list` (when the adapter loads tools) | only `read_file` | The proxy filters the list to what the token may call. The model never sees `create_issue`; the denial below only happens if it is called anyway. |
| `read_file alice/public-docs` | allowed, reaches the upstream | The intended use. |
| `read_file alice/private-salaries` | denied, `capability_denied` | The coder's token constrains `repo` to `alice/public-`. Had the token been broader, `policy_deny` from `policy.cedar` would stop it; the leak demo shows that layer. |
| `create_issue` | denied, `capability_denied` | The coder was never delegated it. The dry-run sends it over the adapter's own session, as a hallucinated call would arrive. |
| `create_issue alice/public-docs` with the orchestrator's root token | held (`-32008`), then allowed | The token allows it, but `policy.cedar` holds every `create_issue` until a person approves it. The interceptor prints the approval id, the operator grants it (`AdminClient.grant_approval`, as `attenuo approval grant` does), and the interceptor retries the identical call once. |
| `read_file` after the orchestrator's lease is revoked | HTTP 401 | Revocation cascades from the orchestrator's lease to the coder's. |

The two JSON-RPC denials are in the audit log with the `decision` id they carried (`#6` and `#7` in the script's output; `#5` is the `tool_result` record of the allowed read). The approval is `#8` to `#12`: the held call (`approval_required`), the approval it opened (`approval_requested`), the grant (`approval_granted`), and the retry with its result (`policy_allow`, `tool_result`). The last call is different: `langchain-mcp-adapters` opens a new MCP session for each tool call, and a session cannot start on a revoked lease, so the proxy answers 401 before MCP begins. That is a transport error in the client, not an MCP error, and **it is not an audit record** in this version (the audit shows the revocation itself, `admin.lease.revoke`). The `denial_interceptor` in `agent.py` turns it into `LeaseRevoked` and stops the run. Against your own server:

```sh
attenuo audit tail -n 10
attenuo audit verify
```

`run.sh` also checks that the fake GitHub server saw exactly two `tools/call`s, the legitimate read and the approved issue.

## How denials reach the model

`langchain-mcp-adapters` lets a JSON-RPC error escape the tool as an exception, which would end the whole agent run. A denial is a decision, so `denial_interceptor` (a `tool_interceptors` entry) catches attenuo's `-32003` and returns it as a tool error: the model reads "read_file is not allowed for this agent (capability_denied). Do not retry it." and the decision id goes to the log. Keep that in any agent you build on this: the model should be told once, plainly, and not given the server's internals.

### Approvals

A call a policy holds for a person arrives as JSON-RPC `-32008` with `approval_id` in its `data`. `denial_interceptor` handles it as the SDK's `Client.call_tool_with_approval` does: it reports the approval id (`on_approval`), waits for the grant (`approval_waiter`, which polls `GET /approvals/{id}` with the caller's own token through `AsyncClient.wait_for_approval`), and retries the identical call once. The server finds the grant by the call's hash, so the retry needs no extra field. A decline or an expiry, or a second `-32008` after the grant, reaches the model as a tool error that tells it not to retry. In the dry-run the operator grants the approval through `AdminClient.grant_approval`; in live mode the interceptor prints `attenuo approval grant <id>` and the run waits until someone runs it or the approval expires. The SR-53 check applies here too: a `-32008` whose decision id the proxy did not send in `X-Attenuo-Decision-Id` is the upstream's own error, and the interceptor neither waits on it nor retries.

### Telling attenuo's denials from the upstream's errors

The upstream is untrusted, and nothing stops it from answering with its own `-32003` and a `reason` of its choosing. A `-32003` is attenuo's only when its `data.decision_id` is in the `X-Attenuo-Decision-Id` header of the proxy's response: the proxy sets that header and never forwards one from the upstream. The attenuo SDKs check this (SR-32); this example does the same (SR-53). The adapter raises `McpError` without the HTTP response, so `connections()` passes an `httpx_client_factory` that builds the `mcp` package's client with a response hook (`ProxyDecisions`), which collects every decision id the proxy sends. `denial_of` accepts a `-32003` only when its decision id is one of them; any other `-32003` is printed as `UPSTREAM ERROR` and given to the model as a plain tool failure, not as a decision. `test_example.py` checks both cases without servers. If you build on a client that gives you no way to see response headers, treat a `-32003` as an upstream error rather than as attenuo's word.

## How the dry-run relates to the live run

The dry-run builds the same `MultiServerMCPClient` (same connection, same interceptor), loads the tools with `get_tools()` and calls them with `ainvoke`, as the agent loop does. The token, the URL, the headers and the tool wrappers are exercised for real; the model's choice of tool calls is the only thing replaced.

## Things to know

- **`langchain-mcp-adapters` is archived upstream** and its README now points to `langchain[mcp]`. Version 0.3.2 works with `langchain` 1.4.7 as pinned in `requirements.txt`; if you move to `langchain[mcp]`, the connection config and interceptor idea carry over, but this example was not run against it.
- **Per-call sessions.** Each tool call is a fresh MCP session, so every call re-sends the bearer (good for revocation) and the token must be valid at each call. A long-running agent re-exchanges before it expires; `MCPToolCallRequest.headers` in an interceptor is the place to put a fresh one. Not shown.
- **Run limits** are not shown here; the [Claude Agent SDK example](../claude-agent-sdk/README.md) has them, and they carry over unchanged. A run limit goes on the coder's capability before the exchange (`Capability(...).with_limits(distinct=("repo", 1))`), and a call over it is a `-32003` with reason `budget_exhausted`, which `denial_interceptor` already hands to the model. Approvals are shown ([above](#approvals)).
- **The root token comes from the dev endpoint** and `alice` is asserted, not verified. See [what the leak demo does not show](../github-leak-demo/README.md#what-this-does-not-show).

## Files

- `agent.py`: the example (`--dry-run`, `--live`).
- `run.sh`: starts the servers, mints the root token, runs the dry-run.
- `requirements.txt`: `langchain==1.4.7`, `langchain-core==1.7.0`, `langchain-anthropic==1.7.6`, `langchain-mcp-adapters==0.3.2`, `langgraph==1.2.16`, `mcp==1.30.0` (run with Python 3.13; the `attenuo` SDK is installed from the checkout).
- `test_example.py`: runs `run.sh` end to end, and checks the interceptor without servers (SR-53, and the approval wait and single retry).

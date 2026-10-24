# Examples

Each example is runnable from a checkout. All of them except the multi-hop demo use the config and policy of the GitHub leak demo, so they behave the same against the same fake GitHub MCP server. The multi-hop demo has its own config and policy, and starts the same fake server with the real GitHub MCP server's tool names.

| Example | Language | Shows | Needs a model |
| --- | --- | --- | --- |
| [github-leak-demo](github-leak-demo/README.md) | shell + `attenuo` CLI | The May 2025 GitHub MCP prompt-injection leak, replayed and stopped. Start here. | no |
| [multi-hop-demo](multi-hop-demo/README.md) | shell + `attenuo` CLI | Delegation narrowing over three hops: alice, a planner, a coder and the GitHub tools, with a refused widening, a refused further delegation, a policy denial, a run limit (`budget_exhausted`), revocation of the chain by `chain_id` and the audit record of a denied call. | no |
| [claude-agent-sdk](claude-agent-sdk/README.md) | Python | A Claude Agent SDK orchestrator delegating to a `coder` sub-agent with a narrowed token, through the proxy, plus a run limit and an approval. | dry-run: no; live: `ANTHROPIC_API_KEY` |
| [langchain-agent](langchain-agent/README.md) | Python | The same with LangChain and `langchain-mcp-adapters`. | dry-run: no; live: `ANTHROPIC_API_KEY` |
| [python-agent](python-agent/agent.py) | Python | A planner delegating to a coder with the Python SDK, with a run limit (`budget_exhausted`) and an approval (`-32008`, granted, retried); `mcp_client_example.py` wires the official `mcp` client to the proxy. | no |
| [typescript-agent](typescript-agent/agent.ts) | TypeScript | The same with the TypeScript SDK. | no |

The two shell demos have a `run.sh` that starts everything it needs on free ports and fails on any step that comes out differently; CI runs both. The two framework examples have a `run.sh` that starts attenuo-server and the fake upstream, mints the root token, and runs a deterministic dry-run; a `test_example.py` runs it under pytest when `ATTENUO_INTEGRATION=1`. The live mode of each (a real model deciding the tool calls) was not run with a key when they were written.

`python-agent` and `typescript-agent` run against a server you start yourself from the demo config, as their header comments show; their steps are also run by each SDK's integration test (`ATTENUO_INTEGRATION=1`).

Tools in these examples are the fake server's (`read_file`, `create_issue`, `delete_repo`); nothing touches real GitHub.

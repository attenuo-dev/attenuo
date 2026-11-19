"""Use the official `mcp` Python client through attenuo's proxy.

attenuo speaks MCP Streamable HTTP at `<server>/mcp/<upstream>` and wants
`Authorization: Bearer <delegation token>` on every request. `attenuo.mcp` produces the URL and
the header; the rest is the MCP client's normal setup.

    pip install -e sdk/python mcp
    ATTENUO_SERVER=http://127.0.0.1:18080 ATTENUO_ADMIN_TOKEN=demo-admin-token \\
        python examples/python-agent/mcp_client_example.py

against the server and fake upstream started as in `agent.py`'s header (the GitHub-leak demo's
config, which listens on 127.0.0.1:18080).

Tested with `mcp` 2.3.0 (which builds on `httpx2`) and with `mcp` 1.30.0 against the fake GitHub
MCP server of the demo; both have `streamable_http_client`. The fallback for older `mcp` 1.x
(`streamablehttp_client(url, headers=...)`) is NOT tested. Note that
a full MCP client opens a session with `initialize` first; the fake upstream accepts that, but a
real one may assign an `Mcp-Session-Id` that the client library then carries by itself.

A denied call arrives as a JSON-RPC error with code -32003; the `mcp` client turns that into an
`McpError` whose `.error.data` holds `{"reason", "decision_id"}`.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from attenuo import AdminClient, Capability, Client, Prefix
from attenuo.mcp import mcp_headers, mcp_url

SERVER = os.environ.get("ATTENUO_SERVER", "http://127.0.0.1:8080")
ADMIN_TOKEN = os.environ.get("ATTENUO_ADMIN_TOKEN", "demo-admin-token")
# The coder's [[agents]] secret in the demo config: an exchange authenticates as its actor.
CODER_SECRET = os.environ.get("ATTENUO_CODER_SECRET", "demo-coder-secret")
# The agent id that the demo config (examples/github-leak-demo/config.toml) grants `github:*`.
PLANNER_AGENT = "assistant"


async def main() -> None:
    from mcp import ClientSession
    from mcp.client import streamable_http

    transport: Any = streamable_http

    def open_transport(url: str, headers: dict[str, str]) -> Any:
        if hasattr(transport, "streamable_http_client"):
            # mcp 1.30 and 2.x: the transport takes a pre-configured http client
            client = transport.create_mcp_http_client(headers=headers)
            return transport.streamable_http_client(url, http_client=client)
        # older mcp 1.x (untested)
        return transport.streamablehttp_client(url, headers=headers)

    admin = AdminClient(SERVER, ADMIN_TOKEN)
    with Client(SERVER) as ob:
        root = admin.mint_root_dev("alice", "https://idp.example", PLANNER_AGENT, ["github:*"])
        token = ob.exchange(
            root,
            "coder",
            [Capability("github", "read_file", repo=Prefix("alice/public-"))],
            client_secret=CODER_SECRET,
        )

    url = mcp_url(SERVER, "github")
    async with open_transport(url, mcp_headers(token)) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("tools the token may call:", [t.name for t in tools.tools])
            result = await session.call_tool(
                "read_file", {"repo": "alice/public-docs", "path": "README.md"}
            )
            print("allowed:", result.content)
            try:
                await session.call_tool("read_file", {"repo": "alice/private-salaries"})
            except Exception as e:  # McpError; the type moved between mcp releases
                print("denied:", e)

    admin.revoke_lease(root.lease, "example finished")
    admin.close()


if __name__ == "__main__":
    asyncio.run(main())

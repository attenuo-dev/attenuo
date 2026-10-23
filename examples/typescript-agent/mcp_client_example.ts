/**
 * Use the official `@modelcontextprotocol/sdk` client through attenuo's proxy.
 *
 * attenuo speaks MCP Streamable HTTP at `<server>/mcp/<upstream>` and wants
 * `Authorization: Bearer <delegation token>` on every request. `mcpUrl` and `mcpHeaders` produce
 * the URL and the header; the rest is the MCP client's normal setup.
 *
 *     cd examples/typescript-agent && npm install
 *     ATTENUO_SERVER=http://127.0.0.1:8080 ATTENUO_ADMIN_TOKEN=demo-admin-token npm run mcp
 *
 * Tested with @modelcontextprotocol/sdk 1.32.1 against the fake GitHub MCP server of the demo
 * (`npm run mcp` here; the integration test runs it too).
 *
 * A denied call arrives as a JSON-RPC error with code -32003; the MCP client turns that into an
 * `McpError` whose `data` holds `{ reason, decision_id }`.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { AdminClient, capability, mcpHeaders, mcpUrl, AttenuoClient, prefix } from "@attenuo/sdk";

const SERVER = process.env.ATTENUO_SERVER ?? "http://127.0.0.1:8080";
const ADMIN_TOKEN = process.env.ATTENUO_ADMIN_TOKEN ?? "demo-admin-token";
const PLANNER_AGENT = "assistant";

const admin = new AdminClient(SERVER, ADMIN_TOKEN);
const ob = new AttenuoClient(SERVER);
const root = await admin.mintRootDev("alice", "https://idp.example", PLANNER_AGENT, {
  capabilities: "github:*",
});
const token = await ob.exchange(
  root,
  "coder",
  [capability("github", "read_file", { repo: prefix("alice/public-") })],
  // The coder's [[agents]] secret: every hop n+1 exchange authenticates as its actor.
  { clientSecret: process.env.ATTENUO_CLIENT_SECRET ?? "demo-coder-secret" },
);

const transport = new StreamableHTTPClientTransport(new URL(mcpUrl(SERVER, "github")), {
  // Sent on every request the transport makes (initialize, tools/*, the session GET and DELETE).
  requestInit: { headers: mcpHeaders(token) },
});
const client = new Client({ name: "attenuo-example", version: "0" });
await client.connect(transport);

const tools = await client.listTools();
console.log(
  "tools the token may call:",
  tools.tools.map((t) => t.name),
);

const allowed = await client.callTool({
  name: "read_file",
  arguments: { repo: "alice/public-docs", path: "README.md" },
});
console.log("allowed:", JSON.stringify(allowed.content));

try {
  await client.callTool({ name: "read_file", arguments: { repo: "alice/private-salaries" } });
  console.log("NOT denied (unexpected)");
  process.exitCode = 1;
} catch (e) {
  console.log("denied:", (e as Error).message);
}

await client.close();
await admin.revokeLease(root.lease, "example finished");

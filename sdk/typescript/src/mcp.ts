/**
 * Helpers for pointing an MCP client at onbehalf's proxy.
 *
 * onbehalf mounts each upstream at `<serverUrl>/mcp/<name>` and speaks MCP Streamable HTTP there.
 * A client needs two things: that URL, and `Authorization: Bearer <delegation token>` on every
 * request (`initialize`, `tools/list`, `tools/call` and the `GET`/`DELETE` session requests).
 */

import { bearer, type Token } from "./token.js";
import { MCP_ACCEPT, normalizeBase } from "./wire.js";

/**
 * Headers an MCP client must send to onbehalf.
 *
 * By default only `Authorization` (and `Mcp-Session-Id` when given): MCP client libraries add
 * `Accept` and `Content-Type` themselves. Pass `contentHeaders: true` for a raw HTTP client.
 */
export function mcpHeaders(
  token: Token | string,
  sessionId?: string,
  opts: { contentHeaders?: boolean } = {},
): Record<string, string> {
  const h: Record<string, string> = { Authorization: `Bearer ${bearer(token)}` };
  if (sessionId) h["Mcp-Session-Id"] = sessionId;
  if (opts.contentHeaders) {
    h.Accept = MCP_ACCEPT;
    h["Content-Type"] = "application/json";
  }
  return h;
}

/** The MCP endpoint for upstream `server`: `http://host:8080/mcp/github`. */
export function mcpUrl(serverUrl: string, server: string): string {
  return `${normalizeBase(serverUrl)}/mcp/${encodeURIComponent(server)}`;
}

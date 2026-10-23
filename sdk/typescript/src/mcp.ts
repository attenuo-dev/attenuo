/**
 * Helpers for pointing an MCP client at onbehalf's proxy.
 *
 * onbehalf mounts each upstream at `<serverUrl>/mcp/<name>` and speaks MCP Streamable HTTP there.
 * A client needs two things: that URL, and `Authorization: Bearer <delegation token>` on every
 * request (`initialize`, `tools/list`, `tools/call` and the `GET`/`DELETE` session requests).
 * A token bound to a key (DPoP) also needs a fresh proof per request: use `mcpFetch`.
 */

import { DpopKey, presented, type DpopKeyLike } from "./dpop.js";
import type { FetchLike } from "./http.js";
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

/**
 * A `fetch` for an MCP client library (for example the `fetch` option of the MCP SDK's
 * `StreamableHTTPClientTransport`) that authorizes every request with the current token.
 *
 * `token` is called per request, so a re-exchanged token is picked up. With `dpopKey`, each
 * request also gets a DPoP proof for its method and URL and the token is sent as
 * `Authorization: DPoP <token>`: what a token bound to that key needs. Static headers
 * (`mcpHeaders`) cannot carry proofs, which are single-use.
 */
export function mcpFetch(
  token: () => Token | string | Promise<Token | string>,
  opts: { dpopKey?: DpopKeyLike; fetch?: FetchLike } = {},
): FetchLike {
  const base = opts.fetch ?? ((input, init) => fetch(input, init));
  let key: Promise<DpopKey | undefined> | undefined;
  return async (input, init = {}) => {
    key ??= DpopKey.of(opts.dpopKey);
    const headers = new Headers(init.headers);
    const auth = await presented(
      bearer(await token()),
      await key,
      init.method ?? "GET",
      String(input),
    );
    for (const [k, v] of Object.entries(auth)) headers.set(k, v);
    return base(input, { ...init, headers });
  };
}

/** The MCP endpoint for upstream `server`: `http://host:8080/mcp/github`. */
export function mcpUrl(serverUrl: string, server: string): string {
  return `${normalizeBase(serverUrl)}/mcp/${encodeURIComponent(server)}`;
}

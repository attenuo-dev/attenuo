/**
 * Helpers for pointing an MCP client at attenuo's proxy.
 *
 * attenuo mounts each upstream at `<serverUrl>/mcp/<name>` and speaks MCP Streamable HTTP there.
 * A client needs two things: that URL, and `Authorization: Bearer <delegation token>` on every
 * request (`initialize`, `tools/list`, `tools/call` and the `GET`/`DELETE` session requests).
 * A token bound to a key (DPoP) also needs a fresh proof per request: use `mcpFetch`.
 */

import { DpopKey, NonceCache, presented, resendOnce, type DpopKeyLike } from "./dpop.js";
import type { FetchLike } from "./http.js";
import { bearer, type Token } from "./token.js";
import { MCP_ACCEPT, normalizeBase } from "./wire.js";

/**
 * Headers an MCP client must send to attenuo.
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
 * (`mcpHeaders`) cannot carry proofs, which are single-use. The latest `DPoP-Nonce` the server
 * sent goes in each proof, and a request the server refuses with `use_dpop_nonce` is sent once
 * more with a proof carrying the new nonce (unless its body is a stream, which cannot be resent).
 * Redirects are not followed (`redirect: "manual"`): a 3xx goes back to the MCP library as it is.
 */
export function mcpFetch(
  token: () => Token | string | Promise<Token | string>,
  opts: { dpopKey?: DpopKeyLike; fetch?: FetchLike } = {},
): FetchLike {
  const base = opts.fetch ?? ((input, init) => fetch(input, init));
  let key: Promise<DpopKey | undefined> | undefined;
  const nonce = new NonceCache();
  return async (input, init = {}) => {
    key ??= DpopKey.of(opts.dpopKey);
    const dpopKey = await key;
    const jwt = bearer(await token());
    const headersNow = async () => {
      const headers = new Headers(init.headers);
      const auth = await presented(jwt, dpopKey, init.method ?? "GET", String(input), nonce.value);
      for (const [k, v] of Object.entries(auth)) headers.set(k, v);
      return headers;
    };
    // Never followed, whatever `init` asks: a redirect would take the body (tool arguments)
    // and the proof to another origin (SR-112). The MCP library gets the 3xx, or a browser's
    // opaque redirect, as it is.
    const redirect = "manual" as const;
    let res = await base(input, { ...init, redirect, headers: await headersNow() });
    const replayable = !(init.body instanceof ReadableStream);
    if (dpopKey !== undefined && (await nonce.update(res)) && replayable) {
      await res.body?.cancel();
      const headers = await headersNow();
      res = await resendOnce(() => base(input, { ...init, redirect, headers }));
      await nonce.update(res);
    }
    return res;
  };
}

/** The MCP endpoint for upstream `server`: `http://host:8080/mcp/github`. */
export function mcpUrl(serverUrl: string, server: string): string {
  return `${normalizeBase(serverUrl)}/mcp/${encodeURIComponent(server)}`;
}

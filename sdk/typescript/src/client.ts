/**
 * Client for the onbehalf server. It mirrors what the `onbehalf` CLI does over HTTP:
 * `POST /token`, `POST /token/renew`, `POST /mcp/{server}` and `POST /access/v1/evaluation`.
 */

import type { CapabilityLike } from "./capability.js";
import { authHeader, Http, type HttpOptions } from "./http.js";
import { bearer, decodeToken, verifyToken, type Jwks, type Token } from "./token.js";
import { mcpHeaders } from "./mcp.js";
import * as w from "./wire.js";

export interface ClientOptions extends HttpOptions {
  /** A default bearer used when a method is called without one. */
  token?: Token | string;
}

export interface InspectOptions {
  /** Check the Ed25519 signature against the server's JWKS (default false: decode only). */
  verify?: boolean;
  /** Where to fetch the JWKS from; defaults to `<serverUrl>/.well-known/jwks.json`. */
  jwksUrl?: string;
  /** Pin the `iss` claim. */
  issuer?: string;
  /** Pin the `aud` claim. */
  audience?: string;
}

export interface McpOptions {
  /** `Mcp-Session-Id` from `initialize`, for upstreams that keep sessions. */
  sessionId?: string;
}

export class OnbehalfClient {
  readonly serverUrl: string;
  /** Default bearer; assign a new one after a re-exchange. */
  token: Token | string | undefined;
  private readonly http: Http;
  private nextId = 1;

  constructor(serverUrl: string, opts: ClientOptions = {}) {
    this.http = new Http(serverUrl, opts);
    this.serverUrl = this.http.base;
    this.token = opts.token;
  }

  /**
   * RFC 8693 token exchange: trade `subjectToken` for a narrower token held by `actor`.
   *
   * For a hop n to n+1 exchange, `subjectToken` is the parent delegation token. For hop 0 (an IdP
   * credential), pass `clientId` and `clientSecret` of a registered agent, or its `actorToken`;
   * the subject token type then defaults to an OIDC ID token, or set `subjectTokenType` to
   * `urn:ietf:params:oauth:token-type:id-jag` for an ID-JAG.
   *
   * Either kind of request authenticates the agent with `clientSecret`, or with `actorToken`: a
   * workload-identity JWT (for example a SPIFFE JWT-SVID) from an `[[actor_trust]]` issuer. Each
   * actor token authenticates one request.
   * `mayAct` lists the agents allowed to exchange the new token next (RFC 8693 §4.4).
   *
   * Throws `ApiError` (`invalid_scope`, `invalid_grant`, ...) on refusal.
   */
  async exchange(
    subjectToken: Token | string,
    actor: string,
    capabilities: CapabilityLike | readonly CapabilityLike[],
    opts: w.ExchangeOptions = {},
  ): Promise<Token> {
    const body = w.exchangeBody(subjectToken, actor, capabilities, opts);
    return w.tokenFromResponse(await w.jsonBody(await this.http.post("/token", { json: body })));
  }

  /** Extend the lease of the token's last hop (`POST /token/renew`). */
  async renew(token?: Token | string): Promise<w.Lease> {
    const res = await this.http.post("/token/renew", {
      headers: authHeader(bearer(token, this.token)),
    });
    return w.leaseFromResponse(await w.jsonBody(res));
  }

  private async rpc(
    token: Token | string | undefined,
    server: string,
    method: string,
    params: Record<string, unknown>,
    sessionId?: string,
  ): Promise<{ result: Record<string, unknown>; decisionId?: string; response: Response }> {
    const res = await this.http.post(`/mcp/${encodeURIComponent(server)}`, {
      headers: mcpHeaders(bearer(token, this.token), sessionId, { contentHeaders: true }),
      json: w.rpcRequest(method, params, this.nextId++),
    });
    return { ...(await w.rpcResult(res)), response: res };
  }

  /** MCP `initialize`; returns the `Mcp-Session-Id` the upstream assigned, if any. */
  async initialize(
    token: Token | string | undefined,
    server: string,
    opts: { clientName?: string; protocolVersion?: string } = {},
  ): Promise<string | undefined> {
    const { response } = await this.rpc(token, server, "initialize", {
      protocolVersion: opts.protocolVersion ?? "2025-06-18",
      capabilities: {},
      clientInfo: { name: opts.clientName ?? "onbehalf-typescript", version: "0" },
    });
    return response.headers.get(w.SESSION_HEADER) ?? undefined;
  }

  /** `tools/call` through the proxy. Throws `DeniedError` when refused. */
  async callTool(
    token: Token | string | undefined,
    server: string,
    tool: string,
    args: Record<string, unknown> = {},
    opts: McpOptions = {},
  ): Promise<w.ToolResult> {
    const { result, decisionId } = await this.rpc(
      token,
      server,
      "tools/call",
      { name: tool, arguments: args },
      opts.sessionId,
    );
    return w.toolResult(result, decisionId);
  }

  /** `tools/list`; the proxy shows only the tools this token may call. */
  async listTools(
    token: Token | string | undefined,
    server: string,
    opts: McpOptions = {},
  ): Promise<w.Tool[]> {
    const { result } = await this.rpc(token, server, "tools/list", {}, opts.sessionId);
    return w.toolsFromResult(result);
  }

  /** Ask for a decision without calling the tool. A deny is returned, not thrown. */
  async authzenEvaluate(
    token: Token | string | undefined,
    server: string,
    tool: string,
    args?: Record<string, unknown>,
  ): Promise<w.AuthzenDecision> {
    const res = await this.http.post("/access/v1/evaluation", {
      headers: authHeader(bearer(token, this.token)),
      json: w.authzenBody(server, tool, args),
    });
    return w.authzenFromResponse(await w.jsonBody(res));
  }

  /** `GET /.well-known/jwks.json`. */
  async jwks(url?: string): Promise<Jwks> {
    const res = url ? await this.http.getUrl(url) : await this.http.get("/.well-known/jwks.json");
    return w.asObject(await w.jsonBody(res), "JWKS") as Jwks;
  }

  /**
   * Decode a delegation token; with `verify: true` also check its Ed25519 signature.
   *
   * Without `verify` nothing is checked and `Token.verified` is false. With it, the server's JWKS
   * is fetched and `VerificationError` is thrown on failure.
   */
  async inspect(jwt: Token | string, opts: InspectOptions = {}): Promise<Token> {
    const raw = typeof jwt === "string" ? jwt : jwt.jwt;
    if (!opts.verify) return decodeToken(raw);
    const verifyOpts: { issuer?: string; audience?: string } = {};
    if (opts.issuer !== undefined) verifyOpts.issuer = opts.issuer;
    if (opts.audience !== undefined) verifyOpts.audience = opts.audience;
    return verifyToken(raw, await this.jwks(opts.jwksUrl), verifyOpts);
  }
}

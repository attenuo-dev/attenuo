/**
 * Client for the attenuo server. It mirrors what the `attenuo` CLI does over HTTP:
 * `POST /token`, `POST /token/renew`, `POST /mcp/{server}` and `POST /access/v1/evaluation`.
 */

import type { CapabilityLike } from "./capability.js";
import { DpopKey, NonceCache, exchangeProofs, presented, type DpopKeyLike } from "./dpop.js";
import { AttenuoError } from "./errors.js";
import { Http, type HttpOptions } from "./http.js";
import { bearer, decodeToken, verifyToken, type Jwks, type Token } from "./token.js";
import { mcpHeaders } from "./mcp.js";
import * as w from "./wire.js";

export interface ClientOptions extends HttpOptions {
  /** A default bearer used when a method is called without one. */
  token?: Token | string;
  /**
   * Make this client sender-constrained (DPoP, RFC 9449): a `DpopKey` or a private JWK. Every
   * request then carries a proof by the key, exchanges bind the new token to it, and tokens are
   * sent as `Authorization: DPoP <token>`. A token bound to a key is refused without proofs, so a
   * copied token is useless on its own. When the server hands out DPoP nonces, the client keeps
   * the latest one, puts it in every proof, and retries a request once on `use_dpop_nonce`.
   */
  dpopKey?: DpopKeyLike;
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

export class AttenuoClient {
  readonly serverUrl: string;
  /** Default bearer; assign a new one after a re-exchange. */
  token: Token | string | undefined;
  private readonly http: Http;
  private nextId = 1;
  private readonly dpopKeyLike: DpopKeyLike | undefined;
  private dpopKeyPromise: Promise<DpopKey | undefined> | undefined;
  private readonly nonce = new NonceCache();

  constructor(serverUrl: string, opts: ClientOptions = {}) {
    this.http = new Http(serverUrl, opts);
    this.serverUrl = this.http.base;
    this.token = opts.token;
    this.dpopKeyLike = opts.dpopKey;
  }

  /** The client's DPoP key (imported on first use), or undefined for a bearer-only client. */
  dpopKey(): Promise<DpopKey | undefined> {
    this.dpopKeyPromise ??= DpopKey.of(this.dpopKeyLike);
    return this.dpopKeyPromise;
  }

  /**
   * `Authorization` (and a DPoP proof with this client's key and the server's `nonce`) to present
   * `jwt` at `path`.
   */
  private auth(jwt: string, path: string): (nonce?: string) => Promise<Record<string, string>> {
    return async (nonce) =>
      presented(jwt, await this.dpopKey(), "POST", `${this.serverUrl}${path}`, nonce);
  }

  /** `POST path` with `headers(nonce)`; once more with the server's new nonce on `use_dpop_nonce`. */
  private async post(
    path: string,
    headers: (nonce?: string) => Promise<Record<string, string>>,
    json?: unknown,
  ): Promise<Response> {
    const send = async () =>
      this.http.post(path, { headers: await headers(this.nonce.value), json });
    let res = await send();
    if ((await this.dpopKey()) !== undefined && (await this.nonce.update(res))) {
      await res.body?.cancel();
      res = await send();
      await this.nonce.update(res);
    }
    return res;
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
   * With a `dpopKey` on the client, the new token is bound to it. When `subjectToken` is bound to
   * another key, the parent's holder must sign off on this delegation (a child of a bound token is
   * always bound): it makes `DpopKey.signOff(tokenUrl, subjectToken, childJkt, actor)` with its
   * key and hands the result to the sub-agent, which passes it as `subjectTokenDpop`. The sign-off
   * names the new token's key and agent, so it is good for this delegation only. When one process
   * holds both keys, pass the parent's key as `subjectDpopKey` instead.
   *
   * Throws `ApiError` (`invalid_scope`, `invalid_grant`, ...) on refusal.
   */
  async exchange(
    subjectToken: Token | string,
    actor: string,
    capabilities: CapabilityLike | readonly CapabilityLike[],
    opts: w.ExchangeOptions = {},
  ): Promise<Token> {
    if (opts.subjectDpopKey !== undefined && opts.subjectTokenDpop !== undefined) {
      throw new AttenuoError("pass subjectDpopKey or subjectTokenDpop, not both");
    }
    const body = w.exchangeBody(subjectToken, actor, capabilities, opts);
    const subjectKey = await DpopKey.of(opts.subjectDpopKey);
    const headers = async (nonce?: string): Promise<Record<string, string>> => {
      const { header, signOff } = await exchangeProofs(
        `${this.serverUrl}/token`,
        String(body.subject_token),
        await this.dpopKey(),
        subjectKey,
        actor,
        nonce,
      );
      const given = signOff ?? opts.subjectTokenDpop;
      if (given !== undefined) body.subject_token_dpop = given;
      return header === undefined ? {} : { dpop: header };
    };
    return w.tokenFromResponse(await w.jsonBody(await this.post("/token", headers, body)));
  }

  /** Extend the lease of the token's last hop (`POST /token/renew`). */
  async renew(token?: Token | string): Promise<w.Lease> {
    const res = await this.post(
      "/token/renew",
      this.auth(bearer(token, this.token), "/token/renew"),
    );
    return w.leaseFromResponse(await w.jsonBody(res));
  }

  private async rpc(
    token: Token | string | undefined,
    server: string,
    method: string,
    params: Record<string, unknown>,
    sessionId?: string,
  ): Promise<{ result: Record<string, unknown>; decisionId?: string; response: Response }> {
    const path = `/mcp/${encodeURIComponent(server)}`;
    const jwt = bearer(token, this.token);
    const headers = mcpHeaders(jwt, sessionId, { contentHeaders: true });
    delete headers.Authorization; // replaced by `auth` (lowercase), with a proof when keyed
    const auth = this.auth(jwt, path);
    const res = await this.post(
      path,
      async (nonce) => ({ ...headers, ...(await auth(nonce)) }),
      w.rpcRequest(method, params, this.nextId++),
    );
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
      clientInfo: { name: opts.clientName ?? "attenuo-typescript", version: "0" },
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
    const res = await this.post(
      "/access/v1/evaluation",
      this.auth(bearer(token, this.token), "/access/v1/evaluation"),
      w.authzenBody(server, tool, args),
    );
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

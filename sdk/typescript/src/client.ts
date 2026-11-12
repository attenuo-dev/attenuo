/**
 * Client for the attenuo server. It mirrors what the `attenuo` CLI does over HTTP:
 * `POST /token`, `POST /token/renew`, `POST /mcp/{server}`, `POST /access/v1/evaluation` (and
 * `/evaluations`), `GET` and `POST /approvals/{id}` and `DELETE /mcp/{server}`.
 */

import type { CapabilityLike } from "./capability.js";
import {
  DpopKey,
  NonceCache,
  exchangeProofs,
  presented,
  resendOnce,
  type DpopKeyLike,
} from "./dpop.js";
import { META_APPROVAL_KEY } from "./approval.js";
import {
  ApprovalNotGrantedError,
  ApprovalRequiredError,
  AttenuoError,
  TransportTimeoutError,
} from "./errors.js";
import { Http, type HttpOptions } from "./http.js";
import { bearer, decodeToken, verifyToken, type Jwks, type Token } from "./token.js";
import { mcpHeaders } from "./mcp.js";
import { DEFAULT_MAX_EVENT_BYTES, callStream, type StreamEvent } from "./sse.js";
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

/** Options of `callTool`. */
export interface CallToolOptions extends McpOptions {
  /**
   * A signed approval token (from a granted `Approval`), sent in
   * `params._meta["dev.attenuo/approval"]`; the proxy removes it before the upstream.
   */
  approvalToken?: string;
}

/** Options of `callToolStream`. */
export interface CallToolStreamOptions extends CallToolOptions {
  /**
   * Refuse an SSE event (or a plain JSON answer) larger than this many bytes (default 16 MiB,
   * the proxy's `max_upstream_body_bytes` default).
   */
  maxEventBytes?: number;
  /** Abort the call and the stream. */
  signal?: AbortSignal;
  /**
   * A total deadline for the whole call in milliseconds, counted from the request's start
   * (default none). The idle `timeoutMs` restarts on every read, so an upstream that sends only
   * keep-alive comments would hold the stream open forever without it (SR-82). On expiry the
   * request is aborted and the stream throws `TransportTimeoutError`. At most 2147483647
   * (`setTimeout`'s limit).
   */
  deadlineMs?: number;
}

/** The longest delay `setTimeout` honours; a longer one fires at once. */
const MAX_TIMER_MS = 2_147_483_647;

export interface ApprovalWaitOptions {
  /** Give up after this many milliseconds (default: wait until the approval expires). */
  timeoutMs?: number;
  /** Milliseconds between polls (default 2000). */
  intervalMs?: number;
}

export interface CallWithApprovalOptions extends McpOptions, ApprovalWaitOptions {
  /** Called once with the `-32008` error, to show the user the approval id. */
  onApproval?: (e: ApprovalRequiredError) => void | Promise<void>;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * `value` as one percent-encoded URL path segment; `.` and `..` are refused because URL
 * normalization removes them even when encoded (SR-31).
 */
function pathSegment(value: string, what: string): string {
  if (value === "" || value === "." || value === "..") {
    throw new TypeError(`${what} must be a non-empty name, got ${JSON.stringify(value)}`);
  }
  return encodeURIComponent(value);
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
  private auth(
    jwt: string,
    path: string,
    method = "POST",
  ): (nonce?: string) => Promise<Record<string, string>> {
    return async (nonce) =>
      presented(jwt, await this.dpopKey(), method, `${this.serverUrl}${path}`, nonce);
  }

  /** `POST path` with `headers(nonce)`; once more with the server's new nonce on `use_dpop_nonce`. */
  private async post(
    path: string,
    headers: (nonce?: string) => Promise<Record<string, string>>,
    json?: unknown,
    method = "POST",
    signal?: AbortSignal,
  ): Promise<Response> {
    const send = (h: Record<string, string>) =>
      this.http.request(method, path, { headers: h, json, ...(signal ? { signal } : {}) });
    let res = await send(await headers(this.nonce.value));
    if ((await this.dpopKey()) !== undefined && (await this.nonce.update(res))) {
      await res.body?.cancel();
      const h = await headers(this.nonce.value);
      res = await resendOnce(() => send(h));
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
    opts: CallToolOptions = {},
  ): Promise<w.ToolResult> {
    const params: Record<string, unknown> = { name: tool, arguments: args };
    if (opts.approvalToken) params._meta = { [META_APPROVAL_KEY]: opts.approvalToken };
    const { result, decisionId } = await this.rpc(
      token,
      server,
      "tools/call",
      params,
      opts.sessionId,
    );
    return w.toolResult(result, decisionId);
  }

  /**
   * `tools/call` with the answer read as it streams: an `AsyncIterable` of `StreamEvent`, one per
   * JSON-RPC message (progress and other notifications as they arrive, then the response, whose
   * event has `result` set).
   *
   * The request is the one `callTool` sends, and it goes out when iteration starts. A denial
   * throws `DeniedError` before anything is yielded; a stream the proxy cuts because the lease
   * was revoked or expired, or the token expired, throws `DeniedError` with that `reason` and the
   * `decisionId` of the proxy's `stream.end` record; any other JSON-RPC error throws what
   * `callTool` throws. A plain JSON answer is yielded as the one final event. An event over
   * `maxEventBytes` throws `AttenuoError`. The client's `timeoutMs` applies between reads, so a
   * stream quiet for longer is aborted with a `TransportTimeoutError`; leaving the loop early
   * closes the connection. `deadlineMs` bounds the whole call, keep-alives included: on expiry it
   * throws `TransportTimeoutError`. An abort through `signal` is thrown as it came.
   */
  callToolStream(
    token: Token | string | undefined,
    server: string,
    tool: string,
    args: Record<string, unknown> = {},
    opts: CallToolStreamOptions = {},
  ): AsyncIterable<StreamEvent> {
    const path = `/mcp/${encodeURIComponent(server)}`;
    const jwt = bearer(token, this.token);
    const maxEventBytes = opts.maxEventBytes ?? DEFAULT_MAX_EVENT_BYTES;
    if (!(maxEventBytes > 0)) throw new TypeError("maxEventBytes must be positive");
    const deadlineMs = opts.deadlineMs;
    if (deadlineMs !== undefined && !(deadlineMs > 0 && deadlineMs <= MAX_TIMER_MS)) {
      throw new RangeError(
        `deadlineMs must be a positive number of milliseconds up to ${MAX_TIMER_MS}`,
      );
    }
    const params: Record<string, unknown> = { name: tool, arguments: args };
    if (opts.approvalToken) params._meta = { [META_APPROVAL_KEY]: opts.approvalToken };
    const id = this.nextId++;
    return this.stream(path, jwt, w.rpcRequest("tools/call", params, id), id, maxEventBytes, opts);
  }

  private async *stream(
    path: string,
    jwt: string,
    body: Record<string, unknown>,
    id: number,
    maxEventBytes: number,
    opts: CallToolStreamOptions,
  ): AsyncGenerator<StreamEvent> {
    const headers = mcpHeaders(jwt, opts.sessionId, { contentHeaders: true });
    delete headers.Authorization; // replaced by `auth` (lowercase), with a proof when keyed
    const auth = this.auth(jwt, path);
    // One controller for the request and the body: the caller's signal, and an idle timer
    // restarted on every read (the whole-request timeout of the other calls would cut a long
    // stream).
    const ctl = new AbortController();
    const onAbort = () => ctl.abort(opts.signal?.reason);
    if (opts.signal?.aborted) onAbort();
    opts.signal?.addEventListener("abort", onAbort, { once: true });
    const ms = this.http.timeoutMs;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // The reason the idle timer aborted with, told apart from the caller's own abort by identity:
    // the client's timeout is a `TransportTimeoutError`, the caller's abort is thrown as it came.
    let idle: DOMException | undefined;
    const restart = () => {
      if (ms <= 0) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        idle = new DOMException("no data within the timeout", "TimeoutError");
        ctl.abort(idle);
      }, ms);
    };
    // The optional total deadline (SR-82): not restarted by reads, so keep-alives cannot hold
    // the stream open past it. A read that still completes after it throws too.
    const deadlineMs = opts.deadlineMs;
    let expired = false;
    const deadlineAbort = new DOMException("stream deadline elapsed", "TimeoutError");
    const deadlineError = () =>
      new TransportTimeoutError(`stream deadline of ${deadlineMs}ms elapsed`, deadlineAbort);
    const deadline =
      deadlineMs === undefined
        ? undefined
        : setTimeout(() => {
            expired = true;
            ctl.abort(deadlineAbort);
          }, deadlineMs);
    const onChunk = () => {
      if (expired) throw deadlineError();
      restart();
    };
    try {
      restart();
      const res = await this.post(
        path,
        async (nonce) => ({ ...headers, ...(await auth(nonce)) }),
        body,
        "POST",
        ctl.signal,
      );
      onChunk();
      yield* callStream(res, id, maxEventBytes, onChunk);
    } catch (e) {
      if (expired) throw deadlineError();
      if (idle !== undefined && ctl.signal.reason === idle) {
        throw new TransportTimeoutError(
          `POST ${this.serverUrl}${path}: no data within ${ms}ms`,
          idle,
        );
      }
      throw e;
    } finally {
      clearTimeout(timer);
      clearTimeout(deadline);
      opts.signal?.removeEventListener("abort", onAbort);
    }
  }

  /**
   * End an MCP session (`DELETE /mcp/{server}` with its `Mcp-Session-Id`). Resolves to `true` when
   * the upstream closed it, `false` when the upstream does not let clients close sessions (405).
   * The proxy's refusals throw what a call would (an unknown session is an `RpcError` with code
   * `-32600`).
   */
  async closeSession(
    token: Token | string | undefined,
    server: string,
    sessionId: string,
  ): Promise<boolean> {
    if (typeof sessionId !== "string" || sessionId === "") {
      throw new TypeError("sessionId must be the Mcp-Session-Id to close");
    }
    const path = `/mcp/${pathSegment(server, "server")}`;
    const auth = this.auth(bearer(token, this.token), path, "DELETE");
    const headers = { accept: w.MCP_ACCEPT, [w.SESSION_HEADER]: sessionId };
    const res = await this.post(
      path,
      async (nonce) => ({ ...headers, ...(await auth(nonce)) }),
      undefined,
      "DELETE",
    );
    return w.sessionClosed(res);
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

  /**
   * `GET /approvals/{id}` with a delegation token of the same run (DPoP signed when the client
   * has a key). Anyone else gets a 404 `ApiError`.
   */
  async getApproval(approvalId: string, token?: Token | string): Promise<w.Approval> {
    if (approvalId === "" || approvalId === "." || approvalId === "..") {
      throw new TypeError(`approvalId must be a non-empty name, got ${JSON.stringify(approvalId)}`);
    }
    const path = `/approvals/${encodeURIComponent(approvalId)}`;
    const res = await this.post(
      path,
      this.auth(bearer(token, this.token), path, "GET"),
      undefined,
      "GET",
    );
    return w.approvalFromJson(await w.jsonBody(res));
  }

  /**
   * Poll `getApproval` until the approval is granted and return it. Throws
   * `ApprovalNotGrantedError` when it is declined, expires, was already used, or `timeoutMs`
   * passes first.
   */
  async waitForApproval(
    approvalId: string,
    token?: Token | string,
    opts: ApprovalWaitOptions = {},
  ): Promise<w.Approval> {
    const interval = opts.intervalMs ?? 2000;
    const deadline = opts.timeoutMs === undefined ? undefined : Date.now() + opts.timeoutMs;
    for (;;) {
      const approval = await this.getApproval(approvalId, token);
      if (w.approvalReady(approval)) return approval;
      let pause = interval;
      if (deadline !== undefined) {
        const left = deadline - Date.now();
        if (left <= 0) throw new ApprovalNotGrantedError(approvalId, "timeout");
        pause = Math.min(interval, left);
      }
      await sleep(pause);
    }
  }

  /**
   * `callTool`; when the call needs an approval (`-32008`), call `onApproval`, wait for the
   * grant, and retry the call once: with the grant's signed approval token in `_meta` when the
   * server returned one, else identically. A second `-32008`, a decline or an expiry is thrown.
   */
  async callToolWithApproval(
    token: Token | string | undefined,
    server: string,
    tool: string,
    args: Record<string, unknown> = {},
    opts: CallWithApprovalOptions = {},
  ): Promise<w.ToolResult> {
    const mcp: McpOptions = opts.sessionId === undefined ? {} : { sessionId: opts.sessionId };
    let granted: w.Approval;
    try {
      return await this.callTool(token, server, tool, args, mcp);
    } catch (e) {
      if (!(e instanceof ApprovalRequiredError) || e.approvalId === undefined) throw e;
      await opts.onApproval?.(e);
      granted = await this.waitForApproval(e.approvalId, token, opts);
    }
    const retry: CallToolOptions =
      granted.approvalToken === undefined ? mcp : { ...mcp, approvalToken: granted.approvalToken };
    return this.callTool(token, server, tool, args, retry);
  }

  /**
   * Grant a pending approval as the run's originating user (`POST /approvals/{id}`,
   * `by = "user"`); resolves to it. `idToken` is that user's OIDC ID token, sent as a plain
   * bearer: a delegation token is refused (403 `agent_token_refused`), another user's is 403
   * `wrong_user`, and an ID token decides once (400 `invalid_grant` after). 409
   * (`approval_not_pending`, `approval_expired`, `lease_revoked`) when it cannot be decided any
   * more, 404 when it is unknown; all `ApiError` (`UnauthorizedError` for a 401).
   */
  async grantApproval(approvalId: string, idToken: string): Promise<w.Approval> {
    return this.decideApproval(approvalId, idToken, "grant");
  }

  /** Decline a pending approval as the run's originating user; errors as `grantApproval`. */
  async declineApproval(approvalId: string, idToken: string): Promise<w.Approval> {
    return this.decideApproval(approvalId, idToken, "decline");
  }

  private async decideApproval(
    approvalId: string,
    idToken: string,
    decision: "grant" | "decline",
  ): Promise<w.Approval> {
    const path = `/approvals/${pathSegment(approvalId, "approvalId")}`;
    const res = await this.http.post(path, {
      headers: w.idTokenHeaders(idToken),
      json: w.approvalDecisionBody(decision),
    });
    return w.approvalFromJson(await w.jsonBody(res));
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

  /**
   * Decide several calls in one request (`POST /access/v1/evaluations`), each decided, charged
   * and audited like `authzenEvaluate`. Resolves to one decision per call, in order; denies are
   * returned, not thrown.
   *
   * `semantic` is AuthZEN's `evaluations_semantic`: `execute_all` (the server's default),
   * `deny_on_first_deny` or `permit_on_first_permit`. A batch stopped by it answers only the
   * calls it decided, so the array can be shorter than `evaluations`. A call the server could
   * not decide is a deny whose `error` says why. More calls than `[authzen] max_batch` is an
   * `ApiError` (400 `batch_too_large`).
   */
  async authzenEvaluateBatch(
    token: Token | string | undefined,
    evaluations: readonly w.AuthzenEvaluationLike[],
    opts: { semantic?: w.EvaluationsSemantic } = {},
  ): Promise<w.AuthzenDecision[]> {
    const body = w.authzenBatchBody(evaluations, opts.semantic);
    const path = "/access/v1/evaluations";
    const res = await this.post(path, this.auth(bearer(token, this.token), path), body);
    return w.authzenBatchFromResponse(await w.jsonBody(res));
  }

  /** `GET /.well-known/authzen-configuration`: the AuthZEN discovery document. No credential is sent. */
  async authzenConfiguration(): Promise<w.AuthzenConfiguration> {
    const res = await this.http.get("/.well-known/authzen-configuration");
    return w.authzenConfigurationFromJson(await w.jsonBody(res));
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

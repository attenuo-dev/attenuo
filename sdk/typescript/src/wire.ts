/** Request building and response parsing shared by the clients. */

import { capabilitiesToJson, type CapabilityLike } from "./capability.js";
import {
  ApiError,
  ApprovalNotGrantedError,
  ApprovalRequiredError,
  AttenuoError,
  DeniedError,
  RateLimitedError,
  RpcError,
  UnauthorizedError,
  UnavailableError,
} from "./errors.js";
import type { DpopKeyLike } from "./dpop.js";
import { b64urlDecode, bearer, decodeToken, parseTime, type Token } from "./token.js";

export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
export const TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";
export const TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
/** RFC 7523 §2.2 `client_assertion_type` of a `private_key_jwt` client assertion. */
export const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const AUTHORIZATION_DETAILS_TYPE = "attenuo_capabilities";

export const CODE_UNAUTHORIZED = -32001;
export const CODE_DENIED = -32003;
export const CODE_APPROVAL_REQUIRED = -32008;
export const CODE_UNAVAILABLE = -32006;
export const CODE_TOO_MANY = -32007;
export const RETRY_AFTER_HEADER = "retry-after";
export const DECISION_ID_HEADER = "x-attenuo-decision-id";
export const SESSION_HEADER = "mcp-session-id";
export const MCP_ACCEPT = "application/json, text/event-stream";

type Json = Record<string, unknown>;

export function normalizeBase(url: string): string {
  const base = url.replace(/\/+$/, "");
  if (!/^https?:\/\//.test(base)) {
    throw new TypeError(
      `serverUrl must be the attenuo server's base URL (http://host:port), got ${JSON.stringify(url)}. ` +
        "To name an MCP upstream, pass it as the `server` argument of callTool/listTools.",
    );
  }
  return base;
}

// --- results ----------------------------------------------------------------------------------

/** Result of `renew`. */
export interface Lease {
  lease: string;
  expiresAt: Date;
  expiresIn: number;
}

/** An allowed `tools/call`. `isError` means the *tool* reported an error. */
export interface ToolResult {
  content: Array<Record<string, unknown>>;
  isError: boolean;
  decisionId: string | undefined;
  /** All text content items joined with newlines. */
  text: string;
  structuredContent: unknown;
  raw: Json;
}

export interface Tool {
  name: string;
  description: string;
  inputSchema: Json;
  raw: Json;
}

/**
 * An approval as `GET /approvals/{id}` and the `/admin/approvals` routes show it. Fields not
 * named here (`labels`, `decision_id`, `created_at`, ...) are in `raw`, among them
 * `untrusted_args` (`[{arg, seq, kind}]`, present when an argument of the call matched an
 * untrusted result of the run). `state` is `pending`, `granted`, `declined` or
 * `consumed`; `expired` is the server's view of whether `expiresAt` has passed. `usable` is true
 * for a grant that a retry of the identical call can still use. `approvalToken` is the signed
 * approval token (`attenuo-approval+jwt`) the server returns while the approval is granted and
 * unexpired, else `undefined` (see `verifyApprovalToken`).
 */
export interface Approval {
  approvalId: string;
  state: string;
  expired: boolean;
  usable: boolean;
  chainId: string;
  callHash: string;
  server: string;
  tool: string;
  arguments: Json;
  expiresAt: Date | undefined;
  approver: Json | undefined;
  consumedBy: string | undefined;
  approvalToken: string | undefined;
  raw: Json;
}

function optTime(v: unknown): Date | undefined {
  if (typeof v !== "string" || v === "") return undefined;
  try {
    return parseTime(v);
  } catch {
    return undefined;
  }
}

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function approvalFromJson(body: unknown): Approval {
  if (!isObject(body) || typeof body.approval_id !== "string") {
    throw new AttenuoError("not an approval: missing approval_id");
  }
  const call = isObject(body.call) ? body.call : {};
  const state = String(body.state ?? "");
  const expired = body.expired === true;
  return {
    approvalId: body.approval_id,
    state,
    expired,
    usable: state === "granted" && !expired,
    chainId: String(body.chain_id ?? ""),
    callHash: String(body.call_hash ?? ""),
    server: String(call.server ?? ""),
    tool: String(call.tool ?? ""),
    arguments: isObject(call.arguments) ? call.arguments : {},
    expiresAt: optTime(body.expires_at),
    approver: isObject(body.approver) ? body.approver : undefined,
    consumedBy: typeof body.consumed_by === "string" ? body.consumed_by : undefined,
    approvalToken:
      typeof body.approval_token === "string" && body.approval_token !== ""
        ? body.approval_token
        : undefined,
    raw: body,
  };
}

/**
 * True when the grant is usable, false while it is still pending; throws
 * `ApprovalNotGrantedError` when waiting longer cannot help.
 */
export function approvalReady(a: Approval): boolean {
  if (a.usable) return true;
  if (a.expired) throw new ApprovalNotGrantedError(a.approvalId, "expired");
  if (a.state === "pending") return false;
  throw new ApprovalNotGrantedError(a.approvalId, a.state || "unknown");
}

/**
 * Answer to an AuthZEN evaluation. A `false` decision is returned, never thrown.
 *
 * On `reason === "approval_required"` the fields the proxy's `-32008` carries are set too:
 * `callHash` (what an approval is bound to), and `approvalId` and `expiresAt` of the pending
 * approval. `approvalId` is absent when the server opened none: the run already has as many
 * pending approvals as it keeps (32), and a PEP that gets diagnostics sees
 * `"too many pending approvals for this run"` in `diagnostics`. The call is then simply denied
 * until an approval of the run is decided or lapses.
 */
export interface AuthzenDecision {
  decision: boolean;
  reason: string;
  decisionId: string | undefined;
  policyIds: string[];
  diagnostics: unknown[];
  approvalId?: string;
  callHash?: string;
  expiresAt?: Date;
  /** Set on a batch entry the server could not decide (it counts as a deny). */
  error?: AuthzenEntryError;
}

/**
 * Why one entry of an AuthZEN batch failed (`context.error`): the HTTP `status` and error `code` a
 * single evaluation of it would have answered (`invalid_request`, `unknown_tool`, ...) and the
 * server's `message`. The rest of the batch is decided as usual.
 */
export interface AuthzenEntryError {
  status: number;
  code: string;
  message: string;
}

/**
 * One call to decide in `authzenEvaluateBatch`: the tool `server/tool` with `args`. A
 * `[server, tool]` or `[server, tool, args]` tuple is taken too.
 */
export interface AuthzenEvaluation {
  server: string;
  tool: string;
  args?: Json;
}

export type AuthzenEvaluationLike =
  | AuthzenEvaluation
  | readonly [server: string, tool: string]
  | readonly [server: string, tool: string, args: Json | undefined];

/** AuthZEN's `evaluations_semantic` for a batch (AuthZEN 1.0 section 7.1.2.1). */
export type EvaluationsSemantic = "execute_all" | "deny_on_first_deny" | "permit_on_first_permit";

const SEMANTICS: readonly string[] = [
  "execute_all",
  "deny_on_first_deny",
  "permit_on_first_permit",
];

/**
 * The AuthZEN discovery document (`GET /.well-known/authzen-configuration`, AuthZEN 1.0 section
 * 9): the decision point's base URL and its two evaluation endpoints, as the server publishes
 * them (from `[server] public_url`).
 */
export interface AuthzenConfiguration {
  policyDecisionPoint: string;
  accessEvaluationEndpoint: string;
  accessEvaluationsEndpoint: string;
  /** `""` when the server does not publish action search. */
  searchActionEndpoint: string;
  raw: Json;
}

/**
 * One result of an AuthZEN action search: the tool `server/name` that an evaluation with the
 * same token and arguments would allow now.
 */
export interface AuthzenAction {
  name: string;
  server: string;
}

/**
 * One page of `POST /access/v1/search/action`. `nextToken` is the token of the next page,
 * undefined after the last (the server's `""`). A page can hold fewer results than its `limit`,
 * even none, while `nextToken` is set: `limit` bounds how many catalogued tools one page
 * evaluates, not how many it returns.
 */
export interface AuthzenActionPage {
  actions: AuthzenAction[];
  nextToken: string | undefined;
  raw: Json;
}

/** Paging of `authzenSearchAction`: `pageToken` is the `nextToken` of the previous page. */
export interface AuthzenSearchOptions {
  pageToken?: string;
  limit?: number;
}

// --- plain HTTP -------------------------------------------------------------------------------

/**
 * The `ApiError` (`UnauthorizedError` for a 401) for a non-success answer. `decisionId` is the
 * body's `decision_id` when `headers` carry an `X-Attenuo-Decision-Id` that vouches for it (see
 * `provenDecisionId`). A JSON-RPC error body (the proxy's 401) gives its `data.reason` and `data`.
 * The server's load refusals are `UnavailableError` (503 `temporarily_unavailable`, or the proxy's
 * `-32006`) and `RateLimitedError` (429 `rate_limited`, or the proxy's `-32007`); see `rpcRefusal`
 * for the proxy's.
 */
export function errorFromResponse(status: number, text: string, headers?: Headers): ApiError {
  let error = "http_error";
  let detail = text.trim();
  let description: string | undefined;
  let code: string | undefined;
  let claimed: unknown;
  let reason: string | undefined;
  let data: Json | undefined;
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  if (typeof body === "object" && body !== null) {
    const b = body as Json;
    if (typeof b.error === "string") {
      error = b.error;
      detail = String(b.detail ?? "");
      if (typeof b.error_description === "string") description = b.error_description;
      if (typeof b.code === "string" && b.code !== "") code = b.code;
      claimed = b.decision_id;
    } else if (typeof b.error === "object" && b.error !== null) {
      // A JSON-RPC error body (the proxy's 401).
      const e = b.error as Json;
      error = String(e.code ?? "rpc_error");
      detail = String(e.message ?? "");
      data = (typeof e.data === "object" && e.data !== null ? e.data : {}) as Json;
      claimed = data.decision_id;
      reason = typeof data.reason === "string" && data.reason !== "" ? data.reason : "unauthorized";
      code = typeof data.code === "string" && data.code !== "" ? data.code : reason;
    }
  }
  const decisionId = provenDecisionId(headers?.get(DECISION_ID_HEADER) ?? undefined, claimed);
  const b = typeof body === "object" && body !== null ? (body as Json) : undefined;
  const refusal =
    data !== undefined
      ? rpcRefusal(status, headers, (b?.error as Json).code, detail, data)
      : typeof b?.error === "string"
        ? restRefusal(status, headers, error, detail, description)
        : undefined;
  if (refusal !== undefined) return refusal;
  if (status === 401) {
    return new UnauthorizedError(
      status,
      error,
      detail,
      description,
      decisionId,
      reason,
      data,
      code,
    );
  }
  return new ApiError(status, error, detail, description, decisionId, code);
}

/**
 * `Retry-After` in whole seconds; undefined when it is missing or not a plain non-negative number
 * (an HTTP-date is not read: the server sends seconds only).
 */
export function retryAfterOf(headers?: Headers): number | undefined {
  const value = headers?.get(RETRY_AFTER_HEADER)?.trim();
  if (value === undefined || !/^[0-9]+$/.test(value)) return undefined;
  return Number(value);
}

/**
 * The server's own 503 `temporarily_unavailable` or 429 `rate_limited` answer of a REST route as
 * `UnavailableError` or `RateLimitedError`, else undefined.
 */
function restRefusal(
  status: number,
  headers: Headers | undefined,
  error: string,
  detail: string,
  description: string | undefined,
): ApiError | undefined {
  const reason = description || error;
  if (status === 503 && error === "temporarily_unavailable") {
    return new UnavailableError(reason, retryAfterOf(headers), detail);
  }
  if (status === 429 && error === "rate_limited") {
    return new RateLimitedError(reason, retryAfterOf(headers), detail);
  }
  return undefined;
}

/**
 * The proxy's own 503 `-32006` or 429 `-32007` as `UnavailableError` or `RateLimitedError`, else
 * undefined. The proxy sets `Retry-After` on these and never relays one from an upstream, so an
 * answer without it is an upstream's own error.
 */
function rpcRefusal(
  status: number,
  headers: Headers | undefined,
  code: unknown,
  message: string,
  data: Json,
): ApiError | undefined {
  if (!headers?.has(RETRY_AFTER_HEADER)) return undefined;
  const reason = typeof data.reason === "string" && data.reason !== "" ? data.reason : undefined;
  if (status === 503 && code === CODE_UNAVAILABLE) {
    return new UnavailableError(
      reason ?? "temporarily_unavailable",
      retryAfterOf(headers),
      message,
      data,
    );
  }
  if (status === 429 && code === CODE_TOO_MANY) {
    return new RateLimitedError(reason ?? "rate_limited", retryAfterOf(headers), message, data);
  }
  return undefined;
}

const RETRIED_REASONS: Record<number, string> = { 503: "overloaded", 429: "rate_limited" };

/**
 * The error of a refusal that the client's `maxRetries` may retry: 503 `overloaded` or 429
 * `rate_limited` from the server's `[limits]`, refused before any work. Undefined for any other
 * answer, `request_timeout` and every denial included. Reads a clone of the body, so `res` can
 * still be read.
 */
export async function retryableRefusal(
  res: Response,
): Promise<UnavailableError | RateLimitedError | undefined> {
  const wanted = RETRIED_REASONS[res.status];
  if (wanted === undefined) return undefined;
  const err = errorFromResponse(res.status, await res.clone().text(), res.headers);
  if (
    (err instanceof UnavailableError || err instanceof RateLimitedError) &&
    err.reason === wanted
  ) {
    return err;
  }
  return undefined;
}

/** The JSON body of a success response; throws `ApiError` otherwise. */
export async function jsonBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!res.ok) throw errorFromResponse(res.status, text, res.headers);
  try {
    return JSON.parse(text);
  } catch {
    throw new AttenuoError(`server sent non-JSON (${res.status}): ${text.slice(0, 200)}`);
  }
}

export function asObject(v: unknown, what: string): Json {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new AttenuoError(`unexpected ${what} response: ${JSON.stringify(v)?.slice(0, 200)}`);
  }
  return v as Json;
}

export interface ExchangeOptions {
  /** Requested lifetime of the new token. */
  ttlSeconds?: number;
  /**
   * The actor's `[[agents]]` secret. A hop n+1 exchange must authenticate as the actor it
   * names, so `clientSecret` is required there and `clientId` defaults to `actor`. For hop 0
   * (an IdP credential as the subject) pass both `clientId` and `clientSecret` of a
   * registered agent.
   */
  clientId?: string;
  clientSecret?: string;
  /**
   * Defaults to the JWT type for a delegation token, or an OIDC ID token when the subject is
   * not a delegation token and client credentials are given.
   */
  subjectTokenType?: string;
  /**
   * RFC 8693 actor token: a workload-identity JWT (for example a SPIFFE JWT-SVID) from an
   * `[[actor_trust]]` issuer that authenticates `actor` instead of (or as well as) a client
   * secret. Sent with `actor_token_type` `urn:ietf:params:oauth:token-type:jwt`. Each actor
   * token authenticates one exchange.
   */
  actorToken?: string;
  /**
   * A `private_key_jwt` client assertion (RFC 7523 §2.2) instead of `clientSecret`, for an
   * agent whose `[[agents]]` entry lists public keys (`jwks`). Make one per request with
   * `DpopKey.clientAssertion(agentId, serverIssuer)` from the agent's private key. Sent with
   * `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`; never
   * together with a client secret. The `use_dpop_nonce` retry and the `maxRetries` retry of a load
   * refusal send the same assertion again, which the server allows because those refusals leave
   * it unused; the load retry is not made when its wait would reach the assertion's `exp`, and the
   * `RateLimitedError` (or `UnavailableError`) is thrown instead. Then mint a new assertion and
   * call again, or mint it with a `lifetime` that covers the waits (at most the server's
   * `client_assertion_max_lifetime_seconds`, 300 by default). Treat an assertion as spent after
   * any other answer.
   */
  clientAssertion?: string;
  /** RFC 8693 §4.4 `may_act` for the new token: the agents allowed to exchange it next. */
  mayAct?: readonly string[];
  /**
   * The key `subjectToken` is bound to (DPoP), when the new token is bound to another key and
   * this process holds both keys: the sign-off (see `DpopKey.signOff`) is made here.
   */
  subjectDpopKey?: DpopKeyLike;
  /**
   * A ready-made `subject_token_dpop` sign-off from the parent's holder (`DpopKey.signOff`),
   * naming this client's key and `actor`. Use it instead of `subjectDpopKey` so the parent's key
   * never leaves the parent's process.
   */
  subjectTokenDpop?: string;
}

export function exchangeBody(
  subjectToken: Token | string,
  actor: string,
  capabilities: CapabilityLike | readonly CapabilityLike[],
  opts: ExchangeOptions,
): Json {
  if (opts.clientAssertion !== undefined && opts.clientAssertion.trim() === "") {
    throw new TypeError("clientAssertion is empty");
  }
  if (opts.clientAssertion !== undefined && opts.clientSecret) {
    // RFC 6749 §2.3: one client authentication method per request.
    throw new TypeError("use clientSecret or clientAssertion, not both");
  }
  if (opts.clientId !== undefined && !opts.clientSecret && opts.clientAssertion === undefined) {
    throw new TypeError("clientId goes with clientSecret or clientAssertion");
  }
  if (opts.actorToken !== undefined && opts.actorToken.trim() === "") {
    throw new TypeError("actorToken is empty");
  }
  const mayAct = opts.mayAct === undefined ? undefined : mayActJson(opts.mayAct);
  // A hop n+1 exchange authenticates as its actor.
  const clientId = opts.clientSecret && opts.clientId === undefined ? actor : opts.clientId;
  // Agent credentials (a client secret or an actor token) alone do not make this hop 0: the
  // server also requires them, as the actor's, on a hop n+1 exchange. Hop 0 is an IdP
  // credential, not a delegation token.
  const authenticated =
    Boolean(opts.clientSecret) ||
    opts.actorToken !== undefined ||
    opts.clientAssertion !== undefined;
  const intake = authenticated && !isDelegationToken(subjectToken);
  const body: Json = {
    grant_type: TOKEN_EXCHANGE_GRANT,
    subject_token: bearer(subjectToken),
    subject_token_type: opts.subjectTokenType ?? (intake ? TYPE_ID_TOKEN : TYPE_JWT),
    actor,
    authorization_details: [
      { type: AUTHORIZATION_DETAILS_TYPE, capabilities: capabilitiesToJson(capabilities) },
    ],
  };
  if (opts.ttlSeconds !== undefined) body.requested_ttl_seconds = Math.trunc(opts.ttlSeconds);
  if (opts.clientSecret) {
    body.client_id = clientId;
    body.client_secret = opts.clientSecret;
  }
  if (opts.clientAssertion !== undefined) {
    // The server reads the client id from the assertion's `sub`.
    if (opts.clientId !== undefined) body.client_id = opts.clientId;
    body.client_assertion_type = CLIENT_ASSERTION_TYPE;
    body.client_assertion = opts.clientAssertion.trim();
  }
  if (opts.actorToken !== undefined) {
    body.actor_token = opts.actorToken.trim();
    body.actor_token_type = TYPE_JWT;
  }
  if (mayAct !== undefined) body.may_act = mayAct;
  return body;
}

/**
 * The `exp` (Unix seconds) of the `client_assertion` in a `POST /token` `body`, read without
 * verifying anything; undefined when the body has none or its `exp` cannot be read.
 *
 * A load refusal (429 `rate_limited`, 503 `overloaded`) leaves the assertion unspent, so the
 * retry may send it again, but only before it expires: the client's retry does not wait past
 * this time.
 */
export function assertionExpiry(body: Json): number | undefined {
  const assertion: unknown = body.client_assertion;
  if (typeof assertion !== "string") return undefined;
  const parts = assertion.split(".");
  if (parts.length !== 3) return undefined;
  let claims: unknown;
  try {
    claims = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]!)));
  } catch {
    return undefined;
  }
  if (typeof claims !== "object" || claims === null || Array.isArray(claims)) return undefined;
  const exp = (claims as { exp?: unknown }).exp;
  return typeof exp === "number" && Number.isFinite(exp) ? Math.trunc(exp) : undefined;
}

/** The RFC 8693 §4.4 `may_act` claim for a list of agent ids. */
export function mayActJson(mayAct: readonly string[]): { sub: string[] } {
  if (typeof mayAct === "string") {
    throw new TypeError("mayAct is a list of agent ids, not a string");
  }
  const sub = [...mayAct];
  if (!sub.every((a) => typeof a === "string" && a !== "")) {
    throw new TypeError("mayAct agent ids must be non-empty strings");
  }
  return { sub };
}

/** Does `token` decode as an attenuo delegation token? Nothing is verified. */
export function isDelegationToken(token: Token | string): boolean {
  if (typeof token !== "string") return true;
  try {
    decodeToken(token);
  } catch {
    return false;
  }
  return true;
}

export function tokenFromResponse(body: unknown): Token {
  if (
    typeof body !== "object" ||
    body === null ||
    typeof (body as Json).access_token !== "string"
  ) {
    throw new AttenuoError(`unexpected token response: ${JSON.stringify(body)?.slice(0, 200)}`);
  }
  const b = body as Json;
  return decodeToken(b.access_token as string, typeof b.lease === "string" ? b.lease : undefined);
}

export function leaseFromResponse(body: unknown): Lease {
  const b = asObject(body, "renew");
  return {
    lease: String(b.lease),
    expiresAt: parseTime(String(b.expires_at)),
    expiresIn: Number(b.expires_in),
  };
}

export function authzenBody(server: string, tool: string, args?: Json): Json {
  // The server fills an empty subject id from the verified chain.
  return {
    subject: { type: "agent", id: "" },
    action: { name: tool, properties: { server } },
    resource: { type: "tool", id: `${server}/${tool}` },
    context: { input: args ?? {} },
  };
}

export function authzenFromResponse(body: unknown): AuthzenDecision {
  const b = asObject(body, "AuthZEN");
  const ctx = (typeof b.context === "object" && b.context !== null ? b.context : {}) as Json;
  const d: AuthzenDecision = {
    decision: b.decision === true,
    reason: String(ctx.reason ?? ""),
    decisionId: typeof ctx.decision_id === "string" ? ctx.decision_id : undefined,
    policyIds: Array.isArray(ctx.policy_ids) ? (ctx.policy_ids as string[]) : [],
    diagnostics: Array.isArray(ctx.diagnostics) ? ctx.diagnostics : [],
  };
  if (typeof ctx.approval_id === "string" && ctx.approval_id !== "") d.approvalId = ctx.approval_id;
  if (typeof ctx.call_hash === "string" && ctx.call_hash !== "") d.callHash = ctx.call_hash;
  const expiresAt = optTime(ctx.expires_at);
  if (expiresAt !== undefined) d.expiresAt = expiresAt;
  const error = entryError(ctx.error);
  if (error !== undefined) d.error = error;
  return d;
}

/**
 * The `POST /access/v1/evaluations` body: the subject as the top-level default (the server fills
 * it from the verified chain) and one `action`/`resource`/`context` entry per call. A
 * `TypeError` for no call (the server answers an empty batch as a single evaluation) or an
 * unknown `semantic`.
 */
export function authzenBatchBody(
  evaluations: readonly AuthzenEvaluationLike[],
  semantic?: EvaluationsSemantic,
): Json {
  const entries = evaluations.map((ev) => {
    const one: AuthzenEvaluation = Array.isArray(ev)
      ? { server: ev[0] as string, tool: ev[1] as string, args: ev[2] as Json | undefined }
      : (ev as AuthzenEvaluation);
    if (typeof one?.server !== "string" || typeof one.tool !== "string") {
      throw new TypeError(`an evaluation is {server, tool, args?} or a tuple, got ${String(ev)}`);
    }
    const body = authzenBody(one.server, one.tool, one.args);
    delete body.subject;
    return body;
  });
  if (entries.length === 0) throw new TypeError("an AuthZEN batch needs at least one evaluation");
  const body: Json = { subject: { type: "agent", id: "" }, evaluations: entries };
  if (semantic !== undefined) {
    if (!SEMANTICS.includes(semantic)) {
      throw new TypeError(`semantic must be one of ${SEMANTICS.join(", ")}, got ${semantic}`);
    }
    body.options = { evaluations_semantic: semantic };
  }
  return body;
}

/**
 * The decisions of a batch answer, in request order. A batch stopped by its semantic answers
 * fewer entries than it asked.
 */
export function authzenBatchFromResponse(body: unknown): AuthzenDecision[] {
  const items = asObject(body, "AuthZEN batch").evaluations;
  if (!Array.isArray(items)) {
    throw new AttenuoError(
      `unexpected AuthZEN batch response: ${JSON.stringify(body)?.slice(0, 200)}`,
    );
  }
  return items.map((item) =>
    authzenFromResponse(
      typeof item === "object" && item !== null && !Array.isArray(item) ? item : {},
    ),
  );
}

export function authzenConfigurationFromJson(body: unknown): AuthzenConfiguration {
  const b = asObject(body, "AuthZEN configuration");
  return {
    policyDecisionPoint: String(b.policy_decision_point ?? ""),
    accessEvaluationEndpoint: String(b.access_evaluation_endpoint ?? ""),
    accessEvaluationsEndpoint: String(b.access_evaluations_endpoint ?? ""),
    searchActionEndpoint: String(b.search_action_endpoint ?? ""),
    raw: b,
  };
}

/**
 * The `POST /access/v1/search/action` body: the subject (filled in by the server from the
 * verified chain), the MCP `server` as the resource, the arguments every candidate is decided
 * with, and `page` when a token or limit is given.
 */
export function authzenSearchActionBody(
  server: string,
  args?: Json,
  opts: AuthzenSearchOptions = {},
): Json {
  const body: Json = {
    subject: { type: "agent", id: "" },
    resource: { type: "mcp_server", id: server },
    context: { input: args ?? {} },
  };
  const page: Json = {};
  if (opts.pageToken !== undefined && opts.pageToken !== "") page.token = opts.pageToken;
  if (opts.limit !== undefined) page.limit = opts.limit;
  if (Object.keys(page).length > 0) body.page = page;
  return body;
}

export function authzenSearchActionFromResponse(body: unknown): AuthzenActionPage {
  const b = asObject(body, "AuthZEN action search");
  if (!Array.isArray(b.results)) {
    throw new AttenuoError(
      `unexpected AuthZEN action search response: ${JSON.stringify(body)?.slice(0, 200)}`,
    );
  }
  const actions = b.results.map((item: unknown): AuthzenAction => {
    const r = item as Json | null;
    if (typeof r !== "object" || r === null || typeof r.name !== "string") {
      throw new AttenuoError(
        `unexpected AuthZEN action search result: ${JSON.stringify(item)?.slice(0, 200)}`,
      );
    }
    const props = r.properties as Json | null | undefined;
    const server = typeof props === "object" && props !== null ? props.server : undefined;
    return { name: r.name, server: typeof server === "string" ? server : "" };
  });
  const page = b.page as Json | null | undefined;
  const token = typeof page === "object" && page !== null ? page.next_token : undefined;
  return {
    actions,
    nextToken: typeof token === "string" && token !== "" ? token : undefined,
    raw: b,
  };
}

function entryError(v: unknown): AuthzenEntryError | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const e = v as Json;
  return {
    status: typeof e.status === "number" && Number.isInteger(e.status) ? e.status : 0,
    code: String(e.code ?? ""),
    message: String(e.message ?? ""),
  };
}

/** The body of `POST /approvals/{id}`; a `TypeError` for anything but `grant` or `decline`. */
export function approvalDecisionBody(decision: string): Json {
  if (decision !== "grant" && decision !== "decline") {
    throw new TypeError(`decision must be "grant" or "decline", got ${JSON.stringify(decision)}`);
  }
  return { decision };
}

/**
 * `Authorization: Bearer` for the user's OIDC ID token. Never DPoP: the server verifies the ID
 * token as at hop 0, and refuses a delegation token there (`agent_token_refused`).
 */
export function idTokenHeaders(idToken: string): Record<string, string> {
  const token = typeof idToken === "string" ? idToken.trim() : "";
  if (token === "") throw new TypeError("idToken must be the user's OIDC ID token");
  return { authorization: `Bearer ${token}` };
}

/**
 * The answer to `DELETE /mcp/{server}`: `true` when the upstream closed the session, `false` when
 * it does not let clients close sessions (405, as MCP allows). The proxy's own refusals throw
 * what a call would (`rpcResult`).
 */
export async function sessionClosed(res: Response): Promise<boolean> {
  if (res.ok) {
    await res.body?.cancel();
    return true;
  }
  if (res.status === 405) {
    await res.body?.cancel();
    return false;
  }
  const sse = (res.headers.get("content-type") ?? "").includes("event-stream");
  const text = await res.text();
  rpcMessageResult(res, parseRpcBody(text, sse), text);
  throw errorFromResponse(res.status, text, res.headers);
}

// --- MCP / JSON-RPC ---------------------------------------------------------------------------

export function rpcRequest(method: string, params: Json, id: number): Json {
  return { jsonrpc: "2.0", id, method, params };
}

/** The JSON-RPC response in a plain JSON or `text/event-stream` body. */
export function parseRpcBody(text: string, sse: boolean): Json | undefined {
  const asMessage = (s: string): Json | undefined => {
    try {
      const v: unknown = JSON.parse(s);
      return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : undefined;
    } catch {
      return undefined;
    }
  };
  if (!sse) return asMessage(text);
  // An SSE event's data may span several `data:` lines; events are separated by blank lines.
  for (const block of text.replace(/\r\n/g, "\n").split("\n\n")) {
    const data = block
      .split("\n")
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).replace(/^ /, ""))
      .join("\n");
    if (!data.trim()) continue;
    const v = asMessage(data);
    if (v && ("result" in v || "error" in v)) return v;
  }
  return undefined;
}

/**
 * `claimed` when it is one of the ids in the `X-Attenuo-Decision-Id` header value, else
 * `undefined` (SR-32). The server and the proxy set that header (comma separated, request order)
 * on every response that carries their decisions, and the proxy forwards no such header from an
 * upstream; an upstream is untrusted and can put any error, and any `decision_id`, in its own
 * body, so an id counts only when the header names it too.
 */
function provenDecisionId(headerValue: string | undefined, claimed: unknown): string | undefined {
  if (typeof claimed !== "string" || claimed === "" || !headerValue) return undefined;
  return headerValue.split(",").some((p) => p.trim() === claimed) ? claimed : undefined;
}

/** The decision id of a `-32003` or `-32008` the proxy produced (`provenDecisionId`). */
function proxyDecisionId(headerValue: string | undefined, data: Json): string | undefined {
  return provenDecisionId(headerValue, data.decision_id);
}

/**
 * The `result` of a JSON-RPC response, or the right error. Denials (`-32003` that the proxy
 * vouches for with `X-Attenuo-Decision-Id`) throw `DeniedError`; a `-32003` without that proof
 * is an upstream's own error and throws `RpcError`. A `-32008` with the same proof throws
 * `ApprovalRequiredError`. `-32001` or HTTP 401 throws `UnauthorizedError` with the error's
 * `data.reason` as `reason` and, when the header vouches for it, its `data.decision_id`. HTTP 503
 * with `-32006` throws `UnavailableError` and HTTP 429 with `-32007` `RateLimitedError`, when the
 * answer carries `Retry-After`; any other JSON-RPC error throws `RpcError`.
 */
export async function rpcResult(res: Response): Promise<{ result: Json; decisionId?: string }> {
  const sse = (res.headers.get("content-type") ?? "").includes("event-stream");
  const text = await res.text();
  return rpcMessageResult(res, parseRpcBody(text, sse), text);
}

/**
 * `rpcResult` for a response message already parsed (`msg`, undefined when the body held none)
 * from `text`; only the status and headers of `res` are used, never its body.
 */
export function rpcMessageResult(
  res: Response,
  msg: Json | undefined,
  text: string,
): { result: Json; decisionId?: string } {
  const headerId = res.headers.get(DECISION_ID_HEADER) ?? undefined;
  if (!msg) {
    if (res.ok) throw new AttenuoError(`no JSON-RPC response in body: ${text.slice(0, 200)}`);
    throw errorFromResponse(res.status, text, res.headers);
  }
  const err = msg.error;
  if (typeof err === "object" && err !== null) {
    const e = err as Json;
    const data = (typeof e.data === "object" && e.data !== null ? e.data : {}) as Json;
    const message = String(e.message ?? "");
    if (e.code === CODE_DENIED) {
      const id = proxyDecisionId(headerId, data);
      if (id !== undefined) {
        throw new DeniedError(String(data.reason ?? "unknown"), id, message, data);
      }
    }
    if (e.code === CODE_APPROVAL_REQUIRED) {
      const id = proxyDecisionId(headerId, data);
      if (id !== undefined) {
        const approvalId =
          typeof data.approval_id === "string" && data.approval_id !== ""
            ? data.approval_id
            : undefined;
        const callHash = typeof data.call_hash === "string" ? data.call_hash : undefined;
        throw new ApprovalRequiredError(
          id,
          approvalId,
          optTime(data.expires_at),
          callHash,
          message,
          data,
        );
      }
    }
    if (e.code === CODE_UNAUTHORIZED || res.status === 401) {
      // Only the proxy answers with HTTP 401. A `-32001` inside a 200 answer can be an upstream's
      // own error, so its `data.reason` is not taken as the server's word.
      const reason =
        res.status === 401 && typeof data.reason === "string" && data.reason !== ""
          ? data.reason
          : "";
      throw new UnauthorizedError(
        401,
        "unauthorized",
        message,
        undefined,
        proxyDecisionId(headerId, data),
        reason || "unauthorized",
        data,
      );
    }
    const refusal = rpcRefusal(res.status, res.headers, e.code, message, data);
    if (refusal !== undefined) throw refusal;
    throw new RpcError(typeof e.code === "number" ? e.code : 0, message, e.data);
  }
  if (!res.ok) throw errorFromResponse(res.status, text, res.headers);
  const result = msg.result;
  const r =
    typeof result === "object" && result !== null && !Array.isArray(result) ? (result as Json) : {};
  return headerId === undefined ? { result: r } : { result: r, decisionId: headerId };
}

export function toolResult(result: Json, decisionId: string | undefined): ToolResult {
  const content = (Array.isArray(result.content) ? result.content : []).filter(
    (c): c is Record<string, unknown> => typeof c === "object" && c !== null,
  );
  return {
    content,
    isError: result.isError === true,
    decisionId,
    text: content
      .filter((c) => c.type === "text")
      .map((c) => String(c.text ?? ""))
      .join("\n"),
    structuredContent: result.structuredContent,
    raw: result,
  };
}

export function toolsFromResult(result: Json): Tool[] {
  return (Array.isArray(result.tools) ? result.tools : [])
    .filter((t): t is Json => typeof t === "object" && t !== null)
    .map((t) => ({
      name: String(t.name ?? ""),
      description: String(t.description ?? ""),
      inputSchema: (typeof t.inputSchema === "object" && t.inputSchema !== null
        ? t.inputSchema
        : {}) as Json,
      raw: t,
    }));
}

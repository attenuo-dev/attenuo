/**
 * Errors thrown by the SDK.
 *
 * `DeniedError` is a decision, not a failure: the server understood the call and said no. Branch
 * on `reason` (`capability_denied`, `policy_deny`, `lease_revoked` ...), not on the message text.
 */

import type { BudgetLimit, LimitKind } from "./admin.js";

type Json = Record<string, unknown>;

/**
 * The stable code of a JSON-RPC error's `data`: `data.code`, or for a server older than the
 * `code` member `data.reason`, else undefined (no `data` object, or neither member a non-empty
 * string).
 */
function stableCodeOf(data: unknown): string | undefined {
  if (typeof data !== "object" || data === null || Array.isArray(data)) return undefined;
  const d = data as Json;
  for (const key of ["code", "reason"]) {
    const v = d[key];
    if (typeof v === "string" && v) return v;
  }
  return undefined;
}

/** `data.code` when it is a non-empty string, else undefined. */
function dataCodeOf(data: Json | undefined): string | undefined {
  const v = data?.code;
  return typeof v === "string" && v ? v : undefined;
}

/** Base class for every error the SDK throws, transport failures included. */
export class AttenuoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The request got no answer: `fetch` failed (connection refused or dropped, DNS, TLS: a
 * `TypeError`), or one of the client's own timers ran out (`TransportTimeoutError`), before or
 * while the body was read. `cause` is the original error. An abort through a signal you passed
 * is not wrapped: it is thrown as it came (an `AbortError`, or the reason you gave), so a
 * cancellation stays a cancellation.
 */
export class TransportError extends AttenuoError {
  constructor(message: string, cause: unknown) {
    super(message);
    this.cause = cause;
  }
}

/**
 * A `TransportError` because one of the client's own timers ran out: its `timeoutMs` (a whole
 * request, or the silence between two reads of a streamed call) or a streamed call's
 * `deadlineMs`. `cause` is the `TimeoutError` `DOMException` the request was aborted with, or
 * undefined for a deadline that passed between reads. A timeout signal you passed yourself
 * (`AbortSignal.timeout`) is yours, and is thrown as it came.
 */
export class TransportTimeoutError extends TransportError {}

/** One run-limit figure pair of a per-user window: allowed calls and the summed amount. */
export interface WindowUsage {
  calls: number;
  amount: number;
}

/** The originating user's usage of a tool across all their runs this UTC hour and day. */
export interface UserWindow {
  hour: WindowUsage;
  day: WindowUsage;
}

/**
 * The run's usage of a destructive tool, or of one with an `outbound` catalog input, before the
 * refused call, as the policy saw it (`context.usage`). `userWindow` is undefined when the
 * server left it out (all its figures zero).
 */
export interface RunUsage {
  calls: number;
  amount: number;
  destinationSeen: boolean;
  userWindow?: UserWindow;
}

/**
 * An argument of the call that copies a value or span of an untrusted result of the run. `seq`
 * is the `tool_result` audit record it matched (undefined for kind `unreadable`); `kind` is
 * `leaf`, `entity`, `kgram` or `unreadable`.
 */
export interface UntrustedArg {
  arg: string;
  kind: string;
  seq?: number;
}

function obj(v: unknown): Json | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : undefined;
}

function int(v: unknown): number {
  return typeof v === "number" && Number.isInteger(v) ? v : 0;
}

/** A `BudgetLimit` from its JSON form; undefined when `v` is not an object. */
export function budgetLimitOf(v: unknown): BudgetLimit | undefined {
  const l = obj(v);
  if (!l) return undefined;
  const out: BudgetLimit = {
    hop: Number(l.hop),
    kind: String(l.kind) as LimitKind,
    used: Number(l.used),
  };
  if (typeof l.arg === "string") out.arg = l.arg;
  if (typeof l.max === "number") out.max = l.max;
  return out;
}

function windowOf(v: unknown): WindowUsage {
  const w = obj(v) ?? {};
  return { calls: int(w.calls), amount: int(w.amount) };
}

/** A `RunUsage` from the `usage` of a refusal; undefined when `v` is not an object. */
export function runUsageOf(v: unknown): RunUsage | undefined {
  const u = obj(v);
  if (!u) return undefined;
  const out: RunUsage = {
    calls: int(u.calls),
    amount: int(u.amount),
    destinationSeen: u.destination_seen === true,
  };
  const uw = obj(u.user_window);
  if (uw) out.userWindow = { hour: windowOf(uw.hour), day: windowOf(uw.day) };
  return out;
}

/** The `untrusted_args` of a refusal; entries that are not objects are skipped. */
export function untrustedArgsOf(v: unknown): UntrustedArg[] {
  if (!Array.isArray(v)) return [];
  const out: UntrustedArg[] = [];
  for (const item of v) {
    const a = obj(item);
    if (!a) continue;
    const u: UntrustedArg = { arg: String(a.arg ?? ""), kind: String(a.kind ?? "") };
    if (typeof a.seq === "number" && Number.isInteger(a.seq)) u.seq = a.seq;
    out.push(u);
  }
  return out;
}

/**
 * The server answered a non-success status, usually `{"error": ..., "code": ..., "detail": ...}`.
 * `code` is the server's stable machine-readable code (`invalid_request`, `audience_mismatch`,
 * `token_expired`, ...; the list is in the HTTP reference under "Errors"): branch on it, never on
 * `detail`, which is text for people and may change. For a server that sends no `code` it is the
 * `error_description` sub-code, or else `error`. `error` is the OAuth-style error
 * (`invalid_grant`, `unauthorized`, ...) and `description` the `error_description`, which is
 * deprecated as a machine field. `stableCode` is the same string as `code`, under the name
 * `RpcError` and `DeniedError` use, so one property reads the stable code of every error the
 * server answered with. `decisionId` is the audit record of a refusal the server recorded (a refused token exchange or
 * renewal, a proxy 401 for a lease that is no longer live). It is taken from the body only when
 * the `X-Attenuo-Decision-Id` header names the same id, the proof the proxy gives for its own
 * records (an upstream's answer it relays never carries that header).
 */
export class ApiError extends AttenuoError {
  readonly code: string;

  constructor(
    readonly status: number,
    readonly error: string,
    readonly detail: string = "",
    readonly description?: string,
    readonly decisionId?: string,
    code?: string,
  ) {
    super(`server answered ${status}: ${error}${detail ? `: ${detail}` : ""}`);
    this.code = code || description || error;
  }

  /** The server's stable code: the same string as `code`. */
  get stableCode(): string {
    return this.code;
  }
}

/**
 * HTTP 401: the bearer is missing, malformed, expired or not ours (JSON-RPC `-32001`).
 *
 * Branch on `reason`, the server's stable code: `missing_token`, `invalid_token`,
 * `token_expired`, `dpop_required`, `invalid_dpop_proof`, `use_dpop_nonce`, and from the proxy
 * also `lease_revoked`, `lease_expired` or `lease_unknown` (the token's lease is no longer live).
 * It is the proxy's `data.reason`, or for a REST route the `error` (`dpop_required` ...) or, when
 * that is the generic `unauthorized`, its `error_description`; `"unauthorized"` when the answer
 * names no reason. `error` keeps what it always held: `"unauthorized"` for every proxy 401. `data`
 * is the proxy's JSON-RPC error `data` (`{}` for a REST route). A lease refusal the proxy
 * recorded carries the record's id in `decisionId`. `code` is the stable code of the answer (see
 * `ApiError`); for a proxy 401 it equals `reason`.
 */
export class UnauthorizedError extends ApiError {
  readonly reason: string;
  readonly data: Json;

  constructor(
    status: number,
    error: string,
    detail = "",
    description?: string,
    decisionId?: string,
    reason?: string,
    data?: Json,
    code?: string,
  ) {
    let r = reason;
    if (!r) {
      r = error && error !== "unauthorized" && error !== "http_error" ? error : description;
    }
    r = r || "unauthorized";
    super(status, error, detail, description, decisionId, code || r);
    this.reason = r;
    this.data = data ?? {};
  }
}

/**
 * HTTP 503 from the server itself: it refused the request for its own load or state, not for
 * anything about the request or its token. It is not a `DeniedError`, nor an
 * `UnauthorizedError`: no decision was made, so code that catches denials does not catch it.
 *
 * `reason` is the server's stable code: on a REST route the `error_description` of its
 * `temporarily_unavailable` answer, on `/mcp/{server}` the `data.reason` of JSON-RPC `-32006`.
 * `code` (and `stableCode`) is the proxy's `data.code` when it sends one (the same string as
 * `data.reason`), else `reason`.
 * `retryAfter` is the `Retry-After` header in whole seconds, undefined when it is missing or not
 * a number. `status` is 503 and `error` is `"temporarily_unavailable"`; `data` is the proxy's
 * JSON-RPC error `data` (`{}` for a REST route).
 *
 * - `overloaded`: `[limits] max_in_flight` requests were already running. The request was
 *   refused before any work (no decision, no audit record, nothing sent upstream), so it is safe
 *   to retry after `retryAfter`. The client's `maxRetries` retries it.
 * - `request_timeout` (REST routes): no answer within `[limits] request_timeout_seconds`. The
 *   handler may have done its work (an issued token, a decision and its audit record), so it is
 *   never retried for you.
 * - Others: `jwks_unavailable`, `dpop_replay_cache_full` and, on the proxy,
 *   `session_registry_full` (the upstream answered `initialize` and the proxy then closed that
 *   session). Not retried for you.
 *
 * On `/mcp/{server}` a `-32006` counts as the proxy's own only with a `Retry-After` header,
 * which the proxy sets on its refusals and never relays from an upstream; without it, it stays
 * an `RpcError`, as an upstream's error.
 */
export class UnavailableError extends ApiError {
  readonly data: Json;

  constructor(
    readonly reason: string,
    readonly retryAfter?: number,
    detail = "",
    data?: Json,
    status = 503,
  ) {
    super(status, "temporarily_unavailable", detail, reason, undefined, dataCodeOf(data) || reason);
    this.data = data ?? {};
  }
}

/**
 * HTTP 429: the caller is over a rate limit of the server. It is not a `DeniedError`, nor an
 * `UnauthorizedError`: the token is good and no decision was made, so code that catches denials
 * does not catch it.
 *
 * `reason` is the server's stable code: `error_description` on a REST route, the `data.reason`
 * of JSON-RPC `-32007` on `/mcp/{server}`. `code` (and `stableCode`) is the proxy's `data.code`
 * when it sends one, else `reason`. `retryAfter` is the `Retry-After` header in whole
 * seconds (until the caller's minute ends), undefined when it is missing or not a number.
 * `status` is 429 and `error` is `"rate_limited"`; `data` is the proxy's JSON-RPC error `data`
 * (`{}` for a REST route).
 *
 * - `rate_limited`: `POST /token` over `[limits] token_requests_per_minute` (per agent) or
 *   `token_unauthenticated_requests_per_minute` (per address), `/mcp/{server}` over
 *   `mcp_requests_per_minute` (per run), or an AuthZEN action search over
 *   `authzen_search_requests_per_minute` (per run). The request was refused before the server
 *   did the work (no token issued, no decision, no audit record, nothing sent upstream), so it
 *   is safe to retry after `retryAfter`. The client's `maxRetries` retries it.
 * - `too_many_sessions` (proxy): the principal holds `[proxy] max_sessions_per_principal` live
 *   sessions; the upstream answered `initialize` and the proxy then closed that session. Close a
 *   session first; not retried for you.
 *
 * On `/mcp/{server}` a `-32007` counts as the proxy's own only with a `Retry-After` header (see
 * `UnavailableError`).
 */
export class RateLimitedError extends ApiError {
  readonly data: Json;

  constructor(
    readonly reason: string,
    readonly retryAfter?: number,
    detail = "",
    data?: Json,
    status = 429,
  ) {
    super(status, "rate_limited", detail, reason, undefined, dataCodeOf(data) || reason);
    this.data = data ?? {};
  }
}

/**
 * A JSON-RPC error that is not a denial (unknown upstream, upstream down, ...).
 *
 * `code` is the JSON-RPC error number (`-32004`, `-32005`, ...). `stableCode` is the server's
 * stable machine-readable code (`unknown_server`, `upstream_unreachable`, ...; the list is in the
 * HTTP reference under "Errors"): `data.code`, or `data.reason` for a server that sends no
 * `code`, else undefined. Branch on it, not on `rpcMessage`. An error the proxy relays from the
 * upstream keeps the upstream's own `data`, so its `stableCode` is whatever the upstream put
 * there, often undefined.
 */
export class RpcError extends AttenuoError {
  readonly stableCode: string | undefined;

  constructor(
    readonly code: number,
    readonly rpcMessage: string,
    readonly data?: unknown,
  ) {
    super(`JSON-RPC error ${code}: ${rpcMessage}`);
    this.stableCode = stableCodeOf(data);
  }
}

/**
 * The proxy denied a call (JSON-RPC `-32003`). `reason` is the stable code; `decisionId` is the
 * id of the audit record. `stableCode` is the stable code under the name `ApiError` and
 * `RpcError` share: `data.code`, or `data.reason` for an older server, else `reason`; for a
 * denial the server sends it is the same string as `reason`. `data` is the error's whole `data` object, and the members the server
 * adds are also typed:
 *
 * - `limit`: the run limit a `budget_exhausted` call would take past its `max`, as a
 *   `BudgetLimit` (it can be stated back to a dry run as it came); else undefined.
 * - `usage`: for a tool the catalog marks destructive or gives an `outbound` input, the run's
 *   usage before this call (with `userWindow` when a policy reads per-user windows and a figure is
 *   not zero); else undefined.
 * - `untrustedArgs`: the arguments that copy an untrusted result of the run (empty when the
 *   server sent none).
 */
export class DeniedError extends AttenuoError {
  readonly reason: string;
  readonly stableCode: string;
  readonly decisionId: string | undefined;
  readonly detail: string;
  readonly data: Json;
  readonly limit: BudgetLimit | undefined;
  readonly usage: RunUsage | undefined;
  readonly untrustedArgs: UntrustedArg[];

  constructor(reason: string, decisionId?: string, detail = "", data?: Json) {
    const message = detail || `attenuo: denied: ${reason}`;
    super(decisionId ? `${message} (decision ${decisionId})` : message);
    this.reason = reason;
    this.decisionId = decisionId;
    this.detail = message;
    this.data = data ?? {};
    this.stableCode = stableCodeOf(this.data) ?? reason;
    this.limit = budgetLimitOf(this.data.limit);
    this.usage = runUsageOf(this.data.usage);
    this.untrustedArgs = untrustedArgsOf(this.data.untrusted_args);
  }
}

/**
 * A policy held the call for an approval (JSON-RPC `-32008`). It is a `DeniedError` with
 * `reason === "approval_required"`, so code that already catches denials keeps working.
 * `approvalId` names the pending approval: show it to the user, who grants it with their own
 * sign-in (`POST /approvals/{id}`), or an operator grants it. Then retry the identical call once
 * (`waitForApproval` and `callToolWithApproval` do this). `approvalId` is undefined when the
 * server could not open an approval, among others when the run already has as many pending
 * approvals as the server keeps for one run (32; its diagnostic is
 * `"too many pending approvals for this run"`). The call is then simply denied, and
 * `callToolWithApproval` throws this error at once, without calling `onApproval`. `callHash` is
 * the RFC 8785 hash of the call the approval is bound to. `data`, `usage` and `untrustedArgs`
 * are set as on `DeniedError`.
 */
export class ApprovalRequiredError extends DeniedError {
  constructor(
    decisionId: string | undefined,
    readonly approvalId: string | undefined,
    readonly expiresAt: Date | undefined,
    readonly callHash: string | undefined,
    detail = "",
    data?: Json,
  ) {
    super("approval_required", decisionId, detail || "attenuo: approval required", data);
  }
}

/**
 * Waiting for an approval ended without a grant. `state` is `declined`, `expired` (nobody decided
 * in time), `consumed` (a retry already used the grant) or `timeout` (the wait's own `timeoutMs`
 * ran out while the approval was still pending).
 */
export class ApprovalNotGrantedError extends AttenuoError {
  constructor(
    readonly approvalId: string,
    readonly state: string,
  ) {
    super(`approval ${approvalId} was not granted: ${state}`);
  }
}

/** A token failed local verification (bad signature, expired, wrong issuer, ...). */
export class VerificationError extends AttenuoError {}

/**
 * The token refresher gave up: the token cannot be kept alive. `reason` is a stable code:
 * `lease_revoked` (revoked, or no longer known to the server), `lease_lost` (an ancestor lease
 * lapsed), `token_expired` (`exp` came before a refresh succeeded), `refused` (the server
 * permanently refused a renewal or exchange, for example `invalid_scope` or a replayed subject
 * token) or `key_mismatch` (the new token is not bound to the DPoP key of the old one). The
 * message never contains a token; `cause` is the underlying error, if any.
 */
export class RefreshError extends AttenuoError {
  constructor(
    readonly reason: string,
    message = "",
    cause?: unknown,
  ) {
    super(`token refresh failed: ${reason}${message ? `: ${message}` : ""}`);
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * Errors thrown by the SDK.
 *
 * `DeniedError` is a decision, not a failure: the server understood the call and said no. Branch
 * on `reason` (`capability_denied`, `policy_deny`, `lease_revoked` ...), not on the message text.
 */

import type { BudgetLimit, LimitKind } from "./admin.js";

type Json = Record<string, unknown>;

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
 * The server answered a non-success status, usually `{"error": ..., "detail": ...}`.
 * `decisionId` is the audit record of a refusal the server recorded (a refused token exchange or
 * renewal, a proxy 401 for a lease that is no longer live). It is taken from the body only when
 * the `X-Attenuo-Decision-Id` header names the same id, the proof the proxy gives for its own
 * records (an upstream's answer it relays never carries that header).
 */
export class ApiError extends AttenuoError {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly detail: string = "",
    readonly description?: string,
    readonly decisionId?: string,
  ) {
    super(`server answered ${status}: ${error}${detail ? `: ${detail}` : ""}`);
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
 * recorded carries the record's id in `decisionId`.
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
  ) {
    super(status, error, detail, description, decisionId);
    let r = reason;
    if (!r) {
      r = error && error !== "unauthorized" && error !== "http_error" ? error : description;
    }
    this.reason = r || "unauthorized";
    this.data = data ?? {};
  }
}

/** A JSON-RPC error that is not a denial (unknown upstream, upstream down, ...). */
export class RpcError extends AttenuoError {
  constructor(
    readonly code: number,
    readonly rpcMessage: string,
    readonly data?: unknown,
  ) {
    super(`JSON-RPC error ${code}: ${rpcMessage}`);
  }
}

/**
 * The proxy denied a call (JSON-RPC `-32003`). `reason` is the stable code; `decisionId` is the
 * id of the audit record. `data` is the error's whole `data` object, and the members the server
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

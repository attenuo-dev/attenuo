/**
 * Errors thrown by the SDK.
 *
 * `DeniedError` is a decision, not a failure: the server understood the call and said no. Branch
 * on `reason` (`capability_denied`, `policy_deny`, `lease_revoked` ...), not on the message text.
 */

/** Base class for every error the SDK throws on purpose. */
export class OnbehalfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The server answered a non-success status, usually `{"error": ..., "detail": ...}`. */
export class ApiError extends OnbehalfError {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly detail: string = "",
    readonly description?: string,
  ) {
    super(`server answered ${status}: ${error}${detail ? `: ${detail}` : ""}`);
  }
}

/** HTTP 401: the bearer is missing, malformed, expired or not ours (JSON-RPC `-32001`). */
export class UnauthorizedError extends ApiError {}

/** A JSON-RPC error that is not a denial (unknown upstream, upstream down, ...). */
export class RpcError extends OnbehalfError {
  constructor(
    readonly code: number,
    readonly rpcMessage: string,
    readonly data?: unknown,
  ) {
    super(`JSON-RPC error ${code}: ${rpcMessage}`);
  }
}

/** The proxy denied a call (JSON-RPC `-32003`). `decisionId` is the id of the audit record. */
export class DeniedError extends OnbehalfError {
  readonly reason: string;
  readonly decisionId: string | undefined;
  readonly detail: string;

  constructor(reason: string, decisionId?: string, detail = "") {
    const message = detail || `onbehalf: denied: ${reason}`;
    super(decisionId ? `${message} (decision ${decisionId})` : message);
    this.reason = reason;
    this.decisionId = decisionId;
    this.detail = message;
  }
}

/** A token failed local verification (bad signature, expired, wrong issuer, ...). */
export class VerificationError extends OnbehalfError {}

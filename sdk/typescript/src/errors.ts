/**
 * Errors thrown by the SDK.
 *
 * `DeniedError` is a decision, not a failure: the server understood the call and said no. Branch
 * on `reason` (`capability_denied`, `policy_deny`, `lease_revoked` ...), not on the message text.
 */

/** Base class for every error the SDK throws on purpose. */
export class AttenuoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The server answered a non-success status, usually `{"error": ..., "detail": ...}`. */
export class ApiError extends AttenuoError {
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
export class RpcError extends AttenuoError {
  constructor(
    readonly code: number,
    readonly rpcMessage: string,
    readonly data?: unknown,
  ) {
    super(`JSON-RPC error ${code}: ${rpcMessage}`);
  }
}

/** The proxy denied a call (JSON-RPC `-32003`). `decisionId` is the id of the audit record. */
export class DeniedError extends AttenuoError {
  readonly reason: string;
  readonly decisionId: string | undefined;
  readonly detail: string;

  constructor(reason: string, decisionId?: string, detail = "") {
    const message = detail || `attenuo: denied: ${reason}`;
    super(decisionId ? `${message} (decision ${decisionId})` : message);
    this.reason = reason;
    this.decisionId = decisionId;
    this.detail = message;
  }
}

/**
 * A policy held the call for an approval (JSON-RPC `-32008`). It is a `DeniedError` with
 * `reason === "approval_required"`, so code that already catches denials keeps working.
 * `approvalId` names the pending approval: show it to the user, who grants it with their own
 * sign-in (`POST /approvals/{id}`), or an operator grants it. Then retry the identical call once
 * (`waitForApproval` and `callToolWithApproval` do this). `approvalId` is undefined when the
 * server could not open an approval; the call is then simply denied. `callHash` is the RFC 8785
 * hash of the call the approval is bound to.
 */
export class ApprovalRequiredError extends DeniedError {
  constructor(
    decisionId: string | undefined,
    readonly approvalId: string | undefined,
    readonly expiresAt: Date | undefined,
    readonly callHash: string | undefined,
    detail = "",
  ) {
    super("approval_required", decisionId, detail || "attenuo: approval required");
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

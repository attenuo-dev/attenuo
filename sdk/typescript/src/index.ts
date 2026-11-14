/**
 * TypeScript SDK for the attenuo authorization server.
 *
 * ```ts
 * import { AdminClient, AttenuoClient, capability, prefix, DeniedError } from "@attenuo/sdk";
 *
 * const admin = new AdminClient("http://127.0.0.1:8080", "admin-token");
 * const root = await admin.mintRootDev("alice", "https://idp.example", "planner", {
 *   capabilities: "github:*",
 * }); // development only
 *
 * const ob = new AttenuoClient("http://127.0.0.1:8080");
 * const coder = await ob.exchange(root, "coder", [
 *   capability("github", "read_file", { repo: prefix("alice/") }),
 * ]);
 * try {
 *   console.log((await ob.callTool(coder, "github", "read_file", { repo: "alice/docs" })).text);
 * } catch (e) {
 *   if (e instanceof DeniedError) console.log("denied:", e.reason, e.decisionId);
 *   else throw e;
 * }
 * ```
 */

export { AdminClient } from "./admin.js";
export {
  APPROVAL_TOKEN_TYPE,
  META_APPROVAL_KEY,
  callHash,
  verifyApprovalToken,
} from "./approval.js";
export type { ApprovalClaims, ApprovalVerifyOptions } from "./approval.js";
export {
  ENTRY_HASH_VERSION,
  EXPORT_FORMAT,
  ExportError,
  GENESIS_HASH,
  SHIPPED_FORMAT,
  crossCheck,
  entryHash,
  parseShipped,
  verifyExport,
} from "./audit.js";
export type {
  BadCheckpoint,
  CheckpointFields,
  CrossCheckReport,
  ExportReport,
  ExportSource,
  ShippedLine,
  ShippedMismatch,
  VerifyExportOptions,
} from "./audit.js";
export type {
  AdminIdentity,
  ApprovalBy,
  ApprovalQuery,
  AuditCheckpoint,
  AuditEntry,
  AuditEntryDetail,
  AuditExportFilter,
  ApprovalPage,
  AuditPage,
  AuditQuery,
  BudgetLimit,
  BudgetRefund,
  CheckpointPage,
  Decision,
  EvaluationBudget,
  EvaluationLabels,
  EvaluationUsage,
  LeaseBudget,
  LeaseLimit,
  LeaseNode,
  LeaseSelector,
  LeaseState,
  LeaseStatus,
  LeaseTree,
  LeaseUsage,
  LimitKind,
  MintRootOptions,
  OperatorsReload,
  PolicyCheck,
  PolicyEvaluateOptions,
  PolicyEvaluation,
  PolicyReload,
  PolicySet,
  RevokeBySelectorOptions,
  RevokeResult,
  SelectorRevocation,
  StatedApproval,
  StatedBudget,
  StatedSession,
  StatedUsage,
  StoredCheckpoint,
  VerifyReport,
} from "./admin.js";
export {
  argLimit,
  capabilitiesToJson,
  capability,
  countedArg,
  equals,
  formatCapability,
  oneOf,
  parseCapability,
  pathPrefix,
  pathProblem,
  prefix,
  range,
  withLimits,
} from "./capability.js";
export type {
  ArgLimit,
  Capability,
  CapabilityLike,
  Constraint,
  Derive,
  Limits,
  RangeBounds,
} from "./capability.js";
export {
  accessTokenHash,
  DpopKey,
  isUseDpopNonce,
  jwkThumbprint,
  NONCE_HEADER,
  NonceCache,
  PROOF_TYPE,
  USE_DPOP_NONCE,
} from "./dpop.js";
export type { DpopKeyLike, Jwk } from "./dpop.js";
export { AttenuoClient } from "./client.js";
export type {
  ApprovalWaitOptions,
  CallToolOptions,
  CallToolStreamOptions,
  CallWithApprovalOptions,
  ClientOptions,
  InspectOptions,
  McpOptions,
} from "./client.js";
export {
  ApiError,
  ApprovalNotGrantedError,
  ApprovalRequiredError,
  DeniedError,
  AttenuoError,
  RateLimitedError,
  RefreshError,
  RpcError,
  TransportError,
  TransportTimeoutError,
  UnauthorizedError,
  UnavailableError,
  VerificationError,
} from "./errors.js";
export type { RunUsage, UntrustedArg, UserWindow, WindowUsage } from "./errors.js";
export type { FetchLike, HttpOptions } from "./http.js";
export { TokenRefresher } from "./refresh.js";
export { DEFAULT_MAX_EVENT_BYTES, SseParser } from "./sse.js";
export type { SseEvent, StreamEvent } from "./sse.js";
export type { RefresherOptions } from "./refresh.js";
export { mcpFetch, mcpHeaders, mcpUrl } from "./mcp.js";
export { decodeToken, Token, TOKEN_TYPE, verifyToken } from "./token.js";
export type { Chain, Hop, Jwks, User, VerifyOptions } from "./token.js";
export type {
  Approval,
  AuthzenAction,
  AuthzenActionPage,
  AuthzenConfiguration,
  AuthzenDecision,
  AuthzenEntryError,
  AuthzenEvaluation,
  AuthzenEvaluationLike,
  AuthzenSearchOptions,
  EvaluationsSemantic,
  ExchangeOptions,
  Lease,
  Tool,
  ToolResult,
} from "./wire.js";

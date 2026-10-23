/**
 * TypeScript SDK for the onbehalf authorization server.
 *
 * ```ts
 * import { AdminClient, OnbehalfClient, capability, prefix, DeniedError } from "@onbehalf/sdk";
 *
 * const admin = new AdminClient("http://127.0.0.1:8080", "admin-token");
 * const root = await admin.mintRootDev("alice", "https://idp.example", "planner", {
 *   capabilities: "github:*",
 * }); // development only
 *
 * const ob = new OnbehalfClient("http://127.0.0.1:8080");
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
export type {
  AuditCheckpoint,
  AuditEntry,
  AuditPage,
  LeaseStatus,
  MintRootOptions,
  PolicyReload,
  RevokeResult,
  VerifyReport,
} from "./admin.js";
export {
  capabilitiesToJson,
  capability,
  equals,
  formatCapability,
  oneOf,
  parseCapability,
  prefix,
} from "./capability.js";
export type { Capability, CapabilityLike, Constraint } from "./capability.js";
export { accessTokenHash, DpopKey, jwkThumbprint } from "./dpop.js";
export type { DpopKeyLike, Jwk } from "./dpop.js";
export { OnbehalfClient } from "./client.js";
export type { ClientOptions, InspectOptions, McpOptions } from "./client.js";
export {
  ApiError,
  DeniedError,
  OnbehalfError,
  RpcError,
  UnauthorizedError,
  VerificationError,
} from "./errors.js";
export type { FetchLike, HttpOptions } from "./http.js";
export { mcpFetch, mcpHeaders, mcpUrl } from "./mcp.js";
export { decodeToken, Token, TOKEN_TYPE, verifyToken } from "./token.js";
export type { Chain, Hop, Jwks, User, VerifyOptions } from "./token.js";
export type { AuthzenDecision, ExchangeOptions, Lease, Tool, ToolResult } from "./wire.js";

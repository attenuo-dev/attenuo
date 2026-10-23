/** Request building and response parsing shared by the clients. */

import { capabilitiesToJson, type CapabilityLike } from "./capability.js";
import { ApiError, DeniedError, OnbehalfError, RpcError, UnauthorizedError } from "./errors.js";
import { bearer, decodeToken, parseTime, type Token } from "./token.js";

export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
export const TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";
export const TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
export const AUTHORIZATION_DETAILS_TYPE = "onbehalf_capabilities";

export const CODE_UNAUTHORIZED = -32001;
export const CODE_DENIED = -32003;
export const DECISION_ID_HEADER = "x-onbehalf-decision-id";
export const SESSION_HEADER = "mcp-session-id";
export const MCP_ACCEPT = "application/json, text/event-stream";

type Json = Record<string, unknown>;

export function normalizeBase(url: string): string {
  const base = url.replace(/\/+$/, "");
  if (!/^https?:\/\//.test(base)) {
    throw new TypeError(
      `serverUrl must be the onbehalf server's base URL (http://host:port), got ${JSON.stringify(url)}. ` +
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

/** Answer to an AuthZEN evaluation. A `false` decision is returned, never thrown. */
export interface AuthzenDecision {
  decision: boolean;
  reason: string;
  decisionId: string | undefined;
  policyIds: string[];
  diagnostics: unknown[];
}

// --- plain HTTP -------------------------------------------------------------------------------

export function errorFromResponse(status: number, text: string): ApiError {
  let error = "http_error";
  let detail = text.trim();
  let description: string | undefined;
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
    } else if (typeof b.error === "object" && b.error !== null) {
      // A JSON-RPC error body (the proxy's 401).
      const e = b.error as Json;
      error = String(e.code ?? "rpc_error");
      detail = String(e.message ?? "");
    }
  }
  const Cls = status === 401 ? UnauthorizedError : ApiError;
  return new Cls(status, error, detail, description);
}

/** The JSON body of a success response; throws `ApiError` otherwise. */
export async function jsonBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!res.ok) throw errorFromResponse(res.status, text);
  try {
    return JSON.parse(text);
  } catch {
    throw new OnbehalfError(`server sent non-JSON (${res.status}): ${text.slice(0, 200)}`);
  }
}

export function asObject(v: unknown, what: string): Json {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new OnbehalfError(`unexpected ${what} response: ${JSON.stringify(v)?.slice(0, 200)}`);
  }
  return v as Json;
}

export interface ExchangeOptions {
  /** Requested lifetime of the new token. */
  ttlSeconds?: number;
  /** Hop 0 only: the registered agent's credentials, with an IdP credential as the subject. */
  clientId?: string;
  clientSecret?: string;
  /** Defaults to the JWT type, or an OIDC ID token when `clientId` is given. */
  subjectTokenType?: string;
}

export function exchangeBody(
  subjectToken: Token | string,
  actor: string,
  capabilities: CapabilityLike | readonly CapabilityLike[],
  opts: ExchangeOptions,
): Json {
  const intake = opts.clientId !== undefined || opts.clientSecret !== undefined;
  if (intake && !(opts.clientId && opts.clientSecret)) {
    throw new TypeError("clientId and clientSecret go together");
  }
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
  if (intake) {
    body.client_id = opts.clientId;
    body.client_secret = opts.clientSecret;
  }
  return body;
}

export function tokenFromResponse(body: unknown): Token {
  if (
    typeof body !== "object" ||
    body === null ||
    typeof (body as Json).access_token !== "string"
  ) {
    throw new OnbehalfError(`unexpected token response: ${JSON.stringify(body)?.slice(0, 200)}`);
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
  return {
    decision: b.decision === true,
    reason: String(ctx.reason ?? ""),
    decisionId: typeof ctx.decision_id === "string" ? ctx.decision_id : undefined,
    policyIds: Array.isArray(ctx.policy_ids) ? (ctx.policy_ids as string[]) : [],
    diagnostics: Array.isArray(ctx.diagnostics) ? ctx.diagnostics : [],
  };
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
 * The `result` of a JSON-RPC response, or the right error. Denials (`-32003`) throw
 * `DeniedError`; `-32001` or HTTP 401 throws `UnauthorizedError`; any other JSON-RPC error throws
 * `RpcError`.
 */
export async function rpcResult(res: Response): Promise<{ result: Json; decisionId?: string }> {
  const headerId = res.headers.get(DECISION_ID_HEADER) ?? undefined;
  const sse = (res.headers.get("content-type") ?? "").includes("event-stream");
  const text = await res.text();
  const msg = parseRpcBody(text, sse);
  if (!msg) {
    if (res.ok) throw new OnbehalfError(`no JSON-RPC response in body: ${text.slice(0, 200)}`);
    throw errorFromResponse(res.status, text);
  }
  const err = msg.error;
  if (typeof err === "object" && err !== null) {
    const e = err as Json;
    const data = (typeof e.data === "object" && e.data !== null ? e.data : {}) as Json;
    const message = String(e.message ?? "");
    if (e.code === CODE_DENIED) {
      const id =
        typeof data.decision_id === "string" && data.decision_id ? data.decision_id : headerId;
      throw new DeniedError(String(data.reason ?? "unknown"), id, message);
    }
    if (e.code === CODE_UNAUTHORIZED || res.status === 401) {
      throw new UnauthorizedError(401, "unauthorized", message);
    }
    throw new RpcError(typeof e.code === "number" ? e.code : 0, message, e.data);
  }
  if (!res.ok) throw errorFromResponse(res.status, text);
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

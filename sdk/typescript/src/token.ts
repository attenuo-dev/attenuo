/**
 * Delegation tokens: decoding without verification, and local Ed25519 verification.
 *
 * A delegation token is a compact JWS (`typ` `onbehalf+jwt`, `alg` `EdDSA`) whose claims carry
 * the delegation `chain`: the originating user and one hop per agent, each with its
 * capabilities, expiry and lease id. `decodeToken` reads those claims and checks nothing. Use
 * `verifyToken` (or `client.inspect(jwt, { verify: true })`) to check the signature against the
 * server's JWKS.
 */

import { type Capability } from "./capability.js";
import { OnbehalfError, VerificationError } from "./errors.js";

export const TOKEN_TYPE = "onbehalf+jwt";

export interface User {
  subject: string;
  issuer: string;
  authenticatedAt: Date;
  attributes: Record<string, unknown>;
}

export interface Hop {
  agent: string;
  capabilities: Capability[];
  issuedAt: Date;
  expiresAt: Date;
  lease: string;
}

/** Who the chain is for, and each agent that acted for them (root first). */
export interface Chain {
  user: User;
  hops: Hop[];
}

export interface Jwks {
  keys?: Array<{ kty?: string; crv?: string; kid?: string; x?: string }>;
}

/** Parse an RFC 3339 timestamp, including the 9-digit fractions the server writes. */
export function parseTime(text: string): Date {
  const t = text.trim().replace(/\.(\d+)/, (_m, d: string) => `.${d.slice(0, 3).padEnd(3, "0")}`);
  const ms = Date.parse(t);
  if (Number.isNaN(ms)) throw new OnbehalfError(`not a timestamp: ${text}`);
  return new Date(ms);
}

export function b64urlDecode(part: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(part)) throw new OnbehalfError("not base64url");
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeJsonPart(part: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
  } catch (e) {
    if (e instanceof OnbehalfError) throw e;
    throw new OnbehalfError(`JWT is not JSON: ${(e as Error).message}`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new OnbehalfError("JWT header and payload must be JSON objects");
  }
  return v as Record<string, unknown>;
}

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

function chainFromJson(obj: Json): Chain {
  const u = obj.originating_user as Json;
  const user: User = {
    subject: u.subject,
    issuer: u.issuer,
    authenticatedAt: parseTime(u.authenticated_at),
    attributes: { ...(u.attributes ?? {}) },
  };
  const hops = (obj.hops as Json[]).map((h): Hop => ({
    agent: h.agent,
    capabilities: h.capabilities as Capability[],
    issuedAt: parseTime(h.issued_at),
    expiresAt: parseTime(h.expires_at),
    lease: h.lease,
  }));
  return { user, hops };
}

/** A delegation token plus what it says. Decoded claims are untrusted unless `verified`. */
export class Token {
  /** The compact JWT. Not enumerable, so logging or serializing a `Token` does not print it. */
  declare readonly jwt: string;

  constructor(
    jwt: string,
    /** Lease of the last hop. Revoke it to stop this agent and everything delegated from it. */
    readonly lease: string,
    readonly expiresAt: Date,
    readonly chain: Chain,
    readonly claims: Record<string, unknown>,
    readonly header: Record<string, unknown>,
    /** True only when produced by `verifyToken` / `inspect(..., { verify: true })`. */
    readonly verified = false,
  ) {
    Object.defineProperty(this, "jwt", { value: jwt, enumerable: false });
  }

  /** The JWT, so `Bearer ${token}` works. */
  toString(): string {
    return this.jwt;
  }

  /** The originating user's subject. */
  get subject(): string {
    return this.chain.user.subject;
  }

  /** The agent this token was issued to (the last hop). */
  get agent(): string {
    return this.chain.hops[this.chain.hops.length - 1]!.agent;
  }

  get agents(): string[] {
    return this.chain.hops.map((h) => h.agent);
  }

  get capabilities(): Capability[] {
    return this.chain.hops[this.chain.hops.length - 1]!.capabilities;
  }

  /** Seconds until the token expires (negative once it has). */
  get expiresIn(): number {
    return (this.expiresAt.getTime() - Date.now()) / 1000;
  }
}

/** The JWT of a `Token` or a string, trimmed. */
export function bearer(token: Token | string | undefined, fallback?: Token | string): string {
  const chosen = token ?? fallback;
  if (chosen === undefined) {
    throw new TypeError("no token: pass one, or give the client a default `token` option");
  }
  return typeof chosen === "string" ? chosen.trim() : chosen.jwt;
}

/** Decode a delegation token. **Nothing is verified**: this is whatever the sender wrote. */
export function decodeToken(jwt: string, lease?: string): Token {
  const raw = jwt.trim();
  const parts = raw.split(".");
  if (parts.length !== 3) throw new OnbehalfError("not a JWT: expected three dot-separated parts");
  const header = decodeJsonPart(parts[0]!);
  const claims = decodeJsonPart(parts[1]!);
  let chain: Chain;
  let exp: Date;
  try {
    chain = chainFromJson(claims.chain as Json);
    const e = Number(claims.exp);
    if (!Number.isFinite(e)) throw new TypeError("exp");
    exp = new Date(e * 1000);
  } catch (e) {
    const what = e instanceof OnbehalfError ? e.message : (e as Error).message;
    throw new OnbehalfError(`payload is not an onbehalf delegation token (bad or missing ${what})`);
  }
  if (chain.hops.length === 0) throw new OnbehalfError("token chain has no hops");
  return new Token(
    raw,
    lease ?? chain.hops[chain.hops.length - 1]!.lease,
    exp,
    chain,
    claims,
    header,
  );
}

/** `act` nests the current agent outermost; return root first. */
function actAgents(act: unknown): string[] {
  const out: string[] = [];
  let cur = act;
  while (typeof cur === "object" && cur !== null) {
    const o = cur as Record<string, unknown>;
    out.push(String(o.sub));
    cur = o.act;
  }
  return out.reverse();
}

export interface VerifyOptions {
  issuer?: string;
  audience?: string;
  /** Seconds since the epoch; defaults to the current time. */
  now?: number;
}

/**
 * Verify `jwt` against a JWKS document and return the decoded, verified token.
 *
 * Checks: `alg` is `EdDSA`, the Ed25519 signature (key chosen by `kid` when the header has one,
 * else the first Ed25519 key), `typ`, `exp`, `iss`/`aud` (pinned when given, otherwise only
 * required to be present), and that `sub` and `act` agree with `chain`. The detached `ou_sig`
 * over the user block is not checked here; the server checks it on every request.
 */
export async function verifyToken(
  jwt: string,
  jwks: Jwks,
  opts: VerifyOptions = {},
): Promise<Token> {
  const tok = decodeToken(jwt);
  if (tok.header.alg !== "EdDSA") {
    throw new VerificationError(
      `unsupported alg ${JSON.stringify(tok.header.alg)}, expected EdDSA`,
    );
  }
  const kid = tok.header.kid;
  const keys = (jwks.keys ?? []).filter(
    (k) => k.kty === "OKP" && k.crv === "Ed25519" && (kid === undefined || k.kid === kid),
  );
  const key = keys[0];
  if (!key) {
    throw new VerificationError(
      `JWKS has no Ed25519 key${kid === undefined ? "" : ` with kid ${JSON.stringify(kid)}`}`,
    );
  }
  const [head, payload, sig] = jwt.trim().split(".") as [string, string, string];
  let ok: boolean;
  try {
    const raw = b64urlDecode(key.x ?? "");
    if (raw.length !== 32) throw new VerificationError(`JWK x is ${raw.length} bytes, expected 32`);
    const pub = await crypto.subtle.importKey("raw", raw, "Ed25519", false, ["verify"]);
    ok = await crypto.subtle.verify(
      "Ed25519",
      pub,
      b64urlDecode(sig),
      new TextEncoder().encode(`${head}.${payload}`),
    );
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    throw new VerificationError(`bad JWKS key or signature: ${(e as Error).message}`);
  }
  if (!ok) throw new VerificationError("signature does not match the server's key");

  const c = tok.claims;
  if (c.typ !== TOKEN_TYPE) {
    throw new VerificationError(`unexpected token type ${JSON.stringify(c.typ)}`);
  }
  if (Number(c.exp) <= (opts.now ?? Date.now() / 1000))
    throw new VerificationError("token expired");
  for (const [claim, want] of [
    ["iss", opts.issuer],
    ["aud", opts.audience],
  ] as const) {
    const got = c[claim];
    if (typeof got !== "string") throw new VerificationError(`missing ${claim} claim`);
    if (want !== undefined && got !== want) {
      throw new VerificationError(
        `${claim} is ${JSON.stringify(got)}, expected ${JSON.stringify(want)}`,
      );
    }
  }
  if (c.sub !== tok.chain.user.subject) {
    throw new VerificationError("sub does not match the chain's originating user");
  }
  const acted = actAgents(c.act);
  const agents = tok.agents;
  if (acted.length !== agents.length || acted.some((a, i) => a !== agents[i])) {
    throw new VerificationError("act does not match the chain's agents");
  }
  return new Token(tok.jwt, tok.lease, tok.expiresAt, tok.chain, tok.claims, tok.header, true);
}

/**
 * Signed approval tokens: offline verification for an external PEP (output labelling,
 * ADR-0009).
 *
 * When an approval is granted, the server's answer carries `approval_token`: a compact JWS with
 * header `typ` `attenuo-approval+jwt`, signed with the issuer key that signs delegation tokens
 * (same `kid`, same JWKS). Its claims bind it to one call of one hop of one run: `iss`, `aud`;
 * `sub` (the approver) and `by` (`user` or `operator`); `chain_id` and `lease` (the run and the
 * calling hop); `ch` (the call hash, {@link callHash}); `iat`, `exp`, `jti` (the approval id);
 * and `cnf.jkt` when the calling hop's token is DPoP-bound.
 *
 * An agent retries the call with the token in `params._meta["dev.attenuo/approval"]`
 * ({@link META_APPROVAL_KEY}); `AttenuoClient.callToolWithApproval` does this. The server's
 * approval record is what makes it single use: {@link verifyApprovalToken} proves the grant was
 * made, not that it has not been used.
 */

import { VerificationError } from "./errors.js";
import { canonicalize } from "./jcs.js";
import { b64urlDecode, checkEd25519Signature, type Jwks } from "./token.js";

/** Header `typ` of an approval token. */
export const APPROVAL_TOKEN_TYPE = "attenuo-approval+jwt";

/** The `params._meta` key that carries an approval token on a retried call. */
export const META_APPROVAL_KEY = "dev.attenuo/approval";

/** The verified claims of an approval token. */
export interface ApprovalClaims {
  /** `jti`. */
  approvalId: string;
  /** `sub`: the user's subject, or `urn:attenuo:admin` for an operator. */
  approver: string;
  /** `user` or `operator`. */
  by: string;
  chainId: string;
  lease: string;
  /** `ch`. */
  callHash: string;
  issuedAt: Date;
  expiresAt: Date;
  /** `cnf.jkt`, or `undefined` for a bearer hop. */
  jkt: string | undefined;
  issuer: string;
  audience: string;
  raw: Record<string, unknown>;
}

/** What {@link verifyApprovalToken} checks besides the signature, `typ` and `exp`. */
export interface ApprovalVerifyOptions {
  /** The call's delegation run. */
  chainId?: string;
  /** The calling hop's lease. */
  lease?: string;
  /** The call hash ({@link callHash}). */
  callHash?: string;
  /**
   * The calling hop's key thumbprint. `null` for a bearer hop (the token must carry no `cnf`);
   * leave it out to skip the check.
   */
  jkt?: string | null;
  issuer?: string;
  audience?: string;
  /** Seconds since the epoch (default: the clock). */
  now?: number;
}

/**
 * The hash an approval is bound to: SHA-256, hex, of the RFC 8785 canonical JSON of
 * `{server, tool, arguments}`, as the server computes it (`ToolCall::call_hash`). `_meta` is not
 * an argument and is never part of it.
 */
export async function callHash(
  server: string,
  tool: string,
  args: Record<string, unknown> = {},
): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize({ server, tool, arguments: args }));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

function decodePart(part: string, what: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
  } catch (e) {
    throw new VerificationError(`approval token ${what} is not JSON: ${(e as Error).message}`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new VerificationError(`approval token ${what} is not an object`);
  }
  return v as Record<string, unknown>;
}

function seconds(v: unknown, claim: string): Date {
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new VerificationError(`missing or non-integer ${claim} claim`);
  }
  return new Date(v * 1000);
}

/**
 * Verify an approval token offline against the issuer's JWKS and return its claims: the EdDSA
 * signature (key chosen by `kid`), header `typ`, `exp` against `now`, and each option that is
 * given. Throws `VerificationError` on any failure.
 */
export async function verifyApprovalToken(
  token: string,
  jwks: Jwks,
  opts: ApprovalVerifyOptions = {},
): Promise<ApprovalClaims> {
  const jwt = token.trim();
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new VerificationError("not a JWT: expected three dot-separated parts");
  }
  const header = decodePart(parts[0] as string, "header");
  const claims = decodePart(parts[1] as string, "payload");
  await checkEd25519Signature(jwt, header, jwks);
  if (header.typ !== APPROVAL_TOKEN_TYPE) {
    throw new VerificationError(
      `typ is ${JSON.stringify(header.typ)}, expected ${JSON.stringify(APPROVAL_TOKEN_TYPE)}`,
    );
  }
  const expiresAt = seconds(claims.exp, "exp");
  if (expiresAt.getTime() / 1000 <= (opts.now ?? Date.now() / 1000)) {
    throw new VerificationError("approval token expired");
  }
  const s: Record<string, string> = {};
  for (const claim of ["iss", "aud", "sub", "by", "chain_id", "lease", "ch", "jti"]) {
    const v = claims[claim];
    if (typeof v !== "string") throw new VerificationError(`missing ${claim} claim`);
    s[claim] = v;
  }
  const cnf = claims.cnf;
  let jkt: string | undefined;
  if (cnf !== undefined) {
    const j = typeof cnf === "object" && cnf !== null ? (cnf as { jkt?: unknown }).jkt : undefined;
    if (typeof j !== "string") throw new VerificationError("cnf has no jkt");
    jkt = j;
  }
  const checks: [string, string | undefined][] = [
    ["iss", opts.issuer],
    ["aud", opts.audience],
    ["chain_id", opts.chainId],
    ["lease", opts.lease],
    ["ch", opts.callHash],
  ];
  for (const [claim, want] of checks) {
    if (want !== undefined && s[claim] !== want) {
      throw new VerificationError(
        `${claim} is ${JSON.stringify(s[claim])}, expected ${JSON.stringify(want)}`,
      );
    }
  }
  if (opts.jkt !== undefined && (jkt ?? null) !== opts.jkt) {
    throw new VerificationError(
      `cnf.jkt is ${JSON.stringify(jkt ?? null)}, expected ${JSON.stringify(opts.jkt)}`,
    );
  }
  return {
    approvalId: s.jti as string,
    approver: s.sub as string,
    by: s.by as string,
    chainId: s.chain_id as string,
    lease: s.lease as string,
    callHash: s.ch as string,
    issuedAt: seconds(claims.iat, "iat"),
    expiresAt,
    jkt,
    issuer: s.iss as string,
    audience: s.aud as string,
    raw: claims,
  };
}

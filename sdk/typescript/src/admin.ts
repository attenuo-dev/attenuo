/**
 * Operator API: revoke leases, read and verify the audit log, reload policy, mint dev roots.
 *
 * Every route needs the static admin bearer (`[admin] token` in the server config). Keep that
 * token out of agents: it can revoke anything and read every decision.
 */

import { capabilitiesToJson, type CapabilityLike } from "./capability.js";
import { DpopKey, type DpopKeyLike } from "./dpop.js";
import { Http, type HttpOptions } from "./http.js";
import { OnbehalfError } from "./errors.js";
import type { Token } from "./token.js";
import * as w from "./wire.js";

const MAX_PAGE = 1000;

type Json = Record<string, unknown>;

export interface RevokeResult {
  leaseId: string;
  revoked: number;
  reason: string;
}

export interface LeaseStatus {
  leaseId: string;
  active: boolean;
  parent: string | undefined;
  expiresAt: string;
  revokedAt: string | undefined;
  revokeReason: string | undefined;
}

/** One row of the hash-chained audit log; `record` is the decision record. */
export interface AuditEntry {
  seq: number;
  record: Json;
  raw: Json;
  /**
   * The request proved possession of the key its token is bound to (DPoP); for an issuance, the
   * new token is bound.
   */
  dpopBound: boolean;
}

export interface AuditPage {
  entries: AuditEntry[];
  /** The `from` for the next page, or undefined at the end. */
  next: number | undefined;
  /** The newest `seq` in the log (0 for an empty log). */
  head: number;
}

/** One parsed JSON Lines object of an audit export, tagged with `type`. */
export type AuditExportLine = { type: string; [key: string]: unknown };

export interface VerifyReport {
  ok: boolean;
  entries: number;
  firstBadSeq: number | undefined;
}

export interface AuditCheckpoint {
  seq: number;
  hash: string;
  [key: string]: unknown;
}

export interface PolicyReload {
  policyIds: string[];
  warnings: string[];
}

export interface MintRootOptions {
  capabilities?: CapabilityLike | readonly CapabilityLike[];
  ttlSeconds?: number;
  attributes?: Record<string, unknown>;
  /**
   * RFC 8693 §4.4 `may_act` for the root token: the agents allowed to exchange it next. Must be
   * within the `[[root_grants]]` entry's `may_act` when that has one. `[]` means nobody may.
   */
  mayAct?: readonly string[];
  /** Bind the root token to this key (DPoP, RFC 9449): a `DpopKey` or a private JWK. */
  dpopKey?: DpopKeyLike;
}

function opt<T>(v: unknown): T | undefined {
  return v === null || v === undefined ? undefined : (v as T);
}

function headOf(page: Json): number {
  const h = page.head;
  return typeof h === "number" && Number.isInteger(h) && h >= 0 ? h : 0;
}

function entriesOf(page: Json): AuditEntry[] {
  const list = Array.isArray(page.entries) ? (page.entries as Json[]) : [];
  return list.map((e) => ({
    seq: Number(e.seq),
    record: { ...((e.record as Json | undefined) ?? {}) },
    raw: e,
    dpopBound: (e.record as Json | undefined)?.dpop_bound === true,
  }));
}

/** Operator client. `mintRootDev` needs `[dev] allow_root_mint = true` on the server. */
export class AdminClient {
  readonly serverUrl: string;
  private readonly http: Http;

  constructor(serverUrl: string, adminToken: string, opts: HttpOptions = {}) {
    this.http = new Http(serverUrl, opts, { authorization: `Bearer ${adminToken}` });
    this.serverUrl = this.http.base;
  }

  /** Revoke a lease and, by cascade, every lease delegated from it. */
  async revokeLease(leaseId: string, reason?: string): Promise<RevokeResult> {
    const res = await this.http.post(`/admin/leases/${encodeURIComponent(leaseId)}/revoke`, {
      json: reason ? { reason } : {},
    });
    const b = w.asObject(await w.jsonBody(res), "revoke");
    return { leaseId: String(b.lease_id), revoked: Number(b.revoked), reason: String(b.reason) };
  }

  async leaseStatus(leaseId: string): Promise<LeaseStatus> {
    const res = await this.http.get(`/admin/leases/${encodeURIComponent(leaseId)}`);
    const b = w.asObject(await w.jsonBody(res), "lease");
    return {
      leaseId: String(b.lease_id),
      active: b.active === true,
      parent: opt<string>(b.parent),
      expiresAt: String(b.expires_at),
      revokedAt: opt<string>(b.revoked_at),
      revokeReason: opt<string>(b.revoke_reason),
    };
  }

  /** One page of entries from `fromSeq`, and the `from` for the next page (or undefined). */
  async audit(fromSeq = 1, limit = 100): Promise<AuditPage> {
    const res = await this.http.get("/admin/audit", { query: { from: fromSeq, limit } });
    const page = w.asObject(await w.jsonBody(res), "audit");
    return { entries: entriesOf(page), next: opt<number>(page.next), head: headOf(page) };
  }

  /**
   * The newest audit `seq` (0 for an empty log), read from `head` of `GET /admin/audit`. Unlike
   * `auditCheckpoint` it signs nothing.
   */
  async auditHead(): Promise<number> {
    return (await this.audit(1, 1)).head;
  }

  /**
   * Stream `GET /admin/audit/export` as parsed JSON Lines objects: a `header`, then `entry` and
   * `checkpoint` objects, each tagged with `type`. Write the raw lines to a file and check it
   * offline with `onbehalf audit verify --file`.
   */
  async *auditExport(fromSeq = 1, toSeq?: number): AsyncGenerator<AuditExportLine> {
    const query: Record<string, number> = { from: fromSeq };
    if (toSeq !== undefined) query.to = toSeq;
    const res = await this.http.get("/admin/audit/export", { query });
    if (!res.ok) throw w.errorFromResponse(res.status, await res.text());
    const decoder = new TextDecoder();
    let buf = "";
    const emit = function* (line: string): Generator<AuditExportLine> {
      if (line.trim() === "") return;
      let v: unknown;
      try {
        v = JSON.parse(line);
      } catch {
        throw new OnbehalfError(`audit export: line is not JSON: ${line.slice(0, 200)}`);
      }
      if (typeof v !== "object" || v === null || Array.isArray(v)) {
        throw new OnbehalfError(`audit export: line is not an object: ${line.slice(0, 200)}`);
      }
      yield v as AuditExportLine;
    };
    if (res.body) {
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        buf += decoder.decode(chunk, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          yield* emit(line);
        }
      }
    }
    buf += decoder.decode();
    yield* emit(buf);
  }

  /** The last `n` audit entries, oldest first. */
  async auditTail(n = 20): Promise<AuditEntry[]> {
    const head = await this.auditHead();
    let start = Math.max(1, head + 1 - n);
    const out: AuditEntry[] = [];
    for (;;) {
      const page = await this.audit(start, MAX_PAGE);
      out.push(...page.entries);
      if (page.next === undefined) return out;
      start = page.next;
    }
  }

  /**
   * The signed checkpoint of the log head (`seq`, `head_hash`, `hash`, `at`, `kid`, `signature`).
   * Each call may create and store a signed checkpoint; use `auditHead` to just read the head.
   */
  async auditCheckpoint(): Promise<AuditCheckpoint> {
    const res = await this.http.get("/admin/audit/checkpoint");
    return w.asObject(await w.jsonBody(res), "checkpoint") as AuditCheckpoint;
  }

  /** Walk the whole hash chain. `ok` is false (not an exception) if it is broken. */
  async auditVerify(): Promise<VerifyReport> {
    const res = await this.http.get("/admin/audit/verify");
    const b = w.asObject(await w.jsonBody(res), "verify");
    return {
      ok: b.ok === true,
      entries: Number(b.entries ?? 0),
      firstBadSeq: opt<number>(b.first_bad_seq),
    };
  }

  /**
   * Re-read the policy file. A policy that does not validate throws `ApiError` (422) and the old
   * set stays in force.
   */
  async policyReload(): Promise<PolicyReload> {
    const res = await this.http.post("/admin/policies/reload", { json: {} });
    const b = w.asObject(await w.jsonBody(res), "policy reload");
    return {
      policyIds: Array.isArray(b.policy_ids) ? (b.policy_ids as string[]) : [],
      warnings: Array.isArray(b.warnings) ? (b.warnings as string[]) : [],
    };
  }

  /** **Development only.** Mint a root token for an asserted, unverified user. */
  async mintRootDev(
    subject: string,
    issuer: string,
    agent: string,
    opts: MintRootOptions = {},
  ): Promise<Token> {
    const body: Json = { subject, issuer, agent };
    if (opts.capabilities !== undefined) body.capabilities = capabilitiesToJson(opts.capabilities);
    if (opts.ttlSeconds !== undefined) body.ttl_seconds = Math.trunc(opts.ttlSeconds);
    if (opts.attributes && Object.keys(opts.attributes).length > 0)
      body.attributes = opts.attributes;
    if (opts.mayAct !== undefined) body.may_act = w.mayActJson(opts.mayAct);
    const key = await DpopKey.of(opts.dpopKey);
    const headers: Record<string, string> = key
      ? { dpop: await key.proof("POST", `${this.serverUrl}/admin/root-token`) }
      : {};
    const res = await this.http.post("/admin/root-token", { json: body, headers });
    return w.tokenFromResponse(await w.jsonBody(res));
  }
}

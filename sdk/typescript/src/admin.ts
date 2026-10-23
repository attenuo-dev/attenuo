/**
 * Operator API: revoke leases, read and verify the audit log, reload policy, mint dev roots.
 *
 * Every route needs the static admin bearer (`[admin] token` in the server config). Keep that
 * token out of agents: it can revoke anything and read every decision.
 */

import { capabilitiesToJson, type CapabilityLike } from "./capability.js";
import { DpopKey, NonceCache, type DpopKeyLike } from "./dpop.js";
import { Http, type HttpOptions } from "./http.js";
import { AttenuoError } from "./errors.js";
import { bearer, type Token } from "./token.js";
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
  /**
   * What sort of event the record is: `decision`, `exchange`, `root_token`, `lease_renew`,
   * `lease_revoke` or `admin`.
   */
  kind: string | undefined;
  /** The lease id of the delegation chain's first hop (undefined for admin records). */
  chainId: string | undefined;
}

export interface AuditPage {
  entries: AuditEntry[];
  /** The `from` for the next page, or undefined at the end. */
  next: number | undefined;
  /** With `order: "desc"`: the `before` of the next (older) page, undefined at seq 1. */
  prev?: number | undefined;
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

/**
 * Filters and paging for `auditQuery` / `auditIter`. Each filter is an exact match, never a
 * pattern; the ones you set combine with AND.
 */
export interface AuditQuery {
  /** `asc` (oldest first from `from`, the default) or `desc` (newest first, `seq < before`). */
  order?: "asc" | "desc";
  from?: number;
  before?: number;
  /** Page size (server default 100, at most 1000). */
  limit?: number;
  /** One kind or several: `decision`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin`. */
  kind?: string | readonly string[];
  /** `allow` or `deny`. */
  decision?: string;
  reason?: string;
  /** The record's `originating_subject`. */
  subject?: string;
  /** An agent among the record's `agents`. */
  agent?: string;
  /** A lease among the record's `leases`. */
  lease?: string;
  server?: string;
  tool?: string;
  chainId?: string;
  /** `at >= since`: an RFC 3339 string or a `Date`. */
  since?: string | Date;
  /** `at < until`: an RFC 3339 string or a `Date`. */
  until?: string | Date;
}

/** A lease named in an audit record, as the registry sees it now. */
export interface LeaseState {
  leaseId: string;
  /** False when the registry does not hold the lease. */
  known: boolean;
  active: boolean;
  parent: string | undefined;
  expiresAt: string | undefined;
  revokedAt: string | undefined;
  revokeReason: string | undefined;
}

/** A stored, signed checkpoint, as the server keeps it (not verified here). */
export interface StoredCheckpoint {
  seq: number;
  head_hash: string;
  at: string;
  kid: string;
  signature: string;
  [key: string]: unknown;
}

/** One audit entry with its context (`GET /admin/audit/entries/{seq}` or `/records/{id}`). */
export interface AuditEntryDetail {
  entry: AuditEntry;
  /** One per lease in the record, root first. */
  leaseStates: LeaseState[];
  /** The oldest stored checkpoint whose signature covers the entry; undefined if none yet. */
  coveredByCheckpoint: StoredCheckpoint | undefined;
  /**
   * The seq of the first policy reload after the entry. When set, the policy in force now may
   * not be the one that decided.
   */
  policyReloadedAfter: number | undefined;
}

export interface CheckpointPage {
  /** Newest first. */
  checkpoints: StoredCheckpoint[];
  /** The `before` of the next (older) page, undefined after the oldest. */
  prev: number | undefined;
}

/** One lease of a `LeaseTree`; `agent`, `issuedAt`, `issuedSeq` come from its issuance record. */
export interface LeaseNode {
  leaseId: string;
  parent: string | undefined;
  agent: string | undefined;
  active: boolean;
  expiresAt: string;
  revokedAt: string | undefined;
  revokeReason: string | undefined;
  issuedAt: string | undefined;
  issuedSeq: number | undefined;
}

/** What a revoke of the lease would reach, changing nothing. */
export interface LeaseTree {
  /** The chain's first hop (also the `chain_id` of its audit records). */
  root: string;
  /** Nearest first, ending at `root`; empty for a root lease. */
  ancestors: LeaseNode[];
  /** The lease, then its descendants breadth-first, cut short when `truncated`. */
  nodes: LeaseNode[];
  /** The `revoked` count a revoke sent now would return (whole subtree). */
  wouldRevoke: number;
  truncated: boolean;
}

/** The policy set in force. `sha256` and `loadedAt` describe the text the engine loaded. */
export interface PolicySet {
  path: string | undefined;
  sha256: string | undefined;
  loadedAt: string;
  policyIds: string[];
  warnings: string[];
  /** Policy id to its text, in the server's order. */
  policies: Record<string, string>;
}

/** The policy file on disk, linted against the running schema. */
export interface PolicyCheck {
  path: string;
  sha256: string;
  loadedSha256: string | undefined;
  differsFromLoaded: boolean;
  /** No errors: a reload would succeed. */
  ok: boolean;
  errorCount: number;
  warningCount: number;
  /** Each has `severity`, `stage`, `message` and, when known, `policy_id`, `line`, `column`. */
  issues: Json[];
  policyIds: string[];
}

/** A dry-run decision from `policyEvaluate`. */
export interface PolicyEvaluation {
  /** `allow` or `deny`. */
  decision: string;
  allowed: boolean;
  reason: string;
  policyIds: string[];
  diagnostics: unknown[];
  /** Always `skipped`. */
  leaseCheck: string;
  /** `token` or `admin_supplied`. */
  chainSource: string;
  tokenExpired: boolean;
}

export interface PolicyEvaluateOptions {
  /** A delegation token, verified by the server; an expired one is accepted and flagged. */
  token?: Token | string;
  /** A chain object instead of a token, checked only structurally. */
  chain?: Json;
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

function strOrUndef(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function entriesOf(page: Json): AuditEntry[] {
  const list = Array.isArray(page.entries) ? (page.entries as Json[]) : [];
  return list.map((e) => ({
    seq: Number(e.seq),
    record: { ...((e.record as Json | undefined) ?? {}) },
    raw: e,
    dpopBound: (e.record as Json | undefined)?.dpop_bound === true,
    kind: strOrUndef((e.record as Json | undefined)?.kind),
    chainId: strOrUndef((e.record as Json | undefined)?.chain_id),
  }));
}

const AUDIT_FILTERS = [
  ["decision", "decision"],
  ["reason", "reason"],
  ["subject", "subject"],
  ["agent", "agent"],
  ["lease", "lease"],
  ["server", "server"],
  ["tool", "tool"],
  ["chainId", "chain_id"],
] as const;

function rfc3339(v: string | Date): string {
  return typeof v === "string" ? v : v.toISOString();
}

function auditParams(q: AuditQuery): Record<string, string | number> {
  const out: Record<string, string | number> = { order: q.order ?? "asc" };
  if (q.limit !== undefined) out.limit = q.limit;
  if (q.from !== undefined) out.from = q.from;
  if (q.before !== undefined) out.before = q.before;
  for (const [key, param] of AUDIT_FILTERS) {
    const v = q[key];
    if (v !== undefined) out[param] = v;
  }
  if (q.kind !== undefined) out.kind = typeof q.kind === "string" ? q.kind : q.kind.join(",");
  if (q.since !== undefined) out.since = rfc3339(q.since);
  if (q.until !== undefined) out.until = rfc3339(q.until);
  return out;
}

function strs(v: unknown): string[] {
  return Array.isArray(v) ? (v as string[]) : [];
}

function entryDetailOf(b: Json): AuditEntryDetail {
  const [entry] = entriesOf({ entries: [w.asObject(b.entry, "audit entry")] });
  const states = Array.isArray(b.lease_states) ? (b.lease_states as Json[]) : [];
  return {
    entry: entry!,
    leaseStates: states.map((s) => ({
      leaseId: String(s.lease_id),
      known: s.known === true,
      active: s.active === true,
      parent: opt<string>(s.parent),
      expiresAt: opt<string>(s.expires_at),
      revokedAt: opt<string>(s.revoked_at),
      revokeReason: opt<string>(s.revoke_reason),
    })),
    coveredByCheckpoint: opt<StoredCheckpoint>(b.covered_by_checkpoint),
    policyReloadedAfter: opt<number>(b.policy_reloaded_after),
  };
}

function leaseNodeOf(n: Json): LeaseNode {
  return {
    leaseId: String(n.lease_id),
    parent: opt<string>(n.parent),
    agent: opt<string>(n.agent),
    active: n.active === true,
    expiresAt: String(n.expires_at),
    revokedAt: opt<string>(n.revoked_at),
    revokeReason: opt<string>(n.revoke_reason),
    issuedAt: opt<string>(n.issued_at),
    issuedSeq: opt<number>(n.issued_seq),
  };
}

function leaseNodes(v: unknown): LeaseNode[] {
  return Array.isArray(v) ? (v as Json[]).map(leaseNodeOf) : [];
}

/** Operator client. `mintRootDev` needs `[dev] allow_root_mint = true` on the server. */
export class AdminClient {
  readonly serverUrl: string;
  private readonly http: Http;
  private readonly nonce = new NonceCache();

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
   * offline with `verifyExport`.
   *
   * `filter.kind` (`decision`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`,
   * `admin`) and `filter.chainId` keep only matching entries. The header then carries a
   * `filter` and the file cannot be verified (its chain has gaps): verify an unfiltered
   * export, then filter.
   */
  async *auditExport(
    fromSeq = 1,
    toSeq?: number,
    filter: { kind?: string; chainId?: string } = {},
  ): AsyncGenerator<AuditExportLine> {
    const query: Record<string, string | number> = { from: fromSeq };
    if (toSeq !== undefined) query.to = toSeq;
    if (filter.kind !== undefined) query.kind = filter.kind;
    if (filter.chainId !== undefined) query.chain_id = filter.chainId;
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
        throw new AttenuoError(`audit export: line is not JSON: ${line.slice(0, 200)}`);
      }
      if (typeof v !== "object" || v === null || Array.isArray(v)) {
        throw new AttenuoError(`audit export: line is not an object: ${line.slice(0, 200)}`);
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

  /**
   * The lease, its descendants and ancestors, and how many leases a revoke would change now. A
   * dry run of `revokeLease`: nothing changes, nothing is audited.
   */
  async leaseTree(leaseId: string, maxNodes?: number): Promise<LeaseTree> {
    const query: Record<string, number> = maxNodes === undefined ? {} : { max_nodes: maxNodes };
    const res = await this.http.get(`/admin/leases/${encodeURIComponent(leaseId)}/tree`, {
      query,
    });
    const b = w.asObject(await w.jsonBody(res), "lease tree");
    return {
      root: String(b.root),
      ancestors: leaseNodes(b.ancestors),
      nodes: leaseNodes(b.nodes),
      wouldRevoke: Number(b.would_revoke ?? 0),
      truncated: b.truncated === true,
    };
  }

  /**
   * One filtered page of `GET /admin/audit`. `order: "desc"` reads newest first (`seq <
   * before`); the answer's `prev` is the `before` of the next older page. A filtered page can
   * come back short, even empty, with a link still set: `auditIter` follows the links.
   */
  async auditQuery(query: AuditQuery = {}): Promise<AuditPage> {
    const res = await this.http.get("/admin/audit", { query: auditParams(query) });
    const page = w.asObject(await w.jsonBody(res), "audit");
    return {
      entries: entriesOf(page),
      next: opt<number>(page.next),
      prev: opt<number>(page.prev),
      head: headOf(page),
    };
  }

  /**
   * Every matching entry in `query.order`, following `next` (asc) or `prev` (desc) until it is
   * null. Pages lazily (default 1000 per page): stop iterating to stop reading.
   */
  async *auditIter(query: AuditQuery = {}): AsyncGenerator<AuditEntry> {
    const desc = query.order === "desc";
    let q: AuditQuery = { limit: MAX_PAGE, ...query };
    for (;;) {
      const page = await this.auditQuery(q);
      yield* page.entries;
      const cur = desc ? page.prev : page.next;
      if (cur === undefined) return;
      if (cur === (desc ? q.before : q.from)) {
        throw new AttenuoError(`audit paging did not advance (cursor ${cur})`);
      }
      q = desc ? { ...q, before: cur } : { ...q, from: cur };
    }
  }

  /** The entry at `seq` with its context. `ApiError` (404) when there is none. */
  async auditEntry(seq: number): Promise<AuditEntryDetail> {
    const res = await this.http.get(`/admin/audit/entries/${Math.trunc(seq)}`);
    return entryDetailOf(w.asObject(await w.jsonBody(res), "audit entry"));
  }

  /**
   * The entry whose record id is `id`: the `decisionId` a denial or an AuthZEN answer carries.
   * `ApiError` 400 if `id` is not a UUID, 404 if no record has it.
   */
  async auditRecord(id: string): Promise<AuditEntryDetail> {
    const res = await this.http.get(`/admin/audit/records/${encodeURIComponent(id)}`);
    return entryDetailOf(w.asObject(await w.jsonBody(res), "audit record"));
  }

  /**
   * Stored checkpoints with `seq < before`, newest first. Read-only: unlike `auditCheckpoint` it
   * never signs.
   */
  async auditCheckpoints(opts: { before?: number; limit?: number } = {}): Promise<CheckpointPage> {
    const query: Record<string, number> = {};
    if (opts.before !== undefined) query.before = opts.before;
    if (opts.limit !== undefined) query.limit = opts.limit;
    const res = await this.http.get("/admin/audit/checkpoints", { query });
    const b = w.asObject(await w.jsonBody(res), "checkpoints");
    return {
      checkpoints: Array.isArray(b.checkpoints) ? (b.checkpoints as StoredCheckpoint[]) : [],
      prev: opt<number>(b.prev),
    };
  }

  /** The policy set in force: file, digest, load time, ids, warnings and texts. */
  async policies(): Promise<PolicySet> {
    const res = await this.http.get("/admin/policies");
    const b = w.asObject(await w.jsonBody(res), "policies");
    const list = Array.isArray(b.policies) ? (b.policies as Json[]) : [];
    return {
      path: opt<string>(b.path),
      sha256: opt<string>(b.sha256),
      loadedAt: String(b.loaded_at ?? ""),
      policyIds: strs(b.policy_ids),
      warnings: strs(b.warnings),
      policies: Object.fromEntries(list.map((p) => [String(p.id), String(p.text)])),
    };
  }

  /**
   * Lint the policy file as it is on disk now, without loading it. `ApiError` (409
   * `check_unavailable`) when the server has no policy file.
   */
  async policyCheck(): Promise<PolicyCheck> {
    const res = await this.http.get("/admin/policies/check");
    const b = w.asObject(await w.jsonBody(res), "policy check");
    return {
      path: String(b.path),
      sha256: String(b.sha256),
      loadedSha256: opt<string>(b.loaded_sha256),
      differsFromLoaded: b.differs_from_loaded === true,
      ok: b.ok === true,
      errorCount: Number(b.error_count ?? 0),
      warningCount: Number(b.warning_count ?? 0),
      issues: Array.isArray(b.issues) ? (b.issues as Json[]) : [],
      policyIds: strs(b.policy_ids),
    };
  }

  /**
   * Dry run: what the loaded policies decide for this call. No lease check, no audit record.
   * Pass `opts.token` (verified by the server) or `opts.chain` (checked only structurally).
   */
  async policyEvaluate(
    server: string,
    tool: string,
    args?: Record<string, unknown>,
    opts: PolicyEvaluateOptions = {},
  ): Promise<PolicyEvaluation> {
    if (opts.token === undefined && opts.chain === undefined) {
      throw new TypeError("policyEvaluate needs a token or a chain");
    }
    const body = w.authzenBody(server, tool, args);
    if (opts.token !== undefined) body.token = bearer(opts.token);
    if (opts.chain !== undefined) {
      body.subject = { ...(body.subject as Json), properties: { chain: opts.chain } };
    }
    const res = await this.http.post("/admin/policies/evaluate", { json: body });
    const b = w.asObject(await w.jsonBody(res), "policy evaluation");
    return {
      decision: String(b.decision ?? ""),
      allowed: b.decision === "allow",
      reason: String(b.reason ?? ""),
      policyIds: strs(b.policy_ids),
      diagnostics: Array.isArray(b.diagnostics) ? b.diagnostics : [],
      leaseCheck: String(b.lease_check ?? ""),
      chainSource: String(b.chain_source ?? ""),
      tokenExpired: b.token_expired === true,
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
    const send = async () => {
      const proofOpts = this.nonce.value === undefined ? {} : { nonce: this.nonce.value };
      const headers: Record<string, string> = key
        ? {
            dpop: await key.proof(
              "POST",
              `${this.serverUrl}/admin/root-token`,
              undefined,
              proofOpts,
            ),
          }
        : {};
      return this.http.post("/admin/root-token", { json: body, headers });
    };
    let res = await send();
    if (key !== undefined && (await this.nonce.update(res))) {
      // `use_dpop_nonce`: retry once with the server's nonce.
      await res.body?.cancel();
      res = await send();
      await this.nonce.update(res);
    }
    return w.tokenFromResponse(await w.jsonBody(res));
  }
}

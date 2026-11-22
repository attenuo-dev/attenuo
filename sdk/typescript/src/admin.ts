/**
 * Operator API: revoke leases, refund a decision's budget charge, read and verify the audit log,
 * reload policy, decide approvals, mint dev roots.
 *
 * Every route needs the static admin bearer (`[admin] token` in the server config). Keep that
 * token out of agents: it can revoke anything and read every decision.
 */

import { capabilitiesToJson, type CapabilityLike } from "./capability.js";
import { DpopKey, NonceCache, resendOnce, type DpopKeyLike } from "./dpop.js";
import { Http, type HttpOptions } from "./http.js";
import { AttenuoError, budgetLimitOf } from "./errors.js";
import { bearer, type Token } from "./token.js";
import * as w from "./wire.js";

const MAX_PAGE = 1000;

type Json = Record<string, unknown>;

/**
 * The answer of `revokeLease`. `auditId` is the id of the `admin.lease.revoke` record,
 * `undefined` when the server could not write it (the revocation stands).
 */
export interface RevokeResult {
  leaseId: string;
  revoked: number;
  reason: string;
  auditId: string | undefined;
}

/**
 * The answer of `refundBudget` (`POST /admin/budgets/refund`). `refunded` counts the token-limit
 * counters credited. The run usage and per-user windows the decision charged are given back too
 * but not counted, so a decision that charged only usage answers 0. `auditId` is the id of the
 * `admin.budget.refund` record, `undefined` when the server could not write it (the refund
 * stands).
 */
export interface BudgetRefund {
  decisionId: string;
  refunded: number;
  reason: string;
  auditId: string | undefined;
}

/** What a decision record says, and what the audit filters take: the server's `Decision`. */
export type Decision = "allow" | "deny";

/**
 * Exactly one selector for `revokeBySelector`: an originating user's `sub` (any issuer), a
 * delegation chain (the first hop's lease id) or a raw MCP session id (`Mcp-Session-Id`).
 */
export type LeaseSelector =
  | { user: string; chainId?: never; session?: never }
  | { chainId: string; user?: never; session?: never }
  | { session: string; user?: never; chainId?: never };

export interface RevokeBySelectorOptions {
  /** Recorded with the revocation (server default `revoked by admin`). */
  reason?: string;
  /** Dry run: change nothing, write no audit record, answer what would be revoked. */
  preview?: boolean;
}

/**
 * The answer of `revokeBySelector` (`POST /admin/leases/revoke`).
 *
 * `selector` is how the server shows the selector: `{user}`, `{chain_id}` or, for a session,
 * `{session_tag, chain_ids}`, never the raw session id. `matched` holds the unrevoked leases the
 * selector named and `revoked` every lease that changed (the matches, then the cascade), each in
 * id order and cut at 10,000 ids (`truncated`); the counts are always complete. On a preview
 * `revoked` is what a revocation sent now would change, and `reason` and `auditId` are
 * `undefined`. `auditId` is also `undefined` when the server could not write the record (the
 * revocation stands).
 */
export interface SelectorRevocation {
  selector: Record<string, unknown>;
  preview: boolean;
  matched: string[];
  revoked: string[];
  matchedCount: number;
  revokedCount: number;
  truncated: boolean;
  reason: string | undefined;
  auditId: string | undefined;
}

/** Filters for `auditExport`; the ones you set combine with AND. */
export interface AuditExportFilter {
  /**
   * `decision`, `tool_result`, `approval_request`, `approval_grant`, `exchange`, `root_token`,
   * `lease_renew`, `lease_revoke`, `admin` or `search`.
   */
  kind?: string;
  /** The delegation chain: the lease id of its first hop. */
  chainId?: string;
  /** The record's `tool`, for example `token.exchange`. */
  tool?: string;
  decision?: Decision;
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
   * What sort of event the record is: `decision`, `tool_result`, `approval_request`,
   * `approval_grant`, `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin` or
   * `search` (one AuthZEN action search, not a decision).
   */
  kind: string | undefined;
  /** The lease id of the delegation chain's first hop (undefined for admin records). */
  chainId: string | undefined;
}

export interface AuditPage {
  entries: AuditEntry[];
  /**
   * The opaque cursor of the next page in the same order (send it as `cursor` with the same
   * filters and range), or undefined once the range has been read. A filtered page can be
   * short, even empty, with a cursor still set.
   */
  nextCursor: string | undefined;
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

/**
 * Who the admin token is (`GET /admin/whoami`, ADR-0016): the operator's `name` (`admin` for
 * the server's `[admin] token`), `role`, and `expiresAt`, the RFC 3339 time the token stops
 * working (absent when it does not expire).
 */
export interface AdminIdentity {
  name: string;
  role: "viewer" | "operator" | "admin" | string;
  expiresAt?: string;
}

export interface PolicyReload {
  policyIds: string[];
  warnings: string[];
}

/**
 * What `POST /admin/operators/reload` changed, by operator name (never a digest): operators
 * `added`, `removed` and `changed` (role, token or expiry).
 */
export interface OperatorsReload {
  added: string[];
  removed: string[];
  changed: string[];
}

/**
 * One list's part of `AgentsReload` (`[[agents]]` or `[[peps]]`): `count` entries in force now,
 * `sha256` of the list's canonical form, and the ids `added`, `removed` and `changed` (another
 * `secret_sha256` or `jwks`).
 */
export interface ClientListChanges {
  count: number;
  sha256: string;
  added: string[];
  removed: string[];
  changed: string[];
}

/**
 * What `POST /admin/agents/reload` put in force. `restartNeeded` names the other sections of the
 * file that differ from the running config (not applied); `warnings` are the startup warnings of
 * the new lists; `restartWarnings` say what the file's own settings would refuse after a restart.
 */
export interface AgentsReload {
  agents: ClientListChanges;
  peps: ClientListChanges;
  restartNeeded: string[];
  warnings: string[];
  restartWarnings: string[];
  /** The id of the `admin.agents.reload` audit record, undefined when it was not written. */
  auditId: string | undefined;
}

/** Overrides of `agentsReload`'s refusals; each is sent only when true. */
export interface AgentsReloadOptions {
  /** Accept a file that leaves `[[agents]]` or `[[peps]]` empty (`agents_reload_empties`). */
  allowEmpty?: boolean;
  /** Accept a file whose `[issuer]` or `[audit]` differs (`config_file_mismatch`). */
  allowMismatch?: boolean;
}

/**
 * What `POST /admin/keys/reload` put in force, by key id (`kid`) only. `changed` is false when
 * the file names the keys in force (nothing was swapped). `verifyingKids` is the set the JWKS
 * lists now, the signing key first; `added` and `removed` compare it with the set before.
 * `auditSigningKid` signs audit checkpoints and prune anchors from now on. `keptUntilRestart`
 * names what stays keyed by the startup key.
 */
export interface KeysReload {
  signingKid: string;
  previousSigningKid: string;
  changed: boolean;
  verifyingKids: string[];
  added: string[];
  removed: string[];
  auditSigningKid: string | undefined;
  keptUntilRestart: string[];
  restartNeeded: string[];
  warnings: string[];
  /** The id of the `admin.keys.reload` audit record, undefined when it was not written. */
  auditId: string | undefined;
}

/** Overrides of `keysReload`'s refusals; each is sent only when true. */
export interface KeysReloadOptions {
  /** Accept a new signing key that drops the current one (`keys_reload_drops_current`). */
  allowDropCurrent?: boolean;
  /** Accept dropping a key that signed audit checkpoints or anchors (`keys_reload_drops_audit_key`). */
  allowDropAuditKey?: boolean;
  /** Accept a file whose `[issuer]` or `[audit]` differs (`config_file_mismatch`). */
  allowMismatch?: boolean;
}

/**
 * A signed prune anchor, as the server sends it (not verified here). `state` (`deleting` or
 * `done`) and `shipped_at` (when `[audit.sink]` delivered it, null until then) come with a
 * stored anchor (`auditAnchors`, `auditPrunePlan`), not with the answer of a prune.
 */
export interface AuditAnchor {
  through_seq: number;
  through_hash: string;
  prune_seq: number;
  prune_entry_hash: string;
  previous_through_seq: number | null;
  archive_sha256: string | null;
  at: string;
  kid: string;
  signature: string;
  state?: string;
  shipped_at?: string | null;
  [key: string]: unknown;
}

/**
 * The bound each prune guard sets (`auditPrunePlan`). `limitedBy` is the refusal code of the
 * guard that set `through` below `requested`, or `"before"`, or undefined when `through` is the
 * request.
 */
export interface PruneGuards {
  requested: number;
  before: string | undefined;
  minAgeCutoff: string;
  liveRunSeq: number | undefined;
  sinkDeliveredThrough: number | undefined;
  sinkDegraded: boolean;
  inProgress: boolean;
  anchorUndelivered: boolean;
  limitedBy: string | undefined;
}

/**
 * The largest boundary the guards allow (`GET /admin/audit/prune/plan`). `through` is undefined
 * when nothing can be pruned. The archive of a prune through `through` is the export
 * `from`..`through`; `checkpoint` is the stored checkpoint at `through`, `at` the time of that
 * entry, `anchor` the newest anchor.
 */
export interface PrunePlan {
  from: number;
  through: number | undefined;
  entries: number;
  checkpoint: StoredCheckpoint | undefined;
  at: string | undefined;
  guards: PruneGuards;
  anchor: AuditAnchor | undefined;
}

/**
 * What `[audit.sink]` did with a prune's anchor: `queued` by this call, the highest checkpoint
 * seq the sink has `deliveredThrough`, when it delivered the anchor (`anchorShippedAt`) and
 * whether it is still queued (`anchorPending`).
 */
export interface PruneShipped {
  queued: boolean;
  deliveredThrough: number | undefined;
  anchorShippedAt: string | undefined;
  anchorPending: boolean;
}

/**
 * The answer of `POST /admin/audit/prune`. `deleting` is true while the maintenance task deletes
 * the rows; `shipped` is undefined without `[audit.sink]`; `already` is true for a repeat of a
 * prune that succeeded (nothing was written).
 */
export interface PruneResult {
  pruneSeq: number;
  prunedThrough: number;
  anchor: AuditAnchor;
  checkpointBefore: StoredCheckpoint | undefined;
  checkpointAfter: StoredCheckpoint | undefined;
  deleting: boolean;
  shipped: PruneShipped | undefined;
  already: boolean;
}

/** What `auditPrune` sends besides `through`: describe the archive, so the server can check it. */
export interface PruneOptions {
  /** SHA-256 (64 lower-case hex) of the archive file's bytes, signed into the anchor. */
  archiveSha256?: string;
  /** The archive's first seq: the prune is refused unless it is the first retained seq. */
  from?: number;
  /** The archive's last entry hash: the prune is refused unless it is the entry hash at `through`. */
  throughHash?: string;
}

/** Prune anchors, newest first (`GET /admin/audit/anchors`). */
export interface AnchorPage {
  anchors: AuditAnchor[];
  /** The opaque cursor of the next (older) page, undefined after the oldest. */
  nextCursor: string | undefined;
}

/**
 * Filters and paging for `auditQuery` / `auditIter`. Each filter is an exact match, never a
 * pattern; the ones you set combine with AND.
 */
export interface AuditQuery {
  /** `asc` (oldest first, the default) or `desc` (newest first). */
  order?: "asc" | "desc";
  /** Lowest seq of the range (default 1). */
  from?: number;
  /** Highest seq of the range (default: the head). */
  to?: number;
  /** The `nextCursor` of the previous page, sent with the same filters, range and order. */
  cursor?: string;
  /** Page size (server default 100, at most 1000). */
  limit?: number;
  /**
   * One kind or several: `decision`, `tool_result`, `approval_request`, `approval_grant`,
   * `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin`, `search`.
   */
  kind?: string | readonly string[];
  decision?: Decision;
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
  /** The opaque cursor of the next (older) page, undefined after the oldest. */
  nextCursor: string | undefined;
}

/** One page of `approvals`, newest first. */
export interface ApprovalPage {
  approvals: w.Approval[];
  /** The opaque cursor of the next (older) page with the same filters, undefined after the last. */
  nextCursor: string | undefined;
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
  /** The hop's run limits and what is left; undefined when it has none and nothing was charged. */
  budget: LeaseBudget | undefined;
}

/**
 * One run limit of a hop and what its counter holds. `arg` is `arg#host` for a derived value.
 * `used` is calls, the sum, for `distinct` the values seen, and for `calls_per` the most calls
 * any one value has had (`values` counts the values). `max` and `remaining` are undefined for a
 * hop issued before the server kept its limits.
 */
export interface LeaseLimit {
  cap: number;
  server: string | undefined;
  tool: string | undefined;
  kind: string;
  arg: string | undefined;
  max: number | undefined;
  used: number;
  remaining: number | undefined;
  values: number | undefined;
}

/** A run's usage of one destructive tool (on the run's root lease). */
export interface LeaseUsage {
  tool: string;
  calls: number;
  amount: number;
  destinations: number;
}

/** The `budget` of a lease tree node. */
export interface LeaseBudget {
  /** The server kept the hop's limits when it issued the token. */
  recorded: boolean;
  limits: LeaseLimit[];
  usage: LeaseUsage[];
}

/**
 * One per-user window of a run's originating user (run limits phase 3): the window of `kind`
 * (`hour` or `day`) holding now, starting at `start` (RFC 3339, UTC), and what every run of
 * the user was allowed in it for `tool` (`"<server>/<tool>"`).
 */
export interface LeaseUserWindow {
  tool: string;
  kind: string;
  start: string;
  calls: number;
  amount: number;
}

/**
 * The `userWindows` of a `LeaseTree`: a window per tool the run used and kind a loaded policy
 * reads, ordered by tool then kind; `truncated` when the server's cap cut the list short.
 */
export interface LeaseUserWindows {
  windows: LeaseUserWindow[];
  truncated: boolean;
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
  /**
   * The run's originating user's per-user windows, read at `root`; undefined when the root
   * lease was issued before the server kept the user's issuer, or the server is older.
   */
  userWindows: LeaseUserWindows | undefined;
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

export type LimitKind = "calls" | "sum" | "calls_per" | "distinct";

/**
 * One run-limit counter: `hop` (position in the chain, root 0), `kind`, `arg` (the counted
 * argument as the limit names it, `arg#host` for a derived one; absent for `calls`), `used`
 * (calls or summed amount; for `calls_per` the calls with this value; for `distinct` how many
 * values the limit has seen) and `max`.
 *
 * The `limit` of a `budget_exhausted` dry run has this shape, and so does an entry of
 * `StatedBudget.limits`, where `max` is optional (when given it must equal the limit's). The
 * SDK sends entries as given, so a refusal's `limit` can be stated back as it came.
 */
export interface BudgetLimit {
  hop: number;
  kind: LimitKind;
  arg?: string;
  used: number;
  max?: number;
}

/**
 * The run-limit state a dry run decides the call in, instead of the store's counters (the
 * `budget` block of `POST /admin/policies/evaluate`, in the vocabulary of a `policy test`
 * case's `budget`). Members left out are not sent. The server checks the block: a malformed
 * one, or an entry that names no limit of the chain matching the call, is its 400
 * `invalid_request`.
 */
export interface StatedBudget {
  /** What every matching `calls` limit has left. */
  callsRemaining?: number;
  /** What every matching `sum` limit has left. */
  amountRemaining?: number;
  /** `false`: the call's value was already counted by each matching `calls_per` and `distinct` limit. */
  destinationNew?: boolean;
  /** `context.budget.limited` when no limit of the chain matches the call (server default `true`). */
  limited?: boolean;
  /** At most 64 single counters, over the figures above. */
  limits?: readonly BudgetLimit[];
}

/**
 * The run's output labels a dry run decides the call with, instead of the store's (the
 * `session` block of `POST /admin/policies/evaluate`, ADR-0009). Members left out (or empty
 * lists) are not sent. The answer's `labels.source` is then `request`; a malformed block is the
 * server's 400 `invalid_request`.
 */
export interface StatedSession {
  /** The `<server>/<tool>` sources the run has read untrusted output from. */
  taintedBy?: readonly string[];
  /** `context.session.tainted` (server default: whether `taintedBy` is non-empty). */
  tainted?: boolean;
  /** The call's arguments that carry a span of untrusted output. */
  untrustedArgs?: readonly string[];
  /** `context.args_contain_untrusted` (server default: whether `untrustedArgs` is non-empty). */
  argsContainUntrusted?: boolean;
}

/** Who granted the approval a dry run is evaluated with. */
export type ApprovalBy = "user" | "operator" | "policy";

/**
 * Evaluate the call as a retry that carries a granted approval (the `approval` block of
 * `POST /admin/policies/evaluate`): `context.approval.present` is true and `by` as given. The
 * dry run never looks up or consumes a stored approval, so it takes no id or token. The
 * answer's `approvalBy` is then `by`.
 */
export interface StatedApproval {
  by: ApprovalBy;
}

/**
 * The run usage a dry run decides the call with (`context.usage`, the `usage` block of
 * `POST /admin/policies/evaluate`), instead of the store's. Members left out are not sent; the
 * server takes them as 0 or `false`. The answer's `usage.source` is then `request`.
 */
export interface StatedUsage {
  calls?: number;
  amount?: number;
  destinationSeen?: boolean;
}

/**
 * `context.budget` of a dry run: what the run limits matching the call have left.
 * `callsRemaining` and `amountRemaining` are `Infinity` when no limit of that kind matches (the
 * server sends `2^63 - 1`, which a JavaScript number cannot hold).
 */
export interface EvaluationBudget {
  limited: boolean;
  callsRemaining: number;
  amountRemaining: number;
  destinationNew: boolean;
  /** `store`: the run's counters as they stand (read, never charged); `request`: as stated. */
  source: "store" | "request";
}

/** The run's output labels the dry run decided with (ADR-0009). */
export interface EvaluationLabels {
  tainted: boolean;
  taintedBy: string[];
  argsContainUntrusted: boolean;
  untrustedArgs: string[];
  source: "store" | "request";
}

/** `context.usage` of a dry run. */
export interface EvaluationUsage {
  calls: number;
  amount: number;
  destinationSeen: boolean;
  /** `untracked`: the server keeps no run usage, so the zeros are not a reading of the run. */
  source: "request" | "store" | "untracked";
}

/**
 * A dry-run decision from `policyEvaluate`. `limit` is set when the call would take a run limit
 * past its `max` (reason `budget_exhausted`). `budget`, `labels` and `usage` are `undefined`
 * only for a server that does not send them; `approvalBy` is the `by` of the granted approval
 * the call was evaluated with.
 */
export interface PolicyEvaluation {
  decision: Decision;
  allowed: boolean;
  reason: string;
  policyIds: string[];
  diagnostics: unknown[];
  /** Always `skipped`. */
  leaseCheck: string;
  /** `token` or `admin_supplied`. */
  chainSource: string;
  tokenExpired: boolean;
  budget?: EvaluationBudget;
  limit?: BudgetLimit;
  labels?: EvaluationLabels;
  usage?: EvaluationUsage;
  approvalBy?: string;
}

export interface PolicyEvaluateOptions {
  /** A delegation token, verified by the server; an expired one is accepted and flagged. */
  token?: Token | string;
  /** A chain object instead of a token, checked only structurally. */
  chain?: Json;
  /** The run-limit counters to decide in, instead of the store's (`budget.source: "request"`). */
  budget?: StatedBudget;
  /** The run's output labels to decide with, instead of the store's (`labels.source: "request"`). */
  session?: StatedSession;
  /** Evaluate as if the call carried a granted approval (`approvalBy` in the answer). */
  approval?: StatedApproval;
  /** `context.usage` to decide with, instead of the store's (`usage.source: "request"`). */
  usage?: StatedUsage;
}

/** Filters for `approvals`. */
export interface ApprovalQuery {
  /** Only the approvals of this delegation run. */
  chainId?: string;
  /** Only approvals in this state: `pending`, `granted`, `declined` or `consumed`. */
  state?: string;
  /** Page size (server default 100, at most 500). */
  limit?: number;
  /** The `nextCursor` of the previous page, sent with the same filters. */
  cursor?: string;
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

function exportParams(
  fromSeq: number,
  toSeq: number | undefined,
  filter: AuditExportFilter,
): Record<string, string | number> {
  const query: Record<string, string | number> = { from: fromSeq };
  if (toSeq !== undefined) query.to = toSeq;
  if (filter.kind !== undefined) query.kind = filter.kind;
  if (filter.chainId !== undefined) query.chain_id = filter.chainId;
  if (filter.tool !== undefined) query.tool = filter.tool;
  if (filter.decision !== undefined) query.decision = filter.decision;
  return query;
}

/** `next_cursor` of a list answer; undefined when absent or null. */
function nextCursorOf(b: Record<string, unknown>): string | undefined {
  return typeof b.next_cursor === "string" ? b.next_cursor : undefined;
}

/** `cur` to follow next, refusing one that repeats the cursor just sent (it would page forever). */
function advance(cur: string | undefined, last: string | undefined): string | undefined {
  if (cur !== undefined && cur === last) {
    throw new AttenuoError("paging did not advance (the server sent the same cursor again)");
  }
  return cur;
}

function rfc3339(v: string | Date): string {
  return typeof v === "string" ? v : v.toISOString();
}

function auditParams(q: AuditQuery): Record<string, string | number> {
  const out: Record<string, string | number> = { order: q.order ?? "asc" };
  if (q.limit !== undefined) out.limit = q.limit;
  if (q.from !== undefined) out.from = q.from;
  if (q.to !== undefined) out.to = q.to;
  if (q.cursor !== undefined) out.cursor = q.cursor;
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

function names(v: unknown): string[] {
  return Array.isArray(v) ? v.map(String) : [];
}

function optNumber(v: unknown): number | undefined {
  return v === null || v === undefined ? undefined : Number(v);
}

function optString(v: unknown): string | undefined {
  return v === null || v === undefined ? undefined : String(v);
}

/** The body of a reload: the overrides that are set, `{}` for none. */
function flags(f: Record<string, boolean | undefined>): Record<string, true> {
  const out: Record<string, true> = {};
  for (const [k, v] of Object.entries(f)) if (v === true) out[k] = true;
  return out;
}

function clientChangesOf(v: unknown): ClientListChanges {
  const b = obj(v) ?? {};
  return {
    count: Number(b.count ?? 0),
    sha256: String(b.sha256 ?? ""),
    added: names(b.added),
    removed: names(b.removed),
    changed: names(b.changed),
  };
}

function anchorOf(v: unknown): AuditAnchor {
  return { ...w.asObject(v, "anchor") } as AuditAnchor;
}

function storedCheckpointOf(v: unknown): StoredCheckpoint | undefined {
  const b = obj(v);
  return b === undefined ? undefined : ({ ...b } as StoredCheckpoint);
}

function prunePlanOf(b: Json): PrunePlan {
  const g = obj(b.guards) ?? {};
  return {
    from: Number(b.from ?? 1),
    through: optNumber(b.through),
    entries: Number(b.entries ?? 0),
    checkpoint: storedCheckpointOf(b.checkpoint),
    at: optString(b.at),
    guards: {
      requested: Number(g.requested ?? 0),
      before: optString(g.before),
      minAgeCutoff: String(g.min_age_cutoff ?? ""),
      liveRunSeq: optNumber(g.live_run_seq),
      sinkDeliveredThrough: optNumber(g.sink_delivered_through),
      sinkDegraded: g.sink_degraded === true,
      inProgress: g.in_progress === true,
      anchorUndelivered: g.anchor_undelivered === true,
      limitedBy: optString(g.limited_by),
    },
    anchor: obj(b.anchor) === undefined ? undefined : anchorOf(b.anchor),
  };
}

function pruneResultOf(b: Json): PruneResult {
  const sh = obj(b.shipped);
  return {
    pruneSeq: Number(b.prune_seq),
    prunedThrough: Number(b.pruned_through),
    anchor: anchorOf(b.anchor),
    checkpointBefore: storedCheckpointOf(b.checkpoint_before),
    checkpointAfter: storedCheckpointOf(b.checkpoint_after),
    deleting: b.deleting === true,
    shipped:
      sh === undefined
        ? undefined
        : {
            queued: sh.queued === true,
            deliveredThrough: optNumber(sh.delivered_through),
            anchorShippedAt: optString(sh.anchor_shipped_at),
            anchorPending: sh.anchor_pending === true,
          },
    already: b.already === true,
  };
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
    budget: budgetOf(n.budget),
  };
}

function budgetOf(v: unknown): LeaseBudget | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const b = v as Json;
  const list = (x: unknown): Json[] => (Array.isArray(x) ? (x as Json[]) : []);
  return {
    recorded: b.recorded === true,
    limits: list(b.limits).map((l) => ({
      cap: Number(l.cap),
      server: opt<string>(l.server),
      tool: opt<string>(l.tool),
      kind: String(l.kind),
      arg: opt<string>(l.arg),
      max: opt<number>(l.max),
      used: Number(l.used),
      remaining: opt<number>(l.remaining),
      values: opt<number>(l.values),
    })),
    usage: list(b.usage).map((u) => ({
      tool: String(u.tool),
      calls: Number(u.calls),
      amount: Number(u.amount),
      destinations: Number(u.destinations),
    })),
  };
}

function userWindowsOf(v: unknown): LeaseUserWindows | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const b = v as Json;
  const list = Array.isArray(b.windows) ? (b.windows as Json[]) : [];
  return {
    windows: list.map((e) => ({
      tool: String(e.tool),
      kind: String(e.kind),
      start: String(e.start),
      calls: Number(e.calls),
      amount: Number(e.amount),
    })),
    truncated: b.truncated === true,
  };
}

function statedBudgetJson(b: StatedBudget): Json {
  const out: Json = {};
  if (b.callsRemaining !== undefined) out.calls_remaining = b.callsRemaining;
  if (b.amountRemaining !== undefined) out.amount_remaining = b.amountRemaining;
  if (b.destinationNew !== undefined) out.destination_new = b.destinationNew;
  if (b.limited !== undefined) out.limited = b.limited;
  if (b.limits !== undefined && b.limits.length > 0) {
    out.limits = b.limits.map((l) => {
      const e: Json = { hop: l.hop, kind: l.kind, used: l.used };
      if (l.arg !== undefined) e.arg = l.arg;
      if (l.max !== undefined) e.max = l.max;
      return e;
    });
  }
  return out;
}

function statedSessionJson(st: StatedSession): Json {
  const out: Json = {};
  if (st.taintedBy !== undefined && st.taintedBy.length > 0) out.tainted_by = [...st.taintedBy];
  if (st.tainted !== undefined) out.tainted = st.tainted;
  if (st.untrustedArgs !== undefined && st.untrustedArgs.length > 0) {
    out.untrusted_args = [...st.untrustedArgs];
  }
  if (st.argsContainUntrusted !== undefined) out.args_contain_untrusted = st.argsContainUntrusted;
  return out;
}

function statedUsageJson(u: StatedUsage): Json {
  const out: Json = {};
  if (u.calls !== undefined) out.calls = u.calls;
  if (u.amount !== undefined) out.amount = u.amount;
  if (u.destinationSeen !== undefined) out.destination_seen = u.destinationSeen;
  return out;
}

/** A remaining figure; `2^63 - 1` (no limit of that kind) parses past the safe range. */
function remaining(v: unknown): number {
  if (typeof v !== "number") return 0;
  return Number.isSafeInteger(v) ? v : Infinity;
}

function obj(v: unknown): Json | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : undefined;
}

function evaluationOf(b: Json): PolicyEvaluation {
  const out: PolicyEvaluation = {
    decision: (b.decision === "allow" ? "allow" : "deny") as Decision,
    allowed: b.decision === "allow",
    reason: String(b.reason ?? ""),
    policyIds: strs(b.policy_ids),
    diagnostics: Array.isArray(b.diagnostics) ? b.diagnostics : [],
    leaseCheck: String(b.lease_check ?? ""),
    chainSource: String(b.chain_source ?? ""),
    tokenExpired: b.token_expired === true,
  };
  const budget = obj(b.budget);
  if (budget) {
    out.budget = {
      limited: budget.limited === true,
      callsRemaining: remaining(budget.calls_remaining),
      amountRemaining: remaining(budget.amount_remaining),
      destinationNew: budget.destination_new === true,
      source: String(budget.source ?? "") as EvaluationBudget["source"],
    };
  }
  const limit = budgetLimitOf(b.limit);
  if (limit) out.limit = limit;
  const session = obj(b.session);
  if (session) {
    out.labels = {
      tainted: session.tainted === true,
      taintedBy: strs(session.tainted_by).map(String),
      argsContainUntrusted: session.args_contain_untrusted === true,
      untrustedArgs: strs(session.untrusted_args).map(String),
      source: String(session.source ?? "") as EvaluationLabels["source"],
    };
  }
  const usage = obj(b.usage);
  if (usage) {
    out.usage = {
      calls: Number(usage.calls ?? 0),
      amount: Number(usage.amount ?? 0),
      destinationSeen: usage.destination_seen === true,
      source: String(usage.source ?? "") as EvaluationUsage["source"],
    };
  }
  const approval = obj(b.approval);
  if (approval?.present === true) out.approvalBy = String(approval.by ?? "");
  return out;
}

function leaseNodes(v: unknown): LeaseNode[] {
  return Array.isArray(v) ? (v as Json[]).map(leaseNodeOf) : [];
}

const SELECTORS = [
  ["user", "user"],
  ["chainId", "chain_id"],
  ["session", "session"],
] as const;

/**
 * The body and query of `POST /admin/leases/revoke`. Throws unless exactly one selector is given
 * and it is not empty. No message names a value: `session` is a secret that grants use of the
 * MCP session.
 */
function selectorRequest(
  selector: LeaseSelector,
  opts: RevokeBySelectorOptions,
): { json: Json; query: Record<string, string> } {
  const sel = selector as Partial<Record<"user" | "chainId" | "session", unknown>>;
  const given = SELECTORS.filter(([key]) => sel[key] !== undefined);
  if (given.length !== 1) {
    throw new TypeError("give exactly one of `user`, `chainId`, `session`");
  }
  const [key, field] = given[0]!;
  const value = sel[key];
  if (typeof value !== "string" || value === "") {
    throw new TypeError(`\`${key}\` must be a non-empty string`);
  }
  const json: Json = { [field]: value };
  if (opts.reason !== undefined) json.reason = opts.reason;
  return { json, query: opts.preview ? { preview: "true" } : {} };
}

function selectorRevocationOf(b: Json): SelectorRevocation {
  const ids = (v: unknown) => (Array.isArray(v) ? v.map(String) : []);
  return {
    selector: { ...((b.selector as Json | undefined) ?? {}) },
    preview: b.preview === true,
    matched: ids(b.matched),
    revoked: ids(b.revoked),
    matchedCount: Number(b.matched_count ?? 0),
    revokedCount: Number(b.revoked_count ?? 0),
    truncated: b.truncated === true,
    reason: b.reason == null ? undefined : String(b.reason),
    auditId: b.audit_id == null ? undefined : String(b.audit_id),
  };
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
    return {
      leaseId: String(b.lease_id),
      revoked: Number(b.revoked),
      reason: String(b.reason),
      auditId: b.audit_id == null ? undefined : String(b.audit_id),
    };
  }

  /**
   * `POST /admin/leases/revoke`: revoke every unrevoked lease of one originating `user` (the
   * `sub`, any issuer), one delegation chain (`chainId`, the first hop's lease id) or the chain
   * that opened one MCP `session` (the raw `Mcp-Session-Id`), each with its descendants, in one
   * transaction. Give exactly one (a `TypeError` otherwise). Matching nothing is not an error:
   * the lists come back empty.
   *
   * `preview: true` changes nothing and writes no audit record: the answer says what a
   * revocation sent now would revoke. The SDK never logs or echoes `session`; the answer shows
   * only its tag and the chains it resolved to.
   */
  async revokeBySelector(
    selector: LeaseSelector,
    opts: RevokeBySelectorOptions = {},
  ): Promise<SelectorRevocation> {
    const { json, query } = selectorRequest(selector, opts);
    const res = await this.http.post("/admin/leases/revoke", { json, query });
    return selectorRevocationOf(w.asObject(await w.jsonBody(res), "revoke"));
  }

  /**
   * `POST /admin/budgets/refund`: give back what the allowed decision `decisionId` charged to its
   * run's limits, once, for a call whose effect did not happen. The server writes an
   * `admin.budget.refund` record (`reason` defaults to `refunded by admin`).
   *
   * A refund that cannot be made is an `ApiError`: 409 `already_refunded`, 410 `charge_pruned`
   * (the charge is older than the server keeps), 404 `not_found` (an unknown id, or a decision
   * that charged nothing). Its `detail` says which, from the decision's audit record.
   */
  async refundBudget(decisionId: string, reason?: string): Promise<BudgetRefund> {
    const id = typeof decisionId === "string" ? decisionId.trim() : "";
    if (id === "") throw new TypeError("decisionId must be the id of an allowed decision");
    const json: Json = { decision_id: id };
    if (reason !== undefined) json.reason = reason;
    const res = await this.http.post("/admin/budgets/refund", { json });
    const b = w.asObject(await w.jsonBody(res), "refund");
    return {
      decisionId: String(b.decision_id ?? ""),
      refunded: typeof b.refunded === "number" && Number.isInteger(b.refunded) ? b.refunded : 0,
      reason: String(b.reason ?? ""),
      auditId: b.audit_id == null ? undefined : String(b.audit_id),
    };
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

  /**
   * One page of entries from `fromSeq`, oldest first, with the cursor of the next page
   * (undefined at the head). Pass it back as `cursor` with the same `fromSeq`.
   */
  async audit(fromSeq = 1, limit = 100, cursor?: string): Promise<AuditPage> {
    const query: Record<string, string | number> = { from: fromSeq, limit };
    if (cursor !== undefined) query.cursor = cursor;
    const res = await this.http.get("/admin/audit", { query });
    const page = w.asObject(await w.jsonBody(res), "audit");
    return { entries: entriesOf(page), nextCursor: nextCursorOf(page), head: headOf(page) };
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
   * `filter.kind` (`decision`, `tool_result`, `approval_request`, `approval_grant`,
   * `exchange`, `root_token`, `lease_renew`, `lease_revoke`, `admin`, `search`), `filter.chainId`, `filter.tool` (for example `token.exchange`)
   * and `filter.decision` (`allow` or `deny`) keep only matching entries, combined with AND.
   * The header then carries a `filter` naming them and the file cannot be verified (its chain
   * has gaps): verify an unfiltered export, then filter. An unknown kind or decision, or an
   * empty value, is an `ApiError` (400).
   */
  async *auditExport(
    fromSeq = 1,
    toSeq?: number,
    filter: AuditExportFilter = {},
  ): AsyncGenerator<AuditExportLine> {
    const query = exportParams(fromSeq, toSeq, filter);
    const res = await this.http.get("/admin/audit/export", { query });
    if (!res.ok) throw w.errorFromResponse(res.status, await res.text(), res.headers);
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
    const start = Math.max(1, head + 1 - n);
    const out: AuditEntry[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await this.audit(start, MAX_PAGE, cursor);
      out.push(...page.entries);
      cursor = advance(page.nextCursor, cursor);
      if (cursor === undefined) return out;
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
   * Re-read `[[admin.operators]]` from the server's config file and put them in force (role
   * `admin`). A list that does not parse, breaks a rule or would leave no `admin` throws
   * `ApiError` (422) and the operators in force stay as they were.
   */
  async operatorsReload(): Promise<OperatorsReload> {
    const res = await this.http.post("/admin/operators/reload", { json: {} });
    const b = w.asObject(await w.jsonBody(res), "operators reload");
    return { added: names(b.added), removed: names(b.removed), changed: names(b.changed) };
  }

  /**
   * Re-read `[[agents]]` and `[[peps]]` from the server's config file and put both in force at
   * once (role `admin`). Tokens already issued are not revoked. A file that does not parse or
   * breaks a startup rule throws `ApiError` 422 `agents_invalid`; one that leaves a list empty,
   * `agents_reload_empties` unless `allowEmpty`; one whose `[issuer]` or `[audit]` differs,
   * `config_file_mismatch` unless `allowMismatch`. On every refusal the lists in force stay as
   * they were.
   */
  async agentsReload(opts: AgentsReloadOptions = {}): Promise<AgentsReload> {
    const json = flags({ allow_empty: opts.allowEmpty, allow_mismatch: opts.allowMismatch });
    const res = await this.http.post("/admin/agents/reload", { json });
    const b = w.asObject(await w.jsonBody(res), "agents reload");
    return {
      agents: clientChangesOf(b.agents),
      peps: clientChangesOf(b.peps),
      restartNeeded: names(b.restart_needed),
      warnings: names(b.warnings),
      restartWarnings: names(b.restart_warnings),
      auditId: optString(b.audit_id),
    };
  }

  /**
   * Re-read the key files `[issuer] private_key_pem_path` and `previous_key_paths` name in the
   * server's config file and put the new signing key and verifying keys in force at once (role
   * `admin`). A new signing key that drops the current one throws `ApiError` 422
   * `keys_reload_drops_current` unless `allowDropCurrent`; dropping a key that signed audit
   * checkpoints or anchors, `keys_reload_drops_audit_key` unless `allowDropAuditKey`; another
   * server's file, `config_file_mismatch` unless `allowMismatch`. On every refusal the keys in
   * force stay as they were.
   */
  async keysReload(opts: KeysReloadOptions = {}): Promise<KeysReload> {
    const json = flags({
      allow_drop_current: opts.allowDropCurrent,
      allow_drop_audit_key: opts.allowDropAuditKey,
      allow_mismatch: opts.allowMismatch,
    });
    const res = await this.http.post("/admin/keys/reload", { json });
    const b = w.asObject(await w.jsonBody(res), "keys reload");
    return {
      signingKid: String(b.signing_kid ?? ""),
      previousSigningKid: String(b.previous_signing_kid ?? ""),
      changed: b.changed === true,
      verifyingKids: names(b.verifying_kids),
      added: names(b.added),
      removed: names(b.removed),
      auditSigningKid: optString(b.audit_signing_kid),
      keptUntilRestart: names(b.kept_until_restart),
      restartNeeded: names(b.restart_needed),
      warnings: names(b.warnings),
      auditId: optString(b.audit_id),
    };
  }

  /**
   * `GET /admin/audit/prune/plan`: the largest boundary the guards allow at or below `through`
   * (a seq), or for entries older than `before` (RFC 3339 or a `Date`), the head when neither is
   * given; a `TypeError` for both. Reads only. `ApiError` 409 `prune_disabled` with
   * `[audit.retention] prune = "off"`.
   */
  async auditPrunePlan(
    opts: { through?: number; before?: string | Date } = {},
  ): Promise<PrunePlan> {
    if (opts.through !== undefined && opts.before !== undefined) {
      throw new TypeError("give `through` or `before`, not both");
    }
    const query: Record<string, string | number> = {};
    if (opts.through !== undefined) query.through = opts.through;
    if (opts.before !== undefined) query.before = rfc3339(opts.before);
    const res = await this.http.get("/admin/audit/prune/plan", { query });
    return prunePlanOf(w.asObject(await w.jsonBody(res), "prune plan"));
  }

  /**
   * `POST /admin/audit/prune`: prune the log through seq `through`. Export `from`..`through`
   * first, verify it and keep it off the host; then pass the SHA-256 of its bytes as
   * `archiveSha256`, its first seq as `from` and its last entry hash as `throughHash`, so the
   * server refuses (409 `prune_archive_mismatch`) unless the archive covers what it prunes. A
   * guard that refuses throws `ApiError` 409 with its code (`prune_not_at_checkpoint`,
   * `prune_too_recent`, `sink_behind`, ...); a `through` below the boundary, 410
   * `audit_pruned`. A repeat of a prune that succeeded answers `already: true`.
   */
  async auditPrune(through: number, opts: PruneOptions = {}): Promise<PruneResult> {
    const json: Record<string, string | number> = { through };
    if (opts.archiveSha256 !== undefined) json.archive_sha256 = opts.archiveSha256;
    if (opts.from !== undefined) json.from = opts.from;
    if (opts.throughHash !== undefined) json.through_hash = opts.throughHash;
    const res = await this.http.post("/admin/audit/prune", { json });
    return pruneResultOf(w.asObject(await w.jsonBody(res), "prune"));
  }

  /**
   * The signed anchors of past prunes, newest first, each with its `state` and `shipped_at`;
   * `cursor` is the `nextCursor` of the previous page (server default page 50, at most 500).
   * Empty for a log never pruned.
   */
  async auditAnchors(opts: { cursor?: string; limit?: number } = {}): Promise<AnchorPage> {
    const query: Record<string, string | number> = {};
    if (opts.cursor !== undefined) query.cursor = opts.cursor;
    if (opts.limit !== undefined) query.limit = opts.limit;
    const res = await this.http.get("/admin/audit/anchors", { query });
    const b = w.asObject(await w.jsonBody(res), "anchors");
    const list = Array.isArray(b.anchors) ? b.anchors.filter((a) => obj(a) !== undefined) : [];
    return { anchors: list.map(anchorOf), nextCursor: nextCursorOf(b) };
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
      userWindows: userWindowsOf(b.user_windows),
    };
  }

  /**
   * One filtered page of `GET /admin/audit`: the range `from`..`to` (default the whole log),
   * oldest first or with `order: "desc"` newest first. `cursor` is the `nextCursor` of the
   * previous page. A filtered page can come back short, even empty, with `nextCursor` still
   * set: `auditIter` follows it.
   */
  async auditQuery(query: AuditQuery = {}): Promise<AuditPage> {
    const res = await this.http.get("/admin/audit", { query: auditParams(query) });
    const page = w.asObject(await w.jsonBody(res), "audit");
    return { entries: entriesOf(page), nextCursor: nextCursorOf(page), head: headOf(page) };
  }

  /**
   * Every matching entry of the range in `query.order`, following `nextCursor` until it is
   * undefined. Pages lazily (default 1000 per page): stop iterating to stop reading. Entries
   * appended meanwhile do not shift the ones not read yet.
   */
  async *auditIter(query: AuditQuery = {}): AsyncGenerator<AuditEntry> {
    let q: AuditQuery = { limit: MAX_PAGE, ...query };
    for (;;) {
      const page = await this.auditQuery(q);
      yield* page.entries;
      const cur = advance(page.nextCursor, q.cursor);
      if (cur === undefined) return;
      q = { ...q, cursor: cur };
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
   * Stored checkpoints, newest first; `cursor` is the `nextCursor` of the previous page (server
   * default page 100, at most 1000). Read-only: unlike `auditCheckpoint` it never signs.
   */
  async auditCheckpoints(opts: { cursor?: string; limit?: number } = {}): Promise<CheckpointPage> {
    const query: Record<string, string | number> = {};
    if (opts.cursor !== undefined) query.cursor = opts.cursor;
    if (opts.limit !== undefined) query.limit = opts.limit;
    const res = await this.http.get("/admin/audit/checkpoints", { query });
    const b = w.asObject(await w.jsonBody(res), "checkpoints");
    return {
      checkpoints: Array.isArray(b.checkpoints) ? (b.checkpoints as StoredCheckpoint[]) : [],
      nextCursor: nextCursorOf(b),
    };
  }

  /** Every stored checkpoint, newest first, following `nextCursor`. */
  async *auditCheckpointsIter(opts: { limit?: number } = {}): AsyncGenerator<StoredCheckpoint> {
    let cursor: string | undefined;
    for (;;) {
      const page = await this.auditCheckpoints({ ...opts, cursor });
      yield* page.checkpoints;
      cursor = advance(page.nextCursor, cursor);
      if (cursor === undefined) return;
    }
  }

  /** The name, role and expiry of the admin token this client sends (`GET /admin/whoami`). */
  async whoami(): Promise<AdminIdentity> {
    const res = await this.http.get("/admin/whoami");
    const b = w.asObject(await w.jsonBody(res), "whoami");
    const who: AdminIdentity = { name: String(b.name ?? ""), role: String(b.role ?? "") };
    const expiresAt = opt<string>(b.expires_at);
    if (expiresAt !== undefined) who.expiresAt = String(expiresAt);
    return who;
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
   * Dry run: what the loaded policies decide for this call. No lease check, no charge, no audit
   * record. Pass `opts.token` (verified by the server) or `opts.chain` (checked only
   * structurally). `opts.budget` states the run-limit counters to decide in instead of the
   * store's; a spent hard limit then answers `budget_exhausted` with `limit` set, as the live
   * call would. `opts.session`, `opts.approval` and `opts.usage` state the run's output labels,
   * a granted approval and `context.usage` the same way. Nothing is checked client side: a
   * malformed block is the server's 400, thrown as `ApiError`.
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
    if (opts.budget !== undefined) body.budget = statedBudgetJson(opts.budget);
    if (opts.session !== undefined) body.session = statedSessionJson(opts.session);
    if (opts.approval !== undefined) body.approval = { by: opts.approval.by };
    if (opts.usage !== undefined) body.usage = statedUsageJson(opts.usage);
    const res = await this.http.post("/admin/policies/evaluate", { json: body });
    return evaluationOf(w.asObject(await w.jsonBody(res), "policy evaluation"));
  }

  /**
   * One page of approvals, newest first, filtered by `query`; `query.cursor` is the
   * `nextCursor` of the previous page, sent with the same filters (`approvalsIter` follows
   * it). An unknown `state` is an `ApiError` (400).
   */
  async approvals(query: ApprovalQuery = {}): Promise<ApprovalPage> {
    const q: Record<string, string | number> = {};
    if (query.chainId) q.chain_id = query.chainId;
    if (query.state) q.state = query.state;
    if (query.limit !== undefined) q.limit = query.limit;
    if (query.cursor !== undefined) q.cursor = query.cursor;
    const res = await this.http.get("/admin/approvals", { query: q });
    const b = w.asObject(await w.jsonBody(res), "approvals");
    return {
      approvals: Array.isArray(b.approvals) ? b.approvals.map(w.approvalFromJson) : [],
      nextCursor: nextCursorOf(b),
    };
  }

  /**
   * Every matching approval, newest first, following `nextCursor`. Approvals created meanwhile
   * sort above the first page and do not shift the rest.
   */
  async *approvalsIter(query: Omit<ApprovalQuery, "cursor"> = {}): AsyncGenerator<w.Approval> {
    let cursor: string | undefined;
    for (;;) {
      const page = await this.approvals({ ...query, cursor });
      yield* page.approvals;
      cursor = advance(page.nextCursor, cursor);
      if (cursor === undefined) return;
    }
  }

  /**
   * One approval: the exact call, the run's labels, state, approver and expiry. `ApiError` (404)
   * when it is unknown.
   */
  async approval(approvalId: string): Promise<w.Approval> {
    const res = await this.http.get(`/admin/approvals/${encodeURIComponent(approvalId)}`);
    return w.approvalFromJson(await w.jsonBody(res));
  }

  /**
   * Grant a pending approval as the operator (`by = "operator"`); returns it. The grant is good
   * for one retry of the identical call by the same hop. `ApiError` 409
   * (`approval_not_pending`, `approval_expired`, `lease_revoked`) when it cannot be decided any
   * more, 404 when it is unknown.
   */
  async grantApproval(approvalId: string): Promise<w.Approval> {
    return this.decideApproval(approvalId, "grant");
  }

  /** Decline a pending approval as the operator; returns it. Errors as `grantApproval`. */
  async declineApproval(approvalId: string): Promise<w.Approval> {
    return this.decideApproval(approvalId, "decline");
  }

  private async decideApproval(approvalId: string, decision: string): Promise<w.Approval> {
    const res = await this.http.post(`/admin/approvals/${encodeURIComponent(approvalId)}`, {
      json: { decision },
    });
    return w.approvalFromJson(await w.jsonBody(res));
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
    const headersNow = async (): Promise<Record<string, string>> => {
      const proofOpts = this.nonce.value === undefined ? {} : { nonce: this.nonce.value };
      return key
        ? {
            dpop: await key.proof(
              "POST",
              `${this.serverUrl}/admin/root-token`,
              undefined,
              proofOpts,
            ),
          }
        : {};
    };
    const send = (headers: Record<string, string>) =>
      this.http.post("/admin/root-token", { json: body, headers });
    let res = await send(await headersNow());
    if (key !== undefined && (await this.nonce.update(res))) {
      // `use_dpop_nonce`: retry once with the server's nonce, on a new connection if need be.
      await res.body?.cancel();
      const headers = await headersNow();
      res = await resendOnce(() => send(headers));
      await this.nonce.update(res);
    }
    return w.tokenFromResponse(await w.jsonBody(res));
  }
}

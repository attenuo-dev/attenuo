/**
 * Offline verification of an audit export.
 *
 * `verifyExport` re-checks a file written by `attenuo audit export` (or
 * `AdminClient.auditExport`) with nothing but the issuer's public keys: the SHA-256 hash chain
 * over RFC 8785 canonical JSON, the range the header declares, and the Ed25519 checkpoint
 * signatures. It follows the Rust `verify_export_with` (`attenuo audit verify --file`) rule
 * for rule, so a file gets the same verdict, and the same `firstBadSeq`, in both.
 *
 * `crossCheck` adds the SR-21 comparison with checkpoints the server shipped off the host
 * (`[audit.sink]`), the Rust `cross_check` (`attenuo audit verify --file --checkpoints`) rule for
 * rule: a checkpoint signed again after it was shipped, one deleted from the export, two
 * different shipped copies for one seq, and a shipped copy that does not verify are reported
 * with the same `seq` and reason in both.
 *
 * An export taken after a prune starts at the first retained entry, and its header carries the
 * prune's signed `anchor`. `verifyExport` checks the anchor's signature, that the file starts
 * right after it, and the prune record when it is in the file, then reports `fromAnchor` and
 * `prunedThrough`, as the Rust check does. `verifyExports` verifies several files, oldest first
 * (the archives of the prunes, then the retained export), and checks that they link into one
 * log, as `attenuo audit verify --file a --file b` does.
 *
 * A file that fails verification gives a report with `ok: false`; a file that cannot be read as
 * an export at all (no header, the wrong format, a filtered export, a line that is not JSON)
 * throws `ExportError`.
 *
 * Differences from the Rust check: it is stricter (the record is hashed as it appears in the
 * file, duplicate object members are refused) and it cannot handle integers beyond 2^53 (a
 * `seq` that large is refused with `ExportError`).
 */

import { AttenuoError } from "./errors.js";
import { canonicalize, parseJson, type JsonValue } from "./jcs.js";
import { b64urlDecode } from "./token.js";

/** First element of the array the entry hash covers. */
export const ENTRY_HASH_VERSION = "attenuo-audit-entry-v2";
/** `prev_hash` of the first entry of a log. */
export const GENESIS_HASH = "0".repeat(64);
/** Value of the header's `format` member. */
export const EXPORT_FORMAT = "attenuo-audit-export-v2";
/** Value of a shipped checkpoint's `format` member. */
export const SHIPPED_FORMAT = "attenuo-shipped-checkpoint-v1";
/** The tool of a prune's own audit record. */
export const PRUNE_TOOL = "admin.audit.prune";
/**
 * The envelope of a prune's signed anchor, shipped through the same sink (ADR-0015). Skipped by
 * `parseShipped`: this package checks the anchor in an export's header, not shipped ones.
 */
const SHIPPED_ANCHOR_FORMAT = "attenuo-shipped-anchor-v1";
const CHECKPOINT_CONTEXT = "attenuo-checkpoint-v1";
const ANCHOR_CONTEXT = "attenuo-audit-anchor-v1";

/** The input is not an audit export this version can verify. */
export class ExportError extends AttenuoError {}

export interface BadCheckpoint {
  seq: number;
  reason: string;
}

/** A prune anchor that failed verification. */
export interface BadAnchor {
  /** The `through_seq` the anchor claims. */
  throughSeq: number;
  reason: string;
}

/** Why two files given in a row to `verifyExports` do not form one log. */
export interface LinkProblem {
  /** Index of the earlier file, from 0, in the order given. */
  earlier: number;
  /** Index of the later file (`earlier + 1`). */
  later: number;
  reason: string;
}

/** The verdict of `verifyExports`. */
export interface ExportsReport {
  /** Every file verifies and every pair of neighbours links. */
  ok: boolean;
  /** Each file's own report, in the order given. */
  files: ExportReport[];
  /** Each pair of neighbouring files that does not link. */
  links: LinkProblem[];
}

/** The verdict on an export (the fields of the Rust `ExportReport`). */
export interface ExportReport {
  /** Every check passed (and, unless `allowUnsignedTail`, every entry is countersigned). */
  ok: boolean;
  /** Entries examined, including the first bad one. */
  entries: number;
  /** Seq of the first entry that fails the chain walk (undefined if the chain is intact). */
  firstBadSeq: number | undefined;
  /** Checkpoints in the file. */
  checkpoints: number;
  /** Highest seq with a valid checkpoint. */
  lastSignedSeq: number | undefined;
  /** Entries after `lastSignedSeq`, covered by the hash chain only. */
  unsignedTail: number;
  badCheckpoints: BadCheckpoint[];
  /** Seq of the first and last entry in the file. */
  firstSeq: number | undefined;
  lastSeq: number | undefined;
  /** The file starts at seq 1 with the genesis `prev_hash`. */
  fromGenesis: boolean;
  /** Entries of the header's range are missing from the start or end of the file. */
  truncated: boolean;
  /** Entries whose seq is outside the header's `from..=to`. */
  outsideRange: number;
  /** Failed only because of an unsigned tail that `allowUnsignedTail` did not accept. */
  unsignedTailRejected: boolean;
  /**
   * The header carries a prune anchor whose signature verifies, and the file starts right after
   * it (its first entry is `through_seq + 1` with `prev_hash` equal to `through_hash`): the
   * entries before were pruned through the server.
   */
  fromAnchor: boolean;
  /** The anchor's `through_seq` when the walk started from a valid header anchor. */
  prunedThrough: number | undefined;
  /** Anchors in the header (0 or 1). */
  anchors: number;
  /** The header's anchor, when it does not verify or does not fit the file. */
  badAnchors: BadAnchor[];
}

/** One parsed line of a shipped-checkpoint file. */
export interface ShippedLine {
  /** 1-based line number in the file. */
  line: number;
  /** The five checkpoint members. */
  checkpoint: CheckpointFields;
  /** Set when the line was an envelope that does not match its own checkpoint. */
  inconsistency: string | undefined;
}

/** `seq`, `head_hash`, `at`, `kid` and `signature` of a checkpoint. */
export interface CheckpointFields {
  seq: number;
  head_hash: string;
  at: string;
  kid: string;
  signature: string;
}

/** A shipped checkpoint the export disagrees with, or one that is unusable. */
export interface ShippedMismatch {
  seq: number;
  /** Line of the shipped file. */
  line: number;
  reason: string;
}

/** The verdict of `crossCheck` (the fields of the Rust `CrossCheckReport`). */
export interface CrossCheckReport {
  /** Lines in the shipped file. */
  shipped: number;
  /** Shipped checkpoints whose seq lies in the export header's `from..=to` (checked). */
  inRange: number;
  /** Of those, the ones the export agrees with. */
  matched: number;
  /**
   * Shipped checkpoints past the export's range: not checked. If the export was taken up to the
   * head of the log, these say the log is shorter than what was shipped.
   */
  beyondRange: number;
  /** Highest seq in the shipped file. */
  lastShippedSeq: number | undefined;
  /** In the order of the shipped file; the first is the first offending seq. */
  mismatches: ShippedMismatch[];
  /** No mismatches. */
  ok: boolean;
}

/** An export to verify. */
export type ExportSource =
  /** The export text: JSON Lines, or the single-object JSON form. */
  | string
  | Uint8Array
  /** Lines (each `string` or UTF-8 `Uint8Array`, with or without the trailing newline). */
  | Iterable<string | Uint8Array>
  /** A file to read (Node.js). */
  | { path: string };

export interface VerifyExportOptions {
  /**
   * The issuer's JWKS (`{ keys: [...] }`, as served at `/.well-known/jwks.json`), or a map of
   * `kid` to the raw 32-byte Ed25519 public key or its base64url `x`.
   */
  checkpointPublicKeys: { keys: unknown[] } | Record<string, Uint8Array | string>;
  /**
   * Accept entries after the last valid checkpoint, which only the hash chain covers (an export
   * taken while the log was ahead of its newest checkpoint). Default false.
   */
  allowUnsignedTail?: boolean;
}

type Obj = { [key: string]: JsonValue };
interface Entry extends Obj {
  seq: number;
  prev_hash: string;
  entry_hash: string;
  record: Obj;
}
interface Checkpoint extends Obj {
  seq: number;
  head_hash: string;
  at: string;
  kid: string;
  signature: string;
}
interface Anchor extends Obj {
  through_seq: number;
  through_hash: string;
  prune_seq: number;
  prune_entry_hash: string;
  previous_through_seq: number | null;
  archive_sha256: string | null;
  at: string;
  kid: string;
  signature: string;
}
interface Parsed {
  header: Obj;
  entries: Entry[];
  checkpoints: Checkpoint[];
}

const enc = new TextEncoder();

async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * SHA-256 (hex) of the RFC 8785 canonical JSON of
 * `["attenuo-audit-entry-v2", seq, prevHash, record]`.
 */
export function entryHash(seq: number, prevHash: string, record: unknown): Promise<string> {
  return sha256Hex(canonicalize([ENTRY_HASH_VERSION, seq, prevHash, record]));
}

/**
 * Verify an audit export offline. Strict like `attenuo audit verify --file`: the header is
 * required, entries outside its `from..=to` fail, a file short of that range fails, and so do
 * entries after the last valid checkpoint unless `allowUnsignedTail` is set.
 */
export async function verifyExport(
  source: ExportSource,
  opts: VerifyExportOptions,
): Promise<ExportReport> {
  const keys = loadKeys(opts.checkpointPublicKeys);
  return verifyParsed(parse(await readText(source)), keys, opts.allowUnsignedTail === true);
}

/**
 * Verify several exports, oldest first, as one log: `attenuo audit verify --file a --file b`.
 * Each file is verified strictly on its own (`allowUnsignedTail` applies to the last file
 * only), then each file and the next must link: both hold entries, the seqs are contiguous, the
 * later file's first `prev_hash` is the earlier file's last entry hash, the earlier file has a
 * checkpoint at its last seq naming that hash, and an anchor in the later file's header names
 * the earlier file's end.
 */
export async function verifyExports(
  sources: Iterable<ExportSource>,
  opts: VerifyExportOptions,
): Promise<ExportsReport> {
  const keys = loadKeys(opts.checkpointPublicKeys);
  const parsed: Parsed[] = [];
  for (const src of sources) parsed.push(parse(await readText(src)));
  const files: ExportReport[] = [];
  for (const [i, p] of parsed.entries()) {
    files.push(
      await verifyParsed(p, keys, opts.allowUnsignedTail === true && i === parsed.length - 1),
    );
  }
  const links = linkProblems(parsed);
  return { ok: files.every((f) => f.ok) && links.length === 0, files, links };
}

function linkProblems(parsed: Parsed[]): LinkProblem[] {
  const out: LinkProblem[] = [];
  for (let i = 0; i + 1 < parsed.length; i++) {
    const a = parsed[i] as Parsed;
    const b = parsed[i + 1] as Parsed;
    const fail = (reason: string): void => {
      out.push({ earlier: i, later: i + 1, reason });
    };
    const last = a.entries[a.entries.length - 1];
    const first = b.entries[0];
    if (last === undefined || first === undefined) {
      fail(
        last === undefined
          ? "the earlier file holds no entries"
          : "the later file holds no entries",
      );
      continue;
    }
    if (last.seq + 1 !== first.seq) {
      fail(
        `the seqs are not contiguous: the earlier file ends at seq ${last.seq}, the later one ` +
          `starts at seq ${first.seq}`,
      );
    } else if (first.prev_hash !== last.entry_hash) {
      fail(
        `the later file's first entry (seq ${first.seq}) does not link to the earlier file's ` +
          `last (its prev_hash is not the entry hash at seq ${last.seq})`,
      );
    }
    const cp = a.checkpoints.find((c) => c.seq === last.seq);
    if (cp === undefined) {
      fail(`the earlier file does not end at a checkpoint: none at its last seq ${last.seq}`);
    } else if (cp.head_hash !== last.entry_hash) {
      fail(
        `the earlier file's checkpoint at its last seq ${last.seq} names another hash than ` +
          "its entry",
      );
    }
    const an = b.header.anchor as Anchor | undefined | null;
    if (an && (an.through_seq !== last.seq || an.through_hash !== last.entry_hash)) {
      fail(
        `the later file's header anchor is through seq ${an.through_seq}, not the earlier ` +
          `file's end at seq ${last.seq} and its hash`,
      );
    }
  }
  return out;
}

async function verifyParsed(
  parsed: Parsed,
  keys: Map<string, Uint8Array>,
  allowUnsignedTail: boolean,
): Promise<ExportReport> {
  const { header, entries, checkpoints: cps } = parsed;
  const from = header.from as number;
  const to = header.to as number;

  const first = entries[0];
  const lastEntry = entries[entries.length - 1];
  const firstSeq = first?.seq;
  const lastSeq = lastEntry?.seq;
  const fromGenesis = firstSeq === 1 && first?.prev_hash === GENESIS_HASH;
  // An anchor in the header: checked here, and the walk starts where it says.
  const anchor = (header.anchor ?? undefined) as Anchor | undefined;
  const badAnchors: BadAnchor[] = [];
  if (anchor !== undefined) {
    let reason = await verifyAnchor(anchor, keys);
    if (reason === undefined && anchor.through_seq + 1 !== from) {
      reason =
        `the header's anchor is through seq ${anchor.through_seq}, but the export starts at ` +
        `${from}`;
    }
    if (reason === undefined) {
      const rec = entries.find((e) => e.seq === anchor.prune_seq);
      if (rec !== undefined) reason = await checkPruneRecord(anchor, rec);
    }
    if (reason !== undefined) badAnchors.push({ throughSeq: anchor.through_seq, reason });
  }
  const startAnchor = badAnchors.length === 0 ? anchor : undefined;
  const genesis = startAnchor === undefined && firstSeq === 1;
  const fromAnchor =
    startAnchor !== undefined &&
    first !== undefined &&
    first.seq === startAnchor.through_seq + 1 &&
    first.prev_hash === startAnchor.through_hash;
  const lo = firstSeq ?? 0;
  const hi = lastSeq ?? 0;
  const inside = cps.filter((c) => c.seq >= lo && c.seq <= hi);

  // Hash chain.
  const wanted = new Set(inside.map((c) => c.seq));
  const okHashes = new Map<number, string>();
  let count = 0;
  let okCount = 0;
  let lastOk: number | undefined;
  let firstBad: number | undefined;
  let expectedSeq = startAnchor === undefined ? 1 : startAnchor.through_seq + 1;
  let expectedPrev = startAnchor === undefined ? GENESIS_HASH : startAnchor.through_hash;
  for (const [i, e] of entries.entries()) {
    count++;
    if (i === 0 && !genesis && startAnchor === undefined) {
      expectedSeq = e.seq;
      expectedPrev = e.prev_hash;
    }
    const good = e.seq === expectedSeq && e.prev_hash === expectedPrev && (await hashMatches(e));
    if (!good) {
      firstBad = e.seq;
      break;
    }
    lastOk = e.seq;
    okCount++;
    if (wanted.has(e.seq)) okHashes.set(e.seq, e.entry_hash);
    expectedSeq = e.seq + 1;
    expectedPrev = e.entry_hash;
  }
  const chainOk = firstBad === undefined;

  // Checkpoints inside the entry window must match an entry hash.
  const bad: BadCheckpoint[] = [];
  let lastSigned: number | undefined;
  for (const cp of [...inside].sort((a, b) => a.seq - b.seq)) {
    const reason = await verifyCheckpoint(cp, keys);
    if (reason !== undefined) {
      bad.push({ seq: cp.seq, reason });
      continue;
    }
    const actual = cp.seq === 0 ? (genesis ? GENESIS_HASH : undefined) : okHashes.get(cp.seq);
    if (actual !== undefined && actual === cp.head_hash) {
      lastSigned = lastSigned === undefined ? cp.seq : Math.max(lastSigned, cp.seq);
    } else if (actual !== undefined) {
      bad.push({ seq: cp.seq, reason: "head hash differs from the log at that seq" });
    } else if (chainOk && (lastOk === undefined || cp.seq > lastOk)) {
      bad.push({ seq: cp.seq, reason: "log ends before this checkpoint (truncated)" });
    }
  }
  // Outside the window the signature is still checked.
  for (const cp of cps) {
    if (cp.seq < lo || cp.seq > hi) {
      const reason = await verifyCheckpoint(cp, keys);
      if (reason !== undefined) bad.push({ seq: cp.seq, reason });
    }
  }

  let unsignedTail = 0;
  if (lastOk !== undefined && lastSigned !== undefined) {
    unsignedTail = Math.max(lastOk - lastSigned, 0);
  } else if (lastOk !== undefined) {
    unsignedTail = okCount;
  }

  const truncated =
    firstSeq !== undefined && lastSeq !== undefined
      ? firstSeq !== from || lastSeq < to
      : to >= from && to > 0;
  const outsideRange = entries.filter((e) => e.seq < from || e.seq > to).length;
  const unsignedTailRejected = unsignedTail > 0 && !allowUnsignedTail;
  const ok =
    chainOk &&
    bad.length === 0 &&
    badAnchors.length === 0 &&
    !truncated &&
    outsideRange === 0 &&
    !unsignedTailRejected;
  return {
    ok,
    entries: count,
    firstBadSeq: firstBad,
    checkpoints: cps.length,
    lastSignedSeq: lastSigned,
    unsignedTail,
    badCheckpoints: bad,
    firstSeq,
    lastSeq,
    fromGenesis,
    truncated,
    outsideRange,
    unsignedTailRejected,
    fromAnchor,
    prunedThrough: startAnchor?.through_seq,
    anchors: anchor === undefined ? 0 : 1,
    badAnchors,
  };
}

const CP_FIELDS = ["seq", "head_hash", "at", "kid", "signature"] as const;

function cp5(c: Checkpoint): CheckpointFields {
  return { seq: c.seq, head_hash: c.head_hash, at: c.at, kid: c.kid, signature: c.signature };
}

const sameCheckpoint = (a: CheckpointFields, b: CheckpointFields): boolean =>
  CP_FIELDS.every((k) => a[k] === b[k]);

/**
 * Parse a JSONL file of shipped checkpoints (`[audit.sink]` file output).
 *
 * A line is the sink's envelope (`format`, `checkpoint`, `kid`, `signature`,
 * `checkpoint_sha256`) or a bare checkpoint (an export's `checkpoint` line, or
 * `GET /admin/audit/checkpoint` saved by an operator's own job). Blank lines are skipped, and
 * so are lines whose `format` is `attenuo-shipped-anchor-v1` (the signed anchor of a prune,
 * which the sink ships with the checkpoints); anything else throws `ExportError`. An envelope that disagrees with its own checkpoint is not
 * an error here: the line carries `inconsistency` and `crossCheck` reports it.
 */
export async function parseShipped(source: ExportSource): Promise<ShippedLine[]> {
  const out: ShippedLine[] = [];
  for (const [n, raw] of (await readText(source)).split("\n").entries()) {
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    if (line.trim() === "") continue;
    const where = `shipped checkpoints, line ${n + 1}`;
    const obj = parseLine(line, where);
    if (!isObj(obj)) throw new ExportError(`${where}: not a JSON object`);
    if (obj.format === SHIPPED_ANCHOR_FORMAT) continue;
    if ("checkpoint" in obj) {
      need(obj, where, { format: "str", kid: "str", signature: "str", checkpoint_sha256: "str" });
      if (
        obj.public_url !== undefined &&
        obj.public_url !== null &&
        typeof obj.public_url !== "string"
      ) {
        throw new ExportError(`${where}: \`public_url\` must be a string`);
      }
      if (!isObj(obj.checkpoint))
        throw new ExportError(`${where}: \`checkpoint\` must be an object`);
      const cp = cp5(toCheckpoint(obj.checkpoint, where));
      out.push({ line: n + 1, checkpoint: cp, inconsistency: await inconsistency(obj, cp) });
    } else {
      const { type, ...rest } = obj;
      if (type !== undefined && type !== "checkpoint") {
        throw new ExportError(`${where}: not a checkpoint line (type ${JSON.stringify(type)})`);
      }
      out.push({
        line: n + 1,
        checkpoint: cp5(toCheckpoint(rest, where)),
        inconsistency: undefined,
      });
    }
  }
  return out;
}

async function inconsistency(env: Obj, cp: CheckpointFields): Promise<string | undefined> {
  if (env.format !== SHIPPED_FORMAT) return `unsupported format \`${String(env.format)}\``;
  if (env.kid !== cp.kid || env.signature !== cp.signature) {
    return "`kid` or `signature` differs from the checkpoint's own";
  }
  if (env.checkpoint_sha256 !== (await sha256Hex(canonicalize(cp)))) {
    return "`checkpoint_sha256` does not match the checkpoint";
  }
  return undefined;
}

/**
 * Compare an audit export with checkpoints shipped off the host (SR-21).
 *
 * A signed checkpoint proves the log prefix `1..=seq` hashed to `head_hash`, but it is signed
 * with the server's own key: someone who holds the host and that key can rewrite the log and
 * sign fresh checkpoints, and the export then verifies. A copy of the original checkpoint that
 * already left the host (the checkpoint sink) is what they cannot change.
 *
 * For each shipped checkpoint inside the export's declared range:
 *
 * - it must verify against the keys (a forged shipped copy would otherwise be trusted);
 * - the export must hold a checkpoint at that seq, identical in every member: a different one
 *   was **signed again after shipping**, none at all means it was **deleted**;
 * - the export's entry at that seq must hash to the shipped `head_hash`.
 *
 * Two different shipped checkpoints for one seq are reported too, and so is an envelope whose
 * `kid`, `signature` or `checkpoint_sha256` disagrees with its checkpoint. This does not
 * replace `verifyExport`: run both.
 */
export async function crossCheck(
  exportSource: ExportSource,
  shippedSource: ExportSource,
  opts: Pick<VerifyExportOptions, "checkpointPublicKeys">,
): Promise<CrossCheckReport> {
  const keys = loadKeys(opts.checkpointPublicKeys);
  const { header, entries, checkpoints } = parse(await readText(exportSource));
  const shipped = await parseShipped(shippedSource);
  const from = header.from as number;
  const to = header.to as number;
  const exported = new Map(checkpoints.map((c) => [c.seq, cp5(c)]));
  const entryHashes = new Map(entries.map((e) => [e.seq, e.entry_hash]));
  const firstBySeq = new Map<number, ShippedLine>();
  const mismatches: ShippedMismatch[] = [];
  let inRange = 0;
  let matched = 0;
  let beyond = 0;
  for (const s of shipped) {
    const cp = s.checkpoint;
    const fail = (reason: string): void => {
      mismatches.push({ seq: cp.seq, line: s.line, reason });
    };
    if (s.inconsistency !== undefined) {
      fail(`shipped envelope is inconsistent: ${s.inconsistency}`);
      continue;
    }
    const prev = firstBySeq.get(cp.seq);
    if (prev === undefined) {
      firstBySeq.set(cp.seq, s);
    } else if (!sameCheckpoint(prev.checkpoint, cp)) {
      fail(
        "the sink holds two different checkpoints for this seq " +
          `(lines ${prev.line} and ${s.line}): ` +
          "the seq was signed again after the first was shipped",
      );
      continue;
    } // else: a retried delivery, same content
    if (cp.seq > to) {
      beyond++;
      continue;
    }
    if (cp.seq < from && !(cp.seq === 0 && from <= 1)) continue;
    inRange++;
    const why = await verifyCheckpoint(cp, keys);
    if (why !== undefined) {
      fail(`shipped checkpoint does not verify: ${why}`);
      continue;
    }
    const problems: string[] = [];
    const e = exported.get(cp.seq);
    if (e === undefined) {
      problems.push("the export has no checkpoint at this seq (deleted after shipping)");
    } else if (!sameCheckpoint(e, cp)) {
      const diff = (["head_hash", "signature", "at", "kid"] as const).filter((k) => e[k] !== cp[k]);
      problems.push(
        "RE-SIGNED after shipping: the export's checkpoint at this seq differs in " +
          diff.join(", "),
      );
    }
    if (cp.seq > 0) {
      const h = entryHashes.get(cp.seq);
      if (h === undefined) {
        problems.push("the export has no entry at this seq");
      } else if (h !== cp.head_hash) {
        problems.push(
          "the export's entry at this seq does not hash to the shipped head_hash " +
            "(history rewritten after shipping)",
        );
      }
    }
    if (problems.length === 0) matched++;
    else fail(problems.join("; "));
  }
  return {
    shipped: shipped.length,
    inRange,
    matched,
    beyondRange: beyond,
    lastShippedSeq:
      shipped.length > 0 ? Math.max(...shipped.map((s) => s.checkpoint.seq)) : undefined,
    mismatches,
    ok: mismatches.length === 0,
  };
}

async function hashMatches(e: Entry): Promise<boolean> {
  try {
    return (await entryHash(e.seq, e.prev_hash, e.record)) === e.entry_hash;
  } catch {
    return false;
  }
}

// ---- parsing -------------------------------------------------------------------------------

async function readText(src: ExportSource): Promise<string> {
  const dec = new TextDecoder("utf-8", { fatal: true });
  try {
    if (typeof src === "string") return src;
    if (src instanceof Uint8Array) return dec.decode(src);
    if ("path" in src) {
      const { readFile } = await import("node:fs/promises");
      return dec.decode(await readFile(src.path));
    }
    let out = "";
    for (const line of src) {
      const s = typeof line === "string" ? line : dec.decode(line);
      out += s.endsWith("\n") ? s : `${s}\n`;
    }
    return out;
  } catch (e) {
    throw new ExportError(`cannot read the export: ${(e as Error).message}`);
  }
}

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isUint = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

function need(o: Obj, where: string, spec: Record<string, "uint" | "str">): void {
  for (const [name, kind] of Object.entries(spec)) {
    const v = o[name];
    if (kind === "uint" ? !isUint(v) : typeof v !== "string") {
      throw new ExportError(
        `${where}: \`${name}\` must be ${kind === "uint" ? "a non-negative integer" : "a string"}`,
      );
    }
  }
}

function parseLine(text: string, where: string): JsonValue {
  try {
    return parseJson(text);
  } catch (e) {
    throw new ExportError(`${where}: ${(e as Error).message}`);
  }
}

function parse(text: string): Parsed {
  let header: Obj | undefined;
  const entries: Entry[] = [];
  const checkpoints: Checkpoint[] = [];
  let whole: JsonValue | undefined;
  if (text.trimStart().startsWith("{")) {
    try {
      whole = parseJson(text);
    } catch {
      whole = undefined;
    }
  }
  if (isObj(whole) && !("type" in whole)) {
    if (whole.header !== undefined) header = whole.header as Obj;
    const rawEntries = whole.entries ?? [];
    const rawCps = whole.checkpoints ?? [];
    if (!Array.isArray(rawEntries) || !Array.isArray(rawCps)) {
      throw new ExportError("`entries` and `checkpoints` must be arrays");
    }
    rawEntries.forEach((e, i) => entries.push(toEntry(e, `entries[${i}]`)));
    rawCps.forEach((c, i) => checkpoints.push(toCheckpoint(c, `checkpoints[${i}]`)));
  } else {
    for (const [n, raw] of text.split("\n").entries()) {
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (line.trim() === "") continue;
      const where = `line ${n + 1}`;
      const obj = parseLine(line, where);
      if (!isObj(obj)) throw new ExportError(`${where}: not a JSON object`);
      const kind = obj.type;
      if (kind === "header") {
        if (header !== undefined) throw new ExportError(`${where}: second header`);
        header = obj;
      } else if (kind === "entry") {
        entries.push(toEntry(obj, where));
      } else if (kind === "checkpoint") {
        checkpoints.push(toCheckpoint(obj, where));
      } else {
        throw new ExportError(`${where}: unknown line type ${JSON.stringify(kind)}`);
      }
    }
  }
  if (header === undefined) {
    throw new ExportError(
      "the export has no header line; the header declares the range of entries the file holds",
    );
  }
  return { header: checkHeader(header), entries, checkpoints };
}

function checkHeader(h: unknown): Obj {
  if (!isObj(h)) throw new ExportError("the header must be an object");
  need(h, "header", { format: "str", exported_at: "str", from: "uint", to: "uint" });
  if (h.format === "attenuo-audit-export-v1") {
    throw new ExportError(
      "export format `attenuo-audit-export-v1` was written by an earlier attenuo whose entry " +
        `hashes were not RFC 8785 canonical; this version verifies only \`${EXPORT_FORMAT}\` ` +
        "(export the log again with this version)",
    );
  }
  if (h.format !== EXPORT_FORMAT) {
    throw new ExportError(
      `unsupported export format \`${String(h.format)}\` (expected \`${EXPORT_FORMAT}\`)`,
    );
  }
  if (h.filter !== undefined && h.filter !== null) {
    throw new ExportError(
      "the export is filtered (its header has a `filter`), so its hash chain has gaps and " +
        "nothing proves it is complete; verify an export taken without kind, chain_id, tool " +
        "or decision filters, then filter that",
    );
  }
  if (h.anchor !== undefined && h.anchor !== null) checkAnchor(h.anchor);
  return h;
}

function checkAnchor(a: unknown): void {
  if (!isObj(a)) throw new ExportError("header: `anchor` must be an object");
  const where = "header anchor";
  need(a, where, {
    through_seq: "uint",
    through_hash: "str",
    prune_seq: "uint",
    prune_entry_hash: "str",
    at: "str",
    kid: "str",
    signature: "str",
  });
  const prev = a.previous_through_seq;
  if (prev !== undefined && prev !== null && !isUint(prev)) {
    throw new ExportError(
      `${where}: \`previous_through_seq\` must be a non-negative integer or null`,
    );
  }
  const digest = a.archive_sha256;
  if (digest !== undefined && digest !== null && typeof digest !== "string") {
    throw new ExportError(`${where}: \`archive_sha256\` must be a string or null`);
  }
}

function toEntry(e: unknown, where: string): Entry {
  if (!isObj(e)) throw new ExportError(`${where}: not a JSON object`);
  need(e, where, { seq: "uint", prev_hash: "str", entry_hash: "str" });
  if (!isObj(e.record)) throw new ExportError(`${where}: \`record\` must be an object`);
  return e as Entry;
}

function toCheckpoint(c: unknown, where: string): Checkpoint {
  if (!isObj(c)) throw new ExportError(`${where}: not a JSON object`);
  need(c, where, { seq: "uint", head_hash: "str", at: "str", kid: "str", signature: "str" });
  return c as Checkpoint;
}

// ---- checkpoints ---------------------------------------------------------------------------

/** Strict unpadded base64url: no padding, no stray characters, no non-zero trailing bits. */
function b64urlStrict(text: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return undefined;
  let raw: Uint8Array;
  try {
    raw = b64urlDecode(text);
  } catch {
    return undefined;
  }
  const again = btoa(String.fromCharCode(...raw))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return again === text ? raw : undefined;
}

function rawKey(kid: string, v: unknown): Uint8Array {
  const raw = typeof v === "string" ? b64urlStrict(v) : v instanceof Uint8Array ? v : undefined;
  if (raw === undefined || raw.length !== 32) {
    throw new ExportError(`key \`${kid}\`: an Ed25519 public key is 32 bytes (raw, or base64url)`);
  }
  return raw;
}

function loadKeys(src: VerifyExportOptions["checkpointPublicKeys"]): Map<string, Uint8Array> {
  const keys = new Map<string, Uint8Array>();
  const list = (src as { keys?: unknown }).keys;
  if (Array.isArray(list)) {
    for (const k of list) {
      if (!isObj(k) || k.kty !== "OKP" || k.crv !== "Ed25519") continue;
      if (typeof k.kid === "string" && typeof k.x === "string") {
        keys.set(k.kid, rawKey(k.kid, k.x));
      }
    }
    return keys;
  }
  for (const [kid, v] of Object.entries(src)) keys.set(kid, rawKey(kid, v));
  return keys;
}

/** Undefined when the signature verifies, else why not. */
function verifyCheckpoint(
  cp: CheckpointFields,
  keys: Map<string, Uint8Array>,
): Promise<string | undefined> {
  const payload = canonicalize([cp.seq, cp.head_hash, cp.at, cp.kid]);
  return verifySigned(cp.kid, CHECKPOINT_CONTEXT, payload, cp.signature, keys);
}

/**
 * The anchor's signature: over the RFC 8785 JSON of `[through_seq, through_hash, prune_seq,
 * prune_entry_hash, previous_through_seq, archive_sha256, at, kid]`, framed with the anchor
 * context.
 */
function verifyAnchor(a: Anchor, keys: Map<string, Uint8Array>): Promise<string | undefined> {
  const payload = canonicalize([
    a.through_seq,
    a.through_hash,
    a.prune_seq,
    a.prune_entry_hash,
    a.previous_through_seq ?? null,
    a.archive_sha256 ?? null,
    a.at,
    a.kid,
  ]);
  return verifySigned(a.kid, ANCHOR_CONTEXT, payload, a.signature, keys);
}

/**
 * `undefined` when `e` is the anchor's prune record: at `prune_seq`, hashing to
 * `prune_entry_hash`, an allowed admin record of `PRUNE_TOOL` by the server, whose
 * `arguments_digest` is that of the anchor's values.
 */
async function checkPruneRecord(a: Anchor, e: Entry): Promise<string | undefined> {
  const r = e.record;
  if (e.seq !== a.prune_seq || e.entry_hash !== a.prune_entry_hash) {
    return "the entry at prune_seq does not hash to prune_entry_hash";
  }
  if (
    r.kind !== "admin" ||
    r.tool !== PRUNE_TOOL ||
    r.server !== "attenuo" ||
    r.decision !== "allow"
  ) {
    return `the entry at prune_seq is not an allowed \`${PRUNE_TOOL}\` admin record`;
  }
  const digest = await sha256Hex(
    canonicalize({
      through_seq: a.through_seq,
      through_hash: a.through_hash,
      previous_through_seq: a.previous_through_seq ?? null,
      archive_sha256: a.archive_sha256 ?? null,
    }),
  );
  if (r.arguments_digest !== digest) {
    return "the prune record's arguments digest does not match the anchor";
  }
  return undefined;
}

async function verifySigned(
  kid: string,
  context: string,
  payloadText: string,
  signature: string,
  keys: Map<string, Uint8Array>,
): Promise<string | undefined> {
  const key = keys.get(kid);
  if (key === undefined) return `unknown signing key \`${kid}\``;
  const sig = b64urlStrict(signature);
  if (sig === undefined) return "signature does not verify";
  const ctx = enc.encode(context);
  const payload = enc.encode(payloadText);
  const msg = new Uint8Array(4 + ctx.length + payload.length);
  new DataView(msg.buffer).setUint32(0, ctx.length);
  msg.set(ctx, 4);
  msg.set(payload, 4 + ctx.length);
  try {
    const pub = await crypto.subtle.importKey("raw", key as BufferSource, "Ed25519", false, [
      "verify",
    ]);
    return (await crypto.subtle.verify("Ed25519", pub, sig as BufferSource, msg))
      ? undefined
      : "signature does not verify";
  } catch {
    return "signature does not verify";
  }
}

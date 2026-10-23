/**
 * Offline verification of an audit export.
 *
 * `verifyExport` re-checks a file written by `attenuo audit export` (or
 * `AdminClient.auditExport`) with nothing but the issuer's public keys: the SHA-256 hash chain
 * over RFC 8785 canonical JSON, the range the header declares, and the Ed25519 checkpoint
 * signatures. It follows the Rust `verify_export_with` (`attenuo audit verify --file`) rule
 * for rule, so a file gets the same verdict, and the same `firstBadSeq`, in both.
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
const CHECKPOINT_CONTEXT = "attenuo-checkpoint-v1";

/** The input is not an audit export this version can verify. */
export class ExportError extends AttenuoError {}

export interface BadCheckpoint {
  seq: number;
  reason: string;
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
  const { header, entries, checkpoints: cps } = parse(await readText(source));
  const from = header.from as number;
  const to = header.to as number;

  const first = entries[0];
  const lastEntry = entries[entries.length - 1];
  const firstSeq = first?.seq;
  const lastSeq = lastEntry?.seq;
  const fromGenesis = firstSeq === 1 && first?.prev_hash === GENESIS_HASH;
  const anchored = firstSeq === 1;
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
  let expectedSeq = 1;
  let expectedPrev = GENESIS_HASH;
  for (const [i, e] of entries.entries()) {
    count++;
    if (i === 0 && !anchored) {
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
    const actual = cp.seq === 0 ? (anchored ? GENESIS_HASH : undefined) : okHashes.get(cp.seq);
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
  const unsignedTailRejected = unsignedTail > 0 && !opts.allowUnsignedTail;
  const ok =
    chainOk && bad.length === 0 && !truncated && outsideRange === 0 && !unsignedTailRejected;
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

function parse(text: string): { header: Obj; entries: Entry[]; checkpoints: Checkpoint[] } {
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
        "nothing proves it is complete; verify an export taken without kind and chain_id " +
        "filters, then filter that",
    );
  }
  return h;
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
async function verifyCheckpoint(
  cp: Checkpoint,
  keys: Map<string, Uint8Array>,
): Promise<string | undefined> {
  const key = keys.get(cp.kid);
  if (key === undefined) return `unknown signing key \`${cp.kid}\``;
  const sig = b64urlStrict(cp.signature);
  if (sig === undefined) return "signature does not verify";
  const ctx = enc.encode(CHECKPOINT_CONTEXT);
  const payload = enc.encode(canonicalize([cp.seq, cp.head_hash, cp.at, cp.kid]));
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

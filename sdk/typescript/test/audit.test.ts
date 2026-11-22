import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  ExportError,
  PRUNE_TOOL,
  SHIPPED_ANCHOR_FORMAT,
  SHIPPED_FORMAT,
  crossCheck,
  parseShipped,
  parseShippedAnchors,
  verifyExport,
  verifyExports,
  type AnchorCheckReport,
  type CrossCheckReport,
  type ExportReport,
  type ShippedMismatch,
  type VerifyExportOptions,
} from "../src/index.js";
import { entryHash, EXPORT_FORMAT, GENESIS_HASH } from "../src/audit.js";
import { canonicalize } from "../src/jcs.js";
import { b64 } from "./helpers.js";

type Obj = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

let priv: CryptoKey;
let jwks: { keys: Obj[] };
let rawPub: Uint8Array;
const KID = "k1";

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  priv = pair.privateKey;
  rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  jwks = { keys: [{ kty: "OKP", crv: "Ed25519", kid: KID, x: b64(rawPub) }] };
});

// The same record and hash are asserted by the Rust test `entry_hash_golden_vector` and by
// sdk/python/tests/test_audit.py.
const GOLDEN_RECORD = {
  agents: ["agent:planner"],
  arguments_digest: "ab".repeat(32),
  chain_depth: 1,
  chain_digest: "cd".repeat(32),
  chain_id: "l1",
  decision: "allow",
  id: "00000000-0000-4000-8000-000000000001",
  kind: "decision",
  leases: ["l1"],
  originating_subject: "user:mudit",
  reason: "policy_allow",
  server: "github",
  tool: "read_file",
  at: "2026-10-23T12:00:00Z",
};
const GOLDEN_HASH = "e8ababad86538918f6eee2d5edb7e6aa4bfa8f8f6ea032f2b5fde00dfe52d693";

const record = (i: number, kind = "decision"): Obj => ({
  ...GOLDEN_RECORD,
  kind,
  reason: `r${i}`,
  tool: `t${i}`,
});

async function sign(seq: number, head: string, kid = KID, key?: CryptoKey): Promise<Obj> {
  const at = "2026-10-23T12:00:00Z";
  const ctx = new TextEncoder().encode("attenuo-checkpoint-v1");
  const payload = new TextEncoder().encode(canonicalize([seq, head, at, kid]));
  const msg = new Uint8Array(4 + ctx.length + payload.length);
  new DataView(msg.buffer).setUint32(0, ctx.length);
  msg.set(ctx, 4);
  msg.set(payload, 4 + ctx.length);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key ?? priv, msg));
  return { seq, head_hash: head, at, kid, signature: b64(sig) };
}

async function makeExport(
  n = 6,
  { start = 1, cps = [3, 6] }: { start?: number; cps?: number[] } = {},
): Promise<Obj[]> {
  let prev = start === 1 ? GENESIS_HASH : "ee".repeat(32);
  const entries: Obj[] = [];
  for (let seq = start; seq < start + n; seq++) {
    const h = await entryHash(seq, prev, record(seq));
    entries.push({ type: "entry", seq, prev_hash: prev, record: record(seq), entry_hash: h });
    prev = h;
  }
  const header = {
    type: "header",
    format: EXPORT_FORMAT,
    from: start,
    to: start + n - 1,
    exported_at: "2026-10-23T12:00:00Z",
  };
  const bySeq = new Map(entries.map((e) => [e.seq as number, e.entry_hash as string]));
  const cpLines: Obj[] = [];
  for (const s of cps) {
    if (bySeq.has(s)) cpLines.push({ type: "checkpoint", ...(await sign(s, bySeq.get(s)!)) });
  }
  return [header, ...entries, ...cpLines];
}

const lines = (objs: Obj[]): string[] => objs.map((o) => JSON.stringify(o) + "\n");
const verify = (objs: Obj[], o: Partial<VerifyExportOptions> = {}): Promise<ExportReport> =>
  verifyExport(lines(objs), { checkpointPublicKeys: jwks, ...o });

describe("verifyExport", () => {
  it("matches the Rust entry hash", async () => {
    expect(await entryHash(7, "11".repeat(32), GOLDEN_RECORD)).toBe(GOLDEN_HASH);
  });

  it("verifies a clean export from lines, text, bytes, a path and the JSON form", async () => {
    const objs = await makeExport();
    const r = await verify(objs);
    expect(r).toMatchObject({
      ok: true,
      entries: 6,
      firstBadSeq: undefined,
      firstSeq: 1,
      lastSeq: 6,
      fromGenesis: true,
      checkpoints: 2,
      lastSignedSeq: 6,
      unsignedTail: 0,
    });
    const text = lines(objs).join("");
    const o = { checkpointPublicKeys: jwks };
    expect((await verifyExport(text, o)).ok).toBe(true);
    expect((await verifyExport(new TextEncoder().encode(text), o)).ok).toBe(true);
    const dir = mkdtempSync(join(tmpdir(), "ob-audit-"));
    try {
      const path = join(dir, "e.jsonl");
      writeFileSync(path, text);
      expect((await verifyExport({ path }, o)).ok).toBe(true);
      await expect(verifyExport({ path: join(dir, "nope") }, o)).rejects.toThrow(/cannot read/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    const form = {
      header: objs[0],
      entries: objs.filter((x) => x.type === "entry"),
      checkpoints: objs.filter((x) => x.type === "checkpoint"),
    };
    expect((await verifyExport(JSON.stringify(form, null, 2), o)).ok).toBe(true);
  });

  it("takes keys as a kid map of raw or base64url keys", async () => {
    const text = lines(await makeExport()).join("");
    for (const keys of [{ [KID]: rawPub }, { [KID]: b64(rawPub) }]) {
      expect((await verifyExport(text, { checkpointPublicKeys: keys })).ok).toBe(true);
    }
    await expect(
      verifyExport(text, { checkpointPublicKeys: { [KID]: new Uint8Array(5) } }),
    ).rejects.toThrow(ExportError);
  });

  it.each([1, 2, 4, 6])("reports one changed byte in entry %i at its seq", async (seq) => {
    const objs = await makeExport();
    objs[seq]!.record.chain_digest = "ce" + "cd".repeat(31);
    const r = await verify(objs);
    expect(r.ok).toBe(false);
    expect(r.firstBadSeq).toBe(seq);
    expect(r.entries).toBe(seq);
  });

  it("covers kind and chain_id in the hash", async () => {
    for (const [field, value] of [
      ["kind", "admin"],
      ["chain_id", "other"],
    ] as const) {
      const objs = await makeExport();
      objs[3]!.record[field] = value;
      expect((await verify(objs)).firstBadSeq).toBe(3);
    }
  });

  it("finds a broken link, a gap and a reorder", async () => {
    let objs = await makeExport();
    objs[3]!.prev_hash = "00".repeat(32);
    expect((await verify(objs)).firstBadSeq).toBe(3);
    objs = await makeExport();
    objs.splice(3, 1);
    const r = await verify(objs);
    expect(r.ok).toBe(false);
    expect(r.firstBadSeq).toBe(4);
    objs = await makeExport();
    [objs[2], objs[3]] = [objs[3]!, objs[2]!];
    expect((await verify(objs)).firstBadSeq).toBe(3);
  });

  it("checks checkpoint signatures and head hashes", async () => {
    let objs = await makeExport();
    objs[objs.length - 1]!.signature = b64(new Uint8Array(64).fill(120));
    let r = await verify(objs);
    expect(r.ok).toBe(false);
    expect(r.badCheckpoints).toEqual([{ seq: 6, reason: "signature does not verify" }]);
    expect(r).toMatchObject({ lastSignedSeq: 3, unsignedTail: 3, unsignedTailRejected: true });

    objs = await makeExport();
    objs[objs.length - 1] = { type: "checkpoint", ...(await sign(6, "ff".repeat(32))) };
    r = await verify(objs);
    expect(r.badCheckpoints.map((b) => b.reason)).toEqual([
      "head hash differs from the log at that seq",
    ]);

    const other = (await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    objs = await makeExport();
    objs[objs.length - 1] = {
      type: "checkpoint",
      ...(await sign(6, objs[6]!.entry_hash, KID, other.privateKey)),
    };
    expect((await verify(objs)).ok).toBe(false);
    objs = await makeExport();
    objs[objs.length - 1] = {
      type: "checkpoint",
      ...(await sign(6, objs[6]!.entry_hash, "nope")),
    };
    expect((await verify(objs)).badCheckpoints[0]!.reason).toContain("unknown signing key `nope`");
  });

  it("only signature-checks a checkpoint outside the entries", async () => {
    const objs = await makeExport();
    objs.push({ type: "checkpoint", ...(await sign(50, "aa".repeat(32))) });
    expect((await verify(objs)).ok).toBe(true);
    objs.push({
      type: "checkpoint",
      ...(await sign(51, "aa".repeat(32))),
      head_hash: "bb".repeat(32),
    });
    const r = await verify(objs);
    expect(r.ok).toBe(false);
    expect(r.badCheckpoints.map((b) => b.seq)).toEqual([51]);
  });

  it("catches a cut tail through the header range", async () => {
    const objs = (await makeExport()).filter((o) => o.seq !== 6 || o.type === "checkpoint");
    const r = await verify(objs);
    expect(r).toMatchObject({ ok: false, truncated: true, lastSeq: 5 });
    expect(r.badCheckpoints).toEqual([]);
  });

  it("rejects an unsigned tail unless allowed", async () => {
    const objs = await makeExport(6, { cps: [3] });
    let r = await verify(objs);
    expect(r).toMatchObject({ ok: false, unsignedTail: 3, unsignedTailRejected: true });
    r = await verify(objs, { allowUnsignedTail: true });
    expect(r).toMatchObject({ ok: true, unsignedTail: 3, unsignedTailRejected: false });
    const none = await makeExport(4, { cps: [] });
    r = await verify(none, { allowUnsignedTail: true });
    expect(r).toMatchObject({ ok: true, unsignedTail: 4, lastSignedSeq: undefined });
    expect((await verify(none)).ok).toBe(false);
  });

  it("enforces the declared range", async () => {
    let objs = await makeExport();
    objs[0]!.to = 8;
    expect(await verify(objs)).toMatchObject({ ok: false, truncated: true });
    objs = await makeExport();
    objs[0]!.from = 2;
    expect(await verify(objs)).toMatchObject({ ok: false, truncated: true, outsideRange: 1 });
    objs = await makeExport();
    objs[0]!.to = 4;
    expect(await verify(objs)).toMatchObject({ ok: false, outsideRange: 2, truncated: false });
    const head = (await makeExport())[0]!;
    expect((await verify([{ ...head, from: 1, to: 3 }])).truncated).toBe(true);
    expect((await verify([{ ...head, from: 5, to: 4 }])).ok).toBe(true);
  });

  it("verifies a window of the log without genesis", async () => {
    const objs = await makeExport(4, { start: 10, cps: [12] });
    const r = await verify(objs, { allowUnsignedTail: true });
    expect(r).toMatchObject({ ok: true, fromGenesis: false, firstSeq: 10 });
    objs[2]!.record.reason = "x";
    expect((await verify(objs, { allowUnsignedTail: true })).firstBadSeq).toBe(11);
  });

  it.each([
    ["no header", (o: Obj[]) => o.shift(), /no header/],
    ["v1", (o: Obj[]) => (o[0]!.format = "attenuo-audit-export-v1"), /v1/],
    ["format", (o: Obj[]) => (o[0]!.format = "nope"), /unsupported/],
    ["filtered", (o: Obj[]) => (o[0]!.filter = { kind: "admin" }), /filtered/],
    ["filtered on tool", (o: Obj[]) => (o[0]!.filter = { tool: "token.exchange" }), /filtered/],
    ["filtered on decision", (o: Obj[]) => (o[0]!.filter = { decision: "deny" }), /filtered/],
    [
      "filtered on tool and decision",
      (o: Obj[]) => (o[0]!.filter = { tool: "token.exchange", decision: "deny" }),
      /filtered/,
    ],
    ["second header", (o: Obj[]) => o.splice(1, 0, { ...o[0]! }), /second header/],
    ["unknown type", (o: Obj[]) => o.push({ type: "mystery" }), /unknown line type/],
    ["negative from", (o: Obj[]) => (o[0]!.from = -1), /non-negative/],
    ["string seq", (o: Obj[]) => (o[1]!.seq = "1"), /non-negative/],
  ])("throws ExportError for input that is not an export: %s", async (_n, mutate, match) => {
    const objs = await makeExport();
    mutate(objs);
    await expect(verify(objs)).rejects.toThrow(ExportError);
    await expect(verify(objs)).rejects.toThrow(match);
  });

  it("throws for garbage lines, duplicate members and constants", async () => {
    const good = lines(await makeExport());
    const o = { checkpointPublicKeys: jwks };
    for (const bad of [
      "not json\n",
      "[1]\n",
      '{"type":"entry","type":"entry"}\n',
      '{"from":NaN}\n',
    ]) {
      await expect(verifyExport([good[0]!, bad, ...good.slice(1)], o)).rejects.toThrow(ExportError);
    }
  });

  it("tolerates blank lines and CRLF", async () => {
    const crlf = lines(await makeExport()).map((l) => l.replace("\n", "\r\n"));
    const r = await verifyExport([...crlf.slice(0, 2), "\r\n", ...crlf.slice(2)], {
      checkpointPublicKeys: jwks,
    });
    expect(r.ok).toBe(true);
  });
});

// ---- cross-check against shipped checkpoints (SR-21) -----------------------------------------

const checkpointsOf = (objs: Obj[]): Obj[] =>
  objs.filter((o) => o.type === "checkpoint").map(({ type: _t, ...cp }) => cp);

const sha256Hex = async (text: string): Promise<string> =>
  Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");

/** What the file sink writes for `cp`. */
const envelope = async (cp: Obj): Promise<Obj> => ({
  checkpoint: cp,
  checkpoint_sha256: await sha256Hex(canonicalize(cp)),
  format: SHIPPED_FORMAT,
  kid: cp.kid,
  public_url: null,
  signature: cp.signature,
});

const shippedLines = async (cps: Obj[]): Promise<string[]> => {
  const out: string[] = [];
  for (const c of cps) out.push(canonicalize(await envelope(c)) + "\n");
  return out;
};

async function cross(
  objs: Obj[],
  shipped?: string[],
  make: { n?: number; start?: number; cps?: number[] } = {},
): Promise<CrossCheckReport> {
  const sent = shipped ?? (await shippedLines(checkpointsOf(await makeExport(make.n, make))));
  return crossCheck(lines(objs), sent, { checkpointPublicKeys: jwks });
}

/** The attacker's export: records from `startAt` changed, hashes recomputed, changed
 * checkpoints signed again with the (stolen) key. */
async function rewritten(startAt: number): Promise<Obj[]> {
  const objs = await makeExport();
  let prev = GENESIS_HASH;
  const bySeq = new Map<number, string>();
  for (const e of objs.filter((o) => o.type === "entry")) {
    if (e.seq >= startAt) e.record = { ...e.record, reason: "rewritten" };
    e.prev_hash = prev;
    e.entry_hash = prev = await entryHash(e.seq, prev, e.record);
    bySeq.set(e.seq, e.entry_hash);
  }
  for (const o of objs.filter((x) => x.type === "checkpoint")) {
    if (o.head_hash === bySeq.get(o.seq)) continue;
    const fresh = await sign(o.seq, bySeq.get(o.seq)!);
    Object.assign(o, fresh, { at: "2026-10-24T00:00:00Z" });
    const ctx = new TextEncoder().encode("attenuo-checkpoint-v1");
    const payload = new TextEncoder().encode(canonicalize([o.seq, o.head_hash, o.at, o.kid]));
    const msg = new Uint8Array(4 + ctx.length + payload.length);
    new DataView(msg.buffer).setUint32(0, ctx.length);
    msg.set(ctx, 4);
    msg.set(payload, 4 + ctx.length);
    o.signature = b64(new Uint8Array(await crypto.subtle.sign("Ed25519", priv, msg)));
  }
  return objs;
}

describe("crossCheck", () => {
  it("accepts a genuine export, a retried delivery, bare lines and a path", async () => {
    const objs = await makeExport();
    const r = await cross(objs);
    expect(r).toMatchObject({
      ok: true,
      mismatches: [],
      shipped: 2,
      inRange: 2,
      matched: 2,
      beyondRange: 0,
      lastShippedSeq: 6,
    });
    const shipped = await shippedLines(checkpointsOf(objs));
    expect((await cross(objs, [...shipped, ...shipped])).ok).toBe(true);
    const bare = [...lines(objs.filter((o) => o.type === "checkpoint")), "\n"];
    expect((await cross(objs, bare)).ok).toBe(true);
    const dir = mkdtempSync(join(tmpdir(), "ob-ship-"));
    try {
      const path = join(dir, "shipped.jsonl");
      writeFileSync(path, shipped.join(""));
      const o = { checkpointPublicKeys: jwks };
      expect((await crossCheck(lines(objs), { path }, o)).ok).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("catches a rewritten and re-signed log", async () => {
    const attacker = await rewritten(2);
    expect((await verify(attacker)).ok).toBe(true); // alone it verifies: the attacker had the key
    const r = await cross(attacker);
    expect(r.ok).toBe(false);
    expect(r.mismatches.map((m) => [m.seq, m.line])).toEqual([
      [3, 1],
      [6, 2],
    ]);
    for (const m of r.mismatches) {
      expect(m.reason).toContain("RE-SIGNED after shipping");
      expect(m.reason).toContain("head_hash");
      expect(m.reason).toContain("history rewritten");
    }
    const late = await cross(await rewritten(5));
    expect(late.mismatches.map((m) => m.seq)).toEqual([6]);
    expect(late.matched).toBe(1);
  });

  it("reports deleted, duplicate and forged shipped checkpoints", async () => {
    const objs = await makeExport(6, { cps: [2, 4, 6] });
    const shipped = await shippedLines(checkpointsOf(objs));
    const gone = objs.filter((o) => !(o.type === "checkpoint" && o.seq === 4));
    let r = await cross(gone, shipped);
    expect(r.mismatches.map((m) => [m.seq, m.line])).toEqual([[4, 2]]);
    expect(r.mismatches[0]!.reason).toContain("deleted after shipping");

    const other = await shippedLines([await sign(4, "ab".repeat(32))]);
    r = await cross(objs, [...shipped, ...other]);
    expect(r.mismatches.map((m) => [m.seq, m.line])).toEqual([[4, 4]]);
    expect(r.mismatches[0]!.reason).toContain(
      "two different checkpoints for this seq (lines 2 and 4)",
    );

    const stranger = (
      (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair
    ).privateKey;
    const head4 = objs.find((o) => o.type === "entry" && o.seq === 4)!.entry_hash;
    const forged = await shippedLines([await sign(4, head4, KID, stranger)]);
    r = await cross(objs, [shipped[0]!, ...forged, shipped[2]!]);
    expect(r.mismatches.map((m) => m.seq)).toEqual([4]);
    expect(r.mismatches[0]!.reason).toContain(
      "shipped checkpoint does not verify: signature does not verify",
    );
    const unknown = await shippedLines([await sign(4, head4, "other")]);
    r = await cross(objs, unknown);
    expect(r.mismatches[0]!.reason).toContain("unknown signing key `other`");
  });

  it("reports an envelope that disagrees with its checkpoint", async () => {
    const objs = await makeExport();
    const cp = checkpointsOf(objs)[0]!;
    const reason = async (env: Obj): Promise<string> =>
      (await cross(objs, [JSON.stringify(env)])).mismatches[0]!.reason;
    expect(await reason({ ...(await envelope(cp)), checkpoint_sha256: "00".repeat(32) })).toContain(
      "checkpoint_sha256",
    );
    expect(await reason({ ...(await envelope(cp)), kid: "other" })).toContain(
      "differs from the checkpoint's own",
    );
    expect(await reason({ ...(await envelope(cp)), format: "v0" })).toContain(
      "unsupported format `v0`",
    );
  });

  it("counts checkpoints past the export and skips those before a window", async () => {
    const objs = await makeExport();
    const log = await makeExport(9, { cps: [3, 6, 9] });
    const r = await cross(objs, await shippedLines(checkpointsOf(log)));
    expect(r).toMatchObject({
      ok: true,
      inRange: 2,
      matched: 2,
      beyondRange: 1,
      lastShippedSeq: 9,
    });
    const window = await makeExport(3, { start: 4, cps: [6] });
    const w = await cross(window, await shippedLines(checkpointsOf(await makeExport())));
    expect([w.inRange, w.mismatches.map((m) => m.seq)]).toEqual([1, [6]]);
  });

  it("skips a prune anchor line in the shipped file", async () => {
    const objs = await makeExport();
    const shipped = await shippedLines(checkpointsOf(objs));
    const anchor =
      JSON.stringify({
        anchor: {
          archive_sha256: null,
          at: "2026-10-24T00:00:00Z",
          kid: "k",
          previous_through_seq: null,
          prune_entry_hash: "ab".repeat(32),
          prune_seq: 7,
          signature: "s",
          through_hash: "cd".repeat(32),
          through_seq: 3,
        },
        anchor_sha256: "ef".repeat(32),
        format: "attenuo-shipped-anchor-v1",
        kid: "k",
        public_url: null,
        signature: "s",
      }) + "\n";
    const [first, second] = shipped as [string, string];
    const withAnchor = [first, anchor, second];
    const parsed = await parseShipped(withAnchor);
    expect(parsed.map((p) => p.line)).toEqual([1, 3]);
    const r = await cross(objs, withAnchor);
    expect(r).toMatchObject({ mismatches: [], shipped: 2, matched: 2 });
    // The anchor itself is checked: this one is not signed by a key of the JWKS.
    expect(r.ok).toBe(false);
    expect(r.anchors).toMatchObject({ ok: false, shipped: 1 });
    expect(r.anchors.mismatches).toEqual([
      {
        seq: 3,
        line: 2,
        reason: "shipped envelope is inconsistent: `anchor_sha256` does not match the anchor",
      },
    ]);
  });

  it("matches the genesis checkpoint and accepts an empty shipped file", async () => {
    const objs = await makeExport(6, { cps: [0, 3, 6] });
    objs.push({ type: "checkpoint", ...(await sign(0, GENESIS_HASH)) });
    const g = await cross(objs, await shippedLines([await sign(0, GENESIS_HASH)]));
    expect(g.matched).toBe(1);
    const empty = await cross(objs, []);
    expect(empty).toMatchObject({ ok: true, shipped: 0, lastShippedSeq: undefined });
  });

  it.each([
    ["not json\n", "shipped checkpoints, line 1"],
    ["[1]\n", "not a JSON object"],
    ['{"type":"entry","seq":1}\n', "not a checkpoint line"],
    ['{"seq":1}\n', "head_hash"],
    ['{"checkpoint":1,"format":"x","kid":"k","signature":"s","checkpoint_sha256":"h"}\n', "object"],
  ])("rejects a shipped file that is not checkpoints: %s", async (text, match) => {
    await expect(parseShipped([text])).rejects.toThrow(match);
    await expect(cross(await makeExport(), [text])).rejects.toThrow(ExportError);
  });

  it("refuses what verifyExport refuses", async () => {
    const objs = await makeExport();
    await expect(cross(objs.slice(1), [])).rejects.toThrow("no header");
    const o = { checkpointPublicKeys: { [KID]: "AAAA" } };
    await expect(crossCheck(lines(objs), [], o)).rejects.toThrow("32 bytes");
  });
});

// ---- a pruned log: the header anchor and several files ------------------------------------

async function signAnchor(a: Obj, key?: CryptoKey): Promise<string> {
  const ctx = new TextEncoder().encode("attenuo-audit-anchor-v1");
  const payload = new TextEncoder().encode(
    canonicalize([
      a.through_seq,
      a.through_hash,
      a.prune_seq,
      a.prune_entry_hash,
      a.previous_through_seq,
      a.archive_sha256,
      a.at,
      a.kid,
    ]),
  );
  const msg = new Uint8Array(4 + ctx.length + payload.length);
  new DataView(msg.buffer).setUint32(0, ctx.length);
  msg.set(ctx, 4);
  msg.set(payload, 4 + ctx.length);
  return b64(new Uint8Array(await crypto.subtle.sign("Ed25519", key ?? priv, msg)));
}

/**
 * A log of 13 entries pruned through 10 by the record at 11: the archive (1..=10, ending at a
 * checkpoint) and the retained export (11..=13, its header carrying the anchor).
 */
async function prunedLog(
  digest: string | null = "ab".repeat(32),
): Promise<{ archive: Obj[]; retained: Obj[] }> {
  const entries: Obj[] = [];
  let prev = GENESIS_HASH;
  for (let seq = 1; seq <= 13; seq++) {
    let rec = record(seq);
    if (seq === 11) {
      const args = {
        through_seq: 10,
        through_hash: entries[9]!.entry_hash,
        previous_through_seq: null,
        archive_sha256: digest,
      };
      rec = {
        ...GOLDEN_RECORD,
        kind: "admin",
        server: "attenuo",
        tool: PRUNE_TOOL,
        decision: "allow",
        reason: "admin_action",
        arguments_digest: await sha256Hex(canonicalize(args)),
      };
    }
    const h = await entryHash(seq, prev, rec);
    entries.push({ type: "entry", seq, prev_hash: prev, record: rec, entry_hash: h });
    prev = h;
  }
  const hashOf = (s: number): string => entries[s - 1]!.entry_hash as string;
  const anchor: Obj = {
    through_seq: 10,
    through_hash: hashOf(10),
    prune_seq: 11,
    prune_entry_hash: hashOf(11),
    previous_through_seq: null,
    archive_sha256: digest,
    at: "2026-10-24T00:00:00Z",
    kid: KID,
  };
  anchor.signature = await signAnchor(anchor);
  const header = (from: number, to: number, extra: Obj = {}): Obj => ({
    type: "header",
    format: EXPORT_FORMAT,
    from,
    to,
    exported_at: "2026-10-24T00:00:00Z",
    ...extra,
  });
  const cps = async (...seqs: number[]): Promise<Obj[]> => {
    const out: Obj[] = [];
    for (const s of seqs) out.push({ type: "checkpoint", ...(await sign(s, hashOf(s))) });
    return out;
  };
  return {
    archive: [header(1, 10), ...entries.slice(0, 10), ...(await cps(5, 10))],
    retained: [header(11, 13, { anchor }), ...entries.slice(10), ...(await cps(11, 13))],
  };
}

const copy = (objs: Obj[]): Obj[] => JSON.parse(JSON.stringify(objs)) as Obj[];

async function withAnchor(objs: Obj[], changes: Obj, key?: CryptoKey): Promise<Obj[]> {
  const out = copy(objs);
  const a = out[0]!.anchor as Obj;
  Object.assign(a, changes);
  a.signature = await signAnchor(a, key);
  return out;
}

describe("a pruned log", () => {
  it("starts the retained export from its signed anchor", async () => {
    const { archive, retained } = await prunedLog();
    const r = await verify(retained);
    expect(r.ok).toBe(true);
    expect([r.fromAnchor, r.fromGenesis, r.prunedThrough, r.anchors]).toEqual([true, false, 10, 1]);
    expect(r.badAnchors).toEqual([]);
    expect((await verify((await prunedLog(null)).retained)).ok).toBe(true);
    const a = await verify(archive);
    expect([a.ok, a.fromGenesis, a.fromAnchor, a.anchors]).toEqual([true, true, false, 0]);
  });

  it("verifies the retained export as a window without its anchor", async () => {
    const { retained } = await prunedLog();
    const bare = copy(retained);
    delete bare[0]!.anchor;
    const r = await verify(bare);
    expect([r.ok, r.fromAnchor, r.prunedThrough, r.anchors]).toEqual([true, false, undefined, 0]);
  });

  it("reports a header anchor that does not verify or does not fit", async () => {
    const { retained } = await prunedLog();
    const other = (
      (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair
    ).privateKey;
    const cases: [Obj[], string][] = [
      [await withAnchor(retained, {}, other), "signature does not verify"],
      [await withAnchor(retained, { kid: "k9" }), "unknown signing key `k9`"],
      [await withAnchor(retained, { through_seq: 9 }), "the header's anchor is through seq 9"],
      [
        await withAnchor(retained, { prune_entry_hash: "00".repeat(32) }),
        "does not hash to prune_entry_hash",
      ],
      [
        await withAnchor(retained, { archive_sha256: "cd".repeat(32) }),
        "arguments digest does not match",
      ],
    ];
    for (const [objs, reason] of cases) {
      const r = await verify(objs);
      expect(r.ok, reason).toBe(false);
      expect(r.fromAnchor, reason).toBe(false);
      expect(r.badAnchors.length, reason).toBe(1);
      expect(r.badAnchors[0]!.reason).toContain(reason);
    }
  });

  it("refuses a malformed header anchor", async () => {
    const { retained } = await prunedLog();
    const bad = copy(retained);
    bad[0]!.anchor.through_seq = "10";
    await expect(verify(bad)).rejects.toThrow(/through_seq/);
    bad[0]!.anchor = "anchor";
    await expect(verify(bad)).rejects.toThrow(ExportError);
  });

  it("verifies archives and the retained export as one log", async () => {
    const { archive, retained } = await prunedLog();
    const dir = mkdtempSync(join(tmpdir(), "attenuo-audit-"));
    try {
      const a = join(dir, "archive.jsonl");
      const b = join(dir, "retained.jsonl");
      writeFileSync(a, lines(archive).join(""));
      writeFileSync(b, lines(retained).join(""));
      const opts = { checkpointPublicKeys: jwks };
      const r = await verifyExports([{ path: a }, { path: b }], opts);
      expect(r.ok).toBe(true);
      expect(r.links).toEqual([]);
      expect(r.files[1]!.fromAnchor).toBe(true);

      const back = await verifyExports([{ path: b }, { path: a }], opts);
      expect(back.ok).toBe(false);
      expect(back.links[0]).toEqual({
        earlier: 0,
        later: 1,
        reason:
          "the seqs are not contiguous: the earlier file ends at seq 13, the later one starts at seq 1",
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    const opts = { checkpointPublicKeys: jwks };
    const short = archive.filter((o) => !(o.type === "checkpoint" && o.seq === 10));
    const r = await verifyExports([lines(short), lines(retained)], opts);
    expect(r.links.some((p) => p.reason.includes("does not end at a checkpoint"))).toBe(true);
    for (const [which, seq] of [
      [0, 4],
      [1, 12],
    ] as const) {
      const files = [copy(archive), copy(retained)];
      const e = files[which]!.find((o) => o.type === "entry" && o.seq === seq)!;
      e.record.reason += "x";
      const v = await verifyExports(
        files.map((f) => lines(f)),
        opts,
      );
      expect(v.ok).toBe(false);
      expect(v.files[which]!.firstBadSeq).toBe(seq);
    }
    const openTail = retained.slice(0, -1);
    const tail = { checkpointPublicKeys: jwks, allowUnsignedTail: true };
    expect((await verifyExports([lines(archive), lines(openTail)], tail)).ok).toBe(true);
    const first = (await verifyExports([lines(openTail), lines(archive)], tail)).files[0]!;
    expect([first.ok, first.unsignedTailRejected]).toEqual([false, true]);
  });

  it("names a header anchor that is not the earlier file's end", async () => {
    const { archive, retained } = await prunedLog();
    const cut = archive.filter(
      (o) => !((o.type === "entry" || o.type === "checkpoint") && o.seq === 10),
    );
    cut[0] = { ...cut[0], to: 9 };
    const r = await verifyExports([lines(cut), lines(retained)], { checkpointPublicKeys: jwks });
    expect(
      r.links.some((p) =>
        p.reason.includes("header anchor is through seq 10, not the earlier file's end at seq 9"),
      ),
    ).toBe(true);
  });
});

describe("verifyExports input", () => {
  it("throws on an empty list and on one export given alone", async () => {
    const o = { checkpointPublicKeys: jwks };
    await expect(verifyExports([], o)).rejects.toThrow("at least one export");
    const { archive } = await prunedLog();
    const text = lines(archive).join("");
    await expect(verifyExports(text as never, o)).rejects.toThrow(ExportError);
    await expect(verifyExports(new TextEncoder().encode(text) as never, o)).rejects.toThrow(
      "not one export",
    );
    await expect(verifyExports({ path: "a.jsonl" } as never, o)).rejects.toThrow("not one export");
  });
});

const GOLDEN = fileURLToPath(new URL("../../../testdata/audit-retention/", import.meta.url));

describe.skipIf(!existsSync(GOLDEN))("the golden files written by the Rust code", () => {
  // Written by `cargo test -p attenuo-audit --test retention write_golden_files -- --ignored`
  // with a fixed key: the anchors here are signed by the server code, not by this test.
  const read = (n: string): string => readFileSync(join(GOLDEN, n), "utf8");
  const names = ["archive-1.jsonl", "archive-2.jsonl", "retained.jsonl"];

  it("verify as one log from genesis", async () => {
    const o: VerifyExportOptions = {
      checkpointPublicKeys: JSON.parse(read("jwks.json")) as { keys: unknown[] },
    };
    const r = await verifyExports(
      names.map((n) => ({ path: join(GOLDEN, n) })),
      o,
    );
    expect(r.ok).toBe(true);
    expect(r.links).toEqual([]);
    expect([r.fromGenesis, r.fromAnchor, r.prunedThrough]).toEqual([true, false, undefined]);
    expect(r.files.map((f) => f.prunedThrough)).toEqual([undefined, 5, 10]);
    expect(r.files.map((f) => f.fromAnchor)).toEqual([false, true, true]);
    // Each anchor signs the digest of the archive that holds the entries it pruned.
    for (const [archive, later] of [
      ["archive-1.jsonl", "archive-2.jsonl"],
      ["archive-2.jsonl", "retained.jsonl"],
    ] as const) {
      const header = JSON.parse(read(later).split("\n")[0] as string) as {
        anchor: { archive_sha256: string };
      };
      const digest = createHash("sha256")
        .update(readFileSync(join(GOLDEN, archive)))
        .digest("hex");
      expect(header.anchor.archive_sha256).toBe(digest);
    }
    const alone = await verifyExports([{ path: join(GOLDEN, "retained.jsonl") }], o);
    expect([alone.ok, alone.fromGenesis, alone.fromAnchor, alone.prunedThrough]).toEqual([
      true,
      false,
      true,
      10,
    ]);
    for (const n of names) {
      const c = await crossCheck(
        { path: join(GOLDEN, n) },
        { path: join(GOLDEN, "shipped.jsonl") },
        o,
      );
      expect(c.ok).toBe(true);
    }
    // One changed member of a signed anchor is caught.
    const text = read("retained.jsonl").split("\n");
    const header = JSON.parse(text[0] as string) as { anchor: { through_hash: string } };
    header.anchor.through_hash = "0".repeat(64);
    const bad = [JSON.stringify(header), ...text.slice(1)].join("\n");
    const r2 = await verifyExports([{ path: join(GOLDEN, "archive-2.jsonl") }, bad], o);
    expect(r2.ok).toBe(false);
    expect(r2.files[1]?.badAnchors.length).toBe(1);
  });
});

// ---- the shipped prune anchors, against the golden files the Rust code writes -------------

const goldenText = (n: string): string => readFileSync(join(GOLDEN, n), "utf8");
const goldenOpts = (): VerifyExportOptions => ({
  checkpointPublicKeys: JSON.parse(goldenText("jwks.json")) as { keys: unknown[] },
});
const goldenSource = (v: string | string[]): string[] | { path: string } =>
  typeof v === "string" ? { path: join(GOLDEN, v) } : v;
const goldenCross = (exp: string | string[], shipped: string | string[]) =>
  crossCheck(goldenSource(exp), goldenSource(shipped), goldenOpts());

interface GoldenCheck {
  export: string;
  shipped: string;
  checkpoints: Obj;
  anchors: Obj;
}
const goldenChecks = (): GoldenCheck[] =>
  existsSync(GOLDEN)
    ? (JSON.parse(goldenText("cross-checks.json")) as { checks: GoldenCheck[] }).checks
    : [];

const mismatchJson = (ms: ShippedMismatch[]): Obj[] =>
  ms.map((m) => ({ seq: m.seq, line: m.line, reason: m.reason }));

describe.skipIf(!existsSync(GOLDEN))("shipped anchors in the golden files", () => {
  // `cross-checks.json` is what the Rust `cross_check` and `cross_check_anchors` answer for each
  // pair, written with the other golden files.
  it.each(goldenChecks().map((c) => [`${c.export}+${c.shipped}`, c] as const))(
    "gives the Rust verdict for %s",
    async (_name, check) => {
      const r = await goldenCross(check.export, check.shipped);
      expect({
        shipped: r.shipped,
        in_range: r.inRange,
        matched: r.matched,
        beyond_range: r.beyondRange,
        below_range: r.belowRange,
        last_shipped_seq: r.lastShippedSeq ?? null,
        mismatches: mismatchJson(r.mismatches),
        ok: r.mismatches.length === 0,
      }).toEqual(check.checkpoints);
      expect({
        shipped: r.anchors.shipped,
        checked: r.anchors.checked,
        matched: r.anchors.matched,
        beyond_range: r.anchors.beyondRange,
        mismatches: mismatchJson(r.anchors.mismatches),
        ok: r.anchors.ok,
      }).toEqual(check.anchors);
      expect(r.ok).toBe(check.checkpoints.ok === true && check.anchors.ok === true);
    },
  );

  it("accounts for both shipped anchors in the archives and the retained export", async () => {
    for (const [n, counts] of [
      ["archive-1.jsonl", [0, 0, 2]],
      ["archive-2.jsonl", [1, 1, 1]],
      ["retained.jsonl", [2, 2, 0]],
    ] as const) {
      const r = await goldenCross(n, "shipped.jsonl");
      expect(r.ok).toBe(true);
      expect([r.anchors.checked, r.anchors.matched, r.anchors.beyondRange]).toEqual(counts);
    }
    expect((await goldenCross("retained.jsonl", "shipped.jsonl")).belowRange).toBe(1);
  });

  it("reports a rewound log that verifies on its own", async () => {
    expect((await verifyExport({ path: join(GOLDEN, "rewound.jsonl") }, goldenOpts())).ok).toBe(
      true,
    );
    const r = await goldenCross("rewound.jsonl", "shipped.jsonl");
    expect([r.ok, r.mismatches]).toEqual([false, []]);
    expect(r.anchors.mismatches).toHaveLength(1);
    const m = r.anchors.mismatches[0]!;
    expect([m.seq, m.line]).toEqual([10, 6]);
    expect(m.reason).toMatch(/^REWOUND: the shipped anchor says the log was pruned through seq 10/);
  });

  it("reports an export that holds the boundary of a later shipped prune", async () => {
    expect((await verifyExport({ path: join(GOLDEN, "stale.jsonl") }, goldenOpts())).ok).toBe(true);
    const r = await goldenCross("stale.jsonl", "shipped.jsonl");
    expect(r.anchors.mismatches).toHaveLength(1);
    expect(r.anchors.mismatches[0]).toMatchObject({ seq: 10 });
    expect(r.anchors.mismatches[0]!.reason).toContain("has its boundary inside this export");
  });

  it("reports a tampered shipped anchor signature", async () => {
    const r = await goldenCross("retained.jsonl", "shipped-bad-signature.jsonl");
    expect([r.ok, r.mismatches]).toEqual([false, []]);
    expect(mismatchJson(r.anchors.mismatches)).toEqual([
      { seq: 10, line: 6, reason: "shipped anchor does not verify: signature does not verify" },
      {
        seq: 10,
        line: 0,
        reason:
          "the export's header anchor is not in the shipped file (it was not shipped, or the " +
          "file is incomplete)",
      },
    ]);
  });

  it("reports another shipped anchor for the header's boundary", async () => {
    const r = await goldenCross("archive-2.jsonl", "shipped-other-anchor.jsonl");
    expect(mismatchJson(r.anchors.mismatches)).toEqual([
      {
        seq: 5,
        line: 5,
        reason: "the export's header carries another anchor for this boundary than the one shipped",
      },
    ]);
  });

  it("reports a header anchor that was not shipped", async () => {
    const text = goldenText("shipped.jsonl")
      .split("\n")
      .filter((l) => l !== "");
    const noFirst = text.filter((l) => !l.includes('"through_seq":5}'));
    expect(noFirst).toHaveLength(text.length - 1);
    const r = await goldenCross("archive-2.jsonl", noFirst);
    expect(r.anchors.mismatches).toHaveLength(1);
    expect(r.anchors.mismatches[0]).toMatchObject({ seq: 5, line: 0 });
    // No anchor line at all, and no anchor in the header: nothing to check.
    const onlyCps = text.filter((l) => !l.includes('"anchor"'));
    const empty: AnchorCheckReport = {
      shipped: 0,
      checked: 0,
      matched: 0,
      beyondRange: 0,
      mismatches: [],
      ok: true,
    };
    const r2 = await goldenCross("archive-1.jsonl", onlyCps);
    expect([r2.ok, r2.anchors]).toEqual([true, empty]);
  });

  it("parses S3 objects joined without newlines", async () => {
    const joined = goldenText("shipped.jsonl").replaceAll("\n", "");
    expect(joined.split("\n")).toHaveLength(1);
    expect(await parseShipped([joined])).toHaveLength(
      (await parseShipped({ path: join(GOLDEN, "shipped.jsonl") })).length,
    );
    const anchors = await parseShippedAnchors([joined]);
    expect(anchors.map((a) => [a.line, a.anchor.through_seq])).toEqual([
      [1, 5],
      [1, 10],
    ]);
    for (const n of ["archive-1.jsonl", "archive-2.jsonl", "retained.jsonl"]) {
      expect((await goldenCross(n, [joined])).ok).toBe(true);
    }
  });

  it("reads the anchor envelopes", async () => {
    const anchors = await parseShippedAnchors({ path: join(GOLDEN, "shipped.jsonl") });
    expect(anchors).toHaveLength(2);
    const first = anchors[0]!;
    expect([first.format, first.publicUrl]).toEqual([SHIPPED_ANCHOR_FORMAT, undefined]);
    expect([first.kid, first.signature]).toEqual([first.anchor.kid, first.anchor.signature]);
    expect(Object.keys(first.anchor).sort()).toEqual([
      "archive_sha256",
      "at",
      "kid",
      "previous_through_seq",
      "prune_entry_hash",
      "prune_seq",
      "signature",
      "through_hash",
      "through_seq",
    ]);
    expect(await parseShippedAnchors(["not json\n", '{"seq":1}\n'])).toEqual([]);
  });

  it("reports inconsistent anchor envelopes and counts a retried delivery once", async () => {
    const text = goldenText("shipped.jsonl")
      .split("\n")
      .filter((l) => l !== "");
    const cps = text.slice(0, -2);
    const first = JSON.parse(text[text.length - 2]!) as Obj;
    const second = JSON.parse(text[text.length - 1]!) as Obj;
    const anchorsOf = async (...envs: Obj[]): Promise<AnchorCheckReport> =>
      (await goldenCross("retained.jsonl", [...cps, ...envs.map((e) => JSON.stringify(e))]))
        .anchors;
    const retry = await anchorsOf(first, first, second);
    expect([retry.ok, retry.shipped, retry.checked, retry.matched]).toEqual([true, 3, 2, 2]);
    for (const [change, reason] of [
      [{ anchor_sha256: "0".repeat(64) }, "`anchor_sha256` does not match the anchor"],
      [{ kid: "other" }, "`kid` or `signature` differs from the anchor's own"],
    ] as const) {
      const r = await anchorsOf({ ...first, ...change }, second);
      expect(r.mismatches[0]).toEqual({
        seq: 5,
        line: cps.length + 1,
        reason: `shipped envelope is inconsistent: ${reason}`,
      });
    }
    // Another format with an `anchor` member is neither an anchor nor a checkpoint, as for the
    // CLI: the file does not parse.
    const other = JSON.stringify({ ...first, format: "v0" });
    expect((await parseShippedAnchors([other]))[0]!.format).toBe("v0");
    await expect(goldenCross("retained.jsonl", [other])).rejects.toThrow(
      "shipped checkpoints, line 1",
    );
  });
});

describe("shipped anchors", () => {
  const anchorLine = (extra: Obj): string =>
    JSON.stringify({
      anchor: {
        archive_sha256: null,
        at: "2026-10-24T00:00:00Z",
        kid: "k",
        previous_through_seq: null,
        prune_entry_hash: "ab".repeat(32),
        prune_seq: 7,
        signature: "s",
        through_hash: "cd".repeat(32),
        through_seq: 3,
      },
      anchor_sha256: "ef".repeat(32),
      format: "attenuo-shipped-anchor-v1",
      kid: "k",
      public_url: null,
      signature: "s",
      ...extra,
    });

  it.each([
    [{ kid: 1 }, "shipped anchors, line 1: `kid` must be a string"],
    [{ anchor_sha256: null }, "`anchor_sha256` must be a string"],
    [{ public_url: 3 }, "`public_url` must be a string"],
    [{ anchor: 1 }, "shipped anchors, line 1: anchor: must be an object"],
    [{ anchor: { through_seq: -1 } }, "`through_seq` must be a non-negative integer"],
  ])("refuses a value with an anchor member that is not a shipped anchor: %j", async (c, m) => {
    await expect(parseShippedAnchors([anchorLine(c)])).rejects.toThrow(m);
  });

  const anchorEnvelope = async (a: Obj): Promise<string> =>
    canonicalize({
      anchor: a,
      anchor_sha256: await sha256Hex(canonicalize(a)),
      format: SHIPPED_ANCHOR_FORMAT,
      kid: a.kid,
      public_url: null,
      signature: a.signature,
    });

  it("checks the shipped checkpoint at the anchor's boundary, twins and a missing header anchor", async () => {
    const { retained } = await prunedLog();
    const anchor = retained[0]!.anchor as Obj;
    const good = await sign(10, anchor.through_hash as string);
    const other = await sign(10, "ee".repeat(32));
    const env = await anchorEnvelope(anchor);
    const ok = await cross(retained, [env, canonicalize(await envelope(good))]);
    expect([ok.ok, ok.belowRange, ok.anchors.matched]).toEqual([true, 1, 1]);
    const bad = await cross(retained, [env, canonicalize(await envelope(other))]);
    expect(bad.mismatches).toEqual([
      {
        seq: 10,
        line: 2,
        reason:
          "the shipped checkpoint at the anchor's through_seq names another hash than the " +
          "anchor (history rewritten before the prune)",
      },
    ]);
    // Two different valid anchors for one boundary.
    const twin: Obj = { ...anchor, archive_sha256: "ff".repeat(32) };
    twin.signature = await signAnchor(twin);
    const twins = await cross(retained, [env, await anchorEnvelope(twin)]);
    expect(twins.anchors.mismatches.map((m) => m.reason)).toEqual([
      "the sink holds two different anchors for this boundary (lines 1 and 2): the log was " +
        "pruned through this seq twice",
    ]);
    // An export that starts right after a shipped anchor's boundary but carries none.
    const bareHeader: Obj = { ...retained[0]! };
    delete bareHeader.anchor;
    const bare = await cross([bareHeader, ...retained.slice(1)], [env]);
    expect(bare.anchors.mismatches.map((m) => m.reason)).toEqual([
      "the export starts right after this shipped anchor's boundary, but its header carries " +
        "no anchor",
    ]);
  });
});

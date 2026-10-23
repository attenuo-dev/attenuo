import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  ExportError,
  verifyExport,
  type ExportReport,
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

import { beforeAll, describe, expect, it } from "vitest";
import { AdminClient, ApiError, capability, OnbehalfError, prefix } from "../src/index.js";
import { jsonResponse, mockFetch, Signer, tokenResponse } from "./helpers.js";

const URL_ = "http://ob.test";
let rootJwt: string;
beforeAll(async () => {
  rootJwt = await (await Signer.create()).mint();
});

const entry = (seq: number) => ({
  seq,
  record: {
    id: `dec-${seq}`,
    decision: "allow",
    reason: "ok",
    tool: "read_file",
    server: "github",
  },
});

describe("AdminClient", () => {
  it("revokes a lease with a reason and sends the admin bearer", async () => {
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({ lease_id: "l1", revoked: 3, reason: "r" }),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    expect(await admin.revokeLease("l1", "r")).toEqual({ leaseId: "l1", revoked: 3, reason: "r" });
    expect(calls[0]!.url.pathname).toBe("/admin/leases/l1/revoke");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer adm");
    expect(calls[0]!.body).toEqual({ reason: "r" });
    await admin.revokeLease("l1");
    expect(calls[1]!.body).toEqual({});
  });

  it("reads lease status", async () => {
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({
        lease_id: "l1",
        active: false,
        parent: null,
        expires_at: "2026-10-23T10:00:00Z",
        revoked_at: "2026-10-23T09:30:00Z",
        revoke_reason: "bad",
      }),
    );
    expect(await new AdminClient(URL_, "adm", { fetch }).leaseStatus("l1")).toEqual({
      leaseId: "l1",
      active: false,
      parent: undefined,
      expiresAt: "2026-10-23T10:00:00Z",
      revokedAt: "2026-10-23T09:30:00Z",
      revokeReason: "bad",
    });
    expect(calls[0]!.url.pathname).toBe("/admin/leases/l1");
  });

  it("pages the audit log", async () => {
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({ entries: [entry(5), entry(6)], next: 7 }),
    );
    const page = await new AdminClient(URL_, "adm", { fetch }).audit(5, 2);
    expect(page.next).toBe(7);
    expect(page.entries.map((e) => e.seq)).toEqual([5, 6]);
    expect(page.entries[0]!.record.id).toBe("dec-5");
    expect(calls[0]!.url.searchParams.get("from")).toBe("5");
    expect(calls[0]!.url.searchParams.get("limit")).toBe("2");
  });

  it("tails the log from the head of GET /admin/audit, following next", async () => {
    const { fetch, calls } = mockFetch((s) => {
      expect(s.url.pathname).not.toBe("/admin/audit/checkpoint");
      const from = Number(s.url.searchParams.get("from"));
      if (s.url.searchParams.get("limit") === "1")
        return jsonResponse({ entries: [entry(1)], next: 2, head: 10 });
      return from === 8
        ? jsonResponse({ entries: [entry(8), entry(9)], next: 10, head: 10 })
        : jsonResponse({ entries: [entry(10)], next: null, head: 10 });
    });
    const tail = await new AdminClient(URL_, "adm", { fetch }).auditTail(3);
    expect(tail.map((e) => e.seq)).toEqual([8, 9, 10]);
    expect(calls.map((c) => c.url.pathname)).toEqual([
      "/admin/audit",
      "/admin/audit",
      "/admin/audit",
    ]);
  });

  it("reads the head, 0 when absent", async () => {
    const a = mockFetch(() => jsonResponse({ entries: [], next: null, head: 12 }));
    expect(await new AdminClient(URL_, "adm", { fetch: a.fetch }).auditHead()).toBe(12);
    const b = mockFetch(() => jsonResponse({ entries: [], next: null }));
    expect(await new AdminClient(URL_, "adm", { fetch: b.fetch }).auditHead()).toBe(0);
  });

  it("streams an export as parsed JSON Lines, across chunk boundaries", async () => {
    const lines = [
      '{"type":"header","from":1,"to":2}',
      '{"type":"entry","seq":1}',
      '{"type":"checkpoint","seq":2}',
    ].join("\n");
    const { fetch, calls } = mockFetch(() => new Response(`${lines}\n`));
    const out = [];
    for await (const l of new AdminClient(URL_, "adm", { fetch }).auditExport(1, 2)) out.push(l);
    expect(out.map((l) => l.type)).toEqual(["header", "entry", "checkpoint"]);
    expect(calls[0]!.url.pathname).toBe("/admin/audit/export");
    expect(calls[0]!.url.searchParams.get("to")).toBe("2");

    const enc = new TextEncoder();
    const chunked = new Response(
      new ReadableStream({
        start(c) {
          c.enqueue(enc.encode('{"type":"ent'));
          c.enqueue(enc.encode('ry","seq":1}\n{"type":"entry","seq":2}'));
          c.close();
        },
      }),
    );
    const got = [];
    for await (const l of new AdminClient(URL_, "adm", {
      fetch: async () => chunked,
    }).auditExport())
      got.push(l.seq);
    expect(got).toEqual([1, 2]);
  });

  it("auditExport surfaces HTTP and parse errors", async () => {
    const bad = mockFetch(() => jsonResponse({ error: "unauthorized" }, 401));
    await expect(
      (async () => {
        for await (const _ of new AdminClient(URL_, "x", { fetch: bad.fetch }).auditExport())
          void _;
      })(),
    ).rejects.toBeInstanceOf(ApiError);
    const junk = mockFetch(() => new Response("nope\n"));
    await expect(
      (async () => {
        for await (const _ of new AdminClient(URL_, "x", { fetch: junk.fetch }).auditExport())
          void _;
      })(),
    ).rejects.toBeInstanceOf(OnbehalfError);
  });

  it("tails an empty log", async () => {
    const { fetch } = mockFetch((s) =>
      s.url.pathname.endsWith("checkpoint")
        ? jsonResponse({ seq: null, hash: null })
        : jsonResponse({ entries: [], next: null, head: 0 }),
    );
    expect(await new AdminClient(URL_, "adm", { fetch }).auditTail(5)).toEqual([]);
  });

  it("reads the checkpoint and the verify report", async () => {
    const { fetch } = mockFetch((s) =>
      s.url.pathname.endsWith("checkpoint")
        ? jsonResponse({ seq: 4, hash: "abc" })
        : jsonResponse({ ok: false, entries: 4, first_bad_seq: 3 }),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    expect(await admin.auditCheckpoint()).toEqual({ seq: 4, hash: "abc" });
    expect(await admin.auditVerify()).toEqual({ ok: false, entries: 4, firstBadSeq: 3 });
  });

  it("reloads policy and surfaces a 422 as ApiError", async () => {
    const ok = mockFetch(() => jsonResponse({ policy_ids: ["p1", "p2"], warnings: ["w"] }));
    expect(await new AdminClient(URL_, "adm", { fetch: ok.fetch }).policyReload()).toEqual({
      policyIds: ["p1", "p2"],
      warnings: ["w"],
    });
    expect(ok.calls[0]!.url.pathname).toBe("/admin/policies/reload");
    const bad = mockFetch(() =>
      jsonResponse({ error: "invalid_policy", detail: "parse error" }, 422),
    );
    await expect(
      new AdminClient(URL_, "adm", { fetch: bad.fetch }).policyReload(),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("mints a dev root token", async () => {
    const { fetch, calls } = mockFetch(() => jsonResponse(tokenResponse(rootJwt, "lease-0")));
    const admin = new AdminClient(URL_, "adm", { fetch });
    const tok = await admin.mintRootDev("alice", "https://idp.example", "planner", {
      capabilities: [capability("github", "read_file", { repo: prefix("a/") }), "github:list"],
      ttlSeconds: 60,
      attributes: { mfa: true },
    });
    expect(tok.subject).toBe("alice");
    expect(calls[0]!.url.pathname).toBe("/admin/root-token");
    expect(calls[0]!.body).toEqual({
      subject: "alice",
      issuer: "https://idp.example",
      agent: "planner",
      capabilities: [
        {
          server: "github",
          tool: "read_file",
          constraints: { repo: { op: "prefix", value: "a/" } },
        },
        { server: "github", tool: "list" },
      ],
      ttl_seconds: 60,
      attributes: { mfa: true },
    });
    await admin.mintRootDev("alice", "i", "planner");
    expect(calls[1]!.body).toEqual({ subject: "alice", issuer: "i", agent: "planner" });
    await admin.mintRootDev("alice", "i", "planner", { mayAct: ["coder", "reviewer"] });
    expect(calls[2]!.body).toEqual({
      subject: "alice",
      issuer: "i",
      agent: "planner",
      may_act: { sub: ["coder", "reviewer"] },
    });
    // An empty list is sent: nobody may exchange the token.
    await admin.mintRootDev("alice", "i", "planner", { mayAct: [] });
    expect(calls[3]!.body).toMatchObject({ may_act: { sub: [] } });
    await expect(
      admin.mintRootDev("alice", "i", "planner", { mayAct: "coder" as unknown as string[] }),
    ).rejects.toThrow(TypeError);
    await expect(admin.mintRootDev("alice", "i", "planner", { mayAct: [""] })).rejects.toThrow(
      TypeError,
    );
    expect(calls).toHaveLength(4);
  });

  it("maps a wrong admin token to ApiError 401", async () => {
    const { fetch } = mockFetch(() =>
      jsonResponse({ error: "unauthorized", detail: "bad admin token" }, 401),
    );
    await expect(new AdminClient(URL_, "wrong", { fetch }).auditVerify()).rejects.toMatchObject({
      status: 401,
    });
  });
});

import { beforeAll, describe, expect, it } from "vitest";
import { AdminClient, ApiError, capability, AttenuoError, prefix } from "../src/index.js";
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
    expect(calls[0]!.url.searchParams.has("kind")).toBe(false);

    const filtered = mockFetch(() => new Response('{"type":"header"}\n'));
    const seen = [];
    for await (const l of new AdminClient(URL_, "adm", { fetch: filtered.fetch }).auditExport(
      3,
      undefined,
      { kind: "lease_renew", chainId: "l 1" },
    ))
      seen.push(l.type);
    expect(seen).toEqual(["header"]);
    const q = filtered.calls[0]!.url.searchParams;
    expect([q.get("from"), q.get("kind"), q.get("chain_id")]).toEqual(["3", "lease_renew", "l 1"]);

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
    ).rejects.toBeInstanceOf(AttenuoError);
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

describe("AdminClient console endpoints", () => {
  const deny = (seq: number) => ({ seq, record: { ...entry(seq).record, decision: "deny" } });

  it("filters newest first and follows prev across a short page", async () => {
    const { fetch, calls } = mockFetch((s) =>
      s.url.searchParams.has("before")
        ? jsonResponse({ entries: [deny(4), deny(2)], next: 10, prev: null, head: 12 })
        : jsonResponse({ entries: [deny(9)], next: null, prev: 9, head: 12 }),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    const query = {
      order: "desc",
      limit: 3,
      decision: "deny",
      kind: ["decision", "exchange"],
      lease: "l 1",
      since: new Date("2026-10-23T09:00:00Z"),
    } as const;
    const page = await admin.auditQuery(query);
    expect([page.next, page.prev, page.head]).toEqual([undefined, 9, 12]);
    expect(Object.fromEntries(calls[0]!.url.searchParams)).toEqual({
      order: "desc",
      limit: "3",
      decision: "deny",
      kind: "decision,exchange",
      lease: "l 1",
      since: "2026-10-23T09:00:00.000Z",
    });
    const seqs = [];
    for await (const e of admin.auditIter(query)) seqs.push(e.seq);
    expect(seqs).toEqual([9, 4, 2]);
    expect(calls[2]!.url.searchParams.get("before")).toBe("9");
  });

  it("iterates oldest first by next, and refuses a cursor that does not move", async () => {
    const asc = mockFetch((s) => {
      const from = Number(s.url.searchParams.get("from") ?? "1");
      return jsonResponse({ entries: [entry(from)], next: from >= 5 ? null : from + 4, head: 5 });
    });
    const seqs = [];
    for await (const e of new AdminClient(URL_, "adm", { fetch: asc.fetch }).auditIter({
      chainId: "c1",
    }))
      seqs.push(e.seq);
    expect(seqs).toEqual([1, 5]);
    expect(Object.fromEntries(asc.calls[0]!.url.searchParams)).toEqual({
      order: "asc",
      limit: "1000",
      chain_id: "c1",
    });
    const stuck = mockFetch(() => jsonResponse({ entries: [], prev: 5, head: 9 }));
    await expect(
      (async () => {
        for await (const _ of new AdminClient(URL_, "adm", { fetch: stuck.fetch }).auditIter({
          order: "desc",
          before: 5,
        }))
          void _;
      })(),
    ).rejects.toBeInstanceOf(AttenuoError);
  });

  const detail = {
    entry: { seq: 7, record: { id: "0b7c", kind: "decision", chain_id: "root" } },
    lease_states: [
      {
        lease_id: "root",
        known: true,
        active: true,
        parent: null,
        expires_at: "2026-10-23T10:00:00Z",
        revoked_at: null,
        revoke_reason: null,
      },
      { lease_id: "gone", known: false },
    ],
    covered_by_checkpoint: { seq: 10, head_hash: "hh" },
    policy_reloaded_after: null,
  };

  it("shows one entry by seq and by record id", async () => {
    const { fetch, calls } = mockFetch(() => jsonResponse(detail));
    const admin = new AdminClient(URL_, "adm", { fetch });
    const d = await admin.auditEntry(7);
    expect(calls[0]!.url.pathname).toBe("/admin/audit/entries/7");
    expect(d.entry.seq).toBe(7);
    expect(d.entry.chainId).toBe("root");
    expect(d.leaseStates.map((s) => [s.leaseId, s.known, s.active])).toEqual([
      ["root", true, true],
      ["gone", false, false],
    ]);
    expect(d.coveredByCheckpoint).toEqual({ seq: 10, head_hash: "hh" });
    expect(d.policyReloadedAfter).toBeUndefined();
    const r = await admin.auditRecord("0b7c/../x");
    expect(calls[1]!.url.pathname).toBe("/admin/audit/records/0b7c%2F..%2Fx");
    expect(r.entry.record.id).toBe("0b7c");
  });

  it("maps a missing entry to ApiError 404", async () => {
    const { fetch } = mockFetch(() =>
      jsonResponse({ error: "not_found", detail: "no entry at seq 99" }, 404),
    );
    await expect(new AdminClient(URL_, "adm", { fetch }).auditEntry(99)).rejects.toMatchObject({
      status: 404,
      error: "not_found",
    });
  });

  it("lists stored checkpoints without signing", async () => {
    const cps = [
      { seq: 20, head_hash: "a" },
      { seq: 10, head_hash: "b" },
    ];
    const { fetch, calls } = mockFetch(() => jsonResponse({ checkpoints: cps, prev: 10 }));
    const admin = new AdminClient(URL_, "adm", { fetch });
    expect(await admin.auditCheckpoints({ before: 30, limit: 2 })).toEqual({
      checkpoints: cps,
      prev: 10,
    });
    expect(calls[0]!.url.pathname).toBe("/admin/audit/checkpoints");
    expect(Object.fromEntries(calls[0]!.url.searchParams)).toEqual({ before: "30", limit: "2" });
    await admin.auditCheckpoints();
    expect(calls[1]!.url.search).toBe("");
  });

  it("reads a lease tree", async () => {
    const node = (id: string, parent: string | null, active = true) => ({
      lease_id: id,
      parent,
      agent: "coder",
      active,
      expires_at: "2026-10-23T19:20:00Z",
      revoked_at: null,
      revoke_reason: null,
      issued_at: parent ? "2026-10-23T19:05:00Z" : null,
      issued_seq: parent ? 42 : null,
    });
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({
        root: "r",
        ancestors: [node("r", null)],
        nodes: [node("l1", "r"), node("l2", "l1", false)],
        would_revoke: 1,
        truncated: false,
      }),
    );
    const tree = await new AdminClient(URL_, "adm", { fetch }).leaseTree("l1", 50);
    expect(calls[0]!.url.pathname).toBe("/admin/leases/l1/tree");
    expect(calls[0]!.url.searchParams.get("max_nodes")).toBe("50");
    expect(tree.root).toBe("r");
    expect(tree.wouldRevoke).toBe(1);
    expect(tree.truncated).toBe(false);
    expect(tree.nodes.map((n) => [n.leaseId, n.active, n.issuedSeq])).toEqual([
      ["l1", true, 42],
      ["l2", false, 42],
    ]);
    expect(tree.ancestors[0]!.issuedAt).toBeUndefined();
  });

  it("reads the policy set and the on-disk check", async () => {
    const { fetch, calls } = mockFetch((s) =>
      s.url.pathname.endsWith("/check")
        ? jsonResponse({
            path: "/etc/p.cedar",
            sha256: "41",
            loaded_sha256: "9f",
            differs_from_loaded: true,
            ok: false,
            error_count: 1,
            warning_count: 0,
            issues: [{ severity: "error", stage: "validate", message: "m", line: 3 }],
            policy_ids: ["a"],
          })
        : jsonResponse({
            path: "/etc/p.cedar",
            sha256: "9f",
            loaded_at: "2026-10-23T19:02:11Z",
            policy_ids: ["a"],
            warnings: [],
            policies: [{ id: "a", text: "permit(...);" }],
          }),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    const ps = await admin.policies();
    expect(calls[0]!.url.pathname).toBe("/admin/policies");
    expect(ps.policies).toEqual({ a: "permit(...);" });
    expect(ps.sha256).toBe("9f");
    const pc = await admin.policyCheck();
    expect(calls[1]!.url.pathname).toBe("/admin/policies/check");
    expect([pc.ok, pc.differsFromLoaded, pc.errorCount, pc.issues[0]!.line]).toEqual([
      false,
      true,
      1,
      3,
    ]);
  });

  it("dry-runs a policy evaluation with a token or a chain", async () => {
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({
        decision: "allow",
        reason: "policy_allow",
        policy_ids: ["a"],
        diagnostics: [],
        lease_check: "skipped",
        chain_source: "token",
        token_expired: true,
      }),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    const ev = await admin.policyEvaluate(
      "github",
      "read_file",
      { repo: "alice/x" },
      { token: " tok " },
    );
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url.pathname).toBe("/admin/policies/evaluate");
    expect(calls[0]!.body).toMatchObject({
      token: "tok",
      resource: { type: "tool", id: "github/read_file" },
      context: { input: { repo: "alice/x" } },
    });
    expect(ev).toEqual({
      decision: "allow",
      allowed: true,
      reason: "policy_allow",
      policyIds: ["a"],
      diagnostics: [],
      leaseCheck: "skipped",
      chainSource: "token",
      tokenExpired: true,
    });
    await admin.policyEvaluate("github", "read_file", undefined, { chain: { hops: [] } });
    const sent = calls[1]!.body as Record<string, Record<string, unknown>>;
    expect(sent.token).toBeUndefined();
    expect(sent.subject!.properties).toEqual({ chain: { hops: [] } });
    await expect(admin.policyEvaluate("github", "read_file")).rejects.toThrow(TypeError);
  });
});

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

  it("sends the tool and decision export filters", async () => {
    const { fetch, calls } = mockFetch(() => new Response('{"type":"header"}\n'));
    const admin = new AdminClient(URL_, "adm", { fetch });
    for await (const _ of admin.auditExport(1, undefined, {
      tool: "token.exchange",
      decision: "deny",
    }))
      void _;
    expect(calls[0]!.url.search).toBe("?from=1&tool=token.exchange&decision=deny");
    for await (const _ of admin.auditExport(2, 9, {
      kind: "decision",
      chainId: "c1",
      tool: "read_file",
      decision: "allow",
    }))
      void _;
    expect(Object.fromEntries(calls[1]!.url.searchParams)).toEqual({
      from: "2",
      to: "9",
      kind: "decision",
      chain_id: "c1",
      tool: "read_file",
      decision: "allow",
    });
    const bad = mockFetch(() => jsonResponse({ error: "invalid_request" }, 400));
    await expect(
      (async () => {
        const it = new AdminClient(URL_, "adm", { fetch: bad.fetch }).auditExport(1, undefined, {
          decision: "maybe" as "deny",
        });
        for await (const _ of it) void _;
      })(),
    ).rejects.toMatchObject({ status: 400 });
  });

  const selected = {
    selector: { chain_id: "c1" },
    preview: false,
    matched: ["c1"],
    revoked: ["c1", "c2"],
    matched_count: 1,
    revoked_count: 2,
    truncated: false,
    reason: "run went wrong",
    audit_id: "3f2a",
  };

  it("revokes by selector", async () => {
    const { fetch, calls } = mockFetch(() => jsonResponse(selected));
    const admin = new AdminClient(URL_, "adm", { fetch });
    expect(await admin.revokeBySelector({ chainId: "c1" }, { reason: "run went wrong" })).toEqual({
      selector: { chain_id: "c1" },
      preview: false,
      matched: ["c1"],
      revoked: ["c1", "c2"],
      matchedCount: 1,
      revokedCount: 2,
      truncated: false,
      reason: "run went wrong",
      auditId: "3f2a",
    });
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url.pathname).toBe("/admin/leases/revoke");
    expect(calls[0]!.url.search).toBe("");
    expect(calls[0]!.body).toEqual({ chain_id: "c1", reason: "run went wrong" });

    await admin.revokeBySelector({ user: "alice@example.com" }, { preview: true });
    expect(calls[1]!.url.search).toBe("?preview=true");
    expect(calls[1]!.body).toEqual({ user: "alice@example.com" });
  });

  it("reads a preview answer for a session", async () => {
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({
        selector: { session_tag: "a1b2c3d4e5f6", chain_ids: [] },
        preview: true,
        matched: [],
        revoked: [],
        matched_count: 0,
        revoked_count: 0,
        truncated: false,
        reason: null,
        audit_id: null,
      }),
    );
    const res = await new AdminClient(URL_, "adm", { fetch }).revokeBySelector(
      { session: "sid-secret" },
      { preview: true },
    );
    expect(calls[0]!.body).toEqual({ session: "sid-secret" });
    expect(res).toMatchObject({ preview: true, matched: [], revoked: [] });
    expect(res.reason).toBeUndefined();
    expect(res.auditId).toBeUndefined();
    expect(res.selector).toEqual({ session_tag: "a1b2c3d4e5f6", chain_ids: [] });
  });

  it.each([
    [{}],
    [{ user: "a", chainId: "c" }],
    [{ chainId: "c", session: "s" }],
    [{ user: "a", chainId: "c", session: "s" }],
    [{ user: "" }],
    [{ session: "" }],
  ])("refuses anything but exactly one selector: %j", async (sel) => {
    const { fetch, calls } = mockFetch(() => jsonResponse(selected));
    const admin = new AdminClient(URL_, "adm", { fetch });
    await expect(
      admin.revokeBySelector(sel as unknown as Parameters<AdminClient["revokeBySelector"]>[0]),
    ).rejects.toThrow(/exactly one|non-empty/);
    expect(calls).toHaveLength(0);
  });

  it("never logs or echoes the session id", async () => {
    const secret = "mcp-session-9f8e7d6c5b4a";
    const logged: string[] = [];
    const methods = ["log", "info", "warn", "error", "debug"] as const;
    const saved = methods.map((m) => console[m]);
    for (const m of methods) console[m] = (...a: unknown[]) => void logged.push(a.join(" "));
    try {
      const bad = mockFetch(() => jsonResponse({ error: "invalid_request" }, 400));
      const err = await new AdminClient(URL_, "adm", { fetch: bad.fetch })
        .revokeBySelector({ session: secret }, { preview: true })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ApiError);
      expect(String(err)).not.toContain(secret);
      const ok = mockFetch(() => jsonResponse(selected));
      const res = await new AdminClient(URL_, "adm", { fetch: ok.fetch }).revokeBySelector({
        session: secret,
      });
      expect(JSON.stringify(res)).not.toContain(secret);
      const both = { session: secret, user: "alice" } as unknown as { session: string };
      const refused = await new AdminClient(URL_, "adm", { fetch: ok.fetch })
        .revokeBySelector(both)
        .catch((e: unknown) => e);
      expect(String(refused)).not.toContain(secret);
    } finally {
      methods.forEach((m, i) => (console[m] = saved[i]!));
    }
    expect(logged.join("\n")).not.toContain(secret);
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
      budget: parent
        ? {
            recorded: true,
            limits: [
              {
                cap: 0,
                server: "bank",
                tool: "pay",
                kind: "calls",
                arg: null,
                max: 2,
                used: 1,
                remaining: 1,
              },
            ],
            usage: [],
          }
        : null,
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
    expect(tree.ancestors[0]!.budget).toBeUndefined();
    expect(tree.nodes[0]!.budget!.limits[0]).toEqual({
      cap: 0,
      server: "bank",
      tool: "pay",
      kind: "calls",
      arg: undefined,
      max: 2,
      used: 1,
      remaining: 1,
      values: undefined,
    });
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

const approvalBody = (state = "pending", extra: Record<string, unknown> = {}) => ({
  approval_id: "a1",
  state,
  expired: false,
  chain_id: "c1",
  lease: "l1",
  call_hash: "h",
  decision_id: "d1",
  call: { server: "github", tool: "delete_repo", arguments: { repo: "x" } },
  labels: [{ seq: 4 }],
  subject: "alice",
  issuer: "https://idp",
  agents: ["planner"],
  created_at: "2026-10-24T10:00:00Z",
  expires_at: "2026-10-24T10:02:00Z",
  ...extra,
});

describe("AdminClient approvals", () => {
  it("lists approvals with filters and reads one", async () => {
    const { fetch, calls } = mockFetch((s) =>
      s.url.pathname === "/admin/approvals"
        ? jsonResponse({ approvals: [approvalBody()] })
        : jsonResponse(approvalBody()),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    const list = await admin.approvals({ chainId: "c1", state: "pending", limit: 10 });
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.url.pathname).toBe("/admin/approvals");
    expect(Object.fromEntries(calls[0]!.url.searchParams)).toEqual({
      chain_id: "c1",
      state: "pending",
      limit: "10",
    });
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer adm");
    expect(list.map((a) => a.approvalId)).toEqual(["a1"]);
    expect(list[0]!.tool).toBe("delete_repo");
    expect(list[0]!.arguments).toEqual({ repo: "x" });
    expect(list[0]!.usable).toBe(false);
    expect(list[0]!.raw.decision_id).toBe("d1");
    await admin.approvals();
    expect(calls[1]!.url.search).toBe("");

    const a = await admin.approval("../a1");
    expect(calls[2]!.url.pathname).toBe("/admin/approvals/..%2Fa1");
    expect(a.state).toBe("pending");
    expect(a.chainId).toBe("c1");
  });

  it("grants and declines as the operator", async () => {
    const { fetch, calls } = mockFetch((s) => {
      const decision = (s.body as { decision: string }).decision;
      return jsonResponse(
        approvalBody(decision === "grant" ? "granted" : "declined", {
          approver: { subject: "urn:attenuo:admin", method: "admin_token", by: "operator" },
        }),
      );
    });
    const admin = new AdminClient(URL_, "adm", { fetch });
    const granted = await admin.grantApproval("a1");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url.pathname).toBe("/admin/approvals/a1");
    expect(calls[0]!.body).toEqual({ decision: "grant" });
    expect(granted.usable).toBe(true);
    expect(granted.approver?.by).toBe("operator");
    const declined = await admin.declineApproval("a1");
    expect(calls[1]!.body).toEqual({ decision: "decline" });
    expect(declined.state).toBe("declined");
    expect(declined.usable).toBe(false);
  });

  it("surfaces 409 and 404 as ApiError", async () => {
    const { fetch } = mockFetch((s) =>
      s.method === "POST"
        ? jsonResponse({ error: "approval_not_pending", detail: "already granted" }, 409)
        : jsonResponse({ error: "not_found", detail: "unknown approval" }, 404),
    );
    const admin = new AdminClient(URL_, "adm", { fetch });
    await expect(admin.grantApproval("a1")).rejects.toMatchObject({
      status: 409,
      error: "approval_not_pending",
    });
    await expect(admin.approval("nope")).rejects.toBeInstanceOf(ApiError);
  });
});

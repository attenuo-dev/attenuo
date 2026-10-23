import { beforeAll, describe, expect, it } from "vitest";
import { AdminClient, ApiError, capability, prefix } from "../src/index.js";
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

  it("tails the log from the checkpoint, following next", async () => {
    const { fetch, calls } = mockFetch((s) => {
      if (s.url.pathname === "/admin/audit/checkpoint") return jsonResponse({ seq: 10, hash: "h" });
      const from = Number(s.url.searchParams.get("from"));
      return from === 8
        ? jsonResponse({ entries: [entry(8), entry(9)], next: 10 })
        : jsonResponse({ entries: [entry(10)], next: null });
    });
    const tail = await new AdminClient(URL_, "adm", { fetch }).auditTail(3);
    expect(tail.map((e) => e.seq)).toEqual([8, 9, 10]);
    expect(calls.map((c) => c.url.pathname)).toEqual([
      "/admin/audit/checkpoint",
      "/admin/audit",
      "/admin/audit",
    ]);
  });

  it("tails an empty log", async () => {
    const { fetch } = mockFetch((s) =>
      s.url.pathname.endsWith("checkpoint")
        ? jsonResponse({ seq: null, hash: null })
        : jsonResponse({ entries: [], next: null }),
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

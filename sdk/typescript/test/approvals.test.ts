import { describe, expect, it } from "vitest";
import {
  ApiError,
  ApprovalNotGrantedError,
  ApprovalRequiredError,
  AttenuoClient,
  DeniedError,
  DpopKey,
  RpcError,
} from "../src/index.js";
import { jsonResponse, mockFetch, rpcErr, rpcOk, type Seen } from "./helpers.js";

const URL_ = "http://ob.test";
const APPROVAL_ID = "0f8e6c1a-4b7d-4f61-9a39-2f4f5b0e8d11";
const HASH = "ab".repeat(32);

function gated(approvalId: string | null = APPROVAL_ID, header = "dec-1"): Response {
  const data: Record<string, unknown> = {
    reason: "approval_required",
    decision_id: "dec-1",
    call_hash: HASH,
  };
  if (approvalId !== null) {
    data.approval_id = approvalId;
    data.expires_at = "2026-10-24T10:02:00.123456789Z";
  }
  return rpcErr(-32008, "attenuo: approval required", data, 200, {
    "x-attenuo-decision-id": header,
  });
}

function allowed(): Response {
  return rpcOk({ content: [{ type: "text", text: "done" }] }, { "x-attenuo-decision-id": "dec-2" });
}

function approval(state: string, expired = false, extra: Record<string, unknown> = {}): Response {
  return jsonResponse({
    approval_id: APPROVAL_ID,
    state,
    expired,
    chain_id: "lease-0",
    lease: "lease-0",
    call_hash: HASH,
    call: { server: "github", tool: "delete_repo", arguments: { repo: "alice/site" } },
    labels: [{ source: "github/read_web", seq: 3 }],
    decision_id: "dec-1",
    subject: "alice",
    issuer: "https://idp.example",
    agents: ["planner"],
    created_at: "2026-10-24T10:00:00Z",
    expires_at: "2026-10-24T10:02:00Z",
    ...extra,
  });
}

function sequence(...answers: Array<() => Response>) {
  return mockFetch((_: Seen) => {
    const next = answers.shift();
    if (!next) throw new Error("no more answers");
    return next();
  });
}

describe("-32008 approval required", () => {
  it("throws ApprovalRequiredError, a DeniedError carrying the approval", async () => {
    const { fetch } = mockFetch(() => gated());
    const err = await new AttenuoClient(URL_, { fetch })
      .callTool("TOK", "github", "delete_repo", { repo: "alice/site" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalRequiredError);
    expect(err).toBeInstanceOf(DeniedError);
    const e = err as ApprovalRequiredError;
    expect(e).toMatchObject({
      reason: "approval_required",
      decisionId: "dec-1",
      approvalId: APPROVAL_ID,
      callHash: HASH,
    });
    expect(e.expiresAt?.toISOString()).toBe("2026-10-24T10:02:00.123Z");
  });

  it("has no approval id when the server could not open one", async () => {
    const { fetch } = mockFetch(() => gated(null));
    const err = await new AttenuoClient(URL_, { fetch })
      .callTool("TOK", "github", "delete_repo")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalRequiredError);
    expect((err as ApprovalRequiredError).approvalId).toBeUndefined();
  });

  it("treats an upstream's own -32008 as an RpcError", async () => {
    const { fetch } = mockFetch(() => gated(APPROVAL_ID, "another-decision"));
    const err = await new AttenuoClient(URL_, { fetch })
      .callTool("TOK", "github", "delete_repo")
      .catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(DeniedError);
    expect(err).toBeInstanceOf(RpcError);
    expect(err).toMatchObject({ code: -32008 });
  });
});

describe("getApproval", () => {
  it("GETs /approvals/{id} with the bearer and parses the answer", async () => {
    const { fetch, calls } = mockFetch(() =>
      approval("granted", false, { approver: { subject: "alice", by: "user" } }),
    );
    const a = await new AttenuoClient(URL_, { fetch }).getApproval(APPROVAL_ID, "TOK");
    expect(a).toMatchObject({
      approvalId: APPROVAL_ID,
      state: "granted",
      usable: true,
      server: "github",
      tool: "delete_repo",
      arguments: { repo: "alice/site" },
      approver: { subject: "alice", by: "user" },
    });
    const c = calls[0]!;
    expect(c.method).toBe("GET");
    expect(c.url.pathname).toBe(`/approvals/${APPROVAL_ID}`);
    expect(c.headers.get("authorization")).toBe("Bearer TOK");
    expect(c.body).toBeUndefined();
  });

  it("signs a GET proof with the client's DPoP key", async () => {
    const { fetch, calls } = mockFetch(() => approval("pending"));
    const dpopKey = await DpopKey.generate();
    await new AttenuoClient(URL_, { fetch, dpopKey }).getApproval(APPROVAL_ID, "TOK");
    const c = calls[0]!;
    expect(c.headers.get("authorization")).toBe("DPoP TOK");
    const part = c.headers.get("dpop")!.split(".")[1]!;
    const claims = JSON.parse(Buffer.from(part, "base64url").toString()) as Record<string, unknown>;
    expect(claims.htm).toBe("GET");
    expect(claims.htu).toBe(`${URL_}/approvals/${APPROVAL_ID}`);
  });

  it("refuses ids that are not one path segment, and passes 404 through", async () => {
    const { fetch } = mockFetch(() => jsonResponse({ error: "not_found", detail: "x" }, 404));
    const ob = new AttenuoClient(URL_, { fetch });
    await expect(ob.getApproval("..", "TOK")).rejects.toThrow(TypeError);
    const err = await ob.getApproval(APPROVAL_ID, "TOK").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(404);
  });
});

describe("waitForApproval", () => {
  it("polls until granted", async () => {
    const { fetch, calls } = sequence(
      () => approval("pending"),
      () => approval("pending"),
      () => approval("granted"),
    );
    const a = await new AttenuoClient(URL_, { fetch }).waitForApproval(APPROVAL_ID, "TOK", {
      intervalMs: 0,
    });
    expect(a.state).toBe("granted");
    expect(calls).toHaveLength(3);
  });

  it.each([
    ["declined", false, "declined"],
    ["consumed", false, "consumed"],
    ["pending", true, "expired"],
    ["granted", true, "expired"],
  ])("stops on %s (expired %s) with %s", async (state, expired, want) => {
    const { fetch } = mockFetch(() => approval(state, expired));
    const err = await new AttenuoClient(URL_, { fetch })
      .waitForApproval(APPROVAL_ID, "TOK", { intervalMs: 0 })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalNotGrantedError);
    expect(err).toMatchObject({ approvalId: APPROVAL_ID, state: want });
  });

  it("gives up after timeoutMs", async () => {
    const { fetch } = mockFetch(() => approval("pending"));
    const err = await new AttenuoClient(URL_, { fetch })
      .waitForApproval(APPROVAL_ID, "TOK", { timeoutMs: 30, intervalMs: 5 })
      .catch((e: unknown) => e);
    expect(err).toMatchObject({ state: "timeout" });
  });
});

describe("callToolWithApproval", () => {
  it("retries the identical call once after the grant", async () => {
    const { fetch, calls } = sequence(
      () => gated(),
      () => approval("pending"),
      () => approval("granted"),
      () => allowed(),
    );
    const shown: Array<string | undefined> = [];
    const r = await new AttenuoClient(URL_, { fetch }).callToolWithApproval(
      "TOK",
      "github",
      "delete_repo",
      { repo: "alice/site" },
      { intervalMs: 0, onApproval: (e) => void shown.push(e.approvalId) },
    );
    expect(r.text).toBe("done");
    expect(shown).toEqual([APPROVAL_ID]);
    const posts = calls.filter((c) => c.method === "POST");
    expect(posts).toHaveLength(2);
    const [first, retry] = posts.map((c) => (c.body as Record<string, unknown>).params);
    expect(retry).toEqual(first);
  });

  it("throws a second -32008, a decline, and an approval without an id", async () => {
    let s = sequence(
      () => gated(),
      () => approval("granted"),
      () => gated(),
    );
    await expect(
      new AttenuoClient(URL_, { fetch: s.fetch }).callToolWithApproval(
        "TOK",
        "g",
        "t",
        {},
        {
          intervalMs: 0,
        },
      ),
    ).rejects.toBeInstanceOf(ApprovalRequiredError);

    s = sequence(
      () => gated(),
      () => approval("declined"),
    );
    const err = await new AttenuoClient(URL_, { fetch: s.fetch })
      .callToolWithApproval("TOK", "g", "t", {}, { intervalMs: 0 })
      .catch((e: unknown) => e);
    expect(err).toMatchObject({ state: "declined" });
    expect(s.calls.map((c) => c.method)).toEqual(["POST", "GET"]);

    s = sequence(() => gated(null));
    await expect(
      new AttenuoClient(URL_, { fetch: s.fetch }).callToolWithApproval("TOK", "g", "t"),
    ).rejects.toBeInstanceOf(ApprovalRequiredError);
    expect(s.calls).toHaveLength(1);
  });
});

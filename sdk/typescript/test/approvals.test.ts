import { describe, expect, it } from "vitest";
import {
  ApiError,
  ApprovalNotGrantedError,
  ApprovalRequiredError,
  AttenuoClient,
  DeniedError,
  DpopKey,
  RpcError,
  UnauthorizedError,
  VerificationError,
  callHash,
  verifyApprovalToken,
} from "../src/index.js";
import { Signer, jsonResponse, mockFetch, rpcErr, rpcOk, type Seen } from "./helpers.js";

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

describe("too many pending approvals", () => {
  it("passes the server's 429 through as an ApiError", async () => {
    const { fetch } = mockFetch(() =>
      jsonResponse(
        {
          error: "too_many_pending_approvals",
          detail: "the run already has 32 pending approvals",
        },
        429,
      ),
    );
    const err = await new AttenuoClient(URL_, { fetch })
      .getApproval(APPROVAL_ID, "TOK")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect([(err as ApiError).status, (err as ApiError).error]).toEqual([
      429,
      "too_many_pending_approvals",
    ]);
  });

  it("reads an AuthZEN approval_required with and without an approval", async () => {
    const ctx = {
      reason: "approval_required",
      policy_ids: ["ask"],
      diagnostics: [],
      decision_id: "d3",
      call_hash: HASH,
      approval_id: APPROVAL_ID,
      expires_at: "2026-11-06T10:02:00.5Z",
    };
    const one = mockFetch(() => jsonResponse({ decision: false, context: ctx }));
    const d = await new AttenuoClient(URL_, { fetch: one.fetch }).authzenEvaluate("TOK", "g", "t");
    expect([d.decision, d.reason, d.approvalId, d.callHash]).toEqual([
      false,
      "approval_required",
      APPROVAL_ID,
      HASH,
    ]);
    expect(d.expiresAt?.toISOString()).toBe("2026-11-06T10:02:00.500Z");

    // The run already holds as many pending approvals as the server keeps: none is opened,
    // and a PEP with diagnostics is told why (SR-92).
    const full = mockFetch(() =>
      jsonResponse({
        decision: false,
        context: {
          reason: "approval_required",
          policy_ids: ["ask"],
          diagnostics: ["too many pending approvals for this run"],
          decision_id: "d4",
          call_hash: HASH,
        },
      }),
    );
    const f = await new AttenuoClient(URL_, { fetch: full.fetch }).authzenEvaluate("TOK", "g", "t");
    expect(f.reason).toBe("approval_required");
    expect([f.approvalId, f.expiresAt, f.callHash]).toEqual([undefined, undefined, HASH]);
    expect(f.diagnostics).toEqual(["too many pending approvals for this run"]);
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

// --- signed approval tokens ---------------------------------------------------------------------

const JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

function approvalToken(
  signer: Signer,
  o: { typ?: string; expDelta?: number; claims?: Record<string, unknown> } = {},
): Promise<string> {
  return signer.mint({
    header: { typ: o.typ ?? "attenuo-approval+jwt" },
    expDelta: o.expDelta ?? 120,
    claims: {
      by: "user",
      chain_id: "lease-0",
      lease: "lease-1",
      ch: HASH,
      jti: APPROVAL_ID,
      ...o.claims,
    },
  });
}

describe("approval tokens", () => {
  it("computes the call hash as the server does", async () => {
    const digest = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode('{"arguments":{"n":1,"to":"bob"},"server":"mail","tool":"send"}'),
      ),
    );
    const expected = Buffer.from(digest).toString("hex");
    expect(await callHash("mail", "send", { to: "bob", n: 1 })).toBe(expected);
    expect(await callHash("mail", "send", { to: "eve", n: 1 })).not.toBe(expected);
    expect(await callHash("mail", "send")).toBe(await callHash("mail", "send", {}));
  });

  it("verifies signature, typ, expiry and the binding", async () => {
    const signer = await Signer.create();
    const token = await approvalToken(signer, { claims: { cnf: { jkt: JKT } } });
    const c = await verifyApprovalToken(token, signer.jwks, {
      chainId: "lease-0",
      lease: "lease-1",
      callHash: HASH,
      jkt: JKT,
      issuer: "http://ob.test",
      audience: "attenuo",
    });
    expect(c).toMatchObject({ approvalId: APPROVAL_ID, approver: "alice", by: "user", jkt: JKT });
    for (const opts of [
      { chainId: "other" },
      { lease: "lease-2" },
      { callHash: "cd".repeat(32) },
      { jkt: null },
      { jkt: "other" },
      { issuer: "http://evil" },
      { audience: "x" },
    ]) {
      await expect(verifyApprovalToken(token, signer.jwks, opts)).rejects.toBeInstanceOf(
        VerificationError,
      );
    }
    const bearer = await approvalToken(signer);
    expect((await verifyApprovalToken(bearer, signer.jwks, { jkt: null })).jkt).toBeUndefined();
    await expect(verifyApprovalToken(bearer, signer.jwks, { jkt: JKT })).rejects.toThrow("cnf.jkt");
    await expect(
      verifyApprovalToken(await approvalToken(signer, { expDelta: -1 }), signer.jwks),
    ).rejects.toThrow("expired");
    await expect(
      verifyApprovalToken(await approvalToken(signer, { typ: "attenuo+jwt" }), signer.jwks),
    ).rejects.toThrow("typ");
    await expect(verifyApprovalToken(token, (await Signer.create()).jwks)).rejects.toBeInstanceOf(
      VerificationError,
    );
    const [head, , sig] = token.split(".");
    const other = (await approvalToken(signer, { claims: { ch: "cd".repeat(32) } })).split(".")[1];
    await expect(
      verifyApprovalToken(`${head}.${other}.${sig}`, signer.jwks),
    ).rejects.toBeInstanceOf(VerificationError);
    await expect(verifyApprovalToken("nope", signer.jwks)).rejects.toBeInstanceOf(
      VerificationError,
    );
  });

  // Signed by the Rust issuer (`wire_format_is_pinned_for_the_sdks` in attenuo-token).
  const RUST_TOKEN =
    "eyJ0eXAiOiJhdHRlbnVvLWFwcHJvdmFsK2p3dCIsImFsZyI6IkVkRFNBIiwia2lkIjoiMU9pU0E5bUd3Um54azdwZl" +
    "AyQ0NHdyJ9.eyJpc3MiOiJodHRwczovL2F0dGVudW8udGVzdCIsImF1ZCI6ImF0dGVudW8iLCJzdWIiOiJhbGljZSI" +
    "sImJ5IjoidXNlciIsImNoYWluX2lkIjoibGVhc2Utcm9vdCIsImxlYXNlIjoibGVhc2UtaG9wIiwiY2giOiJhYmFiY" +
    "WJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwiaWF0Ijo" +
    "xNzkyODQzMjAwLCJleHAiOjE3OTI4NDMzMjAsImp0aSI6IjBmOGU2YzFhLTRiN2QtNGY2MS05YTM5LTJmNGY1YjBlO" +
    "GQxMSIsImNuZiI6eyJqa3QiOiIwWmNPQ09SWk5ZeS1EV3BxcTMwalp5SkdIVE4wZDJIZ2xCVjN1aWd1QTRJIn19.YM" +
    "QGXdHjU1Mzr1i15LY7f74Zl6XliQFvHVBs1FzW0mahmH_ngo3PHkfsZWltnvBvsLrv5GQuSXmCxg-IP45kAw";
  const RUST_JWKS = {
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        alg: "EdDSA",
        use: "sig",
        kid: "1OiSA9mGwRnxk7pfP2CCGw",
        x: "psIk2NjWmiuoUxoim49SIawYPoOBE8gaMWWVX9fpjVU",
      },
    ],
  };
  const RUST_IAT = 1792843200;

  it("verifies a token signed by the server", async () => {
    const c = await verifyApprovalToken(RUST_TOKEN, RUST_JWKS, {
      chainId: "lease-root",
      lease: "lease-hop",
      callHash: HASH,
      jkt: JKT,
      issuer: "https://attenuo.test",
      audience: "attenuo",
      now: RUST_IAT,
    });
    expect(c.approvalId).toBe(APPROVAL_ID);
    expect(c.expiresAt.getTime() / 1000).toBe(RUST_IAT + 120);
    await expect(
      verifyApprovalToken(RUST_TOKEN, RUST_JWKS, { now: RUST_IAT + 120 }),
    ).rejects.toThrow("expired");
  });

  it("parses approvalToken and retries with it in _meta", async () => {
    const { fetch, calls } = sequence(
      () => gated(),
      () => approval("granted", false, { approval_token: "APPROVAL.TOKEN.X" }),
      () => allowed(),
    );
    const r = await new AttenuoClient(URL_, { fetch }).callToolWithApproval(
      "TOK",
      "github",
      "delete_repo",
      { repo: "alice/site" },
      { intervalMs: 0 },
    );
    expect(r.text).toBe("done");
    const [first, retry] = calls
      .filter((c) => c.method === "POST")
      .map((c) => (c.body as Record<string, unknown>).params);
    expect(first).toEqual({ name: "delete_repo", arguments: { repo: "alice/site" } });
    expect(retry).toEqual({
      name: "delete_repo",
      arguments: { repo: "alice/site" },
      _meta: { "dev.attenuo/approval": "APPROVAL.TOKEN.X" },
    });
    const { fetch: f2 } = mockFetch(() => approval("pending"));
    const pending = await new AttenuoClient(URL_, { fetch: f2 }).getApproval(APPROVAL_ID, "TOK");
    expect(pending.approvalToken).toBeUndefined();
  });

  it("callTool sends approvalToken in _meta", async () => {
    const { fetch, calls } = mockFetch(() => allowed());
    await new AttenuoClient(URL_, { fetch }).callTool(
      "TOK",
      "github",
      "delete_repo",
      { repo: "a" },
      { approvalToken: "T" },
    );
    const params = (calls[0]?.body as Record<string, Record<string, unknown>>).params;
    expect(params?._meta).toEqual({ "dev.attenuo/approval": "T" });
  });
});

describe("the user's own decision (K-5)", () => {
  it("posts the decision with the ID token as a plain bearer", async () => {
    const approver = { subject: "alice", method: "id_token", by: "user" };
    const { fetch, calls } = mockFetch((s) =>
      (s.body as { decision: string }).decision === "grant"
        ? approval("granted", false, { approver, approval_token: "a.b.c" })
        : approval("declined", false, { approver }),
    );
    const ob = new AttenuoClient(URL_, {
      fetch,
      token: "DELEGATION",
      dpopKey: await DpopKey.generate(),
    });
    const granted = await ob.grantApproval(APPROVAL_ID, " ID-TOKEN ");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url.pathname).toBe(`/approvals/${APPROVAL_ID}`);
    // The ID token, never the client's delegation token, never DPoP.
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer ID-TOKEN");
    expect(calls[0]!.headers.has("dpop")).toBe(false);
    expect(calls[0]!.body).toEqual({ decision: "grant" });
    expect(granted).toMatchObject({ state: "granted", usable: true, approvalToken: "a.b.c" });
    expect(granted.approver?.by).toBe("user");

    const declined = await ob.declineApproval(APPROVAL_ID, "ID-TOKEN");
    expect(calls[1]!.body).toEqual({ decision: "decline" });
    expect(declined).toMatchObject({ state: "declined", usable: false });
  });

  it.each([
    [403, "agent_token_refused", undefined],
    [403, "wrong_user", undefined],
    [409, "approval_not_pending", undefined],
    [400, "invalid_grant", "replayed"],
    [404, "not_found", undefined],
  ])("throws %i %s as an ApiError", async (status, error, description) => {
    const body: Record<string, unknown> = { error, detail: "refused" };
    if (description !== undefined) body.error_description = description;
    const { fetch } = mockFetch(() => jsonResponse(body, status));
    const err = await new AttenuoClient(URL_, { fetch })
      .grantApproval(APPROVAL_ID, "ID-TOKEN")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status, error, description });
  });

  it("throws a 401 as UnauthorizedError, and refuses bad input before sending", async () => {
    const body = { error: "invalid_token", detail: "expired", error_description: "expired" };
    const { fetch, calls } = mockFetch(() => jsonResponse(body, 401));
    const ob = new AttenuoClient(URL_, { fetch });
    const err = await ob.declineApproval(APPROVAL_ID, "ID-TOKEN").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UnauthorizedError);
    expect(err).toMatchObject({ error: "invalid_token", description: "expired" });
    for (const bad of ["", "  "]) {
      await expect(ob.grantApproval(APPROVAL_ID, bad)).rejects.toThrow(/idToken/);
    }
    await expect(ob.grantApproval("..", "ID-TOKEN")).rejects.toBeInstanceOf(TypeError);
    expect(calls).toHaveLength(1);
  });
});

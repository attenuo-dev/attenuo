/** The server's load refusals (`[limits]`): typed errors, and the opt-in retry of them. */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AdminClient,
  ApiError,
  AttenuoClient,
  DeniedError,
  DpopKey,
  RateLimitedError,
  RpcError,
  TransportError,
  UnauthorizedError,
  UnavailableError,
  type ClientOptions,
  type StreamEvent,
} from "../src/index.js";
import { retryHooks } from "../src/retry.js";
import { assertionExpiry } from "../src/wire.js";
import { jsonResponse, mockFetch, rpcErr, rpcOk, Signer, tokenResponse } from "./helpers.js";

const BASE = "http://ob.test";
const DEC = "6f1c2d9e-0000-4000-8000-000000000001";

// --- the server's answers, as `crates/attenuo-server/src/limits.rs` and the proxy write them --

function restOverloaded(retryAfter: string | null = "1"): Response {
  return jsonResponse(
    {
      error: "temporarily_unavailable",
      detail: "the server is handling too many requests; retry later",
      error_description: "overloaded",
    },
    503,
    retryAfter === null ? {} : { "retry-after": retryAfter },
  );
}

function restHandlerTimeout(): Response {
  return jsonResponse(
    {
      error: "temporarily_unavailable",
      detail: "the request took too long to answer; retry later",
      error_description: "request_timeout",
    },
    503,
    { "retry-after": "1" },
  );
}

function restBodyTimeout(): Response {
  return jsonResponse(
    { error: "request_timeout", detail: "the request body did not arrive in time" },
    408,
  );
}

function restRateLimited(retryAfter: string | null = "42"): Response {
  return jsonResponse(
    {
      error: "rate_limited",
      detail: "too many token requests for this agent; retry later",
      error_description: "rate_limited",
    },
    429,
    retryAfter === null ? {} : { "retry-after": retryAfter },
  );
}

function mcpOverloaded(retryAfter: string | null = "1", reason = "overloaded"): Response {
  return rpcErr(
    -32006,
    `attenuo: temporarily unavailable: ${reason}`,
    { reason },
    503,
    retryAfter === null ? {} : { "retry-after": retryAfter },
  );
}

function mcpRateLimited(retryAfter: string | null = "17", reason = "rate_limited"): Response {
  return rpcErr(
    -32007,
    "attenuo: too many requests for this run; retry later",
    { reason },
    429,
    retryAfter === null ? {} : { "retry-after": retryAfter },
  );
}

function denial(): Response {
  return rpcErr(
    -32003,
    "attenuo: denied: policy_deny",
    { reason: "policy_deny", decision_id: DEC },
    200,
    { "x-attenuo-decision-id": DEC },
  );
}

const OK_TOOL = { content: [{ type: "text", text: "ok" }], isError: false };

function sseResult(text: string): Response {
  const msg = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text }] } };
  return new Response(`event: message\ndata: ${JSON.stringify(msg)}\n\n`, {
    headers: { "content-type": "text/event-stream" },
  });
}

async function caught(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("no error");
}

async function drain(it: AsyncIterable<StreamEvent>): Promise<StreamEvent[]> {
  const out: StreamEvent[] = [];
  for await (const ev of it) out.push(ev);
  return out;
}

function client(handler: Parameters<typeof mockFetch>[0], opts: ClientOptions = {}) {
  const m = mockFetch(handler);
  return { ob: new AttenuoClient(BASE, { fetch: m.fetch, ...opts }), calls: m.calls };
}

/** Answer with `responses` in order (each made fresh), then repeat the last one. */
function sequence(...responses: (() => Response)[]): () => Response {
  const left = [...responses];
  return () => (left.length > 1 ? left.shift()! : left[0]!)();
}

const claimsOf = (jwt: string | null) =>
  JSON.parse(Buffer.from(jwt!.split(".")[1]!, "base64url").toString()) as { jti: string };

// --- typed errors ----------------------------------------------------------------------------

describe("load refusals are typed", () => {
  it("REST 503 overloaded is an UnavailableError, not a denial", async () => {
    const { ob, calls } = client(() => restOverloaded());
    const e = await caught(ob.renew("TOK"));
    expect(e).toBeInstanceOf(UnavailableError);
    const err = e as UnavailableError;
    expect([err.status, err.error, err.reason, err.retryAfter]).toEqual([
      503,
      "temporarily_unavailable",
      "overloaded",
      1,
    ]);
    expect(err.description).toBe("overloaded");
    expect(err.detail).toBe("the server is handling too many requests; retry later");
    expect(err.data).toEqual({});
    expect(err).toBeInstanceOf(ApiError);
    expect(err).not.toBeInstanceOf(DeniedError);
    expect(err).not.toBeInstanceOf(UnauthorizedError);
    expect(err).not.toBeInstanceOf(RateLimitedError);
    expect(calls).toHaveLength(1); // no retry by default
  });

  it("REST 503 request_timeout is an UnavailableError with its reason", async () => {
    const { ob } = client(() => restHandlerTimeout());
    const err = (await caught(
      ob.authzenEvaluate("TOK", "github", "read_file"),
    )) as UnavailableError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect([err.reason, err.retryAfter]).toEqual(["request_timeout", 1]);
  });

  it("REST 408 request_timeout stays a plain ApiError", async () => {
    const { ob } = client(() => restBodyTimeout());
    const err = (await caught(ob.renew("TOK"))) as ApiError;
    expect(err.constructor).toBe(ApiError);
    expect([err.status, err.error]).toEqual([408, "request_timeout"]);
  });

  it("REST 429 rate_limited is a RateLimitedError", async () => {
    const { ob } = client(() => restRateLimited("42"));
    const e = await caught(
      ob.exchange(await (await Signer.create()).mint(), "coder", ["github:read_file"]),
    );
    expect(e).toBeInstanceOf(RateLimitedError);
    const err = e as RateLimitedError;
    expect([err.status, err.error, err.reason, err.retryAfter]).toEqual([
      429,
      "rate_limited",
      "rate_limited",
      42,
    ]);
    expect(err).not.toBeInstanceOf(DeniedError);
    expect(err).not.toBeInstanceOf(UnauthorizedError);
    expect(err).not.toBeInstanceOf(UnavailableError);
  });

  it("other REST 503 temporarily_unavailable answers keep their reason", async () => {
    const { ob } = client(() =>
      jsonResponse(
        { error: "temporarily_unavailable", detail: "x", error_description: "jwks_unavailable" },
        503,
      ),
    );
    const err = (await caught(ob.renew("TOK"))) as UnavailableError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect([err.reason, err.retryAfter]).toEqual(["jwks_unavailable", undefined]);
  });

  it.each([
    ["an HTML 503", () => new Response("<html>Service Unavailable</html>", { status: 503 })],
    ["another 503 error", () => jsonResponse({ error: "internal", detail: "x" }, 503)],
    [
      "a plain-text 429",
      () => new Response("slow down", { status: 429, headers: { "retry-after": "5" } }),
    ],
    ["another 429 error", () => jsonResponse({ error: "too_many", detail: "a front proxy" }, 429)],
  ])("%s stays a plain ApiError", async (_name, response) => {
    const { ob } = client(() => response());
    const err = await caught(ob.renew("TOK"));
    expect((err as ApiError).constructor).toBe(ApiError);
  });

  it("MCP 503 -32006 overloaded is an UnavailableError", async () => {
    const { ob } = client(() => mcpOverloaded("1"));
    const e = await caught(ob.callTool("TOK", "github", "read_file"));
    expect(e).toBeInstanceOf(UnavailableError);
    const err = e as UnavailableError;
    expect([err.status, err.error, err.reason, err.retryAfter]).toEqual([
      503,
      "temporarily_unavailable",
      "overloaded",
      1,
    ]);
    expect(err.data).toEqual({ reason: "overloaded" });
    expect(err.detail).toBe("attenuo: temporarily unavailable: overloaded");
    expect(err).not.toBeInstanceOf(DeniedError);
    expect(err).not.toBeInstanceOf(UnauthorizedError);
    expect(err).not.toBeInstanceOf(RpcError);
  });

  it("MCP 429 -32007 rate_limited is a RateLimitedError", async () => {
    const { ob } = client(() => mcpRateLimited("17"));
    const e = await caught(ob.listTools("TOK", "github"));
    expect(e).toBeInstanceOf(RateLimitedError);
    const err = e as RateLimitedError;
    expect([err.status, err.error, err.reason, err.retryAfter]).toEqual([
      429,
      "rate_limited",
      "rate_limited",
      17,
    ]);
    expect(err.data).toEqual({ reason: "rate_limited" });
    expect(err).not.toBeInstanceOf(DeniedError);
    expect(err).not.toBeInstanceOf(RpcError);
  });

  it("the proxy's session limits are typed with their reason", async () => {
    let { ob } = client(() => mcpRateLimited("30", "too_many_sessions"));
    const e1 = (await caught(ob.initialize("TOK", "github"))) as RateLimitedError;
    expect(e1).toBeInstanceOf(RateLimitedError);
    expect([e1.reason, e1.retryAfter]).toEqual(["too_many_sessions", 30]);
    ({ ob } = client(() => mcpOverloaded("30", "session_registry_full")));
    const e2 = (await caught(ob.initialize("TOK", "github"))) as UnavailableError;
    expect(e2).toBeInstanceOf(UnavailableError);
    expect([e2.reason, e2.retryAfter]).toEqual(["session_registry_full", 30]);
  });

  it.each([
    // The proxy always sets Retry-After on its refusals: without it, an upstream's error.
    ["-32006 without Retry-After", () => mcpOverloaded(null)],
    ["-32007 without Retry-After", () => mcpRateLimited(null)],
    // Not the status the proxy pairs with the code.
    [
      "-32006 in a 200",
      () => rpcErr(-32006, "busy", { reason: "overloaded" }, 200, { "retry-after": "1" }),
    ],
    [
      "-32007 in a 503",
      () => rpcErr(-32007, "x", { reason: "rate_limited" }, 503, { "retry-after": "1" }),
    ],
  ])("%s stays an RpcError", async (_name, response) => {
    const { ob } = client(() => response());
    const err = await caught(ob.callTool("TOK", "github", "read_file"));
    expect(err).toBeInstanceOf(RpcError);
    expect([-32006, -32007]).toContain((err as RpcError).code);
  });

  it.each(["soon", "1.5", "-1", "", " ", "Wed, 21 Oct 2026 07:28:00 GMT"])(
    "a malformed Retry-After %j is undefined",
    async (value) => {
      let { ob } = client(() => restRateLimited(value));
      const e1 = (await caught(ob.renew("TOK"))) as RateLimitedError;
      expect(e1).toBeInstanceOf(RateLimitedError);
      expect(e1.retryAfter).toBeUndefined();
      ({ ob } = client(() => mcpOverloaded(value)));
      const e2 = (await caught(ob.callTool("TOK", "github", "read_file"))) as UnavailableError;
      expect(e2).toBeInstanceOf(UnavailableError);
      expect(e2.retryAfter).toBeUndefined();
    },
  );

  it("a missing Retry-After on a REST route is undefined", async () => {
    const { ob } = client(() => restOverloaded(null));
    const err = (await caught(ob.renew("TOK"))) as UnavailableError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err.retryAfter).toBeUndefined();
  });

  it("a Retry-After with spaces is read", async () => {
    const { ob } = client(() => restRateLimited(" 7 "));
    expect(((await caught(ob.renew("TOK"))) as RateLimitedError).retryAfter).toBe(7);
  });

  it("denials and 401s map as before", async () => {
    let { ob } = client(() => denial());
    const d = (await caught(ob.callTool("TOK", "github", "read_file"))) as DeniedError;
    expect(d).toBeInstanceOf(DeniedError);
    expect([d.reason, d.decisionId]).toEqual(["policy_deny", DEC]);
    ({ ob } = client(() => rpcErr(-32001, "m", { reason: "lease_revoked" }, 401)));
    const u = (await caught(ob.callTool("TOK", "github", "read_file"))) as UnauthorizedError;
    expect(u).toBeInstanceOf(UnauthorizedError);
    expect(u.reason).toBe("lease_revoked");
  });

  it("a streamed call throws the refusal before any event", async () => {
    const { ob } = client(() => mcpRateLimited("9"));
    const seen: StreamEvent[] = [];
    const err = await caught(
      (async () => {
        for await (const ev of ob.callToolStream("TOK", "github", "read_file")) seen.push(ev);
      })(),
    );
    expect(seen).toEqual([]);
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfter).toBe(9);
  });

  it("the admin client gets the typed errors", async () => {
    const m = mockFetch(() => restOverloaded());
    const admin = new AdminClient(BASE, "adm", { fetch: m.fetch });
    const err = (await caught(admin.leaseStatus("lease-1"))) as UnavailableError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err.reason).toBe("overloaded");
  });
});

// --- the opt-in retry ------------------------------------------------------------------------

describe("the opt-in retry", () => {
  const original = { ...retryHooks };
  let sleeps: number[];

  beforeEach(() => {
    sleeps = [];
    retryHooks.sleep = async (ms) => {
      sleeps.push(ms);
    };
    retryHooks.random = () => 0;
  });
  afterEach(() => {
    Object.assign(retryHooks, original);
  });

  it("retries N times, then throws the last refusal", async () => {
    const { ob, calls } = client(() => mcpOverloaded("1"), { maxRetries: 3 });
    const err = (await caught(ob.callTool("TOK", "github", "read_file"))) as UnavailableError;
    expect(err).toBeInstanceOf(UnavailableError);
    expect(err.reason).toBe("overloaded");
    expect(calls).toHaveLength(4);
    expect(sleeps).toEqual([1000, 1000, 1000]);
  });

  it("returns the answer of a retry that succeeds", async () => {
    const { ob, calls } = client(
      sequence(
        () => mcpRateLimited("3"),
        () => rpcOk(OK_TOOL, { "x-attenuo-decision-id": DEC }),
      ),
      { maxRetries: 2 },
    );
    const res = await ob.callTool("TOK", "github", "read_file", { path: "a" });
    expect(res.text).toBe("ok");
    expect(sleeps).toEqual([3000]);
    expect(calls).toHaveLength(2);
    const [first, second] = calls.map((c) => (c.body as { params: unknown }).params);
    expect(first).toEqual({ name: "read_file", arguments: { path: "a" } });
    expect(second).toEqual(first);
  });

  it("retries REST routes too", async () => {
    const child = await (await Signer.create()).mint({ agents: ["planner", "coder"] });
    const { ob, calls } = client(
      sequence(
        () => restOverloaded("1"),
        () => restRateLimited("2"),
        () => jsonResponse(tokenResponse(child, "lease-1")),
      ),
      { maxRetries: 2 },
    );
    const tok = await ob.exchange(await (await Signer.create()).mint(), "coder", [
      "github:read_file",
    ]);
    expect(tok.lease).toBe("lease-1");
    expect(sleeps).toEqual([1000, 2000]);
    expect(calls.map((c) => c.url.pathname)).toEqual(["/token", "/token", "/token"]);
  });

  describe("an exchange with a client assertion", () => {
    let now: number;
    beforeEach(() => {
      // A wall clock at 1,000,000 s that the retry waits move forward.
      now = 1_000_000_000;
      retryHooks.now = () => now;
      retryHooks.sleep = async (ms) => {
        sleeps.push(ms);
        now += ms;
      };
    });
    const assertionsSent = (calls: { body?: unknown }[]) =>
      calls.map((c) => (c.body as { client_assertion?: string }).client_assertion);

    it("sends the same unexpired assertion again", async () => {
      const child = await (await Signer.create()).mint({ agents: ["planner", "coder"] });
      const { ob, calls } = client(
        sequence(
          () => restRateLimited("20"),
          () => restOverloaded("1"),
          () => jsonResponse(tokenResponse(child, "lease-1")),
        ),
        { maxRetries: 3, maxRetryDelayMs: 60_000 },
      );
      const key = await DpopKey.generate();
      const assertion = await key.clientAssertion("coder", "https://a", { iat: 1_000_000 });
      const tok = await ob.exchange(await (await Signer.create()).mint(), "coder", "github:x", {
        clientAssertion: assertion,
      });
      expect(tok.lease).toBe("lease-1");
      expect(sleeps).toEqual([20_000, 1000]);
      expect(assertionsSent(calls)).toEqual([assertion, assertion, assertion]);
    });

    it("does not send an assertion again when the wait would reach its exp", async () => {
      // The first wait (30 s) fits the 60 s assertion, the second (reaching `exp`) does not.
      const { ob, calls } = client(() => restRateLimited("30"), {
        maxRetries: 5,
        maxRetryDelayMs: 60_000,
      });
      const key = await DpopKey.generate();
      const assertion = await key.clientAssertion("coder", "https://a", { iat: 1_000_000 });
      const parent = await (await Signer.create()).mint();
      const err = (await caught(
        ob.exchange(parent, "coder", "github:x", { clientAssertion: assertion }),
      )) as RateLimitedError;
      expect(err).toBeInstanceOf(RateLimitedError);
      expect(err.retryAfter).toBe(30);
      expect(sleeps).toEqual([30_000]);
      expect(assertionsSent(calls)).toEqual([assertion, assertion]);

      // One already past its `exp` by the client's clock is not sent again at all.
      calls.length = 0;
      sleeps.length = 0;
      const old = await key.clientAssertion("coder", "https://a", { iat: 900_000 });
      const again = await caught(
        ob.exchange(parent, "coder", "github:x", { clientAssertion: old }),
      );
      expect(again).toBeInstanceOf(RateLimitedError);
      expect(sleeps).toEqual([]);
      expect(calls).toHaveLength(1);
    });

    it("retries as before without an exp it can read, or with a secret", async () => {
      const child = await (await Signer.create()).mint({ agents: ["planner", "coder"] });
      const parent = await (await Signer.create()).mint();
      for (const auth of [{ clientAssertion: "a.b.c" }, { clientSecret: "s" }]) {
        const { ob } = client(
          sequence(
            () => restRateLimited("50"),
            () => jsonResponse(tokenResponse(child, "lease-1")),
          ),
          { maxRetries: 1, maxRetryDelayMs: 60_000 },
        );
        await ob.exchange(parent, "coder", "github:x", auth);
      }
      expect(sleeps).toEqual([50_000, 50_000]);
    });
  });

  it.each([
    ["authzenConfiguration", "/.well-known/authzen-configuration"],
    ["jwks", "/.well-known/jwks.json"],
  ] as const)("retries %s", async (name, path) => {
    const { ob, calls } = client(
      sequence(
        () => restOverloaded("1"),
        () => jsonResponse({}),
      ),
      { maxRetries: 1 },
    );
    await ob[name]();
    expect(calls.map((c) => c.url.pathname)).toEqual([path, path]);
    expect(sleeps).toEqual([1000]);
  });

  it("retries an approval decision", async () => {
    const approval = { approval_id: "ap-1", state: "granted", expired: false };
    const { ob, calls } = client(
      sequence(
        () => restOverloaded("1"),
        () => jsonResponse(approval),
      ),
      { maxRetries: 1 },
    );
    expect((await ob.grantApproval("ap-1", "ID-TOKEN")).approvalId).toBe("ap-1");
    expect(calls).toHaveLength(2);
    expect(calls.every((c) => c.headers.get("authorization") === "Bearer ID-TOKEN")).toBe(true);
  });

  it.each([
    [
      "503 request_timeout (the handler may have done the work)",
      restHandlerTimeout,
      UnavailableError,
    ],
    ["408 request_timeout", restBodyTimeout, ApiError],
    ["a denial", denial, DeniedError],
    ["a 401", () => rpcErr(-32001, "m", { reason: "invalid_token" }, 401), UnauthorizedError],
    ["429 too_many_sessions", () => mcpRateLimited("30", "too_many_sessions"), RateLimitedError],
    [
      "503 session_registry_full",
      () => mcpOverloaded("30", "session_registry_full"),
      UnavailableError,
    ],
    ["an upstream's -32006", () => mcpOverloaded(null), RpcError],
    ["an HTML 503", () => new Response("Service Unavailable", { status: 503 }), ApiError],
  ] as const)("does not retry %s", async (_name, response, error) => {
    const { ob, calls } = client(() => response(), { maxRetries: 3 });
    expect(await caught(ob.callTool("TOK", "github", "read_file"))).toBeInstanceOf(error);
    expect(calls).toHaveLength(1);
    expect(sleeps).toEqual([]);
  });

  it("does not retry a transport error", async () => {
    const { ob, calls } = client(
      () => {
        throw new TypeError("fetch failed");
      },
      { maxRetries: 3 },
    );
    expect(await caught(ob.callTool("TOK", "github", "read_file"))).toBeInstanceOf(TransportError);
    expect(calls).toHaveLength(1);
  });

  it("throws at once when Retry-After is over the cap", async () => {
    const { ob, calls } = client(() => mcpRateLimited("45"), {
      maxRetries: 3,
      maxRetryDelayMs: 30_000,
    });
    const err = (await caught(ob.callTool("TOK", "github", "read_file"))) as RateLimitedError;
    expect(err.retryAfter).toBe(45);
    expect(calls).toHaveLength(1);
    expect(sleeps).toEqual([]);
  });

  it("waits one second when Retry-After is missing or malformed", async () => {
    const { ob, calls } = client(
      sequence(
        () => restOverloaded(null),
        () => restRateLimited("soon"),
        () => restOverloaded("1"),
      ),
      { maxRetries: 2 },
    );
    expect(await caught(ob.renew("TOK"))).toBeInstanceOf(UnavailableError);
    expect(sleeps).toEqual([1000, 1000]);
    expect(calls).toHaveLength(3);
  });

  it("jitter waits longer, never shorter, and stays under the cap", async () => {
    retryHooks.random = () => 0.999;
    const { ob } = client(
      sequence(
        () => restOverloaded("1"),
        () => restRateLimited("9"),
        () => restOverloaded("1"),
      ),
      { maxRetries: 2, maxRetryDelayMs: 10_000 },
    );
    expect(await caught(ob.renew("TOK"))).toBeInstanceOf(UnavailableError);
    expect(sleeps[0]).toBeGreaterThan(1000);
    expect(sleeps[0]).toBeLessThan(1200);
    expect(sleeps[1]).toBe(10_000); // 9 s plus up to 20 %, capped at maxRetryDelayMs
  });

  it("sends new DPoP proofs on every retry", async () => {
    const { ob, calls } = client(() => mcpOverloaded("1"), {
      maxRetries: 2,
      dpopKey: await DpopKey.generate(),
    });
    expect(await caught(ob.callTool("TOK", "github", "read_file"))).toBeInstanceOf(
      UnavailableError,
    );
    expect(calls).toHaveLength(3);
    const jtis = new Set(calls.map((c) => claimsOf(c.headers.get("dpop")).jti));
    expect(jtis.size).toBe(3);
  });

  it("retries an action search with the same body and new DPoP proofs", async () => {
    const empty = { page: { next_token: "", count: 0 }, results: [] };
    const { ob, calls } = client(
      sequence(
        () => restOverloaded("1"),
        () => jsonResponse(empty),
      ),
      { maxRetries: 1, dpopKey: await DpopKey.generate() },
    );
    const page = await ob.authzenSearchAction("TOK", "github", undefined, { limit: 3 });
    expect(page.actions).toEqual([]);
    expect(sleeps).toEqual([1000]);
    expect(calls.map((c) => c.url.pathname)).toEqual([
      "/access/v1/search/action",
      "/access/v1/search/action",
    ]);
    expect(calls[1]!.body).toEqual(calls[0]!.body);
    expect((calls[0]!.body as { page: unknown }).page).toEqual({ limit: 3 });
    expect(new Set(calls.map((c) => claimsOf(c.headers.get("dpop")).jti)).size).toBe(2);
  });

  it("retries a streamed call before it starts", async () => {
    const { ob, calls } = client(
      sequence(
        () => mcpOverloaded("1"),
        () => mcpRateLimited("2"),
        () => sseResult("streamed"),
      ),
      { maxRetries: 2 },
    );
    const events = await drain(ob.callToolStream("TOK", "github", "read_file"));
    expect(events.at(-1)?.result?.text).toBe("streamed");
    expect(sleeps).toEqual([1000, 2000]);
    expect(calls).toHaveLength(3);
  });

  it("throws the refusal when a streamed call runs out of retries", async () => {
    const { ob, calls } = client(() => mcpOverloaded("1"), { maxRetries: 1 });
    expect(await caught(drain(ob.callToolStream("TOK", "github", "read_file")))).toBeInstanceOf(
      UnavailableError,
    );
    expect(calls).toHaveLength(2);
  });

  it("does not wait past a streamed call's deadline", async () => {
    const { ob, calls } = client(() => mcpRateLimited("5"), { maxRetries: 3 });
    const err = await caught(
      drain(ob.callToolStream("TOK", "github", "read_file", {}, { deadlineMs: 2000 })),
    );
    expect(err).toBeInstanceOf(RateLimitedError);
    expect(calls).toHaveLength(1);
    expect(sleeps).toEqual([]);
  });

  it("does not retry a streamed denial", async () => {
    const { ob, calls } = client(() => denial(), { maxRetries: 3 });
    expect(await caught(drain(ob.callToolStream("TOK", "github", "read_file")))).toBeInstanceOf(
      DeniedError,
    );
    expect(calls).toHaveLength(1);
  });

  it("a streamed call's signal aborts the wait", async () => {
    Object.assign(retryHooks, { sleep: original.sleep });
    const ctl = new AbortController();
    const { ob, calls } = client(() => mcpOverloaded("1"), { maxRetries: 3 });
    const pending = caught(
      drain(ob.callToolStream("TOK", "github", "read_file", {}, { signal: ctl.signal })),
    );
    await new Promise((r) => setTimeout(r, 20));
    ctl.abort(new Error("stop"));
    const err = (await pending) as Error;
    expect(err.message).toBe("stop");
    expect(calls).toHaveLength(1);
  });

  it.each([
    [{ maxRetries: -1 }],
    [{ maxRetries: 11 }],
    [{ maxRetries: 1.5 }],
    [{ maxRetryDelayMs: 0 }],
    [{ maxRetryDelayMs: 300_001 }],
    [{ maxRetryDelayMs: Number.NaN }],
  ])("checks its options: %j", (opts) => {
    expect(() => new AttenuoClient(BASE, opts)).toThrow(RangeError);
  });
});

describe("assertionExpiry", () => {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  it.each([
    [{ exp: 1_000_060 }, 1_000_060],
    [{ exp: 1_000_060.9 }, 1_000_060],
    [{ exp: true }, undefined],
    [{ exp: "1000060" }, undefined],
    [{}, undefined],
    [[1], undefined],
  ] as const)("reads exp from %j without verifying", (claims, exp) => {
    const jwt = `${b64({ alg: "EdDSA" })}.${b64(claims)}.sig`;
    expect(assertionExpiry({ client_assertion: jwt })).toBe(exp);
  });
  it("is undefined for anything that is not a readable JWT", () => {
    expect(assertionExpiry({ client_assertion: "a.!.c" })).toBeUndefined();
    expect(assertionExpiry({ client_assertion: "a.b" })).toBeUndefined();
    expect(assertionExpiry({ client_assertion: "a.e30x.c" })).toBeUndefined();
    expect(assertionExpiry({ client_secret: "s" })).toBeUndefined();
  });
});

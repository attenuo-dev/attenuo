/** The error contract: what a 401, a denial, a REST error and a transport failure carry. */

import { createServer, type AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import {
  AdminClient,
  ApiError,
  ApprovalRequiredError,
  AttenuoClient,
  AttenuoError,
  DeniedError,
  DpopKey,
  ENTRY_HASH_VERSION,
  EXPORT_FORMAT,
  GENESIS_HASH,
  PROOF_TYPE,
  RpcError,
  SHIPPED_FORMAT,
  TransportError,
  TransportTimeoutError,
  UnauthorizedError,
  entryHash,
  type BudgetLimit,
  type RunUsage,
  type UntrustedArg,
} from "../src/index.js";
import { jsonResponse, mockFetch, rpcErr } from "./helpers.js";

const BASE = "http://ob.test";
const DEC = "6f1c2d9e-0000-4000-8000-000000000001";
const PROXY_401_REASONS = [
  "lease_revoked",
  "lease_expired",
  "lease_unknown",
  "dpop_required",
  "invalid_dpop_proof",
  "use_dpop_nonce",
  "token_expired",
  "invalid_token",
  "missing_token",
];

async function caught(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("no error");
}

function client(handler: Parameters<typeof mockFetch>[0], opts: { dpopKey?: DpopKey } = {}) {
  const m = mockFetch(handler);
  return { ob: new AttenuoClient(BASE, { fetch: m.fetch, ...opts }), calls: m.calls };
}

describe("a proxy 401 (K-1)", () => {
  it.each(PROXY_401_REASONS)("carries the reason %s and its record", async (reason) => {
    const data = { reason, decision_id: DEC };
    const { ob } = client(() =>
      rpcErr(-32001, `attenuo: unauthorized: ${reason}`, data, 401, {
        "x-attenuo-decision-id": DEC,
      }),
    );
    const e = (await caught(ob.callTool("TOK", "github", "read_file"))) as UnauthorizedError;
    expect(e).toBeInstanceOf(UnauthorizedError);
    expect(e.reason).toBe(reason);
    expect(e.decisionId).toBe(DEC);
    expect(e.data).toEqual(data);
    // What it always held is unchanged.
    expect([e.status, e.error, e.detail]).toEqual([
      401,
      "unauthorized",
      `attenuo: unauthorized: ${reason}`,
    ]);
  });

  it("takes the decision id only when the header names it (SR-32)", async () => {
    const data = { reason: "lease_revoked", decision_id: DEC };
    const variants: Record<string, string>[] = [{}, { "x-attenuo-decision-id": "another-id" }];
    for (const headers of variants) {
      const { ob } = client(() => rpcErr(-32001, "m", data, 401, headers));
      const e = (await caught(ob.listTools("TOK", "github"))) as UnauthorizedError;
      expect(e.reason).toBe("lease_revoked");
      expect(e.decisionId).toBeUndefined();
    }
  });

  it("keeps no reason from a -32001 inside a 200 answer", async () => {
    // Only the proxy answers with HTTP 401; an upstream can put `-32001` in a 200 body.
    const data = { reason: "lease_revoked", decision_id: DEC };
    const { ob } = client(() => rpcErr(-32001, "m", data, 200));
    const e = (await caught(ob.callTool("TOK", "github", "read_file"))) as UnauthorizedError;
    expect([e.reason, e.decisionId]).toEqual(["unauthorized", undefined]);
  });

  it("is a plain unauthorized without data", async () => {
    const { ob } = client(() => rpcErr(-32001, "who are you", undefined, 401));
    const e = (await caught(ob.callTool("TOK", "github", "read_file"))) as UnauthorizedError;
    expect([e.reason, e.decisionId, e.data]).toEqual(["unauthorized", undefined, {}]);
  });
});

describe("a REST 401", () => {
  it.each([
    [
      { error: "unauthorized", detail: "token_expired", error_description: "token_expired" },
      "token_expired",
    ],
    [{ error: "dpop_required", detail: "a proof is required" }, "dpop_required"],
    [{ error: "invalid_dpop_proof", detail: "x" }, "invalid_dpop_proof"],
  ])("carries the reason (%#)", async (body, reason) => {
    const { ob } = client(() => jsonResponse(body, 401));
    const e = (await caught(ob.renew("TOK"))) as UnauthorizedError;
    expect(e).toBeInstanceOf(UnauthorizedError);
    expect(e.reason).toBe(reason);
    expect(e.error).toBe(body.error);
    expect(e.data).toEqual({});
  });

  it("that is not JSON is plain unauthorized", async () => {
    const { ob } = client(() => new Response("go away", { status: 401 }));
    const e = (await caught(ob.renew("TOK"))) as UnauthorizedError;
    expect([e.error, e.reason]).toEqual(["http_error", "unauthorized"]);
  });
});

describe("a REST error (K-4)", () => {
  it("carries the decision id the header vouches for", async () => {
    const body = {
      error: "invalid_scope",
      detail: "delegation chain is invalid",
      decision_id: DEC,
    };
    const { ob } = client(() => jsonResponse(body, 400, { "x-attenuo-decision-id": DEC }));
    const e = (await caught(ob.exchange("a.b.c", "coder", "github:read_file"))) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e).not.toBeInstanceOf(UnauthorizedError);
    expect([e.error, e.decisionId]).toEqual(["invalid_scope", DEC]);

    for (const res of [
      () => jsonResponse(body, 400),
      () => jsonResponse({ error: "invalid_request", detail: "x" }, 400),
    ]) {
      const { ob: other } = client(res);
      const e2 = (await caught(other.exchange("a.b.c", "coder", "github:read_file"))) as ApiError;
      expect(e2.decisionId).toBeUndefined();
    }
  });
});

describe("a denial keeps what the server says (K-3)", () => {
  const denial =
    (data: Record<string, unknown>, code = -32003) =>
    () =>
      rpcErr(code, "attenuo: denied", data, 200, {
        "x-attenuo-decision-id": String(data.decision_id),
      });

  it("names the limit of budget_exhausted", async () => {
    const limit = { hop: 1, kind: "sum", arg: "amount", max: 100, used: 90 };
    const data = { reason: "budget_exhausted", decision_id: DEC, limit };
    const { ob } = client(denial(data));
    const e = (await caught(ob.callTool("TOK", "pay", "send", { amount: 20 }))) as DeniedError;
    expect(e).toBeInstanceOf(DeniedError);
    expect(e.reason).toBe("budget_exhausted");
    const want: BudgetLimit = { hop: 1, kind: "sum", used: 90, arg: "amount", max: 100 };
    expect(e.limit).toEqual(want);
    expect(e.data).toEqual(data);
    expect(e.usage).toBeUndefined();
    expect(e.untrustedArgs).toEqual([]);
  });

  it("carries usage, per-user windows and untrusted arguments", async () => {
    const data = {
      reason: "policy_deny",
      decision_id: DEC,
      usage: {
        calls: 3,
        amount: 250,
        destination_seen: true,
        user_window: { hour: { calls: 1, amount: 50 }, day: { calls: 4, amount: 900 } },
      },
      untrusted_args: [
        { arg: "to", seq: 41, kind: "leaf" },
        { arg: "body", kind: "unreadable" },
      ],
    };
    const { ob } = client(denial(data));
    const e = (await caught(ob.callTool("TOK", "mail", "send"))) as DeniedError;
    const usage: RunUsage = {
      calls: 3,
      amount: 250,
      destinationSeen: true,
      userWindow: { hour: { calls: 1, amount: 50 }, day: { calls: 4, amount: 900 } },
    };
    expect(e.usage).toEqual(usage);
    const args: UntrustedArg[] = [
      { arg: "to", kind: "leaf", seq: 41 },
      { arg: "body", kind: "unreadable" },
    ];
    expect(e.untrustedArgs).toEqual(args);
    expect(e.limit).toBeUndefined();

    const zero = { ...data, usage: { calls: 0, amount: 0, destination_seen: false } };
    const { ob: ob2 } = client(denial(zero));
    const e2 = (await caught(ob2.callTool("TOK", "mail", "send"))) as DeniedError;
    expect(e2.usage).toEqual({ calls: 0, amount: 0, destinationSeen: false });
  });

  it("keeps the data of approval_required", async () => {
    const data = {
      reason: "approval_required",
      decision_id: DEC,
      call_hash: "ab".repeat(32),
      approval_id: "appr-1",
      expires_at: "2026-11-12T10:00:00Z",
      untrusted_args: [{ arg: "repo", seq: 7, kind: "kgram" }],
      usage: { calls: 1, amount: 0, destination_seen: false },
    };
    const { ob } = client(denial(data, -32008));
    const e = (await caught(ob.callTool("TOK", "github", "delete_repo"))) as ApprovalRequiredError;
    expect(e).toBeInstanceOf(ApprovalRequiredError);
    expect([e.approvalId, e.callHash]).toEqual(["appr-1", "ab".repeat(32)]);
    expect(e.expiresAt).toBeInstanceOf(Date);
    expect(e.untrustedArgs).toEqual([{ arg: "repo", kind: "kgram", seq: 7 }]);
    expect(e.usage).toEqual({ calls: 1, amount: 0, destinationSeen: false });
    expect(e.data).toEqual(data);
  });

  it("tolerates odd shapes and the old constructors", () => {
    const d = new DeniedError("x", "id", "", {
      limit: "no",
      usage: [1],
      untrusted_args: [3, { arg: 1 }],
    });
    expect([d.limit, d.usage]).toEqual([undefined, undefined]);
    expect(d.untrustedArgs).toEqual([{ arg: "1", kind: "" }]);
    expect(new DeniedError("policy_deny", "id-1", "m").data).toEqual({});
    expect(new ApprovalRequiredError("id", "a", undefined, undefined).data).toEqual({});
  });

  it("types nothing of an upstream's own -32003", async () => {
    const data = { reason: "budget_exhausted", decision_id: DEC, limit: { hop: 0 } };
    const { ob } = client(() => rpcErr(-32003, "denied", data));
    const e = await caught(ob.callTool("TOK", "github", "read_file"));
    expect(e).toBeInstanceOf(RpcError);
    expect(e).not.toBeInstanceOf(DeniedError);
  });
});

describe("a transport failure (K-12)", () => {
  it("is a TransportError with what fetch threw as its cause", async () => {
    const boom = new TypeError("fetch failed", { cause: new Error("connect ECONNREFUSED") });
    const { ob } = client(() => {
      throw boom;
    });
    for (const run of [
      () => ob.callTool("TOK", "github", "read_file"),
      () => ob.renew("TOK"),
      () => ob.jwks(),
      () => ob.jwks("http://keys.test/jwks.json"),
    ]) {
      const e = (await caught(run())) as TransportError;
      expect(e).toBeInstanceOf(TransportError);
      expect(e).toBeInstanceOf(AttenuoError);
      expect(e.cause).toBe(boom);
      expect(e.message).toContain("ECONNREFUSED");
    }
  });

  it("covers the client's own timeout but not the caller's abort", async () => {
    const timeout = new DOMException("timed out", "TimeoutError");
    const { ob } = client(() => {
      throw timeout;
    });
    const e = (await caught(ob.renew("TOK"))) as TransportError;
    expect(e).toBeInstanceOf(TransportError);
    expect(e.cause).toBe(timeout);

    const abort = new DOMException("aborted", "AbortError");
    const { ob: ob2 } = client(() => {
      throw abort;
    });
    expect(await caught(ob2.renew("TOK"))).toBe(abort);
  });

  it("covers a body that fails while it is read", async () => {
    const progress = 'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n';
    const broken = () => {
      let sent = false;
      const body = new ReadableStream<Uint8Array>({
        pull(ctl) {
          if (sent) {
            ctl.error(new TypeError("terminated"));
            return;
          }
          sent = true;
          ctl.enqueue(new TextEncoder().encode(progress));
        },
      });
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    };
    const { ob } = client(broken);
    const seen: unknown[] = [];
    let err: unknown;
    try {
      for await (const ev of ob.callToolStream("TOK", "github", "read_file")) seen.push(ev);
    } catch (e) {
      err = e;
    }
    expect(seen).toHaveLength(1);
    expect(err).toBeInstanceOf(TransportError);
    expect((err as TransportError).cause).toBeInstanceOf(TypeError);

    // A plain JSON answer whose body breaks.
    const { ob: ob2 } = client(() => {
      const r = broken();
      return new Response(r.body, { status: 200, headers: { "content-type": "application/json" } });
    });
    expect(await caught(ob2.renew("TOK"))).toBeInstanceOf(TransportError);
  });

  it("is the admin client's too", async () => {
    const m = mockFetch(() => {
      throw new TypeError("fetch failed");
    });
    const admin = new AdminClient(BASE, "adm", { fetch: m.fetch });
    expect(await caught(admin.leaseStatus("lease-1"))).toBeInstanceOf(TransportError);
  });

  it("is what a refused connection to a real socket gives", async () => {
    const port = await new Promise<number>((resolve) => {
      const srv = createServer();
      srv.listen(0, "127.0.0.1", () => {
        const p = (srv.address() as AddressInfo).port;
        srv.close(() => resolve(p));
      });
    });
    const ob = new AttenuoClient(`http://127.0.0.1:${port}`, { timeoutMs: 5000 });
    const e = (await caught(ob.renew("TOK"))) as TransportError;
    expect(e).toBeInstanceOf(TransportError);
    expect(e.cause).toBeInstanceOf(TypeError);
  });

  it("still lets the nonce retry through, and wraps the retry's failure", async () => {
    const key = await DpopKey.generate();
    const { ob, calls } = client(
      () => {
        if (calls.length === 1) {
          return jsonResponse({ error: "use_dpop_nonce" }, 401, {
            "dpop-nonce": "n-1",
            "www-authenticate": 'DPoP error="use_dpop_nonce"',
          });
        }
        throw new DOMException("timed out", "TimeoutError");
      },
      { dpopKey: key },
    );
    const e = (await caught(ob.renew("a.b.c"))) as TransportError;
    expect(calls).toHaveLength(2); // a timeout is not resent
    expect(e).toBeInstanceOf(TransportError);
    expect((e.cause as DOMException).name).toBe("TimeoutError");
  });
});

describe("the audit constants (K-11)", () => {
  it("are exported from the root as the Python SDK's are", async () => {
    expect(GENESIS_HASH).toBe("0".repeat(64));
    expect(ENTRY_HASH_VERSION).toBe("attenuo-audit-entry-v2");
    expect(EXPORT_FORMAT).toBe("attenuo-audit-export-v2");
    expect(SHIPPED_FORMAT).toBe("attenuo-shipped-checkpoint-v1");
    expect(PROOF_TYPE).toBe("dpop+jwt");
    // The value the Python SDK's `entry_hash(1, GENESIS_HASH, {"a": 1})` gives.
    expect(await entryHash(1, GENESIS_HASH, { a: 1 })).toBe(
      "8b0a08f4d4e974318b7cc1319d0c4732579bbbe8c1f4197d956419aa44b40452",
    );
  });
});

describe("a timeout (K-12)", () => {
  it("is a TransportTimeoutError when the client's own timer ran out", async () => {
    const timeout = new DOMException("timed out", "TimeoutError");
    const { ob } = client(() => {
      throw timeout;
    });
    const e = (await caught(ob.renew("TOK"))) as TransportTimeoutError;
    expect(e).toBeInstanceOf(TransportTimeoutError);
    expect(e).toBeInstanceOf(TransportError);
    expect(e).toBeInstanceOf(AttenuoError);
    expect(e.name).toBe("TransportTimeoutError");
    expect(e.cause).toBe(timeout);
  });

  it("is not what a refused connection gives", async () => {
    const { ob } = client(() => {
      throw new TypeError("fetch failed");
    });
    const e = await caught(ob.renew("TOK"));
    expect(e).toBeInstanceOf(TransportError);
    expect(e).not.toBeInstanceOf(TransportTimeoutError);
  });

  it("is a real request's timeoutMs running out", async () => {
    const srv = createServer(() => {}); // accepts, never answers
    const port = await new Promise<number>((resolve) =>
      srv.listen(0, "127.0.0.1", () => resolve((srv.address() as AddressInfo).port)),
    );
    try {
      const ob = new AttenuoClient(`http://127.0.0.1:${port}`, { timeoutMs: 100 });
      const e = (await caught(ob.renew("TOK"))) as TransportTimeoutError;
      expect(e).toBeInstanceOf(TransportTimeoutError);
      expect((e.cause as DOMException).name).toBe("TimeoutError");
    } finally {
      srv.close();
    }
  });

  it("leaves the caller's abort of a streamed call as it came", async () => {
    const ctl = new AbortController();
    const reason = new DOMException("stop", "AbortError");
    const { ob } = client(() => {
      ctl.abort(reason);
      throw reason;
    });
    const err = await (async () => {
      try {
        for await (const _ of ob.callToolStream(
          "TOK",
          "github",
          "read_file",
          {},
          {
            signal: ctl.signal,
          },
        )) {
          void _;
        }
      } catch (e) {
        return e;
      }
      return undefined;
    })();
    expect(err).toBe(reason);
    expect(err).not.toBeInstanceOf(AttenuoError);
  });
});

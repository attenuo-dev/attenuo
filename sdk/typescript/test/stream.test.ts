/** Streamed `tools/call` answers: the SSE parser and `callToolStream`. */

import { describe, expect, it } from "vitest";
import {
  ApprovalRequiredError,
  AttenuoClient,
  AttenuoError,
  DEFAULT_MAX_EVENT_BYTES,
  DeniedError,
  RpcError,
  SseParser,
  type StreamEvent,
  UnauthorizedError,
} from "../src/index.js";
import { jsonResponse, mockFetch } from "./helpers.js";

const URL_ = "http://ob.test";
type Json = Record<string, unknown>;
const SSE = { "content-type": "text/event-stream" };
const enc = new TextEncoder();

function event(msg: unknown, id?: string): string {
  return `${id === undefined ? "" : `id: ${id}\n`}event: message\ndata: ${JSON.stringify(msg)}\n\n`;
}

const progress = (n: number) => ({
  jsonrpc: "2.0",
  method: "notifications/progress",
  params: { progressToken: "t", progress: n, total: 2 },
});

const result = (text: string, id: number = 1) => ({
  jsonrpc: "2.0",
  id,
  result: { content: [{ type: "text", text }], isError: false },
});

const CUT_ID = "0b7c2f5e-9a41-4d3e-8f6a-2c1d5e7f9a30";
const CUT = {
  jsonrpc: "2.0",
  id: null,
  error: {
    code: -32001,
    message: "attenuo: unauthorized: stream ended: lease_revoked",
    data: { reason: "lease_revoked", decision_id: CUT_ID },
  },
};

function sse(body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status: 200, headers: { ...SSE, ...headers } });
}

async function collect(it: AsyncIterable<StreamEvent>): Promise<StreamEvent[]> {
  const out: StreamEvent[] = [];
  for await (const ev of it) out.push(ev);
  return out;
}

async function collectUntilError(
  it: AsyncIterable<StreamEvent>,
): Promise<{ seen: StreamEvent[]; err: unknown }> {
  const seen: StreamEvent[] = [];
  try {
    for await (const ev of it) seen.push(ev);
  } catch (err) {
    return { seen, err };
  }
  throw new Error(`no error; got ${seen.length} events`);
}

function parseAll(body: Uint8Array, chunk?: number, limit = 1 << 20): [string, unknown][] {
  const p = new SseParser(limit);
  const out: [string, unknown][] = [];
  const step = chunk ?? Math.max(body.length, 1);
  for (let i = 0; i < body.length; i += step) {
    for (const e of p.feed(body.subarray(i, i + step))) out.push([e.data, e.lastEventId]);
  }
  p.close();
  return out;
}

const bytes = (...parts: (string | number[])[]) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === "string" ? [...enc.encode(p)] : p)));

describe("SseParser", () => {
  it.each([undefined, 1, 2, 3, 7])(
    "handles line ends, comments, fields and split reads (chunk %s)",
    (chunk) => {
      const body = bytes(
        [0xef, 0xbb, 0xbf],
        ": a comment\r\n",
        "event: message\r\nid: 1\r\ndata: one\r\n\r\n", // CRLF
        "data: two\rdata:three\r\r", // CR, and no space after the colon
        "retry: 10\nid: 7\ndata:  four\nunknown: x\ndata\n\n", // LF; `data` with no colon
        "\n\n", // empty events dispatch nothing
        "id: 8\ndata: dropped, no blank line",
      );
      expect(parseAll(body, chunk)).toEqual([
        ["one", "1"],
        ["two\nthree", "1"], // the last event id carries over
        [" four\n", "7"],
      ]);
    },
  );

  it("counts a last line ended by a lone CR", () => {
    expect(parseAll(bytes("data: x\r\r"))).toEqual([["x", undefined]]);
    expect(parseAll(bytes("data: x\r"))).toEqual([]);
  });

  it("ignores an id with NUL", () => {
    expect(parseAll(bytes("id: 1\n\ndata: a\nid: b\0c\n\n"))).toEqual([["a", "1"]]);
  });

  it("refuses an oversized event", () => {
    const small = `data: ${"x".repeat(50)}\n\n`;
    expect(parseAll(bytes(small.repeat(3)), 5, 64)).toEqual(
      Array(3).fill(["x".repeat(50), undefined]),
    );
    expect(() =>
      parseAll(bytes(`data: ${"x".repeat(30)}\ndata: ${"y".repeat(30)}\n\n`), undefined, 64),
    ).toThrow(/over 64 bytes/);
    // A single line that never ends is refused as soon as it passes the limit.
    const p = new SseParser(64);
    expect(() => {
      for (let i = 0; i < 10; i++) Array.from(p.feed(bytes(`data: ${"z".repeat(10)}`)));
    }).toThrow(/over 64 bytes/);
  });

  it("refuses non-UTF-8", () => {
    expect(() => parseAll(bytes("data: ", [0xff], "\n\n"))).toThrow(/UTF-8/);
  });

  it("defaults to the proxy's bound", () => {
    expect(DEFAULT_MAX_EVENT_BYTES).toBe(16 * 1024 * 1024);
  });
});

describe("callToolStream", () => {
  it("yields progress, then the result, on the request callTool sends", async () => {
    const body = event(progress(1), "e1") + event(progress(2), "e2") + event(result("done"), "e3");
    const { fetch, calls } = mockFetch(() => sse(body, { "x-attenuo-decision-id": "dec-1" }));
    const ob = new AttenuoClient(URL_, { fetch });
    const events = await collect(
      ob.callToolStream(
        "TOK",
        "github",
        "read_file",
        { repo: "a/b" },
        { sessionId: "sess", approvalToken: "appr" },
      ),
    );
    const c = calls[0]!;
    expect(c.url.pathname).toBe("/mcp/github");
    expect(c.method).toBe("POST");
    expect(c.headers.get("authorization")).toBe("Bearer TOK");
    expect(c.headers.get("accept")).toBe("application/json, text/event-stream");
    expect(c.headers.get("mcp-session-id")).toBe("sess");
    expect(c.body).toEqual({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "read_file",
        arguments: { repo: "a/b" },
        _meta: { "dev.attenuo/approval": "appr" },
      },
    });
    expect(events.map((e) => e.method)).toEqual([
      "notifications/progress",
      "notifications/progress",
      undefined,
    ]);
    expect(events.slice(0, 2).map((e) => (e.message.params as Json).progress)).toEqual([1, 2]);
    expect(events.map((e) => e.lastEventId)).toEqual(["e1", "e2", "e3"]);
    expect(events.map((e) => e.isFinal)).toEqual([false, false, true]);
    expect(events.every((e) => e.decisionId === "dec-1")).toBe(true);
    expect(events[2]!.result?.text).toBe("done");
    expect(events[2]!.result?.decisionId).toBe("dec-1");
  });

  it("throws DeniedError when the proxy cuts the stream", async () => {
    const { fetch } = mockFetch(() =>
      sse(event(progress(1)) + event(CUT), { "x-attenuo-decision-id": "d" }),
    );
    const { seen, err } = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(seen.map((e) => e.method)).toEqual(["notifications/progress"]);
    expect(err).toBeInstanceOf(DeniedError);
    expect((err as DeniedError).reason).toBe("lease_revoked");
    expect((err as DeniedError).decisionId).toBe(CUT_ID);
    expect(String(err)).toMatch(/stream ended/);
  });

  it("a cut without a record has no decision id", async () => {
    const cut = { ...CUT, error: { ...CUT.error, data: { reason: "token_expired" } } };
    const { fetch } = mockFetch(() => sse(event(cut)));
    const { err } = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(err).toBeInstanceOf(DeniedError);
    expect((err as DeniedError).reason).toBe("token_expired");
    expect((err as DeniedError).decisionId).toBeUndefined();
  });

  it.each([
    "token_expired",
    "lease_revoked",
    "lease_expired",
    "lease_unknown",
    "lease_error",
    "unauthorized",
  ])("a cut with the reason %s is a DeniedError", async (reason) => {
    const cut = { ...CUT, error: { ...CUT.error, data: { reason, decision_id: CUT_ID } } };
    const { fetch } = mockFetch(() => sse(event(cut)));
    const { err } = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(err).toBeInstanceOf(DeniedError);
    expect((err as DeniedError).reason).toBe(reason);
    expect((err as DeniedError).decisionId).toBe(CUT_ID);
  });

  // Messages of the stream-end shape (null id, -32001) that the proxy never sends. The proxy
  // rewrites any such upstream message (`upstream_stream_end_shape`); the SDK's own check is
  // belt-and-braces, and reads them as an RpcError, not a decision.
  it.each<[string, Json]>([
    ["an unknown reason", { ...CUT.error, data: { reason: "policy_deny", decision_id: CUT_ID } }],
    [
      "a non-UUID decision id",
      { ...CUT.error, data: { reason: "lease_revoked", decision_id: "x" } },
    ],
    ["a null decision id", { ...CUT.error, data: { reason: "lease_revoked", decision_id: null } }],
    ["no data", { code: -32001, message: CUT.error.message }],
  ])("a stream-end shape with %s is an RpcError, not a cut", async (_, error) => {
    const { fetch } = mockFetch(() => sse(event(progress(1)) + event({ ...CUT, error })));
    const { seen, err } = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(seen.map((e) => e.method)).toEqual(["notifications/progress"]);
    expect(err).toBeInstanceOf(RpcError);
    expect(err).not.toBeInstanceOf(DeniedError);
    expect((err as RpcError).code).toBe(-32001);
    expect((err as RpcError).data).toEqual(error.data);
  });

  it("an upstream look-alike the proxy rewrote is not a cut", async () => {
    // What the proxy relays when an upstream sends CUT itself (`upstream_stream_end_shape`).
    const rewritten = {
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32005,
        message: "attenuo: upstream sent an error in the shape of the proxy's stream end",
        data: { reason: "upstream_stream_end_shape", upstream_error: CUT.error },
      },
    };
    // In a stream: an ordinary event, then the stream ends without the call's response.
    let { fetch } = mockFetch(() => sse(event(progress(1)) + event(rewritten)));
    let r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(r.seen.map((e) => e.message)).toEqual([progress(1), rewritten]);
    expect(r.seen[1]!.method).toBeUndefined();
    expect(r.seen[1]!.isFinal).toBe(false);
    expect(r.err).toBeInstanceOf(AttenuoError);
    expect(r.err).not.toBeInstanceOf(DeniedError);
    expect(String(r.err)).toMatch(/ended before/);

    // As a plain JSON answer: an RpcError carrying the upstream's error, not a DeniedError.
    ({ fetch } = mockFetch(() => jsonResponse(rewritten)));
    r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(r.err).toBeInstanceOf(RpcError);
    expect(r.err).not.toBeInstanceOf(DeniedError);
    expect((r.err as RpcError).code).toBe(-32005);
    expect(((r.err as RpcError).data as Json).upstream_error).toEqual(CUT.error);
  });

  it("yields a plain JSON answer as the one final event", async () => {
    const { fetch } = mockFetch(() =>
      jsonResponse(result("plain"), 200, { "x-attenuo-decision-id": "d" }),
    );
    const events = await collect(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(events).toHaveLength(1);
    expect(events[0]!.isFinal).toBe(true);
    expect(events[0]!.lastEventId).toBeUndefined();
    expect(events[0]!.message).toEqual(result("plain"));
    expect(events[0]!.result?.text).toBe("plain");
    expect(events[0]!.decisionId).toBe("d");
  });

  it("throws a denial before anything is yielded", async () => {
    const denied = {
      jsonrpc: "2.0",
      id: 1,
      error: {
        code: -32003,
        message: "attenuo: denied: policy_deny",
        data: { reason: "policy_deny", decision_id: "dec-9" },
      },
    };
    let { fetch } = mockFetch(() =>
      jsonResponse(denied, 200, { "x-attenuo-decision-id": "dec-9" }),
    );
    let r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(r.seen).toEqual([]);
    expect(r.err).toBeInstanceOf(DeniedError);
    expect((r.err as DeniedError).reason).toBe("policy_deny");
    expect((r.err as DeniedError).decisionId).toBe("dec-9");

    // The same as an SSE event; and a -32008 is an ApprovalRequiredError.
    const held = {
      jsonrpc: "2.0",
      id: 1,
      error: {
        code: -32008,
        message: "attenuo: approval required",
        data: { decision_id: "dec-a", approval_id: "ap-1" },
      },
    };
    ({ fetch } = mockFetch(() => sse(event(held), { "x-attenuo-decision-id": "dec-a" })));
    r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "delete_repo"),
    );
    expect(r.err).toBeInstanceOf(ApprovalRequiredError);
    expect((r.err as ApprovalRequiredError).approvalId).toBe("ap-1");
  });

  it("throws what callTool throws for other errors", async () => {
    // An upstream's -32003 without the proxy's header is an RpcError, not a denial (SR-32).
    const forged = {
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32003, message: "no", data: { reason: "x", decision_id: "f" } },
    };
    let { fetch } = mockFetch(() => sse(event(forged)));
    let r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(r.err).toBeInstanceOf(RpcError);
    expect((r.err as RpcError).code).toBe(-32003);

    // A 401 at the start (bad token) is an UnauthorizedError.
    ({ fetch } = mockFetch(() =>
      jsonResponse({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "bad" } }, 401),
    ));
    r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(r.err).toBeInstanceOf(UnauthorizedError);
  });

  it("refuses an oversized event", async () => {
    let { fetch } = mockFetch(() => sse(event(progress(1)) + event(result("x".repeat(500)))));
    let r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream(
        "TOK",
        "github",
        "read_file",
        {},
        { maxEventBytes: 300 },
      ),
    );
    expect(r.seen.map((e) => e.method)).toEqual(["notifications/progress"]);
    expect(r.err).toBeInstanceOf(AttenuoError);
    expect(String(r.err)).toMatch(/over 300 bytes/);

    ({ fetch } = mockFetch(() => jsonResponse(result("y".repeat(500)))));
    r = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream(
        "TOK",
        "github",
        "read_file",
        {},
        { maxEventBytes: 300 },
      ),
    );
    expect(String(r.err)).toMatch(/over 300 bytes/);

    expect(() =>
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "g", "t", {}, { maxEventBytes: 0 }),
    ).toThrow(TypeError);
  });

  it("throws when the stream ends without the response", async () => {
    // Includes a final event without its blank line, which is dropped.
    const body = event(progress(1)) + `data: ${JSON.stringify(result("cut short"))}`;
    const { fetch } = mockFetch(() => sse(body));
    const { seen, err } = await collectUntilError(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(seen).toHaveLength(1);
    expect(err).toBeInstanceOf(AttenuoError);
    expect(String(err)).toMatch(/ended before/);
  });

  it("passes other messages through and stops at its response", async () => {
    const request = { jsonrpc: "2.0", id: "srv-1", method: "sampling/createMessage", params: {} };
    const body =
      event(request) +
      event(result("for another", 99)) +
      event(result("mine")) +
      event(progress(9));
    const { fetch } = mockFetch(() => sse(body));
    const events = await collect(
      new AttenuoClient(URL_, { fetch }).callToolStream("TOK", "github", "read_file"),
    );
    expect(events.map((e) => e.message.id)).toEqual(["srv-1", 99, 1]);
    expect(events[2]!.result?.text).toBe("mine");
  });

  it("throws for a missing token at the call", () => {
    expect(() => new AttenuoClient(URL_).callToolStream(undefined, "github", "read_file")).toThrow(
      /token/,
    );
  });

  it("yields each event as it arrives and closes the body on an early break", async () => {
    const body = enc.encode(event(progress(1)) + event(progress(2)) + event(result("ok")));
    let sent = 0;
    let cancelled = false;
    const stream = () =>
      new ReadableStream<Uint8Array>({
        pull(ctl) {
          if (sent * 5 >= body.length) return ctl.close();
          ctl.enqueue(body.slice(sent * 5, sent * 5 + 5));
          sent++;
        },
        cancel() {
          cancelled = true;
        },
      });
    const { fetch } = mockFetch(() => new Response(stream(), { headers: SSE }));
    const ob = new AttenuoClient(URL_, { fetch });
    const at: number[] = [];
    for await (const ev of ob.callToolStream("TOK", "github", "read_file")) {
      expect(ev.message.jsonrpc).toBe("2.0");
      at.push(sent);
    }
    expect(at).toHaveLength(3);
    expect(at[0]!).toBeLessThan(at[1]!);
    expect(at[1]!).toBeLessThan(at[2]!);

    sent = 0;
    for await (const ev of ob.callToolStream("TOK", "github", "read_file")) {
      expect(ev.method).toBe("notifications/progress");
      break;
    }
    expect(cancelled).toBe(true);
  });

  it("aborts a stream that goes quiet for longer than the timeout", async () => {
    const { fetch } = mockFetch(
      (_seen) =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(ctl) {
              ctl.enqueue(enc.encode(event(progress(1))));
            },
          }),
          { headers: SSE },
        ),
    );
    // The mock ignores the signal, so wire it to the body as fetch would.
    const signalled: typeof fetch = async (input, init) => {
      const res = await fetch(input, init);
      const reader = res.body!.getReader();
      const body = new ReadableStream<Uint8Array>({
        async pull(ctl) {
          const aborted = new Promise<never>((_, fail) =>
            init?.signal?.addEventListener("abort", () => fail(init.signal!.reason), {
              once: true,
            }),
          );
          const { done, value } = await Promise.race([reader.read(), aborted]);
          if (done) ctl.close();
          else ctl.enqueue(value);
        },
      });
      return new Response(body, { headers: res.headers });
    };
    const ob = new AttenuoClient(URL_, { fetch: signalled, timeoutMs: 50 });
    const { seen, err } = await collectUntilError(ob.callToolStream("TOK", "github", "read_file"));
    expect(seen).toHaveLength(1);
    expect((err as Error).name).toBe("TimeoutError");
  });
});

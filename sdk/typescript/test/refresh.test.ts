import { beforeAll, describe, expect, it } from "vitest";
import {
  ApiError,
  decodeToken,
  DpopKey,
  OnbehalfClient,
  RefreshError,
  TokenRefresher,
  type Token,
} from "../src/index.js";
import { jsonResponse, mockFetch, Signer } from "./helpers.js";

const T0 = Math.floor(Date.now() / 1000) * 1000; // ms
let signer: Signer;

beforeAll(async () => {
  signer = await Signer.create();
});

async function mint(ttl = 100, opts: { at?: number; jkt?: string } = {}): Promise<Token> {
  const jwt = await signer.mint({
    agents: ["planner", "coder"],
    expDelta: ttl,
    at: (opts.at ?? T0) / 1000,
    ...(opts.jkt ? { claims: { cnf: { jkt: opts.jkt } } } : {}),
  });
  return decodeToken(jwt);
}

type Reply = Response | Error;

interface Rig {
  r: TokenRefresher;
  clock: { t: number };
  renewals: () => number;
  script: Reply[];
  changes: Token[];
  errors: RefreshError[];
  seen: Array<{ headers: Headers }>;
}

async function rig(
  o: {
    ttl?: number;
    interval?: number;
    serverInterval?: number;
    margin?: number;
    exchange?: (clock: { t: number }) => Promise<Token>;
    token?: Token;
    clientOpts?: ConstructorParameters<typeof OnbehalfClient>[1];
    onChange?: (t: Token) => void;
  } = {},
): Promise<Rig> {
  const clock = { t: T0 };
  const script: Reply[] = [];
  const seen: Array<{ headers: Headers }> = [];
  let renewals = 0;
  const { fetch } = mockFetch((s) => {
    expect(s.url.pathname).toBe("/token/renew");
    seen.push({ headers: s.headers });
    const next = script.shift();
    if (next instanceof Error) throw next;
    if (next) return next;
    renewals++;
    const secs = o.serverInterval ?? 30;
    return jsonResponse({
      lease: "lease-1",
      expires_at: new Date(clock.t + secs * 1000).toISOString(),
      expires_in: secs,
    });
  });
  const changes: Token[] = [];
  const errors: RefreshError[] = [];
  const r = new TokenRefresher({
    client: new OnbehalfClient("http://ob.test", { fetch, ...o.clientOpts }),
    token: o.token ?? (await mint(o.ttl ?? 100)),
    exchange: o.exchange ? () => o.exchange!(clock) : () => mint(o.ttl ?? 100, { at: clock.t }),
    ...(o.interval !== undefined ? { leaseInterval: o.interval } : {}),
    ...(o.margin !== undefined ? { margin: o.margin } : {}),
    now: () => clock.t,
    random: () => 0.5,
    onChange: o.onChange ?? ((t) => changes.push(t)),
    onError: (e) => errors.push(e),
  });
  return { r, clock, renewals: () => renewals, script, changes, errors, seen };
}

/** Run the loop on the fake clock for `ms`, waiting exactly as the timer would. */
async function advance(x: Rig, ms: number): Promise<void> {
  const end = x.clock.t + ms;
  while (x.clock.t < end) {
    const wait = await x.r.tick();
    if (wait === undefined) return;
    x.clock.t = Math.min(x.clock.t + Math.max(wait, 1), end);
  }
  await x.r.tick();
}

const apiError = (status: number, error: string, detail = "") =>
  jsonResponse({ error, detail }, status);

describe("TokenRefresher", () => {
  it("renews at a third of the lease interval", async () => {
    const x = await rig({ ttl: 1000, interval: 30 });
    await advance(x, 9_900);
    expect(x.renewals()).toBe(0);
    await advance(x, 200); // 10 s
    expect(x.renewals()).toBe(1);
    await advance(x, 30_000); // renewed again at 20 and 30
    expect(x.renewals()).toBe(4);
    expect(x.changes).toHaveLength(0);
  });

  it("learns the interval from the first renewal", async () => {
    const x = await rig({ ttl: 1000, serverInterval: 60 });
    await advance(x, 1);
    expect(x.renewals()).toBe(1);
    await advance(x, 19_900);
    expect(x.renewals()).toBe(1);
    await advance(x, 200); // 60 / 3 = 20 s
    expect(x.renewals()).toBe(2);
  });

  it("re-exchanges before exp, with a 20% margin by default", async () => {
    const next = await mint(100, { at: T0 + 80_000 });
    const x = await rig({ interval: 30, exchange: async () => next });
    const old = x.r.token;
    await advance(x, 79_000);
    expect(x.r.token).toBe(old);
    await advance(x, 3_000);
    expect(x.r.token).toBe(next);
    expect(x.changes).toEqual([next]);
    expect(x.errors).toEqual([]);
  });

  it("has a margin floor, a half-life cap and a custom margin", async () => {
    const at = async (ttl: number, margin?: number) => {
      const x = await rig({ ttl, interval: 100, ...(margin !== undefined ? { margin } : {}) });
      return (x.r as unknown as { exchangeAt: number }).exchangeAt - T0;
    };
    expect(await at(10)).toBeCloseTo(5_000, -4);
    expect(await at(4)).toBeCloseTo(2_000, -4);
    expect(await at(100, 50)).toBeCloseTo(50_000, -4);
  });

  it("gives the MCP transport the current token per request", async () => {
    const next = await mint(100, { at: T0 + 90_000 });
    const x = await rig({ interval: 30, exchange: async () => next });
    const old = x.r.token.jwt;
    const { fetch, calls } = mockFetch(() => jsonResponse({}));
    const f = x.r.fetch({ fetch });
    await f("http://ob.test/mcp/github", { method: "POST" });
    await advance(x, 90_000);
    await f("http://ob.test/mcp/github", { method: "POST" });
    expect(calls[0]!.headers.get("authorization")).toBe(`Bearer ${old}`);
    expect(calls[1]!.headers.get("authorization")).toBe(`Bearer ${next.jwt}`);
  });

  it("backs off with jitter on transient failures, then recovers", async () => {
    const x = await rig({ ttl: 1000, interval: 30 });
    x.script.push(apiError(503, "temporarily_unavailable"), new TypeError("fetch failed"));
    x.clock.t += 10_000;
    const waits: number[] = [];
    for (let i = 0; i < 3; i++) {
      const w = await x.r.tick();
      waits.push(w!);
      x.clock.t += w!;
    }
    // random() = 0.5: ceilings of 1 s then 2 s give 0.75 s then 1.5 s.
    expect(waits[0]).toBeCloseTo(750, -1);
    expect(waits[1]).toBeCloseTo(1500, -1);
    expect(x.renewals()).toBe(1);
    expect(x.errors).toEqual([]);
  });

  it("caps the backoff", async () => {
    const x = await rig({ ttl: 100_000, interval: 30 });
    for (let i = 0; i < 12; i++) x.script.push(apiError(503, "x"));
    x.clock.t += 10_000;
    let last = 0;
    for (let i = 0; i < 12; i++) {
      last = (await x.r.tick())!;
      x.clock.t += last;
    }
    expect(last).toBeGreaterThanOrEqual(15_000);
    expect(last).toBeLessThanOrEqual(30_000);
  });

  it("stops on lease_revoked and does not loop", async () => {
    const x = await rig({ ttl: 1000, interval: 30 });
    x.script.push(apiError(400, "invalid_grant", "lease_revoked"));
    x.clock.t += 10_000;
    expect(await x.r.tick()).toBeUndefined();
    expect(x.errors.map((e) => e.reason)).toEqual(["lease_revoked"]);
    expect(x.r.error).toBe(x.errors[0]);
    expect(x.errors[0]!.cause).toBeInstanceOf(ApiError);
    const sent = x.seen.length;
    expect(await x.r.tick()).toBeUndefined();
    expect(x.seen).toHaveLength(sent);
    expect(x.errors).toHaveLength(1);
    expect(() => x.r.provider()).toThrow(RefreshError);
  });

  it.each([
    [apiError(400, "invalid_grant", "lease_unknown"), "lease_revoked"],
    [apiError(400, "invalid_grant", "an ancestor lease is not live: lease_expired"), "lease_lost"],
    [apiError(401, "unauthorized", "token_expired"), "token_expired"],
    [apiError(401, "unauthorized", "invalid_token"), "refused"],
  ])("treats a renew refusal as terminal (%#)", async (resp, reason) => {
    const x = await rig({ ttl: 1000, interval: 30 });
    x.script.push(resp);
    x.clock.t += 10_000;
    await x.r.tick();
    expect(x.errors.map((e) => e.reason)).toEqual([reason]);
  });

  it("treats an exchange refusal as terminal but an outage as retryable", async () => {
    let n = 0;
    const x = await rig({
      ttl: 100,
      interval: 30,
      exchange: async () => {
        n++;
        if (n === 1) throw new TypeError("fetch failed");
        if (n === 2) throw new ApiError(400, "invalid_grant", "replayed");
        return mint(100);
      },
    });
    x.clock.t += 85_000;
    await advance(x, 5_000);
    expect(n).toBe(2);
    expect(x.changes).toHaveLength(0);
    expect(x.errors.map((e) => e.reason)).toEqual(["refused"]);
    expect(x.errors[0]!.message).not.toContain("replayed");
  });

  it("reports token_expired when the exchange keeps failing until exp", async () => {
    const x = await rig({
      ttl: 30,
      interval: 300,
      exchange: async () => {
        throw new TypeError("down");
      },
    });
    await advance(x, 40_000);
    expect(x.errors.map((e) => e.reason)).toEqual(["token_expired"]);
    expect(await x.r.tick()).toBeUndefined();
  });

  it("only adopts a replacement bound to the same DPoP key", async () => {
    const [key, other] = await Promise.all([DpopKey.generate(), DpopKey.generate()]);
    const bound = await mint(100, { jkt: key.thumbprint });
    const cases: Array<[Token, boolean]> = [
      [await mint(100, { jkt: key.thumbprint, at: T0 + 90_000 }), true],
      [await mint(100, { jkt: other.thumbprint, at: T0 + 90_000 }), false],
      [await mint(100, { at: T0 + 90_000 }), false],
    ];
    for (const [replacement, adopted] of cases) {
      const x = await rig({ interval: 30, token: bound, exchange: async () => replacement });
      await advance(x, 95_000);
      expect(x.r.token === replacement).toBe(adopted);
      expect(x.errors.map((e) => e.reason)).toEqual(adopted ? [] : ["key_mismatch"]);
      expect(x.changes).toHaveLength(adopted ? 1 : 0);
    }
  });

  it("signs renewals with the client's DPoP key", async () => {
    const key = await DpopKey.generate();
    const bound = await mint(1000, { jkt: key.thumbprint });
    const x = await rig({ interval: 30, token: bound, clientOpts: { dpopKey: key } });
    x.clock.t += 11_000;
    await x.r.tick();
    expect(x.seen[0]!.headers.get("authorization")).toBe(`DPoP ${bound.jwt}`);
    expect(x.seen[0]!.headers.get("dpop")!.split(".")).toHaveLength(3);
  });

  it("survives a throwing callback without leaking the token", async () => {
    const next = await mint(100, { at: T0 + 80_000 });
    const x = await rig({
      interval: 30,
      exchange: async () => next,
      onChange: () => {
        throw new Error(`secret ${next.jwt}`);
      },
    });
    await advance(x, 90_000);
    expect(x.r.token).toBe(next);
    expect(x.r.error).toBeUndefined();
  });

  it("never puts a token in an error message", async () => {
    const x = await rig({ ttl: 1000, interval: 30 });
    x.script.push(apiError(400, "invalid_grant", "lease_revoked"));
    x.clock.t += 10_000;
    await x.r.tick();
    const e = x.errors[0]!;
    expect(`${e.message} ${JSON.stringify(e)} ${String(e.cause)}`).not.toContain(
      x.r.token.jwt.split(".")[1]!,
    );
  });

  it("rejects bad options", async () => {
    await expect(rig({ interval: 0 })).rejects.toThrow(RangeError);
    await expect(rig({ margin: -1 })).rejects.toThrow(RangeError);
  });

  it("start() returns a disposer that stops the loop", async () => {
    const x = await rig({ ttl: 100_000, interval: 3000 }); // far-off schedule: no waiting
    const dispose = x.r.start();
    await dispose();
    await dispose(); // idempotent
    expect(x.r.error).toBeUndefined();
  });
});

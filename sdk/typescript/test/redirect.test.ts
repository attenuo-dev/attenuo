/**
 * No client of the SDK follows a redirect (SR-112, security review pass 13). With `fetch`'s
 * default `redirect: "follow"`, a `307` from the server URL used to send the request body again
 * to the other origin, client secret and subject token included. Now the other origin gets no
 * request, and the call throws `ApiError` `redirect_not_followed` naming the `Location`.
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { AdminClient, ApiError, AttenuoClient, mcpFetch } from "../src/index.js";

const servers: http.Server[] = [];

async function listen(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((s) => new Promise<void>((resolve) => s.close(() => resolve()))),
  );
});

/** A server answering `307` to a second one, which records every request it gets. */
async function redirecting(): Promise<{ front: string; location: string; seen: string[] }> {
  const seen: string[] = [];
  const other = await listen((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString()));
    req.on("end", () => {
      seen.push(body);
      res.writeHead(400, { "content-type": "application/json" });
      res.end('{"error":"invalid_request"}');
    });
  });
  const location = `${other}/collect`;
  const front = await listen((req, res) => {
    req.resume();
    res.writeHead(307, { location });
    res.end();
  });
  return { front, location, seen };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 200));

describe("a redirect from the server URL (SR-112)", () => {
  it("is not followed: the call throws redirect_not_followed naming the Location", async () => {
    const { front, location, seen } = await redirecting();
    const client = new AttenuoClient(front);
    const err = await client
      .exchange("a.b.c", "coder", [{ server: "gh", tool: "x" }], {
        clientId: "coder",
        clientSecret: "sr112-client-secret",
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const api = err as ApiError;
    expect(api.status).toBe(307);
    expect(api.code).toBe("redirect_not_followed");
    expect(api.message).toContain(`Location ${location}`);
    expect(api.message).toContain("does not follow redirects");
    expect(api.message).not.toContain("sr112-client-secret");
    await settle();
    expect(seen).toEqual([]);
  });

  it("is not followed by action search, and the bearer stays on this origin", async () => {
    const { front, seen } = await redirecting();
    const err = await new AttenuoClient(front)
      .authzenSearchAction("sr112-bearer", "gh", { repo: "a/b" })
      .catch((e: unknown) => e);
    expect((err as ApiError).code).toBe("redirect_not_followed");
    expect((err as ApiError).message).not.toContain("sr112-bearer");
    await settle();
    expect(seen).toEqual([]);
  });

  it("is not followed by the admin client either", async () => {
    const { front, seen } = await redirecting();
    const admin = new AdminClient(front, "sr112-admin-token");
    const err = await admin.revokeLease("lease-1").catch((e: unknown) => e);
    expect((err as ApiError).code).toBe("redirect_not_followed");
    await settle();
    expect(seen).toEqual([]);
  });

  it("asks a fetch given in the options for manual redirects", async () => {
    const inits: RequestInit[] = [];
    const client = new AttenuoClient("http://ob.test", {
      fetch: async (_url, init) => {
        inits.push(init ?? {});
        return new Response(null, { status: 308, headers: { location: "http://other.test/" } });
      },
    });
    const err = await client.authzenConfiguration().catch((e: unknown) => e);
    expect((err as ApiError).code).toBe("redirect_not_followed");
    expect(inits.map((i) => i.redirect)).toEqual(["manual"]);
  });

  it("reads a browser's opaque redirect as one, without a Location", async () => {
    const opaque = { type: "opaqueredirect", status: 0, headers: new Headers(), body: null };
    const client = new AttenuoClient("http://ob.test", {
      fetch: async () => opaque as unknown as Response,
    });
    const err = await client.authzenConfiguration().catch((e: unknown) => e);
    expect((err as ApiError).code).toBe("redirect_not_followed");
    expect((err as ApiError).message).toContain("answered a redirect (no Location)");
  });

  it("is not followed by mcpFetch, whatever the caller's init asks", async () => {
    const { front, seen } = await redirecting();
    const f = mcpFetch(() => "tok");
    const res = await f(`${front}/mcp/gh`, {
      method: "POST",
      body: '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
      redirect: "follow",
    });
    expect(res.status).toBe(307);
    await settle();
    expect(seen).toEqual([]);
  });
});

/**
 * What the client does when the server URL answers a `307` to another origin (SR-112, security
 * review pass 13). Today `fetch` follows it with its default `redirect: "follow"`: the request
 * body, client secret included, is sent again to the other origin; only `Authorization` is
 * dropped. The finding is open; this test pins today's behaviour and changes with the
 * maintainer's choice (the proposal is not to follow redirects, as the Python SDK does not).
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { AttenuoClient } from "../src/index.js";

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

describe("a redirect from the server URL (SR-112)", () => {
  it("is followed today, and the token request body reaches the other origin", async () => {
    const seen: { url?: string; auth?: string; body: string }[] = [];
    const other = await listen((req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c.toString()));
      req.on("end", () => {
        seen.push({ url: req.url, auth: req.headers.authorization, body });
        res.writeHead(400, { "content-type": "application/json" });
        res.end('{"error":"invalid_request"}');
      });
    });
    const front = await listen((req, res) => {
      req.resume();
      res.writeHead(307, { location: `${other}/collect` });
      res.end();
    });
    const client = new AttenuoClient(front);
    await expect(
      client.exchange("a.b.c", "coder", [{ server: "gh", tool: "x" }], {
        clientId: "coder",
        clientSecret: "sr112-client-secret",
      }),
    ).rejects.toThrow();
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe("/collect");
    expect(seen[0]!.auth).toBeUndefined();
    const body = JSON.parse(seen[0]!.body) as Record<string, unknown>;
    expect(body.client_secret).toBe("sr112-client-secret");
    expect(body.subject_token).toBe("a.b.c");
  });
});

/** DPoP (RFC 9449, SR-24): keys, proofs, and the clients putting them on the wire. */

import { createServer, type AddressInfo, type Socket } from "node:net";
import { beforeAll, describe, expect, it } from "vitest";
import {
  accessTokenHash,
  AdminClient,
  DpopKey,
  jwkThumbprint,
  mcpFetch,
  AttenuoClient,
  AttenuoError,
} from "../src/index.js";
import { jsonResponse, mockFetch, rpcOk, Signer, tokenResponse, type Seen } from "./helpers.js";

const BASE = "http://ob.test";
type Json = Record<string, unknown>;

function unb64(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Check a proof's signature with its own header key; return its header and claims. */
async function verify(proof: string | null): Promise<{ header: Json; claims: Json }> {
  expect(proof).toBeTruthy();
  const [h, p, s] = proof!.split(".") as [string, string, string];
  const header = JSON.parse(Buffer.from(h, "base64url").toString()) as Json;
  const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as Json;
  expect(header.typ).toBe("dpop+jwt");
  const jwk = header.jwk as Json;
  expect(jwk.d).toBeUndefined();
  const ed = header.alg === "EdDSA";
  if (!ed) expect(header.alg).toBe("ES256");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk as JsonWebKey,
    ed ? "Ed25519" : { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    ed ? "Ed25519" : { name: "ECDSA", hash: "SHA-256" },
    key,
    unb64(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  expect(ok).toBe(true);
  return { header, claims };
}

const P256 = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  d: "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
};

let signer: Signer;
beforeAll(async () => {
  signer = await Signer.create();
});

const bound = (jkt: string, agents = ["planner"]) =>
  signer.mint({ agents, claims: { cnf: { jkt } } });

describe("DPoP keys", () => {
  it("computes the RFC 8037 thumbprint", async () => {
    const jwk = { kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
    expect(await jwkThumbprint(jwk)).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
  });

  it("round-trips keys and signs with both algorithms", async () => {
    const ed = await DpopKey.generate();
    expect((await DpopKey.fromJwk(ed.privateJwk())).thumbprint).toBe(ed.thumbprint);
    expect(JSON.stringify(ed)).not.toContain(ed.privateJwk().d);
    const p256 = await DpopKey.fromJwk(P256);
    expect(p256.alg).toBe("ES256");
    for (const key of [ed, p256]) {
      const { header, claims } = await verify(
        await key.proof("post", `${BASE}/mcp/github?x=1#f`, "tok"),
      );
      expect(await jwkThumbprint(header.jwk as Json)).toBe(key.thumbprint);
      expect(claims.htm).toBe("POST");
      expect(claims.htu).toBe(`${BASE}/mcp/github`);
      expect(claims.ath).toBe(await accessTokenHash("tok"));
      expect(Math.abs(Number(claims.iat) - Date.now() / 1000)).toBeLessThan(5);
      expect(claims.jti).toBeTruthy();
    }
  });

  it("refuses public, mismatched and unsupported keys", async () => {
    const ed = await DpopKey.generate();
    const other = await DpopKey.generate();
    await expect(DpopKey.fromJwk(ed.publicJwk)).rejects.toBeInstanceOf(AttenuoError);
    await expect(
      DpopKey.fromJwk({ ...ed.privateJwk(), x: other.publicJwk.x }),
    ).rejects.toBeInstanceOf(AttenuoError);
    await expect(DpopKey.fromJwk({ kty: "RSA", n: "x", e: "AQAB", d: "x" })).rejects.toThrow(
      /unsupported/,
    );
  });
});

describe("clients with a DPoP key", () => {
  it("binds on exchange and attaches proofs to every request", async () => {
    const key = await DpopKey.generate();
    const parentKey = await DpopKey.generate();
    const child = await bound(key.thumbprint, ["planner", "coder"]);
    const { fetch, calls } = mockFetch((seen) => {
      if (seen.url.pathname === "/token") return jsonResponse(tokenResponse(child, "lease-1"));
      if (seen.url.pathname === "/token/renew")
        return jsonResponse({ lease: "l", expires_at: "2030-01-01T00:00:00Z", expires_in: 5 });
      if (seen.url.pathname === "/access/v1/evaluation") return jsonResponse({ decision: true });
      return rpcOk({ content: [] });
    });
    const ob = new AttenuoClient(BASE, { fetch, dpopKey: key.privateJwk() });
    const last = () => calls[calls.length - 1]!;

    // Unbound parent: the header proof binds the child and covers nothing.
    const tok = await ob.exchange(await signer.mint(), "coder", "github:read_file");
    expect(tok.dpopJkt).toBe(key.thumbprint);
    let { header, claims } = await verify(last().headers.get("dpop"));
    expect(claims.htu).toBe(`${BASE}/token`);
    expect(claims.ath).toBeUndefined();
    expect((last().body as Json).subject_token_dpop).toBeUndefined();

    // Parent bound to the same key: the proof covers it.
    const parent = await bound(key.thumbprint);
    await ob.exchange(parent, "coder", "github:read_file");
    ({ header, claims } = await verify(last().headers.get("dpop")));
    expect(claims.ath).toBe(await accessTokenHash(parent));
    expect(await jwkThumbprint(header.jwk as Json)).toBe(key.thumbprint);

    // Parent bound to another key: its holder signs off in the body.
    const other = await bound(parentKey.thumbprint);
    await ob.exchange(other, "coder", "github:read_file", { subjectDpopKey: parentKey });
    ({ header, claims } = await verify((last().body as Json).subject_token_dpop as string));
    expect(await jwkThumbprint(header.jwk as Json)).toBe(parentKey.thumbprint);
    expect(claims.ath).toBe(await accessTokenHash(other));
    // SR-40: the sign-off names the new token's key and agent.
    expect(claims.child_jkt).toBe(key.thumbprint);
    expect(claims.child_actor).toBe("coder");
    await expect(
      ob.exchange(other, "coder", "github:read_file", { subjectDpopKey: key }),
    ).rejects.toBeInstanceOf(AttenuoError);

    // A sign-off made by the parent's holder elsewhere is passed through as it is.
    const detached = await parentKey.signOff(`${BASE}/token`, other, key.thumbprint, "coder");
    await ob.exchange(other, "coder", "github:read_file", { subjectTokenDpop: detached });
    expect((last().body as Json).subject_token_dpop).toBe(detached);
    await expect(
      ob.exchange(other, "coder", "github:read_file", {
        subjectDpopKey: parentKey,
        subjectTokenDpop: detached,
      }),
    ).rejects.toBeInstanceOf(AttenuoError);

    // Every use of a token carries a proof for that request.
    const before = calls.length;
    await ob.callTool(child, "github", "read_file");
    await ob.renew(child);
    await ob.authzenEvaluate(child, "github", "read_file");
    expect(calls.length - before).toBe(3);
    for (const c of calls.slice(before)) {
      expect(c.headers.get("authorization")).toBe(`DPoP ${child}`);
      ({ claims } = await verify(c.headers.get("dpop")));
      expect(claims.htu).toBe(c.url.toString());
      expect(claims.ath).toBe(await accessTokenHash(child));
    }
  });

  it("sends a plain bearer without a key", async () => {
    const { fetch, calls } = mockFetch(() => rpcOk({ content: [] }));
    await new AttenuoClient(BASE, { fetch }).callTool("a.b.c", "github", "read_file");
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer a.b.c");
    expect(calls[0]!.headers.get("dpop")).toBeNull();
  });

  it("binds a dev root token", async () => {
    const key = await DpopKey.generate();
    const root = await bound(key.thumbprint);
    const { fetch, calls } = mockFetch(() => jsonResponse(tokenResponse(root)));
    const admin = new AdminClient(BASE, "adm", { fetch });
    const tok = await admin.mintRootDev("alice", "https://idp.example", "planner", {
      dpopKey: key,
    });
    expect(tok.dpopJkt).toBe(key.thumbprint);
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer adm");
    const { claims } = await verify(calls[0]!.headers.get("dpop"));
    expect(claims.htu).toBe(`${BASE}/admin/root-token`);
    expect(claims.ath).toBeUndefined();
  });

  it("mcpFetch adds a fresh proof per request", async () => {
    const key = await DpopKey.generate();
    const { fetch, calls } = mockFetch(() => new Response(null, { status: 200 }));
    const f = mcpFetch(() => "a.b.c", { dpopKey: key, fetch });
    await f(`${BASE}/mcp/github`, { method: "POST", headers: { Authorization: "Bearer stale" } });
    await f(`${BASE}/mcp/github`);
    const proofs = await Promise.all(
      calls.map(async (c) => (await verify(c.headers.get("dpop"))).claims),
    );
    expect(proofs.map((p) => p.htm)).toEqual(["POST", "GET"]);
    expect(proofs[0]!.jti).not.toBe(proofs[1]!.jti);
    expect(calls.map((c) => c.headers.get("authorization"))).toEqual(["DPoP a.b.c", "DPoP a.b.c"]);

    const plain = mockFetch(() => new Response(null, { status: 200 }));
    await mcpFetch(() => "a.b.c", { fetch: plain.fetch })(`${BASE}/mcp/github`);
    expect(plain.calls[0]!.headers.get("authorization")).toBe("Bearer a.b.c");
  });
});

/**
 * A fake server that wants its current nonce in every proof (RFC 9449 §8). Refusals are the
 * resource-server kind (401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"`) except on
 * `/token` and `/admin/root-token`, which answer like an authorization server (400, JSON `error`).
 */
function nonceServer(ok: (seen: Seen) => Response) {
  const state = { nonce: "n-1", seen: [] as (string | undefined)[] };
  const handler = async (seen: Seen): Promise<Response> => {
    const proof = seen.headers.get("dpop");
    const nonce = proof ? ((await verify(proof)).claims.nonce as string | undefined) : undefined;
    state.seen.push(nonce);
    if (proof && nonce !== state.nonce) {
      if (seen.url.pathname === "/token" || seen.url.pathname === "/admin/root-token") {
        return jsonResponse({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": state.nonce });
      }
      return jsonResponse({ jsonrpc: "2.0", id: 1, error: { code: -32001, message: "x" } }, 401, {
        "WWW-Authenticate": 'DPoP error="use_dpop_nonce", algs="EdDSA ES256"',
        "DPoP-Nonce": state.nonce,
      });
    }
    const res = ok(seen);
    res.headers.set("DPoP-Nonce", state.nonce);
    return res;
  };
  return { state, handler };
}

function okForEveryRoute(child: string) {
  return (seen: Seen): Response => {
    switch (seen.url.pathname) {
      case "/token":
      case "/admin/root-token":
        return jsonResponse(tokenResponse(child));
      case "/token/renew":
        return jsonResponse({ lease: "l", expires_at: "2030-01-01T00:00:00Z", expires_in: 5 });
      case "/access/v1/evaluation":
        return jsonResponse({ decision: true });
      default:
        return rpcOk({ content: [] });
    }
  };
}

describe("DPoP server nonces", () => {
  it("caches the nonce and retries once on use_dpop_nonce", async () => {
    const key = await DpopKey.generate();
    const child = await bound(key.thumbprint, ["planner", "coder"]);
    const server = nonceServer(okForEveryRoute(child));
    const { fetch, calls } = mockFetch(server.handler);
    const ob = new AttenuoClient(BASE, { fetch, dpopKey: key });

    // First request: no nonce yet, refused, retried once with the server's nonce.
    await ob.callTool(child, "github", "read_file");
    expect(server.state.seen).toEqual([undefined, "n-1"]);
    const [first, retry] = calls as [Seen, Seen];
    expect(retry.body).toEqual(first.body);
    expect((await verify(first.headers.get("dpop"))).claims.jti).not.toBe(
      (await verify(retry.headers.get("dpop"))).claims.jti,
    );

    // Later requests carry the cached nonce straight away, on every route.
    await ob.renew(child);
    await ob.authzenEvaluate(child, "github", "read_file");
    await ob.exchange(child, "reviewer", ["github:read_file"]);
    expect(server.state.seen.slice(2)).toEqual(["n-1", "n-1", "n-1"]);

    // The server rolls its nonce: one more refusal (the 400 of `/token`), one retry.
    server.state.nonce = "n-2";
    await ob.exchange(child, "reviewer", ["github:read_file"]);
    expect(server.state.seen.slice(5)).toEqual(["n-1", "n-2"]);
    await ob.callTool(child, "github", "read_file");
    expect(server.state.seen.slice(7)).toEqual(["n-2"]);
  });

  it("signs callToolStream and retries it once on use_dpop_nonce", async () => {
    const key = await DpopKey.generate();
    const child = await bound(key.thumbprint, ["planner", "coder"]);
    const body =
      'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n' +
      'data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"bound"}]}}\n\n';
    const server = nonceServer(
      () => new Response(body, { headers: { "content-type": "text/event-stream" } }),
    );
    const { fetch, calls } = mockFetch(server.handler);
    const ob = new AttenuoClient(BASE, { fetch, dpopKey: key });
    const events = [];
    for await (const ev of ob.callToolStream(child, "github", "read_file")) events.push(ev);
    expect(events.at(-1)?.result?.text).toBe("bound");
    expect(server.state.seen).toEqual([undefined, "n-1"]);
    const [first, retry] = calls as [Seen, Seen];
    expect(retry.body).toEqual(first.body);
    expect(retry.headers.get("authorization")).toBe(`DPoP ${child}`);
    const { claims } = await verify(retry.headers.get("dpop"));
    expect(claims.htm).toBe("POST");
    expect(claims.htu).toBe(`${BASE}/mcp/github`);
  });

  it("retries only once", async () => {
    const key = await DpopKey.generate();
    const child = await bound(key.thumbprint);
    const server = nonceServer(okForEveryRoute(child));
    let n = 0;
    const { fetch, calls } = mockFetch((seen) => {
      server.state.nonce = `r-${n++}`; // never the one the client just learned
      return server.handler(seen);
    });
    const ob = new AttenuoClient(BASE, { fetch, dpopKey: key });
    await expect(ob.renew(child)).rejects.toThrow();
    expect(calls).toHaveLength(2);
  });

  it("does not retry without a key", async () => {
    const { fetch, calls } = mockFetch(() =>
      jsonResponse({ error: "use_dpop_nonce" }, 401, {
        "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
        "DPoP-Nonce": "n",
      }),
    );
    await expect(new AttenuoClient(BASE, { fetch }).renew("a.b.c")).rejects.toThrow();
    expect(calls).toHaveLength(1);
  });

  it("mcpFetch and the admin root mint retry with the server's nonce", async () => {
    const key = await DpopKey.generate();
    const child = await bound(key.thumbprint);
    const server = nonceServer(okForEveryRoute(child));
    const { fetch } = mockFetch(server.handler);
    const f = mcpFetch(() => "a.b.c", { dpopKey: key, fetch });
    const init = { method: "POST", body: JSON.stringify({ id: 1 }) };
    expect((await f(`${BASE}/mcp/github`, init)).status).toBe(200);
    expect((await f(`${BASE}/mcp/github`, init)).status).toBe(200);
    expect(server.state.seen).toEqual([undefined, "n-1", "n-1"]);

    const admin = new AdminClient(BASE, "adm", { fetch });
    server.state.seen.length = 0;
    const tok = await admin.mintRootDev("alice", "https://idp", "planner", { dpopKey: key });
    await admin.mintRootDev("alice", "https://idp", "planner", { dpopKey: key });
    expect(tok.dpopJkt).toBe(key.thumbprint);
    expect(server.state.seen).toEqual([undefined, "n-1", "n-1"]);
  });

  it("resends the retry once, with the same proof, when the connection drops", async () => {
    const key = await DpopKey.generate();
    const child = await bound(key.thumbprint, ["planner", "coder"]);
    const server = nonceServer(okForEveryRoute(child));
    let dropped = 0;
    const { fetch, calls } = mockFetch((seen) => {
      // The retry lands on the connection the server is closing after its refusal.
      if (calls.length === 2 && dropped++ === 0) throw new TypeError("fetch failed");
      return server.handler(seen);
    });
    const ob = new AttenuoClient(BASE, { fetch, dpopKey: key });
    await ob.callTool(child, "github", "read_file");
    expect(calls).toHaveLength(3);
    const [, retry, resent] = calls as [Seen, Seen, Seen];
    expect(resent.headers.get("dpop")).toBe(retry.headers.get("dpop"));
    expect((await verify(resent.headers.get("dpop"))).claims.nonce).toBe("n-1");
    expect(resent.body).toEqual(retry.body);

    // mcpFetch and the root mint do the same.
    for (const run of [
      () =>
        mcpFetch(() => "a.b.c", { dpopKey: key, fetch })(`${BASE}/mcp/github`, {
          method: "POST",
          body: JSON.stringify({ id: 1 }),
        }),
      () =>
        new AdminClient(BASE, "adm", { fetch }).mintRootDev("alice", "https://idp", "planner", {
          dpopKey: key,
        }),
    ]) {
      calls.length = 0;
      dropped = 0;
      await run();
      expect(calls).toHaveLength(3);
      expect(calls[2]!.headers.get("dpop")).toBe(calls[1]!.headers.get("dpop"));
    }
  });

  it("does not resend the first request, a second drop or an abort", async () => {
    const key = await DpopKey.generate();
    const child = await bound(key.thumbprint, ["planner", "coder"]);
    const server = nonceServer(okForEveryRoute(child));
    let fail: (() => never) | undefined = () => {
      throw new TypeError("fetch failed");
    };
    const { fetch, calls } = mockFetch((seen) => (fail ? fail() : server.handler(seen)));
    const ob = new AttenuoClient(BASE, { fetch, dpopKey: key });
    await expect(ob.callTool(child, "github", "read_file")).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(1);

    fail = undefined;
    calls.length = 0;
    const drops = mockFetch((seen) => {
      if (drops.calls.length >= 2) throw new TypeError("fetch failed");
      return server.handler(seen);
    });
    const ob2 = new AttenuoClient(BASE, { fetch: drops.fetch, dpopKey: key });
    await expect(ob2.callTool(child, "github", "read_file")).rejects.toThrow(TypeError);
    expect(drops.calls).toHaveLength(3);

    const aborts = mockFetch((seen) => {
      if (aborts.calls.length === 2) throw new DOMException("aborted", "AbortError");
      return server.handler(seen);
    });
    const ob3 = new AttenuoClient(BASE, { fetch: aborts.fetch, dpopKey: key });
    await expect(ob3.callTool(child, "github", "read_file")).rejects.toThrow("aborted");
    expect(aborts.calls).toHaveLength(2);
  });

  it("gets the retry through a server that closes the refused connection", async () => {
    // Like attenuo-server: the 401 goes out before the body is read, and the connection is
    // closed a moment later without `Connection: close`.
    const nonces: (string | undefined)[] = [];
    let connections = 0;
    const srv = createServer((sock: Socket) => {
      connections++;
      let buf = "";
      const onData = (d: Buffer) => {
        buf += d.toString("latin1");
        const end = buf.indexOf("\r\n\r\n");
        if (end < 0) return;
        sock.off("data", onData);
        const proof = buf
          .slice(0, end)
          .split("\r\n")
          .find((l) => l.toLowerCase().startsWith("dpop:"))!
          .slice(5)
          .trim();
        const claims = JSON.parse(
          Buffer.from(proof.split(".")[1]!, "base64url").toString(),
        ) as Json;
        nonces.push(claims.nonce as string | undefined);
        if (claims.nonce !== "n-1") {
          const body = '{"error":"use_dpop_nonce"}';
          sock.write(
            "HTTP/1.1 401 Unauthorized\r\n" +
              'www-authenticate: DPoP error="use_dpop_nonce"\r\ndpop-nonce: n-1\r\n' +
              `content-type: application/json\r\ncontent-length: ${body.length}\r\n\r\n${body}`,
          );
          setTimeout(() => sock.destroy(), 300);
        } else {
          sock.end("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}");
        }
      };
      sock.on("data", onData);
    });
    await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
    try {
      const { port } = srv.address() as AddressInfo;
      const f = mcpFetch(() => "a.b.c", { dpopKey: await DpopKey.generate() });
      const r = await f(`http://127.0.0.1:${port}/mcp/github`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: 1 }),
      });
      expect(r.status).toBe(200);
      // The retry went out on the closing connection, unread; its resend on a new one.
      expect(nonces).toEqual([undefined, "n-1"]);
      expect(connections).toBe(2);
    } finally {
      srv.close();
    }
  });

  it("puts a nonce in a proof only when given", async () => {
    const key = await DpopKey.generate();
    expect((await verify(await key.proof("POST", `${BASE}/token`))).claims.nonce).toBeUndefined();
    const { claims } = await verify(
      await key.proof("POST", `${BASE}/token`, undefined, { nonce: "abc" }),
    );
    expect(claims.nonce).toBe("abc");
  });
});

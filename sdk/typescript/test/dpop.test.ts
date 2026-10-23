/** DPoP (RFC 9449, SR-24): keys, proofs, and the clients putting them on the wire. */

import { beforeAll, describe, expect, it } from "vitest";
import {
  accessTokenHash,
  AdminClient,
  DpopKey,
  jwkThumbprint,
  mcpFetch,
  OnbehalfClient,
  OnbehalfError,
} from "../src/index.js";
import { jsonResponse, mockFetch, rpcOk, Signer, tokenResponse } from "./helpers.js";

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
    await expect(DpopKey.fromJwk(ed.publicJwk)).rejects.toBeInstanceOf(OnbehalfError);
    await expect(
      DpopKey.fromJwk({ ...ed.privateJwk(), x: other.publicJwk.x }),
    ).rejects.toBeInstanceOf(OnbehalfError);
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
    const ob = new OnbehalfClient(BASE, { fetch, dpopKey: key.privateJwk() });
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
    ).rejects.toBeInstanceOf(OnbehalfError);

    // A sign-off made by the parent's holder elsewhere is passed through as it is.
    const detached = await parentKey.signOff(`${BASE}/token`, other, key.thumbprint, "coder");
    await ob.exchange(other, "coder", "github:read_file", { subjectTokenDpop: detached });
    expect((last().body as Json).subject_token_dpop).toBe(detached);
    await expect(
      ob.exchange(other, "coder", "github:read_file", {
        subjectDpopKey: parentKey,
        subjectTokenDpop: detached,
      }),
    ).rejects.toBeInstanceOf(OnbehalfError);

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
    await new OnbehalfClient(BASE, { fetch }).callTool("a.b.c", "github", "read_file");
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

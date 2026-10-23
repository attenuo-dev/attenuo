import { beforeAll, describe, expect, it } from "vitest";
import { decodeToken, AttenuoError, Token, VerificationError, verifyToken } from "../src/index.js";
import { b64, Signer } from "./helpers.js";

let signer: Signer;
beforeAll(async () => {
  signer = await Signer.create();
});

describe("decodeToken", () => {
  it("reads the chain and hides the jwt", async () => {
    const jwt = await signer.mint({ agents: ["assistant", "coder"] });
    const tok = decodeToken(jwt);
    expect(tok.agents).toEqual(["assistant", "coder"]);
    expect(tok.agent).toBe("coder");
    expect(tok.subject).toBe("alice");
    expect(tok.lease).toBe("lease-1");
    expect(tok.verified).toBe(false);
    expect(tok.capabilities).toEqual([{ server: "github", tool: "*" }]);
    expect(tok.expiresIn).toBeGreaterThan(800);
    expect(tok.chain.user.authenticatedAt.toISOString()).toBe("2026-10-23T09:00:00.500Z");
    expect(String(tok)).toBe(jwt);
    expect(JSON.stringify(tok)).not.toContain(jwt);
    expect(Object.keys(tok)).not.toContain("jwt");
    expect(tok).toBeInstanceOf(Token);
  });

  it("prefers the lease the server reported", async () => {
    expect(decodeToken(await signer.mint(), "lease-x").lease).toBe("lease-x");
  });

  it("rejects garbage", () => {
    expect(() => decodeToken("a.b")).toThrow(AttenuoError);
    expect(() => decodeToken("a.b.c")).toThrow(AttenuoError);
    const notToken = `${b64("{}")}.${b64('{"exp":1}')}.${b64("x")}`;
    expect(() => decodeToken(notToken)).toThrow(/not an attenuo delegation token/);
  });
});

describe("verifyToken", () => {
  it("accepts a good token and marks it verified", async () => {
    const jwt = await signer.mint({ agents: ["assistant", "coder"] });
    const tok = await verifyToken(jwt, signer.jwks, {
      issuer: "http://ob.test",
      audience: "attenuo",
    });
    expect(tok.verified).toBe(true);
    expect(tok.agents).toEqual(["assistant", "coder"]);
  });

  it("rejects a flipped signature", async () => {
    const [h, p, s] = (await signer.mint()).split(".") as [string, string, string];
    const bad = `${h}.${p}.${(s[0] === "A" ? "B" : "A") + s.slice(1)}`;
    await expect(verifyToken(bad, signer.jwks)).rejects.toThrow(VerificationError);
  });

  it("rejects a tampered payload", async () => {
    const [h, , s] = (await signer.mint()).split(".") as [string, string, string];
    const other = (await signer.mint({ subject: "mallory" })).split(".")[1]!;
    await expect(verifyToken(`${h}.${other}.${s}`, signer.jwks)).rejects.toThrow(/signature/);
  });

  it("rejects another key, a wrong kid and an empty JWKS", async () => {
    const jwt = await signer.mint();
    const other = await Signer.create();
    await expect(verifyToken(jwt, other.jwks)).rejects.toThrow(/signature/);
    const wrongKid = { keys: [{ ...signer.jwks.keys[0]!, kid: "other" }] };
    await expect(verifyToken(jwt, wrongKid)).rejects.toThrow(/kid/);
    await expect(verifyToken(jwt, { keys: [] })).rejects.toThrow(/no Ed25519 key/);
  });

  it("rejects a short key", async () => {
    const jwks = { keys: [{ ...signer.jwks.keys[0]!, x: b64("short") }] };
    await expect(verifyToken(await signer.mint(), jwks)).rejects.toThrow(/32/);
  });

  it("rejects wrong alg, typ, expiry, issuer and audience", async () => {
    await expect(
      verifyToken(await signer.mint({ header: { alg: "HS256" } }), signer.jwks),
    ).rejects.toThrow(/alg/);
    await expect(
      verifyToken(await signer.mint({ claims: { typ: "JWT" } }), signer.jwks),
    ).rejects.toThrow(/type/);
    await expect(verifyToken(await signer.mint({ expDelta: -5 }), signer.jwks)).rejects.toThrow(
      /expired/,
    );
    const jwt = await signer.mint();
    await expect(verifyToken(jwt, signer.jwks, { issuer: "http://evil" })).rejects.toThrow(/iss/);
    await expect(verifyToken(jwt, signer.jwks, { audience: "other" })).rejects.toThrow(/aud/);
  });

  it("rejects sub or act that disagree with the chain", async () => {
    await expect(
      verifyToken(await signer.mint({ claims: { sub: "bob" } }), signer.jwks),
    ).rejects.toThrow(/sub/);
    await expect(
      verifyToken(await signer.mint({ claims: { act: { sub: "intruder" } } }), signer.jwks),
    ).rejects.toThrow(/act/);
  });

  it("uses an injected clock", async () => {
    const jwt = await signer.mint();
    const far = Date.now() / 1000 + 10_000;
    await expect(verifyToken(jwt, signer.jwks, { now: far })).rejects.toThrow(/expired/);
  });
});

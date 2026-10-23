/** Build delegation tokens by hand and mock `fetch` for unit tests. */

import type { FetchLike } from "../src/index.js";

export function b64(data: Uint8Array | string): string {
  return Buffer.from(data).toString("base64url");
}

function iso(sec: number): string {
  return new Date(sec * 1000).toISOString().replace(/\.\d+Z$/, ".123456789Z");
}

export function hop(agent: string, caps: unknown[], lease: string, ttl = 900) {
  const now = Math.floor(Date.now() / 1000);
  return {
    agent,
    capabilities: caps,
    issued_at: iso(now),
    expires_at: iso(now + ttl),
    lease,
  };
}

export interface MintOptions {
  agents?: string[];
  subject?: string;
  caps?: unknown[];
  expDelta?: number;
  claims?: Record<string, unknown>;
  header?: Record<string, unknown>;
}

export class Signer {
  private constructor(
    private readonly key: CryptoKey,
    readonly jwks: { keys: Array<Record<string, string>> },
  ) {}

  static async create(): Promise<Signer> {
    const pair = (await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return new Signer(pair.privateKey, {
      keys: [{ kty: "OKP", crv: "Ed25519", kid: "k1", x: b64(raw) }],
    });
  }

  async mint(o: MintOptions = {}): Promise<string> {
    const agents = o.agents ?? ["planner"];
    const subject = o.subject ?? "alice";
    const caps = o.caps ?? [{ server: "github", tool: "*" }];
    const now = Math.floor(Date.now() / 1000);
    let act: Record<string, unknown> | undefined;
    for (const a of agents) act = act ? { sub: a, act } : { sub: a };
    const payload = {
      iss: "http://ob.test",
      aud: "onbehalf",
      sub: subject,
      act,
      jti: "jti-1",
      iat: now,
      exp: now + (o.expDelta ?? 900),
      typ: "onbehalf+jwt",
      ou_sig: "sig",
      chain: {
        originating_user: {
          subject,
          issuer: "https://idp.example",
          authenticated_at: "2026-10-23T09:00:00.5Z",
        },
        hops: agents.map((a, i) => hop(a, caps, `lease-${i}`)),
      },
      ...o.claims,
    };
    const head = { alg: "EdDSA", typ: "JWT", kid: "k1", ...o.header };
    const signing = `${b64(JSON.stringify(head))}.${b64(JSON.stringify(payload))}`;
    const sig = new Uint8Array(
      await crypto.subtle.sign("Ed25519", this.key, new TextEncoder().encode(signing)),
    );
    return `${signing}.${b64(sig)}`;
  }
}

export function tokenResponse(jwt: string, lease = "lease-0", expiresIn = 900) {
  return {
    access_token: jwt,
    issued_token_type: "urn:ietf:params:oauth:token-type:jwt",
    token_type: "Bearer",
    expires_in: expiresIn,
    lease,
  };
}

export interface Seen {
  url: URL;
  method: string;
  headers: Headers;
  body: unknown;
}

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/** A fetch mock: records every request and answers with `handler(seen)`. */
export function mockFetch(handler: (seen: Seen) => Response | Promise<Response>) {
  const calls: Seen[] = [];
  const fetch: FetchLike = async (input, init) => {
    const headers = new Headers(init?.headers);
    const raw = init?.body;
    const seen: Seen = {
      url: new URL(input),
      method: init?.method ?? "GET",
      headers,
      body: typeof raw === "string" ? JSON.parse(raw) : undefined,
    };
    calls.push(seen);
    return handler(seen);
  };
  return { fetch, calls };
}

export function rpcOk(result: unknown, headers: Record<string, string> = {}) {
  return jsonResponse({ jsonrpc: "2.0", id: 1, result }, 200, headers);
}

export function rpcErr(
  code: number,
  message: string,
  data?: unknown,
  status = 200,
  headers: Record<string, string> = {},
) {
  return jsonResponse({ jsonrpc: "2.0", id: 1, error: { code, message, data } }, status, headers);
}

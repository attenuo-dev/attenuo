/**
 * `tlsCaCert`, `tlsClientCert` and `tlsClientKey` over real TLS on 127.0.0.1. Certificates are
 * made at test time with `openssl`; every server listens on a port the kernel picks.
 */

import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, truncateSync, writeFileSync } from "node:fs";
import { inspect } from "node:util";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AdminClient,
  ApiError,
  AttenuoClient,
  TransportError,
  TransportTimeoutError,
  capability,
  mcpFetch,
  tlsFetch,
} from "../src/index.js";
import { MAX_CA_BYTES, origin } from "../src/tls.js";
import { exchangeBody, TYPE_ID_TOKEN, TYPE_JWT } from "../src/wire.js";
import { Signer } from "./helpers.js";
import { Ca, ClientCert, TlsServer, tempDir } from "./tlsutil.js";

let dir = "";
let remove = () => {};
let ca: Ca;
let otherCa: Ca;
let client: ClientCert;
let other: ClientCert;
let caFile = "";
let parent = "";
const servers: TlsServer[] = [];

async function server(by: Ca, names = ["IP:127.0.0.1"]): Promise<TlsServer> {
  const leaf = by.leaf(names, `srv${servers.length}`);
  const s = await TlsServer.start(leaf.cert, leaf.key);
  servers.push(s);
  return s;
}

function write(name: string, data: string): string {
  const p = join(dir, name);
  writeFileSync(p, data);
  return p;
}

function noKeyBytes(text: string, cc: ClientCert = client): void {
  for (const chunk of cc.keyChunks()) expect(text).not.toContain(chunk);
}

function thrown(f: () => unknown): Error {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error("did not throw");
}

beforeAll(async () => {
  ({ dir, remove } = tempDir());
  ca = new Ca(dir, "ca");
  otherCa = new Ca(dir, "other-ca");
  client = new ClientCert(dir, "planner");
  other = new ClientCert(dir, "other");
  caFile = ca.certPath;
  parent = await (await Signer.create()).mint();
});

afterAll(async () => {
  await Promise.all(servers.map((s) => s.close()));
  remove();
});

const withCert = () => ({
  tlsCaCert: caFile,
  tlsClientCert: client.certPath,
  tlsClientKey: client.keyPath,
});

describe("trust", () => {
  it("trusts the given CA and nothing else", async () => {
    const good = await server(ca);
    const bad = await server(otherCa);
    const ok = new AttenuoClient(good.url, { tlsCaCert: caFile });
    good.answer = { status: 200, body: { keys: [] } };
    expect(await ok.jwks()).toEqual({ keys: [] });
    const refused = new AttenuoClient(bad.url, { tlsCaCert: caFile });
    const e = await refused.jwks().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(TransportError);
    expect(bad.seen).toEqual([]);
  });

  it("does not trust NODE_EXTRA_CA_CERTS or the built-in roots next to the CA", async (ctx) => {
    // NODE_EXTRA_CA_CERTS is read at start, so a child process runs the built package.
    const dist = fileURLToPath(new URL("../dist/index.js", import.meta.url));
    if (!existsSync(dist)) ctx.skip();
    const s = await server(ca);
    s.answer = { status: 200, body: { keys: [] } };
    const script = `
      const { AttenuoClient } = await import(${JSON.stringify(pathToFileURL(dist).href)});
      const url = process.argv[1], other = process.argv[2];
      const plain = await fetch(url + "/x").then((r) => r.status, (e) => "refused");
      const opt = await new AttenuoClient(url, { tlsCaCert: other }).jwks().then(() => "ok", (e) => e.name);
      console.log(JSON.stringify([plain, opt]));`;
    const out = await new Promise<string>((ok, fail) => {
      execFile(
        process.execPath,
        ["--input-type=module", "-e", script, s.url, otherCa.certPath],
        { env: { ...process.env, NODE_EXTRA_CA_CERTS: ca.certPath } },
        (e, stdout) => (e ? fail(e) : ok(stdout)),
      );
    });
    // Node trusts the test CA from NODE_EXTRA_CA_CERTS; the client with tlsCaCert does not.
    expect(JSON.parse(out)).toEqual([200, "TransportError"]);
  });

  it("refuses a hostname mismatch", async () => {
    const s = await server(ca, ["DNS:other.test"]);
    const e = await new AttenuoClient(s.url, { tlsCaCert: caFile }).jwks().catch((x: unknown) => x);
    expect(e).toBeInstanceOf(TransportError);
    expect(String((e as Error).message)).toMatch(/altnames|hostname|IP: 127\.0\.0\.1/i);
    expect(s.seen).toEqual([]);
  });

  it("sets up the admin client with the CA", async () => {
    const s = await server(ca);
    s.answer = { status: 200, body: { subject: "urn:attenuo:admin", kind: "token" } };
    const admin = new AdminClient(s.url, "t", { tlsCaCert: caFile });
    await admin.whoami();
    expect(s.seen[0]!.path).toBe("/admin/whoami");
    // The admin client presents no certificate.
    expect(s.seen[0]!.peerCert).toBeUndefined();
    const refused = new AdminClient(s.url, "t", { tlsCaCert: otherCa.certPath });
    await expect(refused.whoami()).rejects.toBeInstanceOf(TransportError);
  });
});

describe("the client certificate", () => {
  it("goes to the server's origin only", async () => {
    const main = await server(ca);
    const elsewhere = await server(ca);
    main.answer = elsewhere.answer = { status: 200, body: { keys: [] } };
    const c = new AttenuoClient(main.url, withCert());
    await c.jwks();
    // A JWKS URL on another origin (another port), with a path like the server's own.
    await c.jwks(`${elsewhere.url}/.well-known/jwks.json`);
    await c.jwks(`${elsewhere.url}/token`);
    // The same origin spelled with its port and a path goes with the certificate.
    await c.jwks(`${main.url}/other/path`);
    expect(main.seen.map((s) => s.peerCert)).toEqual([client.der, client.der]);
    expect(elsewhere.seen.map((s) => s.peerCert)).toEqual([undefined, undefined]);
  });

  it("is kept to the server's origin by tlsFetch and mcpFetch too", async () => {
    const main = await server(ca);
    const elsewhere = await server(ca);
    const f = mcpFetch(() => parent, { fetch: tlsFetch(main.url, withCert()) });
    await (await f(`${main.url}/mcp/github`, { method: "POST", body: "{}" })).text();
    await (await f(`${elsewhere.url}/mcp/github`, { method: "POST", body: "{}" })).text();
    expect(main.seen[0]!.peerCert).toEqual(client.der);
    expect(elsewhere.seen[0]!.peerCert).toBeUndefined();
    // The other origin still trusts only the CA.
    const stranger = await server(otherCa);
    await expect(f(`${stranger.url}/mcp/github`)).rejects.toThrow();
  });

  it("is not carried by a redirect", async () => {
    const main = await server(ca);
    const elsewhere = await server(ca);
    main.answer = { status: 307, body: {}, headers: { location: `${elsewhere.url}/token` } };
    const c = new AttenuoClient(main.url, withCert());
    const e = await c
      .exchange(parent, "planner", [capability("github", "read_file")])
      .catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).error).toBe("redirect_not_followed");
    expect(elsewhere.seen).toEqual([]);
  });

  it("times out as the client's own fetch does", async () => {
    const s = await server(ca);
    s.hang = true;
    const c = new AttenuoClient(s.url, { ...withCert(), timeoutMs: 100 });
    await expect(c.jwks()).rejects.toBeInstanceOf(TransportTimeoutError);
  });

  it("compares origins by scheme, host and port", () => {
    expect(origin("https://A.test/x")).toBe(origin("https://a.test:443/y"));
    expect(origin("https://a.test")).not.toBe(origin("https://a.test:8443"));
    expect(origin("https://a.test")).not.toBe(origin("http://a.test"));
    expect(origin("https://a.test")).not.toBe(origin("https://b.test"));
  });
});

describe("token exchange with the certificate", () => {
  it("sends client_id and no secret when the certificate is the credential", async () => {
    const s = await server(ca);
    s.answer = { status: 401, body: { error: "client_authentication_failed" } };
    const c = new AttenuoClient(s.url, withCert());
    const caps = [capability("github", "read_file")];
    const calls = [
      c.exchange(parent, "planner", caps),
      c.exchange(parent, "planner", caps, { clientId: "planner-2" }),
      c.exchange(parent, "planner", caps, { clientSecret: "s3" }),
      c.exchange(parent, "planner", caps, { actorToken: "a.b.c" }),
    ];
    for (const call of calls) await expect(call).rejects.toBeInstanceOf(ApiError);
    const bodies = s.seen.map((x) => JSON.parse(x.body) as Record<string, unknown>);
    const byPath = new Map(bodies.map((b) => [JSON.stringify(b), b]));
    expect(byPath.size).toBe(4);
    expect(s.seen.every((x) => x.peerCert?.equals(client.der))).toBe(true);
    const find = (f: (b: Record<string, unknown>) => boolean) => bodies.filter(f);
    expect(find((b) => b.client_id === "planner" && b.client_secret === undefined)).toHaveLength(1);
    expect(find((b) => b.client_id === "planner-2" && b.client_secret === undefined)).toHaveLength(
      1,
    );
    expect(find((b) => b.client_secret === "s3" && b.client_id === "planner")).toHaveLength(1);
    expect(find((b) => b.actor_token === "a.b.c" && b.client_id === undefined)).toHaveLength(1);
  });

  it("builds the body as before without a certificate", () => {
    const caps = [capability("github", "read_file")];
    let b = exchangeBody(parent, "planner", caps, {}, true);
    expect([b.client_id, b.client_secret, b.subject_token_type]).toEqual([
      "planner",
      undefined,
      TYPE_JWT,
    ]);
    // Hop 0: the certificate authenticates, so the subject is an ID token as with a secret.
    b = exchangeBody("not-a-jwt", "planner", caps, {}, true);
    expect(b.subject_token_type).toBe(TYPE_ID_TOKEN);
    b = exchangeBody(parent, "planner", caps, {});
    expect(b.client_id).toBeUndefined();
    expect(() => exchangeBody(parent, "planner", caps, { clientId: "planner" })).toThrow(
      /clientId goes with/,
    );
    expect(() =>
      exchangeBody(parent, "planner", caps, { clientId: "x", actorToken: "a.b.c" }, true),
    ).toThrow(/clientId goes with/);
  });
});

describe("refusals when the client is made", () => {
  const url = "https://a.test";

  it("needs the certificate and the key together", () => {
    expect(() => new AttenuoClient(url, { tlsClientCert: "/nonexistent/c.pem" })).toThrow(
      /^tlsClientCert needs tlsClientKey/,
    );
    expect(() => new AttenuoClient(url, { tlsClientKey: "/nonexistent/k.pem" })).toThrow(
      /^tlsClientKey needs tlsClientCert/,
    );
  });

  it("needs https:// for a client certificate", () => {
    for (const http of ["http://a.test", "http://127.0.0.1:8080"]) {
      expect(() => new AttenuoClient(http, withCert())).toThrow(/need an https:\/\/ server URL/);
    }
  });

  it("takes a CA with an http:// server without a word", () => {
    expect(() => new AttenuoClient("http://a.test", { tlsCaCert: caFile })).not.toThrow();
  });

  it("refuses fetch next to the options", () => {
    const fetch = () => Promise.resolve(new Response(null));
    expect(() => new AttenuoClient(url, { fetch, tlsCaCert: caFile })).toThrow(
      /either fetch or the tls/,
    );
    expect(() => new AdminClient(url, "t", { fetch, tlsCaCert: caFile })).toThrow(
      /either fetch or the tls/,
    );
  });

  it("refuses a private key in the CA or the certificate file", () => {
    const both = write("both.pem", client.pem + client.keyPem);
    for (const f of [both, client.keyPath]) {
      const e = thrown(() => new AttenuoClient(url, { tlsCaCert: f }));
      expect(e.message).toMatch(/holds a private key/);
      noKeyBytes(e.message);
    }
    expect(
      () => new AttenuoClient(url, { tlsClientCert: both, tlsClientKey: client.keyPath }),
    ).toThrow(/holds a private key/);
    for (const label of ["ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "DSA PRIVATE KEY"]) {
      const odd = write(
        "odd.pem",
        `${ca.pem}-----BEGIN ${label}-----\nU0VDUkVU\n-----END ${label}-----\n`,
      );
      expect(() => new AttenuoClient(url, { tlsCaCert: odd })).toThrow(/holds a private key/);
    }
  });

  it("needs one unencrypted key that is the certificate's", () => {
    const cert = client.certPath;
    const two = write("two.pem", client.keyPem + other.keyPem);
    const both = write("both2.pem", client.pem + client.keyPem);
    for (const bad of [two, both, cert]) {
      expect(() => new AttenuoClient(url, { tlsClientCert: cert, tlsClientKey: bad })).toThrow(
        /exactly one unencrypted private key/,
      );
    }
    const enc = join(dir, "enc.pem");
    execFileSync("openssl", [
      "pkey",
      "-in",
      client.keyPath,
      "-aes256",
      "-passout",
      "pass:pw",
      "-out",
      enc,
    ]);
    const legacy = write(
      "legacy.pem",
      "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nU0VDUkVU\n-----END EC PRIVATE KEY-----\n",
    );
    for (const f of [enc, legacy]) {
      expect(() => new AttenuoClient(url, { tlsClientCert: cert, tlsClientKey: f })).toThrow(
        /is an encrypted private key/,
      );
    }
    const ossh = write(
      "ossh.pem",
      "-----BEGIN OPENSSH PRIVATE KEY-----\nU0VDUkVU\n-----END OPENSSH PRIVATE KEY-----\n",
    );
    const e = thrown(() => new AttenuoClient(url, { tlsClientCert: cert, tlsClientKey: ossh }));
    expect(e.message).toMatch(/kind of private key/);
    expect(e.message).not.toContain("U0VDUkVU");
    const mismatch = thrown(
      () => new AttenuoClient(url, { tlsClientCert: cert, tlsClientKey: other.keyPath }),
    );
    expect(mismatch.message).toMatch(/is not the private key of the certificate/);
    expect(mismatch.cause).toBeUndefined();
    noKeyBytes(mismatch.message, other);
  });

  it("names the option and the path, never the content", () => {
    const missing = join(dir, "missing.pem");
    const empty = write("empty.pem", " \n\n");
    const broken = write(
      "broken.pem",
      "-----BEGIN CERTIFICATE-----\nS3CR3T!!!***\n-----END CERTIFICATE-----\n",
    );
    const text = write("text.pem", "hello SECRETSECRET\n");
    expect(() => new AttenuoClient(url, { tlsCaCert: missing })).toThrow(
      /^cannot read tlsCaCert .*missing\.pem: ENOENT$/,
    );
    expect(() => new AttenuoClient(url, { tlsCaCert: empty })).toThrow(/^tlsCaCert .* is empty$/);
    expect(() => new AttenuoClient(url, { tlsCaCert: "" })).toThrow(/tlsCaCert is an empty path/);
    expect(
      () => new AttenuoClient(url, { tlsClientCert: client.certPath, tlsClientKey: missing }),
    ).toThrow(/^cannot read tlsClientKey /);
    for (const bad of [broken, text]) {
      for (const opts of [
        { tlsCaCert: bad },
        { tlsClientCert: bad, tlsClientKey: client.keyPath },
        { tlsClientCert: client.certPath, tlsClientKey: bad },
      ]) {
        const e = thrown(() => new AttenuoClient(url, opts));
        expect(e.message).toMatch(/^(cannot read )?tls(CaCert|ClientCert|ClientKey) /);
        expect(e.message).not.toMatch(/S3CR3T|SECRET/);
      }
    }
  });

  it("refuses a large file", () => {
    const big = write("big.pem", "");
    truncateSync(big, MAX_CA_BYTES + 1);
    expect(() => new AttenuoClient(url, { tlsCaCert: big })).toThrow(/is larger than/);
  });

  it.skipIf(process.platform === "win32")("refuses a FIFO or a directory without blocking", () => {
    const fifo = join(dir, "fifo.pem");
    execFileSync("mkfifo", [fifo]);
    // Nothing ever writes to the FIFO: a blocking open would hang the test.
    expect(() => new AttenuoClient(url, { tlsCaCert: fifo })).toThrow(/is not a regular file/);
    expect(
      () => new AttenuoClient(url, { tlsClientCert: client.certPath, tlsClientKey: fifo }),
    ).toThrow(/^tlsClientKey .* is not a regular file/);
    expect(() => new AttenuoClient(url, { tlsClientCert: fifo, tlsClientKey: fifo })).toThrow(
      /^tlsClientCert .* is not a regular file/,
    );
    const sub = join(dir, "sub");
    mkdirSync(sub);
    expect(() => new AdminClient(url, "t", { tlsCaCert: sub })).toThrow(
      /is not a regular file|cannot read/,
    );
  });

  it("shows no key bytes when the client is printed", () => {
    const c = new AttenuoClient(url, withCert());
    for (const text of [inspect(c, { depth: 20, showHidden: true }), JSON.stringify(c)]) {
      noKeyBytes(text);
    }
  });
});

describe("answers and requests tlsFetch must not mishandle", () => {
  const raws = [
    ["a status of 600", "HTTP/1.1 600 Weird\r\ncontent-length: 0\r\n\r\n"],
    ["a reason phrase with a control byte", "HTTP/1.1 200 O\x01K\r\ncontent-length: 0\r\n\r\n"],
    [
      "a 101 Switching Protocols",
      "HTTP/1.1 101 Switching Protocols\r\nupgrade: x\r\nconnection: upgrade\r\n\r\n",
    ],
    [
      "a body in an encoding that was not asked for",
      "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 4\r\n\r\nxxxx",
    ],
  ] as const;

  for (const [what, raw] of raws) {
    it(`rejects ${what} (tlsFetch and AttenuoClient), and the process lives on`, async () => {
      const s = await server(ca);
      s.raw = raw;
      const f = tlsFetch(s.url, { tlsCaCert: caFile });
      const e = await f(`${s.url}/x`).catch((x: unknown) => x);
      expect(e).toBeInstanceOf(TypeError);
      expect((e as Error).message).toBe("fetch failed");
      const c = new AttenuoClient(s.url, withCert());
      await expect(c.jwks()).rejects.toBeInstanceOf(TransportError);
    });
  }

  it("stops reading the request body when aborted", async () => {
    const s = await server(ca);
    const f = tlsFetch(s.url, { tlsCaCert: caFile });
    const ctl = new AbortController();
    const body = new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}) });
    const p = f(`${s.url}/x`, {
      method: "POST",
      body,
      signal: ctl.signal,
      duplex: "half",
    } as RequestInit);
    ctl.abort(new Error("stop"));
    await expect(p).rejects.toThrow("stop");
    // Aborted before the call: nothing is sent.
    await expect(f(`${s.url}/x`, { signal: AbortSignal.abort() })).rejects.toThrow();
    expect(s.seen).toEqual([]);
  });

  it("refuses credentials in the URL and a Request", async () => {
    const s = await server(ca);
    const f = tlsFetch(s.url, { tlsCaCert: caFile });
    const withUser = s.url.replace("https://", "https://user:pw@");
    await expect(f(`${withUser}/x`)).rejects.toThrow(/credentials/);
    const req = new Request(`${s.url}/x`) as unknown as string;
    await expect(f(req)).rejects.toThrow(/not a Request/);
    expect(s.seen).toEqual([]);
  });

  it("asks for identity only and drops headers fetch forbids", async () => {
    const s = await server(ca);
    const f = tlsFetch(s.url, { tlsCaCert: caFile });
    const headers = { "accept-encoding": "gzip, br", host: "evil.test", "x-ok": "1" };
    await (await f(`${s.url}/x`, { headers })).text();
    const h = s.seen[0]!.headers;
    expect(h["accept-encoding"]).toBe("identity");
    expect(h.host).toBe(new URL(s.url).host);
    expect(h["x-ok"]).toBe("1");
  });

  it("refuses a CA or certificate file whose BEGIN line ends in other white space", () => {
    for (const ws of ["\f", "\v"]) {
      const body = client.keyPem.replace(
        "-----BEGIN PRIVATE KEY-----",
        `-----BEGIN PRIVATE KEY-----${ws}`,
      );
      const hidden = write("hidden.pem", client.pem + body);
      expect(() => new AttenuoClient("https://a.test", { tlsCaCert: hidden })).toThrow(
        /holds a private key/,
      );
      expect(
        () =>
          new AttenuoClient("https://a.test", {
            tlsClientCert: hidden,
            tlsClientKey: client.keyPath,
          }),
      ).toThrow(/holds a private key/);
    }
    // A BEGIN line the parser does not read is refused, not skipped.
    const odd = write(
      "odd-begin.pem",
      ca.pem + "-----BEGIN CERTIFICATE-----junk\nAAAA\n-----END CERTIFICATE-----\n",
    );
    expect(() => new AttenuoClient("https://a.test", { tlsCaCert: odd })).toThrow(
      /is not a readable PEM file/,
    );
  });

  it("refuses a key of another type than the certificate", () => {
    for (const alg of [
      ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
      ["genpkey", "-algorithm", "ED25519"],
    ]) {
      const out = join(dir, `${alg[2]}.key`);
      execFileSync("openssl", [...alg, "-out", out]);
      const e = thrown(
        () =>
          new AttenuoClient("https://a.test", {
            tlsClientCert: client.certPath,
            tlsClientKey: out,
          }),
      );
      expect(e.message).toMatch(/is not the private key of the certificate/);
      expect(e.cause).toBeUndefined();
    }
  });

  it("refuses tlsClientCert on the admin client", () => {
    const opts = { tlsClientCert: client.certPath, tlsClientKey: client.keyPath } as object;
    expect(() => new AdminClient("https://a.test", "t", opts)).toThrow(/takes no tlsClientCert/);
  });
});

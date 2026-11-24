/**
 * Certificates made at test time with the `openssl` command, and local HTTPS servers that record
 * the client certificate they were shown. Nothing here reaches beyond 127.0.0.1.
 */

import { execFileSync } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { TLSSocket } from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";

function openssl(args: string[], cwd: string): void {
  execFileSync("openssl", args, { cwd, stdio: ["ignore", "ignore", "pipe"] });
}

/** A temporary directory, removed by the returned function. */
export function tempDir(): { dir: string; remove: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "attenuo-tls-"));
  return { dir, remove: () => rmSync(dir, { recursive: true, force: true }) };
}

const EC = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];

/** A CA in `dir`: `<name>.pem` and `<name>.key`. */
export class Ca {
  readonly pem: string;
  readonly certPath: string;
  readonly keyPath: string;

  constructor(
    readonly dir: string,
    readonly name: string,
  ) {
    this.certPath = join(dir, `${name}.pem`);
    this.keyPath = join(dir, `${name}.key`);
    openssl(
      [
        "req",
        "-x509",
        ...EC,
        "-keyout",
        this.keyPath,
        "-out",
        this.certPath,
        "-days",
        "30",
        "-subj",
        `/CN=${name}`,
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
      ],
      dir,
    );
    this.pem = readFileSync(this.certPath, "utf8");
  }

  /** A server certificate for `names` (`IP:127.0.0.1`, `DNS:other.test`) signed by this CA. */
  leaf(
    names: string[],
    name: string,
  ): { cert: string; key: string; certPath: string; keyPath: string } {
    const keyPath = join(this.dir, `${name}.key`);
    const csr = join(this.dir, `${name}.csr`);
    const certPath = join(this.dir, `${name}.crt`);
    const ext = join(this.dir, `${name}.ext`);
    writeFileSync(
      ext,
      `basicConstraints=critical,CA:FALSE\nsubjectAltName=${names.join(",")}\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n`,
    );
    openssl(
      ["req", "-new", ...EC, "-keyout", keyPath, "-out", csr, "-subj", `/CN=${name}`],
      this.dir,
    );
    openssl(
      [
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        this.certPath,
        "-CAkey",
        this.keyPath,
        "-CAcreateserial",
        "-out",
        certPath,
        "-days",
        "30",
        "-extfile",
        ext,
      ],
      this.dir,
    );
    chmodSync(keyPath, 0o600);
    return {
      cert: readFileSync(certPath, "utf8"),
      key: readFileSync(keyPath, "utf8"),
      certPath,
      keyPath,
    };
  }
}

/** A self-signed client certificate (`CA:FALSE`, `clientAuth`), as attenuo pins them. */
export class ClientCert {
  readonly certPath: string;
  readonly keyPath: string;
  readonly pem: string;
  readonly keyPem: string;
  readonly der: Buffer;
  /** What `tls_client_cert_sha256` pins: lower-case hex SHA-256 of the DER. */
  readonly sha256: string;

  constructor(dir: string, name: string) {
    this.certPath = join(dir, `${name}.crt`);
    this.keyPath = join(dir, `${name}.key`);
    openssl(
      [
        "req",
        "-x509",
        ...EC,
        "-keyout",
        this.keyPath,
        "-out",
        this.certPath,
        "-days",
        "30",
        "-subj",
        `/CN=${name}`,
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "extendedKeyUsage=clientAuth",
      ],
      dir,
    );
    chmodSync(this.keyPath, 0o600);
    this.pem = readFileSync(this.certPath, "utf8");
    this.keyPem = readFileSync(this.keyPath, "utf8");
    this.der = new X509Certificate(this.pem).raw;
    this.sha256 = createHash("sha256").update(this.der).digest("hex");
  }

  /** 12-character pieces of the key's base64 body, none of which may show up in output. */
  keyChunks(): string[] {
    const body = this.keyPem
      .split("\n")
      .filter((l) => !l.startsWith("-----"))
      .join("");
    const out: string[] = [];
    for (let i = 0; i + 12 <= body.length; i += 12) out.push(body.slice(i, i + 12));
    return out;
  }
}

export interface Seen {
  path: string;
  /** The DER of the client certificate the handshake carried, or undefined. */
  peerCert: Buffer | undefined;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

/**
 * An HTTPS server on 127.0.0.1, on a port the kernel picks (kept bound), that asks every client
 * for a certificate and accepts any, recording what it saw.
 */
export class TlsServer {
  readonly seen: Seen[] = [];
  answer: { status: number; body: unknown; headers?: Record<string, string> } = {
    status: 200,
    body: { ok: true },
  };
  /** Answer nothing (for a client timeout). */
  hang = false;
  /** Write these bytes as the whole answer instead. */
  raw: string | undefined;
  private constructor(private readonly server: Server) {}

  static async start(cert: string, key: string): Promise<TlsServer> {
    const server = createServer({ cert, key, requestCert: true, rejectUnauthorized: false });
    const s = new TlsServer(server);
    server.on("request", (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const peer = (req.socket as TLSSocket).getPeerCertificate(false);
        s.seen.push({
          path: req.url ?? "",
          peerCert: peer && "raw" in peer && peer.raw ? peer.raw : undefined,
          body: Buffer.concat(chunks).toString("utf8"),
          headers: req.headers,
        });
        if (s.raw !== undefined) {
          // Bytes no well-behaved server sends (a status of 600, a 101), written as they are.
          req.socket.end(s.raw);
          return;
        }
        if (s.hang) return;
        res.writeHead(s.answer.status, {
          "content-type": "application/json",
          ...s.answer.headers,
        });
        res.end(JSON.stringify(s.answer.body));
      });
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    return s;
  }

  get url(): string {
    const { port } = this.server.address() as { port: number };
    return `https://127.0.0.1:${port}`;
  }

  close(): Promise<void> {
    this.server.closeAllConnections();
    return new Promise((ok) => this.server.close(() => ok()));
  }
}

/**
 * `tlsCaCert`, `tlsClientCert` and `tlsClientKey`: the CA a client trusts for the attenuo
 * server's certificate, and the TLS client certificate it presents to the server (RFC 8705
 * `self_signed_tls_client_auth`). The rules are those of the `attenuo` CLI's `--tls-*` options:
 *
 * - With `tlsCaCert`, the certificates in that file are the only roots trusted: Node's built-in
 *   roots (and `NODE_EXTRA_CA_CERTS`) are not trusted next to them. Certificate and hostname
 *   checks stay on (`rejectUnauthorized: true` is set, whatever `NODE_TLS_REJECT_UNAUTHORIZED`
 *   says); nothing here can turn them off.
 * - `tlsClientCert` and `tlsClientKey` go together and need an `https://` server URL. The
 *   certificate is presented on connections to the origin (scheme, host and port) of the server
 *   URL only: `tlsFetch` picks the connection pool by the request's origin, in one place
 *   (`agentFor`), and every other origin gets a pool with the CA and no certificate. Redirects are
 *   never followed (`node:https` does not follow them), so the certificate is not carried to a
 *   `Location` either.
 * - Each file is read once, when the client is made. Anything but a regular file (a FIFO, a
 *   directory) is refused before it is read, and so is a file over the size limit. An error names
 *   the option and the path, never the file's content. A CA or certificate file that holds a
 *   private key is refused.
 *
 * Global `fetch` cannot take a CA or a client certificate, so with these options requests go
 * through `node:https`, loaded with `process.getBuiltinModule` (Node 20.16 or later) only when an
 * option is given: the SDK imports no Node module at its top level and still loads elsewhere.
 * `node:https` does not use `HTTP_PROXY` or `HTTPS_PROXY`: with these options the client always
 * connects directly.
 */

import type * as FsModule from "node:fs";
import type * as HttpsModule from "node:https";
import type * as CryptoModule from "node:crypto";
import type * as TlsModule from "node:tls";
import type * as NetModule from "node:net";
import type { IncomingMessage } from "node:http";
import type { FetchLike } from "./http.js";

/** The largest CA bundle read (a system bundle is a few hundred KiB). */
export const MAX_CA_BYTES = 4 << 20;
/** The largest client certificate or key file read. */
export const MAX_CLIENT_BYTES = 1 << 20;

/** The TLS options of `AttenuoClient` and `tlsFetch`. */
export interface TlsOptions {
  /**
   * A PEM file with the CA certificates to trust for the server's TLS certificate. They are the
   * only roots trusted: Node's built-in roots are not used next to them.
   */
  tlsCaCert?: string;
  /**
   * A PEM file with a TLS client certificate to present to the server (and only to its origin).
   * Needs `tlsClientKey` and an `https://` server URL.
   */
  tlsClientCert?: string;
  /** The certificate's private key: an unencrypted PEM file with that one key. */
  tlsClientKey?: string;
}

const CA = "tlsCaCert";
const CERT = "tlsClientCert";
const KEY = "tlsClientKey";

// Any white space but a newline around the BEGIN line: OpenSSL accepts `\f` and `\v` there too.
const BEGIN = /^[^\S\n]*-----BEGIN ([^\r\n]*?)-----[^\S\n]*$/gm;
const SUPPORTED_KEYS = ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"];

interface Node {
  fs: typeof FsModule;
  https: typeof HttpsModule;
  crypto: typeof CryptoModule;
  tls: typeof TlsModule;
  net: typeof NetModule;
}

/** The Node modules these options need, or an error where there are none. */
function node(): Node {
  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  const get = proc?.getBuiltinModule;
  if (typeof get !== "function") {
    throw new TypeError(
      "the tlsCaCert, tlsClientCert and tlsClientKey options need Node.js 20.16 or later",
    );
  }
  const load = <T>(id: string): T => get.call(proc, id) as T;
  return {
    fs: load<typeof FsModule>("node:fs"),
    https: load<typeof HttpsModule>("node:https"),
    crypto: load<typeof CryptoModule>("node:crypto"),
    tls: load<typeof TlsModule>("node:tls"),
    net: load<typeof NetModule>("node:net"),
  };
}

function checkPath(option: string, value: unknown): string {
  if (typeof value !== "string") throw new TypeError(`${option} must be a path (a string)`);
  if (value === "") throw new TypeError(`${option} is an empty path`);
  return value;
}

/** The error code of a failed `fs` call (`ENOENT`, ...), never its message. */
function why(e: unknown): string {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "an error";
}

/**
 * At most `max` bytes of `path`. Opened without blocking (`O_NONBLOCK`, which a regular file
 * ignores); anything but a regular file is refused, as checked on the open handle.
 */
function readFile(n: Node, option: string, path: string, max: number): Buffer {
  const { fs } = n;
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = fs.openSync(path, flags);
  } catch (e) {
    throw new TypeError(`cannot read ${option} ${path}: ${why(e)}`);
  }
  let buf: Buffer;
  let len = 0;
  try {
    let st: FsModule.Stats;
    try {
      st = fs.fstatSync(fd);
    } catch (e) {
      throw new TypeError(`cannot read ${option} ${path}: ${why(e)}`);
    }
    if (!st.isFile()) throw new TypeError(`${option} ${path} is not a regular file`);
    if (st.size > max) throw new TypeError(`${option} ${path} is larger than ${max} bytes`);
    buf = Buffer.alloc(max + 1);
    for (;;) {
      let got: number;
      try {
        got = fs.readSync(fd, buf, len, buf.length - len, null);
      } catch (e) {
        buf.fill(0);
        throw new TypeError(`cannot read ${option} ${path}: ${why(e)}`);
      }
      if (got === 0) break;
      len += got;
      if (len > max) break;
    }
  } finally {
    fs.closeSync(fd);
  }
  if (len > max) {
    buf.fill(0);
    throw new TypeError(`${option} ${path} is larger than ${max} bytes`);
  }
  const out = buf.subarray(0, len);
  if (out.toString("latin1").trim() === "") throw new TypeError(`${option} ${path} is empty`);
  return out;
}

/** The labels of the PEM `BEGIN` lines. Only compared, never shown: they come from the file. */
function labels(text: string): string[] {
  return [...text.matchAll(BEGIN)].map((m) => m[1]!.trim());
}

/**
 * Whether `text` holds a private key of any kind. Any `PRIVATE KEY-----` counts, whatever the
 * BEGIN line around it looks like, so no spelling of the line gets one past this check.
 */
const hasPrivateKey = (text: string) =>
  text.includes("PRIVATE KEY-----") || labels(text).some((l) => l.endsWith("PRIVATE KEY"));

/** Whether every `-----BEGIN ` in `text` is a BEGIN line `labels` reads. */
const allBeginsRead = (text: string) =>
  (text.match(/-----BEGIN /g) ?? []).length === labels(text).length;

/** The DER of each `CERTIFICATE` block; undefined when a block cannot be read. */
function certificates(n: Node, text: string): Buffer[] | undefined {
  const out: Buffer[] = [];
  const re = new RegExp(BEGIN.source, "gm");
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const label = m[1]!.trim();
    const endMarker = `-----END ${label}-----`;
    const end = text.indexOf(endMarker, re.lastIndex);
    if (end < 0) return undefined;
    if (label === "CERTIFICATE") {
      const body = text.slice(re.lastIndex, end).replace(/\s+/g, "");
      if (body === "" || !/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return undefined;
      const der = Buffer.from(body, "base64");
      try {
        new n.crypto.X509Certificate(der);
      } catch {
        return undefined;
      }
      out.push(der);
    }
    re.lastIndex = end + endMarker.length;
  }
  return out;
}

const pem = (der: Buffer) =>
  `-----BEGIN CERTIFICATE-----\n${der.toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;

function readCa(n: Node, path: string): string[] {
  const text = readFile(n, CA, path, MAX_CA_BYTES).toString("latin1");
  if (hasPrivateKey(text)) {
    throw new TypeError(`${CA} ${path} holds a private key; it must hold only the CA certificates`);
  }
  const ders = allBeginsRead(text) ? certificates(n, text) : undefined;
  if (ders === undefined) throw new TypeError(`${CA} ${path} is not a readable PEM file`);
  if (ders.length === 0) throw new TypeError(`${CA} ${path} holds no PEM certificate`);
  return ders.map(pem);
}

/** The client certificate file (certificates only) and the key file (one unencrypted key). */
function readClient(n: Node, cert: string, key: string): { cert: string; key: Buffer } {
  const text = readFile(n, CERT, cert, MAX_CLIENT_BYTES).toString("latin1");
  if (hasPrivateKey(text)) {
    throw new TypeError(
      `${CERT} ${cert} holds a private key; give the key in ${KEY} and only the certificate here`,
    );
  }
  const ders = certificates(n, text);
  if (
    ders === undefined ||
    ders.length === 0 ||
    !allBeginsRead(text) ||
    labels(text).some((l) => l !== "CERTIFICATE")
  ) {
    throw new TypeError(
      `${CERT} ${cert} must hold the client certificate in PEM (\`BEGIN CERTIFICATE\`) and nothing else`,
    );
  }
  const keyBytes = readFile(n, KEY, key, MAX_CLIENT_BYTES);
  // Only the BEGIN lines and the legacy encryption header are looked at as text.
  const head = keyBytes.toString("latin1");
  const found = labels(head);
  const encrypted =
    found.some((l) => l.startsWith("ENCRYPTED")) ||
    /^Proc-Type:[ \t]*4,[ \t]*ENCRYPTED/m.test(head);
  let error: string | undefined;
  if (encrypted) {
    error = `${KEY} ${key} is an encrypted private key; it must be unencrypted (for example \`openssl pkey -in <key> -out <plain key>\`, then chmod 600)`;
  } else if (found.some((l) => l.endsWith("PRIVATE KEY") && !SUPPORTED_KEYS.includes(l))) {
    error = `${KEY} ${key} holds a kind of private key that cannot be read; it needs PEM \`BEGIN PRIVATE KEY\` (PKCS#8), \`BEGIN EC PRIVATE KEY\` or \`BEGIN RSA PRIVATE KEY\``;
  } else if (
    found.length !== 1 ||
    !allBeginsRead(head) ||
    !SUPPORTED_KEYS.includes(found[0]!) ||
    (head.match(/-----END /g) ?? []).length !== 1
  ) {
    error = `${KEY} ${key} must hold exactly one unencrypted private key in PEM (\`BEGIN PRIVATE KEY\`, \`BEGIN EC PRIVATE KEY\` or \`BEGIN RSA PRIVATE KEY\`) and nothing else`;
  }
  if (error !== undefined) {
    keyBytes.fill(0);
    throw new TypeError(error);
  }
  // OpenSSL takes a key of another type than the certificate's (an RSA key with an EC
  // certificate) and then sends no certificate at all, so the pair is checked here.
  let matches = false;
  try {
    matches = new n.crypto.X509Certificate(ders[0]!).checkPrivateKey(
      n.crypto.createPrivateKey(keyBytes),
    );
  } catch {
    // Not rethrown: Node's message is not shown.
  }
  if (!matches) {
    keyBytes.fill(0);
    throw new TypeError(mismatch(key, cert));
  }
  return { cert: ders.map(pem).join(""), key: keyBytes };
}

const mismatch = (key: string, cert: string) =>
  `${KEY} ${key} is not the private key of the certificate in ${CERT} ${cert}, or they cannot be used as a client certificate`;

/** The origin of `url`: scheme, host and port, the default port filled in. */
export function origin(url: string | URL): string {
  const u = typeof url === "string" ? new URL(url) : url;
  const port = u.port !== "" ? u.port : u.protocol === "https:" ? "443" : "80";
  return `${u.protocol}//${u.hostname.toLowerCase()}:${port}`;
}

/**
 * The options of one client, read and checked: an `https.Agent` for the server's origin (with
 * the client certificate when one is given) and one for every other origin (never with it).
 */
class TlsSettings {
  readonly origin: string;
  readonly caCert: string | undefined;
  readonly clientCert: string | undefined;
  readonly clientKey: string | undefined;
  readonly server: HttpsModule.Agent;
  readonly other: HttpsModule.Agent;

  constructor(serverUrl: string, opts: TlsOptions) {
    // The pairing is checked before any file is read.
    if (opts.tlsClientCert !== undefined && opts.tlsClientKey === undefined) {
      throw new TypeError(`${CERT} needs ${KEY}: the private key of the certificate`);
    }
    if (opts.tlsClientKey !== undefined && opts.tlsClientCert === undefined) {
      throw new TypeError(`${KEY} needs ${CERT}: the certificate of the key`);
    }
    this.caCert = opts.tlsCaCert === undefined ? undefined : checkPath(CA, opts.tlsCaCert);
    this.clientCert =
      opts.tlsClientCert === undefined ? undefined : checkPath(CERT, opts.tlsClientCert);
    this.clientKey =
      opts.tlsClientKey === undefined ? undefined : checkPath(KEY, opts.tlsClientKey);
    const https = /^https:\/\//i.test(serverUrl);
    if (this.clientCert !== undefined && !https) {
      throw new TypeError(
        `${CERT} and ${KEY} need an https:// server URL; a client certificate cannot be sent over plain HTTP`,
      );
    }
    this.origin = origin(serverUrl);
    const n = node();
    const ca = this.caCert === undefined ? undefined : readCa(n, this.caCert);
    const context = (extra: { cert?: string; key?: Buffer }) => {
      const opts: TlsModule.SecureContextOptions = { ...extra };
      if (ca !== undefined) opts.ca = ca;
      return n.tls.createSecureContext(opts);
    };
    let other: TlsModule.SecureContext | undefined;
    try {
      other = context({});
    } catch {
      // Not rethrown: Node's message is not shown.
    }
    if (other === undefined) {
      throw new TypeError(
        `${CA} ${String(this.caCert)}: a certificate in it cannot be used as a CA`,
      );
    }
    let server = other;
    if (this.clientCert !== undefined && this.clientKey !== undefined) {
      const client = readClient(n, this.clientCert, this.clientKey);
      let made: TlsModule.SecureContext | undefined;
      try {
        made = context(client);
      } catch {
        // Not rethrown: Node's message is not shown.
      } finally {
        // OpenSSL holds its own copy now.
        client.key.fill(0);
      }
      if (made === undefined) throw new TypeError(mismatch(this.clientKey, this.clientCert));
      server = made;
    }
    const agent = (secureContext: TlsModule.SecureContext) =>
      new n.https.Agent({
        keepAlive: true,
        timeout: 5_000,
        scheduling: "lifo",
        secureContext,
        rejectUnauthorized: true,
      });
    this.other = agent(other);
    this.server = server === other ? this.other : agent(server);
  }

  /** The one place that chooses: the agent with the certificate only for the server's origin. */
  agentFor(url: URL): HttpsModule.Agent {
    return origin(url) === this.origin ? this.server : this.other;
  }

  toJSON(): Record<string, unknown> {
    return { caCert: this.caCert, clientCert: this.clientCert, clientKey: this.clientKey };
  }
}

/** `init.body` as something `node:https` can write. */
async function bodyBytes(body: RequestInit["body"]): Promise<Uint8Array | string | undefined> {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof ReadableStream) {
    return new Uint8Array(await new Response(body).arrayBuffer());
  }
  throw new TypeError("tlsFetch: unsupported request body type");
}

const NULL_BODY = new Set([204, 205, 304]);

/**
 * Request headers `fetch` never lets a caller set; `node:https` would send them as given (a
 * `Host` would even change the name the server's certificate is checked against).
 */
const FORBIDDEN = new Set([
  "accept-encoding",
  "connection",
  "content-length",
  "expect",
  "host",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const failed = (cause: unknown) => new TypeError("fetch failed", { cause });

/**
 * `res` (from `node:https`) as a web `Response` whose body read failures are `TypeError`s.
 * Throws what `new Response` throws (a status outside 200-599, a reason phrase it refuses).
 */
function toResponse(res: IncomingMessage, method: string, abortReason: () => unknown): Response {
  const headers = new Headers();
  const raw = res.rawHeaders;
  for (let i = 0; i + 1 < raw.length; i += 2) headers.append(raw[i]!, raw[i + 1]!);
  const status = res.statusCode ?? 0;
  const init = { status, statusText: res.statusMessage ?? "", headers };
  const encoding = (headers.get("content-encoding") ?? "identity").trim().toLowerCase();
  if (encoding !== "identity") {
    // Asked for `identity` only: a body in another encoding is not handed on undecoded.
    throw new Error("the server answered with a content-encoding that was not asked for");
  }
  if (NULL_BODY.has(status) || method === "HEAD") {
    const response = new Response(null, init);
    res.resume();
    return response;
  }
  let settled = false;
  const body = new ReadableStream<Uint8Array>({
    start(ctl) {
      // No listener here may throw: it runs on an event emitter, where a throw would end the
      // process. Every one checks `settled` before it touches the controller.
      const fail = (e: unknown) => {
        if (settled) return;
        settled = true;
        const reason = abortReason();
        ctl.error(reason !== undefined ? reason : new TypeError("terminated", { cause: e }));
      };
      res.on("data", (chunk: Buffer) => {
        if (settled) return;
        ctl.enqueue(new Uint8Array(chunk));
        if ((ctl.desiredSize ?? 1) <= 0) res.pause();
      });
      res.on("end", () => {
        if (settled) return;
        settled = true;
        ctl.close();
      });
      res.on("error", fail);
      res.on("close", () => {
        if (!res.complete) fail(new Error("the connection closed before the body ended"));
      });
    },
    pull() {
      res.resume();
    },
    cancel() {
      settled = true;
      res.destroy();
    },
  });
  return new Response(body, init);
}

/** The URL of `input`; refuses what global `fetch` refuses, and a `Request`. */
function requestUrl(input: unknown): URL {
  if (typeof input !== "string" && !(input instanceof URL)) {
    throw new TypeError("tlsFetch takes the URL as a string or a URL, not a Request");
  }
  let url: URL;
  try {
    url = new URL(input);
  } catch (e) {
    throw new TypeError("tlsFetch: not a valid URL", { cause: e });
  }
  if (url.username !== "" || url.password !== "") {
    throw new TypeError("tlsFetch: a URL with credentials (user:password@) is refused");
  }
  return url;
}

/** `p`, or the abort reason as soon as `signal` aborts. */
function abortable<T>(p: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return p;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    if (signal.aborted) return onAbort();
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

/** A `fetch` over `node:https` with the agents of `tls`. Redirects are not followed. */
function httpsFetch(n: Node, tls: TlsSettings): FetchLike {
  return async (input, init = {}) => {
    const url = requestUrl(input);
    if (url.protocol !== "https:") {
      // No TLS on this request: global `fetch`, as without the options. Never follows a
      // redirect from here.
      return fetch(url, { ...init, redirect: "manual" });
    }
    const signal = init.signal ?? undefined;
    signal?.throwIfAborted();
    const method = (init.method ?? "GET").toUpperCase();
    if (method === "CONNECT" || method === "TRACE" || method === "TRACK") {
      throw new TypeError(`tlsFetch: the method ${method} is refused`);
    }
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((v, k) => {
      if (!FORBIDDEN.has(k) && !k.startsWith("proxy-")) headers[k] = v;
    });
    // The body is handed on as the server sent it, so only `identity` is asked for.
    headers["accept-encoding"] = "identity";
    const data = await abortable(bodyBytes(init.body), signal);
    signal?.throwIfAborted();
    if (data !== undefined) {
      headers["content-length"] = String(
        typeof data === "string" ? Buffer.byteLength(data) : data.byteLength,
      );
    }
    return await new Promise<Response>((resolve, reject) => {
      let aborted = false;
      let done = false;
      const settle = (f: () => void) => {
        if (done) return;
        done = true;
        f();
      };
      // The name the server's certificate is checked against is the URL's host, always.
      const host = url.hostname.replace(/^\[|\]$/g, "");
      const options: HttpsModule.RequestOptions = {
        method,
        headers,
        agent: tls.agentFor(url),
      };
      if (n.net.isIP(host) === 0) options.servername = host;
      let req: ReturnType<typeof n.https.request>;
      try {
        req = n.https.request(url, options);
      } catch (e) {
        // For example a header value Node refuses.
        reject(failed(e));
        return;
      }
      const onAbort = () => {
        aborted = true;
        req.destroy();
        settle(() => reject(signal?.reason));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      req.on("response", (res) => {
        // An abort while the body is read destroys the request, and so the body, too.
        res.on("close", () => signal?.removeEventListener("abort", onAbort));
        let response: Response;
        try {
          response = toResponse(res, method, () => (aborted ? signal?.reason : undefined));
        } catch (e) {
          res.destroy();
          settle(() => reject(failed(e)));
          return;
        }
        settle(() => resolve(response));
      });
      req.on("upgrade", (_res, socket) => {
        // A 101: no `fetch` answer can carry it.
        socket.destroy();
        settle(() => reject(failed(new Error("the server switched protocols"))));
      });
      req.on("error", (e) => {
        signal?.removeEventListener("abort", onAbort);
        // As global `fetch` does: a network failure is a `TypeError` with the cause.
        settle(() => reject(aborted ? signal?.reason : failed(e)));
      });
      req.on("close", () => {
        // Anything else that ends the request without an answer.
        settle(() => reject(failed(new Error("the connection closed without an answer"))));
      });
      if (signal?.aborted) {
        onAbort();
        return;
      }
      req.end(data);
    });
  };
}

/**
 * A `fetch` that trusts `tlsCaCert` and presents the client certificate of `tlsClientCert` and
 * `tlsClientKey` to the origin of `serverUrl` only (Node.js 20.16 or later). Every other origin
 * gets the same trust and no certificate. Redirects are never followed. For an MCP client
 * library that talks to attenuo's proxy: pass it as `mcpFetch(token, { fetch })`.
 *
 * The files are read and checked here, once; an error names the option and the path only.
 */
export function tlsFetch(serverUrl: string, opts: TlsOptions): FetchLike {
  const tls = new TlsSettings(serverUrl, opts);
  return httpsFetch(node(), tls);
}

/** `tlsFetch` when any option is given, else undefined. */
export function optionalTlsFetch(serverUrl: string, opts: TlsOptions): FetchLike | undefined {
  if (
    opts.tlsCaCert === undefined &&
    opts.tlsClientCert === undefined &&
    opts.tlsClientKey === undefined
  ) {
    return undefined;
  }
  return tlsFetch(serverUrl, opts);
}

import { normalizeBase } from "./wire.js";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface HttpOptions {
  /** Defaults to the global `fetch`. Pass your own for proxies, tests or custom TLS. */
  fetch?: FetchLike;
  /** Extra headers sent on every request. */
  headers?: Record<string, string>;
  /** Per-request timeout in milliseconds (default 30000, `0` disables). */
  timeoutMs?: number;
}

export const DEFAULT_TIMEOUT_MS = 30_000;

/** A tiny fetch wrapper: base URL, default headers, timeout, JSON bodies. */
export class Http {
  readonly base: string;
  private readonly doFetch: FetchLike;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;

  constructor(serverUrl: string, opts: HttpOptions = {}, headers: Record<string, string> = {}) {
    this.base = normalizeBase(serverUrl);
    this.doFetch = opts.fetch ?? ((input, init) => fetch(input, init));
    this.headers = { ...opts.headers, ...headers };
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  request(
    method: string,
    path: string,
    opts: {
      headers?: Record<string, string>;
      json?: unknown;
      query?: Record<string, string | number>;
    } = {},
  ): Promise<Response> {
    let url = `${this.base}${path}`;
    if (opts.query) {
      const qs = new URLSearchParams(Object.entries(opts.query).map(([k, v]) => [k, String(v)]));
      url += `?${qs.toString()}`;
    }
    const headers: Record<string, string> = { ...this.headers, ...opts.headers };
    const init: RequestInit = { method, headers };
    if (opts.json !== undefined) {
      headers["content-type"] ??= "application/json";
      init.body = JSON.stringify(opts.json);
    }
    if (this.timeoutMs > 0) init.signal = AbortSignal.timeout(this.timeoutMs);
    return this.doFetch(url, init);
  }

  /** GET an absolute URL (a JWKS served elsewhere) with this client's fetch and timeout. */
  getUrl(url: string): Promise<Response> {
    const init: RequestInit = { method: "GET", headers: { ...this.headers } };
    if (this.timeoutMs > 0) init.signal = AbortSignal.timeout(this.timeoutMs);
    return this.doFetch(url, init);
  }

  get(path: string, opts: Parameters<Http["request"]>[2] = {}): Promise<Response> {
    return this.request("GET", path, opts);
  }

  post(path: string, opts: Parameters<Http["request"]>[2] = {}): Promise<Response> {
    return this.request("POST", path, opts);
  }
}

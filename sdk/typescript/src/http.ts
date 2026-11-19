import { ApiError, TransportError, TransportTimeoutError } from "./errors.js";
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

/**
 * Is `e`, thrown by `fetch` or by a read of its body, a transport failure? `fetch` signals a
 * network error with a `TypeError`; the client's own timeout (`ownTimeout`) aborts with a
 * `TimeoutError`. Any other abort is the caller's and is not one.
 */
function isTransportFailure(e: unknown, ownTimeout: boolean): boolean {
  if (e instanceof TransportError) return false;
  if (e instanceof TypeError) return true;
  return ownTimeout && (e as { name?: unknown } | null)?.name === "TimeoutError";
}

/** `e` as a `TransportError`; the client's own timeout as its `TransportTimeoutError`. */
function transportError(method: string, url: string, e: unknown): TransportError {
  const err = e as { message?: unknown; cause?: unknown; name?: unknown } | null;
  const inner = (err?.cause as { message?: unknown } | null | undefined)?.message;
  const why = typeof inner === "string" && inner !== "" ? ` (${inner})` : "";
  const message = `${method} ${url} failed: ${String(err?.message ?? e)}${why}`;
  return err?.name === "TimeoutError"
    ? new TransportTimeoutError(message, e)
    : new TransportError(message, e);
}

/**
 * `res` with a body whose read failures are `TransportError`s too. A response without a body,
 * or one the platform will not rebuild, is returned as it is.
 */
function guardBody(res: Response, method: string, url: string, ownTimeout: boolean): Response {
  const body = res.body;
  if (body === null) return res;
  const reader = body.getReader();
  const guarded = new ReadableStream<Uint8Array>({
    async pull(ctl) {
      try {
        const { done, value } = await reader.read();
        if (done) ctl.close();
        else ctl.enqueue(value);
      } catch (e) {
        ctl.error(isTransportFailure(e, ownTimeout) ? transportError(method, url, e) : e);
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  try {
    return new Response(guarded, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  } catch {
    reader.releaseLock();
    return res;
  }
}

/** The `error` and `code` of the `ApiError` a 3xx answer throws (SR-112). */
export const REDIRECT_NOT_FOLLOWED = "redirect_not_followed";

/**
 * The error for a redirect answer, else undefined. No client of the SDK follows a redirect
 * (`redirect: "manual"`): a followed `307` or `308` would send the body again to wherever
 * `Location` names, a client secret, client assertion or subject token included (SR-112). Node
 * hands back the 3xx itself; a browser hands back an opaque redirect (`type` `opaqueredirect`,
 * status 0) whose `Location` it does not show.
 */
export function redirectError(res: Response, method: string, url: string): ApiError | undefined {
  const opaque = res.type === "opaqueredirect";
  if (!opaque && !(res.status >= 300 && res.status < 400)) return undefined;
  const location = opaque ? null : res.headers.get("location");
  const where = location ? `Location ${location}` : "no Location";
  const status = opaque ? "a redirect" : String(res.status);
  return new ApiError(
    res.status,
    REDIRECT_NOT_FOLLOWED,
    `${method} ${url} answered ${status} (${where}); the client does not follow redirects, ` +
      "so the server URL must be the final URL, the one that answers without a redirect",
  );
}

/**
 * A tiny fetch wrapper: base URL, default headers, timeout, JSON bodies. A transport failure,
 * while sending or while reading the body, is a `TransportError` whose `cause` is what `fetch`
 * threw. Redirects are not followed: a 3xx is an `ApiError` `redirect_not_followed`
 * (`redirectError`).
 */
export class Http {
  readonly base: string;
  private readonly doFetch: FetchLike;
  private readonly headers: Record<string, string>;
  /** Per-request timeout in milliseconds; `0` disables it. */
  readonly timeoutMs: number;

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
      /** Replaces the per-request timeout (a streamed answer keeps its own idle timer). */
      signal?: AbortSignal;
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
    const ownTimeout = !opts.signal && this.timeoutMs > 0;
    if (opts.signal) init.signal = opts.signal;
    else if (ownTimeout) init.signal = AbortSignal.timeout(this.timeoutMs);
    return this.send(method, url, init, ownTimeout);
  }

  private async send(
    method: string,
    url: string,
    init: RequestInit,
    ownTimeout: boolean,
  ): Promise<Response> {
    let res: Response;
    try {
      // Passed in `init`, so a `fetch` given in the options gets it too (SR-112).
      res = await this.doFetch(url, { ...init, redirect: "manual" });
    } catch (e) {
      throw isTransportFailure(e, ownTimeout) ? transportError(method, url, e) : e;
    }
    const redirect = redirectError(res, method, url);
    if (redirect !== undefined) {
      await res.body?.cancel().catch(() => undefined);
      throw redirect;
    }
    return guardBody(res, method, url, ownTimeout);
  }

  /** GET an absolute URL (a JWKS served elsewhere) with this client's fetch and timeout. */
  getUrl(url: string): Promise<Response> {
    const init: RequestInit = { method: "GET", headers: { ...this.headers } };
    if (this.timeoutMs > 0) init.signal = AbortSignal.timeout(this.timeoutMs);
    return this.send("GET", url, init, this.timeoutMs > 0);
  }

  get(path: string, opts: Parameters<Http["request"]>[2] = {}): Promise<Response> {
    return this.request("GET", path, opts);
  }

  post(path: string, opts: Parameters<Http["request"]>[2] = {}): Promise<Response> {
    return this.request("POST", path, opts);
  }
}

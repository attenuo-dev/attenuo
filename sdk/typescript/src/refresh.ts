/**
 * Keep a delegation token alive: renew its lease and re-exchange before it expires.
 *
 * A delegation token has two clocks. Its lease lapses unless renewed (`POST /token/renew`, every
 * `[issuer] lease_interval_seconds` at most), and the token has a hard `exp` that renewal cannot
 * move. `TokenRefresher` runs both:
 *
 * - renew the lease at a third of the lease interval;
 * - before `exp` (`margin` seconds early; default 20% of the lifetime, at least 5 s) call your
 *   `exchange` function for a replacement token;
 * - expose the current token through `token` and `provider` (what `mcpFetch` takes, so an MCP
 *   transport picks the new token up on its next request) and tell `onChange` about each one;
 * - retry failures with jittered exponential backoff, but stop with a `RefreshError`
 *   (`onError`) when the lease is revoked, the server refuses for good, or the token expires.
 *
 * **The exchange function.** The server lets a parent token delegate to a given actor once, so
 * calling `client.exchange(sameParent, ...)` again is refused as `replayed`. `exchange` must
 * bring a fresh subject token each time (a new parent from the planner, or a new IdP credential
 * at hop 0) and return the new `Token`. Give it the same client you use for calls.
 *
 * **DPoP.** A bound token (`Token.dpopJkt`) stays bound to the same key: renewals go through your
 * client, which signs with its `dpopKey`, and a replacement bound to a different key (or to none)
 * is rejected (`key_mismatch`) rather than adopted.
 *
 * Tokens are never logged or put in error messages.
 */

import type { OnbehalfClient } from "./client.js";
import { ApiError, RefreshError, UnauthorizedError } from "./errors.js";
import type { FetchLike } from "./http.js";
import type { DpopKeyLike } from "./dpop.js";
import { mcpFetch } from "./mcp.js";
import type { Token } from "./token.js";
import type { Lease } from "./wire.js";

const MIN_MARGIN_S = 5;
const MARGIN_FRACTION = 0.2;
const MIN_SPACING_MS = 1000;
const BACKOFF_BASE_MS = 1000;
const BACKOFF_CAP_MS = 30_000;

export interface RefresherOptions {
  /** The client used for renewals (so it signs DPoP proofs with its own key). */
  client: OnbehalfClient;
  /** The token to keep alive. */
  token: Token;
  /** Returns a replacement token. Needs a fresh subject token each call (see the module docs). */
  exchange: () => Promise<Token>;
  /**
   * The server's `[issuer] lease_interval_seconds`. Left out, it is learned from the first
   * renewal, which then happens right away.
   */
  leaseInterval?: number;
  /** Seconds before `exp` to re-exchange (default: 20% of the lifetime, at least 5). */
  margin?: number;
  /** Called with each replacement token. */
  onChange?: (token: Token) => void;
  /** Called once, when the refresher gives up. */
  onError?: (error: RefreshError) => void;
  /** Milliseconds since the epoch; replace with a fake clock in tests. */
  now?: () => number;
  /** Uniform in [0, 1); replace for deterministic backoff in tests. */
  random?: () => number;
}

type Kind = "renew" | "exchange";

function terminal(kind: Kind, e: unknown): RefreshError | undefined {
  if (!(e instanceof ApiError)) return undefined;
  const detail = `${e.error} ${e.detail}`;
  let reason: string;
  if (e instanceof UnauthorizedError) {
    reason = detail.includes("token_expired") ? "token_expired" : "refused";
  } else if (kind === "renew" && e.status === 400 && e.error === "invalid_grant") {
    const gone = detail.includes("lease_revoked") || detail.includes("lease_unknown");
    reason = gone ? "lease_revoked" : "lease_lost";
  } else if (e.status >= 400 && e.status < 500 && e.status !== 408 && e.status !== 429) {
    reason = "refused";
  } else {
    return undefined;
  }
  return new RefreshError(reason, `${kind} answered ${e.status} ${e.error}`, e);
}

export class TokenRefresher {
  private current: Token;
  private failure: RefreshError | undefined;
  private interval: number | undefined; // seconds
  private readonly learn: boolean;
  private renewAt = 0; // ms
  private exchangeAt: number;
  private readonly fails: Record<Kind, number> = { renew: 0, exchange: 0 };
  private readonly retryAt: Record<Kind, number> = { renew: 0, exchange: 0 };
  private readonly now: () => number;
  private readonly random: () => number;
  private loop: Promise<void> | undefined;
  private stopped = false;
  private wake: (() => void) | undefined;

  constructor(private readonly opts: RefresherOptions) {
    if (opts.leaseInterval !== undefined && !(opts.leaseInterval > 0)) {
      throw new RangeError("leaseInterval must be positive");
    }
    if (opts.margin !== undefined && !(opts.margin >= 0)) {
      throw new RangeError("margin must not be negative");
    }
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    this.current = opts.token;
    this.interval = opts.leaseInterval;
    this.learn = opts.leaseInterval === undefined;
    if (opts.leaseInterval !== undefined)
      this.renewAt = this.now() + (opts.leaseInterval * 1000) / 3;
    this.exchangeAt = this.exchangeTime(opts.token);
  }

  /** The current token. */
  get token(): Token {
    return this.current;
  }

  /** Set once the refresher has given up. */
  get error(): RefreshError | undefined {
    return this.failure;
  }

  /**
   * The current token, for `mcpFetch(refresher.provider)` or any per-request hook. Throws the
   * `RefreshError` once the refresher has given up.
   */
  readonly provider = (): Token => {
    if (this.failure) throw this.failure;
    return this.current;
  };

  /** A `fetch` for an MCP client transport that always sends the current token. */
  fetch(opts: { dpopKey?: DpopKeyLike; fetch?: FetchLike } = {}): FetchLike {
    return mcpFetch(this.provider, opts);
  }

  /**
   * Run in the background until the returned disposer is called (or the refresher gives up).
   * The disposer stops the loop and resolves once any request in flight has finished.
   */
  start(): () => Promise<void> {
    if (!this.loop && !this.stopped) this.loop = this.run();
    return () => this.stop();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.wake?.();
    await this.loop;
  }

  /**
   * Run whatever is due once. Returns the milliseconds to wait before the next call, or
   * `undefined` when the refresher has finished (or given up). `start()` is a loop around this;
   * tests call it directly with a fake `now`.
   */
  async tick(): Promise<number | undefined> {
    const kind = this.due(this.now());
    if (kind === "exchange") {
      let next: Token | undefined;
      try {
        next = await this.opts.exchange();
      } catch (e) {
        this.failed("exchange", e);
      }
      if (next) this.exchanged(next);
    } else if (kind === "renew") {
      let lease: Lease | undefined;
      try {
        lease = await this.opts.client.renew(this.current);
      } catch (e) {
        this.failed("renew", e);
      }
      if (lease) this.renewed(lease);
    }
    return this.delay();
  }

  private async run(): Promise<void> {
    while (!this.stopped) {
      const wait = await this.tick();
      if (wait === undefined || this.stopped) return;
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, wait);
        timer.unref?.();
        this.wake = () => {
          clearTimeout(timer);
          resolve();
        };
      });
      this.wake = undefined;
    }
  }

  // -- schedule --
  private exchangeTime(token: Token): number {
    const last = token.chain.hops[token.chain.hops.length - 1]!;
    const life = Math.max((token.expiresAt.getTime() - last.issuedAt.getTime()) / 1000, 0);
    const margin = this.opts.margin ?? Math.max(MIN_MARGIN_S, MARGIN_FRACTION * life);
    return token.expiresAt.getTime() - Math.min(margin, life / 2) * 1000;
  }

  private due(now: number): Kind | undefined {
    if (this.failure) return undefined;
    if (now >= this.current.expiresAt.getTime()) {
      this.fail(new RefreshError("token_expired", "the token reached exp"));
      return undefined;
    }
    if (now >= Math.max(this.exchangeAt, this.retryAt.exchange)) return "exchange";
    if (now >= Math.max(this.renewAt, this.retryAt.renew)) return "renew";
    return undefined;
  }

  private delay(): number | undefined {
    if (this.failure) return undefined;
    const wake = Math.min(
      Math.max(this.exchangeAt, this.retryAt.exchange),
      Math.max(this.renewAt, this.retryAt.renew),
      this.current.expiresAt.getTime(),
    );
    return Math.max(wake - this.now(), 0);
  }

  // -- outcomes --
  private renewed(lease: Lease): void {
    this.fails.renew = 0;
    this.retryAt.renew = 0;
    if (this.learn && lease.expiresIn > 0)
      this.interval = Math.max(this.interval ?? 0, lease.expiresIn);
    const interval = this.interval ?? lease.expiresIn;
    let step = interval / 3;
    if (lease.expiresIn > 0) step = Math.min(step, lease.expiresIn / 2); // capped by parent or exp
    this.renewAt = this.now() + Math.max(step, 0.5) * 1000;
  }

  private exchanged(next: Token): void {
    if (next.dpopJkt !== this.current.dpopJkt) {
      this.fail(new RefreshError("key_mismatch", "the new token is not bound to the same key"));
      return;
    }
    const now = this.now();
    this.current = next;
    this.fails.exchange = 0;
    this.retryAt.exchange = 0;
    // Never hot-loop on a provider that hands back a token that is already due.
    this.exchangeAt = Math.max(this.exchangeTime(next), now + MIN_SPACING_MS);
    // A fresh token comes with a fresh lease; renew a third of an interval from now.
    this.renewAt = now + (this.interval ? (this.interval * 1000) / 3 : 0);
    this.fails.renew = 0;
    this.retryAt.renew = 0;
    this.notify(() => this.opts.onChange?.(next));
  }

  private failed(kind: Kind, e: unknown): void {
    const end = terminal(kind, e);
    if (end) {
      this.fail(end);
      return;
    }
    const now = this.now();
    this.fails[kind] += 1;
    const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** (this.fails[kind] - 1));
    let wait = ceiling / 2 + this.random() * (ceiling / 2);
    const left = this.current.expiresAt.getTime() - now;
    wait = Math.min(wait, Math.max(left / 2, 100)); // leave room for another try before exp
    this.retryAt[kind] = now + wait;
  }

  private fail(err: RefreshError): void {
    if (this.failure) return;
    this.failure = err;
    this.notify(() => this.opts.onError?.(err));
  }

  /** A bad callback must not kill the refresher; its error text could hold anything, so drop it. */
  private notify(fn: () => void): void {
    try {
      fn();
    } catch {
      // ignored on purpose
    }
  }
}

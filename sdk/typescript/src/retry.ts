/**
 * The opt-in retry of load refusals (`new AttenuoClient(url, { maxRetries })`).
 *
 * Only the two refusals the server's `[limits]` make before doing any work are retried: 503
 * `overloaded` and 429 `rate_limited` (`retryableRefusal`). Never a `request_timeout` (the
 * handler may have run), never a denial, never a transport error.
 */

import { retryableRefusal } from "./wire.js";

/** The longest `Retry-After` the client waits out unless told otherwise, in milliseconds. */
export const DEFAULT_MAX_RETRY_DELAY_MS = 10_000;
const MAX_RETRIES_LIMIT = 10;
const MAX_RETRY_DELAY_LIMIT_MS = 300_000;
/** What a retried refusal without a readable `Retry-After` waits. */
const NO_RETRY_AFTER_DELAY_MS = 1_000;
/**
 * Each wait is up to this fraction longer than `Retry-After`, so clients refused together do not
 * all come back in the same instant.
 */
const JITTER = 0.2;

/** Indirections so tests can replace the clock and the randomness. Not part of the API. */
export const retryHooks = {
  random: (): number => Math.random(),
  sleep: (ms: number, signal?: AbortSignal): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason);
        return;
      }
      const onAbort = () => {
        clearTimeout(t);
        reject(signal?.reason);
      };
      const t = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      signal?.addEventListener("abort", onAbort, { once: true });
    }),
};

/** `maxRetries` and `maxRetryDelayMs` of a client, checked once. */
export class RetryPolicy {
  readonly maxRetries: number;
  readonly maxRetryDelayMs: number;

  constructor(maxRetries = 0, maxRetryDelayMs = DEFAULT_MAX_RETRY_DELAY_MS) {
    if (!Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > MAX_RETRIES_LIMIT) {
      throw new RangeError(`maxRetries must be an integer between 0 and ${MAX_RETRIES_LIMIT}`);
    }
    if (!(maxRetryDelayMs > 0 && maxRetryDelayMs <= MAX_RETRY_DELAY_LIMIT_MS)) {
      throw new RangeError(
        `maxRetryDelayMs must be more than 0 and at most ${MAX_RETRY_DELAY_LIMIT_MS}`,
      );
    }
    this.maxRetries = maxRetries;
    this.maxRetryDelayMs = maxRetryDelayMs;
  }

  /**
   * Milliseconds to wait before sending again, after `retries` retries already made; undefined to
   * hand `res` back as it is. `leftMs` is what remains of a streamed call's `deadlineMs`: a wait
   * that would outlast it is not made. Reads a clone of `res`'s body when it is a 429 or 503.
   */
  async delayMs(res: Response, retries: number, leftMs?: number): Promise<number | undefined> {
    if (retries >= this.maxRetries) return undefined;
    const refusal = await retryableRefusal(res);
    if (refusal === undefined) return undefined;
    const base =
      refusal.retryAfter === undefined ? NO_RETRY_AFTER_DELAY_MS : refusal.retryAfter * 1000;
    // Waiting less than the server asked would only be refused again.
    if (base > this.maxRetryDelayMs) return undefined;
    const wait = Math.min(base * (1 + JITTER * retryHooks.random()), this.maxRetryDelayMs);
    if (leftMs !== undefined && wait >= leftMs) return undefined;
    return wait;
  }
}

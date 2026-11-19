/**
 * An incremental `text/event-stream` parser and the streamed `tools/call` answer.
 *
 * The parser follows the SSE rules of the WHATWG HTML standard: LF, CRLF and CR line ends,
 * `data:` lines joined with `\n`, a blank line ends an event, comment lines (`:`) and the
 * `event:` and `retry:` fields are ignored, `id:` sets the last event id (kept across events, as
 * the standard says, for `Last-Event-ID`), and an event with no terminating blank line when the
 * stream ends is dropped. It refuses an event (or a single line) over `maxEventBytes`.
 */

import { AttenuoError, DeniedError, RpcError } from "./errors.js";
import * as w from "./wire.js";

/**
 * The default bound on one SSE event (or a plain JSON answer) of a streamed call: 16 MiB, the
 * proxy's `[proxy] max_upstream_body_bytes` default.
 */
export const DEFAULT_MAX_EVENT_BYTES = 16 * 1024 * 1024;

/**
 * The `data.reason` values the proxy's stream-end event carries (`end_event_recorded` in
 * crates/attenuo-proxy/src/guard.rs): the token and lease reasons of the server's authorizer,
 * and `unauthorized` for a re-check that failed for another reason. These are the reasons on
 * the wire, not the `StreamEndCause` metric labels: `lease_other`, `recheck_unavailable` and
 * `recheck_failed` never appear in an event.
 */
const STREAM_END_REASONS: ReadonlySet<string> = new Set([
  "token_expired",
  "lease_revoked",
  "lease_expired",
  "lease_unknown",
  "lease_error",
  "unauthorized",
]);

/** `data.decision_id` of a stream-end event, when present: a UUID in its hyphenated form. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const CR = 0x0d;
const LF = 0x0a;

type Json = Record<string, unknown>;

/** One dispatched SSE event: its joined `data` and the last event id at that point. */
export interface SseEvent {
  data: string;
  lastEventId: string | undefined;
}

function concat(parts: Uint8Array[], total: number): Uint8Array {
  if (parts.length === 1) return parts[0]!;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Feed bytes as they arrive; get back the events they complete. */
export class SseParser {
  lastEventId: string | undefined;
  private partial: Uint8Array[] = [];
  private partialLen = 0;
  private skipLf = false; // the last chunk ended in CR: a leading LF completes that CRLF
  private data: string[] = [];
  private size = 0; // bytes of the lines of the event being read
  private first = true; // a UTF-8 BOM may open the stream
  private readonly decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

  constructor(readonly maxEventBytes: number = DEFAULT_MAX_EVENT_BYTES) {
    if (!(maxEventBytes > 0)) throw new TypeError("maxEventBytes must be positive");
  }

  /** The events `chunk` completes, each as soon as it is parsed (consume them all). */
  *feed(chunk: Uint8Array): Generator<SseEvent> {
    let start = 0;
    if (this.skipLf && chunk.length > 0) {
      this.skipLf = false;
      if (chunk[0] === LF) start = 1;
    }
    for (let i = start; i < chunk.length; i++) {
      const b = chunk[i];
      if (b !== CR && b !== LF) continue;
      const piece = chunk.subarray(start, i);
      let end = i + 1;
      if (b === CR) {
        if (end < chunk.length) {
          if (chunk[end] === LF) end++;
        } else {
          this.skipLf = true;
        }
      }
      this.take(this.partialLen + piece.length + (end - i));
      const line =
        this.partialLen === 0
          ? piece
          : concat([...this.partial, piece], this.partialLen + piece.length);
      this.partial = [];
      this.partialLen = 0;
      const event = this.line(line);
      start = end;
      i = end - 1;
      if (event !== undefined) yield event;
    }
    if (start < chunk.length) {
      // Copy: the caller may reuse its buffer.
      this.partial.push(chunk.slice(start));
      this.partialLen += chunk.length - start;
      if (this.size + this.partialLen > this.maxEventBytes) throw this.tooBig();
    }
  }

  /** End of stream: an event without its blank line, and a line without its end, are dropped. */
  close(): void {
    this.partial = [];
    this.partialLen = 0;
    this.data = [];
    this.size = 0;
  }

  private take(n: number): void {
    this.size += n;
    if (this.size > this.maxEventBytes) throw this.tooBig();
  }

  private tooBig(): AttenuoError {
    return new AttenuoError(`SSE event over ${this.maxEventBytes} bytes refused`);
  }

  private line(raw: Uint8Array): SseEvent | undefined {
    if (raw.length === 0) {
      const data = this.data;
      this.data = [];
      this.size = 0;
      this.first = false;
      return data.length === 0
        ? undefined
        : { data: data.join("\n"), lastEventId: this.lastEventId };
    }
    let line: string;
    try {
      line = this.decoder.decode(raw);
    } catch {
      throw new AttenuoError("SSE stream is not UTF-8");
    }
    if (this.first) {
      this.first = false;
      if (line.startsWith("﻿")) line = line.slice(1);
    }
    if (line.startsWith(":")) return undefined;
    const colon = line.indexOf(":");
    const name = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (name === "data") this.data.push(value);
    else if (name === "id" && !value.includes("\0")) this.lastEventId = value;
    // `event`, `retry` and unknown fields are ignored.
    return undefined;
  }
}

/**
 * One JSON-RPC message of a streamed `tools/call` answer (`callToolStream`).
 *
 * `message` is the message as sent: a notification (`notifications/progress`,
 * `notifications/message`, ...), a request from the server, or the response to the call.
 */
export interface StreamEvent {
  message: Json;
  /** The notification's or request's `method`; undefined for a response. */
  method: string | undefined;
  /**
   * The SSE last event id when the message arrived (what a client sends as `Last-Event-ID` to
   * resume); undefined for a plain JSON answer or a stream without ids.
   */
  lastEventId: string | undefined;
  /** The proxy's `X-Attenuo-Decision-Id` for the call. */
  decisionId: string | undefined;
  /** Set on the final event only: the call's result. */
  result: w.ToolResult | undefined;
  /** True for the event that carries the call's result (always the last one). */
  isFinal: boolean;
}

/**
 * The proxy's last event on a stream it cut, as a `DeniedError`; undefined for a message without
 * the stream-end shape.
 *
 * The shape is a response (no `method`) whose `id` is null or absent and whose error code is
 * `-32001`. A message of that shape is a cut only when `data.reason` is one the proxy sends and
 * `data.decision_id` is absent or a UUID string: then it is a `DeniedError` with that reason and
 * id. Anything else of that shape is an `RpcError` with code `-32001`, which still ends the
 * call, but not as a decision.
 *
 * This is belt-and-braces: the real guard is the proxy, which rewrites any upstream message of
 * the stream-end shape to `-32005` `upstream_stream_end_shape` before it reaches the client.
 * The proxy's `X-Attenuo-Decision-Id` header went out before the cut, so it cannot vouch for
 * this decision id the way it does for a `-32003`.
 */
export function streamEndError(msg: Json): DeniedError | RpcError | undefined {
  const err = msg.error;
  if ("method" in msg || (msg.id !== null && msg.id !== undefined)) return undefined;
  if (typeof err !== "object" || err === null) return undefined;
  const e = err as Json;
  if (e.code !== w.CODE_UNAUTHORIZED) return undefined;
  const message = String(e.message ?? "");
  const data = e.data;
  if (typeof data === "object" && data !== null && !Array.isArray(data)) {
    const d = data as Json;
    const reason = d.reason;
    const id = d.decision_id;
    const idOk = !("decision_id" in d) || (typeof id === "string" && UUID.test(id));
    if (typeof reason === "string" && STREAM_END_REASONS.has(reason) && idOk) {
      return new DeniedError(reason, id as string | undefined, message, d);
    }
  }
  return new RpcError(w.CODE_UNAUTHORIZED, message, data);
}

function streamEvent(
  message: Json,
  lastEventId: string | undefined,
  decisionId: string | undefined,
  result?: w.ToolResult,
): StreamEvent {
  return {
    message,
    method: typeof message.method === "string" ? message.method : undefined,
    lastEventId,
    decisionId,
    result,
    isFinal: result !== undefined,
  };
}

/**
 * Turns the body of one `tools/call` response into `StreamEvent` values. `onChunk` is called
 * after each read (the client resets its idle timer there). A JSON-RPC error throws what
 * `callTool` throws; the proxy's stream-end event throws `DeniedError`, and a message of its shape that is
 * not one throws `RpcError` (see `streamEndError`).
 */
export async function* callStream(
  res: Response,
  requestId: number,
  maxEventBytes: number,
  onChunk: () => void = () => {},
): AsyncGenerator<StreamEvent> {
  const headerId = res.headers.get(w.DECISION_ID_HEADER) ?? undefined;
  const sse = (res.headers.get("content-type") ?? "").includes("event-stream");
  const reader = res.body?.getReader();
  let finished = false;
  try {
    if (!sse || !res.ok) {
      // A whole body read at once (a JSON answer, or an error status): one final event.
      const parts: Uint8Array[] = [];
      let total = 0;
      while (reader) {
        const { done, value } = await reader.read();
        onChunk();
        if (done) break;
        parts.push(value);
        total += value.length;
        if (total > maxEventBytes) {
          throw new AttenuoError(`response over ${maxEventBytes} bytes refused`);
        }
      }
      finished = true;
      const text = new TextDecoder().decode(concat(parts, total));
      const msg = w.parseRpcBody(text, sse);
      const { result, decisionId } = w.rpcMessageResult(res, msg, text);
      yield streamEvent(msg ?? {}, undefined, decisionId, w.toolResult(result, decisionId));
      return;
    }
    const parser = new SseParser(maxEventBytes);
    while (reader) {
      const { done, value } = await reader.read();
      onChunk();
      if (done) break;
      for (const ev of parser.feed(value)) {
        if (!ev.data.trim()) continue;
        let msg: unknown;
        try {
          msg = JSON.parse(ev.data);
        } catch {
          throw new AttenuoError(`SSE event is not JSON: ${ev.data.slice(0, 200)}`);
        }
        if (typeof msg !== "object" || msg === null || Array.isArray(msg)) {
          throw new AttenuoError(`SSE event is not one JSON-RPC message: ${ev.data.slice(0, 200)}`);
        }
        const m = msg as Json;
        const isResponse = !("method" in m) && ("result" in m || "error" in m);
        if (!isResponse) {
          yield streamEvent(m, ev.lastEventId, headerId);
          continue;
        }
        const cut = streamEndError(m);
        if (cut !== undefined) throw cut;
        if (m.id !== requestId) {
          yield streamEvent(m, ev.lastEventId, headerId);
          continue;
        }
        const { result, decisionId } = w.rpcMessageResult(res, m, ev.data);
        yield streamEvent(m, ev.lastEventId, decisionId, w.toolResult(result, decisionId));
        return;
      }
    }
    finished = true;
    parser.close();
    throw new AttenuoError("stream ended before the tools/call response");
  } finally {
    // Leaving early (a break in `for await`, a refusal, an error) closes the connection.
    if (!finished) await reader?.cancel().catch(() => {});
  }
}

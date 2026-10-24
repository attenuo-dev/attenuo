/**
 * Capabilities and argument constraints, serialized exactly as the Rust `Capability` is.
 *
 * ```ts
 * capability("github", "read_file", { repo: prefix("alice/public-") })
 * // { server: "github", tool: "read_file",
 * //   constraints: { repo: { op: "prefix", value: "alice/public-" } } }
 * ```
 *
 * `constraints` is omitted when empty. `server` and `tool` are an exact name, `*`, or a prefix
 * glob such as `read_*`.
 *
 * Run limits (ADR-0010) ride along as `limits`, omitted when empty:
 *
 * ```ts
 * withLimits(capability("banking", "send_money"), { calls: 1, sum: { arg: "amount", max: 10 } })
 * ```
 *
 * `distinct` bounds how many different values an argument may take, and `calls_per` and
 * `distinct` can count the host of a URL argument instead of the whole value:
 *
 * ```ts
 * withLimits(capability("web", "get_webpage"), { distinct: argLimit("url", 2, { derive: "host" }) })
 * // limits: { distinct: { arg: "url", max: 2, derive: "host" } }
 * ```
 *
 * A child token is attenuated by passing such capabilities to `exchange`. The server keeps a
 * child's figures no larger than its parent's (it lowers larger ones and fills in a limit the
 * child leaves out), and charges every call to every hop.
 */

export type Constraint =
  | { op: "equals"; value: unknown }
  | { op: "one_of"; value: unknown[] }
  | { op: "prefix"; value: string };

/**
 * What a `calls_per` or `distinct` limit may count instead of the argument itself. `"host"`: the
 * host of a URL argument (lowercased, without port or user info), so two pages of one site are one
 * value; a value with no host cannot be counted and the call is refused (`limit_arg_invalid`).
 */
export type Derive = "host";

/**
 * A run limit over one argument: a total (`sum`), a count per value (`calls_per`) or a count of
 * values (`distinct`). `derive` (`calls_per` and `distinct` only) counts a value derived from the
 * argument; the server then names it `arg#host` in records and errors.
 */
export interface ArgLimit {
  arg: string;
  max: number;
  derive?: Derive;
}

/**
 * Run limits (ADR-0010): at most `calls` matched calls, a total of at most `sum.max` over
 * argument `sum.arg`, at most `calls_per.max` calls per value of argument `calls_per.arg`, and at
 * most `distinct.max` different values of argument `distinct.arg`. List-valued arguments count
 * each element.
 */
export interface Limits {
  calls?: number;
  sum?: ArgLimit;
  calls_per?: ArgLimit;
  distinct?: ArgLimit;
}

/** `argLimit("url", 2, { derive: "host" })` is `{ arg: "url", max: 2, derive: "host" }`. */
export function argLimit(arg: string, max: number, opts: { derive?: Derive } = {}): ArgLimit {
  const out: ArgLimit = { arg, max };
  if (opts.derive !== undefined) out.derive = opts.derive;
  return out;
}

export interface Capability {
  server: string;
  tool: string;
  constraints?: Record<string, Constraint>;
  limits?: Limits;
}

/** Anything that can be turned into a capability: an object, `"server:tool"`, or a raw JSON dict. */
export type CapabilityLike = Capability | string;

/** The argument must equal this JSON value exactly. */
export function equals(value: unknown): Constraint {
  return { op: "equals", value };
}

/** The argument must equal one of these values. Accepts `oneOf("a", "b")` or `oneOf(["a", "b"])`. */
export function oneOf(...values: unknown[]): Constraint {
  const list = values.length === 1 && Array.isArray(values[0]) ? [...values[0]] : values;
  return { op: "one_of", value: list };
}

/** The argument must be a string starting with `value`. */
export function prefix(value: string): Constraint {
  return { op: "prefix", value };
}

function isConstraint(v: unknown): v is Constraint {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    (o.op === "equals" && "value" in o) ||
    (o.op === "one_of" && Array.isArray(o.value)) ||
    (o.op === "prefix" && typeof o.value === "string")
  );
}

/**
 * `server:tool` plus optional per-argument constraints. A bare value is shorthand for `equals`:
 *
 * ```ts
 * capability("github", "create_issue", { repo: oneOf("acme/api", "acme/web"), draft: false })
 * ```
 */
export function capability(
  server: string,
  tool: string,
  constraints: Record<string, unknown> = {},
): Capability {
  if (!server || !tool) throw new TypeError("a capability needs a non-empty server and tool");
  const entries = Object.entries(constraints)
    .map(([k, v]): [string, Constraint] => [k, isConstraint(v) ? v : equals(v)])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const cap: Capability = { server, tool };
  if (entries.length > 0) cap.constraints = Object.fromEntries(entries);
  return cap;
}

function isCount(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

const DERIVATIONS: readonly string[] = ["host"];

/**
 * Check a `limits` object and return a normalized copy. A kind or derivation this SDK does not
 * know is refused, as the server refuses it, rather than dropped.
 */
function checkLimits(raw: unknown): Limits {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new TypeError("limits must be an object");
  }
  const out: Limits = {};
  for (const [kind, v] of Object.entries(raw as Record<string, unknown>)) {
    if (kind === "calls") {
      if (!isCount(v)) throw new TypeError("limits.calls must be an integer >= 0");
      out.calls = v;
    } else if (kind === "sum" || kind === "calls_per" || kind === "distinct") {
      const o = v as Record<string, unknown> | null;
      const allowed = kind === "sum" ? ["arg", "max"] : ["arg", "max", "derive"];
      const ok =
        typeof o === "object" &&
        o !== null &&
        Object.keys(o).every((k) => allowed.includes(k)) &&
        typeof o.arg === "string" &&
        o.arg !== "" &&
        isCount(o.max) &&
        (o.derive === undefined || DERIVATIONS.includes(o.derive as string));
      if (!ok) {
        const shape =
          kind === "sum"
            ? "{arg: string, max: integer >= 0}"
            : '{arg: string, max: integer >= 0, derive?: "host"}';
        throw new TypeError(`limits.${kind} must be ${shape}`);
      }
      const lim: ArgLimit = { arg: o.arg as string, max: o.max as number };
      if (o.derive !== undefined) lim.derive = o.derive as Derive;
      out[kind] = lim;
    } else {
      throw new TypeError(
        `unknown limit kind ${JSON.stringify(kind)} (one of calls, sum, calls_per, distinct)`,
      );
    }
  }
  return out;
}

/** What a limit counts as the server names it: `arg`, or `arg#host` for a derived value. */
export function countedArg(l: ArgLimit): string {
  return l.derive === undefined ? l.arg : `${l.arg}#${l.derive}`;
}

/** A copy of `cap` carrying run `limits` (ADR-0010); an empty object removes them. */
export function withLimits(cap: Capability, limits: Limits): Capability {
  const out: Capability = { ...cap };
  const checked = checkLimits(limits);
  if (Object.keys(checked).length > 0) out.limits = checked;
  else delete out.limits;
  return out;
}

/** `"github:read_file"` becomes `capability("github", "read_file")`. */
export function parseCapability(text: string): Capability {
  const t = text.trim();
  const i = t.indexOf(":");
  const server = i < 0 ? "" : t.slice(0, i);
  const tool = i < 0 ? "" : t.slice(i + 1);
  if (!server || !tool)
    throw new TypeError(`capability ${JSON.stringify(text)} must look like 'server:tool'`);
  return capability(server, tool);
}

function fromJson(obj: Capability): Capability {
  const raw = obj.constraints ?? {};
  for (const [k, c] of Object.entries(raw)) {
    if (!isConstraint(c)) {
      throw new TypeError(`capability ${obj.server}:${obj.tool}: unknown constraint for ${k}`);
    }
  }
  const cap = capability(obj.server, obj.tool, raw);
  return obj.limits === undefined ? cap : withLimits(cap, obj.limits);
}

/**
 * Normalize capabilities (objects, `"server:tool"` strings, raw dicts) to wire JSON. A
 * comma-separated string such as `"github:read_file,github:create_issue"` is split, like the CLI's
 * `--cap`.
 */
export function capabilitiesToJson(caps: CapabilityLike | readonly CapabilityLike[]): Capability[] {
  const items: readonly CapabilityLike[] =
    typeof caps === "string" || !Array.isArray(caps) ? [caps as CapabilityLike] : caps;
  const out: Capability[] = [];
  for (const item of items) {
    if (typeof item === "string") {
      for (const part of item.split(",")) if (part.trim()) out.push(parseCapability(part));
    } else {
      out.push(fromJson(item));
    }
  }
  return out;
}

/**
 * Human-readable form: `github:read_file{repo={"op":"prefix","value":"alice/"}}`, with run
 * limits after it: `banking:send_money[calls<=1,sum(amount)<=10]`, or
 * `web:get_webpage[distinct(url#host)<=2]`.
 */
export function formatCapability(cap: Capability): string {
  let out = `${cap.server}:${cap.tool}`;
  const cs = Object.entries(cap.constraints ?? {});
  if (cs.length > 0) out += `{${cs.map(([k, c]) => `${k}=${JSON.stringify(c)}`).join(",")}}`;
  const l = cap.limits ?? {};
  const ls: string[] = [];
  if (l.calls !== undefined) ls.push(`calls<=${l.calls}`);
  if (l.sum) ls.push(`sum(${l.sum.arg})<=${l.sum.max}`);
  if (l.calls_per) ls.push(`calls_per(${countedArg(l.calls_per)})<=${l.calls_per.max}`);
  if (l.distinct) ls.push(`distinct(${countedArg(l.distinct)})<=${l.distinct.max}`);
  if (ls.length > 0) out += `[${ls.join(",")}]`;
  return out;
}

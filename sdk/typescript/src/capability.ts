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
 */

export type Constraint =
  | { op: "equals"; value: unknown }
  | { op: "one_of"; value: unknown[] }
  | { op: "prefix"; value: string };

export interface Capability {
  server: string;
  tool: string;
  constraints?: Record<string, Constraint>;
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
  return capability(obj.server, obj.tool, raw);
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

/** Human-readable form: `github:read_file{repo={"op":"prefix","value":"alice/"}}`. */
export function formatCapability(cap: Capability): string {
  const base = `${cap.server}:${cap.tool}`;
  const cs = Object.entries(cap.constraints ?? {});
  if (cs.length === 0) return base;
  return `${base}{${cs.map(([k, c]) => `${k}=${JSON.stringify(c)}`).join(",")}}`;
}

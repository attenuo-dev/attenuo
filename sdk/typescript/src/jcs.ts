/**
 * RFC 8785 JSON Canonicalization Scheme, and the strict JSON parser the audit verifier reads
 * exports with.
 *
 * `canonicalize` relies on two facts about JavaScript: `JSON.stringify` of a string escapes
 * exactly what RFC 8785 section 3.2.2.2 prescribes (`"`, `\`, `\b \f \n \r \t`, other control
 * characters as lowercase `\u00xx`, nothing else), and `Number.prototype.toString` is the
 * ECMAScript number-to-string algorithm RFC 8785 section 3.2.2.3 names. Object members are
 * sorted by UTF-16 code units, which is what the default string comparison does.
 *
 * Numbers are doubles, as in RFC 8785. The Rust side keeps the digits of integers beyond 2^53;
 * a double cannot, so `parseJson` refuses such an integer literal instead of rounding it.
 */

import { AttenuoError } from "./errors.js";

export type JsonValue =
  null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** The RFC 8785 canonical form of `value`. Throws on `NaN`, `Infinity` and unsafe integers. */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new AttenuoError("JCS: non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const members: string[] = [];
      for (const k of keys) {
        if (obj[k] === undefined) continue;
        members.push(`${JSON.stringify(k)}:${canonicalize(obj[k])}`);
      }
      return `{${members.join(",")}}`;
    }
    default:
      throw new AttenuoError(`JCS: cannot encode a ${typeof value}`);
  }
}

const MAX_DEPTH = 256;
const NUMBER = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;

/**
 * Where a parse found numbers written with a fraction or an exponent (`10.0`, `1e1`): for each
 * object or array, the member names or indexes that held one. A double cannot tell `10.0` from
 * `10`, so a reader that wants an integer, as Rust's `u64` does, asks this map instead.
 */
export type FractionMarks = WeakMap<object, Set<string | number>>;

/**
 * Parse JSON text strictly: RFC 8259 grammar only, duplicate object members are an error, and
 * an integer literal beyond 2^53 is an error rather than a silent rounding. Throws
 * `AttenuoError` with the offset of the problem. When `marks` is given, it records where a
 * number was written with a fraction or an exponent.
 */
export function parseJson(text: string, marks?: FractionMarks): JsonValue {
  return parseValues(text, false, marks)[0] as JsonValue;
}

/**
 * Parse text that holds JSON values one after the other, as `parseJson` parses one: S3 objects
 * joined with `cat`, which adds no newline between them. Whitespace alone gives `[]`.
 */
export function parseJsonValues(text: string, marks?: FractionMarks): JsonValue[] {
  return parseValues(text, true, marks);
}

function parseValues(text: string, many: boolean, marks?: FractionMarks): JsonValue[] {
  let i = 0;
  // Whether the value `value` just returned was a number written with a fraction or exponent.
  let fraction = false;
  const mark = (container: object, key: string | number): void => {
    if (marks === undefined) return;
    let set = marks.get(container);
    if (set === undefined) {
      set = new Set();
      marks.set(container, set);
    }
    set.add(key);
  };
  const fail = (msg: string): never => {
    throw new AttenuoError(`invalid JSON at offset ${i}: ${msg}`);
  };
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text[i] as string)) i++;
  };
  const string = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      const c = text.charCodeAt(i);
      if (Number.isNaN(c)) return fail("unterminated string");
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c < 0x20) return fail("control character in string");
      if (c !== 0x5c) {
        out += text[i];
        i++;
        continue;
      }
      const e = text[i + 1];
      i += 2;
      switch (e) {
        case '"':
        case "\\":
        case "/":
          out += e;
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) return fail("bad \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          break;
        }
        default:
          return fail("bad escape");
      }
    }
  };
  const value = (depth: number): JsonValue => {
    fraction = false;
    const v = parseValue(depth);
    fraction = typeof v === "number" && fraction;
    return v;
  };
  const parseValue = (depth: number): JsonValue => {
    if (depth > MAX_DEPTH) return fail("nested too deeply");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: { [key: string]: JsonValue } = {};
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') return fail("expected a member name");
        const k = string();
        if (Object.prototype.hasOwnProperty.call(obj, k)) return fail(`duplicate member "${k}"`);
        ws();
        if (text[i] !== ":") return fail("expected ':'");
        i++;
        const v = value(depth + 1);
        if (fraction) mark(obj, k);
        // `__proto__` must stay an own property, not set the prototype.
        Object.defineProperty(obj, k, {
          value: v,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        return fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr: JsonValue[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value(depth + 1));
        if (fraction) mark(arr, arr.length - 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        return fail("expected ',' or ']'");
      }
    }
    if (c === '"') return string();
    for (const [word, v] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) return fail("unexpected character");
    i += m[0].length;
    const n = Number(m[0]);
    if (m[1] === undefined && m[2] === undefined && !Number.isSafeInteger(n)) {
      return fail(`integer ${m[0]} is beyond 2^53`);
    }
    if (!Number.isFinite(n)) return fail("number out of range");
    fraction = m[1] !== undefined || m[2] !== undefined;
    return n;
  };
  if (!many) {
    const v = value(0);
    ws();
    if (i < text.length) fail("trailing characters");
    return [v];
  }
  const out: JsonValue[] = [];
  ws();
  while (i < text.length) {
    out.push(value(0));
    ws();
  }
  return out;
}

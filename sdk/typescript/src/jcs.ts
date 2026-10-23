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

import { OnbehalfError } from "./errors.js";

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
      if (!Number.isFinite(value)) throw new OnbehalfError("JCS: non-finite number");
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
      throw new OnbehalfError(`JCS: cannot encode a ${typeof value}`);
  }
}

const MAX_DEPTH = 256;
const NUMBER = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;

/**
 * Parse JSON text strictly: RFC 8259 grammar only, duplicate object members are an error, and
 * an integer literal beyond 2^53 is an error rather than a silent rounding. Throws
 * `OnbehalfError` with the offset of the problem.
 */
export function parseJson(text: string): JsonValue {
  let i = 0;
  const fail = (msg: string): never => {
    throw new OnbehalfError(`invalid JSON at offset ${i}: ${msg}`);
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
        // `__proto__` must stay an own property, not set the prototype.
        Object.defineProperty(obj, k, {
          value: value(depth + 1),
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
    return n;
  };
  const v = value(0);
  ws();
  if (i < text.length) fail("trailing characters");
  return v;
}

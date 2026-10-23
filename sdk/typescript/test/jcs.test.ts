import { describe, expect, it } from "vitest";
import { canonicalize, parseJson } from "../src/jcs.js";

// The known answers are the RFC 8785 examples (sections 3.2.2, 3.2.3 and Appendix B), the same
// ones crates/onbehalf-core/src/jcs.rs checks against the Rust implementation.
const canon = (text: string): string => canonicalize(parseJson(text));

const hex = (s: string): string => Buffer.from(s, "utf8").toString("hex");

describe("canonicalize: RFC 8785 vectors", () => {
  it("arrays", () => {
    expect(canon('[56, {"d": true, "10": null, "1": [ ]}]')).toBe(
      '[56,{"1":[],"10":null,"d":true}]',
    );
  });

  it("french: sorting ignores locale", () => {
    expect(
      canon(`{"peach": "This sorting order", "péché": "is wrong according to French",
                "pêche": "but canonicalization MUST", "sin": "ignore locale"}`),
    ).toBe(
      '{"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}',
    );
  });

  it("structures", () => {
    expect(
      canon(`{"1": {"f": {"f": "hi","F": 5} ,"\\n": 56.0}, "10": { }, "": "empty",
                "a": { }, "111": [ {"e": "yes","E": "no" } ], "A": { }}`),
    ).toBe(
      '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}',
    );
  });

  it("unicode is not normalized", () => {
    expect(canon('{"Unnormalized Unicode":"A\\u030a"}')).toBe('{"Unnormalized Unicode":"Å"}');
  });

  it("values (section 3.2.2)", () => {
    expect(
      canon(`{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
                "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\"\\/",
                "literals": [null, true, false]}`),
    ).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  it("sorts member names by UTF-16 code units (section 3.2.3)", () => {
    const out = canon(`{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", "\\u000a": "Newline",
                "1": "One", "\\u0080": "Control\\u007f", "\\ud83d\\ude02": "Smiley",
                "\\u00f6": "Latin Small Letter O With Diaeresis",
                "\\ufb33": "Hebrew Letter Dalet With Dagesh", "</script>": "Browser Challenge"}`);
    expect(hex(out)).toBe(
      "7b225c6e223a224e65776c696e65222c225c72223a2243617272696167652052" +
        "657475726e222c2231223a224f6e65222c223c2f7363726970743e223a224272" +
        "6f77736572204368616c6c656e6765222c22c280223a22436f6e74726f6c7f22" +
        "2c22c3b6223a224c6174696e20536d616c6c204c6574746572204f2057697468" +
        "20446961657265736973222c22e282ac223a224575726f205369676e222c22f0" +
        "9f9882223a22536d696c6579222c22efacb3223a22486562726577204c657474" +
        "65722044616c6574205769746820446167657368227d",
    );
  });

  it("Appendix B: IEEE 754 doubles", () => {
    const cases: Array<[bigint, string | null]> = [
      [0x0000000000000000n, "0"],
      [0x8000000000000000n, "0"],
      [0x0000000000000001n, "5e-324"],
      [0x8000000000000001n, "-5e-324"],
      [0x7fefffffffffffffn, "1.7976931348623157e+308"],
      [0xffefffffffffffffn, "-1.7976931348623157e+308"],
      [0x4340000000000000n, "9007199254740992"],
      [0xc340000000000000n, "-9007199254740992"],
      [0x4430000000000000n, "295147905179352830000"],
      [0x7fffffffffffffffn, null],
      [0x7ff0000000000000n, null],
      [0x44b52d02c7e14af5n, "9.999999999999997e+22"],
      [0x44b52d02c7e14af6n, "1e+23"],
      [0x44b52d02c7e14af7n, "1.0000000000000001e+23"],
      [0x444b1ae4d6e2ef4en, "999999999999999700000"],
      [0x444b1ae4d6e2ef4fn, "999999999999999900000"],
      [0x444b1ae4d6e2ef50n, "1e+21"],
      [0x3eb0c6f7a0b5ed8cn, "9.999999999999997e-7"],
      [0x3eb0c6f7a0b5ed8dn, "0.000001"],
      [0x41b3de4355555553n, "333333333.3333332"],
      [0x41b3de4355555554n, "333333333.33333325"],
      [0x41b3de4355555555n, "333333333.3333333"],
      [0x41b3de4355555556n, "333333333.3333334"],
      [0x41b3de4355555557n, "333333333.33333343"],
      [0xbecbf647612f3696n, "-0.0000033333333333333333"],
      [0x43143ff3c1cb0959n, "1424953923781206.2"],
    ];
    for (const [bits, want] of cases) {
      const dv = new DataView(new ArrayBuffer(8));
      dv.setBigUint64(0, bits);
      const v = dv.getFloat64(0);
      if (want === null) expect(() => canonicalize(v), bits.toString(16)).toThrow();
      else expect(canonicalize(v), bits.toString(16)).toBe(want);
    }
  });

  it("escapes control characters in lowercase and leaves the rest alone", () => {
    const s = Array.from({ length: 0x20 }, (_, i) => String.fromCharCode(i)).join("") + "\u007f /";
    expect(canonicalize(s)).toBe(
      '"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r' +
        "\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018" +
        '\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\u007f /"',
    );
    expect(JSON.parse(canonicalize(s))).toBe(s);
  });

  it("member order does not matter; non-finite numbers are refused", () => {
    expect(canonicalize({ b: { y: 1, x: 2 }, a: [{ d: 0, c: 1 }] })).toBe(
      '{"a":[{"c":1,"d":0}],"b":{"x":2,"y":1}}',
    );
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize(() => 1)).toThrow();
  });
});

describe("parseJson", () => {
  it("parses what JSON.parse parses", () => {
    const text = '{"a":[1,-2.5e3,true,null,"x\\u00e9\\ud83d\\ude02"],"b":{}}';
    expect(parseJson(text)).toEqual(JSON.parse(text));
    expect(parseJson(" \n[ ] \t")).toEqual([]);
  });

  it("refuses duplicates, big integers, bad grammar and deep nesting", () => {
    for (const bad of [
      '{"a":1,"a":2}',
      "9007199254740993",
      "[1,]",
      "{'a':1}",
      '{"a":1',
      '"\\x"',
      '"a\nb"',
      "01",
      "NaN",
      "[1] x",
      "1e999",
      "[".repeat(300) + "]".repeat(300),
    ]) {
      expect(() => parseJson(bad), bad.slice(0, 20)).toThrow();
    }
  });

  it("keeps __proto__ as plain data", () => {
    const v = parseJson('{"__proto__":{"x":1}}') as Record<string, unknown>;
    expect(Object.keys(v)).toEqual(["__proto__"]);
    expect(({} as Record<string, unknown>).x).toBeUndefined();
    expect(canonicalize(v)).toBe('{"__proto__":{"x":1}}');
  });
});

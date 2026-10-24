import { describe, expect, it } from "vitest";
import {
  capabilitiesToJson,
  capability,
  equals,
  formatCapability,
  oneOf,
  parseCapability,
  prefix,
  withLimits,
} from "../src/index.js";

describe("capability", () => {
  it("serializes constraints like the Rust Capability", () => {
    expect(capability("github", "read_file", { repo: prefix("alice/public-") })).toEqual({
      server: "github",
      tool: "read_file",
      constraints: { repo: { op: "prefix", value: "alice/public-" } },
    });
  });

  it("omits empty constraints", () => {
    expect(JSON.stringify(capability("github", "read_file"))).toBe(
      '{"server":"github","tool":"read_file"}',
    );
  });

  it("treats a bare value as equals and sorts keys", () => {
    const cap = capability("g", "t", { b: 1, a: oneOf("x", "y"), c: equals(["z"]) });
    expect(Object.keys(cap.constraints!)).toEqual(["a", "b", "c"]);
    expect(cap.constraints).toEqual({
      a: { op: "one_of", value: ["x", "y"] },
      b: { op: "equals", value: 1 },
      c: { op: "equals", value: ["z"] },
    });
  });

  it("accepts oneOf with an array", () => {
    expect(oneOf(["a", "b"])).toEqual({ op: "one_of", value: ["a", "b"] });
  });

  it("rejects empty server or tool", () => {
    expect(() => capability("", "t")).toThrow(TypeError);
    expect(() => capability("s", "")).toThrow(TypeError);
  });

  it("parses server:tool and splits comma lists", () => {
    expect(parseCapability(" github:read_file ")).toEqual({ server: "github", tool: "read_file" });
    expect(() => parseCapability("nope")).toThrow(/server:tool/);
    expect(capabilitiesToJson("github:read_file, github:create_issue")).toEqual([
      { server: "github", tool: "read_file" },
      { server: "github", tool: "create_issue" },
    ]);
  });

  it("normalizes mixed inputs", () => {
    expect(
      capabilitiesToJson([
        "a:b",
        capability("c", "d", { x: prefix("p") }),
        { server: "e", tool: "f", constraints: { y: { op: "equals", value: 2 } } },
      ]),
    ).toEqual([
      { server: "a", tool: "b" },
      { server: "c", tool: "d", constraints: { x: { op: "prefix", value: "p" } } },
      { server: "e", tool: "f", constraints: { y: { op: "equals", value: 2 } } },
    ]);
    expect(capabilitiesToJson(capability("a", "b"))).toHaveLength(1);
  });

  it("rejects an unknown constraint op in raw JSON", () => {
    const bad = { server: "a", tool: "b", constraints: { x: { op: "glob", value: "*" } } };
    expect(() => capabilitiesToJson([bad as never])).toThrow(/unknown constraint/);
  });

  it("formats for humans", () => {
    expect(formatCapability(capability("g", "t"))).toBe("g:t");
    expect(formatCapability(capability("g", "t", { r: prefix("a/") }))).toBe(
      'g:t{r={"op":"prefix","value":"a/"}}',
    );
  });

  it("carries run limits and refuses kinds it does not know", () => {
    const wire = {
      server: "banking",
      tool: "send_money",
      limits: {
        calls: 1,
        sum: { arg: "amount", max: 10 },
        calls_per: { arg: "recipient", max: 1 },
      },
    };
    const cap = withLimits(capability("banking", "send_money"), wire.limits);
    expect(cap).toEqual(wire);
    expect(capabilitiesToJson([wire])).toEqual([wire]);
    expect(formatCapability(cap)).toBe(
      "banking:send_money[calls<=1,sum(amount)<=10,calls_per(recipient)<=1]",
    );
    expect(withLimits(cap, {})).toEqual({ server: "banking", tool: "send_money" });
    for (const bad of [
      { distinct: { arg: "to", max: 1 } },
      { calls: -1 },
      { calls: 1.5 },
      { sum: { arg: "amount" } },
    ]) {
      expect(() => capabilitiesToJson([{ server: "b", tool: "t", limits: bad as never }])).toThrow(
        TypeError,
      );
    }
  });
});

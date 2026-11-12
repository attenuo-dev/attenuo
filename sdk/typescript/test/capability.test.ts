import { describe, expect, it } from "vitest";
import {
  capabilitiesToJson,
  capability,
  equals,
  formatCapability,
  oneOf,
  parseCapability,
  pathPrefix,
  pathProblem,
  prefix,
  range,
  withLimits,
  argLimit,
  countedArg,
} from "../src/index.js";
import type { Capability } from "../src/index.js";

describe("capability", () => {
  it("serializes constraints like the Rust Capability", () => {
    expect(capability("github", "read_file", { repo: prefix("alice/public-") })).toEqual({
      server: "github",
      tool: "read_file",
      constraints: { repo: { op: "prefix", value: "alice/public-" } },
    });
  });

  it("serializes pathPrefix like the Rust Capability and reads it back", () => {
    const cap = capability("fs", "read_file", {
      path: pathPrefix("/workspace/"),
      dir: pathPrefix("docs"),
    });
    expect(cap.constraints).toEqual({
      dir: { op: "path_prefix", value: "docs" },
      path: { op: "path_prefix", value: "/workspace/" },
    });
    expect(capabilitiesToJson([cap])).toEqual([cap]);
    expect(pathPrefix("/w")).not.toEqual(prefix("/w"));
  });

  it("refuses a path_prefix path the server refuses, saying why", () => {
    const cases: [string, string][] = [
      ["", "is empty"],
      ["/workspace/../etc", "holds a `.` or `..` segment"],
      ["/workspace/..", "holds a `.` or `..` segment"],
      ["./src", "holds a `.` or `..` segment"],
      ["/workspace/.", "holds a `.` or `..` segment"],
      ["/workspace//a", "holds an empty segment (`//`)"],
      ["//workspace", "holds an empty segment (`//`)"],
      ["C:\\work", "holds a backslash"],
      ["/w\u0000", "holds a control character"],
      ["/w\tx", "holds a control character"],
      ["/w\u007f", "holds a control character"],
      ["/w\u0085", "holds a control character"],
      ["/w/%2e%2e", "holds a percent-encoded `.`, `/` or `\\`"],
      ["/w/%2E", "holds a percent-encoded `.`, `/` or `\\`"],
      ["/w%2Fx", "holds a percent-encoded `.`, `/` or `\\`"],
      ["/w%5cx", "holds a percent-encoded `.`, `/` or `\\`"],
    ];
    for (const [path, why] of cases) {
      expect(pathProblem(path), path).toBe(why);
      expect(() => pathPrefix(path), path).toThrow(`a path_prefix constraint's path ${why}`);
      expect(
        () =>
          capabilitiesToJson([
            { server: "s", tool: "t", constraints: { p: { op: "path_prefix", value: path } } },
          ]),
        path,
      ).toThrow(TypeError);
    }
    for (const ok of ["/", "/workspace", "/workspace/", "docs", "a/b/", "~/x", "/a%20b", "/..."]) {
      expect(pathProblem(ok), ok).toBeUndefined();
      expect(pathPrefix(ok)).toEqual({ op: "path_prefix", value: ok });
    }
    expect(() => pathPrefix(1 as unknown as string)).toThrow(TypeError);
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

  it("serializes a range like the server, a missing bound omitted", () => {
    const cap = capability("banking", "send_money", {
      amount: range({ min: 0, max: 2000 }),
      fee: range({ max: 5 }),
    });
    expect(cap.constraints).toEqual({
      amount: { op: "range", value: { min: 0, max: 2000 } },
      fee: { op: "range", value: { max: 5 } },
    });
    expect(JSON.stringify(range({ min: -3, max: undefined }))).toBe(
      '{"op":"range","value":{"min":-3}}',
    );
    expect(capabilitiesToJson([cap])).toEqual([cap]);
  });

  it("refuses a malformed range in the builder and in raw JSON", () => {
    for (const bad of [{}, { min: 3, max: 2 }, { min: 1.5 }, { max: 2 ** 63 }]) {
      expect(() => range(bad)).toThrow(TypeError);
    }
    for (const value of [{}, { min: 3, max: 2 }, { min: 0, maximum: 10 }, [0, 10], { max: "5" }]) {
      const raw = { server: "s", tool: "t", constraints: { n: { op: "range", value } } };
      expect(() => capabilitiesToJson([raw as never])).toThrow(/unknown constraint/);
    }
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
      { window: { arg: "to", max: 1 } },
      { calls: -1 },
      { calls: 1.5 },
      { sum: { arg: "amount" } },
      { sum: { arg: "url", max: 1, derive: "host" } },
      { distinct: { arg: "url", max: 1, derive: "path" } },
      { distinct: { arg: "", max: 1 } },
      { calls_per: { arg: "to", max: 1, extra: 1 } },
    ]) {
      expect(() => capabilitiesToJson([{ server: "b", tool: "t", limits: bad as never }])).toThrow(
        TypeError,
      );
    }
  });

  it("types distinct and derived limits for a child token", () => {
    const cap = withLimits(capability("web", "get_webpage"), {
      calls: 5,
      distinct: argLimit("url", 2, { derive: "host" }),
    });
    const wire = {
      server: "web",
      tool: "get_webpage",
      limits: { calls: 5, distinct: { arg: "url", max: 2, derive: "host" } },
    };
    expect(cap).toEqual(wire);
    expect(capabilitiesToJson([wire as Capability])).toEqual([wire]);
    expect(formatCapability(cap)).toBe("web:get_webpage[calls<=5,distinct(url#host)<=2]");
    expect(countedArg(argLimit("to", 1))).toBe("to");
    const mail = withLimits(capability("mail", "send"), {
      calls_per: argLimit("to", 1),
      distinct: argLimit("to", 3),
    });
    expect(mail.limits).toEqual({
      calls_per: { arg: "to", max: 1 },
      distinct: { arg: "to", max: 3 },
    });
  });
});

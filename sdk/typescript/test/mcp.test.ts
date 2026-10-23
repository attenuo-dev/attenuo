import { describe, expect, it } from "vitest";
import { decodeToken, mcpHeaders, mcpUrl } from "../src/index.js";
import { Signer } from "./helpers.js";

describe("mcp helpers", () => {
  it("builds the proxy URL", () => {
    expect(mcpUrl("http://127.0.0.1:8080/", "github")).toBe("http://127.0.0.1:8080/mcp/github");
    expect(() => mcpUrl("github", "x")).toThrow(/base URL/);
  });

  it("produces just Authorization by default", () => {
    expect(mcpHeaders("abc")).toEqual({ Authorization: "Bearer abc" });
  });

  it("adds a session id and content headers on request", async () => {
    const tok = decodeToken(await (await Signer.create()).mint());
    expect(mcpHeaders(tok, "s1", { contentHeaders: true })).toEqual({
      Authorization: `Bearer ${tok.jwt}`,
      "Mcp-Session-Id": "s1",
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    });
  });

  it("requires a token", () => {
    expect(() => mcpHeaders(undefined as never)).toThrow(/no token/);
  });
});

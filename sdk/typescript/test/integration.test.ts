/**
 * The GitHub-leak scenario through the SDK, against the real server and a fake MCP upstream.
 *
 * Skipped unless `ATTENUO_INTEGRATION=1`. Needs prebuilt binaries: `attenuo-server` and
 * `examples/fake_mcp` in `ATTENUO_BIN_DIR` (default `<repo>/.bin`). Build them with
 *
 *   cargo build -p attenuo-server && cargo build -p attenuo-proxy --example fake_mcp
 *
 * and copy `target/debug/attenuo-server` and `target/debug/examples/fake_mcp` there. Starts both
 * on free ports with the demo config from `examples/github-leak-demo` and plays `run.sh`.
 */

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  createWriteStream,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AdminClient,
  ApiError,
  capability,
  DeniedError,
  DpopKey,
  mcpFetch,
  mcpUrl,
  AttenuoClient,
  prefix,
  RefreshError,
  type Token,
  TokenRefresher,
  UnauthorizedError,
  VerificationError,
  ExportError,
  verifyExport,
  withLimits,
} from "../src/index.js";

// [[agents]] secrets in the demo config: an exchange authenticates as its actor.
const CODER_SECRET = "demo-coder-secret";
const TESTER_SECRET = "demo-tester-secret";

const enabled = process.env.ATTENUO_INTEGRATION === "1";
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const DEMO = join(ROOT, "examples", "github-leak-demo");
const ADMIN_TOKEN = "demo-admin-token";

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = createServer();
    s.on("error", fail);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => ok(port));
    });
  });
}

function binaries(): { server: string; fake: string } {
  const dir = process.env.ATTENUO_BIN_DIR ?? join(ROOT, ".bin");
  const server = join(dir, "attenuo-server");
  const fake = [join(dir, "examples", "fake_mcp"), join(dir, "fake_mcp")].find(existsSync);
  if (!existsSync(server) || !fake) {
    throw new Error(
      `attenuo-server / fake_mcp not found in ${dir}; build them and set ATTENUO_BIN_DIR (see this file's header)`,
    );
  }
  return { server, fake };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Start the fake upstream and the server with the demo config, plus `tokenSection` (a `[token]`
 * table) when given and `fakeArgs` for the upstream; resolves once both answer.
 */
async function startStack(
  tokenSection = "",
  fakeArgs: string[] = [],
): Promise<{ url: string; work: string; procs: ChildProcess[] }> {
  const work = mkdtempSync(join(tmpdir(), "attenuo-it-"));
  const procs: ChildProcess[] = [];
  const built = binaries();
  // Copy them: a shared CARGO_TARGET_DIR can be rebuilt under us mid-test.
  const serverBin = join(work, "attenuo-server");
  const fakeBin = join(work, "fake_mcp");
  copyFileSync(built.server, serverBin);
  copyFileSync(built.fake, fakeBin);

  const obPort = await freePort();
  let mcpPort = await freePort();
  while (mcpPort === obPort) mcpPort = await freePort();
  const config = readFileSync(join(DEMO, "config.toml"), "utf8")
    .replaceAll("18080", String(obPort))
    .replaceAll("13001", String(mcpPort))
    .replaceAll("examples/github-leak-demo/policy.cedar", join(DEMO, "policy.cedar"))
    .replace("[audit]\n", `${tokenSection}[audit]\n`);
  writeFileSync(join(work, "config.toml"), config);

  const fakeOut = join(work, "fake-mcp.out");
  const fakeLog = join(work, "fake-mcp.log");
  const serverLog = join(work, "server.log");
  const out = (path: string) => createWriteStream(path);
  const fakeOutS = out(fakeOut);
  const fakeLogS = out(fakeLog);
  const serverLogS = out(serverLog);
  await Promise.all(
    [fakeOutS, fakeLogS, serverLogS].map((s) => new Promise((r) => s.once("open", r))),
  );
  procs.push(
    spawn(fakeBin, ["--port", String(mcpPort), ...fakeArgs], {
      stdio: ["ignore", fakeOutS, fakeLogS],
    }),
    spawn(serverBin, ["--config", join(work, "config.toml")], {
      stdio: ["ignore", serverLogS, serverLogS],
      env: { ...process.env, RUST_LOG: "warn" },
    }),
  );
  const url = `http://127.0.0.1:${obPort}`;

  const deadline = Date.now() + 20_000;
  for (;;) {
    let ready = false;
    try {
      ready = (await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1000) })).ok;
    } catch {
      /* not up yet */
    }
    if (ready && readFileSync(fakeOut, "utf8").includes("listening")) break;
    for (const p of procs) {
      if (p.exitCode !== null) {
        throw new Error(`a server exited early:\n${readFileSync(serverLog, "utf8")}`);
      }
    }
    if (Date.now() > deadline) {
      throw new Error(`server did not start:\n${readFileSync(serverLog, "utf8")}`);
    }
    await sleep(100);
  }
  return { url, work, procs };
}

async function stopStack(procs: ChildProcess[], work: string): Promise<void> {
  for (const p of procs) p.kill("SIGTERM");
  await sleep(200);
  for (const p of procs) if (p.exitCode === null) p.kill("SIGKILL");
  if (work) rmSync(work, { recursive: true, force: true });
}

describe.skipIf(!enabled)("GitHub leak scenario against the real server", () => {
  let procs: ChildProcess[] = [];
  let work = "";
  let url = "";

  beforeAll(async () => {
    ({ url, work, procs } = await startStack());
  });

  afterAll(async () => {
    await stopStack(procs, work);
  });

  const upstreamCalls = () =>
    readFileSync(join(work, "fake-mcp.log"), "utf8")
      .split("\n")
      .filter((l) => l.includes("tools/call"));

  it("replays the scenario", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);

    // 1. A broad root token for Alice's assistant (dev mint: no IdP in this setup).
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    expect(root.subject).toBe("alice");
    expect(root.agent).toBe("assistant");
    expect(root.chain.hops).toHaveLength(1);

    // 2. The assistant hands its coder read_file and nothing else.
    const coder = await ob.exchange(root, "coder", [capability("github", "read_file")], {
      ttlSeconds: 600,
      clientSecret: CODER_SECRET,
    });
    expect(coder.agents).toEqual(["assistant", "coder"]);
    expect(coder.capabilities).toEqual([{ server: "github", tool: "read_file" }]);
    expect(coder.lease).not.toBe(root.lease);

    // 3. The token verifies against the server's JWKS; a tampered copy does not.
    const verified = await ob.inspect(coder, { verify: true, issuer: url, audience: "attenuo" });
    expect(verified.verified).toBe(true);
    expect(verified.chain).toEqual(coder.chain);
    const [head, payload, sig] = coder.jwt.split(".") as [string, string, string];
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    await expect(
      ob.inspect(`${head}.${payload}.${flipped}`, { verify: true }),
    ).rejects.toBeInstanceOf(VerificationError);

    // 4. Tools visible to the coder: only what it may call.
    const names = (await ob.listTools(coder, "github")).map((t) => t.name);
    expect(names).toContain("read_file");
    expect(names).not.toContain("create_issue");

    // 5. The intended read: allowed, forwarded upstream.
    const ok = await ob.callTool(coder, "github", "read_file", {
      repo: "alice/public-docs",
      path: "README.md",
    });
    expect(ok.isError).toBe(false);
    expect(ok.decisionId).toBeTruthy();
    const allowedDecision = ok.decisionId!;

    // 6. The AuthZEN endpoint agrees with the proxy, and nothing reaches upstream.
    expect(
      (await ob.authzenEvaluate(coder, "github", "read_file", { repo: "alice/public-docs" }))
        .decision,
    ).toBe(true);
    const verdict = await ob.authzenEvaluate(coder, "github", "read_file", {
      repo: "alice/private-salaries",
    });
    expect(verdict.decision).toBe(false);
    expect(verdict.reason).toBe("policy_deny");

    // 7. The injected read of a private repo: the token allows read_file, the policy does not.
    const policyDenied = await ob
      .callTool(coder, "github", "read_file", { repo: "alice/private-salaries", path: "2025.csv" })
      .catch((e: unknown) => e);
    expect(policyDenied).toBeInstanceOf(DeniedError);
    const pd = policyDenied as DeniedError;
    expect(pd.reason).toBe("policy_deny");
    expect(pd.decisionId).toBeTruthy();

    // 8. Exfiltration through create_issue: never delegated.
    const capDenied = (await ob
      .callTool(coder, "github", "create_issue", { repo: "alice/public-docs", title: "leak" })
      .catch((e: unknown) => e)) as DeniedError;
    expect(capDenied).toBeInstanceOf(DeniedError);
    expect(capDenied.reason).toBe("capability_denied");

    // 9. Attenuation is monotonic: the coder cannot widen, and a prefix constraint binds.
    const widen = await ob
      .exchange(coder, "tester", [capability("github", "create_issue")], {
        clientSecret: TESTER_SECRET,
      })
      .catch((e: unknown) => e);
    expect(widen).toBeInstanceOf(ApiError);
    expect(widen).toMatchObject({ status: 400, error: "invalid_scope" });
    const tester = await ob.exchange(
      coder,
      "tester",
      [capability("github", "read_file", { repo: prefix("alice/public-d") })],
      { clientSecret: TESTER_SECRET },
    );
    expect(tester.chain.hops).toHaveLength(3);
    expect(
      (await ob.callTool(tester, "github", "read_file", { repo: "alice/public-docs" })).decisionId,
    ).toBeTruthy();
    const narrowed = await ob
      .callTool(tester, "github", "read_file", { repo: "alice/public-other" })
      .catch((e: unknown) => e);
    expect(narrowed).toMatchObject({ reason: "capability_denied" });

    // 10. Renewal extends the coder's lease.
    const lease = await ob.renew(coder);
    expect(lease.lease).toBe(coder.lease);
    expect(lease.expiresIn).toBeGreaterThan(0);

    // 11. A bad bearer is a 401, not a denial.
    await expect(
      ob.callTool("not.a.token", "github", "read_file", { repo: "alice/public-docs" }),
    ).rejects.toBeInstanceOf(UnauthorizedError);

    // 12. Revoke the root lease: the cascade takes the coder and the tester with it.
    const revoked = await admin.revokeLease(root.lease, "agent session compromised");
    expect(revoked.revoked).toBe(3);
    expect((await admin.leaseStatus(coder.lease)).active).toBe(false);
    const after = (await ob
      .callTool(coder, "github", "read_file", { repo: "alice/public-docs", path: "README.md" })
      .catch((e: unknown) => e)) as DeniedError;
    expect(after).toBeInstanceOf(DeniedError);
    expect(after.reason).toBe("lease_revoked");
    await expect(
      ob.callTool(tester, "github", "read_file", { repo: "alice/public-docs" }),
    ).rejects.toBeInstanceOf(DeniedError);
    await expect(ob.renew(coder)).rejects.toBeInstanceOf(ApiError); // a revoked lease is final

    // 13. The audit log has every decision, and its hash chain verifies.
    const report = await admin.auditVerify();
    expect(report.ok).toBe(true);
    expect(report.entries).toBeGreaterThanOrEqual(8);
    const byId = new Map((await admin.auditTail(200)).map((e) => [e.record.id, e]));
    expect(byId.get(allowedDecision)?.record.decision).toBe("allow");
    expect(byId.get(pd.decisionId)?.record.reason).toBe("policy_deny");
    expect(byId.get(capDenied.decisionId)?.record.reason).toBe("capability_denied");
    expect(byId.get(after.decisionId)?.record.reason).toBe("lease_revoked");
    expect((await admin.auditCheckpoint()).seq).toBeGreaterThanOrEqual(report.entries);

    // 14. Only the intended reads (one for the coder, one for the tester) reached upstream.
    expect(upstreamCalls()).toHaveLength(2);

    // 15. Policy reload works and keeps the policies.
    expect((await admin.policyReload()).policyIds).toContain("read_file_public_repos_only");
  });

  it("binds tokens to keys and refuses them without proofs (SR-24)", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const [assistantKey, coderKey] = await Promise.all([DpopKey.generate(), DpopKey.generate()]);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
      dpopKey: assistantKey,
    });
    expect(root.dpopJkt).toBe(assistantKey.thumbprint);

    // The coder binds its token to its own key. The assistant signs off on this delegation (to
    // the coder's key and agent id) without handing over its own key (SR-40).
    const ob = new AttenuoClient(url, { dpopKey: coderKey.privateJwk() });
    const signOff = (agent: string) =>
      assistantKey.signOff(`${url}/token`, root.jwt, coderKey.thumbprint, agent);
    // A sign-off for another agent is no good.
    const refused = await ob
      .exchange(root, "coder", [capability("github", "read_file")], {
        clientSecret: CODER_SECRET,
        subjectTokenDpop: await signOff("tester"),
      })
      .catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(ApiError);
    expect((refused as ApiError).status).toBe(401);
    const coder = await ob.exchange(root, "coder", [capability("github", "read_file")], {
      clientSecret: CODER_SECRET,
      subjectTokenDpop: await signOff("coder"),
    });
    expect(coder.dpopJkt).toBe(coderKey.thumbprint);
    const ok = await ob.callTool(coder, "github", "read_file", { repo: "alice/public-docs" });
    expect(ok.decisionId).toBeTruthy();
    expect((await ob.listTools(coder, "github")).map((t) => t.name)).toEqual(["read_file"]);
    expect(
      (await ob.authzenEvaluate(coder, "github", "read_file", { repo: "alice/public-x" })).decision,
    ).toBe(true);
    expect((await ob.renew(coder)).expiresIn).toBeGreaterThan(0);

    // An MCP client library's fetch, with a proof per request.
    const keyed = mcpFetch(() => coder, { dpopKey: coderKey });
    const res = await keyed(mcpUrl(url, "github"), {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("read_file");

    // The same token without the key: refused everywhere.
    const thief = new AttenuoClient(url);
    const noProof = await thief
      .callTool(coder, "github", "read_file", { repo: "alice/public-docs" })
      .catch((e: unknown) => e);
    expect(noProof).toBeInstanceOf(UnauthorizedError);
    await expect(thief.renew(coder)).rejects.toMatchObject({ status: 401, error: "dpop_required" });
    await expect(
      thief.exchange(coder, "tester", "github:read_file", { clientSecret: TESTER_SECRET }),
    ).rejects.toMatchObject({ status: 401, error: "dpop_required" });
    // Another key does not help either.
    const other = new AttenuoClient(url, { dpopKey: await DpopKey.generate() });
    await expect(other.renew(coder)).rejects.toMatchObject({ error: "invalid_dpop_proof" });

    // The audit log records the bound use.
    const entries = await admin.auditTail(50);
    expect(entries.find((e) => e.record.id === ok.decisionId)?.dpopBound).toBe(true);
    await admin.revokeLease(root.lease);
  });

  async function until(cond: () => boolean, what: string, ms = 10_000): Promise<void> {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      if (cond()) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`timed out waiting for ${what}`);
  }

  it("keeps a short-lived token alive, then stops on revocation", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    // Each exchange needs a fresh parent: a parent delegates to an actor once.
    const exchange = async () => {
      const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
        capabilities: ["github:*"],
      });
      return ob.exchange(root, "coder", [capability("github", "read_file")], {
        ttlSeconds: 6,
        clientSecret: CODER_SECRET,
      });
    };
    const first = await exchange();
    const changes: Token[] = [];
    const errors: RefreshError[] = [];
    const refresher = new TokenRefresher({
      client: ob,
      token: first,
      exchange,
      onChange: (t) => changes.push(t),
      onError: (e) => errors.push(e),
    });
    const dispose = refresher.start();
    try {
      await until(() => changes.length > 0, "a replacement token");
      expect(refresher.token.jwt).not.toBe(first.jwt);
      expect(refresher.token.lease).not.toBe(first.lease);
      const ok = await ob.callTool(refresher.token, "github", "read_file", {
        repo: "alice/public-docs",
      });
      expect(ok.decisionId).toBeTruthy();
      expect((await admin.auditTail(100)).some((e) => e.record.tool === "lease.renew")).toBe(true);
      await admin.revokeLease(refresher.token.lease, "test");
      await until(() => errors.length > 0, "the terminal error");
    } finally {
      await dispose();
    }
    expect(errors[0]!.reason).toBe("lease_revoked");
    expect(refresher.error).toBe(errors[0]);
    await expect(
      ob.callTool(refresher.token, "github", "read_file", { repo: "alice/public-docs" }),
    ).rejects.toMatchObject({ reason: "lease_revoked" });
  });

  it("keeps the DPoP key across a refresh", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const [assistantKey, coderKey] = await Promise.all([DpopKey.generate(), DpopKey.generate()]);
    const ob = new AttenuoClient(url, { dpopKey: coderKey });
    const exchange = async () => {
      const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
        capabilities: ["github:*"],
        dpopKey: assistantKey,
      });
      return ob.exchange(root, "coder", [capability("github", "read_file")], {
        ttlSeconds: 6,
        clientSecret: CODER_SECRET,
        subjectDpopKey: assistantKey,
      });
    };
    const first = await exchange();
    expect(first.dpopJkt).toBe(coderKey.thumbprint);
    const changes: Token[] = [];
    const refresher = new TokenRefresher({
      client: ob,
      token: first,
      exchange,
      onChange: (t) => changes.push(t),
    });
    const dispose = refresher.start();
    try {
      await until(() => changes.length > 0, "a replacement token");
      expect(refresher.error).toBeUndefined();
      expect(refresher.token.dpopJkt).toBe(coderKey.thumbprint);
      const ok = await ob.callTool(refresher.token, "github", "read_file", {
        repo: "alice/public-docs",
      });
      expect(ok.decisionId).toBeTruthy();
      expect((await ob.renew(refresher.token)).expiresIn).toBeGreaterThan(0);
    } finally {
      await dispose();
    }
  });

  // The examples need `npm install` in examples/typescript-agent (and the SDK built); skipped
  // when that has not been done.
  const EXAMPLES = join(ROOT, "examples", "typescript-agent");
  const exampleReady = existsSync(join(EXAMPLES, "node_modules", "@attenuo", "sdk", "dist"));
  const mcpReady = existsSync(join(EXAMPLES, "node_modules", "@modelcontextprotocol", "sdk"));

  const runExample = (script: string) =>
    spawnSync(join(EXAMPLES, "node_modules", ".bin", "tsx"), [script], {
      cwd: EXAMPLES,
      encoding: "utf8",
      timeout: 60_000,
      env: { ...process.env, ATTENUO_SERVER: url, ATTENUO_ADMIN_TOKEN: ADMIN_TOKEN },
    });

  it.skipIf(!exampleReady)("runs examples/typescript-agent/agent.ts", () => {
    const proc = runExample("agent.ts");
    expect(proc.status, proc.stdout + proc.stderr).toBe(0);
    // The delegated prefix constraint stops the private repo before policy is even asked.
    expect(proc.stdout.match(/not allowed \(capability_denied/g)).toHaveLength(2);
    // The run limit (one distinct repo) stops the second public repo.
    expect(proc.stdout).toContain("not allowed (budget_exhausted");
    // create_issue asks for an approval; after the operator's grant the retry is allowed.
    expect(proc.stdout).toContain("approval_required (-32008)");
    expect(proc.stdout).toContain("retried once with the grant: allowed");
    expect(proc.stdout).toContain("stopping: lease_revoked");
    expect(proc.stdout).toContain("chain ok=true");
  });

  it.skipIf(!exampleReady || !mcpReady)(
    "runs the official MCP client example through the proxy",
    () => {
      const proc = runExample("mcp_client_example.ts");
      expect(proc.status, proc.stdout + proc.stderr).toBe(0);
      expect(proc.stdout).toContain("tools the token may call: [ 'read_file' ]");
      expect(proc.stdout).toContain("allowed:");
      expect(proc.stdout).toContain("denied:");
    },
  );
});

describe.skipIf(!enabled)("streamed tools/call against the real server", () => {
  let procs: ChildProcess[] = [];
  let work = "";
  let url = "";

  beforeAll(async () => {
    // A fake upstream that streams its answers, and the proxy's re-check every second.
    ({ url, work, procs } = await startStack("[proxy]\nstream_recheck_seconds = 1\n\n", ["--sse"]));
  });

  afterAll(async () => {
    await stopStack(procs, work);
  });

  it("relays events in order and throws DeniedError when revocation cuts the stream", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const coder = await ob.exchange(root, "coder", [capability("github", "read_file")], {
      clientSecret: CODER_SECRET,
    });
    const args = { repo: "alice/public-docs", path: "README.md" };

    const events = [];
    for await (const ev of ob.callToolStream(coder, "github", "read_file", args)) events.push(ev);
    expect(events.map((e) => e.method)).toEqual(["notifications/message", undefined]);
    expect((events[0]!.message.params as { data: string }).data).toBe("working");
    const final = events[1]!;
    expect(final.isFinal).toBe(true);
    expect(final.lastEventId).toBe("0");
    expect(final.result?.isError).toBe(false);
    expect(final.result?.decisionId).toBeTruthy();
    expect((await admin.auditRecord(final.result!.decisionId!)).entry.record.decision).toBe(
      "allow",
    );

    // A denial is thrown before anything streams.
    const denied = ob.callToolStream(coder, "github", "read_file", { repo: "alice/private-x" });
    await expect(denied[Symbol.asyncIterator]().next()).rejects.toMatchObject({
      reason: "policy_deny",
    });

    // The upstream holds the response back for 20 s; revoke the lease after the first event.
    const stream = ob.callToolStream(coder, "github", "read_file", { ...args, hold_ms: 20000 });
    const held = stream[Symbol.asyncIterator]();
    const first = await held.next();
    expect(first.done).toBe(false);
    expect(first.value?.method).toBe("notifications/message");
    const started = Date.now();
    expect((await admin.revokeLease(coder.lease!, "stream test")).revoked).toBe(1);
    const cut = await held.next().then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(Date.now() - started).toBeLessThan(10_000); // one re-check interval (1 s), with slack
    expect(cut).toBeInstanceOf(DeniedError);
    expect((cut as DeniedError).reason).toBe("lease_revoked");
    const end = (await admin.auditRecord((cut as DeniedError).decisionId!)).entry;
    expect([end.record.tool, end.record.decision, end.record.reason]).toEqual([
      "stream.end",
      "deny",
      "lease_revoked",
    ]);
  });
});

describe.skipIf(!enabled)("DPoP server nonces against the real server", () => {
  let procs: ChildProcess[] = [];
  let work = "";
  let url = "";

  beforeAll(async () => {
    ({ url, work, procs } = await startStack('[token]\ndpop_nonce = "required"\n\n'));
  });

  afterAll(async () => {
    await stopStack(procs, work);
  });

  it("picks up the nonce from use_dpop_nonce, retries once and reuses it", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const key = await DpopKey.generate();
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
      dpopKey: key,
    });
    expect(root.dpopJkt).toBe(key.thumbprint);

    // Raw: a proof without the nonce is refused with the nonce to use.
    const raw = await fetch(`${url}/token/renew`, {
      method: "POST",
      headers: {
        authorization: `DPoP ${root.jwt}`,
        dpop: await key.proof("POST", `${url}/token/renew`, root.jwt),
      },
    });
    expect(raw.status).toBe(401);
    expect(((await raw.json()) as { error: string }).error).toBe("use_dpop_nonce");
    expect(raw.headers.get("www-authenticate")).toContain('error="use_dpop_nonce"');
    expect(raw.headers.get("dpop-nonce")).toBeTruthy();

    const ob = new AttenuoClient(url, { dpopKey: key });
    const res = await ob.callTool(root, "github", "read_file", { repo: "alice/public-docs" });
    expect(res.decisionId).toBeTruthy();
    expect((await ob.renew(root)).expiresIn).toBeGreaterThan(0);
    const coder = await ob.exchange(root, "coder", ["github:read_file"], {
      clientSecret: CODER_SECRET,
    });
    expect(coder.dpopJkt).toBe(key.thumbprint);

    // Through the fetch an MCP client library would use.
    const f = mcpFetch(() => coder, { dpopKey: key });
    const r = await f(mcpUrl(url, "github"), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "read_file", arguments: { repo: "alice/public-docs" } },
      }),
    });
    expect(r.status).toBe(200);
    expect(((await r.json()) as { result?: unknown }).result).toBeTruthy();
    await admin.revokeLease(root.lease);
  });
});

describe.skipIf(!enabled)("filtered export and revocation by selector", () => {
  let procs: ChildProcess[] = [];
  let work = "";
  let url = "";

  beforeAll(async () => {
    ({ url, work, procs } = await startStack());
  });

  afterAll(async () => {
    await stopStack(procs, work);
  });

  // First in this stack: the fake upstream hands every caller the same session id and the proxy
  // binds it to the first caller, so this test must open the stack's first MCP session.
  it("revokes by session: an unknown id matches nothing, a real one its chain", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);

    const unknown = await admin.revokeBySelector({ session: "no-such-session" }, { preview: true });
    expect(unknown).toMatchObject({ preview: true, matched: [], revoked: [], revokedCount: 0 });
    expect(unknown.selector.chain_ids).toEqual([]);
    expect(String(unknown.selector.session_tag)).toHaveLength(12);
    expect(JSON.stringify(unknown.selector)).not.toContain("no-such-session");

    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const coder = await ob.exchange(root, "coder", ["github:read_file"], {
      clientSecret: CODER_SECRET,
    });
    const sid = await ob.initialize(coder, "github");
    expect(sid).toBeTruthy();
    const both = [root.lease, coder.lease].sort();

    const preview = await admin.revokeBySelector({ session: sid! }, { preview: true });
    expect(preview.selector.chain_ids).toEqual([root.lease]);
    expect([...preview.matched].sort()).toEqual(both);
    expect([...preview.revoked].sort()).toEqual(both);
    expect((await admin.leaseStatus(coder.lease)).active).toBe(true);

    const done = await admin.revokeBySelector({ session: sid! }, { reason: "session hijacked" });
    expect(done.preview).toBe(false);
    expect([...done.revoked].sort()).toEqual(both);
    expect(done.auditId).toBeTruthy();
    expect(JSON.stringify(done)).not.toContain(sid!);
    const after = await ob
      .callTool(coder, "github", "read_file", { repo: "alice/public-docs" }, { sessionId: sid! })
      .catch((e: unknown) => e);
    expect(after).toBeInstanceOf(DeniedError);
    expect((after as DeniedError).reason).toBe("lease_revoked");
  });

  it("exports only token.exchange denials, and verification refuses the file", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const coder = await ob.exchange(root, "coder", ["github:read_file"], {
      clientSecret: CODER_SECRET,
    });
    // A widening exchange: refused, and recorded as a `deny` of tool `token.exchange`.
    await expect(
      ob.exchange(coder, "tester", ["github:create_issue"], { clientSecret: TESTER_SECRET }),
    ).rejects.toMatchObject({ status: 400, error: "invalid_scope" });

    const lines = [];
    for await (const l of admin.auditExport(1, undefined, {
      tool: "token.exchange",
      decision: "deny",
    }))
      lines.push(l);
    expect(lines[0]).toMatchObject({
      type: "header",
      filter: { tool: "token.exchange", decision: "deny" },
    });
    const entries = lines.filter((l) => l.type === "entry") as unknown as {
      record: { tool: string; decision: string; chain_id?: string; reason?: string };
    }[];
    expect(entries.length).toBeGreaterThan(0);
    expect(new Set(entries.map((e) => `${e.record.tool} ${e.record.decision}`))).toEqual(
      new Set(["token.exchange deny"]),
    );
    expect(
      entries.some(
        (e) => e.record.chain_id === root.lease && e.record.reason === "exchange_widening",
      ),
    ).toBe(true);

    const jwks = (await (await fetch(`${url}/.well-known/jwks.json`)).json()) as {
      keys: unknown[];
    };
    const text = lines.map((l) => JSON.stringify(l)).join("\n") + "\n";
    await expect(verifyExport(text, { checkpointPublicKeys: jwks })).rejects.toThrow(ExportError);
    await expect(verifyExport(text, { checkpointPublicKeys: jwks })).rejects.toThrow(/filtered/);

    await expect(
      (async () => {
        for await (const _ of admin.auditExport(1, undefined, { decision: "maybe" as "deny" }))
          void _;
      })(),
    ).rejects.toMatchObject({ status: 400 });
    await admin.revokeLease(root.lease);
  });

  it("revokes by chain id: preview first, then for real", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const coder = await ob.exchange(root, "coder", ["github:read_file"], {
      clientSecret: CODER_SECRET,
    });
    const both = [root.lease, coder.lease].sort();

    // A preview changes nothing and writes nothing.
    const head = await admin.auditHead();
    const preview = await admin.revokeBySelector({ chainId: root.lease }, { preview: true });
    expect(preview).toMatchObject({
      preview: true,
      selector: { chain_id: root.lease },
      matchedCount: 2,
      revokedCount: 2,
      truncated: false,
      reason: undefined,
      auditId: undefined,
    });
    expect([...preview.matched].sort()).toEqual(both);
    expect([...preview.revoked].sort()).toEqual(both);
    expect(await admin.auditHead()).toBe(head);
    expect((await admin.leaseStatus(root.lease)).active).toBe(true);
    const byUser = await admin.revokeBySelector({ user: "alice" }, { preview: true });
    expect(byUser.selector).toEqual({ user: "alice" });
    expect(byUser.matched).toContain(root.lease);

    // For real: the chain is revoked and the revocation is audited.
    const done = await admin.revokeBySelector(
      { chainId: root.lease },
      { reason: "run went wrong" },
    );
    expect(done).toMatchObject({ preview: false, revokedCount: 2, reason: "run went wrong" });
    expect([...done.revoked].sort()).toEqual(both);
    const record = (await admin.auditRecord(done.auditId!)).entry.record;
    expect([record.tool, record.kind]).toEqual(["admin.lease.revoke", "lease_revoke"]);
    expect((await admin.leaseStatus(coder.lease)).active).toBe(false);
    await expect(
      ob.callTool(coder, "github", "read_file", { repo: "alice/public-docs" }),
    ).rejects.toMatchObject({ reason: "lease_revoked" });

    // Nothing is left to match, and an unknown chain is an empty answer, not an error.
    const again = await admin.revokeBySelector({ chainId: root.lease }, { preview: true });
    expect(again).toMatchObject({ matched: [], revoked: [], revokedCount: 0 });
    const unknown = await admin.revokeBySelector({ chainId: "no-such-chain" }, { preview: true });
    expect(unknown).toMatchObject({ matched: [], revoked: [] });
  });
  it("dry-runs with a stated budget, session, approval and usage", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const coder = await ob.exchange(
      root,
      "coder",
      [withLimits(capability("github", "read_file"), { calls: 2 })],
      { clientSecret: CODER_SECRET },
    );
    const read = { repo: "alice/public-docs", path: "README.md" };
    const head = await admin.auditHead();

    // From the store: a fresh run, nothing used, no labels.
    const live = await admin.policyEvaluate("github", "read_file", read, { token: coder });
    expect([live.decision, live.reason]).toEqual(["allow", "policy_allow"]);
    expect(live.budget).toMatchObject({ source: "store", limited: true });
    expect(live.labels).toMatchObject({ source: "store", tainted: false });

    // Stated: one call left on the `calls: 2` limit, and a tainted run.
    const session = { taintedBy: ["web/fetch"], untrustedArgs: ["path"] };
    const ok = await admin.policyEvaluate("github", "read_file", read, {
      token: coder,
      budget: { callsRemaining: 1 },
      session,
      usage: { calls: 3, amount: 7, destinationSeen: true },
    });
    expect([ok.decision, ok.reason, ok.limit]).toEqual(["allow", "policy_allow", undefined]);
    expect(ok.budget).toMatchObject({ source: "request", limited: true, callsRemaining: 1 });
    expect(ok.labels).toEqual({
      tainted: true,
      taintedBy: ["web/fetch"],
      argsContainUntrusted: true,
      untrustedArgs: ["path"],
      source: "request",
    });
    expect(ok.usage).toEqual({ calls: 3, amount: 7, destinationSeen: true, source: "request" });

    // The stated figures run out: refused as the live call would be, with the limit it hit.
    const spent = await admin.policyEvaluate("github", "read_file", read, {
      token: coder,
      budget: { callsRemaining: 0 },
      session,
    });
    expect([spent.decision, spent.reason]).toEqual(["deny", "budget_exhausted"]);
    expect(spent.budget!.source).toBe("request");
    expect(spent.labels!.source).toBe("request");
    expect(spent.limit).toEqual({ hop: 1, kind: "calls", used: 2, max: 2 });
    expect(spent.usage).toEqual({ calls: 0, amount: 0, destinationSeen: false, source: "request" });

    // A stated approval: create_issue asks without one and passes with one.
    const issue = { repo: "alice/public-docs", title: "typo" };
    const asked = await admin.policyEvaluate("github", "create_issue", issue, { token: root });
    expect([asked.reason, asked.approvalBy]).toEqual(["approval_required", undefined]);
    const granted = await admin.policyEvaluate("github", "create_issue", issue, {
      token: root,
      approval: { by: "operator" },
    });
    expect([granted.decision, granted.approvalBy]).toEqual(["allow", "operator"]);

    // The server checks the blocks: its 400 comes back as ApiError.
    const bad = await admin
      .policyEvaluate("github", "read_file", read, { token: coder, usage: { calls: -1 } })
      .catch((e: unknown) => e);
    expect(bad).toBeInstanceOf(ApiError);
    expect(bad).toMatchObject({ status: 400, error: "invalid_request" });

    // Nothing was audited or charged: the live run still has both calls.
    expect(await admin.auditHead()).toBe(head);
    for (let i = 0; i < 2; i++) {
      expect((await ob.callTool(coder, "github", "read_file", read)).decisionId).toBeTruthy();
    }
    await expect(ob.callTool(coder, "github", "read_file", read)).rejects.toMatchObject({
      reason: "budget_exhausted",
    });
    await admin.revokeLease(root.lease);
  });
});

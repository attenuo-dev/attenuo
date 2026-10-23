/**
 * The GitHub-leak scenario through the SDK, against the real server and a fake MCP upstream.
 *
 * Skipped unless `ONBEHALF_INTEGRATION=1`. Needs prebuilt binaries: `onbehalf-server` and
 * `examples/fake_mcp` in `ONBEHALF_BIN_DIR` (default `<repo>/.bin`). Build them with
 *
 *   cargo build -p onbehalf-server && cargo build -p onbehalf-proxy --example fake_mcp
 *
 * and copy `target/debug/onbehalf-server` and `target/debug/examples/fake_mcp` there. Starts both
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
  OnbehalfClient,
  prefix,
  RefreshError,
  type Token,
  TokenRefresher,
  UnauthorizedError,
  VerificationError,
} from "../src/index.js";

// [[agents]] secrets in the demo config: an exchange authenticates as its actor.
const CODER_SECRET = "demo-coder-secret";
const TESTER_SECRET = "demo-tester-secret";

const enabled = process.env.ONBEHALF_INTEGRATION === "1";
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
  const dir = process.env.ONBEHALF_BIN_DIR ?? join(ROOT, ".bin");
  const server = join(dir, "onbehalf-server");
  const fake = [join(dir, "examples", "fake_mcp"), join(dir, "fake_mcp")].find(existsSync);
  if (!existsSync(server) || !fake) {
    throw new Error(
      `onbehalf-server / fake_mcp not found in ${dir}; build them and set ONBEHALF_BIN_DIR (see this file's header)`,
    );
  }
  return { server, fake };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Start the fake upstream and the server with the demo config, plus `tokenSection` (a `[token]`
 * table) when given; resolves once both answer.
 */
async function startStack(
  tokenSection = "",
): Promise<{ url: string; work: string; procs: ChildProcess[] }> {
  const work = mkdtempSync(join(tmpdir(), "onbehalf-it-"));
  const procs: ChildProcess[] = [];
  const built = binaries();
  // Copy them: a shared CARGO_TARGET_DIR can be rebuilt under us mid-test.
  const serverBin = join(work, "onbehalf-server");
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
    spawn(fakeBin, ["--port", String(mcpPort)], { stdio: ["ignore", fakeOutS, fakeLogS] }),
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
    const ob = new OnbehalfClient(url);

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
    const verified = await ob.inspect(coder, { verify: true, issuer: url, audience: "onbehalf" });
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
    const ob = new OnbehalfClient(url, { dpopKey: coderKey.privateJwk() });
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
    const thief = new OnbehalfClient(url);
    const noProof = await thief
      .callTool(coder, "github", "read_file", { repo: "alice/public-docs" })
      .catch((e: unknown) => e);
    expect(noProof).toBeInstanceOf(UnauthorizedError);
    await expect(thief.renew(coder)).rejects.toMatchObject({ status: 401, error: "dpop_required" });
    await expect(
      thief.exchange(coder, "tester", "github:read_file", { clientSecret: TESTER_SECRET }),
    ).rejects.toMatchObject({ status: 401, error: "dpop_required" });
    // Another key does not help either.
    const other = new OnbehalfClient(url, { dpopKey: await DpopKey.generate() });
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
    const ob = new OnbehalfClient(url);
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
    const ob = new OnbehalfClient(url, { dpopKey: coderKey });
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
  const exampleReady = existsSync(join(EXAMPLES, "node_modules", "@onbehalf", "sdk", "dist"));
  const mcpReady = existsSync(join(EXAMPLES, "node_modules", "@modelcontextprotocol", "sdk"));

  const runExample = (script: string) =>
    spawnSync(join(EXAMPLES, "node_modules", ".bin", "tsx"), [script], {
      cwd: EXAMPLES,
      encoding: "utf8",
      timeout: 60_000,
      env: { ...process.env, ONBEHALF_SERVER: url, ONBEHALF_ADMIN_TOKEN: ADMIN_TOKEN },
    });

  it.skipIf(!exampleReady)("runs examples/typescript-agent/agent.ts", () => {
    const proc = runExample("agent.ts");
    expect(proc.status, proc.stdout + proc.stderr).toBe(0);
    // The delegated prefix constraint stops the private repo before policy is even asked.
    expect(proc.stdout.match(/not allowed \(capability_denied/g)).toHaveLength(2);
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

    const ob = new OnbehalfClient(url, { dpopKey: key });
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

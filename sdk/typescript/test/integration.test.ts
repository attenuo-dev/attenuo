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
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  createWriteStream,
} from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AdminClient,
  ApiError,
  ApprovalRequiredError,
  callHash,
  capability,
  DeniedError,
  DpopKey,
  mcpFetch,
  mcpUrl,
  AttenuoClient,
  prefix,
  RateLimitedError,
  RefreshError,
  RpcError,
  type Token,
  TokenRefresher,
  tlsFetch,
  TransportError,
  UnauthorizedError,
  VerificationError,
  ExportError,
  crossCheck,
  verifyExport,
  verifyExports,
  withLimits,
} from "../src/index.js";
import { retryHooks } from "../src/retry.js";
import { Ca, ClientCert, tempDir } from "./tlsutil.js";

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
 * table) when given and `fakeArgs` for the upstream; resolves once both answer. `policyExtra` is
 * appended to the demo policy, and each `edits` key of the config is replaced by its value.
 * `{work}` in the config stands for the stack's own directory.
 */
async function startStack(
  tokenSection = "",
  fakeArgs: string[] = [],
  opts: {
    policyExtra?: string;
    edits?: Record<string, string>;
    /** Serve the main listener over TLS (`[server.tls]`, client certificates optional). */
    tls?: { cert: string; key: string; ca: string };
  } = {},
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
  let policy = join(DEMO, "policy.cedar");
  if (opts.policyExtra !== undefined) {
    policy = join(work, "policy.cedar");
    writeFileSync(policy, readFileSync(join(DEMO, "policy.cedar"), "utf8") + opts.policyExtra);
  }
  let config = readFileSync(join(DEMO, "config.toml"), "utf8")
    .replaceAll("18080", String(obPort))
    .replaceAll("13001", String(mcpPort))
    .replaceAll("examples/github-leak-demo/policy.cedar", policy)
    .replace("[audit]\n", `${tokenSection}[audit]\n`);
  for (const [from, to] of Object.entries(opts.edits ?? {})) {
    if (!config.includes(from)) throw new Error(`not in the demo config: ${from}`);
    config = config.replace(from, to);
  }
  if (opts.tls) {
    config = config.replace(
      "[issuer]\n",
      `public_url = "https://127.0.0.1:${obPort}"\n\n[server.tls]\n` +
        `cert_pem_path = "${opts.tls.cert}"\nkey_pem_path = "${opts.tls.key}"\n` +
        `client_certificates = "optional"\n\n[issuer]\n`,
    );
  }
  writeFileSync(join(work, "config.toml"), config.replaceAll("{work}", work));

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
  const url = `${opts.tls ? "https" : "http"}://127.0.0.1:${obPort}`;
  const probe = opts.tls ? tlsFetch(url, { tlsCaCert: opts.tls.ca }) : fetch;

  const deadline = Date.now() + 20_000;
  for (;;) {
    let ready = false;
    try {
      ready = (await probe(`${url}/healthz`, { signal: AbortSignal.timeout(1000) })).ok;
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

/** Wait until the server at `url` answers `/healthz`, or throw with its log. */
async function waitHealthy(url: string, work: string, proc: ChildProcess): Promise<void> {
  const deadline = Date.now() + 20_000;
  for (;;) {
    try {
      if ((await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1000) })).ok) return;
    } catch {
      /* not up yet */
    }
    if (proc.exitCode !== null || Date.now() > deadline) {
      throw new Error(`server did not start:\n${readFileSync(join(work, "server.log"), "utf8")}`);
    }
    await sleep(100);
  }
}

/**
 * Stop the stack's server and start it again on the same port and config. A server with an
 * ephemeral issuer key or a `:memory:` audit store forgets its tokens; one with files keeps them
 * and forgets only what lives in the process, such as the rate limits' minutes.
 */
async function restartServer(stack: { url: string; work: string; procs: ChildProcess[] }) {
  const old = stack.procs[1]!;
  const exited = new Promise((r) => old.once("exit", r));
  old.kill("SIGTERM");
  await exited;
  const log = createWriteStream(join(stack.work, "server.log"), { flags: "a" });
  await new Promise((r) => log.once("open", r));
  const proc = spawn(
    join(stack.work, "attenuo-server"),
    ["--config", join(stack.work, "config.toml")],
    {
      stdio: ["ignore", log, log],
      env: { ...process.env, RUST_LOG: "warn" },
    },
  );
  stack.procs[1] = proc;
  await waitHealthy(stack.url, stack.work, proc);
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
    expect(pd.stableCode).toBe("policy_deny");
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

    // 11. A bad bearer is a 401, not a denial, and says why.
    const badBearer = (await ob
      .callTool("not.a.token", "github", "read_file", { repo: "alice/public-docs" })
      .catch((e: unknown) => e)) as UnauthorizedError;
    expect(badBearer).toBeInstanceOf(UnauthorizedError);
    expect(badBearer.reason).toBe("invalid_token");
    expect(badBearer.decisionId).toBeUndefined(); // a token that does not verify writes no record

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
    // A request without a per-call decision is a 401 that names the reason and its record.
    const listing = (await ob
      .listTools(tester, "github")
      .catch((e: unknown) => e)) as UnauthorizedError;
    expect(listing).toBeInstanceOf(UnauthorizedError);
    expect(listing.reason).toBe("lease_revoked");
    expect(listing.decisionId).toBeTruthy();
    const renewal = (await ob.renew(coder).catch((e: unknown) => e)) as ApiError; // final
    expect(renewal).toBeInstanceOf(ApiError);
    expect([renewal.status, renewal.error]).toEqual([400, "invalid_grant"]);
    expect(renewal.decisionId).toBeTruthy();

    // 13. The audit log has every decision, and its hash chain verifies.
    const report = await admin.auditVerify();
    expect(report.ok).toBe(true);
    expect(report.entries).toBeGreaterThanOrEqual(8);
    const byId = new Map((await admin.auditTail(200)).map((e) => [e.record.id, e]));
    expect(byId.get(allowedDecision)?.record.decision).toBe("allow");
    expect(byId.get(pd.decisionId)?.record.reason).toBe("policy_deny");
    expect(byId.get(capDenied.decisionId)?.record.reason).toBe("capability_denied");
    expect(byId.get(after.decisionId)?.record.reason).toBe("lease_revoked");
    const listed = byId.get(listing.decisionId!)?.record;
    expect([listed?.tool, listed?.reason]).toEqual(["tools/list", "lease_revoked"]);
    const renewRecord = byId.get(renewal.decisionId!)?.record;
    expect([renewRecord?.tool, renewRecord?.reason]).toEqual(["lease.renew", "lease_revoked"]);
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
    // Every route says why the same way: `reason`, for the proxy as for REST routes.
    expect(noProof).toBeInstanceOf(UnauthorizedError);
    expect((noProof as UnauthorizedError).reason).toBe("dpop_required");
    await expect(thief.listTools(coder, "github")).rejects.toMatchObject({
      reason: "dpop_required",
    });
    await expect(thief.renew(coder)).rejects.toMatchObject({
      status: 401,
      error: "dpop_required",
      reason: "dpop_required",
    });
    await expect(
      thief.exchange(coder, "tester", "github:read_file", { clientSecret: TESTER_SECRET }),
    ).rejects.toMatchObject({ status: 401, error: "dpop_required", reason: "dpop_required" });
    // Another key does not help either.
    const other = new AttenuoClient(url, { dpopKey: await DpopKey.generate() });
    await expect(other.renew(coder)).rejects.toMatchObject({
      error: "invalid_dpop_proof",
      reason: "invalid_dpop_proof",
    });
    await expect(
      other.callTool(coder, "github", "read_file", { repo: "alice/public-docs" }),
    ).rejects.toMatchObject({ reason: "invalid_dpop_proof" });

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
    expect((cut as DeniedError).stableCode).toBe("lease_revoked");
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
    // Action search signs its own URL and picks up the nonce like evaluation.
    const found = await ob.authzenSearchAction(coder, "github", { repo: "alice/public-x" });
    expect(found.actions.map((a) => a.name)).toEqual(["read_file"]);

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
    const over = (await ob
      .callTool(coder, "github", "read_file", read)
      .catch((e: unknown) => e)) as DeniedError;
    expect(over).toBeInstanceOf(DeniedError);
    expect(over.reason).toBe("budget_exhausted");
    // The refusal names the limit, as the dry run did.
    expect(over.limit).toEqual({ hop: 1, kind: "calls", used: 2, max: 2 });
    expect(over.data.limit).toEqual(over.limit);
    await admin.revokeLease(root.lease);
  });
});

describe.skipIf(!enabled)("pending approvals cap against the real server", () => {
  let procs: ChildProcess[] = [];
  let work = "";
  let url = "";

  beforeAll(async () => {
    ({ url, work, procs } = await startStack());
  });

  afterAll(async () => {
    await stopStack(procs, work);
  });

  it("answers approval_required without an approval id past 32 pending (SR-92)", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const issue = (title: string) => ({ repo: "alice/public-docs", title });
    const held = async (title: string): Promise<ApprovalRequiredError> => {
      const e = await ob.callTool(root, "github", "create_issue", issue(title)).catch((x) => x);
      expect(e).toBeInstanceOf(ApprovalRequiredError);
      return e as ApprovalRequiredError;
    };

    const ids: string[] = [];
    for (let n = 0; n < 32; n++) {
      const e = await held(`t${n}`);
      expect(e.approvalId).toBeTruthy();
      ids.push(e.approvalId!);
    }

    const full = await held("one too many");
    expect(full.reason).toBe("approval_required");
    expect(full.decisionId).toBeTruthy();
    expect([full.approvalId, full.expiresAt]).toEqual([undefined, undefined]);
    expect(full.callHash).toBe(await callHash("github", "create_issue", issue("one too many")));

    const told: ApprovalRequiredError[] = [];
    const again = await ob
      .callToolWithApproval(root, "github", "create_issue", issue("one too many"), {
        onApproval: (e) => void told.push(e),
      })
      .catch((x: unknown) => x);
    expect(again).toBeInstanceOf(ApprovalRequiredError);
    expect(told).toEqual([]);

    const verdict = await ob.authzenEvaluate(root, "github", "create_issue", issue("also"));
    expect([verdict.decision, verdict.reason, verdict.approvalId]).toEqual([
      false,
      "approval_required",
      undefined,
    ]);
    expect(verdict.callHash).toBe(await callHash("github", "create_issue", issue("also")));

    // A repeat of a waiting call keeps its approval, in the -32008 and in AuthZEN.
    expect((await held("t7")).approvalId).toBe(ids[7]);
    const t7 = await ob.authzenEvaluate(root, "github", "create_issue", issue("t7"));
    expect(t7.approvalId).toBe(ids[7]);
    expect(t7.expiresAt).toBeInstanceOf(Date);

    // Deciding one makes room for the next.
    await admin.declineApproval(ids[0]!);
    const room = await held("one too many");
    expect(room.approvalId).toBeTruthy();
    expect(ids).not.toContain(room.approvalId);
    await admin.revokeLease(root.lease);
  });
});

describe.skipIf(!enabled)("decimal catalog input against the real server", () => {
  let procs: ChildProcess[] = [];
  let work = "";
  let url = "";

  beforeAll(async () => {
    ({ url, work, procs } = await startStack("", [], {
      policyExtra:
        '\n@id("read_file_amount_below_100")\n' +
        'forbid(principal, action == Action::"github/read_file", resource)\n' +
        'when { context.input has amount && !context.input.amount.lessThan(decimal("100.0")) };\n',
      edits: {
        'inputs = { repo = "string", path = "string" }':
          'inputs = { repo = "string", path = "string", amount = "decimal" }',
      },
    }));
  });

  afterAll(async () => {
    await stopStack(procs, work);
  });

  it("compares a JSON number as a Cedar decimal and refuses more than 4 digits", async () => {
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const ob = new AttenuoClient(url);
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const read = (amount: unknown) => ({ repo: "alice/public-docs", path: "README.md", amount });
    for (const fine of [12.5, 99.9999, 0, 99]) {
      expect((await ob.callTool(root, "github", "read_file", read(fine))).decisionId).toBeTruthy();
      expect((await ob.authzenEvaluate(root, "github", "read_file", read(fine))).decision).toBe(
        true,
      );
    }
    for (const over of [100, 150.25]) {
      await expect(ob.callTool(root, "github", "read_file", read(over))).rejects.toMatchObject({
        reason: "policy_deny",
      });
      const v = await ob.authzenEvaluate(root, "github", "read_file", read(over));
      expect(v.reason).toBe("policy_deny");
    }
    for (const bad of [1.23456, "12.5"]) {
      const e = await ob.callTool(root, "github", "read_file", read(bad)).catch((x) => x);
      expect(e).toBeInstanceOf(DeniedError);
      expect((e as DeniedError).reason).toBe("input_type_mismatch");
      const v = await ob.authzenEvaluate(root, "github", "read_file", read(bad));
      expect([v.decision, v.reason]).toEqual([false, "input_type_mismatch"]);
    }
    const dry = await admin.policyEvaluate("github", "read_file", read(12.5), { token: root });
    expect(dry.decision).toBe("allow");
    const dryBad = await admin.policyEvaluate("github", "read_file", read(1.23456), {
      token: root,
    });
    expect([dryBad.decision, dryBad.reason]).toEqual(["deny", "input_type_mismatch"]);
    await admin.revokeLease(root.lease);
  });
});

describe.skipIf(!enabled)(
  "refund, AuthZEN batch and discovery, user decision, session close (K-5)",
  () => {
    const ISSUER = "https://idp.example";
    let procs: ChildProcess[] = [];
    let work = "";
    let url = "";
    let jwksServer: HttpServer | undefined;
    let idpKey: CryptoKey;

    const b64u = (d: Uint8Array | string) => Buffer.from(d).toString("base64url");
    async function idToken(sub: string, jti: string): Promise<string> {
      const now = Math.floor(Date.now() / 1000);
      const head = { alg: "EdDSA", typ: "JWT", kid: "idp-1" };
      const claims = { iss: ISSUER, sub, aud: "demo-approval-page", iat: now, exp: now + 300, jti };
      const signing = `${b64u(JSON.stringify(head))}.${b64u(JSON.stringify(claims))}`;
      const sig = await crypto.subtle.sign("Ed25519", idpKey, new TextEncoder().encode(signing));
      return `${signing}.${b64u(new Uint8Array(sig))}`;
    }

    beforeAll(async () => {
      // A stand-in OIDC issuer: an Ed25519 key, its JWKS on a local port, trusted by `[[idps]]`.
      const pair = (await crypto.subtle.generateKey("Ed25519", true, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      idpKey = pair.privateKey;
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      const jwks = JSON.stringify({
        keys: [{ kty: "OKP", crv: "Ed25519", kid: "idp-1", x: b64u(raw) }],
      });
      const srv = createHttpServer((_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(jwks);
      });
      jwksServer = srv;
      const port = await new Promise<number>((ok) =>
        srv.listen(0, "127.0.0.1", () => ok((srv.address() as { port: number }).port)),
      );
      const idps = `[[idps]]\nissuer = "${ISSUER}"\njwks_url = "http://127.0.0.1:${port}/jwks"\n\n`;
      ({ url, work, procs } = await startStack(idps));
    });

    afterAll(async () => {
      await stopStack(procs, work);
      jwksServer?.close();
    });

    it("closes an MCP session, and refuses another run's or an unknown one", async () => {
      const admin = new AdminClient(url, ADMIN_TOKEN);
      const ob = new AttenuoClient(url);
      const root = await admin.mintRootDev("alice", ISSUER, "assistant", {
        capabilities: ["github:*"],
      });
      const coder = await ob.exchange(root, "coder", ["github:read_file"], {
        clientSecret: CODER_SECRET,
      });
      const sid = await ob.initialize(coder, "github");
      expect(sid, "the fake upstream assigns a session id").toBeTruthy();
      const other = await admin.mintRootDev("alice", ISSUER, "assistant", {
        capabilities: ["github:*"],
      });
      const mismatch = await ob.closeSession(other, "github", sid!).catch((e: unknown) => e);
      expect(mismatch).toBeInstanceOf(DeniedError);
      expect((mismatch as DeniedError).reason).toBe("session_mismatch");
      expect(await ob.closeSession(coder, "github", sid!)).toBe(true);
      const unknown = await ob.closeSession(coder, "github", "no-such-session").catch((e) => e);
      expect(unknown).toBeInstanceOf(RpcError);
      expect((unknown as RpcError).code).toBe(-32600);
      expect((unknown as RpcError).stableCode).toBe("session_unknown");
      await admin.revokeLease(root.lease);
      await admin.revokeLease(other.lease);
    });

    it("refunds a charged decision once", async () => {
      const admin = new AdminClient(url, ADMIN_TOKEN);
      const ob = new AttenuoClient(url);
      const root = await admin.mintRootDev("alice", ISSUER, "assistant", {
        capabilities: ["github:*"],
      });
      const coder = await ob.exchange(
        root,
        "coder",
        [withLimits(capability("github", "read_file"), { calls: 1 })],
        { clientSecret: CODER_SECRET },
      );
      const read = { repo: "alice/public-docs", path: "README.md" };
      const first = await ob.callTool(coder, "github", "read_file", read);
      expect(first.decisionId).toBeTruthy();
      await expect(ob.callTool(coder, "github", "read_file", read)).rejects.toMatchObject({
        reason: "budget_exhausted",
      });
      const refund = await admin.refundBudget(first.decisionId!, "upstream failed");
      expect(refund.decisionId).toBe(first.decisionId);
      expect(refund.refunded).toBeGreaterThanOrEqual(1);
      expect(refund.reason).toBe("upstream failed");
      expect(refund.auditId).toBeTruthy();
      expect((await ob.callTool(coder, "github", "read_file", read)).decisionId).toBeTruthy();
      await expect(admin.refundBudget(first.decisionId!)).rejects.toMatchObject({
        status: 409,
        error: "already_refunded",
        decisionId: undefined,
      });
      await expect(
        admin.refundBudget("00000000-0000-4000-8000-000000000000"),
      ).rejects.toMatchObject({ status: 404, error: "not_found" });
      await admin.revokeLease(root.lease);
    });

    it("decides a batch in order, stops on the first deny, and serves discovery", async () => {
      const admin = new AdminClient(url, ADMIN_TOKEN);
      const ob = new AttenuoClient(url);
      const root = await admin.mintRootDev("alice", ISSUER, "assistant", {
        capabilities: ["github:*"],
      });
      const coder = await ob.exchange(root, "coder", ["github:read_file"], {
        clientSecret: CODER_SECRET,
      });
      const read = { repo: "alice/public-docs", path: "README.md" };
      const issue = { repo: "alice/public-docs", title: "t" };
      const [allow, deny] = await ob.authzenEvaluateBatch(coder, [
        { server: "github", tool: "read_file", args: read },
        ["github", "create_issue", issue],
      ]);
      expect(allow!.decision).toBe(true);
      expect(allow!.decisionId).toBeTruthy();
      expect([deny!.decision, deny!.reason]).toEqual([false, "capability_denied"]);
      const stopped = await ob.authzenEvaluateBatch(
        coder,
        [
          ["github", "create_issue", issue],
          ["github", "read_file", read],
        ],
        { semantic: "deny_on_first_deny" },
      );
      expect(stopped.map((d) => d.decision)).toEqual([false]);
      await expect(
        ob.authzenEvaluateBatch("not-a-token", [["github", "read_file", read]]),
      ).rejects.toBeInstanceOf(UnauthorizedError);

      expect(await ob.authzenConfiguration()).toMatchObject({
        policyDecisionPoint: url,
        accessEvaluationEndpoint: `${url}/access/v1/evaluation`,
        accessEvaluationsEndpoint: `${url}/access/v1/evaluations`,
      });
      await admin.revokeLease(root.lease);
    });

    it("searches actions as evaluation would decide them, page by page", async () => {
      const admin = new AdminClient(url, ADMIN_TOKEN);
      const ob = new AttenuoClient(url);
      const root = await admin.mintRootDev("alice", ISSUER, "assistant", {
        capabilities: ["github:*"],
      });
      const coder = await ob.exchange(root, "coder", ["github:read_file"], {
        clientSecret: CODER_SECRET,
      });
      const pub = { repo: "alice/public-docs", path: "README.md" };
      const priv = { repo: "alice/private-salaries", path: "pay.csv" };
      const collect = async (token: typeof root, args: Record<string, unknown>, limit?: number) => {
        const out = [];
        for await (const a of ob.authzenSearchActionIter(token, "github", args, { limit })) {
          out.push(a);
        }
        return out;
      };

      const page = await ob.authzenSearchAction(coder, "github", pub);
      expect(page.actions).toEqual([{ name: "read_file", server: "github" }]);
      expect(page.nextToken).toBeUndefined();
      expect((await ob.authzenEvaluate(coder, "github", "read_file", pub)).decision).toBe(true);
      // The policy forbids the private repo, so nothing is a result for these arguments.
      expect((await ob.authzenSearchAction(coder, "github", priv)).actions).toEqual([]);

      // One candidate per page: the catalog is create_issue, delete_repo, read_file. The first
      // page is approval-gated create_issue, never a result, so it is empty with a token.
      const first = await ob.authzenSearchAction(root, "github", pub, { limit: 1 });
      expect(first.actions).toEqual([]);
      expect(first.nextToken).toBeTruthy();
      const paged = await collect(root, pub, 1);
      expect(paged).toEqual(await collect(root, pub));
      expect(paged).toContainEqual({ name: "read_file", server: "github" });
      expect(paged).not.toContainEqual({ name: "create_issue", server: "github" });
      for (const a of paged) {
        expect((await ob.authzenEvaluate(root, "github", a.name, pub)).decision).toBe(true);
      }

      await expect(ob.authzenSearchAction("not-a-token", "github", pub)).rejects.toBeInstanceOf(
        UnauthorizedError,
      );
      await expect(ob.authzenSearchAction(coder, "github/read_file", pub)).rejects.toMatchObject({
        status: 400,
        code: "invalid_search_resource",
      });
      await expect(
        ob.authzenSearchAction(coder, "github", pub, { pageToken: "not-a-token" }),
      ).rejects.toMatchObject({ code: "invalid_cursor" });
      expect((await ob.authzenConfiguration()).searchActionEndpoint).toBe(
        `${url}/access/v1/search/action`,
      );

      await admin.revokeLease(root.lease);
      expect((await ob.authzenSearchAction(coder, "github", pub)).actions).toEqual([]);
    });

    it("lets the user decide with their ID token, and nobody else", async () => {
      const admin = new AdminClient(url, ADMIN_TOKEN);
      const ob = new AttenuoClient(url);
      const root = await admin.mintRootDev("alice", ISSUER, "assistant", {
        capabilities: ["github:*"],
      });
      const issue = { repo: "alice/public-docs", title: "from the user" };
      const held = (await ob
        .callTool(root, "github", "create_issue", issue)
        .catch((e) => e)) as ApprovalRequiredError;
      expect(held).toBeInstanceOf(ApprovalRequiredError);
      const id = held.approvalId!;

      await expect(ob.grantApproval(id, root.jwt)).rejects.toMatchObject({
        status: 403,
        error: "agent_token_refused",
      });
      await expect(ob.grantApproval(id, await idToken("mallory", "j-0"))).rejects.toMatchObject({
        status: 403,
        error: "wrong_user",
      });
      const token = await idToken("alice", "j-1");
      const granted = await ob.grantApproval(id, token);
      expect(granted).toMatchObject({ state: "granted", usable: true });
      expect(granted.approver?.by).toBe("user");
      const done = await ob.callTool(root, "github", "create_issue", issue, {
        approvalToken: granted.approvalToken!,
      });
      expect(done.decisionId).toBeTruthy();

      const second = (await ob
        .callTool(root, "github", "create_issue", { ...issue, title: "again" })
        .catch((e) => e)) as ApprovalRequiredError;
      expect(second.approvalId).toBeTruthy();
      await expect(ob.declineApproval(second.approvalId!, token)).rejects.toMatchObject({
        status: 400,
        error: "invalid_grant",
      });
      const declined = await ob.declineApproval(second.approvalId!, await idToken("alice", "j-2"));
      expect(declined.state).toBe("declined");
      await admin.revokeLease(root.lease);
    });
  },
);

// ---- private_key_jwt client assertions and the retries that send them again ---------------
//
// The server leaves a client assertion unused when it refuses the request with `use_dpop_nonce`
// or `429 rate_limited` (SR-108, SR-111), because the client is told to send the same request
// again. These tests check that the SDK's retries then succeed against the real server, and that
// the load retry does not send an assertion that will have expired.

/** An `[[agents]]` entry for `signer` that authenticates with `key`'s client assertions. */
function signerAgent(key: DpopKey): string {
  return `[[agents]]\nid = "signer"\njwks = '${JSON.stringify({ keys: [key.publicJwk] })}'\n\n`;
}

interface Sent {
  assertion?: string;
  status: number;
  error?: string;
}

/** The global `fetch`, keeping each `POST /token` and its answer. */
function recordingFetch() {
  const sent: Sent[] = [];
  const f = async (input: string, init?: RequestInit): Promise<Response> => {
    const res = await fetch(input, init);
    if (new URL(input).pathname === "/token") {
      const body = JSON.parse(String(init?.body)) as { client_assertion?: string };
      const answer = (await res.clone().json()) as { error?: string };
      sent.push({ assertion: body.client_assertion, status: res.status, error: answer.error });
    }
    return res;
  };
  return { fetch: f, sent };
}

describe.skipIf(!enabled)("a client assertion across the nonce retry", () => {
  let stack = { url: "", work: "", procs: [] as ChildProcess[] };
  let clientKey: DpopKey;

  beforeAll(async () => {
    clientKey = await DpopKey.generate();
    stack = await startStack(`[token]\ndpop_nonce = "required"\n\n${signerAgent(clientKey)}`);
  });

  afterAll(async () => {
    await stopStack(stack.procs, stack.work);
  });

  it("is sent again with a proof that carries the nonce, and accepted", async () => {
    // A fresh client's first exchange is refused `use_dpop_nonce`; the retry sends the same
    // assertion with the nonce, and the server accepts it. The next exchange has the nonce
    // already: one request.
    const { url } = stack;
    const key = await DpopKey.generate();
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const root = () =>
      admin.mintRootDev("alice", "https://idp.example", "assistant", {
        capabilities: ["github:*"],
        dpopKey: key,
      });
    const [firstRoot, laterRoot] = [await root(), await root()];
    const rec = recordingFetch();
    const ob = new AttenuoClient(url, { dpopKey: key, fetch: rec.fetch });

    let assertion = await clientKey.clientAssertion("signer", url);
    let child = await ob.exchange(firstRoot, "signer", ["github:read_file"], {
      clientAssertion: assertion,
    });
    expect(child.dpopJkt).toBe(key.thumbprint);
    expect(child.chain.hops.at(-1)?.agent).toBe("signer");
    expect(rec.sent).toEqual([
      { assertion, status: 401, error: "use_dpop_nonce" },
      { assertion, status: 200, error: undefined },
    ]);

    rec.sent.length = 0;
    assertion = await clientKey.clientAssertion("signer", url);
    child = await ob.exchange(laterRoot, "signer", ["github:read_file"], {
      clientAssertion: assertion,
    });
    expect(rec.sent).toEqual([{ assertion, status: 200, error: undefined }]);
    // The bound child works through the proxy.
    const res = await ob.callTool(child, "github", "read_file", { repo: "alice/public-docs" });
    expect(res.decisionId).toBeTruthy();
  });
});

describe.skipIf(!enabled)("a client assertion across the load retry", () => {
  // `token_requests_per_minute = 1`, and an issuer key and audit store (leases, spent
  // credentials) in files: a restart keeps the tokens and every spent assertion and forgets only
  // the rate limit's minute, so the tests restart the server in place of waiting it out.
  let stack = { url: "", work: "", procs: [] as ChildProcess[] };
  let clientKey: DpopKey;
  const original = { ...retryHooks };

  beforeAll(async () => {
    clientKey = await DpopKey.generate();
    stack = await startStack(
      `[limits]\ntoken_requests_per_minute = 1\n\n${signerAgent(clientKey)}`,
      [],
      {
        edits: {
          'sqlite_path = ":memory:"': 'sqlite_path = "{work}/audit.sqlite"',
          "[issuer]\n": '[issuer]\nprivate_key_pem_path = "{work}/issuer.pem"\n',
        },
      },
    );
  });

  afterAll(async () => {
    Object.assign(retryHooks, original);
    await stopStack(stack.procs, stack.work);
  });

  it("sends the same assertion while it lasts, and throws when it would expire", async () => {
    const { url } = stack;
    const admin = new AdminClient(url, ADMIN_TOKEN);
    const roots: Token[] = [];
    for (let i = 0; i < 3; i++) {
      roots.push(
        await admin.mintRootDev("alice", "https://idp.example", "assistant", {
          capabilities: ["github:*"],
        }),
      );
    }
    const waits: number[] = [];
    retryHooks.random = () => 0;
    retryHooks.sleep = async (ms) => {
      waits.push(ms);
      await restartServer(stack);
    };
    const rec = recordingFetch();
    const ob = new AttenuoClient(url, {
      fetch: rec.fetch,
      maxRetries: 1,
      maxRetryDelayMs: 120_000,
    });
    const caps = ["github:read_file"];
    await ob.exchange(roots[0]!, "signer", caps, {
      clientAssertion: await clientKey.clientAssertion("signer", url),
    });
    expect(waits).toEqual([]);

    // Over the limit: 429 with `Retry-After` until the minute ends. The assertion lasts longer,
    // so the client waits (here: the restart) and sends it again, and it is accepted.
    rec.sent.length = 0;
    const lasting = await clientKey.clientAssertion("signer", url, { lifetime: 300 });
    const child = await ob.exchange(roots[1]!, "signer", caps, { clientAssertion: lasting });
    expect(child.chain.hops.at(-1)?.agent).toBe("signer");
    expect(waits).toHaveLength(1);
    expect(waits[0]).toBeGreaterThanOrEqual(1000);
    expect(waits[0]).toBeLessThanOrEqual(60_000);
    expect(rec.sent).toEqual([
      { assertion: lasting, status: 429, error: "rate_limited" },
      { assertion: lasting, status: 200, error: undefined },
    ]);

    // Over the limit again, with an assertion that would expire before the minute ends: not
    // sent again; the refusal is thrown at once.
    rec.sent.length = 0;
    const short = await clientKey.clientAssertion("signer", url, { lifetime: 5 });
    const err = await ob.exchange(roots[2]!, "signer", caps, { clientAssertion: short }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfter).toBeGreaterThan(5);
    expect(waits).toHaveLength(1);
    expect(rec.sent).toEqual([{ assertion: short, status: 429, error: "rate_limited" }]);

    // What the caller does: wait out `retryAfter` (here: the restart), mint, call again.
    await restartServer(stack);
    await ob.exchange(roots[2]!, "signer", caps, {
      clientAssertion: await clientKey.clientAssertion("signer", url),
    });
    expect(rec.sent.map((x) => x.status)).toEqual([429, 200]);
  });
});

/** A new Ed25519 private key, PKCS #8 PEM, written to `path`. */
function writeKey(path: string): void {
  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}

describe.skipIf(!enabled)("agents and keys reload against the real server", () => {
  // The issuer key is a file of the stack's own, and each test edits the config file.
  let stack = { url: "", work: "", procs: [] as ChildProcess[] };

  beforeAll(async () => {
    stack = await startStack("", [], {
      edits: { "[issuer]\n": '[issuer]\nprivate_key_pem_path = "{work}/issuer.pem"\n' },
    });
  });

  afterAll(async () => {
    await stopStack(stack.procs, stack.work);
  });

  it("adds an agent and refuses a file that empties the list", async () => {
    const config = join(stack.work, "config.toml");
    const text = readFileSync(config, "utf8");
    const admin = new AdminClient(stack.url, ADMIN_TOKEN);
    const same = await admin.agentsReload();
    expect([same.agents.count, same.agents.added, same.agents.removed]).toEqual([2, [], []]);
    expect([same.peps.count, same.restartNeeded]).toEqual([0, []]);
    expect(same.auditId).toBeTruthy();
    expect(same.agents.sha256).toHaveLength(64);

    const digest = createHash("sha256").update("demo-auditor-secret").digest("hex");
    writeFileSync(config, `${text}\n[[agents]]\nid = "auditor"\nsecret_sha256 = "${digest}"\n`);
    const added = await admin.agentsReload();
    expect([added.agents.count, added.agents.added]).toEqual([3, ["auditor"]]);
    expect(added.agents.sha256).not.toBe(same.agents.sha256);

    // A file cut short before its [[agents]]: refused, and nothing changes.
    writeFileSync(config, text.split("[[agents]]")[0]!);
    const err = await admin.agentsReload().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect([(err as ApiError).status, (err as ApiError).code]).toEqual([
      422,
      "agents_reload_empties",
    ]);
    writeFileSync(config, text);
    const back = await admin.agentsReload();
    expect([back.agents.removed, back.agents.count]).toEqual([["auditor"], 2]);
  });

  it("rotates the signing key, and refuses to drop the current one", async () => {
    const config = join(stack.work, "config.toml");
    const text = readFileSync(config, "utf8");
    const oldPem = join(stack.work, "issuer.pem");
    const newPem = join(stack.work, "issuer-2.pem");
    writeKey(newPem);
    const admin = new AdminClient(stack.url, ADMIN_TOKEN);
    const same = await admin.keysReload();
    expect([same.changed, same.signingKid]).toEqual([false, same.previousSigningKid]);
    expect(same.verifyingKids).toEqual([same.signingKid]);
    const oldKid = same.signingKid;

    writeFileSync(config, text.replace(oldPem, newPem));
    const err = await admin.keysReload().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect([(err as ApiError).status, (err as ApiError).code]).toEqual([
      422,
      "keys_reload_drops_current",
    ]);

    writeFileSync(
      config,
      text.replace(
        `private_key_pem_path = "${oldPem}"`,
        `private_key_pem_path = "${newPem}"\nprevious_key_paths = ["${oldPem}"]`,
      ),
    );
    const rotated = await admin.keysReload();
    expect([rotated.changed, rotated.previousSigningKid]).toEqual([true, oldKid]);
    expect(rotated.signingKid).not.toBe(oldKid);
    expect(rotated.added).toEqual([rotated.signingKid]);
    expect(rotated.verifyingKids).toEqual([rotated.signingKid, oldKid]);
    expect(rotated.auditSigningKid).toBe(rotated.signingKid);
    const jwks = (await (await fetch(`${stack.url}/.well-known/jwks.json`)).json()) as {
      keys: { kid: string }[];
    };
    expect(jwks.keys.map((k) => k.kid)).toEqual(rotated.verifyingKids);
    expect((await admin.keysReload()).changed).toBe(false);
  });
});

describe.skipIf(!enabled)("audit retention against the real server", () => {
  // A file audit log with a checkpoint every 3 entries, the file checkpoint sink,
  // `prune = "manual"` and `min_age_seconds = 5`. The run-state retentions are 0 (keep
  // everything) so that the start-up floor on `min_age_seconds` is 0, and the test makes no
  // lease, so no live run holds the boundary. The maintenance task, which deletes the pruned
  // rows, runs every second.
  let stack = { url: "", work: "", procs: [] as ChildProcess[] };

  beforeAll(async () => {
    stack = await startStack(
      "[leases]\nretention_seconds = 0\nrun_state_retention_seconds = 0\n" +
        "user_window_retention_seconds = 0\nmaintenance_interval_seconds = 1\n\n" +
        '[audit.retention]\nprune = "manual"\nmin_age_seconds = 5\n\n' +
        '[audit.sink]\nkind = "file"\npath = "{work}/shipped.jsonl"\n\n',
      [],
      {
        edits: {
          'sqlite_path = ":memory:"': 'sqlite_path = "{work}/audit.sqlite"\ncheckpoint_every = 3',
        },
      },
    );
  });

  afterAll(async () => {
    await stopStack(stack.procs, stack.work);
  });

  /** Write an export's lines to `path`; the SHA-256 of the file's bytes. */
  async function writeExport(path: string, lines: AsyncIterable<object>): Promise<string> {
    let text = "";
    for await (const l of lines) text += JSON.stringify(l) + "\n";
    writeFileSync(path, text);
    return createHash("sha256").update(text).digest("hex");
  }

  const refusal = async (p: Promise<unknown>): Promise<[number, string | undefined]> => {
    const err = await p.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    return [(err as ApiError).status, (err as ApiError).code];
  };

  it("plans, refuses, prunes and lists the anchor, which the SDK then cross-checks", async () => {
    const admin = new AdminClient(stack.url, ADMIN_TOKEN);
    const jwks = (await (await fetch(`${stack.url}/.well-known/jwks.json`)).json()) as {
      keys: unknown[];
    };
    expect((await admin.auditAnchors()).anchors).toEqual([]);
    // Admin records belong to no run, so the live-run guard does not hold them.
    for (let i = 0; i < 6; i++) await admin.policyReload();
    const early = await admin.auditPrunePlan();
    expect([early.through, early.guards.limitedBy]).toEqual([undefined, "prune_too_recent"]);
    // Until the entries are old enough: polled, not one fixed sleep, so a slow machine only
    // waits longer.
    const oldEnough = Date.now() + 60_000;
    let plan = await admin.auditPrunePlan();
    while (plan.guards.limitedBy === "prune_too_recent" && Date.now() < oldEnough) {
      await sleep(250);
      plan = await admin.auditPrunePlan();
    }
    expect([plan.from, plan.guards.limitedBy, plan.anchor]).toEqual([1, undefined, undefined]);
    const through = plan.through!;
    expect(plan.checkpoint?.seq).toBe(through);
    expect(plan.entries).toBe(through);
    const archive = join(stack.work, "archive.jsonl");
    const digest = await writeExport(archive, admin.auditExport(1, through));

    // A boundary that is not a checkpoint is refused, with the server's code.
    expect(await refusal(admin.auditPrune(through - 1, { archiveSha256: digest }))).toEqual([
      409,
      "prune_not_at_checkpoint",
    ]);
    const done = await admin.auditPrune(through, { archiveSha256: digest, from: 1 });
    expect([done.prunedThrough, done.already]).toEqual([through, false]);
    expect([done.anchor.through_seq, done.anchor.archive_sha256]).toEqual([through, digest]);
    expect(done.shipped).toBeDefined();
    const again = await admin.auditPrune(through, { archiveSha256: digest });
    expect([again.already, again.anchor.signature]).toEqual([true, done.anchor.signature]);
    expect(await refusal(admin.auditPrune(through, { archiveSha256: "f".repeat(64) }))).toEqual([
      409,
      "prune_conflict",
    ]);
    expect(await refusal(admin.auditPrune(through - 3, { archiveSha256: digest }))).toEqual([
      410,
      "audit_pruned",
    ]);

    const page = await admin.auditAnchors({ limit: 10 });
    expect(page.anchors.map((a) => a.through_seq)).toEqual([through]);
    expect(page.nextCursor).toBeUndefined();
    expect([page.anchors[0]!.signature, page.anchors[0]!.prune_seq]).toEqual([
      done.anchor.signature,
      done.pruneSeq,
    ]);
    const deadline = Date.now() + 10_000;
    for (;;) {
      const a = (await admin.auditAnchors()).anchors[0]!;
      if (a.state === "done" && typeof a.shipped_at === "string") break;
      if (Date.now() > deadline) throw new Error(`the prune did not finish: ${JSON.stringify(a)}`);
      await sleep(100);
    }

    // The retained export starts from the anchor; it and the archive verify as one log, and it
    // cross-checks against what the sink shipped, anchor included.
    const retained = join(stack.work, "retained.jsonl");
    await writeExport(retained, admin.auditExport(through + 1));
    const opts = { checkpointPublicKeys: jwks };
    const r = await verifyExports([{ path: archive }, { path: retained }], opts);
    expect(r.ok).toBe(true);
    const c = await crossCheck(
      { path: retained },
      { path: join(stack.work, "shipped.jsonl") },
      opts,
    );
    expect(c.ok).toBe(true);
    expect([c.anchors.shipped, c.anchors.checked, c.anchors.matched]).toEqual([1, 1, 1]);
  });
});

describe.skipIf(!enabled)("a TLS client certificate against the real server", () => {
  let stack: { url: string; work: string; procs: ChildProcess[] } | undefined;
  let tls: { dir: string; remove: () => void } | undefined;
  let ca = "";
  let coder: ClientCert;

  beforeAll(async () => {
    tls = tempDir();
    const authority = new Ca(tls.dir, "it-ca");
    const leaf = authority.leaf(["IP:127.0.0.1"], "server");
    coder = new ClientCert(tls.dir, "coder");
    ca = authority.certPath;
    const coderSecretSha256 = createHash("sha256").update(CODER_SECRET).digest("hex");
    stack = await startStack("", [], {
      tls: { cert: leaf.certPath, key: leaf.keyPath, ca },
      // The coder agent is pinned by its certificate, with no secret.
      edits: {
        [`secret_sha256 = "${coderSecretSha256}"`]: `tls_client_cert_sha256 = ["${coder.sha256}"]`,
      },
    });
  }, 60_000);

  afterAll(async () => {
    if (stack) await stopStack(stack.procs, stack.work);
    tls?.remove();
  });

  it("exchanges with the certificate alone, and is refused without it", async () => {
    const url = stack!.url;
    const admin = new AdminClient(url, ADMIN_TOKEN, { tlsCaCert: ca });
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const caps = [capability("github", "read_file")];
    const ob = new AttenuoClient(url, {
      tlsCaCert: ca,
      tlsClientCert: coder.certPath,
      tlsClientKey: coder.keyPath,
    });
    const token = await ob.exchange(root, "coder", caps);
    expect(token.agent).toBe("coder");
    const result = await ob.callTool(token, "github", "read_file", {
      repo: "alice/public-docs",
      path: "README.md",
    });
    expect(result.isError).toBe(false);

    const noCert = new AttenuoClient(url, { tlsCaCert: ca });
    const e = await noCert.exchange(root, "coder", caps).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).status).toBe(401);
    // The server's certificate is checked: a client trusting another CA cannot connect.
    const stranger = new Ca(tls!.dir, "stranger");
    const refused = new AttenuoClient(url, { tlsCaCert: stranger.certPath });
    await expect(refused.exchange(root, "coder", caps)).rejects.toBeInstanceOf(TransportError);
  });
});

describe.skipIf(!enabled)("a CA-issued client certificate against the real server", () => {
  const spiffeId = "spiffe://example.org/ns/agents/sa/coder";
  let stack: { url: string; work: string; procs: ChildProcess[] } | undefined;
  let tls: { dir: string; remove: () => void } | undefined;
  let ca = "";
  let chainPath = "";
  let leafPath = "";
  let keyPath = "";

  beforeAll(async () => {
    tls = tempDir();
    const authority = new Ca(tls.dir, "it-ca");
    const server = authority.leaf(["IP:127.0.0.1"], "server");
    ca = authority.certPath;
    // The agents' root CA, an intermediate under it, and coder's certificate from the
    // intermediate: the server trusts the root only.
    const root = new Ca(tls.dir, "agents-root");
    const mid = new Ca(tls.dir, "agents-mid", root);
    const leaf = mid.leaf([`URI:${spiffeId}`], "coder", "clientAuth");
    leafPath = leaf.certPath;
    keyPath = leaf.keyPath;
    chainPath = join(tls.dir, "coder-chain.crt");
    writeFileSync(chainPath, leaf.cert + mid.pem);
    const coderSecretSha256 = createHash("sha256").update(CODER_SECRET).digest("hex");
    stack = await startStack("", [], {
      tls: { cert: server.certPath, key: server.keyPath, ca },
      edits: {
        [`secret_sha256 = "${coderSecretSha256}"`]:
          `tls_client_ca_pem_path = "${root.certPath}"\n` +
          `tls_client_auth_san_uri = "${spiffeId}"`,
      },
    });
  }, 60_000);

  afterAll(async () => {
    if (stack) await stopStack(stack.procs, stack.work);
    tls?.remove();
  });

  it("exchanges with the leaf and its intermediate, and is refused with the leaf alone", async () => {
    const url = stack!.url;
    const admin = new AdminClient(url, ADMIN_TOKEN, { tlsCaCert: ca });
    const root = await admin.mintRootDev("alice", "https://idp.example", "assistant", {
      capabilities: ["github:*"],
    });
    const caps = [capability("github", "read_file")];
    const withChain = new AttenuoClient(url, {
      tlsCaCert: ca,
      tlsClientCert: chainPath,
      tlsClientKey: keyPath,
    });
    expect((await withChain.exchange(root, "coder", caps)).agent).toBe("coder");

    const leafOnly = new AttenuoClient(url, {
      tlsCaCert: ca,
      tlsClientCert: leafPath,
      tlsClientKey: keyPath,
    });
    const e = await leafOnly.exchange(root, "coder", caps).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).status).toBe(401);
  });
});

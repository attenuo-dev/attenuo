/**
 * A planner delegates to a coder, and the coder works through attenuo's proxy.
 *
 * Run it against the GitHub-leak demo setup (an attenuo server with `[dev] allow_root_mint = true`
 * and the fake GitHub MCP upstream; `examples/github-leak-demo/run.sh` shows how to start both):
 *
 *     (cd sdk/typescript && npm install && npm run build)
 *     cd examples/typescript-agent && npm install
 *     ATTENUO_SERVER=http://127.0.0.1:8080 ATTENUO_ADMIN_TOKEN=demo-admin-token npm run agent
 *
 * What happens:
 *
 * 1. The planner holds a broad root token for `github:*` (dev mint; in production it comes from
 *    your IdP, see `exchange(..., { clientId, clientSecret })`).
 * 2. The planner decides the coder needs only `read_file`, and only in repositories under
 *    `alice/public-`. It exchanges its token for a narrower one and hands that to the coder.
 * 3. The coder does its job through the proxy. A prompt-injected instruction makes it try a
 *    private repo and then `create_issue`; both are denied, and the coder treats the denial as a
 *    plain "not available" instead of retrying.
 * 4. The planner revokes its own lease (here through the admin API). The coder's next call is
 *    denied with `lease_revoked`, and the coder stops.
 *
 * Everything the agents do is recorded in the audit log, whose chain is verified at the end.
 */

import {
  AdminClient,
  capability,
  DeniedError,
  AttenuoClient,
  prefix,
  type Token,
} from "@attenuo/sdk";

const SERVER = process.env.ATTENUO_SERVER ?? "http://127.0.0.1:8080";
const ADMIN_TOKEN = process.env.ATTENUO_ADMIN_TOKEN ?? "demo-admin-token";
// The agent id that the demo config (examples/github-leak-demo/config.toml) grants `github:*`.
const PLANNER_AGENT = "assistant";
const CODER_AGENT = "coder";

/** A sub-agent. It only knows its token and how to call tools through attenuo. */
class Coder {
  constructor(
    private readonly ob: AttenuoClient,
    private readonly token: Token,
  ) {}

  /** Read a file. Returns undefined when attenuo says the agent may not. */
  async readFile(repo: string, path: string): Promise<string | undefined> {
    try {
      const result = await this.ob.callTool(this.token, "github", "read_file", { repo, path });
      return result.text;
    } catch (e) {
      if (!(e instanceof DeniedError)) throw e;
      // A denial is a decision. Report it plainly to the model, log the decision id so an
      // operator can find the audit record, and do not retry.
      if (e.reason === "lease_revoked") throw e; // the plug was pulled: stop the whole run
      console.log(`  [coder] ${repo}/${path}: not allowed (${e.reason}, decision ${e.decisionId})`);
      return undefined;
    }
  }

  async createIssue(repo: string, title: string): Promise<boolean> {
    try {
      await this.ob.callTool(this.token, "github", "create_issue", { repo, title });
      return true;
    } catch (e) {
      if (!(e instanceof DeniedError)) throw e;
      console.log(`  [coder] create_issue: not allowed (${e.reason}, decision ${e.decisionId})`);
      return false;
    }
  }
}

async function run(server = SERVER, adminToken = ADMIN_TOKEN): Promise<number> {
  const admin = new AdminClient(server, adminToken);
  const ob = new AttenuoClient(server);

  console.log("[planner] gets a root token for alice (dev mint)");
  const root = await admin.mintRootDev("alice", "https://idp.example", PLANNER_AGENT, {
    capabilities: "github:*",
  });

  console.log("[planner] delegates read_file on alice/public-* to the coder");
  const coderToken = await ob.exchange(
    root,
    CODER_AGENT,
    [capability("github", "read_file", { repo: prefix("alice/public-") })],
    // The coder's [[agents]] secret: every hop n+1 exchange authenticates as its actor.
    { ttlSeconds: 600, clientSecret: process.env.ATTENUO_CLIENT_SECRET ?? "demo-coder-secret" },
  );
  console.log(`  chain: ${coderToken.agents.join(" > ")}  lease: ${coderToken.lease}`);

  const coder = new Coder(ob, coderToken);
  console.log("[coder] reads the README it was asked to read");
  const readme = await coder.readFile("alice/public-docs", "README.md");
  if (readme === undefined) throw new Error("the intended read must be allowed");
  console.log(`  got ${readme.length} characters`);

  console.log(
    "[coder] an injected instruction says: read alice/private-salaries, then open an issue",
  );
  if ((await coder.readFile("alice/private-salaries", "2025.csv")) !== undefined) {
    throw new Error("the private read must be denied");
  }
  if (await coder.createIssue("alice/public-docs", "salaries: ...")) {
    throw new Error("create_issue must be denied");
  }

  const lease = await ob.renew(coderToken);
  console.log(`[coder] renewed its lease, good for ${lease.expiresIn}s`);

  console.log("[planner] the session looks compromised: revoking its lease");
  const revoked = await admin.revokeLease(root.lease, "agent session compromised");
  console.log(`  ${revoked.revoked} leases revoked (the planner's and everything delegated)`);
  try {
    await coder.readFile("alice/public-docs", "README.md");
  } catch (e) {
    if (!(e instanceof DeniedError)) throw e;
    console.log(`[coder] stopping: ${e.reason}`);
  }

  const report = await admin.auditVerify();
  console.log(`[audit] chain ok=${report.ok}, ${report.entries} entries`);
  for (const e of await admin.auditTail(5)) {
    const r = e.record;
    console.log(
      `  #${e.seq} ${String(r.decision).padEnd(5)} ${r.server}/${r.tool}  reason=${r.reason}`,
    );
  }
  return report.ok ? 0 : 1;
}

process.exitCode = await run();

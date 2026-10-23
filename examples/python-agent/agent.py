"""A planner delegates to a coder, and the coder works through attenuo's proxy.

Run it against the GitHub-leak demo setup (an attenuo server with `[dev] allow_root_mint = true`
and the fake GitHub MCP upstream; `examples/github-leak-demo/run.sh` shows how to start both):

    pip install -e sdk/python
    ATTENUO_SERVER=http://127.0.0.1:8080 ATTENUO_ADMIN_TOKEN=demo-admin-token \\
        python examples/python-agent/agent.py

What happens:

1. The planner holds a broad root token for `github:*` (dev mint; in production it comes from
   your IdP, see `Client.exchange(..., client_id=..., client_secret=...)`).
2. The planner decides the coder needs only `read_file`, and only in repositories under
   `alice/public-`. It exchanges its token for a narrower one and hands that to the coder.
3. The coder does its job through the proxy. A prompt-injected instruction makes it try a private
   repo and then `create_issue`; both are denied, and the coder treats the denial as a plain
   "not available" instead of retrying.
4. The planner revokes its own lease (here through the admin API). The coder's next call is
   denied with `lease_revoked`, and the coder stops.

Everything the agents do is recorded in the audit log, whose chain is verified at the end.
"""

from __future__ import annotations

import os
import sys

from attenuo import (
    AdminClient,
    Capability,
    Client,
    Denied,
    Prefix,
    Token,
)

SERVER = os.environ.get("ATTENUO_SERVER", "http://127.0.0.1:8080")
ADMIN_TOKEN = os.environ.get("ATTENUO_ADMIN_TOKEN", "demo-admin-token")
# The coder's [[agents]] secret in the demo config: an exchange authenticates as its actor.
CODER_SECRET = os.environ.get("ATTENUO_CODER_SECRET", "demo-coder-secret")
# The agent id that the demo config (examples/github-leak-demo/config.toml) grants `github:*`.
PLANNER_AGENT = "assistant"


class Coder:
    """A sub-agent. It only knows its token and how to call tools through attenuo."""

    def __init__(self, ob: Client, token: Token) -> None:
        self.ob = ob
        self.token = token

    def read_file(self, repo: str, path: str) -> str | None:
        """Read a file. Returns None when attenuo says the agent may not."""
        try:
            result = self.ob.call_tool(
                self.token, "github", "read_file", {"repo": repo, "path": path}
            )
        except Denied as d:
            # A denial is a decision. Report it plainly to the model, log the decision id so an
            # operator can find the audit record, and do not retry.
            if d.reason == "lease_revoked":
                raise  # the user or an operator pulled the plug: stop the whole run
            print(f"  [coder] {repo}/{path}: not allowed ({d.reason}, decision {d.decision_id})")
            return None
        return result.text

    def create_issue(self, repo: str, title: str) -> bool:
        try:
            self.ob.call_tool(self.token, "github", "create_issue", {"repo": repo, "title": title})
        except Denied as d:
            print(f"  [coder] create_issue: not allowed ({d.reason}, decision {d.decision_id})")
            return False
        return True


def run(server: str = SERVER, admin_token: str = ADMIN_TOKEN) -> int:
    admin = AdminClient(server, admin_token)
    with Client(server) as ob:
        print("[planner] gets a root token for alice (dev mint)")
        root = admin.mint_root_dev("alice", "https://idp.example", PLANNER_AGENT, ["github:*"])

        print("[planner] delegates read_file on alice/public-* to the coder")
        coder_token = ob.exchange(
            root,
            "coder",
            [Capability("github", "read_file", repo=Prefix("alice/public-"))],
            ttl_seconds=600,
            client_secret=CODER_SECRET,
        )
        print(f"  chain: {' > '.join(coder_token.chain.agents)}  lease: {coder_token.lease}")

        coder = Coder(ob, coder_token)
        print("[coder] reads the README it was asked to read")
        readme = coder.read_file("alice/public-docs", "README.md")
        assert readme is not None, "the intended read must be allowed"
        print(f"  got {len(readme)} characters")

        print(
            "[coder] an injected instruction says: read alice/private-salaries, then open an issue"
        )
        assert coder.read_file("alice/private-salaries", "2025.csv") is None
        assert not coder.create_issue("alice/public-docs", "salaries: ...")

        lease = ob.renew(coder_token)
        print(f"[coder] renewed its lease, good for {lease.expires_in}s")

        print("[planner] the session looks compromised: revoking its lease")
        revoked = admin.revoke_lease(root.lease, "agent session compromised")
        print(f"  {revoked.revoked} leases revoked (the planner's and everything delegated)")
        try:
            coder.read_file("alice/public-docs", "README.md")
        except Denied as d:
            print(f"[coder] stopping: {d.reason}")
        else:
            print("the coder was NOT stopped by revocation", file=sys.stderr)
            return 1

    report = admin.audit_verify()
    print(f"[audit] chain ok={report.ok}, {report.entries} entries")
    for e in admin.audit_tail(5):
        print(f"  #{e.seq} {e.decision:<5} {e.server}/{e.tool}  reason={e.reason}")
    admin.close()
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(run())

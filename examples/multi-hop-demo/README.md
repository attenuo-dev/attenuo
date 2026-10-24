# Multi-hop delegation demo

> The demo config sets `[dev] allow_root_mint = true` so step 1 can mint the planner's root token without an identity provider. Real deployments leave that off and mint root tokens at `POST /token` from an OIDC ID token or ID-JAG (see [identity providers](../../docs/guides/identity-providers.md)).

Alice asks a planner agent to fix a bug in the `acme/api` repository. The planner reads the issues, decides what needs doing and hands the coding to a coder sub-agent. The coder calls the GitHub MCP server's tools. Each hand-off is an RFC 8693 token exchange, and each one narrows what the next agent can do: the planner holds less than alice could grant, the coder holds less than the planner, and nobody below the coder holds anything at all. Then the operator ends the whole run with one revocation.

| Hop | Agent | Holds |
| --- | --- | --- |
| user | alice | the person the run is for (`sub` of every token, the originating user of every audit record) |
| 1 | planner | `get_file_contents`, `list_issues`, `create_issue`, `create_or_update_file`, each with `repo` starting with `acme/`; `may_act: [coder]`, so only the coder may exchange its token |
| 2 | coder | `get_file_contents` and `create_or_update_file` with `repo` starting with `acme/api`, a `distinct` run limit of 1 on `repo` (one repository per run); no `list_issues`, no `create_issue`; `may_act: []`, so nobody may exchange its token |

The policy (`policy.cedar`) holds for every hop: reads anywhere under `acme/`, writes only to `agent/*` branches, never to `main`, and no third agent below the coder.

## Run it

```sh
examples/multi-hop-demo/run.sh
```

It needs a Rust toolchain, `curl` and `python3`, and no network beyond loopback: there is no model, the GitHub server is the fake MCP upstream the other examples use (started with the real GitHub MCP server's tool names), and every call goes through attenuo on a random local port. Everything lives in a temp directory that an exit trap removes (`KEEP=1` keeps it for the logs); `ATTENUO_BIN_DIR=DIR` uses prebuilt binaries instead of `cargo build`. The script checks the exit status and the decision of every step, the audit entry count (12) and the number of calls that reached the upstream (2), and exits non-zero if anything comes out differently, so CI runs it as a test.

The policy has its own tests, which need no server (`run.sh` runs them first):

```sh
cargo run -q -p attenuo-cli -- policy test examples/multi-hop-demo/policy_test.yaml
cargo run -q -p attenuo-cli -- policy lint examples/multi-hop-demo/policy.cedar --config examples/multi-hop-demo/config.toml
```

## What happens

| Step | Who | Request | Result | Why |
| --- | --- | --- | --- | --- |
| 1 | alice → planner | exchange 1: root token for `planner`, `--may-act coder` | issued, lease = the chain id | Takes the `[[root_grants]]` ceiling: four tools, `repo` under `acme/`. |
| 2 | planner | `list_issues acme/api` | allowed, reaches upstream | Hop 1 can read issues; the coder will not be able to. |
| 3 | planner → coder | exchange: `github:get_file_contents` on any repo | refused, `invalid_scope` | Not covered by the parent's last hop, which has it only under `acme/`. A token can only narrow. |
| 4 | planner → coder | exchange 2: the narrowed set above, `may_act: []` | issued | Authenticated as `coder` (HTTP Basic, secret on stdin). The raw RFC 8693 JSON request, because the CLI's `--may-act` cannot say "nobody". |
| 5 | | `token inspect --verify` | two hops, each narrower | The chain, constraints and limits are in the token and verify against the JWKS. |
| 6 | coder → reviewer | exchange 3: one capability, authenticated as `reviewer` | refused, `invalid_request` (`may_act`) | The coder's token says nobody may exchange it. |
| 7 | coder | `get_file_contents acme/api src/lib.rs` | allowed, reaches upstream | The intended read. Charges the `distinct` limit with `acme/api`. |
| 8 | coder | `create_or_update_file acme/api` on `main` | denied, `policy_deny` | The token allows the write; the policy `no_writes_to_default_branch` does not. |
| 9 | coder | `create_issue acme/api` | denied, `capability_denied` | The planner never delegated `create_issue`. |
| 10 | coder | `get_file_contents acme/api-client` | denied, `budget_exhausted` | Inside the coder's prefix and allowed by policy, but the run limit allows one repository and `acme/api` was the first. |
| 11 | operator | `lease tree`, `lease revoke --chain-id … --preview` | 2 leases would be revoked | The tree shows the coder's budget: `distinct repo 1/1 (0 left)`. The preview changes nothing. |
| 12 | operator | `lease revoke --chain-id <planner lease>` | 2 leases revoked | `POST /admin/leases/revoke` with `chain_id`: the planner's lease and everything delegated from it. |
| 13 | coder | the read that worked in step 7 | denied, `lease_revoked` | The coder's token is still unexpired; its lease is not. |
| 14 | operator | `audit tail`, `audit verify` | 12 entries, chain OK | Below. |
| 15 | operator | `audit show --id <step 8's decision>` | the decision chain | Both hops (`planner > coder for alice`), the deciding policy, the chain id, the hashes, and both leases, revoked now. |

At the end the script prints what the fake GitHub server received: two `tools/call`s, the planner's list and the coder's read. The four denied calls never left attenuo.

### The 12 audit entries

1 the root token, 2 the dev mint (admin), 3 and 4 the planner's `list_issues` and its `tool_result`, 5 the exchange to the coder, 6 and 7 the coder's read and its `tool_result`, 8 the write to `main` (`policy_deny`), 9 `create_issue` (`capability_denied`), 10 the second repository (`budget_exhausted`), 11 the revocation (admin), 12 the read after it (`lease_revoked`). The two refused exchanges (steps 3 and 6) are not in the log: the server answers them with a 400 and writes no record, so they appear only in the server's log. The preview in step 11 writes nothing either.

## Transcript

Output of `examples/multi-hop-demo/run.sh` from one real run. Ports, lease ids, decision ids, hashes and timestamps differ on every run, and tokens are shortened for display.

```text
== Setup
# attenuo at http://127.0.0.1:40771 proxies a fake GitHub MCP server at port 59415 as 'github'.
# Policy: reads anywhere in acme/, writes only to agent/* branches, never to main. See policy.cedar.
# The policy's tests run offline first (policy_test.yaml).
$ attenuo policy test examples/multi-hop-demo/policy_test.yaml
examples/multi-hop-demo/policy_test.yaml
  ✓ the coder reads a file in acme/api  (allow: policy_allow [read_in_acme])
  ✓ the coder's write to main is refused by policy, though its token allows the write  (deny: policy_deny [no_writes_to_default_branch])
  ✓ a read of a second acme/api repository passes policy (the server's run limit refuses it)  (allow: policy_allow [read_in_acme])
  ✓ the coder cannot open issues, the planner did not delegate create_issue  (deny: capability_denied)
  ✓ the coder cannot read acme repositories outside acme/api  (deny: capability_denied)
  ✓ the coder cannot list issues, even in acme/api  (deny: capability_denied)
  ✓ the coder may write to an agent branch  (allow: policy_allow [write_to_agent_branches])
  ✓ the planner reads issues across acme  (allow: policy_allow [read_in_acme])
  ✓ the planner opens an issue in acme  (allow: policy_allow [open_issues_in_acme])
  ✓ the planner's token stops at the acme organisation  (deny: capability_denied)
  ✓ reads outside acme get no permit  (deny: policy_deny)
  ✓ a write without a branch is refused  (deny: policy_deny [no_writes_to_default_branch])
  ✓ a write to master is refused like one to main  (deny: policy_deny [no_writes_to_default_branch])
  ✓ a third agent below the coder is refused even for a read  (deny: policy_deny [forbid_chains_past_the_coder])

14 passed, 0 failed (14 cases in 1 file)
all 5 policies exercised

== 1. Exchange 1, alice -> planner: the planner's root token (hop 1)
# Read files and issues, open issues and write files, all only under acme/. may_act: only the
# coder may exchange this token. (The dev mint stands in for an OIDC ID token at POST /token.)
$ attenuo token root --subject alice --agent planner --may-act coder
lease       7579e3cc-dc12-4e64-b025-99813a775185
expires_in  900s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 2. The planner looks at the issues it was asked to plan for: allowed
$ ATTENUO_TOKEN="$PLANNER" attenuo call --server github --tool list_issues --arg repo=acme/api
ALLOWED
{"arguments":{"repo":"acme/api"},"name":"list_issues"}

== 3. Refused exchange: the coder asks for get_file_contents on any repository
# The coder authenticates as itself (its secret on stdin). The parent's last hop covers
# get_file_contents only under acme/, so a capability with no repo constraint is wider: refused.
$ printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$PLANNER" attenuo token exchange --actor coder --client-secret-stdin --cap github:get_file_contents
error: server answered 400 Bad Request: invalid_scope: delegation chain is invalid: hop 1 widens capabilities relative to hop 0: requested capability `github:get_file_contents` is not covered by the parent capability set

== 4. Exchange 2, planner -> coder (hop 2), narrowed at every point
# repo narrowed from acme/ to acme/api, a distinct limit of 1 on repo (one repository per run),
# no list_issues, no create_issue, and may_act: [] so nobody may exchange it. The CLI's --may-act
# cannot say 'nobody', so this one is the raw RFC 8693 request, credentials on stdin:
$ cat examples/multi-hop-demo/coder-exchange.json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "$PLANNER_TOKEN",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "actor": "coder",
  "authorization_details": [
    {
      "type": "attenuo_capabilities",
      "capabilities": [
        {
          "server": "github",
          "tool": "get_file_contents",
          "constraints": { "repo": { "op": "prefix", "value": "acme/api" } },
          "limits": { "distinct": { "arg": "repo", "max": 1 } }
        },
        {
          "server": "github",
          "tool": "create_or_update_file",
          "constraints": { "repo": { "op": "prefix", "value": "acme/api" } },
          "limits": { "distinct": { "arg": "repo", "max": 1 } }
        }
      ]
    }
  ],
  "may_act": [],
  "requested_ttl_seconds": 600
}
$ printf "user = \"coder:demo-coder-secret\"\n" | curl -sS -K - -H "content-type: application/json" --data-binary @"$WORK/coder-exchange.json" "$ATTENUO_SERVER/token" | tee "$WORK/coder.json" | show_issued
lease       f394e221-96af-48b4-84ec-4068f73d6d96
expires_in  600s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...
type        urn:ietf:params:oauth:token-type:jwt

== 5. What the coder's token says: two hops, each narrower than the one above
$ attenuo token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-24T20:03:11Z
└─ agent planner
     can   github:create_issue {repo starts with "acme/"}, github:create_or_update_file {repo starts with "acme/"}, github:get_file_contents {repo starts with "acme/"}, github:list_issues {repo starts with "acme/"}
     until 2026-10-24T20:18:11Z (in 14m 59s)
     lease 7579e3cc-dc12-4e64-b025-99813a775185
   └─ agent coder  <- holds this token
        can   github:create_or_update_file {repo starts with "acme/api"} [distinct repo <= 1], github:get_file_contents {repo starts with "acme/api"} [distinct repo <= 1]
        until 2026-10-24T20:13:11Z (in 9m 59s)
        lease f394e221-96af-48b4-84ec-4068f73d6d96

iss http://127.0.0.1:40771   aud attenuo   jti bf822797-4521-449d-94a9-1cce8257cb8f
exp 2026-10-24T20:13:11Z (in 9m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 6. Exchange 3, refused: the coder tries to hand its token to a reviewer agent
# The reviewer authenticates fine, but the coder's token carries may_act: [].
$ printf "%s\n" demo-reviewer-secret | ATTENUO_TOKEN="$CODER" attenuo token exchange --actor reviewer --client-secret-stdin --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"equals","value":"acme/api"}}}'
error: server answered 400 Bad Request: invalid_request: agent `reviewer` is not permitted to act on this token (may_act)

== 7. The coder reads the file it was asked to fix: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
ALLOWED
{"arguments":{"path":"src/lib.rs","repo":"acme/api"},"name":"get_file_contents"}

== 8. The coder pushes its fix straight to main: denied by policy
# create_or_update_file on acme/api is in the coder's token; the policy wants an agent/* branch.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_or_update_file --arg repo=acme/api --arg path=src/lib.rs --arg branch=main --arg content="fn fixed() {}"
DENIED  policy_deny
decision 93494a86-c8d5-4d67-ae30-06249c7d1659

== 9. The coder tries to open an issue: denied, the planner never delegated create_issue
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_issue --arg repo=acme/api --arg title="fix pushed"
DENIED  capability_denied
decision dcb46ca7-4703-48ca-9bd3-ad95915b559f

== 10. The coder reads from a second repository under acme/api: denied by the run limit
# acme/api-client is inside the coder's repo prefix and the policy allows the read, but the
# distinct limit allows one repository per run and acme/api was the first.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api-client --arg path=README.md
DENIED  budget_exhausted
decision afc9e451-ca4b-4f1f-a90c-cc3af9e77673

== 11. The operator looks at the chain before acting
# The chain id is the planner's lease, the first hop's (also the chain_id of every audit record).
$ attenuo lease tree "$PLANNER_LEASE"
root lease (no ancestors)
7579e3cc-dc12-4e64-b025-99813a775185  planner  active, expires 2026-10-24T20:08:11.346896237Z  issued #1
└─ f394e221-96af-48b4-84ec-4068f73d6d96  coder  active, expires 2026-10-24T20:08:11.41791925Z  issued #5
        limit github/create_or_update_file distinct repo 0/1 (1 left)
        limit github/get_file_contents distinct repo 1/1 (0 left)
would revoke 2 lease(s) if revoked now
$ attenuo lease revoke --chain-id "$PLANNER_LEASE" --preview
preview: nothing was changed
selector  chain_id 7579e3cc-dc12-4e64-b025-99813a775185
matched   2 lease(s)
would revoke 2 lease(s)
  7579e3cc-dc12-4e64-b025-99813a775185
  f394e221-96af-48b4-84ec-4068f73d6d96

== 12. The operator revokes the whole chain by chain_id
$ attenuo lease revoke --chain-id "$PLANNER_LEASE" --reason "planner run went wrong"
selector  chain_id 7579e3cc-dc12-4e64-b025-99813a775185
matched   2 lease(s)
revoked 2 lease(s)
  7579e3cc-dc12-4e64-b025-99813a775185
  f394e221-96af-48b4-84ec-4068f73d6d96
reason    planner run went wrong
audit     f408dcd9-2b12-42d7-94d9-b890e9bfd5c8

== 13. The coder's next call, even the one that worked before, is denied
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
DENIED  lease_revoked
decision 59972648-36b7-499a-a44a-cc0a375b5ce6

== 14. The audit log records every decision, and its hash chain checks out
$ attenuo audit tail -n 50
#1    2026-10-24T20:03:11.346896237Z  ALLOW attenuo/token.root  planner for alice  reason=token_issued  id=e776cd0a-3a67-4858-9443-c3da1156b072
#2    2026-10-24T20:03:11.346896237Z  ALLOW attenuo/admin.root_token  by urn:attenuo:admin  reason=admin_action  id=505674f5-da95-41b3-b916-6d4d712a2e30
#3    2026-10-24T20:03:11.369589598Z  ALLOW github/list_issues  planner for alice  reason=policy_allow  id=b4711520-a7d8-4b09-94a6-b1a8455ae2a2
#4    2026-10-24T20:03:11.378506582Z  tool_result  github/list_issues  planner for alice  decision=b4711520-a7d8-4b09-94a6-b1a8455ae2a2  label=untrusted size=119  id=26cb0dd9-010a-4aa1-8769-1a88e03a3bda
#5    2026-10-24T20:03:11.41791925Z  ALLOW attenuo/token.exchange  planner > coder for alice  reason=token_issued  id=74f32851-2aae-40c8-96e6-3ce6d18efd3e
#6    2026-10-24T20:03:11.515068227Z  ALLOW github/get_file_contents  planner > coder for alice  reason=policy_allow  id=904898f1-17e1-489d-bc6a-d9366061338e
#7    2026-10-24T20:03:11.521505178Z  tool_result  github/get_file_contents  planner > coder for alice  decision=904898f1-17e1-489d-bc6a-d9366061338e  label=untrusted size=149  id=9f5a003d-0b58-4765-bc0a-2a53872f54e1
#8    2026-10-24T20:03:11.536324249Z  DENY  github/create_or_update_file  planner > coder for alice  reason=policy_deny  id=93494a86-c8d5-4d67-ae30-06249c7d1659
#9    2026-10-24T20:03:11.555638456Z  DENY  github/create_issue  planner > coder for alice  reason=capability_denied  id=dcb46ca7-4703-48ca-9bd3-ad95915b559f
#10   2026-10-24T20:03:11.570651107Z  DENY  github/get_file_contents  planner > coder for alice  reason=budget_exhausted  id=afc9e451-ca4b-4f1f-a90c-cc3af9e77673
#11   2026-10-24T20:03:11.608841764Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=f408dcd9-2b12-42d7-94d9-b890e9bfd5c8
#12   2026-10-24T20:03:11.623168956Z  DENY  github/get_file_contents  planner > coder for alice  reason=lease_revoked  id=59972648-36b7-499a-a44a-cc0a375b5ce6
$ attenuo audit verify
audit chain OK: 12 entries verified
checkpoints: none signed yet

== 15. The decision chain of the refused write
# The record names both hops, the policy that decided, the leases (revoked now) and its hashes.
$ attenuo audit show --id "$WRITE_DECISION"
#8    2026-10-24T20:03:11.536324249Z  DENY  github/create_or_update_file  planner > coder for alice  reason=policy_deny  id=93494a86-c8d5-4d67-ae30-06249c7d1659
kind        decision
chain       7579e3cc-dc12-4e64-b025-99813a775185
policies    no_writes_to_default_branch
hash        edb413b55521ea8071163bfa31a55e989b5a57ed1c73b0a1abe3700f330d015e
prev hash   642909ad9777e6f07747f0f732103a9451bad96773fa18bdee466054550a20d5
leases      (root first, as the registry sees them now)
  7579e3cc-dc12-4e64-b025-99813a775185  REVOKED 2026-10-24T20:03:11.608841764Z (planner run went wrong)
  f394e221-96af-48b4-84ec-4068f73d6d96  REVOKED 2026-10-24T20:03:11.608841764Z (planner run went wrong)
checkpoint  none yet: the entry is newer than every checkpoint, only the hash chain covers it
policy      not reloaded since this entry

== What reached the GitHub server
  fake-mcp: tools/call list_issues {"repo":"acme/api"}
  fake-mcp: tools/call get_file_contents {"path":"src/lib.rs","repo":"acme/api"}
  -> 2 tools/calls reached upstream (the planner's list and the coder's read). The four denied calls never left attenuo.
```

## Files

- `config.toml`: server config with the catalog (four GitHub MCP tools), the upstream, the admin token, the planner's root grant (`may_act = ["coder"]`) and the `coder` and `reviewer` agents. `run.sh` rewrites the ports and the policy path in a copy.
- `policy.cedar`: reads under `acme/`, issues under `acme/`, writes only to `agent/*` branches, a forbid on writes to `main` or `master` (or with no branch), and a forbid on chains deeper than two agents.
- `policy_test.yaml`: fourteen cases, one for every policy decision the demo makes and for what the narrowing takes away, with the demo's two token chains; all five policies are exercised. `budget_exhausted` and `lease_revoked` are server state and are checked by `run.sh` instead.
- `coder-exchange.json`: the RFC 8693 request of step 4, with the planner's token filled in by `run.sh`.
- `run.sh`.

## What this does not show

- Hop 0 comes from the development endpoint, which trusts the admin to say who alice is; a real deployment exchanges an OIDC ID token or ID-JAG at `POST /token`. The agents authenticate with client secrets from `[[agents]]`, not with workload identity (`actor_token`).
- "May not delegate further" is `may_act: []`, an empty list of agents allowed to exchange the token. `attenuo token exchange --may-act` drops empty values, so the CLI cannot ask for it and step 4 uses `curl`; the Python SDK can (`Client.exchange(..., may_act=[])`). `token inspect` does not print `may_act`. The policy's depth forbid is a second line of defence, should a deeper chain ever be issued.
- Refused exchanges leave no audit record.
- One run limit per capability: the coder's write has its own `distinct` counter, so a write to a second repository would be refused by that counter separately.

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

It needs a Rust toolchain, `curl` and `python3`, and no network beyond loopback: there is no model, the GitHub server is the fake MCP upstream the other examples use (started with the real GitHub MCP server's tool names), and every call goes through attenuo on a random local port. Everything lives in a temp directory that an exit trap removes (`KEEP=1` keeps it for the logs); `ATTENUO_BIN_DIR=DIR` uses prebuilt binaries instead of `cargo build`. The script checks the exit status and the decision of every step, the audit entry count (14) and the number of calls that reached the upstream (2), and exits non-zero if anything comes out differently, so CI runs it as a test.

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
| 3 | planner → coder | exchange: `github:get_file_contents` on any repo | refused, `invalid_scope`, audited | Not covered by the parent's last hop, which has it only under `acme/`. A token can only narrow. The refusal is a `deny` record (`exchange_widening`) whose id the error prints. |
| 4 | planner → coder | exchange 2: the narrowed set above, `may_act: []` | issued | Authenticated as `coder` (HTTP Basic, secret on stdin). The raw RFC 8693 JSON request, because the CLI's `--may-act` cannot say "nobody". |
| 5 | | `token inspect --verify` | two hops, each narrower | The chain, constraints and limits are in the token and verify against the JWKS. |
| 6 | coder → reviewer | exchange 3: one capability, authenticated as `reviewer` | refused, `invalid_request` (`may_act`), audited | The coder's token says nobody may exchange it. A `deny` record, `exchange_actor_not_permitted`. |
| 7 | coder | `get_file_contents acme/api src/lib.rs` | allowed, reaches upstream | The intended read. Charges the `distinct` limit with `acme/api`. |
| 8 | coder | `create_or_update_file acme/api` on `main` | denied, `policy_deny` | The token allows the write; the policy `no_writes_to_default_branch` does not. |
| 9 | coder | `create_issue acme/api` | denied, `capability_denied` | The planner never delegated `create_issue`. |
| 10 | coder | `get_file_contents acme/api-client` | denied, `budget_exhausted` | Inside the coder's prefix and allowed by policy, but the run limit allows one repository and `acme/api` was the first. |
| 11 | operator | `lease tree`, `lease revoke --chain-id … --preview` | 2 leases would be revoked | The tree shows the coder's budget: `distinct repo 1/1 (0 left)`. The preview changes nothing. |
| 12 | operator | `lease revoke --chain-id <planner lease>` | 2 leases revoked | `POST /admin/leases/revoke` with `chain_id`: the planner's lease and everything delegated from it. |
| 13 | coder | the read that worked in step 7 | denied, `lease_revoked` | The coder's token is still unexpired; its lease is not. |
| 14 | operator | `audit tail`, `audit verify` | 14 entries, chain OK | Below. |
| 15 | operator | `audit show --id <step 3's decision>` | the refused exchange | A `deny` of `attenuo/token.exchange` against the planner's chain, reason `exchange_widening`. |
| 16 | operator | `audit show --id <step 8's decision>` | the decision chain | Both hops (`planner > coder for alice`), the deciding policy, the chain id, the hashes, and both leases, revoked now. |

At the end the script prints what the fake GitHub server received: two `tools/call`s, the planner's list and the coder's read. The four denied calls never left attenuo.

### The 14 audit entries

1 the root token, 2 the dev mint (admin), 3 and 4 the planner's `list_issues` and its `tool_result`, 5 the refused widening exchange (`deny attenuo/token.exchange`, `exchange_widening`, the planner's chain), 6 the exchange to the coder, 7 the refused exchange to the reviewer (`exchange_actor_not_permitted`, the coder's chain), 8 and 9 the coder's read and its `tool_result`, 10 the write to `main` (`policy_deny`), 11 `create_issue` (`capability_denied`), 12 the second repository (`budget_exhausted`), 13 the revocation (admin), 14 the read after it (`lease_revoked`). A refused exchange is recorded because its subject token verified; one with a token that does not verify would only be a server log line. Neither refusal used anything up: step 4 is issued after step 3 was refused. The preview in step 11 writes nothing.

## Transcript

Output of `examples/multi-hop-demo/run.sh` from one real run. Ports, lease ids, decision ids, hashes and timestamps differ on every run, and tokens are shortened for display.

```text
== Setup
# attenuo at http://127.0.0.1:40307 proxies a fake GitHub MCP server at port 40691 as 'github'.
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
lease       fc62325d-76bb-4bae-ba45-2250dea9e15b
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
decision 10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223

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
lease       4bfeff7c-6c02-460d-8fcf-495320689e49
expires_in  600s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...
type        urn:ietf:params:oauth:token-type:jwt

== 5. What the coder's token says: two hops, each narrower than the one above
$ attenuo token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-24T20:21:14Z
└─ agent planner
     can   github:create_issue {repo starts with "acme/"}, github:create_or_update_file {repo starts with "acme/"}, github:get_file_contents {repo starts with "acme/"}, github:list_issues {repo starts with "acme/"}
     until 2026-10-24T20:36:14Z (in 14m 59s)
     lease fc62325d-76bb-4bae-ba45-2250dea9e15b
   └─ agent coder  <- holds this token
        can   github:create_or_update_file {repo starts with "acme/api"} [distinct repo <= 1], github:get_file_contents {repo starts with "acme/api"} [distinct repo <= 1]
        until 2026-10-24T20:31:15Z (in 9m 59s)
        lease 4bfeff7c-6c02-460d-8fcf-495320689e49

iss http://127.0.0.1:40307   aud attenuo   jti a632ce55-3398-4d95-b421-811f28714d0d
exp 2026-10-24T20:31:15Z (in 9m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 6. Exchange 3, refused: the coder tries to hand its token to a reviewer agent
# The reviewer authenticates fine, but the coder's token carries may_act: [].
$ printf "%s\n" demo-reviewer-secret | ATTENUO_TOKEN="$CODER" attenuo token exchange --actor reviewer --client-secret-stdin --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"equals","value":"acme/api"}}}'
error: server answered 400 Bad Request: invalid_request: agent `reviewer` is not permitted to act on this token (may_act)
decision b622ff04-fdb1-42e3-a358-7a2f9e01fce6

== 7. The coder reads the file it was asked to fix: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
ALLOWED
{"arguments":{"path":"src/lib.rs","repo":"acme/api"},"name":"get_file_contents"}

== 8. The coder pushes its fix straight to main: denied by policy
# create_or_update_file on acme/api is in the coder's token; the policy wants an agent/* branch.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_or_update_file --arg repo=acme/api --arg path=src/lib.rs --arg branch=main --arg content="fn fixed() {}"
DENIED  policy_deny
decision b9ea41e2-431f-4093-9414-5bcbe1e85bf4

== 9. The coder tries to open an issue: denied, the planner never delegated create_issue
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_issue --arg repo=acme/api --arg title="fix pushed"
DENIED  capability_denied
decision 8dacb752-5f20-4b84-b6e5-e38a097a700a

== 10. The coder reads from a second repository under acme/api: denied by the run limit
# acme/api-client is inside the coder's repo prefix and the policy allows the read, but the
# distinct limit allows one repository per run and acme/api was the first.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api-client --arg path=README.md
DENIED  budget_exhausted
decision 514278db-67fd-4919-8d3d-076469fb03a3

== 11. The operator looks at the chain before acting
# The chain id is the planner's lease, the first hop's (also the chain_id of every audit record).
$ attenuo lease tree "$PLANNER_LEASE"
root lease (no ancestors)
fc62325d-76bb-4bae-ba45-2250dea9e15b  planner  active, expires 2026-10-24T20:26:14.941809399Z  issued #1
└─ 4bfeff7c-6c02-460d-8fcf-495320689e49  coder  active, expires 2026-10-24T20:26:15.015566593Z  issued #6
        limit github/create_or_update_file distinct repo 0/1 (1 left)
        limit github/get_file_contents distinct repo 1/1 (0 left)
would revoke 2 lease(s) if revoked now
$ attenuo lease revoke --chain-id "$PLANNER_LEASE" --preview
preview: nothing was changed
selector  chain_id fc62325d-76bb-4bae-ba45-2250dea9e15b
matched   2 lease(s)
would revoke 2 lease(s)
  4bfeff7c-6c02-460d-8fcf-495320689e49
  fc62325d-76bb-4bae-ba45-2250dea9e15b

== 12. The operator revokes the whole chain by chain_id
$ attenuo lease revoke --chain-id "$PLANNER_LEASE" --reason "planner run went wrong"
selector  chain_id fc62325d-76bb-4bae-ba45-2250dea9e15b
matched   2 lease(s)
revoked 2 lease(s)
  4bfeff7c-6c02-460d-8fcf-495320689e49
  fc62325d-76bb-4bae-ba45-2250dea9e15b
reason    planner run went wrong
audit     27cb42d0-71e4-4dd2-b64c-ea28eb6eda71

== 13. The coder's next call, even the one that worked before, is denied
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
DENIED  lease_revoked
decision a75a93fa-a002-4a97-8037-ee90711ab402

== 14. The audit log records every decision, and its hash chain checks out
$ attenuo audit tail -n 50
#1    2026-10-24T20:21:14.941809399Z  ALLOW attenuo/token.root  planner for alice  reason=token_issued  id=0ace6bc6-0224-430c-a576-8d7a2782a36e
#2    2026-10-24T20:21:14.941809399Z  ALLOW attenuo/admin.root_token  by urn:attenuo:admin  reason=admin_action  id=0427c1df-cde3-49d1-925e-8a172c46971a
#3    2026-10-24T20:21:14.964186301Z  ALLOW github/list_issues  planner for alice  reason=policy_allow  id=0ea0d7a5-c601-4ba7-8cc7-bbda77ebd6e7
#4    2026-10-24T20:21:14.972275268Z  tool_result  github/list_issues  planner for alice  decision=0ea0d7a5-c601-4ba7-8cc7-bbda77ebd6e7  label=untrusted size=119  id=33362b21-aa48-439b-8d83-6a6bcb0efab9
#5    2026-10-24T20:21:14.98866813Z  DENY  attenuo/token.exchange  planner for alice  reason=exchange_widening  id=10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223
#6    2026-10-24T20:21:15.015566593Z  ALLOW attenuo/token.exchange  planner > coder for alice  reason=token_issued  id=52b02728-86a3-4bf5-b49e-e2ebacd4af6e
#7    2026-10-24T20:21:15.084209433Z  DENY  attenuo/token.exchange  planner > coder for alice  reason=exchange_actor_not_permitted  id=b622ff04-fdb1-42e3-a358-7a2f9e01fce6
#8    2026-10-24T20:21:15.103740995Z  ALLOW github/get_file_contents  planner > coder for alice  reason=policy_allow  id=73877b76-2286-4069-a52a-b48d4a9ede40
#9    2026-10-24T20:21:15.112545887Z  tool_result  github/get_file_contents  planner > coder for alice  decision=73877b76-2286-4069-a52a-b48d4a9ede40  label=untrusted size=149  id=3cf051f3-70ec-416f-a0b5-baad1bafba0b
#10   2026-10-24T20:21:15.131375034Z  DENY  github/create_or_update_file  planner > coder for alice  reason=policy_deny  id=b9ea41e2-431f-4093-9414-5bcbe1e85bf4
#11   2026-10-24T20:21:15.153413549Z  DENY  github/create_issue  planner > coder for alice  reason=capability_denied  id=8dacb752-5f20-4b84-b6e5-e38a097a700a
#12   2026-10-24T20:21:15.17014705Z  DENY  github/get_file_contents  planner > coder for alice  reason=budget_exhausted  id=514278db-67fd-4919-8d3d-076469fb03a3
#13   2026-10-24T20:21:15.213878087Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=27cb42d0-71e4-4dd2-b64c-ea28eb6eda71
#14   2026-10-24T20:21:15.229653567Z  DENY  github/get_file_contents  planner > coder for alice  reason=lease_revoked  id=a75a93fa-a002-4a97-8037-ee90711ab402
$ attenuo audit verify
audit chain OK: 14 entries verified
checkpoints: none signed yet

== 15. The refused widening exchange is in the log too
# A refused exchange whose subject token verified is a deny record against the parent's chain.
$ attenuo audit show --id "$WIDEN_DECISION"
#5    2026-10-24T20:21:14.98866813Z  DENY  attenuo/token.exchange  planner for alice  reason=exchange_widening  id=10ce6d75-b2e0-4aa7-a563-7b2fc5a8b223
kind        decision
chain       fc62325d-76bb-4bae-ba45-2250dea9e15b
hash        0413259ad5d3bdaf080eb50f1abd994b8794703c9f4ec6fcb0f11e8664c224d7
prev hash   b7275be4094ff5c39f91d3b3fa73ddbfeaf694ee1f6bd7ca2991dec22e49754e
leases      (root first, as the registry sees them now)
  fc62325d-76bb-4bae-ba45-2250dea9e15b  REVOKED 2026-10-24T20:21:15.213878087Z (planner run went wrong)
checkpoint  none yet: the entry is newer than every checkpoint, only the hash chain covers it
policy      not reloaded since this entry

== 16. The decision chain of the refused write
# The record names both hops, the policy that decided, the leases (revoked now) and its hashes.
$ attenuo audit show --id "$WRITE_DECISION"
#10   2026-10-24T20:21:15.131375034Z  DENY  github/create_or_update_file  planner > coder for alice  reason=policy_deny  id=b9ea41e2-431f-4093-9414-5bcbe1e85bf4
kind        decision
chain       fc62325d-76bb-4bae-ba45-2250dea9e15b
policies    no_writes_to_default_branch
hash        6cca9e0d709067a1a56588f127ae6e9bcce8b2b2516f6ccc566a673faf6ce819
prev hash   9ac98f274331722fd67bfd7091e990b1c1d471c09f987c7f04bb5e8555da6afe
leases      (root first, as the registry sees them now)
  fc62325d-76bb-4bae-ba45-2250dea9e15b  REVOKED 2026-10-24T20:21:15.213878087Z (planner run went wrong)
  4bfeff7c-6c02-460d-8fcf-495320689e49  REVOKED 2026-10-24T20:21:15.213878087Z (planner run went wrong)
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
- One run limit per capability: the coder's write has its own `distinct` counter, so a write to a second repository would be refused by that counter separately.

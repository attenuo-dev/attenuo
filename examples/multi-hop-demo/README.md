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
| 4 | planner → coder | exchange 2: the narrowed set above, `may_act: []` | issued | Authenticated as `coder` (secret on stdin). `--no-delegation` sends `may_act: []`; each capability is a JSON `--cap` with its constraint and limit. |
| 5 | | `token inspect --verify` | two hops, each narrower, `may_act []` | The chain, constraints, limits and `may_act` are in the token and verify against the JWKS. |
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
# attenuo at http://127.0.0.1:53831 proxies a fake GitHub MCP server at port 34313 as 'github'.
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
lease       fc687213-e1f6-4f52-be26-152387a86f2a
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
decision a4d3aeff-8095-45a1-86f0-0e28de32da05

== 4. Exchange 2, planner -> coder (hop 2), narrowed at every point
# repo narrowed from acme/ to acme/api, a distinct limit of 1 on repo (one repository per run),
# no list_issues, no create_issue, and --no-delegation (may_act: []) so nobody may exchange it.
$ printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$PLANNER" attenuo token exchange --actor coder --client-secret-stdin --no-delegation --ttl-seconds 600 --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/api"}},"limits":{"distinct":{"arg":"repo","max":1}}}' --cap '{"server":"github","tool":"create_or_update_file","constraints":{"repo":{"op":"prefix","value":"acme/api"}},"limits":{"distinct":{"arg":"repo","max":1}}}'
lease       254a57a7-504a-4e01-870f-06d66a034687
expires_in  600s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 5. What the coder's token says: two hops, each narrower than the one above
$ attenuo token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-24T20:36:39Z
└─ agent planner
     can   github:create_issue {repo starts with "acme/"}, github:create_or_update_file {repo starts with "acme/"}, github:get_file_contents {repo starts with "acme/"}, github:list_issues {repo starts with "acme/"}
     until 2026-10-24T20:51:39Z (in 14m 59s)
     lease fc687213-e1f6-4f52-be26-152387a86f2a
   └─ agent coder  <- holds this token
        can   github:create_or_update_file {repo starts with "acme/api"} [distinct repo <= 1], github:get_file_contents {repo starts with "acme/api"} [distinct repo <= 1]
        until 2026-10-24T20:46:39Z (in 9m 59s)
        lease 254a57a7-504a-4e01-870f-06d66a034687

iss http://127.0.0.1:53831   aud attenuo   jti 7aeb93d4-aea1-49d5-ab4d-e5868777549b
kid TVMUVqtMRfIgwfaiuNOssA   ou_kid TVMUVqtMRfIgwfaiuNOssA
exp 2026-10-24T20:46:39Z (in 9m 59s)
may_act []: no agent may exchange this token
verified: signature, type, issuer, audience, expiry, chain

== 6. Exchange 3, refused: the coder tries to hand its token to a reviewer agent
# The reviewer authenticates fine, but the coder's token carries may_act: [].
$ printf "%s\n" demo-reviewer-secret | ATTENUO_TOKEN="$CODER" attenuo token exchange --actor reviewer --client-secret-stdin --cap '{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"equals","value":"acme/api"}}}'
error: server answered 400 Bad Request: invalid_request: agent `reviewer` is not permitted to act on this token (may_act)
decision 6e0429d7-529e-4a36-b88d-6084e5ea80b6

== 7. The coder reads the file it was asked to fix: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
ALLOWED
{"arguments":{"path":"src/lib.rs","repo":"acme/api"},"name":"get_file_contents"}

== 8. The coder pushes its fix straight to main: denied by policy
# create_or_update_file on acme/api is in the coder's token; the policy wants an agent/* branch.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_or_update_file --arg repo=acme/api --arg path=src/lib.rs --arg branch=main --arg content="fn fixed() {}"
DENIED  policy_deny
decision 2e156546-15e4-4168-91f5-3faeb6871786

== 9. The coder tries to open an issue: denied, the planner never delegated create_issue
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_issue --arg repo=acme/api --arg title="fix pushed"
DENIED  capability_denied
decision 40d705aa-bc4b-4c1d-9b9a-93fd87a9031e

== 10. The coder reads from a second repository under acme/api: denied by the run limit
# acme/api-client is inside the coder's repo prefix and the policy allows the read, but the
# distinct limit allows one repository per run and acme/api was the first.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api-client --arg path=README.md
DENIED  budget_exhausted
decision 98737a37-fc57-435a-8660-4665022c7b43

== 11. The operator looks at the chain before acting
# The chain id is the planner's lease, the first hop's (also the chain_id of every audit record).
$ attenuo lease tree "$PLANNER_LEASE"
root lease (no ancestors)
fc687213-e1f6-4f52-be26-152387a86f2a  planner  active, expires 2026-10-24T20:41:39.794191298Z  issued #1
└─ 254a57a7-504a-4e01-870f-06d66a034687  coder  active, expires 2026-10-24T20:41:39.874986778Z  issued #6
        limit github/create_or_update_file distinct repo 0/1 (1 left)
        limit github/get_file_contents distinct repo 1/1 (0 left)
would revoke 2 lease(s) if revoked now
$ attenuo lease revoke --chain-id "$PLANNER_LEASE" --preview
preview: nothing was changed
selector  chain_id fc687213-e1f6-4f52-be26-152387a86f2a
matched   2 lease(s)
would revoke 2 lease(s)
  254a57a7-504a-4e01-870f-06d66a034687
  fc687213-e1f6-4f52-be26-152387a86f2a

== 12. The operator revokes the whole chain by chain_id
$ attenuo lease revoke --chain-id "$PLANNER_LEASE" --reason "planner run went wrong"
selector  chain_id fc687213-e1f6-4f52-be26-152387a86f2a
matched   2 lease(s)
revoked 2 lease(s)
  254a57a7-504a-4e01-870f-06d66a034687
  fc687213-e1f6-4f52-be26-152387a86f2a
reason    planner run went wrong
audit     092534bf-f3ad-44f4-b20b-de269067305a

== 13. The coder's next call, even the one that worked before, is denied
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs
DENIED  lease_revoked
decision 88fc8d8d-a59e-4e76-b894-9440eeeb458d

== 14. The audit log records every decision, and its hash chain checks out
$ attenuo audit tail -n 50
#1    2026-10-24T20:36:39.794191298Z  ALLOW attenuo/token.root  planner for alice  reason=token_issued  id=33917a5d-de75-4fb5-a824-086afed96724
#2    2026-10-24T20:36:39.794191298Z  ALLOW attenuo/admin.root_token  by urn:attenuo:admin  reason=admin_action  id=75e33984-3400-4357-b251-f5e3958833a2
#3    2026-10-24T20:36:39.820296318Z  ALLOW github/list_issues  planner for alice  reason=policy_allow  id=0ff58861-96a5-4227-bde4-b337eeec01db
#4    2026-10-24T20:36:39.831660405Z  tool_result  github/list_issues  planner for alice  decision=0ff58861-96a5-4227-bde4-b337eeec01db  label=untrusted size=119  id=28e5db27-4cce-49ac-9676-635f989b51c3
#5    2026-10-24T20:36:39.850626261Z  DENY  attenuo/token.exchange  planner for alice  reason=exchange_widening  id=a4d3aeff-8095-45a1-86f0-0e28de32da05
#6    2026-10-24T20:36:39.874986778Z  ALLOW attenuo/token.exchange  planner > coder for alice  reason=token_issued  id=f557b789-7d09-48d7-8d9f-ef1e3c6ddac2
#7    2026-10-24T20:36:39.92216652Z  DENY  attenuo/token.exchange  planner > coder for alice  reason=exchange_actor_not_permitted  id=6e0429d7-529e-4a36-b88d-6084e5ea80b6
#8    2026-10-24T20:36:39.946105685Z  ALLOW github/get_file_contents  planner > coder for alice  reason=policy_allow  id=52dcf62d-ee47-49d5-9646-6e6e03d54a86
#9    2026-10-24T20:36:39.955514584Z  tool_result  github/get_file_contents  planner > coder for alice  decision=52dcf62d-ee47-49d5-9646-6e6e03d54a86  label=untrusted size=149  id=e8dcf25d-d59d-41a2-9b99-2e292f069dc5
#10   2026-10-24T20:36:39.970954354Z  DENY  github/create_or_update_file  planner > coder for alice  reason=policy_deny  id=2e156546-15e4-4168-91f5-3faeb6871786
#11   2026-10-24T20:36:39.999109404Z  DENY  github/create_issue  planner > coder for alice  reason=capability_denied  id=40d705aa-bc4b-4c1d-9b9a-93fd87a9031e
#12   2026-10-24T20:36:40.015708718Z  DENY  github/get_file_contents  planner > coder for alice  reason=budget_exhausted  id=98737a37-fc57-435a-8660-4665022c7b43
#13   2026-10-24T20:36:40.060894592Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=092534bf-f3ad-44f4-b20b-de269067305a
#14   2026-10-24T20:36:40.077264639Z  DENY  github/get_file_contents  planner > coder for alice  reason=lease_revoked  id=88fc8d8d-a59e-4e76-b894-9440eeeb458d
$ attenuo audit verify
audit chain OK: 14 entries verified
checkpoints: none signed yet

== 15. The refused widening exchange is in the log too
# A refused exchange whose subject token verified is a deny record against the parent's chain.
$ attenuo audit show --id "$WIDEN_DECISION"
#5    2026-10-24T20:36:39.850626261Z  DENY  attenuo/token.exchange  planner for alice  reason=exchange_widening  id=a4d3aeff-8095-45a1-86f0-0e28de32da05
kind        decision
chain       fc687213-e1f6-4f52-be26-152387a86f2a
hash        b842eb0ab2d7d3259437bc329b117559d242a50dc27a278230c87ce4904f455f
prev hash   3bc7085bc8e3640c6be08364cb1b77d6343e153a0c7b8c17f34305c0e62db178
leases      (root first, as the registry sees them now)
  fc687213-e1f6-4f52-be26-152387a86f2a  REVOKED 2026-10-24T20:36:40.060894592Z (planner run went wrong)
checkpoint  none yet: the entry is newer than every checkpoint, only the hash chain covers it
policy      not reloaded since this entry

== 16. The decision chain of the refused write
# The record names both hops, the policy that decided, the leases (revoked now) and its hashes.
$ attenuo audit show --id "$WRITE_DECISION"
#10   2026-10-24T20:36:39.970954354Z  DENY  github/create_or_update_file  planner > coder for alice  reason=policy_deny  id=2e156546-15e4-4168-91f5-3faeb6871786
kind        decision
chain       fc687213-e1f6-4f52-be26-152387a86f2a
policies    no_writes_to_default_branch
hash        6ca277beada03625091dfda2f5b55bb167f2e3a920df06b14f0059d402b3b82f
prev hash   6623f66c3fca118d71c709e1829ff94a00f62fae824e89965c1b6b3ff5c7b20f
leases      (root first, as the registry sees them now)
  fc687213-e1f6-4f52-be26-152387a86f2a  REVOKED 2026-10-24T20:36:40.060894592Z (planner run went wrong)
  254a57a7-504a-4e01-870f-06d66a034687  REVOKED 2026-10-24T20:36:40.060894592Z (planner run went wrong)
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
- `run.sh`.

## What this does not show

- Hop 0 comes from the development endpoint, which trusts the admin to say who alice is; a real deployment exchanges an OIDC ID token or ID-JAG at `POST /token`. The agents authenticate with client secrets from `[[agents]]`, not with workload identity (`actor_token`).
- "May not delegate further" is `may_act: []`, an empty list of agents allowed to exchange the token (`attenuo token exchange --no-delegation`; the Python SDK's `Client.exchange(..., may_act=[])`). Without it the coder's token would carry no `may_act` and any authenticated agent could exchange it. `token inspect` shows it (`may_act []: no agent may exchange this token`, step 5). The policy's depth forbid is a second line of defence, should a deeper chain ever be issued.
- One run limit per capability: the coder's write has its own `distinct` counter, so a write to a second repository would be refused by that counter separately.

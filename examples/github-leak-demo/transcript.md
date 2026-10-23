# Transcript

Output of `examples/github-leak-demo/run.sh` from one real run. Ports, lease ids and timestamps differ on every run, and tokens are shortened for display. The script exits non-zero if any step comes out differently, so it doubles as a smoke test.

```text

== Setup
# onbehalf at http://127.0.0.1:37545 proxies a fake GitHub MCP server at port 36689 as 'github'.
# Policy: read_file only when repo like "alice/public-*". See policy.cedar.
# The policy has its own tests (policy_test.yaml). They run offline, before any server traffic.
$ onbehalf policy test examples/github-leak-demo/policy_test.yaml
examples/github-leak-demo/policy_test.yaml
  ✓ coder may read a public repo  (allow: policy_allow [read_file_public_repos_only])
  ✓ the injected read of a private repo is denied  (deny: policy_deny)
  ✓ read_file without a repo argument is denied  (deny: policy_deny)
  ✓ create_issue is denied by capability when coder was only given read_file  (deny: capability_denied)
  ✓ the assistant's own broad token still gets no permit for create_issue  (deny: policy_deny)
  ✓ delete_repo without MFA is denied by the forbid  (deny: policy_deny [forbid_sensitive_without_mfa])
  ✓ delete_repo with MFA is still denied, because nothing permits it  (deny: policy_deny)
  ✓ a four-agent chain is forbidden even for a public read  (deny: policy_deny [forbid_deep_chains])
  ✓ a three-agent chain is fine  (allow: policy_allow [read_file_public_repos_only])

9 passed, 0 failed (9 cases in 1 file)

== 1. Alice's assistant gets a broad token (any github tool), like the over-privileged PAT
$ onbehalf token root --subject alice --agent assistant --cap "github:*"
lease       35d377ab-f0de-4684-bb89-df1224cfac38
expires_in  900s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 2. The assistant hands its 'coder' sub-agent read_file and nothing else
# The coder authenticates as itself ([[agents]] in config.toml): only it can receive a token in its name.
$ onbehalf token exchange --subject-token "$ROOT_TOKEN" --actor coder --client-secret demo-coder-secret --cap github:read_file
lease       52ed84ac-d063-4e44-ae38-791474a8558d
expires_in  899s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 3. What the coder's token says
$ onbehalf token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-23T01:37:46Z
└─ agent assistant
     can   github:*
     until 2026-10-23T01:52:46Z (in 14m 59s)
     lease 35d377ab-f0de-4684-bb89-df1224cfac38
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-23T01:52:46Z (in 14m 59s)
        lease 52ed84ac-d063-4e44-ae38-791474a8558d

iss http://127.0.0.1:37545   aud onbehalf   jti 472592c3-d2dd-40be-81cb-0665b6937ecb
exp 2026-10-23T01:52:46Z (in 14m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 4. The coder reads a public repo as intended: allowed
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
ALLOWED
{"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}

== 5. A malicious issue tells the coder to read alice/private-salaries: denied by policy
# read_file is in the token, but the policy only lets it touch alice/public-*.
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
DENIED  policy_deny
decision 63d1f7a5-f381-42fc-bd5a-3dea265ef45b

== 6. The injection tries to copy the data out through create_issue: denied, never delegated
$ onbehalf call --token "$CODER" --server github --tool create_issue --arg repo=alice/public-docs --arg title=leak
DENIED  capability_denied
decision e70cbc87-b6ec-41f9-9392-90a4304004c0

== 7. Alice sees the session going wrong and revokes the assistant's lease
$ onbehalf lease revoke "$ROOT_LEASE" --reason "agent session compromised"
revoked 2 lease(s) starting at 35d377ab-f0de-4684-bb89-df1224cfac38 (reason: agent session compromised)
$ onbehalf lease show "$CODER_LEASE"
lease    52ed84ac-d063-4e44-ae38-791474a8558d
active   no
parent   35d377ab-f0de-4684-bb89-df1224cfac38
expires  2026-10-23T01:42:46.748854205Z
revoked  2026-10-23T01:37:46.86410935Z (agent session compromised)

== 8. The coder's next call, even the legitimate one, is denied: the revocation cascaded
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
DENIED  lease_revoked
decision ea6665d4-0cb7-4aea-9610-5a741ba2fde4

== 9. The audit log records every decision, and its hash chain checks out
$ onbehalf audit tail -n 10
#1    2026-10-23T01:37:46.718928231Z  ALLOW onbehalf/token.root  assistant for alice  reason=token_issued  id=a328e9c6-3200-4d27-b6b4-cd07f2c8e3cf
#2    2026-10-23T01:37:46.718928231Z  ALLOW onbehalf/admin.root_token  by admin  reason=admin_action  id=41fdef66-fce1-4f93-b8d2-c963602922a1
#3    2026-10-23T01:37:46.748854205Z  ALLOW onbehalf/token.exchange  assistant > coder for alice  reason=token_issued  id=52a5633b-ce6b-4301-b97b-9490180f28d3
#4    2026-10-23T01:37:46.798007633Z  ALLOW github/read_file  assistant > coder for alice  reason=policy_allow  id=291afe3e-caf9-4d2c-b3b8-fde72310f247
#5    2026-10-23T01:37:46.824037313Z  DENY  github/read_file  assistant > coder for alice  reason=policy_deny  id=63d1f7a5-f381-42fc-bd5a-3dea265ef45b
#6    2026-10-23T01:37:46.844491494Z  DENY  github/create_issue  assistant > coder for alice  reason=capability_denied  id=e70cbc87-b6ec-41f9-9392-90a4304004c0
#7    2026-10-23T01:37:46.86410935Z  ALLOW onbehalf/admin.lease.revoke  by admin  reason=admin_action  id=b9dc49e4-3dc2-46ed-a05f-6ef0ebf41ac1
#8    2026-10-23T01:37:46.900319702Z  DENY  github/read_file  assistant > coder for alice  reason=lease_revoked  id=ea6665d4-0cb7-4aea-9610-5a741ba2fde4
$ onbehalf audit verify
audit chain OK: 8 entries verified

== What reached the GitHub server
  fake-mcp: tools/call read_file {"path":"README.md","repo":"alice/public-docs"}
  -> 1 tools/call reached upstream. The three denied calls never left onbehalf.
```

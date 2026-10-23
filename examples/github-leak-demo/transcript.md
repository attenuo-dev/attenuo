# Transcript

Output of `examples/github-leak-demo/run.sh` from one real run. Ports, lease ids and timestamps differ on every run, and tokens are shortened for display. The script exits non-zero if any step comes out differently, so it doubles as a smoke test.

```text
== Setup
# onbehalf at http://127.0.0.1:46797 proxies a fake GitHub MCP server at port 33719 as 'github'.
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
lease       192bc269-5eda-437e-8686-0321c8ef1289
expires_in  900s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 2. The assistant hands its 'coder' sub-agent read_file and nothing else
$ onbehalf token exchange --subject-token "$ROOT_TOKEN" --actor coder --cap github:read_file
lease       06634ead-f76f-4b22-a5f9-07dbe3c368cb
expires_in  899s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 3. What the coder's token says
$ onbehalf token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-23T01:15:16Z
└─ agent assistant
     can   github:*
     until 2026-10-23T01:30:16Z (in 14m 59s)
     lease 192bc269-5eda-437e-8686-0321c8ef1289
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-23T01:30:16Z (in 14m 59s)
        lease 06634ead-f76f-4b22-a5f9-07dbe3c368cb

iss http://127.0.0.1:46797   aud onbehalf   jti f551dc9f-0044-48a2-82f8-9de3ecef12d9
exp 2026-10-23T01:30:16Z (in 14m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 4. The coder reads a public repo as intended: allowed
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
ALLOWED
{"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}

== 5. A malicious issue tells the coder to read alice/private-salaries: denied by policy
# read_file is in the token, but the policy only lets it touch alice/public-*.
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
DENIED  policy_deny
decision 1e58136f-66ef-46bd-b401-e256dbe832f0

== 6. The injection tries to copy the data out through create_issue: denied, never delegated
$ onbehalf call --token "$CODER" --server github --tool create_issue --arg repo=alice/public-docs --arg title=leak
DENIED  capability_denied
decision b0c09318-84a0-4178-b851-3102a820f372

== 7. Alice sees the session going wrong and revokes the assistant's lease
$ onbehalf lease revoke "$ROOT_LEASE" --reason "agent session compromised"
revoked 2 lease(s) starting at 192bc269-5eda-437e-8686-0321c8ef1289 (reason: agent session compromised)
$ onbehalf lease show "$CODER_LEASE"
lease    06634ead-f76f-4b22-a5f9-07dbe3c368cb
active   no
parent   192bc269-5eda-437e-8686-0321c8ef1289
expires  2026-10-23T01:20:16.520098571Z
revoked  2026-10-23T01:15:16.600968008Z (agent session compromised)

== 8. The coder's next call, even the legitimate one, is denied: the revocation cascaded
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
DENIED  lease_revoked
decision e3bf5d36-e2cc-49ee-bcca-001583fbfa55

== 9. The audit log records every decision, and its hash chain checks out
$ onbehalf audit tail -n 10
#1    2026-10-23T01:15:16.491188739Z  ALLOW onbehalf/token.root  assistant for alice  reason=token_issued  id=79d58e41-13e6-4f11-86ec-d722816bf97c
#2    2026-10-23T01:15:16.520098571Z  ALLOW onbehalf/token.exchange  assistant > coder for alice  reason=token_issued  id=3b2fff04-78ca-4ad4-860c-551876bdae13
#3    2026-10-23T01:15:16.561124617Z  ALLOW github/read_file  assistant > coder for alice  reason=policy_allow  id=f7508e59-a346-4142-ad84-16601b3291fd
#4    2026-10-23T01:15:16.578048565Z  DENY  github/read_file  assistant > coder for alice  reason=policy_deny  id=1e58136f-66ef-46bd-b401-e256dbe832f0
#5    2026-10-23T01:15:16.590372859Z  DENY  github/create_issue  assistant > coder for alice  reason=capability_denied  id=b0c09318-84a0-4178-b851-3102a820f372
#6    2026-10-23T01:15:16.618847037Z  DENY  github/read_file  assistant > coder for alice  reason=lease_revoked  id=e3bf5d36-e2cc-49ee-bcca-001583fbfa55
$ onbehalf audit verify
audit chain OK: 6 entries verified

== What reached the GitHub server
  fake-mcp: tools/call read_file {"path":"README.md","repo":"alice/public-docs"}
  -> 1 tools/call reached upstream. The three denied calls never left onbehalf.
```

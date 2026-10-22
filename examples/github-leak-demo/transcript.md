# Transcript

Output of `examples/github-leak-demo/run.sh` from one real run. Ports, lease ids and timestamps differ on every run, and tokens are shortened for display. The script exits non-zero if any step comes out differently, so it doubles as a smoke test.

```text

== Setup
# onbehalf at http://127.0.0.1:54571 proxies a fake GitHub MCP server at port 57545 as 'github'.
# Policy: read_file only when repo like "alice/public-*". See policy.cedar.

== 1. Alice's assistant gets a broad token (any github tool), like the over-privileged PAT
$ onbehalf token root --subject alice --agent assistant --cap "github:*"
lease       3d3a8102-a43a-4b9f-b6a7-f4cdd6881f62
expires_in  900s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 2. The assistant hands its 'coder' sub-agent read_file and nothing else
$ onbehalf token exchange --subject-token "$ROOT_TOKEN" --actor coder --cap github:read_file
lease       c231546b-4d28-472e-aeb3-ae51a754c858
expires_in  899s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 3. What the coder's token says
$ onbehalf token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-22T21:49:28Z
└─ agent assistant
     can   github:*
     until 2026-10-22T22:04:28Z (in 14m 59s)
     lease 3d3a8102-a43a-4b9f-b6a7-f4cdd6881f62
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-22T22:04:28Z (in 14m 59s)
        lease c231546b-4d28-472e-aeb3-ae51a754c858

iss http://127.0.0.1:54571   aud onbehalf   jti 0e9d0fff-f660-4fe1-b42a-66da5f1432be
exp 2026-10-22T22:04:28Z (in 14m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 4. The coder reads a public repo as intended: allowed
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
ALLOWED
{"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}

== 5. A malicious issue tells the coder to read alice/private-salaries: denied by policy
# read_file is in the token, but the policy only lets it touch alice/public-*.
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
DENIED  policy_deny
decision 03385801-54dc-48d9-b70f-0fb8ef156ee7

== 6. The injection tries to copy the data out through create_issue: denied, never delegated
$ onbehalf call --token "$CODER" --server github --tool create_issue --arg repo=alice/public-docs --arg title=leak
DENIED  capability_denied
decision 5436be55-2a38-4863-b963-adb4ea605ea6

== 7. Alice sees the session going wrong and revokes the assistant's lease
$ onbehalf lease revoke "$ROOT_LEASE" --reason "agent session compromised"
revoked 2 lease(s) starting at 3d3a8102-a43a-4b9f-b6a7-f4cdd6881f62 (reason: agent session compromised)
$ onbehalf lease show "$CODER_LEASE"
lease    c231546b-4d28-472e-aeb3-ae51a754c858
active   no
parent   3d3a8102-a43a-4b9f-b6a7-f4cdd6881f62
expires  2026-10-22T22:04:28.679003234Z
revoked  2026-10-22T21:49:28.838754076Z (agent session compromised)

== 8. The coder's next call, even the legitimate one, is denied: the revocation cascaded
$ onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
DENIED  lease_revoked
decision 51282084-9e0e-4a0b-9623-1ba535ab811f

== 9. The audit log records every decision, and its hash chain checks out
$ onbehalf audit tail -n 10
#1    2026-10-22T21:49:28.679003234Z  ALLOW onbehalf/token.root  assistant for alice  reason=token_issued  id=8caaa2a1-82f1-4b1a-83fd-54d840dd91a8
#2    2026-10-22T21:49:28.71103649Z  ALLOW onbehalf/token.exchange  assistant > coder for alice  reason=token_issued  id=3090d009-cc76-4908-ae15-91bc385557eb
#3    2026-10-22T21:49:28.770709034Z  ALLOW github/read_file  assistant > coder for alice  reason=policy_allow  id=44b938a4-c946-4416-8af9-f15ae63506bc
#4    2026-10-22T21:49:28.794825731Z  DENY  github/read_file  assistant > coder for alice  reason=policy_deny  id=03385801-54dc-48d9-b70f-0fb8ef156ee7
#5    2026-10-22T21:49:28.814611174Z  DENY  github/create_issue  assistant > coder for alice  reason=capability_denied  id=5436be55-2a38-4863-b963-adb4ea605ea6
#6    2026-10-22T21:49:28.87762415Z  DENY  github/read_file  assistant > coder for alice  reason=lease_revoked  id=51282084-9e0e-4a0b-9623-1ba535ab811f
$ onbehalf audit verify
audit chain OK: 6 entries verified

== What reached the GitHub server
  fake-mcp: tools/call read_file {"path":"README.md","repo":"alice/public-docs"}
  -> 1 tools/call reached upstream. The three denied calls never left onbehalf.
```

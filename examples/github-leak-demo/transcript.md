# Transcript

Output of `examples/github-leak-demo/run.sh` from one real run. Ports, lease ids and timestamps differ on every run, and tokens are shortened for display. The script exits non-zero if any step comes out differently, so it doubles as a smoke test.

```text

== Setup
# attenuo at http://127.0.0.1:55369 proxies a fake GitHub MCP server at port 43097 as 'github'.
# Policy: read_file only when repo like "alice/public-*". See policy.cedar.
# The policy has its own tests (policy_test.yaml). They run offline, before any server traffic.
$ attenuo policy test examples/github-leak-demo/policy_test.yaml
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
$ attenuo token root --subject alice --agent assistant --cap "github:*"
lease       f3ea96dc-396a-4eb0-9924-e7b34e33aa72
expires_in  900s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 2. The assistant hands its 'coder' sub-agent read_file and nothing else
# The coder authenticates as itself ([[agents]] in config.toml): only it can receive a token in its name.
# Its secret goes in on stdin (or ATTENUO_CLIENT_SECRET, or --client-secret-file), never in argv;
# so do the tokens (ATTENUO_TOKEN, --token-file or --token -).
$ printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$ROOT_TOKEN" attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file
lease       67d6e0f2-c38b-4f87-a035-c472cfe453ac
expires_in  899s
token       eyJ0eXAiOiJvbmJlaGFsZitq...

== 3. What the coder's token says
$ attenuo token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-23T01:43:42Z
└─ agent assistant
     can   github:*
     until 2026-10-23T01:58:42Z (in 14m 59s)
     lease f3ea96dc-396a-4eb0-9924-e7b34e33aa72
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-23T01:58:42Z (in 14m 59s)
        lease 67d6e0f2-c38b-4f87-a035-c472cfe453ac

iss http://127.0.0.1:55369   aud attenuo   jti 99c2781e-5c05-4600-9bad-dafd87f58785
exp 2026-10-23T01:58:42Z (in 14m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 4. The coder reads a public repo as intended: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
ALLOWED
{"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}

== 5. A malicious issue tells the coder to read alice/private-salaries: denied by policy
# read_file is in the token, but the policy only lets it touch alice/public-*.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
DENIED  policy_deny
decision 369bac7f-b84b-4420-89d5-8056e22939a5

== 6. The injection tries to copy the data out through create_issue: denied, never delegated
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=leak
DENIED  capability_denied
decision d0e9fc25-8a84-48bf-93e2-bb0e654b7ccb

== 7. Alice sees the session going wrong and revokes the assistant's lease
$ attenuo lease revoke "$ROOT_LEASE" --reason "agent session compromised"
revoked 2 lease(s) starting at f3ea96dc-396a-4eb0-9924-e7b34e33aa72 (reason: agent session compromised)
$ attenuo lease show "$CODER_LEASE"
lease    67d6e0f2-c38b-4f87-a035-c472cfe453ac
active   no
parent   f3ea96dc-396a-4eb0-9924-e7b34e33aa72
expires  2026-10-23T01:48:42.103377339Z
revoked  2026-10-23T01:43:42.169715443Z (agent session compromised)

== 8. The coder's next call, even the legitimate one, is denied: the revocation cascaded
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
DENIED  lease_revoked
decision abe9f8f9-0724-4784-9172-6745c6e628f9

== 9. The audit log records every decision, and its hash chain checks out
$ attenuo audit tail -n 10
#1    2026-10-23T01:43:42.086457142Z  ALLOW attenuo/token.root  assistant for alice  reason=token_issued  id=328cd90a-3c21-429c-a3f9-2839bef596a6
#2    2026-10-23T01:43:42.086457142Z  ALLOW attenuo/admin.root_token  by urn:attenuo:admin  reason=admin_action  id=6b39d9c2-f720-4e07-9d63-2f228c7092a8
#3    2026-10-23T01:43:42.103377339Z  ALLOW attenuo/token.exchange  assistant > coder for alice  reason=token_issued  id=5f052355-f77f-4a16-b0e6-0cd476e2a94f
#4    2026-10-23T01:43:42.133457841Z  ALLOW github/read_file  assistant > coder for alice  reason=policy_allow  id=31dbb4f9-d31e-486d-a703-44836e9e858e
#5    2026-10-23T01:43:42.148994973Z  DENY  github/read_file  assistant > coder for alice  reason=policy_deny  id=369bac7f-b84b-4420-89d5-8056e22939a5
#6    2026-10-23T01:43:42.160063945Z  DENY  github/create_issue  assistant > coder for alice  reason=capability_denied  id=d0e9fc25-8a84-48bf-93e2-bb0e654b7ccb
#7    2026-10-23T01:43:42.169715443Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=26a60386-a01e-436c-901f-156b9a336a30
#8    2026-10-23T01:43:42.186751983Z  DENY  github/read_file  assistant > coder for alice  reason=lease_revoked  id=abe9f8f9-0724-4784-9172-6745c6e628f9
$ attenuo audit verify
audit chain OK: 9 entries verified
checkpoints: none signed yet

== What reached the GitHub server
  fake-mcp: tools/call read_file {"path":"README.md","repo":"alice/public-docs"}
  -> 1 tools/call reached upstream. The three denied calls never left attenuo.
```

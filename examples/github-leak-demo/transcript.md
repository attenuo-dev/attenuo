# Transcript

Output of `examples/github-leak-demo/run.sh` from one real run. Ports, lease ids and timestamps differ on every run, and tokens are shortened for display. The script exits non-zero if any step comes out differently, so it doubles as a smoke test.

```text


== Setup
# attenuo at http://127.0.0.1:34201 proxies a fake GitHub MCP server at port 51751 as 'github'.
# Policy: read_file only when repo like "alice/public-*"; create_issue there only after an approval. See policy.cedar.
# The policy has its own tests (policy_test.yaml). They run offline, before any server traffic.
$ attenuo policy test examples/github-leak-demo/policy_test.yaml
examples/github-leak-demo/policy_test.yaml
  ✓ coder may read a public repo  (allow: policy_allow [read_file_public_repos_only])
  ✓ the injected read of a private repo is denied  (deny: policy_deny)
  ✓ read_file without a repo argument is denied  (deny: policy_deny)
  ✓ create_issue is denied by capability when coder was only given read_file  (deny: capability_denied)
  ✓ the assistant's own create_issue in a public repo waits for an approval  (deny: approval_required [ask_before_create_issue])
  ✓ once approved, the identical create_issue is allowed  (allow: policy_allow [create_issue_public_repos])
  ✓ create_issue in a private repo gets no permit, approved or not  (deny: policy_deny)
  ✓ delete_repo without MFA is denied by the forbid  (deny: policy_deny [forbid_sensitive_without_mfa])
  ✓ delete_repo with MFA is still denied, because nothing permits it  (deny: policy_deny)
  ✓ a four-agent chain is forbidden even for a public read  (deny: policy_deny [forbid_deep_chains])
  ✓ a three-agent chain is fine  (allow: policy_allow [read_file_public_repos_only])

11 passed, 0 failed (11 cases in 1 file)

== 1. Alice's assistant gets a broad token (any github tool), like the over-privileged PAT
$ attenuo token root --subject alice --agent assistant --cap "github:*"
lease       75e72205-b9bd-4264-8b96-b1fd883ffde4
expires_in  900s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 2. The assistant hands its 'coder' sub-agent read_file and nothing else
# The coder authenticates as itself ([[agents]] in config.toml): only it can receive a token in its name.
# Its secret goes in on stdin (or ATTENUO_CLIENT_SECRET, or --client-secret-file), never in argv;
# so do the tokens (ATTENUO_TOKEN, --token-file or --token -).
$ printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$ROOT_TOKEN" attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file
lease       73115269-1fc8-4413-a1d8-c0bb699ac3c3
expires_in  899s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 3. What the coder's token says
$ attenuo token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-24T16:20:29Z
└─ agent assistant
     can   github:*
     until 2026-10-24T16:35:29Z (in 14m 59s)
     lease 75e72205-b9bd-4264-8b96-b1fd883ffde4
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-24T16:35:29Z (in 14m 59s)
        lease 73115269-1fc8-4413-a1d8-c0bb699ac3c3

iss http://127.0.0.1:34201   aud attenuo   jti 67dfeae5-2805-4be2-b39f-af3d82a60ec7
kid LqGVeHwSODgU8UVPEjCdCg   ou_kid LqGVeHwSODgU8UVPEjCdCg
exp 2026-10-24T16:35:29Z (in 14m 59s)
may_act (absent): any authenticated agent may exchange this token
verified: signature, type, issuer, audience, expiry, chain

== 4. The coder reads a public repo as intended: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool read_file --arg repo=alice/public-docs --arg path=README.md
ALLOWED
{"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}

== 5. A malicious issue tells the coder to read alice/private-salaries: denied by policy
# read_file is in the token, but the policy only lets it touch alice/public-*.
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
DENIED  policy_deny
decision 1d7ce4d2-d683-45dc-ad2a-b0f6d9f08076

== 6. The injection tries to copy the data out through create_issue: denied, never delegated
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool create_issue --arg repo=alice/public-docs --arg title=leak
DENIED  capability_denied
decision ba3131d8-8302-49bd-84a1-25001c8c8ac2

== 7. Alice sees the session going wrong and revokes the assistant's lease
$ attenuo lease revoke "$ROOT_LEASE" --reason "agent session compromised"
revoked 2 lease(s) starting at 75e72205-b9bd-4264-8b96-b1fd883ffde4 (reason: agent session compromised)
$ attenuo lease show "$CODER_LEASE"
lease    73115269-1fc8-4413-a1d8-c0bb699ac3c3
active   no
parent   75e72205-b9bd-4264-8b96-b1fd883ffde4
expires  2026-10-24T16:25:29.222491365Z
revoked  2026-10-24T16:20:29.312083173Z (agent session compromised)

== 8. The coder's next call, even the legitimate one, is denied: the revocation cascaded
$ ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool read_file --arg repo=alice/public-docs --arg path=README.md
DENIED  lease_revoked
decision 091d844b-2140-4f8a-a837-69005b866db9

== 9. The audit log records every decision, and its hash chain checks out
$ attenuo audit tail -n 10
#1    2026-10-24T16:20:29.198717969Z  ALLOW attenuo/token.root  assistant for alice  reason=token_issued  id=498af7f4-d28f-4d61-9814-5d3caa42e475
#2    2026-10-24T16:20:29.198717969Z  ALLOW attenuo/admin.root_token  by urn:attenuo:admin  reason=admin_action  id=63daf438-4911-4621-b1b6-4f3a875c32f5
#3    2026-10-24T16:20:29.222491365Z  ALLOW attenuo/token.exchange  assistant > coder for alice  reason=token_issued  id=5f7d677f-0d34-42df-a4dd-23743c8ea61b
#4    2026-10-24T16:20:29.264583002Z  ALLOW github/read_file  assistant > coder for alice  reason=policy_allow  id=9640c9de-523c-4a32-b171-374c9aa578a9
#5    2026-10-24T16:20:29.274523875Z  tool_result  github/read_file  assistant > coder for alice  decision=9640c9de-523c-4a32-b171-374c9aa578a9  label=untrusted size=149  id=574faf0a-0288-4c63-a4b7-61e45beaf555
#6    2026-10-24T16:20:29.287843116Z  DENY  github/read_file  assistant > coder for alice  reason=policy_deny  id=1d7ce4d2-d683-45dc-ad2a-b0f6d9f08076
#7    2026-10-24T16:20:29.300455586Z  DENY  github/create_issue  assistant > coder for alice  reason=capability_denied  id=ba3131d8-8302-49bd-84a1-25001c8c8ac2
#8    2026-10-24T16:20:29.312083173Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=abbd9301-e500-4bc3-8ffe-abe2285a4da8
#9    2026-10-24T16:20:29.335156817Z  DENY  github/read_file  assistant > coder for alice  reason=lease_revoked  id=091d844b-2140-4f8a-a837-69005b866db9
$ attenuo audit verify
audit chain OK: 9 entries verified
checkpoints: none signed yet

== What reached the GitHub server
  fake-mcp: tools/call read_file {"path":"README.md","repo":"alice/public-docs"}
  -> 1 tools/call reached upstream. The three denied calls never left attenuo.
```

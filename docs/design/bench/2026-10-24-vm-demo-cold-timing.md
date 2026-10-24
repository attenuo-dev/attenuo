# GitHub leak demo, cold and warm run time, 2026-10-24, vm

Commit `de3cf75` (main), dev profile, rustc 1.99.1 (58cf8f9c3 2026-10-13), cargo 1.99.1.
Command: `examples/github-leak-demo/run.sh`, as the READMEs tell a reader to run it, timed with the bash `time` keyword. Each cold run used a new, empty `CARGO_TARGET_DIR`. The cargo registry (`~/.cargo/registry`) was already populated, so crate downloads are not included. Shared development container, but no other build was running: load average 0.04 / 0.38 / 0.26 before the first run, up to 3.9 during the builds.

## Machine

```
$ nproc
4
$ lscpu | grep 'Model name'
Model name:                              Intel(R) Xeon(R) Processor @ 2.10GHz
$ free -g
               total        used        free      shared  buff/cache   available
Mem:              15           0          12           0           2          14
Swap:              0           0           0
$ rustc --version
rustc 1.99.1 (58cf8f9c3 2026-10-13)
```

## Results

| Run | Settings | real | user | sys |
| --- | --- | --- | --- | --- |
| cold | `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0` | 1m22.393s | 3m37.024s | 0m24.934s |
| warm 1 | same target dir | 0m0.914s | 0m0.642s | 0m0.263s |
| warm 2 | same target dir | 0m0.876s | 0m0.585s | 0m0.292s |
| warm 3 | same target dir | 0m0.877s | 0m0.582s | 0m0.300s |
| cold | cargo defaults (debug info on, incremental on) | 1m31.187s | 4m40.260s | 0m34.192s |
| warm | cargo defaults, same target dir | 0m0.905s | 0m0.651s | 0m0.265s |

`run.sh` does not print build and scenario time separately. The audit timestamps below put the nine steps at about 0.12 s (05:26:50.93 to 05:26:51.05), so a cold run is almost entirely compiling, and a warm run is mostly the two no-op `cargo build` calls and `cargo metadata`. The default-settings target dir was 3.1 GB after the build.

All six runs exited 0, and the output was the same in every run apart from ports, ids and timestamps.

## Output of the first cold run

stderr:

```text
building (first run takes a while)...
```

stdout:

```text

== Setup
# attenuo at http://127.0.0.1:57953 proxies a fake GitHub MCP server at port 34189 as 'github'.
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
lease       a45e1f23-87ed-4999-830a-45710b0a0151
expires_in  900s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 2. The assistant hands its 'coder' sub-agent read_file and nothing else
# The coder authenticates as itself ([[agents]] in config.toml): only it can receive a token in its name.
# Its secret goes in on stdin (or ATTENUO_CLIENT_SECRET, or --client-secret-file), never in argv;
# so do the tokens (ATTENUO_TOKEN, --token-file or --token -).
$ printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$ROOT_TOKEN" attenuo token exchange --actor coder --client-secret-stdin --cap github:read_file
lease       8985980f-343f-4601-8550-bc9dacbb7a17
expires_in  899s
token       eyJ0eXAiOiJhdHRlbnVvK2p3...

== 3. What the coder's token says
$ attenuo token inspect "$CODER" --verify
user alice  (issuer https://idp.example)
  authenticated 2026-10-24T05:26:50Z
└─ agent assistant
     can   github:*
     until 2026-10-24T05:41:50Z (in 14m 59s)
     lease a45e1f23-87ed-4999-830a-45710b0a0151
   └─ agent coder  <- holds this token
        can   github:read_file
        until 2026-10-24T05:41:50Z (in 14m 59s)
        lease 8985980f-343f-4601-8550-bc9dacbb7a17

iss http://127.0.0.1:57953   aud attenuo   jti 70b9e391-ce35-46b9-a0d1-b9e85ab0abd9
exp 2026-10-24T05:41:50Z (in 14m 59s)
verified: signature, type, issuer, audience, expiry, chain

== 4. The coder reads a public repo as intended: allowed
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
ALLOWED
{"arguments":{"path":"README.md","repo":"alice/public-docs"},"name":"read_file"}

== 5. A malicious issue tells the coder to read alice/private-salaries: denied by policy
# read_file is in the token, but the policy only lets it touch alice/public-*.
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
DENIED  policy_deny
decision 1a6e770c-867a-412e-a165-91d3cc6792d0

== 6. The injection tries to copy the data out through create_issue: denied, never delegated
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool create_issue --arg repo=alice/public-docs --arg title=leak
DENIED  capability_denied
decision 4fde6d18-06a1-404c-99b2-3238f124c730

== 7. Alice sees the session going wrong and revokes the assistant's lease
$ attenuo lease revoke "$ROOT_LEASE" --reason "agent session compromised"
revoked 2 lease(s) starting at a45e1f23-87ed-4999-830a-45710b0a0151 (reason: agent session compromised)
$ attenuo lease show "$CODER_LEASE"
lease    8985980f-343f-4601-8550-bc9dacbb7a17
active   no
parent   a45e1f23-87ed-4999-830a-45710b0a0151
expires  2026-10-24T05:31:50.953893136Z
revoked  2026-10-24T05:26:51.02873959Z (agent session compromised)

== 8. The coder's next call, even the legitimate one, is denied: the revocation cascaded
$ ATTENUO_TOKEN="$CODER" attenuo call --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md
DENIED  lease_revoked
decision bad28b31-7005-4d87-ba3b-e95b4f17e566

== 9. The audit log records every decision, and its hash chain checks out
$ attenuo audit tail -n 10
#1    2026-10-24T05:26:50.932064163Z  ALLOW attenuo/token.root  assistant for alice  reason=token_issued  id=1d5c3fa4-0d09-431c-ba98-7d1656b44625
#2    2026-10-24T05:26:50.932064163Z  ALLOW attenuo/admin.root_token  by urn:attenuo:admin  reason=admin_action  id=01f8aa60-ac9d-4c46-aa05-074809e3a56f
#3    2026-10-24T05:26:50.953893136Z  ALLOW attenuo/token.exchange  assistant > coder for alice  reason=token_issued  id=81a668b0-cc22-4416-8855-3f826485e930
#4    2026-10-24T05:26:50.988181944Z  ALLOW github/read_file  assistant > coder for alice  reason=policy_allow  id=4a85d62d-65cc-42c1-ae52-231fdb1c1dac
#5    2026-10-24T05:26:51.005816861Z  DENY  github/read_file  assistant > coder for alice  reason=policy_deny  id=1a6e770c-867a-412e-a165-91d3cc6792d0
#6    2026-10-24T05:26:51.017454907Z  DENY  github/create_issue  assistant > coder for alice  reason=capability_denied  id=4fde6d18-06a1-404c-99b2-3238f124c730
#7    2026-10-24T05:26:51.02873959Z  ALLOW attenuo/admin.lease.revoke  by urn:attenuo:admin  reason=admin_action  id=0feaf02c-2403-41f6-9eab-86b99ead8231
#8    2026-10-24T05:26:51.054633286Z  DENY  github/read_file  assistant > coder for alice  reason=lease_revoked  id=bad28b31-7005-4d87-ba3b-e95b4f17e566
$ attenuo audit verify
audit chain OK: 8 entries verified
checkpoints: none signed yet

== What reached the GitHub server
  fake-mcp: tools/call read_file {"path":"README.md","repo":"alice/public-docs"}
  -> 1 tools/call reached upstream. The three denied calls never left attenuo.
```

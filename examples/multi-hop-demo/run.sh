#!/usr/bin/env bash
# Delegation narrowing over three hops, end to end: alice -> planner -> coder -> GitHub tool.
#
#   examples/multi-hop-demo/run.sh
#
# Starts attenuo-server and a fake GitHub MCP server on free local ports, then plays the
# scenario with the `attenuo` CLI. No model, no real GitHub and no network beyond loopback. Exits non-zero if any step does not come
# out as expected. Re-runnable: nothing is written outside a temp dir, which the exit trap
# removes.
#
# Environment:
#   KEEP=1                keep the temp dir (logs, rendered config) after the run
#   ATTENUO_BIN_DIR=DIR  use prebuilt attenuo-server / attenuo / examples/fake_mcp from DIR
#                         instead of building (default: cargo build into the target dir)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-multi-hop.XXXXXX")"
PIDS=()

cleanup() {
  local rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "demo failed (exit $rc). Last server log lines:" >&2
    tail -n 15 "$WORK/server.log" 2>/dev/null >&2 || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# --- output helpers ------------------------------------------------------------------------
if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'; else B=""; D=""; R=""; fi
say()  { printf '\n%s== %s%s\n' "$B" "$*" "$R"; }
note() { printf '%s# %s%s\n' "$D" "$*" "$R"; }

# Show a command, run it, show its output, and check its exit status (default 0).
# Usage: step EXPECTED_STATUS 'command string'      -> output also left in $OUT
step() {
  local want="$1" cmd="$2" rc=0
  printf '$ %s\n' "$cmd"
  OUT="$(eval "$cmd" 2>&1)" || rc=$?
  # Long tokens make a transcript unreadable; shorten them for display only.
  printf '%s\n' "$OUT" | sed -E 's/(token +[A-Za-z0-9_-]{24})[A-Za-z0-9_.-]+/\1.../'
  if [ "$rc" -ne "$want" ]; then
    echo "!! expected exit status $want, got $rc" >&2
    exit 1
  fi
}

# Check that the last step's output contains a string.
expect() {
  printf '%s\n' "$OUT" | grep -qF -- "$1" || { echo "!! expected output to contain: $1" >&2; exit 1; }
}

# Pull `key  value` out of the CLI's text output.
field() { printf '%s\n' "$OUT" | sed -n -E "s/^$1 +([^ ]+).*/\1/p" | head -n1; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' \
    2>/dev/null || echo $((20000 + RANDOM % 30000))
}

# --- build ----------------------------------------------------------------------------------
if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building (first run takes a while)..." >&2
  cargo build -q -p attenuo-server -p attenuo-cli
  cargo build -q -p attenuo-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
SERVER_BIN="$BIN/attenuo-server"; FAKE_BIN="$BIN/examples/fake_mcp"; CLI="$BIN/attenuo"
[ -x "$FAKE_BIN" ] || FAKE_BIN="$BIN/fake_mcp"
attenuo() { "$CLI" "$@"; }

# --- start the two servers on free ports ---------------------------------------------------
OB_PORT="$(free_port)"; MCP_PORT="$(free_port)"
while [ "$MCP_PORT" = "$OB_PORT" ]; do MCP_PORT="$(free_port)"; done

sed -e "s/18090/$OB_PORT/g" -e "s/13002/$MCP_PORT/g" \
    -e "s#examples/multi-hop-demo/policy.cedar#$HERE/policy.cedar#" \
    "$HERE/config.toml" > "$WORK/config.toml"

# The tool names of the real GitHub MCP server, as in config.toml's catalog.
"$FAKE_BIN" --port "$MCP_PORT" \
  --tools get_file_contents,list_issues,create_issue,create_or_update_file \
  > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
RUST_LOG=warn "$SERVER_BIN" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null 2>&1 \
    && grep -q listening "$WORK/fake-mcp.out" 2>/dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null || { echo "server did not start" >&2; exit 1; }

export ATTENUO_SERVER="http://127.0.0.1:$OB_PORT"
export ATTENUO_ADMIN_TOKEN="demo-admin-token"
unset ATTENUO_TOKEN ATTENUO_CLIENT_SECRET

# --- the scenario --------------------------------------------------------------------------
say "Setup"
note "attenuo at $ATTENUO_SERVER proxies a fake GitHub MCP server at port $MCP_PORT as 'github'."
note "Policy: reads anywhere in acme/, writes only to agent/* branches, never to main. See policy.cedar."
note "The policy's tests run offline first (policy_test.yaml)."
step 0 'attenuo policy test examples/multi-hop-demo/policy_test.yaml'

say "1. Exchange 1, alice -> planner: the planner's root token (hop 1)"
note "Read files and issues, open issues and write files, all only under acme/. may_act: only the"
note "coder may exchange this token. (The dev mint stands in for an OIDC ID token at POST /token.)"
step 0 'attenuo token root --subject alice --agent planner --may-act coder'
PLANNER="$(field token)"; PLANNER_LEASE="$(field lease)"

say "2. The planner looks at the issues it was asked to plan for: allowed"
step 0 'ATTENUO_TOKEN="$PLANNER" attenuo call --upstream github --tool list_issues --arg repo=acme/api'
expect ALLOWED

say "3. Refused exchange: the coder asks for get_file_contents on any repository"
note "The coder authenticates as itself (its secret on stdin). The parent's last hop covers"
note "get_file_contents only under acme/, so a capability with no repo constraint is wider: refused."
step 1 'printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$PLANNER" attenuo token exchange --actor coder --client-secret-stdin --cap github:get_file_contents'
expect "is not covered by the parent"
WIDEN_DECISION="$(field decision)"
[ -n "$WIDEN_DECISION" ] || { echo "!! expected the refusal to name its audit record" >&2; exit 1; }

say "4. Exchange 2, planner -> coder (hop 2), narrowed at every point"
note "repo narrowed from acme/ to acme/api, a distinct limit of 1 on repo (one repository per run),"
note "no list_issues, no create_issue, and --no-delegation (may_act: []) so nobody may exchange it."
step 0 'printf "%s\n" demo-coder-secret | ATTENUO_TOKEN="$PLANNER" attenuo token exchange --actor coder --client-secret-stdin --no-delegation --ttl-seconds 600 --cap '"'"'{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"prefix","value":"acme/api"}},"limits":{"distinct":{"arg":"repo","max":1}}}'"'"' --cap '"'"'{"server":"github","tool":"create_or_update_file","constraints":{"repo":{"op":"prefix","value":"acme/api"}},"limits":{"distinct":{"arg":"repo","max":1}}}'"'"''
CODER="$(field token)"; CODER_LEASE="$(field lease)"

say "5. What the coder's token says: two hops, each narrower than the one above"
step 0 'attenuo token inspect "$CODER" --verify'
expect "may_act []: no agent may exchange this token"

say "6. Exchange 3, refused: the coder tries to hand its token to a reviewer agent"
note "The reviewer authenticates fine, but the coder's token carries may_act: []."
step 1 'printf "%s\n" demo-reviewer-secret | ATTENUO_TOKEN="$CODER" attenuo token exchange --actor reviewer --client-secret-stdin --cap '"'"'{"server":"github","tool":"get_file_contents","constraints":{"repo":{"op":"equals","value":"acme/api"}}}'"'"''
expect "is not permitted to act on this token (may_act)"
expect "decision "

say "7. The coder reads the file it was asked to fix: allowed"
step 0 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs'
expect ALLOWED

say "8. The coder pushes its fix straight to main: denied by policy"
note "create_or_update_file on acme/api is in the coder's token; the policy wants an agent/* branch."
step 2 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool create_or_update_file --arg repo=acme/api --arg path=src/lib.rs --arg branch=main --arg content="fn fixed() {}"'
expect policy_deny
WRITE_DECISION="$(field decision)"

say "9. The coder tries to open an issue: denied, the planner never delegated create_issue"
step 2 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool create_issue --arg repo=acme/api --arg title="fix pushed"'
expect capability_denied

say "10. The coder reads from a second repository under acme/api: denied by the run limit"
note "acme/api-client is inside the coder's repo prefix and the policy allows the read, but the"
note "distinct limit allows one repository per run and acme/api was the first."
step 2 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/api-client --arg path=README.md'
expect budget_exhausted

say "11. The operator looks at the chain before acting"
note "The chain id is the planner's lease, the first hop's (also the chain_id of every audit record)."
step 0 'attenuo lease tree "$PLANNER_LEASE"'
step 0 'attenuo lease revoke --chain-id "$PLANNER_LEASE" --preview'

say "12. The operator revokes the whole chain by chain_id"
step 0 'attenuo lease revoke --chain-id "$PLANNER_LEASE" --reason "planner run went wrong"'
expect "revoked 2 lease(s)"

say "13. The coder's next call, even the one that worked before, is denied"
step 2 'ATTENUO_TOKEN="$CODER" attenuo call --upstream github --tool get_file_contents --arg repo=acme/api --arg path=src/lib.rs'
expect lease_revoked

say "14. The audit log records every decision, and its hash chain checks out"
step 0 'attenuo audit tail -n 50'
step 0 'attenuo audit verify'
expect "audit chain OK: 14 entries verified"

say "15. The refused widening exchange is in the log too"
note "A refused exchange whose subject token verified is a deny record against the parent's chain."
step 0 'attenuo audit show --id "$WIDEN_DECISION"'
expect exchange_widening

say "16. The decision chain of the refused write"
note "The record names both hops, the policy that decided, the leases (revoked now) and its hashes."
step 0 'attenuo audit show --id "$WRITE_DECISION"'
expect no_writes_to_default_branch

say "What reached the GitHub server"
UPSTREAM_CALLS="$(grep -c 'tools/call' "$WORK/fake-mcp.log" || true)"
grep 'tools/call' "$WORK/fake-mcp.log" | sed 's/^/  /'
echo "  -> $UPSTREAM_CALLS tools/calls reached upstream (the planner's list and the coder's read). The four denied calls never left attenuo."
[ "$UPSTREAM_CALLS" = 2 ] || { echo "!! expected exactly 2 upstream calls" >&2; exit 1; }

#!/usr/bin/env bash
# Reproduce the May 2025 GitHub MCP prompt-injection leak, and stop it, end to end.
#
#   examples/github-leak-demo/run.sh
#
# Starts onbehalf-server and a fake GitHub MCP server on free local ports, then plays the
# scenario with the `onbehalf` CLI. Exits non-zero if any step does not come out as expected.
# Re-runnable: nothing is written outside a temp dir, which the exit trap removes.
#
# Environment:
#   KEEP=1                keep the temp dir (logs, rendered config) after the run
#   ONBEHALF_BIN_DIR=DIR  use prebuilt onbehalf-server / onbehalf / examples/fake_mcp from DIR
#                         instead of building (default: cargo build into the target dir)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/onbehalf-demo.XXXXXX")"
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

# Pull `key  value` out of the CLI's text output.
field() { printf '%s\n' "$OUT" | sed -n -E "s/^$1 +([^ ]+).*/\1/p" | head -n1; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' \
    2>/dev/null || echo $((20000 + RANDOM % 30000))
}

# --- build ----------------------------------------------------------------------------------
if [ -n "${ONBEHALF_BIN_DIR:-}" ]; then
  BIN="$ONBEHALF_BIN_DIR"
else
  echo "building (first run takes a while)..." >&2
  cargo build -q -p onbehalf-server -p onbehalf-cli
  cargo build -q -p onbehalf-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
SERVER_BIN="$BIN/onbehalf-server"; FAKE_BIN="$BIN/examples/fake_mcp"; CLI="$BIN/onbehalf"
[ -x "$FAKE_BIN" ] || FAKE_BIN="$BIN/fake_mcp"
onbehalf() { "$CLI" "$@"; }

# --- start the two servers on free ports ---------------------------------------------------
OB_PORT="$(free_port)"; MCP_PORT="$(free_port)"
while [ "$MCP_PORT" = "$OB_PORT" ]; do MCP_PORT="$(free_port)"; done

sed -e "s/18080/$OB_PORT/g" -e "s/13001/$MCP_PORT/g" \
    -e "s#examples/github-leak-demo/policy.cedar#$HERE/policy.cedar#" \
    "$HERE/config.toml" > "$WORK/config.toml"

"$FAKE_BIN" --port "$MCP_PORT" > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
RUST_LOG=warn "$SERVER_BIN" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null 2>&1 \
    && grep -q listening "$WORK/fake-mcp.out" 2>/dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$OB_PORT/healthz" >/dev/null || { echo "server did not start" >&2; exit 1; }

export ONBEHALF_SERVER="http://127.0.0.1:$OB_PORT"
export ONBEHALF_ADMIN_TOKEN="demo-admin-token"

# --- the scenario --------------------------------------------------------------------------
say "Setup"
note "onbehalf at $ONBEHALF_SERVER proxies a fake GitHub MCP server at port $MCP_PORT as 'github'."
note "Policy: read_file only when repo like \"alice/public-*\". See policy.cedar."
note "The policy has its own tests (policy_test.yaml). They run offline, before any server traffic."
step 0 'onbehalf policy test examples/github-leak-demo/policy_test.yaml'

say "1. Alice's assistant gets a broad token (any github tool), like the over-privileged PAT"
step 0 'onbehalf token root --subject alice --agent assistant --cap "github:*"'
ROOT_TOKEN="$(field token)"; ROOT_LEASE="$(field lease)"

say "2. The assistant hands its 'coder' sub-agent read_file and nothing else"
note "The coder authenticates as itself ([[agents]] in config.toml): only it can receive a token in its name."
note "Its secret goes in on stdin (or ONBEHALF_CLIENT_SECRET, or --client-secret-file), never in argv."
step 0 'printf "%s\n" demo-coder-secret | onbehalf token exchange --subject-token "$ROOT_TOKEN" --actor coder --client-secret-stdin --cap github:read_file'
CODER="$(field token)"; CODER_LEASE="$(field lease)"

say "3. What the coder's token says"
step 0 'onbehalf token inspect "$CODER" --verify'

say "4. The coder reads a public repo as intended: allowed"
step 0 'onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md'

say "5. A malicious issue tells the coder to read alice/private-salaries: denied by policy"
note "read_file is in the token, but the policy only lets it touch alice/public-*."
step 2 'onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv'

say "6. The injection tries to copy the data out through create_issue: denied, never delegated"
step 2 'onbehalf call --token "$CODER" --server github --tool create_issue --arg repo=alice/public-docs --arg title=leak'

say "7. Alice sees the session going wrong and revokes the assistant's lease"
step 0 'onbehalf lease revoke "$ROOT_LEASE" --reason "agent session compromised"'
step 0 'onbehalf lease show "$CODER_LEASE"'

say "8. The coder's next call, even the legitimate one, is denied: the revocation cascaded"
step 2 'onbehalf call --token "$CODER" --server github --tool read_file --arg repo=alice/public-docs --arg path=README.md'

say "9. The audit log records every decision, and its hash chain checks out"
step 0 'onbehalf audit tail -n 10'
step 0 'onbehalf audit verify'

say "What reached the GitHub server"
UPSTREAM_CALLS="$(grep -c 'tools/call' "$WORK/fake-mcp.log" || true)"
grep 'tools/call' "$WORK/fake-mcp.log" | sed 's/^/  /'
echo "  -> $UPSTREAM_CALLS tools/call reached upstream. The three denied calls never left onbehalf."
[ "$UPSTREAM_CALLS" = 1 ] || { echo "!! expected exactly 1 upstream call" >&2; exit 1; }

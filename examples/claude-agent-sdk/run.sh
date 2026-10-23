#!/usr/bin/env bash
# Run the Claude Agent SDK example end to end, without a model (dry-run).
#
#   examples/claude-agent-sdk/run.sh            # dry-run, no API key needed
#   LIVE=1 ANTHROPIC_API_KEY=sk-ant-... examples/claude-agent-sdk/run.sh   # real agents
#
# Starts onbehalf-server and the fake GitHub MCP server on free local ports with the config and
# policy of examples/github-leak-demo, mints the orchestrator's root token through the dev
# endpoint, and runs agent.py. Exits non-zero if any call does not come out as expected.
#
# Environment:
#   LIVE=1                run the agents with Claude instead of the dry-run
#   PYTHON=PATH           a Python with onbehalf, mcp and claude-agent-sdk installed; by default a
#                         venv in the temp dir is created and requirements.txt installed
#   KEEP=1                keep the temp dir (logs, rendered config) after the run
#   ONBEHALF_BIN_DIR=DIR  use prebuilt onbehalf-server / fake_mcp from DIR instead of building

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DEMO="$ROOT/examples/github-leak-demo"
cd "$ROOT"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/onbehalf-example.XXXXXX")"
PIDS=()

cleanup() {
  local rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "example failed (exit $rc). Last server log lines:" >&2
    tail -n 15 "$WORK/server.log" 2>/dev/null >&2 || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' \
    2>/dev/null || echo $((20000 + RANDOM % 30000))
}

# --- binaries -------------------------------------------------------------------------------
if [ -n "${ONBEHALF_BIN_DIR:-}" ]; then
  BIN="$ONBEHALF_BIN_DIR"
else
  echo "building (first run takes a while)..." >&2
  cargo build -q -p onbehalf-server
  cargo build -q -p onbehalf-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
SERVER_BIN="$BIN/onbehalf-server"; FAKE_BIN="$BIN/examples/fake_mcp"
[ -x "$FAKE_BIN" ] || FAKE_BIN="$BIN/fake_mcp"

# --- python ---------------------------------------------------------------------------------
if [ -z "${PYTHON:-}" ]; then
  echo "creating a venv and installing requirements (set PYTHON= to skip)..." >&2
  python3 -m venv "$WORK/venv"
  PYTHON="$WORK/venv/bin/python"
  "$PYTHON" -m pip install -q -r "$HERE/requirements.txt" -e "$ROOT/sdk/python"
fi

# --- servers, on free ports, with the leak demo's config and policy -------------------------
OB_PORT="$(free_port)"; MCP_PORT="$(free_port)"
while [ "$MCP_PORT" = "$OB_PORT" ]; do MCP_PORT="$(free_port)"; done

sed -e "s/18080/$OB_PORT/g" -e "s/13001/$MCP_PORT/g" \
    -e "s#examples/github-leak-demo/policy.cedar#$DEMO/policy.cedar#" \
    "$DEMO/config.toml" > "$WORK/config.toml"

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

# --- the orchestrator's root token (dev endpoint; real deployments use an IdP) ---------------
ROOT_JSON="$(curl -sf -X POST "$ONBEHALF_SERVER/admin/root-token" \
  -H "Authorization: Bearer $ONBEHALF_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"subject":"alice","issuer":"https://idp.example","agent":"assistant","capabilities":["github:*"]}')"
ONBEHALF_ROOT_TOKEN="$(printf '%s' "$ROOT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
ONBEHALF_ROOT_LEASE="$(printf '%s' "$ROOT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["lease"])')"
export ONBEHALF_ROOT_TOKEN ONBEHALF_ROOT_LEASE

if [ "${LIVE:-0}" = 1 ]; then MODE=--live; else MODE=--dry-run; fi
"$PYTHON" "$HERE/agent.py" "$MODE"

# --- what reached the upstream --------------------------------------------------------------
if [ "$MODE" = --dry-run ]; then
  echo
  echo "What reached the fake GitHub server:"
  grep 'tools/call' "$WORK/fake-mcp.log" | sed 's/^/  /'
  CALLS="$(grep -c 'tools/call' "$WORK/fake-mcp.log" || true)"
  [ "$CALLS" = 1 ] || { echo "!! expected exactly 1 upstream tools/call, saw $CALLS" >&2; exit 1; }
  echo "  -> 1 tools/call reached upstream; nothing denied ever left onbehalf."
fi

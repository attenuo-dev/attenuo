#!/usr/bin/env bash
# Browser smoke test of the admin console against the real attenuo-server binary.
#
#   scripts/console-smoke.sh
#
# Builds attenuo-server, the attenuo CLI and the fake MCP upstream, starts the server with the
# GitHub leak demo's config plus an `[admin_ui]` listener (writes allowed) on free local ports,
# then runs the Playwright scripts in tests/console/ with `node --test`. They populate the log
# through the CLI (a chain, denials, a `budget_exhausted` decision, approvals), open every
# console page in headless Chromium in both themes, and fail on any console error, page error
# or CSP violation. Both servers are stopped on exit, pass or fail.
#
# Needs Node 20 or later and Playwright with its Chromium: `npm ci` in tests/console, then
# `npx playwright install --with-deps chromium` (CI does both). A machine with Playwright
# installed globally works without the `npm ci`.
#
# Environment:
#   ATTENUO_BIN_DIR=DIR      use prebuilt attenuo-server, attenuo and examples/fake_mcp from DIR
#   CONSOLE_SMOKE_SHOTS=DIR  write the screenshots (one per page per theme) to DIR; by default
#                            they go to a temp dir that is removed unless KEEP=1
#   KEEP=1                   keep the temp dir (config, logs, screenshots) after the run

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DEMO="$ROOT/examples/github-leak-demo"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-console-smoke.XXXXXX")"
PIDS=()
cleanup() {
  local rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo "console browser smoke test failed (exit $rc). Last server log lines:" >&2
    tail -n 20 "$WORK/server.log" >&2 2>/dev/null || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

if [ -n "${ATTENUO_BIN_DIR:-}" ]; then
  BIN="$ATTENUO_BIN_DIR"
else
  echo "building attenuo-server, attenuo and fake_mcp..." >&2
  cargo build --locked -q -p attenuo-server -p attenuo-cli
  cargo build --locked -q -p attenuo-proxy --features testing --example fake_mcp
  BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
fi
SERVER_BIN="$BIN/attenuo-server"
CLI_BIN="$BIN/attenuo"
FAKE_BIN="$BIN/examples/fake_mcp"
[ -x "$FAKE_BIN" ] || FAKE_BIN="$BIN/fake_mcp"

MAIN_PORT="$(free_port)"
MCP_PORT="$(free_port)"
UI_PORT="$(free_port)"
while [ "$MCP_PORT" = "$MAIN_PORT" ]; do MCP_PORT="$(free_port)"; done
while [ "$UI_PORT" = "$MAIN_PORT" ] || [ "$UI_PORT" = "$MCP_PORT" ]; do UI_PORT="$(free_port)"; done

# The demo config with its ports and policy path rewritten (as run.sh does), plus the console
# and root grants for two more users.
sed -e "s/18080/$MAIN_PORT/g" -e "s/13001/$MCP_PORT/g" \
    -e "s#examples/github-leak-demo/policy.cedar#$DEMO/policy.cedar#" \
    "$DEMO/config.toml" > "$WORK/config.toml"
cat >> "$WORK/config.toml" <<EOF

[admin_ui]
enabled = true
listen = "127.0.0.1:$UI_PORT"
allow_write = true

# Users whose chains the lease page's chain and user revocations act on.
[[root_grants]]
subject = "bob"
issuer = "https://idp.example"
agent = "assistant"
capabilities = ["github:*"]

[[root_grants]]
subject = "carol"
issuer = "https://idp.example"
agent = "assistant"
capabilities = ["github:*"]
EOF

"$FAKE_BIN" --port "$MCP_PORT" > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
RUST_LOG=warn "$SERVER_BIN" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 100); do
  curl -sf -o /dev/null "http://127.0.0.1:$MAIN_PORT/healthz" \
    && curl -sf -o /dev/null "http://127.0.0.1:$UI_PORT/admin/ui/" \
    && grep -q listening "$WORK/fake-mcp.out" 2>/dev/null && break
  sleep 0.1
done
curl -sf -o /dev/null "http://127.0.0.1:$UI_PORT/admin/ui/" || { echo "server did not start" >&2; exit 1; }

SHOTS="${CONSOLE_SMOKE_SHOTS:-$WORK/screenshots}"
mkdir -p "$SHOTS"

# The CLI must not pick up a developer's own server or tokens.
unset ATTENUO_TOKEN ATTENUO_SERVER ATTENUO_ADMIN_TOKEN

start="$(date +%s)"
CONSOLE_SMOKE_SERVER="http://127.0.0.1:$MAIN_PORT" \
CONSOLE_SMOKE_UI="http://127.0.0.1:$UI_PORT" \
CONSOLE_SMOKE_ADMIN_TOKEN="demo-admin-token" \
CONSOLE_SMOKE_CLI="$CLI_BIN" \
CONSOLE_SMOKE_SHOTS="$SHOTS" \
  node --test --test-concurrency=1 "$ROOT/tests/console/console.test.cjs"
echo "console browser smoke test passed in $(( $(date +%s) - start ))s; screenshots in $SHOTS" >&2

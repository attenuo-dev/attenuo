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
# or CSP violation. A second attenuo-server on the same upstream, whose console listener does
# not allow writes, is where the tests check that the console refuses a revocation there. The
# main server also has four `[[admin.operators]]` (viewer, operator, operator with a future
# expiry, expired viewer); tests/console/roles.test.cjs then logs in as each, and as the admin
# token, in a fresh page and checks the header, the buttons the role allows and the expired
# login message. All servers are stopped on exit, pass or fail.
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

# Five distinct free ports: main, upstream, console, and the read-only server's main and console.
PORTS=()
while [ "${#PORTS[@]}" -lt 5 ]; do
  p="$(free_port)"
  case " ${PORTS[*]:-} " in *" $p "*) ;; *) PORTS+=("$p") ;; esac
done
MAIN_PORT="${PORTS[0]}"
MCP_PORT="${PORTS[1]}"
UI_PORT="${PORTS[2]}"
RO_MAIN_PORT="${PORTS[3]}"
RO_UI_PORT="${PORTS[4]}"

# The demo policy plus a destructive tool the policy allows outright and asks about once the
# run is tainted unless the call carries an approval, which the policy page's dry runs with
# stated run labels and a stated approval use.
cp "$DEMO/policy.cedar" "$WORK/policy.cedar"
cat >> "$WORK/policy.cedar" <<'EOF'

// Console smoke test only (scripts/console-smoke.sh).
@id("smoke_permit_add_label")
permit(principal, action == Action::"github/add_label", resource);

@id("smoke_ask_add_label_on_tainted_run")
@obligation("approval")
forbid(principal, action == Action::"github/add_label", resource)
when { context.session.tainted && !context.approval.present };
EOF

# The demo config with its ports rewritten (as run.sh does) and that policy, plus the console,
# the catalog entry of the extra tool and root grants for two more users.
sed -e "s/18080/$MAIN_PORT/g" -e "s/13001/$MCP_PORT/g" \
    -e "s#examples/github-leak-demo/policy.cedar#$WORK/policy.cedar#" \
    "$DEMO/config.toml" > "$WORK/config.toml"
cat >> "$WORK/config.toml" <<EOF

# Destructive (not readonly): asked about on a tainted run by the smoke policy above.
[policy.catalog.github.add_label]
inputs = { repo = "string", label = "string" }

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

# Named operators (tests/console/roles.test.cjs): a viewer, an operator, an operator whose
# entry expires in the future and a viewer whose entry has expired. The config holds only the
# SHA-256 of each token, which `attenuo admin operator hash` computes.
VIEWER_TOKEN="smoke-viewer-token"
OPERATOR_TOKEN="smoke-operator-token"
EXPIRING_TOKEN="smoke-expiring-operator-token"
EXPIRING_AT="2099-12-31T23:59:59Z"
EXPIRED_TOKEN="smoke-expired-viewer-token"
operator_entry() { # name role token [expires_at]
  local digest
  digest="$(printf '%s\n' "$3" | "$CLI_BIN" admin operator hash)"
  printf '\n[[admin.operators]]\nname = "%s"\nrole = "%s"\ntoken_sha256 = "%s"\n' "$1" "$2" "$digest"
  [ -z "${4:-}" ] || printf 'expires_at = "%s"\n' "$4"
}
{
  operator_entry vera viewer "$VIEWER_TOKEN"
  operator_entry otto operator "$OPERATOR_TOKEN"
  operator_entry tara operator "$EXPIRING_TOKEN" "$EXPIRING_AT"
  operator_entry gone viewer "$EXPIRED_TOKEN" "2020-01-01T00:00:00Z"
} >> "$WORK/config.toml"

# The read-only server: the same config on its own ports, with a console that cannot write.
sed -e "s/18080/$RO_MAIN_PORT/g" -e "s/13001/$MCP_PORT/g" \
    -e "s#examples/github-leak-demo/policy.cedar#$DEMO/policy.cedar#" \
    "$DEMO/config.toml" > "$WORK/config-ro.toml"
cat >> "$WORK/config-ro.toml" <<EOF

[admin_ui]
enabled = true
listen = "127.0.0.1:$RO_UI_PORT"
allow_write = false
EOF

"$FAKE_BIN" --port "$MCP_PORT" > "$WORK/fake-mcp.out" 2> "$WORK/fake-mcp.log" &
PIDS+=($!)
RUST_LOG=warn "$SERVER_BIN" --config "$WORK/config.toml" > "$WORK/server.log" 2>&1 &
PIDS+=($!)
RUST_LOG=warn "$SERVER_BIN" --config "$WORK/config-ro.toml" > "$WORK/server-ro.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 100); do
  curl -sf -o /dev/null "http://127.0.0.1:$MAIN_PORT/healthz" \
    && curl -sf -o /dev/null "http://127.0.0.1:$UI_PORT/admin/ui/" \
    && curl -sf -o /dev/null "http://127.0.0.1:$RO_UI_PORT/admin/ui/" \
    && grep -q listening "$WORK/fake-mcp.out" 2>/dev/null && break
  sleep 0.1
done
for port in "$UI_PORT" "$RO_UI_PORT"; do
  curl -sf -o /dev/null "http://127.0.0.1:$port/admin/ui/" || { echo "server on $port did not start" >&2; exit 1; }
done

SHOTS="${CONSOLE_SMOKE_SHOTS:-$WORK/screenshots}"
mkdir -p "$SHOTS"

# The CLI must not pick up a developer's own server or tokens.
unset ATTENUO_TOKEN ATTENUO_SERVER ATTENUO_ADMIN_TOKEN

start="$(date +%s)"
CONSOLE_SMOKE_SERVER="http://127.0.0.1:$MAIN_PORT" \
CONSOLE_SMOKE_UI="http://127.0.0.1:$UI_PORT" \
CONSOLE_SMOKE_RO_SERVER="http://127.0.0.1:$RO_MAIN_PORT" \
CONSOLE_SMOKE_RO_UI="http://127.0.0.1:$RO_UI_PORT" \
CONSOLE_SMOKE_ADMIN_TOKEN="demo-admin-token" \
CONSOLE_SMOKE_CLI="$CLI_BIN" \
CONSOLE_SMOKE_SHOTS="$SHOTS" \
CONSOLE_SMOKE_VIEWER_TOKEN="$VIEWER_TOKEN" \
CONSOLE_SMOKE_OPERATOR_TOKEN="$OPERATOR_TOKEN" \
CONSOLE_SMOKE_EXPIRING_TOKEN="$EXPIRING_TOKEN" \
CONSOLE_SMOKE_EXPIRING_AT="$EXPIRING_AT" \
CONSOLE_SMOKE_EXPIRED_TOKEN="$EXPIRED_TOKEN" \
  node --test --test-concurrency=1 "$ROOT/tests/console/console.test.cjs" "$ROOT/tests/console/roles.test.cjs"
echo "console browser smoke test passed in $(( $(date +%s) - start ))s; screenshots in $SHOTS" >&2

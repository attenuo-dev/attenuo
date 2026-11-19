#!/usr/bin/env bash
# The GitHub leak demo from the published image: no Rust toolchain, nothing built from source.
#
#   examples/github-leak-demo/run-docker.sh
#
# Pulls the release image and the stock Python image, starts compose.image.yml (attenuo-server in
# front of a fake GitHub MCP server), and plays the scenario of run.sh with the CLI inside the
# server's container: a broad root token, a narrower one for the sub-agent, one allowed read, two
# denied calls, a revocation that cuts the sub-agent off, and a verified audit chain. Exits
# non-zero on the first step that does not come out as described, and always stops the
# containers.
#
# Needs docker with the compose plugin (v2.20 or later) and a free port on 127.0.0.1.
#
# Environment:
#   ATTENUO_IMAGE        the server image (default ghcr.io/attenuo-dev/attenuo:0.1.0)
#   ATTENUO_HOST_PORT    the host port for the agent-facing listener (default 8080)
#   KEEP=1               leave the containers running afterwards; the script prints how to use
#                        and stop them

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

command -v docker >/dev/null 2>&1 || { echo "docker is not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the docker compose plugin is not installed" >&2; exit 1; }

export COMPOSE_FILE=compose.image.yml
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-attenuo-leak-demo}"
ATTENUO_ADMIN_TOKEN="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
export ATTENUO_ADMIN_TOKEN
# Addresses as the server's own container sees them.
MAIN=http://127.0.0.1:8080
ADMIN=http://127.0.0.1:9102

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "the demo failed (exit $rc). Container logs:" >&2
    docker compose logs --no-color --tail 30 >&2 2>/dev/null || true
  fi
  if [ "${KEEP:-0}" = 1 ] && [ "$rc" -eq 0 ]; then
    cat <<EOF

The containers are still running (KEEP=1). The admin token for this run:
  export ATTENUO_ADMIN_TOKEN=$ATTENUO_ADMIN_TOKEN
Run the CLI in the server's container, for example:
  docker compose -p $COMPOSE_PROJECT_NAME exec attenuo attenuo --server $ADMIN audit tail
Stop them with:
  docker compose -p $COMPOSE_PROJECT_NAME down --volumes
EOF
  else
    docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

fail() { echo "!! $*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

# The CLI in the server's container. Tokens go in on stdin, never in argv.
cli() { docker compose exec -T attenuo attenuo "$@"; }

# Run a command, print its output, and check its exit status. Output is left in $OUT.
expect() {
  local want="$1" rc=0
  shift
  OUT="$("$@" 2>&1)" || rc=$?
  printf '%s\n' "$OUT" | sed -E 's/(token +[A-Za-z0-9_-]{24})[A-Za-z0-9_.-]+/\1.../'
  [ "$rc" -eq "$want" ] || fail "expected exit status $want, got $rc"
}

field() { printf '%s\n' "$OUT" | sed -n -E "s/^$1 +([^ ]+).*/\1/p" | head -n1; }

say "Start attenuo and the fake GitHub MCP server"
docker compose up --detach --wait --wait-timeout 120
expect 0 cli --server "$MAIN" health

say "1. Alice's assistant gets a broad token: github:*"
expect 0 cli --server "$ADMIN" token root --subject alice --agent assistant --cap 'github:*'
ROOT_TOKEN="$(field token)"; ROOT_LEASE="$(field lease)"
[ -n "$ROOT_TOKEN" ] && [ -n "$ROOT_LEASE" ] || fail "no token or lease in the output"

say "2. The assistant hands its coder sub-agent github:read_file only"
expect 0 sh -c 'printf "%s\n%s\n" "$1" demo-coder-secret | docker compose exec -T attenuo sh -c '\''read -r t; ATTENUO_TOKEN="$t" exec attenuo --server '"$MAIN"' token exchange --actor coder --client-secret-stdin --cap github:read_file'\' _ "$ROOT_TOKEN"
CODER="$(field token)"
[ -n "$CODER" ] || fail "no coder token in the output"

coder_call() { printf '%s\n' "$CODER" | cli --server "$MAIN" call --token - --upstream github "$@"; }

say "3. The coder reads the public repository: allowed"
expect 0 coder_call --tool read_file --arg repo=alice/public-docs --arg path=README.md

say "4. The injected call reads the private repository: denied by the policy"
expect 2 coder_call --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
case "$OUT" in *policy_deny*) ;; *) fail "expected policy_deny" ;; esac

say "5. The injected create_issue that would copy the data out: never delegated"
expect 2 coder_call --tool create_issue --arg repo=alice/public-docs --arg title=leak
case "$OUT" in *capability_denied*) ;; *) fail "expected capability_denied" ;; esac

say "6. Alice revokes the assistant's lease"
expect 0 cli --server "$ADMIN" lease revoke "$ROOT_LEASE" --reason "agent session compromised"

say "7. The coder's next call, even the legitimate one: cut off"
expect 2 coder_call --tool read_file --arg repo=alice/public-docs --arg path=README.md
case "$OUT" in *lease_revoked*) ;; *) fail "expected lease_revoked" ;; esac

say "8. The audit log"
expect 0 cli --server "$ADMIN" audit tail -n 20
expect 0 cli --server "$ADMIN" audit verify

say "What reached the fake GitHub server"
docker compose logs --no-color --no-log-prefix fake-mcp | grep 'tools/call' || true
calls="$(docker compose logs --no-color fake-mcp | grep -c 'tools/call' || true)"
[ "$calls" = 1 ] || fail "expected exactly 1 upstream call, got $calls"
echo "1 call reached the upstream: the legitimate read."

say "demo passed"

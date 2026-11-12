#!/usr/bin/env bash
# End-to-end test of the Dockerfile and docker-compose.yml.
#
#   scripts/compose-smoke.sh
#
# Builds both targets (the release image attenuo:dev and the demo image attenuo:demo), checks
# what the release image contains, starts the compose demo, waits for the server's health check
# (`attenuo health`) to pass, and plays the leak demo's scenario with the CLI inside the server's
# container: a root token from the admin listener, an exchange, an allowed call, two denials,
# a revocation that cascades, and a verified audit chain. Also checks from the host that only
# the main port is published and that it answers /admin/* with 404. Exits non-zero on the first
# check that fails and always takes the compose project down (containers, network, volumes).
#
# Needs docker with the compose plugin (v2.20 or later), curl and a free 127.0.0.1:8080. The
# first build compiles the workspace in release mode and takes a while.
#
# Environment:
#   COMPOSE_FILE         extra compose files, as compose reads them (for example a build
#                        override with a proxy); the default is docker-compose.yml
#   KEEP_IMAGES=1        keep attenuo:dev and attenuo:demo afterwards (default: keep; set 0
#                        to remove them)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export COMPOSE_PROJECT_NAME="attenuo-smoke-$$"
ATTENUO_ADMIN_TOKEN="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
export ATTENUO_ADMIN_TOKEN
MAIN=http://127.0.0.1:8080
ADMIN=http://127.0.0.1:9102

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "compose smoke test failed (exit $rc). Container logs:" >&2
    docker compose logs --no-color --tail 30 >&2 2>/dev/null || true
  fi
  docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [ "${KEEP_IMAGES:-1}" = 0 ]; then
    docker image rm attenuo:dev attenuo:demo >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

fail() { echo "!! $*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }

# The CLI in the server's container. Tokens go in on stdin or through the environment of the
# exec, never in argv.
cli() { docker compose exec -T attenuo attenuo "$@"; }

# Run a command, print its output, and check its exit status. Output is left in $OUT.
expect() {
  local want="$1" rc=0
  shift
  printf '$ %s\n' "$*"
  OUT="$("$@" 2>&1)" || rc=$?
  printf '%s\n' "$OUT" | sed -E 's/(token +[A-Za-z0-9_-]{24})[A-Za-z0-9_.-]+/\1.../'
  [ "$rc" -eq "$want" ] || fail "expected exit status $want, got $rc"
}

field() { printf '%s\n' "$OUT" | sed -n -E "s/^$1 +([^ ]+).*/\1/p" | head -n1; }

say "Build both targets"
docker compose build

say "Release image contents"
bins="$(docker run --rm --entrypoint /bin/ls attenuo:dev /usr/local/bin | tr '\n' ' ')"
echo "/usr/local/bin: $bins"
[ "$bins" = "attenuo attenuo-server " ] || fail "release image /usr/local/bin is not exactly attenuo and attenuo-server"
for tool in curl wget fake-mcp fake_mcp; do
  if docker run --rm --entrypoint /bin/sh attenuo:dev -c "command -v $tool" >/dev/null 2>&1; then
    fail "$tool is in the release image"
  fi
done
echo "no curl, wget or fake MCP server"
uid="$(docker run --rm --entrypoint /usr/bin/id attenuo:dev -u)"
[ "$uid" = 10001 ] || fail "release image runs as uid $uid, not 10001"
echo "runs as uid $uid"
check="$(docker image inspect -f '{{json .Config.Healthcheck.Test}}' attenuo:dev)"
echo "HEALTHCHECK $check"
case "$check" in *'"attenuo"'*'"health"'*) ;; *) fail "HEALTHCHECK is not attenuo health" ;; esac
docker run --rm --entrypoint /bin/sh attenuo:demo -c 'command -v fake-mcp' >/dev/null \
  || fail "fake-mcp is missing from the demo image"
echo "demo image has fake-mcp"

say "Start the demo and wait for the health check"
docker compose up --detach --wait --wait-timeout 90
status="$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q attenuo)")"
echo "attenuo container: $status"
[ "$status" = healthy ] || fail "attenuo container is $status"
expect 0 cli --server "$MAIN" health
expect 0 cli --server "$MAIN" health --ready
# The admin listener has no /healthz: the check must not pass against it.
expect 1 cli --server "$ADMIN" health

say "Ports seen from the host"
code="$(curl -s -o /dev/null -w '%{http_code}' "$MAIN/healthz")"
echo "GET $MAIN/healthz -> $code"
[ "$code" = 200 ] || fail "main port not reachable from the host"
code="$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $ATTENUO_ADMIN_TOKEN" "$MAIN/admin/policies")"
echo "GET $MAIN/admin/policies (with the admin token) -> $code"
[ "$code" = 404 ] || fail "main port serves /admin/*"
if curl -s -o /dev/null --max-time 3 "$ADMIN/healthz"; then
  fail "admin port 9102 is reachable from the host"
fi
echo "$ADMIN is not reachable from the host"

say "1. Root token from the admin listener"
expect 0 cli --server "$ADMIN" token root --subject alice --agent assistant --cap 'github:*'
ROOT_TOKEN="$(field token)"; ROOT_LEASE="$(field lease)"
[ -n "$ROOT_TOKEN" ] && [ -n "$ROOT_LEASE" ] || fail "no token or lease in the output"
# The main listener does not serve the admin API.
expect 1 cli --server "$MAIN" lease show "$ROOT_LEASE"

say "2. Exchange for the coder on the main listener"
expect 0 sh -c 'printf "%s\n%s\n" "$1" demo-coder-secret | docker compose exec -T attenuo sh -c '\''read -r t; ATTENUO_TOKEN="$t" exec attenuo --server '"$MAIN"' token exchange --actor coder --client-secret-stdin --cap github:read_file'\' _ "$ROOT_TOKEN"
CODER="$(field token)"
[ -n "$CODER" ] || fail "no coder token in the output"

coder_call() { printf '%s\n' "$CODER" | cli --server "$MAIN" call --token - --upstream github "$@"; }

say "3. Allowed and denied calls"
expect 0 coder_call --tool read_file --arg repo=alice/public-docs --arg path=README.md
expect 2 coder_call --tool read_file --arg repo=alice/private-salaries --arg path=2025.csv
expect 2 coder_call --tool create_issue --arg repo=alice/public-docs --arg title=leak

say "4. Revoke the root lease; the coder is cut off"
expect 0 cli --server "$ADMIN" lease revoke "$ROOT_LEASE" --reason "agent session compromised"
expect 2 coder_call --tool read_file --arg repo=alice/public-docs --arg path=README.md

say "5. Audit chain"
expect 0 cli --server "$ADMIN" audit verify

say "What reached the fake GitHub server"
calls="$(docker compose logs --no-color fake-mcp | grep -c 'tools/call' || true)"
echo "$calls tools/call reached the upstream"
[ "$calls" = 1 ] || fail "expected exactly 1 upstream call, got $calls"

say "compose smoke test passed"

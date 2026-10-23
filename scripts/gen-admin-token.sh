#!/usr/bin/env bash
# Print a random admin token (256 bits, hex) for attenuo-server's [admin] token.
#
#   scripts/gen-admin-token.sh            # token only, safe to capture: TOKEN=$(scripts/gen-admin-token.sh)
#
# Put it in the server config's [admin] section (or the file your deployment mounts) and export
# the same value as ATTENUO_ADMIN_TOKEN for the `attenuo` CLI. Do not commit it.
set -euo pipefail

if command -v openssl >/dev/null 2>&1; then
  token="$(openssl rand -hex 32)"
else
  token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

printf '%s\n' "$token"
if [ -t 1 ]; then
  {
    echo
    echo "server config:   [admin]  token = \"$token\""
    echo "CLI:             export ATTENUO_ADMIN_TOKEN=$token"
  } >&2
fi

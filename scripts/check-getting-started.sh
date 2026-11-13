#!/usr/bin/env bash
# Run the getting-started guide as a newcomer would, and fail when it no longer works as written.
#
#   scripts/check-getting-started.sh
#
# The rules and the `<!-- check: ... -->` markers are in scripts/check-doc-commands.sh, which
# does the work for every page under this check; this script runs it on the guide.
#
# Environment:
#   GUIDE=FILE  check another copy of the guide (default docs/guides/getting-started.md)
#   KEEP=1      keep the temp dir (the shell script run, each block's output, server logs)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_LABEL="getting started" exec bash "$ROOT_DIR/scripts/check-doc-commands.sh" \
  "${GUIDE:-$ROOT_DIR/docs/guides/getting-started.md}"

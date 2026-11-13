#!/usr/bin/env bash
# Run the getting-started guide as a newcomer would, and fail when it no longer works as written.
#
#   scripts/check-getting-started.sh
#
# The commands are read from docs/guides/getting-started.md itself, not copied here, so a change
# to the guide is checked on the next run and a command cannot be edited without the check
# running the new text. The rules:
#
# - Every ```sh block in the guide is run, in order, in one bash shell (variables, aliases and
#   the working directory carry from one block to the next, as in the reader's terminal). HOME
#   is a temp dir, so `~/attenuo-try` is scratch, and the shell starts in a stand-in checkout
#   whose `target/` is the cargo target dir, so `$REPO/target/debug/...` finds the binaries.
# - No command in a block may exit non-zero (pipefail is on), unless the block says otherwise.
# - A ```text or ```json block that comes right after a ```sh block, with no prose between
#   them, is that block's output: it must match what the commands printed (stdout and stderr),
#   after both are normalised by the rules in `normalise` below (times, UUIDs, key ids, runs
#   of spaces). A ```sh block that ends in `# ...` comment lines and has no such block gives
#   its expected output in those lines instead.
# - The guide's ports, 127.0.0.1:8080 and 127.0.0.1:3001, are replaced by free local ports in
#   the commands (not in the expected output: the token's `iss` is the default issuer, which
#   stays http://127.0.0.1:8080 whatever the listen port).
#
# A block can carry a marker, an HTML comment on the line right before its fence. Readers do
# not see it on GitHub or on the docs site. The markers are:
#
#   <!-- check: build -->       run only its `cargo build` lines, from the checkout, with your
#                               own HOME and CARGO_TARGET_DIR (`git clone` and `cd` are skipped)
#   <!-- check: background -->  one command, started in the background as a second terminal
#                               would run it; the next block waits until both ports answer
#   <!-- check: exit 2 -->      some command in the block exits 2 (the CLI's denial status),
#                               and no command exits with any other non-zero status
#
# A guide with no ```sh block, or with an unknown marker, fails the check.
#
# On failure it prints the block (with its line in the guide), the commands that failed and a
# diff of expected and actual output, and exits 1. The servers it started (and only those) are
# stopped on exit, pass or fail. Linux and macOS; needs bash, curl, jq, openssl and python3.
#
# Environment:
#   GUIDE=FILE  check another copy of the guide (default docs/guides/getting-started.md)
#   KEEP=1      keep the temp dir (the shell script run, each block's output, server logs)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
GUIDE="${GUIDE:-$ROOT_DIR/docs/guides/getting-started.md}"
[ -f "$GUIDE" ] || { echo "guide not found: $GUIDE" >&2; exit 2; }
for tool in curl jq openssl python3; do
  command -v "$tool" >/dev/null || { echo "check-getting-started: needs $tool" >&2; exit 2; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attenuo-getting-started.XXXXXX")"
PIDFILE="$WORK/pids"
: > "$PIDFILE"
cleanup() {
  local rc=$?
  local pid
  while read -r pid; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done < "$PIDFILE"
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}
SERVER_PORT="$(free_port)"
UPSTREAM_PORT="$(free_port)"
while [ "$UPSTREAM_PORT" = "$SERVER_PORT" ]; do UPSTREAM_PORT="$(free_port)"; done

# The extractor and the comparison, in one Python file: `plan` turns the guide into a bash
# script (run.sh) and one expected-output file per block; `compare` checks the results.
cat > "$WORK/guide.py" <<'PY'
import difflib, json, os, re, sys

FENCE = re.compile(r"^```(\S*)\s*$")
MARKER = re.compile(r"^<!--\s*check:\s*(.*?)\s*-->\s*$")
KNOWN = {"build", "background", "exit 2"}


def parse(path):
    """The fenced blocks of the guide: (line, info, marker, body, prose_since_previous)."""
    lines = open(path, encoding="utf-8").read().split("\n")
    blocks, i, prose, marker = [], 0, False, None
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            mk = MARKER.match(lines[i])
            if mk:
                marker = mk.group(1)
                if marker not in KNOWN:
                    sys.exit(f"{path}:{i + 1}: unknown check marker {marker!r} (known: {sorted(KNOWN)})")
            elif lines[i].strip():
                prose, marker = True, None
            i += 1
            continue
        start, body = i + 1, []
        i += 1
        while i < len(lines) and not lines[i].startswith("```"):
            body.append(lines[i])
            i += 1
        blocks.append({"line": start, "info": m.group(1), "marker": marker, "body": body, "prose": prose})
        prose, marker = False, None
        i += 1
    return blocks


def ports(text, server, upstream):
    text = text.replace("127.0.0.1:8080", f"127.0.0.1:{server}")
    text = text.replace("127.0.0.1:3001", f"127.0.0.1:{upstream}")
    return re.sub(r"--port 3001\b", f"--port {upstream}", text)


def plan(guide, work, server, upstream):
    blocks = parse(guide)
    steps = []
    for n, b in enumerate(blocks):
        if b["info"] != "sh":
            continue
        expected = None
        nxt = blocks[n + 1] if n + 1 < len(blocks) else None
        if nxt and nxt["info"] in ("text", "json") and not nxt["prose"]:
            expected = nxt["body"]
        body = list(b["body"])
        if expected is None:
            tail = []
            while body and body[-1].startswith("# "):
                tail.insert(0, body.pop()[2:])
            if tail:
                expected = tail
        steps.append({"line": b["line"], "marker": b["marker"], "body": body, "expected": expected})
    if not steps:
        sys.exit(f"{guide}: no ```sh blocks found")
    out = os.path.join(work, "out")
    os.makedirs(out, exist_ok=True)
    run = [
        "shopt -s expand_aliases",
        "set -o pipefail",
        f"__gs_out={out}",
        "__gs_block=0",
        # Every failing command is recorded against the block it ran in.
        "trap 'printf \"%s\\t%s\\n\" \"$?\" \"$BASH_COMMAND\" >> \"$__gs_out/$__gs_block.err\"' ERR",
        "__gs_wait() {",
        "  local i",
        "  for i in $(seq 1 300); do",
        f"    curl -s -o /dev/null http://127.0.0.1:{server}/healthz && curl -s -o /dev/null http://127.0.0.1:{upstream}/ && return 0",
        "    sleep 0.1",
        "  done",
        "  echo 'the background commands did not start listening within 30 s' > \"$__gs_out/$__gs_block.err\"",
        "  return 0",
        "}",
    ]
    build, waiting, manifest = [], False, []
    for k, s in enumerate(steps):
        text = ports("\n".join(s["body"]), server, upstream)
        manifest.append({"id": k, "line": s["line"], "marker": s["marker"], "text": text,
                         "expected": None if s["expected"] is None else "\n".join(s["expected"])})
        if s["marker"] == "build":
            build += [l for l in s["body"] if l.startswith("cargo build ")]
            if not build:
                sys.exit(f"{guide}:{s['line']}: a build block without a `cargo build` line")
            continue
        if s["marker"] == "background":
            cmds = [l for l in s["body"] if l.strip() and not l.lstrip().startswith("#")]
            if len(cmds) != 1:
                sys.exit(f"{guide}:{s['line']}: a background block must be one command")
            run += [f"__gs_block={k}", f"{ports(cmds[0], server, upstream)} > \"$__gs_out/{k}.out\" 2>&1 &",
                    f"echo $! >> {os.path.join(work, 'pids')}", f": > \"$__gs_out/{k}.done\""]
            waiting = True
            continue
        if waiting:
            run += [f"__gs_block={k}", "__gs_wait"]
            waiting = False
        run += [f"__gs_block={k}", "{", text, f"}} > \"$__gs_out/{k}.out\" 2>&1",
                f": > \"$__gs_out/{k}.done\""]
    if not build:
        sys.exit(f"{guide}: no block marked <!-- check: build -->")
    open(os.path.join(work, "run.sh"), "w").write("\n".join(run) + "\n")
    open(os.path.join(work, "build.sh"), "w").write("set -euo pipefail\n" + "\n".join(build) + "\n")
    json.dump(manifest, open(os.path.join(work, "manifest.json"), "w"))


# Values that differ on every run. Applied to the guide's text and to the actual output alike.
RULES = [
    # The guide shortens ids in `audit tail` to four characters and "...".
    (re.compile(r"\b(id|decision)=[0-9a-f]{4}(\.\.\.|[0-9a-f-]*)"), r"\1=<id>"),
    (re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z"), "<time>"),
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<uuid>"),
    (re.compile(r"\(in (\d+[hms] ?)+\)"), "(in <duration>)"),
    (re.compile(r"\b(kid|ou_kid) [A-Za-z0-9_-]+"), r"\1 <kid>"),
]


def normalise(text):
    out = []
    for line in text.split("\n"):
        for rx, sub in RULES:
            line = rx.sub(sub, line)
        line = re.sub(r"[ \t]+", " ", line).strip()
        out.append(line)
    while out and not out[-1]:
        out.pop()
    return out


def compare(guide, work):
    manifest = json.load(open(os.path.join(work, "manifest.json")))
    out = os.path.join(work, "out")
    failed = 0
    ran = 0
    for s in manifest:
        if s["marker"] == "build":
            continue
        k, where = s["id"], f"{guide}:{s['line']}"
        problems = []
        if not os.path.exists(os.path.join(out, f"{k}.done")):
            problems.append("did not run (an earlier block stopped the shell)")
        errs = []
        ep = os.path.join(out, f"{k}.err")
        if os.path.exists(ep):
            # A failing last command is recorded twice: for itself and for its block.
            errs = [l.split("\t", 1) for l in dict.fromkeys(open(ep).read().splitlines()) if l]
        bad = [e for e in errs if len(e) != 2 or not (s["marker"] == "exit 2" and e[0] == "2")]
        for e in bad:
            problems.append(f"command failed: {e[1] if len(e) == 2 else e[0]}" + (f" (exit {e[0]})" if len(e) == 2 else ""))
        if s["marker"] == "exit 2" and not any(len(e) == 2 and e[0] == "2" for e in errs) and not problems:
            problems.append("no command exited 2, but the block is marked <!-- check: exit 2 -->")
        actual = open(os.path.join(out, f"{k}.out"), errors="replace").read() if os.path.exists(os.path.join(out, f"{k}.out")) else ""
        if s["expected"] is not None and s["marker"] != "background":
            want, got = normalise(s["expected"]), normalise(actual)
            if want != got:
                diff = "\n".join(difflib.unified_diff(want, got, "guide (normalised)", "actual (normalised)", lineterm=""))
                problems.append("output differs from the guide:\n" + diff)
        ran += 1
        if problems:
            failed += 1
            print(f"\nFAIL {where}", file=sys.stderr)
            print("  " + s["text"].replace("\n", "\n  "), file=sys.stderr)
            for p in problems:
                print("  -> " + p.replace("\n", "\n     "), file=sys.stderr)
            if actual and not any(p.startswith("output differs") for p in problems):
                print("  output:\n     " + actual.rstrip().replace("\n", "\n     "), file=sys.stderr)
    if failed:
        for s in manifest:
            p = os.path.join(out, f"{s['id']}.out")
            if s["marker"] == "background" and os.path.exists(p):
                tail = open(p, errors="replace").read().rstrip().split("\n")[-15:]
                print(f"\nlast lines of the background command at {guide}:{s['line']}:", file=sys.stderr)
                print("     " + "\n     ".join(tail), file=sys.stderr)
        print(f"\ngetting started: {failed} of {ran} blocks failed ({guide}); the first failure is"
              " usually the cause of the ones after it", file=sys.stderr)
        sys.exit(1)
    print(f"getting started: all {ran} blocks ran as the guide says ({guide})")


if __name__ == "__main__":
    if sys.argv[1] == "plan":
        plan(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        compare(sys.argv[2], sys.argv[3])
PY

python3 "$WORK/guide.py" plan "$GUIDE" "$WORK" "$SERVER_PORT" "$UPSTREAM_PORT"

# Step 1, as written, from this checkout and with the caller's cargo settings.
echo "building (the guide's cargo build commands)..." >&2
bash "$WORK/build.sh"
TARGET="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"

# A stand-in checkout: every top-level entry of this one, with `target` pointing at the cargo
# target dir, wherever CARGO_TARGET_DIR put it.
CHECKOUT="$WORK/checkout"
mkdir -p "$CHECKOUT" "$WORK/home"
for entry in "$ROOT_DIR"/* "$ROOT_DIR"/.[!.]*; do
  [ -e "$entry" ] || continue
  [ "$(basename "$entry")" = target ] && continue
  ln -s "$entry" "$CHECKOUT/$(basename "$entry")"
done
ln -s "$TARGET" "$CHECKOUT/target"

# The reader's shell: a fresh HOME, no attenuo settings or log level from the caller's.
echo "running the guide's commands (server on $SERVER_PORT, fake MCP server on $UPSTREAM_PORT)..." >&2
(
  cd "$CHECKOUT"
  while IFS= read -r var; do unset "$var"; done < <(compgen -e | grep -E '^(ATTENUO_|ATTENUO__)' || true)
  unset RUST_LOG
  export HOME="$WORK/home"
  run=(bash --noprofile --norc "$WORK/run.sh")
  if command -v timeout >/dev/null; then run=(timeout 300 "${run[@]}"); fi
  "${run[@]}"
) || true

python3 "$WORK/guide.py" compare "$GUIDE" "$WORK"

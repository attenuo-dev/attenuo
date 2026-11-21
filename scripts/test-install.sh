#!/usr/bin/env bash
# Test scripts/install.sh against a fake release served from a local directory.
#
# No network and no real binaries: it packs two stand-in "binaries" the way the release
# workflow packs the real ones (attenuo-<tag>-<target>/attenuo and attenuo-server in a
# .tar.gz, plus SHA256SUMS), serves them with python3's http.server on a free loopback
# port, and runs install.sh with ATTENUO_BASE_URL pointing there. The machine's `uname` is
# replaced by a stand-in on PATH so every supported target, and an unsupported one, is
# exercised on any runner.
#
# Checks: each of the four targets installs both binaries and they run; the latest release
# is found through the /latest redirect; a wrong checksum, a missing SHA256SUMS entry, a
# malformed entry, an archive without a binary, an unknown version, an unsupported system
# and a bad ATTENUO_VERSION each fail and install nothing; a second install replaces the
# first; the PATH hint appears only when the directory is not on PATH.
#
# Run: scripts/test-install.sh   (needs bash, python3, curl, tar)

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
install_sh="$here/install.sh"
work=$(mktemp -d)
server_pid=""
cleanup() {
    [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

pass=0
fail() {
    echo "FAIL: $*" >&2
    exit 1
}
ok() {
    pass=$((pass + 1))
    echo "ok: $*"
}

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

targets="x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin"

# Build a release directory: $1 tag, $2 a word the stand-in binaries print.
make_release() {
    local tag=$1 word=$2 dir="$work/www/download/$1" t name
    mkdir -p "$dir"
    for t in $targets; do
        name="attenuo-$tag-$t"
        mkdir -p "$work/pack/$name"
        for bin in attenuo attenuo-server; do
            printf '#!/bin/sh\necho "%s %s %s %s"\n' "$bin" "$tag" "$t" "$word" >"$work/pack/$name/$bin"
            chmod 755 "$work/pack/$name/$bin"
        done
        echo "licence" >"$work/pack/$name/LICENSE"
        tar -C "$work/pack" -czf "$dir/$name.tar.gz" "$name"
        rm -rf "${work:?}/pack/$name"
    done
    (cd "$dir" && sha ./*.tar.gz | sed 's|\./||' >SHA256SUMS)
}

make_release v0.1.0 first
make_release v0.2.0 second

# The fake server: static files, and /latest redirects to /tag/v0.2.0 as GitHub does.
cat >"$work/serve.py" <<'PY'
import http.server, sys

class H(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/latest":
            self.send_response(302)
            self.send_header("Location", "/tag/v0.2.0")
            self.end_headers()
            return
        if self.path.startswith("/tag/"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"release page")
            return
        super().do_GET()

    def log_message(self, *a):
        pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY
(cd "$work/www" && exec python3 "$work/serve.py") >"$work/port" &
server_pid=$!
for _ in $(seq 1 50); do
    [ -s "$work/port" ] && break
    sleep 0.1
done
port=$(cat "$work/port")
[ -n "$port" ] || fail "the test server did not start"
base="http://127.0.0.1:$port"

# A stand-in `uname`: FAKE_OS and FAKE_ARCH choose what it reports.
mkdir "$work/bin"
cat >"$work/bin/uname" <<'SH'
#!/bin/sh
case "$1" in
    -s) echo "$FAKE_OS" ;;
    -m) echo "$FAKE_ARCH" ;;
    *) echo "$FAKE_OS" ;;
esac
SH
chmod 755 "$work/bin/uname"

# run_install <dest> [VAR=value ...]: run install.sh; output in $work/out, status returned.
run_install() {
    local dest=$1
    shift
    env PATH="$work/bin:$PATH" HOME="$work/home" FAKE_OS="${FAKE_OS:-Linux}" FAKE_ARCH="${FAKE_ARCH:-x86_64}" \
        ATTENUO_BASE_URL="$base" ATTENUO_INSTALL_DIR="$dest" "$@" ${INSTALL_SHELL:-sh} "$install_sh" >"$work/out" 2>&1
}

expect_failure() { # <name> <text the error must contain> <dest>
    local name=$1 text=$2 dest=$3
    grep -qF -- "$text" "$work/out" || fail "$name: expected \"$text\" in: $(cat "$work/out")"
    if [ -e "$dest/attenuo" ] || [ -e "$dest/attenuo-server" ]; then
        fail "$name: something was installed"
    fi
    ok "$name"
}

# 1. Every supported target, at a pinned version.
i=0
while read -r os arch want; do
    i=$((i + 1))
    dest="$work/dest$i"
    FAKE_OS=$os FAKE_ARCH=$arch run_install "$dest" ATTENUO_VERSION=v0.1.0 || fail "$os $arch: $(cat "$work/out")"
    for bin in attenuo attenuo-server; do
        [ -x "$dest/$bin" ] || fail "$os $arch: $bin is not installed or not executable"
        got=$("$dest/$bin")
        [ "$got" = "$bin v0.1.0 $want first" ] || fail "$os $arch: $bin printed \"$got\""
    done
    grep -q "checksum ok" "$work/out" || fail "$os $arch: no checksum line"
    ok "installs $want"
done <<EOF
Linux x86_64 x86_64-unknown-linux-musl
Linux amd64 x86_64-unknown-linux-musl
Linux aarch64 aarch64-unknown-linux-musl
Linux arm64 aarch64-unknown-linux-musl
Darwin x86_64 x86_64-apple-darwin
Darwin arm64 aarch64-apple-darwin
EOF

# 2. No version given: the latest release, found through the redirect. Then the same
#    directory again at the older version: the binaries are replaced.
dest="$work/latest"
run_install "$dest" || fail "latest: $(cat "$work/out")"
[ "$("$dest/attenuo")" = "attenuo v0.2.0 x86_64-unknown-linux-musl second" ] || fail "latest: wrong binary"
ok "installs the latest release when no version is given"
run_install "$dest" ATTENUO_VERSION=v0.1.0 || fail "reinstall: $(cat "$work/out")"
[ "$("$dest/attenuo-server")" = "attenuo-server v0.1.0 x86_64-unknown-linux-musl first" ] || fail "reinstall: not replaced"
[ -z "$(find "$dest" -name '.*.new.*')" ] || fail "reinstall: a temporary file was left behind"
ok "a second install replaces the first"

# 3. The PATH hint.
grep -q "is not on your PATH" "$work/out" || fail "no PATH hint for a directory that is not on PATH"
run_install "$dest" ATTENUO_VERSION=v0.1.0 PATH="$work/bin:$dest:$PATH" || fail "path: $(cat "$work/out")"
if grep -q "is not on your PATH" "$work/out"; then fail "PATH hint shown for a directory on PATH"; fi
ok "the PATH hint appears only when it is needed"

# 4. Failures. Each release below is v0.1.0 with one thing wrong.
break_release() { # <tag>: a copy of v0.1.0's files under another tag, names rewritten
    local tag=$1 dir="$work/www/download/$1" f
    mkdir -p "$dir"
    for f in "$work/www/download/v0.1.0"/*.tar.gz; do
        cp "$f" "$dir/$(basename "$f" | sed "s/v0\.1\.0/$tag/")"
    done
    sed "s/v0\.1\.0/$tag/" "$work/www/download/v0.1.0/SHA256SUMS" >"$dir/SHA256SUMS"
}
x86="x86_64-unknown-linux-musl"

# The archive's directory name carries the tag, so a renamed copy has the right checksum
# but no attenuo-<tag>-<target>/ directory: the "no binary" case.
break_release v0.9.1
dest="$work/f1"
if run_install "$dest" ATTENUO_VERSION=v0.9.1; then fail "archive without the binaries: installed"; fi
expect_failure "an archive without the binaries is refused" "has no attenuo-v0.9.1-$x86/attenuo" "$dest"

break_release v0.9.2
echo "tampered" >>"$work/www/download/v0.9.2/attenuo-v0.9.2-$x86.tar.gz"
dest="$work/f2"
if run_install "$dest" ATTENUO_VERSION=v0.9.2; then fail "wrong checksum: installed"; fi
expect_failure "a wrong checksum is refused" "checksum mismatch" "$dest"

break_release v0.9.3
grep -v "$x86" "$work/www/download/v0.9.3/SHA256SUMS" >"$work/sums" && mv "$work/sums" "$work/www/download/v0.9.3/SHA256SUMS"
dest="$work/f3"
if run_install "$dest" ATTENUO_VERSION=v0.9.3; then fail "missing entry: installed"; fi
expect_failure "a missing SHA256SUMS entry is refused" "has no entry for" "$dest"

break_release v0.9.4
sed "s/^[0-9a-f]*  attenuo-v0.9.4-$x86/zz  attenuo-v0.9.4-$x86/" "$work/www/download/v0.9.4/SHA256SUMS" >"$work/sums" && mv "$work/sums" "$work/www/download/v0.9.4/SHA256SUMS"
dest="$work/f4"
if run_install "$dest" ATTENUO_VERSION=v0.9.4; then fail "malformed entry: installed"; fi
expect_failure "a malformed SHA256SUMS entry is refused" "malformed entry" "$dest"

# An entry for another file whose name merely contains this archive's name must not match.
break_release v0.9.5
real=$(grep "$x86" "$work/www/download/v0.9.5/SHA256SUMS" | cut -d ' ' -f 1)
{
    grep -v "$x86" "$work/www/download/v0.9.5/SHA256SUMS"
    echo "$real  attenuo-v0.9.5-$x86.tar.gz.sig"
} >"$work/sums" && mv "$work/sums" "$work/www/download/v0.9.5/SHA256SUMS"
dest="$work/f5"
if run_install "$dest" ATTENUO_VERSION=v0.9.5; then fail "near-miss name: installed"; fi
expect_failure "an entry for a longer file name does not match" "has no entry for" "$dest"

dest="$work/f6"
if run_install "$dest" ATTENUO_VERSION=v9.9.9; then fail "unknown version: installed"; fi
expect_failure "an unknown version fails" "could not download" "$dest"

dest="$work/f7"
if run_install "$dest" ATTENUO_VERSION=latest; then fail "bad version word: installed"; fi
expect_failure "ATTENUO_VERSION must be a tag" "must be a release tag" "$dest"

dest="$work/f8"
if run_install "$dest" "ATTENUO_VERSION=v0.1.0/../x"; then fail "version with a slash: installed"; fi
expect_failure "a version with a path character is refused" "cannot have" "$dest"

dest="$work/f9"
if FAKE_OS=FreeBSD run_install "$dest" ATTENUO_VERSION=v0.1.0; then fail "FreeBSD: installed"; fi
expect_failure "an unsupported operating system fails" "no release binary for the operating system" "$dest"

dest="$work/f10"
if FAKE_ARCH=riscv64 run_install "$dest" ATTENUO_VERSION=v0.1.0; then fail "riscv64: installed"; fi
expect_failure "an unsupported architecture fails" "no release binary for the architecture" "$dest"

echo "install.sh: $pass checks passed"

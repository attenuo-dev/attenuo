#!/bin/sh
# Install the attenuo binaries (`attenuo` and `attenuo-server`) from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/attenuo-dev/attenuo/main/scripts/install.sh | sh
#
# It downloads the archive for this machine and the release's SHA256SUMS, checks the
# archive's SHA-256 against that file, and copies the two binaries into a directory you own.
# It never asks for sudo and changes nothing else. Nothing is installed when a check fails.
#
# The checksum protects against a damaged or incomplete download. It comes from the same
# release as the archive, so it does not protect against a release that was replaced; the
# container image is signed with cosign for that (docs/release/0.1.0.md).
#
# Environment:
#   ATTENUO_VERSION      release tag to install, for example v0.1.0 (default: the latest release)
#   ATTENUO_INSTALL_DIR  where the binaries go (default: $HOME/.local/bin)
#   ATTENUO_BASE_URL     where releases are served from (default:
#                        https://github.com/attenuo-dev/attenuo/releases); for a mirror, and
#                        for this script's test
#
# Supported: Linux x86_64 and aarch64 (static musl binaries), macOS x86_64 and arm64.
# Tested by scripts/test-install.sh.

set -eu

BASE_URL="${ATTENUO_BASE_URL:-https://github.com/attenuo-dev/attenuo/releases}"
INSTALL_DIR="${ATTENUO_INSTALL_DIR:-${HOME:-}/.local/bin}"
VERSION="${ATTENUO_VERSION:-}"

say() { printf '%s\n' "$*"; }
die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "this script needs \`$1\`, which was not found"
}

# The release target for this machine.
target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux) os_part=unknown-linux-musl ;;
        Darwin) os_part=apple-darwin ;;
        *) die "no release binary for the operating system \"$os\"; build from source (see CONTRIBUTING.md) or use the container image" ;;
    esac
    case "$arch" in
        x86_64 | amd64) arch_part=x86_64 ;;
        aarch64 | arm64) arch_part=aarch64 ;;
        *) die "no release binary for the architecture \"$arch\"; build from source (see CONTRIBUTING.md) or use the container image" ;;
    esac
    printf '%s-%s' "$arch_part" "$os_part"
}

# The latest release's tag: `releases/latest` redirects to `releases/tag/<tag>`.
latest_version() {
    url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$BASE_URL/latest") ||
        die "could not find the latest release at $BASE_URL/latest; set ATTENUO_VERSION"
    tag=${url##*/}
    case "$tag" in
        v[0-9]*) printf '%s' "$tag" ;;
        *) die "could not read a release tag from \"$url\"; set ATTENUO_VERSION" ;;
    esac
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    else
        die "this script needs \`sha256sum\` or \`shasum\` to check the download"
    fi
}

main() {
    need curl
    need tar
    need uname
    [ -n "$INSTALL_DIR" ] || die "HOME is not set; set ATTENUO_INSTALL_DIR"

    tgt=$(target)
    [ -n "$VERSION" ] || VERSION=$(latest_version)
    case "$VERSION" in
        v[0-9]*) ;;
        *) die "ATTENUO_VERSION must be a release tag such as v0.1.0, got \"$VERSION\"" ;;
    esac
    case "$VERSION" in
        *[!A-Za-z0-9.+-]*) die "ATTENUO_VERSION has a character a release tag cannot have: \"$VERSION\"" ;;
    esac

    name="attenuo-$VERSION-$tgt"
    archive="$name.tar.gz"
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064  # expand now: $tmp is fixed from here on
    trap "rm -rf '$tmp'" EXIT INT TERM

    say "attenuo $VERSION for $tgt"
    curl -fsSL -o "$tmp/$archive" "$BASE_URL/download/$VERSION/$archive" ||
        die "could not download $BASE_URL/download/$VERSION/$archive"
    curl -fsSL -o "$tmp/SHA256SUMS" "$BASE_URL/download/$VERSION/SHA256SUMS" ||
        die "could not download $BASE_URL/download/$VERSION/SHA256SUMS"

    # A line of SHA256SUMS is "<hex>  <name>" (or "<hex> *<name>"). Take the line of this
    # archive only, by exact name.
    want=$(awk -v f="$archive" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/SHA256SUMS")
    [ -n "$want" ] || die "SHA256SUMS of $VERSION has no entry for $archive; nothing was installed"
    case "$want" in
        *[!0-9a-f]* | "") die "SHA256SUMS of $VERSION has a malformed entry for $archive; nothing was installed" ;;
    esac
    [ "${#want}" -eq 64 ] || die "SHA256SUMS of $VERSION has a malformed entry for $archive; nothing was installed"
    got=$(sha256_of "$tmp/$archive")
    [ "$got" = "$want" ] ||
        die "checksum mismatch for $archive (expected $want, got $got); nothing was installed"
    say "checksum ok"

    mkdir "$tmp/x"
    tar -xzf "$tmp/$archive" -C "$tmp/x"
    for bin in attenuo attenuo-server; do
        [ -f "$tmp/x/$name/$bin" ] || die "$archive has no $name/$bin; nothing was installed"
    done

    mkdir -p "$INSTALL_DIR"
    for bin in attenuo attenuo-server; do
        # Copy next to the destination and rename, so a running binary is replaced whole.
        cp "$tmp/x/$name/$bin" "$INSTALL_DIR/.$bin.new.$$"
        chmod 755 "$INSTALL_DIR/.$bin.new.$$"
        mv -f "$INSTALL_DIR/.$bin.new.$$" "$INSTALL_DIR/$bin"
    done
    say "installed $INSTALL_DIR/attenuo and $INSTALL_DIR/attenuo-server"

    case ":${PATH:-}:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            say ""
            say "$INSTALL_DIR is not on your PATH. Add it, for example:"
            say "  export PATH=\"$INSTALL_DIR:\$PATH\""
            ;;
    esac
    say ""
    say "Next: https://github.com/attenuo-dev/attenuo/blob/main/docs/guides/getting-started.md"
}

# Everything runs from main, called on the last line, so a download cut off part-way
# through this script runs nothing.
main "$@"

# syntax=docker/dockerfile:1
#
# Two images from one file:
#
#   docker build -t attenuo:dev .                     # release image (target `runtime`, the default)
#   docker build --target demo -t attenuo:demo .      # demo tooling: the fake MCP server
#   docker compose up --build --wait                  # the leak demo, see docker-compose.yml
#
# The release image holds `attenuo-server` and the `attenuo` CLI and nothing else from this
# repository: no fake MCP server, no curl. Its HEALTHCHECK is `attenuo health`.
#
# The rust-version in Cargo.toml is 1.89; builds use the release rust-toolchain.toml pins
# (1.99.1). Keep the base image on that release: with any other, rustup downloads the pinned
# toolchain during the build.

# Pinned by digest (multi-arch index, SR-30). Refresh: Dependabot (docker ecosystem), or
# `docker buildx imagetools inspect rust:1-bookworm` and paste the top-level Digest.
FROM rust:1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS build
WORKDIR /src
COPY . .
# The toolchain rust-toolchain.toml names, without the rustfmt and clippy components it also
# lists: the base image has the toolchain but not those, and a build needs neither, so naming
# it here keeps rustup from downloading them on every build.
# Cache mounts keep the registry and target dir between builds; the binaries are copied out
# inside the same RUN because the target mount does not survive it.
# Each target architecture gets its own caches (BuildKit sets TARGETARCH). A multi-arch build
# runs both architectures at once: sharing one registry made the two unpack the same crate
# and fail with "File exists", and sharing one target dir would let one architecture's
# binaries overwrite the other's between the build and the copy.
ARG TARGETARCH
RUN --mount=type=cache,id=attenuo-cargo-registry-${TARGETARCH},sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=attenuo-target-${TARGETARCH},sharing=locked,target=/src/target \
    export RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)" \
 && cargo build --release --locked -p attenuo-server -p attenuo-cli \
 && mkdir /out \
 && cp target/release/attenuo-server target/release/attenuo /out/

# The fake MCP server (a test double that echoes calls), built only for the `demo` target.
FROM build AS build-demo
ARG TARGETARCH
RUN --mount=type=cache,id=attenuo-cargo-registry-${TARGETARCH},sharing=locked,target=/usr/local/cargo/registry \
    --mount=type=cache,id=attenuo-target-${TARGETARCH},sharing=locked,target=/src/target \
    export RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)" \
 && cargo build --release --locked -p attenuo-proxy --features testing --example fake_mcp \
 && cp target/release/examples/fake_mcp /out/fake-mcp

# Pinned by digest (multi-arch index, SR-30). Refresh: Dependabot (docker ecosystem), or
# `docker buildx imagetools inspect debian:bookworm-slim` and paste the top-level Digest.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS base
# No packages are installed: TLS uses rustls with its own built-in roots (webpki-roots), not the
# system store, and the health check is the CLI's own.
RUN groupadd --system --gid 10001 attenuo \
 && useradd --system --uid 10001 --gid attenuo --home-dir /var/lib/attenuo --shell /usr/sbin/nologin attenuo \
 && mkdir -p /var/lib/attenuo /etc/attenuo \
 && chown attenuo:attenuo /var/lib/attenuo \
 && chmod 0700 /var/lib/attenuo
USER attenuo
WORKDIR /var/lib/attenuo

# Demo tooling only; never deploy this image. Used by docker-compose.yml for the fake upstream.
FROM base AS demo
COPY --from=build-demo /out/fake-mcp /usr/local/bin/
ENTRYPOINT ["fake-mcp"]
CMD ["--host", "0.0.0.0", "--port", "3001"]

# The release image. Last in the file, so it is what a plain `docker build` produces.
FROM base AS runtime
COPY --from=build /out/attenuo-server /out/attenuo /usr/local/bin/
ENV RUST_LOG=info
EXPOSE 8080
# `attenuo health` asks GET /healthz and exits 0 or 1. It names the URL itself, so an
# ATTENUO_SERVER set in the container for admin commands does not move the check. A config
# whose [server] listen uses another port needs the same change here (or a compose/k8s
# healthcheck of its own); use `health --ready` for a readiness probe (GET /readyz).
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD ["attenuo", "--server", "http://127.0.0.1:8080", "health", "--timeout", "3"]

# Mount a config at /etc/attenuo/config.toml (see config/example.toml). A config that listens on
# 0.0.0.0 here needs [admin] listen (an address of its own, not published to agents) or
# [admin] serve_on_main_listener = true, or the server refuses to start (S-1).
ENTRYPOINT ["attenuo-server"]
CMD ["--config", "/etc/attenuo/config.toml"]

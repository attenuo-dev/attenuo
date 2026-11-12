# syntax=docker/dockerfile:1
#
# attenuo-server, the `attenuo` CLI and the demo fake MCP server in one small image.
#
#   docker build -t attenuo:dev .
#   docker compose up --build        # server + fake GitHub MCP, see docker-compose.yml
#
# The rust-version in Cargo.toml is 1.89; builds use the release rust-toolchain.toml pins
# (1.99.1). Keep the base image on that release: with any other, rustup downloads the pinned
# toolchain during the build.

# Pinned by digest (multi-arch index, SR-30). Refresh: Dependabot (docker ecosystem), or
# `docker buildx imagetools inspect rust:1-bookworm` and paste the top-level Digest.
FROM rust:1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /src
COPY . .
# Cache mounts keep the registry and target dir between builds; the binaries are copied out
# inside the same RUN because the target mount does not survive it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p attenuo-server -p attenuo-cli \
 && cargo build --release --locked -p attenuo-proxy --features testing --example fake_mcp \
 && mkdir /out \
 && cp target/release/attenuo-server target/release/attenuo /out/ \
 && cp target/release/examples/fake_mcp /out/fake-mcp

# Pinned by digest (multi-arch index, SR-30). Refresh: Dependabot (docker ecosystem), or
# `docker buildx imagetools inspect debian:bookworm-slim` and paste the top-level Digest.
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS runtime
# curl is only for the HEALTHCHECK.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 attenuo \
 && useradd --system --uid 10001 --gid attenuo --home-dir /var/lib/attenuo --shell /usr/sbin/nologin attenuo \
 && mkdir -p /var/lib/attenuo /etc/attenuo \
 && chown attenuo:attenuo /var/lib/attenuo
COPY --from=build /out/attenuo-server /out/attenuo /out/fake-mcp /usr/local/bin/

USER attenuo
WORKDIR /var/lib/attenuo
ENV RUST_LOG=info
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

# Mount a config at /etc/attenuo/config.toml (see config/example.toml).
ENTRYPOINT ["attenuo-server"]
CMD ["--config", "/etc/attenuo/config.toml"]

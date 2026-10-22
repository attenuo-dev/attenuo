# syntax=docker/dockerfile:1
#
# onbehalf-server, the `onbehalf` CLI and the demo fake MCP server in one small image.
#
#   docker build -t onbehalf:dev .
#   docker compose up --build        # server + fake GitHub MCP, see docker-compose.yml
#
# The rust-version in Cargo.toml is 1.85; the toolchain is `stable`, so build with a current
# image rather than pinning the minimum.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# Cache mounts keep the registry and target dir between builds; the binaries are copied out
# inside the same RUN because the target mount does not survive it.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p onbehalf-server -p onbehalf-cli \
 && cargo build --release --locked -p onbehalf-proxy --features testing --example fake_mcp \
 && mkdir /out \
 && cp target/release/onbehalf-server target/release/onbehalf /out/ \
 && cp target/release/examples/fake_mcp /out/fake-mcp

FROM debian:bookworm-slim AS runtime
# curl is only for the HEALTHCHECK.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 onbehalf \
 && useradd --system --uid 10001 --gid onbehalf --home-dir /var/lib/onbehalf --shell /usr/sbin/nologin onbehalf \
 && mkdir -p /var/lib/onbehalf /etc/onbehalf \
 && chown onbehalf:onbehalf /var/lib/onbehalf
COPY --from=build /out/onbehalf-server /out/onbehalf /out/fake-mcp /usr/local/bin/

USER onbehalf
WORKDIR /var/lib/onbehalf
ENV RUST_LOG=info
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

# Mount a config at /etc/onbehalf/config.toml (see config/example.toml).
ENTRYPOINT ["onbehalf-server"]
CMD ["--config", "/etc/onbehalf/config.toml"]

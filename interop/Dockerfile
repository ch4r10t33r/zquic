# zquic interop runner image
#
# Compatible with quic-interop-runner (https://github.com/quic-interop/quic-interop-runner).
#
# Build:
#   docker build -t zquic-interop -f interop/Dockerfile .
#
# The quic-interop-runner will invoke:
#   docker run --network <...> -e TESTCASE=<...> -e ROLE=<server|client> \
#              -e SSLKEYLOGFILE=<path> -e QLOGDIR=<path> \
#              -v /www:/www -v /downloads:/downloads \
#              -v /certs:/certs \
#              zquic-interop

# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.15.0
ARG ZIG_VERSION=0.15.0
RUN wget -q https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz \
    && tar -xf zig-linux-x86_64-${ZIG_VERSION}.tar.xz \
    && mv zig-linux-x86_64-${ZIG_VERSION} /usr/local/zig \
    && rm zig-linux-x86_64-${ZIG_VERSION}.tar.xz

ENV PATH="/usr/local/zig:${PATH}"

WORKDIR /build
COPY . .

# Build the server and client binaries.
RUN zig build -Doptimize=ReleaseFast

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/server /usr/local/bin/zquic-server
COPY --from=builder /build/zig-out/bin/client /usr/local/bin/zquic-client
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

# quic-interop-runner convention: entrypoint is /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]

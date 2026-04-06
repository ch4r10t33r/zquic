# zquic interop runner image
#
# Compatible with quic-interop-runner (https://github.com/quic-interop/quic-interop-runner).
#
# ── Local build (multi-stage, downloads Zig at build time) ──────────────────
#   docker build -t zquic-interop -f interop/Dockerfile .
#
# ── CI build (pre-built binaries supplied via --build-context) ──────────────
#   zig build -Doptimize=ReleaseFast
#   docker build -t zquic-interop \
#     --build-arg PREBUILT=1 \
#     -f interop/Dockerfile .
#
# The quic-interop-runner will invoke:
#   docker run --network <...> -e TESTCASE=<...> -e ROLE=<server|client> \
#              -e SSLKEYLOGFILE=<path> -e QLOGDIR=<path> \
#              -v /www:/www -v /downloads:/downloads -v /certs:/certs \
#              zquic-interop

ARG PREBUILT=0

# ── Stage 1a: build with local Zig download (PREBUILT=0) ────────────────────
FROM debian:bookworm-slim AS builder-download
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Download latest Zig 0.15.x dev tarball via the official JSON index.
RUN set -eux; \
    ZIG_URL=$(curl -fsSL https://ziglang.org/download/index.json \
        | grep -o '"x86_64-linux":[^}]*' \
        | grep -o '"tarball":"[^"]*"' \
        | head -1 \
        | sed 's/"tarball":"//;s/"//g'); \
    echo "Downloading Zig from: ${ZIG_URL}"; \
    curl -fsSL "${ZIG_URL}" -o /tmp/zig.tar.xz; \
    mkdir -p /usr/local/zig; \
    tar -xf /tmp/zig.tar.xz --strip-components=1 -C /usr/local/zig; \
    rm /tmp/zig.tar.xz

ENV PATH="/usr/local/zig:${PATH}"

WORKDIR /build
COPY . .
RUN zig build -Doptimize=ReleaseFast

# ── Stage 1b: pre-built binaries already on disk (PREBUILT=1) ───────────────
FROM debian:bookworm-slim AS builder-prebuilt
WORKDIR /build
COPY zig-out/ zig-out/

# ── Stage selector ──────────────────────────────────────────────────────────
FROM builder-${PREBUILT:-download} AS builder

# ── Stage 2: minimal runtime image ──────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/server /usr/local/bin/zquic-server
COPY --from=builder /build/zig-out/bin/client /usr/local/bin/zquic-client
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

# quic-interop-runner convention: entrypoint is /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]

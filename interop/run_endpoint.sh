#!/usr/bin/env bash
# Entry point for the quic-interop-runner.
#
# Environment variables set by the runner:
#   ROLE        — "server" or "client"
#   TESTCASE    — one of: handshake, transfer, retry, resumption, zerortt,
#                          http3, connectionmigration, rebind, keyupdate,
#                          multiconnect, v2
#   SERVER      — hostname / IP of the server (client role only)
#   CLIENT      — hostname / IP of the client (server role only)
#   PORT        — UDP port to bind/connect
#   REQUESTS    — space-separated list of URLs to fetch (client role only)
#   SSLKEYLOGFILE — path where TLS secrets should be written
#   QLOGDIR     — directory for qlog output
#   LOGS        — directory for additional log files
#
# Interop-runner test case mapping:
#   handshake          → basic QUIC handshake
#   transfer           → HTTP/0.9 file transfer
#   retry              → server sends Retry packet before accepting
#   resumption         → session ticket resumption (1-RTT)
#   zerortt            → 0-RTT early data
#   http3              → HTTP/3 GET
#   connectionmigration→ client migrates to a new port after connection
#   rebind             → server rebinds to a new address/port
#   keyupdate          → key update mid-connection
#   multiconnect       → multiple sequential connections
#   v2                 → QUIC version 2 (RFC 9369) — not yet supported

set -euo pipefail

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-handshake}"
PORT="${PORT:-443}"
SERVER="${SERVER:-localhost}"
SSLKEYLOGFILE="${SSLKEYLOGFILE:-/dev/null}"
QLOGDIR="${QLOGDIR:-/tmp/qlogs}"
CERT_DIR="${CERT_DIR:-/certs}"

mkdir -p "${QLOGDIR}"

# Shared flags
COMMON_FLAGS=(
    --port "${PORT}"
    --keylog "${SSLKEYLOGFILE}"
    --qlog-dir "${QLOGDIR}"
)

# Map test cases to feature flags understood by our binaries.
case "${TESTCASE}" in
    handshake|multiconnect)
        EXTRA_FLAGS=()
        ;;
    transfer)
        EXTRA_FLAGS=(--http09)
        ;;
    retry)
        EXTRA_FLAGS=(--retry)
        ;;
    resumption)
        EXTRA_FLAGS=(--resumption)
        ;;
    zerortt)
        EXTRA_FLAGS=(--early-data)
        ;;
    http3)
        EXTRA_FLAGS=(--http3)
        ;;
    connectionmigration)
        EXTRA_FLAGS=(--migrate)
        ;;
    rebind)
        EXTRA_FLAGS=(--rebind)
        ;;
    keyupdate)
        EXTRA_FLAGS=(--key-update)
        ;;
    v2)
        # QUIC v2 not yet supported — exit with interop "unsupported" code 127.
        echo "TESTCASE v2 not supported" >&2
        exit 127
        ;;
    *)
        echo "Unknown TESTCASE: ${TESTCASE}" >&2
        exit 127
        ;;
esac

if [[ "${ROLE}" == "server" ]]; then
    exec zquic-server \
        "${COMMON_FLAGS[@]}" \
        "${EXTRA_FLAGS[@]}" \
        --cert "${CERT_DIR}/cert.pem" \
        --key  "${CERT_DIR}/priv.key" \
        --www  /www
else
    # Build URL list from REQUESTS env var.
    URL_FLAGS=()
    for url in ${REQUESTS:-}; do
        URL_FLAGS+=(--url "${url}")
    done

    exec zquic-client \
        "${COMMON_FLAGS[@]}" \
        "${EXTRA_FLAGS[@]}" \
        --host "${SERVER}" \
        "${URL_FLAGS[@]}" \
        --output /downloads
fi

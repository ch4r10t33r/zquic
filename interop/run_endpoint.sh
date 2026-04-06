#!/usr/bin/env bash
# Entry point for the quic-interop-runner.
#
# Environment variables set by the runner (via docker-compose.yml):
#   ROLE            — "server" or "client"
#   TESTCASE        — e.g. handshake, transfer, retry, resumption, zerortt,
#                     http3, connectionmigration, keyupdate, chacha20,
#                     multiplexing, rebind
#   REQUESTS        — space-separated URLs for client to download
#                     Format: "https://server4:443/path ..."
#                     The server host and port are parsed from here.
#   SSLKEYLOGFILE   — where to write TLS key material (NSS key log format)
#   QLOGDIR         — directory for qlog output
#   CERTS           — directory containing cert.pem and priv.key (server role)

set -euo pipefail

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-handshake}"
SSLKEYLOGFILE="${SSLKEYLOGFILE:-/dev/null}"
QLOGDIR="${QLOGDIR:-/logs/qlog}"
CERT_DIR="${CERTS:-/certs}"

mkdir -p "${QLOGDIR}"

# Map test cases to feature flags understood by our binaries.
# Unknown or unsupported test cases exit 127 so the runner marks them "unsupported".
case "${TESTCASE}" in
    handshake|multiplexing|multiconnect)
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
    chacha20)
        EXTRA_FLAGS=(--chacha20)
        ;;
    v2)
        echo "TESTCASE v2 not supported" >&2
        exit 127
        ;;
    *)
        echo "Unknown TESTCASE: ${TESTCASE}" >&2
        exit 127
        ;;
esac

if [[ "${ROLE}" == "server" ]]; then
    # Disable reverse-path filtering so we can receive packets routed through
    # the network simulator (source IP is on a different subnet than our NIC).
    sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
    sysctl -w net.ipv4.conf.eth0.rp_filter=0 2>/dev/null || true
    # Add a route for the client subnet via the sim's rightnet gateway so
    # our UDP responses are sent back through the sim (not dropped).
    ip route add 193.167.0.0/24 via 193.167.100.2 2>/dev/null || true
    exec zquic-server \
        --port 443 \
        --keylog "${SSLKEYLOGFILE}" \
        --qlog-dir "${QLOGDIR}" \
        "${EXTRA_FLAGS[@]}" \
        --cert "${CERT_DIR}/cert.pem" \
        --key  "${CERT_DIR}/priv.key" \
        --www  /www
else
    # Parse the server host and port from the first URL in REQUESTS.
    # The docker-compose does not set a SERVER env var for the client
    # container; the server address is encoded in the REQUESTS URLs.
    # URL format: https://server4:443/path
    HOST="server4"
    PORT="443"
    if [[ -n "${REQUESTS:-}" ]]; then
        FIRST_URL="${REQUESTS%% *}"         # take only the first URL
        HOSTPATH="${FIRST_URL#https://}"    # strip https://
        HOSTPORT="${HOSTPATH%%/*}"          # strip everything after the first /
        if [[ "${HOSTPORT}" == *:* ]]; then
            HOST="${HOSTPORT%:*}"
            PORT="${HOSTPORT##*:}"
        else
            HOST="${HOSTPORT}"
        fi
    fi

    # Build per-URL download flags.
    URL_FLAGS=()
    for url in ${REQUESTS:-}; do
        URL_FLAGS+=(--url "${url}")
    done

    exec zquic-client \
        --host "${HOST}" \
        --port "${PORT}" \
        --keylog "${SSLKEYLOGFILE}" \
        --qlog-dir "${QLOGDIR}" \
        "${EXTRA_FLAGS[@]}" \
        "${URL_FLAGS[@]}" \
        --output /downloads
fi

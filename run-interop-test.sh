#!/bin/bash
# Helper script to run QUIC interop tests with instrumented binaries

set -e

ZQUIC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER_DIR="/Users/partha/projects/zig/quic-interop-runner"
INTEROP_DIR="$ZQUIC_DIR/interop"

echo "🔨 Building Docker image with instrumented binaries..."
docker build -t zquic-interop -f "$INTEROP_DIR/Dockerfile.prebuilt" "$ZQUIC_DIR"

echo "📋 Running QUIC interop tests..."
cd "$RUNNER_DIR"

# Run specific tests: handshake and transfer
python3 run.py \
  --protocol quic \
  --server zquic \
  --client zquic \
  --tests handshake,transfer \
  --log-dir /tmp/zquic-interop-logs

echo "✅ Tests completed!"
echo "📊 Results in /tmp/zquic-interop-logs/"
echo ""
echo "View server logs:"
echo "  cat /tmp/zquic-interop-logs/*/zquic_zquic/transfer/server/*.log | grep 'io:'"
echo ""
echo "View client logs:"
echo "  cat /tmp/zquic-interop-logs/*/zquic_zquic/transfer/client/*.log | grep 'io:'"

#!/bin/bash
# Local HTTP/0.9 transfer test without Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BIN="$SCRIPT_DIR/zig-out/bin/server"
CLIENT_BIN="$SCRIPT_DIR/zig-out/bin/client"

# Create test directories
TEST_DIR="/tmp/zquic-local-test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"/{www,downloads,certs,logs}

echo "📁 Test directory: $TEST_DIR"

# Generate test certificates (P-256 ECDSA)
echo "🔐 Generating certificates..."
openssl ecparam -name prime256v1 -genkey -noout -out "$TEST_DIR/certs/key.pem"
openssl req -x509 -new -key "$TEST_DIR/certs/key.pem" -out "$TEST_DIR/certs/cert.pem" \
  -days 1 -subj "/CN=localhost" 2>/dev/null

# Generate test files
echo "📄 Generating test files..."
dd if=/dev/urandom of="$TEST_DIR/www/file1.bin" bs=1M count=1 2>/dev/null
dd if=/dev/urandom of="$TEST_DIR/www/file2.bin" bs=1M count=2 2>/dev/null
dd if=/dev/urandom of="$TEST_DIR/www/file3.bin" bs=1M count=3 2>/dev/null

echo "✅ Generated files:"
ls -lh "$TEST_DIR/www/"

# Start server in background
echo ""
echo "🚀 Starting server on localhost:4433..."
"$SERVER_BIN" \
  --port 4433 \
  --cert "$TEST_DIR/certs/cert.pem" \
  --key "$TEST_DIR/certs/key.pem" \
  --www "$TEST_DIR/www" \
  --http09 \
  2>&1 | tee "$TEST_DIR/logs/server.log" &

SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
  echo "❌ Server failed to start"
  cat "$TEST_DIR/logs/server.log"
  exit 1
fi

echo "✅ Server running (PID: $SERVER_PID)"
echo ""

# Run client
echo "📥 Starting client - downloading files..."
"$CLIENT_BIN" \
  --host 127.0.0.1 \
  --port 4433 \
  --output "$TEST_DIR/downloads" \
  --url "https://127.0.0.1:4433/file1.bin" \
  --url "https://127.0.0.1:4433/file2.bin" \
  --url "https://127.0.0.1:4433/file3.bin" \
  2>&1 | tee "$TEST_DIR/logs/client.log" || true

echo ""

# Kill server
echo "🛑 Stopping server..."
kill $SERVER_PID 2>/dev/null || true
sleep 1

# Check results
echo ""
echo "📊 RESULTS:"
echo "==========="

echo ""
echo "Downloaded files:"
ls -lh "$TEST_DIR/downloads/" 2>/dev/null || echo "  (none)"

echo ""
echo "Server logs (with instrumentation):"
echo "---"
grep "io:" "$TEST_DIR/logs/server.log" | head -50
echo "---"

echo ""
echo "Client logs:"
echo "---"
grep "io:" "$TEST_DIR/logs/client.log" | head -20
echo "---"

echo ""
echo "✅ Test complete! Logs at: $TEST_DIR/logs/"

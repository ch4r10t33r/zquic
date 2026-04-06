# Testing the Instrumented HTTP/0.9 Transfer Fix

## Status: ✅ Binaries Built

Your instrumented binaries are ready:
- `/Users/partha/projects/zig/zquic/zig-out/bin/server` (4.5M)
- `/Users/partha/projects/zig/zquic/zig-out/bin/client` (3.1M)

Built with Zig 0.15.0 at 22:02 on 2026-04-06

## Quick Start

### Option 1: Using the Helper Script (Recommended)

```bash
cd /Users/partha/projects/zig/zquic
./run-interop-test.sh
```

This will:
1. Build Docker image with your instrumented binaries
2. Run QUIC interop tests (handshake + transfer)
3. Collect logs with full instrumentation output

### Option 2: Manual Docker Build & Test

```bash
cd /Users/partha/projects/zig/zquic

# Build Docker image
docker build -t zquic-interop -f interop/Dockerfile.prebuilt .

# Run tests using quic-interop-runner
cd /Users/partha/projects/zig/quic-interop-runner
python3 run.py \
  --server zquic \
  --client zquic \
  --tests handshake,transfer \
  --log-dir /tmp/zquic-logs
```

### Option 3: Manual Docker Container (for debugging)

```bash
# Build image
docker build -t zquic-test -f /Users/partha/projects/zig/zquic/interop/Dockerfile.prebuilt \
  /Users/partha/projects/zig/zquic

# Create test files
mkdir -p /tmp/server-www
dd if=/dev/urandom of=/tmp/server-www/sweet-infinite-rocket bs=1M count=2
dd if=/dev/urandom of=/tmp/server-www/arctic-pleased-merchant bs=1M count=3
dd if=/dev/urandom of=/tmp/server-www/smooth-guilty-actress bs=1M count=5

# Run server (in background)
docker run --rm \
  -v /tmp/server-www:/www \
  -p 443:443/udp \
  -e ROLE=server \
  -e TESTCASE=transfer \
  -e CERTS=/certs \
  zquic-test 2>&1 | tee /tmp/server.log &

SERVER_PID=$!
sleep 2

# Run client
mkdir -p /tmp/client-downloads
docker run --rm \
  -v /tmp/client-downloads:/downloads \
  --network host \
  -e ROLE=client \
  -e TESTCASE=transfer \
  -e REQUESTS="https://127.0.0.1:443/sweet-infinite-rocket https://127.0.0.1:443/arctic-pleased-merchant https://127.0.0.1:443/smooth-guilty-actress" \
  zquic-test 2>&1 | tee /tmp/client.log

# Kill server
kill $SERVER_PID 2>/dev/null || true
```

## Analyzing the Logs

### View All Instrumentation Logs

```bash
# Server logs with instrumentation
grep "io:" /tmp/zquic-logs/*/zquic_zquic/transfer/server/*.log | head -100

# Client logs with instrumentation
grep "io:" /tmp/zquic-logs/*/zquic_zquic/transfer/client/*.log | head -100
```

### Key Log Messages to Look For

**Success indicators:**
```
io: STREAM frame parsed: stream_id=0 offset=0 data_len=17 fin=true
io: handleHttp09Stream called: stream_id=0 data_len=17
io: http09 stream_id=0 parsed path=/sweet-infinite-rocket
io: http09 stream_id=0 opened (size=2097152)
io: http09 stream_id=0 chunk: bytes=1200 offset=0 fin=false
```

**Error indicators:**
```
io: STREAM frame parse error ft=0x0b: [ERROR_TYPE]
io: process1RttPacket: no matching connection found
io: http09 stream_id=X parse error: [ERROR_TYPE]
io: file not found: /path/to/file
io: build1RttPacketFull error payload_len=X: [ERROR]
```

### Using DEBUG_PLAN.md for Diagnosis

Once you have logs, use `DEBUG_PLAN.md` to interpret them:
```bash
# Read the diagnostic flowchart
cat /Users/partha/projects/zig/zquic/DEBUG_PLAN.md
```

## Troubleshooting

### "docker: command not found"
Docker is in OrbStack but may not be accessible. Try:
```bash
# Check if Docker is running
docker ps

# If not found, you may need to start OrbStack or configure Docker access
```

### "python3: No module named..."
Install requirements:
```bash
cd /Users/partha/projects/zig/quic-interop-runner
pip3 install -r requirements.txt
```

### Test Timeout
If the transfer test still times out, check:
1. All instrumentation logs are present (look for "io:" messages)
2. Follow the diagnostic flowchart in `DEBUG_PLAN.md`
3. Share the first error message from logs

## Expected Results

### If Transfer Test Passes ✅
```
Results:
  handshake: PASSED
  transfer:  PASSED
```
The HTTP/0.9 slot opening and sending would be working correctly.

### If Transfer Test Fails (Expected) ❌
```
Results:
  handshake: PASSED
  transfer:  FAILED (timeout)
```

With the instrumentation, the logs will show exactly where it fails:
- Frame parsing errors → Issue with STREAM frame decoding
- "no matching connection" → Connection state problem
- Parse errors → GET request format issue
- File not found → Test setup issue
- Send errors → Packet building issue

## Next Steps

1. **Run the test:** Execute the helper script or manual option above
2. **Capture logs:** Extract the "io:" debug messages
3. **Identify failure point:** Use the log messages to pinpoint the issue
4. **Fix and iterate:** Make code changes and rebuild binaries
5. **Verify:** Re-run tests to confirm the fix

## Files Reference

- **Instrumented code:** `src/transport/io.zig`
- **Binaries:** `zig-out/bin/{server,client}`
- **Docker config:** `interop/Dockerfile.prebuilt`
- **Test runner:** `/Users/partha/projects/zig/quic-interop-runner/`
- **Diagnostics:** `DEBUG_PLAN.md`
- **Implementation notes:** `IMPLEMENTATION_SUMMARY.md`

## Zig Version Info

To rebuild after code changes:
```bash
/Users/partha/.local/share/zigup/0.15.0/files/zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu
```

Or set an alias:
```bash
# In your shell config (~/.bashrc, ~/.zshrc, etc.):
export PATH="/Users/partha/.local/share/zigup/0.15.0/files:$PATH"
```

Then just use: `zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu`

# QUIC Interop Transfer Timeout - Debug Plan

## Issue Summary
The `transfer` interop test times out at 60s. The handshake succeeds, but HTTP/0.9 file transfers don't complete. The server receives the GET requests but enters an idle state (2s poll intervals) without sending responses.

## Root Cause Hypothesis
HTTP/0.9 response slots are never being opened, likely due to:
1. STREAM frames not being parsed correctly
2. Request parsing errors (parseRequest failing)
3. Path resolution errors (resolvePath failing)
4. File not found errors
5. Silent failures in send path (serialize/build1RttPacketFull)

## Instrumentation Added

All changes are in `src/transport/io.zig`. The instrumentation adds detailed logging at each step of the HTTP/0.9 request handling pipeline:

### STREAM Frame Parsing (lines 1470-1480)
**Logs:**
```
io: STREAM frame parse error ft=0xXX: {error}
io: STREAM frame parsed: stream_id=X offset=X data_len=X fin=X
```

**What to look for:**
- If you see "parse error" messages, there's an issue with frame parsing
- If you see "parsed" messages, frames are being decoded correctly
- Compare `stream_id` with expected values (0, 4, 8 for HTTP/0.9)

### HTTP/0.9 Stream Opening (lines 1597-1643)
**Logs in order:**
```
io: handleHttp09Stream called: stream_id=X data_len=X
io: http09 stream_id=X rejected (not client-initiated, % 4 = X)  [OR]
io: http09 stream_id=X empty data  [OR]
io: http09 stream_id=X parse error: {error} (data=X)  [OR]
io: http09 stream_id=X parsed path=/...  [then]
io: http09 stream_id=X resolvePath error: {error}  [OR]
io: file not found: /path/to/file  [OR]
io: http09 stream_id=X opened (size=X)  [SUCCESS]
```

**What to look for:**
- "handleHttp09Stream called" confirms STREAM data reaching the handler
- "empty data" means the request body is empty - likely first segment only
- "parse error" (Incomplete, NotAGetRequest, etc.) means request parsing failed
- "opened (size=X)" means successful slot opening - this should appear 3 times for 3 files

### Send-Side Errors (lines 1514-1548)
**Logs:**
```
io: http09 stream_id=X chunk: bytes=X offset=X fin=X frame_len=X
io: build1RttPacketFull error payload_len=X: {error}
io: sendto error pkt_len=X: {error}
io: http09 stream_id=X complete
```

**What to look for:**
- "chunk" messages appear if slots are opened (confirms response sending starts)
- "build1RttPacketFull error" or "sendto error" indicate packet building/sending failure
- If you see "chunk" but then no more, the send path is failing silently

## Testing Procedure

### 1. Build with Instrumentation
```bash
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu  # For Docker (Apple Silicon)
# OR
zig build -Doptimize=ReleaseFast                             # For local macOS testing
```

### 2. Run Local Test (macOS)
If you want to test locally on macOS (though network simulation won't work):
```bash
./zig-out/bin/server &
SERVER_PID=$!
./zig-out/bin/client 127.0.0.1 443 http://127.0.0.1:443/file1.bin http://127.0.0.1:443/file2.bin
kill $SERVER_PID
```

### 3. Run Interop Tests with Docker
Build Linux ELF binaries:
```bash
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu
cd interop
./run_endpoint.sh --local
```

## Expected Log Sequence for Success

For 3 HTTP/0.9 downloads (files 1-3):

```
io: STREAM frame parsed: stream_id=0 offset=0 data_len=17 fin=true
io: handleHttp09Stream called: stream_id=0 data_len=17
io: http09 stream_id=0 parsed path=/file1.bin
io: http09 stream_id=0 opened (size=2097152)

io: STREAM frame parsed: stream_id=4 offset=0 data_len=17 fin=true
io: handleHttp09Stream called: stream_id=4 data_len=17
io: http09 stream_id=4 parsed path=/file2.bin
io: http09 stream_id=4 opened (size=3145728)

io: STREAM frame parsed: stream_id=8 offset=0 data_len=17 fin=true
io: handleHttp09Stream called: stream_id=8 data_len=17
io: http09 stream_id=8 parsed path=/file3.bin
io: http09 stream_id=8 opened (size=5242880)

io: http09 stream_id=0 chunk: bytes=1200 offset=0 fin=false frame_len=1217
io: http09 stream_id=0 chunk: bytes=1200 offset=1200 fin=false frame_len=1217
... (many more chunks)
io: http09 stream_id=0 chunk: bytes=XXXX offset=X fin=true frame_len=XXXX
io: http09 stream_id=0 complete
```

## Common Issues & Diagnostics

### Issue: No "handleHttp09Stream called" messages
**Possible causes:**
1. STREAM frames not being parsed (see "STREAM frame parse error")
2. Frame type byte not matching 0x08-0x0f
3. processAppFrames not being reached

**Next steps:**
- Add logging to processAppFrames loop iteration
- Verify client is actually sending packets

### Issue: "handleHttp09Stream called" but "parse error: Incomplete"
**Cause:** GET request spans multiple STREAM frames
**Fix:** Handle multiframe requests - not currently supported

### Issue: "parse error: NotAGetRequest" or other parse errors
**Cause:** Client not sending proper HTTP/0.9 format
**Check:** Verify buildRequest in http09/client.zig creates "GET <path>\r\n"

### Issue: "file not found" errors
**Cause:** Server www directory doesn't have test files
**Check:** Test files are generated in /tmp/server_www_* during interop run

### Issue: "build1RttPacketFull error" or "sendto error"
**Cause:** Network/packet building issues
**Check:** Frame/packet size calculations, encrypt key availability

## Key Metric: The 2-Second Poll

**Problem log line:**
```
io: server waiting (2s idle, sock=3)
```

This repeating message means poll_timeout_ms >= 2000, which only happens when **no HTTP/0.9 slots are active**.

**If you see this message:**
- It means `flushPendingHttp09Responses` isn't finding any active slots
- The slots were never opened (no "opened (size=X)" messages before this)
- OR slots were opened but immediately closed due to errors

**Diagnostic:** Search logs for "opened (size=" - if you don't find any, slots never opened.

## Stack Overview for Reference

```
Server.run()  [polls & receives packets]
├── process1RttPacket()  [decrypts 1-RTT payload]
│   └── processAppFrames()  [parses frames]
│       └── handleStreamData()  [dispatches to protocol handler]
│           └── handleHttp09Stream()  [opens response slots]  ← PRIMARY FOCUS
│               ├── parseRequest()  [parse "GET /path\r\n"]
│               ├── resolvePath()  [validate path]
│               └── Opens Http09OutSlot
│
├── flushPendingHttp09Responses()  [sends file chunks]
│   └── http09SendNextChunk()
│       ├── file.read()  [read 1200 bytes from file]
│       ├── StreamFrame.serialize()  [create frame]
│       └── send1Rtt()  [encrypt & send packet]  ← SECONDARY FOCUS
│           ├── build1RttPacketFull()  [create QUIC packet]
│           └── sendto()  [send UDP datagram]
```

## Quick Win Checks

Before diving deep, verify these simple things:
1. ✓ Client is sending GET requests (not other methods)
2. ✓ Stream IDs are 0, 4, 8 (not 1, 2, 3, etc.)
3. ✓ Requests include "\r\n" terminator
4. ✓ Server has -Dhttp09=true config flag
5. ✓ www_dir is set to a directory with test files

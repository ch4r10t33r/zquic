# QUIC interop `transfer` — stack follow-up (context)

This note captures findings from a **local quic-interop-runner** run where **`handshake` succeeded** but **`transfer`** (three parallel HTTP/0.9 downloads, multi‑MB files) **hit the 60s timeout**. Use it as implementation context; it is not a spec.

## Symptom recap

- Server logs showed **short 1-RTT packets** from the client (typical of GET requests), then **`io: server waiting (Ns idle, …)`** with **2s poll intervals**.
- In `Server.run`, **2s idle** implies **`poll_timeout_ms == 2000`**, i.e. the loop did **not** see any **`http09_slots` with `active == true`** at the start of that iteration.
- So either **no slots stayed open**, or **work was considered finished on the server** while the **client never completed** all downloads.

Relevant code: `src/transport/io.zig` (`Server.run`, `flushPendingHttp09Responses`, `handleHttp09Stream`, `http09SendNextChunk`, `send1Rtt`; client `downloadUrls`, `process1RttPacket`, `handleStreamResponse`).

---

## 1. Confirm why HTTP/0.9 slots go inactive

Possible causes:

- **`handleHttp09Stream` never leaves slots active**: early `return` (parse/path/file open), or **`http/0.9 out slots full`**.
- **Slots open then close immediately** without the client getting a complete transfer:
  - **`http09SendNextChunk`**: `serialize` failure (fixed **2048**-byte frame buffer vs ~**1200**-byte file reads plus STREAM framing), **`read` error**, or **`send1Rtt` / `build1RttPacketFull` failure** (`catch` paths that **`slot.close()`**).

**Suggested work:** Short-lived, high-signal logging (or temporary asserts) around: slot open (**stream id**, path), first successful send per stream, **`serialize` / `read` / `sendto` errors**, slot close. Optionally correlate with **SSLKEYLOGFILE** + PCAP.

---

## 2. Client receive path for large / parallel responses

The client exits when **`streams_done >= urls.len`**, driven by **`processPacket` → `process1RttPacket` → STREAM handling**. Silent **`catch return`** on decrypt, header protection peek, or **unknown frame** types can stall progress without **`download complete`** logs.

**Suggested work:** Verify **1-RTT decrypt and key phase** over a long run of server packets; **STREAM handling** for **non-zero offsets** and ordering if the server splits bodies across many frames; **stream id alignment** with **`downloadUrls`** (**0, 4, 8, …**).

---

## 3. Real QUIC send-side flow control

Transport parameters in `src/crypto/quic_tls.zig` advertise large windows, but **`io.zig` send paths** do not obviously **enforce peer MAX_DATA / MAX_STREAM_DATA** (or buffer when credit is exhausted). Peers that enforce limits strictly may cause stalls or violations.

**Suggested work:** Track **connection- and stream-level send credit** from peer frames; block or queue sends when exhausted; emit **MAX_DATA / MAX_STREAM_DATA** on the receive side as data is consumed—prefer wiring **`transport/flow_control.zig`** / **`stream_manager.zig`** instead of only skipping control frames in **`processAppFrames`**.

---

## 4. Scheduling / fairness across multiple `http09_slots`

`flushPendingHttp09Responses` uses a **global per-call budget** (e.g. 256 chunks) over all connections and slots. Several **multi‑MB** streams under **delay/bandwidth simulation** can look like **starvation** or **slow tail** relative to the runner timeout.

**Suggested work:** After correctness is proven, tune **round-robin / byte budget** or **flush until no progress** (within bounds) so parallel **`transfer`** finishes reliably under the interop scenario.

---

## 5. Loss, ACK, and recovery

If the network simulator **drops** packets, behavior depends on **ACK handling**, **retransmission**, and **PTO/RTO**. Worth validating once the happy path is solid.

---

## 6. Local interop hygiene (environment, not stack)

### Python / quic-interop-runner (not on PyPI)

**Do not** run `pip install quic-interop-runner` — there is **no such package** on PyPI.

```sh
git clone https://github.com/quic-interop/quic-interop-runner.git
cd quic-interop-runner
pip3 install -r requirements.txt   # or: python3 -m pip install -r requirements.txt
```

Then run tests from that directory with `python3 run.py ...` (see upstream README).

### macOS + Docker image

For **macOS** + **`Dockerfile.prebuilt`**:

- Binaries in **`zig-out/bin/`** must be **Linux ELF** inside the image, not **Mach-O**. Example:  
  `zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-gnu` (Apple Silicon) or **`-Dtarget=x86_64-linux-gnu`** (Intel).
- **`quic-interop-runner`** requires **`--log-dir`** to point at a path that **does not exist** yet (it refuses an existing directory).
- **`docker network prune`** may be needed if Docker reports **subnet pool overlap** when creating **`leftnet` / `rightnet`**.

---

## Suggested order of work

1. **Instrument** slot lifecycle + send errors + client decrypt/frame drops on the failing **`transfer`** case.  
2. **Fix** the first concrete bug found (often buffer/size, early return, or silent send failure).  
3. **Add** send-side flow control if the peer or spec demands it.  
4. **Tune** flush scheduling and then **loss/recovery** as needed.

---

## Related fixes already landed (context)

- **ACK-before-CRYPTO** in coalesced **Initial** / **Handshake** packets: use **`skipAckBody`** and **`continue`** so following **CRYPTO** (e.g. Finished) is not skipped (`src/transport/io.zig`).

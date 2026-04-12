# zquic

A pure-Zig implementation of the QUIC transport protocol (RFC 9000 / 9001 / 9002) with full HTTP/3 and QPACK support.

[![CI](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml)

## Protocol Coverage

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | ✅ Complete |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | ✅ Complete |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | ✅ Complete |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | ✅ Complete |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK: Header Compression for HTTP/3 | ✅ Complete |
| [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | QUIC Version 2 | ✅ Complete |

### Frame support

| Frame | Type | Status |
|-------|------|--------|
| PADDING / PING | 0x00–0x01 | ✅ |
| ACK / ACK-ECN | 0x02–0x03 | ✅ |
| RESET_STREAM | 0x04 | ✅ |
| STOP_SENDING | 0x05 | ✅ |
| CRYPTO | 0x06 | ✅ |
| NEW_TOKEN | 0x07 | ✅ |
| STREAM | 0x08–0x0f | ✅ |
| MAX_DATA | 0x10 | ✅ |
| MAX_STREAM_DATA | 0x11 | ✅ |
| MAX_STREAMS (bidi/uni) | 0x12–0x13 | ✅ |
| DATA_BLOCKED | 0x14 | ✅ |
| STREAM_DATA_BLOCKED | 0x15 | ✅ |
| STREAMS_BLOCKED | 0x16–0x17 | ✅ |
| NEW_CONNECTION_ID | 0x18 | ✅ |
| RETIRE_CONNECTION_ID | 0x19 | ✅ |
| PATH_CHALLENGE / PATH_RESPONSE | 0x1a–0x1b | ✅ |
| CONNECTION_CLOSE (transport/app) | 0x1c–0x1d | ✅ |
| HANDSHAKE_DONE | 0x1e | ✅ |

## Interop Results

All 13/13 [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) test cases pass:

| Test | Status |
|------|--------|
| `handshake` | ✅ |
| `transfer` | ✅ |
| `retry` | ✅ |
| `chacha20` | ✅ |
| `keyupdate` | ✅ |
| `resumption` | ✅ |
| `zerortt` | ✅ |
| `http3` | ✅ |
| `connectionmigration` | ✅ |
| `multiplexing` | ✅ |
| `v2` | ✅ |
| `ecn` | ✅ |
| `rebind-port` | ✅ |

## Performance

Loopback throughput benchmark on Apple Silicon (M-series Mac), comparing zquic
against [quiche](https://github.com/cloudflare/quiche) (Cloudflare, Rust/BoringSSL) and
[ngtcp2](https://github.com/ngtcp2/ngtcp2) (C/quictls). All built with release
optimizations; steady-state averages (runs 3–5), 5 runs per data point.

| Transfer | zquic | quiche | ngtcp2 | Notes |
|----------|------:|-------:|-------:|-------|
| 1 MB | **335 Mbps** | 229 Mbps | 206 Mbps | zquic leads: fast handshake + protocol efficiency |
| 10 MB | **1,134 Mbps** | 957 Mbps | 1,007 Mbps | zquic leads all three at medium transfers |
| 50 MB | 2,113 Mbps | 1,779 Mbps | **2,750 Mbps** | zquic beats quiche; ngtcp2 leads with quictls |
| 100 MB | 2,352 Mbps | 1,871 Mbps | **2,668 Mbps** | zquic sustains 2.4 Gbps, beating quiche by 26% |

**Key takeaways:**
- zquic **beats quiche at every transfer size** thanks to cached AES key schedules, higher per-flush packet budgets, larger per-packet payloads, and batched client receives.
- At 100 MB bulk transfers, zquic reaches **2.4 Gbps** — within 12% of ngtcp2's hand-optimized C/quictls stack.
- ngtcp2 leads at large transfers where quictls's assembly-optimized AES-GCM dominates.

Reproduce with:
```sh
# Quick self-benchmark
zig build bench-e2e -Doptimize=ReleaseFast -- --size-mb 50

# Two-way comparative benchmark (requires Rust toolchain for quiche)
bash bench/local_compare.sh zquic quiche

# Three-way benchmark (also requires cmake + libev for ngtcp2)
SIZE_MB=100 RUNS=5 bash bench/local_compare.sh zquic quiche ngtcp2
```

## Requirements

- Zig **0.15.x**

## Building

```sh
zig build               # build library + server/client binaries
zig build test          # run all 141 unit tests
zig build examples      # build the example programs
```

## Examples

```sh
zig build examples
./zig-out/bin/echo_server        # crypto primitives walkthrough
./zig-out/bin/parse_packet       # parse a QUIC Initial packet header
./zig-out/bin/session_resumption # session tickets and 0-RTT key derivation
```

### Derive Initial secrets (RFC 9001 §5.2)

```zig
const zquic = @import("zquic");
const crypto_keys = zquic.crypto.keys;
const types = zquic.types;

const dcid = try types.ConnectionId.fromSlice(&[_]u8{
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
});
const secrets = crypto_keys.InitialSecrets.derive(dcid.slice());
// secrets.client.key  — AES-128-GCM write key
// secrets.client.iv   — AEAD base IV
// secrets.client.hp   — header protection key
```

### Encode / decode a variable-length integer (RFC 9000 §16)

```zig
const varint = zquic.varint;

var buf: [8]u8 = undefined;
const encoded = try varint.encode(&buf, 15293); // → 2 bytes: 0x7b 0xbd
const decoded = try varint.decode(encoded);
// decoded.value == 15293
```

### Parse a Long Header packet

```zig
const header_mod = zquic.packet.header;

const result = try header_mod.parseLong(raw_bytes);
// result.header.packet_type  — .initial / .handshake / .zero_rtt / .retry
// result.header.dcid         — ConnectionId
// result.header.version      — u32
// result.consumed            — bytes consumed
```

### AES-128-GCM encrypt / decrypt

```zig
const aead_mod = zquic.crypto.aead;

var ciphertext: [plaintext.len + 16]u8 = undefined;
try aead_mod.encryptAes128Gcm(&ciphertext, plaintext, aad, key, nonce);

var recovered: [plaintext.len]u8 = undefined;
try aead_mod.decryptAes128Gcm(&recovered, &ciphertext, aad, key, nonce);
```

### Session tickets and 0-RTT

```zig
const session = zquic.crypto.session;

var store = session.TicketStore{};
store.store(ticket);

if (store.get(now_ms)) |t| {
    const keys = session.deriveEarlyKeys(t);
    // keys.key / keys.iv / keys.hp  — ready for 0-RTT AEAD
}
```

### HTTP/3 framing

```zig
const h3 = zquic.http3.frame;

var buf: [256]u8 = undefined;
const written = try h3.writeFrame(&buf, @intFromEnum(h3.FrameType.headers), encoded_header_block);

const result = try h3.parseFrame(buf[0..written]);
// result.frame.headers.data / result.frame.data / result.frame.settings …
```

## Module Map

```
src/
  varint.zig              Variable-length integer codec (RFC 9000 §16)
  types.zig               ConnectionId, StreamId, TransportError, …
  packet/
    header.zig            Long/Short header parse + serialize
    number.zig            Packet number encode/decode (RFC 9000 §A.3)
    packet.zig            Initial, Retry, Version Negotiation builders
    retry.zig             Retry integrity tag (RFC 9001 §5.8)
    version_negotiation.zig  Version Negotiation parse/build
  crypto/
    keys.zig              HKDF-Expand-Label, Initial secret derivation, key update
    aead.zig              AES-128-GCM + ChaCha20-Poly1305, header protection
    initial.zig           Initial packet protect/unprotect helpers
    quic_tls.zig          QUIC-TLS adapter (nonblock ↔ CRYPTO frames)
    session.zig           Session tickets, PSK store, 0-RTT key derivation
    key_update.zig        Key update (RFC 9001 §6), KeyPhaseState
  frames/
    frame.zig             Frame union + parseOne dispatcher
    ack.zig               ACK frame with ECN
    crypto_frame.zig      CRYPTO frame
    stream.zig            STREAM frame
    transport.zig         RESET_STREAM, STOP_SENDING, MAX_DATA, PATH_CHALLENGE, …
  transport/
    io.zig                UDP event loop: server + client, HTTP/0.9 + HTTP/3 I/O
    connection.zig        Connection state machine + ACK manager
    endpoint.zig          UDP socket dispatch
    stream_manager.zig    Stream multiplexing + in-order receive buffer
    flow_control.zig      Connection + stream flow control
    migration.zig         Path validation, connection migration (RFC 9000 §9)
  loss/
    recovery.zig          RTT estimation (SRTT/RTTVAR), PTO, packet-threshold loss detection
    congestion.zig        New Reno congestion control (cwnd, ssthresh, slow start / CA / recovery)
  http09/
    server.zig            HTTP/0.9 request parser + path resolver
    client.zig            HTTP/0.9 request builder + download path helper
  http3/
    frame.zig             HTTP/3 frame codec (RFC 9114 §7)
    qpack.zig             QPACK: static table, dynamic table (RFC 9204)
  cmd/
    server.zig            QUIC server binary
    client.zig            QUIC client binary
vendor/tls/               ianic/tls.zig @ 34248f38c189 (Zig 0.15 compatible)
interop/
  Dockerfile              Self-contained local build
  Dockerfile.prebuilt     CI-optimised image from pre-built binaries
  run_endpoint.sh         quic-interop-runner entry point
examples/
  echo_server.zig         Crypto primitives walkthrough
  parse_packet.zig        Parse a QUIC Initial packet
  session_resumption.zig  Session tickets and 0-RTT
```

## TLS Integration

QUIC uses TLS 1.3 without the TLS record layer (RFC 9001). A thin adapter in
`src/crypto/quic_tls.zig` strips/adds the 5-byte TLS record header so raw
handshake bytes flow through QUIC CRYPTO frames. The vendored
[ianic/tls.zig](https://github.com/ianic/tls.zig) `nonblock` API is used.

## Releases

See [CHANGELOG.md](CHANGELOG.md) for version history. Releases are published
automatically on `v*` tags via `.github/workflows/release.yml`.

## License

MIT

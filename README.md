# zquic

A pure Zig implementation of the QUIC transport protocol (RFC 9000 / 9001 / 9002).

[![CI](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4r10t33r/zquic/actions/workflows/ci.yml)

## Protocol Coverage

| RFC | Title | Status |
|-----|-------|--------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | core modules complete |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | keys, AEAD, header protection, adapter |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | RTT, PTO, New Reno |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | framing complete |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK: Header Compression for HTTP/3 | literal encoding (no dynamic table yet) |

## Requirements

- Zig **0.15.x**

## Building

```sh
zig build               # build library + server/client binaries
zig build test          # run all 97 unit tests
zig build examples      # build the example programs
```

## Examples

Three self-contained examples live in `examples/`. Build and run them with:

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

// Store a ticket received from the server.
var store = session.TicketStore{};
store.store(ticket);

// On the next connection, retrieve and derive 0-RTT keys.
if (store.get(now_ms)) |t| {
    const keys = session.deriveEarlyKeys(t);
    // keys.key / keys.iv / keys.hp  — ready for 0-RTT AEAD
}
```

### HTTP/3 framing

```zig
const h3 = zquic.http3.frame;

// Write a HEADERS frame.
var buf: [256]u8 = undefined;
const written = try h3.writeFrame(&buf, @intFromEnum(h3.FrameType.headers), encoded_header_block);

// Parse any frame.
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
    keys.zig              HKDF-Expand-Label, Initial secret derivation
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
    transport.zig         RESET_STREAM, MAX_DATA, PATH_CHALLENGE, …
  transport/
    connection.zig        Connection state machine + ACK manager
    endpoint.zig          UDP socket dispatch
    stream_manager.zig    Stream multiplexing + in-order receive buffer
    flow_control.zig      Connection + stream flow control
    migration.zig         Path validation, connection migration (RFC 9000 §9)
  loss/
    recovery.zig          RTT estimation, PTO, loss detection (RFC 9002)
    congestion.zig        New Reno congestion control
  http09/
    server.zig            HTTP/0.9 request parser + path resolver
    client.zig            HTTP/0.9 request builder + download path helper
  http3/
    frame.zig             HTTP/3 frame codec (RFC 9114 §7)
    qpack.zig             QPACK static table + literal header encode/decode
  cmd/
    server.zig            QUIC server binary (interop runner entry point)
    client.zig            QUIC client binary (interop runner entry point)
vendor/tls/               ianic/tls.zig @ 34248f38c189 (Zig 0.15 compatible)
interop/
  Dockerfile              Self-contained local build (downloads Zig at build time)
  Dockerfile.prebuilt     CI-optimised image from pre-built binaries
  run_endpoint.sh         quic-interop-runner entry point
examples/
  echo_server.zig         Crypto primitives walkthrough
  parse_packet.zig        Parse a QUIC Initial packet
  session_resumption.zig  Session tickets and 0-RTT
```

## TLS Integration

QUIC uses TLS 1.3 without the TLS record layer (RFC 9001). A thin adapter
in `src/crypto/quic_tls.zig` strips/adds the 5-byte TLS record header so
raw handshake bytes flow through QUIC CRYPTO frames. The vendored
[ianic/tls.zig](https://github.com/ianic/tls.zig) `nonblock` API is used.

## Pending / In Progress

| Area | What's missing |
|------|---------------|
| **UDP I/O loop** | `src/cmd/server.zig` and `client.zig` parse flags correctly but the actual send/recv loop (wiring `Endpoint` to a real UDP socket) is not yet written |
| **Full TLS handshake** | `quic_tls.Endpoint` drives the `nonblock` API but the integration path from `Connection` → `Endpoint` → OS socket is not wired end-to-end |
| **SSLKEYLOGFILE** | TLS session key export for Wireshark is not yet implemented |
| **qlog** | Structured QUIC event logging to `$QLOGDIR` is not yet written |
| **ALPN negotiation** | `h3` / `hq-interop` ALPN selection is planned but not wired |
| **QUIC v2** | RFC 9369 (version 0x6b3343cf) — interop runner test case `v2` exits 127 |
| **ChaCha20 interop** | `chacha20` test case: cipher suite negotiation not yet wired |
| **QPACK dynamic table** | `decodeHeaders` rejects indexed field lines; dynamic table capacity is 0 |
| **Connection migration I/O** | `MigrationManager` state machine is complete; OS-level socket rebind is not |

## QUIC Interop Runner

This implementation targets the [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
full test suite. The Docker image is built on every merge to `master`.

| Test case | Status |
|-----------|--------|
| `handshake` | 🔧 framework ready, UDP I/O pending |
| `transfer` | 🔧 HTTP/0.9 helpers ready, I/O pending |
| `retry` | 🔧 Retry integrity tag complete, server trigger pending |
| `resumption` | 🔧 ticket store + PSK ready, handshake wire-up pending |
| `zerortt` | 🔧 0-RTT keys derivable, early data sending pending |
| `http3` | 🔧 framing + QPACK ready, I/O pending |
| `keyupdate` | 🔧 `KeyPhaseState` complete, trigger pending |
| `connectionmigration` | 🔧 `MigrationManager` complete, socket rebind pending |
| `multiconnect` | 🔧 connection manager ready, I/O pending |
| `chacha20` | ⏳ cipher suite negotiation not wired |
| `v2` | ❌ not supported (exits 127) |

## License

MIT

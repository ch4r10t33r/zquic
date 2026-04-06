# zquic

A pure Zig implementation of the QUIC transport protocol.

## Protocol Coverage

| RFC | Title |
|-----|-------|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK: Header Compression for HTTP/3 |

## Requirements

- Zig 0.15.x

## Building

```sh
zig build          # build library + binaries
zig build test     # run unit tests
```

## Design

```
src/
  varint.zig          Variable-length integer codec (RFC 9000 §16)
  types.zig           Core types: ConnectionId, StreamId, TransportError, …
  packet/             Packet header parsing and serialization
  crypto/             Key derivation, AEAD, header protection, TLS adapter
  frames/             All QUIC frame types
  transport/          Connection state machine, endpoint, streams, flow control
  loss/               Loss detection and congestion control (RFC 9002)
  http09/             HTTP/0.9 for interop tests
  http3/              HTTP/3 framing and QPACK
  cmd/                server and client binaries for interop runner
vendor/tls/           tls.zig vendored @ 34248f38c189 (Zig 0.15 compatible)
interop/              Docker image and run_endpoint.sh for quic-interop-runner
```

## TLS Integration

QUIC uses TLS 1.3 in a non-standard way: the TLS record layer is replaced by
QUIC's own packet protection (RFC 9001). The library vendors
[tls.zig](https://github.com/ianic/tls.zig) at a Zig 0.15-compatible commit
and uses its `nonblock` API. A thin adapter strips/adds TLS record headers
so that raw handshake bytes flow through QUIC CRYPTO frames.

## QUIC Interop Runner

This implementation targets the full [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
test suite:

`handshake`, `transfer`, `chacha20`, `keyupdate`, `retry`, `resumption`,
`zerortt`, `http3`, `multiconnect`, `v2`, `rebind-port`, `rebind-addr`,
`connectionmigration`

## License

MIT

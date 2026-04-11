# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [v0.1.0] - 2026-04-11

### Added

#### Protocol coverage
- **RFC 9000** — QUIC transport: connection establishment, packet processing,
  stream multiplexing, flow control, connection migration, path validation
- **RFC 9001** — QUIC-TLS: Initial/Handshake/1-RTT encryption, header protection,
  key updates (client-initiated and server-initiated), session tickets, 0-RTT
- **RFC 9002** — Loss detection and congestion control: New Reno (cwnd, ssthresh,
  slow start / congestion avoidance / recovery states), RTT estimation (SRTT,
  RTTVAR, PTO), packet-threshold loss detection — all wired into the event loop
- **RFC 9114** — HTTP/3: framing (DATA, HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE,
  CANCEL_PUSH, MAX_PUSH_ID), control streams, trailing HEADERS, GOAWAY on shutdown
- **RFC 9204** — QPACK: static table, dynamic table insertions, encoder/decoder
  streams, Section Acknowledgements, blocked streams
- **RFC 9369** — QUIC v2: initial secrets, packet type bits, Retry integrity tag

#### Frame handling
- RESET_STREAM (0x04) and STOP_SENDING (0x05) — stream cancellation
- CONNECTION_CLOSE (0x1c/0x1d) with draining period (3 × PTO, RFC 9000 §10.2.2)
- RETIRE_CONNECTION_ID (0x19) — CID lifecycle management with fresh CID issuance
- STREAMS_BLOCKED (0x16/0x17) — responds with MAX_STREAMS
- MAX_DATA, MAX_STREAM_DATA, DATA_BLOCKED, STREAM_DATA_BLOCKED — flow control
- PATH_CHALLENGE / PATH_RESPONSE — path validation and connection migration
- NEW_CONNECTION_ID — alternative CIDs for migration
- ECN (ACK-ECN frames, ECT(0) marking on all outgoing packets)

#### Infrastructure
- Idle timeout: connections idle for >30 s are silently closed (RFC 9000 §10.1)
- Congestion controller and RTT estimator reset on path migration (RFC 9002 §9.4)
- Release CI workflow (`.github/workflows/release.yml`) triggered on `v*` tags:
  runs tests + fmt check, builds linux/amd64 binaries, creates GitHub Release
- QLog writer for structured connection traces
- Stateless Reset token generation and detection

#### Interop
- All 13 QUIC interop runner test cases passing:
  `handshake`, `transfer`, `retry`, `chacha20`, `keyupdate`, `v2`, `ecn`,
  `resumption`, `http3`, `zerortt`, `connectionmigration`, `multiplexing`,
  `rebind-port`

### Known limitations
- 0-RTT anti-replay: no server-side nonce cache (safe for idempotent file serving;
  see issue #75 for the roadmap item)
- Connection-level stream limits are advertised but not enforced on the receive side

---

[Unreleased]: https://github.com/ch4r10t33r/zquic/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/ch4r10t33r/zquic/releases/tag/v0.1.0

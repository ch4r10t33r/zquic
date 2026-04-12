# Embedding zquic (non-HTTP QUIC applications)

The `transport.io` server and client are still oriented around the quic-interop-runner
HTTP/0.9 and HTTP/3 paths. The following pieces exist so other protocols can reuse the
same TLS 1.3 + QUIC stack:

## Custom ALPN

- `ServerConfig.alpn` and `ClientConfig.alpn`: when set, this exact string is sent in the
  TLS handshake (single protocol). It takes precedence over `http3` / `http09`.
- `serverTlsAlpn(&ServerConfig)` and `clientTlsAlpn(&ClientConfig)` return the effective
  ALPN slice used for the handshake (including the HTTP defaults when `alpn` is null).

## Raw application STREAM data

When `raw_application_streams` is true on **both** `ServerConfig` and `ClientConfig`:

- Incoming STREAM frames are appended to per-stream buffers (`RawAppStreamSlot`) as opaque
  bytes. No HTTP/0.9 or HTTP/3 parsing is performed.
- Data is merged using the same contiguous-offset rules as the HTTP/3 download path
  (duplicates and gaps are handled conservatively).

This is intended for embedders that will drive their own framing on top of QUIC streams.

## Not covered yet (follow-up work)

- A dedicated poll/endpoint API for external UDP sockets (`feedPacket` / shared sockets).
- Helpers to **open** locally initiated uni/bidi streams with arbitrary application data
  (the interop client still uses HTTP request generators for outbound streams).
- Publishing read buffers to embedders without copying (today data lives in
  `ArrayListUnmanaged` inside `ConnState` / `Client`).

Dependents can import the library module as `zquic` after adding a `build.zig.zon`
dependency; the module re-exports `vendor/tls` as `tls` for the zquic package.

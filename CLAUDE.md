# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

- `cargo build` — build the `mitmproxy` library.
- `cargo run --example dumper -- --help` — show the demo example CLI options.
- `cargo run --example dumper -- --bind 127.0.0.1:8080` — start the demo HTTP proxy on `127.0.0.1:8080`.
- `cargo run --example dumper -- --mode socks5 --bind 127.0.0.1:1080` — start the demo in SOCKS5 mode on `127.0.0.1:1080`.
- `RUST_LOG=debug cargo run --example dumper -- --bind 127.0.0.1:8080` — run the demo with connection/protocol logs.
- `cargo test` — run unit tests and doc tests.
- `cargo test <pattern>` — run tests matching a name.
- `cargo test <exact_name> -- --exact --nocapture` — run a single exact test and show output.
- `cargo test -- --list` — list all test names.
- `cargo fmt --all` — format the codebase.
- `cargo fmt --all -- --check` — check formatting without changing files.
- `cargo clippy --all-targets --all-features` — run linting.

## Manual verification

- HTTP proxy path: start the proxy with `cargo run --example dumper -- --bind 127.0.0.1:8080`, then run `curl -x http://127.0.0.1:8080 http://httpbin.org/get`
- HTTPS MITM path: start the proxy with a stable CA via `cargo run --example dumper -- --bind 127.0.0.1:8080 --ca-cert ca.crt --ca-key ca.key`, then run `curl --cacert ca.crt -x http://127.0.0.1:8080 https://httpbin.org/get`
- HTTP/2 path: with the same CA-backed startup command, run `curl --cacert ca.crt --http2 -x http://127.0.0.1:8080 https://httpbin.org/get -v`
- SOCKS5 mode: start the proxy with `cargo run --example dumper -- --mode socks5 --bind 127.0.0.1:1080`, then run `curl --socks5 127.0.0.1:1080 http://httpbin.org/get`
- HTTPS/WSS interception requires the client to trust the CA certificate. If `--ca-cert/--ca-key` are not supplied, startup generates a temporary CA, so the client trust step must be repeated after each run.

## Architecture overview

- This repository is a Rust library crate plus a demo example. `Cargo.toml` defines the package as `mitmproxy-rs`, and the exported library crate name is `mitmproxy`; downstream code imports `mitmproxy`, not `mitmproxy-rs`.
- `src/lib.rs` is the public API surface. It re-exports the config types, `ProxyServer`, `TlsInterceptor`, `CaBuilder`, `ProxyError`, and the interception API. One body type is exported: `StreamBody = BoxBody<Bytes, BoxError>` (streaming, used by all interceptor hooks).
- `src/examples/dumper.rs` is the demo entrypoint (run via `cargo run --example dumper`). It installs the rustls ring crypto provider, initializes tracing, parses CLI flags such as `--bind`, `--mode`, upstream proxy settings, and optional CA paths, then runs a logging interceptor with hexdump output for body chunks.
- `src/server.rs` owns the accept loop. Each accepted TCP connection gets its own `UpstreamConnector`, then dispatches to either `HttpHandler` or `Socks5Handler` based on `ProxyConfig.mode`. Connection failures are isolated to the spawned task; the listener keeps accepting new connections.
- `src/config.rs` holds the runtime configuration model: proxy mode (`Http` vs `Socks5`), optional chained upstream proxy, optional CA material, upstream TLS verification toggle, HTTP/2 toggle, and the certificate cache size.
- `src/interceptor.rs` defines the user extension point. Custom interceptors must implement `intercept_request_streaming` and `intercept_response_streaming` (streaming). Two additional methods have default passthrough implementations: `intercept_ws_client_frame` and `intercept_ws_server_frame`. `PassthroughInterceptor` is the built-in no-op implementation.
- `src/handler/http.rs` contains most of the protocol machinery. It handles plain HTTP proxy requests, HTTPS `CONNECT`, TLS termination, HTTP/1.1 forwarding, HTTP/2 forwarding, h2c prior-knowledge, and WebSocket/h2c upgrade relay. All logic stays in this single file.
- All HTTP paths use streaming bodies end-to-end via `intercept_request_streaming`/`intercept_response_streaming`. WebSocket and h2c upgrade negotiation paths buffer the request body internally before calling the streaming interceptor, because upgrade negotiation requires the full request before the connection switches protocols.
- Connection lifetime is managed with `AbortOnDrop(tokio::task::AbortHandle)`: the upstream connection task is aborted when no longer referenced. For responses that stream a body back to the client, the guard is embedded in the body stream itself via `stream_body_with_guard`, keeping the connection alive until the last byte is sent.
- Protocol sniffing (`sniff_cleartext_protocol`) reads up to 24 bytes to distinguish TLS (first byte `0x16`), H2 prior knowledge (full HTTP/2 connection preface), and plain HTTP/1.1. The peeked bytes are replayed via `PrependIo` so the real parser sees the complete stream.
- HTTPS interception works by acknowledging `CONNECT`, sniffing the protocol of the tunnelled stream, and routing TLS (`0x16` first byte) through `handle_tls_tunnel_with_upstream`. The proxy first completes the upstream TLS handshake to read the real server certificate's Subject Alternative Names, then generates a mirrored fake certificate (via `TlsInterceptor::get_or_create_cert_mirrored`) signed by the proxy CA, and finally accepts the client TLS handshake with that mirrored certificate.
- HTTP/2 support is negotiated independently on each side of the MITM. `serve_tls_tunnel` checks ALPN on the client-side TLS session and on the upstream TLS session separately, so client and upstream protocol versions can differ.
- WebSocket interception lives inside the HTTP/1.1 tunnel path. The proxy upgrades both sides, then relays frames through `intercept_ws_client_frame` and `intercept_ws_server_frame`.
- `src/handler/socks5.rs` implements the incoming SOCKS5 server. It supports only no-auth client connections, handles CONNECT requests, then peeks the first tunneled byte to decide between the TLS interception path and the plain HTTP tunnel path reused from `src/handler/http.rs`.
- `src/upstream.rs` handles outbound connectivity to the real target. It supports direct TCP/TLS connections, HTTP CONNECT upstream proxies, and SOCKS5 upstream proxies. Chained upstream SOCKS5 authentication is supported here, even though the inbound SOCKS5 server itself only accepts no-auth clients.
- `src/tls/interceptor.rs` owns certificate generation and caching. `ProxyServer::bind` generates a temporary CA when no CA is supplied, and `TlsInterceptor` signs leaf certificates on demand per hostname. The primary path is `get_or_create_cert_mirrored`, which mirrors the upstream certificate's SANs into the fake leaf cert. Generated server configs are cached in an LRU keyed by hostname. `TlsInterceptor::new_with_h2` and `from_ca_with_h2` let callers control whether `h2` is advertised in ALPN.
- `src/error.rs` defines `ProxyError`. Interceptor failures are converted into proxy-level errors; in practice HTTP failures return `502 Bad Gateway`, while WebSocket frame interception failures terminate the upgraded connection.

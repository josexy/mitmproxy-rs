# mitmproxy-rs

A Rust Man-In-The-Middle (MITM) proxy library for transparent interception and inspection of HTTP, HTTPS, HTTP/2, and WebSocket traffic.

## Features

- **Protocol support**
  - HTTP/1.1 plaintext proxy
  - HTTPS transparent TLS interception (dynamic certificate generation)
  - HTTP/2 (negotiated via ALPN)
  - WebSocket / WSS frame-level interception

- **Proxy modes**
  - HTTP/HTTPS CONNECT proxy
  - SOCKS5 proxy

- **Configuration**
  - Upstream proxy chaining (HTTP / SOCKS5, with authentication)
  - Custom CA certificate or auto-generated at startup
  - TLS certificate verification toggle (for test environments)
  - HTTP/2 can be disabled
  - LRU per-hostname certificate cache (default 1000 entries)

## Quick start

### Dependencies

```toml
[dependencies]
mitmproxy-rs = { path = "." }
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
hyper = "1"
http-body-util = "0.1"
```

### Minimal example

```rust
use async_trait::async_trait;
use hyper::{Request, Response};
use mitmproxy::{BoxError, Interceptor, ProxyConfig, ProxyServer, StreamBody};

struct LogInterceptor;

#[async_trait]
impl Interceptor for LogInterceptor {
    async fn intercept_request_streaming(
        &self,
        req: Request<StreamBody>,
    ) -> Result<Request<StreamBody>, BoxError> {
        println!("→ {} {}", req.method(), req.uri());
        Ok(req)
    }

    async fn intercept_response_streaming(
        &self,
        res: Response<StreamBody>,
    ) -> Result<Response<StreamBody>, BoxError> {
        println!("← {}", res.status());
        Ok(res)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ProxyConfig::default();
    let server = ProxyServer::bind("127.0.0.1:8080".parse()?, config, LogInterceptor).await?;
    server.run().await?;
    Ok(())
}
```

Test with curl after starting the proxy:

```bash
# HTTP
curl -x http://127.0.0.1:8080 http://httpbin.org/get

# HTTPS (requires trusting the CA certificate — see below)
curl --cacert ca.crt -x http://127.0.0.1:8080 https://httpbin.org/get
```

## Running the demo

```bash
# HTTP proxy on 127.0.0.1:8080
cargo run --example dumper -- --bind 127.0.0.1:8080

# SOCKS5 proxy on 127.0.0.1:1080
cargo run --example dumper -- --mode socks5 --bind 127.0.0.1:1080

# HTTPS MITM with a stable CA (client must trust ca.crt)
cargo run --example dumper -- --bind 127.0.0.1:8080 --ca-cert ca.crt --ca-key ca.key

# With debug logs
RUST_LOG=debug cargo run --example dumper -- --bind 127.0.0.1:8080
```

## Interceptor API

Implement the `Interceptor` trait to inspect or modify traffic:

| Method | Required | Description |
|---|---|---|
| `intercept_request_streaming` | yes | Intercept outbound requests (streaming body) |
| `intercept_response_streaming` | yes | Intercept inbound responses (streaming body) |
| `intercept_ws_client_frame` | no | Intercept WebSocket frames from client |
| `intercept_ws_server_frame` | no | Intercept WebSocket frames from server |

All interceptor methods use `StreamBody = BoxBody<Bytes, BoxError>` — bodies flow as chunks without full buffering. WebSocket and h2c upgrade paths buffer the request body internally before invoking the interceptor, since the upgrade handshake requires the complete request before the connection switches protocols.

Use `PassthroughInterceptor` as a no-op default.

## Project layout

```
src/
├── lib.rs              # Public API surface
├── config.rs           # ProxyConfig / ProxyMode / UpstreamProxy
├── interceptor.rs      # Interceptor trait (StreamBody / BoxError / WsFrame)
├── server.rs           # ProxyServer accept loop
├── handler/
│   ├── http.rs         # HTTP/HTTPS CONNECT, WebSocket, HTTP/2
│   └── socks5.rs       # SOCKS5 handshake and dispatch
├── tls/
│   ├── interceptor.rs  # Dynamic certificate generation + LRU cache
│   └── certs.rs        # CA / leaf certificate builders
├── upstream.rs         # UpstreamConnector (direct / HTTP / SOCKS5)
└── error.rs            # ProxyError
examples/
└── dumper.rs           # Demo: hexdump logging interceptor + CLI
```

## License

MIT

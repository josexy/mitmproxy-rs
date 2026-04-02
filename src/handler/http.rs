use bytes::Bytes;
use futures_util::{SinkExt, StreamExt, stream};
use http_body_util::{BodyExt, Full, StreamBody as HttpStreamBody, combinators::BoxBody};
use hyper::body::{Body, Incoming};
use hyper::ext::ReasonPhrase;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::SanType;
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Role;
use tracing::{debug, error};
use x509_parser::prelude::*;

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::interceptor::{BoxError, Interceptor, StreamBody, WsFrame};
use crate::tls::TlsInterceptor;
use crate::upstream::UpstreamConnector;

pub struct HttpHandler {
    config: Arc<ProxyConfig>,
    tls_interceptor: Arc<TlsInterceptor>,
    interceptor: Arc<dyn Interceptor>,
    upstream: Arc<UpstreamConnector>,
}

impl HttpHandler {
    pub fn new(
        config: Arc<ProxyConfig>,
        tls_interceptor: Arc<TlsInterceptor>,
        interceptor: Arc<dyn Interceptor>,
        upstream: Arc<UpstreamConnector>,
    ) -> Self {
        Self {
            config,
            tls_interceptor,
            interceptor,
            upstream,
        }
    }

    pub async fn handle(self: Arc<Self>, stream: TcpStream) {
        // Sniff the first bytes to detect h2c prior knowledge before handing
        // the connection to the hyper auto-builder. An h2c prior knowledge
        // client sends the HTTP/2 connection preface directly; we route it
        // through a dedicated h2c path so the upstream also speaks HTTP/2 and
        // streaming responses work correctly without buffering.
        let (proto, io) = match sniff_cleartext_protocol(stream).await {
            Ok(v) => v,
            Err(e) => {
                debug!("protocol sniff failed: {e}");
                return;
            }
        };

        if matches!(proto, CleartextProtocol::H2PriorKnowledge) {
            let handler = Arc::clone(&self);
            let client_io = TokioIo::new(io);
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                async move { handler.handle_h2c_request(req).await }
            });
            if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(client_io, svc)
                .await
            {
                debug!("h2c connection error: {e}");
            }
            return;
        }

        let io = TokioIo::new(io);
        let handler = Arc::clone(&self);

        let svc = service_fn(move |req: Request<Incoming>| {
            let handler = Arc::clone(&handler);
            async move { handler.dispatch(req).await }
        });

        let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
            debug!("HTTP connection error: {e}");
        }
    }

    async fn dispatch(
        &self,
        req: Request<Incoming>,
    ) -> std::result::Result<Response<StreamBody>, hyper::Error> {
        if req.method() == Method::CONNECT {
            match self.handle_connect(req).await {
                Ok(res) => Ok(full_body_response_to_stream(res)),
                Err(e) => {
                    error!("CONNECT error: {e}");
                    Ok(bad_gateway_stream())
                }
            }
        } else {
            match self.handle_plain_http(req).await {
                Ok(res) => Ok(res),
                Err(e) => {
                    error!("HTTP error: {e}");
                    Ok(bad_gateway_stream())
                }
            }
        }
    }

    async fn handle_connect(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let host_port = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .ok_or_else(|| ProxyError::Protocol("CONNECT missing host".into()))?;

        let (host, port) = parse_host_port(&host_port, 443)?;
        debug!("CONNECT {host}:{port}");
        let on_upgrade = hyper::upgrade::on(req);
        let config = Arc::clone(&self.config);
        let tls_interceptor = Arc::clone(&self.tls_interceptor);
        let interceptor = Arc::clone(&self.interceptor);
        let upstream = Arc::clone(&self.upstream);

        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(e) => {
                    error!("CONNECT upgrade failed for {host}:{port}: {e}");
                    return;
                }
            };

            let client_io = TokioIo::new(upgraded);
            if let Err(e) = serve_fixed_target_tunnel(
                client_io,
                &host,
                port,
                config.enable_h2(),
                tls_interceptor,
                interceptor,
                upstream,
            )
            .await
            {
                error!("CONNECT tunnel error: {e}");
            }
        });

        let mut res = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();
        res.extensions_mut()
            .insert(ReasonPhrase::from_static(b"Connection Established"));
        Ok(res)
    }

    async fn handle_plain_http(&self, mut req: Request<Incoming>) -> Result<Response<StreamBody>> {
        debug!("plain HTTP {} {}", req.method(), req.uri());
        let is_ws = is_websocket_upgrade(req.headers());
        let is_h2c_upgrade_req = is_h2c_upgrade(req.headers());
        let client_on = (is_ws || is_h2c_upgrade_req).then(|| hyper::upgrade::on(&mut req));

        let (parts, body) = req.into_parts();
        // Upgrade paths must buffer so the full request is available before the
        // protocol switch; normal paths stream directly without buffering.
        let stream_body = if is_ws || is_h2c_upgrade_req {
            let body_bytes = body.collect().await.map_err(ProxyError::Hyper)?.to_bytes();
            full_to_stream_body(Full::new(body_bytes))
        } else {
            incoming_to_stream_body(body)
        };
        let req = Request::from_parts(parts, stream_body);

        let req = self
            .interceptor
            .intercept_request_streaming(req)
            .await
            .map_err(ProxyError::Interceptor)?;

        let (host, port) = extract_upstream_target(&req, 80)?;
        let upstream_stream = self.upstream.connect(&host, port).await?;
        let io = TokioIo::new(upstream_stream);

        let (sender, conn) = hyper::client::conn::http1::handshake::<_, StreamBody>(io)
            .await
            .map_err(ProxyError::Hyper)?;
        let conn_guard = AbortOnDrop(tokio::spawn(conn.with_upgrades()).abort_handle());
        let sender = Arc::new(Mutex::new(sender));

        if is_ws {
            return forward_websocket_upgrade(
                req,
                client_on.unwrap(),
                Arc::clone(&sender),
                Arc::clone(&self.interceptor),
                conn_guard,
            )
            .await;
        }

        if is_h2c_upgrade_req {
            return forward_h2c_upgrade(
                req,
                client_on.unwrap(),
                Arc::clone(&sender),
                Arc::clone(&self.interceptor),
                conn_guard,
            )
            .await;
        }

        let res = sender
            .lock()
            .await
            .send_request(req)
            .await
            .map_err(ProxyError::Hyper)?;
        let (parts, body) = res.into_parts();
        let stream_body = stream_body_with_guard(incoming_to_stream_body(body), conn_guard);
        let res = Response::from_parts(parts, stream_body);

        self.interceptor
            .intercept_response_streaming(res)
            .await
            .map_err(ProxyError::Interceptor)
    }

    /// Handle an h2c prior-knowledge request (streaming response, no body buffering).
    async fn handle_h2c_request(
        &self,
        req: Request<Incoming>,
    ) -> std::result::Result<Response<StreamBody>, hyper::Error> {
        debug!("h2c [prior knowledge] {} {}", req.method(), req.uri());

        let (parts, body) = req.into_parts();
        let stream_body = incoming_to_stream_body(body);
        let req = Request::from_parts(parts, stream_body);

        let req = match self.interceptor.intercept_request_streaming(req).await {
            Ok(r) => r,
            Err(e) => {
                error!("h2c intercept_request error: {e}");
                return Ok(bad_gateway_stream());
            }
        };

        let (host, port) = match extract_upstream_target(&req, 80) {
            Ok(v) => v,
            Err(e) => {
                error!("h2c upstream target error: {e}");
                return Ok(bad_gateway_stream());
            }
        };

        let upstream_stream = match self.upstream.connect(&host, port).await {
            Ok(s) => s,
            Err(e) => {
                error!("h2c upstream connect error: {e}");
                return Ok(bad_gateway_stream());
            }
        };

        let io = TokioIo::new(upstream_stream);
        let (mut sender, conn) = match hyper::client::conn::http2::handshake::<_, _, StreamBody>(
            TokioExecutor::new(),
            io,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("h2c upstream handshake error: {e}");
                return Ok(bad_gateway_stream());
            }
        };
        let conn_guard = AbortOnDrop(tokio::spawn(conn).abort_handle());

        let res = match sender.send_request(req).await {
            Ok(r) => r,
            Err(e) => {
                error!("h2c upstream send error: {e}");
                return Ok(bad_gateway_stream());
            }
        };

        // Stream the response body directly to the client without buffering.
        // This is required for server-sent events and other long-lived streams.
        let (parts, body) = res.into_parts();
        let stream_body = stream_body_with_guard(incoming_to_stream_body(body), conn_guard);
        let res = Response::from_parts(parts, stream_body);

        match self.interceptor.intercept_response_streaming(res).await {
            Ok(r) => Ok(r),
            Err(e) => {
                error!("h2c intercept_response error: {e}");
                Ok(bad_gateway_stream())
            }
        }
    }
}

pub(crate) async fn serve_fixed_target_tunnel<IO>(
    client_io: IO,
    host: &str,
    port: u16,
    enable_h2: bool,
    tls_interceptor: Arc<TlsInterceptor>,
    interceptor: Arc<dyn Interceptor>,
    upstream: Arc<UpstreamConnector>,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let upstream_stream = upstream.connect(host, port).await?;
    serve_fixed_target_tunnel_with_upstream(
        client_io,
        host,
        port,
        enable_h2,
        tls_interceptor,
        interceptor,
        upstream,
        upstream_stream,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_fixed_target_tunnel_with_upstream<IO, U>(
    client_io: IO,
    host: &str,
    port: u16,
    enable_h2: bool,
    tls_interceptor: Arc<TlsInterceptor>,
    interceptor: Arc<dyn Interceptor>,
    upstream: Arc<UpstreamConnector>,
    upstream_stream: U,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match sniff_cleartext_protocol(client_io).await? {
        (CleartextProtocol::Tls, client_io) => {
            handle_tls_tunnel_with_upstream(
                client_io,
                host,
                tls_interceptor,
                interceptor,
                upstream,
                upstream_stream,
                enable_h2,
            )
            .await
        }
        (CleartextProtocol::H2PriorKnowledge, client_io) => {
            debug!("Plain HTTP/2 tunnel for {host}:{port}");
            serve_h2_inner(client_io, upstream_stream, interceptor, true).await
        }
        (CleartextProtocol::Http1, client_io) => {
            debug!("Plain HTTP tunnel for {host}:{port}");
            serve_http1_inner(client_io, upstream_stream, interceptor).await
        }
    }
}

/// 1. Parse SNI from client ClientHello (bytes already peeked into `client_io`).
/// 2. Complete the **upstream** TLS handshake first so we can inspect the real
///    server certificate and extract its Subject Alternative Names.
/// 3. Generate a fake leaf certificate that mirrors the upstream SANs, signed by
///    the proxy CA.  This makes the forged cert match exactly what the real server
///    would present (same DNS names, IP SANs, wildcards, etc.).
/// 4. Accept the **client** TLS handshake with the mirrored fake certificate.
/// 5. Hand both TLS streams to `serve_tls_tunnel` for HTTP/1.1 or HTTP/2 proxying.
///
/// Note: the upstream TLS connection is established without advertising h2 ALPN.
/// Any h2 client will be served via the existing h2→h1 translation path inside
/// `serve_h2_inner` / `AnyUpstreamSender`.
async fn handle_tls_tunnel_with_upstream<IO, U>(
    client_io: PrependIo<IO>,
    host: &str,
    tls_interceptor: Arc<TlsInterceptor>,
    interceptor: Arc<dyn Interceptor>,
    upstream: Arc<UpstreamConnector>,
    upstream_stream: U,
    enable_h2: bool,
) -> Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client_hello, client_io) = extract_client_hello_info(client_io).await?;
    let tls_host = select_tls_server_name(client_hello.sni, host);

    // Step 1: connect to upstream TLS, forwarding the client's ALPN preferences, cipher
    // suites, and supported TLS versions so that the upstream sees the same fingerprint as
    // the real client (mirrors Go behaviour: `NextProtos: chi.SupportedProtos` filtered by
    // disableHTTP2).
    let upstream_alpn = upstream_alpn_from_client(&client_hello.alpn, enable_h2);
    let connector = TlsConnector::from(upstream.tls_client_config_mimicking_client(
        upstream_alpn,
        &client_hello.cipher_suites,
        &client_hello.supported_versions,
    ));
    let server_name = tls_server_name(&tls_host)?;
    let tls_upstream = connector
        .connect(server_name, upstream_stream)
        .await
        .map_err(ProxyError::Io)?;

    // Step 2: extract SANs from the upstream leaf certificate.
    let upstream_sans =
        extract_upstream_sans(tls_upstream.get_ref().1.peer_certificates(), &tls_host);

    let negotiated_cipher_suite = tls_upstream.get_ref().1.negotiated_cipher_suite();
    let protocol_version = tls_upstream.get_ref().1.protocol_version();
    let alpn_protocol = tls_upstream.get_ref().1.alpn_protocol();

    debug!(
        "Upstream TLS handshake: negotiated_cipher_suite: {:?}, protocol_version: {:?}, alpn_protocol: {:?}",
        negotiated_cipher_suite,
        protocol_version,
        str::from_utf8(alpn_protocol.unwrap_or_default())
    );

    // Step 3: read what protocol the upstream actually negotiated, then offer only that
    // protocol to the client in the fake cert's TLS config (mirrors Go's
    // `NextProtos: []string{cs.NegotiatedProtocol}` with fallback to "http/1.1").
    let negotiated_proto = tls_upstream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|b| b.to_vec())
        .unwrap_or_else(|| b"http/1.1".to_vec());
    let client_alpn = vec![negotiated_proto];

    let server_cfg = tls_interceptor
        .get_or_create_cert_mirrored_with_alpn(&tls_host, upstream_sans, client_alpn)
        .await?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let tls_client = acceptor.accept(client_io).await.map_err(ProxyError::Io)?;

    serve_tls_tunnel(tls_client, tls_upstream, interceptor, enable_h2).await
}

/// Run the HTTP proxy on an already-decrypted TLS stream, dispatching on ALPN
/// (H2 client → `serve_h2_inner`; HTTP/1.1 client → `serve_http1_inner`).
pub(crate) async fn serve_tls_tunnel<C, U>(
    tls_client: tokio_rustls::server::TlsStream<C>,
    tls_upstream: tokio_rustls::client::TlsStream<U>,
    interceptor: Arc<dyn Interceptor>,
    enable_h2: bool,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client_h2 = enable_h2 && tls_client.get_ref().1.alpn_protocol() == Some(b"h2");
    let upstream_h2 = enable_h2 && tls_upstream.get_ref().1.alpn_protocol() == Some(b"h2");
    debug!("TLS tunnel: client_h2={client_h2}, upstream_h2={upstream_h2}");

    if client_h2 {
        serve_h2_inner(tls_client, tls_upstream, interceptor, upstream_h2).await
    } else {
        serve_http1_inner(tls_client, tls_upstream, interceptor).await
    }
}

#[derive(Debug)]
enum CleartextProtocol {
    Tls,
    H2PriorKnowledge,
    Http1,
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

async fn sniff_cleartext_protocol<IO>(mut io: IO) -> Result<(CleartextProtocol, PrependIo<IO>)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = Vec::with_capacity(H2_PREFACE.len());
    while prefix.len() < H2_PREFACE.len() {
        let mut byte = [0u8; 1];
        let n = io.read(&mut byte).await.map_err(ProxyError::Io)?;
        if n == 0 {
            return Err(ProxyError::Protocol(
                "connection closed before protocol detection".into(),
            ));
        }

        prefix.push(byte[0]);

        if prefix.len() == 1 && prefix[0] == 0x16 {
            return Ok((CleartextProtocol::Tls, PrependIo::new(io, prefix)));
        }

        if prefix[prefix.len() - 1] != H2_PREFACE[prefix.len() - 1] {
            return Ok((CleartextProtocol::Http1, PrependIo::new(io, prefix)));
        }
    }

    Ok((
        CleartextProtocol::H2PriorKnowledge,
        PrependIo::new(io, prefix),
    ))
}

fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("websocket"))
        .unwrap_or(false)
}

fn is_h2c_upgrade(headers: &hyper::HeaderMap) -> bool {
    let has_h2c = headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("h2c"))
        .unwrap_or(false);
    if !has_h2c {
        return false;
    }

    let has_http2_settings = headers.get("HTTP2-Settings").is_some();
    let has_upgrade_token = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(connection_has_upgrade_tokens)
        .unwrap_or(false);

    has_http2_settings && has_upgrade_token
}

fn connection_has_upgrade_tokens(value: &str) -> bool {
    let mut has_upgrade = false;
    let mut has_http2_settings = false;

    for token in value.split(',').map(|part| part.trim()) {
        if token.eq_ignore_ascii_case("Upgrade") {
            has_upgrade = true;
        } else if token.eq_ignore_ascii_case("HTTP2-Settings") {
            has_http2_settings = true;
        }
    }

    has_upgrade && has_http2_settings
}

fn strip_websocket_extensions(headers: &mut hyper::HeaderMap) {
    headers.remove("sec-websocket-extensions");
}

async fn forward_websocket_upgrade(
    mut req: Request<StreamBody>,
    client_on: hyper::upgrade::OnUpgrade,
    sender: Arc<Mutex<hyper::client::conn::http1::SendRequest<StreamBody>>>,
    interceptor: Arc<dyn Interceptor>,
    conn_guard: AbortOnDrop,
) -> Result<Response<StreamBody>> {
    strip_websocket_extensions(req.headers_mut());
    let mut res = sender
        .lock()
        .await
        .send_request(req)
        .await
        .map_err(ProxyError::Hyper)?;

    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_on = hyper::upgrade::on(&mut res);
        tokio::spawn(relay_websocket(
            client_on,
            upstream_on,
            interceptor,
            Some(conn_guard),
        ));
        let (parts, _) = res.into_parts();
        return Ok(Response::from_parts(
            parts,
            full_to_stream_body(Full::new(Bytes::new())),
        ));
    }

    // conn_guard dropped here — upgrade didn't happen, conn no longer needed
    drop(conn_guard);
    let (parts, body) = res.into_parts();
    let stream_body = incoming_to_stream_body(body);
    let res = Response::from_parts(parts, stream_body);
    interceptor
        .intercept_response_streaming(res)
        .await
        .map_err(ProxyError::Interceptor)
}

async fn forward_h2c_upgrade(
    req: Request<StreamBody>,
    client_on: hyper::upgrade::OnUpgrade,
    sender: Arc<Mutex<hyper::client::conn::http1::SendRequest<StreamBody>>>,
    interceptor: Arc<dyn Interceptor>,
    conn_guard: AbortOnDrop,
) -> Result<Response<StreamBody>> {
    let mut res = sender
        .lock()
        .await
        .send_request(req)
        .await
        .map_err(ProxyError::Hyper)?;

    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_on = hyper::upgrade::on(&mut res);
        tokio::spawn(relay_upgraded_tunnel(
            client_on,
            upstream_on,
            Some(conn_guard),
        ));
        let (parts, _) = res.into_parts();
        return Ok(Response::from_parts(
            parts,
            full_to_stream_body(Full::new(Bytes::new())),
        ));
    }

    // conn_guard dropped here — upgrade didn't happen, conn no longer needed
    drop(conn_guard);
    let (parts, body) = res.into_parts();
    let stream_body = incoming_to_stream_body(body);
    let res = Response::from_parts(parts, stream_body);
    interceptor
        .intercept_response_streaming(res)
        .await
        .map_err(ProxyError::Interceptor)
}

/// Serve an HTTP/1.1 MITM tunnel, including WebSocket and h2c upgrade detection.
async fn serve_http1_inner<C, U>(
    client: C,
    upstream: U,
    interceptor: Arc<dyn Interceptor>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let upstream_io = TokioIo::new(upstream);
    let (sender, conn) = hyper::client::conn::http1::handshake::<_, StreamBody>(upstream_io)
        .await
        .map_err(ProxyError::Hyper)?;
    let _conn_guard = AbortOnDrop(tokio::spawn(conn.with_upgrades()).abort_handle());
    let sender = Arc::new(Mutex::new(sender));
    let client_io = TokioIo::new(client);

    let svc = service_fn(move |mut req: Request<Incoming>| {
        let interceptor = Arc::clone(&interceptor);
        let sender = Arc::clone(&sender);
        async move {
            let is_ws = is_websocket_upgrade(req.headers());
            let is_h2c = is_h2c_upgrade(req.headers());
            if is_ws || is_h2c {
                if is_ws {
                    debug!("WebSocket detected: {}", req.uri());
                } else {
                    debug!("h2c upgrade detected: {}", req.uri());
                }
                let client_on = hyper::upgrade::on(&mut req);
                let (parts, body) = req.into_parts();
                let body_bytes = body.collect().await.map_err(BoxError::new)?.to_bytes();
                let req = Request::from_parts(parts, full_to_stream_body(Full::new(body_bytes)));
                let mut req = interceptor.intercept_request_streaming(req).await?;

                if is_ws {
                    strip_websocket_extensions(req.headers_mut());
                    let mut res = sender
                        .lock()
                        .await
                        .send_request(req)
                        .await
                        .map_err(BoxError::new)?;

                    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
                        let upstream_on = hyper::upgrade::on(&mut res);
                        tokio::spawn(relay_websocket(
                            client_on,
                            upstream_on,
                            Arc::clone(&interceptor),
                            None,
                        ));
                        let (parts, _) = res.into_parts();
                        return Ok(Response::from_parts(
                            parts,
                            full_to_stream_body(Full::new(Bytes::new())),
                        ));
                    }

                    let (parts, body) = res.into_parts();
                    let stream_body = incoming_to_stream_body(body);
                    let res = Response::from_parts(parts, stream_body);
                    return interceptor.intercept_response_streaming(res).await;
                }

                let mut res = sender
                    .lock()
                    .await
                    .send_request(req)
                    .await
                    .map_err(BoxError::new)?;

                if res.status() == StatusCode::SWITCHING_PROTOCOLS {
                    let upstream_on = hyper::upgrade::on(&mut res);
                    tokio::spawn(relay_upgraded_tunnel(client_on, upstream_on, None));
                    let (parts, _) = res.into_parts();
                    return Ok(Response::from_parts(
                        parts,
                        full_to_stream_body(Full::new(Bytes::new())),
                    ));
                }

                let (parts, body) = res.into_parts();
                let stream_body = incoming_to_stream_body(body);
                let res = Response::from_parts(parts, stream_body);
                return interceptor.intercept_response_streaming(res).await;
            }

            let (parts, body) = req.into_parts();
            let stream_body = incoming_to_stream_body(body);
            let req = Request::from_parts(parts, stream_body);
            let req = interceptor.intercept_request_streaming(req).await?;
            let res = sender
                .lock()
                .await
                .send_request(req)
                .await
                .map_err(BoxError::new)?;
            let (parts, body) = res.into_parts();
            let stream_body = incoming_to_stream_body(body);
            let res = Response::from_parts(parts, stream_body);
            interceptor.intercept_response_streaming(res).await
        }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(client_io, svc)
        .with_upgrades()
        .await
        .map_err(ProxyError::Hyper)
}

/// Serve an HTTP/2 MITM tunnel. `upstream_h2` controls whether the upstream
/// connection speaks HTTP/2 (`true`) or HTTP/1.1 (`false`).
async fn serve_h2_inner<C, U>(
    client: C,
    upstream: U,
    interceptor: Arc<dyn Interceptor>,
    upstream_h2: bool,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let upstream_io = TokioIo::new(upstream);

    let (sender, _conn_guard): (Arc<Mutex<AnyUpstreamSender>>, AbortOnDrop) = if upstream_h2 {
        let (s, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), upstream_io)
            .await
            .map_err(ProxyError::Hyper)?;
        let guard = AbortOnDrop(tokio::spawn(conn).abort_handle());
        (Arc::new(Mutex::new(AnyUpstreamSender::H2(s))), guard)
    } else {
        let (s, conn) = hyper::client::conn::http1::handshake(upstream_io)
            .await
            .map_err(ProxyError::Hyper)?;
        let guard = AbortOnDrop(tokio::spawn(conn.with_upgrades()).abort_handle());
        (Arc::new(Mutex::new(AnyUpstreamSender::H1(s))), guard)
    };

    let client_io = TokioIo::new(client);
    let svc = service_fn(move |req: Request<Incoming>| {
        let interceptor = Arc::clone(&interceptor);
        let sender = Arc::clone(&sender);
        async move {
            let (parts, body) = req.into_parts();
            let stream_body = incoming_to_stream_body(body);
            let req = Request::from_parts(parts, stream_body);
            let mut req = interceptor.intercept_request_streaming(req).await?;

            // When forwarding an H2 request to an H1 upstream, ensure the Host
            // header is present. In H2 the host is carried in the :authority
            // pseudo-header (exposed as the URI authority); H1 requires an
            // explicit Host header.
            // Do NOT add Host when the upstream is also H2: RFC 9113 §8.3.1
            // says clients SHOULD NOT send Host when :authority is present.
            // Strict servers (e.g. Google) return PROTOCOL_ERROR if Host appears
            // alongside :authority.
            if !upstream_h2
                && !req.headers().contains_key(hyper::header::HOST)
                && let Some(authority) = req.uri().authority()
                && let Ok(value) = hyper::header::HeaderValue::from_str(authority.as_str())
            {
                req.headers_mut().insert(hyper::header::HOST, value);
            }

            let res = sender
                .lock()
                .await
                .send_request(req)
                .await
                .map_err(BoxError::new)?;
            let (parts, body) = res.into_parts();
            let stream_body = incoming_to_stream_body(body);
            let res = Response::from_parts(parts, stream_body);

            interceptor.intercept_response_streaming(res).await
        }
    });

    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(client_io, svc)
        .await
        .map_err(ProxyError::Hyper)
}

/// Relay WebSocket frames between the client and upstream, passing each through the interceptor.
async fn relay_websocket(
    client_on: hyper::upgrade::OnUpgrade,
    upstream_on: hyper::upgrade::OnUpgrade,
    interceptor: Arc<dyn Interceptor>,
    _conn_guard: Option<AbortOnDrop>,
) {
    let (client_up, upstream_up) = match tokio::try_join!(client_on, upstream_on) {
        Ok(pair) => pair,
        Err(e) => {
            debug!("WebSocket upgrade failed: {e}");
            return;
        }
    };

    let client_ws =
        WebSocketStream::from_raw_socket(TokioIo::new(client_up), Role::Server, None).await;
    let upstream_ws =
        WebSocketStream::from_raw_socket(TokioIo::new(upstream_up), Role::Client, None).await;

    let (mut c_sink, mut c_stream) = client_ws.split();
    let (mut u_sink, mut u_stream) = upstream_ws.split();

    loop {
        tokio::select! {
            msg = c_stream.next() => {
                let Some(Ok(msg)) = msg else { break };
                let frame = WsFrame { message: msg };
                match interceptor.intercept_ws_client_frame(frame).await {
                    Ok(f) => { let _ = u_sink.send(f.message).await; }
                    Err(_) => break,
                }
            }
            msg = u_stream.next() => {
                let Some(Ok(msg)) = msg else { break };
                let frame = WsFrame { message: msg };
                match interceptor.intercept_ws_server_frame(frame).await {
                    Ok(f) => { let _ = c_sink.send(f.message).await; }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn relay_upgraded_tunnel(
    client_on: hyper::upgrade::OnUpgrade,
    upstream_on: hyper::upgrade::OnUpgrade,
    _conn_guard: Option<AbortOnDrop>,
) {
    let (client_up, upstream_up) = match tokio::try_join!(client_on, upstream_on) {
        Ok(pair) => pair,
        Err(e) => {
            debug!("Upgrade relay failed: {e}");
            return;
        }
    };

    let mut client_up = TokioIo::new(client_up);
    let mut upstream_up = TokioIo::new(upstream_up);
    if let Err(e) = tokio::io::copy_bidirectional(&mut client_up, &mut upstream_up).await {
        debug!("Upgrade relay IO error: {e}");
    }
}

/// Unified upstream sender that can speak either HTTP/1.1 or HTTP/2.
enum AnyUpstreamSender {
    H1(hyper::client::conn::http1::SendRequest<StreamBody>),
    H2(hyper::client::conn::http2::SendRequest<StreamBody>),
}

impl AnyUpstreamSender {
    async fn send_request(
        &mut self,
        req: Request<StreamBody>,
    ) -> std::result::Result<Response<Incoming>, hyper::Error> {
        match self {
            Self::H1(s) => s.send_request(req).await,
            Self::H2(s) => s.send_request(req).await,
        }
    }
}

/// An `AsyncRead + AsyncWrite` wrapper that replays a peeked prefix before
/// delegating to the inner stream.
pub(crate) struct PrependIo<IO> {
    prefix: Bytes,
    offset: usize,
    inner: IO,
}

impl<IO> PrependIo<IO> {
    pub(crate) fn new(inner: IO, prefix: impl Into<Bytes>) -> Self {
        Self {
            prefix: prefix.into(),
            offset: 0,
            inner,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for PrependIo<IO> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for PrependIo<IO> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Aborts the wrapped task when dropped.
struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Wraps `body` so that `guard` is kept alive while the body is being streamed,
/// then dropped (aborting the guarded task) when the stream ends or is dropped.
fn stream_body_with_guard(body: StreamBody, guard: AbortOnDrop) -> StreamBody {
    let s = stream::unfold((body, Some(guard)), |(mut body, guard)| async move {
        body.frame().await.map(|item| (item, (body, guard)))
    });
    BoxBody::new(HttpStreamBody::new(s))
}

/// Convert `hyper::body::Incoming` to `StreamBody` without buffering.
///
/// When the body is already empty (e.g. a GET request that came in with
/// `END_STREAM` on the HEADERS frame), use an explicit empty `Full` body so
/// that hyper's h2 client sets `END_STREAM` on the HEADERS frame rather than
/// sending a separate empty DATA frame.  Some strict h2 servers (Google,
/// etc.) return `PROTOCOL_ERROR` when a GET request has a body — even an
/// empty one.
fn incoming_to_stream_body(body: hyper::body::Incoming) -> StreamBody {
    if body.is_end_stream() {
        full_to_stream_body(Full::new(Bytes::new()))
    } else {
        BoxBody::new(body.map_err(BoxError::new))
    }
}

/// Wrap a `Full<Bytes>` into a `StreamBody` (zero-copy, no allocation).
fn full_to_stream_body(full: Full<Bytes>) -> StreamBody {
    BoxBody::new(full.map_err(|e| match e {}))
}

/// Convert a `Response<Full<Bytes>>` into `Response<StreamBody>`.
fn full_body_response_to_stream(res: Response<Full<Bytes>>) -> Response<StreamBody> {
    let (parts, body) = res.into_parts();
    Response::from_parts(parts, full_to_stream_body(body))
}

fn extract_upstream_target<B>(req: &Request<B>, default_port: u16) -> Result<(String, u16)> {
    if let Some(authority) = req.uri().authority() {
        return parse_host_port(authority.as_str(), default_port);
    }

    if let Some(host) = req.uri().host() {
        return Ok((
            host.to_string(),
            req.uri().port_u16().unwrap_or(default_port),
        ));
    }

    let host_header = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ProxyError::Protocol("missing host".into()))?;
    parse_host_port(host_header, default_port)
}

/// Parsed fields from the TLS ClientHello that the proxy needs for MITM.
#[derive(Debug)]
struct ClientHelloInfo {
    sni: Option<String>,
    /// Cipher suites advertised by the client, as raw u16 values in client order.
    cipher_suites: Vec<rustls::CipherSuite>,
    /// ALPN protocols advertised by the client (extension type 16).
    /// Empty if the client did not include an ALPN extension.
    alpn: Vec<Vec<u8>>,
    /// TLS versions from the supported_versions extension (type 43).
    /// Values: 0x0304 = TLS 1.3, 0x0303 = TLS 1.2.
    /// Empty if the extension was absent (pre-TLS-1.3 clients).
    supported_versions: Vec<rustls::ProtocolVersion>,
}

async fn extract_client_hello_info<IO>(
    mut io: PrependIo<IO>,
) -> Result<(ClientHelloInfo, PrependIo<PrependIo<IO>>)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    const TLS_RECORD_HEADER_LEN: usize = 5;
    const MAX_TLS_RECORD_LEN: usize = 16 * 1024 + 2048;

    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN);
    while record.len() < TLS_RECORD_HEADER_LEN {
        let mut buf = [0u8; TLS_RECORD_HEADER_LEN];
        let n = io
            .read(&mut buf[..TLS_RECORD_HEADER_LEN - record.len()])
            .await
            .map_err(ProxyError::Io)?;
        if n == 0 {
            return Ok((
                ClientHelloInfo {
                    sni: None,
                    cipher_suites: vec![],
                    alpn: vec![],
                    supported_versions: vec![],
                },
                PrependIo::new(io, record),
            ));
        }
        record.extend_from_slice(&buf[..n]);
    }

    if record[0] != 0x16 {
        return Ok((
            ClientHelloInfo {
                sni: None,
                cipher_suites: vec![],
                alpn: vec![],
                supported_versions: vec![],
            },
            PrependIo::new(io, record),
        ));
    }

    let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if payload_len > MAX_TLS_RECORD_LEN {
        return Ok((
            ClientHelloInfo {
                sni: None,
                cipher_suites: vec![],
                alpn: vec![],
                supported_versions: vec![],
            },
            PrependIo::new(io, record),
        ));
    }

    let target_len = TLS_RECORD_HEADER_LEN + payload_len;
    while record.len() < target_len {
        let remaining = target_len - record.len();
        let mut buf = vec![0u8; remaining.min(1024)];
        let n = io.read(&mut buf).await.map_err(ProxyError::Io)?;
        if n == 0 {
            break;
        }
        record.extend_from_slice(&buf[..n]);
    }

    let info = parse_client_hello_info(&record);
    debug!("ClientHelloInfo: {:#?}", info);
    Ok((info, PrependIo::new(io, record)))
}

fn parse_client_hello_info(record: &[u8]) -> ClientHelloInfo {
    parse_client_hello_info_inner(record).unwrap_or(ClientHelloInfo {
        sni: None,
        cipher_suites: vec![],
        alpn: vec![],
        supported_versions: vec![],
    })
}

fn parse_client_hello_info_inner(record: &[u8]) -> Option<ClientHelloInfo> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + record_len {
        return None;
    }

    let mut handshake = &record[5..5 + record_len];
    if take_u8(&mut handshake)? != 0x01 {
        return None;
    }

    let hello_len = take_u24(&mut handshake)?;
    let mut hello = take_slice(&mut handshake, hello_len)?;

    // skip: legacy_version (2) + random (32)
    take_slice(&mut hello, 2 + 32)?;
    let session_id_len = take_u8(&mut hello)? as usize;
    take_slice(&mut hello, session_id_len)?;
    let cipher_suites_len = take_u16(&mut hello)? as usize;
    let cipher_suites_bytes = take_slice(&mut hello, cipher_suites_len)?;
    let cipher_suites = parse_cipher_suites(cipher_suites_bytes);
    let compression_methods_len = take_u8(&mut hello)? as usize;
    take_slice(&mut hello, compression_methods_len)?;

    let extensions_len = take_u16(&mut hello)? as usize;
    let mut extensions = take_slice(&mut hello, extensions_len)?;

    let mut sni: Option<String> = None;
    let mut alpn: Vec<Vec<u8>> = vec![];
    let mut supported_versions: Vec<rustls::ProtocolVersion> = vec![];

    while !extensions.is_empty() {
        let ext_type = take_u16(&mut extensions)?;
        let ext_len = take_u16(&mut extensions)? as usize;
        let ext_data = take_slice(&mut extensions, ext_len)?;
        match ext_type {
            0 => sni = parse_server_name_extension(ext_data),
            16 => alpn = parse_alpn_extension(ext_data),
            43 => supported_versions = parse_supported_versions_extension(ext_data),
            _ => {}
        }
    }

    Some(ClientHelloInfo {
        sni,
        cipher_suites,
        alpn,
        supported_versions,
    })
}

fn parse_server_name_extension(extension: &[u8]) -> Option<String> {
    let mut list = extension;
    let list_len = take_u16(&mut list)? as usize;
    let mut names = take_slice(&mut list, list_len)?;

    while !names.is_empty() {
        let name_type = take_u8(&mut names)?;
        let name_len = take_u16(&mut names)? as usize;
        let name = take_slice(&mut names, name_len)?;
        if name_type == 0 {
            return std::str::from_utf8(name).ok().map(str::to_owned);
        }
    }

    None
}

/// Parse a TLS ALPN extension (type 16).
/// Format: protocol_list_len(u16) + [proto_len(u8) + proto_bytes]*
fn parse_alpn_extension(extension: &[u8]) -> Vec<Vec<u8>> {
    let mut input = extension;
    let list_len = match take_u16(&mut input) {
        Some(l) => l as usize,
        None => return vec![],
    };
    let mut list = match take_slice(&mut input, list_len) {
        Some(s) => s,
        None => return vec![],
    };
    let mut protocols = Vec::new();
    while !list.is_empty() {
        let proto_len = match take_u8(&mut list) {
            Some(l) => l as usize,
            None => break,
        };
        match take_slice(&mut list, proto_len) {
            Some(p) => protocols.push(p.to_vec()),
            None => break,
        }
    }
    protocols
}

/// Parse the cipher suites bytes from a ClientHello (list of u16 values, big-endian).
fn parse_cipher_suites(data: &[u8]) -> Vec<rustls::CipherSuite> {
    let mut input = data;
    let mut suites = Vec::with_capacity(input.len() / 2);
    while let Some(v) = take_u16(&mut input) {
        suites.push(rustls::CipherSuite::from(v));
    }
    suites
}

/// Parse a TLS supported_versions extension (type 43) from a ClientHello.
/// Format: list_len(u8) + [version(u16)]*.
fn parse_supported_versions_extension(extension: &[u8]) -> Vec<rustls::ProtocolVersion> {
    fn inner(data: &[u8]) -> Option<Vec<rustls::ProtocolVersion>> {
        let mut input = data;
        let list_len = take_u8(&mut input)? as usize;
        let mut list = take_slice(&mut input, list_len)?;
        let mut versions = Vec::new();
        while let Some(v) = take_u16(&mut list) {
            versions.push(rustls::ProtocolVersion::from(v));
        }
        Some(versions)
    }
    inner(extension).unwrap_or_default()
}

/// Build the ALPN list to advertise to the upstream, derived from what the client offered.
///
/// Mirrors Go's logic: pass the client's `SupportedProtos` through, removing `h2` when
/// the proxy has h2 disabled.  Falls back to `["http/1.1"]` if the resulting list is empty.
fn upstream_alpn_from_client(client_alpn: &[Vec<u8>], enable_h2: bool) -> Vec<Vec<u8>> {
    if client_alpn.is_empty() {
        // Client didn't advertise ALPN — use sensible defaults.
        return if enable_h2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
    }
    let filtered: Vec<Vec<u8>> = client_alpn
        .iter()
        .filter(|p| enable_h2 || p.as_slice() != b"h2")
        .cloned()
        .collect();
    if filtered.is_empty() {
        vec![b"http/1.1".to_vec()]
    } else {
        filtered
    }
}

fn take_u8(input: &mut &[u8]) -> Option<u8> {
    Some(take_slice(input, 1)?[0])
}

fn take_u16(input: &mut &[u8]) -> Option<u16> {
    let bytes = take_slice(input, 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u24(input: &mut &[u8]) -> Option<usize> {
    let bytes = take_slice(input, 3)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

fn take_slice<'a>(input: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if input.len() < len {
        return None;
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Some(head)
}

fn select_tls_server_name(client_sni: Option<String>, host: &str) -> String {
    client_sni.unwrap_or_else(|| normalize_tls_server_name(host))
}

fn normalize_tls_server_name(host: &str) -> String {
    if host.starts_with('[') && host.ends_with(']') {
        let candidate = &host[1..host.len() - 1];
        if candidate.parse::<IpAddr>().is_ok() {
            return candidate.to_string();
        }
    }

    host.to_string()
}

fn tls_server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|e| ProxyError::Protocol(e.to_string()))
}

fn parse_host_port(host_port: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(idx) = host_port.rfind(':') {
        let host = host_port[..idx].to_string();
        let port = host_port[idx + 1..]
            .parse::<u16>()
            .map_err(|_| ProxyError::Protocol(format!("invalid port in {host_port}")))?;
        Ok((host, port))
    } else {
        Ok((host_port.to_string(), default_port))
    }
}

/// Parse the SANs from the upstream server's leaf certificate so that the fake
/// certificate can mirror them exactly.  Falls back to a single SAN derived from
/// `fallback_hostname` if parsing fails or no SANs are present.
fn extract_upstream_sans(
    peer_certs: Option<&[CertificateDer<'_>]>,
    fallback_hostname: &str,
) -> Vec<SanType> {
    let Some(certs) = peer_certs else {
        debug!("upstream sent no peer certificates for {fallback_hostname}, using hostname SAN");
        return hostname_san(fallback_hostname);
    };
    let Some(leaf) = certs.first() else {
        debug!("upstream peer certificate list empty for {fallback_hostname}, using hostname SAN");
        return hostname_san(fallback_hostname);
    };

    let cert = match X509Certificate::from_der(leaf.as_ref()) {
        Ok((_, c)) => c,
        Err(e) => {
            debug!(
                "upstream cert DER parse error for {fallback_hostname}: {e}, using hostname SAN"
            );
            return hostname_san(fallback_hostname);
        }
    };

    let validity = cert.validity();
    debug!(
        "upstream cert [{}]: subject=\"{}\", issuer=\"{}\",isca={}, version={}, valid {} → {}",
        fallback_hostname,
        cert.subject(),
        cert.issuer(),
        cert.is_ca(),
        cert.version().to_string(),
        validity.not_before,
        validity.not_after,
    );

    let mut sans = Vec::new();
    let mut san_strs = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        san_strs.push(format!("DNS:{dns}"));
                        if let Ok(ia5) = (*dns).try_into() {
                            sans.push(SanType::DnsName(ia5));
                        }
                    }
                    GeneralName::IPAddress(ip_bytes) => {
                        let ip_addr = match ip_bytes.len() {
                            4 => {
                                let arr: [u8; 4] = (*ip_bytes).try_into().unwrap();
                                IpAddr::V4(std::net::Ipv4Addr::from(arr))
                            }
                            16 => {
                                let arr: [u8; 16] = (*ip_bytes).try_into().unwrap();
                                IpAddr::V6(std::net::Ipv6Addr::from(arr))
                            }
                            _ => continue,
                        };
                        san_strs.push(format!("IP:{ip_addr}"));
                        sans.push(SanType::IpAddress(ip_addr));
                    }
                    _ => {}
                }
            }
        }
    }

    if sans.is_empty() {
        debug!(
            "upstream cert [{}]: no SANs found, falling back to hostname SAN",
            fallback_hostname
        );
        hostname_san(fallback_hostname)
    } else {
        debug!(
            "upstream cert [{}]: SANs=[{}]",
            fallback_hostname,
            san_strs.join(", ")
        );
        sans
    }
}

fn hostname_san(hostname: &str) -> Vec<SanType> {
    let san = if let Ok(ip) = hostname.parse::<IpAddr>() {
        SanType::IpAddress(ip)
    } else {
        match hostname.try_into() {
            Ok(dns) => SanType::DnsName(dns),
            Err(_) => return vec![],
        }
    };
    vec![san]
}

fn bad_gateway_stream() -> Response<StreamBody> {
    let body = BoxBody::new(Full::new(Bytes::from("502 Bad Gateway")).map_err(|e| match e {}));
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(body)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{CONNECTION, HOST, UPGRADE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn sniff_detects_tls() {
        let (mut client, server) = duplex(64);
        client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        drop(client);

        let (proto, mut io) = sniff_cleartext_protocol(server).await.unwrap();
        assert!(matches!(proto, CleartextProtocol::Tls));

        let mut buf = [0u8; 3];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, &[0x16, 0x03, 0x01]);
    }

    #[tokio::test]
    async fn sniff_detects_h2_prior_knowledge() {
        let (mut client, server) = duplex(64);
        client.write_all(H2_PREFACE).await.unwrap();
        drop(client);

        let (proto, mut io) = sniff_cleartext_protocol(server).await.unwrap();
        assert!(matches!(proto, CleartextProtocol::H2PriorKnowledge));

        let mut buf = vec![0u8; H2_PREFACE.len()];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, H2_PREFACE);
    }

    #[tokio::test]
    async fn sniff_falls_back_to_http1_and_replays_prefix() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (mut client, server) = duplex(128);
        client.write_all(payload).await.unwrap();
        drop(client);

        let (proto, mut io) = sniff_cleartext_protocol(server).await.unwrap();
        assert!(matches!(proto, CleartextProtocol::Http1));

        let mut buf = vec![0u8; payload.len()];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn h2c_upgrade_detection_requires_http2_settings_connection_tokens() {
        let req = Request::builder()
            .uri("http://example.com/")
            .header(UPGRADE, "h2c")
            .header(CONNECTION, "Upgrade, HTTP2-Settings")
            .header("HTTP2-Settings", "AAMAAABkAAQCAAAAAAIAAAAA")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_h2c_upgrade(req.headers()));
    }

    #[test]
    fn h2c_upgrade_detection_rejects_missing_http2_settings() {
        let req = Request::builder()
            .uri("http://example.com/")
            .header(UPGRADE, "h2c")
            .header(CONNECTION, "Upgrade")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(!is_h2c_upgrade(req.headers()));
    }

    #[test]
    fn websocket_upgrade_is_not_h2c() {
        let req = Request::builder()
            .uri("http://example.com/")
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(is_websocket_upgrade(req.headers()));
        assert!(!is_h2c_upgrade(req.headers()));
    }

    #[test]
    fn extract_upstream_target_uses_host_header_for_origin_form() {
        let req = Request::builder()
            .uri("/")
            .header(HOST, "example.com:8080")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (host, port) = extract_upstream_target(&req, 80).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn select_tls_server_name_prefers_client_sni() {
        let selected = select_tls_server_name(Some("example.com".into()), "172.67.168.106");
        assert_eq!(selected, "example.com");
    }

    #[test]
    fn normalize_tls_server_name_strips_ipv6_brackets() {
        assert_eq!(normalize_tls_server_name("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(normalize_tls_server_name("example.com"), "example.com");
    }

    #[test]
    fn parse_client_hello_info_extracts_sni() {
        let record = client_hello_record(Some("example.com"), &[], &[], &[]);
        let info = parse_client_hello_info(&record);
        assert_eq!(info.sni, Some("example.com".into()));
        assert!(info.alpn.is_empty());
    }

    #[test]
    fn parse_client_hello_info_returns_none_without_sni() {
        let record = client_hello_record(None, &[], &[], &[]);
        let info = parse_client_hello_info(&record);
        assert_eq!(info.sni, None);
    }

    #[test]
    fn parse_client_hello_info_extracts_alpn() {
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let record = client_hello_record(Some("example.com"), &alpn, &[], &[]);
        let info = parse_client_hello_info(&record);
        assert_eq!(info.sni, Some("example.com".into()));
        assert_eq!(info.alpn, alpn);
    }

    #[test]
    fn parse_client_hello_info_extracts_cipher_suites() {
        let suites = vec![
            rustls::CipherSuite::from(0x1301u16),
            rustls::CipherSuite::from(0x1302u16),
            rustls::CipherSuite::from(0x1302),
            rustls::CipherSuite::from(0x1303),
            rustls::CipherSuite::from(0xc02b),
        ];
        let record = client_hello_record(Some("example.com"), &[], &suites, &[]);
        let info = parse_client_hello_info(&record);
        assert_eq!(info.cipher_suites, suites);
    }

    #[test]
    fn parse_client_hello_info_extracts_supported_versions() {
        let versions = vec![
            rustls::ProtocolVersion::from(0x0304u16),
            rustls::ProtocolVersion::from(0x0303),
        ];
        let record = client_hello_record(Some("example.com"), &[], &[], &versions);
        let info = parse_client_hello_info(&record);
        assert_eq!(info.supported_versions, versions);
    }

    #[test]
    fn parse_client_hello_info_no_supported_versions_when_absent() {
        let record = client_hello_record(Some("example.com"), &[], &[], &[]);
        let info = parse_client_hello_info(&record);
        assert!(info.supported_versions.is_empty());
    }

    #[tokio::test]
    async fn extract_client_hello_info_replays_tls_record() {
        let record = client_hello_record(Some("example.com"), &[], &[], &[]);
        let (mut client, server) = duplex(256);
        client.write_all(&record[1..]).await.unwrap();
        drop(client);

        let io = PrependIo::new(server, record[..1].to_vec());
        let (info, mut replayed) = extract_client_hello_info(io).await.unwrap();
        assert_eq!(info.sni, Some("example.com".into()));

        let mut replayed_record = vec![0u8; record.len()];
        replayed.read_exact(&mut replayed_record).await.unwrap();
        assert_eq!(replayed_record, record);
    }

    #[test]
    fn upstream_alpn_from_client_filters_h2_when_disabled() {
        let client = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let result = upstream_alpn_from_client(&client, false);
        assert_eq!(result, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn upstream_alpn_from_client_passes_through_when_enabled() {
        let client = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let result = upstream_alpn_from_client(&client, true);
        assert_eq!(result, client);
    }

    #[test]
    fn upstream_alpn_from_client_fallback_when_empty() {
        let result = upstream_alpn_from_client(&[], false);
        assert_eq!(result, vec![b"http/1.1".to_vec()]);
        let result = upstream_alpn_from_client(&[], true);
        assert_eq!(result, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    fn client_hello_record(
        server_name: Option<&str>,
        alpn_protocols: &[Vec<u8>],
        cipher_suite_values: &[rustls::CipherSuite],
        supported_version_values: &[rustls::ProtocolVersion],
    ) -> Vec<u8> {
        let mut hello = Vec::new();
        // legacy_version
        hello.extend_from_slice(&[0x03, 0x03]);
        // random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);
        // session_id (empty)
        hello.push(0);
        // cipher suites
        let suites: Vec<u16> = if cipher_suite_values.is_empty() {
            vec![0x1301]
        } else {
            cipher_suite_values.iter().map(|s| u16::from(*s)).collect()
        };
        hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for &s in &suites {
            hello.extend_from_slice(&s.to_be_bytes());
        }
        // compression methods (1 byte: null)
        hello.push(1);
        hello.push(0);

        let mut extensions = Vec::new();

        if let Some(server_name) = server_name {
            let server_name = server_name.as_bytes();
            let mut name_list = Vec::new();
            name_list.push(0);
            name_list.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
            name_list.extend_from_slice(server_name);

            let mut server_name_ext = Vec::new();
            server_name_ext.extend_from_slice(&(name_list.len() as u16).to_be_bytes());
            server_name_ext.extend_from_slice(&name_list);

            extensions.extend_from_slice(&0u16.to_be_bytes());
            extensions.extend_from_slice(&(server_name_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&server_name_ext);
        }

        if !alpn_protocols.is_empty() {
            let mut proto_list = Vec::new();
            for proto in alpn_protocols {
                proto_list.push(proto.len() as u8);
                proto_list.extend_from_slice(proto);
            }
            let mut alpn_ext = Vec::new();
            alpn_ext.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
            alpn_ext.extend_from_slice(&proto_list);
            extensions.extend_from_slice(&16u16.to_be_bytes());
            extensions.extend_from_slice(&(alpn_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn_ext);
        }

        if !supported_version_values.is_empty() {
            // supported_versions extension (type 43): list_len(u8) + [u16]*
            let mut sv_list = Vec::new();
            for &v in supported_version_values {
                let v16 = u16::from(v);
                sv_list.extend_from_slice(&v16.to_be_bytes());
            }
            let mut sv_ext = Vec::new();
            sv_ext.push(sv_list.len() as u8);
            sv_ext.extend_from_slice(&sv_list);
            extensions.extend_from_slice(&43u16.to_be_bytes());
            extensions.extend_from_slice(&(sv_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sv_ext);
        }

        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hello_len = hello.len() as u32;
        handshake.extend_from_slice(&hello_len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use crate::handler::http::serve_fixed_target_tunnel_with_upstream;
use crate::interceptor::Interceptor;
use crate::tls::TlsInterceptor;
use crate::upstream::UpstreamConnector;

pub struct Socks5Handler {
    config: Arc<ProxyConfig>,
    tls_interceptor: Arc<TlsInterceptor>,
    interceptor: Arc<dyn Interceptor>,
    upstream: Arc<UpstreamConnector>,
}

impl Socks5Handler {
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
        if let Err(e) = self.do_handle(stream).await {
            debug!("SOCKS5 error: {e}");
        }
    }

    async fn do_handle(&self, mut stream: TcpStream) -> Result<()> {
        // Step 1: version negotiation.
        let mut header = [0u8; 2];
        stream
            .read_exact(&mut header)
            .await
            .map_err(ProxyError::Io)?;
        if header[0] != 0x05 {
            return Err(ProxyError::Socks5(format!(
                "unsupported SOCKS version: {}",
                header[0]
            )));
        }

        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream
            .read_exact(&mut methods)
            .await
            .map_err(ProxyError::Io)?;

        // Only no-authentication (0x00) is accepted.
        if methods.contains(&0x00) {
            stream
                .write_all(&[0x05, 0x00])
                .await
                .map_err(ProxyError::Io)?;
        } else {
            stream
                .write_all(&[0x05, 0xFF])
                .await
                .map_err(ProxyError::Io)?;
            return Err(ProxyError::Socks5("no acceptable auth method".into()));
        }

        // Step 2: read the CONNECT request.
        let mut req_header = [0u8; 4];
        stream
            .read_exact(&mut req_header)
            .await
            .map_err(ProxyError::Io)?;

        if req_header[1] != 0x01 {
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(ProxyError::Io)?;
            return Err(ProxyError::Socks5(format!(
                "unsupported command: {}",
                req_header[1]
            )));
        }

        let (host, port) = self.read_address(&mut stream, req_header[3]).await?;
        debug!("SOCKS5 CONNECT {host}:{port}");

        // Step 3: establish upstream TCP connection.
        let upstream_tcp = match self.upstream.connect(&host, port).await {
            Ok(s) => s,
            Err(e) => {
                stream
                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok();
                return Err(e);
            }
        };

        // Send success reply.
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(ProxyError::Io)?;

        serve_fixed_target_tunnel_with_upstream(
            stream,
            &host,
            port,
            self.config.enable_h2(),
            Arc::clone(&self.tls_interceptor),
            Arc::clone(&self.interceptor),
            Arc::clone(&self.upstream),
            upstream_tcp,
        )
        .await?;

        Ok(())
    }

    async fn read_address(&self, stream: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
        let host = match atyp {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await.map_err(ProxyError::Io)?;
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(ProxyError::Io)?;
                let mut name = vec![0u8; len[0] as usize];
                stream.read_exact(&mut name).await.map_err(ProxyError::Io)?;
                String::from_utf8(name).map_err(|_| ProxyError::Socks5("invalid domain".into()))?
            }
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await.map_err(ProxyError::Io)?;
                let ip = std::net::Ipv6Addr::from(addr);
                format!("[{ip}]")
            }
            _ => return Err(ProxyError::Socks5(format!("unknown address type: {atyp}"))),
        };

        let mut port_bytes = [0u8; 2];
        stream
            .read_exact(&mut port_bytes)
            .await
            .map_err(ProxyError::Io)?;
        let port = u16::from_be_bytes(port_bytes);

        Ok((host, port))
    }
}

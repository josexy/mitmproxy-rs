use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::debug;

use crate::config::{ProxyConfig, ProxyMode};
use crate::error::Result;
use crate::handler::{HttpHandler, Socks5Handler};
use crate::interceptor::Interceptor;
use crate::tls::{TlsInterceptor, certs::CaBuilder};
use crate::upstream::UpstreamConnector;

pub struct ProxyServer {
    addr: SocketAddr,
    config: Arc<ProxyConfig>,
    tls_ctx: Arc<TlsInterceptor>,
    interceptor: Arc<dyn Interceptor>,
}

impl ProxyServer {
    pub async fn bind(
        addr: SocketAddr,
        config: ProxyConfig,
        interceptor: impl Interceptor,
    ) -> Result<Self> {
        let cache_size = config.cert_cache_size;
        let tls_ctx = match &config.ca_cert {
            Some(ca) => Arc::new(TlsInterceptor::new_with_h2(
                ca.clone(),
                cache_size,
                config.enable_h2(),
            )?),
            None => {
                let ca = CaBuilder::new()
                    .with_common_name("mitmproxy CA")
                    .with_organization_name("mitmproxy")
                    .build()
                    .map_err(|e| crate::error::ProxyError::Protocol(e.to_string()))?;
                Arc::new(TlsInterceptor::from_ca_with_h2(
                    ca,
                    cache_size,
                    config.enable_h2(),
                )?)
            }
        };

        Ok(Self {
            addr,
            config: Arc::new(config),
            tls_ctx,
            interceptor: Arc::new(interceptor),
        })
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        debug!("Proxy listening on {}", self.addr);

        let config = self.config;
        let tls_ctx = self.tls_ctx;
        let interceptor = self.interceptor;

        loop {
            let (stream, _peer) = listener.accept().await?;
            let config = Arc::clone(&config);
            let tls_ctx = Arc::clone(&tls_ctx);
            let interceptor = Arc::clone(&interceptor);

            tokio::spawn(async move {
                let upstream = Arc::new(UpstreamConnector::new(Arc::clone(&config)));
                let mode = config.mode.clone();
                match mode {
                    ProxyMode::Http => {
                        let handler =
                            Arc::new(HttpHandler::new(config, tls_ctx, interceptor, upstream));
                        handler.handle(stream).await;
                    }
                    ProxyMode::Socks5 => {
                        let handler =
                            Arc::new(Socks5Handler::new(config, tls_ctx, interceptor, upstream));
                        handler.handle(stream).await;
                    }
                }
            });
        }
    }
}

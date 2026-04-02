use std::{net::SocketAddr, path::PathBuf};

/// 代理运行模式
#[derive(Debug, Clone, Default)]
pub enum ProxyMode {
    #[default]
    Http,
    Socks5,
}

/// 上游代理类型
#[derive(Debug, Clone)]
pub enum UpstreamKind {
    Http,
    Socks5,
}

/// 上游代理配置
#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    pub kind: UpstreamKind,
    pub addr: SocketAddr,
    pub auth: Option<(String, String)>,
}

/// CA 证书和私钥
#[derive(Debug, Clone)]
pub struct CaCert {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// 代理全局配置
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    pub upstream_proxy: Option<UpstreamProxy>,
    pub ca_cert: Option<CaCert>,
    pub skip_tls_verify: Option<bool>,
    pub disable_h2: Option<bool>,
    pub cert_cache_size: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Http,
            upstream_proxy: None,
            ca_cert: None,
            skip_tls_verify: None,
            disable_h2: None,
            cert_cache_size: 1000,
        }
    }
}

impl ProxyConfig {
    pub fn new(mode: ProxyMode) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }

    pub fn with_upstream(mut self, upstream: UpstreamProxy) -> Self {
        self.upstream_proxy = Some(upstream);
        self
    }

    pub fn with_ca_cert(mut self, ca_cert: CaCert) -> Self {
        self.ca_cert = Some(ca_cert);
        self
    }

    pub fn with_skip_tls_verify(mut self, skip: bool) -> Self {
        self.skip_tls_verify = Some(skip);
        self
    }

    pub fn with_disable_h2(mut self, disable: bool) -> Self {
        self.disable_h2 = Some(disable);
        self
    }

    pub fn with_cert_cache_size(mut self, size: usize) -> Self {
        self.cert_cache_size = size;
        self
    }

    pub fn build(self) -> Self {
        self
    }

    pub fn enable_h2(&self) -> bool {
        !self.disable_h2.unwrap_or(false)
    }

    pub fn tls_verify(&self) -> bool {
        self.skip_tls_verify.unwrap_or(false)
    }
}

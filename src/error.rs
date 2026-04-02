use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("Certificate generation error: {0}")]
    CertGen(#[from] rcgen::Error),

    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("SOCKS5 error: {0}")]
    Socks5(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Upstream connection error: {0}")]
    Upstream(String),

    #[error("Interceptor error: {0}")]
    Interceptor(#[source] crate::interceptor::BoxError),
}

impl From<crate::interceptor::BoxError> for ProxyError {
    fn from(value: crate::interceptor::BoxError) -> Self {
        Self::Interceptor(value)
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;

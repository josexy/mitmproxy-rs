use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{Request, Response};

pub struct BoxError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl BoxError {
    pub fn new<E>(value: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(value))
    }

    pub fn into_inner(self) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self.0
    }
}

impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for BoxError {
    fn from(value: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        Self(value)
    }
}

impl std::fmt::Debug for BoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for BoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for BoxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// Streaming body type used by the streaming interceptor hooks (no full buffering required).
pub type StreamBody = BoxBody<Bytes, BoxError>;

/// A WebSocket frame passed to the interceptor hooks.
pub struct WsFrame {
    pub message: tokio_tungstenite::tungstenite::Message,
}

#[async_trait]
pub trait Interceptor: Send + Sync + 'static {
    /// Streaming request interceptor: the body flows as chunks without full buffering.
    async fn intercept_request_streaming(
        &self,
        req: Request<StreamBody>,
    ) -> Result<Request<StreamBody>, BoxError>;

    /// Streaming response interceptor: the body flows as chunks without full buffering.
    async fn intercept_response_streaming(
        &self,
        res: Response<StreamBody>,
    ) -> Result<Response<StreamBody>, BoxError>;

    async fn intercept_ws_client_frame(&self, frame: WsFrame) -> Result<WsFrame, BoxError> {
        Ok(frame)
    }

    async fn intercept_ws_server_frame(&self, frame: WsFrame) -> Result<WsFrame, BoxError> {
        Ok(frame)
    }
}

/// No-op interceptor that passes all traffic through unmodified.
pub struct PassthroughInterceptor;

#[async_trait]
impl Interceptor for PassthroughInterceptor {
    async fn intercept_request_streaming(
        &self,
        req: Request<StreamBody>,
    ) -> Result<Request<StreamBody>, BoxError> {
        Ok(req)
    }

    async fn intercept_response_streaming(
        &self,
        res: Response<StreamBody>,
    ) -> Result<Response<StreamBody>, BoxError> {
        Ok(res)
    }
}

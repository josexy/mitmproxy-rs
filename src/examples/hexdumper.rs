use std::net::SocketAddr;
use std::path::PathBuf;

use async_trait::async_trait;
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures_util::stream;
use http_body_util::{BodyExt, StreamBody as HttpStreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::{Request, Response};
use mitmproxy::{
    BoxError, CaCert, Interceptor, ProxyConfig, ProxyMode, ProxyServer, StreamBody, UpstreamKind,
    UpstreamProxy, WsFrame,
};
use tokio::sync::mpsc;

struct LogInterceptor;

#[async_trait]
impl Interceptor for LogInterceptor {
    async fn intercept_request_streaming(
        &self,
        req: Request<StreamBody>,
    ) -> Result<Request<StreamBody>, BoxError> {
        println!("→ {} {}", req.method(), req.uri());
        println!("request headers:");
        for (name, value) in req.headers() {
            println!("  {}: {}", name, value.to_str().unwrap_or("<non-utf8>"));
        }

        let (parts, body) = req.into_parts();
        let body = hexdump_body_stream("request", body);
        Ok(Request::from_parts(parts, body))
    }

    async fn intercept_response_streaming(
        &self,
        res: Response<StreamBody>,
    ) -> Result<Response<StreamBody>, BoxError> {
        println!("← {}", res.status());
        println!("response headers:");
        for (name, value) in res.headers() {
            println!("  {}: {}", name, value.to_str().unwrap_or("<non-utf8>"));
        }

        let (parts, body) = res.into_parts();
        let body = hexdump_body_stream("response", body);
        Ok(Response::from_parts(parts, body))
    }

    async fn intercept_ws_client_frame(&self, frame: WsFrame) -> Result<WsFrame, BoxError> {
        println!("ws client → server: {}", format_ws_message(&frame));
        Ok(frame)
    }

    async fn intercept_ws_server_frame(&self, frame: WsFrame) -> Result<WsFrame, BoxError> {
        println!("ws server → client: {}", format_ws_message(&frame));
        Ok(frame)
    }
}

fn format_ws_message(frame: &WsFrame) -> String {
    match &frame.message {
        tokio_tungstenite::tungstenite::Message::Text(text) => {
            format!("text: {}", text)
        }
        tokio_tungstenite::tungstenite::Message::Binary(data) => {
            format!("binary: {} bytes", data.len())
        }
        tokio_tungstenite::tungstenite::Message::Ping(data) => {
            format!("ping: {} bytes", data.len())
        }
        tokio_tungstenite::tungstenite::Message::Pong(data) => {
            format!("pong: {} bytes", data.len())
        }
        tokio_tungstenite::tungstenite::Message::Close(frame) => match frame {
            Some(frame) => format!("close: code={}, reason={}", frame.code, frame.reason),
            None => "close".to_string(),
        },
        tokio_tungstenite::tungstenite::Message::Frame(_) => "raw frame".to_string(),
    }
}

fn format_hexdump(data: &[u8]) -> String {
    let mut result = String::new();
    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        result.push_str(&format!("{:08x}  ", chunk_idx * 16));
        for i in 0..16 {
            if i == 8 {
                result.push(' ');
            }
            if i < chunk.len() {
                result.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                result.push_str("   ");
            }
        }
        result.push_str(" |");
        for b in chunk {
            if b.is_ascii_graphic() || *b == b' ' {
                result.push(*b as char);
            } else {
                result.push('.');
            }
        }
        result.push_str("|\n");
    }
    result
}

fn hexdump_body_stream(label: &'static str, body: StreamBody) -> StreamBody {
    use hyper::body::Body as _;
    if body.size_hint().upper() == Some(0) {
        println!("[{label} hexdump] <empty stream>");
        return body;
    }

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, BoxError>>(16);

    tokio::spawn(async move {
        let mut body = body;
        loop {
            match body.frame().await {
                None => {
                    println!("[{label} hexdump] <end of stream>");
                    break;
                }
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        if !data.is_empty() {
                            println!("[{label} hexdump]\n{}", format_hexdump(data));
                        }
                    }
                    let _ = tx.send(Ok(frame)).await;
                }
                Some(Err(e)) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    let s = stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    BoxBody::new(HttpStreamBody::new(s))
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliProxyMode {
    Http,
    Socks5,
}

impl From<CliProxyMode> for ProxyMode {
    fn from(value: CliProxyMode) -> Self {
        match value {
            CliProxyMode::Http => ProxyMode::Http,
            CliProxyMode::Socks5 => ProxyMode::Socks5,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliUpstreamKind {
    Http,
    Socks5,
}

impl From<CliUpstreamKind> for UpstreamKind {
    fn from(value: CliUpstreamKind) -> Self {
        match value {
            CliUpstreamKind::Http => UpstreamKind::Http,
            CliUpstreamKind::Socks5 => UpstreamKind::Socks5,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "mitmproxy-rs")]
struct Cli {
    #[arg(short = 'b', long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    #[arg(long, value_enum, default_value_t = CliProxyMode::Http)]
    mode: CliProxyMode,

    #[arg(long, value_enum, requires = "upstream_addr")]
    upstream_kind: Option<CliUpstreamKind>,

    #[arg(long, requires = "upstream_kind")]
    upstream_addr: Option<SocketAddr>,

    #[arg(long, requires = "upstream_pass")]
    upstream_user: Option<String>,

    #[arg(long, requires = "upstream_user")]
    upstream_pass: Option<String>,

    #[arg(long, requires = "ca_key")]
    ca_cert: Option<PathBuf>,

    #[arg(long, requires = "ca_cert")]
    ca_key: Option<PathBuf>,

    #[arg(long)]
    no_tls_verify: bool,

    #[arg(long)]
    no_h2: bool,

    #[arg(long, default_value_t = 1000)]
    cert_cache_size: usize,
}

impl Cli {
    fn into_runtime(self) -> Result<(SocketAddr, ProxyConfig), Box<dyn std::error::Error>> {
        if self.cert_cache_size == 0 {
            panic!("--cert-cache-size must be greater than 0");
        }

        let upstream = match (self.upstream_kind, self.upstream_addr) {
            (Some(kind), Some(addr)) => Some(UpstreamProxy {
                kind: kind.into(),
                addr,
                auth: match (self.upstream_user, self.upstream_pass) {
                    (Some(user), Some(pass)) => Some((user, pass)),
                    (None, None) => None,
                    _ => unreachable!("clap enforces paired upstream auth flags"),
                },
            }),
            (None, None) => {
                if self.upstream_user.is_some() || self.upstream_pass.is_some() {
                    panic!(
                        "--upstream-user/--upstream-pass require --upstream-kind and --upstream-addr"
                    );
                }
                None
            }
            _ => unreachable!("clap enforces paired upstream proxy flags"),
        };

        let ca_cert = match (self.ca_cert, self.ca_key) {
            (Some(cert_path), Some(key_path)) => Some(CaCert {
                cert_path: cert_path,
                key_path: key_path,
            }),
            (None, None) => None,
            _ => unreachable!("clap enforces paired CA flags"),
        };

        let config = ProxyConfig {
            mode: self.mode.into(),
            upstream_proxy: upstream,
            ca_cert,
            skip_tls_verify: Some(self.no_tls_verify),
            disable_h2: Some(self.no_h2),
            cert_cache_size: self.cert_cache_size,
        };

        Ok((self.bind, config))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_line_number(true)
        .with_file(true)
        .with_level(true)
        .with_writer(std::io::stdout)
        .with_max_level(tracing::Level::ERROR)
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let (bind_addr, config) = Cli::parse().into_runtime()?;
    let server = ProxyServer::bind(bind_addr, config, LogInterceptor).await?;
    server.run().await?;
    Ok(())
}

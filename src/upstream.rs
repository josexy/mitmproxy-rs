use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::config::{ProxyConfig, UpstreamKind};
use crate::error::{ProxyError, Result};

pub struct UpstreamConnector {
    config: Arc<ProxyConfig>,
    tls_client_config: Arc<ClientConfig>,
}

impl UpstreamConnector {
    pub fn new(config: Arc<ProxyConfig>) -> Self {
        let mut tls_client_config = if config.tls_verify() {
            build_verified_client_config()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        };
        tls_client_config.alpn_protocols = alpn_protocols(config.enable_h2());

        Self {
            config,
            tls_client_config: Arc::new(tls_client_config),
        }
    }

    pub fn tls_client_config(&self) -> Arc<ClientConfig> {
        self.tls_client_config_with_h2(self.config.enable_h2())
    }

    pub fn tls_client_config_with_h2(&self, enable_h2: bool) -> Arc<ClientConfig> {
        if self.config.enable_h2() == enable_h2 {
            return Arc::clone(&self.tls_client_config);
        }

        let mut tls_client_config = (*self.tls_client_config).clone();
        tls_client_config.alpn_protocols = alpn_protocols(enable_h2);
        Arc::new(tls_client_config)
    }

    /// Build a TLS client config that mimics the client's TLS fingerprint.
    ///
    /// Filters the proxy's supported cipher suites to those the client advertised (preserving
    /// client order), and restricts the TLS version set to what the client declared in the
    /// `supported_versions` extension (type 43).  Falls back to proxy defaults when the client
    /// lists are empty or contain no locally-supported values.
    ///
    /// This makes the upstream TLS handshake look like it originates from the real client
    /// rather than from the proxy's fixed defaults, which matters for fingerprint-aware
    /// servers (e.g. Cloudflare JA3/JA4 checks).
    pub fn tls_client_config_mimicking_client(
        &self,
        alpn: Vec<Vec<u8>>,
        cipher_suites: &[rustls::CipherSuite],
        supported_versions: &[rustls::ProtocolVersion],
    ) -> Arc<ClientConfig> {
        use std::collections::HashSet;

        let default_provider = rustls::crypto::ring::default_provider();

        // Filter to cipher suites the client advertised, in client order.
        // Fall back to all supported suites if none overlap.
        let filtered_suites: Vec<rustls::SupportedCipherSuite> = if cipher_suites.is_empty() {
            default_provider.cipher_suites.clone()
        } else {
            let client_set: HashSet<u16> = cipher_suites.iter().copied().map(u16::from).collect();
            let v: Vec<_> = default_provider
                .cipher_suites
                .iter()
                .filter(|cs| client_set.contains(&u16::from(cs.suite())))
                .copied()
                .collect();
            if v.is_empty() {
                default_provider.cipher_suites.clone()
            } else {
                v
            }
        };

        // Map supported_versions extension values to rustls version descriptors.
        // 0x0304 = TLS 1.3, 0x0303 = TLS 1.2.  Default to both when absent.
        let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> =
            if supported_versions.is_empty() {
                vec![&rustls::version::TLS13, &rustls::version::TLS12]
            } else {
                let mut versions = Vec::new();
                if supported_versions.contains(&rustls::ProtocolVersion::TLSv1_3) {
                    versions.push(&rustls::version::TLS13);
                }
                if supported_versions.contains(&rustls::ProtocolVersion::TLSv1_2) {
                    versions.push(&rustls::version::TLS12);
                }
                if versions.is_empty() {
                    vec![&rustls::version::TLS13, &rustls::version::TLS12]
                } else {
                    versions
                }
            };

        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: filtered_suites,
            ..default_provider
        };

        let mut cfg = if self.config.tls_verify() {
            let mut root_store = RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            root_store.add_parsable_certificates(native.certs);
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&protocol_versions)
                .expect("TLS 1.2/1.3 are supported by the ring provider")
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&protocol_versions)
                .expect("TLS 1.2/1.3 are supported by the ring provider")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        };
        cfg.alpn_protocols = alpn;
        Arc::new(cfg)
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        match &self.config.upstream_proxy {
            None => {
                let addr = format!("{host}:{port}");
                TcpStream::connect(&addr).await.map_err(ProxyError::Io)
            }
            Some(upstream) => match upstream.kind {
                UpstreamKind::Http => self.connect_via_http_proxy(host, port).await,
                UpstreamKind::Socks5 => self.connect_via_socks5(host, port).await,
            },
        }
    }

    pub async fn connect_tls(&self, host: &str, port: u16) -> Result<TlsStream<TcpStream>> {
        self.connect_tls_with_h2(host, port, self.config.enable_h2())
            .await
    }

    pub async fn connect_tls_with_h2(
        &self,
        host: &str,
        port: u16,
        enable_h2: bool,
    ) -> Result<TlsStream<TcpStream>> {
        let stream = self.connect(host, port).await?;
        let connector = TlsConnector::from(self.tls_client_config_with_h2(enable_h2));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| ProxyError::Protocol(e.to_string()))?;
        connector
            .connect(server_name, stream)
            .await
            .map_err(ProxyError::Io)
    }

    async fn connect_via_http_proxy(&self, host: &str, port: u16) -> Result<TcpStream> {
        let upstream = self.config.upstream_proxy.as_ref().unwrap();
        let mut stream = TcpStream::connect(upstream.addr)
            .await
            .map_err(ProxyError::Io)?;

        use tokio::io::AsyncWriteExt;
        let connect_req = if let Some((user, pass)) = &upstream.auth {
            use base64::Engine;
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            format!(
                "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
            )
        } else {
            format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n")
        };

        stream
            .write_all(connect_req.as_bytes())
            .await
            .map_err(ProxyError::Io)?;

        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1024];
        let mut response = String::new();
        loop {
            let n = stream.read(&mut buf).await.map_err(ProxyError::Io)?;
            if n == 0 {
                return Err(ProxyError::Upstream(
                    "upstream proxy closed connection".into(),
                ));
            }
            response.push_str(&String::from_utf8_lossy(&buf[..n]));
            if response.contains("\r\n\r\n") {
                break;
            }
        }

        if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
            return Err(ProxyError::Upstream(format!(
                "HTTP proxy CONNECT failed: {}",
                response.lines().next().unwrap_or("")
            )));
        }

        Ok(stream)
    }

    async fn connect_via_socks5(&self, host: &str, port: u16) -> Result<TcpStream> {
        let upstream = self.config.upstream_proxy.as_ref().unwrap();
        let mut stream = TcpStream::connect(upstream.addr)
            .await
            .map_err(ProxyError::Io)?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let auth_method: u8 = if upstream.auth.is_some() { 0x02 } else { 0x00 };
        stream
            .write_all(&[0x05, 0x01, auth_method])
            .await
            .map_err(ProxyError::Io)?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.map_err(ProxyError::Io)?;
        if resp[0] != 0x05 {
            return Err(ProxyError::Socks5("invalid SOCKS5 response".into()));
        }

        if resp[1] == 0x02 {
            let (user, pass) = upstream.auth.as_ref().unwrap();
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await.map_err(ProxyError::Io)?;
            stream.read_exact(&mut resp).await.map_err(ProxyError::Io)?;
            if resp[1] != 0x00 {
                return Err(ProxyError::Socks5("SOCKS5 authentication failed".into()));
            }
        } else if resp[1] != 0x00 {
            return Err(ProxyError::Socks5(
                "no acceptable SOCKS5 auth method".into(),
            ));
        }

        let host_bytes = host.as_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
        req.extend_from_slice(host_bytes);
        req.push((port >> 8) as u8);
        req.push((port & 0xff) as u8);
        stream.write_all(&req).await.map_err(ProxyError::Io)?;

        let mut reply = [0u8; 4];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(ProxyError::Io)?;
        if reply[1] != 0x00 {
            return Err(ProxyError::Socks5(format!(
                "SOCKS5 CONNECT failed: code {}",
                reply[1]
            )));
        }

        match reply[3] {
            0x01 => {
                let mut _addr = [0u8; 4];
                stream
                    .read_exact(&mut _addr)
                    .await
                    .map_err(ProxyError::Io)?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(ProxyError::Io)?;
                let mut _addr = vec![0u8; len[0] as usize];
                stream
                    .read_exact(&mut _addr)
                    .await
                    .map_err(ProxyError::Io)?;
            }
            0x04 => {
                let mut _addr = [0u8; 16];
                stream
                    .read_exact(&mut _addr)
                    .await
                    .map_err(ProxyError::Io)?;
            }
            _ => {
                return Err(ProxyError::Socks5(
                    "unknown address type in SOCKS5 reply".into(),
                ));
            }
        }
        let mut _port = [0u8; 2];
        stream
            .read_exact(&mut _port)
            .await
            .map_err(ProxyError::Io)?;

        Ok(stream)
    }
}

fn build_verified_client_config() -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    root_store.add_parsable_certificates(native.certs);
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn alpn_protocols(enable_h2: bool) -> Vec<Vec<u8>> {
    let mut protocols = Vec::with_capacity(2);
    if enable_h2 {
        protocols.push(b"h2".to_vec());
    }
    protocols.push(b"http/1.1".to_vec());
    protocols
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_client_config_sets_http_alpn() {
        install_crypto_provider();
        let mut cfg = build_verified_client_config();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}

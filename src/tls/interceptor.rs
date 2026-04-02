use lru::LruCache;
use rcgen::{KeyPair, SanType};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Cursor;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

use crate::config::CaCert;
use crate::error::{ProxyError, Result};
use crate::tls::certs::{Ca, CaBuilder, CertificateBuilder};

/// Cached certificate material (chain + private key bytes).
/// We cache this rather than the full `ServerConfig` so that each connection
/// can assemble a `ServerConfig` with the ALPN negotiated by the upstream.
struct CertMaterial {
    cert_chain: Vec<CertificateDer<'static>>,
    /// Raw PKCS8 DER bytes for the leaf private key.
    key_der_bytes: Vec<u8>,
}

pub struct TlsInterceptor {
    ca: Ca,
    ca_chain: Vec<CertificateDer<'static>>,
    cert_cache: Mutex<LruCache<String, Arc<CertMaterial>>>,
    alpn_protocols: Vec<Vec<u8>>,
}

impl std::fmt::Debug for TlsInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsInterceptor")
            .field("ca_chain_len", &self.ca_chain.len())
            .finish_non_exhaustive()
    }
}

impl TlsInterceptor {
    pub fn new(ca_cert: CaCert, cache_size: usize) -> Result<Self> {
        Self::new_with_h2(ca_cert, cache_size, true)
    }

    pub fn new_with_h2(ca_cert: CaCert, cache_size: usize, enable_h2: bool) -> Result<Self> {
        let ca = CaBuilder::from(ca_cert.cert_path, ca_cert.key_path)
            .map_err(|e| ProxyError::Protocol(e.to_string()))?;
        Self::from_ca_with_h2(ca, cache_size, enable_h2)
    }

    pub fn from_ca_with_h2(ca: Ca, cache_size: usize, enable_h2: bool) -> Result<Self> {
        let pem = ca.serialize_pem();
        let ca_chain = load_cert_chain(pem.cert_pem.as_bytes())?;
        let ca_key_pair = KeyPair::from_pem(&pem.private_key_pem).map_err(ProxyError::CertGen)?;
        validate_ca_chain_and_key(&ca_chain, &ca_key_pair)?;

        Ok(Self {
            ca,
            ca_chain,
            cert_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(1000).unwrap()),
            )),
            alpn_protocols: alpn_protocols(enable_h2),
        })
    }

    pub async fn get_or_create_cert(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        let material = self
            .get_or_create_cert_material(hostname, vec![subject_alt_name(hostname)?])
            .await?;
        let cfg = Self::build_server_config_from_material(&material, self.alpn_protocols.clone())?;
        Ok(Arc::new(cfg))
    }

    /// Like `get_or_create_cert_mirrored` but advertises exactly `alpn` to the client.
    ///
    /// Call this after the upstream TLS handshake completes so that the fake
    /// certificate's `ServerConfig` offers only the protocol the upstream negotiated
    /// (matching the Go proxy's behaviour: `NextProtos: []string{cs.NegotiatedProtocol}`).
    pub async fn get_or_create_cert_mirrored_with_alpn(
        &self,
        hostname: &str,
        upstream_sans: Vec<SanType>,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<ServerConfig>> {
        let sans = if upstream_sans.is_empty() {
            vec![subject_alt_name(hostname)?]
        } else {
            upstream_sans
        };
        let material = self.get_or_create_cert_material(hostname, sans).await?;
        let cfg = Self::build_server_config_from_material(&material, alpn)?;
        Ok(Arc::new(cfg))
    }

    /// Get or create cert material (chain + key bytes) for `hostname`, cached by hostname.
    /// `sans` is only used if the cache misses.
    async fn get_or_create_cert_material(
        &self,
        hostname: &str,
        sans: Vec<SanType>,
    ) -> Result<Arc<CertMaterial>> {
        {
            let mut cache = self.cert_cache.lock().await;
            if let Some(m) = cache.get(hostname) {
                debug!("Using cached certificate for {hostname}");
                return Ok(Arc::clone(m));
            }
        }
        let material = self.build_cert_material_with_sans(hostname, sans)?;
        debug!("Generated faked certificate for {hostname}");
        let arc = Arc::new(material);
        self.cert_cache
            .lock()
            .await
            .put(hostname.to_string(), Arc::clone(&arc));
        Ok(arc)
    }

    fn build_cert_material_with_sans(
        &self,
        hostname: &str,
        sans: Vec<SanType>,
    ) -> Result<CertMaterial> {
        let cert = CertificateBuilder::new()
            .with_server_auth()
            .with_common_name(hostname)
            .with_sans(sans)
            .build(Some(&self.ca))
            .map_err(|e| ProxyError::Protocol(e.to_string()))?;

        let mut cert_chain = Vec::with_capacity(1 + self.ca_chain.len());
        cert_chain.push(CertificateDer::from(cert.cert().der().to_vec()));
        cert_chain.extend(self.ca_chain.iter().cloned());
        let key_der_bytes = cert.key_pair().serialize_der();

        debug!("Generated TLS cert for {hostname} from CA");
        Ok(CertMaterial {
            cert_chain,
            key_der_bytes,
        })
    }

    fn build_server_config_from_material(
        material: &CertMaterial,
        alpn: Vec<Vec<u8>>,
    ) -> Result<ServerConfig> {
        let key_der = PrivateKeyDer::try_from(material.key_der_bytes.clone())
            .map_err(|e| ProxyError::Protocol(e.to_string()))?;
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(material.cert_chain.clone(), key_der)
            .map_err(ProxyError::Tls)?;
        cfg.alpn_protocols = alpn;
        Ok(cfg)
    }
}

fn subject_alt_name(hostname: &str) -> Result<SanType> {
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }

    Ok(SanType::DnsName(hostname.try_into().map_err(|_| {
        ProxyError::Protocol(format!("invalid hostname: {hostname}"))
    })?))
}

fn load_cert_chain(cert_pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(ProxyError::Io)?;
    if certs.is_empty() {
        return Err(ProxyError::Protocol(
            "CA cert PEM did not contain any certificates".into(),
        ));
    }
    Ok(certs)
}

fn validate_ca_chain_and_key(
    ca_chain: &[CertificateDer<'static>],
    ca_key_pair: &KeyPair,
) -> Result<()> {
    let key_der = PrivateKeyDer::try_from(ca_key_pair.serialize_der())
        .map_err(|e| ProxyError::Protocol(e.to_string()))?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(ca_chain.to_vec(), key_der)
        .map_err(ProxyError::Tls)?;
    Ok(())
}

fn alpn_protocols(enable_h2: bool) -> Vec<Vec<u8>> {
    let mut protocols = Vec::with_capacity(2);
    if enable_h2 {
        protocols.push(b"h2".to_vec());
    }
    protocols.push(b"http/1.1".to_vec());
    protocols
}

#[cfg(test)]
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ca() -> Ca {
        CaBuilder::new()
            .with_common_name("mitmproxy CA")
            .with_organization_name("mitmproxy")
            .build()
            .unwrap()
    }

    #[test]
    fn reload_generated_ca_for_signing() {
        install_crypto_provider();
        let interceptor = TlsInterceptor::from_ca_with_h2(make_test_ca(), 8, true).unwrap();

        assert_eq!(interceptor.ca_chain.len(), 1);
        assert!(!interceptor.ca_chain[0].as_ref().is_empty());
    }

    #[test]
    fn reject_mismatched_ca_key_pair() {
        install_crypto_provider();
        let pem1 = make_test_ca().serialize_pem();
        let pem2 = make_test_ca().serialize_pem();

        let dir = std::env::temp_dir();
        let cert_path = dir.join("mitmproxy_test_ca1.crt");
        let key_path = dir.join("mitmproxy_test_ca2.key");
        std::fs::write(&cert_path, &pem1.cert_pem).unwrap();
        std::fs::write(&key_path, &pem2.private_key_pem).unwrap();

        let mismatched = CaCert {
            cert_path,
            key_path,
        };
        let err = TlsInterceptor::new(mismatched, 8).unwrap_err();
        assert!(matches!(err, ProxyError::Tls(_)));
    }

    #[tokio::test]
    async fn generates_cert_from_typed_ca() {
        install_crypto_provider();
        let ca = CaBuilder::new()
            .with_common_name("mitmproxy CA")
            .with_organization_name("mitmproxy")
            .build()
            .unwrap();
        let interceptor = TlsInterceptor::from_ca_with_h2(ca, 8, true).unwrap();

        interceptor.get_or_create_cert("localhost").await.unwrap();
    }

    #[tokio::test]
    async fn generates_cert_for_ipv4_subject_alt_name() {
        install_crypto_provider();
        let interceptor = TlsInterceptor::from_ca_with_h2(make_test_ca(), 8, true).unwrap();

        interceptor.get_or_create_cert("127.0.0.1").await.unwrap();
    }

    #[tokio::test]
    async fn generates_cert_for_ipv6_subject_alt_name() {
        install_crypto_provider();
        let interceptor = TlsInterceptor::from_ca_with_h2(make_test_ca(), 8, true).unwrap();

        interceptor.get_or_create_cert("::1").await.unwrap();
    }
}

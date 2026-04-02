use chrono::Datelike;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, date_time_ymd,
};
use std::error::Error;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PemCertifiedKey {
    pub cert_pem: String,
    pub private_key_pem: String,
}

pub use rcgen::SanType;

pub struct Ca {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    pub fn serialize_pem(&self) -> PemCertifiedKey {
        PemCertifiedKey {
            cert_pem: self.cert_pem.clone(),
            private_key_pem: self.issuer.key().serialize_pem(),
        }
    }

    pub fn issuer(&self) -> &Issuer<'static, KeyPair> {
        &self.issuer
    }
}

pub struct Cert {
    cert: Certificate,
    key_pair: KeyPair,
}

impl Cert {
    #[cfg(test)]
    pub fn serialize_pem(&self) -> PemCertifiedKey {
        PemCertifiedKey {
            cert_pem: self.cert.pem(),
            private_key_pem: self.key_pair.serialize_pem(),
        }
    }

    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

pub struct CaBuilder {
    params: CertificateParams,
}

impl CaBuilder {
    pub fn new() -> Self {
        let mut params: CertificateParams = CertificateParams::new(vec![]).unwrap();
        params.use_authority_key_identifier_extension = true;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        Self { params }
    }

    pub fn from(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Ca, Box<dyn Error>> {
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Ca, Box<dyn Error>> {
        let key_pair = parse_private_key(key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key_pair)?;

        Ok(Ca {
            cert_pem: cert_pem.to_string(),
            issuer,
        })
    }

    #[cfg(test)]
    pub fn with_country_name(mut self, country_name: &str) -> Self {
        self.params
            .distinguished_name
            .push(DnType::CountryName, country_name);
        self
    }

    pub fn with_organization_name(mut self, organization_name: &str) -> Self {
        self.params
            .distinguished_name
            .push(DnType::OrganizationName, organization_name);
        self
    }

    pub fn with_common_name(mut self, common_name: &str) -> Self {
        self.params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        self
    }

    pub fn with_validity_days(mut self, days: u32) -> Self {
        let now = chrono::Utc::now();
        let after = now + chrono::Duration::days(days as i64);
        self.params.not_before = date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        self.params.not_after = date_time_ymd(after.year(), after.month() as u8, after.day() as u8);
        self
    }

    pub fn build(self) -> Result<Ca, Box<dyn Error>> {
        let key_pair = generate_private_key()?;
        let cert = self.params.self_signed(&key_pair)?;

        Ok(Ca {
            cert_pem: cert.pem(),
            issuer: Issuer::new(self.params, key_pair),
        })
    }
}

pub struct CertificateBuilder {
    params: CertificateParams,
}

impl CertificateBuilder {
    pub fn new() -> Self {
        let mut params: CertificateParams = CertificateParams::new(vec![]).unwrap();
        params.use_authority_key_identifier_extension = true;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        Self { params }
    }

    #[cfg(test)]
    pub fn with_country_name(mut self, country_name: &str) -> Self {
        self.params
            .distinguished_name
            .push(DnType::CountryName, country_name);
        self
    }

    pub fn with_common_name(mut self, common_name: &str) -> Self {
        self.params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        self
    }

    #[cfg(test)]
    pub fn with_validity_days(mut self, days: u32) -> Self {
        let now = chrono::Utc::now();
        let after = now + chrono::Duration::days(days as i64);
        self.params.not_before = date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        self.params.not_after = date_time_ymd(after.year(), after.month() as u8, after.day() as u8);
        self
    }

    pub fn with_server_auth(mut self) -> Self {
        let val = ExtendedKeyUsagePurpose::ServerAuth;
        if !self.params.extended_key_usages.contains(&val) {
            self.params.extended_key_usages.push(val);
        }
        self
    }

    pub fn with_sans(mut self, sans: Vec<SanType>) -> Self {
        self.params.subject_alt_names.extend(sans);
        self
    }

    pub fn build(self, ca: Option<&Ca>) -> Result<Cert, Box<dyn Error>> {
        let key_pair = generate_private_key()?;
        let cert = match ca {
            Some(ca) => self.params.signed_by(&key_pair, ca.issuer())?,
            None => self.params.self_signed(&key_pair)?,
        };
        Ok(Cert { cert, key_pair })
    }
}

pub fn generate_private_key() -> Result<KeyPair, Box<dyn Error>> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
    Ok(key_pair)
}

pub fn parse_private_key(pem_str: &str) -> Result<KeyPair, Box<dyn Error>> {
    let key_pair = KeyPair::from_pem(pem_str)?;
    Ok(key_pair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::vec;

    #[test]
    fn test_gen_ca() -> Result<(), Box<dyn Error>> {
        let common_name = "example-ca.com";
        let ca = CaBuilder::new()
            .with_common_name(common_name)
            .with_country_name("US")
            .with_validity_days(3650)
            .build()?;
        let pem = ca.serialize_pem();
        assert!(!pem.cert_pem.is_empty());
        assert!(!pem.private_key_pem.is_empty());
        Ok(())
    }

    #[test]
    fn test_load_ca_from_files() -> Result<(), Box<dyn Error>> {
        let generated = CaBuilder::new()
            .with_common_name("example-ca.com")
            .with_country_name("US")
            .with_validity_days(3650)
            .build()?;
        let pem = generated.serialize_pem();

        let base = std::env::temp_dir().join(format!(
            "mitmproxy-rs-ca-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&base)?;
        let cert_path = base.join("ca.crt");
        let key_path = base.join("ca.key");
        fs::write(&cert_path, &pem.cert_pem)?;
        fs::write(&key_path, &pem.private_key_pem)?;

        let loaded = CaBuilder::from(&cert_path, &key_path)?;
        let loaded_pem = loaded.serialize_pem();
        assert_eq!(loaded_pem.cert_pem, pem.cert_pem);
        assert_eq!(loaded_pem.private_key_pem, pem.private_key_pem);

        let cert = CertificateBuilder::new()
            .with_server_auth()
            .with_common_name("localhost")
            .with_sans(vec![SanType::DnsName("localhost".try_into()?)])
            .build(Some(&loaded))?;
        let cert_pem = cert.serialize_pem();
        assert!(!cert_pem.cert_pem.is_empty());

        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_dir(&base);
        Ok(())
    }

    #[test]
    fn test_gen_self_signed_cert() -> Result<(), Box<dyn Error>> {
        let common_name = "localhost";
        let sans = vec![
            SanType::DnsName("localhost".try_into()?),
            SanType::IpAddress("127.0.0.1".parse()?),
        ];
        let cert = CertificateBuilder::new()
            .with_server_auth()
            .with_country_name("US")
            .with_validity_days(365)
            .with_sans(sans)
            .with_common_name(common_name)
            .build(None)?;
        let pem = cert.serialize_pem();
        assert!(!pem.cert_pem.is_empty());
        assert!(!pem.private_key_pem.is_empty());
        Ok(())
    }

    #[test]
    fn test_gen_self_issuer() -> Result<(), Box<dyn Error>> {
        let ca = CaBuilder::new()
            .with_common_name("example-ca.com")
            .with_country_name("US")
            .with_validity_days(3650)
            .build()?;

        let common_name = "localhost";
        let sans = vec![
            SanType::DnsName("localhost".try_into()?),
            SanType::IpAddress("127.0.0.1".parse()?),
        ];
        let cert = CertificateBuilder::new()
            .with_server_auth()
            .with_country_name("US")
            .with_validity_days(365)
            .with_sans(sans)
            .with_common_name(common_name)
            .build(Some(&ca))?;
        let pem = cert.serialize_pem();
        assert!(!pem.cert_pem.is_empty());
        assert!(!pem.private_key_pem.is_empty());
        Ok(())
    }
}

//! The egress CA and the certificates it signs for intercepted hosts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

const CA_NAME: &str = "Spawnbox egress CA";
const CA_YEARS: i64 = 10;
const LEAF_DAYS: i64 = 30;
/// Leaf certificates are made again well before they expire.
const LEAF_REUSE: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_CACHED: usize = 4096;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A new CA: certificate PEM and private key PEM.
pub fn generate_ca() -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, CA_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * CA_YEARS);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

pub struct Ca {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<HashMap<String, (Instant, Arc<ServerConfig>)>>,
}

impl Ca {
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parse the egress CA key")?;
        let issuer =
            Issuer::from_ca_cert_pem(cert_pem, key).context("parse the egress CA certificate")?;
        let cert_der = rustls::pki_types::pem::PemObject::from_pem_slice(cert_pem.as_bytes())
            .context("parse the egress CA certificate")?;
        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            cert_der,
            issuer,
            provider: provider(),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A TLS server config that presents a certificate for `host`. Offers
    /// only HTTP/1.1, so the proxy can read and change requests.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut leaves = self.leaves.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((made, config)) = leaves.get(host)
            && made.elapsed() < LEAF_REUSE
        {
            return Ok(Arc::clone(config));
        }
        let config = Arc::new(self.make_config(host)?);
        if leaves.len() >= MAX_CACHED {
            leaves.clear();
        }
        leaves.insert(host.to_owned(), (Instant::now(), Arc::clone(&config)));
        Ok(config)
    }

    fn make_config(&self, host: &str) -> Result<ServerConfig> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(LEAF_DAYS);
        let cert = params.signed_by(&key, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone(), self.cert_der.clone()], key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConfig;
    use rustls::pki_types::ServerName;
    use std::io::{Read, Write};

    /// A client that trusts only the CA completes a handshake with a leaf
    /// for the right name, and fails for another name.
    #[test]
    fn leaf_certificates_chain_to_the_ca() {
        let (cert, key) = generate_ca().unwrap();
        let ca = Ca::load(&cert, &key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der.clone()).unwrap();
        let client = Arc::new(
            ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        assert!(
            handshake(
                &client,
                ca.server_config("api.github.com").unwrap(),
                "api.github.com"
            )
            .is_ok()
        );
        assert!(
            handshake(
                &client,
                ca.server_config("example.com").unwrap(),
                "api.github.com"
            )
            .is_err()
        );
        assert!(Arc::ptr_eq(
            &ca.server_config("api.github.com").unwrap(),
            &ca.server_config("api.github.com").unwrap()
        ));
    }

    fn handshake(
        client: &Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        name: &str,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let mut c = rustls::ClientConnection::new(Arc::clone(client), name)?;
        let mut s = rustls::ServerConnection::new(server)?;
        for _ in 0..10 {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets()?;
            let mut buf = Vec::new();
            s.write_tls(&mut buf).unwrap();
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets()?;
            if !c.is_handshaking() && !s.is_handshaking() {
                c.writer().write_all(b"hi").unwrap();
                let mut buf = Vec::new();
                c.write_tls(&mut buf).unwrap();
                s.read_tls(&mut &buf[..]).unwrap();
                s.process_new_packets()?;
                let mut got = [0; 2];
                s.reader().read_exact(&mut got).unwrap();
                assert_eq!(&got, b"hi");
                return Ok(());
            }
        }
        panic!("handshake did not finish");
    }
}

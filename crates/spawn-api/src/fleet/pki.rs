//! The fleet's own CA. It signs one certificate for the primary and one for
//! each worker. Fleet TLS trusts only this CA, and each side checks the
//! other's name: `primary` or the worker's node ID.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_name};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::secretbox::SecretBox;

pub const PRIMARY: &str = "primary";
const CA_NAME: &str = "Spawnbox fleet CA";
const CA_YEARS: i64 = 20;
const LEAF_YEARS: i64 = 5;
const CA_LABEL: &str = crate::secretbox::FLEET_CA_LABEL;
pub const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key";
pub const CERT_FILE: &str = "node.crt";
pub const KEY_FILE: &str = "node.key";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Hex SHA-256 of a certificate's DER bytes.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pem_der(pem: &str) -> Result<CertificateDer<'static>> {
    CertificateDer::from_pem_slice(pem.as_bytes()).context("parse a PEM certificate")
}

fn leaf_params(name: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec![name.to_owned()])?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * LEAF_YEARS);
    Ok(params)
}

pub struct FleetCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl FleetCa {
    /// Loads the CA from `dir`, or makes one. The key is kept encrypted with
    /// the secrets key.
    pub fn load_or_create(dir: &Path, sbox: &SecretBox) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (cert_path, key_path) = (dir.join(CA_CERT_FILE), dir.join(CA_KEY_FILE));
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {}
            (false, false) => {
                let key = KeyPair::generate()?;
                let mut params = CertificateParams::new(Vec::<String>::new())?;
                params.distinguished_name.push(DnType::CommonName, CA_NAME);
                params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
                params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
                let now = OffsetDateTime::now_utc();
                params.not_before = now - time::Duration::days(1);
                params.not_after = now + time::Duration::days(365 * CA_YEARS);
                let cert = params.self_signed(&key)?;
                let sealed = sbox.seal(CA_LABEL, key.serialize_pem().as_bytes())?;
                crate::secrets::write_new(&key_path, &sealed, 0o600)?;
                crate::secrets::write_new(&cert_path, cert.pem().as_bytes(), 0o644)?;
                eprintln!("created the fleet CA {}", cert_path.display());
            }
            _ => bail!(
                "found only one of {} and {}; restore or remove both",
                cert_path.display(),
                key_path.display()
            ),
        }
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key = sbox
            .open(CA_LABEL, &std::fs::read(&key_path)?)
            .and_then(|k| String::from_utf8(k).ok())
            .with_context(|| {
                format!("cannot decrypt {}: wrong secrets key?", key_path.display())
            })?;
        let key = KeyPair::from_pem(&key).context("parse the fleet CA key")?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key).context("parse the fleet CA")?;
        Ok(Self { cert_pem, issuer })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(fingerprint(&pem_der(&self.cert_pem)?))
    }

    /// Signs the key in `csr_pem` for `name`. Only the key is taken from the
    /// request; the name, usages and lifetime are set here.
    pub fn sign(&self, csr_pem: &str, name: &str) -> Result<String> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .context("the certificate request is not valid")?;
        let cert = leaf_params(name)?.signed_by(&csr.public_key, &self.issuer)?;
        Ok(cert.pem())
    }

    /// The primary's own identity, made once and kept in `dir`.
    pub fn primary_identity(&self, dir: &Path) -> Result<Identity> {
        if !Identity::exists(dir) {
            let key = KeyPair::generate()?;
            let cert = leaf_params(PRIMARY)?.signed_by(&key, &self.issuer)?;
            Identity::save(dir, &cert.pem(), &key.serialize_pem(), &self.cert_pem)?;
        }
        Identity::load(dir)
    }
}

/// A new key and a certificate request for it, as PEM.
pub fn new_request() -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let csr = CertificateParams::new(Vec::<String>::new())?.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

/// This host's fleet certificate and key, and the fleet CA.
#[derive(Clone)]
pub struct Identity {
    pub cert_pem: String,
    key_pem: String,
    pub ca_pem: String,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

impl Identity {
    pub fn exists(dir: &Path) -> bool {
        dir.join(CERT_FILE).exists()
    }

    /// The certificate is written last, so a half-done save is not taken
    /// for a done one. Files left by one are replaced.
    pub fn save(dir: &Path, cert_pem: &str, key_pem: &str, ca_pem: &str) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        for name in [KEY_FILE, CA_CERT_FILE] {
            let _ = std::fs::remove_file(dir.join(name));
        }
        crate::secrets::write_new(&dir.join(KEY_FILE), key_pem.as_bytes(), 0o600)?;
        if dir.join(CA_CERT_FILE) != dir.join(CERT_FILE) {
            crate::secrets::write_new(&dir.join(CA_CERT_FILE), ca_pem.as_bytes(), 0o644)?;
        }
        crate::secrets::write_new(&dir.join(CERT_FILE), cert_pem.as_bytes(), 0o644)
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .with_context(|| format!("read {}", dir.join(name).display()))
        };
        Ok(Self {
            cert_pem: read(CERT_FILE)?,
            key_pem: read(KEY_FILE)?,
            ca_pem: read(CA_CERT_FILE)?,
        })
    }

    fn chain(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let certs = vec![pem_der(&self.cert_pem)?, pem_der(&self.ca_pem)?];
        let key = PrivateKeyDer::from_pem_slice(self.key_pem.as_bytes())
            .context("parse the fleet key")?;
        Ok((certs, key))
    }

    fn roots(&self) -> Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(pem_der(&self.ca_pem)?)?;
        Ok(roots)
    }

    /// Server side. With `peer`, a client must show a fleet certificate for
    /// that name. Without, a client certificate is optional (for the join
    /// call) and handlers check it with `Peer::is`.
    pub fn server_config(&self, peer: Option<&str>) -> Result<Arc<ServerConfig>> {
        self.server_with(peer, peer.is_some())
    }

    /// Server side: a client must show a fleet certificate, for any name.
    /// Handlers check the name with `Peer::is`.
    pub fn server_config_any(&self) -> Result<Arc<ServerConfig>> {
        self.server_with(None, true)
    }

    fn server_with(&self, peer: Option<&str>, required: bool) -> Result<Arc<ServerConfig>> {
        let provider = provider();
        let builder =
            WebPkiClientVerifier::builder_with_provider(Arc::new(self.roots()?), provider.clone());
        let inner = if required {
            builder.build()?
        } else {
            builder.allow_unauthenticated().build()?
        };
        let verifier = Arc::new(NamedClient {
            inner,
            name: peer
                .map(|p| ServerName::try_from(p.to_owned()))
                .transpose()?,
        });
        let (certs, key) = self.chain()?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// Client side: shows this identity and accepts only a server with a
    /// fleet certificate for `peer`, whatever address it is reached at.
    pub fn client_config(&self, peer: &str) -> Result<ClientConfig> {
        let provider = provider();
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(self.roots()?), provider.clone())
                .build()?;
        let verifier = Arc::new(NamedServer {
            inner,
            name: ServerName::try_from(peer.to_owned())?,
        });
        let (certs, key) = self.chain()?;
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certs, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Client config for joining: no client certificate yet. The server must
/// send a CA whose SHA-256 is `ca_sha256` and a certificate from it for
/// `primary`.
pub fn join_config(ca_sha256: &str) -> Result<ClientConfig> {
    let provider = provider();
    let verifier = Arc::new(Pinned {
        ca_sha256: ca_sha256.to_ascii_lowercase(),
        provider: provider.clone(),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The fleet certificate a TLS client showed, if any. Only certificates the
/// fleet CA signed get past the handshake.
#[derive(Clone, Default)]
pub struct Peer(pub Option<CertificateDer<'static>>);

impl Peer {
    /// Whether the certificate names `name`.
    pub fn is(&self, name: &str) -> bool {
        let (Some(der), Ok(name)) = (&self.0, ServerName::try_from(name)) else {
            return false;
        };
        ParsedCertificate::try_from(der).is_ok_and(|cert| verify_server_name(&cert, &name).is_ok())
    }
}

#[derive(Debug)]
struct NamedServer {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for NamedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct Pinned {
    ca_sha256: String,
    provider: Arc<CryptoProvider>,
}

fn general(error: impl fmt::Display) -> rustls::Error {
    rustls::Error::General(error.to_string())
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| fingerprint(c) == self.ca_sha256)
            .ok_or_else(|| general("the primary's fleet CA does not match --primary-ca-sha256"))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone().into_owned())?;
        let inner =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(general)?;
        NamedServer {
            inner,
            name: ServerName::try_from(PRIMARY).map_err(general)?,
        }
        .verify_server_cert(end_entity, &[], server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct NamedClient {
    inner: Arc<dyn ClientCertVerifier>,
    name: Option<ServerName<'static>>,
}

impl ClientCertVerifier for NamedClient {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        if let Some(name) = &self.name {
            verify_server_name(&ParsedCertificate::try_from(end_entity)?, name)?;
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("spawnbox-pki-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn signs_requests_for_the_given_name_only() {
        let dir = temp("sign");
        let sbox = SecretBox::new(&[7; 32]).unwrap();
        let ca = FleetCa::load_or_create(&dir, &sbox).unwrap();
        let again = FleetCa::load_or_create(&dir, &sbox).unwrap();
        assert_eq!(ca.cert_pem(), again.cert_pem());

        let (_, csr) = new_request().unwrap();
        let cert = ca.sign(&csr, "nod_abc").unwrap();
        let peer = Peer(Some(pem_der(&cert).unwrap()));
        assert!(peer.is("nod_abc"));
        assert!(!peer.is("nod_abd"));
        assert!(!peer.is(PRIMARY));
        assert!(!Peer::default().is("nod_abc"));
        assert!(ca.sign("not a request", "nod_abc").is_err());

        let primary = ca.primary_identity(&dir.join("primary")).unwrap();
        assert!(Peer(Some(pem_der(&primary.cert_pem).unwrap())).is(PRIMARY));
        assert!(primary.server_config(None).is_ok());
        assert!(primary.client_config("nod_abc").is_ok());
        assert!(join_config(&ca.fingerprint().unwrap()).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

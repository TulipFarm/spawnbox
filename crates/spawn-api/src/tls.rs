//! HTTPS for the API and preview listeners. Certificate files are re-read
//! when they change, so a renewal needs no restart.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use axum::Router;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// A slow or silent client gives up its handshake after this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RELOAD_EVERY: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct Files {
    /// PEM certificate chain, leaf first.
    pub cert: PathBuf,
    /// PEM private key.
    pub key: PathBuf,
}

/// A TCP listener, with TLS when certificate files are given.
pub enum Bound {
    Plain(TcpListener),
    Tls(Listener),
}

impl Bound {
    pub async fn bind(addr: SocketAddr, tls: Option<Files>) -> Result<Self> {
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("listen on {addr}"))?;
        Ok(match tls {
            None => Self::Plain(tcp),
            Some(files) => Self::Tls(Listener::start(tcp, files)?),
        })
    }

    pub fn url(&self, addr: SocketAddr) -> String {
        match self {
            Self::Plain(_) => format!("http://{addr}"),
            Self::Tls(_) => format!("https://{addr}"),
        }
    }

    pub async fn serve(
        self,
        router: Router,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => {
                axum::serve(tcp, router)
                    .with_graceful_shutdown(shutdown)
                    .await
            }
            Self::Tls(tls) => {
                axum::serve(tls, router)
                    .with_graceful_shutdown(shutdown)
                    .await
            }
        }
    }
}

/// Accepts TCP connections and runs each TLS handshake in its own task, so
/// one slow client cannot hold up the others.
pub struct Listener {
    accepted: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl Listener {
    fn start(tcp: TcpListener, files: Files) -> Result<Self> {
        let certs = Arc::new(Reloading::load(files)?);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&certs) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self::accept_loop(tcp, Arc::new(config), Some(certs))
    }

    /// With a fixed config, such as fleet mutual TLS.
    pub async fn bind(addr: SocketAddr, config: Arc<ServerConfig>) -> Result<Self> {
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("listen on {addr}"))?;
        Self::accept_loop(tcp, config, None)
    }

    fn accept_loop(
        tcp: TcpListener,
        config: Arc<ServerConfig>,
        certs: Option<Arc<Reloading>>,
    ) -> Result<Self> {
        let local = tcp.local_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let (tx, accepted) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut reload = tokio::time::interval(RELOAD_EVERY);
            loop {
                let (stream, peer) = tokio::select! {
                    () = tx.closed() => return,
                    _ = reload.tick() => {
                        if let Some(certs) = &certs {
                            certs.reload_if_changed();
                        }
                        continue;
                    }
                    accepted = tcp.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            // Out of file descriptors, most likely.
                            eprintln!("accept on {local}: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    },
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let handshake =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                    if let Ok(Ok(tls)) = handshake.await {
                        let _ = tx.send((tls, peer)).await;
                    }
                });
            }
        });
        Ok(Self { accepted, local })
    }
}

/// Handlers on a fleet listener get the client's certificate as `Peer`.
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, Listener>>
    for crate::fleet::pki::Peer
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        let cert = stream
            .io()
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.clone().into_owned());
        Self(cert)
    }
}

impl axum::serve::Listener for Listener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(accepted) => accepted,
            // The accept task ended: no more connections.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// When and how big each file was, to notice changes.
type Stamp = [(Option<SystemTime>, u64); 2];

#[derive(Debug)]
struct Reloading {
    files: Files,
    current: RwLock<(Arc<CertifiedKey>, Stamp)>,
}

impl Reloading {
    fn load(files: Files) -> Result<Self> {
        let stamp = stamp(&files);
        let key = read(&files)?;
        Ok(Self {
            files,
            current: RwLock::new((Arc::new(key), stamp)),
        })
    }

    /// Keeps the old certificate if the new files are not valid, for
    /// example while they are being written.
    fn reload_if_changed(&self) {
        let stamp = stamp(&self.files);
        if self.current.read().is_ok_and(|current| current.1 == stamp) {
            return;
        }
        match read(&self.files) {
            Ok(key) => {
                if let Ok(mut current) = self.current.write() {
                    *current = (Arc::new(key), stamp);
                }
                eprintln!("loaded new certificate {}", self.files.cert.display());
            }
            Err(error) => eprintln!(
                "keeping the old certificate; {}: {error:#}",
                self.files.cert.display()
            ),
        }
    }
}

impl ResolvesServerCert for Reloading {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .ok()
            .map(|current| Arc::clone(&current.0))
    }
}

fn stamp(files: &Files) -> Stamp {
    [&files.cert, &files.key].map(|path| match std::fs::metadata(path) {
        Ok(meta) => (meta.modified().ok(), meta.len()),
        Err(_) => (None, 0),
    })
}

fn read(files: &Files) -> Result<CertifiedKey> {
    let cert_pem =
        std::fs::read(&files.cert).with_context(|| format!("read {}", files.cert.display()))?;
    let key_pem =
        std::fs::read(&files.key).with_context(|| format!("read {}", files.key.display()))?;
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{} is not a PEM certificate chain", files.cert.display()))?;
    if certs.is_empty() {
        bail!("{} has no certificate", files.cert.display());
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .with_context(|| format!("{} is not a PEM private key", files.key.display()))?;
    CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
        .context("the key does not match the certificate")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(dir: &std::path::Path, name: &str) -> Files {
        let cert = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let files = Files {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        };
        std::fs::write(&files.cert, cert.cert.pem()).unwrap();
        std::fs::write(&files.key, cert.signing_key.serialize_pem()).unwrap();
        files
    }

    fn leaf(certs: &Reloading) -> Vec<u8> {
        certs.current.read().unwrap().0.cert[0].to_vec()
    }

    #[test]
    fn reloads_changed_files_and_keeps_good_ones() {
        let dir = std::env::temp_dir().join(format!("spawnbox-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let files = write_pair(&dir, "a.test");
        let certs = Reloading::load(files.clone()).unwrap();
        let first = leaf(&certs);

        certs.reload_if_changed();
        assert_eq!(leaf(&certs), first);

        write_pair(&dir, "b.test");
        certs.reload_if_changed();
        let second = leaf(&certs);
        assert_ne!(second, first);

        std::fs::write(&files.key, "not a key").unwrap();
        certs.reload_if_changed();
        assert_eq!(leaf(&certs), second);

        let other = rcgen::generate_simple_self_signed(vec!["c.test".to_owned()]).unwrap();
        std::fs::write(&files.key, other.signing_key.serialize_pem()).unwrap();
        assert!(read(&files).is_err(), "a key for another certificate");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

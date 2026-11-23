//! TLS connections to mail servers (IMAP and SMTP), with rustls: the same TLS library and
//! crypto (ring) as the HTTPS requests to Gmail, and Mozilla's root certificates.
//!
//! Certificates are always checked, against the host name asked for. There is no setting
//! to turn that off.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::mail::Offline;

/// How long a connection may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a server may stay silent once it is connected.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

fn config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            // Development builds only: one more root (a test server's own CA) from
            // NIMBRA_TEST_CA. A release build has no way to trust anything else.
            #[cfg(debug_assertions)]
            if let Some(path) = std::env::var_os("NIMBRA_TEST_CA") {
                use rustls::pki_types::CertificateDer;
                use rustls::pki_types::pem::PemObject as _;
                if let Ok(certs) = CertificateDer::pem_file_iter(&path) {
                    for cert in certs.flatten() {
                        let _ = roots.add(cert);
                    }
                }
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Arc::new(
                ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("ring supports the default TLS versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// A plain TCP connection, with timeouts. Not being able to reach the server at all is
/// `Offline`: no network, most likely (or a wrong host, which setting up an account checks).
pub fn tcp(host: &str, port: u16) -> Result<TcpStream> {
    if !crate::servers::is_host(host) {
        bail!("unexpected server name");
    }
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|_| anyhow!(Offline))
        .with_context(|| format!("looking up {host}"))?
        .collect();
    let mut last = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(anyhow!(Offline)).context(format!(
        "connecting to {host}:{port}{}",
        last.map(|e| format!(" ({e})")).unwrap_or_default()
    ))
}

/// Makes a connection secure: the TLS handshake, done now so that a certificate that does
/// not check out is said at once rather than on the first read.
pub fn upgrade(tcp: TcpStream, host: &str) -> Result<TlsStream> {
    let name = ServerName::try_from(host.to_string()).context("unexpected server name")?;
    let connection = ClientConnection::new(config(), name)?;
    let mut stream = StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        if let Err(error) = stream.conn.complete_io(&mut stream.sock) {
            return Err(handshake_error(error, host));
        }
    }
    Ok(stream)
}

/// TLS from the first byte.
pub fn connect(host: &str, port: u16) -> Result<TlsStream> {
    upgrade(tcp(host, port)?, host)
}

fn handshake_error(error: io::Error, host: &str) -> anyhow::Error {
    let tls = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match tls {
        Some(rustls::Error::InvalidCertificate(why)) => anyhow!(
            "{host}’s certificate could not be verified ({why:?}), so Nimbra did not connect."
        ),
        Some(other) => anyhow!("A secure connection to {host} could not be made ({other})."),
        None => anyhow!(Offline).context(format!("connecting securely to {host}: {error}")),
    }
}

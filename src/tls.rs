//! TLS configuration for both inbound (termination) and outbound (origination).
//!
//! Provides helpers to load PEM-encoded certificates and private keys from
//! disk and to construct [`rustls::ServerConfig`] and
//! [`hyper_rustls::HttpsConnector`] instances for the proxy's two TLS roles:
//!
//! - **Termination (client -> proxy):** Accepts HTTPS connections using a
//!   locally loaded certificate chain and private key.
//! - **Origination (proxy -> upstream):** Initiates HTTPS connections to
//!   upstream backends using the platform root certificate store.

use std::io::BufReader;
use std::sync::Arc;

use hyper_rustls::HttpsConnectorBuilder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::{ProxyError, Result, TlsConfig};

/// Builds a [`TlsAcceptor`] from the given TLS configuration.
///
/// Loads the PEM-encoded certificate chain and private key from the paths
/// specified in `config`, constructs a [`rustls::ServerConfig`] with safe
/// defaults (no client authentication), and wraps it in a
/// [`TlsAcceptor`] suitable for use with [`tokio::net::TcpListener`].
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(format!("failed to build TLS server config: {e}")))?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Builds an HTTPS connector for outbound connections to upstream backends.
///
/// Uses the Mozilla root certificate store via [`webpki_roots`] for server
/// verification. The resulting connector supports both `http://` and
/// `https://` schemes; plain HTTP connections pass through unmodified.
pub fn build_https_connector()
-> hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build()
}

/// Loads PEM-encoded X.509 certificates from the file at `path`.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| ProxyError::Tls(format!("failed to open cert file {path}: {e}")))?;

    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ProxyError::Tls(format!("failed to parse certificates from {path}: {e}")))
}

/// Loads the first PEM-encoded private key from the file at `path`.
///
/// Supports PKCS#1 (RSA), PKCS#8, and SEC1 (EC) key formats.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| ProxyError::Tls(format!("failed to open key file {path}: {e}")))?;

    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)
            .map_err(|e| ProxyError::Tls(format!("failed to parse key from {path}: {e}")))?
        {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            Some(_) => continue,
            None => {
                return Err(ProxyError::Tls(format!("no private key found in {path}")));
            }
        }
    }
}

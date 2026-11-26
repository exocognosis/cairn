//! Server-side TLS for the client-facing endpoint. Callers authenticate another way (every
//! KMS request carries an AWS SigV4 signature), so no client certificate is asked for.

use rustls::ServerConfig;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

fn invalid(what: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string())
}

/// Server-side TLS for a hop whose callers authenticate another way: the KMS endpoint, where
/// every request carries an AWS SigV4 signature. No client certificate is asked for.
pub struct ServerTls {
    acceptor: TlsAcceptor,
}

impl ServerTls {
    /// A self-signed certificate for the given host names or IP addresses, as (cert, key)
    /// PEM. The caller trusts the certificate itself; there is no CA to protect.
    pub fn self_signed(hosts: &[String]) -> std::io::Result<(String, String)> {
        let key = rcgen::KeyPair::generate().map_err(invalid)?;
        let mut params = rcgen::CertificateParams::new(hosts.to_vec()).map_err(invalid)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "cairn kms endpoint");
        let cert = params.self_signed(&key).map_err(invalid)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> std::io::Result<Self> {
        let chain =
            rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        if chain.is_empty() {
            return Err(invalid("no certificate in PEM"));
        }
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
            .ok_or_else(|| invalid("no private key in PEM"))?;
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(invalid)?
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .map_err(invalid)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub fn load(cert: &Path, key: &Path) -> std::io::Result<Self> {
        let read = |p: &Path| {
            std::fs::read_to_string(p)
                .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", p.display())))
        };
        Self::from_pem(&read(cert)?, &read(key)?)
    }

    /// Accept TLS connections on `listener` and relay each one's plaintext to `backend`.
    /// Runs until the task is dropped.
    pub async fn terminate(self, listener: tokio::net::TcpListener, backend: std::net::SocketAddr) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            };
            let acceptor = self.acceptor.clone();
            tokio::spawn(async move {
                let handshake = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    acceptor.accept(stream),
                );
                let Ok(Ok(mut tls)) = handshake.await else {
                    return;
                };
                let Ok(mut inner) = tokio::net::TcpStream::connect(backend).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut inner).await;
            });
        }
    }
}

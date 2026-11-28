//! Server-side TLS for the client-facing endpoint. Callers authenticate another way (every
//! KMS request carries an AWS SigV4 signature), so no client certificate is asked for.

use rustls::ServerConfig;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Most connections the front holds open at once, and most from one client address. One
/// client opening connections and leaving them idle cannot use up the endpoint for the rest.
pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_PER_CLIENT: usize = 32;

type Open = Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>;

/// One open connection's place in the count; gives it back when dropped.
struct Slot {
    open: Open,
    who: std::net::IpAddr,
}

impl Slot {
    fn take(open: &Open, who: std::net::IpAddr) -> Option<Self> {
        let mut counts = open.lock().unwrap_or_else(|e| e.into_inner());
        if counts.values().sum::<usize>() >= MAX_CONNECTIONS
            || counts.get(&who).copied().unwrap_or(0) >= MAX_PER_CLIENT
        {
            return None;
        }
        *counts.entry(who).or_insert(0) += 1;
        Some(Self {
            open: open.clone(),
            who,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.who) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.who);
            }
        }
    }
}

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
        let open: Open = Arc::default();
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            };
            // Over the limit: closed at once, before any TLS work is done for it.
            let Some(slot) = Slot::take(&open, peer.ip()) else {
                continue;
            };
            let acceptor = self.acceptor.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let handshake = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    acceptor.accept(stream),
                );
                let Ok(Ok(tls)) = handshake.await else {
                    return;
                };
                let Ok(mut inner) = tokio::net::TcpStream::connect(backend).await else {
                    return;
                };
                // The server behind closes a connection that is silent for 10 seconds; when
                // it does, or when the client is done, this side closes too. Waiting for both
                // directions to end would let a client hold the connection open by itself.
                let (mut from_client, mut to_client) = tokio::io::split(tls);
                let (mut from_server, mut to_server) = inner.split();
                let request = async {
                    use tokio::io::AsyncWriteExt;
                    let _ = tokio::io::copy(&mut from_client, &mut to_server).await;
                    let _ = to_server.shutdown().await;
                };
                let reply = tokio::io::copy(&mut from_server, &mut to_client);
                tokio::pin!(request, reply);
                tokio::select! {
                    _ = &mut request => {
                        // The client finished sending: let the reply through, briefly.
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            &mut reply,
                        )
                        .await;
                    }
                    _ = &mut reply => {}
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A front on a free port, relaying to a backend that answers `ok` to anything it is sent
    /// and closes a connection that says nothing for 300 ms. Returns the front's address and
    /// a TLS client configuration that trusts it.
    async fn front() -> (std::net::SocketAddr, tokio_rustls::TlsConnector) {
        let (cert, key) = ServerTls::self_signed(&["localhost".to_owned()]).unwrap();
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 64];
                    let read =
                        tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buffer));
                    if let Ok(Ok(n)) = read.await {
                        if n > 0 {
                            let _ = stream.write_all(b"ok").await;
                        }
                    }
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = ServerTls::from_pem(&cert, &key).unwrap();
        tokio::spawn(tls.terminate(listener, backend_addr));
        let mut roots = rustls::RootCertStore::empty();
        for der in rustls_pemfile::certs(&mut cert.as_bytes()) {
            roots.add(der.unwrap()).unwrap();
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        (addr, tokio_rustls::TlsConnector::from(Arc::new(config)))
    }

    async fn ask(addr: std::net::SocketAddr, connector: &tokio_rustls::TlsConnector) -> Vec<u8> {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut reply = Vec::new();
        if let Ok(mut tls) = connector.connect(name, tcp).await {
            let _ = tls.write_all(b"hello").await;
            let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut reply)).await;
        }
        reply
    }

    #[tokio::test]
    async fn a_client_that_goes_silent_after_the_handshake_is_closed() {
        let (addr, connector) = front().await;
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut silent = connector.connect(name, tcp).await.unwrap();
        // Nothing is sent. The server behind gives up on the connection, and the front then
        // closes its side too: it does not wait for the client to finish.
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(5), silent.read_to_end(&mut rest));
        assert!(
            closed.await.is_ok(),
            "the front kept a silent connection open"
        );
        assert_eq!(ask(addr, &connector).await, b"ok");
    }

    #[tokio::test]
    async fn one_client_cannot_hold_every_connection() {
        let (addr, connector) = front().await;
        // Connections that never start TLS: each is held until the handshake times out.
        let mut held = Vec::new();
        for _ in 0..MAX_PER_CLIENT {
            held.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            ask(addr, &connector).await.is_empty(),
            "a client over its limit was served"
        );
        // Its places come back when its connections end.
        drop(held);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(ask(addr, &connector).await, b"ok");
    }
}

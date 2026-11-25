//! Mutual TLS for node links, trusted by pinned certificate fingerprints.
//!
//! Every node holds a self-signed certificate that carries its identity as a DNS name
//! (`leaf-2-signer-3.cairn`, `root-1.cairn`, `party-2.cairn`, `coordinator.cairn`) and a table
//! `fingerprints.json` that says which certificate belongs to which node. There is no
//! certificate authority: a certificate is trusted because its fingerprint is in the table and
//! for no other reason. On every connection:
//!
//! * the caller checks that the server's certificate is pinned for the node it meant to reach;
//! * the server requires a client certificate pinned for some node, and the transport drops
//!   any frame whose `from` is not that node.
//!
//! The table is re-read when the file changes, and the transport checks it again on every
//! request, so removing a fingerprint cuts that certificate off without a restart
//! (revocation) and a node may have two fingerprints while it changes certificate (rotation).
//! `cairn keygen` writes certificates for a whole cluster; `cairn tls-rotate` lets a node make
//! its own, so no machine need ever hold another node's TLS key.
//!
//! TLS 1.3 only, `ring` provider.

use crate::wire::NodeId;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use threshold_mldsa::fips204;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// DNS name that identifies a node in its certificate.
pub fn dns_name(id: NodeId) -> String {
    match id {
        NodeId::Coordinator => "coordinator.cairn".into(),
        NodeId::Signer { leaf, signer } => format!("leaf-{leaf}-signer-{signer}.cairn"),
        NodeId::Root(k) => format!("root-{k}.cairn"),
        NodeId::Party(k) => format!("party-{k}.cairn"),
    }
}

fn file_stem(id: NodeId) -> String {
    id.to_string().replace('/', "_")
}

pub fn fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    fips204::shake256(&[b"cairn/tls-fingerprint/v1", cert_der], &mut out);
    out
}

fn invalid(what: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string())
}

/// A self-signed certificate and key for one node, in PEM.
fn self_signed(id: NodeId) -> std::io::Result<(String, String)> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate().map_err(invalid)?;
    let mut params = CertificateParams::new(vec![dns_name(id)]).map_err(invalid)?;
    params
        .distinguished_name
        .push(DnType::CommonName, id.to_string());
    let cert = params.self_signed(&key).map_err(invalid)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn write_key(path: &Path, key: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut f, key.as_bytes())
}

/// Certificates and keys for a whole cluster, in PEM.
pub struct ClusterTls {
    /// Per node: certificate and private key.
    pub nodes: BTreeMap<NodeId, (String, String)>,
}

impl ClusterTls {
    /// Create one self-signed certificate per node id.
    pub fn generate(ids: &[NodeId]) -> std::io::Result<Self> {
        let nodes = ids
            .iter()
            .map(|id| Ok((*id, self_signed(*id)?)))
            .collect::<std::io::Result<_>>()?;
        Ok(Self { nodes })
    }

    /// Fingerprint table: which certificate is which node.
    pub fn fingerprints(&self) -> std::io::Result<BTreeMap<String, String>> {
        self.nodes
            .iter()
            .map(|(id, (cert, _))| {
                let der = first_cert(cert)?;
                Ok((id.to_string(), hex(&fingerprint(&der))))
            })
            .collect()
    }

    /// Write `fingerprints.json`, and per node `<id>.pem` and `<id>.key` (mode 0600).
    /// A node needs only the table and its own pair.
    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let table = serde_json::to_string_pretty(&self.fingerprints()?).map_err(invalid)?;
        std::fs::write(dir.join("fingerprints.json"), table)?;
        for (id, (cert, key)) in &self.nodes {
            std::fs::write(dir.join(format!("{}.pem", file_stem(*id))), cert)?;
            write_key(&dir.join(format!("{}.key", file_stem(*id))), key)?;
        }
        Ok(())
    }

    /// The TLS identity of one node, built from memory (tests, in-process clusters).
    pub fn identity(&self, id: NodeId) -> std::io::Result<TlsIdentity> {
        let (cert, key) = self
            .nodes
            .get(&id)
            .ok_or_else(|| invalid(format!("no certificate for {id}")))?;
        let table = serde_json::to_string(&self.fingerprints()?).map_err(invalid)?;
        TlsIdentity::from_pem(id, cert, key, Pins::fixed(parse_pins(&table)?))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    let bytes: Option<Vec<u8>> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect();
    bytes?.try_into().ok()
}

fn first_cert(pem: &str) -> std::io::Result<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| invalid("no certificate in PEM"))?
}

/// One node's entry in `fingerprints.json`: one fingerprint, or several while a certificate
/// is being replaced.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
enum Entry {
    One(String),
    Many(Vec<String>),
}

impl Entry {
    fn list(self) -> Vec<String> {
        match self {
            Entry::One(fp) => vec![fp],
            Entry::Many(fps) => fps,
        }
    }

    fn from_list(mut fps: Vec<String>) -> Self {
        if fps.len() == 1 {
            Entry::One(fps.remove(0))
        } else {
            Entry::Many(fps)
        }
    }
}

type Table = HashMap<[u8; 32], NodeId>;

fn parse_pins(text: &str) -> std::io::Result<Table> {
    let entries: BTreeMap<String, Entry> = serde_json::from_str(text).map_err(invalid)?;
    let mut table = Table::new();
    for (name, entry) in entries {
        let id: NodeId = name.parse().map_err(invalid)?;
        for fp in entry.list() {
            let fp = unhex(&fp).ok_or_else(|| invalid("bad fingerprint"))?;
            if table.insert(fp, id).is_some_and(|other| other != id) {
                return Err(invalid("one fingerprint pinned for two nodes"));
            }
        }
    }
    Ok(table)
}

/// The pinned fingerprints, re-read from disk when the file changes.
struct Pins {
    path: Option<PathBuf>,
    state: RwLock<(Option<SystemTime>, Table)>,
}

impl std::fmt::Debug for Pins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pins")
    }
}

impl Pins {
    fn fixed(table: Table) -> Arc<Self> {
        Arc::new(Self {
            path: None,
            state: RwLock::new((None, table)),
        })
    }

    fn file(path: PathBuf) -> std::io::Result<Arc<Self>> {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        Ok(Arc::new(Self {
            state: RwLock::new((modified, parse_pins(&text)?)),
            path: Some(path),
        }))
    }

    /// Pick up a changed file. A file that cannot be read or parsed (half written, say)
    /// leaves the table as it was; the next lookup tries again.
    fn refresh(&self) {
        let Some(path) = &self.path else { return };
        let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified()) else {
            return;
        };
        if self.state.read().expect("pins").0 == Some(modified) {
            return;
        }
        if let Some(table) = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| parse_pins(&text).ok())
        {
            *self.state.write().expect("pins") = (Some(modified), table);
        }
    }

    fn node(&self, cert: &[u8]) -> Option<NodeId> {
        self.refresh();
        self.state
            .read()
            .expect("pins")
            .1
            .get(&fingerprint(cert))
            .copied()
    }
}

/// Accepts a certificate if and only if it is pinned: as a server, for the node the caller
/// addressed; as a client, for any node. The handshake signature is checked as usual, so the
/// peer must hold the certificate's key.
#[derive(Debug)]
struct Pinned {
    pins: Arc<Pins>,
    algorithms: WebPkiSupportedAlgorithms,
}

fn refused(what: &str) -> rustls::Error {
    rustls::Error::General(what.into())
}

impl Pinned {
    fn tls13(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let node = self
            .pins
            .node(end_entity)
            .ok_or_else(|| refused("server certificate is not pinned"))?;
        match server_name {
            ServerName::DnsName(name) if name.as_ref() == dns_name(node) => {
                Ok(ServerCertVerified::assertion())
            }
            _ => Err(refused("server certificate is pinned for another node")),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(refused("TLS 1.3 only"))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.pins
            .node(end_entity)
            .map(|_| ClientCertVerified::assertion())
            .ok_or_else(|| refused("client certificate is not pinned"))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(refused("TLS 1.3 only"))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// One node's TLS configuration: how it proves who it is and how it recognises its peers.
pub struct TlsIdentity {
    pub id: NodeId,
    connector: TlsConnector,
    acceptor: TlsAcceptor,
    pins: Arc<Pins>,
    cert_der: Vec<u8>,
    signing: Arc<dyn rustls::sign::SigningKey>,
}

/// Prefix of everything signed outside the TLS handshake. A TLS 1.3 handshake signature
/// starts with 64 spaces, so the two can never be confused.
const ATTEST_DOMAIN: &[u8] = b"cairn/attest/v1\0";

impl TlsIdentity {
    /// Sign `statement` with this node's TLS key. Returns the certificate and the signature.
    pub fn attest(&self, statement: &[u8]) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        use rustls::SignatureScheme::{ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ED25519};
        let signer = self
            .signing
            .choose_scheme(&[ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ED25519])
            .ok_or_else(|| invalid("TLS key cannot sign statements"))?;
        let signature = signer
            .sign(&[ATTEST_DOMAIN, statement].concat())
            .map_err(invalid)?;
        Ok((self.cert_der.clone(), signature))
    }

    /// Did `node` sign `statement`? True only if `cert` is pinned for `node` in this node's
    /// own table right now and `signature` verifies under the certificate's key.
    pub fn attested_by(
        &self,
        node: NodeId,
        cert: &[u8],
        statement: &[u8],
        signature: &[u8],
    ) -> bool {
        if self.pins.node(cert) != Some(node) {
            return false;
        }
        let der = CertificateDer::from(cert);
        let Ok(parsed) = webpki::EndEntityCert::try_from(&der) else {
            return false;
        };
        let message = [ATTEST_DOMAIN, statement].concat();
        [
            webpki::ring::ECDSA_P256_SHA256,
            webpki::ring::ECDSA_P384_SHA384,
            webpki::ring::ED25519,
        ]
        .iter()
        .any(|algorithm| {
            parsed
                .verify_signature(*algorithm, &message, signature)
                .is_ok()
        })
    }

    fn from_pem(
        id: NodeId,
        cert_pem: &str,
        key_pem: &str,
        pins: Arc<Pins>,
    ) -> std::io::Result<Self> {
        let provider: Arc<CryptoProvider> = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(Pinned {
            pins: pins.clone(),
            algorithms: provider.signature_verification_algorithms,
        });
        let chain = vec![first_cert(cert_pem)?];
        let key = || -> std::io::Result<PrivateKeyDer<'static>> {
            rustls_pemfile::private_key(&mut key_pem.as_bytes())?
                .ok_or_else(|| invalid("no private key in PEM"))
        };
        let cert_der = chain[0].to_vec();
        let signing = rustls::crypto::ring::sign::any_supported_type(&key()?).map_err(invalid)?;
        let versions = &[&rustls::version::TLS13];
        let client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(invalid)?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_client_auth_cert(chain.clone(), key()?)
            .map_err(invalid)?;
        let server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(invalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key()?)
            .map_err(invalid)?;
        Ok(Self {
            id,
            connector: TlsConnector::from(Arc::new(client)),
            acceptor: TlsAcceptor::from(Arc::new(server)),
            pins,
            cert_der,
            signing,
        })
    }

    /// Load a node's identity from a directory written by [`ClusterTls::write`] or
    /// [`rotate`]. The fingerprint table is followed on disk from then on.
    pub fn load(dir: &Path, id: NodeId) -> std::io::Result<Self> {
        let read = |name: String| {
            std::fs::read_to_string(dir.join(&name))
                .map_err(|e| std::io::Error::new(e.kind(), format!("{name}: {e}")))
        };
        Self::from_pem(
            id,
            &read(format!("{}.pem", file_stem(id)))?,
            &read(format!("{}.key", file_stem(id)))?,
            Pins::file(dir.join("fingerprints.json"))?,
        )
    }

    pub(crate) fn connector(&self) -> &TlsConnector {
        &self.connector
    }

    pub(crate) fn acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }

    pub(crate) fn server_name(to: NodeId) -> ServerName<'static> {
        ServerName::try_from(dns_name(to)).expect("node names are valid DNS names")
    }

    /// Which node this certificate is pinned for right now, if any.
    pub(crate) fn peer(&self, certs: Option<&[CertificateDer<'_>]>) -> Option<NodeId> {
        self.pins.node(certs?.first()?)
    }
}

fn read_entries(dir: &Path) -> std::io::Result<BTreeMap<String, Vec<String>>> {
    let path = dir.join("fingerprints.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e),
    };
    let entries: BTreeMap<String, Entry> = serde_json::from_str(&text).map_err(invalid)?;
    Ok(entries.into_iter().map(|(k, v)| (k, v.list())).collect())
}

/// Replace the table in one step, so a running node never reads half a file.
fn write_entries(dir: &Path, entries: BTreeMap<String, Vec<String>>) -> std::io::Result<()> {
    let entries: BTreeMap<String, Entry> = entries
        .into_iter()
        .filter(|(_, fps)| !fps.is_empty())
        .map(|(k, fps)| (k, Entry::from_list(fps)))
        .collect();
    let text = serde_json::to_string_pretty(&entries).map_err(invalid)?;
    parse_pins(&text)?;
    let tmp = dir.join("fingerprints.json.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(tmp, dir.join("fingerprints.json"))
}

/// Trust `fingerprint` as a certificate of `id`, in addition to any already pinned.
pub fn pin(dir: &Path, id: NodeId, fingerprint: &str) -> std::io::Result<()> {
    let fingerprint = fingerprint.trim().to_lowercase();
    unhex(&fingerprint).ok_or_else(|| invalid("a fingerprint is 64 hex characters"))?;
    let mut entries = read_entries(dir)?;
    let fps = entries.entry(id.to_string()).or_default();
    if !fps.contains(&fingerprint) {
        fps.push(fingerprint);
    }
    write_entries(dir, entries)
}

/// Stop trusting one certificate of `id`, or all of them. Returns how many were removed.
pub fn unpin(dir: &Path, id: NodeId, fingerprint: Option<&str>) -> std::io::Result<usize> {
    let fingerprint = fingerprint.map(|f| f.trim().to_lowercase());
    let mut entries = read_entries(dir)?;
    let fps = entries.entry(id.to_string()).or_default();
    let before = fps.len();
    fps.retain(|fp| fingerprint.as_ref().is_some_and(|f| f != fp));
    let removed = before - fps.len();
    write_entries(dir, entries)?;
    Ok(removed)
}

/// Give `id` a new key and self-signed certificate in `dir`, made on this machine, and pin it
/// in this directory's own table in place of the old one. The previous pair is kept as
/// `<id>.pem.old` / `<id>.key.old`. Returns the old fingerprint, if there was one, and the new.
/// A running node keeps its old certificate until it is restarted.
pub fn rotate(dir: &Path, id: NodeId) -> std::io::Result<(Option<String>, String)> {
    std::fs::create_dir_all(dir)?;
    let (cert_path, key_path) = (
        dir.join(format!("{}.pem", file_stem(id))),
        dir.join(format!("{}.key", file_stem(id))),
    );
    let old = match std::fs::read_to_string(&cert_path) {
        Ok(pem) => Some(hex(&fingerprint(&first_cert(&pem)?))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let (cert, key) = self_signed(id)?;
    let new = hex(&fingerprint(&first_cert(&cert)?));
    if old.is_some() {
        std::fs::rename(&cert_path, cert_path.with_extension("pem.old"))?;
        if key_path.exists() {
            std::fs::rename(&key_path, key_path.with_extension("key.old"))?;
        }
    }
    write_key(&key_path, &key)?;
    std::fs::write(&cert_path, cert)?;
    let mut entries = read_entries(dir)?;
    let fps = entries.entry(id.to_string()).or_default();
    fps.retain(|fp| Some(fp) != old.as_ref());
    fps.push(new.clone());
    write_entries(dir, entries)?;
    Ok((old, new))
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

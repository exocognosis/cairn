//! Mutual TLS for node links.
//!
//! `cairn keygen` creates one cluster CA and one certificate per node. A node's certificate
//! carries its identity as a DNS name (`leaf-2-signer-3.cairn`, `root-1.cairn`,
//! `coordinator.cairn`). On every connection:
//!
//! * the caller verifies that the server's certificate chains to the cluster CA and is the
//!   certificate of the node it meant to reach (standard server-name verification);
//! * the server requires a client certificate chaining to the cluster CA and maps it to a
//!   [`NodeId`] through a pinned fingerprint table, and the transport drops any frame whose
//!   `from` is not that node.
//!
//! TLS 1.3 only, `ring` provider. The CA key is used once, at key generation, and is not kept.

use crate::wire::NodeId;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
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

/// Certificates and keys for a whole cluster, in PEM.
pub struct ClusterTls {
    pub ca_pem: String,
    /// Per node: certificate and private key.
    pub nodes: BTreeMap<NodeId, (String, String)>,
}

impl ClusterTls {
    /// Create a CA and one certificate per node id.
    pub fn generate(ids: &[NodeId]) -> std::io::Result<Self> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
        let ca_key = KeyPair::generate().map_err(invalid)?;
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(invalid)?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "cairn cluster CA");
        let ca = ca_params.self_signed(&ca_key).map_err(invalid)?;
        let mut nodes = BTreeMap::new();
        for id in ids {
            let key = KeyPair::generate().map_err(invalid)?;
            let mut params = CertificateParams::new(vec![dns_name(*id)]).map_err(invalid)?;
            params
                .distinguished_name
                .push(DnType::CommonName, id.to_string());
            let cert = params.signed_by(&key, &ca, &ca_key).map_err(invalid)?;
            nodes.insert(*id, (cert.pem(), key.serialize_pem()));
        }
        Ok(Self {
            ca_pem: ca.pem(),
            nodes,
        })
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

    /// Write `ca.pem`, `fingerprints.json`, and per node `<id>.pem` and `<id>.key` (mode 0600).
    /// A node needs only the first two and its own pair.
    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), &self.ca_pem)?;
        let table = serde_json::to_string_pretty(&self.fingerprints()?).map_err(invalid)?;
        std::fs::write(dir.join("fingerprints.json"), table)?;
        for (id, (cert, key)) in &self.nodes {
            std::fs::write(dir.join(format!("{}.pem", file_stem(*id))), cert)?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(format!("{}.key", file_stem(*id))))?;
            std::io::Write::write_all(&mut f, key.as_bytes())?;
        }
        Ok(())
    }

    /// The TLS identity of one node, built from memory (tests, in-process clusters).
    pub fn identity(&self, id: NodeId) -> std::io::Result<TlsIdentity> {
        let (cert, key) = self
            .nodes
            .get(&id)
            .ok_or_else(|| invalid(format!("no certificate for {id}")))?;
        TlsIdentity::from_pem(id, &self.ca_pem, cert, key, &self.fingerprints()?)
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

/// One node's TLS configuration: how it proves who it is and how it recognises its peers.
pub struct TlsIdentity {
    pub id: NodeId,
    connector: TlsConnector,
    acceptor: TlsAcceptor,
    known: HashMap<[u8; 32], NodeId>,
}

impl TlsIdentity {
    pub fn from_pem(
        id: NodeId,
        ca_pem: &str,
        cert_pem: &str,
        key_pem: &str,
        fingerprints: &BTreeMap<String, String>,
    ) -> std::io::Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(first_cert(ca_pem)?).map_err(invalid)?;
        let roots = Arc::new(roots);
        let chain = vec![first_cert(cert_pem)?];
        let key = || -> std::io::Result<PrivateKeyDer<'static>> {
            rustls_pemfile::private_key(&mut key_pem.as_bytes())?
                .ok_or_else(|| invalid("no private key in PEM"))
        };
        let versions = &[&rustls::version::TLS13];
        let client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(invalid)?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(chain.clone(), key()?)
            .map_err(invalid)?;
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
                .build()
                .map_err(invalid)?;
        let server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(invalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key()?)
            .map_err(invalid)?;
        let known = fingerprints
            .iter()
            .map(|(name, fp)| {
                Ok((
                    unhex(fp).ok_or_else(|| invalid("bad fingerprint"))?,
                    name.parse().map_err(invalid)?,
                ))
            })
            .collect::<std::io::Result<_>>()?;
        Ok(Self {
            id,
            connector: TlsConnector::from(Arc::new(client)),
            acceptor: TlsAcceptor::from(Arc::new(server)),
            known,
        })
    }

    /// Load a node's identity from a directory written by [`ClusterTls::write`].
    pub fn load(dir: &Path, id: NodeId) -> std::io::Result<Self> {
        let read = |name: String| {
            std::fs::read_to_string(dir.join(&name))
                .map_err(|e| std::io::Error::new(e.kind(), format!("{name}: {e}")))
        };
        let fingerprints: BTreeMap<String, String> =
            serde_json::from_str(&read("fingerprints.json".into())?).map_err(invalid)?;
        Self::from_pem(
            id,
            &read("ca.pem".into())?,
            &read(format!("{}.pem", file_stem(id)))?,
            &read(format!("{}.key", file_stem(id)))?,
            &fingerprints,
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

    /// Which node presented this certificate, if it is one of the cluster's.
    pub(crate) fn peer(&self, certs: Option<&[CertificateDer<'_>]>) -> Option<NodeId> {
        self.known.get(&fingerprint(certs?.first()?)).copied()
    }
}

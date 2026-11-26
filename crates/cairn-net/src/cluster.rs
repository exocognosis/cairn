//! Address books, key files and an in-process cluster.

use crate::node::{FaultMode, Peers, RootNode, SignerNode};
use crate::tls::{ClusterTls, TlsIdentity};
use crate::transport::{serve, Link};
use crate::wire::NodeId;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use threshold_mldsa::{deal, Gadget, GroupPublic, KeyShare};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Number of root engine nodes a default cluster runs (three active, one spare).
pub const ROOT_ENGINES: u8 = 4;

/// Parse an address book: a JSON object `{"leaf_1/signer_1": "host:port", ...}` or the inline
/// form `leaf_1/signer_1=host:port,root_1=host:port`.
pub fn parse_peers(text: &str) -> Result<Peers, String> {
    let text = text.trim();
    let pairs: Vec<(String, String)> = if text.starts_with('{') {
        let map: BTreeMap<String, String> =
            serde_json::from_str(text).map_err(|e| format!("peers: {e}"))?;
        map.into_iter().collect()
    } else {
        text.split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|pair| {
                pair.trim()
                    .split_once('=')
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .ok_or(format!("peers: expected id=addr, got {pair:?}"))
            })
            .collect::<Result<_, _>>()?
    };
    pairs
        .into_iter()
        .map(|(id, addr)| Ok((id.parse::<NodeId>()?, addr)))
        .collect()
}

pub fn peers_to_json(peers: &Peers) -> String {
    let map: BTreeMap<String, &String> = peers
        .iter()
        .map(|(id, addr)| (id.to_string(), addr))
        .collect();
    serde_json::to_string_pretty(&map).expect("address book encodes")
}

/// Every node id of a two-tier tower, signers first.
pub fn node_ids(shape: &[Gadget]) -> Vec<NodeId> {
    let mut ids = Vec::new();
    for leaf in 1..=shape[0].n {
        for signer in 1..=shape[1].n {
            ids.push(NodeId::Signer { leaf, signer });
        }
    }
    ids.extend((1..=ROOT_ENGINES).map(NodeId::Root));
    ids
}

/// Consecutive ports on one host, in [`node_ids`] order.
pub fn local_peers(shape: &[Gadget], host: &str, base_port: u16) -> Peers {
    node_ids(shape)
        .into_iter()
        .enumerate()
        .map(|(i, id)| (id, format!("{host}:{}", base_port + i as u16)))
        .collect()
}

pub fn share_file(dir: &Path, id: NodeId) -> PathBuf {
    dir.join(format!("{}.share", id.to_string().replace('/', "_")))
}

/// Write `group.bin`, one share file per signer (mode 0600), and under `dir/tls` a cluster CA
/// with one certificate per node and one for the coordinator.
pub fn write_keys(dir: &Path, group: &GroupPublic, shares: &[KeyShare]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("group.bin"), group.to_bytes())?;
    let mut ids = node_ids(&group.shape);
    ids.push(NodeId::Coordinator);
    ClusterTls::generate(&ids)?.write(&dir.join("tls"))?;
    for share in shares {
        let id = NodeId::from_path(&share.path)
            .ok_or_else(|| std::io::Error::other("not a two-tier share"))?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(share_file(dir, id))?;
        std::io::Write::write_all(&mut f, &share.to_bytes())?;
    }
    Ok(())
}

pub fn read_group(path: &Path) -> std::io::Result<GroupPublic> {
    GroupPublic::from_bytes(&std::fs::read(path)?)
        .ok_or_else(|| std::io::Error::other("malformed group file"))
}

pub fn read_share(path: &Path) -> std::io::Result<KeyShare> {
    KeyShare::from_bytes(&std::fs::read(path)?)
        .ok_or_else(|| std::io::Error::other("malformed share file"))
}

/// Run a signer node on `listener` until the task is dropped.
pub async fn run_signer(listener: TcpListener, node: SignerNode, delay: Duration) {
    let tls = node.link.tls.clone();
    serve(listener, Arc::new(node), delay, tls).await
}

pub async fn run_root(
    listener: TcpListener,
    node: RootNode,
    delay: Duration,
    tls: Arc<TlsIdentity>,
) {
    serve(listener, Arc::new(node), delay, tls).await
}

/// A whole cluster inside this process: real TCP listeners on loopback, every node a task, and
/// the reference MPC worker on real Unix sockets. For tests; processes are separate in
/// `cairn node` deployments.
pub struct LocalCluster {
    pub group: Arc<GroupPublic>,
    pub peers: Peers,
    tls: ClusterTls,
    tasks: Vec<JoinHandle<()>>,
    _worker: mpc_bridge::Worker,
}

impl LocalCluster {
    /// Deal a 3-of-4 x 3-of-4 tower from `seed` and start 16 signers and 4 root engines.
    /// `delay` is the injected one-way latency on every node's links.
    pub async fn start(
        seed: &[u8; 32],
        faults: &[(NodeId, FaultMode)],
        round_timeout: Duration,
        delay: Duration,
    ) -> std::io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let shape = [
            Gadget::new(3, 4).expect("shape"),
            Gadget::new(3, 4).expect("shape"),
        ];
        let (group, shares) = deal(seed, &shape, &mut OsRng).map_err(std::io::Error::other)?;
        let group = Arc::new(group);
        let socket_dir = std::env::temp_dir().join(format!(
            "cn-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let worker = mpc_bridge::serve(&socket_dir, Duration::from_secs(30))?;

        let mut listeners = Vec::new();
        let mut peers = Peers::new();
        for id in node_ids(&shape) {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            peers.insert(id, listener.local_addr()?.to_string());
            listeners.push((id, listener));
        }
        let fault = |id: NodeId| {
            faults
                .iter()
                .find(|(f, _)| *f == id)
                .map(|(_, m)| *m)
                .unwrap_or_default()
        };
        let mut ids = node_ids(&shape);
        ids.push(NodeId::Coordinator);
        let tls = ClusterTls::generate(&ids)?;
        let mut shares: BTreeMap<NodeId, KeyShare> = shares
            .into_iter()
            .filter_map(|s| Some((NodeId::from_path(&s.path)?, s)))
            .collect();
        let mut tasks = Vec::new();
        for (id, listener) in listeners {
            tasks.push(match shares.remove(&id) {
                Some(share) => {
                    let node = SignerNode {
                        id,
                        group: group.clone(),
                        share,
                        peers: peers.clone(),
                        link: Link::new(round_timeout, delay, Arc::new(tls.identity(id)?)),
                        fault: fault(id),
                        policy: crate::node::default_policy(),
                        approved: Default::default(),
                    };
                    tokio::spawn(run_signer(listener, node, delay))
                }
                None => {
                    let node = RootNode::new(
                        id,
                        group.clone(),
                        fault(id),
                        socket_dir.clone(),
                        Duration::from_secs(30),
                    );
                    tokio::spawn(run_root(listener, node, delay, Arc::new(tls.identity(id)?)))
                }
            });
        }
        Ok(Self {
            group,
            peers,
            tls,
            tasks,
            _worker: worker,
        })
    }

    /// TLS identity of any node of this cluster (the coordinator's, or one to impersonate with).
    pub fn identity(&self, id: NodeId) -> Arc<TlsIdentity> {
        Arc::new(self.tls.identity(id).expect("cluster certificate"))
    }

    /// Take a node off the network (its port stops answering).
    pub fn kill(&mut self, id: NodeId) {
        if let Some(pos) = self.peers.keys().position(|k| *k == id) {
            self.tasks[pos].abort();
        }
    }
}

impl Drop for LocalCluster {
    fn drop(&mut self) {
        self.tasks.iter().for_each(JoinHandle::abort);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_books_parse_in_both_forms() {
        let shape = [Gadget::new(3, 4).unwrap(), Gadget::new(3, 4).unwrap()];
        let peers = local_peers(&shape, "127.0.0.1", 7100);
        assert_eq!(peers.len(), 20);
        assert_eq!(
            peers[&NodeId::Signer { leaf: 1, signer: 1 }],
            "127.0.0.1:7100"
        );
        assert_eq!(peers[&NodeId::Root(4)], "127.0.0.1:7119");
        assert_eq!(parse_peers(&peers_to_json(&peers)).unwrap(), peers);
        let inline = parse_peers("leaf_2/signer_3=10.0.0.2:7000, root_1=10.0.0.9:7200").unwrap();
        assert_eq!(inline[&NodeId::Root(1)], "10.0.0.9:7200");
        assert!(parse_peers("nonsense").is_err());
    }
}

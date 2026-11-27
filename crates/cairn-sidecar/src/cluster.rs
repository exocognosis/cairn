//! Running the tower as separate OS processes: the cluster-backed KMS signer, a process
//! launcher for tests and benchmarks, and a minimal CometBFT RPC stand-in.

use cairn_core::{Backend, SignerError, ThresholdSigner};
use cairn_net::cluster::{node_ids, peers_to_json, share_file, write_keys};
use cairn_net::{Coordinator, FaultMode, NetPolicy, NetReport, NodeId, Peers, TlsIdentity};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::io::Read as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use threshold_mldsa::{deal, Gadget, GroupPublic, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

/// Signs by coordinating a TCP cluster. Owns a runtime so it can sit behind the blocking KMS
/// endpoint.
pub struct ClusterSigner {
    runtime: tokio::runtime::Runtime,
    coordinator: Coordinator,
    /// Report of the most recent signature.
    pub last_report: Option<NetReport>,
}

impl ClusterSigner {
    pub fn new(
        group: Arc<GroupPublic>,
        peers: Peers,
        policy: NetPolicy,
        tls: Arc<TlsIdentity>,
    ) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        Ok(Self {
            runtime,
            coordinator: Coordinator::new(group, peers, policy, tls),
            last_report: None,
        })
    }

    pub fn sign_with_report(
        &mut self,
        message: &[u8],
    ) -> Result<([u8; SIGNATURE_BYTES], NetReport), String> {
        self.runtime
            .block_on(self.coordinator.sign(message))
            .map_err(|e| e.to_string())
    }
}

impl ThresholdSigner for ClusterSigner {
    fn backend(&self) -> Backend {
        Backend::Tower
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.coordinator.group().pk
    }

    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignerError> {
        let (signature, report) = self
            .sign_with_report(message)
            .map_err(SignerError::Failed)?;
        self.last_report = Some(report);
        Ok(signature)
    }
}

/// `n` distinct free loopback ports (bound once, then released).
pub fn free_ports(n: usize) -> std::io::Result<Vec<u16>> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<_, _>>()?;
    listeners
        .iter()
        .map(|l| Ok(l.local_addr()?.port()))
        .collect()
}

pub fn wait_for_port(addr: &str, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if addr
            .parse::<SocketAddr>()
            .is_ok_and(|a| TcpStream::connect_timeout(&a, Duration::from_millis(200)).is_ok())
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

pub struct ClusterOptions {
    /// The `cairn` executable to run for every node.
    pub exe: PathBuf,
    /// Working directory: keys, address book and logs are written here.
    pub dir: PathBuf,
    pub seed: [u8; 32],
    pub faults: Vec<(NodeId, FaultMode)>,
    /// One-way injected latency on every node, milliseconds.
    pub link_delay_ms: u64,
    pub round_timeout_ms: u64,
    /// Extra flags for every signer and root engine, such as `--policy org`.
    pub node_args: Vec<String>,
}

/// A cluster of real OS processes on loopback: 16 signers, 4 root engines, 1 MPC worker.
/// Dropping it kills them.
pub struct ProcessCluster {
    pub dir: PathBuf,
    pub group: Arc<GroupPublic>,
    pub peers: Peers,
    pub peers_file: PathBuf,
    pub group_file: PathBuf,
    /// Directory with the cluster CA, fingerprints and every node's certificate and key.
    pub tls_dir: PathBuf,
    socket_dir: PathBuf,
    children: Vec<Child>,
}

fn fault_name(mode: FaultMode) -> &'static str {
    match mode {
        FaultMode::None => "none",
        FaultMode::Stall => "stall",
        FaultMode::BadShare => "bad-share",
        FaultMode::WrongChallenge => "wrong-challenge",
        FaultMode::BadResponse => "bad-response",
        FaultMode::BadOpening => "bad-opening",
    }
}

impl ProcessCluster {
    pub fn spawn(opts: &ClusterOptions) -> std::io::Result<Self> {
        let shape = [
            Gadget::new(3, 4).expect("shape"),
            Gadget::new(3, 4).expect("shape"),
        ];
        let (group, shares) =
            deal(&opts.seed, &shape, &mut rand::rngs::OsRng).map_err(std::io::Error::other)?;
        let keys = opts.dir.join("keys");
        let _ = std::fs::remove_dir_all(&opts.dir);
        write_keys(&keys, &group, &shares)?;
        drop(shares);
        let ids = node_ids(&shape);
        let ports = free_ports(ids.len())?;
        let peers: Peers = ids
            .iter()
            .zip(&ports)
            .map(|(id, p)| (*id, format!("127.0.0.1:{p}")))
            .collect();
        let (peers_file, group_file) = (opts.dir.join("peers.json"), keys.join("group.bin"));
        std::fs::write(&peers_file, peers_to_json(&peers))?;
        // Unix socket paths must stay short, so the sockets live under the system temp dir.
        let socket_dir =
            std::env::temp_dir().join(format!("cairn-mpc-{}-{}", std::process::id(), ports[0]));

        let log = |name: &str| {
            std::fs::File::create(opts.dir.join(format!("{name}.log"))).map(Stdio::from)
        };
        let mut cluster = Self {
            dir: opts.dir.clone(),
            group: Arc::new(group),
            peers: peers.clone(),
            peers_file,
            group_file,
            tls_dir: keys.join("tls"),
            socket_dir,
            children: Vec::new(),
        };
        cluster.children.push(
            Command::new(&opts.exe)
                .args(["mpc-worker", "--socket-dir"])
                .arg(&cluster.socket_dir)
                .stderr(log("mpc-worker")?)
                .spawn()?,
        );
        for id in &ids {
            let fault = opts
                .faults
                .iter()
                .find(|(f, _)| f == id)
                .map(|(_, m)| *m)
                .unwrap_or_default();
            let mut cmd = Command::new(&opts.exe);
            cmd.arg("node")
                .args([
                    "--role",
                    if matches!(id, NodeId::Root(_)) {
                        "root"
                    } else {
                        "signer"
                    },
                ])
                .args(["--id", &id.to_string()])
                .args(["--bind", &peers[id]])
                .arg("--peers")
                .arg(&cluster.peers_file)
                .arg("--group")
                .arg(&cluster.group_file)
                .arg("--tls")
                .arg(&cluster.tls_dir)
                .args(["--fault", fault_name(fault)])
                .args(["--link-delay-ms", &opts.link_delay_ms.to_string()])
                .args(["--round-timeout-ms", &opts.round_timeout_ms.to_string()])
                .args(&opts.node_args);
            match id {
                NodeId::Root(_) => cmd.arg("--mpc-socket-dir").arg(&cluster.socket_dir),
                _ => cmd.arg("--share").arg(share_file(&keys, *id)),
            };
            cluster.children.push(
                cmd.stderr(log(&id.to_string().replace('/', "_"))?)
                    .spawn()?,
            );
        }
        for addr in peers.values() {
            if !wait_for_port(addr, Duration::from_secs(20)) {
                return Err(std::io::Error::other(format!(
                    "node on {addr} did not start"
                )));
            }
        }
        let sockets_up =
            || (1..=3).all(|p| mpc_bridge::socket_path(&cluster.socket_dir, p).exists());
        let start = Instant::now();
        while !sockets_up() {
            if start.elapsed() > Duration::from_secs(20) {
                return Err(std::io::Error::other("MPC worker did not start"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(cluster)
    }

    /// The coordinator's TLS identity for this cluster.
    pub fn coordinator_tls(&self) -> std::io::Result<Arc<TlsIdentity>> {
        TlsIdentity::load(&self.tls_dir, NodeId::Coordinator).map(Arc::new)
    }

    /// Number of OS processes in the cluster (signers, root engines and the MPC worker).
    pub fn processes(&self) -> usize {
        self.children.len()
    }
}

impl Drop for ProcessCluster {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.socket_dir);
    }
}

/// A minimal CometBFT RPC stand-in: answers the three JSON-RPC POST methods pqc-sidecar's
/// `cometbft` adapter calls (`status`, `commit`, `block_results`) for a chain whose tip is
/// fixed at `latest`. It lets a stock pqc-sidecar run end to end without a chain. It proves
/// nothing about consensus: use `chain.verify = "trust_node"` with it.
pub struct MockChain {
    pub addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    worker: Option<std::thread::JoinHandle<()>>,
}

fn hash_hex(tag: &str, chain: &str, height: u64) -> String {
    let mut h = Sha3_256::new();
    h.update(tag.as_bytes());
    h.update(chain.as_bytes());
    h.update(height.to_be_bytes());
    hex::encode_upper(h.finalize())
}

/// Block hash and validators hash the mock reports for `height`.
pub fn mock_block(chain: &str, height: u64) -> (String, String) {
    (
        hash_hex("block", chain, height),
        hash_hex("validators", chain, 0),
    )
}

fn mock_rpc(chain: &str, latest: u64, request: &Value) -> Value {
    let height = || {
        request["params"]["height"]
            .as_str()
            .and_then(|h| h.parse::<u64>().ok())
    };
    let result = match request["method"].as_str() {
        Some("status") => json!({
            "node_info": { "network": chain, "version": "0.38.26", "moniker": "cairn-mock" },
            "sync_info": {
                "latest_block_height": latest.to_string(),
                "latest_block_time": "2026-01-01T00:00:00Z",
                "earliest_block_height": "1",
                "catching_up": false
            },
            "validator_info": { "address": "0000000000000000000000000000000000000000", "voting_power": "1" }
        }),
        Some("commit") => match height().filter(|h| (1..=latest).contains(h)) {
            Some(h) => {
                let (block, validators) = mock_block(chain, h);
                json!({
                    "signed_header": {
                        "header": {
                            "version": { "block": "11", "app": "1" },
                            "chain_id": chain,
                            "height": h.to_string(),
                            "time": "2026-01-01T00:00:00Z",
                            "validators_hash": validators,
                            "next_validators_hash": validators,
                            "proposer_address": "0000000000000000000000000000000000000000"
                        },
                        "commit": {
                            "height": h.to_string(),
                            "round": 0,
                            "block_id": { "hash": block, "parts": { "total": 1, "hash": block } },
                            "signatures": []
                        }
                    },
                    // The tip's commit is not canonical until the next block exists.
                    "canonical": h < latest
                })
            }
            None => {
                return json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32603, "message": "height not available" } })
            }
        },
        Some("block_results") => json!({
            "height": height().unwrap_or(0).to_string(),
            "txs_results": null,
            "finalize_block_events": null,
            "validator_updates": null,
            "consensus_param_updates": null,
            "app_hash": ""
        }),
        _ => {
            return json!({ "jsonrpc": "2.0", "id": request["id"], "error": { "code": -32601, "message": "method not found" } })
        }
    };
    json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
}

impl MockChain {
    pub fn serve(listen: &str, chain: &str, latest: u64) -> std::io::Result<Self> {
        let server = Arc::new(tiny_http::Server::http(listen).map_err(std::io::Error::other)?);
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
        let (srv, chain) = (server.clone(), chain.to_string());
        let worker = std::thread::spawn(move || {
            for mut request in srv.incoming_requests() {
                let mut body = Vec::new();
                if request
                    .as_reader()
                    .take(64 * 1024)
                    .read_to_end(&mut body)
                    .is_err()
                {
                    continue;
                }
                let reply = mock_rpc(
                    &chain,
                    latest,
                    &serde_json::from_slice(&body).unwrap_or(Value::Null),
                );
                let header = tiny_http::Header::from_bytes("Content-Type", "application/json")
                    .expect("static header");
                let _ = request.respond(
                    tiny_http::Response::from_string(reply.to_string()).with_header(header),
                );
            }
        });
        Ok(Self {
            addr,
            server,
            worker: Some(worker),
        })
    }

    pub fn join(mut self) {
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

impl Drop for MockChain {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

/// pqc-sidecar configuration that signs through a cairn KMS endpoint.
pub fn sidecar_config(
    kms_url: &str,
    rpc_url: &str,
    chain: &str,
    work: &Path,
    telemetry_port: u16,
) -> String {
    format!(
        "[signer]\nbackend = \"aws_kms\"\naws_kms_key_id = \"alias/cairn-tower\"\naws_region = \"us-east-1\"\n\
         aws_endpoint_url = \"{kms_url}\"\npublic_key_file = \"{}\"\n\n\
         [chain]\nadapter = \"cometbft\"\nid = \"cosmos:{chain}\"\nrpc_url = \"{rpc_url}\"\npoll_interval_ms = 200\n\
         start_height = 100\nverify = \"trust_node\"\n\n\
         [checkpoint]\ninterval = 100\n\n\
         [telemetry]\nlisten = \"127.0.0.1:{telemetry_port}\"\n\n\
         [output]\ncertificate_dir = \"{}\"\n",
        work.join("public_key.hex").display(),
        work.join("certs").display(),
    )
}

/// Signs by coordinating a flat committee (the three-round protocol) over TLS.
pub struct CommitteeSigner {
    runtime: tokio::runtime::Runtime,
    coordinator: cairn_net::FlatCoordinator,
}

impl CommitteeSigner {
    pub fn new(
        key: Arc<threshold_mldsa::mithril::GroupKey>,
        peers: Peers,
        policy: NetPolicy,
        tls: Arc<TlsIdentity>,
    ) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let mut coordinator = cairn_net::FlatCoordinator::new(key, peers, policy, tls);
        // Fetch the first mask commitments now, so the first request starts at round 2.
        runtime.block_on(coordinator.warm());
        Ok(Self {
            runtime,
            coordinator,
        })
    }

    pub fn sign_with_report(
        &mut self,
        message: &[u8],
    ) -> Result<([u8; SIGNATURE_BYTES], NetReport), String> {
        self.runtime
            .block_on(self.coordinator.sign(message))
            .map_err(|e| e.to_string())
    }
}

impl ThresholdSigner for CommitteeSigner {
    fn backend(&self) -> Backend {
        Backend::Flat
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.coordinator.key().pk
    }

    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignerError> {
        let outcome = self.sign_with_report(message);
        // One audit line per request on stderr: what was asked, who signed, what it took.
        let checkpoint = cairn_net::policy::Checkpoint::parse(message);
        let line = match &outcome {
            Ok((_, report)) => serde_json::json!({
                "event": "signed",
                "chain": checkpoint.as_ref().map(|c| c.chain.clone()),
                "height": checkpoint.as_ref().map(|c| c.height),
                "signers": report.signers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "executions": report.rejections + 1,
                "fault_retries": report.retries,
                "faults": report.faults.iter().map(|f| format!("{f:?}")).collect::<Vec<_>>(),
                "elapsed_ms": report.elapsed.as_millis() as u64,
            }),
            Err(reason) => serde_json::json!({
                "event": "not_signed",
                "chain": checkpoint.as_ref().map(|c| c.chain.clone()),
                "height": checkpoint.as_ref().map(|c| c.height),
                "reason": reason,
            }),
        };
        eprintln!("{line}");
        outcome
            .map(|(signature, _)| signature)
            .map_err(SignerError::Failed)
    }
}

/// A flat committee as real OS processes on loopback: one `cairn node --role party` each.
pub struct ProcessCommittee {
    pub dir: PathBuf,
    pub key: Arc<threshold_mldsa::mithril::GroupKey>,
    pub peers: Peers,
    pub peers_file: PathBuf,
    pub committee_file: PathBuf,
    pub tls_dir: PathBuf,
    children: Vec<Child>,
}

impl ProcessCommittee {
    pub fn spawn(
        exe: &Path,
        dir: &Path,
        t: usize,
        n: usize,
        faults: &[(NodeId, FaultMode)],
        link_delay_ms: u64,
        round_timeout_ms: u64,
    ) -> std::io::Result<Self> {
        Self::spawn_with(exe, dir, t, n, faults, link_delay_ms, round_timeout_ms, &[])
    }

    /// As [`spawn`](Self::spawn), with more arguments for every party (its policy, say).
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with(
        exe: &Path,
        dir: &Path,
        t: usize,
        n: usize,
        faults: &[(NodeId, FaultMode)],
        link_delay_ms: u64,
        round_timeout_ms: u64,
        party_args: &[String],
    ) -> std::io::Result<Self> {
        use cairn_net::flat::{party_share_file, write_flat_keys};
        let (key, parties) = threshold_mldsa::mithril::keygen(t, n, &mut rand::rngs::OsRng)
            .ok_or_else(|| std::io::Error::other("no parameter set for that committee"))?;
        let keys = dir.join("keys");
        let _ = std::fs::remove_dir_all(dir);
        write_flat_keys(&keys, &key, &parties)?;
        drop(parties);
        let ports = free_ports(n)?;
        let peers: Peers = (1..=n as u8)
            .zip(&ports)
            .map(|(k, p)| (NodeId::Party(k), format!("127.0.0.1:{p}")))
            .collect();
        let peers_file = dir.join("peers.json");
        std::fs::write(&peers_file, peers_to_json(&peers))?;
        let mut committee = Self {
            dir: dir.to_path_buf(),
            key: Arc::new(key),
            peers: peers.clone(),
            peers_file,
            committee_file: keys.join("committee.bin"),
            tls_dir: keys.join("tls"),
            children: Vec::new(),
        };
        for (id, addr) in &peers {
            let fault = faults
                .iter()
                .find(|(f, _)| f == id)
                .map(|(_, m)| *m)
                .unwrap_or_default();
            let log = std::fs::File::create(dir.join(format!("{id}.log"))).map(Stdio::from)?;
            committee.children.push(
                Command::new(exe)
                    .args([
                        "node",
                        "--role",
                        "party",
                        "--id",
                        &id.to_string(),
                        "--bind",
                        addr,
                    ])
                    .arg("--peers")
                    .arg(&committee.peers_file)
                    .arg("--committee")
                    .arg(&committee.committee_file)
                    .arg("--tls")
                    .arg(&committee.tls_dir)
                    .arg("--share")
                    .arg(party_share_file(&keys, *id))
                    .arg("--state")
                    .arg(dir.join(format!("{id}.state.json")))
                    .arg("--audit-log")
                    .arg(dir.join(format!("{id}.audit.log")))
                    .args(["--fault", fault_name(fault)])
                    .args(["--link-delay-ms", &link_delay_ms.to_string()])
                    .args(["--round-timeout-ms", &round_timeout_ms.to_string()])
                    .args(party_args)
                    .stderr(log)
                    .spawn()?,
            );
        }
        for addr in peers.values() {
            if !wait_for_port(addr, Duration::from_secs(20)) {
                return Err(std::io::Error::other(format!(
                    "party on {addr} did not start"
                )));
            }
        }
        Ok(committee)
    }

    pub fn coordinator_tls(&self) -> std::io::Result<Arc<TlsIdentity>> {
        TlsIdentity::load(&self.tls_dir, NodeId::Coordinator).map(Arc::new)
    }
}

impl Drop for ProcessCommittee {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

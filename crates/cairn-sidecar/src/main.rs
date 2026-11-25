//! `cairn`: demo, benchmark and KMS-compatible endpoint for the committee tower.

use cairn_net::cluster as net;
use cairn_net::{FaultMode, Link, NetPolicy, NodeId, Peers, RootNode, SignerNode, TlsIdentity};
use cairn_sidecar::cluster::{ClusterSigner, MockChain};
use cairn_sidecar::{
    bench, kms, write_certificate, write_public_key, Certificate, CertifierConfig, Checkpoint,
    TowerCertifier,
};
use cascade_tower::{Tower, TowerParams};
use rand::rngs::OsRng;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use threshold_mldsa::TrustedEngine;

const USAGE: &str = "\
cairn: committee-tower threshold ML-DSA-65 checkpoint signing (v2, research build)

Single process (simulation harness):
  cairn demo [--out <dir>] [--height <n>] [--interval <k>] [--seed-hex <64 hex>]
  cairn verify --certificate <file.pqcc> --public-key <file>
      Verify a certificate with RustCrypto ml-dsa (exit code 2 if it does not verify).
  cairn bench [--signatures <n>] [--json <file>]
  cairn mithril-demo [--threshold <t>] [--parties <n>] [--out <dir>]
  cairn mithril-bench [--signatures <n>]
      Prototype of the three-round protocol without MPC (signatures verify under FIPS 204 but
      are not the deterministic ones). In-process; see docs/PRODUCTION_PATH.md.

Multi-process cluster:
  cairn keygen --out <dir> [--seed-hex <64 hex>] [--host <ip>] [--base-port <port>]
      Trusted-dealer setup: writes group.bin, one .share file per signer, peers.json,
      public_key.hex and tls/ (cluster CA, one certificate and key per node).
  cairn node --role signer|root --id <leaf_i/signer_j|root_k> --bind <addr:port>
             --peers <peers.json|id=addr,...> --group <group.bin> --tls <dir>
             [--share <file>]            (signer)
             [--mpc-socket-dir <dir>]    (root: MPC backend party sockets)
             [--round-timeout-ms <n>] [--mpc-timeout-ms <n>] [--link-delay-ms <n>] [--fault <mode>]
  cairn keygen --out <dir> --committee <T-of-N>      (flat committee, three-round protocol)
  cairn node --role party --id party_<k> --bind <addr:port> --peers <peers.json>
             --committee <committee.bin> --tls <dir> --share <file>
             [--state <file>] [--audit-log <file>] [--chains <caip2,caip2>]
      A party signs only well-formed checkpoints for its committee key, on the listed chains
      if given, never below its last signed height and never two at one height (kept in
      --state across restarts).
  cairn serve-kms --committee <committee.bin> --peers <peers.json> --tls <dir> [--listen ...]
  cairn committee-bench [--committees 2-of-3,3-of-4] [--signatures <n>] [--rtt-ms <a,b>]
  cairn mpc-worker --socket-dir <dir>
      Reference three-party MPC backend (clear text, NOT a secure computation).
  cairn serve-kms [--listen <addr:port>] [--public-key-out <file>]
                  [--peers <peers.json> --group <group.bin> --tls <dir>]   (sign through a cluster)
                  [--round-timeout-ms <n>] [--mpc-timeout-ms <n>] [--link-delay-ms <n>]
                  [--access-key-id <id> --secret-access-key-file <file>]
      Requests must be signed (AWS SigV4) with those credentials; the secret may also come
      from CAIRN_KMS_SECRET_ACCESS_KEY. Without credentials the endpoint binds loopback only.
      KMS-compatible endpoint for pqc-sidecar's aws_kms backend. Without --peers the tower runs
      inside this process.
  cairn mock-chain [--listen <addr:port>] [--chain-id <id>] [--height <n>]
      Minimal CometBFT RPC stand-in for end-to-end runs without a chain.
  cairn remote-bench --peers <peers.json> --group <group.bin> --tls <dir> [--signatures <n>]
                     [--round-timeout-ms <n>] [--mpc-timeout-ms <n>]
      Measure signing through a cluster that is already running (for example across hosts).
  cairn cluster-bench [--signatures <n>] [--rtt-ms <a,b,...>] [--json <file>]
      Spawn 16 signer, 4 root-engine and 1 MPC-worker processes per scenario and measure.

See README.md, \"Status\", for what is and is not secure in this build.";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn read_public_key(
    path: &std::path::Path,
) -> Result<[u8; threshold_mldsa::PUBLIC_KEY_BYTES], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{} is not a hex ML-DSA-65 public key", path.display()))
}

/// Decode a `.pqcc` v2 certificate and verify it under a public key with RustCrypto `ml-dsa`.
fn verify_files(cert: &std::path::Path, pk: &std::path::Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    let certificate = Certificate::from_bytes(&bytes).map_err(|e| e.to_string())?;
    certificate
        .verify(&read_public_key(pk)?)
        .map_err(|e| e.to_string())?;
    let c = &certificate.checkpoint;
    Ok(json!({
        "valid": true,
        "format": 2,
        "scheme": "ML-DSA-65",
        "chain_id": c.chain,
        "epoch": c.epoch,
        "height": c.height,
        "block_hash": hex::encode_upper(&c.block_hash),
        "finality_commitment": hex::encode_upper(&c.finality_commitment),
        "key_id": hex::encode(certificate.key_id),
    }))
}

/// A well-formed checkpoint for benchmarks. Heights follow the clock so that repeated runs
/// against the same committee never go backwards.
fn bench_checkpoint(pk: &[u8], i: u32) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    cairn_net::policy::Checkpoint {
        chain: "cosmos:cairn-bench-1".into(),
        epoch: 1,
        height: now * 1000 + i as u64,
        block_hash: rand::random::<[u8; 32]>().to_vec(),
        finality_commitment: rand::random::<[u8; 32]>().to_vec(),
        key_id: cairn_net::policy::key_id(pk),
    }
    .message()
}

fn ms(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    arg(args, name).map_or(Ok(default), |v| {
        v.parse().map_err(|_| format!("bad {name}"))
    })
}

/// `--peers`: a file holding the address book, or the inline `id=addr,...` form.
fn peers(args: &[String]) -> Result<Option<Peers>, String> {
    let Some(value) = arg(args, "--peers") else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&value).unwrap_or(value);
    net::parse_peers(&text).map(Some)
}

/// `--tls <dir>`: this node's certificate and key, the cluster CA and the fingerprint table.
fn tls(args: &[String], id: NodeId) -> Result<Arc<TlsIdentity>, String> {
    let dir =
        arg(args, "--tls").ok_or("needs --tls <dir> (written by `cairn keygen` as <out>/tls)")?;
    TlsIdentity::load(&PathBuf::from(dir), id)
        .map(Arc::new)
        .map_err(|e| format!("TLS identity of {id}: {e}"))
}

fn seed(args: &[String]) -> Result<[u8; 32], String> {
    match arg(args, "--seed-hex") {
        None => Ok(rand::random()),
        Some(h) => hex::decode(h.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| "--seed-hex must be 64 hex characters".to_string()),
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let params = TowerParams::default_16();
    match args.first().map(String::as_str) {
        Some("demo") => {
            let out = PathBuf::from(arg(args, "--out").unwrap_or_else(|| "out".into()));
            let interval: u64 = arg(args, "--interval")
                .map_or(Ok(100), |v| v.parse())
                .map_err(|_| "bad --interval")?;
            let height: u64 = arg(args, "--height")
                .map_or(Ok(1200), |v| v.parse())
                .map_err(|_| "bad --height")?;
            let tower =
                Tower::deal(&seed(args)?, &params, &mut OsRng).map_err(|e| e.to_string())?;
            let config = CertifierConfig {
                checkpoint_interval: interval,
                ..CertifierConfig::default()
            };
            let mut certifier = TowerCertifier::new(tower, TrustedEngine::new(), config);
            let checkpoint = Checkpoint {
                chain: "cosmos:cairn-devnet-1".into(),
                epoch: 1,
                height,
                block_hash: rand::random::<[u8; 32]>().to_vec(),
                finality_commitment: rand::random::<[u8; 32]>().to_vec(),
            };
            let (certificate, report) =
                certifier.certify(&checkpoint).map_err(|e| e.to_string())?;
            let file = write_certificate(&out, &certificate).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    format!("{e} already exists (certificates are never overwritten); pass another --out")
                }
                _ => e.to_string(),
            })?;
            let pk = out.join("public_key.hex");
            write_public_key(&pk, certifier.public_key()).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({
                    "certificate": file,
                    "public_key": pk,
                    "signers": params.signers(),
                    "tower": "3-of-4 x 3-of-4",
                    "signature_bytes": certificate.signature.len(),
                    "rejected_attempts": report.rejections,
                    "messages": report.wire.messages,
                    "elapsed_ms": report.elapsed.as_secs_f64() * 1e3,
                    "key_id": hex::encode(certificate.key_id),
                })
            );
            // Check what is on disk, the way an outside verifier would, and that tampering fails.
            let summary = verify_files(&file, &pk)?;
            let mut tampered = std::fs::read(&file).map_err(|e| e.to_string())?;
            let at = tampered.len() - 3000;
            tampered[at] ^= 1;
            let pk_bytes = read_public_key(&pk)?;
            let rejected =
                Certificate::from_bytes(&tampered).map_or(true, |c| c.verify(&pk_bytes).is_err());
            if !rejected {
                return Err("a tampered certificate verified".into());
            }
            eprintln!(
                "OK: 16 signers produced one standard ML-DSA-65 signature; verified from disk with \
                 RustCrypto ml-dsa (height {}), tampered copy rejected.\n\
                 Check it again any time: cairn verify --certificate {} --public-key {}",
                summary["height"],
                file.display(),
                pk.display()
            );
            Ok(())
        }
        Some("verify") => {
            let cert = PathBuf::from(
                arg(args, "--certificate").ok_or("verify needs --certificate <file.pqcc>")?,
            );
            let pk =
                PathBuf::from(arg(args, "--public-key").ok_or("verify needs --public-key <file>")?);
            println!("{}", verify_files(&cert, &pk)?);
            Ok(())
        }
        Some("bench") => {
            let n: u32 = arg(args, "--signatures")
                .map_or(Ok(200), |v| v.parse())
                .map_err(|_| "bad --signatures")?;
            if n == 0 {
                return Err("--signatures must be at least 1".into());
            }
            let results: Vec<_> = bench::Scenario::ALL
                .iter()
                .map(|s| bench::run(*s, n, &params))
                .collect();
            println!("{}", bench::markdown(&results));
            println!(
                "Rejected attempts per certificate (healthy):\n{}",
                bench::histogram(&results[0])
            );
            if let Some(path) = arg(args, "--json") {
                let doc = json!(results.iter().map(bench::to_json).collect::<Vec<_>>());
                std::fs::write(&path, format!("{doc:#}\n")).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        Some("serve-kms") => {
            let listen = arg(args, "--listen").unwrap_or_else(|| "127.0.0.1:8200".into());
            let pk_out = arg(args, "--public-key-out").map(PathBuf::from);
            // Credentials callers must sign requests with (AWS SigV4), as pqc-sidecar does.
            let auth = match arg(args, "--access-key-id") {
                Some(id) => {
                    let secret = match arg(args, "--secret-access-key-file") {
                        Some(file) => std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?.trim().to_owned(),
                        None => std::env::var("CAIRN_KMS_SECRET_ACCESS_KEY").map_err(|_| {
                            "--access-key-id needs --secret-access-key-file or CAIRN_KMS_SECRET_ACCESS_KEY"
                        })?,
                    };
                    if secret.is_empty() {
                        return Err("the KMS secret access key is empty".into());
                    }
                    Some(cairn_sidecar::sigv4::KmsAuth::new(id, secret))
                }
                None => {
                    eprintln!("cairn: KMS requests are NOT authenticated (no --access-key-id); loopback only");
                    None
                }
            };
            let endpoint = match peers(args)? {
                Some(peers) if arg(args, "--committee").is_some() => {
                    let file = arg(args, "--committee").ok_or("--committee <committee.bin>")?;
                    let key = Arc::new(
                        cairn_net::flat::read_committee(&PathBuf::from(file))
                            .map_err(|e| e.to_string())?,
                    );
                    let policy = NetPolicy {
                        round_timeout: Duration::from_millis(ms(args, "--round-timeout-ms", 5000)?),
                        link_delay: Duration::from_millis(ms(args, "--link-delay-ms", 0)?),
                        ..NetPolicy::default()
                    };
                    if let Some(path) = &pk_out {
                        write_public_key(path, &key.pk).map_err(|e| e.to_string())?;
                    }
                    eprintln!(
                        "cairn: signing through a {}-of-{} committee (three-round protocol)",
                        key.params.t, key.params.n
                    );
                    let signer = cairn_sidecar::cluster::CommitteeSigner::new(
                        key,
                        peers,
                        policy,
                        tls(args, NodeId::Coordinator)?,
                    )
                    .map_err(|e| e.to_string())?;
                    kms::serve_with(&listen, signer, auth.clone())
                }
                Some(peers) => {
                    let file = arg(args, "--group").ok_or("--peers needs --group <group.bin>")?;
                    let group =
                        Arc::new(net::read_group(&PathBuf::from(file)).map_err(|e| e.to_string())?);
                    let policy = NetPolicy {
                        round_timeout: Duration::from_millis(ms(args, "--round-timeout-ms", 2000)?),
                        mpc_timeout: Duration::from_millis(ms(args, "--mpc-timeout-ms", 30_000)?),
                        link_delay: Duration::from_millis(ms(args, "--link-delay-ms", 0)?),
                        ..NetPolicy::default()
                    };
                    if let Some(path) = &pk_out {
                        write_public_key(path, &group.pk).map_err(|e| e.to_string())?;
                    }
                    eprintln!(
                        "cairn: signing through a TCP cluster of {} nodes",
                        peers.len()
                    );
                    let signer =
                        ClusterSigner::new(group, peers, policy, tls(args, NodeId::Coordinator)?)
                            .map_err(|e| e.to_string())?;
                    kms::serve_with(&listen, signer, auth.clone())
                }
                None => {
                    let tower = Tower::deal(&seed(args)?, &params, &mut OsRng)
                        .map_err(|e| e.to_string())?;
                    let certifier = TowerCertifier::new(
                        tower,
                        TrustedEngine::new(),
                        CertifierConfig::default(),
                    );
                    if let Some(path) = &pk_out {
                        write_public_key(path, certifier.public_key())
                            .map_err(|e| e.to_string())?;
                    }
                    kms::serve_with(&listen, certifier, auth.clone())
                }
            }
            .map_err(|e| e.to_string())?;
            eprintln!(
                "cairn: KMS-compatible tower endpoint on {} (aws_endpoint_url)",
                endpoint.url()
            );
            endpoint.join();
            Ok(())
        }
        Some("keygen") => {
            let out = PathBuf::from(arg(args, "--out").ok_or("keygen needs --out <dir>")?);
            let host = arg(args, "--host").unwrap_or_else(|| "127.0.0.1".into());
            let base: u16 = arg(args, "--base-port")
                .map_or(Ok(7100), |v| v.parse())
                .map_err(|_| "bad --base-port")?;
            if let Some(spec) = arg(args, "--committee") {
                // A flat committee for the three-round protocol: "--committee 3-of-4".
                let (t, n) = spec
                    .split_once("-of-")
                    .and_then(|(t, n)| Some((t.parse::<usize>().ok()?, n.parse::<usize>().ok()?)))
                    .ok_or("--committee expects T-of-N, for example 3-of-4")?;
                let (key, parties) = threshold_mldsa::mithril::keygen(t, n, &mut OsRng)
                    .ok_or("no parameter set for that committee (N at most 6)")?;
                cairn_net::flat::write_flat_keys(&out, &key, &parties)
                    .map_err(|e| format!("writing keys: {e}"))?;
                let peers = cairn_net::flat::flat_peers(n, &host, base);
                std::fs::write(out.join("peers.json"), net::peers_to_json(&peers))
                    .map_err(|e| e.to_string())?;
                write_public_key(&out.join("public_key.hex"), &key.pk)
                    .map_err(|e| e.to_string())?;
                println!(
                    "{}",
                    json!({ "out": out, "committee": spec, "nodes": peers.len(), "key_id": hex::encode(cairn_sidecar::key_id(&key.pk)) })
                );
                return Ok(());
            }
            let (group, shares) = threshold_mldsa::deal(&seed(args)?, params.tiers(), &mut OsRng)
                .map_err(|e| e.to_string())?;
            net::write_keys(&out, &group, &shares).map_err(|e| format!("writing keys: {e}"))?;
            let peers = net::local_peers(params.tiers(), &host, base);
            std::fs::write(out.join("peers.json"), net::peers_to_json(&peers))
                .map_err(|e| e.to_string())?;
            write_public_key(&out.join("public_key.hex"), &group.pk).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({ "out": out, "signers": shares.len(), "nodes": peers.len(), "key_id": hex::encode(cairn_sidecar::key_id(&group.pk)) })
            );
            Ok(())
        }
        Some("node") => {
            let id: NodeId = arg(args, "--id").ok_or("node needs --id")?.parse()?;
            let role = arg(args, "--role").ok_or("node needs --role signer|root")?;
            let bind = arg(args, "--bind").ok_or("node needs --bind <addr:port>")?;
            let peers = peers(args)?.ok_or("node needs --peers")?;
            if role == "party" {
                let NodeId::Party(_) = id else {
                    return Err(format!("--role party does not match --id {id}"));
                };
                let key = cairn_net::flat::read_committee(&PathBuf::from(
                    arg(args, "--committee").ok_or("a party needs --committee <committee.bin>")?,
                ))
                .map_err(|e| e.to_string())?;
                let share = cairn_net::flat::read_party_share(&PathBuf::from(
                    arg(args, "--share").ok_or("a party needs --share <file>")?,
                ))
                .map_err(|e| e.to_string())?;
                if NodeId::Party(share.index + 1) != id {
                    return Err(format!("share file is for another party than {id}"));
                }
                let delay = Duration::from_millis(ms(args, "--link-delay-ms", 0)?);
                let fault: FaultMode =
                    arg(args, "--fault").map_or(Ok(FaultMode::None), |f| f.parse())?;
                let identity = tls(args, id)?;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let _ = peers;
                return runtime.block_on(async {
                    let listener = tokio::net::TcpListener::bind(&bind)
                        .await
                        .map_err(|e| format!("bind {bind}: {e}"))?;
                    eprintln!("cairn node {id}: committee party on {bind}");
                    let policy = cairn_net::policy::Policy::open(
                        &key.pk,
                        cairn_net::policy::PolicyConfig {
                            chains: arg(args, "--chains").map(|c| c.split(',').map(|x| x.trim().to_owned()).collect()),
                            state_file: arg(args, "--state").map(PathBuf::from),
                            audit_log: arg(args, "--audit-log").map(PathBuf::from),
                        },
                    )
                    .map_err(|e| format!("signing policy state: {e}"))?;
                    if arg(args, "--state").is_none() {
                        eprintln!("cairn node {id}: no --state file; the last signed height is forgotten on restart");
                    }
                    let node = cairn_net::PartyNode::new(id, Arc::new(key), share, fault, policy);
                    cairn_net::flat::run_party(listener, node, delay, identity).await;
                    Ok(())
                });
            }
            let group = Arc::new(
                net::read_group(&PathBuf::from(
                    arg(args, "--group").ok_or("node needs --group")?,
                ))
                .map_err(|e| e.to_string())?,
            );
            let delay = Duration::from_millis(ms(args, "--link-delay-ms", 0)?);
            let link = Link::new(
                Duration::from_millis(ms(args, "--round-timeout-ms", 2000)?),
                delay,
                tls(args, id)?,
            );
            let fault: FaultMode =
                arg(args, "--fault").map_or(Ok(FaultMode::None), |f| f.parse())?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::bind(&bind)
                    .await
                    .map_err(|e| format!("bind {bind}: {e}"))?;
                match (role.as_str(), id) {
                    ("signer", NodeId::Signer { .. }) => {
                        let file = arg(args, "--share").ok_or("a signer needs --share <file>")?;
                        let share =
                            net::read_share(&PathBuf::from(file)).map_err(|e| e.to_string())?;
                        if Some(share.path.clone()) != id.path() {
                            return Err(format!("share file is for another signer than {id}"));
                        }
                        eprintln!("cairn node {id}: signer on {bind}");
                        net::run_signer(
                            listener,
                            SignerNode {
                                id,
                                group,
                                share,
                                peers,
                                link,
                                fault,
                            },
                            delay,
                        )
                        .await;
                    }
                    ("root", NodeId::Root(_)) => {
                        let dir = arg(args, "--mpc-socket-dir")
                            .ok_or("a root engine needs --mpc-socket-dir <dir>")?;
                        let mpc = Duration::from_millis(ms(args, "--mpc-timeout-ms", 30_000)?);
                        eprintln!("cairn node {id}: root engine on {bind}, MPC sockets in {dir}");
                        net::run_root(
                            listener,
                            RootNode::new(id, group, fault, dir.into(), mpc),
                            delay,
                            link.tls.clone(),
                        )
                        .await;
                    }
                    _ => return Err(format!("--role {role} does not match --id {id}")),
                }
                Ok(())
            })
        }
        Some("mpc-worker") => {
            let dir = arg(args, "--socket-dir").ok_or("mpc-worker needs --socket-dir <dir>")?;
            let worker = mpc_bridge::serve(&PathBuf::from(&dir), Duration::from_secs(30))
                .map_err(|e| e.to_string())?;
            eprintln!("cairn mpc-worker: reference backend (clear text, not MPC) on {dir}/p{{1,2,3}}.sock");
            worker.join();
            Ok(())
        }
        Some("mock-chain") => {
            let listen = arg(args, "--listen").unwrap_or_else(|| "127.0.0.1:26657".into());
            let chain = arg(args, "--chain-id").unwrap_or_else(|| "cairn-devnet-1".into());
            let height: u64 = arg(args, "--height")
                .map_or(Ok(150), |v| v.parse())
                .map_err(|_| "bad --height")?;
            let mock = MockChain::serve(&listen, &chain, height).map_err(|e| e.to_string())?;
            eprintln!("cairn mock-chain: CometBFT RPC stand-in for {chain} at height {height} on http://{}", mock.addr);
            mock.join();
            Ok(())
        }
        Some("cluster-bench") => {
            let n: u32 = arg(args, "--signatures")
                .map_or(Ok(100), |v| v.parse())
                .map_err(|_| "bad --signatures")?;
            let rtts: Vec<u64> = arg(args, "--rtt-ms")
                .unwrap_or_else(|| "0,50".into())
                .split(',')
                .map(|v| v.trim().parse().map_err(|_| "bad --rtt-ms"))
                .collect::<Result<_, _>>()?;
            if n == 0 {
                return Err("--signatures must be at least 1".into());
            }
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let work = std::env::temp_dir().join(format!("cairn-bench-{}", std::process::id()));
            let mut results = Vec::new();
            for rtt in rtts {
                for scenario in bench::Scenario::ALL {
                    eprintln!(
                        "cluster-bench: {} at {rtt} ms RTT, {n} certificates",
                        scenario.name()
                    );
                    results.push(bench::run_cluster(&exe, &work, scenario, n, rtt)?);
                }
            }
            let _ = std::fs::remove_dir_all(&work);
            println!("{}", bench::cluster_markdown(&results));
            if let Some(path) = arg(args, "--json") {
                let doc = json!(results.iter().map(bench::cluster_json).collect::<Vec<_>>());
                std::fs::write(&path, format!("{doc:#}\n")).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        Some("remote-bench") => {
            let n: u32 = arg(args, "--signatures")
                .map_or(Ok(20), |v| v.parse())
                .map_err(|_| "bad --signatures")?;
            let peers = peers(args)?.ok_or("remote-bench needs --peers")?;
            if let Some(file) = arg(args, "--committee") {
                // A flat committee that is already running (three-round protocol).
                let key = Arc::new(
                    cairn_net::flat::read_committee(&PathBuf::from(file))
                        .map_err(|e| e.to_string())?,
                );
                let policy = NetPolicy {
                    round_timeout: Duration::from_millis(ms(args, "--round-timeout-ms", 10_000)?),
                    ..NetPolicy::default()
                };
                let pk_bytes = key.pk;
                let (t, total) = (key.params.t, key.params.n);
                let mut signer = cairn_sidecar::cluster::CommitteeSigner::new(
                    key,
                    peers,
                    policy,
                    tls(args, NodeId::Coordinator)?,
                )
                .map_err(|e| e.to_string())?;
                let (mut ms_all, mut execs, mut bytes) = (Vec::new(), 0.0, 0.0);
                for i in 0..n {
                    let message = bench_checkpoint(&pk_bytes, i);
                    let (_, report) = signer.sign_with_report(&message)?;
                    ms_all.push(report.elapsed.as_secs_f64() * 1e3);
                    execs += report.rejections as f64 + 1.0;
                    bytes += report.coordinator_bytes.values().sum::<u64>() as f64 / t as f64;
                }
                ms_all.sort_by(|a, b| a.total_cmp(b));
                let at = |q: f64| ms_all[((ms_all.len() - 1) as f64 * q).round() as usize];
                println!(
                    "| {t}-of-{total} | {n} | {:.0} / {:.0} / {:.0} / {:.0} | {:.2} | {:.0} |",
                    ms_all.iter().sum::<f64>() / ms_all.len() as f64,
                    at(0.5),
                    at(0.95),
                    at(1.0),
                    execs / n as f64,
                    bytes / n as f64 / 1e3
                );
                return Ok(());
            }
            let file = arg(args, "--group").ok_or("remote-bench needs --group <group.bin>")?;
            let group = Arc::new(net::read_group(&PathBuf::from(file)).map_err(|e| e.to_string())?);
            let policy = NetPolicy {
                round_timeout: Duration::from_millis(ms(args, "--round-timeout-ms", 5000)?),
                mpc_timeout: Duration::from_millis(ms(args, "--mpc-timeout-ms", 30_000)?),
                ..NetPolicy::default()
            };
            let nodes = peers.len();
            let pk = group.pk;
            let mut signer =
                ClusterSigner::new(group, peers, policy, tls(args, NodeId::Coordinator)?)
                    .map_err(|e| e.to_string())?;
            let result = bench::measure(&mut signer, &pk, bench::Scenario::Healthy, n, 0, nodes)?;
            println!("{}", bench::cluster_markdown(std::slice::from_ref(&result)));
            println!("{:#}", bench::cluster_json(&result));
            Ok(())
        }
        Some("mithril-demo") => {
            use threshold_mldsa::mithril;
            let t: usize = arg(args, "--threshold")
                .map_or(Ok(3), |v| v.parse())
                .map_err(|_| "bad --threshold")?;
            let n: usize = arg(args, "--parties")
                .map_or(Ok(4), |v| v.parse())
                .map_err(|_| "bad --parties")?;
            let out = PathBuf::from(arg(args, "--out").unwrap_or_else(|| "out-mithril".into()));
            let (key, parties) =
                mithril::keygen(t, n, &mut OsRng).ok_or("no parameter set for that (T, N)")?;
            let checkpoint = Checkpoint {
                chain: "cosmos:cairn-devnet-1".into(),
                epoch: 1,
                height: 1200,
                block_hash: rand::random::<[u8; 32]>().to_vec(),
                finality_commitment: rand::random::<[u8; 32]>().to_vec(),
            };
            let key_id = cairn_sidecar::key_id(&key.pk);
            let message = checkpoint
                .signing_message(&key_id)
                .map_err(|e| e.to_string())?;
            let active: Vec<u8> = (0..t as u8).collect();
            let start = std::time::Instant::now();
            let (signature, stats) =
                mithril::sign_local(&key, &parties, &active, &message, &mut OsRng)
                    .ok_or("signing did not finish")?;
            let elapsed = start.elapsed();
            let certificate = Certificate {
                checkpoint,
                key_id,
                signature: Box::new(signature),
            };
            let file = write_certificate(&out, &certificate).map_err(|e| e.to_string())?;
            let pk = out.join("public_key.hex");
            write_public_key(&pk, &key.pk).map_err(|e| e.to_string())?;
            let summary = verify_files(&file, &pk)?;
            println!(
                "{}",
                json!({
                    "scheme": "three-round threshold ML-DSA-65 (Mithril prototype)",
                    "threshold": t, "parties": n,
                    "certificate": file, "public_key": pk,
                    "executions": stats.executions,
                    "bytes_per_party_per_execution": stats.bytes_per_party,
                    "elapsed_ms": elapsed.as_secs_f64() * 1e3,
                    "verified": summary["valid"],
                })
            );
            Ok(())
        }
        Some("mithril-bench") => {
            use threshold_mldsa::mithril;
            let n_sig: u32 = arg(args, "--signatures")
                .map_or(Ok(50), |v| v.parse())
                .map_err(|_| "bad --signatures")?;
            println!("| T-of-N | K | signatures | executions (mean / max) | compute ms per signature (mean / p95) | kB per party per execution |\n|---|---|---|---|---|---|");
            for (t, n) in [(2usize, 3usize), (3, 4), (3, 5), (4, 4), (2, 6)] {
                let (key, parties) = mithril::keygen(t, n, &mut OsRng).ok_or("no parameter set")?;
                let active: Vec<u8> = (0..t as u8).collect();
                let (mut ms_all, mut execs, mut max_exec, mut bytes) =
                    (Vec::new(), 0u32, 0u32, 0usize);
                for i in 0..n_sig {
                    let message = format!("pqc-sidecar/checkpoint/v2 bench {i}").into_bytes();
                    let start = std::time::Instant::now();
                    let (_, stats) =
                        mithril::sign_local(&key, &parties, &active, &message, &mut OsRng)
                            .ok_or("signing did not finish")?;
                    ms_all.push(start.elapsed().as_secs_f64() * 1e3);
                    execs += stats.executions;
                    max_exec = max_exec.max(stats.executions);
                    bytes = bytes.max(stats.bytes_per_party);
                }
                ms_all.sort_by(|a, b| a.total_cmp(b));
                let mean = ms_all.iter().sum::<f64>() / ms_all.len() as f64;
                let p95 = ms_all[((ms_all.len() - 1) as f64 * 0.95).round() as usize];
                println!(
                    "| {t}-of-{n} | {} | {n_sig} | {:.2} / {max_exec} | {mean:.0} / {p95:.0} | {:.0} |",
                    key.params.reps,
                    execs as f64 / n_sig as f64,
                    bytes as f64 / 1e3
                );
            }
            Ok(())
        }
        Some("committee-bench") => {
            use cairn_sidecar::cluster::{CommitteeSigner, ProcessCommittee};
            let n_sig: u32 = arg(args, "--signatures")
                .map_or(Ok(100), |v| v.parse())
                .map_err(|_| "bad --signatures")?;
            let rtts: Vec<u64> = arg(args, "--rtt-ms")
                .unwrap_or_else(|| "0,50".into())
                .split(',')
                .map(|v| v.trim().parse().map_err(|_| "bad --rtt-ms"))
                .collect::<Result<_, _>>()?;
            let shapes: Vec<(usize, usize)> = arg(args, "--committees")
                .unwrap_or_else(|| "2-of-3,3-of-4,3-of-5".into())
                .split(',')
                .map(|c| {
                    c.split_once("-of-")
                        .and_then(|(t, n)| Some((t.parse().ok()?, n.parse().ok()?)))
                        .ok_or("bad --committees")
                })
                .collect::<Result<_, _>>()?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let work =
                std::env::temp_dir().join(format!("cairn-committee-bench-{}", std::process::id()));
            println!("| RTT ms | committee | certs | latency ms (mean / p50 / p95 / max) | executions (mean) | kB per party per cert |\n|---|---|---|---|---|---|");
            for rtt in rtts {
                for (t, n) in &shapes {
                    let committee = ProcessCommittee::spawn(
                        &exe,
                        &work.join(format!("{t}-{n}-{rtt}")),
                        *t,
                        *n,
                        &[],
                        rtt / 2,
                        5000,
                    )
                    .map_err(|e| format!("spawning the committee: {e}"))?;
                    let policy = NetPolicy {
                        round_timeout: Duration::from_millis(5000),
                        link_delay: Duration::from_millis(rtt / 2),
                        ..NetPolicy::default()
                    };
                    let tls = committee.coordinator_tls().map_err(|e| e.to_string())?;
                    let mut signer = CommitteeSigner::new(
                        committee.key.clone(),
                        committee.peers.clone(),
                        policy,
                        tls,
                    )
                    .map_err(|e| e.to_string())?;
                    let (mut ms_all, mut execs, mut bytes) = (Vec::new(), 0.0, 0.0);
                    for i in 0..n_sig {
                        let message = bench_checkpoint(&committee.key.pk, i);
                        let (_, report) = signer.sign_with_report(&message)?;
                        ms_all.push(report.elapsed.as_secs_f64() * 1e3);
                        execs += report.rejections as f64 + 1.0;
                        bytes += report.coordinator_bytes.values().sum::<u64>() as f64 / *t as f64;
                    }
                    ms_all.sort_by(|a, b| a.total_cmp(b));
                    let at = |q: f64| ms_all[((ms_all.len() - 1) as f64 * q).round() as usize];
                    println!(
                        "| {rtt} | {t}-of-{n} | {n_sig} | {:.0} / {:.0} / {:.0} / {:.0} | {:.2} | {:.0} |",
                        ms_all.iter().sum::<f64>() / ms_all.len() as f64,
                        at(0.5),
                        at(0.95),
                        at(1.0),
                        execs / n_sig as f64,
                        bytes / n_sig as f64 / 1e3
                    );
                }
            }
            let _ = std::fs::remove_dir_all(&work);
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

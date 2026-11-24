//! `cairn`: demo, benchmark and KMS-compatible endpoint for the committee tower.

use cairn_net::cluster as net;
use cairn_net::{FaultMode, Link, NetPolicy, NodeId, Peers, RootNode, SignerNode};
use cairn_sidecar::cluster::{ClusterSigner, MockChain};
use cairn_sidecar::{
    bench, kms, write_certificate, write_public_key, CertifierConfig, Checkpoint, TowerCertifier,
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
  cairn bench [--signatures <n>] [--json <file>]

Multi-process cluster:
  cairn keygen --out <dir> [--seed-hex <64 hex>] [--host <ip>] [--base-port <port>]
      Trusted-dealer setup: writes group.bin, one .share file per signer, peers.json and
      public_key.hex.
  cairn node --role signer|root --id <leaf_i/signer_j|root_k> --bind <addr:port>
             --peers <peers.json|id=addr,...> --group <group.bin>
             [--share <file>]            (signer)
             [--mpc-socket-dir <dir>]    (root: MPC backend party sockets)
             [--round-timeout-ms <n>] [--mpc-timeout-ms <n>] [--link-delay-ms <n>] [--fault <mode>]
  cairn mpc-worker --socket-dir <dir>
      Reference three-party MPC backend (clear text, NOT a secure computation).
  cairn serve-kms [--listen <addr:port>] [--public-key-out <file>]
                  [--peers <peers.json> --group <group.bin>]   (sign through a TCP cluster)
                  [--round-timeout-ms <n>] [--mpc-timeout-ms <n>] [--link-delay-ms <n>]
      KMS-compatible endpoint for pqc-sidecar's aws_kms backend. Without --peers the tower runs
      inside this process.
  cairn mock-chain [--listen <addr:port>] [--chain-id <id>] [--height <n>]
      Minimal CometBFT RPC stand-in for end-to-end runs without a chain.
  cairn cluster-bench [--signatures <n>] [--rtt-ms <a,b,...>] [--json <file>]
      Spawn 16 signer, 4 root-engine and 1 MPC-worker processes per scenario and measure.

See README.md, \"Status\", for what is and is not secure in this build.";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
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
            let file = write_certificate(&out, &certificate).map_err(|e| e.to_string())?;
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
            eprintln!(
                "verify: pqc-sidecar verify --certificate {} --public-key {}",
                file.display(),
                pk.display()
            );
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
            let endpoint = match peers(args)? {
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
                        ClusterSigner::new(group, peers, policy).map_err(|e| e.to_string())?;
                    kms::serve(&listen, signer)
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
                    kms::serve(&listen, certifier)
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
            let group = Arc::new(
                net::read_group(&PathBuf::from(
                    arg(args, "--group").ok_or("node needs --group")?,
                ))
                .map_err(|e| e.to_string())?,
            );
            let delay = Duration::from_millis(ms(args, "--link-delay-ms", 0)?);
            let link = Link {
                timeout: Duration::from_millis(ms(args, "--round-timeout-ms", 2000)?),
                delay,
            };
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

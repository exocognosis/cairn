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
      public_key.hex and tls/ (one self-signed certificate and key per node, pinned).
  cairn node --role signer|root --id <leaf_i/signer_j|root_k> --bind <addr:port>
             --peers <peers.json|id=addr,...> --group <group.bin> --tls <dir>
             [--share <file>]            (signer)
             [--mpc-socket-dir <dir>]    (root: MPC backend party sockets)
             [--round-timeout-ms <n>] [--mpc-timeout-ms <n>] [--link-delay-ms <n>] [--fault <mode>]
  cairn node --role party ... [--policy checkpoint|org]
             checkpoint (default): [--chains <caip2,...>] [--state <file>] [--audit-log <file>]
             org: --org-rule <rule.json> --approvals <dir> [--audit-log <file>]
      What this party agrees to sign. checkpoint: pqc-sidecar checkpoints, never two for one
      height. org: any payload that enough of the approvers in rule.json have approved
      (rule.json holds a required count and each approver's name and public key hex; see
      docs/ORG_POLICY.md); the party reads approvals from its own --approvals directory.
  cairn approver-keygen --name <approver> --out <dir>
  cairn approve --name <approver> --key <name.approver.key> --committee-key <public_key.hex>
                --payload <file> --out <approvals dir> [--ttl-secs <n>]   (default one hour)
      An approver's key, and one approval of one payload for one committee. Copy the
      approval file into every party's approvals directory.
  cairn keygen --out <dir> --committee <T-of-N>      (flat committee, TRUSTED DEALER; tests only)
  cairn keygen --out <dir> --members <roster.json>   (the same, shape taken from a roster)
      A roster names the committee: a threshold and a list of members, each with an id and
      weight 1. Party k is the k-th member; members.json in <dir> records that. The same
      flag works for committee-init. Weighted or larger rosters are refused: the
      three-round protocol has no weights and at most six parties.
  cairn identity --out <file>                         (a party's long-term identity key)
  cairn dkg-party --id party_<k> --bind <addr:port> --roster <roster.json> --identity <file>
                  --tls <dir> --out <dir>
  cairn dkg --roster <roster.json> --peers <peers.json> --tls <dir> [--public-key-out <file>]
      Distributed key generation: no machine ever holds the whole key. Each party runs
      dkg-party; then one run of dkg drives it. roster.json lists every party's public
      identity key. `cairn committee-init --committee T-of-N --out <dir>` makes identities,
      a roster and TLS certificates on one machine for local use.
  cairn node --role party --id party_<k> --bind <addr:port> --peers <peers.json>
             --committee <committee.bin> --tls <dir> --share <file>
             [--state <file>] [--audit-log <file>] [--chains <caip2,caip2>] [--mask-ttl-s <n>]
             [--metrics-listen <addr:port>]
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
                  [--tls-cert <kms.pem> --tls-key <kms.key>] [--metrics-listen <addr:port>]
      Requests must be signed (AWS SigV4) with those credentials; the secret may also come
      from CAIRN_KMS_SECRET_ACCESS_KEY. Without credentials the endpoint binds loopback only.
      KMS-compatible endpoint for pqc-sidecar's aws_kms backend. Without --peers the tower runs
      inside this process.
      With --tls-cert the endpoint speaks HTTPS; give the caller the certificate as its trust
      root (for pqc-sidecar: SSL_CERT_FILE=kms.pem). --metrics-listen serves Prometheus
      counters on /metrics and a liveness check on /healthz, unauthenticated.
  cairn share-recover --id party_<k> --identity <file> --roster <file> --committee <committee.bin>
                      --dir <exchange dir> --out <dir> [--wait-secs <n>]
  cairn share-help --share <party_j.share> --identity <file> --roster <file>
                   --committee <committee.bin> --request <request.bin> --out <reply-j.bin>
      Restore a party's share after its machine is lost, from the other parties, without
      changing the key. Every secret received is checked against the committee's public keys.
      This does not invalidate a leaked copy of the old share.
  cairn kms-cert --out <dir> [--host <name-or-ip>[,<name-or-ip>...]]
  cairn kms-failover --listen <addr:port> --backends <addr:port>,<addr:port>[,...]
                     [--connect-timeout-ms <n>]
      TCP relay in front of several `serve-kms` coordinators: each connection goes to the
      first that accepts it. Holds no key. Run it beside the sidecar.
  cairn tls-rotate --tls <dir> --id <node>      (new node certificate, made on this machine)
  cairn tls-pin --tls <dir> --id <node> --fingerprint <hex>
  cairn tls-unpin --tls <dir> --id <node> [--fingerprint <hex>]   (revoke one or all)
      Self-signed certificate and key for the KMS endpoint's HTTPS listener.
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

/// The committee's shape, from `--members <file>` (a roster: who is on the committee) or
/// `--committee T-of-N`. With a roster, party `k` is its `k`-th member.
fn committee_shape(
    args: &[String],
) -> Result<(usize, usize, Option<cairn_core::Roster>, String), String> {
    use cairn_core::RosterProvider as _;
    match (arg(args, "--members"), arg(args, "--committee")) {
        (Some(_), Some(_)) => Err("give --members or --committee, not both".into()),
        (Some(file), None) => {
            let roster = cairn_core::FileRoster(PathBuf::from(file))
                .roster()
                .map_err(|e| e.to_string())?;
            let (t, n) = roster.flat_shape().map_err(|e| e.to_string())?;
            Ok((t, n, Some(roster), format!("{t}-of-{n}")))
        }
        (None, Some(spec)) => {
            let (t, n) = spec
                .split_once("-of-")
                .and_then(|(t, n)| Some((t.parse::<usize>().ok()?, n.parse::<usize>().ok()?)))
                .ok_or("--committee expects T-of-N, for example 3-of-4")?;
            Ok((t, n, None, spec))
        }
        (None, None) => Err("needs --committee T-of-N or --members <roster.json>".into()),
    }
}

/// Record which member is which party: `members.json` beside the keys.
fn write_members(out: &std::path::Path, roster: &cairn_core::Roster) -> Result<(), String> {
    let members: Vec<serde_json::Value> = roster
        .members
        .iter()
        .enumerate()
        .map(|(k, m)| {
            json!({ "node": format!("party_{}", k + 1), "id": m.id, "public_key": m.public_key, "weight": m.weight })
        })
        .collect();
    std::fs::write(
        out.join("members.json"),
        serde_json::to_string_pretty(&json!({ "threshold": roster.threshold, "members": members }))
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
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

/// `--tls <dir>`: this node's certificate and key and the fingerprint table.
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
            // HTTPS on the listen address, with a certificate from `cairn kms-cert`.
            let server_tls = match (arg(args, "--tls-cert"), arg(args, "--tls-key")) {
                (Some(cert), Some(key)) => Some(
                    cairn_net::tls::ServerTls::load(&PathBuf::from(cert), &PathBuf::from(key))
                        .map_err(|e| e.to_string())?,
                ),
                (None, None) => {
                    if auth.is_some() {
                        eprintln!("cairn: KMS requests travel over plain HTTP (no --tls-cert)");
                    }
                    None
                }
                _ => return Err("--tls-cert and --tls-key go together".into()),
            };
            let metrics = kms::Metrics::new();
            if let Some(addr) = arg(args, "--metrics-listen") {
                let addr = kms::serve_metrics(&addr, metrics.clone()).map_err(|e| e.to_string())?;
                eprintln!("cairn: metrics on http://{addr}/metrics, health on /healthz");
            }
            let options = kms::KmsOptions {
                auth,
                tls: server_tls,
                metrics: Some(metrics),
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
                        parallel_attempts: ms(args, "--parallel-attempts", 2)? as usize,
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
                    kms::serve_opts(&listen, signer, options)
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
                    kms::serve_opts(&listen, signer, options)
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
                    kms::serve_opts(&listen, certifier, options)
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
            if arg(args, "--committee").is_some() || arg(args, "--members").is_some() {
                // A flat committee for the three-round protocol: "--committee 3-of-4", or
                // a roster naming its members.
                let (t, n, roster, spec) = committee_shape(args)?;
                let (key, parties) = threshold_mldsa::mithril::keygen(t, n, &mut OsRng)
                    .ok_or("no parameter set for that committee (N at most 6)")?;
                cairn_net::flat::write_flat_keys(&out, &key, &parties)
                    .map_err(|e| format!("writing keys: {e}"))?;
                let peers = cairn_net::flat::flat_peers(n, &host, base);
                std::fs::write(out.join("peers.json"), net::peers_to_json(&peers))
                    .map_err(|e| e.to_string())?;
                write_public_key(&out.join("public_key.hex"), &key.pk)
                    .map_err(|e| e.to_string())?;
                if let Some(roster) = &roster {
                    write_members(&out, roster)?;
                }
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
                    let audit_log = arg(args, "--audit-log").map(PathBuf::from);
                    let policy: Box<dyn cairn_policy::PolicyEngine> = match arg(args, "--policy")
                        .as_deref()
                    {
                        None | Some("checkpoint") => {
                            let policy = cairn_net::policy::Policy::open(
                                &key.pk,
                                cairn_net::policy::PolicyConfig {
                                    chains: arg(args, "--chains").map(|c| {
                                        c.split(',').map(|x| x.trim().to_owned()).collect()
                                    }),
                                    state_file: arg(args, "--state").map(PathBuf::from),
                                    audit_log,
                                },
                            )
                            .map_err(|e| format!("signing policy state: {e}"))?;
                            if arg(args, "--state").is_none() {
                                eprintln!("cairn node {id}: no --state file; the last signed height is forgotten on restart");
                            }
                            Box::new(cairn_policy::PosCheckpointPolicy::from(policy))
                        }
                        Some("org") => {
                            let rule = arg(args, "--org-rule")
                                .ok_or("--policy org needs --org-rule <rule.json>")?;
                            let approvals = arg(args, "--approvals")
                                .ok_or("--policy org needs --approvals <dir>")?;
                            if audit_log.is_none() {
                                eprintln!("cairn node {id}: no --audit-log; approval decisions are not recorded");
                            }
                            let config = cairn_policy::org::OrgConfig::load(
                                &PathBuf::from(rule),
                                PathBuf::from(approvals),
                                audit_log,
                            )?;
                            eprintln!(
                                "cairn node {id}: organization policy, {} of {} approvers",
                                config.required,
                                config.approvers.len()
                            );
                            Box::new(cairn_policy::OrgGovernancePolicy::new(&key.pk, config)?)
                        }
                        Some(other) => {
                            return Err(format!("unknown --policy {other:?} (checkpoint or org)"))
                        }
                    };
                    let mut node = cairn_net::PartyNode::new(
                        id,
                        Arc::new(key),
                        share,
                        fault,
                        policy,
                        identity,
                    );
                    node.mask_ttl = Duration::from_secs(ms(args, "--mask-ttl-s", 120)?);
                    if let Some(addr) = arg(args, "--metrics-listen") {
                        let stats = node.stats.clone();
                        let at = cairn_sidecar::kms::serve_text_metrics(&addr, move || {
                            stats.render()
                        })
                        .map_err(|e| format!("metrics on {addr}: {e}"))?;
                        eprintln!("cairn node {id}: metrics on http://{at}/metrics");
                    }
                    cairn_net::flat::run_party(listener, node, delay).await;
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
                                policy: cairn_net::node::default_policy(),
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
                        parallel_attempts: ms(args, "--parallel-attempts", 1)? as usize,
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
        Some(cmd @ ("share-recover" | "share-help")) => {
            use cairn_net::dkg::{self, recover};
            let need = |flag: &str| arg(args, flag).ok_or(format!("{cmd} needs {flag}"));
            let read = |flag: &str| {
                let file = need(flag)?;
                std::fs::read(&file).map_err(|e| format!("{file}: {e}"))
            };
            let identity = dkg::Identity::from_pkcs8(&read("--identity")?)?;
            let roster = dkg::roster_from_json(&String::from_utf8_lossy(&read("--roster")?))?;
            let key = cairn_net::flat::read_committee(&PathBuf::from(need("--committee")?))
                .map_err(|e| e.to_string())?;
            if cmd == "share-help" {
                let share = cairn_net::flat::read_party_share(&PathBuf::from(need("--share")?))
                    .map_err(|e| e.to_string())?;
                let request: recover::Request =
                    bincode::deserialize(&read("--request")?).map_err(|e| e.to_string())?;
                let reply = recover::help(&identity, &roster, &key, &share, &request)?;
                let out = need("--out")?;
                std::fs::write(&out, bincode::serialize(&reply).map_err(|e| e.to_string())?)
                    .map_err(|e| format!("{out}: {e}"))?;
                eprintln!(
                    "cairn: sealed the secrets party {} shares with party {} into {out}",
                    share.index + 1,
                    request.index + 1
                );
                return Ok(());
            }
            let NodeId::Party(number) = need("--id")?.parse::<NodeId>()? else {
                return Err("--id must be party_<k>".into());
            };
            let dir = PathBuf::from(need("--dir")?);
            let out = PathBuf::from(need("--out")?);
            let wait = Duration::from_secs(ms(args, "--wait-secs", 3600)?);
            let (mut pending, request) =
                recover::Pending::begin(&identity, &roster, &key, number - 1)?;
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(
                dir.join("request.bin"),
                bincode::serialize(&request).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            eprintln!(
                "cairn: wrote {}; give it to the other parties and put their replies in {} as \
                 reply-*.bin. Keep this process running: the decryption keys exist only here.",
                dir.join("request.bin").display(),
                dir.display()
            );
            let started = std::time::Instant::now();
            let mut seen = std::collections::BTreeSet::new();
            while !pending.missing(&key).is_empty() {
                if started.elapsed() > wait {
                    return Err(format!(
                        "gave up with {} subset secret(s) missing; start again with a new request",
                        pending.missing(&key).len()
                    ));
                }
                std::thread::sleep(Duration::from_millis(500));
                for entry in std::fs::read_dir(&dir)
                    .map_err(|e| e.to_string())?
                    .flatten()
                {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    // Keyed by size too, so a file caught half-written is read again.
                    let size = entry.metadata().map_or(0, |m| m.len());
                    if !name.starts_with("reply-") || !seen.insert((name.clone(), size)) {
                        continue;
                    }
                    let outcome = std::fs::read(entry.path())
                        .map_err(|e| e.to_string())
                        .and_then(|b| {
                            bincode::deserialize::<recover::Reply>(&b).map_err(|e| e.to_string())
                        })
                        .and_then(|reply| pending.accept(&roster, &key, &reply));
                    match outcome {
                        Ok(left) => eprintln!("cairn: {name} accepted, {left} subset(s) missing"),
                        Err(e) => eprintln!("cairn: {name} refused: {e}"),
                    }
                }
            }
            let share = pending.finish(&key)?;
            cairn_net::flat::write_party_files(&out, &key, &share).map_err(|e| e.to_string())?;
            eprintln!(
                "cairn: share of party {number} restored into {}",
                out.display()
            );
            Ok(())
        }
        Some(cmd @ ("tls-rotate" | "tls-pin" | "tls-unpin")) => {
            let dir = PathBuf::from(arg(args, "--tls").ok_or("needs --tls <dir>")?);
            let id: NodeId = arg(args, "--id")
                .ok_or("needs --id <node>, e.g. party_2 or coordinator")?
                .parse()
                .map_err(|e| format!("--id: {e}"))?;
            let fingerprint = arg(args, "--fingerprint");
            let out = match cmd {
                "tls-rotate" => {
                    let (old, new) = cairn_net::tls::rotate(&dir, id).map_err(|e| e.to_string())?;
                    json!({ "node": id.to_string(), "fingerprint": new, "replaces": old,
                        "next": "every peer runs `cairn tls-pin` with this fingerprint; restart this node; then every peer runs `cairn tls-unpin` with the replaced one" })
                }
                "tls-pin" => {
                    let fp = fingerprint.ok_or("tls-pin needs --fingerprint <hex>")?;
                    cairn_net::tls::pin(&dir, id, &fp).map_err(|e| e.to_string())?;
                    json!({ "node": id.to_string(), "pinned": fp })
                }
                _ => {
                    let removed = cairn_net::tls::unpin(&dir, id, fingerprint.as_deref())
                        .map_err(|e| e.to_string())?;
                    json!({ "node": id.to_string(), "removed": removed })
                }
            };
            println!("{out}");
            Ok(())
        }
        Some("kms-failover") => {
            let listen = arg(args, "--listen").ok_or("kms-failover needs --listen <addr:port>")?;
            let backends = arg(args, "--backends")
                .ok_or("kms-failover needs --backends <addr:port>,<addr:port>")?
                .split(',')
                .map(|b| {
                    use std::net::ToSocketAddrs;
                    b.to_socket_addrs()
                        .ok()
                        .and_then(|mut found| found.next())
                        .ok_or(format!("--backends: cannot resolve {b}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let timeout = Duration::from_millis(ms(args, "--connect-timeout-ms", 1000)?);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::bind(&listen)
                    .await
                    .map_err(|e| format!("bind {listen}: {e}"))?;
                eprintln!("cairn kms-failover: {listen} -> {backends:?}");
                cairn_net::failover::relay(listener, backends, timeout).await;
                Ok(())
            })
        }
        Some("approver-keygen") => {
            use std::os::unix::fs::OpenOptionsExt;
            let name = arg(args, "--name").ok_or("approver-keygen needs --name <approver>")?;
            let out = PathBuf::from(arg(args, "--out").ok_or("approver-keygen needs --out <dir>")?);
            let seed: [u8; 32] = rand::random();
            let key = cairn_policy::org::ApproverKey::from_seed(&name, &seed)
                .ok_or("approver names use a-z, 0-9, - and _ only")?;
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            let (secret, public) = (
                out.join(format!("{name}.approver.key")),
                out.join(format!("{name}.approver.pub")),
            );
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&secret)
                .map_err(|e| format!("{}: {e}", secret.display()))?;
            use std::io::Write as _;
            writeln!(f, "{}", hex::encode(seed)).map_err(|e| e.to_string())?;
            std::fs::write(&public, format!("{}\n", hex::encode(key.public_key())))
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({ "approver": name, "key": secret, "public_key": public })
            );
            Ok(())
        }
        Some("approve") => {
            let name = arg(args, "--name").ok_or("approve needs --name <approver>")?;
            let read = |flag: &str| -> Result<Vec<u8>, String> {
                let path = arg(args, flag).ok_or(format!("approve needs {flag} <file>"))?;
                std::fs::read(&path).map_err(|e| format!("{path}: {e}"))
            };
            let seed: [u8; 32] = std::str::from_utf8(&read("--key")?)
                .ok()
                .and_then(|text| hex::decode(text.trim()).ok())
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or("--key is not an approver key file")?;
            let committee = read_public_key(&PathBuf::from(
                arg(args, "--committee-key")
                    .ok_or("approve needs --committee-key <public_key.hex>")?,
            ))?;
            let payload = read("--payload")?;
            let out =
                PathBuf::from(arg(args, "--out").ok_or("approve needs --out <approvals dir>")?);
            let ttl: u64 = arg(args, "--ttl-secs")
                .map_or(Ok(3600), |v| v.parse())
                .map_err(|_| "bad --ttl-secs")?;
            let not_after = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs()
                + ttl;
            let approval = cairn_policy::org::ApproverKey::from_seed(&name, &seed)
                .ok_or("approver names use a-z, 0-9, - and _ only")?
                .approve(&committee, &payload, not_after);
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            let path = approval.write(&out).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({ "approver": name, "payload_sha3": hex::encode(approval.payload_sha3), "not_after": not_after, "file": path })
            );
            Ok(())
        }
        Some("kms-cert") => {
            use std::os::unix::fs::OpenOptionsExt;
            let out = PathBuf::from(arg(args, "--out").ok_or("kms-cert needs --out <dir>")?);
            let hosts: Vec<String> = arg(args, "--host")
                .unwrap_or_else(|| "localhost,127.0.0.1".into())
                .split(',')
                .map(str::to_owned)
                .collect();
            let (cert, key) =
                cairn_net::tls::ServerTls::self_signed(&hosts).map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            std::fs::write(out.join("kms.pem"), cert).map_err(|e| e.to_string())?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(out.join("kms.key"))
                .map_err(|e| format!("kms.key: {e}"))?;
            std::io::Write::write_all(&mut f, key.as_bytes()).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({ "cert": out.join("kms.pem"), "key": out.join("kms.key"), "hosts": hosts })
            );
            Ok(())
        }
        Some("identity") => {
            use std::os::unix::fs::OpenOptionsExt;
            let out = PathBuf::from(arg(args, "--out").ok_or("identity needs --out <file>")?);
            let identity = cairn_net::dkg::Identity::generate()?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&out)
                .map_err(|e| format!("{}: {e}", out.display()))?;
            std::io::Write::write_all(&mut f, identity.to_pkcs8()).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({ "identity_file": out, "public": hex::encode(identity.public()) })
            );
            Ok(())
        }
        Some("committee-init") => {
            // Local and test convenience: one machine makes every identity and the TLS
            // certificates. It never makes the signing key; `cairn dkg` does that jointly.
            let out = PathBuf::from(arg(args, "--out").ok_or("committee-init needs --out <dir>")?);
            let (t, n, mut members, spec) = committee_shape(args)?;
            if threshold_mldsa::mithril::params_65(t, n).is_none() {
                return Err("no parameter set for that committee (N at most 6)".into());
            }
            let t = t as u8;
            let host = arg(args, "--host").unwrap_or_else(|| "127.0.0.1".into());
            let base: u16 = arg(args, "--base-port")
                .map_or(Ok(7300), |v| v.parse())
                .map_err(|_| "bad --base-port")?;
            let mut identities = Vec::new();
            for k in 1..=n {
                use std::os::unix::fs::OpenOptionsExt;
                let dir = out.join(format!("party_{k}"));
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let identity = cairn_net::dkg::Identity::generate()?;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(dir.join("identity.pk8"))
                    .map_err(|e| e.to_string())?;
                std::io::Write::write_all(&mut f, identity.to_pkcs8())
                    .map_err(|e| e.to_string())?;
                // The roster's key for a member is the identity made for it here.
                if let Some(member) = members.as_mut().map(|r| &mut r.members[k - 1]) {
                    member.public_key = hex::encode(identity.public());
                }
                identities.push(identity.public());
            }
            if let Some(roster) = &members {
                write_members(&out, roster)?;
            }
            let roster = cairn_net::dkg::Roster {
                threshold: t,
                identities,
            };
            std::fs::write(
                out.join("roster.json"),
                cairn_net::dkg::roster_to_json(&roster),
            )
            .map_err(|e| e.to_string())?;
            let peers = cairn_net::flat::flat_peers(n, &host, base);
            std::fs::write(out.join("peers.json"), net::peers_to_json(&peers))
                .map_err(|e| e.to_string())?;
            let mut ids: Vec<NodeId> = peers.keys().copied().collect();
            ids.push(NodeId::Coordinator);
            cairn_net::ClusterTls::generate(&ids)
                .and_then(|tls| tls.write(&out.join("tls")))
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({ "out": out, "committee": spec, "next": "start `cairn dkg-party` for each party, then `cairn dkg`" })
            );
            Ok(())
        }
        Some("dkg-party") => {
            let id: NodeId = arg(args, "--id")
                .ok_or("dkg-party needs --id party_<k>")?
                .parse()?;
            let bind = arg(args, "--bind").ok_or("dkg-party needs --bind <addr:port>")?;
            let out = PathBuf::from(arg(args, "--out").ok_or("dkg-party needs --out <dir>")?);
            let roster = cairn_net::dkg::roster_from_json(
                &std::fs::read_to_string(
                    arg(args, "--roster").ok_or("dkg-party needs --roster <file>")?,
                )
                .map_err(|e| e.to_string())?,
            )?;
            let identity = cairn_net::dkg::Identity::from_pkcs8(
                &std::fs::read(arg(args, "--identity").ok_or("dkg-party needs --identity <file>")?)
                    .map_err(|e| e.to_string())?,
            )?;
            let identity_tls = tls(args, id)?;
            let node = Arc::new(cairn_net::dkg::DkgNode::new(
                id,
                roster,
                &identity,
                out.clone(),
            ));
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::bind(&bind).await.map_err(|e| format!("bind {bind}: {e}"))?;
                eprintln!("cairn dkg-party {id}: waiting for key generation on {bind}");
                tokio::select! {
                    _ = cairn_net::transport::serve(listener, node.clone(), Duration::ZERO, identity_tls) => {}
                    _ = node.finished() => {
                        // Let the last reply leave before exiting.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                }
                eprintln!("cairn dkg-party {id}: wrote committee.bin and its share to {}", out.display());
                Ok(())
            })
        }
        Some("dkg") => {
            let roster = cairn_net::dkg::roster_from_json(
                &std::fs::read_to_string(arg(args, "--roster").ok_or("dkg needs --roster <file>")?)
                    .map_err(|e| e.to_string())?,
            )?;
            let peers = peers(args)?.ok_or("dkg needs --peers")?;
            let link = Link::new(
                Duration::from_millis(ms(args, "--round-timeout-ms", 20_000)?),
                Duration::ZERO,
                tls(args, NodeId::Coordinator)?,
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let pk = runtime.block_on(cairn_net::dkg::run(&roster, &peers, &link))?;
            if let Some(path) = arg(args, "--public-key-out") {
                write_public_key(&PathBuf::from(path), &pk).map_err(|e| e.to_string())?;
            }
            println!(
                "{}",
                json!({ "generated": true, "parties": roster.n(), "threshold": roster.threshold, "key_id": hex::encode(cairn_sidecar::key_id(&pk)) })
            );
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

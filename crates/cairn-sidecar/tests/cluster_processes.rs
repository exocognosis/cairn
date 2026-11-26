//! The tower as separate OS processes over TCP, and a stock pqc-sidecar signing through it.
//!
//! Every node here is its own `cairn` process: 16 signers, 4 root engines, 1 MPC reference
//! worker, plus `cairn serve-kms` as the coordinator and `cairn mock-chain` as the chain RPC.
//!
//! The live test needs the unmodified pqc-sidecar binary (`scripts/setup-verifiers.sh`, or
//! `CAIRN_PQC_SIDECAR_BIN`). Without it the test prints `SKIPPED`, unless
//! `CAIRN_REQUIRE_EXTERNAL_VERIFIERS=1`.

use cairn_net::{FaultMode, NetPolicy, NodeId, CHECKPOINT_DOMAIN};
use cairn_sidecar::cluster::{
    free_ports, mock_block, sidecar_config, wait_for_port, ClusterOptions, ClusterSigner,
    ProcessCluster,
};
use cairn_sidecar::Certificate;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204;

const CAIRN: &str = env!("CARGO_BIN_EXE_cairn");

fn work_dir(tag: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}", std::process::id()))
}

fn options(tag: &str, seed: [u8; 32], faults: Vec<(NodeId, FaultMode)>) -> ClusterOptions {
    ClusterOptions {
        exe: CAIRN.into(),
        dir: work_dir(tag),
        seed,
        faults,
        link_delay_ms: 0,
        round_timeout_ms: 500,
        node_args: Vec::new(),
    }
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sixteen_signer_processes_sign_over_tcp_with_faulty_peers() {
    let seed = [91u8; 32];
    let faults = vec![
        (NodeId::Signer { leaf: 1, signer: 1 }, FaultMode::Stall),
        (NodeId::Signer { leaf: 3, signer: 2 }, FaultMode::BadShare),
        (NodeId::Root(1), FaultMode::BadResponse),
    ];
    let cluster = ProcessCluster::spawn(&options("procs", seed, faults)).unwrap();
    assert_eq!(
        cluster.processes(),
        21,
        "16 signers, 4 root engines, 1 MPC worker"
    );
    let policy = NetPolicy {
        round_timeout: Duration::from_millis(500),
        ..NetPolicy::default()
    };
    let mut signer = ClusterSigner::new(
        cluster.group.clone(),
        cluster.peers.clone(),
        policy,
        cluster.coordinator_tls().unwrap(),
    )
    .unwrap();

    let message = [CHECKPOINT_DOMAIN, b" processes"].concat();
    let start = Instant::now();
    let (signature, report) = signer.sign_with_report(&message).unwrap();
    // Byte-identical to one deterministic FIPS 204 signer holding the whole key.
    assert_eq!(
        signature,
        fips204::sign_reference(&fips204::keygen_internal(&seed), &message).0
    );
    assert!(
        start.elapsed() >= Duration::from_millis(500),
        "the stalled process cost a real deadline"
    );
    let culprits: Vec<_> = report.faults.iter().filter_map(|f| f.culprit).collect();
    assert_eq!(culprits.len(), 3, "{:?}", report.faults);
    for bad in [
        NodeId::Signer { leaf: 1, signer: 1 },
        NodeId::Signer { leaf: 3, signer: 2 },
        NodeId::Root(1),
    ] {
        assert!(
            culprits.contains(&bad),
            "{bad} not named in {:?}",
            report.faults
        );
    }

    // All three are excluded now: the next checkpoint runs clean.
    let (_, report) = signer
        .sign_with_report(&[CHECKPOINT_DOMAIN, b" again"].concat())
        .unwrap();
    assert!(
        report.faults.is_empty() && report.retries == 0,
        "{:?}",
        report.faults
    );
}

fn off_the_shelf_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk = EncodedVerifyingKey::<MlDsa65>::try_from(pk).unwrap();
    let Ok(sig) = Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(message, &[], &sig)
}

fn sidecar_binary() -> Option<PathBuf> {
    let default =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/pqc-sidecar/release/pqc-sidecar");
    let path = std::env::var_os("CAIRN_PQC_SIDECAR_BIN")
        .map(PathBuf::from)
        .unwrap_or(default);
    if path.exists() {
        return Some(path);
    }
    assert!(
        std::env::var_os("CAIRN_REQUIRE_EXTERNAL_VERIFIERS").is_none(),
        "pqc-sidecar binary not found at {}",
        path.display()
    );
    eprintln!(
        "SKIPPED: pqc-sidecar binary not found at {} (set CAIRN_PQC_SIDECAR_BIN)",
        path.display()
    );
    None
}

#[test]
fn stock_pqc_sidecar_signs_a_live_checkpoint_through_the_cluster() {
    let Some(sidecar) = sidecar_binary() else {
        return;
    };
    let cluster = ProcessCluster::spawn(&options("live", rand::random(), vec![])).unwrap();
    let work = cluster.dir.clone();
    let ports = free_ports(3).unwrap();
    let (kms, rpc) = (
        format!("127.0.0.1:{}", ports[0]),
        format!("127.0.0.1:{}", ports[1]),
    );
    let log =
        |name: &str| Stdio::from(std::fs::File::create(work.join(format!("{name}.log"))).unwrap());

    // Coordinator: the KMS-compatible endpoint, signing through the TCP cluster.
    let _kms = Kill(
        Command::new(CAIRN)
            .args([
                "serve-kms",
                "--listen",
                &kms,
                "--round-timeout-ms",
                "1000",
                "--peers",
            ])
            .arg(&cluster.peers_file)
            .arg("--group")
            .arg(&cluster.group_file)
            .arg("--tls")
            .arg(&cluster.tls_dir)
            .stderr(log("serve-kms"))
            .spawn()
            .unwrap(),
    );
    // Chain: a CometBFT RPC stand-in whose tip is at height 150.
    let chain = "cairn-devnet-1";
    let _chain = Kill(
        Command::new(CAIRN)
            .args([
                "mock-chain",
                "--listen",
                &rpc,
                "--chain-id",
                chain,
                "--height",
                "150",
            ])
            .stderr(log("mock-chain"))
            .spawn()
            .unwrap(),
    );
    assert!(
        wait_for_port(&kms, Duration::from_secs(20))
            && wait_for_port(&rpc, Duration::from_secs(20))
    );

    let config = work.join("pqc-sidecar.toml");
    let text = sidecar_config(
        &format!("http://{kms}"),
        &format!("http://{rpc}"),
        chain,
        &work,
        ports[2],
    );
    std::fs::write(&config, text).unwrap();
    let stock = |args: &[&str]| {
        let mut cmd = Command::new(&sidecar);
        // Placeholder credentials: the endpoint is local and ignores request signatures.
        cmd.args(args)
            .env("AWS_ACCESS_KEY_ID", "local")
            .env("AWS_SECRET_ACCESS_KEY", "local")
            .env("AWS_EC2_METADATA_DISABLED", "true");
        cmd
    };

    // 1. GetPublicKey, by the stock binary's own KMS client.
    let pk_file = work.join("public_key.hex");
    let out = stock(&[
        "kms-public-key",
        "--config",
        config.to_str().unwrap(),
        "--public-key-out",
        pk_file.to_str().unwrap(),
    ])
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "kms-public-key: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pk = hex::decode(std::fs::read_to_string(&pk_file).unwrap().trim()).unwrap();
    assert_eq!(
        pk, cluster.group.pk,
        "the sidecar read the tower's public key"
    );

    // 2. Live Sign: run the stock daemon until it has written the checkpoint at height 100.
    let daemon = Kill(
        stock(&["--config", config.to_str().unwrap()])
            .stdout(log("pqc-sidecar"))
            .stderr(log("pqc-sidecar-err"))
            .spawn()
            .unwrap(),
    );
    let cert_file = work.join("certs/00000000000000000100.pqcc");
    let start = Instant::now();
    while !cert_file.exists() {
        if start.elapsed() > Duration::from_secs(90) {
            let tail = |f: &str| std::fs::read_to_string(work.join(f)).unwrap_or_default();
            panic!(
                "pqc-sidecar wrote no certificate.\nsidecar: {}\n{}\nkms: {}",
                tail("pqc-sidecar.log"),
                tail("pqc-sidecar-err.log"),
                tail("serve-kms.log")
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(200));
    drop(daemon);

    // 3. The certificate the stock sidecar wrote is a standard one over the mock block.
    let bytes = std::fs::read(&cert_file).unwrap();
    let certificate = Certificate::from_bytes(&bytes).unwrap();
    let (block_hash, validators_hash) = mock_block(chain, 100);
    assert_eq!(certificate.checkpoint.chain, format!("cosmos:{chain}"));
    assert_eq!(certificate.checkpoint.height, 100);
    assert_eq!(
        hex::encode_upper(&certificate.checkpoint.block_hash),
        block_hash
    );
    assert_eq!(
        hex::encode_upper(&certificate.checkpoint.finality_commitment),
        validators_hash
    );
    let message = certificate
        .checkpoint
        .signing_message(&certificate.key_id)
        .unwrap();
    assert!(
        off_the_shelf_verify(&pk, &message, certificate.signature.as_slice()),
        "RustCrypto ml-dsa accepts"
    );

    let mut tampered = bytes.clone();
    let at = tampered.len() - 3309 + 100; // inside the signature's z encoding
    tampered[at] ^= 1;
    let bad_file = work.join("tampered.pqcc");
    std::fs::write(&bad_file, &tampered).unwrap();
    let bad = Certificate::from_bytes(&tampered).unwrap();
    assert!(
        !off_the_shelf_verify(&pk, &message, bad.signature.as_slice()),
        "RustCrypto ml-dsa rejects tampering"
    );

    let verify = |file: &Path| {
        stock(&[
            "verify",
            "--certificate",
            file.to_str().unwrap(),
            "--public-key",
            pk_file.to_str().unwrap(),
        ])
        .output()
        .unwrap()
    };
    let ok = verify(&cert_file);
    assert!(
        ok.status.success(),
        "pqc-sidecar verify: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stdout).contains("\"valid\":true"));
    assert!(
        !verify(&bad_file).status.success(),
        "pqc-sidecar verify rejects tampering"
    );
    eprintln!(
        "stock pqc-sidecar certificate: {}",
        String::from_utf8_lossy(&ok.stdout).trim()
    );
}

#[test]
fn stock_pqc_sidecar_signs_through_a_three_round_committee() {
    use cairn_sidecar::cluster::ProcessCommittee;
    let Some(sidecar) = sidecar_binary() else {
        return;
    };
    let work = work_dir("committee");
    // Four party processes, threshold three, no MPC backend and no root engines.
    let committee = ProcessCommittee::spawn(Path::new(CAIRN), &work, 3, 4, &[], 0, 5000).unwrap();
    let ports = free_ports(3).unwrap();
    let (kms, rpc) = (
        format!("127.0.0.1:{}", ports[0]),
        format!("127.0.0.1:{}", ports[1]),
    );
    let log =
        |name: &str| Stdio::from(std::fs::File::create(work.join(format!("{name}.log"))).unwrap());
    let _kms = Kill(
        Command::new(CAIRN)
            .args([
                "serve-kms",
                "--listen",
                &kms,
                "--access-key-id",
                "local",
                "--peers",
            ])
            .env("CAIRN_KMS_SECRET_ACCESS_KEY", "local")
            .arg(&committee.peers_file)
            .arg("--committee")
            .arg(&committee.committee_file)
            .arg("--tls")
            .arg(&committee.tls_dir)
            .stderr(log("serve-kms"))
            .spawn()
            .unwrap(),
    );
    let chain = "cairn-devnet-1";
    let _chain = Kill(
        Command::new(CAIRN)
            .args([
                "mock-chain",
                "--listen",
                &rpc,
                "--chain-id",
                chain,
                "--height",
                "150",
            ])
            .stderr(log("mock-chain"))
            .spawn()
            .unwrap(),
    );
    assert!(
        wait_for_port(&kms, Duration::from_secs(20))
            && wait_for_port(&rpc, Duration::from_secs(20))
    );
    let config = work.join("pqc-sidecar.toml");
    std::fs::write(
        &config,
        sidecar_config(
            &format!("http://{kms}"),
            &format!("http://{rpc}"),
            chain,
            &work,
            ports[2],
        ),
    )
    .unwrap();
    let stock = |args: &[&str]| {
        let mut cmd = Command::new(&sidecar);
        cmd.args(args)
            .env("AWS_ACCESS_KEY_ID", "local")
            .env("AWS_SECRET_ACCESS_KEY", "local")
            .env("AWS_EC2_METADATA_DISABLED", "true");
        cmd
    };
    let pk_file = work.join("public_key.hex");
    let out = stock(&[
        "kms-public-key",
        "--config",
        config.to_str().unwrap(),
        "--public-key-out",
        pk_file.to_str().unwrap(),
    ])
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "kms-public-key: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pk = hex::decode(std::fs::read_to_string(&pk_file).unwrap().trim()).unwrap();
    assert_eq!(pk, committee.key.pk);

    // The endpoint checks the request signature: the same call with another secret is refused.
    let denied = Command::new(&sidecar)
        .args([
            "kms-public-key",
            "--config",
            config.to_str().unwrap(),
            "--public-key-out",
        ])
        .arg(work.join("denied.hex"))
        .env("AWS_ACCESS_KEY_ID", "local")
        .env("AWS_SECRET_ACCESS_KEY", "not-the-secret")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "a request signed with the wrong secret must be refused"
    );

    let daemon = Kill(
        stock(&["--config", config.to_str().unwrap()])
            .stdout(log("pqc-sidecar"))
            .stderr(log("pqc-sidecar-err"))
            .spawn()
            .unwrap(),
    );
    let cert_file = work.join("certs/00000000000000000100.pqcc");
    let start = Instant::now();
    while !cert_file.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "pqc-sidecar wrote no certificate"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(200));
    drop(daemon);

    let bytes = std::fs::read(&cert_file).unwrap();
    let certificate = Certificate::from_bytes(&bytes).unwrap();
    assert_eq!(certificate.checkpoint.height, 100);
    let message = certificate
        .checkpoint
        .signing_message(&certificate.key_id)
        .unwrap();
    assert!(
        off_the_shelf_verify(&pk, &message, certificate.signature.as_slice()),
        "RustCrypto ml-dsa accepts"
    );
    let verify = |file: &Path| {
        stock(&[
            "verify",
            "--certificate",
            file.to_str().unwrap(),
            "--public-key",
            pk_file.to_str().unwrap(),
        ])
        .output()
        .unwrap()
    };
    assert!(
        verify(&cert_file).status.success(),
        "unmodified pqc-sidecar verify accepts"
    );
    let mut tampered = bytes.clone();
    let at = tampered.len() - 3309 + 100;
    tampered[at] ^= 1;
    let bad_file = work.join("tampered.pqcc");
    std::fs::write(&bad_file, &tampered).unwrap();
    assert!(
        !verify(&bad_file).status.success(),
        "pqc-sidecar verify rejects tampering"
    );
}

#[test]
fn processes_generate_a_key_together_and_sign_with_it() {
    use cairn_net::{NetPolicy as Policy, Peers};
    use cairn_sidecar::cluster::CommitteeSigner;
    let work = work_dir("dkg");
    let _ = std::fs::remove_dir_all(&work);
    let ports = free_ports(3).unwrap();
    let base = ports[0];
    let run = |args: &[&str]| {
        let out = Command::new(CAIRN).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "cairn {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let keys = work.join("keys");
    let (keys_s, base_s) = (keys.to_str().unwrap().to_owned(), base.to_string());
    // Identities, roster and TLS for a 2-of-3 committee on consecutive ports.
    run(&[
        "committee-init",
        "--out",
        &keys_s,
        "--committee",
        "2-of-3",
        "--base-port",
        &base_s,
    ]);
    let roster = keys.join("roster.json");
    let (peers_file, tls) = (keys.join("peers.json"), keys.join("tls"));
    // Use three independently free ports rather than the consecutive ones init wrote.
    let peers: Peers = (1..=3u8)
        .zip(&ports)
        .map(|(k, p)| (NodeId::Party(k), format!("127.0.0.1:{p}")))
        .collect();
    std::fs::write(&peers_file, cairn_net::cluster::peers_to_json(&peers)).unwrap();

    // Three key-generation processes, then the driver.
    let mut dkg_parties: Vec<Kill> = (1..=3)
        .map(|k| {
            let dir = keys.join(format!("party_{k}"));
            Command::new(CAIRN)
                .args([
                    "dkg-party",
                    "--id",
                    &format!("party_{k}"),
                    "--bind",
                    &peers[&NodeId::Party(k as u8)],
                ])
                .arg("--roster")
                .arg(&roster)
                .arg("--identity")
                .arg(dir.join("identity.pk8"))
                .arg("--tls")
                .arg(&tls)
                .arg("--out")
                .arg(&dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map(Kill)
                .unwrap()
        })
        .collect();
    for addr in peers.values() {
        assert!(wait_for_port(addr, Duration::from_secs(20)));
    }
    let pk_file = work.join("public_key.hex");
    run(&[
        "dkg",
        "--roster",
        roster.to_str().unwrap(),
        "--peers",
        peers_file.to_str().unwrap(),
        "--tls",
        tls.to_str().unwrap(),
        "--public-key-out",
        pk_file.to_str().unwrap(),
    ]);
    for child in &mut dkg_parties {
        assert!(
            child.0.wait().unwrap().success(),
            "a key-generation party failed"
        );
    }
    let pk = hex::decode(std::fs::read_to_string(&pk_file).unwrap().trim()).unwrap();

    // Every party ended with the same public key, its own share, and not the whole key.
    let mut nodes = Vec::new();
    for k in 1..=3u16 {
        let dir = keys.join(format!("party_{k}"));
        let committee = cairn_net::flat::read_committee(&dir.join("committee.bin")).unwrap();
        assert_eq!(committee.pk.to_vec(), pk);
        let share =
            cairn_net::flat::read_party_share(&dir.join(format!("party_{k}.share"))).unwrap();
        assert_eq!(
            share.subsets().len(),
            2,
            "a 2-of-3 party holds two of the three subset secrets"
        );
        nodes.push(Kill(
            Command::new(CAIRN)
                .args([
                    "node",
                    "--role",
                    "party",
                    "--id",
                    &format!("party_{k}"),
                    "--bind",
                    &peers[&NodeId::Party(k as u8)],
                ])
                .arg("--peers")
                .arg(&peers_file)
                .arg("--committee")
                .arg(dir.join("committee.bin"))
                .arg("--tls")
                .arg(&tls)
                .arg("--share")
                .arg(dir.join(format!("party_{k}.share")))
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
    }
    for addr in peers.values() {
        assert!(wait_for_port(addr, Duration::from_secs(20)));
    }

    // Sign a checkpoint with the jointly generated key.
    let key = std::sync::Arc::new(
        cairn_net::flat::read_committee(&keys.join("party_1/committee.bin")).unwrap(),
    );
    let tls_id =
        std::sync::Arc::new(cairn_net::TlsIdentity::load(&tls, NodeId::Coordinator).unwrap());
    let policy = || Policy {
        round_timeout: Duration::from_secs(5),
        ..Policy::default()
    };
    let mut signer = CommitteeSigner::new(key.clone(), peers.clone(), policy(), tls_id).unwrap();
    let checkpoint = |height: u64| {
        cairn_net::policy::Checkpoint {
            chain: "cosmos:cairn-test-1".into(),
            epoch: 1,
            height,
            block_hash: vec![1; 32],
            finality_commitment: vec![2; 32],
            key_id: cairn_net::policy::key_id(&pk),
        }
        .message()
    };
    let message = checkpoint(100);
    let (signature, _) = signer.sign_with_report(&message).unwrap();
    assert!(
        off_the_shelf_verify(&pk, &message, &signature),
        "RustCrypto ml-dsa accepts a signature under the generated key"
    );

    // A standby coordinator on "another machine": its own certificate, made there, pinned by
    // the running parties as a second certificate of the coordinator. Nothing is restarted.
    let standby_tls = work.join("standby-tls");
    std::fs::create_dir_all(&standby_tls).unwrap();
    std::fs::copy(
        tls.join("fingerprints.json"),
        standby_tls.join("fingerprints.json"),
    )
    .unwrap();
    let rotated = run(&[
        "tls-rotate",
        "--tls",
        standby_tls.to_str().unwrap(),
        "--id",
        "coordinator",
    ]);
    let rotated: serde_json::Value = serde_json::from_str(&rotated).unwrap();
    run(&[
        "tls-pin",
        "--tls",
        tls.to_str().unwrap(),
        "--id",
        "coordinator",
        "--fingerprint",
        rotated["fingerprint"].as_str().unwrap(),
    ]);
    let standby_id = std::sync::Arc::new(
        cairn_net::TlsIdentity::load(&standby_tls, NodeId::Coordinator).unwrap(),
    );
    let mut standby = CommitteeSigner::new(key, peers, policy(), standby_id).unwrap();
    // Both alive: each signs its own height through the same parties.
    for height in [101, 102, 103] {
        let who = if height == 102 {
            &mut signer
        } else {
            &mut standby
        };
        let message = checkpoint(height);
        let (signature, _) = who.sign_with_report(&message).unwrap();
        assert!(off_the_shelf_verify(&pk, &message, &signature));
    }
    // The parties' own rule holds across coordinators: no second checkpoint at a height.
    let mut conflicting = cairn_net::policy::Checkpoint {
        chain: "cosmos:cairn-test-1".into(),
        epoch: 1,
        height: 103,
        block_hash: vec![9; 32],
        finality_commitment: vec![2; 32],
        key_id: cairn_net::policy::key_id(&pk),
    };
    assert!(signer.sign_with_report(&conflicting.message()).is_err());
    // The first coordinator is gone; the standby carries on.
    drop(signer);
    conflicting.height = 104;
    let message = conflicting.message();
    let (signature, _) = standby.sign_with_report(&message).unwrap();
    assert!(off_the_shelf_verify(&pk, &message, &signature));
}

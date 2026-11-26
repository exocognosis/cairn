//! No chain-specific code: a committee of real processes signs checkpoints for an
//! Ethereum-style and a Solana-style chain id, each party asking an external program (the
//! operator's finality check) before the built-in never-sign-twice rules. The same committee
//! code, started with `--policy hook`, serves a payload that is not a checkpoint at all.

use cairn_sidecar::cluster::ProcessCommittee;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CAIRN: &str = env!("CARGO_BIN_EXE_cairn");

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn cairn(args: &[&str]) -> Result<String, String> {
    let out = Command::new(CAIRN).args(args).output().unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// A stand-in for an operator's own check: allow a payload only if a file named after its
/// SHA3-256 digest exists in `allowed`. A real one would ask a node or a light client.
fn hook(dir: &Path, allowed: &Path) -> PathBuf {
    let path = dir.join("finality-check.sh");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\ndigest=$(sed 's/.*\"payload_sha3\":\"\\([0-9a-f]*\\)\".*/\\1/')\n\
             [ -e '{}'/\"$digest\" ] && exit 0\necho 'block is not final on this node'\nexit 1\n",
            allowed.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn sha3_hex(bytes: &[u8]) -> String {
    use sha3::Digest as _;
    hex::encode(sha3::Sha3_256::digest(bytes))
}

struct Deployment {
    base: PathBuf,
    allowed: PathBuf,
    committee: ProcessCommittee,
    pk_file: PathBuf,
}

fn deploy(tag: &str, policy: &str) -> Deployment {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let allowed = base.join("allowed");
    std::fs::create_dir_all(&allowed).unwrap();
    let hook = hook(&base, &allowed);
    let party_args: Vec<String> = ["--policy", policy, "--policy-command", text(&hook)]
        .map(String::from)
        .to_vec();
    let committee = ProcessCommittee::spawn_with(
        Path::new(CAIRN),
        &base.join("committee"),
        2,
        3,
        &[],
        0,
        5000,
        &party_args,
    )
    .unwrap();
    let pk_file = base.join("public_key.hex");
    std::fs::write(&pk_file, hex::encode(committee.key.pk)).unwrap();
    Deployment {
        base,
        allowed,
        committee,
        pk_file,
    }
}

impl Deployment {
    fn sign(&self, extra: &[&str]) -> Result<serde_json::Value, String> {
        let peers = self.committee.peers_file.clone();
        let mut args = vec![
            "sign",
            "--peers",
            text(&peers),
            "--committee",
            text(&self.committee.committee_file),
            "--tls",
            text(&self.committee.tls_dir),
        ];
        args.extend_from_slice(extra);
        cairn(&args).map(|out| serde_json::from_str(&out).unwrap())
    }
}

#[test]
fn checkpoints_of_any_chain_pass_an_external_check_and_the_built_in_rules() {
    let d = deploy("any-chain", "checkpoint");
    let key_id = cairn_sidecar::key_id(&d.committee.key.pk);
    let checkpoint = |chain: &str, height: u64, hash: u8| cairn_sidecar::Checkpoint {
        chain: chain.into(),
        epoch: 7,
        height,
        block_hash: vec![hash; 32],
        finality_commitment: vec![],
    };
    let sign = |c: &cairn_sidecar::Checkpoint, certificate: &Path| {
        d.sign(&[
            "--chain",
            &c.chain,
            "--epoch",
            "7",
            "--height",
            &c.height.to_string(),
            "--block-hash",
            &hex::encode(&c.block_hash),
            "--certificate-out",
            text(certificate),
        ])
    };
    let finalize = |c: &cairn_sidecar::Checkpoint| {
        let message = c.signing_message(&key_id).unwrap();
        std::fs::write(d.allowed.join(sha3_hex(&message)), b"").unwrap();
    };

    for (chain, slot) in [
        ("eip155:1", 9_000_000u64),
        ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", 250_000_000),
        ("polkadot:91b171bb158e2d3848fa23a9f1c25182", 21_000_000),
    ] {
        let certificate = d.base.join("checkpoint.pqcc");
        let block = checkpoint(chain, slot, 1);
        // The operator's check has not seen this block as final: every party refuses.
        let refused = sign(&block, &certificate).unwrap_err();
        assert!(
            refused.contains("block is not final on this node"),
            "{refused}"
        );
        // Once it has, the committee signs and the certificate verifies.
        finalize(&block);
        sign(&block, &certificate).unwrap();
        cairn(&[
            "verify",
            "--certificate",
            text(&certificate),
            "--public-key",
            text(&d.pk_file),
        ])
        .unwrap();
        // A second block at the same slot is refused by the built-in rules even though the
        // external check allows it; an earlier slot likewise.
        for conflicting in [checkpoint(chain, slot, 2), checkpoint(chain, slot - 1, 3)] {
            finalize(&conflicting);
            let refused = sign(&conflicting, &certificate).unwrap_err();
            assert!(refused.contains("height"), "{refused}");
        }
    }
    drop(d.committee);
    let _ = std::fs::remove_dir_all(&d.base);
}

#[test]
fn an_external_check_alone_decides_for_payloads_that_are_not_checkpoints() {
    let d = deploy("hook-only", "hook");
    let payload = d.base.join("payload.bin");
    std::fs::write(&payload, b"firmware 2.1 for device class B").unwrap();
    let refused = d.sign(&["--payload", text(&payload)]).unwrap_err();
    assert!(
        refused.contains("block is not final on this node"),
        "{refused}"
    );

    std::fs::write(
        d.allowed.join(sha3_hex(b"firmware 2.1 for device class B")),
        b"",
    )
    .unwrap();
    let signed = d.sign(&["--payload", text(&payload)]).unwrap();
    let signature = hex::decode(signed["signature_hex"].as_str().unwrap()).unwrap();
    assert!(cairn_core::verify(
        &d.committee.key.pk,
        b"firmware 2.1 for device class B",
        &signature
    ));
    drop(d.committee);
    let _ = std::fs::remove_dir_all(&d.base);
}

#[test]
fn a_roster_can_come_from_any_program() {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("roster-cmd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("validators.sh");
    std::fs::write(
        &source,
        "#!/bin/sh\necho '{\"threshold\":3,\"members\":[{\"id\":\"val-a\"},{\"id\":\"val-b\"},{\"id\":\"val-c\"},{\"id\":\"val-d\"}]}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = dir.join("keys");
    cairn(&[
        "keygen",
        "--out",
        text(&out),
        "--members-command",
        text(&source),
    ])
    .unwrap();
    let members: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("members.json")).unwrap()).unwrap();
    assert_eq!(members["threshold"], 3);
    assert_eq!(members["members"][3]["id"], "val-d");
    assert!(out.join("party_4.share").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

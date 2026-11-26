//! An organization's committee as real processes: three parties running `--policy org`,
//! approvals made with the `cairn approve` command, and a payload that is not a checkpoint.

use cairn_net::{NetPolicy, NodeId, TlsIdentity};
use cairn_sidecar::cluster::{CommitteeSigner, ProcessCommittee};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use threshold_mldsa::fips204::verify_standard;

const CAIRN: &str = env!("CARGO_BIN_EXE_cairn");

fn cairn(args: &[&str]) {
    let out = Command::new(CAIRN).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "cairn {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn an_organization_committee_signs_only_what_two_approvers_approved() {
    let base: PathBuf =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("org-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (org, approvals, work) = (
        base.join("org"),
        base.join("approvals"),
        base.join("committee"),
    );
    std::fs::create_dir_all(&approvals).unwrap();

    // Three approvers, two required.
    let mut approvers = serde_json::Map::new();
    for name in ["alice", "bob", "carol"] {
        cairn(&["approver-keygen", "--name", name, "--out", text(&org)]);
        let public = std::fs::read_to_string(org.join(format!("{name}.approver.pub"))).unwrap();
        approvers.insert(name.into(), public.trim().into());
    }
    let rule = org.join("rule.json");
    std::fs::write(
        &rule,
        serde_json::json!({ "required": 2, "approvers": approvers }).to_string(),
    )
    .unwrap();

    let party_args: Vec<String> = [
        "--policy",
        "org",
        "--org-rule",
        text(&rule),
        "--approvals",
        text(&approvals),
    ]
    .map(String::from)
    .to_vec();
    let committee =
        ProcessCommittee::spawn_with(Path::new(CAIRN), &work, 2, 3, &[], 0, 5000, &party_args)
            .unwrap();
    let mut signer = CommitteeSigner::new(
        committee.key.clone(),
        committee.peers.clone(),
        NetPolicy {
            round_timeout: Duration::from_secs(5),
            ..NetPolicy::default()
        },
        Arc::new(TlsIdentity::load(&committee.tls_dir, NodeId::Coordinator).unwrap()),
    )
    .unwrap();

    let pk = committee.key.pk;
    let pk_file = base.join("public_key.hex");
    std::fs::write(&pk_file, hex::encode(pk)).unwrap();
    let payload = b"release 4.2.0, artifact sha256 9f2c";
    let payload_file = base.join("payload.bin");
    std::fs::write(&payload_file, payload).unwrap();
    let approve = |name: &str| {
        cairn(&[
            "approve",
            "--name",
            name,
            "--key",
            text(&org.join(format!("{name}.approver.key"))),
            "--committee-key",
            text(&pk_file),
            "--payload",
            text(&payload_file),
            "--out",
            text(&approvals),
        ]);
    };

    // No approvals, then one: the parties refuse and say why.
    let refused = signer.sign_with_report(payload).unwrap_err();
    assert!(refused.contains("0 of 2 required approvals"), "{refused}");
    approve("alice");
    let refused = signer.sign_with_report(payload).unwrap_err();
    assert!(refused.contains("1 of 2 required approvals"), "{refused}");

    // Two: a standard signature over the payload itself.
    approve("carol");
    let (signature, _) = signer.sign_with_report(payload).unwrap();
    assert!(verify_standard(&pk, payload, &signature));

    // Another payload is still refused, and every decision is in each party's log.
    assert!(signer.sign_with_report(b"release 6.6.6").is_err());
    let log = std::fs::read_to_string(work.join("party_1.audit.log")).unwrap();
    assert!(log.contains(r#""approved_by":["alice","carol"]"#), "{log}");
    assert!(log.contains(r#""event":"refused""#) && log.contains(r#""event":"authorized""#));
    drop(committee);
    let _ = std::fs::remove_dir_all(&base);
}

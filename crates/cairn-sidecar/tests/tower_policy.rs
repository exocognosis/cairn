//! The tower under an organization's rules: 16 signer and 4 root-engine processes, each
//! running `--policy org` and asking an external program as well. Nothing is signed until
//! two approvers approved the payload and the program allows it.

use cairn_net::NetPolicy;
use cairn_sidecar::cluster::{ClusterOptions, ClusterSigner, ProcessCluster};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
fn tower_nodes_enforce_the_organization_rule_and_an_external_program() {
    let base: PathBuf =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("tower-org-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (org, approvals) = (base.join("org"), base.join("approvals"));
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

    // The operator's own check: refuse everything while a `freeze` file exists.
    let freeze = base.join("freeze");
    let hook = base.join("change-freeze.sh");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\ncat >/dev/null\n[ -e '{}' ] || exit 0\necho 'change freeze in effect'\nexit 1\n",
            freeze.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    let node_args = [
        "--policy",
        "org",
        "--org-rule",
        text(&rule),
        "--approvals",
        text(&approvals),
        "--policy-command",
        text(&hook),
    ]
    .map(String::from)
    .to_vec();
    let cluster = ProcessCluster::spawn(&ClusterOptions {
        exe: CAIRN.into(),
        dir: base.join("tower"),
        seed: [47u8; 32],
        faults: Vec::new(),
        link_delay_ms: 0,
        round_timeout_ms: 5000,
        node_args,
    })
    .unwrap();
    let mut signer = ClusterSigner::new(
        cluster.group.clone(),
        cluster.peers.clone(),
        NetPolicy {
            round_timeout: Duration::from_secs(5),
            ..NetPolicy::default()
        },
        cluster.coordinator_tls().unwrap(),
    )
    .unwrap();

    let pk = cluster.group.pk;
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

    // No approvals, then one: the nodes refuse and say why.
    let refused = signer.sign_with_report(payload).unwrap_err();
    assert!(refused.contains("0 of 2 required approvals"), "{refused}");
    approve("alice");
    let refused = signer.sign_with_report(payload).unwrap_err();
    assert!(refused.contains("1 of 2 required approvals"), "{refused}");

    // Two approvals, but the operator's program says no.
    approve("bob");
    std::fs::write(&freeze, b"").unwrap();
    let refused = signer.sign_with_report(payload).unwrap_err();
    assert!(refused.contains("change freeze in effect"), "{refused}");

    // Both agree: a standard signature over the payload itself.
    std::fs::remove_file(&freeze).unwrap();
    let (signature, _) = signer.sign_with_report(payload).unwrap();
    assert!(cairn_core::verify(&pk, payload, &signature));

    // A payload nobody approved is still refused.
    let refused = signer.sign_with_report(b"release 6.6.6").unwrap_err();
    assert!(refused.contains("0 of 2 required approvals"), "{refused}");
    drop(cluster);
    let _ = std::fs::remove_dir_all(&base);
}

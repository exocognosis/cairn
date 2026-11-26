//! `cairn keygen` and `cairn committee-init` take the committee from a roster file.

use std::path::Path;
use std::process::Command;

const CAIRN: &str = env!("CARGO_BIN_EXE_cairn");

fn cairn(args: &[&str]) -> (bool, String) {
    let out = Command::new(CAIRN).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_roster_names_the_committee() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("roster-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = |name: &str, body: &str| {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let roster = file(
        "roster.json",
        r#"{"threshold":2,"members":[{"id":"ops-east"},{"id":"ops-west"},{"id":"security"}]}"#,
    );
    let out = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let members = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(dir.join(name).join("members.json")).unwrap())
            .unwrap()
    };

    // Dealer key generation: three shares, and a record of who is which party.
    assert!(cairn(&["keygen", "--out", &out("dealt"), "--members", &roster]).0);
    assert!(dir.join("dealt/party_3.share").exists() && !dir.join("dealt/party_4.share").exists());
    let m = members("dealt");
    assert_eq!(m["threshold"], 2);
    assert_eq!(m["members"][2]["node"], "party_3");
    assert_eq!(m["members"][2]["id"], "security");

    // Setup for distributed generation: each member gets the identity key made for it.
    assert!(cairn(&["committee-init", "--out", &out("dkg"), "--members", &roster]).0);
    let m = members("dkg");
    let keys: std::collections::BTreeSet<&str> = (0..3)
        .map(|k| m["members"][k]["public_key"].as_str().unwrap())
        .collect();
    assert!(keys.len() == 3 && keys.iter().all(|k| k.len() == 64));

    // What the three-round protocol cannot serve is refused, with the reason.
    let weighted = file(
        "weighted.json",
        r#"{"threshold":3,"members":[{"id":"a","weight":2},{"id":"b"},{"id":"c"}]}"#,
    );
    let (ok, why) = cairn(&["keygen", "--out", &out("w"), "--members", &weighted]);
    assert!(!ok && why.contains("unequal weights"), "{why}");
    let many: Vec<String> = (0..9).map(|i| format!(r#"{{"id":"m{i}"}}"#)).collect();
    let large = file(
        "large.json",
        &format!(r#"{{"threshold":6,"members":[{}]}}"#, many.join(",")),
    );
    let (ok, why) = cairn(&["keygen", "--out", &out("l"), "--members", &large]);
    assert!(!ok && why.contains("no parameters for 6-of-9"), "{why}");
    let (ok, why) = cairn(&[
        "keygen",
        "--out",
        &out("b"),
        "--members",
        &roster,
        "--committee",
        "2-of-3",
    ]);
    assert!(!ok && why.contains("not both"), "{why}");
    let _ = std::fs::remove_dir_all(&dir);
}

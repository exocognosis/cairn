//! Hostile input: every parser that takes bytes from the network or from a file another
//! party wrote is fed random bytes and damaged copies of valid input. Nothing may panic, and
//! a live KMS endpoint must keep serving afterwards.
//!
//! The generator is seeded, so a failure reproduces. This is not coverage-guided fuzzing; it
//! catches the panics, overflows and unbounded allocations a parser falls into first.

use cairn_net::wire::{Body, Frame, NodeId, NET_VERSION};
use cairn_sidecar::Certificate;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::io::{Read as _, Write as _};
use threshold_mldsa::mithril;

/// Random bytes, and a valid input with bytes flipped, cut off or appended.
fn damaged(rng: &mut StdRng, valid: &[u8]) -> Vec<u8> {
    let mut bytes = valid.to_vec();
    match rng.gen_range(0..5) {
        0 => {
            let len = rng.gen_range(0..200);
            return (0..len).map(|_| rng.gen()).collect();
        }
        1 if !bytes.is_empty() => {
            for _ in 0..rng.gen_range(1..8) {
                let at = rng.gen_range(0..bytes.len());
                bytes[at] = rng.gen();
            }
        }
        2 if !bytes.is_empty() => bytes.truncate(rng.gen_range(0..bytes.len())),
        3 => bytes.extend((0..rng.gen_range(1..64)).map(|_| rng.gen::<u8>())),
        // A length field set to something enormous.
        _ if bytes.len() >= 8 => {
            let at = rng.gen_range(0..bytes.len() - 7);
            bytes[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes()[..8]);
        }
        _ => {}
    }
    bytes
}

#[test]
fn key_and_wire_parsers_survive_damaged_input() {
    let mut rng = StdRng::seed_from_u64(0xCA12_0001);
    let (key, parties) = mithril::keygen(2, 3, &mut rng).unwrap();
    let (state, _) = parties[0].round1(&key, &mut rng);
    let w = mithril::w_to_wire(&state.reveal()[0]);
    let (group, share) = (key.to_bytes(), parties[0].to_bytes());
    for _ in 0..300 {
        let _ = mithril::GroupKey::from_bytes(&damaged(&mut rng, &group));
        let _ = mithril::PartyKey::from_bytes(&damaged(&mut rng, &share));
    }
    for _ in 0..3000 {
        let bytes = damaged(&mut rng, &w);
        let _ = mithril::w_from_wire(&bytes);
        let _ = mithril::z_from_wire(&bytes);
        let _ = mithril::unpack_k(&bytes);
    }
}

#[test]
fn frames_survive_damaged_input() {
    let mut rng = StdRng::seed_from_u64(0xCA12_0002);
    let frames: Vec<Vec<u8>> = [
        Body::Prepare {
            message: b"cairn".to_vec(),
        },
        Body::Abort,
        Body::PolicyRefused {
            reason: "no".into(),
        },
    ]
    .into_iter()
    .map(|body| {
        bincode::serialize(&Frame {
            version: NET_VERSION,
            from: NodeId::Coordinator,
            to: NodeId::Root(1),
            session: [7; 32],
            body,
        })
        .unwrap()
    })
    .collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for i in 0..20_000 {
        let payload = damaged(&mut rng, &frames[i % frames.len()]);
        // As the transport reads it: a length, then that many bytes.
        let mut stream = (payload.len() as u32).to_be_bytes().to_vec();
        stream.extend(&payload);
        if rng.gen_ratio(1, 10) {
            stream[..4].copy_from_slice(&rng.gen::<[u8; 4]>());
        }
        let _ = runtime.block_on(cairn_net::transport::read_frame(&mut stream.as_slice()));
    }
}

#[test]
fn text_and_file_parsers_survive_damaged_input() {
    let mut rng = StdRng::seed_from_u64(0xCA12_0003);
    let checkpoint = cairn_net::policy::Checkpoint {
        chain: "cosmos:cairn-devnet-1".into(),
        epoch: 3,
        height: 100,
        block_hash: vec![1; 32],
        finality_commitment: vec![2; 32],
        key_id: [3; 32],
    }
    .message();
    assert!(cairn_net::policy::Checkpoint::parse(&checkpoint).is_some());
    let approver = cairn_policy::org::ApproverKey::from_seed("alice", &[9; 32]).unwrap();
    let approval = approver.approve(&[1; 1952], b"payload", u64::MAX).to_json();
    assert!(cairn_policy::org::Approval::from_json(approval.as_bytes()).is_some());
    let roster = r#"{"threshold":2,"identities":["00","11","22"]}"#;
    let peers = r#"{"party_1":"127.0.0.1:7300","root_1":"127.0.0.1:7301"}"#;
    for _ in 0..20_000 {
        let _ = cairn_net::policy::Checkpoint::parse(&damaged(&mut rng, &checkpoint));
        let _ = cairn_policy::org::Approval::from_json(&damaged(&mut rng, approval.as_bytes()));
        let _ = Certificate::from_bytes(&damaged(&mut rng, &checkpoint));
        let text = String::from_utf8_lossy(&damaged(&mut rng, roster.as_bytes())).into_owned();
        let _ = cairn_net::dkg::roster_from_json(&text);
        let text = String::from_utf8_lossy(&damaged(&mut rng, peers.as_bytes())).into_owned();
        let _ = cairn_net::cluster::parse_peers(&text);
    }
}

#[test]
fn the_kms_endpoint_keeps_serving_after_garbage_requests() {
    let mut rng = StdRng::seed_from_u64(0xCA12_0004);
    let roster = cairn_core::Roster::uniform(2, (1..=3).map(|i| format!("party-{i}")));
    let endpoint =
        cairn_sidecar::kms::serve("127.0.0.1:0", cairn_core::LocalFlat::deal(&roster).unwrap())
            .unwrap();
    let addr = endpoint.url().trim_start_matches("http://").to_owned();
    let valid = b"POST / HTTP/1.1\r\nHost: kms\r\nX-Amz-Target: TrentService.GetPublicKey\r\n\
        Content-Type: application/x-amz-json-1.1\r\nContent-Length: 22\r\nConnection: close\r\n\r\n\
        {\"KeyId\":\"alias/cairn\"}";
    let send = |bytes: &[u8]| -> String {
        let mut stream = std::net::TcpStream::connect(&addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let _ = stream.write_all(bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
        String::from_utf8_lossy(&reply).into_owned()
    };
    for _ in 0..300 {
        send(&damaged(&mut rng, valid));
    }
    // Headers that promise far more than is sent, and a body that is not JSON.
    send(b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\nx");
    send(b"POST / HTTP/1.1\r\nX-Amz-Target: TrentService.Sign\r\nContent-Length: 4\r\n\r\n\xff\xfe\x00{");
    let reply = send(valid);
    assert!(
        reply.starts_with("HTTP/1.1 200") && reply.contains("PublicKey"),
        "{reply}"
    );
}

#[test]
fn a_request_that_never_sends_its_body_does_not_stop_the_endpoint() {
    let roster = cairn_core::Roster::uniform(2, (1..=3).map(|i| format!("party-{i}")));
    let endpoint =
        cairn_sidecar::kms::serve("127.0.0.1:0", cairn_core::LocalFlat::deal(&roster).unwrap())
            .unwrap();
    let addr = endpoint.url().trim_start_matches("http://").to_owned();
    // Headers that promise a body, then silence, with the connection held open.
    let mut stalled = std::net::TcpStream::connect(&addr).unwrap();
    stalled
        .write_all(b"POST / HTTP/1.1\r\nHost: kms\r\nContent-Length: 5000\r\n\r\n")
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // Another client is still served, and promptly.
    let mut stream = std::net::TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: kms\r\nX-Amz-Target: TrentService.GetPublicKey\r\n\
        Content-Type: application/x-amz-json-1.1\r\nContent-Length: 22\r\nConnection: close\r\n\r\n\
        {\"KeyId\":\"alias/cairn\"}",
        )
        .unwrap();
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    let reply = String::from_utf8_lossy(&reply);
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    // And the silent connection is closed by the endpoint, not held for ever.
    stalled
        .set_read_timeout(Some(std::time::Duration::from_secs(25)))
        .unwrap();
    let mut rest = Vec::new();
    let closed = stalled.read_to_end(&mut rest);
    assert!(closed.is_ok(), "the endpoint kept a silent connection open");
}

/// Valid inputs for the coverage-guided fuzzer to start from (`scripts/fuzz.sh`).
#[test]
#[ignore = "writes fuzz seeds; run by scripts/fuzz.sh"]
fn write_fuzz_seeds() {
    let Some(dir) = std::env::var_os("CAIRN_FUZZ_SEEDS").map(std::path::PathBuf::from) else {
        return;
    };
    let write = |target: &str, name: &str, bytes: &[u8]| {
        let dir = dir.join(target);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    };
    let mut rng = StdRng::seed_from_u64(0xCA12_0005);
    let (key, parties) = mithril::keygen(2, 3, &mut rng).unwrap();
    let (state, _) = parties[0].round1(&key, &mut rng);
    write("keys", "group", &key.to_bytes());
    write("keys", "share", &parties[0].to_bytes());
    write("keys", "w", &mithril::w_to_wire(&state.reveal()[0]));
    for (name, body) in [
        (
            "prepare",
            Body::Prepare {
                message: b"cairn".to_vec(),
            },
        ),
        ("abort", Body::Abort),
        (
            "refused",
            Body::PolicyRefused {
                reason: "no".into(),
            },
        ),
    ] {
        let payload = bincode::serialize(&Frame {
            version: NET_VERSION,
            from: NodeId::Coordinator,
            to: NodeId::Root(1),
            session: [7; 32],
            body,
        })
        .unwrap();
        let mut stream = (payload.len() as u32).to_be_bytes().to_vec();
        stream.extend(&payload);
        write("frame", name, &stream);
    }
    let checkpoint = cairn_net::policy::Checkpoint {
        chain: "cosmos:cairn-devnet-1".into(),
        epoch: 3,
        height: 100,
        block_hash: vec![1; 32],
        finality_commitment: vec![2; 32],
        key_id: [3; 32],
    }
    .message();
    write("text", "checkpoint", &checkpoint);
    let approver = cairn_policy::org::ApproverKey::from_seed("alice", &[9; 32]).unwrap();
    let approval = approver.approve(&[1; 1952], b"payload", u64::MAX).to_json();
    write("text", "approval", approval.as_bytes());
    write(
        "text",
        "roster",
        br#"{"threshold":2,"identities":["00","11","22"]}"#,
    );
    write(
        "text",
        "peers",
        br#"{"party_1":"127.0.0.1:7300","root_1":"127.0.0.1:7301"}"#,
    );
}

//! `cairn serve-kms --backend`: the engine behind the KMS-compatible API is a stated choice.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Command, Stdio};

const CAIRN: &str = env!("CARGO_BIN_EXE_cairn");

fn kms_call(addr: &str, target: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let body = body.to_string();
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: kms\r\nX-Amz-Target: {target}\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response.split(' ').nth(1).unwrap().parse().unwrap();
    let json = response.split("\r\n\r\n").nth(1).unwrap();
    (status, serde_json::from_str(json).unwrap())
}

/// Start `serve-kms` on a free port and sign one message through it; returns two signatures
/// of the same message.
fn two_signatures(backend: &str) -> (Vec<u8>, Vec<u8>) {
    let mut child = Command::new(CAIRN)
        .args(["serve-kms", "--listen", "127.0.0.1:0", "--backend", backend])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let addr = loop {
        let line = lines.next().expect("serve-kms exited").unwrap();
        if let Some((_, rest)) = line.split_once(&format!("{backend} endpoint on http://")) {
            break rest.split_whitespace().next().unwrap().to_owned();
        }
    };
    let (status, got) = kms_call(
        &addr,
        "TrentService.GetPublicKey",
        serde_json::json!({ "KeyId": "alias/cairn" }),
    );
    assert_eq!(status, 200);
    let der = B64.decode(got["PublicKey"].as_str().unwrap()).unwrap();
    let pk: [u8; 1952] = der[der.len() - 1952..].try_into().unwrap();
    let message = b"any payload at all";
    let sign = || {
        let (status, got) = kms_call(
            &addr,
            "TrentService.Sign",
            serde_json::json!({
                "KeyId": "alias/cairn",
                "Message": B64.encode(message),
                "MessageType": "RAW",
                "SigningAlgorithm": "ML_DSA_SHAKE_256",
            }),
        );
        assert_eq!(status, 200, "{got}");
        let signature = B64.decode(got["Signature"].as_str().unwrap()).unwrap();
        assert!(cairn_core::verify(&pk, message, &signature));
        signature
    };
    let pair = (sign(), sign());
    child.kill().unwrap();
    let _ = child.wait();
    pair
}

// The endpoint caches by message, so repeats are equal for either engine; what differs is
// which engine produced the signature, and the endpoint names it at startup.
#[test]
fn either_backend_serves_standard_signatures() {
    for backend in ["flat", "tower"] {
        let (a, b) = two_signatures(backend);
        assert_eq!(a, b, "{backend}");
    }
}

#[test]
fn a_backend_that_contradicts_the_key_material_is_refused() {
    for args in [
        ["--backend", "tower", "--committee", "committee.bin"],
        ["--backend", "flat", "--group", "group.bin"],
        ["--backend", "ring", "--listen", "127.0.0.1:0"],
    ] {
        let out = Command::new(CAIRN).arg("serve-kms").args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("--backend"), "{args:?}");
    }
}

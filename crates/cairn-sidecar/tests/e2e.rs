//! End to end: a local 16-signer tower (3-of-4 x 3-of-4) produces a real `.pqcc` checkpoint
//! certificate that unmodified verifiers accept.
//!
//! External verifiers are looked up at:
//! * `CAIRN_PQC_SIDECAR_BIN`, else `<workspace>/target/pqc-sidecar/release/pqc-sidecar`
//!   (built by `scripts/setup-verifiers.sh` from an untouched pqc-sidecar checkout);
//! * `CAIRN_PQCC_VERIFY_JS`, else the published `@exocognosis/pqc-sidecar-verify` npm package
//!   under `<workspace>/target/pqcc-verify` (installed by the same script).
//!
//! Missing verifiers are skipped with a notice unless `CAIRN_REQUIRE_EXTERNAL_VERIFIERS=1`.
//! The RustCrypto `ml-dsa` check (an off-the-shelf FIPS 204 verifier) always runs.

use cairn_sidecar::{
    bench, kms, write_certificate, write_public_key, Certificate, CertifierConfig, CertifyError,
    Checkpoint, TowerCertifier,
};
use cascade_tower::{Tower, TowerParams};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use rand::rngs::OsRng;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use threshold_mldsa::{Behavior, TrustedEngine};

fn certifier() -> TowerCertifier<TrustedEngine> {
    let tower = Tower::deal(&rand::random(), &TowerParams::default_16(), &mut OsRng).unwrap();
    TowerCertifier::new(tower, TrustedEngine::new(), CertifierConfig::default())
}

fn checkpoint(height: u64) -> Checkpoint {
    Checkpoint {
        chain: "cosmos:cosmoshub-4".into(),
        epoch: 7,
        height,
        block_hash: rand::random::<[u8; 32]>().to_vec(),
        finality_commitment: rand::random::<[u8; 32]>().to_vec(),
    }
}

/// Verification with nothing of ours in the path: RustCrypto ml-dsa, empty context.
fn off_the_shelf_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk = EncodedVerifyingKey::<MlDsa65>::try_from(pk).unwrap();
    let sig = Signature::<MlDsa65>::try_from(signature).unwrap();
    VerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(message, &[], &sig)
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn external(env: &str, default: PathBuf, what: &str) -> Option<PathBuf> {
    let path = std::env::var_os(env).map(PathBuf::from).unwrap_or(default);
    if path.exists() {
        return Some(path);
    }
    assert!(
        std::env::var_os("CAIRN_REQUIRE_EXTERNAL_VERIFIERS").is_none(),
        "{what} not found at {} (set {env})",
        path.display()
    );
    eprintln!(
        "SKIPPED: {what} not found at {} (set {env})",
        path.display()
    );
    None
}

#[test]
fn sixteen_signer_tower_certificate_verifies_with_unmodified_verifiers() {
    let mut certifier = certifier();
    let (certificate, report) = certifier.certify(&checkpoint(1200)).unwrap();
    let pk = *certifier.public_key();

    // Standard sizes and a clean round trip through the wire format.
    assert_eq!((pk.len(), certificate.signature.len()), (1952, 3309));
    let bytes = certificate.to_bytes().unwrap();
    let decoded = Certificate::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, certificate);
    decoded.verify(&pk).unwrap();
    assert!(
        report
            .wire
            .bytes_sent
            .keys()
            .filter(|p| p.len() == 2)
            .count()
            >= 9,
        "nine signers took part"
    );

    // Off-the-shelf FIPS 204 verifier.
    let message = certificate
        .checkpoint
        .signing_message(&certificate.key_id)
        .unwrap();
    assert!(off_the_shelf_verify(
        &pk,
        &message,
        certificate.signature.as_slice()
    ));
    assert!(!off_the_shelf_verify(
        &pk,
        &[message.clone(), vec![0]].concat(),
        certificate.signature.as_slice()
    ));

    // Files as pqc-sidecar writes and reads them.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cert_file = write_certificate(&dir, &certificate).unwrap();
    assert!(
        write_certificate(&dir, &certificate).is_err(),
        "certificates are never overwritten"
    );
    let pk_file = dir.join("public_key.hex");
    write_public_key(&pk_file, &pk).unwrap();
    let mut tampered = bytes.clone();
    tampered[40] ^= 1; // inside the block hash
    let bad_file = dir.join("tampered.pqcc");
    std::fs::write(&bad_file, &tampered).unwrap();
    let args = |cert: &Path| {
        [
            "--certificate".into(),
            cert.as_os_str().to_owned(),
            "--public-key".into(),
            pk_file.as_os_str().to_owned(),
        ]
    };

    // Unmodified pqc-sidecar.
    let bin = workspace().join("target/pqc-sidecar/release/pqc-sidecar");
    if let Some(bin) = external("CAIRN_PQC_SIDECAR_BIN", bin, "pqc-sidecar binary") {
        let out = Command::new(&bin)
            .arg("verify")
            .args(args(&cert_file))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "pqc-sidecar verify failed: {stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let summary: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        assert_eq!(summary["valid"], true);
        assert_eq!(summary["format"], 2);
        assert_eq!(summary["height"], 1200);
        assert!(!Command::new(&bin)
            .arg("verify")
            .args(args(&bad_file))
            .output()
            .unwrap()
            .status
            .success());
        eprintln!("pqc-sidecar verify: {}", stdout.trim());
    }

    // Unmodified pqc-sidecar-verify (TypeScript, a second FIPS 204 implementation).
    let js = workspace()
        .join("target/pqcc-verify/node_modules/@exocognosis/pqc-sidecar-verify/dist/cli.js");
    if let Some(js) = external("CAIRN_PQCC_VERIFY_JS", js, "pqc-sidecar-verify cli.js") {
        let out = Command::new("node")
            .arg(&js)
            .args(args(&cert_file))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "pqc-sidecar-verify failed: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!Command::new("node")
            .arg(&js)
            .args(args(&bad_file))
            .output()
            .unwrap()
            .status
            .success());
        eprintln!(
            "pqc-sidecar-verify: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
}

#[test]
fn only_checkpoint_heights_are_certified() {
    let mut certifier = certifier();
    assert!(certifier.is_checkpoint(300) && !certifier.is_checkpoint(301));
    let err = certifier.certify(&checkpoint(1201)).err().unwrap();
    assert!(matches!(
        err,
        CertifyError::NotCheckpoint {
            height: 1201,
            interval: 100
        }
    ));
}

#[test]
fn faulty_signers_do_not_stop_certificates() {
    let mut certifier = certifier();
    certifier.tower_mut().signer_mut(&[1, 2]).unwrap().behavior = Behavior::Offline;
    certifier.tower_mut().signer_mut(&[3, 1]).unwrap().behavior = Behavior::BadResponse;
    for height in [100, 200, 300] {
        let (certificate, report) = certifier.certify(&checkpoint(height)).unwrap();
        certificate.verify(certifier.public_key()).unwrap();
        // Blamed once, then excluded for the following checkpoints.
        assert_eq!(report.fault_retries, (height == 100) as u32);
    }
}

fn kms_call(url: &str, target: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let body = body.to_string();
    let mut stream = std::net::TcpStream::connect(url.trim_start_matches("http://")).unwrap();
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

/// The same request over TLS, trusting exactly `cert_pem`.
fn kms_call_tls(addr: std::net::SocketAddr, cert_pem: &str) -> Result<u16, String> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
    let tcp = std::net::TcpStream::connect(addr).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: kms\r\nX-Amz-Target: TrentService.GetPublicKey\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    )
    .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    response
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "no HTTP response".to_string())
}

#[test]
fn kms_endpoint_serves_https_and_counts_requests() {
    use cairn_gateway::tls::ServerTls;
    let hosts = ["localhost".to_string()];
    let (cert, key) = ServerTls::self_signed(&hosts).unwrap();
    let metrics = kms::Metrics::new();
    let endpoint = kms::serve_opts(
        "127.0.0.1:0",
        certifier(),
        kms::KmsOptions {
            tls: Some(ServerTls::from_pem(&cert, &key).unwrap()),
            metrics: Some(metrics.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(endpoint.url().starts_with("https://"));
    assert_eq!(kms_call_tls(endpoint.addr, &cert), Ok(200));
    // A caller that trusts a different certificate does not get through.
    let (other, _) = ServerTls::self_signed(&hosts).unwrap();
    assert!(kms_call_tls(endpoint.addr, &other).is_err());
    assert!(metrics.render().contains("cairn_kms_requests_total 1\n"));

    let scrape = kms::serve_metrics("127.0.0.1:0", metrics).unwrap();
    let mut stream = std::net::TcpStream::connect(scrape).unwrap();
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert!(body.contains("cairn_kms_signatures_total 0"));
}

#[test]
fn kms_endpoint_signs_through_the_tower() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let certifier = certifier();
    let pk = *certifier.public_key();
    let endpoint = kms::serve("127.0.0.1:0", certifier).unwrap();

    let (status, got) = kms_call(
        &endpoint.url(),
        "TrentService.GetPublicKey",
        serde_json::json!({ "KeyId": "alias/cairn" }),
    );
    assert_eq!(status, 200);
    let der = B64.decode(got["PublicKey"].as_str().unwrap()).unwrap();
    assert_eq!(der, [kms::SPKI_PREFIX.as_slice(), &pk].concat());
    assert_eq!(got["KeySpec"], "ML_DSA_65");

    let message = b"pqc-sidecar/checkpoint/v2 ...".to_vec();
    let request = serde_json::json!({
        "KeyId": "alias/cairn",
        "Message": B64.encode(&message),
        "MessageType": "RAW",
        "SigningAlgorithm": "ML_DSA_SHAKE_256",
    });
    let (status, got) = kms_call(&endpoint.url(), "TrentService.Sign", request.clone());
    assert_eq!(status, 200);
    let signature = B64.decode(got["Signature"].as_str().unwrap()).unwrap();
    assert_eq!(signature.len(), 3309);
    assert!(off_the_shelf_verify(&pk, &message, &signature));

    let mut digest = request;
    digest["MessageType"] = "DIGEST".into();
    assert_eq!(
        kms_call(&endpoint.url(), "TrentService.Sign", digest).0,
        400
    );
    assert_eq!(
        kms_call(
            &endpoint.url(),
            "TrentService.Decrypt",
            serde_json::json!({})
        )
        .0,
        400
    );
}

#[test]
fn benchmark_harness_runs() {
    let r = bench::run(bench::Scenario::OneMalicious, 3, &TowerParams::default_16());
    assert_eq!(r.signatures, 3);
    assert!(r.fault_retries >= 1.0 && r.signer_bytes.mean > 0.0);
    assert!(bench::markdown(std::slice::from_ref(&r)).contains("one-malicious"));
    assert_eq!(bench::to_json(&r)["signers"], 16);
}

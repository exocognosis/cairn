//! `cairn`: demo, benchmark and KMS-compatible endpoint for the committee tower.

use cairn_sidecar::{
    bench, kms, write_certificate, write_public_key, CertifierConfig, Checkpoint, TowerCertifier,
};
use cascade_tower::{Tower, TowerParams};
use rand::rngs::OsRng;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use threshold_mldsa::TrustedEngine;

const USAGE: &str = "\
cairn: committee-tower threshold ML-DSA-65 checkpoint signing (v1, research build)

  cairn demo [--out <dir>] [--height <n>] [--interval <k>] [--seed-hex <64 hex>]
      Deal a 16-signer tower (3-of-4 x 3-of-4) in this process, certify one checkpoint and
      write <dir>/<height>.pqcc and <dir>/public_key.hex.

  cairn bench [--signatures <n>] [--json <file>]
      Measure signing latency, rejection-retry distribution and bytes per signer.

  cairn serve-kms [--listen <addr:port>] [--public-key-out <file>] [--seed-hex <64 hex>]
      Serve the tower behind the KMS API that pqc-sidecar's aws_kms signer backend speaks.

Every signer and the attempt engine run inside this one process. That is a test harness, not
threshold custody. See README.md, \"Status\".";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
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
            let tower =
                Tower::deal(&seed(args)?, &params, &mut OsRng).map_err(|e| e.to_string())?;
            let certifier =
                TowerCertifier::new(tower, TrustedEngine::new(), CertifierConfig::default());
            if let Some(path) = arg(args, "--public-key-out") {
                write_public_key(&PathBuf::from(path), certifier.public_key())
                    .map_err(|e| e.to_string())?;
            }
            let endpoint = kms::serve(&listen, certifier).map_err(|e| e.to_string())?;
            eprintln!(
                "cairn: KMS-compatible tower endpoint on {} (aws_endpoint_url)",
                endpoint.url()
            );
            endpoint.join();
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

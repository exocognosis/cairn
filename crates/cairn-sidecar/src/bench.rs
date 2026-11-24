//! Benchmark harness: checkpoint signing latency, rejection-retry distribution, bytes per signer.
//!
//! All signers and the ideal-functionality engine run in one process, so latency here is the
//! protocol's local compute and bookkeeping. It excludes network delay and, above all, the cost
//! of a real MPC evaluating the engine's two phases (the dominant cost in any deployment).

use crate::certificate::Checkpoint;
use crate::certifier::{CertifierConfig, TowerCertifier};
use cascade_tower::{Tower, TowerParams};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use threshold_mldsa::{Behavior, TrustedEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// All 16 signers honest and online.
    Healthy,
    /// One signer of the default signing set is offline at every checkpoint.
    OneOffline,
    /// One signer of the default signing set sends an inconsistent response at every checkpoint.
    OneMalicious,
}

impl Scenario {
    pub const ALL: [Scenario; 3] = [
        Scenario::Healthy,
        Scenario::OneOffline,
        Scenario::OneMalicious,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Scenario::Healthy => "healthy",
            Scenario::OneOffline => "one-offline",
            Scenario::OneMalicious => "one-malicious",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

fn summarize(mut v: Vec<f64>) -> Summary {
    v.sort_by(|a, b| a.total_cmp(b));
    let at = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    Summary {
        mean: v.iter().sum::<f64>() / v.len() as f64,
        p50: at(0.5),
        p95: at(0.95),
        max: at(1.0),
    }
}

#[derive(Debug, Clone)]
pub struct BenchResult {
    pub scenario: Scenario,
    pub signers: usize,
    pub signatures: u32,
    /// In-process wall time per certificate, milliseconds.
    pub latency_ms: Summary,
    /// Logical time spent waiting on silent signers per certificate, milliseconds.
    pub timeout_wait_ms: f64,
    /// Rejected attempts before the accepted one: count -> number of certificates.
    pub rejection_histogram: BTreeMap<u32, u32>,
    pub rejections: Summary,
    pub fault_retries: f64,
    /// Broadcast bytes per participating signer per certificate.
    pub signer_bytes: Summary,
    /// Broadcast bytes per committee relay (leaf or root) per certificate.
    pub relay_bytes: Summary,
    /// Size of each signer's sealed engine inputs and outputs per certificate.
    pub engine_io_bytes: f64,
    pub messages: f64,
}

pub fn run(scenario: Scenario, signatures: u32, params: &TowerParams) -> BenchResult {
    let mut tower = Tower::deal(&rand::random(), params, &mut OsRng).expect("tower shape");
    match scenario {
        Scenario::Healthy => {}
        Scenario::OneOffline => {
            tower.signer_mut(&[1, 1]).expect("signer").behavior = Behavior::Offline
        }
        Scenario::OneMalicious => {
            tower.signer_mut(&[2, 2]).expect("signer").behavior = Behavior::BadResponse
        }
    }
    let depth = params.tiers().len();
    // Reinstate before every signature so the faulty signer costs every checkpoint (worst case).
    let config = CertifierConfig {
        checkpoint_interval: 100,
        reinstate_every: 1,
        ..CertifierConfig::default()
    };
    let mut certifier = TowerCertifier::new(tower, TrustedEngine::new(), config);

    let (mut latency, mut rejections, mut signer_bytes, mut relay_bytes) =
        (vec![], vec![], vec![], vec![]);
    let (mut waits, mut retries, mut engine_io, mut messages) = (0.0, 0.0, 0.0, 0.0);
    let mut histogram = BTreeMap::new();
    for i in 1..=signatures as u64 {
        let checkpoint = Checkpoint {
            chain: "cosmos:cairn-bench-1".into(),
            epoch: 1,
            height: i * 100,
            block_hash: rand::random::<[u8; 32]>().to_vec(),
            finality_commitment: rand::random::<[u8; 32]>().to_vec(),
        };
        let (_, report) = certifier
            .certify(&checkpoint)
            .expect("benchmark tower signs");
        latency.push(report.elapsed.as_secs_f64() * 1e3);
        waits += report.wire.timeout_wait.as_secs_f64() * 1e3;
        rejections.push(report.rejections as f64);
        *histogram.entry(report.rejections).or_insert(0) += 1;
        retries += report.fault_retries as f64;
        messages += report.wire.messages as f64;
        for (path, bytes) in &report.wire.bytes_sent {
            if path.len() == depth {
                &mut signer_bytes
            } else {
                &mut relay_bytes
            }
            .push(*bytes as f64);
        }
        let io = &report.wire.engine_io_bytes;
        engine_io += io.values().sum::<u64>() as f64 / io.len().max(1) as f64;
    }
    let n = signatures as f64;
    BenchResult {
        scenario,
        signers: params.signers(),
        signatures,
        latency_ms: summarize(latency),
        timeout_wait_ms: waits / n,
        rejection_histogram: histogram,
        rejections: summarize(rejections),
        fault_retries: retries / n,
        signer_bytes: summarize(signer_bytes),
        relay_bytes: summarize(relay_bytes),
        engine_io_bytes: engine_io / n,
        messages: messages / n,
    }
}

fn summary_json(s: &Summary) -> Value {
    json!({ "mean": s.mean, "p50": s.p50, "p95": s.p95, "max": s.max })
}

pub fn to_json(r: &BenchResult) -> Value {
    json!({
        "scenario": r.scenario.name(),
        "signers": r.signers,
        "signatures": r.signatures,
        "latency_ms": summary_json(&r.latency_ms),
        "timeout_wait_ms_mean": r.timeout_wait_ms,
        "rejections": summary_json(&r.rejections),
        "rejection_histogram": r.rejection_histogram.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),
        "fault_retries_mean": r.fault_retries,
        "signer_broadcast_bytes": summary_json(&r.signer_bytes),
        "relay_broadcast_bytes": summary_json(&r.relay_bytes),
        "signer_engine_io_bytes_mean": r.engine_io_bytes,
        "messages_mean": r.messages,
    })
}

pub fn markdown(results: &[BenchResult]) -> String {
    let mut out = String::from(
        "| scenario | certs | latency ms (mean / p50 / p95 / max) | rejections (mean / p95 / max) | fault retries | timeout wait ms | signer bytes (mean / max) | relay bytes (mean) | messages |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in results {
        out += &format!(
            "| {} | {} | {:.1} / {:.1} / {:.1} / {:.1} | {:.2} / {:.0} / {:.0} | {:.2} | {:.0} | {:.0} / {:.0} | {:.0} | {:.0} |\n",
            r.scenario.name(),
            r.signatures,
            r.latency_ms.mean,
            r.latency_ms.p50,
            r.latency_ms.p95,
            r.latency_ms.max,
            r.rejections.mean,
            r.rejections.p95,
            r.rejections.max,
            r.fault_retries,
            r.timeout_wait_ms,
            r.signer_bytes.mean,
            r.signer_bytes.max,
            r.relay_bytes.mean,
            r.messages,
        );
    }
    out
}

/// Text histogram of rejected attempts per certificate.
pub fn histogram(r: &BenchResult) -> String {
    let mut out = String::new();
    for (k, v) in &r.rejection_histogram {
        let bar = "#".repeat((*v as usize * 50).div_ceil(r.signatures as usize));
        out += &format!("{k:>3} | {bar} {v}\n");
    }
    out
}

//! The signing session: attempts, deterministic retry synchronization, fault handling.

use crate::engine::{z_digest, AttemptEngine, MaskOpening, Verdict};
use crate::fips204::{self, vec_add, vec_zero, Hint, L, N, SIGNATURE_BYTES};
use crate::keys::GroupPublic;
use crate::party::{unflatten, Committee, Party};
use crate::protocol::{AttemptCtx, Fault, FaultKind, Message, Round, Wire};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SignPolicy {
    /// Cap on Fiat-Shamir rejections (expected ~4 per signature for ML-DSA-65).
    pub max_rejections: u32,
    /// Cap on fault retries (timeouts, blamed signers) per signature.
    pub max_fault_retries: u32,
    /// How long a round waits for a silent party. Logical in v1: accounted, not slept.
    pub round_timeout: Duration,
    /// Keep the full message transcript in the report.
    pub record_transcript: bool,
}

impl Default for SignPolicy {
    fn default() -> Self {
        Self {
            max_rejections: 512,
            max_fault_retries: 16,
            round_timeout: Duration::from_secs(2),
            record_transcript: false,
        }
    }
}

pub struct SignReport {
    /// Attempts rejected by the FIPS 204 abort conditions before the accepted one.
    pub rejections: u32,
    /// Attempts aborted by a fault and retried.
    pub fault_retries: u32,
    /// Every fault seen, fatal to its attempt or absorbed.
    pub faults: Vec<Fault>,
    pub wire: Wire,
    /// Wall-clock time of the in-process run (excludes `wire.timeout_wait`).
    pub elapsed: Duration,
}

pub struct Signed {
    /// Standard FIPS 204 ML-DSA-65 signature, 3,309 bytes.
    pub signature: [u8; SIGNATURE_BYTES],
    pub report: SignReport,
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("root committee lost its quorum; faults: {0:?}")]
    QuorumLost(Vec<Fault>),
    #[error("fault retries exhausted; faults: {0:?}")]
    Stalled(Vec<Fault>),
    #[error("rejection limit reached")]
    RejectionLimit,
    #[error("assembled signature failed standard verification")]
    InvalidSignature,
}

fn hint_positions(h: &Hint) -> Vec<u16> {
    h.iter()
        .enumerate()
        .flat_map(|(i, p)| {
            p.iter()
                .enumerate()
                .filter(|(_, &b)| b)
                .map(move |(j, _)| (i * N + j) as u16)
        })
        .collect()
}

/// One attempt. `Ok(None)` is a clean Fiat-Shamir rejection.
fn run_attempt<P: Party, E: AttemptEngine>(
    root: &mut Committee<P>,
    engine: &mut E,
    group: &GroupPublic,
    ctx: &AttemptCtx,
    wire: &mut Wire,
) -> Result<Option<[u8; SIGNATURE_BYTES]>, Fault> {
    let (active, _) = root.commit(ctx, wire)?;
    let seeds = root.seed_input(ctx, wire)?;
    let MaskOpening { c_tilde, mask } = engine.mask_phase(ctx, group, &active, seeds)?;
    root.challenge(ctx, &active, mask, &c_tilde, wire)?;
    let (_, parts) = root.respond(ctx, wire)?;
    match engine.response_phase(ctx, group, &active, parts)? {
        Verdict::Reject => {
            root.open(ctx, false, None, wire)?;
            Ok(None)
        }
        Verdict::Accept { hint, z_digests } => {
            let openings = root.open(ctx, true, Some(&hint_positions(&hint)), wire)?;
            let mut z = vec_zero(L);
            for (path, digest) in &z_digests {
                let late = || Fault {
                    culprit: Some(path.clone()),
                    kind: FaultKind::Timeout(Round::HintCarry),
                };
                let opening = openings.iter().find(|o| &o.path == path).ok_or_else(late)?;
                let z_p = unflatten(&opening.z)
                    .filter(|z_p| &z_digest(z_p) == digest)
                    .ok_or(Fault {
                        culprit: Some(path.clone()),
                        kind: FaultKind::OpeningMismatch,
                    })?;
                z = vec_add(&z, &z_p);
            }
            Ok(Some(fips204::pack_signature(&c_tilde, &z, &hint)))
        }
    }
}

/// Sign `message` (empty context) with the tower rooted at `root`.
///
/// Retry rules, all functions of broadcast data so every node stays in step:
/// * rejection: `attempt += 1` (so `kappa += L`), same signing set;
/// * attributed fault: exclude the culprit for the session, `retry += 1`, same `kappa`;
/// * unattributed fault: suspend one spare-covered candidate in rotation, `retry += 1`.
///
/// Repeating a `kappa` after a fault is safe in the deterministic variant: the mask, hence `c~`
/// and `z`, are functions of `(K, mu, kappa)` only, and each run uses a fresh additive sharing.
pub fn sign<P: Party, E: AttemptEngine>(
    root: &mut Committee<P>,
    engine: &mut E,
    group: &GroupPublic,
    message: &[u8],
    policy: &SignPolicy,
) -> Result<Signed, SignError> {
    let start = Instant::now();
    let mu = fips204::message_representative(&group.tr, &[], message);
    let mut wire = Wire::new(policy.round_timeout);
    wire.record = policy.record_transcript;
    let (mut attempt, mut retry, mut probes) = (0u32, 0u32, 0u32);
    let mut faults = Vec::new();
    loop {
        let ctx = AttemptCtx::new(&group.pk, mu, attempt, retry);
        match run_attempt(root, engine, group, &ctx, &mut wire) {
            Ok(Some(signature)) => {
                root.reset();
                if !fips204::verify_standard(&group.pk, message, &signature) {
                    return Err(SignError::InvalidSignature);
                }
                faults.append(&mut wire.faults);
                let report = SignReport {
                    rejections: attempt,
                    fault_retries: retry,
                    faults,
                    wire,
                    elapsed: start.elapsed(),
                };
                return Ok(Signed { signature, report });
            }
            Ok(None) => {
                attempt += 1;
                if attempt > policy.max_rejections {
                    return Err(SignError::RejectionLimit);
                }
            }
            Err(fault) => {
                root.reset();
                wire.broadcast(Message::Abort {
                    header: ctx.header(&[]),
                    fault: fault.clone(),
                });
                faults.append(&mut wire.faults);
                faults.push(fault.clone());
                if fault.culprit.as_deref() == Some(&[]) {
                    return Err(SignError::QuorumLost(faults));
                }
                retry += 1;
                if retry > policy.max_fault_retries {
                    return Err(SignError::Stalled(faults));
                }
                match &fault.culprit {
                    Some(path) => root.exclude(path),
                    None => {
                        if !root.probe(probes) {
                            return Err(SignError::Stalled(faults));
                        }
                        probes += 1;
                    }
                }
            }
        }
    }
}

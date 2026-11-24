//! The MPC boundary.
//!
//! Everything non-linear in an ML-DSA attempt (ExpandMask's SHAKE256, HighBits/LowBits, the four
//! abort checks, MakeHint) happens behind [`AttemptEngine`]. Values that must stay inside that
//! boundary travel as [`Sealed`]: coordinators can route, merge and split them but cannot read
//! them. An engine opens exactly: `c~` per attempt, the accept bit, and for an accepted attempt
//! the hint (the signers open `z` themselves).
//!
//! [`TrustedEngine`] is an in-process *ideal functionality*. It is NOT a secure computation: the
//! process running it sees the signing seed and every rejected candidate. It exists so the
//! protocol, tower and certificate path can be built and tested end to end; a real backend (the
//! MP-SPDZ `mldsa65_sign_attempt` program of the lattice-aggregation prototype) implements the
//! same two phases. See ARCHITECTURE.md, "Trust boundary".

use crate::fips204::{
    self, challenge_mul, commit_mask, expand_mask, finish_attempt, fq_mul, inf_norm, mat_vec_coeff,
    red, sample_in_ball, vec_add, vec_scale, vec_sub, vec_zero, Hint, PolyVec, BETA, C_TILDE_BYTES,
    K, L, Q,
};
use crate::keys::{seed_share_commitment, Active, GroupPublic, Path};
use crate::protocol::{AttemptCtx, Fault, FaultKind};
use rand::{rngs::OsRng, Rng};
use zeroize::Zeroize;

/// A value that lives inside the MPC boundary.
pub struct Sealed<T>(T);

impl<T> Sealed<T> {
    /// Seal a party's private input. Called by signers on their own values.
    pub fn seal(value: T) -> Self {
        Self(value)
    }

    /// Open inside an engine. Only [`AttemptEngine`] implementations may call this.
    pub fn engine_open(self) -> T {
        self.0
    }
}

impl<T> Sealed<Vec<T>> {
    pub fn merge(parts: impl IntoIterator<Item = Self>) -> Self {
        Self(parts.into_iter().flat_map(|p| p.0).collect())
    }
}

/// A signer's share of the signing seed `K`, as dealt.
pub struct SeedPart {
    pub path: Path,
    pub k_share: [i32; 32],
}

/// An additive share of the mask `y`.
pub struct MaskShare(pub(crate) PolyVec);

impl Sealed<MaskShare> {
    /// Re-share additively among `n` holders (uniform shares summing to the input).
    pub fn split(mut self, n: usize) -> Vec<Self> {
        let mut out: Vec<PolyVec> = Vec::with_capacity(n);
        let mut last = std::mem::take(&mut self.0 .0);
        for _ in 1..n {
            let share: PolyVec = (0..L)
                .map(|_| std::array::from_fn(|_| OsRng.gen_range(0..Q)))
                .collect();
            last = vec_sub(&last, &share);
            out.push(share);
        }
        out.push(last);
        out.into_iter().map(|s| Sealed(MaskShare(s))).collect()
    }

    pub(crate) fn unseal_own(self) -> PolyVec {
        self.0 .0
    }
}

/// A signer's linear response share: `z_p = y_p + c w_p s1_p`, `r_p = A y_p - c w_p s2_p`.
pub struct ResponsePart {
    pub path: Path,
    pub z: PolyVec,
    pub r: PolyVec,
}

pub struct MaskOpening {
    pub c_tilde: [u8; C_TILDE_BYTES],
    pub mask: Sealed<MaskShare>,
}

pub enum Verdict {
    /// The attempt failed a norm or hint bound. Nothing else is opened, not even which bound.
    Reject,
    Accept {
        hint: Hint,
        /// Digest of each signer's `z_p` as input, so a wrong public opening is attributable.
        z_digests: Vec<(Path, [u8; 32])>,
    },
}

pub fn z_digest(z: &PolyVec) -> [u8; 32] {
    let bytes: Vec<u8> = z.iter().flatten().flat_map(|c| c.to_le_bytes()).collect();
    let mut out = [0u8; 32];
    fips204::shake256(&[b"cairn/z-digest/v1", &bytes], &mut out);
    out
}

/// The two phases of one signing attempt behind the MPC boundary.
pub trait AttemptEngine {
    /// Phase A: reconstruct `K`, run the exact FIPS 204 `ExpandMask(rho'', kappa)`, compute
    /// `w = A y` and open only `c~`. The mask stays sealed.
    fn mask_phase(
        &mut self,
        ctx: &AttemptCtx,
        group: &GroupPublic,
        active: &Active,
        seeds: Sealed<Vec<SeedPart>>,
    ) -> Result<MaskOpening, Fault>;

    /// Phase B: sum the response shares, evaluate the abort conditions and open the verdict.
    fn response_phase(
        &mut self,
        ctx: &AttemptCtx,
        group: &GroupPublic,
        active: &Active,
        parts: Sealed<Vec<ResponsePart>>,
    ) -> Result<Verdict, Fault>;
}

struct Pending {
    session: [u8; 32],
    c_tilde: [u8; C_TILDE_BYTES],
    w: PolyVec,
}

/// In-process ideal functionality. Not secure computation; see the module docs.
#[derive(Default)]
pub struct TrustedEngine {
    pending: Option<Pending>,
    /// Count of each phase run (for benchmarks and tests).
    pub mask_phases: u64,
    pub response_phases: u64,
}

impl TrustedEngine {
    pub fn new() -> Self {
        Self::default()
    }
}

fn blame(path: &Path, kind: FaultKind) -> Fault {
    Fault { culprit: Some(path.clone()), kind }
}

impl AttemptEngine for TrustedEngine {
    fn mask_phase(
        &mut self,
        ctx: &AttemptCtx,
        group: &GroupPublic,
        active: &Active,
        seeds: Sealed<Vec<SeedPart>>,
    ) -> Result<MaskOpening, Fault> {
        self.mask_phases += 1;
        self.pending = None;
        let mut seeds = seeds.engine_open();
        let weights = active.weights();
        let mut k_acc = [0i32; 32];
        for (path, w) in &weights {
            let part = seeds
                .iter()
                .find(|p| &p.path == path)
                .ok_or_else(|| blame(path, FaultKind::BadSeedShare))?;
            if group.seed_commitments.get(path) != Some(&seed_share_commitment(path, &part.k_share)) {
                return Err(blame(path, FaultKind::BadSeedShare));
            }
            for (acc, v) in k_acc.iter_mut().zip(part.k_share) {
                *acc = red(*acc as i64 + fq_mul(v, *w) as i64);
            }
        }
        seeds.iter_mut().for_each(|p| p.k_share.zeroize());
        if k_acc.iter().any(|&v| v > 255) {
            k_acc.zeroize();
            return Err(Fault { culprit: None, kind: FaultKind::Unattributed });
        }
        let mut k = k_acc.map(|v| v as u8);
        k_acc.zeroize();
        // Deterministic FIPS 204 variant: rnd = 0^32. kappa advances by L per rejected attempt.
        let mut rho_pp = fips204::mask_seed(&k, &[0u8; 32], &ctx.mu);
        k.zeroize();
        let y = expand_mask(&rho_pp, (ctx.attempt as usize * L) as u16);
        rho_pp.zeroize();
        let (w, c_tilde) = commit_mask(group.a_hat(), &y, &ctx.mu);
        self.pending = Some(Pending { session: ctx.session, c_tilde, w });
        Ok(MaskOpening { c_tilde, mask: Sealed(MaskShare(y)) })
    }

    fn response_phase(
        &mut self,
        ctx: &AttemptCtx,
        group: &GroupPublic,
        active: &Active,
        parts: Sealed<Vec<ResponsePart>>,
    ) -> Result<Verdict, Fault> {
        self.response_phases += 1;
        let unattributed = || Fault { culprit: None, kind: FaultKind::Unattributed };
        let mut pending = self.pending.take().filter(|p| p.session == ctx.session).ok_or_else(unattributed)?;
        let mut parts = parts.engine_open();
        let c = sample_in_ball(&pending.c_tilde);
        let (mut z, mut r) = (vec_zero(L), vec_zero(K));
        let mut z_digests = Vec::new();
        for (path, weight) in active.weights() {
            let part = parts
                .iter()
                .find(|p| p.path == path)
                .ok_or_else(|| blame(&path, FaultKind::InconsistentResponse))?;
            // Linear consistency against the public verification share: A z_p - r_p = c w_p T_p.
            let t_p = group.verification.get(&path).ok_or_else(unattributed)?;
            let lhs = vec_sub(&mat_vec_coeff(group.a_hat(), &part.z), &part.r);
            if lhs != challenge_mul(&c, &vec_scale(t_p, weight)) {
                return Err(blame(&path, FaultKind::InconsistentResponse));
            }
            z = vec_add(&z, &part.z);
            r = vec_add(&r, &part.r);
            z_digests.push((path, z_digest(&part.z)));
        }
        parts.iter_mut().for_each(|p| {
            p.z.zeroize();
            p.r.zeroize();
        });
        // Mask consistency: r must equal w - c s2, so r - w has norm at most beta. This holds
        // or fails independently of the rejection outcome, so checking it first leaks nothing.
        let consistent = inf_norm(&vec_sub(&r, &pending.w)) <= BETA;
        pending.w.zeroize();
        if !consistent {
            z.zeroize();
            r.zeroize();
            return Err(unattributed());
        }
        let ct0 = challenge_mul(&c, &group.t0);
        let verdict = match finish_attempt(&z, &r, &ct0) {
            Ok(hint) => Verdict::Accept { hint, z_digests },
            Err(_) => Verdict::Reject,
        };
        z.zeroize();
        r.zeroize();
        Ok(verdict)
    }
}

//! Shamir sharing over Z_q, nested key dealing, and the public group description.
//!
//! v1 uses a trusted dealer (see DECISIONS.md D-04). The secret vector is
//! `s1 (L polys) || s2 (K polys) || K (32 bytes, one field element each)`.

use crate::fips204::{
    self, fq_inv, fq_mul, red, ExpandedKey, MatrixHat, Poly, PolyVec, K, L, N, PUBLIC_KEY_BYTES, Q,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hard ceiling on the size of any interactive committee (the measured MPC wall).
pub const MAX_COMMITTEE: usize = 6;

/// Position in the tower, root first, 1-based Shamir x-coordinates. `[2, 3]` is signer 3 of leaf 2.
pub type Path = Vec<u8>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShapeError {
    #[error("committee of {0} exceeds the N <= {MAX_COMMITTEE} ceiling")]
    TooLarge(usize),
    #[error("threshold {t} is not in 1..={n}")]
    BadThreshold { t: usize, n: usize },
    #[error("a tower needs at least one tier")]
    Empty,
}

/// One tier of the tower: `t`-of-`n`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gadget {
    pub n: u8,
    pub t: u8,
}

impl Gadget {
    pub fn new(t: usize, n: usize) -> Result<Self, ShapeError> {
        if n > MAX_COMMITTEE {
            return Err(ShapeError::TooLarge(n));
        }
        if t == 0 || t > n {
            return Err(ShapeError::BadThreshold { t, n });
        }
        Ok(Self {
            n: n as u8,
            t: t as u8,
        })
    }
}

/// Lagrange coefficient at zero for x-coordinate `i` within `set`.
pub fn lagrange_at_zero(i: u8, set: &[u8]) -> i32 {
    let (mut num, mut den) = (1i32, 1i32);
    for &j in set.iter().filter(|&&j| j != i) {
        num = fq_mul(num, j as i32);
        den = fq_mul(den, red(j as i64 - i as i64));
    }
    fq_mul(num, fq_inv(den))
}

fn shamir_split<R: Rng + CryptoRng>(secret: &[i32], g: Gadget, rng: &mut R) -> Vec<Vec<i32>> {
    let coeffs: Vec<Vec<i32>> = (1..g.t)
        .map(|_| secret.iter().map(|_| rng.gen_range(0..Q)).collect())
        .collect();
    (1..=g.n as i32)
        .map(|x| {
            (0..secret.len())
                .map(|e| {
                    // Horner evaluation of secret + c1 x + ... at x.
                    let mut acc = 0i32;
                    for c in coeffs.iter().rev() {
                        acc = fq_mul(red(acc as i64 + c[e] as i64), x);
                    }
                    red(acc as i64 + secret[e] as i64)
                })
                .collect()
        })
        .collect()
}

/// One signer's share of the group key. Never serialized; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyShare {
    #[zeroize(skip)]
    pub path: Path,
    pub(crate) s1: PolyVec,
    pub(crate) s2: PolyVec,
    pub(crate) k: [i32; 32],
}

impl KeyShare {
    fn from_flat(path: Path, flat: &[i32]) -> Self {
        let poly = |i: usize| -> Poly { flat[i * N..(i + 1) * N].try_into().unwrap() };
        Self {
            path,
            s1: (0..L).map(poly).collect(),
            s2: (L..L + K).map(poly).collect(),
            k: flat[(L + K) * N..].try_into().unwrap(),
        }
    }
}

pub(crate) fn seed_share_commitment(path: &[u8], k: &[i32; 32]) -> [u8; 32] {
    let bytes: Vec<u8> = k.iter().flat_map(|v| v.to_le_bytes()).collect();
    let mut out = [0u8; 32];
    fips204::shake256(
        &[b"cairn/seed-share/v1", &[path.len() as u8], path, &bytes],
        &mut out,
    );
    out
}

/// Everything public about a dealt tower key.
pub struct GroupPublic {
    /// Standard FIPS 204 ML-DSA-65 public key (1,952 bytes).
    pub pk: [u8; PUBLIC_KEY_BYTES],
    pub rho: [u8; 32],
    pub tr: [u8; 64],
    /// `t0` is treated as public, as in the ML-DSA security analysis.
    pub t0: PolyVec,
    /// Tower shape, root first.
    pub shape: Vec<Gadget>,
    /// Per-signer verification share `T_p = A s1_p + s2_p` (a Shamir share of `t`).
    pub verification: BTreeMap<Path, PolyVec>,
    /// Per-signer commitment to its share of the signing seed `K`.
    pub seed_commitments: BTreeMap<Path, [u8; 32]>,
    a_hat: OnceLock<MatrixHat>,
}

impl GroupPublic {
    pub fn a_hat(&self) -> &MatrixHat {
        self.a_hat.get_or_init(|| fips204::expand_a(&self.rho))
    }
}

/// Trusted-dealer key generation for a tower of the given shape (root first).
/// Returns the public description and one share per signer, in path order.
pub fn deal<R: Rng + CryptoRng>(
    seed: &[u8; 32],
    shape: &[Gadget],
    rng: &mut R,
) -> Result<(GroupPublic, Vec<KeyShare>), ShapeError> {
    if shape.is_empty() {
        return Err(ShapeError::Empty);
    }
    for g in shape {
        Gadget::new(g.t as usize, g.n as usize)?;
    }
    let key: ExpandedKey = fips204::keygen_internal(seed);
    let mut flat: Vec<i32> = key
        .s1
        .iter()
        .chain(&key.s2)
        .flat_map(|p| p.iter().copied())
        .collect();
    flat.extend(key.k.iter().map(|&b| b as i32));

    let mut shares = Vec::new();
    let mut stack = vec![(Path::new(), flat)];
    while let Some((path, mut secret)) = stack.pop() {
        if path.len() == shape.len() {
            shares.push(KeyShare::from_flat(path, &secret));
        } else {
            for (i, child) in shamir_split(&secret, shape[path.len()], rng)
                .into_iter()
                .enumerate()
            {
                let mut p = path.clone();
                p.push(i as u8 + 1);
                stack.push((p, child));
            }
        }
        secret.zeroize();
    }
    shares.sort_by(|a, b| a.path.cmp(&b.path));

    let a_hat = fips204::expand_a(&key.rho);
    let verification = shares
        .iter()
        .map(|s| {
            let t = fips204::vec_add(&fips204::mat_vec_coeff(&a_hat, &s.s1), &s.s2);
            (s.path.clone(), t)
        })
        .collect();
    let seed_commitments = shares
        .iter()
        .map(|s| (s.path.clone(), seed_share_commitment(&s.path, &s.k)))
        .collect();
    let group = GroupPublic {
        pk: key.pk,
        rho: key.rho,
        tr: key.tr,
        t0: key.t0.clone(),
        shape: shape.to_vec(),
        verification,
        seed_commitments,
        a_hat: OnceLock::from(a_hat),
    };
    Ok((group, shares))
}

/// The signers taking part in one attempt, as a tree mirroring the tower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Active {
    Signer,
    Committee(Vec<(u8, Active)>),
}

impl Active {
    /// Composed Lagrange weight of every active signer: the product of the per-tier
    /// coefficients along its path. The weighted shares sum to the secret.
    pub fn weights(&self) -> Vec<(Path, i32)> {
        let mut out = Vec::new();
        self.walk(&mut Vec::new(), 1, &mut out);
        out
    }

    fn walk(&self, path: &mut Path, weight: i32, out: &mut Vec<(Path, i32)>) {
        match self {
            Active::Signer => out.push((path.clone(), weight)),
            Active::Committee(children) => {
                let set: Vec<u8> = children.iter().map(|(i, _)| *i).collect();
                for (i, child) in children {
                    path.push(*i);
                    child.walk(path, fq_mul(weight, lagrange_at_zero(*i, &set)), out);
                    path.pop();
                }
            }
        }
    }

    /// True when the active set can reconstruct under `shape` (root first).
    pub fn is_authorized(&self, shape: &[Gadget]) -> bool {
        match (self, shape.split_first()) {
            (Active::Signer, None) => true,
            (Active::Committee(children), Some((g, rest))) => {
                children.len() >= g.t as usize
                    && children.iter().all(|(_, c)| c.is_authorized(rest))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ceiling_is_enforced() {
        assert_eq!(Gadget::new(4, 7), Err(ShapeError::TooLarge(7)));
        assert!(Gadget::new(4, 6).is_ok());
        assert!(Gadget::new(0, 4).is_err());
    }

    #[test]
    fn nested_shares_reconstruct_through_composed_weights() {
        let shape = [Gadget::new(3, 4).unwrap(), Gadget::new(3, 4).unwrap()];
        let seed = [9u8; 32];
        let (group, shares) = deal(&seed, &shape, &mut OsRng).unwrap();
        assert_eq!(shares.len(), 16);
        let key = fips204::keygen_internal(&seed);
        assert_eq!(group.pk, key.pk);
        // Leaves 1, 2, 4 with members {1,2,3}, {2,3,4}, {1,3,4}.
        let active = Active::Committee(vec![
            (
                1,
                Active::Committee(vec![
                    (1, Active::Signer),
                    (2, Active::Signer),
                    (3, Active::Signer),
                ]),
            ),
            (
                2,
                Active::Committee(vec![
                    (2, Active::Signer),
                    (3, Active::Signer),
                    (4, Active::Signer),
                ]),
            ),
            (
                4,
                Active::Committee(vec![
                    (1, Active::Signer),
                    (3, Active::Signer),
                    (4, Active::Signer),
                ]),
            ),
        ]);
        assert!(active.is_authorized(&shape));
        let mut s1 = fips204::vec_zero(L);
        let mut k = [0i32; 32];
        for (path, w) in active.weights() {
            let share = shares.iter().find(|s| s.path == path).unwrap();
            s1 = fips204::vec_add(&s1, &fips204::vec_scale(&share.s1, w));
            for (acc, v) in k.iter_mut().zip(share.k) {
                *acc = red(*acc as i64 + fq_mul(v, w) as i64);
            }
        }
        assert_eq!(s1, key.s1);
        assert_eq!(k.map(|v| v as u8), key.k);
    }
}

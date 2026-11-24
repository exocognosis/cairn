//! Nested leaf-to-root additive share compression.
//!
//! A signer at path `[i, j]` holds a nested Shamir share. For an active set it multiplies the
//! share by its composed Lagrange weight `Lambda_i * lambda_j` (root coefficient of its leaf
//! times leaf coefficient of itself). The results `s^(i,j)` are a plain additive sharing of the
//! master key among the active signers. Each signer then splits its `s^(i,j)` into one uniform
//! additive sub-share per root engine and sends each sub-share to one engine only. Every engine
//! adds what it received, so the nine active signers collapse into a 3-party additive sharing.
//!
//! Nobody reconstructs anything on the way: a leaf's share of the key `s~^(i)` would be the sum
//! of its signers' `lambda_j * share`, and that sum is never formed; a root engine sees one
//! uniform sub-share of each signer.
//!
//! What this does and does not preserve is spelled out in ARCHITECTURE.md §10.6: the shares at
//! rest keep the tower's access structure, but for the duration of a signing session the key is
//! 3-party shared among the root engines.

use crate::fips204::{
    self, challenge_mul, fq_mul, mat_vec_coeff, red, sample_in_ball, vec_add, vec_sub, MatrixHat,
    PolyVec, C_TILDE_BYTES, K, L, N, Q,
};
use crate::keys::{GroupPublic, KeyShare};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const S1_LEN: usize = L * N;
pub const S2_LEN: usize = K * N;
pub const SEED_LEN: usize = 32;

/// An additive share (or sub-share) of `(s1, s2, K)` over `Z_q`, flat and row-major.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AdditiveShare {
    pub s1: Vec<i32>,
    pub s2: Vec<i32>,
    pub k: Vec<i32>,
}

pub fn to_polys(flat: &[i32]) -> PolyVec {
    flat.chunks(N)
        .map(|c| c.try_into().expect("whole polynomials"))
        .collect()
}

pub fn to_flat(v: &PolyVec) -> Vec<i32> {
    v.iter().flatten().copied().collect()
}

impl AdditiveShare {
    pub fn zero() -> Self {
        Self {
            s1: vec![0; S1_LEN],
            s2: vec![0; S2_LEN],
            k: vec![0; SEED_LEN],
        }
    }

    /// Shape and range check for a share received from the network.
    pub fn is_well_formed(&self) -> bool {
        self.s1.len() == S1_LEN
            && self.s2.len() == S2_LEN
            && self.k.len() == SEED_LEN
            && self
                .s1
                .iter()
                .chain(&self.s2)
                .chain(&self.k)
                .all(|c| (0..Q).contains(c))
    }

    fn zip(&self, other: &Self, f: impl Fn(i32, i32) -> i32) -> Self {
        let z = |a: &[i32], b: &[i32]| a.iter().zip(b).map(|(x, y)| f(*x, *y)).collect();
        Self {
            s1: z(&self.s1, &other.s1),
            s2: z(&self.s2, &other.s2),
            k: z(&self.k, &other.k),
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        self.zip(other, |a, b| red(a as i64 + b as i64))
    }

    pub fn scale(&self, w: i32) -> Self {
        self.zip(self, |a, _| fq_mul(a, w))
    }

    pub fn sum<'a>(parts: impl IntoIterator<Item = &'a Self>) -> Self {
        parts.into_iter().fold(Self::zero(), |acc, p| acc.add(p))
    }

    /// Split into `n` uniform additive sub-shares.
    pub fn split<R: Rng + CryptoRng>(&self, n: usize, rng: &mut R) -> Vec<Self> {
        let mut rest = self.clone();
        let mut out = Vec::with_capacity(n);
        for _ in 1..n {
            let rand = |len: usize, rng: &mut R| (0..len).map(|_| rng.gen_range(0..Q)).collect();
            let part = Self {
                s1: rand(S1_LEN, rng),
                s2: rand(S2_LEN, rng),
                k: rand(SEED_LEN, rng),
            };
            rest = rest.zip(&part, |a, b| red(a as i64 - b as i64));
            out.push(part);
        }
        out.push(rest);
        out
    }

    /// `A s1 + s2` for this share. Uniform for a uniform share; the values of all holders sum to
    /// the public `t`, so publishing it reveals nothing and makes a wrong share attributable.
    pub fn verification(&self, a_hat: &MatrixHat) -> PolyVec {
        vec_add(
            &mat_vec_coeff(a_hat, &to_polys(&self.s1)),
            &to_polys(&self.s2),
        )
    }

    /// The linear half of an attempt for an additive holder: `z = y + c s1`, `r = A y - c s2`.
    pub fn respond(
        &self,
        a_hat: &MatrixHat,
        y: &PolyVec,
        c_tilde: &[u8; C_TILDE_BYTES],
    ) -> (PolyVec, PolyVec) {
        let c = sample_in_ball(c_tilde);
        let z = vec_add(y, &challenge_mul(&c, &to_polys(&self.s1)));
        let r = vec_sub(
            &mat_vec_coeff(a_hat, y),
            &challenge_mul(&c, &to_polys(&self.s2)),
        );
        (z, r)
    }
}

impl KeyShare {
    /// Step 1 of the compression: this signer's direct additive share of the master key for an
    /// active set in which its composed Lagrange weight is `weight`.
    pub fn flatten(&self, weight: i32) -> AdditiveShare {
        let scale = |v: &PolyVec| v.iter().flatten().map(|c| fq_mul(*c, weight)).collect();
        AdditiveShare {
            s1: scale(&self.s1),
            s2: scale(&self.s2),
            k: self.k.iter().map(|c| fq_mul(*c, weight)).collect(),
        }
    }

    /// Serialize for a share file. The bytes are the signer's long-term secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        let flat = self.flatten(1);
        bincode::serialize(&(&self.path, &flat)).expect("share encoding cannot fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (path, flat): (Vec<u8>, AdditiveShare) = bincode::deserialize(bytes).ok()?;
        flat.is_well_formed().then(|| Self {
            path,
            s1: to_polys(&flat.s1),
            s2: to_polys(&flat.s2),
            k: flat.k.clone().try_into().expect("checked length"),
        })
    }
}

/// Does `(verification values per engine)` add up to the signer's public verification share
/// times its weight? `parts` holds `A a1 + a2` as reported by each engine for one signer.
pub fn sub_shares_consistent(
    group: &GroupPublic,
    path: &[u8],
    weight: i32,
    parts: &[PolyVec],
) -> bool {
    let Some(t_p) = group.verification.get(path) else {
        return false;
    };
    let sum = parts
        .iter()
        .fold(fips204::vec_zero(K), |acc, p| vec_add(&acc, p));
    sum == fips204::vec_scale(t_p, weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{deal, lagrange_at_zero, Active, Gadget, Path};
    use rand::{rngs::OsRng, seq::SliceRandom};
    use std::collections::BTreeMap;

    fn secret(seed: &[u8; 32]) -> AdditiveShare {
        let key = fips204::keygen_internal(seed);
        AdditiveShare {
            s1: to_flat(&key.s1),
            s2: to_flat(&key.s2),
            k: key.k.iter().map(|b| *b as i32).collect(),
        }
    }

    fn random_active(shape: &[Gadget]) -> Active {
        let pick = |g: Gadget| {
            let mut all: Vec<u8> = (1..=g.n).collect();
            all.shuffle(&mut OsRng);
            all.truncate(g.t as usize);
            all.sort();
            all
        };
        Active::Committee(
            pick(shape[0])
                .into_iter()
                .map(|i| {
                    (
                        i,
                        Active::Committee(
                            pick(shape[1])
                                .into_iter()
                                .map(|j| (j, Active::Signer))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    }

    /// Property test for the compression: over random active sets, the three engine shares sum to
    /// the master key, while no view (any single engine, any single signer, and the coordinator,
    /// which sees no share at all) contains the master key or any leaf's share of it.
    #[test]
    fn compression_is_exact_and_no_view_holds_a_leaf_secret_or_the_key() {
        let shape = [Gadget::new(3, 4).unwrap(), Gadget::new(3, 4).unwrap()];
        for round in 0..24u8 {
            let seed = [round.wrapping_mul(29).wrapping_add(3); 32];
            let (group, shares) = deal(&seed, &shape, &mut OsRng).unwrap();
            let s = secret(&seed);
            let active = random_active(&shape);
            let weights: BTreeMap<Path, i32> = active.weights().into_iter().collect();
            assert_eq!(weights.len(), 9);

            // What each engine receives, per signer; what each signer keeps is its own share.
            let mut engine_views: Vec<Vec<(Path, AdditiveShare)>> = vec![vec![]; 3];
            let mut flattened: BTreeMap<Path, AdditiveShare> = BTreeMap::new();
            for (path, w) in &weights {
                let share = shares.iter().find(|x| &x.path == path).unwrap();
                let hat = share.flatten(*w);
                for (k, sub) in hat.split(3, &mut OsRng).into_iter().enumerate() {
                    engine_views[k].push((path.clone(), sub));
                }
                flattened.insert(path.clone(), hat);
            }

            // Correctness: engine shares sum to s, and the verification values are consistent.
            let engine_shares: Vec<AdditiveShare> = engine_views
                .iter()
                .map(|v| AdditiveShare::sum(v.iter().map(|(_, x)| x)))
                .collect();
            assert!(
                AdditiveShare::sum(&engine_shares) == s,
                "root shares must sum to the master key"
            );
            let t_sum = engine_shares.iter().fold(fips204::vec_zero(K), |acc, e| {
                vec_add(&acc, &e.verification(group.a_hat()))
            });
            let key = fips204::keygen_internal(&seed);
            assert_eq!(
                t_sum,
                vec_add(&mat_vec_coeff(group.a_hat(), &key.s1), &key.s2)
            );
            for (path, w) in &weights {
                let parts: Vec<PolyVec> = engine_views
                    .iter()
                    .map(|v| {
                        v.iter()
                            .find(|(p, _)| p == path)
                            .unwrap()
                            .1
                            .verification(group.a_hat())
                    })
                    .collect();
                assert!(sub_shares_consistent(&group, path, *w, &parts));
                assert!(!sub_shares_consistent(
                    &group,
                    path,
                    red(*w as i64 + 1),
                    &parts
                ));
            }

            // The forbidden values: the master key, each leaf's share of it (sigma_i, the Shamir
            // share dealt to leaf i), and each leaf's weighted contribution Lambda_i * sigma_i.
            let Active::Committee(leaves) = &active else {
                unreachable!()
            };
            let root_set: Vec<u8> = leaves.iter().map(|(i, _)| *i).collect();
            let mut forbidden = vec![s.clone()];
            for (i, leaf) in leaves {
                let Active::Committee(members) = leaf else {
                    unreachable!()
                };
                let set: Vec<u8> = members.iter().map(|(j, _)| *j).collect();
                let sigma = AdditiveShare::sum(
                    set.iter()
                        .map(|j| {
                            let share = shares.iter().find(|x| x.path == [*i, *j]).unwrap();
                            share.flatten(lagrange_at_zero(*j, &set))
                        })
                        .collect::<Vec<_>>()
                        .iter(),
                );
                let weighted = AdditiveShare::sum(set.iter().map(|j| &flattened[&vec![*i, *j]]));
                assert!(
                    weighted == sigma.scale(lagrange_at_zero(*i, &root_set)),
                    "Lambda_i * sigma_i"
                );
                forbidden.push(sigma);
                forbidden.push(weighted);
            }

            // No engine ever holds a forbidden value: not as a received sub-share, not as its
            // per-leaf partial sums, not as its final share. No single signer's flattened share
            // is one either. The coordinator's view is empty by construction (sub-shares travel
            // signer -> engine only; the networked test asserts that on real frames).
            for (view, total) in engine_views.iter().zip(&engine_shares) {
                let mut seen: Vec<AdditiveShare> = view.iter().map(|(_, x)| x.clone()).collect();
                for (i, _) in leaves {
                    seen.push(AdditiveShare::sum(
                        view.iter().filter(|(p, _)| p[0] == *i).map(|(_, x)| x),
                    ));
                }
                seen.push(total.clone());
                assert!(
                    seen.iter().all(|x| !forbidden.contains(x)),
                    "an engine view holds a secret"
                );
                // Two engines together still do not hold the key.
            }
            for pair in [[0, 1], [0, 2], [1, 2]] {
                let two = AdditiveShare::sum(pair.iter().map(|k| &engine_shares[*k]));
                assert!(!forbidden.contains(&two));
            }
            assert!(flattened.values().all(|x| !forbidden.contains(x)));
        }
    }

    #[test]
    fn share_file_round_trip() {
        let (_, shares) = deal(&[4; 32], &[Gadget::new(3, 4).unwrap()], &mut OsRng).unwrap();
        let back = KeyShare::from_bytes(&shares[2].to_bytes()).unwrap();
        assert_eq!(back.path, shares[2].path);
        assert!(back.flatten(1) == shares[2].flatten(1));
        assert!(KeyShare::from_bytes(&[1, 2, 3]).is_none());
    }
}

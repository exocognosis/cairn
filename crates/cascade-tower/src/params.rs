//! Tower shape and its corruption bounds.
//!
//! The bounds are the read-once threshold-tree results of the `CertTowers` Lean 4 library
//! (machine-checked, no `sorry`; the sources are private and not vendored here, see
//! ARCHITECTURE.md "Formal links"). For a gadget list `[(k_1,t_1), ..., (k_L,t_L)]`, root first:
//!
//! * `CertTowers.Access.minAuth_isLeast`: the least authorized signer set has `prod t_j` members.
//! * `CertTowers.Access.minBlock_isLeast`: the least blocking set has `prod (k_j - t_j + 1)`.
//! * `CertTowers.ThresholdTree.rootProb_cons` / `rootProb_list`: under i.i.d. corruption with
//!   probability `f`, `Pr[root compromised]` is the per-tier binomial tail iterated up the tree.
//!
//! This module evaluates those closed forms; it does not re-prove them. The exhaustive test in
//! this file checks the two extremal bounds against brute force for the default tower.

use std::collections::BTreeSet;
use threshold_mldsa::{Gadget, Path, ShapeError};

/// Shape of a committee tower, root first. Every tier obeys the `N <= 6` ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TowerParams {
    tiers: Vec<Gadget>,
}

impl TowerParams {
    /// Tiers as `(t, n)`, root first.
    pub fn new(tiers: &[(usize, usize)]) -> Result<Self, ShapeError> {
        if tiers.is_empty() {
            return Err(ShapeError::Empty);
        }
        let tiers = tiers.iter().map(|&(t, n)| Gadget::new(t, n)).collect::<Result<_, _>>()?;
        Ok(Self { tiers })
    }

    /// The v1 default: four 3-of-4 leaf committees under a 3-of-4 root, 16 signers.
    pub fn default_16() -> Self {
        Self::new(&[(3, 4), (3, 4)]).expect("static shape")
    }

    pub fn tiers(&self) -> &[Gadget] {
        &self.tiers
    }

    pub fn signers(&self) -> usize {
        self.tiers.iter().map(|g| g.n as usize).product()
    }

    /// Fewest corrupt signers that can sign (`minAuth_isLeast`): `prod t_j`.
    pub fn min_forging_coalition(&self) -> usize {
        self.tiers.iter().map(|g| g.t as usize).product()
    }

    /// Fewest absent or refusing signers that can stop signing (`minBlock_isLeast`).
    pub fn min_blocking_coalition(&self) -> usize {
        self.tiers.iter().map(|g| (g.n - g.t + 1) as usize).product()
    }

    /// `Pr[root compromised]` when each signer is corrupt independently with probability `f`.
    pub fn root_compromise_probability(&self, f: f64) -> f64 {
        self.tiers.iter().rev().fold(f, |p, g| binomial_tail(g.n as u32, g.t as u32, p))
    }

    /// `Pr[signing blocked]` when each signer is offline independently with probability `f`.
    pub fn root_blocked_probability(&self, f: f64) -> f64 {
        self.tiers
            .iter()
            .rev()
            .fold(f, |p, g| binomial_tail(g.n as u32, (g.n - g.t + 1) as u32, p))
    }

    /// All signer paths, in order.
    pub fn paths(&self) -> Vec<Path> {
        let mut out = vec![Path::new()];
        for g in &self.tiers {
            out = out
                .into_iter()
                .flat_map(|p| (1..=g.n).map(move |i| [p.clone(), vec![i]].concat()))
                .collect();
        }
        out
    }

    /// The access function `F`: can this set of signers produce a signature?
    pub fn is_authorized(&self, set: &BTreeSet<Path>) -> bool {
        fn node(tiers: &[Gadget], prefix: &mut Path, set: &BTreeSet<Path>) -> bool {
            let Some((g, rest)) = tiers.split_first() else {
                return set.contains(prefix);
            };
            let mut good = 0;
            for i in 1..=g.n {
                prefix.push(i);
                good += node(rest, prefix, set) as u8;
                prefix.pop();
            }
            good >= g.t
        }
        node(&self.tiers, &mut Path::new(), set)
    }

    /// Does removing this set leave the remaining signers unable to sign?
    pub fn is_blocking(&self, set: &BTreeSet<Path>) -> bool {
        let rest: BTreeSet<Path> = self.paths().into_iter().filter(|p| !set.contains(p)).collect();
        !self.is_authorized(&rest)
    }
}

/// `Pr[Bin(k, p) >= theta]` (`CertTowers.ThresholdTree.binTail`).
pub fn binomial_tail(k: u32, theta: u32, p: f64) -> f64 {
    let choose = |m: u32| (0..m).fold(1.0, |acc, i| acc * (k - i) as f64 / (i + 1) as f64);
    (theta..=k).map(|m| choose(m) * p.powi(m as i32) * (1.0 - p).powi((k - m) as i32)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_tower_bounds() {
        let p = TowerParams::default_16();
        assert_eq!((p.signers(), p.min_forging_coalition(), p.min_blocking_coalition()), (16, 9, 4));
        assert!(TowerParams::new(&[(3, 4), (4, 7)]).is_err());
    }

    #[test]
    fn extremal_bounds_match_brute_force_over_all_subsets() {
        let p = TowerParams::default_16();
        let paths = p.paths();
        let (mut min_auth, mut min_block) = (usize::MAX, usize::MAX);
        for mask in 0u32..1 << 16 {
            let set: BTreeSet<Path> = (0..16).filter(|i| mask >> i & 1 == 1).map(|i| paths[i].clone()).collect();
            let size = set.len();
            if size < min_auth && p.is_authorized(&set) {
                min_auth = size;
            }
            if size < min_block && p.is_blocking(&set) {
                min_block = size;
            }
        }
        assert_eq!(min_auth, p.min_forging_coalition());
        assert_eq!(min_block, p.min_blocking_coalition());
    }

    #[test]
    fn iid_corruption_contracts_below_the_fixed_point() {
        let p = TowerParams::default_16();
        // One 3-of-4 gadget maps 0.10 to about 0.0037; two tiers to about 2e-7.
        let one = binomial_tail(4, 3, 0.10);
        assert!((one - 0.0037).abs() < 1e-4);
        let two = p.root_compromise_probability(0.10);
        assert!(two < 3e-7 && two > 1e-7);
        assert!((p.root_compromise_probability(1.0) - 1.0).abs() < 1e-12);
    }
}

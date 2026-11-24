//! Deterministic, stake-weighted assignment of validators to tower seats for one epoch.
//!
//! Every node computes the same assignment from `(epoch, epoch_seed, validator set, shape)`.
//! Seats are drawn without replacement with probability proportional to stake (one seat per
//! validator), then dealt across the leaf committees in snake order of descending stake so that
//! no leaf concentrates the heaviest validators.

use crate::params::TowerParams;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::collections::{BTreeMap, BTreeSet};
use threshold_mldsa::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    /// Stable identifier (consensus address or public key bytes).
    pub id: Vec<u8>,
    pub stake: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AssignError {
    #[error("{have} validators with stake cannot fill {need} seats")]
    TooFewValidators { have: usize, need: usize },
    #[error("duplicate validator id")]
    DuplicateId,
    #[error("assignment needs a two-tier tower")]
    NotTwoTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub epoch: u64,
    /// Seat (tower path) to validator.
    pub seats: BTreeMap<Path, Validator>,
}

/// What a given set of corrupt validators can do to this epoch's tower.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    pub corrupt_seats: usize,
    /// The corrupt seats alone can sign.
    pub can_forge: bool,
    /// The corrupt seats can stop the honest ones from signing.
    pub can_block: bool,
}

fn uniform_below(xof: &mut impl XofReader, bound: u128) -> u128 {
    // Rejection sampling: unbiased for any bound.
    let zone = u128::MAX - u128::MAX % bound;
    loop {
        let mut b = [0u8; 16];
        xof.read(&mut b);
        let v = u128::from_be_bytes(b);
        if v < zone {
            return v % bound;
        }
    }
}

pub fn assign(
    epoch: u64,
    epoch_seed: &[u8; 32],
    validators: &[Validator],
    params: &TowerParams,
) -> Result<Assignment, AssignError> {
    let [root, leaf] = params.tiers() else {
        return Err(AssignError::NotTwoTier);
    };
    let mut pool: Vec<&Validator> = validators.iter().filter(|v| v.stake > 0).collect();
    pool.sort_by(|a, b| a.id.cmp(&b.id));
    if pool.windows(2).any(|w| w[0].id == w[1].id) {
        return Err(AssignError::DuplicateId);
    }
    let need = params.signers();
    if pool.len() < need {
        return Err(AssignError::TooFewValidators {
            have: pool.len(),
            need,
        });
    }

    let mut h = Shake256::default();
    h.update(b"cairn/assign/v1");
    h.update(&epoch.to_be_bytes());
    h.update(epoch_seed);
    h.update(&[root.t, root.n, leaf.t, leaf.n]);
    for v in &pool {
        h.update(&(v.id.len() as u32).to_be_bytes());
        h.update(&v.id);
        h.update(&v.stake.to_be_bytes());
    }
    let mut xof = h.finalize_xof();

    let mut chosen: Vec<&Validator> = Vec::with_capacity(need);
    while chosen.len() < need {
        let total: u128 = pool.iter().map(|v| v.stake as u128).sum();
        let mut ticket = uniform_below(&mut xof, total);
        let pos = pool
            .iter()
            .position(|v| {
                if ticket < v.stake as u128 {
                    true
                } else {
                    ticket -= v.stake as u128;
                    false
                }
            })
            .expect("ticket is below the total stake");
        chosen.push(pool.remove(pos));
    }

    chosen.sort_by(|a, b| b.stake.cmp(&a.stake).then(a.id.cmp(&b.id)));
    let leaves = root.n as usize;
    let seats = chosen
        .into_iter()
        .enumerate()
        .map(|(p, v)| {
            let (row, col) = (p / leaves, p % leaves);
            let col = if row % 2 == 1 { leaves - 1 - col } else { col };
            (vec![col as u8 + 1, row as u8 + 1], v.clone())
        })
        .collect();
    Ok(Assignment { epoch, seats })
}

impl Assignment {
    pub fn seat_of(&self, id: &[u8]) -> Option<&Path> {
        self.seats.iter().find(|(_, v)| v.id == id).map(|(p, _)| p)
    }

    /// Total stake seated in each leaf committee.
    pub fn leaf_stake(&self) -> BTreeMap<u8, u128> {
        let mut out = BTreeMap::new();
        for (path, v) in &self.seats {
            *out.entry(path[0]).or_default() += v.stake as u128;
        }
        out
    }

    /// Evaluate the tower's access function on the seats held by `corrupt` validators.
    pub fn exposure(&self, params: &TowerParams, corrupt: &BTreeSet<Vec<u8>>) -> Exposure {
        let seats: BTreeSet<Path> = self
            .seats
            .iter()
            .filter(|(_, v)| corrupt.contains(&v.id))
            .map(|(p, _)| p.clone())
            .collect();
        Exposure {
            corrupt_seats: seats.len(),
            can_forge: params.is_authorized(&seats),
            can_block: params.is_blocking(&seats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validators(n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                id: vec![i as u8, 0xaa],
                stake: 1_000 + 37 * (i as u64 * i as u64 % 101),
            })
            .collect()
    }

    #[test]
    fn deterministic_and_input_order_independent() {
        let p = TowerParams::default_16();
        let v = validators(40);
        let a = assign(7, &[1; 32], &v, &p).unwrap();
        let mut shuffled = v.clone();
        shuffled.reverse();
        assert_eq!(a, assign(7, &[1; 32], &shuffled, &p).unwrap());
        assert_ne!(a, assign(8, &[1; 32], &v, &p).unwrap());
        assert_ne!(a, assign(7, &[2; 32], &v, &p).unwrap());
        assert_eq!(a.seats.len(), 16);
        let ids: BTreeSet<_> = a.seats.values().map(|v| v.id.clone()).collect();
        assert_eq!(ids.len(), 16, "one seat per validator");
        assert_eq!(a.seats.keys().cloned().collect::<Vec<_>>(), p.paths());
    }

    #[test]
    fn selection_follows_stake() {
        let p = TowerParams::default_16();
        let mut v = validators(64);
        v[0].stake = 1_000_000; // a whale is seated in (almost) every epoch
        let seated = (0..200u64)
            .filter(|e| {
                assign(*e, &[3; 32], &v, &p)
                    .unwrap()
                    .seat_of(&v[0].id)
                    .is_some()
            })
            .count();
        assert!(seated >= 198, "whale seated {seated}/200");
        let small = (0..200u64)
            .filter(|e| {
                assign(*e, &[3; 32], &v, &p)
                    .unwrap()
                    .seat_of(&v[1].id)
                    .is_some()
            })
            .count();
        assert!(small < 120, "small validator seated {small}/200");
    }

    #[test]
    fn snake_order_balances_leaves_and_exposure_uses_the_access_function() {
        let p = TowerParams::default_16();
        let v: Vec<Validator> = (0..16)
            .map(|i| Validator {
                id: vec![i],
                stake: 100 - i as u64,
            })
            .collect();
        let a = assign(1, &[0; 32], &v, &p).unwrap();
        let stakes: Vec<u128> = a.leaf_stake().into_values().collect();
        assert!(stakes.iter().max().unwrap() - stakes.iter().min().unwrap() <= 4);
        // Eight corrupt validators cannot forge (bound is 9); three cannot block (bound is 4).
        let eight: BTreeSet<Vec<u8>> = (0..8).map(|i| vec![i]).collect();
        assert!(!a.exposure(&p, &eight).can_forge);
        let three: BTreeSet<Vec<u8>> = (0..3).map(|i| vec![i]).collect();
        assert!(!a.exposure(&p, &three).can_block);
        assert_eq!(
            assign(1, &[0; 32], &v[..15], &p),
            Err(AssignError::TooFewValidators { have: 15, need: 16 })
        );
    }
}

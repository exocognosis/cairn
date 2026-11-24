//! The two-tier tower: a root committee whose parties are leaf committees.
//!
//! Tier roles in one attempt:
//! * **Leaf tier** (per leaf, `n <= 6` signers): the four message rounds among the leaf's
//!   signers, and the linear work of re-sharing the leaf's mask share and collecting its
//!   members' response shares.
//! * **Root tier** (`n <= 6` leaf committees): the same four rounds among the leaves, plus the
//!   non-linear attempt engine (mask derivation, rounding, abort checks, hint aggregation).
//!
//! No interactive committee anywhere has more than six parties.

use crate::params::TowerParams;
use rand::{CryptoRng, Rng};
use std::sync::Arc;
use threshold_mldsa::{
    deal, sign, AttemptEngine, Committee, GroupPublic, Party, ShapeError, SignError, SignPolicy, Signed, Signer,
    PUBLIC_KEY_BYTES,
};

#[derive(Debug, thiserror::Error)]
pub enum TowerError {
    #[error(transparent)]
    Shape(#[from] ShapeError),
    #[error("v1 builds two-tier towers only (got {0} tiers)")]
    NotTwoTier(usize),
}

pub type LeafCommittee = Committee<Signer>;

pub struct Tower {
    params: TowerParams,
    group: Arc<GroupPublic>,
    root: Committee<LeafCommittee>,
}

impl Tower {
    /// Trusted-dealer setup: derive the ML-DSA-65 key from `seed`, share it down the tower and
    /// build every signer in this process. See DECISIONS.md D-04 for what a deployment replaces.
    pub fn deal<R: Rng + CryptoRng>(seed: &[u8; 32], params: &TowerParams, rng: &mut R) -> Result<Self, TowerError> {
        let [root_g, leaf_g] = params.tiers() else {
            return Err(TowerError::NotTwoTier(params.tiers().len()));
        };
        let (group, shares) = deal(seed, params.tiers(), rng)?;
        let group = Arc::new(group);
        let mut shares = shares.into_iter().peekable();
        let mut leaves = Vec::new();
        for leaf in 1..=root_g.n {
            let mut signers = Vec::new();
            while let Some(share) = shares.next_if(|s| s.path[0] == leaf) {
                signers.push(Signer::new(share, group.clone()));
            }
            leaves.push(Committee::new(group.clone(), vec![leaf], leaf_g.t as usize, signers)?);
        }
        let root = Committee::new(group.clone(), vec![], root_g.t as usize, leaves)?;
        Ok(Self { params: params.clone(), group, root })
    }

    pub fn params(&self) -> &TowerParams {
        &self.params
    }

    pub fn group(&self) -> &Arc<GroupPublic> {
        &self.group
    }

    /// The epoch public key: a standard FIPS 204 ML-DSA-65 encoding.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.group.pk
    }

    /// Signer at `[leaf, member]` (1-based), e.g. to script a fault.
    pub fn signer_mut(&mut self, path: &[u8]) -> Option<&mut Signer> {
        let [leaf, member] = path else { return None };
        self.root
            .members_mut()
            .get_mut(leaf.checked_sub(1)? as usize)?
            .members_mut()
            .get_mut(member.checked_sub(1)? as usize)
    }

    /// Produce one standard ML-DSA-65 signature over `message` (empty context).
    pub fn sign<E: AttemptEngine>(
        &mut self,
        engine: &mut E,
        message: &[u8],
        policy: &SignPolicy,
    ) -> Result<Signed, SignError> {
        sign(&mut self.root, engine, &self.group, message, policy)
    }

    /// Bring every excluded or suspended signer back (epoch boundary).
    pub fn reinstate(&mut self) {
        self.root.reinstate();
    }
}

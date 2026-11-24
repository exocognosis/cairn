//! Parties of the signing protocol: a key-holding [`Signer`] and a [`Committee`] of parties.
//!
//! A committee is itself a [`Party`], so committees nest: a tower is a committee of committees.
//! Every committee is capped at [`MAX_COMMITTEE`](crate::keys::MAX_COMMITTEE) members.

use crate::engine::{MaskShare, ResponsePart, Sealed, SeedPart};
use crate::fips204::{
    self, challenge_mul, mat_vec_coeff, sample_in_ball, vec_add, vec_scale, vec_sub, PolyVec,
    C_TILDE_BYTES, K, L, N, Q,
};
use crate::keys::{Active, Gadget, GroupPublic, KeyShare, Path, ShapeError};
use crate::protocol::{AttemptCtx, Fault, FaultKind, Message, Opening, Round, Wire};
use rand::{rngs::OsRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use zeroize::Zeroize;

pub type CTilde = [u8; C_TILDE_BYTES];

/// One participant of a committee: a signer, or a whole sub-committee acting as one party.
pub trait Party {
    /// Shamir x-coordinate within the parent committee (1-based).
    fn index(&self) -> u8;
    /// Round 1. Returns the active sub-tree and the signer-level participation bindings.
    fn commit(&mut self, ctx: &AttemptCtx, wire: &mut Wire) -> Result<(Active, Vec<(Path, [u8; 32])>), Fault>;
    /// Sealed seed shares for the engine's mask phase.
    fn seed_input(&mut self, ctx: &AttemptCtx, wire: &mut Wire) -> Result<Sealed<Vec<SeedPart>>, Fault>;
    /// Round 2. Takes this party's sealed mask share and the opened `c~`; returns the echo.
    fn challenge(
        &mut self,
        ctx: &AttemptCtx,
        root: &Active,
        mask: Sealed<MaskShare>,
        c_tilde: &CTilde,
        wire: &mut Wire,
    ) -> Result<CTilde, Fault>;
    /// Round 3. Commitments to the response shares, and the sealed shares for the engine.
    #[allow(clippy::type_complexity)]
    fn respond(
        &mut self,
        ctx: &AttemptCtx,
        wire: &mut Wire,
    ) -> Result<(Vec<(Path, [u8; 32])>, Sealed<Vec<ResponsePart>>), Fault>;
    /// Round 4. On reject: erase the attempt and open nothing. On accept: open `z_p`.
    fn open(
        &mut self,
        ctx: &AttemptCtx,
        accept: bool,
        hint: Option<&[u16]>,
        wire: &mut Wire,
    ) -> Result<Vec<Opening>, Fault>;
    /// Drop a blamed signer or sub-committee for the rest of the session.
    fn exclude(&mut self, path: &[u8]);
    /// After an unattributed abort: suspend the `n`-th candidate. False if no spare exists.
    fn probe(&mut self, n: u32) -> bool;
    /// Erase all per-attempt state.
    fn reset(&mut self);
}

/// Scripted deviations, for tests and fault benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Honest,
    /// Never answers.
    Offline,
    /// Goes silent in the given round of every attempt it joins.
    SilentAt(Round),
    /// Echoes a different `c~`.
    WrongChallenge,
    /// Opens a `z_p` that does not match its commitment.
    BadOpening,
    /// Commits to and opens a `z_p` other than the one it gave the engine.
    OpeningMismatch,
    /// Gives the engine an inconsistent `(z_p, r_p)`.
    BadResponse,
    /// Gives the engine a wrong seed share.
    BadSeedShare,
    /// Uses a different mask share than the one it received (not attributable).
    ShiftMask,
}

pub fn participation_binding(ctx: &AttemptCtx, path: &[u8], seed_commitment: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    fips204::shake256(
        &[b"cairn/participate/v1", &ctx.session, &[path.len() as u8], path, seed_commitment],
        &mut out,
    );
    out
}

pub fn z_commitment(ctx: &AttemptCtx, path: &[u8], z: &[i32], salt: &[u8; 32]) -> [u8; 32] {
    let bytes: Vec<u8> = z.iter().flat_map(|c| c.to_le_bytes()).collect();
    let mut out = [0u8; 32];
    fips204::shake256(
        &[b"cairn/z-commit/v1", &ctx.session, &[path.len() as u8], path, &bytes, salt],
        &mut out,
    );
    out
}

pub fn flatten(v: &PolyVec) -> Vec<i32> {
    v.iter().flatten().copied().collect()
}

pub fn unflatten(flat: &[i32]) -> Option<PolyVec> {
    (flat.len() == L * N && flat.iter().all(|c| (0..Q).contains(c)))
        .then(|| flat.chunks(N).map(|c| c.try_into().unwrap()).collect())
}

#[derive(Default)]
struct AttemptState {
    y: PolyVec,
    z: PolyVec,
    c_tilde: Option<CTilde>,
    weight: i32,
    salt: [u8; 32],
}

impl AttemptState {
    fn erase(&mut self) {
        self.y.zeroize();
        self.z.zeroize();
        self.salt.zeroize();
        self.weight = 0;
        self.c_tilde = None;
    }
}

/// A key-share holder.
pub struct Signer {
    share: KeyShare,
    group: Arc<GroupPublic>,
    pub behavior: Behavior,
    state: AttemptState,
}

impl Signer {
    pub fn new(share: KeyShare, group: Arc<GroupPublic>) -> Self {
        Self { share, group, behavior: Behavior::Honest, state: AttemptState::default() }
    }

    pub fn path(&self) -> &Path {
        &self.share.path
    }

    fn silent(&self, round: Round) -> Result<(), Fault> {
        if self.behavior == Behavior::Offline || self.behavior == Behavior::SilentAt(round) {
            return Err(Fault { culprit: Some(self.share.path.clone()), kind: FaultKind::Timeout(round) });
        }
        Ok(())
    }
}

impl Party for Signer {
    fn index(&self) -> u8 {
        *self.share.path.last().expect("signer path is never empty")
    }

    fn commit(&mut self, ctx: &AttemptCtx, wire: &mut Wire) -> Result<(Active, Vec<(Path, [u8; 32])>), Fault> {
        self.state.erase();
        self.silent(Round::Commitment)?;
        let path = self.share.path.clone();
        let binding = participation_binding(ctx, &path, &self.group.seed_commitments[&path]);
        wire.broadcast(Message::Commitment { header: ctx.header(&path), active: Active::Signer, binding });
        Ok((Active::Signer, vec![(path, binding)]))
    }

    fn seed_input(&mut self, _ctx: &AttemptCtx, wire: &mut Wire) -> Result<Sealed<Vec<SeedPart>>, Fault> {
        let mut k_share = self.share.k;
        if self.behavior == Behavior::BadSeedShare {
            k_share[0] = (k_share[0] + 1) % Q;
        }
        wire.engine_io(&self.share.path, 32 * 4);
        Ok(Sealed::seal(vec![SeedPart { path: self.share.path.clone(), k_share }]))
    }

    fn challenge(
        &mut self,
        ctx: &AttemptCtx,
        root: &Active,
        mask: Sealed<MaskShare>,
        c_tilde: &CTilde,
        wire: &mut Wire,
    ) -> Result<CTilde, Fault> {
        self.silent(Round::Challenge)?;
        let path = self.share.path.clone();
        self.state.y = mask.unseal_own();
        wire.engine_io(&path, L * N * 4);
        if self.behavior == Behavior::ShiftMask {
            self.state.y[0][0] = (self.state.y[0][0] + 1) % Q;
        }
        self.state.weight = root
            .weights()
            .into_iter()
            .find(|(p, _)| p == &path)
            .map(|(_, w)| w)
            .ok_or(Fault { culprit: None, kind: FaultKind::Unattributed })?;
        self.state.c_tilde = Some(*c_tilde);
        let mut echo = *c_tilde;
        if self.behavior == Behavior::WrongChallenge {
            echo[0] ^= 1;
        }
        wire.broadcast(Message::Challenge { header: ctx.header(&path), c_tilde: echo.to_vec() });
        Ok(echo)
    }

    fn respond(
        &mut self,
        ctx: &AttemptCtx,
        wire: &mut Wire,
    ) -> Result<(Vec<(Path, [u8; 32])>, Sealed<Vec<ResponsePart>>), Fault> {
        self.silent(Round::MaskedResponse)?;
        let path = self.share.path.clone();
        let c_tilde = self.state.c_tilde.ok_or(Fault { culprit: Some(path.clone()), kind: FaultKind::Timeout(Round::Challenge) })?;
        let c = sample_in_ball(&c_tilde);
        // The linear share arithmetic every signer does locally:
        //   z_p = y_p + c (w_p s1_p),   r_p = A y_p - c (w_p s2_p).
        let w = self.state.weight;
        let z = vec_add(&self.state.y, &challenge_mul(&c, &vec_scale(&self.share.s1, w)));
        let mut r = vec_sub(
            &mat_vec_coeff(self.group.a_hat(), &self.state.y),
            &challenge_mul(&c, &vec_scale(&self.share.s2, w)),
        );
        if self.behavior == Behavior::BadResponse {
            r[0][0] = (r[0][0] + 1) % Q;
        }
        self.state.z = z.clone();
        if self.behavior == Behavior::OpeningMismatch {
            self.state.z[0][0] = (self.state.z[0][0] + 1) % Q;
        }
        OsRng.fill_bytes(&mut self.state.salt);
        let commitment = z_commitment(ctx, &path, &flatten(&self.state.z), &self.state.salt);
        wire.engine_io(&path, (L + K) * N * 4);
        wire.broadcast(Message::MaskedResponse {
            header: ctx.header(&path),
            commitments: vec![(path.clone(), commitment)],
        });
        Ok((vec![(path.clone(), commitment)], Sealed::seal(vec![ResponsePart { path, z, r }])))
    }

    fn open(
        &mut self,
        ctx: &AttemptCtx,
        accept: bool,
        _hint: Option<&[u16]>,
        wire: &mut Wire,
    ) -> Result<Vec<Opening>, Fault> {
        let path = self.share.path.clone();
        if !accept {
            // Rejected: erase y_p and z_p. Nothing about this attempt is ever opened.
            self.state.erase();
            wire.broadcast(Message::HintCarry { header: ctx.header(&path), accept, openings: vec![], hint: None });
            return Ok(vec![]);
        }
        self.silent(Round::HintCarry)?;
        let mut z = flatten(&self.state.z);
        if self.behavior == Behavior::BadOpening {
            z[0] = (z[0] + 1) % Q;
        }
        let opening = Opening { path: path.clone(), z, salt: self.state.salt };
        self.state.erase();
        wire.broadcast(Message::HintCarry {
            header: ctx.header(&path),
            accept,
            openings: vec![opening.clone()],
            hint: None,
        });
        Ok(vec![opening])
    }

    fn exclude(&mut self, _path: &[u8]) {}

    fn probe(&mut self, _n: u32) -> bool {
        false
    }

    fn reset(&mut self) {
        self.state.erase();
    }
}

/// A `t`-of-`n` committee (`n <= 6`) of parties, itself a party of its parent.
pub struct Committee<P> {
    group: Arc<GroupPublic>,
    path: Path,
    gadget: Gadget,
    members: Vec<P>,
    excluded: BTreeSet<u8>,
    suspended: Option<u8>,
    active: Vec<usize>,
    commitments: BTreeMap<Path, [u8; 32]>,
}

impl<P: Party> Committee<P> {
    /// `path` is this committee's position in the tower (empty for the root).
    pub fn new(group: Arc<GroupPublic>, path: Path, threshold: usize, members: Vec<P>) -> Result<Self, ShapeError> {
        let gadget = Gadget::new(threshold, members.len())?;
        Ok(Self {
            group,
            path,
            gadget,
            members,
            excluded: BTreeSet::new(),
            suspended: None,
            active: Vec::new(),
            commitments: BTreeMap::new(),
        })
    }

    pub fn gadget(&self) -> Gadget {
        self.gadget
    }

    pub fn members_mut(&mut self) -> &mut [P] {
        &mut self.members
    }

    pub fn excluded(&self) -> &BTreeSet<u8> {
        &self.excluded
    }

    fn child_path(&self, index: u8) -> Path {
        let mut p = self.path.clone();
        p.push(index);
        p
    }

    fn is_child(&self, path: &[u8]) -> bool {
        path.len() == self.path.len() + 1 && path.starts_with(&self.path)
    }

    /// Account for a fault raised by a direct child (the round timer ran out on it).
    fn observe(&self, fault: &Fault, wire: &mut Wire) {
        let direct = fault.culprit.as_deref().is_some_and(|p| self.is_child(p));
        if direct && matches!(fault.kind, FaultKind::Timeout(_)) {
            wire.timed_out();
        }
    }

    fn live(&self) -> Vec<u8> {
        self.members
            .iter()
            .map(|m| m.index())
            .filter(|i| !self.excluded.contains(i) && self.suspended != Some(*i))
            .collect()
    }
}

impl<P: Party> Party for Committee<P> {
    fn index(&self) -> u8 {
        self.path.last().copied().unwrap_or(0)
    }

    fn commit(&mut self, ctx: &AttemptCtx, wire: &mut Wire) -> Result<(Active, Vec<(Path, [u8; 32])>), Fault> {
        self.active.clear();
        self.commitments.clear();
        let live = self.live();
        let (mut children, mut bindings) = (Vec::new(), Vec::new());
        for pos in 0..self.members.len() {
            if children.len() == self.gadget.t as usize {
                break;
            }
            let index = self.members[pos].index();
            if !live.contains(&index) {
                continue;
            }
            let child_path = self.child_path(index);
            let result = self.members[pos].commit(ctx, wire).and_then(|(active, b)| {
                // A signer's binding must match its public seed-share commitment.
                let ok = active != Active::Signer
                    || self.group.seed_commitments.get(&child_path).is_some_and(|sc| {
                        b.len() == 1 && b[0].1 == participation_binding(ctx, &child_path, sc)
                    });
                if ok {
                    Ok((active, b))
                } else {
                    Err(Fault { culprit: Some(child_path.clone()), kind: FaultKind::BadBinding })
                }
            });
            match result {
                Ok((active, b)) => {
                    children.push((index, active));
                    bindings.extend(b);
                    self.active.push(pos);
                }
                Err(fault) => {
                    // Not fatal: the committee carries on with its other members, and the
                    // silent one is not waited for again in this session.
                    self.observe(&fault, wire);
                    wire.faults.push(fault);
                    self.excluded.insert(index);
                }
            }
        }
        if children.len() < self.gadget.t as usize {
            self.active.clear();
            return Err(Fault { culprit: Some(self.path.clone()), kind: FaultKind::Timeout(Round::Commitment) });
        }
        let active = Active::Committee(children);
        let mut binding = [0u8; 32];
        let flat: Vec<u8> = bindings.iter().flat_map(|(_, b)| *b).collect();
        fips204::shake256(&[b"cairn/tier-binding/v1", &ctx.session, &flat], &mut binding);
        wire.broadcast(Message::Commitment { header: ctx.header(&self.path), active: active.clone(), binding });
        Ok((active, bindings))
    }

    fn seed_input(&mut self, ctx: &AttemptCtx, wire: &mut Wire) -> Result<Sealed<Vec<SeedPart>>, Fault> {
        let mut parts = Vec::new();
        for &pos in &self.active.clone() {
            parts.push(self.members[pos].seed_input(ctx, wire).inspect_err(|f| self.observe(f, wire))?);
        }
        Ok(Sealed::merge(parts))
    }

    fn challenge(
        &mut self,
        ctx: &AttemptCtx,
        root: &Active,
        mask: Sealed<MaskShare>,
        c_tilde: &CTilde,
        wire: &mut Wire,
    ) -> Result<CTilde, Fault> {
        let active = self.active.clone();
        // Linear tier work: re-share this committee's mask share among its active members.
        for (&pos, share) in active.iter().zip(mask.split(active.len())) {
            let child = self.child_path(self.members[pos].index());
            let echo = self.members[pos]
                .challenge(ctx, root, share, c_tilde, wire)
                .inspect_err(|f| self.observe(f, wire))?;
            if &echo != c_tilde {
                return Err(Fault { culprit: Some(child), kind: FaultKind::ChallengeMismatch });
            }
        }
        wire.broadcast(Message::Challenge { header: ctx.header(&self.path), c_tilde: c_tilde.to_vec() });
        Ok(*c_tilde)
    }

    fn respond(
        &mut self,
        ctx: &AttemptCtx,
        wire: &mut Wire,
    ) -> Result<(Vec<(Path, [u8; 32])>, Sealed<Vec<ResponsePart>>), Fault> {
        let (mut commitments, mut parts) = (Vec::new(), Vec::new());
        for &pos in &self.active.clone() {
            let (c, p) = self.members[pos].respond(ctx, wire).inspect_err(|f| self.observe(f, wire))?;
            commitments.extend(c);
            parts.push(p);
        }
        self.commitments = commitments.iter().cloned().collect();
        wire.broadcast(Message::MaskedResponse { header: ctx.header(&self.path), commitments: commitments.clone() });
        Ok((commitments, Sealed::merge(parts)))
    }

    fn open(
        &mut self,
        ctx: &AttemptCtx,
        accept: bool,
        hint: Option<&[u16]>,
        wire: &mut Wire,
    ) -> Result<Vec<Opening>, Fault> {
        let mut openings = Vec::new();
        for &pos in &self.active.clone() {
            let child = self.child_path(self.members[pos].index());
            let opened = self.members[pos].open(ctx, accept, hint, wire).inspect_err(|f| self.observe(f, wire))?;
            for o in &opened {
                // Each committee checks its own signers' openings against their commitments.
                if self.is_child(&o.path)
                    && self.commitments.get(&o.path) != Some(&z_commitment(ctx, &o.path, &o.z, &o.salt))
                {
                    return Err(Fault { culprit: Some(child), kind: FaultKind::BadOpening });
                }
            }
            openings.extend(opened);
        }
        self.commitments.clear();
        wire.broadcast(Message::HintCarry {
            header: ctx.header(&self.path),
            accept,
            openings: openings.clone(),
            hint: hint.map(<[u16]>::to_vec),
        });
        Ok(openings)
    }

    fn exclude(&mut self, path: &[u8]) {
        if !path.starts_with(&self.path) || path.len() <= self.path.len() {
            return;
        }
        let next = path[self.path.len()];
        if self.is_child(path) {
            self.excluded.insert(next);
        } else if let Some(m) = self.members.iter_mut().find(|m| m.index() == next) {
            m.exclude(path);
        }
    }

    fn probe(&mut self, n: u32) -> bool {
        self.suspended = None;
        let live = self.live();
        if live.is_empty() {
            return false;
        }
        let pick = live[n as usize % live.len()];
        if live.len() > self.gadget.t as usize {
            self.suspended = Some(pick);
            return true;
        }
        let deeper = n / live.len() as u32;
        self.members.iter_mut().find(|m| m.index() == pick).is_some_and(|m| m.probe(deeper))
    }

    fn reset(&mut self) {
        self.active.clear();
        self.commitments.clear();
        self.members.iter_mut().for_each(Party::reset);
    }
}

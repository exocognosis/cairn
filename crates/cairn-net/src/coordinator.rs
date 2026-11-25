//! The session coordinator: drives one signature across signer and root-engine nodes.
//!
//! The coordinator is the process that received the signing request (`cairn serve-kms`). It is
//! not trusted with secrets: it sees `Prepare`/`Ready`, the public per-signer check values, the
//! opened `c~`, verdicts, and for the accepted attempt `z` and the hint. Share material travels
//! signer to root engine only.
//!
//! One session:
//! 1. **Prepare** (commitment round): every live signer and root engine answers `Ready`. Peers
//!    that miss the wall-clock deadline are skipped and excluded.
//! 2. **Deal**: the nine active signers send additive sub-shares to the three active engines.
//! 3. **Collect**: engines publish `A a1 + a2` per sub-share; the coordinator checks each
//!    signer's three values against its public verification share (a wrong share names its
//!    signer) and derives the engines' verification shares.
//! 4. **Attempts**: `Mask` (challenge round) then `Finish` (masked response and hint/carry),
//!    repeated on Fiat-Shamir rejection with `attempt + 1`, i.e. `kappa + 5`.
//!
//! Any fault aborts the session, excludes the culprit and starts a new session with the same
//! `attempt`, so the result is still the deterministic FIPS 204 signature.

use crate::node::{ready_binding, Peers};
use crate::tls::TlsIdentity;
use crate::transport::{call, CallError, Link, Pool};
use crate::wire::{Body, Frame, NodeId, Outcome, NET_VERSION};
use futures_util::future::join_all;
use mpc_bridge::{hint_from_positions, PARTIES};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use threshold_mldsa::fips204::{self, vec_add, vec_zero, PolyVec, K, L, SIGNATURE_BYTES};
use threshold_mldsa::flatten::{sub_shares_consistent, to_flat, to_polys};
use threshold_mldsa::{Active, GroupPublic};

#[derive(Debug, Clone)]
pub struct NetPolicy {
    /// Wall-clock deadline for a control exchange (prepare, deal, collect, install).
    pub round_timeout: Duration,
    /// Wall-clock deadline for one MPC phase (`Mask`, `Finish`).
    pub mpc_timeout: Duration,
    /// Injected one-way latency on the coordinator's links.
    pub link_delay: Duration,
    pub max_rejections: u32,
    pub max_retries: u32,
    /// Forget exclusions every this many signatures (0: never).
    pub reinstate_every: u64,
    /// Record the kind of every frame the coordinator receives.
    pub record: bool,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            round_timeout: Duration::from_secs(2),
            mpc_timeout: Duration::from_secs(30),
            link_delay: Duration::ZERO,
            max_rejections: 512,
            max_retries: 16,
            reinstate_every: 16,
            record: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetFaultKind {
    /// No reply within the wall-clock deadline.
    Timeout,
    Unreachable,
    /// The node answered with something other than the expected reply.
    Refused(String),
    BadBinding,
    /// Sub-shares fail the signer's public verification share.
    BadShare,
    /// A signer could not reach a root engine, or an engine is missing a sub-share.
    Undelivered,
    /// An engine reported a different `c~` or verdict than the other two.
    Equivocation,
    /// The MPC backend named this engine's response as inconsistent.
    InconsistentResponse,
    /// The attempt failed and no single node can be named.
    Unattributed(String),
    /// A party's signing policy refused the message.
    Policy(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetFault {
    pub culprit: Option<NodeId>,
    pub kind: NetFaultKind,
}

#[derive(Debug, Default)]
pub struct NetReport {
    pub rejections: u32,
    pub retries: u32,
    pub faults: Vec<NetFault>,
    pub elapsed: Duration,
    /// Bytes exchanged between the coordinator and each node (both directions).
    pub coordinator_bytes: BTreeMap<NodeId, u64>,
    /// Bytes each active signer exchanged with the root engines (sub-shares).
    pub p2p_bytes: BTreeMap<NodeId, u64>,
    pub exchanges: u64,
    /// Kinds of frames the coordinator received (when `NetPolicy::record`).
    pub received_kinds: Vec<&'static str>,
    /// Final active signers and engines.
    pub signers: Vec<NodeId>,
    pub engines: Vec<NodeId>,
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("quorum lost ({0}); faults: {1:?}")]
    QuorumLost(&'static str, Vec<NetFault>),
    #[error("retries exhausted; faults: {0:?}")]
    Stalled(Vec<NetFault>),
    #[error("rejection limit reached")]
    RejectionLimit,
    #[error("refused by signing policy: {0}")]
    Policy(String),
}

pub struct Coordinator {
    group: Arc<GroupPublic>,
    peers: Peers,
    tls: Arc<TlsIdentity>,
    pool: Arc<Pool>,
    pub policy: NetPolicy,
    excluded: BTreeSet<NodeId>,
    signed: u64,
}

fn fault(culprit: NodeId, kind: NetFaultKind) -> NetFault {
    NetFault {
        culprit: Some(culprit),
        kind,
    }
}

/// The value at least two of three agree on, and who disagrees.
fn majority<T: PartialEq + Clone>(values: &[T]) -> Option<(T, Option<usize>)> {
    for i in 0..values.len() {
        let same: Vec<usize> = (0..values.len())
            .filter(|j| values[*j] == values[i])
            .collect();
        if same.len() * 2 > values.len() {
            return Some((
                values[i].clone(),
                (0..values.len()).find(|j| !same.contains(j)),
            ));
        }
    }
    None
}

impl Coordinator {
    pub fn new(
        group: Arc<GroupPublic>,
        peers: Peers,
        policy: NetPolicy,
        tls: Arc<TlsIdentity>,
    ) -> Self {
        Self {
            group,
            peers,
            tls,
            pool: Arc::default(),
            policy,
            excluded: BTreeSet::new(),
            signed: 0,
        }
    }

    pub fn group(&self) -> &Arc<GroupPublic> {
        &self.group
    }

    pub fn excluded(&self) -> &BTreeSet<NodeId> {
        &self.excluded
    }

    pub fn reinstate(&mut self) {
        self.excluded.clear();
    }

    async fn ask(
        &self,
        report: &std::sync::Mutex<&mut NetReport>,
        to: NodeId,
        session: [u8; 32],
        body: Body,
        timeout: Duration,
    ) -> Result<Body, NetFault> {
        let frame = Frame {
            version: NET_VERSION,
            from: NodeId::Coordinator,
            to,
            session,
            body,
        };
        let addr = self
            .peers
            .get(&to)
            .ok_or_else(|| fault(to, NetFaultKind::Unreachable))?;
        let link = Link {
            timeout,
            delay: self.policy.link_delay,
            tls: self.tls.clone(),
            pool: self.pool.clone(),
        };
        match call(addr, &link, &frame).await {
            Ok(x) => {
                let mut r = report.lock().expect("report");
                *r.coordinator_bytes.entry(to).or_default() += (x.sent + x.received) as u64;
                r.exchanges += 1;
                if self.policy.record {
                    r.received_kinds.push(x.reply.body.kind());
                }
                Ok(x.reply.body)
            }
            Err(CallError::Timeout) => Err(fault(to, NetFaultKind::Timeout)),
            Err(CallError::Unreachable(_)) => Err(fault(to, NetFaultKind::Unreachable)),
            Err(CallError::Protocol(e)) => Err(fault(to, NetFaultKind::Refused(e))),
        }
    }

    async fn ask_all(
        &self,
        report: &std::sync::Mutex<&mut NetReport>,
        targets: &[NodeId],
        session: [u8; 32],
        body: impl Fn(usize) -> Body,
        timeout: Duration,
    ) -> Vec<Result<Body, NetFault>> {
        join_all(
            targets
                .iter()
                .enumerate()
                .map(|(i, to)| self.ask(report, *to, session, body(i), timeout)),
        )
        .await
    }

    /// One session from `Prepare` to a signature. `Ok(None)` cannot happen; rejections loop
    /// inside. Faults come back as `Err` with the nodes to exclude.
    async fn session(
        &self,
        report: &mut NetReport,
        message: &[u8],
        attempt: &mut u32,
    ) -> Result<[u8; SIGNATURE_BYTES], SessionEnd> {
        let session: [u8; 32] = rand::random();
        let shape = &self.group.shape;
        let (root_g, leaf_g) = (shape[0], shape[1]);
        let rt = self.policy.round_timeout;
        let report = std::sync::Mutex::new(report);

        // 1. Prepare: who is there?
        let candidates: Vec<NodeId> = self
            .peers
            .keys()
            .filter(|id| !self.excluded.contains(id))
            .copied()
            .collect();
        let replies = self
            .ask_all(
                &report,
                &candidates,
                session,
                |_| Body::Prepare {
                    message: message.to_vec(),
                },
                rt,
            )
            .await;
        let mut faults = Vec::new();
        let mut ready = BTreeSet::new();
        for (id, reply) in candidates.iter().zip(replies) {
            match reply {
                Ok(Body::Ready { binding })
                    if binding == ready_binding(&session, *id, &self.group) =>
                {
                    ready.insert(*id);
                }
                Ok(Body::Ready { .. }) => faults.push(fault(*id, NetFaultKind::BadBinding)),
                Ok(other) => faults.push(fault(*id, NetFaultKind::Refused(other.kind().into()))),
                Err(f) => faults.push(f),
            }
        }
        // Silence here is absorbed: skip the node, keep going with the rest.
        let absorbed = faults;

        let mut leaves = Vec::new();
        for leaf in 1..=root_g.n {
            let members: Vec<u8> = (1..=leaf_g.n)
                .filter(|s| ready.contains(&NodeId::Signer { leaf, signer: *s }))
                .take(leaf_g.t as usize)
                .collect();
            if members.len() == leaf_g.t as usize && leaves.len() < root_g.t as usize {
                leaves.push((
                    leaf,
                    Active::Committee(members.into_iter().map(|s| (s, Active::Signer)).collect()),
                ));
            }
        }
        let roots: Vec<u8> = ready
            .iter()
            .filter_map(|id| {
                if let NodeId::Root(k) = id {
                    Some(*k)
                } else {
                    None
                }
            })
            .take(PARTIES)
            .collect();
        if leaves.len() < root_g.t as usize {
            return Err(SessionEnd::QuorumLost("leaf committees", absorbed));
        }
        if roots.len() < PARTIES {
            return Err(SessionEnd::QuorumLost("root engines", absorbed));
        }
        let active = Active::Committee(leaves);
        let weights = active.weights();
        let signers: Vec<NodeId> = weights
            .iter()
            .filter_map(|(p, _)| NodeId::from_path(p))
            .collect();
        let engines: Vec<NodeId> = roots.iter().map(|k| NodeId::Root(*k)).collect();
        let abort = |mut faults: Vec<NetFault>| {
            let mut all = absorbed.clone();
            all.append(&mut faults);
            SessionEnd::Faults(all, engines.clone(), session)
        };

        // 2. Deal: signers send sub-shares straight to the engines.
        let deal = |_| Body::Deal {
            active: active.clone(),
            roots: roots.clone(),
        };
        // A signer's deal includes three nested exchanges with the engines.
        let replies = self.ask_all(&report, &signers, session, deal, rt * 2).await;
        let mut faults = Vec::new();
        for (id, reply) in signers.iter().zip(replies) {
            match reply {
                Ok(Body::Dealt { p2p_bytes }) => {
                    *report
                        .lock()
                        .expect("report")
                        .p2p_bytes
                        .entry(*id)
                        .or_default() += p2p_bytes;
                }
                Ok(Body::DealFailed { root }) => {
                    faults.push(fault(NodeId::Root(root), NetFaultKind::Undelivered))
                }
                Ok(other) => faults.push(fault(*id, NetFaultKind::Refused(other.kind().into()))),
                Err(f) => faults.push(f),
            }
        }
        if !faults.is_empty() {
            return Err(abort(faults));
        }

        // 3. Collect and check.
        let replies = self
            .ask_all(
                &report,
                &engines,
                session,
                |_| Body::Collect {
                    active: active.clone(),
                },
                rt,
            )
            .await;
        let mut per_engine: Vec<BTreeMap<Vec<u8>, PolyVec>> = Vec::new();
        for (id, reply) in engines.iter().zip(replies) {
            match reply {
                Ok(Body::ShareCheck { values, missing }) if missing.is_empty() => {
                    per_engine.push(
                        values
                            .into_iter()
                            .filter(|(_, v)| v.len() == K * 256)
                            .map(|(p, v)| (p, to_polys(&v)))
                            .collect(),
                    );
                }
                Ok(Body::ShareCheck { missing, .. }) => {
                    let named = missing
                        .iter()
                        .filter_map(|p| NodeId::from_path(p))
                        .map(|s| fault(s, NetFaultKind::Undelivered));
                    faults.extend(named);
                }
                Ok(other) => faults.push(fault(*id, NetFaultKind::Refused(other.kind().into()))),
                Err(f) => faults.push(f),
            }
        }
        if !faults.is_empty() {
            return Err(abort(faults));
        }
        for (path, weight) in &weights {
            let parts: Option<Vec<PolyVec>> =
                per_engine.iter().map(|e| e.get(path).cloned()).collect();
            if !parts.is_some_and(|parts| sub_shares_consistent(&self.group, path, *weight, &parts))
            {
                if let Some(signer) = NodeId::from_path(path) {
                    faults.push(fault(signer, NetFaultKind::BadShare));
                }
            }
        }
        if !faults.is_empty() {
            return Err(abort(faults));
        }
        let verification: Vec<Vec<i32>> = per_engine
            .iter()
            .map(|e| to_flat(&e.values().fold(vec_zero(K), |acc, v| vec_add(&acc, v))))
            .collect();

        let install = |i: usize| Body::Install {
            slot: i as u8 + 1,
            verification: verification.clone(),
        };
        for (id, reply) in engines
            .iter()
            .zip(self.ask_all(&report, &engines, session, install, rt).await)
        {
            match reply {
                Ok(Body::Installed) => {}
                Ok(other) => faults.push(fault(*id, NetFaultKind::Refused(other.kind().into()))),
                Err(f) => faults.push(f),
            }
        }
        if !faults.is_empty() {
            return Err(abort(faults));
        }
        {
            let mut r = report.lock().expect("report");
            r.signers = signers.clone();
            r.engines = engines.clone();
        }

        // 4. Attempts.
        let mpc = self.policy.mpc_timeout;
        loop {
            let replies = self
                .ask_all(
                    &report,
                    &engines,
                    session,
                    |_| Body::Mask { attempt: *attempt },
                    mpc,
                )
                .await;
            let mut opened = Vec::new();
            for (id, reply) in engines.iter().zip(replies) {
                match reply {
                    Ok(Body::Challenge { c_tilde }) => opened.push(c_tilde),
                    Ok(Body::BackendFault { message, .. }) => {
                        return Err(abort(vec![NetFault {
                            culprit: None,
                            kind: NetFaultKind::Unattributed(message),
                        }]))
                    }
                    Ok(other) => {
                        faults.push(fault(*id, NetFaultKind::Refused(other.kind().into())))
                    }
                    Err(f) => faults.push(f),
                }
            }
            if !faults.is_empty() {
                return Err(abort(faults));
            }
            let c_tilde: [u8; 48] = match majority(&opened) {
                Some((value, None)) => value.try_into().map_err(|_| abort(vec![]))?,
                Some((_, Some(odd))) => {
                    return Err(abort(vec![fault(engines[odd], NetFaultKind::Equivocation)]))
                }
                None => {
                    return Err(abort(vec![NetFault {
                        culprit: None,
                        kind: NetFaultKind::Unattributed("c~ differs".into()),
                    }]))
                }
            };

            let replies = self
                .ask_all(&report, &engines, session, |_| Body::Finish, mpc)
                .await;
            let mut outcomes = Vec::new();
            for (id, reply) in engines.iter().zip(replies) {
                match reply {
                    Ok(Body::Verdict(outcome)) => outcomes.push(outcome),
                    Ok(Body::BackendFault {
                        blame: true, party, ..
                    }) if (1..=PARTIES as u8).contains(&party) => {
                        return Err(abort(vec![fault(
                            engines[party as usize - 1],
                            NetFaultKind::InconsistentResponse,
                        )]))
                    }
                    Ok(Body::BackendFault { message, .. }) => {
                        return Err(abort(vec![NetFault {
                            culprit: None,
                            kind: NetFaultKind::Unattributed(message),
                        }]))
                    }
                    Ok(other) => {
                        faults.push(fault(*id, NetFaultKind::Refused(other.kind().into())))
                    }
                    Err(f) => faults.push(f),
                }
            }
            if !faults.is_empty() {
                return Err(abort(faults));
            }
            let outcome = match majority(&outcomes) {
                Some((value, None)) => value,
                Some((_, Some(odd))) => {
                    return Err(abort(vec![fault(engines[odd], NetFaultKind::Equivocation)]))
                }
                None => {
                    return Err(abort(vec![NetFault {
                        culprit: None,
                        kind: NetFaultKind::Unattributed("verdicts differ".into()),
                    }]))
                }
            };
            match outcome {
                Outcome::Reject => {
                    report.lock().expect("report").rejections += 1;
                    *attempt += 1;
                    if *attempt > self.policy.max_rejections {
                        return Err(SessionEnd::RejectionLimit);
                    }
                }
                Outcome::Accept { hint, z } => {
                    let well_formed = z.len() == PARTIES && z.iter().all(|v| v.len() == L * 256);
                    let signature = hint_from_positions(&hint).filter(|_| well_formed).map(|h| {
                        let sum = z
                            .iter()
                            .fold(vec_zero(L), |acc, v| vec_add(&acc, &to_polys(v)));
                        fips204::pack_signature(&c_tilde, &sum, &h)
                    });
                    self.ask_all(&report, &engines, session, |_| Body::Abort, rt)
                        .await;
                    return match signature
                        .filter(|s| fips204::verify_standard(&self.group.pk, message, s))
                    {
                        Some(signature) => {
                            report.lock().expect("report").faults.extend(absorbed);
                            Ok(signature)
                        }
                        None => Err(SessionEnd::Faults(
                            vec![NetFault {
                                culprit: None,
                                kind: NetFaultKind::Unattributed("invalid signature".into()),
                            }],
                            vec![],
                            session,
                        )),
                    };
                }
            }
        }
    }

    /// Produce one standard ML-DSA-65 signature over `message` (empty context) with the cluster.
    pub async fn sign(
        &mut self,
        message: &[u8],
    ) -> Result<([u8; SIGNATURE_BYTES], NetReport), NetError> {
        let start = Instant::now();
        if self.policy.reinstate_every != 0 && self.signed % self.policy.reinstate_every == 0 {
            self.reinstate();
        }
        self.signed += 1;
        let mut report = NetReport::default();
        let mut attempt = 0u32;
        let mut probes = 0usize;
        loop {
            match self.session(&mut report, message, &mut attempt).await {
                Ok(signature) => {
                    report.elapsed = start.elapsed();
                    for f in &report.faults {
                        self.excluded.extend(f.culprit);
                    }
                    return Ok((signature, report));
                }
                Err(SessionEnd::RejectionLimit) => return Err(NetError::RejectionLimit),
                Err(SessionEnd::QuorumLost(what, mut faults)) => {
                    report.faults.append(&mut faults);
                    return Err(NetError::QuorumLost(what, report.faults));
                }
                Err(SessionEnd::Faults(faults, engines, session)) => {
                    // Tell the engines to erase the aborted session.
                    {
                        let guard = std::sync::Mutex::new(&mut report);
                        self.ask_all(
                            &guard,
                            &engines,
                            session,
                            |_| Body::Abort,
                            self.policy.round_timeout,
                        )
                        .await;
                    }
                    for f in &faults {
                        match f.culprit {
                            Some(id) => {
                                self.excluded.insert(id);
                            }
                            // Unattributed: rotate the engines out one at a time.
                            None => {
                                if let Some(id) = engines.get(probes % PARTIES.max(1)) {
                                    self.excluded.insert(*id);
                                }
                                probes += 1;
                            }
                        }
                    }
                    report.faults.extend(faults);
                    report.retries += 1;
                    if report.retries > self.policy.max_retries {
                        return Err(NetError::Stalled(report.faults));
                    }
                }
            }
        }
    }
}

enum SessionEnd {
    QuorumLost(&'static str, Vec<NetFault>),
    /// Faults, the engines to notify, and the session id.
    Faults(Vec<NetFault>, Vec<NodeId>, [u8; 32]),
    RejectionLimit,
}

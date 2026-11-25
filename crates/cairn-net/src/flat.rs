//! A flat committee running the three-round threshold protocol over the network.
//!
//! `T` of `N` parties, `N <= 6`, each a node (`party_k`) holding its replicated shares. There is
//! no MPC backend and no root engine. The coordinator relays the three rounds; everything it
//! carries is public. One protocol execution:
//!
//! 1. `M1`: each active party samples its masks and returns a commitment.
//! 2. `M2`: each party receives all commitments and reveals its `w` values.
//! 3. `M3`: each party receives all `w` values, checks them against the commitments it was
//!    given in round 2, and answers wherever its own rejection test passes.
//!
//! The coordinator combines the first repetition every party answered. An execution yields a
//! signature about half the time, so it repeats with a fresh session until one does.
//!
//! A party answers at most once per session, and erases its masks when it does: a mask that
//! answered two different challenges would leak its share. The coordinator can make an
//! execution fail (by relaying inconsistently) but cannot make a party reuse a mask.

use crate::coordinator::{NetError, NetFault, NetFaultKind, NetPolicy, NetReport};
use crate::node::{FaultMode, Peers, CHECKPOINT_DOMAIN};
use crate::tls::{ClusterTls, TlsIdentity};
use crate::transport::{call, serve, CallError, Handler, Link, Pool, Reply};
use crate::wire::{Body, Frame, NodeId, NET_VERSION};
use futures_util::future::join_all;
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204::{PolyVec, SIGNATURE_BYTES};
use threshold_mldsa::mithril::{self, GroupKey, PartyKey, Round1};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct PartySession {
    message: Vec<u8>,
    round1: Option<Round1>,
    own_commitment: [u8; 32],
    commitments: Option<BTreeMap<u8, [u8; 32]>>,
}

/// One member of a flat committee.
pub struct PartyNode {
    pub id: NodeId,
    pub key: Arc<GroupKey>,
    pub share: PartyKey,
    pub fault: FaultMode,
    sessions: Mutex<HashMap<[u8; 32], PartySession>>,
}

const MAX_SESSIONS: usize = 64;

fn refused(reason: &str) -> Body {
    Body::Refused {
        reason: reason.into(),
    }
}

impl PartyNode {
    pub fn new(id: NodeId, key: Arc<GroupKey>, share: PartyKey, fault: FaultMode) -> Self {
        Self {
            id,
            key,
            share,
            fault,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn respond(&self, session: [u8; 32], body: Body) -> Body {
        let mut sessions = self.sessions.lock().expect("party sessions");
        match body {
            Body::M1 { message } => {
                if !message.starts_with(CHECKPOINT_DOMAIN) {
                    return refused("not a checkpoint message");
                }
                if sessions.len() >= MAX_SESSIONS {
                    sessions.clear();
                }
                let (round1, commitment) = self.share.round1(&self.key, &mut OsRng);
                let state = PartySession {
                    message,
                    round1: Some(round1),
                    own_commitment: commitment,
                    commitments: None,
                };
                sessions.insert(session, state);
                Body::M1Commit { commitment }
            }
            Body::M2 { commitments } => {
                let Some(state) = sessions.get_mut(&session) else {
                    return refused("unknown session");
                };
                let map: BTreeMap<u8, [u8; 32]> = commitments.into_iter().collect();
                // Reveal only once, and only if our own commitment is among those relayed.
                if state.commitments.is_some()
                    || map.get(&self.share.index) != Some(&state.own_commitment)
                {
                    sessions.remove(&session);
                    return refused(
                        "commitment set is not consistent with this party's commitment",
                    );
                }
                let Some(round1) = &state.round1 else {
                    return refused("no masks for this session");
                };
                let w = round1.reveal().iter().map(mithril::w_to_wire).collect();
                state.commitments = Some(map);
                Body::M2Reveal { w }
            }
            Body::M3 { revealed } => {
                // Whatever happens, this session's masks are used up now.
                let Some(mut state) = sessions.remove(&session) else {
                    return refused("unknown session");
                };
                let (Some(round1), Some(commitments)) =
                    (state.round1.take(), state.commitments.take())
                else {
                    return refused("rounds out of order");
                };
                let mut map: BTreeMap<u8, Vec<PolyVec>> = BTreeMap::new();
                for (index, ws) in revealed {
                    let Some(ws) = ws
                        .iter()
                        .map(|w| mithril::w_from_wire(w))
                        .collect::<Option<Vec<_>>>()
                    else {
                        return refused("malformed w");
                    };
                    map.insert(index, ws);
                }
                if map.keys().ne(commitments.keys())
                    || map.values().any(|w| w.len() != self.key.params.reps)
                {
                    return refused("revealed set does not match the commitment set");
                }
                match self
                    .share
                    .round3(&self.key, round1, &state.message, &commitments, &map)
                {
                    Some(mut z) => {
                        if self.fault == FaultMode::BadResponse {
                            for r in z.iter_mut().flatten() {
                                r[0][0] = (r[0][0] + 1) % threshold_mldsa::fips204::Q;
                            }
                        }
                        Body::M3Response {
                            z: z.iter()
                                .map(|r| r.as_ref().map(mithril::z_to_wire))
                                .collect(),
                        }
                    }
                    None => refused("an opening does not match its commitment"),
                }
            }
            Body::Abort => {
                sessions.remove(&session);
                Body::Ack
            }
            _ => refused("unexpected request"),
        }
    }
}

impl Handler for PartyNode {
    fn handle(&self, request: Frame) -> Reply<'_> {
        Box::pin(async move {
            if self.fault == FaultMode::Stall {
                return None;
            }
            let body = if request.to != self.id || request.from != NodeId::Coordinator {
                refused("misaddressed frame")
            } else {
                self.respond(request.session, request.body)
            };
            Some(Frame {
                version: NET_VERSION,
                from: self.id,
                to: request.from,
                session: request.session,
                body,
            })
        })
    }
}

/// Drives signatures across a flat committee.
pub struct FlatCoordinator {
    key: Arc<GroupKey>,
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

impl FlatCoordinator {
    pub fn new(key: Arc<GroupKey>, peers: Peers, policy: NetPolicy, tls: Arc<TlsIdentity>) -> Self {
        Self {
            key,
            peers,
            tls,
            pool: Arc::default(),
            policy,
            excluded: BTreeSet::new(),
            signed: 0,
        }
    }

    pub fn key(&self) -> &Arc<GroupKey> {
        &self.key
    }

    pub fn excluded(&self) -> &BTreeSet<NodeId> {
        &self.excluded
    }

    async fn ask(
        &self,
        report: &Mutex<&mut NetReport>,
        to: NodeId,
        session: [u8; 32],
        body: Body,
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
            timeout: self.policy.round_timeout,
            delay: self.policy.link_delay,
            tls: self.tls.clone(),
            pool: self.pool.clone(),
        };
        match call(addr, &link, &frame).await {
            Ok(x) => {
                let mut r = report.lock().expect("report");
                *r.coordinator_bytes.entry(to).or_default() += (x.sent + x.received) as u64;
                r.exchanges += 1;
                match x.reply.body {
                    Body::Refused { reason } => Err(fault(to, NetFaultKind::Refused(reason))),
                    body => Ok(body),
                }
            }
            Err(CallError::Timeout) => Err(fault(to, NetFaultKind::Timeout)),
            Err(CallError::Unreachable(_)) => Err(fault(to, NetFaultKind::Unreachable)),
            Err(CallError::Protocol(e)) => Err(fault(to, NetFaultKind::Refused(e))),
        }
    }

    /// One round to every active party. Collects replies through `take`, or the faults.
    async fn round<T>(
        &self,
        report: &Mutex<&mut NetReport>,
        active: &[u8],
        session: [u8; 32],
        body: &Body,
        take: impl Fn(Body) -> Option<T>,
    ) -> Result<BTreeMap<u8, T>, Vec<NetFault>> {
        let replies = join_all(
            active
                .iter()
                .map(|i| self.ask(report, NodeId::Party(i + 1), session, body.clone())),
        )
        .await;
        let (mut out, mut faults) = (BTreeMap::new(), Vec::new());
        for (index, reply) in active.iter().zip(replies) {
            match reply.map(&take) {
                Ok(Some(value)) => {
                    out.insert(*index, value);
                }
                Ok(None) => faults.push(fault(
                    NodeId::Party(index + 1),
                    NetFaultKind::Refused("unexpected reply".into()),
                )),
                Err(f) => faults.push(f),
            }
        }
        if faults.is_empty() {
            Ok(out)
        } else {
            Err(faults)
        }
    }

    /// One protocol execution. `Ok(None)` means it completed but no repetition yielded a
    /// signature (the expected outcome about half the time).
    async fn execute(
        &self,
        report: &Mutex<&mut NetReport>,
        active: &[u8],
        message: &[u8],
    ) -> Result<Option<[u8; SIGNATURE_BYTES]>, Vec<NetFault>> {
        let session: [u8; 32] = rand::random();
        let m1 = Body::M1 {
            message: message.to_vec(),
        };
        let commitments = self
            .round(report, active, session, &m1, |b| {
                if let Body::M1Commit { commitment } = b {
                    Some(commitment)
                } else {
                    None
                }
            })
            .await?;
        let m2 = Body::M2 {
            commitments: commitments.iter().map(|(i, c)| (*i, *c)).collect(),
        };
        let wire_w = self
            .round(report, active, session, &m2, |b| {
                if let Body::M2Reveal { w } = b {
                    Some(w)
                } else {
                    None
                }
            })
            .await?;
        let m3 = Body::M3 {
            revealed: wire_w.iter().map(|(i, w)| (*i, w.clone())).collect(),
        };
        let wire_z = self
            .round(report, active, session, &m3, |b| {
                if let Body::M3Response { z } = b {
                    Some(z)
                } else {
                    None
                }
            })
            .await?;

        let malformed = |i: &u8| {
            vec![fault(
                NodeId::Party(i + 1),
                NetFaultKind::Refused("malformed value".into()),
            )]
        };
        let mut revealed = BTreeMap::new();
        for (i, ws) in &wire_w {
            let ws: Option<Vec<PolyVec>> = ws.iter().map(|w| mithril::w_from_wire(w)).collect();
            revealed.insert(
                *i,
                ws.filter(|w| w.len() == self.key.params.reps)
                    .ok_or_else(|| malformed(i))?,
            );
        }
        let mut responses = BTreeMap::new();
        for (i, zs) in &wire_z {
            let zs: Option<Vec<Option<PolyVec>>> = zs
                .iter()
                .map(|z| {
                    z.as_ref()
                        .map(|z| mithril::z_from_wire(z))
                        .map_or(Some(None), |z| z.map(Some))
                })
                .collect();
            responses.insert(
                *i,
                zs.filter(|z| z.len() == self.key.params.reps)
                    .ok_or_else(|| malformed(i))?,
            );
        }
        // A repetition every party answered but that does not verify means someone sent a wrong
        // response. The protocol cannot say who; report it unattributed.
        let complete =
            (0..self.key.params.reps).any(|rep| responses.values().all(|z| z[rep].is_some()));
        let signature = mithril::combine(&self.key, message, &revealed, &responses);
        if signature.is_none() && complete && self.suspicious(&revealed, &responses, message) {
            return Err(vec![NetFault {
                culprit: None,
                kind: NetFaultKind::Unattributed("responses do not verify".into()),
            }]);
        }
        Ok(signature)
    }

    /// Did a fully answered repetition fail for a reason other than the public bounds? The
    /// bounds (norm of z, delta, hint weight) fail honestly; an equation mismatch does not.
    fn suspicious(
        &self,
        revealed: &BTreeMap<u8, Vec<PolyVec>>,
        responses: &BTreeMap<u8, Vec<Option<PolyVec>>>,
        message: &[u8],
    ) -> bool {
        mithril::equation_fails(&self.key, message, revealed, responses)
    }

    /// Produce one signature that any FIPS 204 verifier accepts, with the committee.
    pub async fn sign(
        &mut self,
        message: &[u8],
    ) -> Result<([u8; SIGNATURE_BYTES], NetReport), NetError> {
        let start = Instant::now();
        if self.policy.reinstate_every != 0 && self.signed % self.policy.reinstate_every == 0 {
            self.excluded.clear();
        }
        self.signed += 1;
        let mut report = NetReport::default();
        let params = self.key.params;
        let mut rotate = 0usize;
        loop {
            let live: Vec<u8> = (0..params.n as u8)
                .filter(|i| {
                    self.peers.contains_key(&NodeId::Party(i + 1))
                        && !self.excluded.contains(&NodeId::Party(i + 1))
                })
                .collect();
            if live.len() < params.t {
                return Err(NetError::QuorumLost("committee parties", report.faults));
            }
            // After an unattributed failure, shift which T of the live parties sign.
            let mut active: Vec<u8> = (0..params.t)
                .map(|k| live[(k + rotate) % live.len()])
                .collect();
            active.sort();
            let outcome = {
                let guard = Mutex::new(&mut report);
                self.execute(&guard, &active, message).await
            };
            match outcome {
                Ok(Some(signature)) => {
                    report.elapsed = start.elapsed();
                    report.signers = active.iter().map(|i| NodeId::Party(i + 1)).collect();
                    return Ok((signature, report));
                }
                // Completed without a signature: the protocol's own retry, not a fault.
                Ok(None) => {
                    report.rejections += 1;
                    if report.rejections > self.policy.max_rejections {
                        return Err(NetError::RejectionLimit);
                    }
                }
                Err(faults) => {
                    for f in &faults {
                        match f.culprit {
                            Some(id) => {
                                self.excluded.insert(id);
                            }
                            None => rotate += 1,
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

/// Address book for a flat committee on one host: consecutive ports.
pub fn flat_peers(n: usize, host: &str, base_port: u16) -> Peers {
    (1..=n as u8)
        .map(|k| {
            (
                NodeId::Party(k),
                format!("{host}:{}", base_port + k as u16 - 1),
            )
        })
        .collect()
}

pub fn party_share_file(dir: &Path, id: NodeId) -> PathBuf {
    dir.join(format!("{id}.share"))
}

/// Write `committee.bin`, one share file per party (mode 0600) and `tls/` under `dir`.
pub fn write_flat_keys(dir: &Path, key: &GroupKey, parties: &[PartyKey]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("committee.bin"), key.to_bytes())?;
    let mut ids: Vec<NodeId> = parties.iter().map(|p| NodeId::Party(p.index + 1)).collect();
    for party in parties {
        let path = party_share_file(dir, NodeId::Party(party.index + 1));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut f, &party.to_bytes())?;
    }
    ids.push(NodeId::Coordinator);
    ClusterTls::generate(&ids)?.write(&dir.join("tls"))
}

pub fn read_committee(path: &Path) -> std::io::Result<GroupKey> {
    GroupKey::from_bytes(&std::fs::read(path)?)
        .ok_or_else(|| std::io::Error::other("malformed committee file"))
}

pub fn read_party_share(path: &Path) -> std::io::Result<PartyKey> {
    PartyKey::from_bytes(&std::fs::read(path)?)
        .ok_or_else(|| std::io::Error::other("malformed party share file"))
}

pub async fn run_party(
    listener: TcpListener,
    node: PartyNode,
    delay: Duration,
    tls: Arc<TlsIdentity>,
) {
    serve(listener, Arc::new(node), delay, tls).await
}

/// A flat committee inside this process on real loopback TLS sockets, for tests.
pub struct LocalCommittee {
    pub key: Arc<GroupKey>,
    pub peers: Peers,
    tls: ClusterTls,
    tasks: Vec<JoinHandle<()>>,
}

impl LocalCommittee {
    pub async fn start(
        t: usize,
        n: usize,
        faults: &[(NodeId, FaultMode)],
        delay: Duration,
    ) -> std::io::Result<Self> {
        let (key, parties) = mithril::keygen(t, n, &mut OsRng)
            .ok_or_else(|| std::io::Error::other("no parameters"))?;
        let key = Arc::new(key);
        let mut ids: Vec<NodeId> = (1..=n as u8).map(NodeId::Party).collect();
        ids.push(NodeId::Coordinator);
        let tls = ClusterTls::generate(&ids)?;
        let (mut peers, mut tasks) = (Peers::new(), Vec::new());
        for party in parties {
            let id = NodeId::Party(party.index + 1);
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            peers.insert(id, listener.local_addr()?.to_string());
            let fault = faults
                .iter()
                .find(|(f, _)| *f == id)
                .map(|(_, m)| *m)
                .unwrap_or_default();
            let node = PartyNode::new(id, key.clone(), party, fault);
            tasks.push(tokio::spawn(run_party(
                listener,
                node,
                delay,
                Arc::new(tls.identity(id)?),
            )));
        }
        Ok(Self {
            key,
            peers,
            tls,
            tasks,
        })
    }

    pub fn identity(&self, id: NodeId) -> Arc<TlsIdentity> {
        Arc::new(self.tls.identity(id).expect("committee certificate"))
    }
}

impl Drop for LocalCommittee {
    fn drop(&mut self) {
        self.tasks.iter().for_each(JoinHandle::abort);
    }
}

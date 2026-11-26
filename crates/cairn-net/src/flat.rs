//! A flat committee running the three-round threshold protocol over the network.
//!
//! `T` of `N` parties, `N <= 6`, each a node (`party_k`) holding its replicated shares. There is
//! no MPC backend and no root engine. The coordinator relays the three rounds; everything it
//! carries is public. One protocol execution:
//!
//! 1. `Presign`: each party samples its masks and returns a commitment. This does not depend
//!    on the message or on who signs, so it runs ahead of time: the coordinator fetches the
//!    next execution's commitments while the current one is in round 3.
//! 2. `M2`: each party receives the message and all commitments and reveals its `w` values.
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
use crate::node::{FaultMode, Peers};
use crate::tls::{ClusterTls, TlsIdentity};
use crate::transport::{call, serve, CallError, Handler, Link, Pool, Reply};
use crate::wire::{Attestation, Body, Frame, NodeId, NET_VERSION};
use cairn_policy::{PolicyEngine, SignContext};
use futures_util::future::join_all;
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use threshold_mldsa::fips204::{PolyVec, SIGNATURE_BYTES};
use threshold_mldsa::mithril::{self, GroupKey, PartyKey, Round1};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct PartySession {
    message: Vec<u8>,
    round1: Round1,
    commitments: BTreeMap<u8, [u8; 32]>,
    opened: Instant,
}

/// Masks sampled ahead of time: id, state, commitment, and when they were sampled.
type Presigned = ([u8; 32], Round1, [u8; 32], Instant);

/// Default lifetime of unused masks and of a session waiting for round 3. Masks exist only in
/// memory; keeping them short-lived bounds what a restored snapshot of a party could replay.
pub const MASK_TTL: Duration = Duration::from_secs(120);

/// How many unused precomputed mask sets a party keeps; the oldest are dropped beyond this.
const MAX_PRESIGNS: usize = 16;

/// One member of a flat committee.
pub struct PartyNode {
    pub id: NodeId,
    pub key: Arc<GroupKey>,
    pub share: PartyKey,
    pub fault: FaultMode,
    sessions: Mutex<HashMap<[u8; 32], PartySession>>,
    presigns: Mutex<std::collections::VecDeque<Presigned>>,
    policy: Box<dyn PolicyEngine>,
    /// Unused masks and half-finished sessions older than this are erased.
    pub mask_ttl: Duration,
    pub stats: Arc<PartyStats>,
    /// Signs the commitment set this party was shown and checks the other parties' signatures.
    tls: Arc<TlsIdentity>,
}

/// What a party signs in round 2: this session, this message, exactly these commitments.
/// Every party answers round 3 only if every other active party signed the same statement,
/// so a coordinator cannot show different parties different commitment sets.
pub fn commitment_statement(
    session: &[u8; 32],
    message: &[u8],
    commitments: &BTreeMap<u8, [u8; 32]>,
) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut out = b"commitment-set\0".to_vec();
    out.extend_from_slice(session);
    out.extend_from_slice(&Sha3_256::digest(message));
    out.push(commitments.len() as u8);
    for (index, commitment) in commitments {
        out.push(*index);
        out.extend_from_slice(commitment);
    }
    out
}

/// What a party has done since it started, for its operator's monitoring. Counts only:
/// nothing here depends on a share or a mask.
pub struct PartyStats {
    started: Instant,
    presigns: AtomicU64,
    sessions: AtomicU64,
    responses: AtomicU64,
    policy_refused: AtomicU64,
    refused: AtomicU64,
    last_response: AtomicU64,
}

impl Default for PartyStats {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            presigns: AtomicU64::new(0),
            sessions: AtomicU64::new(0),
            responses: AtomicU64::new(0),
            policy_refused: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            last_response: AtomicU64::new(0),
        }
    }
}

impl PartyStats {
    fn record(&self, reply: &Body) {
        let counter = match reply {
            Body::PresignCommit { .. } => &self.presigns,
            Body::M2Reveal { .. } => &self.sessions,
            Body::M3Response { .. } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                self.last_response.store(now, Ordering::Relaxed);
                &self.responses
            }
            Body::PolicyRefused { .. } => &self.policy_refused,
            Body::Refused { .. } => &self.refused,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text format.
    pub fn render(&self) -> String {
        let rows: [(&str, &str, &str, u64); 7] = [
            (
                "cairn_party_presigns_total",
                "counter",
                "Masks sampled ahead of time.",
                self.presigns.load(Ordering::Relaxed),
            ),
            (
                "cairn_party_sessions_total",
                "counter",
                "Signing sessions this party's policy authorised and joined.",
                self.sessions.load(Ordering::Relaxed),
            ),
            (
                "cairn_party_responses_total",
                "counter",
                "Signature responses released.",
                self.responses.load(Ordering::Relaxed),
            ),
            (
                "cairn_party_policy_refused_total",
                "counter",
                "Messages this party's signing policy refused.",
                self.policy_refused.load(Ordering::Relaxed),
            ),
            (
                "cairn_party_refused_total",
                "counter",
                "Requests refused as malformed, inconsistent or out of order.",
                self.refused.load(Ordering::Relaxed),
            ),
            (
                "cairn_party_last_response_timestamp_seconds",
                "gauge",
                "Unix time of the last response released; 0 if none.",
                self.last_response.load(Ordering::Relaxed),
            ),
            (
                "cairn_party_uptime_seconds",
                "gauge",
                "Seconds since this party started.",
                self.started.elapsed().as_secs(),
            ),
        ];
        rows.iter()
            .map(|(name, kind, help, value)| {
                format!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n")
            })
            .collect()
    }
}

const MAX_SESSIONS: usize = 64;

fn refused(reason: &str) -> Body {
    Body::Refused {
        reason: reason.into(),
    }
}

impl PartyNode {
    pub fn new(
        id: NodeId,
        key: Arc<GroupKey>,
        share: PartyKey,
        fault: FaultMode,
        policy: impl PolicyEngine,
        tls: Arc<TlsIdentity>,
    ) -> Self {
        Self {
            id,
            key,
            share,
            fault,
            sessions: Mutex::new(HashMap::new()),
            presigns: Mutex::default(),
            policy: Box::new(policy),
            mask_ttl: MASK_TTL,
            stats: Arc::default(),
            tls,
        }
    }

    fn respond(&self, session: [u8; 32], body: Body) -> Body {
        let mut sessions = self.sessions.lock().expect("party sessions");
        // Erase anything that has waited too long, before looking at the request.
        let ttl = self.mask_ttl;
        sessions.retain(|_, state| state.opened.elapsed() < ttl);
        self.presigns
            .lock()
            .expect("presigns")
            .retain(|(_, _, _, sampled)| sampled.elapsed() < ttl);
        match body {
            Body::Presign => {
                // Round 1, offline: independent of the message and of who will sign.
                let (round1, commitment) = self.share.round1(&self.key, &mut OsRng);
                let id: [u8; 32] = rand::random();
                let mut presigns = self.presigns.lock().expect("presigns");
                if presigns.len() >= MAX_PRESIGNS {
                    presigns.pop_front();
                }
                presigns.push_back((id, round1, commitment, Instant::now()));
                Body::PresignCommit { id, commitment }
            }
            Body::M2 {
                message,
                presign,
                commitments,
            } => {
                let signers: Vec<u8> = commitments.iter().map(|(index, _)| *index).collect();
                let ctx = SignContext {
                    session: &session,
                    party: self.share.index,
                    signers: &signers,
                };
                if let Err(refused) = self.policy.authorize_sign(&ctx, &message) {
                    return Body::PolicyRefused {
                        reason: refused.to_string(),
                    };
                }
                // Take the masks out of the pool: they can serve this one session only.
                let taken = {
                    let mut presigns = self.presigns.lock().expect("presigns");
                    presigns
                        .iter()
                        .position(|(id, _, _, _)| *id == presign)
                        .and_then(|pos| presigns.remove(pos))
                };
                let Some((_, round1, own, _)) = taken else {
                    return refused("unknown or used presign");
                };
                let map: BTreeMap<u8, [u8; 32]> = commitments.into_iter().collect();
                if sessions.contains_key(&session) || map.get(&self.share.index) != Some(&own) {
                    sessions.remove(&session);
                    return refused(
                        "commitment set is not consistent with this party's commitment",
                    );
                }
                if sessions.len() >= MAX_SESSIONS {
                    sessions.clear();
                }
                // Sign the set we were shown before revealing anything.
                let statement = commitment_statement(&session, &message, &map);
                let Ok((cert, signature)) = self.tls.attest(&statement) else {
                    return refused("cannot sign the commitment set");
                };
                let attestation = Attestation { cert, signature };
                let w = round1.reveal().iter().map(mithril::w_to_wire).collect();
                sessions.insert(
                    session,
                    PartySession {
                        message,
                        round1,
                        commitments: map,
                        opened: Instant::now(),
                    },
                );
                Body::M2Reveal { w, attestation }
            }
            Body::M3 {
                revealed,
                attestations,
            } => {
                // Whatever happens, this session's masks are used up now.
                let Some(PartySession {
                    message,
                    round1,
                    commitments,
                    ..
                }) = sessions.remove(&session)
                else {
                    return refused("unknown session");
                };
                // Every other active party must have signed the very set we signed: same
                // session, same message, same commitments. Checked against our own pin table.
                let statement = commitment_statement(&session, &message, &commitments);
                for index in commitments.keys().filter(|i| **i != self.share.index) {
                    let signed = attestations.iter().any(|(from, a)| {
                        from == index
                            && self.tls.attested_by(
                                NodeId::Party(index + 1),
                                &a.cert,
                                &statement,
                                &a.signature,
                            )
                    });
                    if !signed {
                        return refused("another party did not sign this commitment set");
                    }
                }
                // Our own openings come from our own state, never from the coordinator.
                let mut map: BTreeMap<u8, Vec<PolyVec>> = BTreeMap::new();
                map.insert(self.share.index, round1.reveal());
                for (index, ws) in revealed {
                    if index == self.share.index {
                        continue;
                    }
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
                    .round3(&self.key, round1, &message, &commitments, &map)
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
            self.stats.record(&body);
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

/// Per party: (presign id, commitment) pairs fetched ahead of time.
type CommitmentPool = BTreeMap<u8, std::collections::VecDeque<([u8; 32], [u8; 32], Instant)>>;

/// The coordinator stops using a prefetched commitment well before the party erases its masks.
const PRESIGN_MAX_AGE: Duration = Duration::from_secs(60);

/// Drives signatures across a flat committee.
pub struct FlatCoordinator {
    key: Arc<GroupKey>,
    peers: Peers,
    tls: Arc<TlsIdentity>,
    pool: Arc<Pool>,
    pub policy: NetPolicy,
    excluded: BTreeSet<NodeId>,
    signed: u64,
    /// Commitments fetched ahead of time, per party: (presign id, commitment).
    presigns: Mutex<CommitmentPool>,
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
            presigns: Mutex::default(),
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
                    Body::PolicyRefused { reason } => Err(fault(to, NetFaultKind::Policy(reason))),
                    body => Ok(body),
                }
            }
            Err(CallError::Timeout) => Err(fault(to, NetFaultKind::Timeout)),
            Err(CallError::Unreachable(_)) => Err(fault(to, NetFaultKind::Unreachable)),
            Err(CallError::Protocol(e)) => Err(fault(to, NetFaultKind::Refused(e))),
        }
    }

    /// One round with the same body for every active party.
    async fn round<T>(
        &self,
        report: &Mutex<&mut NetReport>,
        active: &[u8],
        session: [u8; 32],
        body: &Body,
        take: impl Fn(Body) -> Option<T>,
    ) -> Result<BTreeMap<u8, T>, Vec<NetFault>> {
        self.round_with(report, active, session, |_| body.clone(), take)
            .await
    }

    /// One round to every active party. Collects replies through `take`, or the faults.
    async fn round_with<T>(
        &self,
        report: &Mutex<&mut NetReport>,
        active: &[u8],
        session: [u8; 32],
        body: impl Fn(u8) -> Body,
        take: impl Fn(Body) -> Option<T>,
    ) -> Result<BTreeMap<u8, T>, Vec<NetFault>> {
        let replies = join_all(
            active
                .iter()
                .map(|i| self.ask(report, NodeId::Party(i + 1), session, body(*i))),
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

    /// Round 1 for `parties`: ask each for a fresh mask commitment and remember it.
    async fn fetch_presigns(
        &self,
        report: &Mutex<&mut NetReport>,
        parties: &[u8],
    ) -> Result<(), Vec<NetFault>> {
        let got = self
            .round(report, parties, rand::random(), &Body::Presign, |b| {
                if let Body::PresignCommit { id, commitment } = b {
                    Some((id, commitment))
                } else {
                    None
                }
            })
            .await?;
        let mut pool = self.presigns.lock().expect("presigns");
        for (party, presign) in got {
            pool.entry(party)
                .or_default()
                .push_back((presign.0, presign.1, Instant::now()));
        }
        Ok(())
    }

    /// Fetch mask commitments for the parties that would sign next, so that the next request
    /// starts at round 2. Failures are left for the signing path to report.
    pub async fn warm(&mut self) {
        let params = self.key.params;
        let active: Vec<u8> = (0..params.n as u8)
            .filter(|i| {
                self.peers.contains_key(&NodeId::Party(i + 1))
                    && !self.excluded.contains(&NodeId::Party(i + 1))
            })
            .take(params.t)
            .collect();
        let mut scratch = NetReport::default();
        let guard = Mutex::new(&mut scratch);
        for _ in 0..self.policy.parallel_attempts.max(1) {
            let _ = self.fetch_presigns(&guard, &active).await;
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
        // Round 1 normally happened ahead of time; fetch for anyone we have nothing from.
        // Executions may run side by side, so take one presign per party under a single lock
        // and fetch again if another execution got there first.
        let mut fetches = 0;
        let mine: BTreeMap<u8, ([u8; 32], [u8; 32])> = loop {
            let missing: Vec<u8> = {
                let mut pool = self.presigns.lock().expect("presigns");
                pool.values_mut()
                    .for_each(|q| q.retain(|(_, _, fetched)| fetched.elapsed() < PRESIGN_MAX_AGE));
                let missing: Vec<u8> = active
                    .iter()
                    .copied()
                    .filter(|i| !pool.get(i).is_some_and(|q| !q.is_empty()))
                    .collect();
                if missing.is_empty() {
                    break active
                        .iter()
                        .filter_map(|i| {
                            pool.get_mut(i)?.pop_front().map(|(id, c, _)| (*i, (id, c)))
                        })
                        .collect();
                }
                missing
            };
            fetches += 1;
            if fetches > 4 {
                return Err(vec![NetFault {
                    culprit: None,
                    kind: NetFaultKind::Unattributed("missing presign".into()),
                }]);
            }
            self.fetch_presigns(report, &missing).await?;
        };
        let commitments: Vec<(u8, [u8; 32])> = mine.iter().map(|(i, (_, c))| (*i, *c)).collect();
        let round2 = self
            .round_with(
                report,
                active,
                session,
                |to| Body::M2 {
                    message: message.to_vec(),
                    presign: mine[&to].0,
                    commitments: commitments.clone(),
                },
                |b| {
                    if let Body::M2Reveal { w, attestation } = b {
                        Some((w, attestation))
                    } else {
                        None
                    }
                },
            )
            .await?;
        // A party whose signature over the set does not verify would make every honest party
        // refuse round 3; name it here instead.
        let statement =
            commitment_statement(&session, message, &commitments.iter().copied().collect());
        if let Some((i, _)) = round2.iter().find(|(i, (_, a))| {
            !self
                .tls
                .attested_by(NodeId::Party(**i + 1), &a.cert, &statement, &a.signature)
        }) {
            return Err(vec![fault(
                NodeId::Party(i + 1),
                NetFaultKind::Refused("commitment-set signature does not verify".into()),
            )]);
        }
        let attestations: Vec<(u8, Attestation)> =
            round2.iter().map(|(i, (_, a))| (*i, a.clone())).collect();
        let wire_w: BTreeMap<u8, Vec<Vec<u8>>> =
            round2.into_iter().map(|(i, (w, _))| (i, w)).collect();
        // Round 3, and in parallel round 1 of the next execution. Each party gets the others'
        // openings; it already holds its own.
        let (wire_z, _prefetched) = futures_util::future::join(
            self.round_with(
                report,
                active,
                session,
                |to| Body::M3 {
                    revealed: wire_w
                        .iter()
                        .filter(|(i, _)| **i != to)
                        .map(|(i, w)| (*i, w.clone()))
                        .collect(),
                    attestations: attestations
                        .iter()
                        .filter(|(i, _)| *i != to)
                        .cloned()
                        .collect(),
                },
                |b| {
                    if let Body::M3Response { z } = b {
                        Some(z)
                    } else {
                        None
                    }
                },
            ),
            self.fetch_presigns(report, active),
        )
        .await;
        let wire_z = wire_z?;

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
            // Name the sender if the key carries per-subset public keys; otherwise rotate.
            return Err(
                match mithril::blame(&self.key, message, &revealed, &responses) {
                    Some(guilty) if !guilty.is_empty() => guilty
                        .into_iter()
                        .map(|i| fault(NodeId::Party(i + 1), NetFaultKind::InconsistentResponse))
                        .collect(),
                    _ => vec![NetFault {
                        culprit: None,
                        kind: NetFaultKind::Unattributed("responses do not verify".into()),
                    }],
                },
            );
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
            // Run the executions side by side and stop at the first signature. The ones still
            // in flight are dropped; the parties erase their half-finished sessions.
            let outcomes = {
                use futures_util::stream::{FuturesUnordered, StreamExt};
                let guard = Mutex::new(&mut report);
                let mut running: FuturesUnordered<_> = (0..self.policy.parallel_attempts.max(1))
                    .map(|_| self.execute(&guard, &active, message))
                    .collect();
                let mut outcomes = Vec::new();
                while let Some(outcome) = running.next().await {
                    let done = matches!(outcome, Ok(Some(_)));
                    outcomes.push(outcome);
                    if done {
                        break;
                    }
                }
                outcomes
            };
            let mut signature = None;
            let mut faulted = false;
            for outcome in outcomes {
                match outcome {
                    Ok(Some(found)) => signature = Some(found),
                    // Completed without a signature: the protocol's own retry, not a fault.
                    Ok(None) => report.rejections += 1,
                    Err(faults) => {
                        // A policy refusal is the parties doing their job: report it, exclude
                        // nobody.
                        if let Some(reason) = faults.iter().find_map(|f| match &f.kind {
                            NetFaultKind::Policy(reason) => Some(reason.clone()),
                            _ => None,
                        }) {
                            return Err(NetError::Policy(reason));
                        }
                        for f in &faults {
                            match f.culprit {
                                Some(id) => {
                                    self.excluded.insert(id);
                                }
                                None if !faulted => rotate += 1,
                                None => {}
                            }
                        }
                        report.faults.extend(faults);
                        faulted = true;
                    }
                }
            }
            if let Some(signature) = signature {
                report.elapsed = start.elapsed();
                report.signers = active.iter().map(|i| NodeId::Party(i + 1)).collect();
                return Ok((signature, report));
            }
            if report.rejections > self.policy.max_rejections {
                return Err(NetError::RejectionLimit);
            }
            if faulted {
                report.retries += 1;
                if report.retries > self.policy.max_retries {
                    return Err(NetError::Stalled(report.faults));
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

/// Write one party's results of a key generation: `committee.bin` and its own share file.
pub fn write_party_files(dir: &Path, key: &GroupKey, share: &PartyKey) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("committee.bin"), key.to_bytes())?;
    let path = party_share_file(dir, NodeId::Party(share.index + 1));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut f, &share.to_bytes())
}

pub fn read_committee(path: &Path) -> std::io::Result<GroupKey> {
    GroupKey::from_bytes(&std::fs::read(path)?)
        .ok_or_else(|| std::io::Error::other("malformed committee file"))
}

pub fn read_party_share(path: &Path) -> std::io::Result<PartyKey> {
    PartyKey::from_bytes(&std::fs::read(path)?)
        .ok_or_else(|| std::io::Error::other("malformed party share file"))
}

pub async fn run_party(listener: TcpListener, node: PartyNode, delay: Duration) {
    let tls = node.tls.clone();
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
        Self::start_with(t, n, faults, delay, MASK_TTL).await
    }

    /// As [`start`](Self::start), with a chosen lifetime for unused masks.
    pub async fn start_with(
        t: usize,
        n: usize,
        faults: &[(NodeId, FaultMode)],
        delay: Duration,
        mask_ttl: Duration,
    ) -> std::io::Result<Self> {
        Self::start_policy(t, n, faults, delay, mask_ttl, |pk| {
            Box::new(cairn_policy::PosCheckpointPolicy::from(
                cairn_policy::pos::Policy::ephemeral(pk),
            ))
        })
        .await
    }

    /// As [`start_with`](Self::start_with), each party running the policy `policy` builds for
    /// the committee's public key.
    pub async fn start_policy(
        t: usize,
        n: usize,
        faults: &[(NodeId, FaultMode)],
        delay: Duration,
        mask_ttl: Duration,
        policy: impl Fn(&[u8]) -> Box<dyn PolicyEngine>,
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
            let mut node = PartyNode::new(
                id,
                key.clone(),
                party,
                fault,
                policy(&key.pk),
                Arc::new(tls.identity(id)?),
            );
            node.mask_ttl = mask_ttl;
            tasks.push(tokio::spawn(run_party(listener, node, delay)));
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

//! Signer and root-engine nodes.
//!
//! A **signer** holds one nested Shamir share. Per session it answers `Prepare`, and on `Deal`
//! flattens its share for the announced active set and sends one additive sub-share to each
//! root engine, directly (the coordinator never carries share material).
//!
//! A **root engine** collects sub-shares, sums them into its additive share of the key, and
//! plays one party of the three-party MPC backend through the IPC bridge. Between the two MPC
//! phases it does the linear step `z_k = y_k + c s1_k`, `r_k = A y_k - c s2_k` on its own share.

use crate::transport::{call, Handler, Link, Reply};
use crate::wire::{Body, Frame, NodeId, Outcome, NET_VERSION};
use futures_util::future::join_all;
use mpc_bridge::ipc::{FAULT_BLAME, PARTIES};
use mpc_bridge::{MaskRequest, PartyClient, Request, ResponseRequest};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use threshold_mldsa::fips204::{self, PolyVec, C_TILDE_BYTES, Q};
use threshold_mldsa::flatten::{to_flat, to_polys};
use threshold_mldsa::{AdditiveShare, GroupPublic, KeyShare, Path};

/// Address book: where each node listens.
pub type Peers = BTreeMap<NodeId, String>;

pub use cairn_policy::pos::CHECKPOINT_DOMAIN;
use cairn_policy::{PolicyEngine, SignContext};

/// Scripted deviations, for tests, benchmarks and drills.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultMode {
    #[default]
    None,
    /// Accept connections, never answer.
    Stall,
    /// Signer: deal sub-shares of a wrong share.
    BadShare,
    /// Root engine: report a different `c~`.
    WrongChallenge,
    /// Root engine: give the MPC backend an inconsistent response share.
    BadResponse,
}

impl std::str::FromStr for FaultMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "none" => FaultMode::None,
            "stall" => FaultMode::Stall,
            "bad-share" => FaultMode::BadShare,
            "wrong-challenge" => FaultMode::WrongChallenge,
            "bad-response" => FaultMode::BadResponse,
            _ => return Err(format!("unknown fault mode {s:?}")),
        })
    }
}

pub fn ready_binding(session: &[u8; 32], id: NodeId, group: &GroupPublic) -> [u8; 32] {
    let commitment = id
        .path()
        .and_then(|p| group.seed_commitments.get(&p).copied())
        .unwrap_or([0u8; 32]);
    let mut out = [0u8; 32];
    fips204::shake256(
        &[
            b"cairn/net-ready/v2",
            session,
            id.to_string().as_bytes(),
            &commitment,
        ],
        &mut out,
    );
    out
}

/// What a signer says it approved: a digest of the session and its message. It travels with
/// every sub-share, so an engine only sums shares from signers that approved its message.
pub fn message_digest(session: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    fips204::shake256(&[b"cairn/net-message/v1", session, message], &mut out);
    out
}

/// What a root engine signs before any mask exists: the session, its message, the active
/// set with its weights, the three engines in slot order and their verification shares. An
/// engine runs the mask phase only when the other two signed the same statement, so a
/// coordinator cannot show the engines different sessions.
pub fn session_statement(
    session: &[u8; 32],
    message: &[u8],
    active: &threshold_mldsa::Active,
    roots: &[u8],
    verification: &[Vec<i32>],
) -> Vec<u8> {
    let mut data = Vec::new();
    for (path, weight) in active.weights() {
        data.push(path.len() as u8);
        data.extend_from_slice(&path);
        data.extend_from_slice(&weight.to_le_bytes());
    }
    data.push(0xff);
    data.extend_from_slice(roots);
    for share in verification {
        data.extend_from_slice(&(share.len() as u32).to_le_bytes());
        for coefficient in share {
            data.extend_from_slice(&coefficient.to_le_bytes());
        }
    }
    let mut out = [0u8; 32];
    fips204::shake256(
        &[
            b"cairn/net-session/v1",
            session,
            &message_digest(session, message),
            &data,
        ],
        &mut out,
    );
    out.to_vec()
}

/// Sessions a signer has approved a message for and not yet dealt in: session to digest.
#[derive(Default)]
pub struct Approved(Mutex<HashMap<[u8; 32], [u8; 32]>>);

impl Approved {
    fn insert(&self, session: [u8; 32], digest: [u8; 32]) {
        let mut map = self.0.lock().expect("approved sessions");
        if map.len() >= MAX_SESSIONS {
            map.clear();
        }
        map.insert(session, digest);
    }

    fn take(&self, session: &[u8; 32]) -> Option<[u8; 32]> {
        self.0.lock().expect("approved sessions").remove(session)
    }
}

fn refused(reason: &str) -> Body {
    Body::Refused {
        reason: reason.into(),
    }
}

/// What the node's policy says about `message`, as a refusal reason. A policy may run a
/// program or call a service, so it is asked on a blocking thread, never on the threads that
/// carry the node's network traffic. A policy that panics refuses.
pub(crate) async fn policy_refusal(
    policy: &Arc<dyn PolicyEngine>,
    session: [u8; 32],
    party: u8,
    signers: Vec<u8>,
    message: Vec<u8>,
) -> Option<String> {
    let policy = policy.clone();
    let asked = tokio::task::spawn_blocking(move || {
        let ctx = SignContext {
            session: &session,
            party,
            signers: &signers,
        };
        policy.authorize_sign(&ctx, &message)
    });
    match asked.await {
        Ok(Ok(())) => None,
        Ok(Err(refused)) => Some(refused.to_string()),
        Err(_) => Some("the signing policy failed".into()),
    }
}

/// The policy tower nodes run unless given another: the checkpoint format check.
pub fn default_policy() -> Arc<dyn PolicyEngine> {
    Arc::new(cairn_policy::pos::CheckpointPrefix)
}

/// A signer node.
pub struct SignerNode {
    pub id: NodeId,
    pub group: Arc<GroupPublic>,
    pub share: KeyShare,
    pub peers: Peers,
    pub link: Link,
    pub fault: FaultMode,
    /// Asked before this signer agrees to a message.
    pub policy: Arc<dyn PolicyEngine>,
    /// Messages this signer approved, by session. A share is dealt once per approval.
    pub approved: Approved,
}

impl SignerNode {
    async fn deal(
        &self,
        session: [u8; 32],
        active: threshold_mldsa::Active,
        roots: Vec<u8>,
    ) -> Body {
        let path = self.share.path.clone();
        // No share leaves this signer for a session whose message its policy did not accept,
        // and none leaves twice.
        let Some(message) = self.approved.take(&session) else {
            return refused("no approved message for this session");
        };
        let mut distinct = roots.clone();
        distinct.sort();
        distinct.dedup();
        if distinct.len() != PARTIES
            || roots.len() != PARTIES
            || !active.is_authorized(&self.group.shape)
        {
            return refused("not an authorized active set with three distinct root engines");
        }
        let Some(weight) = active
            .weights()
            .into_iter()
            .find(|(p, _)| p == &path)
            .map(|(_, w)| w)
        else {
            return refused("this signer is not in the active set");
        };
        // Step 1: direct additive share of the master key. Step 2: one sub-share per engine.
        let mut hat = self.share.flatten(weight);
        if self.fault == FaultMode::BadShare {
            hat.s1[0] = (hat.s1[0] + 1) % Q;
        }
        let subs = hat.split(PARTIES, &mut OsRng);
        let sends = roots.iter().zip(subs).map(|(root, share)| {
            let frame = Frame {
                version: NET_VERSION,
                from: self.id,
                to: NodeId::Root(*root),
                session,
                body: Body::SubShare {
                    path: path.clone(),
                    share,
                    message,
                },
            };
            async move {
                let Some(addr) = self.peers.get(&NodeId::Root(*root)) else {
                    return Err(*root);
                };
                match call(addr, &self.link, &frame).await {
                    Ok(x) if x.reply.body == Body::Ack => Ok(x.sent as u64 + x.received as u64),
                    _ => Err(*root),
                }
            }
        });
        let mut p2p_bytes = 0;
        for result in join_all(sends).await {
            match result {
                Ok(bytes) => p2p_bytes += bytes,
                Err(root) => return Body::DealFailed { root },
            }
        }
        Body::Dealt { p2p_bytes }
    }
}

impl Handler for SignerNode {
    fn handle(&self, request: Frame) -> Reply<'_> {
        Box::pin(async move {
            if self.fault == FaultMode::Stall {
                return None;
            }
            let body = if request.to != self.id || request.from != NodeId::Coordinator {
                refused("misaddressed frame")
            } else {
                match request.body {
                    Body::Prepare { message } => {
                        let refusal = policy_refusal(
                            &self.policy,
                            request.session,
                            0,
                            Vec::new(),
                            message.clone(),
                        );
                        match refusal.await {
                            None => {
                                self.approved.insert(
                                    request.session,
                                    message_digest(&request.session, &message),
                                );
                                Body::Ready {
                                    binding: ready_binding(&request.session, self.id, &self.group),
                                }
                            }
                            Some(reason) => Body::PolicyRefused { reason },
                        }
                    }
                    Body::Deal { active, roots } => self.deal(request.session, active, roots).await,
                    Body::Abort => {
                        self.approved.take(&request.session);
                        Body::Ack
                    }
                    _ => refused("unexpected request"),
                }
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

#[derive(Default)]
struct RootSession {
    message: Vec<u8>,
    subs: BTreeMap<Path, AdditiveShare>,
    share: Option<AdditiveShare>,
    slot: u8,
    verification: Vec<Vec<i32>>,
    /// The active set this engine collected for.
    active: Option<threshold_mldsa::Active>,
    /// The engines in slot order and the statement this engine signed at install.
    roots: Vec<u8>,
    statement: Vec<u8>,
    /// The other two engines signed the same statement.
    agreed: bool,
    y: Option<PolyVec>,
    c_tilde: Option<[u8; C_TILDE_BYTES]>,
}

/// A root MPC engine node.
pub struct RootNode {
    pub id: NodeId,
    pub group: Arc<GroupPublic>,
    pub fault: FaultMode,
    /// Directory holding the MPC backend's party sockets `p1.sock`..`p3.sock`.
    pub mpc_socket_dir: PathBuf,
    /// Deadline for one MPC phase.
    pub mpc_timeout: Duration,
    /// Asked before the root engine opens a session for a message.
    pub policy: Arc<dyn PolicyEngine>,
    /// This engine's identity, for signing the session and checking the other engines'
    /// signatures. Set by `run_root`; without it the engine installs nothing.
    pub tls: Option<Arc<crate::tls::TlsIdentity>>,
    sessions: Mutex<HashMap<[u8; 32], RootSession>>,
}

/// Sessions a root engine keeps at once; the oldest state is dropped beyond this.
const MAX_SESSIONS: usize = 64;

impl RootNode {
    pub fn new(
        id: NodeId,
        group: Arc<GroupPublic>,
        fault: FaultMode,
        mpc_socket_dir: PathBuf,
        mpc_timeout: Duration,
    ) -> Self {
        Self {
            id,
            group,
            fault,
            mpc_socket_dir,
            mpc_timeout,
            policy: default_policy(),
            tls: None,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn with<T>(&self, session: &[u8; 32], f: impl FnOnce(&mut RootSession) -> T) -> Option<T> {
        self.sessions
            .lock()
            .expect("root sessions")
            .get_mut(session)
            .map(f)
    }

    async fn backend(&self, slot: u8, request: Request) -> Result<mpc_bridge::Reply, Box<Body>> {
        let client = PartyClient::new(&self.mpc_socket_dir, slot as usize, self.mpc_timeout);
        match tokio::task::spawn_blocking(move || client.call(&request)).await {
            Ok(Ok(mpc_bridge::Reply::Fault {
                code,
                party,
                message,
            })) => Err(Box::new(Body::BackendFault {
                blame: code == FAULT_BLAME,
                party,
                message,
            })),
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(e)) => Err(Box::new(Body::BackendFault {
                blame: false,
                party: 0,
                message: format!("MPC backend: {e}"),
            })),
            Err(e) => Err(Box::new(Body::BackendFault {
                blame: false,
                party: 0,
                message: e.to_string(),
            })),
        }
    }

    fn collect(&self, session: &[u8; 32], active: &threshold_mldsa::Active) -> Body {
        if !active.is_authorized(&self.group.shape) {
            return refused("active set is not authorized");
        }
        let a_hat = self.group.a_hat();
        self.with(session, |s| {
            let (mut values, mut missing, mut parts) = (Vec::new(), Vec::new(), Vec::new());
            for (path, _) in active.weights() {
                match s.subs.get(&path) {
                    Some(sub) => {
                        values.push((path, to_flat(&sub.verification(a_hat))));
                        parts.push(sub);
                    }
                    None => missing.push(path),
                }
            }
            // Step 3: this engine's additive share of the master key.
            s.share = missing.is_empty().then(|| AdditiveShare::sum(parts));
            s.subs.clear();
            s.active = Some(active.clone());
            Body::ShareCheck { values, missing }
        })
        .unwrap_or_else(|| refused("unknown session"))
    }

    /// Install the MPC slot and sign the session this engine was shown.
    fn install(
        &self,
        session: &[u8; 32],
        slot: u8,
        roots: Vec<u8>,
        verification: Vec<Vec<i32>>,
    ) -> Body {
        let Some(tls) = &self.tls else {
            return refused("this engine has no identity to sign the session with");
        };
        let a_hat = self.group.a_hat();
        self.with(session, |s| {
            let own = s.share.as_ref().map(|sh| to_flat(&sh.verification(a_hat)));
            let slot_ok = (1..=PARTIES as u8).contains(&slot)
                && verification.len() == PARTIES
                && roots.len() == PARTIES
                && roots.get(slot as usize - 1).map(|k| NodeId::Root(*k)) == Some(self.id);
            let (true, Some(active)) = (slot_ok, s.active.as_ref()) else {
                return refused("install does not name this engine's slot");
            };
            if own.as_ref() != verification.get(slot as usize - 1) {
                return refused("verification shares do not match this engine's share");
            }
            let statement = session_statement(session, &s.message, active, &roots, &verification);
            let Ok((cert, signature)) = tls.attest(&statement) else {
                return refused("cannot sign the session");
            };
            s.slot = slot;
            s.verification = verification;
            s.roots = roots;
            s.statement = statement;
            s.agreed = false;
            Body::Installed {
                attestation: crate::wire::Attestation { cert, signature },
            }
        })
        .unwrap_or_else(|| refused("unknown session"))
    }

    /// True once the other two engines are known to have signed this engine's statement.
    fn agreed(&self, session: &[u8; 32], attestations: &[(u8, crate::wire::Attestation)]) -> bool {
        let Some(tls) = &self.tls else {
            return false;
        };
        self.with(session, |s| {
            if s.agreed {
                return true;
            }
            if s.slot == 0 {
                return false;
            }
            s.agreed = s
                .roots
                .iter()
                .filter(|k| NodeId::Root(**k) != self.id)
                .all(|k| {
                    attestations.iter().any(|(from, a)| {
                        from == k
                            && tls.attested_by(
                                NodeId::Root(*k),
                                &a.cert,
                                &s.statement,
                                &a.signature,
                            )
                    })
                });
            s.agreed
        })
        .unwrap_or(false)
    }

    async fn mask(&self, session: [u8; 32], attempt: u32) -> Body {
        let Some(Some((slot, k_share, message))) = self.with(&session, |s| {
            s.share
                .as_ref()
                .map(|sh| (s.slot, sh.k.clone(), s.message.clone()))
        }) else {
            return refused("no installed share for this session");
        };
        if slot == 0 {
            return refused("no MPC slot installed");
        }
        let mu = fips204::message_representative(&self.group.tr, &[], &message);
        let request = Request::Mask(MaskRequest {
            session,
            party: slot,
            attempt,
            mu,
            rho: self.group.rho,
            k_share,
        });
        match self.backend(slot, request).await {
            Ok(mpc_bridge::Reply::MaskOk { c_tilde, y_share }) => {
                self.with(&session, |s| {
                    s.y = Some(to_polys(&y_share));
                    s.c_tilde = Some(c_tilde);
                });
                let mut echo = c_tilde;
                if self.fault == FaultMode::WrongChallenge {
                    echo[0] ^= 1;
                }
                Body::Challenge {
                    c_tilde: echo.to_vec(),
                }
            }
            Ok(_) => refused("unexpected MPC reply"),
            Err(fault) => *fault,
        }
    }

    async fn finish(&self, session: [u8; 32]) -> Body {
        let a_hat = self.group.a_hat();
        let prepared = self.with(&session, |s| {
            let (share, y, c_tilde) = (s.share.as_ref()?, s.y.take()?, s.c_tilde.take()?);
            // The linear step, on this engine's own additive share.
            let (z, mut r) = share.respond(a_hat, &y, &c_tilde);
            if self.fault == FaultMode::BadResponse {
                r[0][0] = (r[0][0] + 1) % Q;
            }
            let t: [Vec<i32>; PARTIES] = s.verification.clone().try_into().ok()?;
            Some((
                s.slot,
                Request::Response(Box::new(ResponseRequest {
                    session,
                    party: s.slot,
                    z_share: to_flat(&z),
                    r_share: to_flat(&r),
                    t0: to_flat(&self.group.t0),
                    t,
                })),
            ))
        });
        let Some(Some((slot, request))) = prepared else {
            return refused("no mask phase for this session");
        };
        match self.backend(slot, request).await {
            Ok(mpc_bridge::Reply::Reject) => Body::Verdict(Outcome::Reject),
            Ok(mpc_bridge::Reply::Accept { hint, z }) => Body::Verdict(Outcome::Accept {
                hint,
                z: z.to_vec(),
            }),
            Ok(_) => refused("unexpected MPC reply"),
            Err(fault) => *fault,
        }
    }

    async fn close(&self, session: [u8; 32]) {
        let slot = self
            .sessions
            .lock()
            .expect("root sessions")
            .remove(&session)
            .map(|s| s.slot);
        if let Some(slot) = slot.filter(|s| *s != 0) {
            let _ = self.backend(slot, Request::Close(session)).await;
        }
    }
}

impl Handler for RootNode {
    fn handle(&self, request: Frame) -> Reply<'_> {
        Box::pin(async move {
            if self.fault == FaultMode::Stall {
                return None;
            }
            let session = request.session;
            let from_coordinator = request.from == NodeId::Coordinator;
            let body = match request.body {
                _ if request.to != self.id => refused("misaddressed frame"),
                Body::Prepare { message } if from_coordinator => {
                    let refusal =
                        policy_refusal(&self.policy, session, 0, Vec::new(), message.clone());
                    if let Some(reason) = refusal.await {
                        Body::PolicyRefused { reason }
                    } else {
                        let mut sessions = self.sessions.lock().expect("root sessions");
                        if sessions.len() >= MAX_SESSIONS {
                            sessions.clear();
                        }
                        sessions.insert(
                            session,
                            RootSession {
                                message,
                                ..RootSession::default()
                            },
                        );
                        Body::Ready {
                            binding: ready_binding(&session, self.id, &self.group),
                        }
                    }
                }
                Body::SubShare {
                    path,
                    share,
                    message,
                } => {
                    // Point to point from the signer that owns `path`.
                    if NodeId::from_path(&path) != Some(request.from) || !share.is_well_formed() {
                        refused("sub-share does not come from its signer")
                    } else {
                        self.with(&session, |s| {
                            if message != message_digest(&session, &s.message) {
                                return refused("sub-share is for another message");
                            }
                            s.subs.insert(path, share);
                            Body::Ack
                        })
                        .unwrap_or_else(|| refused("unknown session"))
                    }
                }
                Body::Collect { active } if from_coordinator => self.collect(&session, &active),
                Body::Install {
                    slot,
                    roots,
                    verification,
                } if from_coordinator => self.install(&session, slot, roots, verification),
                Body::Mask {
                    attempt,
                    attestations,
                } if from_coordinator => {
                    if self.agreed(&session, &attestations) {
                        self.mask(session, attempt).await
                    } else {
                        refused("the other engines did not sign this session")
                    }
                }
                Body::Finish if from_coordinator => self.finish(session).await,
                Body::Abort if from_coordinator => {
                    self.close(session).await;
                    Body::Ack
                }
                _ => refused("unexpected request"),
            };
            Some(Frame {
                version: NET_VERSION,
                from: self.id,
                to: request.from,
                session,
                body,
            })
        })
    }
}

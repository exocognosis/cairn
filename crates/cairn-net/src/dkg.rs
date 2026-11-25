//! Distributed key generation for a flat committee: no dealer, and no machine that ever holds
//! the whole key.
//!
//! This follows the four-round protocol in Appendix D of *Efficient Threshold ML-DSA*. For
//! every subset `S` of `N - T + 1` parties, the lowest-indexed member (its leader) picks a seed
//! `K_S` and shares it with the other members. All parties also commit to and then reveal
//! public randomness `R`. Each member of `S` derives the subset's short secret as
//! `H(S, K_S, R)`, so no single party chooses it, and the leader publishes
//! `t_S = A s1_S + s2_S` behind a commitment. The public key is the sum of the `t_S`. At the
//! end every party signs the transcript it saw, so a relay that showed parties different
//! things is caught.
//!
//! Two additions, because cairn's parties talk through a coordinator they do not trust:
//!
//! * a round 0 in which each party publishes fresh X25519 keys, signed with its long-term
//!   Ed25519 identity, and
//! * the seeds `K_S` travel encrypted end to end (X25519, HKDF, ChaCha20-Poly1305) under those
//!   keys. The coordinator and the TLS certificate authority only ever see ciphertext.
//!
//! What each party must have beforehand: its own identity key and the public identity keys of
//! all the others (the roster). Exchanging those out of band is the one trust step left.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::{aead, agreement, hkdf};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use threshold_mldsa::fips204::{self, PolyVec, K};
use threshold_mldsa::mithril::{self, GroupKey, PartyKey, Subset};

type Bytes32 = [u8; 32];

/// A party's long-term identity (Ed25519). The private part never leaves the party.
pub struct Identity {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
}

impl Identity {
    pub fn generate() -> Result<Self, String> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| "key generation failed")?;
        Self::from_pkcs8(doc.as_ref())
    }

    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, String> {
        let pair = Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| "not an Ed25519 PKCS#8 key")?;
        Ok(Self {
            pair,
            pkcs8: bytes.to_vec(),
        })
    }

    pub fn to_pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn public(&self) -> Bytes32 {
        self.pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public keys are 32 bytes")
    }
}

/// Who is in the committee: the threshold and every party's public identity key, by index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    pub threshold: u8,
    pub identities: Vec<Bytes32>,
}

impl Roster {
    pub fn n(&self) -> usize {
        self.identities.len()
    }

    fn subsets(&self) -> Vec<Subset> {
        mithril::all_subsets(self.threshold as usize, self.n())
    }

    fn digest(&self) -> Bytes32 {
        hash(&[
            b"cairn/dkg/roster/v1",
            &bincode::serialize(self).expect("roster encodes"),
        ])
    }
}

fn hash(parts: &[&[u8]]) -> Bytes32 {
    let mut out = [0u8; 32];
    fips204::shake256(parts, &mut out);
    out
}

/// Round 0: fresh X25519 public keys, one per other party, signed by the sender's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub index: u8,
    pub ephemeral: Vec<(u8, Bytes32)>,
    pub signature: Vec<u8>,
}

/// Round 1: commitment to this party's randomness, and sealed seeds for the subsets it leads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub index: u8,
    pub commitment: Bytes32,
    /// For each other member of a subset this party leads: the seeds, encrypted to it.
    pub sealed: Vec<(u8, Vec<u8>)>,
}

/// Round 2: the randomness opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reveal {
    pub index: u8,
    pub randomness: Bytes32,
}

/// Round 3: commitments to the partial public keys of the subsets this party leads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCommit {
    pub index: u8,
    pub commitments: Vec<(Subset, Bytes32)>,
}

/// Round 4: those partial public keys, and a signature over the whole transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyReveal {
    pub index: u8,
    pub partial: Vec<(Subset, Vec<u8>)>,
    pub signature: Vec<u8>,
}

fn hello_bytes(
    session: &Bytes32,
    roster: &Bytes32,
    index: u8,
    ephemeral: &[(u8, Bytes32)],
) -> Vec<u8> {
    let mut m = b"cairn/dkg/hello/v1".to_vec();
    m.extend_from_slice(session);
    m.extend_from_slice(roster);
    m.push(index);
    for (peer, key) in ephemeral {
        m.push(*peer);
        m.extend_from_slice(key);
    }
    m
}

fn final_bytes(transcript: &Bytes32, index: u8, partial: &[(Subset, Vec<u8>)]) -> Vec<u8> {
    let mut m = b"cairn/dkg/final/v1".to_vec();
    m.extend_from_slice(transcript);
    m.push(index);
    m.extend_from_slice(&bincode::serialize(partial).expect("partial keys encode"));
    m
}

fn seal_key(
    shared: &[u8],
    session: &Bytes32,
    from: u8,
    to: u8,
) -> Result<aead::LessSafeKey, String> {
    let info: &[&[u8]] = &[b"cairn/dkg/seal/v1", session, &[from, to]];
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"cairn").extract(shared);
    let okm = prk
        .expand(info, &aead::CHACHA20_POLY1305)
        .map_err(|_| "key derivation failed")?;
    Ok(aead::LessSafeKey::new(okm.into()))
}

fn commit_randomness(index: u8, r: &Bytes32) -> Bytes32 {
    hash(&[b"cairn/dkg/commit-r/v1", &[index], r])
}

fn commit_partial(subset: &[u8], t_s: &[u8]) -> Bytes32 {
    hash(&[b"cairn/dkg/commit-t/v1", &[subset.len() as u8], subset, t_s])
}

/// One party's run of the key generation. Each method consumes the previous round's messages
/// from all parties (including its own) and produces this party's next message.
pub struct DkgParty {
    index: u8,
    roster: Roster,
    identity: Identity,
    session: Bytes32,
    ephemeral: BTreeMap<u8, agreement::EphemeralPrivateKey>,
    my_hello: Option<Hello>,
    seeds: BTreeMap<Subset, Bytes32>,
    randomness: Bytes32,
    hellos: Vec<Hello>,
    commits: Vec<Commit>,
    reveals: Vec<Reveal>,
    key_commits: Vec<KeyCommit>,
    rho: Bytes32,
    secrets: BTreeMap<Subset, (PolyVec, PolyVec)>,
    my_partials: Vec<(Subset, Vec<u8>)>,
}

fn sorted<T: Clone>(mut v: Vec<T>, key: impl Fn(&T) -> u8) -> Vec<T> {
    v.sort_by_key(|x| key(x));
    v
}

impl DkgParty {
    pub fn new(
        roster: Roster,
        identity: Identity,
        index: u8,
        session: Bytes32,
    ) -> Result<Self, String> {
        let n = roster.n();
        if mithril::params_65(roster.threshold as usize, n).is_none() {
            return Err("no parameter set for this committee".into());
        }
        if roster.identities.get(index as usize) != Some(&identity.public()) {
            return Err("this identity is not at that index in the roster".into());
        }
        Ok(Self {
            index,
            roster,
            identity,
            session,
            ephemeral: BTreeMap::new(),
            my_hello: None,
            seeds: BTreeMap::new(),
            randomness: rand::random(),
            hellos: Vec::new(),
            commits: Vec::new(),
            reveals: Vec::new(),
            key_commits: Vec::new(),
            rho: [0; 32],
            secrets: BTreeMap::new(),
            my_partials: Vec::new(),
        })
    }

    fn check_set<T>(
        &self,
        items: &[T],
        index: impl Fn(&T) -> u8,
        mine: Option<&T>,
    ) -> Result<(), String>
    where
        T: PartialEq,
    {
        let indices: Vec<u8> = items.iter().map(&index).collect();
        if indices != (0..self.roster.n() as u8).collect::<Vec<_>>() {
            return Err("a round is missing a party or lists one twice".into());
        }
        // What the relay shows us as our own message must be what we sent.
        if mine.is_some_and(|m| &items[self.index as usize] != m) {
            return Err("our own message was altered in transit".into());
        }
        Ok(())
    }

    /// Round 0.
    pub fn hello(&mut self) -> Result<Hello, String> {
        let rng = SystemRandom::new();
        let mut ephemeral = Vec::new();
        for peer in (0..self.roster.n() as u8).filter(|p| *p != self.index) {
            let key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
                .map_err(|_| "X25519 failed")?;
            let public: Bytes32 = key
                .compute_public_key()
                .map_err(|_| "X25519 failed")?
                .as_ref()
                .try_into()
                .map_err(|_| "X25519")?;
            ephemeral.push((peer, public));
            self.ephemeral.insert(peer, key);
        }
        let message = hello_bytes(&self.session, &self.roster.digest(), self.index, &ephemeral);
        let hello = Hello {
            index: self.index,
            ephemeral,
            signature: self.identity.pair.sign(&message).as_ref().to_vec(),
        };
        self.my_hello = Some(hello.clone());
        Ok(hello)
    }

    /// Round 1: verify everyone's hello, seal seeds for the subsets we lead, commit to `r`.
    pub fn commit(&mut self, hellos: Vec<Hello>) -> Result<Commit, String> {
        let hellos = sorted(hellos, |h| h.index);
        self.check_set(&hellos, |h| h.index, self.my_hello.as_ref())?;
        let roster_digest = self.roster.digest();
        for h in &hellos {
            let message = hello_bytes(&self.session, &roster_digest, h.index, &h.ephemeral);
            UnparsedPublicKey::new(&ED25519, &self.roster.identities[h.index as usize])
                .verify(&message, &h.signature)
                .map_err(|_| format!("party {} did not sign its key-exchange keys", h.index + 1))?;
        }
        // Seeds for the subsets this party leads.
        let mut per_peer: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
        for subset in self
            .roster
            .subsets()
            .into_iter()
            .filter(|s| s[0] == self.index)
        {
            let seed: Bytes32 = rand::random();
            for member in subset.iter().filter(|m| **m != self.index) {
                per_peer
                    .entry(*member)
                    .or_default()
                    .extend_from_slice(&seed);
            }
            self.seeds.insert(subset, seed);
        }
        let mut sealed = Vec::new();
        for (peer, mut plaintext) in per_peer {
            let their = hellos[peer as usize]
                .ephemeral
                .iter()
                .find(|(to, _)| *to == self.index)
                .ok_or("missing key")?
                .1;
            let mine = self.ephemeral.remove(&peer).ok_or("key already used")?;
            let key = agreement::agree_ephemeral(
                mine,
                &agreement::UnparsedPublicKey::new(&agreement::X25519, their),
                |shared| seal_key(shared, &self.session, self.index, peer),
            )
            .map_err(|_| "key agreement failed")??;
            key.seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(self.session),
                &mut plaintext,
            )
            .map_err(|_| "sealing failed")?;
            sealed.push((peer, plaintext));
        }
        self.hellos = hellos;
        Ok(Commit {
            index: self.index,
            commitment: commit_randomness(self.index, &self.randomness),
            sealed,
        })
    }

    /// Round 2: open the seeds sent to us, then reveal `r`.
    pub fn reveal(&mut self, commits: Vec<Commit>) -> Result<Reveal, String> {
        let commits = sorted(commits, |c| c.index);
        self.check_set(&commits, |c| c.index, None)?;
        for leader in 0..self.index {
            let led: Vec<Subset> = self
                .roster
                .subsets()
                .into_iter()
                .filter(|s| s[0] == leader && s.contains(&self.index))
                .collect();
            if led.is_empty() {
                continue;
            }
            let mut ciphertext = commits[leader as usize]
                .sealed
                .iter()
                .find(|(to, _)| *to == self.index)
                .ok_or_else(|| format!("party {} sent us no seeds", leader + 1))?
                .1
                .clone();
            let their = self.hellos[leader as usize]
                .ephemeral
                .iter()
                .find(|(to, _)| *to == self.index)
                .ok_or("missing key")?
                .1;
            let mine = self.ephemeral.remove(&leader).ok_or("key already used")?;
            let key = agreement::agree_ephemeral(
                mine,
                &agreement::UnparsedPublicKey::new(&agreement::X25519, their),
                |shared| seal_key(shared, &self.session, leader, self.index),
            )
            .map_err(|_| "key agreement failed")??;
            let plaintext = key
                .open_in_place(
                    aead::Nonce::assume_unique_for_key([0; 12]),
                    aead::Aad::from(self.session),
                    &mut ciphertext,
                )
                .map_err(|_| format!("seeds from party {} do not decrypt", leader + 1))?;
            if plaintext.len() != 32 * led.len() {
                return Err(format!(
                    "party {} sent the wrong number of seeds",
                    leader + 1
                ));
            }
            for (subset, seed) in led.into_iter().zip(plaintext.chunks(32)) {
                self.seeds
                    .insert(subset, seed.try_into().expect("32 bytes"));
            }
        }
        self.commits = commits;
        Ok(Reveal {
            index: self.index,
            randomness: self.randomness,
        })
    }

    /// Round 3: check the openings, derive every secret we hold, commit to the `t_S` we lead.
    pub fn key_commit(&mut self, reveals: Vec<Reveal>) -> Result<KeyCommit, String> {
        let reveals = sorted(reveals, |r| r.index);
        self.check_set(&reveals, |r| r.index, None)?;
        for (r, c) in reveals.iter().zip(&self.commits) {
            if commit_randomness(r.index, &r.randomness) != c.commitment {
                return Err(format!(
                    "party {} opened different randomness than it committed to",
                    r.index + 1
                ));
            }
        }
        let randomness: Vec<u8> = reveals.iter().flat_map(|r| r.randomness).collect();
        self.rho = hash(&[b"cairn/dkg/seed/v1", &randomness]);
        let mut commitments = Vec::new();
        for (subset, seed) in &self.seeds {
            let secret = mithril::derive_subset_secret(subset, seed, &randomness);
            if subset[0] == self.index {
                let packed = mithril::pack_k(&mithril::subset_public(&self.rho, &secret));
                commitments.push((subset.clone(), commit_partial(subset, &packed)));
                self.my_partials.push((subset.clone(), packed));
            }
            self.secrets.insert(subset.clone(), secret);
        }
        self.reveals = reveals;
        Ok(KeyCommit {
            index: self.index,
            commitments,
        })
    }

    fn transcript(&self) -> Bytes32 {
        let encoded = bincode::serialize(&(
            &self.hellos,
            &self.commits,
            &self.reveals,
            &self.key_commits,
        ))
        .expect("transcript encodes");
        hash(&[
            b"cairn/dkg/transcript/v1",
            &self.session,
            &self.roster.digest(),
            &encoded,
        ])
    }

    /// Round 4: check that every leader committed to the `t_S` we can compute ourselves, then
    /// publish ours and sign the transcript.
    pub fn key_reveal(&mut self, key_commits: Vec<KeyCommit>) -> Result<KeyReveal, String> {
        let key_commits = sorted(key_commits, |k| k.index);
        self.check_set(&key_commits, |k| k.index, None)?;
        for subset in self.roster.subsets() {
            let leader = subset[0];
            let committed = key_commits[leader as usize]
                .commitments
                .iter()
                .find(|(s, _)| s == &subset)
                .ok_or_else(|| {
                    format!("party {} did not commit for a subset it leads", leader + 1)
                })?
                .1;
            // Every member of the subset can recompute t_S and so check its leader.
            if let Some(secret) = self.secrets.get(&subset) {
                let expect = commit_partial(
                    &subset,
                    &mithril::pack_k(&mithril::subset_public(&self.rho, secret)),
                );
                if committed != expect {
                    return Err(format!(
                        "party {} committed to a wrong partial key",
                        leader + 1
                    ));
                }
            }
        }
        self.key_commits = key_commits;
        let message = final_bytes(&self.transcript(), self.index, &self.my_partials);
        Ok(KeyReveal {
            index: self.index,
            partial: self.my_partials.clone(),
            signature: self.identity.pair.sign(&message).as_ref().to_vec(),
        })
    }

    /// Final step: verify every signature and opening, and assemble the public key and this
    /// party's share.
    pub fn finish(self, key_reveals: Vec<KeyReveal>) -> Result<(GroupKey, PartyKey), String> {
        let key_reveals = sorted(key_reveals, |k| k.index);
        self.check_set(&key_reveals, |k| k.index, None)?;
        let transcript = self.transcript();
        let mut t_full = fips204::vec_zero(K);
        let mut seen = 0;
        for reveal in &key_reveals {
            let message = final_bytes(&transcript, reveal.index, &reveal.partial);
            UnparsedPublicKey::new(&ED25519, &self.roster.identities[reveal.index as usize])
                .verify(&message, &reveal.signature)
                .map_err(|_| format!("party {} signed a different transcript", reveal.index + 1))?;
            let committed = &self.key_commits[reveal.index as usize].commitments;
            if reveal.partial.len() != committed.len() {
                return Err(format!(
                    "party {} revealed the wrong number of partial keys",
                    reveal.index + 1
                ));
            }
            for (subset, packed) in &reveal.partial {
                if committed.iter().find(|(s, _)| s == subset).map(|(_, c)| *c)
                    != Some(commit_partial(subset, packed))
                {
                    return Err(format!(
                        "party {} opened a different partial key",
                        reveal.index + 1
                    ));
                }
                let t_s = mithril::unpack_k(packed).ok_or("malformed partial key")?;
                t_full = fips204::vec_add(&t_full, &t_s);
                seen += 1;
            }
        }
        if seen != self.roster.subsets().len() {
            return Err("not every subset contributed a partial key".into());
        }
        let key = GroupKey::from_parts(
            self.roster.threshold as usize,
            self.roster.n(),
            self.rho,
            &t_full,
        )
        .ok_or("no parameter set for this committee")?;
        Ok((key, PartyKey::from_shares(self.index, self.secrets)))
    }
}

/// A request to a party for one step, carrying the previous round's messages from everyone.
#[derive(Serialize, Deserialize)]
pub enum Step {
    Hello,
    Commit(Vec<Hello>),
    Reveal(Vec<Commit>),
    KeyCommit(Vec<Reveal>),
    KeyReveal(Vec<KeyCommit>),
    Finish(Vec<KeyReveal>),
}

/// A node that takes part in one key generation and then writes its results to disk:
/// `committee.bin` (public) and `party_<k>.share` (secret, mode 0600) under `out_dir`.
pub struct DkgNode {
    pub id: crate::wire::NodeId,
    roster: Roster,
    identity_pkcs8: Vec<u8>,
    out_dir: std::path::PathBuf,
    state: std::sync::Mutex<Option<(Bytes32, DkgParty)>>,
    done: tokio::sync::Notify,
}

impl DkgNode {
    pub fn new(
        id: crate::wire::NodeId,
        roster: Roster,
        identity: &Identity,
        out_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            id,
            roster,
            identity_pkcs8: identity.to_pkcs8().to_vec(),
            out_dir,
            state: std::sync::Mutex::new(None),
            done: tokio::sync::Notify::new(),
        }
    }

    /// Resolves once this node has written its key files.
    pub async fn finished(&self) {
        self.done.notified().await
    }

    fn step(&self, session: Bytes32, step: Step) -> Result<Vec<u8>, String> {
        let crate::wire::NodeId::Party(k) = self.id else {
            return Err("not a committee party".into());
        };
        let mut state = self.state.lock().expect("dkg state");
        let enc = |m: &dyn erased::Encode| m.encode();
        if let Step::Hello = step {
            // A new session replaces an unfinished one; a finished node has exited.
            let identity = Identity::from_pkcs8(&self.identity_pkcs8)?;
            let mut party = DkgParty::new(self.roster.clone(), identity, k - 1, session)?;
            let hello = party.hello()?;
            *state = Some((session, party));
            return Ok(enc(&hello));
        }
        let Some((current, party)) = state.as_mut().filter(|(s, _)| *s == session) else {
            return Err("no key generation in progress for this session".into());
        };
        let _ = current;
        match step {
            Step::Hello => unreachable!("handled above"),
            Step::Commit(v) => party.commit(v).map(|m| enc(&m)),
            Step::Reveal(v) => party.reveal(v).map(|m| enc(&m)),
            Step::KeyCommit(v) => party.key_commit(v).map(|m| enc(&m)),
            Step::KeyReveal(v) => party.key_reveal(v).map(|m| enc(&m)),
            Step::Finish(v) => {
                let (_, party) = state.take().expect("checked above");
                let (key, share) = party.finish(v)?;
                crate::flat::write_party_files(&self.out_dir, &key, &share)
                    .map_err(|e| format!("writing key files: {e}"))?;
                self.done.notify_one();
                Ok(key.pk.to_vec())
            }
        }
    }
}

mod erased {
    /// Encode any of the round messages without naming its type.
    pub trait Encode {
        fn encode(&self) -> Vec<u8>;
    }

    impl<T: serde::Serialize> Encode for T {
        fn encode(&self) -> Vec<u8> {
            bincode::serialize(self).expect("round message encodes")
        }
    }
}

impl crate::transport::Handler for DkgNode {
    fn handle(&self, request: crate::wire::Frame) -> crate::transport::Reply<'_> {
        use crate::wire::{Body, Frame, NodeId, NET_VERSION};
        Box::pin(async move {
            let body = match (&request.body, request.from, request.to == self.id) {
                (Body::Dkg(bytes), NodeId::Coordinator, true) => {
                    match bincode::deserialize::<Step>(bytes) {
                        Ok(step) => match self.step(request.session, step) {
                            Ok(reply) => Body::DkgReply(reply),
                            Err(reason) => Body::Refused { reason },
                        },
                        Err(_) => Body::Refused {
                            reason: "malformed key generation step".into(),
                        },
                    }
                }
                _ => Body::Refused {
                    reason: "unexpected request".into(),
                },
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

/// Drive a key generation across the roster's parties and return the public key they all
/// report. The driver relays public messages and ciphertext; it learns no secret.
pub async fn run(
    roster: &Roster,
    peers: &crate::node::Peers,
    link: &crate::transport::Link,
) -> Result<[u8; threshold_mldsa::PUBLIC_KEY_BYTES], String> {
    use crate::wire::{Body, Frame, NodeId, NET_VERSION};
    use futures_util::future::join_all;
    let session: Bytes32 = rand::random();
    let parties: Vec<NodeId> = (1..=roster.n() as u8).map(NodeId::Party).collect();
    let round = |step: Vec<u8>| {
        let parties = &parties;
        async move {
            let calls = parties.iter().map(|to| {
                let frame = Frame {
                    version: NET_VERSION,
                    from: NodeId::Coordinator,
                    to: *to,
                    session,
                    body: Body::Dkg(step.clone()),
                };
                async move {
                    let addr = peers
                        .get(to)
                        .ok_or_else(|| format!("no address for {to}"))?;
                    match crate::transport::call(addr, link, &frame).await {
                        Ok(x) => match x.reply.body {
                            Body::DkgReply(bytes) => Ok(bytes),
                            Body::Refused { reason } => Err(format!("{to}: {reason}")),
                            other => Err(format!("{to}: unexpected reply {}", other.kind())),
                        },
                        Err(e) => Err(format!("{to}: {e}")),
                    }
                }
            });
            join_all(calls)
                .await
                .into_iter()
                .collect::<Result<Vec<Vec<u8>>, String>>()
        }
    };
    fn decode<T: serde::de::DeserializeOwned>(replies: Vec<Vec<u8>>) -> Result<Vec<T>, String> {
        replies
            .iter()
            .map(|b| bincode::deserialize(b).map_err(|_| "malformed round message".to_string()))
            .collect()
    }
    let enc = |step: &Step| bincode::serialize(step).expect("step encodes");
    let hellos: Vec<Hello> = decode(round(enc(&Step::Hello)).await?)?;
    let commits: Vec<Commit> = decode(round(enc(&Step::Commit(hellos))).await?)?;
    let reveals: Vec<Reveal> = decode(round(enc(&Step::Reveal(commits))).await?)?;
    let key_commits: Vec<KeyCommit> = decode(round(enc(&Step::KeyCommit(reveals))).await?)?;
    let key_reveals: Vec<KeyReveal> = decode(round(enc(&Step::KeyReveal(key_commits))).await?)?;
    let keys = round(enc(&Step::Finish(key_reveals))).await?;
    if keys.iter().any(|k| k != &keys[0]) {
        return Err("parties ended with different public keys".into());
    }
    keys[0]
        .clone()
        .try_into()
        .map_err(|_| "malformed public key".to_string())
}

/// A roster as JSON: `{"threshold": 3, "identities": ["<hex>", ...]}`.
pub fn roster_to_json(roster: &Roster) -> String {
    let ids: Vec<String> = roster
        .identities
        .iter()
        .map(|k| k.iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    serde_json::to_string_pretty(
        &serde_json::json!({ "threshold": roster.threshold, "identities": ids }),
    )
    .expect("roster encodes")
}

pub fn roster_from_json(text: &str) -> Result<Roster, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("roster: {e}"))?;
    let threshold = v["threshold"]
        .as_u64()
        .and_then(|t| u8::try_from(t).ok())
        .ok_or("roster: bad threshold")?;
    let identities = v["identities"]
        .as_array()
        .ok_or("roster: identities must be a list")?
        .iter()
        .map(|h| {
            let h = h.as_str()?;
            let bytes: Option<Vec<u8>> = (0..h.len() / 2)
                .map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok())
                .collect();
            bytes?.try_into().ok()
        })
        .collect::<Option<Vec<Bytes32>>>()
        .ok_or("roster: identities must be 64 hex characters each")?;
    Ok(Roster {
        threshold,
        identities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn setup(t: u8, n: usize) -> Vec<DkgParty> {
        let identities: Vec<Identity> = (0..n).map(|_| Identity::generate().unwrap()).collect();
        let roster = Roster {
            threshold: t,
            identities: identities.iter().map(Identity::public).collect(),
        };
        identities
            .into_iter()
            .enumerate()
            .map(|(i, id)| DkgParty::new(roster.clone(), id, i as u8, [5; 32]).unwrap())
            .collect()
    }

    fn run(mut parties: Vec<DkgParty>) -> Result<Vec<(GroupKey, PartyKey)>, String> {
        let hellos: Vec<Hello> = parties
            .iter_mut()
            .map(|p| p.hello())
            .collect::<Result<_, _>>()?;
        let commits: Vec<Commit> = parties
            .iter_mut()
            .map(|p| p.commit(hellos.clone()))
            .collect::<Result<_, _>>()?;
        let reveals: Vec<Reveal> = parties
            .iter_mut()
            .map(|p| p.reveal(commits.clone()))
            .collect::<Result<_, _>>()?;
        let kc: Vec<KeyCommit> = parties
            .iter_mut()
            .map(|p| p.key_commit(reveals.clone()))
            .collect::<Result<_, _>>()?;
        let kr: Vec<KeyReveal> = parties
            .iter_mut()
            .map(|p| p.key_reveal(kc.clone()))
            .collect::<Result<_, _>>()?;
        parties.into_iter().map(|p| p.finish(kr.clone())).collect()
    }

    #[test]
    fn parties_agree_on_a_key_they_can_sign_with_and_no_one_holds_it_all() {
        for (t, n) in [(2u8, 3usize), (3, 4)] {
            let out = run(setup(t, n)).unwrap();
            let pk = out[0].0.pk;
            assert!(
                out.iter().all(|(k, _)| k.pk == pk),
                "all parties derive the same public key"
            );
            let subsets = mithril::all_subsets(t as usize, n);
            for (i, (_, share)) in out.iter().enumerate() {
                let expect: Vec<Subset> = subsets
                    .iter()
                    .filter(|s| s.contains(&(i as u8)))
                    .cloned()
                    .collect();
                assert_eq!(
                    share.subsets(),
                    expect,
                    "party {i} holds exactly its subsets' secrets"
                );
                assert!(
                    share.subsets().len() < subsets.len(),
                    "and not every secret"
                );
            }
            // The generated key signs under the three-round protocol.
            let (keys, shares): (Vec<GroupKey>, Vec<PartyKey>) = out.into_iter().unzip();
            let active: Vec<u8> = (0..t).collect();
            let (signature, _) =
                mithril::sign_local(&keys[0], &shares, &active, b"after dkg", &mut OsRng).unwrap();
            assert!(fips204::verify_standard(&pk, b"after dkg", &signature));
        }
    }

    #[test]
    fn deviations_and_a_lying_relay_are_caught() {
        // A party opens different randomness than it committed to.
        let mut p = setup(2, 3);
        let hellos: Vec<Hello> = p.iter_mut().map(|x| x.hello().unwrap()).collect();
        let commits: Vec<Commit> = p
            .iter_mut()
            .map(|x| x.commit(hellos.clone()).unwrap())
            .collect();
        let mut reveals: Vec<Reveal> = p
            .iter_mut()
            .map(|x| x.reveal(commits.clone()).unwrap())
            .collect();
        reveals[2].randomness[0] ^= 1;
        assert!(p[0].key_commit(reveals).unwrap_err().contains("party 3"));

        // A hello not signed by the roster identity (a relay substituting its own keys).
        let mut p = setup(2, 3);
        let mut hellos: Vec<Hello> = p.iter_mut().map(|x| x.hello().unwrap()).collect();
        hellos[1].ephemeral[0].1[0] ^= 1;
        assert!(p[0].commit(hellos).unwrap_err().contains("party 2"));

        // A leader publishes a partial key that does not match the shared seed.
        let mut p = setup(2, 3);
        let hellos: Vec<Hello> = p.iter_mut().map(|x| x.hello().unwrap()).collect();
        let commits: Vec<Commit> = p
            .iter_mut()
            .map(|x| x.commit(hellos.clone()).unwrap())
            .collect();
        let reveals: Vec<Reveal> = p
            .iter_mut()
            .map(|x| x.reveal(commits.clone()).unwrap())
            .collect();
        let mut kc: Vec<KeyCommit> = p
            .iter_mut()
            .map(|x| x.key_commit(reveals.clone()).unwrap())
            .collect();
        kc[0].commitments[0].1[0] ^= 1;
        assert!(p[1].key_reveal(kc).unwrap_err().contains("party 1"));

        // The relay shows one party a different round: its transcript signature gives it away.
        let mut p = setup(2, 3);
        let hellos: Vec<Hello> = p.iter_mut().map(|x| x.hello().unwrap()).collect();
        let commits: Vec<Commit> = p
            .iter_mut()
            .map(|x| x.commit(hellos.clone()).unwrap())
            .collect();
        let reveals: Vec<Reveal> = p
            .iter_mut()
            .map(|x| x.reveal(commits.clone()).unwrap())
            .collect();
        let kc: Vec<KeyCommit> = p
            .iter_mut()
            .map(|x| x.key_commit(reveals.clone()).unwrap())
            .collect();
        let mut altered = commits.clone();
        altered[1].sealed.clear();
        p[2].commits = altered;
        let kr: Vec<KeyReveal> = p
            .iter_mut()
            .map(|x| x.key_reveal(kc.clone()).unwrap())
            .collect();
        let err = p.remove(0).finish(kr).err().unwrap();
        assert!(
            err.contains("party 3 signed a different transcript"),
            "{err}"
        );
    }
}

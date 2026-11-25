//! Restoring one party's share after its machine is lost, without changing the key.
//!
//! Every subset secret is held by `N - T + 1` parties, so whatever one party held, the others
//! hold between them. The party being restored signs a request with its identity key; each
//! helper that agrees seals the subset secrets the two have in common to a fresh X25519 key
//! from that request. The restored party checks every secret against the committee's public
//! per-subset keys, so a helper cannot hand over a wrong one.
//!
//! This is recovery, not refresh. The secrets do not change: a copy of the old share that
//! leaked is still a valid share. If the old machine may have been read by someone else,
//! generate a new key instead.

use super::*;
use ring::rand::SecureRandom;
use threshold_mldsa::fips204::{centered, L, N};

const ETA: i32 = 4;
type SecretWire = Vec<(Subset, Vec<i32>, Vec<i32>)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub index: u8,
    pub committee: Bytes32,
    pub nonce: Bytes32,
    /// One fresh X25519 public key per possible helper.
    pub ephemeral: Vec<(u8, Bytes32)>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub from: u8,
    pub ephemeral: Bytes32,
    pub sealed: Vec<u8>,
    pub signature: Vec<u8>,
}

fn committee_digest(key: &GroupKey) -> Bytes32 {
    hash(&[b"cairn/recover/committee/v1", &key.pk])
}

fn request_bytes(r: &Request) -> Vec<u8> {
    let mut m = b"cairn/recover/request/v1".to_vec();
    m.extend_from_slice(&r.committee);
    m.push(r.index);
    m.extend_from_slice(&r.nonce);
    m.extend_from_slice(&bincode::serialize(&r.ephemeral).expect("keys encode"));
    m
}

fn session(r: &Request) -> Bytes32 {
    hash(&[b"cairn/recover/session/v1", &request_bytes(r), &r.signature])
}

fn reply_bytes(session: &Bytes32, from: u8, ephemeral: &Bytes32, sealed: &[u8]) -> Vec<u8> {
    let mut m = b"cairn/recover/reply/v1".to_vec();
    m.extend_from_slice(session);
    m.push(from);
    m.extend_from_slice(ephemeral);
    m.extend_from_slice(sealed);
    m
}

fn check_committee(roster: &Roster, key: &GroupKey) -> Result<(), String> {
    if roster.threshold as usize != key.params.t || roster.n() != key.params.n {
        return Err("the roster does not describe this committee".into());
    }
    if key.subset_keys.is_empty() {
        return Err("this committee file has no per-subset public keys to check against".into());
    }
    Ok(())
}

fn verify(identity: &Bytes32, message: &[u8], signature: &[u8], who: u8) -> Result<(), String> {
    UnparsedPublicKey::new(&ED25519, identity)
        .verify(message, signature)
        .map_err(|_| format!("signature of party {} does not verify", who + 1))
}

fn fresh_x25519() -> Result<(agreement::EphemeralPrivateKey, Bytes32), String> {
    let key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
        .map_err(|_| "X25519 failed")?;
    let public = key
        .compute_public_key()
        .map_err(|_| "X25519 failed")?
        .as_ref()
        .try_into()
        .map_err(|_| "X25519")?;
    Ok((key, public))
}

/// A helper's side: seal the secrets it shares with the requesting party.
pub fn help(
    identity: &Identity,
    roster: &Roster,
    key: &GroupKey,
    share: &PartyKey,
    request: &Request,
) -> Result<Reply, String> {
    check_committee(roster, key)?;
    let (from, to) = (share.index, request.index);
    if to as usize >= roster.n() || from == to {
        return Err("the request is not from another member of this committee".into());
    }
    if request.committee != committee_digest(key) {
        return Err("the request is for a different committee key".into());
    }
    if roster.identities.get(from as usize) != Some(&identity.public()) {
        return Err("this identity is not the roster's key for this share".into());
    }
    verify(
        &roster.identities[to as usize],
        &request_bytes(request),
        &request.signature,
        to,
    )?;
    let their = request
        .ephemeral
        .iter()
        .find(|(helper, _)| *helper == from)
        .ok_or("the request has no key for this helper")?
        .1;
    let secrets: SecretWire = share
        .subsets()
        .into_iter()
        .filter(|s| s.contains(&to))
        .map(|s| {
            let (s1, s2) = share.secret(&s).expect("listed subset");
            let flat = |v: &PolyVec| v.iter().flatten().copied().collect();
            (s.clone(), flat(s1), flat(s2))
        })
        .collect();
    let session = session(request);
    let (mine, ephemeral) = fresh_x25519()?;
    let mut sealed = bincode::serialize(&secrets).map_err(|e| e.to_string())?;
    agreement::agree_ephemeral(
        mine,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, their),
        |shared| seal_key(shared, &session, from, to),
    )
    .map_err(|_| "key agreement failed")??
    .seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key([0; 12]),
        aead::Aad::from(session),
        &mut sealed,
    )
    .map_err(|_| "sealing failed")?;
    let signature = identity
        .pair
        .sign(&reply_bytes(&session, from, &ephemeral, &sealed))
        .as_ref()
        .to_vec();
    Ok(Reply {
        from,
        ephemeral,
        sealed,
        signature,
    })
}

/// The restoring party's side, alive from request to the last reply: the X25519 private
/// keys exist only in this value.
pub struct Pending {
    request: Request,
    keys: BTreeMap<u8, agreement::EphemeralPrivateKey>,
    got: BTreeMap<Subset, (PolyVec, PolyVec)>,
}

impl Pending {
    pub fn begin(
        identity: &Identity,
        roster: &Roster,
        key: &GroupKey,
        index: u8,
    ) -> Result<(Self, Request), String> {
        check_committee(roster, key)?;
        if roster.identities.get(index as usize) != Some(&identity.public()) {
            return Err("this identity is not the roster's key for that party".into());
        }
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "no randomness")?;
        let (mut keys, mut ephemeral) = (BTreeMap::new(), Vec::new());
        for helper in (0..roster.n() as u8).filter(|h| *h != index) {
            let (private, public) = fresh_x25519()?;
            keys.insert(helper, private);
            ephemeral.push((helper, public));
        }
        let mut request = Request {
            index,
            committee: committee_digest(key),
            nonce,
            ephemeral,
            signature: Vec::new(),
        };
        request.signature = identity
            .pair
            .sign(&request_bytes(&request))
            .as_ref()
            .to_vec();
        let pending = Self {
            request: request.clone(),
            keys,
            got: BTreeMap::new(),
        };
        Ok((pending, request))
    }

    /// Check and keep one helper's secrets. Returns how many subsets are still missing.
    pub fn accept(
        &mut self,
        roster: &Roster,
        key: &GroupKey,
        reply: &Reply,
    ) -> Result<usize, String> {
        let (from, to) = (reply.from, self.request.index);
        let identity = roster
            .identities
            .get(from as usize)
            .filter(|_| from != to)
            .ok_or("reply from outside the committee")?;
        let session = session(&self.request);
        verify(
            identity,
            &reply_bytes(&session, from, &reply.ephemeral, &reply.sealed),
            &reply.signature,
            from,
        )?;
        let mine = self
            .keys
            .remove(&from)
            .ok_or_else(|| format!("party {} already replied", from + 1))?;
        let mut sealed = reply.sealed.clone();
        let opener = agreement::agree_ephemeral(
            mine,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, reply.ephemeral),
            |shared| seal_key(shared, &session, from, to),
        )
        .map_err(|_| "key agreement failed")??;
        let plaintext = opener
            .open_in_place(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(session),
                &mut sealed,
            )
            .map_err(|_| format!("reply from party {} does not decrypt", from + 1))?;
        let secrets: SecretWire = bincode::deserialize(plaintext).map_err(|e| e.to_string())?;
        for (subset, s1, s2) in secrets {
            let wrong = || format!("party {} sent a wrong secret for {subset:?}", from + 1);
            let expected = key.subset_keys.get(&subset).ok_or_else(wrong)?;
            let short = |v: &[i32], polys: usize| {
                v.len() == polys * N && v.iter().all(|c| centered(*c).abs() <= ETA)
            };
            if !subset.contains(&to) || !subset.contains(&from) || !short(&s1, L) || !short(&s2, K)
            {
                return Err(wrong());
            }
            let unflat = |v: &[i32]| -> PolyVec {
                v.chunks(N)
                    .map(|c| c.try_into().expect("whole polynomial"))
                    .collect()
            };
            let secret = (unflat(&s1), unflat(&s2));
            if &mithril::subset_public(&key.rho, &secret) != expected {
                return Err(wrong());
            }
            self.got.insert(subset, secret);
        }
        Ok(self.missing(key).len())
    }

    /// Subsets this party must hold and has not received yet.
    pub fn missing(&self, key: &GroupKey) -> Vec<Subset> {
        mithril::all_subsets(key.params.t, key.params.n)
            .into_iter()
            .filter(|s| s.contains(&self.request.index) && !self.got.contains_key(s))
            .collect()
    }

    pub fn finish(self, key: &GroupKey) -> Result<PartyKey, String> {
        match self.missing(key).len() {
            0 => Ok(PartyKey::from_shares(self.request.index, self.got)),
            n => Err(format!("{n} subset secret(s) still missing")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn committee(t: usize, n: usize) -> (GroupKey, Vec<PartyKey>, Vec<Identity>, Roster) {
        let (key, parties) = mithril::keygen(t, n, &mut OsRng).unwrap();
        let ids: Vec<Identity> = (0..n).map(|_| Identity::generate().unwrap()).collect();
        let roster = Roster {
            threshold: t as u8,
            identities: ids.iter().map(Identity::public).collect(),
        };
        (key, parties, ids, roster)
    }

    #[test]
    fn a_lost_share_is_rebuilt_from_the_other_parties() {
        for (t, n) in [(2, 3), (3, 4), (3, 5)] {
            let (key, parties, ids, roster) = committee(t, n);
            let lost = 1u8;
            let (mut pending, request) = Pending::begin(&ids[1], &roster, &key, lost).unwrap();
            for helper in (0..n).filter(|h| *h != lost as usize) {
                let reply = help(&ids[helper], &roster, &key, &parties[helper], &request).unwrap();
                pending.accept(&roster, &key, &reply).unwrap();
            }
            let rebuilt = pending.finish(&key).unwrap();
            assert_eq!(rebuilt.to_bytes(), parties[1].to_bytes(), "{t}-of-{n}");
        }
    }

    #[test]
    fn forged_requests_and_wrong_secrets_are_refused() {
        let (key, parties, ids, roster) = committee(3, 4);
        let outsider = Identity::generate().unwrap();
        // Someone without party 2's identity key cannot ask for its share.
        assert!(Pending::begin(&outsider, &roster, &key, 1).is_err());
        let (mut pending, request) = Pending::begin(&ids[1], &roster, &key, 1).unwrap();
        let mut forged = request.clone();
        forged.index = 2;
        assert!(help(&ids[0], &roster, &key, &parties[0], &forged).is_err());
        let mut swapped = request.clone();
        swapped.ephemeral[0].1 = [7; 32];
        assert!(help(&ids[0], &roster, &key, &parties[0], &swapped).is_err());

        // A reply that was altered, or made for another request, is refused.
        let good = help(&ids[0], &roster, &key, &parties[0], &request).unwrap();
        let mut altered = good.clone();
        altered.sealed[0] ^= 1;
        assert!(pending.accept(&roster, &key, &altered).is_err());
        let (_, other_request) = Pending::begin(&ids[1], &roster, &key, 1).unwrap();
        let stale = help(&ids[2], &roster, &key, &parties[2], &other_request).unwrap();
        assert!(pending.accept(&roster, &key, &stale).is_err());

        // A helper holding secrets of a different key is caught by the public check.
        let (_, other_parties) = mithril::keygen(3, 4, &mut OsRng).unwrap();
        let wrong = help(&ids[3], &roster, &key, &other_parties[3], &request).unwrap();
        assert!(pending
            .accept(&roster, &key, &wrong)
            .unwrap_err()
            .contains("wrong secret"));

        assert!(pending.accept(&roster, &key, &good).is_ok());
        assert!(pending.accept(&roster, &key, &good).is_err());
        assert!(pending.finish(&key).is_err());
    }
}

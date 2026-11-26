//! Both engines with every party in this process: for tests, demos and benchmarks, and the
//! reference for what a networked signer must do.

use crate::roster::{Roster, RosterError};
use crate::signer::{Backend, SignerError, ThresholdSigner};
use crate::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use cascade_tower::Tower;
use rand::rngs::StdRng;
use rand::SeedableRng;
use threshold_mldsa::mithril::{keygen, sign_local, GroupKey, PartyKey};
use threshold_mldsa::{AttemptEngine, SignPolicy};

/// The three-round protocol among the first `T` parties of an in-process committee.
pub struct LocalFlat {
    key: GroupKey,
    parties: Vec<PartyKey>,
    active: Vec<u8>,
    rng: StdRng,
}

impl LocalFlat {
    /// Deal a fresh key for `roster` (trusted dealer, this process).
    pub fn deal(roster: &Roster) -> Result<Self, RosterError> {
        let (t, n) = roster.flat_shape()?;
        let mut rng = StdRng::from_entropy();
        let (key, parties) = keygen(t, n, &mut rng)
            .ok_or_else(|| RosterError::NotFlat(format!("no parameters for {t}-of-{n}")))?;
        Ok(Self {
            key,
            parties,
            active: (1..=t as u8).collect(),
            rng,
        })
    }
}

impl ThresholdSigner for LocalFlat {
    fn backend(&self) -> Backend {
        Backend::Flat
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.key.pk
    }

    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignerError> {
        sign_local(
            &self.key,
            &self.parties,
            &self.active,
            message,
            &mut self.rng,
        )
        .map(|(signature, _)| signature)
        .ok_or_else(|| SignerError::Failed("no execution produced a signature".into()))
    }
}

/// An in-process tower and its root engine.
pub struct LocalTower<E> {
    pub tower: Tower,
    pub engine: E,
    pub policy: SignPolicy,
}

impl<E: AttemptEngine + Send + 'static> ThresholdSigner for LocalTower<E> {
    fn backend(&self) -> Backend {
        Backend::Tower
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        *self.tower.public_key()
    }

    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignerError> {
        self.tower
            .sign(&mut self.engine, message, &self.policy)
            .map(|signed| signed.signature)
            .map_err(|e| SignerError::Failed(e.to_string()))
    }
}

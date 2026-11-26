//! One interface over every way cairn produces a signature.

use crate::roster::Roster;
use crate::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

/// Which protocol is behind a signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The three-round protocol with replicated short shares. Committees of up to six,
    /// unweighted. Fresh randomness every run: two runs over one message give two different
    /// valid signatures.
    Flat,
    /// The two-tier tower with a root engine. Larger committees, more rounds.
    Tower,
}

impl Backend {
    /// Whether signing one message twice (same key, same signers) gives the same bytes.
    pub fn deterministic(self) -> bool {
        matches!(self, Self::Tower)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::Tower => "tower",
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "flat" => Ok(Self::Flat),
            "tower" => Ok(Self::Tower),
            other => Err(format!("unknown backend {other:?} (flat or tower)")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The operation does not exist for this backend (yet).
    #[error("not supported: {0}")]
    Unsupported(&'static str),
    /// The committee did not produce a signature.
    #[error("{0}")]
    Failed(String),
}

/// A committee that signs. The message is opaque: deciding whether it should be signed is the
/// policy layer's job, on each party, before this is reached.
pub trait ThresholdSigner: Send + 'static {
    fn backend(&self) -> Backend;

    /// The committee's standard ML-DSA-65 public key.
    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES];

    /// One standard ML-DSA-65 signature over `message` (empty context).
    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignerError>;

    /// Move the same key to a new committee, or refresh the current shares. No backend
    /// implements this: refreshing short replicated shares without a dealer is an open
    /// problem (docs/BLOCKERS.md). The method exists so callers have one place to ask.
    fn reshare(&mut self, _next: &Roster) -> Result<(), SignerError> {
        Err(SignerError::Unsupported(
            "share refresh and resharing are not implemented",
        ))
    }
}

impl<S: ThresholdSigner + ?Sized> ThresholdSigner for Box<S> {
    fn backend(&self) -> Backend {
        (**self).backend()
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        (**self).public_key()
    }

    fn sign(&mut self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignerError> {
        (**self).sign(message)
    }

    fn reshare(&mut self, next: &Roster) -> Result<(), SignerError> {
        (**self).reshare(next)
    }
}

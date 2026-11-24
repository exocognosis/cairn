//! Wire messages, the per-attempt context, faults and byte accounting.

use crate::fips204::{self, C_TILDE_BYTES};
use crate::keys::{Active, Path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

pub const WIRE_VERSION: u8 = 1;

/// The four message rounds of one signing attempt, at every tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Round {
    /// Participation: fixes the signing set, hence the Lagrange weights.
    Commitment,
    /// Echo of the opened challenge seed `c~`.
    Challenge,
    /// Hiding commitment to the masked response share `z_p`.
    MaskedResponse,
    /// Verdict; for an accepted attempt the `z_p` openings and the aggregated hint.
    HintCarry,
}

/// Public context of one attempt. Every honest node derives the same value from the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCtx {
    /// Binds key, message, rejection counter and fault-retry counter; fresh per attempt.
    pub session: [u8; 32],
    /// Rejection counter. `kappa = attempt * L`, exactly as in FIPS 204 Algorithm 7.
    pub attempt: u32,
    /// Fault-retry counter (timeouts, blamed signers). Does not advance `kappa`.
    pub retry: u32,
    /// FIPS 204 message representative `mu`.
    pub mu: [u8; 64],
}

impl AttemptCtx {
    pub fn new(pk: &[u8], mu: [u8; 64], attempt: u32, retry: u32) -> Self {
        let mut session = [0u8; 32];
        fips204::shake256(
            &[
                b"cairn/session/v1",
                pk,
                &mu,
                &attempt.to_be_bytes(),
                &retry.to_be_bytes(),
            ],
            &mut session,
        );
        Self {
            session,
            attempt,
            retry,
            mu,
        }
    }

    pub fn header(&self, sender: &[u8]) -> Header {
        Header {
            version: WIRE_VERSION,
            session: self.session,
            attempt: self.attempt,
            retry: self.retry,
            sender: sender.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// No message within the round timeout.
    Timeout(Round),
    /// Participation binding does not match the public seed-share commitment.
    BadBinding,
    /// Echoed `c~` differs from the opened one.
    ChallengeMismatch,
    /// Opened `z_p` does not match its round-3 commitment.
    BadOpening,
    /// Opened `z_p` differs from the value given to the engine.
    OpeningMismatch,
    /// Seed share fails its dealt commitment.
    BadSeedShare,
    /// `(z_p, r_p)` fails the verification-share check.
    InconsistentResponse,
    /// The attempt is inconsistent but no single signer can be named (mask-share deviation).
    Unattributed,
}

/// An abort with, where possible, the signer or committee responsible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fault {
    pub culprit: Option<Path>,
    pub kind: FaultKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub version: u8,
    pub session: [u8; 32],
    pub attempt: u32,
    pub retry: u32,
    /// Tower path of the sender; a committee's own path for tier-level messages.
    pub sender: Path,
}

/// Opening of one signer's masked response share (accepted attempts only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub path: Path,
    /// `z_p`, `L * 256` coefficients mod q.
    pub z: Vec<i32>,
    pub salt: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Commitment {
        header: Header,
        active: Active,
        binding: [u8; 32],
    },
    Challenge {
        header: Header,
        c_tilde: Vec<u8>,
    },
    MaskedResponse {
        header: Header,
        commitments: Vec<(Path, [u8; 32])>,
    },
    HintCarry {
        header: Header,
        accept: bool,
        openings: Vec<Opening>,
        hint: Option<Vec<u16>>,
    },
    Abort {
        header: Header,
        fault: Fault,
    },
}

impl Message {
    pub fn header(&self) -> &Header {
        match self {
            Message::Commitment { header, .. }
            | Message::Challenge { header, .. }
            | Message::MaskedResponse { header, .. }
            | Message::HintCarry { header, .. }
            | Message::Abort { header, .. } => header,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("message encoding cannot fail")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

pub fn c_tilde_from_wire(v: &[u8]) -> Option<[u8; C_TILDE_BYTES]> {
    v.try_into().ok()
}

/// In-memory broadcast channel with a codec round trip and per-sender accounting.
///
/// v1 runs every signer in one process; authentication of `sender` is the transport's job
/// (mTLS peer identity in a deployment) and is out of scope here.
#[derive(Default)]
pub struct Wire {
    /// Bytes each sender put on the broadcast channel (multiply by fan-out for a full mesh).
    pub bytes_sent: BTreeMap<Path, u64>,
    /// Size of each signer's sealed inputs to / outputs from the engine. This is the size of the
    /// values, not the traffic of a real MPC evaluating them.
    pub engine_io_bytes: BTreeMap<Path, u64>,
    pub messages: u64,
    /// Faults a committee absorbed without aborting (members silent at the commitment round).
    pub faults: Vec<Fault>,
    pub timeouts: u32,
    /// Logical time lost waiting for silent parties.
    pub timeout_wait: Duration,
    pub round_timeout: Duration,
    /// Full transcript, kept when `record` is set (tests, audits).
    pub record: bool,
    pub transcript: Vec<Message>,
}

impl Wire {
    pub fn new(round_timeout: Duration) -> Self {
        Self {
            round_timeout,
            ..Self::default()
        }
    }

    /// Broadcast: encode, decode (the receiver's view) and account.
    pub fn broadcast(&mut self, msg: Message) -> Message {
        let bytes = msg.encode();
        let received = Message::decode(&bytes).expect("codec round trip");
        debug_assert_eq!(received, msg);
        *self
            .bytes_sent
            .entry(msg.header().sender.clone())
            .or_default() += bytes.len() as u64;
        self.messages += 1;
        if self.record {
            self.transcript.push(msg);
        }
        received
    }

    pub fn engine_io(&mut self, path: &[u8], bytes: usize) {
        *self.engine_io_bytes.entry(path.to_vec()).or_default() += bytes as u64;
    }

    /// A round closed without a message from some party.
    pub fn timed_out(&mut self) {
        self.timeouts += 1;
        self.timeout_wait += self.round_timeout;
    }
}

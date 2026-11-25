//! Node identities and the framed messages nodes exchange over TCP.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use threshold_mldsa::{Active, AdditiveShare, Path};

pub const NET_VERSION: u8 = 2;
/// Largest accepted frame (a share-check reply carries nine 6 kB values).
pub const MAX_FRAME: usize = 16 << 20;

/// Typed node identity. Text form: `leaf_2/signer_3`, `root_1`, `coordinator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NodeId {
    /// The session coordinator (the process that received the signing request).
    Coordinator,
    Signer {
        leaf: u8,
        signer: u8,
    },
    /// A root MPC engine.
    Root(u8),
    /// A member of a flat committee running the three-round protocol.
    Party(u8),
}

impl NodeId {
    /// Tower path of a signer.
    pub fn path(&self) -> Option<Path> {
        match self {
            NodeId::Signer { leaf, signer } => Some(vec![*leaf, *signer]),
            _ => None,
        }
    }

    pub fn from_path(path: &[u8]) -> Option<Self> {
        match path {
            [leaf, signer] => Some(NodeId::Signer {
                leaf: *leaf,
                signer: *signer,
            }),
            _ => None,
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeId::Coordinator => write!(f, "coordinator"),
            NodeId::Signer { leaf, signer } => write!(f, "leaf_{leaf}/signer_{signer}"),
            NodeId::Root(k) => write!(f, "root_{k}"),
            NodeId::Party(k) => write!(f, "party_{k}"),
        }
    }
}

impl FromStr for NodeId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || {
            format!("bad node id {s:?} (expected leaf_<i>/signer_<j>, root_<k>, party_<k> or coordinator)")
        };
        let num = |t: &str, prefix: &str| {
            t.strip_prefix(prefix)
                .and_then(|n| n.parse::<u8>().ok())
                .filter(|n| *n > 0)
        };
        if s == "coordinator" {
            return Ok(NodeId::Coordinator);
        }
        if let Some(k) = num(s, "root_") {
            return Ok(NodeId::Root(k));
        }
        if let Some(k) = num(s, "party_") {
            return Ok(NodeId::Party(k));
        }
        let (leaf, signer) = s.split_once('/').ok_or_else(bad)?;
        match (num(leaf, "leaf_"), num(signer, "signer_")) {
            (Some(leaf), Some(signer)) => Ok(NodeId::Signer { leaf, signer }),
            _ => Err(bad()),
        }
    }
}

/// Outcome of the response phase as a root engine reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Reject,
    /// Hint positions and the three engines' `z_k`, all opened by the MPC backend.
    Accept {
        hint: Vec<u16>,
        z: Vec<Vec<i32>>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    // Requests.
    /// Round 1 (commitment): announce the message, ask who takes part.
    Prepare {
        message: Vec<u8>,
    },
    /// To an active signer: flatten your share for `active` and send sub-shares to `roots`.
    Deal {
        active: Active,
        roots: Vec<u8>,
    },
    /// Signer to root engine, point to point: one additive sub-share.
    SubShare {
        path: Path,
        share: AdditiveShare,
    },
    /// To a root engine: sum the sub-shares and publish the per-signer check values.
    Collect {
        active: Active,
    },
    /// To a root engine: its MPC party slot and the three engines' verification shares.
    Install {
        slot: u8,
        verification: Vec<Vec<i32>>,
    },
    /// Round 2 (challenge): run the mask phase for `attempt`, report the opened `c~`.
    Mask {
        attempt: u32,
    },
    /// Rounds 3 and 4 (masked response, hint/carry): run the response phase, report the verdict.
    Finish,
    /// Drop the session and erase its state.
    Abort,
    /// Three-round protocol, round 1, ahead of any request: sample masks and commit to them.
    Presign,
    /// Round 2: sign `message` with the masks committed as `presign`; here are everyone's
    /// commitments; reveal your `w` values.
    M2 {
        message: Vec<u8>,
        presign: [u8; 32],
        commitments: Vec<(u8, [u8; 32])>,
    },
    /// Round 3: here are the other parties' `w` values (packed, 23 bits per coefficient; the
    /// recipient already has its own); answer where your rejection test passes.
    M3 {
        revealed: Vec<(u8, Vec<Vec<u8>>)>,
    },

    // Replies.
    Ready {
        binding: [u8; 32],
    },
    PresignCommit {
        id: [u8; 32],
        commitment: [u8; 32],
    },
    M2Reveal {
        w: Vec<Vec<u8>>,
    },
    /// One entry per parallel repetition: `z1`, or `None` where the party's test rejected.
    M3Response {
        z: Vec<Option<Vec<u8>>>,
    },
    Dealt {
        p2p_bytes: u64,
    },
    /// A signer could not deliver a sub-share to this root engine.
    DealFailed {
        root: u8,
    },
    Ack,
    /// `A a1 + a2` of each received sub-share, by signer path; `missing` lists absent ones.
    ShareCheck {
        values: Vec<(Path, Vec<i32>)>,
        missing: Vec<Path>,
    },
    Installed,
    Challenge {
        c_tilde: Vec<u8>,
    },
    Verdict(Outcome),
    /// The party's own signing policy refuses this message. Not a fault of the party.
    PolicyRefused {
        reason: String,
    },
    /// The node will not do this (policy, unknown session, malformed request).
    Refused {
        reason: String,
    },
    /// The MPC backend reported a fault. `party` is a slot number when `blame` is set.
    BackendFault {
        blame: bool,
        party: u8,
        message: String,
    },
}

impl Body {
    pub fn kind(&self) -> &'static str {
        match self {
            Body::Prepare { .. } => "Prepare",
            Body::Deal { .. } => "Deal",
            Body::SubShare { .. } => "SubShare",
            Body::Collect { .. } => "Collect",
            Body::Install { .. } => "Install",
            Body::Mask { .. } => "Mask",
            Body::Finish => "Finish",
            Body::Abort => "Abort",
            Body::Presign => "Presign",
            Body::M2 { .. } => "M2",
            Body::M3 { .. } => "M3",
            Body::PresignCommit { .. } => "PresignCommit",
            Body::M2Reveal { .. } => "M2Reveal",
            Body::M3Response { .. } => "M3Response",
            Body::Ready { .. } => "Ready",
            Body::Dealt { .. } => "Dealt",
            Body::DealFailed { .. } => "DealFailed",
            Body::Ack => "Ack",
            Body::ShareCheck { .. } => "ShareCheck",
            Body::Installed => "Installed",
            Body::Challenge { .. } => "Challenge",
            Body::Verdict(_) => "Verdict",
            Body::Refused { .. } => "Refused",
            Body::PolicyRefused { .. } => "PolicyRefused",
            Body::BackendFault { .. } => "BackendFault",
        }
    }
}

/// One message on the wire: `u32` big-endian length, then this struct in `bincode`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub version: u8,
    pub from: NodeId,
    pub to: NodeId,
    pub session: [u8; 32],
    pub body: Body,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids_round_trip_as_text() {
        for id in [
            NodeId::Coordinator,
            NodeId::Root(3),
            NodeId::Signer { leaf: 2, signer: 4 },
        ] {
            assert_eq!(id.to_string().parse::<NodeId>().unwrap(), id);
        }
        assert_eq!(
            NodeId::Signer { leaf: 1, signer: 2 }.to_string(),
            "leaf_1/signer_2"
        );
        assert_eq!("root_4".parse::<NodeId>().unwrap(), NodeId::Root(4));
        for bad in ["leaf_1", "leaf_0/signer_1", "root_x", "signer_1/leaf_1", ""] {
            assert!(bad.parse::<NodeId>().is_err(), "{bad}");
        }
        assert_eq!(
            NodeId::from_path(&[3, 1]),
            Some(NodeId::Signer { leaf: 3, signer: 1 })
        );
    }
}

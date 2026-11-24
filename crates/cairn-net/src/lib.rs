//! Multi-process execution of the cairn tower over TCP.
//!
//! * [`wire`]: typed node identities (`leaf_i/signer_j`, `root_k`) and framed messages.
//! * [`transport`]: length-prefixed frames over `tokio::net` with wall-clock deadlines.
//! * [`node`]: signer nodes and root MPC engine nodes.
//! * [`coordinator`]: the session driver (share compression, attempts, fault retries).
//! * [`cluster`]: address books, key files, and an in-process cluster for tests.

pub mod cluster;
pub mod coordinator;
pub mod node;
pub mod transport;
pub mod wire;

pub use coordinator::{Coordinator, NetError, NetFault, NetFaultKind, NetPolicy, NetReport};
pub use node::{FaultMode, Peers, RootNode, SignerNode, CHECKPOINT_DOMAIN};
pub use transport::{CallError, Link};
pub use wire::{Body, Frame, NodeId};

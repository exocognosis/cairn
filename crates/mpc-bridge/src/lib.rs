//! IPC bridge to the three-party MPC backend for the non-linear half of an ML-DSA attempt.
//!
//! * [`ipc`]: the wire protocol (Unix domain sockets, length-prefixed binary frames).
//! * [`client`]: [`PartyClient`] for one party port, and [`IpcEngine`], which puts the bridge
//!   behind `threshold_mldsa::AttemptEngine`.
//! * [`worker`]: a clear-text reference worker speaking the same protocol, as a library and as
//!   the `cairn-mpc-worker` process. Not a secure computation.
//!
//! The MP-SPDZ program and its launcher live under `mpc/mp-spdz/` in the repository root.

pub mod client;
pub mod ipc;
pub mod worker;

pub use client::{hint_from_positions, IpcEngine, PartyClient};
pub use ipc::{MaskRequest, Reply, Request, ResponseRequest, PARTIES};
pub use worker::{serve, socket_path, Worker};

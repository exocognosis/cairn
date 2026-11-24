//! Leaf-committee threshold ML-DSA-65 (FIPS 204) signing.
//!
//! A `t`-of-`n` committee with `n <= 6` produces one standard 3,309-byte ML-DSA-65 signature.
//! The mask is the exact FIPS 204 `ExpandMask` output, so the result is byte-identical to what a
//! single deterministic signer holding the whole key would produce.
//!
//! Linear share arithmetic runs in the signers ([`party`]); everything non-linear runs behind
//! the MPC boundary ([`engine`]). v1 ships only an in-process ideal functionality for that
//! boundary: read the status section of the README before relying on anything here.

pub mod engine;
pub mod fips204;
pub mod flatten;
pub mod keys;
pub mod mithril;
pub mod party;
pub mod protocol;
pub mod session;

pub use engine::{AttemptEngine, TrustedEngine};
pub use fips204::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
pub use flatten::AdditiveShare;
pub use keys::{deal, Active, Gadget, GroupPublic, KeyShare, Path, ShapeError, MAX_COMMITTEE};
pub use party::{Behavior, Committee, Party, Signer};
pub use protocol::{Fault, FaultKind, Message, Round, Wire};
pub use session::{sign, SignError, SignPolicy, SignReport, Signed};

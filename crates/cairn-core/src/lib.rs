//! The shared signing kernel.
//!
//! Everything above this crate (what may be signed, who is on the committee, how clients ask
//! for a signature) differs between deployments. What is underneath does not: `T` of `N`
//! parties jointly produce one standard ML-DSA-65 signature and the private key is never
//! assembled. This crate is that common part, and it knows nothing about blocks, heights,
//! chains, cloud APIs or approval workflows:
//!
//! * [`ThresholdSigner`]: bytes in, a 3,309-byte FIPS 204 signature out. Both engines sit
//!   behind it ([`Backend::Flat`], the three-round protocol for committees of up to six, and
//!   [`Backend::Tower`], the two-tier tower with a root engine), as do the networked
//!   coordinators built on them in other crates.
//! * [`Roster`] and [`RosterProvider`]: who is on the committee, with weights, wherever that
//!   list comes from.
//! * [`verify`]: the standard FIPS 204 check.

pub mod local;
pub mod roster;
pub mod signer;

pub use local::{LocalFlat, LocalTower};
pub use roster::{FileRoster, Member, Roster, RosterError, RosterProvider, StaticRoster};
pub use signer::{Backend, SignerError, ThresholdSigner};
pub use threshold_mldsa::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

/// Standard ML-DSA-65 verification (empty context), as any FIPS 204 verifier does it.
pub fn verify(public_key: &[u8; PUBLIC_KEY_BYTES], message: &[u8], signature: &[u8]) -> bool {
    <[u8; SIGNATURE_BYTES]>::try_from(signature)
        .is_ok_and(|s| threshold_mldsa::fips204::verify_standard(public_key, message, &s))
}

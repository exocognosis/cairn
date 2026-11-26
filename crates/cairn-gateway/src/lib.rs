//! Front ends: how clients ask a cairn signer for a signature.
//!
//! A front end takes any [`cairn_core::ThresholdSigner`] and speaks one client protocol. It
//! does not know which engine is behind the signer or what policy the parties run.
//!
//! * [`kms`]: the two AWS KMS JSON calls pqc-sidecar's `aws_kms` backend makes, with optional
//!   SigV4 request authentication ([`sigv4`]).

pub mod kms;
pub mod sigv4;

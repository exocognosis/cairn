//! Committee tower: small threshold ML-DSA committees composed hierarchically.
//!
//! One dishonest-majority MPC stops being practical at about six parties. A tower keeps every
//! interactive committee at or under that size and reaches more signers by nesting: 16 signers
//! as four 3-of-4 leaf committees under a 3-of-4 root. The corruption bounds of the composition
//! are the read-once threshold-tree theorems of the `CertTowers` Lean 4 library ([`params`]).

pub mod assignment;
pub mod params;
pub mod tower;

pub use assignment::{assign, AssignError, Assignment, Exposure, Validator};
pub use params::{binomial_tail, TowerParams};
pub use tower::{LeafCommittee, Tower, TowerError};

//! What a party agrees to sign.
//!
//! This is the one place deployments differ in substance. The signing kernel treats a message
//! as opaque bytes; before a party reveals anything for it, the party asks its own
//! [`PolicyEngine`]. The coordinator relays requests and is not trusted to choose.
//!
//! * [`PosCheckpointPolicy`] ([`pos`]): proof-of-stake checkpoints. The message must be a
//!   well-formed pqc-sidecar checkpoint for this committee's key, and never conflict with one
//!   already signed.
//! * [`Unrestricted`]: signs anything. For tests, and for deployments that enforce their rules
//!   somewhere the parties trust. It protects nothing by itself.
//!
//! An organization's rules (approvals, limits, roles) are another implementation of the same
//! trait; none ships yet.

pub mod pos;

pub use pos::PosCheckpointPolicy;

/// What a party knows about a signing request besides the payload.
#[derive(Debug, Clone, Copy)]
pub struct SignContext<'a> {
    /// The signing session's identifier.
    pub session: &'a [u8; 32],
    /// This party's index in the committee.
    pub party: u8,
    /// The indices asked to sign together, this party included.
    pub signers: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The policy will not sign this payload. The reason is sent back to the coordinator.
    #[error("{0}")]
    Refused(String),
}

/// A party's own decision on a signing request. On `Ok` the decision must already be durable
/// if it constrains later ones: the party reveals its secret-dependent values right after.
pub trait PolicyEngine: Send + Sync + 'static {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError>;
}

impl<P: PolicyEngine + ?Sized> PolicyEngine for Box<P> {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError> {
        (**self).authorize_sign(ctx, payload)
    }
}

/// Signs any payload.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unrestricted;

impl PolicyEngine for Unrestricted {
    fn authorize_sign(&self, _ctx: &SignContext, _payload: &[u8]) -> Result<(), PolicyError> {
        Ok(())
    }
}

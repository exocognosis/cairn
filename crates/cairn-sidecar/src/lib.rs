//! Adapter between the cairn committee tower and PQC Sidecar.
//!
//! Two integration paths, neither of which changes pqc-sidecar or its verifiers:
//!
//! * [`TowerCertifier`] builds `.pqcc` v2 certificates directly ([`certificate`] implements
//!   pqc-sidecar's `FORMAT.md`), for embedding the tower in a daemon.
//! * [`kms::serve`] exposes the tower behind the KMS API pqc-sidecar's `aws_kms` signer backend
//!   already speaks, so a stock pqc-sidecar signs through the tower by configuration alone.

pub mod bench;
pub mod certificate;
pub mod certifier;
pub mod cluster;
pub mod kms;

pub use certificate::{key_id, Certificate, CertificateError, Checkpoint};
pub use certifier::{
    write_certificate, write_public_key, CertifierConfig, CertifyError, TowerCertifier,
};

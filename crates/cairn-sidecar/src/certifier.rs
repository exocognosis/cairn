//! Tower-backed checkpoint certifier: the piece that stands where pqc-sidecar's single-key
//! signer stands.

use crate::certificate::{key_id, Certificate, CertificateError, Checkpoint};
use cascade_tower::Tower;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use threshold_mldsa::{AttemptEngine, SignError, SignPolicy, SignReport, Signed, PUBLIC_KEY_BYTES};

#[derive(Debug, Clone)]
pub struct CertifierConfig {
    /// Certify every `K`-th finalized height. The tower targets checkpoint cadence, not
    /// per-block signing; `certify` refuses other heights.
    pub checkpoint_interval: u64,
    /// Bring excluded signers back every this many signatures (0: never).
    pub reinstate_every: u64,
    pub policy: SignPolicy,
}

impl Default for CertifierConfig {
    fn default() -> Self {
        Self {
            checkpoint_interval: 100,
            reinstate_every: 16,
            policy: SignPolicy::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CertifyError {
    #[error("height {height} is not a checkpoint (interval {interval})")]
    NotCheckpoint { height: u64, interval: u64 },
    #[error(transparent)]
    Certificate(#[from] CertificateError),
    #[error(transparent)]
    Sign(#[from] SignError),
}

pub struct TowerCertifier<E> {
    tower: Tower,
    engine: E,
    config: CertifierConfig,
    key_id: [u8; 32],
    signed: u64,
}

impl<E: AttemptEngine> TowerCertifier<E> {
    pub fn new(tower: Tower, engine: E, config: CertifierConfig) -> Self {
        let key_id = key_id(tower.public_key());
        Self {
            tower,
            engine,
            config,
            key_id,
            signed: 0,
        }
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        self.tower.public_key()
    }

    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    pub fn tower_mut(&mut self) -> &mut Tower {
        &mut self.tower
    }

    pub fn is_checkpoint(&self, height: u64) -> bool {
        self.config.checkpoint_interval != 0 && height % self.config.checkpoint_interval == 0
    }

    /// One tower signature over arbitrary bytes (empty context), verified before return.
    pub fn sign_message(&mut self, message: &[u8]) -> Result<Signed, SignError> {
        if self.config.reinstate_every != 0 && self.signed % self.config.reinstate_every == 0 {
            self.tower.reinstate();
        }
        self.signed += 1;
        self.tower
            .sign(&mut self.engine, message, &self.config.policy)
    }

    /// Certify a finalized checkpoint. The caller is responsible for finality: hand this only
    /// blocks pqc-sidecar's chain adapter (or equivalent) has verified as final.
    pub fn certify(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> Result<(Certificate, SignReport), CertifyError> {
        if !self.is_checkpoint(checkpoint.height) {
            return Err(CertifyError::NotCheckpoint {
                height: checkpoint.height,
                interval: self.config.checkpoint_interval,
            });
        }
        let message = checkpoint.signing_message(&self.key_id)?;
        let Signed { signature, report } = self.sign_message(&message)?;
        let certificate = Certificate {
            checkpoint: checkpoint.clone(),
            key_id: self.key_id,
            signature: Box::new(signature),
        };
        certificate.verify(self.tower.public_key())?;
        Ok((certificate, report))
    }
}

/// Write `<dir>/<height:020>.pqcc` atomically. Never overwrites an existing certificate.
pub fn write_certificate(dir: &Path, certificate: &Certificate) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(certificate.file_name());
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            path.display().to_string(),
        ));
    }
    let bytes = certificate
        .to_bytes()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = dir.join(format!(".{}.tmp", certificate.file_name()));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Write the public key as hex, the form `pqc-sidecar verify --public-key` reads.
pub fn write_public_key(path: &Path, pk: &[u8; PUBLIC_KEY_BYTES]) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", hex::encode(pk)))
}

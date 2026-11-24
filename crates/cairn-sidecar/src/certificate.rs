//! `.pqcc` certificate format, version 2, as defined normatively by pqc-sidecar's `FORMAT.md`.
//!
//! pqc-sidecar is a binary crate, so the encoding is implemented here from that document. The
//! integration tests check the result against the unmodified `pqc-sidecar verify` and the
//! `pqc-sidecar-verify` npm package, so any drift from the format fails the build.

use sha3::{Digest, Sha3_256};
use threshold_mldsa::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};

pub const CHECKPOINT_DOMAIN: &[u8] = b"pqc-sidecar/checkpoint/v2";
pub const KEY_ID_DOMAIN: &[u8] = b"pqc-sidecar/key-id/v2";
pub const MAGIC: &[u8; 4] = b"PQCC";
pub const FORMAT_VERSION: u8 = 2;
pub const FILE_EXTENSION: &str = "pqcc";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CertificateError {
    #[error("chain id is not CAIP-2")]
    BadChain,
    #[error("block hash must be 1 to 64 bytes")]
    BadBlockHash,
    #[error("finality commitment must be at most 64 bytes")]
    BadCommitment,
    #[error("malformed certificate: {0}")]
    Malformed(&'static str),
    #[error("key id does not match the public key")]
    KeyMismatch,
    #[error("signature does not verify")]
    BadSignature,
}

/// CAIP-2: `[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}`.
pub fn is_caip2(s: &str) -> bool {
    let Some((ns, reference)) = s.split_once(':') else {
        return false;
    };
    (3..=8).contains(&ns.len())
        && ns
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit())
        && (1..=32).contains(&reference.len())
        && reference
            .bytes()
            .all(|b| b == b'-' || b == b'_' || b.is_ascii_alphanumeric())
}

/// `SHA3-256("pqc-sidecar/key-id/v2" || pk)`.
pub fn key_id(pk: &[u8; PUBLIC_KEY_BYTES]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(KEY_ID_DOMAIN);
    h.update(pk);
    h.finalize().into()
}

/// A finalized block to attest to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// CAIP-2 chain id, e.g. `cosmos:cosmoshub-4`.
    pub chain: String,
    pub epoch: u64,
    pub height: u64,
    pub block_hash: Vec<u8>,
    pub finality_commitment: Vec<u8>,
}

impl Checkpoint {
    fn validate(&self) -> Result<(), CertificateError> {
        if !is_caip2(&self.chain) {
            return Err(CertificateError::BadChain);
        }
        if self.block_hash.is_empty() || self.block_hash.len() > 64 {
            return Err(CertificateError::BadBlockHash);
        }
        if self.finality_commitment.len() > 64 {
            return Err(CertificateError::BadCommitment);
        }
        Ok(())
    }

    fn body(&self, out: &mut Vec<u8>) {
        out.push(self.chain.len() as u8);
        out.extend_from_slice(self.chain.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.push(self.block_hash.len() as u8);
        out.extend_from_slice(&self.block_hash);
        out.push(self.finality_commitment.len() as u8);
        out.extend_from_slice(&self.finality_commitment);
    }

    /// The exact bytes the tower signs.
    pub fn signing_message(&self, key_id: &[u8; 32]) -> Result<Vec<u8>, CertificateError> {
        self.validate()?;
        let mut m = CHECKPOINT_DOMAIN.to_vec();
        self.body(&mut m);
        m.extend_from_slice(key_id);
        Ok(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub checkpoint: Checkpoint,
    pub key_id: [u8; 32],
    pub signature: Box<[u8; SIGNATURE_BYTES]>,
}

impl Certificate {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CertificateError> {
        self.checkpoint.validate()?;
        let mut out = MAGIC.to_vec();
        out.push(FORMAT_VERSION);
        self.checkpoint.body(&mut out);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(self.signature.as_slice());
        Ok(out)
    }

    /// Strict decode: wrong magic, version, lengths, truncation and trailing bytes are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CertificateError> {
        struct Reader<'a>(&'a [u8]);
        impl<'a> Reader<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], CertificateError> {
                if self.0.len() < n {
                    return Err(CertificateError::Malformed("truncated"));
                }
                let (head, tail) = self.0.split_at(n);
                self.0 = tail;
                Ok(head)
            }
            fn u8(&mut self) -> Result<u8, CertificateError> {
                Ok(self.take(1)?[0])
            }
            fn u64(&mut self) -> Result<u64, CertificateError> {
                Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
            }
        }
        let mut r = Reader(bytes);
        if r.take(4)? != MAGIC {
            return Err(CertificateError::Malformed("magic"));
        }
        if r.u8()? != FORMAT_VERSION {
            return Err(CertificateError::Malformed("version"));
        }
        let chain_len = r.u8()? as usize;
        let chain = String::from_utf8(r.take(chain_len)?.to_vec())
            .map_err(|_| CertificateError::BadChain)?;
        let epoch = r.u64()?;
        let height = r.u64()?;
        let hash_len = r.u8()? as usize;
        let block_hash = r.take(hash_len)?.to_vec();
        let commitment_len = r.u8()? as usize;
        let finality_commitment = r.take(commitment_len)?.to_vec();
        let key_id = r.take(32)?.try_into().unwrap();
        let signature = Box::new(r.take(SIGNATURE_BYTES)?.try_into().unwrap());
        if !r.0.is_empty() {
            return Err(CertificateError::Malformed("trailing bytes"));
        }
        let checkpoint = Checkpoint {
            chain,
            epoch,
            height,
            block_hash,
            finality_commitment,
        };
        checkpoint.validate()?;
        Ok(Self {
            checkpoint,
            key_id,
            signature,
        })
    }

    /// Valid iff the key id matches `pk` and the signature is a FIPS 204 ML-DSA-65 signature
    /// over the signing message (empty context).
    pub fn verify(&self, pk: &[u8; PUBLIC_KEY_BYTES]) -> Result<(), CertificateError> {
        if self.key_id != key_id(pk) {
            return Err(CertificateError::KeyMismatch);
        }
        let m = self.checkpoint.signing_message(&self.key_id)?;
        if threshold_mldsa::fips204::verify_standard(pk, &m, &self.signature) {
            Ok(())
        } else {
            Err(CertificateError::BadSignature)
        }
    }

    /// `<height, 20 digits>.pqcc`, the name pqc-sidecar gives its certificates.
    pub fn file_name(&self) -> String {
        format!("{:020}.{FILE_EXTENSION}", self.checkpoint.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caip2_rules() {
        assert!(is_caip2("cosmos:cosmoshub-4") && is_caip2("eip155:1"));
        for bad in [
            "cosmoshub-4",
            "co:x",
            "Cosmos:x",
            "cosmos:",
            "cosmos:a b",
            "toolongnamespace:x",
        ] {
            assert!(!is_caip2(bad), "{bad}");
        }
    }

    #[test]
    fn strict_decode() {
        let c = Certificate {
            checkpoint: Checkpoint {
                chain: "cosmos:test-1".into(),
                epoch: 3,
                height: 1200,
                block_hash: vec![7; 32],
                finality_commitment: vec![9; 32],
            },
            key_id: [5; 32],
            signature: Box::new([1; SIGNATURE_BYTES]),
        };
        let bytes = c.to_bytes().unwrap();
        assert_eq!(
            bytes.len(),
            4 + 1 + 1 + 13 + 8 + 8 + 1 + 32 + 1 + 32 + 32 + SIGNATURE_BYTES
        );
        assert_eq!(Certificate::from_bytes(&bytes).unwrap(), c);
        assert!(Certificate::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Certificate::from_bytes(&[bytes.clone(), vec![0]].concat()).is_err());
        let mut v1 = bytes.clone();
        v1[4] = 1;
        assert_eq!(
            Certificate::from_bytes(&v1),
            Err(CertificateError::Malformed("version"))
        );
        assert_eq!(c.file_name(), "00000000000000001200.pqcc");
    }
}

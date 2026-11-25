//! What a party agrees to sign, decided by the party itself.
//!
//! The coordinator relays requests but is not trusted to choose what gets signed. Before a
//! party reveals anything for a message it checks, on its own:
//!
//! * the message is a well-formed pqc-sidecar checkpoint (`FORMAT.md`, version 2);
//! * it names this committee's key;
//! * its chain is one this party was configured to serve, if a list was given;
//! * it does not conflict with what this party has already signed: never a lower height than
//!   the last one on that chain, and never a different checkpoint at the same height.
//!
//! The last rule is kept in a small state file written before the party answers, so it holds
//! across restarts. With `T` honest-rule-following parties out of `T` needed, two conflicting
//! checkpoints for one height cannot both be signed.

use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;

pub const CHECKPOINT_DOMAIN: &[u8] = b"pqc-sidecar/checkpoint/v2";
const KEY_ID_DOMAIN: &[u8] = b"pqc-sidecar/key-id/v2";

/// `SHA3-256("pqc-sidecar/key-id/v2" || pk)`.
pub fn key_id(pk: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(KEY_ID_DOMAIN);
    h.update(pk);
    h.finalize().into()
}

/// The fields of a checkpoint signing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub chain: String,
    pub epoch: u64,
    pub height: u64,
    pub block_hash: Vec<u8>,
    pub finality_commitment: Vec<u8>,
    pub key_id: [u8; 32],
}

impl Checkpoint {
    /// The exact bytes that are signed.
    pub fn message(&self) -> Vec<u8> {
        let mut m = CHECKPOINT_DOMAIN.to_vec();
        m.push(self.chain.len() as u8);
        m.extend_from_slice(self.chain.as_bytes());
        m.extend_from_slice(&self.epoch.to_be_bytes());
        m.extend_from_slice(&self.height.to_be_bytes());
        m.push(self.block_hash.len() as u8);
        m.extend_from_slice(&self.block_hash);
        m.push(self.finality_commitment.len() as u8);
        m.extend_from_slice(&self.finality_commitment);
        m.extend_from_slice(&self.key_id);
        m
    }

    /// Strict parse: exact domain, lengths in range, no trailing bytes.
    pub fn parse(message: &[u8]) -> Option<Self> {
        let mut rest = message.strip_prefix(CHECKPOINT_DOMAIN)?;
        let mut take = |n: usize| -> Option<&[u8]> {
            let (head, tail) = (rest.get(..n)?, rest.get(n..)?);
            rest = tail;
            Some(head)
        };
        let chain_len = take(1)?[0] as usize;
        let chain = std::str::from_utf8(take(chain_len)?).ok()?.to_owned();
        let epoch = u64::from_be_bytes(take(8)?.try_into().ok()?);
        let height = u64::from_be_bytes(take(8)?.try_into().ok()?);
        let hash_len = take(1)?[0] as usize;
        let block_hash = take(hash_len)?.to_vec();
        let commitment_len = take(1)?[0] as usize;
        let finality_commitment = take(commitment_len)?.to_vec();
        let key_id: [u8; 32] = take(32)?.try_into().ok()?;
        let caip2 = chain.split_once(':').is_some_and(|(ns, reference)| {
            (3..=8).contains(&ns.len())
                && ns
                    .bytes()
                    .all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit())
                && (1..=32).contains(&reference.len())
                && reference
                    .bytes()
                    .all(|b| b == b'-' || b == b'_' || b.is_ascii_alphanumeric())
        });
        (rest.is_empty() && caip2 && (1..=64).contains(&hash_len) && commitment_len <= 64)
            .then_some(Self {
                chain,
                epoch,
                height,
                block_hash,
                finality_commitment,
                key_id,
            })
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyConfig {
    /// CAIP-2 chain ids this party serves. `None`: any chain.
    pub chains: Option<Vec<String>>,
    /// Where the last signed checkpoint per chain is kept. `None`: memory only, lost on restart.
    pub state_file: Option<PathBuf>,
    /// Append-only log of every decision, one JSON object per line.
    pub audit_log: Option<PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One party's signing policy and its memory of what it has signed.
pub struct Policy {
    key_id: [u8; 32],
    config: PolicyConfig,
    /// Per chain: last signed height and the digest of the message signed there.
    last: BTreeMap<String, (u64, String)>,
}

impl Policy {
    /// Load (or start) the policy state for the committee key `pk`.
    pub fn open(pk: &[u8], config: PolicyConfig) -> std::io::Result<Self> {
        let last = match &config.state_file {
            Some(path) if path.exists() => {
                serde_json::from_slice(&std::fs::read(path)?).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("{}: {e}", path.display()),
                    )
                })?
            }
            _ => BTreeMap::new(),
        };
        Ok(Self {
            key_id: key_id(pk),
            config,
            last,
        })
    }

    /// In-memory policy with no chain restriction (tests, throwaway committees).
    pub fn ephemeral(pk: &[u8]) -> Self {
        Self {
            key_id: key_id(pk),
            config: PolicyConfig::default(),
            last: BTreeMap::new(),
        }
    }

    fn audit(
        &self,
        event: &str,
        session: &[u8; 32],
        checkpoint: Option<&Checkpoint>,
        detail: &str,
    ) {
        let Some(path) = &self.config.audit_log else {
            return;
        };
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let line = serde_json::json!({
            "time": time,
            "event": event,
            "session": hex(&session[..8]),
            "chain": checkpoint.map(|c| c.chain.clone()),
            "epoch": checkpoint.map(|c| c.epoch),
            "height": checkpoint.map(|c| c.height),
            "block_hash": checkpoint.map(|c| hex(&c.block_hash)),
            "detail": detail,
        });
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.config.state_file else {
            return Ok(());
        };
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(&self.last).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    }

    /// Decide whether to sign `message`. On `Ok`, the decision is already recorded (and on
    /// disk, if a state file is configured): the party may reveal its openings.
    pub fn authorize(&mut self, message: &[u8], session: &[u8; 32]) -> Result<Checkpoint, String> {
        let refuse = |policy: &Self, checkpoint: Option<&Checkpoint>, reason: &str| {
            policy.audit("refused", session, checkpoint, reason);
            Err(reason.to_owned())
        };
        let Some(checkpoint) = Checkpoint::parse(message) else {
            return refuse(self, None, "not a well-formed checkpoint message");
        };
        if checkpoint.key_id != self.key_id {
            return refuse(self, Some(&checkpoint), "checkpoint names another key");
        }
        if self
            .config
            .chains
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&checkpoint.chain))
        {
            return refuse(self, Some(&checkpoint), "chain is not served by this party");
        }
        let digest = hex(&Sha3_256::digest(message));
        match self.last.get(&checkpoint.chain) {
            Some((height, _)) if checkpoint.height < *height => {
                return refuse(
                    self,
                    Some(&checkpoint),
                    "height is below the last signed height",
                );
            }
            Some((height, signed)) if checkpoint.height == *height && *signed != digest => {
                return refuse(
                    self,
                    Some(&checkpoint),
                    "a different checkpoint was already signed at this height",
                );
            }
            Some((height, _)) if checkpoint.height == *height => {}
            _ => {
                self.last
                    .insert(checkpoint.chain.clone(), (checkpoint.height, digest));
                if let Err(e) = self.persist() {
                    self.last.remove(&checkpoint.chain);
                    return refuse(
                        self,
                        Some(&checkpoint),
                        &format!("cannot record the decision: {e}"),
                    );
                }
            }
        }
        self.audit("authorized", session, Some(&checkpoint), "");
        Ok(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(pk: &[u8], chain: &str, height: u64, hash: u8) -> Vec<u8> {
        Checkpoint {
            chain: chain.into(),
            epoch: 1,
            height,
            block_hash: vec![hash; 32],
            finality_commitment: vec![7; 32],
            key_id: key_id(pk),
        }
        .message()
    }

    #[test]
    fn messages_round_trip_and_malformed_ones_are_refused() {
        let m = checkpoint(b"pk", "cosmos:hub-4", 100, 1);
        let c = Checkpoint::parse(&m).unwrap();
        assert_eq!(
            (c.chain.as_str(), c.height, c.message()),
            ("cosmos:hub-4", 100, m.clone())
        );
        assert!(Checkpoint::parse(&m[..m.len() - 1]).is_none());
        assert!(Checkpoint::parse(&[m.clone(), vec![0]].concat()).is_none());
        assert!(Checkpoint::parse(b"pqc-sidecar/checkpoint/v2 anything").is_none());
        assert!(Checkpoint::parse(&checkpoint(b"pk", "NotCaip2", 1, 1)).is_none());
    }

    #[test]
    fn no_conflicting_or_older_checkpoint_is_signed_even_after_a_restart() {
        let dir = std::env::temp_dir().join(format!("cairn-policy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = PolicyConfig {
            chains: Some(vec!["cosmos:hub-4".into()]),
            state_file: Some(dir.join("state.json")),
            audit_log: Some(dir.join("audit.log")),
        };
        let s = [0u8; 32];
        let mut policy = Policy::open(b"pk", config.clone()).unwrap();
        assert!(policy
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 100, 1), &s)
            .is_ok());
        // The same checkpoint again (a retry) is fine; a different one at that height is not.
        assert!(policy
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 100, 1), &s)
            .is_ok());
        assert!(policy
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 100, 2), &s)
            .is_err());
        assert!(policy
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 200, 1), &s)
            .is_ok());
        assert!(
            policy
                .authorize(&checkpoint(b"pk", "cosmos:hub-4", 100, 1), &s)
                .is_err(),
            "older height"
        );
        // Other key, other chain.
        assert!(policy
            .authorize(&checkpoint(b"other", "cosmos:hub-4", 300, 1), &s)
            .is_err());
        assert!(policy
            .authorize(&checkpoint(b"pk", "cosmos:other-1", 300, 1), &s)
            .is_err());
        // A restarted party remembers.
        let mut restarted = Policy::open(b"pk", config).unwrap();
        assert!(restarted
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 200, 9), &s)
            .is_err());
        assert!(restarted
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 150, 1), &s)
            .is_err());
        assert!(restarted
            .authorize(&checkpoint(b"pk", "cosmos:hub-4", 201, 1), &s)
            .is_ok());
        let audit = std::fs::read_to_string(dir.join("audit.log")).unwrap();
        assert_eq!(audit.lines().count(), 10);
        assert!(
            audit.contains("\"event\":\"refused\"") && audit.contains("\"event\":\"authorized\"")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

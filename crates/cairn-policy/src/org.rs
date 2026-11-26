//! An organization's rule: a payload is signed once enough named approvers have approved it.
//!
//! Each party holds the same list of approvers (a name and an ML-DSA-65 public key each) and
//! the number required. An approver signs a statement binding the committee's key, the
//! payload's SHA3-256 digest and an expiry time, and delivers that approval to every party as
//! a small file. A party signs a payload only if its own approvals directory holds valid,
//! unexpired approvals from enough different approvers, and it writes the decision to its
//! audit log first.
//!
//! The coordinator carries none of this and cannot forge it: approvals reach parties by
//! whatever channel the organization trusts (a shared mount, a sync job, a ticket system's
//! export), and each party checks every signature itself.
//!
//! What this does not do: it puts no limit on how often an approved payload is signed (each
//! run gives a valid signature of the same bytes), it reads no meaning into the payload
//! (amounts, roles), and an approver's key is a file, not a hardware token or a login.

use crate::pos::key_id;
use crate::{PolicyEngine, PolicyError, SignContext};
use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature, VerifyingKey};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// FIPS 204 context string of an approval signature: no other cairn signature uses it.
pub const APPROVAL_CONTEXT: &[u8] = b"cairn/approval/v1";
const PUBLIC_KEY_BYTES: usize = 1952;
/// Largest approval file a party reads.
const MAX_APPROVAL_FILE: u64 = 16 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    (text.len() % 2 == 0 && text.is_ascii())
        .then(|| {
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
                .collect()
        })
        .flatten()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Approver names appear in file names: lower-case letters, digits, `-` and `_` only.
pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn statement(committee_key_id: &[u8; 32], digest: &[u8; 32], not_after: u64) -> Vec<u8> {
    [
        committee_key_id.as_slice(),
        digest.as_slice(),
        &not_after.to_be_bytes(),
    ]
    .concat()
}

/// One approver's statement that a payload may be signed by a committee until a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub approver: String,
    pub payload_sha3: [u8; 32],
    /// Unix seconds after which parties ignore this approval.
    pub not_after: u64,
    pub signature: Vec<u8>,
}

impl Approval {
    /// `<payload digest>.<approver>.json`: where a party looks for it.
    pub fn file_name(digest: &[u8; 32], approver: &str) -> String {
        format!("{}.{approver}.json", hex(digest))
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({
            "approver": self.approver,
            "payload_sha3": hex(&self.payload_sha3),
            "not_after": self.not_after,
            "signature": hex(&self.signature),
        })
        .to_string()
    }

    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        Some(Self {
            approver: v.get("approver")?.as_str()?.to_owned(),
            payload_sha3: unhex(v.get("payload_sha3")?.as_str()?)?.try_into().ok()?,
            not_after: v.get("not_after")?.as_u64()?,
            signature: unhex(v.get("signature")?.as_str()?)?,
        })
    }

    /// Write the approval into `dir` under its expected name.
    pub fn write(&self, dir: &Path) -> std::io::Result<PathBuf> {
        let path = dir.join(Self::file_name(&self.payload_sha3, &self.approver));
        std::fs::write(&path, self.to_json())?;
        Ok(path)
    }
}

/// An approver's signing key: a 32-byte seed, expanded as FIPS 204 key generation does.
pub struct ApproverKey {
    name: String,
    key: ExpandedSigningKey<MlDsa65>,
}

impl ApproverKey {
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Option<Self> {
        valid_name(name).then(|| Self {
            name: name.to_owned(),
            key: ExpandedSigningKey::<MlDsa65>::from_seed(&(*seed).into()),
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().encode().to_vec()
    }

    /// Approve `payload` for the committee with public key `committee_pk` until `not_after`.
    pub fn approve(&self, committee_pk: &[u8], payload: &[u8], not_after: u64) -> Approval {
        let digest: [u8; 32] = Sha3_256::digest(payload).into();
        let signature = self
            .key
            .sign_deterministic(
                &statement(&key_id(committee_pk), &digest, not_after),
                APPROVAL_CONTEXT,
            )
            .expect("context is short")
            .encode()
            .to_vec();
        Approval {
            approver: self.name.clone(),
            payload_sha3: digest,
            not_after,
            signature,
        }
    }
}

/// The rule a party enforces.
#[derive(Debug, Clone)]
pub struct OrgConfig {
    /// How many different approvers must have approved a payload.
    pub required: usize,
    /// Approver name to ML-DSA-65 public key.
    pub approvers: BTreeMap<String, Vec<u8>>,
    /// Where this party finds approvals.
    pub approvals_dir: PathBuf,
    /// Append-only log of every decision, one JSON object per line. When set, a payload is
    /// signed only if its decision could be written.
    pub audit_log: Option<PathBuf>,
}

impl OrgConfig {
    /// Read `{"required": 2, "approvers": {"alice": "<public key hex>", ...}}`.
    pub fn load(
        rule_file: &Path,
        approvals_dir: PathBuf,
        audit_log: Option<PathBuf>,
    ) -> Result<Self, String> {
        let bad = |what: &str| format!("{}: {what}", rule_file.display());
        let bytes = std::fs::read(rule_file).map_err(|e| bad(&e.to_string()))?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| bad(&e.to_string()))?;
        let required = v
            .get("required")
            .and_then(|r| r.as_u64())
            .ok_or_else(|| bad("no \"required\" number"))? as usize;
        let approvers = v
            .get("approvers")
            .and_then(|a| a.as_object())
            .ok_or_else(|| bad("no \"approvers\" object"))?
            .iter()
            .map(|(name, key)| {
                key.as_str()
                    .and_then(unhex)
                    .map(|key| (name.clone(), key))
                    .ok_or_else(|| bad(&format!("approver {name}: key is not hex")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            required,
            approvers,
            approvals_dir,
            audit_log,
        })
    }
}

/// [`OrgConfig`] enforced for one committee key.
pub struct OrgGovernancePolicy {
    committee_key_id: [u8; 32],
    required: usize,
    approvers: BTreeMap<String, VerifyingKey<MlDsa65>>,
    approvals_dir: PathBuf,
    audit_log: Option<PathBuf>,
}

impl OrgGovernancePolicy {
    pub fn new(committee_pk: &[u8], config: OrgConfig) -> Result<Self, String> {
        if config.required == 0 || config.required > config.approvers.len() {
            return Err(format!(
                "{} approvals required of {} approvers",
                config.required,
                config.approvers.len()
            ));
        }
        let mut approvers = BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        for (name, key) in config.approvers {
            if !valid_name(&name) {
                return Err(format!("approver name {name:?} is not allowed"));
            }
            if key.len() != PUBLIC_KEY_BYTES {
                return Err(format!("approver {name}: not an ML-DSA-65 public key"));
            }
            // One person under two names would count twice.
            if !seen.insert(key.clone()) {
                return Err(format!("approver {name}: key is listed twice"));
            }
            let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(key.as_slice())
                .map_err(|_| format!("approver {name}: not an ML-DSA-65 public key"))?;
            approvers.insert(name, VerifyingKey::<MlDsa65>::decode(&encoded));
        }
        Ok(Self {
            committee_key_id: key_id(committee_pk),
            required: config.required,
            approvers,
            approvals_dir: config.approvals_dir,
            audit_log: config.audit_log,
        })
    }

    /// The approvers with a valid, unexpired approval of `digest` in this party's directory.
    fn approved_by(&self, digest: &[u8; 32], at: u64) -> Vec<String> {
        self.approvers
            .iter()
            .filter(|(name, key)| {
                let path = self.approvals_dir.join(Approval::file_name(digest, name));
                let small = std::fs::metadata(&path).is_ok_and(|m| m.len() <= MAX_APPROVAL_FILE);
                small
                    && std::fs::read(&path)
                        .ok()
                        .and_then(|bytes| Approval::from_json(&bytes))
                        .is_some_and(|approval| {
                            approval.approver == **name
                                && approval.payload_sha3 == *digest
                                && approval.not_after >= at
                                && Signature::<MlDsa65>::try_from(approval.signature.as_slice())
                                    .is_ok_and(|signature| {
                                        key.verify_with_context(
                                            &statement(
                                                &self.committee_key_id,
                                                digest,
                                                approval.not_after,
                                            ),
                                            APPROVAL_CONTEXT,
                                            &signature,
                                        )
                                    })
                        })
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn audit(&self, line: serde_json::Value) -> std::io::Result<()> {
        let Some(path) = &self.audit_log else {
            return Ok(());
        };
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{line}")?;
        f.sync_data()
    }
}

impl PolicyEngine for OrgGovernancePolicy {
    fn authorize_sign(&self, ctx: &SignContext, payload: &[u8]) -> Result<(), PolicyError> {
        let digest: [u8; 32] = Sha3_256::digest(payload).into();
        let at = now();
        let approved_by = self.approved_by(&digest, at);
        let enough = approved_by.len() >= self.required;
        let recorded = self.audit(serde_json::json!({
            "time": at,
            "event": if enough { "authorized" } else { "refused" },
            "session": hex(&ctx.session[..8]),
            "payload_sha3": hex(&digest),
            "approved_by": approved_by,
            "required": self.required,
        }));
        match (enough, recorded) {
            (false, _) => Err(PolicyError::Refused(format!(
                "{} of {} required approvals",
                approved_by.len(),
                self.required
            ))),
            (true, Err(e)) => Err(PolicyError::Refused(format!(
                "cannot record the decision: {e}"
            ))),
            (true, Ok(())) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: SignContext = SignContext {
        session: &[9; 32],
        party: 1,
        signers: &[1, 2],
    };

    fn setup(tag: &str, required: usize) -> (PathBuf, Vec<ApproverKey>, OrgGovernancePolicy) {
        let dir = std::env::temp_dir().join(format!("cairn-org-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys: Vec<ApproverKey> = ["alice", "bob", "carol"]
            .iter()
            .enumerate()
            .map(|(i, name)| ApproverKey::from_seed(name, &[i as u8 + 1; 32]).unwrap())
            .collect();
        let rule = serde_json::json!({
            "required": required,
            "approvers": keys.iter().map(|k| (k.name.clone(), hex(&k.public_key()))).collect::<BTreeMap<_, _>>(),
        });
        std::fs::write(dir.join("rule.json"), rule.to_string()).unwrap();
        let config = OrgConfig::load(
            &dir.join("rule.json"),
            dir.clone(),
            Some(dir.join("audit.log")),
        )
        .unwrap();
        let policy = OrgGovernancePolicy::new(b"committee", config).unwrap();
        (dir, keys, policy)
    }

    #[test]
    fn a_payload_is_signed_only_with_enough_valid_approvals() {
        let (dir, keys, policy) = setup("count", 2);
        let payload = b"pay 100 to account 7";
        let later = now() + 600;
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        keys[0]
            .approve(b"committee", payload, later)
            .write(&dir)
            .unwrap();
        assert_eq!(
            policy.authorize_sign(&CTX, payload),
            Err(PolicyError::Refused("1 of 2 required approvals".into()))
        );
        keys[2]
            .approve(b"committee", payload, later)
            .write(&dir)
            .unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_ok());
        // The approvals cover that payload only.
        assert!(policy
            .authorize_sign(&CTX, b"pay 900 to account 7")
            .is_err());
        let log = std::fs::read_to_string(dir.join("audit.log")).unwrap();
        assert_eq!(log.lines().count(), 4);
        assert!(log.contains(r#""approved_by":["alice","carol"]"#) && log.contains("authorized"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn approvals_that_do_not_count() {
        let (dir, keys, policy) = setup("bad", 2);
        let payload = b"rotate the signing key";
        let later = now() + 600;
        let digest: [u8; 32] = Sha3_256::digest(payload).into();
        keys[0]
            .approve(b"committee", payload, later)
            .write(&dir)
            .unwrap();

        // Expired.
        keys[1]
            .approve(b"committee", payload, now() - 1)
            .write(&dir)
            .unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        // Made for another committee's key.
        keys[1]
            .approve(b"other", payload, later)
            .write(&dir)
            .unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        // Alice's approval copied under Bob's name, with and without the name changed inside.
        let mut forged = keys[0].approve(b"committee", payload, later);
        std::fs::write(
            dir.join(Approval::file_name(&digest, "bob")),
            forged.to_json(),
        )
        .unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        forged.approver = "bob".into();
        forged.write(&dir).unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        // An expiry pushed out after signing.
        let mut stretched = keys[1].approve(b"committee", payload, now() - 1);
        stretched.not_after = later;
        stretched.write(&dir).unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        // Someone who is not an approver.
        let mallory = ApproverKey::from_seed("mallory", &[66; 32]).unwrap();
        mallory
            .approve(b"committee", payload, later)
            .write(&dir)
            .unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());

        keys[1]
            .approve(b"committee", payload, later)
            .write(&dir)
            .unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rules_that_cannot_be_enforced_are_refused() {
        let key = ApproverKey::from_seed("alice", &[1; 32])
            .unwrap()
            .public_key();
        let config = |required, approvers: &[(&str, Vec<u8>)]| OrgConfig {
            required,
            approvers: approvers
                .iter()
                .map(|(n, k)| (n.to_string(), k.clone()))
                .collect(),
            approvals_dir: PathBuf::from("."),
            audit_log: None,
        };
        let new = |c| OrgGovernancePolicy::new(b"committee", c).is_ok();
        assert!(new(config(1, &[("alice", key.clone())])));
        assert!(!new(config(0, &[("alice", key.clone())])));
        assert!(!new(config(2, &[("alice", key.clone())])));
        assert!(!new(config(1, &[("../alice", key.clone())])));
        assert!(!new(config(1, &[("alice", vec![1, 2, 3])])));
        assert!(!new(config(2, &[("alice", key.clone()), ("alias", key)])));
        assert!(ApproverKey::from_seed("Not Allowed", &[1; 32]).is_none());
    }

    #[test]
    fn a_decision_that_cannot_be_logged_is_not_signed() {
        let (dir, keys, _) = setup("log", 1);
        let config = OrgConfig::load(
            &dir.join("rule.json"),
            dir.clone(),
            Some(dir.join("missing").join("audit.log")),
        )
        .unwrap();
        let policy = OrgGovernancePolicy::new(b"committee", config).unwrap();
        keys[0]
            .approve(b"committee", b"x", now() + 600)
            .write(&dir)
            .unwrap();
        assert!(matches!(
            policy.authorize_sign(&CTX, b"x"),
            Err(PolicyError::Refused(reason)) if reason.starts_with("cannot record")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

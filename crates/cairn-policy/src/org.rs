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
    /// The file the rule came from. When set, the party reads it again whenever it changes,
    /// so an approver is added or removed without a restart; a rule it cannot read or that
    /// is not valid refuses everything until it is fixed.
    pub rule_file: Option<PathBuf>,
    /// When set, approvals of a payload can be used for this many seconds from the first
    /// time this party authorizes it, and not after, whatever their own expiry says.
    pub use_window_secs: Option<u64>,
    /// The file first uses are recorded in. Keep it out of the approvals directory, which
    /// whoever delivers approvals can write to. `None` keeps the record in memory only.
    pub use_record: Option<PathBuf>,
}

impl OrgConfig {
    /// Read `{"required": 2, "approvers": {"alice": "<public key hex>", ...}}`, with an
    /// optional `"use_window_secs": <n>`.
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
        let use_window_secs = match v.get("use_window_secs") {
            None => None,
            Some(n) => Some(
                n.as_u64()
                    .ok_or_else(|| bad("\"use_window_secs\" is not a number"))?,
            ),
        };
        Ok(Self {
            required,
            approvers,
            approvals_dir,
            audit_log,
            rule_file: Some(rule_file.to_owned()),
            use_window_secs,
            use_record: Some(PathBuf::from(format!("{}.used", rule_file.display()))),
        })
    }
}

/// The part of the rule that can change while the party runs.
struct Rule {
    required: usize,
    approvers: BTreeMap<String, VerifyingKey<MlDsa65>>,
    use_window_secs: Option<u64>,
}

impl Rule {
    fn build(config: &OrgConfig) -> Result<Self, String> {
        if config.required == 0 || config.required > config.approvers.len() {
            return Err(format!(
                "{} approvals required of {} approvers",
                config.required,
                config.approvers.len()
            ));
        }
        let mut approvers = BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        for (name, key) in &config.approvers {
            if !valid_name(name) {
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
            approvers.insert(name.clone(), VerifyingKey::<MlDsa65>::decode(&encoded));
        }
        Ok(Self {
            required: config.required,
            approvers,
            use_window_secs: config.use_window_secs,
        })
    }
}

/// [`OrgConfig`] enforced for one committee key.
pub struct OrgGovernancePolicy {
    committee_key_id: [u8; 32],
    /// The rule in force and the bytes of the rule file it was built from.
    rule: std::sync::Mutex<(Rule, Vec<u8>)>,
    rule_file: Option<PathBuf>,
    approvals_dir: PathBuf,
    audit_log: Option<PathBuf>,
    use_record: Option<PathBuf>,
    /// First uses this party knows of, by payload digest.
    used: std::sync::Mutex<BTreeMap<[u8; 32], u64>>,
    /// The latest time this party has decided at. Decisions never use an earlier one, so
    /// setting the machine's clock back revives no approval and reopens no use window.
    latest: std::sync::Mutex<u64>,
    /// Where `latest` is kept across restarts: beside the use record, when there is one.
    clock_file: Option<PathBuf>,
    wall: Box<dyn Fn() -> u64 + Send + Sync>,
}

/// The time in a clock file. A file that does not exist is time zero; one that cannot be read
/// is an error.
fn read_clock(path: &Path) -> std::io::Result<u64> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse()
            .map_err(|_| std::io::Error::other("unreadable clock file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

/// Replace the clock file with `at`: written beside it and renamed, so a crash leaves the old
/// time or the new one.
fn write_clock(path: &Path, at: u64) -> std::io::Result<()> {
    // Parties may share one rule file, and so one clock file: each writes its own temporary.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = PathBuf::from(format!(
        "{}.{}.{}.tmp",
        path.display(),
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(&tmp)?;
    writeln!(f, "{at}")?;
    f.sync_data()?;
    std::fs::rename(&tmp, path)
}

/// The first uses in a record file: one `<payload digest hex> <unix time>` per line. A file
/// that does not exist is an empty record; a line that cannot be read is an error.
fn read_use_record(path: &Path) -> std::io::Result<BTreeMap<[u8; 32], u64>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e),
    };
    let mut used = BTreeMap::new();
    for line in text.lines() {
        let entry = line.split_once(' ').and_then(|(digest, at)| {
            Some((
                <[u8; 32]>::try_from(unhex(digest)?).ok()?,
                at.parse::<u64>().ok()?,
            ))
        });
        let (digest, at) =
            entry.ok_or_else(|| std::io::Error::other("unreadable line in the use record"))?;
        // Two parties sharing one file may both record a payload: the earlier time stands.
        let first = used.entry(digest).or_insert(at);
        *first = at.min(*first);
    }
    Ok(used)
}

impl OrgGovernancePolicy {
    pub fn new(committee_pk: &[u8], config: OrgConfig) -> Result<Self, String> {
        let rule = Rule::build(&config)?;
        let bytes = match &config.rule_file {
            Some(file) => std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?,
            None => Vec::new(),
        };
        let used = match &config.use_record {
            Some(file) => read_use_record(file).map_err(|e| format!("{}: {e}", file.display()))?,
            None => BTreeMap::new(),
        };
        let clock_file = config
            .use_record
            .as_ref()
            .map(|file| PathBuf::from(format!("{}.clock", file.display())));
        let latest = match &clock_file {
            Some(file) => read_clock(file).map_err(|e| format!("{}: {e}", file.display()))?,
            None => 0,
        };
        Ok(Self {
            latest: std::sync::Mutex::new(latest),
            clock_file,
            wall: Box::new(now),
            use_record: config.use_record,
            used: std::sync::Mutex::new(used),
            committee_key_id: key_id(committee_pk),
            rule: std::sync::Mutex::new((rule, bytes)),
            rule_file: config.rule_file,
            approvals_dir: config.approvals_dir,
            audit_log: config.audit_log,
        })
    }

    /// Bring `current` up to date with the rule file, if there is one and it changed.
    fn refresh(&self, current: &mut (Rule, Vec<u8>)) -> Result<(), String> {
        let Some(file) = &self.rule_file else {
            return Ok(());
        };
        let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
        if bytes != current.1 {
            let config = OrgConfig::load(file, self.approvals_dir.clone(), None)?;
            *current = (Rule::build(&config)?, bytes);
        }
        Ok(())
    }

    /// The time to decide at: the machine's clock, or the latest time already decided at if
    /// the clock is behind it. An advance is written down before it is used; if that fails
    /// the time is still returned, with the error, so that the refusal can be logged.
    fn time(&self) -> (u64, std::io::Result<()>) {
        let mut latest = self.latest.lock().expect("clock");
        let mut at = (self.wall)().max(*latest);
        if at > *latest {
            if let Some(file) = &self.clock_file {
                // Another party sharing the file may be ahead: its time stands.
                let written = read_clock(file).and_then(|on_disk| {
                    at = at.max(on_disk);
                    if at > on_disk {
                        write_clock(file, at)
                    } else {
                        Ok(())
                    }
                });
                if let Err(e) = written {
                    return (at, Err(e));
                }
            }
            *latest = at;
        }
        (at, Ok(()))
    }

    /// With a use window: when this party first authorized `digest`, recorded now if never.
    /// The record is a file, so it survives a restart. While the party runs it also remembers
    /// every entry, and refuses if the file has lost one: deleting or editing the file does
    /// not reopen a window.
    fn first_use(&self, digest: &[u8; 32], at: u64) -> std::io::Result<u64> {
        let mut used = self.used.lock().expect("use record");
        if let Some(path) = &self.use_record {
            let on_disk = read_use_record(path)?;
            let kept = |(digest, first): (&[u8; 32], &u64)| {
                on_disk.get(digest).is_some_and(|there| there <= first)
            };
            if !used.iter().all(kept) {
                return Err(std::io::Error::other(
                    "the use record lost an entry: it was removed or changed",
                ));
            }
            *used = on_disk;
        }
        if let Some(first) = used.get(digest) {
            return Ok(*first);
        }
        if let Some(path) = &self.use_record {
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut f = options.open(path)?;
            writeln!(f, "{} {at}", hex(digest))?;
            f.sync_data()?;
        }
        used.insert(*digest, at);
        Ok(at)
    }

    /// The approvers with a valid, unexpired approval of `digest` in this party's directory.
    fn approved_by(&self, rule: &Rule, digest: &[u8; 32], at: u64) -> Vec<String> {
        rule.approvers
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
        let (at, clock) = self.time();
        let mut current = self.rule.lock().expect("organization rule");
        let refuse = |event: &str, reason: String| {
            // Best effort: a refusal stands whether or not it could be logged.
            let _ = self.audit(serde_json::json!({
                "time": at,
                "event": event,
                "session": hex(&ctx.session[..8]),
                "payload_sha3": hex(&digest),
                "reason": reason,
            }));
            Err(PolicyError::Refused(reason))
        };
        if let Err(e) = clock {
            return refuse("refused", format!("cannot record the time: {e}"));
        }
        if let Err(e) = self.refresh(&mut current) {
            return refuse(
                "rule_unusable",
                format!("the organization rule is unusable: {e}"),
            );
        }
        let rule = &current.0;
        let approved_by = self.approved_by(rule, &digest, at);
        let enough = approved_by.len() >= rule.required;
        if let (true, Some(window)) = (enough, rule.use_window_secs) {
            match self.first_use(&digest, at) {
                Ok(first) if at <= first.saturating_add(window) => {}
                Ok(first) => {
                    return refuse(
                        "spent",
                        format!("the approvals of this payload were used at {first} and its {window} s window has passed"),
                    )
                }
                Err(e) => return refuse("refused", format!("cannot record the first use: {e}")),
            }
        }
        let recorded = self.audit(serde_json::json!({
            "time": at,
            "event": if enough { "authorized" } else { "refused" },
            "session": hex(&ctx.session[..8]),
            "payload_sha3": hex(&digest),
            "approved_by": approved_by,
            "required": rule.required,
        }));
        match (enough, recorded) {
            (false, _) => Err(PolicyError::Refused(format!(
                "{} of {} required approvals",
                approved_by.len(),
                rule.required
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
            rule_file: None,
            use_window_secs: None,
            use_record: None,
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

    fn write_rule(dir: &Path, keys: &[&ApproverKey], required: usize, window: Option<u64>) {
        let approvers: BTreeMap<_, _> = keys
            .iter()
            .map(|k| (k.name.clone(), hex(&k.public_key())))
            .collect();
        let mut rule = serde_json::json!({ "required": required, "approvers": approvers });
        if let Some(window) = window {
            rule["use_window_secs"] = window.into();
        }
        std::fs::write(dir.join("rule.json"), rule.to_string()).unwrap();
    }

    #[test]
    fn a_removed_approver_stops_counting_without_a_restart() {
        let (dir, keys, policy) = setup("revoke", 2);
        let payload = b"grant admin to dave";
        for key in [&keys[0], &keys[2]] {
            key.approve(b"committee", payload, now() + 600)
                .write(&dir)
                .unwrap();
        }
        assert!(policy.authorize_sign(&CTX, payload).is_ok());

        // Carol leaves: her approval, still on disk and still unexpired, no longer counts.
        write_rule(&dir, &[&keys[0], &keys[1]], 2, None);
        assert_eq!(
            policy.authorize_sign(&CTX, payload),
            Err(PolicyError::Refused("1 of 2 required approvals".into()))
        );
        // A rule that cannot be enforced refuses everything, and says so.
        write_rule(&dir, &[&keys[0]], 2, None);
        let Err(PolicyError::Refused(reason)) = policy.authorize_sign(&CTX, payload) else {
            panic!("an unusable rule authorized a payload");
        };
        assert!(reason.contains("rule is unusable"), "{reason}");
        std::fs::write(dir.join("rule.json"), "not json").unwrap();
        assert!(policy.authorize_sign(&CTX, payload).is_err());
        // Restored, it signs again.
        write_rule(&dir, &[&keys[0], &keys[1], &keys[2]], 2, None);
        assert!(policy.authorize_sign(&CTX, payload).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_clock_set_back_does_not_reopen_a_window_or_revive_an_approval() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let (dir, keys, mut policy) = setup("rollback", 2);
        write_rule(&dir, &[&keys[0], &keys[1], &keys[2]], 2, Some(60));
        let clock = std::sync::Arc::new(AtomicU64::new(1_000_000));
        let wall = clock.clone();
        policy.wall = Box::new(move || wall.load(Ordering::SeqCst));
        let approve = |payload: &[u8], not_after: u64| {
            for key in [&keys[0], &keys[1]] {
                key.approve(b"committee", payload, not_after)
                    .write(&dir)
                    .unwrap();
            }
        };
        approve(b"windowed", 2_000_000);
        approve(b"short-lived", 1_000_050);
        assert!(policy.authorize_sign(&CTX, b"windowed").is_ok());

        // Time passes: the window closes and the short approval expires.
        clock.store(1_000_100, Ordering::SeqCst);
        assert!(policy.authorize_sign(&CTX, b"windowed").is_err());
        assert!(policy.authorize_sign(&CTX, b"short-lived").is_err());

        // The clock is set back to when both were good. Neither comes back.
        clock.store(1_000_010, Ordering::SeqCst);
        assert!(policy.authorize_sign(&CTX, b"windowed").is_err());
        assert!(policy.authorize_sign(&CTX, b"short-lived").is_err());

        // Nor after a restart: the latest time is on disk.
        let config = OrgConfig::load(&dir.join("rule.json"), dir.clone(), None).unwrap();
        let mut restarted = OrgGovernancePolicy::new(b"committee", config).unwrap();
        let wall = clock.clone();
        restarted.wall = Box::new(move || wall.load(Ordering::SeqCst));
        assert!(restarted.authorize_sign(&CTX, b"windowed").is_err());
        assert!(restarted.authorize_sign(&CTX, b"short-lived").is_err());

        // A time that cannot be written down is not decided at.
        clock.store(1_000_200, Ordering::SeqCst);
        approve(b"later", 2_000_000);
        let file = dir.join("rule.json.used.clock");
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        match restarted.authorize_sign(&CTX, b"later") {
            Err(PolicyError::Refused(reason)) => assert!(reason.contains("time"), "{reason}"),
            other => panic!("authorized without a recorded time: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn approvals_are_spent_after_their_use_window() {
        let (dir, keys, policy) = setup("window", 2);
        write_rule(&dir, &[&keys[0], &keys[1], &keys[2]], 2, Some(60));
        let approve = |payload: &[u8]| {
            for key in [&keys[0], &keys[1]] {
                key.approve(b"committee", payload, now() + 86_400)
                    .write(&dir)
                    .unwrap();
            }
        };
        let record = dir.join("rule.json.used");
        let line = |payload: &[u8], at: u64| {
            let digest: [u8; 32] = Sha3_256::digest(payload).into();
            format!("{} {at}\n", hex(&digest))
        };
        let recorded = |payload: &[u8]| {
            std::fs::read_to_string(&record)
                .is_ok_and(|text| text.contains(&line(payload, 0)[..64]))
        };

        // Within the window a payload can be authorized again: a session may be retried.
        let fresh = b"release 1.0";
        approve(fresh);
        assert!(!recorded(fresh));
        assert!(policy.authorize_sign(&CTX, fresh).is_ok());
        assert!(policy.authorize_sign(&CTX, fresh).is_ok());
        assert!(recorded(fresh));
        // The record is not in the approvals directory under the payload's name.
        assert!(!dir.join(line(fresh, 0)[..64].to_owned() + ".used").exists());

        // First used long ago: the approvals have a day left, and are spent all the same.
        let old = b"release 0.9";
        approve(old);
        let mut text = std::fs::read_to_string(&record).unwrap();
        text.push_str(&line(old, now() - 3600));
        std::fs::write(&record, &text).unwrap();
        let spent = |policy: &OrgGovernancePolicy| {
            let Err(PolicyError::Refused(reason)) = policy.authorize_sign(&CTX, old) else {
                panic!("spent approvals authorized a payload");
            };
            assert!(reason.contains("window has passed"), "{reason}");
        };
        spent(&policy);
        // A payload nobody approved leaves no record.
        assert!(policy.authorize_sign(&CTX, b"release 6.6").is_err());
        assert!(!recorded(b"release 6.6"));

        // Deleting the record does not reopen the window: the running party notices.
        std::fs::remove_file(&record).unwrap();
        for payload in [&old[..], &fresh[..]] {
            let Err(PolicyError::Refused(reason)) = policy.authorize_sign(&CTX, payload) else {
                panic!("a deleted use record authorized a payload");
            };
            assert!(reason.contains("lost an entry"), "{reason}");
        }
        // Neither does dropping one line, or moving a first use later.
        std::fs::write(&record, line(fresh, now())).unwrap();
        assert!(policy.authorize_sign(&CTX, old).is_err());
        std::fs::write(
            &record,
            text.replace(&line(old, now() - 3600), &line(old, now())),
        )
        .unwrap();
        assert!(policy.authorize_sign(&CTX, old).is_err());
        // Put back, it works again, and a restarted party reads the same record.
        std::fs::write(&record, &text).unwrap();
        assert!(policy.authorize_sign(&CTX, fresh).is_ok());
        let config = OrgConfig::load(&dir.join("rule.json"), dir.clone(), None).unwrap();
        let restarted = OrgGovernancePolicy::new(b"committee", config).unwrap();
        spent(&restarted);
        assert!(restarted.authorize_sign(&CTX, fresh).is_ok());
        // A record that cannot be read stops the party from starting.
        std::fs::write(&record, "not a record\n").unwrap();
        let config = OrgConfig::load(&dir.join("rule.json"), dir.clone(), None).unwrap();
        assert!(OrgGovernancePolicy::new(b"committee", config).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

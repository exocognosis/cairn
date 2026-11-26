//! Who is on the committee.
//!
//! The kernel sees a list of members with weights and the weight needed to sign. Where the list
//! comes from is the deployment's business: a file an operator edits, a directory service, or
//! a chain's staking state. Each source implements [`RosterProvider`].

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use threshold_mldsa::mithril::params_65;

fn one() -> u64 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// A name unique within the roster.
    pub id: String,
    /// The member's identity key or certificate fingerprint, hex. Opaque to the kernel.
    #[serde(default)]
    pub public_key: String,
    #[serde(default = "one")]
    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    /// Total weight that must take part for a signature.
    pub threshold: u64,
    pub members: Vec<Member>,
}

#[derive(Debug, thiserror::Error)]
pub enum RosterError {
    #[error("roster source: {0}")]
    Source(String),
    #[error("roster is invalid: {0}")]
    Invalid(String),
    #[error("the flat backend cannot serve this roster: {0}")]
    NotFlat(String),
}

impl Roster {
    /// `threshold` of `members.len()`, every member with weight one.
    pub fn uniform(threshold: usize, ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            threshold: threshold as u64,
            members: ids
                .into_iter()
                .map(|id| Member {
                    id,
                    public_key: String::new(),
                    weight: 1,
                })
                .collect(),
        }
    }

    pub fn total_weight(&self) -> u64 {
        self.members
            .iter()
            .fold(0u64, |sum, m| sum.saturating_add(m.weight))
    }

    pub fn validate(&self) -> Result<(), RosterError> {
        let invalid = |reason: &str| Err(RosterError::Invalid(reason.into()));
        if self.members.is_empty() {
            return invalid("no members");
        }
        if self
            .members
            .iter()
            .any(|m| m.id.is_empty() || m.weight == 0)
        {
            return invalid("a member has no id or no weight");
        }
        let mut ids: Vec<&str> = self.members.iter().map(|m| m.id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return invalid("two members share an id");
        }
        if self.threshold == 0 || self.threshold > self.total_weight() {
            return invalid("threshold is zero or above the total weight");
        }
        Ok(())
    }

    /// `(T, N)` if the three-round protocol can serve this roster: unweighted, and a size it
    /// has parameters for. Weighted or large rosters need the tower.
    pub fn flat_shape(&self) -> Result<(usize, usize), RosterError> {
        self.validate()?;
        if self.members.iter().any(|m| m.weight != 1) {
            return Err(RosterError::NotFlat("members have unequal weights".into()));
        }
        let (t, n) = (self.threshold as usize, self.members.len());
        if params_65(t, n).is_none() {
            return Err(RosterError::NotFlat(format!(
                "no parameters for {t}-of-{n}"
            )));
        }
        Ok((t, n))
    }
}

/// A source of the current committee.
pub trait RosterProvider: Send {
    fn roster(&self) -> Result<Roster, RosterError>;
}

/// A fixed roster held in memory.
pub struct StaticRoster(pub Roster);

impl RosterProvider for StaticRoster {
    fn roster(&self) -> Result<Roster, RosterError> {
        self.0.validate()?;
        Ok(self.0.clone())
    }
}

/// A roster kept as JSON in a file, read again on every call so an operator's edit is seen.
pub struct FileRoster(pub PathBuf);

impl RosterProvider for FileRoster {
    fn roster(&self) -> Result<Roster, RosterError> {
        let source =
            |e: &dyn std::fmt::Display| RosterError::Source(format!("{}: {e}", self.0.display()));
        let bytes = std::fs::read(&self.0).map_err(|e| source(&e))?;
        let roster: Roster = serde_json::from_slice(&bytes).map_err(|e| source(&e))?;
        roster.validate()?;
        Ok(roster)
    }
}

/// A roster printed by a program the operator owns: it reads a chain's validator set, a
/// directory, a configuration repository, whatever holds the membership, and writes the
/// roster as JSON on standard output. cairn has no code for any particular source. The
/// program is run directly (no shell) on every call.
pub struct CommandRoster {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandRoster {
    /// Split `"program arg arg"` on whitespace.
    pub fn parse(line: &str) -> Option<Self> {
        let mut words = line.split_whitespace().map(str::to_owned);
        Some(Self {
            program: words.next()?,
            args: words.collect(),
        })
    }
}

impl RosterProvider for CommandRoster {
    fn roster(&self) -> Result<Roster, RosterError> {
        let source = |what: String| RosterError::Source(format!("{}: {what}", self.program));
        let output = std::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(|e| source(e.to_string()))?;
        if !output.status.success() {
            return Err(source(format!("exited with {}", output.status)));
        }
        let roster: Roster = serde_json::from_slice(&output.stdout)
            .map_err(|e| source(format!("output is not a roster: {e}")))?;
        roster.validate()?;
        Ok(roster)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: usize) -> impl Iterator<Item = String> {
        (1..=n).map(|i| format!("party-{i}"))
    }

    #[test]
    fn the_flat_backend_takes_only_small_unweighted_rosters() {
        assert_eq!(Roster::uniform(3, names(5)).flat_shape().unwrap(), (3, 5));
        assert!(matches!(
            Roster::uniform(67, names(100)).flat_shape(),
            Err(RosterError::NotFlat(_))
        ));
        let mut weighted = Roster::uniform(2, names(3));
        weighted.members[0].weight = 2;
        assert!(weighted.validate().is_ok());
        assert!(matches!(
            weighted.flat_shape(),
            Err(RosterError::NotFlat(_))
        ));
    }

    #[test]
    fn invalid_rosters_are_refused() {
        assert!(Roster::uniform(4, names(3)).validate().is_err());
        assert!(Roster::uniform(0, names(3)).validate().is_err());
        let mut twice = Roster::uniform(2, names(3));
        twice.members[1].id = "party-1".into();
        assert!(twice.validate().is_err());
    }

    #[test]
    fn a_file_roster_follows_the_file() {
        let path = std::env::temp_dir().join(format!("cairn-roster-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"threshold":2,"members":[{"id":"a"},{"id":"b"},{"id":"c","weight":1}]}"#,
        )
        .unwrap();
        let provider = FileRoster(path.clone());
        assert_eq!(provider.roster().unwrap().flat_shape().unwrap(), (2, 3));
        std::fs::write(&path, r#"{"threshold":9,"members":[{"id":"a"}]}"#).unwrap();
        assert!(matches!(provider.roster(), Err(RosterError::Invalid(_))));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_command_roster_is_whatever_the_program_prints() {
        let sh = |script: &str| CommandRoster {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
        };
        let printed = sh(r#"echo '{"threshold":3,"members":[{"id":"v1"},{"id":"v2"},{"id":"v3"},{"id":"v4","weight":5}]}'"#)
            .roster()
            .unwrap();
        assert_eq!((printed.threshold, printed.total_weight()), (3, 8));
        assert!(matches!(sh("exit 2").roster(), Err(RosterError::Source(_))));
        assert!(matches!(
            sh("echo nonsense").roster(),
            Err(RosterError::Source(_))
        ));
        assert!(matches!(
            sh(r#"echo '{"threshold":5,"members":[{"id":"v1"}]}'"#).roster(),
            Err(RosterError::Invalid(_))
        ));
        assert!(CommandRoster::parse("/nonexistent/roster-source")
            .unwrap()
            .roster()
            .is_err());
        assert!(CommandRoster::parse(" ").is_none());
    }
}

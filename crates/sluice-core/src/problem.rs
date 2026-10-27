//! What a rule reader could not read or check, as data.
//!
//! Wherever Sluice cannot read a rule exactly, it reads it as broadly as the unread part could
//! reach (fail closed), so a problem costs savings, never a detection. Its kind lets the report
//! group problems and say per kind what the user can do, such as giving the source of a
//! function the rules call.

use std::fmt;

use crate::ids::{Engine, RuleId};

/// One thing Sluice could not read or check, and what it did instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// What kind of problem it is.
    pub kind: ProblemKind,
    /// The rule it concerns, if there is one.
    pub rule: Option<RuleId>,
    /// What happened and what Sluice did, as a sentence.
    pub message: String,
}

/// The kinds of [`Problem`], each with its own advice in the report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProblemKind {
    /// A file, document or rule Sluice could not read. It stands in as a rule that may read
    /// anything.
    Unreadable,
    /// A function or parser the rules call whose source is not among them. Each rule that calls
    /// it may read anything until the source is given.
    UnknownFunction {
        /// The rule language it belongs to.
        engine: Engine,
        /// Its name, as the rules call it.
        name: String,
    },
    /// A part of a rule Sluice reads as broadly as it could reach, such as free text or a
    /// wildcard field name.
    ReadBroadly,
    /// Names Sluice could not check and read as they most likely are, such as lower-case calls
    /// read as KQL's own functions.
    Unchecked,
    /// Rules that share an id, so the proof cannot tell their alerts apart.
    SharedId,
    /// A rule that names another one, which is not loaded.
    MissingRule,
    /// Rules or files left out on purpose, such as disabled rules.
    LeftOut,
    /// A recipe Sluice could not apply, or an AI advisor's answer it did not take.
    Recipe,
}

impl ProblemKind {
    /// The kind's name in `plan.json`, in snake case, without the details a kind carries.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::UnknownFunction { .. } => "unknown_function",
            Self::ReadBroadly => "read_broadly",
            Self::Unchecked => "unchecked",
            Self::SharedId => "shared_id",
            Self::MissingRule => "missing_rule",
            Self::LeftOut => "left_out",
            Self::Recipe => "recipe",
        }
    }
}

impl Problem {
    /// A problem of `kind`, about `rule` if it concerns one.
    #[must_use]
    pub fn new(kind: ProblemKind, rule: Option<RuleId>, message: impl Into<String>) -> Self {
        Self {
            kind,
            rule,
            message: message.into(),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_reads_as_its_message() {
        let problem = Problem::new(
            ProblemKind::UnknownFunction {
                engine: Engine::Sentinel,
                name: "my_parser".into(),
            },
            Some(RuleId::of(Engine::Sentinel, "r")),
            "sentinel:r: uses `my_parser`",
        );
        assert_eq!(problem.to_string(), "sentinel:r: uses `my_parser`");
    }

    #[test]
    fn every_kind_has_its_own_snake_case_name() {
        let kinds = [
            ProblemKind::Unreadable,
            ProblemKind::UnknownFunction {
                engine: Engine::Sentinel,
                name: "f".into(),
            },
            ProblemKind::ReadBroadly,
            ProblemKind::Unchecked,
            ProblemKind::SharedId,
            ProblemKind::MissingRule,
            ProblemKind::LeftOut,
            ProblemKind::Recipe,
        ];
        let names: std::collections::BTreeSet<_> = kinds.iter().map(ProblemKind::name).collect();
        assert_eq!(names.len(), kinds.len());
        assert!(
            names
                .iter()
                .all(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "{names:?}"
        );
        assert_eq!(
            ProblemKind::UnknownFunction {
                engine: Engine::Elastic,
                name: String::new()
            }
            .name(),
            "unknown_function"
        );
    }
}

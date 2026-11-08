//! The kinds of saving an analysis makes (`--mode`), and how much each made.
//!
//! Every mode is held to the safety contract alike: the guardrails keep what a rule reads and
//! the proof checks the result. The modes differ in what they propose, and in what the SIEM
//! still has afterwards: `duplicates` and `implied` lose nothing, since every event arrives and
//! what is left out is there or comes back; `counts` sends counts in place of events no rule
//! could match, whose originals stay in the archive only.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A kind of saving.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Fields that repeat what the event already says (a rendered `Message`, the original line
    /// next to its parsed fields, XML that repeats columns) and empty fields: the recipes' field
    /// removals. Every event arrives, with every value it had.
    Duplicates,
    /// Values the kind of event, or another field of it, implies: removed while a field holds
    /// one, and put back exactly from the plan.
    Implied,
    /// Frequent events no rule could match, counted per minute instead of sent one by one: the
    /// recipes' routing. The events themselves stay in the archive.
    Counts,
}

impl Mode {
    /// Every mode, in the order the report lists them: from what loses nothing to what sends
    /// counts in place of events.
    pub const ALL: [Self; 3] = [Self::Duplicates, Self::Implied, Self::Counts];

    /// The modes that lose nothing: every event reaches the SIEM with every value it had, or
    /// one put back exactly.
    pub const LOSSLESS: [Self; 2] = [Self::Duplicates, Self::Implied];

    /// The mode's name, as `--mode` takes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Duplicates => "duplicates",
            Self::Implied => "implied",
            Self::Counts => "counts",
        }
    }

    /// What the mode leaves out, in a few words for the report.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Duplicates => {
                "fields that repeat what the event already says, and empty fields; every event \
                 still arrives with all its values"
            }
            Self::Implied => {
                "values that follow from the kind of event or from another field, left out only \
                 while they hold and put back exactly from the plan"
            }
            Self::Counts => {
                "frequent events no rule could match, counted per minute instead of sent one by \
                 one; the events themselves stay in the archive"
            }
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_mode_has_its_flag_name_and_a_description() {
        assert_eq!(Mode::Duplicates.to_string(), "duplicates");
        assert_eq!(Mode::Implied.to_string(), "implied");
        assert_eq!(Mode::Counts.to_string(), "counts");
        assert!(
            Mode::Duplicates
                .describe()
                .starts_with("fields that repeat")
        );
        assert!(
            Mode::Implied
                .describe()
                .starts_with("values that follow from the kind of event")
        );
        assert!(Mode::Counts.describe().contains("stay in the archive"));
        assert_eq!(Mode::ALL, [Mode::Duplicates, Mode::Implied, Mode::Counts]);
    }

    #[test]
    fn only_counting_is_not_lossless() {
        assert!(!Mode::LOSSLESS.contains(&Mode::Counts));
        assert!(
            Mode::ALL
                .iter()
                .filter(|m| !Mode::LOSSLESS.contains(m))
                .eq([&Mode::Counts])
        );
    }
}

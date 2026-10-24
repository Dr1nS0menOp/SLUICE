//! The kinds of saving an analysis makes (`--mode`), and how much each made.
//!
//! Every mode is held to the safety contract alike: the guardrails keep what a rule reads and
//! the proof checks the result. The modes differ in what they propose.

use std::fmt;

use serde::Serialize;

/// A kind of saving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The recipes' savings: rendered text and empty fields removed, and events no rule could
    /// match counted instead of sent, all held to what every rule and query reads.
    Rules,
    /// Values the kind of event, or another field of it, implies: removed while a field holds
    /// one, and put back exactly from the plan.
    Implied,
}

impl Mode {
    /// Every mode, in the order the report lists them.
    pub const ALL: [Self; 2] = [Self::Rules, Self::Implied];

    /// The mode's name, as `--mode` takes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::Implied => "implied",
        }
    }

    /// What the mode removes, in a few words for the report.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Rules => "what the recipes propose and no rule reads",
            Self::Implied => {
                "values that follow from the kind of event or from another field, left out only \
                 while they hold and put back exactly from the plan"
            }
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

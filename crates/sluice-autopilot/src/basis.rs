//! On what grounds the rules count as every rule the SIEM runs (ADR 0021).

/// Why the rules of an analysis are, or are not, taken to be complete. Only complete rules let
/// the guardrails summarize events: a rule Sluice was not given could match any event it would
/// not forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum RulesBasis {
    /// Nothing says the rules are complete: only savings that keep every event are made.
    #[default]
    NotKnown,
    /// The operator declared them complete (`--rules-complete`); Sluice cannot check that.
    Claimed,
    /// Every rule set was read from its SIEM (`sluice rules fetch`).
    Fetched,
    /// The rules of a self-contained sample, such as the synthetic demo.
    SelfContained,
}

impl RulesBasis {
    /// Whether the guardrails may summarize events.
    #[must_use]
    pub fn is_complete(self) -> bool {
        self != Self::NotKnown
    }

    /// The basis of several rule sets together: the weakest of them, where a claim is weaker
    /// than a fetch.
    #[must_use]
    pub fn weakest(bases: impl IntoIterator<Item = Self>) -> Self {
        bases
            .into_iter()
            .min_by_key(|basis| match basis {
                Self::NotKnown => 0,
                Self::Claimed => 1,
                Self::Fetched | Self::SelfContained => 2,
            })
            .unwrap_or_default()
    }

    /// One sentence for people reading a report.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::NotKnown => {
                "Sluice does not know whether these are all the rules your SIEM runs, so it only \
                 made savings that keep every event (read them with `sluice rules fetch`, or pass \
                 --rules-complete)."
            }
            Self::Claimed => {
                "You declared that these are all the rules your SIEM runs (--rules-complete); \
                 Sluice cannot check that."
            }
            Self::Fetched => "The rules were read from the SIEM itself (`sluice rules fetch`).",
            Self::SelfContained => "These are all the rules of this synthetic sample.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c3_only_a_basis_says_the_rules_are_complete() {
        assert!(!RulesBasis::NotKnown.is_complete());
        assert!(RulesBasis::Claimed.is_complete());
        assert_eq!(RulesBasis::default(), RulesBasis::NotKnown);
    }

    #[test]
    fn c3_several_sets_are_as_complete_as_the_weakest() {
        use RulesBasis::{Claimed, Fetched, NotKnown};
        assert_eq!(RulesBasis::weakest([Fetched, Claimed]), Claimed);
        assert_eq!(RulesBasis::weakest([Fetched, NotKnown, Claimed]), NotKnown);
        assert_eq!(RulesBasis::weakest([Fetched]), Fetched);
        assert_eq!(RulesBasis::weakest([]), NotKnown);
    }
}

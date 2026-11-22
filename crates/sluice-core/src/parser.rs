//! How a SIEM parses a text line into named fields: a parser pack (ADR 0043).
//!
//! A text source's line is one string, but the SIEM's rules test fields it parses out of it,
//! such as `cs-uri-query` of a web request or `src_ip` of a firewall line. Without the parser,
//! Sluice cannot tell which lines such a rule could match, so it keeps them all (ADR 0020). A
//! source that names its parser (`format: {kind: text, field, parser}`) lets the guardrails, the
//! proof and the data plane read the same fields the SIEM does.
//!
//! This is data only: `sluice-rules` parses lines with it (for the proof), and `sluice-vector`
//! writes the same regular expressions as VRL (for the data plane). Both use Rust's `regex`
//! engine, so a line is parsed alike on both sides.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::schema::Schema;

/// A parser pack, resolved: the patterns a line is tried against, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineParser {
    /// The pack's id, such as `nginx/combined`.
    pub id: String,
    /// The convention its field names are in, which decides which rules can read them.
    pub convention: Schema,
    /// Tried in order; the first that matches the whole line gives its fields.
    pub patterns: Vec<LinePattern>,
}

/// One pattern of a parser pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinePattern {
    /// A regular expression in Rust's syntax, with named groups.
    pub regex: String,
    /// Which named group gives which field. A group that did not take part in the match gives
    /// no field.
    pub fields: Vec<(String, FieldPath)>,
}

impl LineParser {
    /// Every field one of its patterns can give.
    #[must_use]
    pub fn fields(&self) -> BTreeSet<&FieldPath> {
        self.patterns
            .iter()
            .flat_map(|p| p.fields.iter().map(|(_, field)| field))
            .collect()
    }

    /// Whether the parser gives `field`.
    #[must_use]
    pub fn gives(&self, field: &FieldPath) -> bool {
        self.patterns
            .iter()
            .any(|p| p.fields.iter().any(|(_, f)| f == field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parser_gives_the_fields_of_every_pattern() {
        let parser = LineParser {
            id: "p".into(),
            convention: Schema::Sigma,
            patterns: vec![
                LinePattern {
                    regex: "(?P<a>x)".into(),
                    fields: vec![("a".into(), "src_ip".into())],
                },
                LinePattern {
                    regex: "(?P<b>y)".into(),
                    fields: vec![("b".into(), "dst_ip".into())],
                },
            ],
        };
        let fields: Vec<&str> = parser.fields().into_iter().map(FieldPath::as_str).collect();
        assert_eq!(fields, ["dst_ip", "src_ip"]);
        assert!(parser.gives(&"src_ip".into()));
        assert!(!parser.gives(&"user".into()));
    }
}

//! Template classifiers: VRL conditions that recognise a template's events.
//!
//! The classifier mirrors discovery exactly, because it decides which reductions apply to an
//! event:
//!
//! - **Keyset:** the sorted leaf paths of `flatten(.)` joined by newlines equal the template's,
//!   and each discriminator renders to the recorded value. Any drift (an extra or missing field)
//!   fails to match, so drifted events pass through untouched.
//! - **Text:** a regex equivalent to "this line splits and masks into these tokens", including
//!   the syslog header that discovery reduced to its program name.
//!
//! A template that cannot be described (mixed headers) has no classifier, and its events pass
//! through.

use sluice_core::template::token::{HEX, NUM, WILDCARD};
use sluice_core::template::{LineHeader, TemplateShape};

use crate::syntax;

/// Variable holding the joined key set of the event.
pub(crate) const KEYS: &str = "_sluice_keys";

/// How a template is recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Classifier {
    /// A boolean expression over [`KEYS`] and event fields.
    Keyset(String),
    /// A regex literal over the text in `field`.
    Text {
        /// Field holding the line.
        field: sluice_core::field::FieldPath,
        /// VRL regex literal.
        regex: String,
    },
}

/// The classifier for a shape, or `None` if it has none.
pub(crate) fn classifier(shape: &TemplateShape) -> Option<Classifier> {
    match shape {
        TemplateShape::Keyset {
            discriminators,
            paths,
        } => {
            let joined: Vec<&str> = paths
                .iter()
                .map(sluice_core::field::FieldPath::as_str)
                .collect();
            let mut parts = vec![format!("{KEYS} == {}", syntax::string(&joined.join("\n")))];
            parts.extend(discriminators.iter().map(|(field, value)| {
                format!(
                    "(to_string({}) ?? \"\") == {}",
                    syntax::path(field),
                    syntax::string(value)
                )
            }));
            Some(Classifier::Keyset(parts.join(" && ")))
        }
        TemplateShape::Text {
            field,
            header,
            tokens,
        } => Some(Classifier::Text {
            field: field.clone(),
            regex: syntax::regex(&text_regex(*header, tokens)?)?,
        }),
    }
}

/// Matches the syslog timestamp and host that discovery strips (BSD or ISO timestamp).
const SYSLOG_PREFIX: &str = r"^\s*(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+\S+\s+";

fn text_regex(header: LineHeader, tokens: &[String]) -> Option<String> {
    let mut regex = String::new();
    let content = match header {
        LineHeader::Mixed => return None,
        LineHeader::None => {
            regex.push_str(r"^\s*");
            tokens
        }
        LineHeader::Syslog => {
            let (program, rest) = tokens.split_first()?;
            regex.push_str(SYSLOG_PREFIX);
            if program == WILDCARD {
                regex.push_str(r"[^\s\[:]+");
            } else {
                regex.push_str(&regex::escape(program));
            }
            // The tag: `prog:`, `prog[pid]:`, or anything bracketed before the colon(s).
            regex.push_str(r"(?:\[\S*?)?:+");
            if !rest.is_empty() {
                regex.push_str(r"\s+");
            }
            rest
        }
    };
    let parts: Vec<String> = content.iter().map(|t| token_regex(t)).collect();
    regex.push_str(&parts.join(r"\s+"));
    regex.push_str(r"\s*$");
    Some(regex)
}

/// A masked token as a regex: placeholders become their patterns, literal text is escaped.
fn token_regex(token: &str) -> String {
    if token == WILDCARD {
        return r"\S+".to_owned();
    }
    let mut out = String::new();
    let mut rest = token;
    while !rest.is_empty() {
        let next_num = rest.find(NUM);
        let next_hex = rest.find(HEX);
        let (at, placeholder, pattern) = match (next_num, next_hex) {
            (Some(n), Some(h)) if h < n => (h, HEX, r"(?:0[xX][0-9a-fA-F]+|[0-9a-fA-F]{8,})"),
            (Some(n), _) => (n, NUM, r"\d+"),
            (None, Some(h)) => (h, HEX, r"(?:0[xX][0-9a-fA-F]+|[0-9a-fA-F]{8,})"),
            (None, None) => {
                out.push_str(&regex::escape(rest));
                break;
            }
        };
        out.push_str(&regex::escape(&rest[..at]));
        out.push_str(pattern);
        rest = &rest[at + placeholder.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(header: LineHeader, tokens: &[&str], line: &str) -> bool {
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        let regex = text_regex(header, &tokens).unwrap();
        regex::Regex::new(&regex).unwrap().is_match(line)
    }

    #[test]
    fn token_placeholders_become_patterns() {
        assert_eq!(token_regex("sshd[<NUM>]:"), r"sshd\[\d+\]:");
        assert_eq!(token_regex("<*>"), r"\S+");
        assert_eq!(
            token_regex("(<HEX>)"),
            r"\((?:0[xX][0-9a-fA-F]+|[0-9a-fA-F]{8,})\)"
        );
        assert_eq!(token_regex("a.b"), r"a\.b");
    }

    #[test]
    fn syslog_lines_match_by_program_and_content() {
        let tokens = [
            "sshd",
            "Failed",
            "password",
            "for",
            "<*>",
            "from",
            "<NUM>.<NUM>.<NUM>.<NUM>",
        ];
        assert!(matches(
            LineHeader::Syslog,
            &tokens,
            "Oct 10 08:00:02 web01 sshd[7107]: Failed password for alice from 10.0.0.1"
        ));
        assert!(matches(
            LineHeader::Syslog,
            &tokens,
            "2026-10-10T08:00:02.1+00:00 web01 sshd: Failed password for bob from 10.0.0.2"
        ));
        assert!(!matches(
            LineHeader::Syslog,
            &tokens,
            "Oct 10 08:00:02 web01 sudo[1]: Failed password for alice from 10.0.0.1"
        ));
        assert!(!matches(
            LineHeader::Syslog,
            &tokens,
            "Oct 10 08:00:02 web01 sshd[1]: Failed password for invalid user x from 10.0.0.1"
        ));
    }

    #[test]
    fn headerless_lines_match_whole() {
        let tokens = ["<NUM>.<NUM>.<NUM>.<NUM>", "-", "\"GET", "<*>"];
        assert!(matches(LineHeader::None, &tokens, "10.0.0.1 - \"GET /x"));
        assert!(!matches(LineHeader::None, &tokens, "10.0.0.1 - \"POST /x"));
    }

    #[test]
    fn mixed_headers_have_no_classifier() {
        let shape = TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::Mixed,
            tokens: vec!["x".into()],
        };
        assert_eq!(classifier(&shape), None);
    }
}

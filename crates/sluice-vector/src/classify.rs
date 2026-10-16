//! Template classifiers: VRL conditions that recognise a template's events.
//!
//! The classifier mirrors discovery exactly, because it decides which reductions apply to an
//! event:
//!
//! - **Keyset:** the sorted leaf paths of `flatten(.)` joined by newlines equal one of the
//!   template's key sets, and each discriminator renders to the recorded value. Any drift (a key
//!   set discovery did not see) fails to match, so drifted events pass through untouched.
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
            variants,
            ..
        } => {
            // A template without a key set accepts no event: its events pass through.
            if variants.is_empty() {
                return None;
            }
            let key_sets: Vec<String> = variants
                .iter()
                .map(|paths| {
                    let joined: Vec<&str> = paths
                        .iter()
                        .map(sluice_core::field::FieldPath::as_str)
                        .collect();
                    format!("{KEYS} == {}", syntax::string(&joined.join("\n")))
                })
                .collect();
            let mut parts = vec![if key_sets.len() == 1 {
                key_sets.concat()
            } else {
                format!("({})", key_sets.join(" || "))
            }];
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
    fn placeholders_are_replaced_in_the_order_they_occur() {
        let hex = r"(?:0[xX][0-9a-fA-F]+|[0-9a-fA-F]{8,})";
        assert_eq!(token_regex("<HEX>-<NUM>"), format!(r"{hex}\-\d+"));
        assert_eq!(token_regex("<NUM>-<HEX>"), format!(r"\d+\-{hex}"));
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

    use std::collections::BTreeSet;

    use serde_json::{Value, json};
    use sluice_core::field::FieldPath;

    /// Whether the classifier of `shape` accepts `event`, run in VRL.
    fn accepts(shape: &TemplateShape, event: Value) -> bool {
        let condition = match classifier(shape).expect("a classifier") {
            Classifier::Keyset(expression) => expression,
            Classifier::Text { field, regex } => {
                format!("match(string({}) ?? \"\", {regex})", syntax::path(&field))
            }
        };
        let source =
            format!("{KEYS} = join(keys(flatten(.)), \"\\n\")\n.sluice_out = {condition}\n");
        let program = crate::runtime::CompiledProgram::compile("classify", source)
            .unwrap_or_else(|e| panic!("{e}"));
        let Value::Object(fields) = event else {
            unreachable!()
        };
        let (body, _) = program.run(&fields).expect("runs");
        serde_json::to_value(&body).expect("json")["sluice_out"] == json!(true)
    }

    fn keyset(discriminators: &[(&str, &str)], variants: &[&[&str]]) -> TemplateShape {
        let variants: Vec<BTreeSet<FieldPath>> = variants
            .iter()
            .map(|v| v.iter().map(|p| FieldPath::from(*p)).collect())
            .collect();
        TemplateShape::Keyset {
            discriminators: discriminators
                .iter()
                .map(|(f, v)| (FieldPath::from(*f), (*v).to_owned()))
                .collect(),
            paths: variants.iter().flatten().cloned().collect(),
            variants,
        }
    }

    #[test]
    fn a_key_set_template_takes_exactly_its_variants() {
        let shape = keyset(
            &[("EventID", "4624")],
            &[&["EventID", "User"], &["EventID", "Ip", "User"]],
        );
        assert!(accepts(&shape, json!({"EventID": 4624, "User": "a"})));
        assert!(accepts(
            &shape,
            json!({"EventID": "4624", "User": "a", "Ip": "1"})
        ));
        assert!(
            !accepts(&shape, json!({"EventID": 4624, "User": "a", "New": 1})),
            "drift"
        );
        assert!(!accepts(&shape, json!({"EventID": 4624})), "a missing key");
        assert!(
            !accepts(&shape, json!({"EventID": 4625, "User": "a"})),
            "another event id"
        );
        assert!(!accepts(&shape, json!({"EventID": null, "User": "a"})));
    }

    #[test]
    fn nested_keys_are_compared_as_flattened_paths() {
        let shape = keyset(&[], &[&["event.code", "process.name"]]);
        assert!(accepts(
            &shape,
            json!({"event": {"code": "1"}, "process": {"name": "x"}})
        ));
        assert!(!accepts(
            &shape,
            json!({"event": {"code": "1"}, "process": {"name": "x", "pid": 1}})
        ));
    }

    #[test]
    fn empty_objects_and_arrays_flatten_as_discovery_assumes() {
        // Discovery: arrays are leaves, empty objects contribute no path.
        let shape = keyset(&[], &[&["a", "list"]]);
        assert!(accepts(&shape, json!({"a": 1, "list": [1, {"x": 2}]})));
        assert!(
            accepts(&shape, json!({"a": 1, "list": [], "empty": {}})),
            "an empty object adds no key"
        );
    }

    #[test]
    fn discriminators_render_as_discovery_renders_them() {
        // Discovery renders with serde_json: strings as they are, other scalars as JSON text.
        for (value, rendered) in [
            (json!(4624), "4624"),
            (json!(-1), "-1"),
            (json!(true), "true"),
            (json!(4624.5), "4624.5"),
            (json!("4624"), "4624"),
        ] {
            let shape = keyset(&[("EventID", rendered)], &[&["EventID"]]);
            assert!(
                accepts(&shape, json!({ "EventID": value })),
                "{value} as {rendered}"
            );
        }
    }

    #[test]
    fn null_and_whole_floats_render_as_discovery_now_renders_them() {
        // Discovery used to render these as `null` and `4624.0`: their events never classified.
        for (value, rendered) in [(json!(null), ""), (json!(4624.0), "4624")] {
            let shape = keyset(&[("EventID", rendered)], &[&["EventID"]]);
            assert!(accepts(&shape, json!({ "EventID": value })), "{value}");
        }
    }

    #[test]
    fn a_template_without_variants_has_no_classifier() {
        let shape = TemplateShape::Keyset {
            discriminators: Vec::new(),
            paths: BTreeSet::new(),
            variants: Vec::new(),
        };
        assert_eq!(classifier(&shape), None);
    }

    #[test]
    fn hostile_discriminator_values_compare_literally() {
        for value in ["{{ .x }}", "a\"b", "back\\slash", "new\nline"] {
            let shape = keyset(&[("Action", value)], &[&["Action"]]);
            assert!(accepts(&shape, json!({"Action": value})), "{value:?}");
            assert!(
                !accepts(&shape, json!({"Action": format!("{value}x")})),
                "{value:?}"
            );
        }
    }

    #[test]
    fn a_text_template_takes_lines_with_its_tokens_only() {
        let shape = TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::Syslog,
            tokens: vec![
                "sshd".into(),
                "Accepted".into(),
                "password".into(),
                "for".into(),
                "<*>".into(),
            ],
        };
        assert!(accepts(
            &shape,
            json!({"message": "Oct  9 08:00:01 h sshd[1]: Accepted password for alice"})
        ));
        assert!(!accepts(
            &shape,
            json!({"message": "Oct  9 08:00:01 h sshd[1]: Accepted password for alice now"})
        ));
        assert!(!accepts(&shape, json!({"message": 42})), "a non-text value");
        assert!(!accepts(&shape, json!({})), "no line at all");
    }

    #[test]
    fn a_wildcard_program_name_takes_any_program_but_needs_a_tag() {
        assert!(matches(
            LineHeader::Syslog,
            &["<*>", "started"],
            "Oct 10 08:00:02 h cron[1]: started"
        ));
        assert!(!matches(
            LineHeader::Syslog,
            &["<*>", "started"],
            "Oct 10 08:00:02 h started"
        ));
    }

    #[test]
    fn hex_and_number_placeholders_take_only_their_characters() {
        assert!(matches(LineHeader::None, &["id=<HEX>"], "id=0x1F"));
        assert!(matches(LineHeader::None, &["id=<HEX>"], "id=deadbeef01"));
        assert!(!matches(LineHeader::None, &["id=<HEX>"], "id=xyz"));
        assert!(matches(LineHeader::None, &["port=<NUM>"], "port=443"));
        assert!(!matches(LineHeader::None, &["port=<NUM>"], "port=https"));
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

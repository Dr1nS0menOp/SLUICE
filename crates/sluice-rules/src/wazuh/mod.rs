//! Wazuh rules: what each `<rule>` needs from the data.
//!
//! Wazuh evaluates rules on its own decoded view of an event. Sluice forwards JSON, which Wazuh's
//! JSON decoder exposes under the same dotted names, so `<field name="a.b">` and static fields
//! such as `<srcip>` refer to event fields of those names. Anything matched against the raw log
//! (`<match>`, `<regex>`, `<program_name>`, `<hostname>`) needs the raw text intact.
//!
//! Exact Wazuh verification (the `logtest` API) is separate; these requirements only feed the
//! guardrails, so every uncertainty widens them.

mod xml;

use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::rules::{RequiredFields, RuleRequirements};

use self::xml::{RawChild, RawRule};
use crate::error::RulesError;

/// Static decoder fields that a JSON-decoded event carries under the same name.
const STATIC_FIELDS: [&str; 15] = [
    "srcip",
    "dstip",
    "srcport",
    "dstport",
    "srcuser",
    "dstuser",
    "user",
    "protocol",
    "action",
    "id",
    "url",
    "data",
    "extra_data",
    "status",
    "system_name",
];

/// Tags matched against the raw log line or its syslog header.
const RAW_TEXT_TAGS: [&str; 4] = ["match", "regex", "program_name", "hostname"];

/// Tags that only scope, chain or describe a rule. Ignoring a scope only widens it.
const NEUTRAL_TAGS: [&str; 15] = [
    "if_sid",
    "if_group",
    "if_level",
    "decoded_as",
    "category",
    "description",
    "group",
    "mitre",
    "info",
    "options",
    "check_if_ignored",
    "ignore",
    "time",
    "weekday",
    "location",
];

/// A loaded Wazuh rule set.
#[derive(Debug, Clone)]
pub struct WazuhRules {
    requirements: Vec<RuleRequirements>,
    problems: Vec<String>,
}

impl WazuhRules {
    /// Parses Wazuh rule files (one string per file).
    ///
    /// # Errors
    ///
    /// Returns [`RulesError::WazuhXml`] if a file is not well-formed.
    pub fn parse<'a>(files: impl IntoIterator<Item = &'a str>) -> Result<Self, RulesError> {
        let mut requirements = Vec::new();
        let mut problems = Vec::new();
        for file in files {
            for (n, raw) in xml::rules(file)?.into_iter().enumerate() {
                requirements.push(requirement(&raw, n, &mut problems));
            }
        }
        Ok(Self {
            requirements,
            problems,
        })
    }

    /// What each rule needs from the data.
    #[must_use]
    pub fn requirements(&self) -> &[RuleRequirements] {
        &self.requirements
    }

    /// Rule parts that could not be understood; the affected rules were widened.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

fn requirement(raw: &RawRule, position: usize, problems: &mut Vec<String>) -> RuleRequirements {
    let Some(id) = raw.attributes.get("id") else {
        problems.push(format!("Wazuh rule #{position} has no id"));
        return RuleRequirements::opaque(RuleId::new(format!("wazuh:unknown:{position}")));
    };
    let rule = RuleId::new(format!("wazuh:{id}"));
    let mut builder = Builder {
        stateful: raw.attributes.contains_key("frequency")
            || raw.attributes.contains_key("timeframe"),
        ..Builder::default()
    };
    for child in &raw.children {
        builder.add(child, &rule, problems);
    }
    RuleRequirements {
        rule,
        logsource: LogSource::default(),
        fields: if builder.unknown_fields {
            RequiredFields::Unknown
        } else {
            RequiredFields::Known(builder.fields)
        },
        matches_raw_text: builder.raw_text,
        stateful: builder.stateful,
        prefilter: Predicate::all(builder.conditions),
    }
}

#[derive(Default)]
struct Builder {
    fields: BTreeSet<FieldPath>,
    unknown_fields: bool,
    raw_text: bool,
    stateful: bool,
    conditions: Vec<Predicate>,
}

impl Builder {
    fn add(&mut self, child: &RawChild, rule: &RuleId, problems: &mut Vec<String>) {
        let tag = child.tag.as_str();
        if tag == "field" {
            let Some(name) = child.attributes.get("name") else {
                self.unknown(rule, "a <field> without name", problems);
                return;
            };
            self.field_condition(name, child);
        } else if STATIC_FIELDS.contains(&tag) {
            self.field_condition(tag, child);
        } else if RAW_TEXT_TAGS.contains(&tag) {
            self.raw_text = true;
            self.conditions.push(Predicate::Always);
        } else if tag == "list" {
            match child.attributes.get("field") {
                Some(field) => {
                    self.fields.insert(FieldPath::new(field.as_str()));
                }
                None => self.raw_text = true,
            }
            self.conditions.push(Predicate::Always);
        } else if let Some(compared) = cross_event_option(tag, child) {
            self.stateful = true;
            if let Compared::Field(field) = compared {
                self.fields.insert(field);
            }
        } else if tag.starts_with("if_matched") {
            self.stateful = true;
        } else if !NEUTRAL_TAGS.contains(&tag) {
            self.unknown(rule, &format!("unknown tag <{tag}>"), problems);
        }
    }

    fn field_condition(&mut self, name: &str, child: &RawChild) {
        self.fields.insert(FieldPath::new(name));
        let negated = child.attributes.get("negate").is_some_and(|v| v == "yes");
        let regex_type = child
            .attributes
            .get("type")
            .map_or("osregex", String::as_str);
        let condition = match literal(&child.text) {
            Some(text) if !negated && regex_type != "pcre2" => Predicate::Field(FieldTest {
                field: FieldPath::new(name),
                op: MatchOp::Contains,
                values: vec![text.to_owned()],
                case_sensitive: false,
            }),
            _ => Predicate::Always,
        };
        self.conditions.push(condition);
    }

    fn unknown(&mut self, rule: &RuleId, what: &str, problems: &mut Vec<String>) {
        problems.push(format!("{rule}: {what}; treated as reading every field"));
        self.unknown_fields = true;
        self.raw_text = true;
        self.conditions.push(Predicate::Always);
    }
}

/// What a `same_*` / `different_*` / `not_same_*` option compares across events.
enum Compared {
    /// An event body field.
    Field(FieldPath),
    /// Something outside the body, such as the agent location.
    Metadata,
}

/// `Some` if `tag` is a cross-event comparison option (which makes a rule stateful).
fn cross_event_option(tag: &str, child: &RawChild) -> Option<Compared> {
    let rest = tag
        .strip_prefix("same_")
        .or_else(|| tag.strip_prefix("different_"))
        .or_else(|| tag.strip_prefix("not_same_"))?;
    let field = match rest {
        "field" => child.text.trim(),
        "source_ip" => "srcip",
        "src_port" => "srcport",
        "dst_port" => "dstport",
        other if STATIC_FIELDS.contains(&other) => other,
        _ => return Some(Compared::Metadata),
    };
    Some(Compared::Field(FieldPath::new(field)))
}

/// The value if it is a plain literal under both `OS_Match` and `OS_Regex`, so that "contains,
/// case-insensitive" is a superset of what Wazuh matches. Anything with operators, escapes,
/// anchors, negation, variables, CIDR or `.` is not.
fn literal(text: &str) -> Option<&str> {
    let text = text.trim();
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | ':' | '@' | ','));
    plain.then_some(text)
}

#[cfg(test)]
mod tests;

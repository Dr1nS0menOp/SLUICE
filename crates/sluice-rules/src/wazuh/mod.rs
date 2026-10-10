//! Wazuh rules: what each `<rule>` needs from the data.
//!
//! Wazuh evaluates rules on its own decoded view of an event. Sluice forwards JSON, which Wazuh's
//! JSON decoder exposes under the same dotted names, so `<field name="a.b">` and static fields
//! such as `<srcip>` refer to event fields of those names. Anything matched against the raw log
//! (`<match>`, `<regex>`, `<program_name>`, `<hostname>`) needs the raw text intact.
//!
//! Exact Wazuh verification (the `logtest` API) is separate; these requirements only feed the
//! guardrails, so every uncertainty widens them.

mod chains;
mod decoders;
mod xml;

use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::rules::{RequiredFields, RuleRequirements};

use self::chains::Parsed;
use self::decoders::Decoders;
use self::xml::{RawChild, RawElement};
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
    /// A file that still cannot be read becomes one opaque rule that applies everywhere and may
    /// read anything (fail closed), and is reported in [`WazuhRules::problems`].
    ///
    /// # Errors
    ///
    /// Never at present; the `Result` leaves room for errors that must stop the load.
    pub fn parse<'a>(files: impl IntoIterator<Item = &'a str>) -> Result<Self, RulesError> {
        Self::parse_with_decoders(files, std::iter::empty())
    }

    /// Parses Wazuh rule files together with the decoder files they rely on. A rule's
    /// `<decoded_as>` then bounds what it can see by the decoder's program names, and `<if_sid>`
    /// chains pass a parent's bounds and fields to its children.
    ///
    /// # Errors
    ///
    /// As [`WazuhRules::parse`].
    pub fn parse_with_decoders<'a>(
        files: impl IntoIterator<Item = &'a str>,
        decoder_files: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, RulesError> {
        let mut parsed = Vec::new();
        let mut problems = Vec::new();
        let decoders = Decoders::parse(decoder_files, &mut problems);
        for (index, file) in files.into_iter().enumerate() {
            match xml::rules(file) {
                Ok(raws) => {
                    for (n, raw) in raws.into_iter().enumerate() {
                        parsed.push(requirement(&raw, n, &decoders, &mut problems));
                    }
                }
                Err(error) => {
                    problems.push(format!(
                        "Wazuh rule file {index} could not be read ({error}); it is treated as \
                         a rule that may read anything"
                    ));
                    parsed.push(Parsed {
                        requirements: RuleRequirements::opaque(RuleId::new(format!(
                            "wazuh:unreadable:{index}"
                        ))),
                        parents: Vec::new(),
                    });
                }
            }
        }
        let mut requirements = chains::inherit(parsed);
        for rule in &mut requirements {
            whole_json_line(rule);
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

/// On a JSON event, Wazuh matches `<match>` and `<regex>` against the whole JSON line: keys,
/// values and punctuation. Removing any field, even an empty one, changes that line, so a
/// `"ErrorCode":""` key alone makes rule 1002 (`$BAD_WORDS`) fire (verified with `logtest`,
/// Wazuh 4.14.8). Such a rule reads every field of a JSON event. A rule that only sees text lines
/// keeps its field list: on a text template the line is all Wazuh receives.
fn whole_json_line(rule: &mut RuleRequirements) {
    if rule.matches_raw_text && !rule.text_lines_only {
        rule.fields = RequiredFields::Unknown;
    }
}

fn requirement(
    raw: &RawElement,
    position: usize,
    decoders: &Decoders,
    problems: &mut Vec<String>,
) -> Parsed {
    let Some(id) = raw.attributes.get("id") else {
        problems.push(format!("Wazuh rule #{position} has no id"));
        return Parsed {
            requirements: RuleRequirements::opaque(RuleId::new(format!(
                "wazuh:unknown:{position}"
            ))),
            parents: Vec::new(),
        };
    };
    let rule = RuleId::new(format!("wazuh:{id}"));
    let mut builder = Builder {
        stateful: raw.attributes.contains_key("frequency")
            || raw.attributes.contains_key("timeframe"),
        ..Builder::default()
    };
    let mut parents = Vec::new();
    let mut text_lines_only = false;
    for child in &raw.children {
        match child.tag.as_str() {
            "decoded_as" => {
                builder.conditions.push(decoders.condition(&child.text));
                text_lines_only |= decoders.never_json(&child.text);
            }
            "category" => {
                builder
                    .conditions
                    .push(decoders.category_condition(&child.text));
                text_lines_only |= decoders.category_never_json(&child.text);
            }
            "if_sid" => parents.extend(
                child
                    .text
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            ),
            "if_fts" => match decoders.fts_fields() {
                Some(names) => builder.first_time_seen(names),
                None => builder.add(child, &rule, problems),
            },
            _ => builder.add(child, &rule, problems),
        }
    }
    let requirements = RuleRequirements {
        rule,
        logsource: LogSource::default(),
        fields: if builder.unknown_fields {
            RequiredFields::Unknown
        } else {
            RequiredFields::Known(builder.fields)
        },
        matches_raw_text: builder.raw_text,
        stateful: builder.stateful,
        text_lines_only,
        prefilter: Predicate::all(builder.conditions),
    };
    Parsed {
        requirements,
        parents,
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

    /// `<if_fts/>`: the rule fires the first time a combination of the decoder's `<fts>` names
    /// is seen. That history only takes events that passed the rule's other conditions, so it
    /// is stateful in the sense of ADR 0004, and it reads those names: `name` (the decoder) and
    /// `location` are not in the event body, `hostname` and `program_name` come from the raw
    /// syslog header, and every other name is a decoded field.
    fn first_time_seen(&mut self, names: &BTreeSet<String>) {
        self.stateful = true;
        for name in names {
            match name.as_str() {
                "name" | "location" => {}
                "hostname" | "program_name" => self.raw_text = true,
                field => {
                    self.fields.insert(FieldPath::new(field));
                }
            }
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
            // A pattern the pre-filter cannot express still needs a value in the field; a
            // negated one may also pass when the field is missing.
            _ if !negated => Predicate::present(FieldPath::new(name)),
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

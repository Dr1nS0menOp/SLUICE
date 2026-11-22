//! Whether a source's declared `schema` fits its records, as far as its rules show.
//!
//! A wrong `schema` is the one mistake the proof cannot notice: the rules then test names the
//! records do not have, their alerts are the same on both sides (none), and Sluice may cut what
//! the SIEM's rules read under the right names (architecture, "Field names"). When the rules that
//! apply to a source read fields that are almost all missing from its records, the declaration
//! is likely wrong, and the operator hears so, with a guess at the convention the records do
//! follow.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::logsource::LogSource;
use sluice_core::rules::{RequiredFields, RuleRequirements};
use sluice_core::schema::Schema;
use sluice_core::template::{Template, TemplateShape};

/// Below this many distinct fields the rules read, a mismatch says too little to report.
const MIN_FIELDS: usize = 3;

/// At most this share of the fields the rules read may be found in the records, in percent, for
/// the schema to look wrong.
const MAX_FOUND_PERCENT: usize = 25;

/// One hint per JSON source whose declared schema its rules' fields do not fit.
pub(crate) fn schema_hints(
    requirements: &[&RuleRequirements],
    templates: &[Template],
) -> Vec<String> {
    let mut sources: BTreeMap<&str, Vec<&Template>> = BTreeMap::new();
    for template in templates
        .iter()
        .filter(|t| matches!(t.shape, TemplateShape::Keyset { .. }) && t.schema.is_declared())
    {
        sources
            .entry(template.source.as_str())
            .or_default()
            .push(template);
    }
    sources
        .into_iter()
        .filter_map(|(source, templates)| hint(source, &templates, requirements))
        .collect()
}

fn hint(
    source: &str,
    templates: &[&Template],
    requirements: &[&RuleRequirements],
) -> Option<String> {
    let schema = templates.first()?.schema;
    let read: BTreeSet<&FieldPath> = requirements
        .iter()
        .filter(|rule| rule.field_names.is_some_and(|names| schema.can_read(names)))
        // Rules that are surely for this data: every attribute they name, the source names alike.
        // One that applies only because the source leaves an attribute unknown (a Sysmon rule on
        // the Security channel) may well read fields this data never has.
        .filter(|rule| {
            templates
                .iter()
                .any(|t| surely_for(&rule.logsource, &t.logsource))
        })
        .filter_map(|rule| match &rule.fields {
            RequiredFields::Known(fields) => Some(fields),
            RequiredFields::Unknown => None,
        })
        .flatten()
        .collect();
    if read.len() < MIN_FIELDS {
        return None;
    }
    let present: BTreeSet<&FieldPath> = templates.iter().flat_map(|t| &t.fields).collect();
    let found = read
        .iter()
        .filter(|field| present.iter().any(|p| field.may_denote(p)))
        .count();
    if found * 100 > read.len() * MAX_FOUND_PERCENT {
        return None;
    }
    let missing: Vec<&str> = read
        .iter()
        .filter(|field| !present.iter().any(|p| field.may_denote(p)))
        .take(3)
        .map(|field| field.as_str())
        .collect();
    let guess = Schema::guess(present.iter().map(|p| p.as_str()))
        .filter(|guess| *guess != schema)
        .map_or_else(
            || " Check which convention its records follow.".to_owned(),
            |guess| format!(" Its field names look like `schema: {guess}`."),
        );
    Some(format!(
        "{source}: declares `schema: {schema}`, but its records have only {found} of the {} \
         fields its rules read (missing: {}, …), so those rules may match nothing here and the \
         proof cannot tell.{guess}",
        read.len(),
        missing.join(", ")
    ))
}

/// Whether every attribute `rule` names, `data` names with the same value.
fn surely_for(rule: &LogSource, data: &LogSource) -> bool {
    let same = |rule: &Option<String>, data: &Option<String>| {
        rule.as_ref()
            .is_none_or(|value| data.as_ref().is_some_and(|d| d.eq_ignore_ascii_case(value)))
    };
    same(&rule.product, &data.product)
        && same(&rule.service, &data.service)
        && same(&rule.category, &data.category)
}

#[cfg(test)]
mod tests {
    use sluice_core::ids::{Engine, RuleId};
    use sluice_core::predicate::Predicate;
    use sluice_core::template::TemplateStats;

    use super::*;

    fn template(schema: Schema, fields: &[&str]) -> Template {
        Template {
            id: "t".into(),
            source: "winlog".into(),
            logsource: LogSource::default(),
            schema,
            pattern: String::new(),
            shape: TemplateShape::Keyset {
                discriminators: Vec::new(),
                paths: fields.iter().map(|&f| f.into()).collect(),
                variants: vec![fields.iter().map(|&f| f.into()).collect()],
            },
            fields: fields.iter().map(|&f| f.into()).collect(),
            text_fields: BTreeSet::new(),
            parser: None,
            stats: TemplateStats::default(),
        }
    }

    fn rule(fields: &[&str]) -> RuleRequirements {
        RuleRequirements {
            rule: RuleId::of(Engine::Sigma, "r"),
            logsource: LogSource::default(),
            field_names: Some(Schema::Sigma),
            fields: RequiredFields::Known(fields.iter().map(|&f| f.into()).collect()),
            matches_raw_text: false,
            stateful: false,
            text_lines_only: false,
            prefilter: Predicate::Always,
        }
    }

    const ECS_RECORD: [&str; 5] = [
        "@timestamp",
        "event.code",
        "process.executable",
        "process.command_line",
        "host.name",
    ];

    #[test]
    fn records_without_the_fields_the_rules_read_say_the_schema_looks_wrong_and_guess_one() {
        let rules = rule(&["Image", "CommandLine", "ParentImage", "User"]);
        let hints = schema_hints(&[&rules], &[template(Schema::Sigma, &ECS_RECORD)]);
        assert_eq!(hints.len(), 1, "{hints:?}");
        assert!(
            hints[0].starts_with(
                "winlog: declares `schema: sigma`, but its records have only 0 of the 4"
            )
        );
        assert!(hints[0].contains("look like `schema: ecs`"), "{}", hints[0]);
    }

    #[test]
    fn records_with_the_fields_the_rules_read_raise_no_hint() {
        let rules = rule(&["Image", "CommandLine", "ParentImage"]);
        let sigma = template(Schema::Sigma, &["EventID", "Image", "CommandLine", "User"]);
        assert_eq!(schema_hints(&[&rules], &[sigma]), Vec::<String>::new());
    }

    #[test]
    fn a_rule_that_applies_only_because_an_attribute_is_unknown_is_not_counted() {
        let mut sysmon = rule(&["Image", "CommandLine", "ParentImage", "User"]);
        sysmon.logsource.category = Some("process_creation".into());
        assert_eq!(
            schema_hints(&[&sysmon], &[template(Schema::Sigma, &ECS_RECORD)]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn too_few_fields_or_another_convention_say_nothing() {
        let few = rule(&["Image", "CommandLine"]);
        assert_eq!(
            schema_hints(&[&few], &[template(Schema::Sigma, &ECS_RECORD)]),
            Vec::<String>::new()
        );
        let many = rule(&["Image", "CommandLine", "ParentImage", "User"]);
        assert_eq!(
            schema_hints(&[&many], &[template(Schema::Ecs, &ECS_RECORD)]),
            Vec::<String>::new(),
            "rules of another convention are widened anyway (ADR 0018)"
        );
    }
}

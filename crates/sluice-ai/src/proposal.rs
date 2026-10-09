//! What the model may answer, and how an answer becomes a [`Recipe`].
//!
//! The schema is deliberately narrow. The model judges two things: which fields only repeat
//! other fields or fixed text (lossless drops), and whether the whole template is routine noise
//! that can be summarized. Everything else (rule awareness, rarity, proof) stays with Sluice.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Value, json};
use sluice_core::field::FieldPath;
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::template::Template;

/// The model's answer, as constrained by [`schema`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Answer {
    pub(crate) security_value: SecurityValue,
    pub(crate) boilerplate_fields: Vec<String>,
    pub(crate) summarize: bool,
    pub(crate) summary_keys: Vec<String>,
    pub(crate) rationale: String,
}

/// How much a template matters to security on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SecurityValue {
    None,
    Low,
    Medium,
    High,
}

/// The JSON schema the model's output is constrained to.
pub(crate) fn schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["security_value", "boilerplate_fields", "summarize", "summary_keys", "rationale"],
        "properties": {
            "security_value": {
                "type": "string",
                "enum": ["none", "low", "medium", "high"],
                "description": "How useful this event type is for detecting or investigating attacks."
            },
            "boilerplate_fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Field paths that only repeat other fields of the same event, or hold text that is identical in every event of this type. Never fields with unique information."
            },
            "summarize": {
                "type": "boolean",
                "description": "True only if individual events of this type are routine noise and counts per summary key would serve investigations equally well."
            },
            "summary_keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Field paths to count summarized events by (2 to 4 fields that identify who/what/where)."
            },
            "rationale": {
                "type": "string",
                "description": "One or two sentences explaining the judgment."
            }
        }
    })
}

/// Turns an answer into a recipe, keeping only what the template actually has.
///
/// Field names the model invents are dropped, summarizing needs `none` or `low` security value
/// and at least one real key, and an answer that proposes nothing yields `None`.
pub(crate) fn to_recipe(answer: &Answer, template: &Template, model: &str) -> Option<Recipe> {
    let known = |name: &String| template.fields.contains(name.as_str());
    let drops: BTreeSet<FieldPath> = answer
        .boilerplate_fields
        .iter()
        .filter(|f| known(f))
        .map(|f| FieldPath::new(f.as_str()))
        .collect();
    let keys: Vec<FieldPath> = answer
        .summary_keys
        .iter()
        .filter(|f| known(f))
        .map(|f| FieldPath::new(f.as_str()))
        .collect();

    let mut reductions = Vec::new();
    if !drops.is_empty() {
        reductions.push(Reduction::DropFields { fields: drops });
    }
    let low_value = matches!(
        answer.security_value,
        SecurityValue::None | SecurityValue::Low
    );
    if answer.summarize && low_value && !keys.is_empty() {
        reductions.push(Reduction::Summarize { summary_keys: keys });
    }
    if reductions.is_empty() {
        return None;
    }
    Recipe::new(
        template.id.clone(),
        reductions,
        Provenance::Ai {
            model: model.to_owned(),
        },
        answer.rationale.clone(),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use sluice_core::template::{TemplateShape, TemplateStats};

    use super::*;

    fn template() -> Template {
        Template {
            id: "t".into(),
            source: "s".into(),
            logsource: sluice_core::logsource::LogSource::default(),
            pattern: "p".into(),
            shape: TemplateShape::Keyset {
                discriminators: vec![],
                paths: BTreeSet::new(),
            },
            fields: ["message", "event.original", "host.name", "path"]
                .into_iter()
                .map(FieldPath::from)
                .collect(),
            text_fields: BTreeSet::new(),
            stats: TemplateStats::default(),
        }
    }

    fn answer(value: SecurityValue, summarize: bool) -> Answer {
        Answer {
            security_value: value,
            boilerplate_fields: vec!["event.original".into(), "invented.field".into()],
            summarize,
            summary_keys: vec!["host.name".into(), "nope".into()],
            rationale: "health checks".into(),
        }
    }

    #[test]
    fn invented_fields_are_ignored() {
        let recipe = to_recipe(&answer(SecurityValue::None, true), &template(), "m").unwrap();
        assert_eq!(
            recipe.reductions(),
            [
                Reduction::DropFields {
                    fields: BTreeSet::from([FieldPath::from("event.original")])
                },
                Reduction::Summarize {
                    summary_keys: vec!["host.name".into()]
                },
            ]
        );
        assert_eq!(recipe.provenance(), &Provenance::Ai { model: "m".into() });
    }

    #[test]
    fn valuable_templates_are_never_summarized() {
        let recipe = to_recipe(&answer(SecurityValue::High, true), &template(), "m").unwrap();
        assert!(recipe.reductions().iter().all(|r| !r.is_routing()));
    }

    #[test]
    fn empty_answers_propose_nothing() {
        let nothing = Answer {
            boilerplate_fields: vec![],
            summarize: false,
            ..answer(SecurityValue::Medium, false)
        };
        assert_eq!(to_recipe(&nothing, &template(), "m"), None);
    }

    #[test]
    fn the_schema_requires_every_field() {
        let schema = schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"].as_array().unwrap().len(), 5);
    }
}

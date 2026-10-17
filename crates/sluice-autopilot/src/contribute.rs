//! Recipes an AI advisor proposed and the proof kept, written as community recipes, so they can
//! be contributed (`sluice recipes contribute`, PLAN.md M12: "Sigma for pipelines").
//!
//! A recipe file holds no sample value: it matches by log source, schema and either the
//! template's discriminators or its pattern (Drain's tokens, variable parts masked), and it
//! carries the proposal's reductions and rationale. A recipe without discriminators or pattern
//! applies to the whole source, so it keeps only lossless reductions, as the recipe book
//! requires.

use serde_json::{Map, Value, json};
use sluice_core::recipe::{Level, Provenance, Reduction};
use sluice_core::schema::Schema;
use sluice_core::template::{Template, TemplateShape};

use crate::analyze::Analysis;
use crate::recipes::RecipeBook;

/// One recipe ready to contribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    /// Its path in a recipe directory, mirroring its id (`contrib/<source>/<event>.yaml`).
    pub path: String,
    /// The recipe file.
    pub yaml: String,
}

/// Every AI proposal of `analysis` whose template the proof kept a saving for, as a community
/// recipe the recipe book accepts.
#[must_use]
pub fn ai_recipes(analysis: &Analysis) -> Vec<Contribution> {
    analysis
        .discovery
        .templates
        .iter()
        .zip(&analysis.selection.recipes)
        .filter(|(_, effective)| !effective.is_passthrough())
        .filter_map(|(template, _)| {
            let proposal = analysis.proposals.get(&template.id)?;
            let Provenance::Ai { model } = proposal.provenance() else {
                return None;
            };
            contribution(template, proposal.reductions(), model, proposal.rationale())
        })
        .collect()
}

/// The recipe for `template`, or `None` when nothing of it can be a recipe or the recipe book
/// would refuse it.
fn contribution(
    template: &Template,
    reductions: &[Reduction],
    model: &str,
    rationale: &str,
) -> Option<Contribution> {
    let mut matcher = Map::new();
    let mut logsource = Map::new();
    for (name, value) in [
        ("product", &template.logsource.product),
        ("service", &template.logsource.service),
        ("category", &template.logsource.category),
    ] {
        if let Some(value) = value {
            logsource.insert(name.to_owned(), json!(value));
        }
    }
    matcher.insert("logsource".to_owned(), Value::Object(logsource));
    if template.schema != Schema::Undeclared {
        matcher.insert("schema".to_owned(), json!(template.schema));
    }
    let specific = match &template.shape {
        TemplateShape::Keyset { discriminators, .. } => {
            let values: Map<String, Value> = discriminators
                .iter()
                .map(|(field, value)| (field.to_string(), json!(value)))
                .collect();
            let specific = !values.is_empty();
            if specific {
                matcher.insert("discriminators".to_owned(), Value::Object(values));
            }
            specific
        }
        TemplateShape::Text { .. } => {
            matcher.insert("pattern".to_owned(), json!(template.pattern));
            true
        }
    };
    let reductions: Vec<&Reduction> = reductions
        .iter()
        .filter(|r| specific || r.level() == Level::Lossless)
        .collect();
    if reductions.is_empty() {
        return None;
    }
    let event = template
        .id
        .as_str()
        .split_once(':')
        .map_or(template.id.as_str(), |(_, rest)| rest)
        .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
    let source = template
        .source
        .as_str()
        .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
    let id = format!("contrib/{source}/{event}");
    let description = match &template.shape {
        TemplateShape::Text { .. } => format!("Lines like `{}`", template.pattern),
        TemplateShape::Keyset { discriminators, .. } if !discriminators.is_empty() => {
            let parts: Vec<String> = discriminators
                .iter()
                .map(|(field, value)| format!("{field} {value}"))
                .collect();
            format!("{} events with {}", template.source, parts.join(", "))
        }
        TemplateShape::Keyset { .. } => format!("Every {} event", template.source),
    };
    let recipe = json!({
        "id": id,
        "description": description,
        "match": matcher,
        "reductions": reductions,
        "rationale": format!(
            "{} (Proposed by {model} and proven on a local sample: review before contributing.)",
            rationale.trim()
        ),
    });
    let yaml = serde_yaml_ng::to_string(&recipe).ok()?;
    let path = format!("{id}.yaml");
    RecipeBook::parse([(path.as_str(), yaml.as_str())]).ok()?;
    Some(Contribution { path, yaml })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sluice_core::field::FieldPath;
    use sluice_core::logsource::LogSource;
    use sluice_core::template::{LineHeader, TemplateStats};

    use super::*;

    fn template(shape: TemplateShape) -> Template {
        Template {
            id: "windows-security:4624:ce1f".into(),
            source: "windows-security".into(),
            logsource: LogSource {
                product: Some("windows".into()),
                service: Some("security".into()),
                category: None,
                complete: false,
            },
            schema: Schema::Sigma,
            pattern: "EventID=4624".into(),
            shape,
            fields: ["Message".into()].into(),
            text_fields: BTreeSet::new(),
            stats: TemplateStats::default(),
        }
    }

    fn reductions() -> Vec<Reduction> {
        vec![
            Reduction::DropFields {
                fields: [FieldPath::new("Message")].into(),
            },
            Reduction::Summarize {
                summary_keys: vec![FieldPath::new("TargetUserName")],
            },
        ]
    }

    #[test]
    fn a_proposal_becomes_a_recipe_the_book_accepts() {
        let keyset = template(TemplateShape::Keyset {
            discriminators: vec![(FieldPath::new("EventID"), "4624".into())],
            paths: BTreeSet::new(),
            variants: Vec::new(),
        });
        let out = contribution(&keyset, &reductions(), "m", "Rendered text.").expect("a recipe");
        assert_eq!(out.path, "contrib/windows-security/4624-ce1f.yaml");
        assert!(out.yaml.contains("EventID: '4624'"), "{}", out.yaml);
        assert!(out.yaml.contains("op: summarize"), "{}", out.yaml);
        assert!(out.yaml.contains("Proposed by m"), "{}", out.yaml);
        assert!(out.yaml.contains("schema: sigma"), "{}", out.yaml);
    }

    #[test]
    fn a_text_template_matches_by_its_pattern() {
        let text = template(TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::None,
            tokens: vec!["x".into()],
        });
        let out = contribution(&text, &reductions(), "m", "x").expect("a recipe");
        assert!(out.yaml.contains("pattern: EventID=4624"), "{}", out.yaml);
    }

    #[test]
    fn a_source_wide_recipe_keeps_lossless_reductions_only() {
        let wide = template(TemplateShape::Keyset {
            discriminators: Vec::new(),
            paths: BTreeSet::new(),
            variants: Vec::new(),
        });
        let out = contribution(&wide, &reductions(), "m", "x").expect("a recipe");
        assert!(!out.yaml.contains("summarize"), "{}", out.yaml);
        let summarizing = &reductions()[1..];
        assert_eq!(contribution(&wide, summarizing, "m", "x"), None);
    }
}

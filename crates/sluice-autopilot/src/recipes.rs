//! Community recipes: YAML proposals that target templates by what they *are*.
//!
//! A recipe matches templates by log source plus either discriminator values (JSON templates,
//! such as `EventID: "4624"`) or a substring of the template pattern (text templates). Template
//! ids are hashes of the exact shape, so recipes never name them.
//!
//! - A **specific** recipe has a discriminator or pattern matcher, and may use any reduction.
//! - A **source-wide** recipe matches only on log source. It may only contain lossless (L1)
//!   reductions, because it applies to templates its author never saw.
//!
//! A template gets every matching source-wide recipe plus at most one specific recipe, merged.
//! Two matching specific recipes are a conflict: the template gets neither, and the conflict is
//! reported.

use std::collections::BTreeMap;

use serde::Deserialize;
use sluice_core::field::FieldPath;
use sluice_core::ids::TemplateId;
use sluice_core::logsource::LogSource;
use sluice_core::recipe::{Level, Provenance, Recipe, Reduction};
use sluice_core::template::{Template, TemplateShape};

use crate::error::AutopilotError;

include!(concat!(env!("OUT_DIR"), "/embedded_recipes.rs"));

/// A Sluice recipe: proposed reductions for one kind of log event. Proposals are never trusted: the guardrails
/// narrow them to what the loaded rules allow, and the shadow proof rolls back anything that
/// changes an alert. See `recipes/README.md`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[schemars(title = "Sluice recipe")]
#[serde(deny_unknown_fields)]
struct RecipeFile {
    /// Unique id, mirroring the file path: `<vendor>/<product>/<event>`.
    id: String,
    /// One line on what the recipe targets.
    description: String,
    /// Which templates the recipe applies to.
    #[serde(rename = "match")]
    matcher: Matcher,
    /// The proposed reductions. Without `discriminators` or `pattern`, only lossless ones
    /// (`drop_fields`, `drop_empty_fields`) are allowed.
    reductions: Vec<Reduction>,
    /// Why the reductions are safe and worthwhile, stating only facts that hold for every
    /// deployment of the source.
    rationale: String,
}

/// Which templates a recipe applies to. Every given condition must hold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct Matcher {
    /// The Sigma-style log source; every attribute given must equal the template's.
    logsource: LogSource,
    /// JSON templates: discriminator values, such as `EventID: "4624"`.
    #[serde(default)]
    discriminators: BTreeMap<String, String>,
    /// Text templates: a substring of the template pattern.
    #[serde(default)]
    pattern: Option<String>,
}

impl Matcher {
    fn is_specific(&self) -> bool {
        !self.discriminators.is_empty() || self.pattern.is_some()
    }

    fn matches(&self, template: &Template) -> bool {
        same_logsource(&self.logsource, &template.logsource)
            && self
                .discriminators
                .iter()
                .all(|(field, value)| match &template.shape {
                    TemplateShape::Keyset { discriminators, .. } => discriminators
                        .iter()
                        .any(|(f, v)| f.as_str() == field && v == value),
                    TemplateShape::Text { .. } => false,
                })
            && self
                .pattern
                .as_ref()
                .is_none_or(|p| template.pattern.contains(p.as_str()))
    }
}

/// Every attribute the recipe names must be present on the template and equal. Unlike rule
/// scoping, an unknown template attribute does *not* match: a recipe must be sure of its target.
fn same_logsource(recipe: &LogSource, template: &LogSource) -> bool {
    let same = |r: &Option<String>, t: &Option<String>| match (r, t) {
        (None, _) => true,
        (Some(r), Some(t)) => r.eq_ignore_ascii_case(t),
        (Some(_), None) => false,
    };
    same(&recipe.product, &template.product)
        && same(&recipe.service, &template.service)
        && same(&recipe.category, &template.category)
}

/// A validated recipe set.
#[derive(Debug, Clone)]
pub struct RecipeBook {
    recipes: Vec<RecipeFile>,
}

/// The recipe chosen for each template, and what could not be resolved.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    /// The merged recipe of every template that has one.
    pub recipes: BTreeMap<TemplateId, Recipe>,
    /// Templates with conflicting specific recipes (they get none).
    pub conflicts: Vec<String>,
}

impl RecipeBook {
    /// The community recipes built into Sluice.
    ///
    /// # Errors
    ///
    /// Returns [`AutopilotError::Recipe`] if an embedded recipe is invalid (caught by tests).
    pub fn embedded() -> Result<Self, AutopilotError> {
        Self::parse(EMBEDDED.iter().copied())
    }

    /// The built-in recipes plus an operator's own, given as `(path, YAML)`. An operator recipe
    /// with the id of a built-in one replaces it, so an exported recipe can be edited in place
    /// (`sluice recipes export`).
    ///
    /// # Errors
    ///
    /// As [`RecipeBook::parse`], for the operator's files.
    pub fn embedded_with<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AutopilotError> {
        let operator = Self::parse(files)?;
        let mut recipes: Vec<RecipeFile> = Self::embedded()?
            .recipes
            .into_iter()
            .filter(|r| !operator.recipes.iter().any(|o| o.id == r.id))
            .collect();
        recipes.extend(operator.recipes);
        recipes.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { recipes })
    }

    /// The built-in recipe files as `(path, YAML)`, to combine with an operator's own.
    #[must_use]
    pub fn embedded_files() -> &'static [(&'static str, &'static str)] {
        EMBEDDED
    }

    /// Parses recipe files given as `(path, YAML)`.
    ///
    /// # Errors
    ///
    /// Returns [`AutopilotError::Recipe`] for invalid YAML, unknown fields, a source-wide recipe
    /// with non-lossless reductions, conflicting reductions, or duplicate ids.
    pub fn parse<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AutopilotError> {
        let mut recipes: Vec<RecipeFile> = Vec::new();
        for (path, yaml) in files {
            let invalid = |why: String| AutopilotError::Recipe {
                path: path.to_owned(),
                why,
            };
            let recipe: RecipeFile =
                serde_yaml_ng::from_str(yaml).map_err(|e| invalid(e.to_string()))?;
            if !recipe.matcher.is_specific()
                && recipe
                    .reductions
                    .iter()
                    .any(|r| r.level() != Level::Lossless)
            {
                return Err(invalid(
                    "a source-wide recipe may only use lossless reductions".into(),
                ));
            }
            Recipe::new(
                "validation".into(),
                recipe.reductions.clone(),
                Provenance::Operator,
                "",
            )
            .map_err(|e| invalid(e.to_string()))?;
            if recipes.iter().any(|r| r.id == recipe.id) {
                return Err(invalid(format!("duplicate recipe id {}", recipe.id)));
            }
            recipes.push(recipe);
        }
        recipes.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { recipes })
    }

    /// The JSON Schema of a recipe file, generated from the types the parser uses so the two
    /// cannot drift apart. The repository keeps a copy in `recipes/recipe.schema.json`.
    #[must_use]
    pub fn json_schema() -> String {
        let schema = schemars::schema_for!(RecipeFile);
        // A generated schema is plain JSON values; serializing it cannot fail.
        serde_json::to_string_pretty(&schema).unwrap_or_default() + "\n"
    }

    /// Every recipe as `(id, description)`, sorted by id.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.recipes
            .iter()
            .map(|r| (r.id.as_str(), r.description.as_str()))
    }

    /// Number of recipes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recipes.len()
    }

    /// Whether the book is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }

    /// Chooses and merges the recipes for each template.
    #[must_use]
    pub fn resolve(&self, templates: &[Template]) -> Resolution {
        let mut resolution = Resolution::default();
        for template in templates {
            let matching: Vec<&RecipeFile> = self
                .recipes
                .iter()
                .filter(|r| r.matcher.matches(template))
                .collect();
            let specific: Vec<&&RecipeFile> = matching
                .iter()
                .filter(|r| r.matcher.is_specific())
                .collect();
            if specific.len() > 1 {
                let ids: Vec<&str> = specific.iter().map(|r| r.id.as_str()).collect();
                resolution
                    .conflicts
                    .push(format!("{}: {}", template.id, ids.join(", ")));
                continue;
            }
            if let Some(recipe) = merge(template, &matching) {
                resolution.recipes.insert(template.id.clone(), recipe);
            }
        }
        resolution
    }
}

/// Merges matching recipes: field drops are unioned, other reductions kept once.
fn merge(template: &Template, matching: &[&RecipeFile]) -> Option<Recipe> {
    if matching.is_empty() {
        return None;
    }
    let mut drops = std::collections::BTreeSet::<FieldPath>::new();
    let mut others: Vec<Reduction> = Vec::new();
    for recipe in matching {
        for reduction in &recipe.reductions {
            match reduction {
                Reduction::DropFields { fields } => drops.extend(fields.iter().cloned()),
                other if !others.contains(other) => others.push(other.clone()),
                _ => {}
            }
        }
    }
    let mut reductions = Vec::new();
    if !drops.is_empty() {
        reductions.push(Reduction::DropFields { fields: drops });
    }
    reductions.extend(others);
    let ids: Vec<&str> = matching.iter().map(|r| r.id.as_str()).collect();
    let rationale: Vec<&str> = matching.iter().map(|r| r.rationale.trim()).collect();
    // Only one recipe can carry a routing reduction (specific ones), so this cannot conflict.
    Recipe::new(
        template.id.clone(),
        reductions,
        Provenance::Community {
            recipe: ids.join(" + "),
        },
        rationale.join(" "),
    )
    .ok()
}

#[cfg(test)]
mod tests;

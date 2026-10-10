//! What the autopilot did and why, as data (for tools) and as a self-contained HTML page.

mod html;
mod text;

use std::collections::BTreeMap;

use sluice_core::guard::EffectiveRecipe;
use sluice_core::logsource::LogSource;
use sluice_core::proof::Volume;
use sluice_core::rules::RuleRequirements;
use sluice_core::template::Template;
use sluice_rules::{SigmaRules, WazuhRules};

pub use self::html::render_html;
use crate::analyze::Analysis;
use crate::spot::SpotCheck;

/// The report of one analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Volume through the data plane in total.
    pub total: Volume,
    /// Alerts on the full sample.
    pub alerts_full: usize,
    /// Alerts on the forwarded data.
    pub alerts_forwarded: usize,
    /// Whether the proof holds (it always does for an enforced selection).
    pub proven: bool,
    /// Rule count per engine, for context.
    pub rules: Vec<(String, usize)>,
    /// One row per template, largest volume first.
    pub templates: Vec<TemplateRow>,
    /// Rules that no template's log source can feed: they can never fire on this data.
    pub coverage_gaps: Vec<String>,
    /// Rules or recipes that could not be fully understood.
    pub problems: Vec<String>,
    /// Sources where many rules apply only because the log source leaves an attribute unknown;
    /// declaring it (or `complete: true`) lets the guardrails ignore those rules.
    pub scope_hints: Vec<String>,
    /// The spot check with the SIEM's own rules, if one ran.
    pub spot_check: Option<SpotCheck>,
}

/// What happens to one template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRow {
    /// Template id.
    pub id: String,
    /// Source id.
    pub source: String,
    /// Human-readable shape.
    pub pattern: String,
    /// Volume of this template.
    pub volume: Volume,
    /// The enforced reductions, in plain words. Empty: forwarded unchanged.
    pub actions: Vec<String>,
    /// Why proposals were refused or narrowed, in plain words.
    pub adjustments: Vec<String>,
    /// Where the proposal came from, if there was one.
    pub provenance: Option<String>,
}

impl Report {
    /// Builds the report of an analysis.
    #[must_use]
    pub fn new(analysis: &Analysis, sigma: &SigmaRules, wazuh: Option<&WazuhRules>) -> Self {
        let proof = &analysis.selection.proof;
        let mut templates: Vec<TemplateRow> = analysis
            .discovery
            .templates
            .iter()
            .zip(&analysis.selection.recipes)
            .map(|(template, recipe)| row(analysis, template, recipe))
            .collect();
        templates.sort_by(|a, b| {
            b.volume
                .bytes_in
                .cmp(&a.volume.bytes_in)
                .then(a.id.cmp(&b.id))
        });

        let mut rules = vec![("Sigma".to_owned(), sigma.requirements().len())];
        let mut requirements: Vec<&RuleRequirements> = sigma.requirements().iter().collect();
        if let Some(wazuh) = wazuh {
            rules.push(("Wazuh".to_owned(), wazuh.requirements().len()));
            requirements.extend(wazuh.requirements());
        }
        Self {
            total: proof.total,
            alerts_full: proof.full_alerts.len(),
            alerts_forwarded: proof.forwarded_alerts.len(),
            proven: proof.holds(),
            rules,
            templates,
            coverage_gaps: coverage_gaps(&requirements, &analysis.discovery.templates),
            scope_hints: scope_hints(&requirements, &analysis.discovery.templates),
            problems: analysis.problems.clone(),
            spot_check: analysis.spot_check.clone(),
        }
    }

    /// Share of input bytes not sent to the SIEM, in percent (0–100).
    #[must_use]
    pub fn saved_percent(&self) -> f64 {
        percent(
            self.total.bytes_in - self.total.bytes_out.min(self.total.bytes_in),
            self.total.bytes_in,
        )
    }
}

/// `part` as a percentage of `whole`. Sample sizes stay far below 2^52, so the conversion to
/// `f64` is exact in practice.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

fn row(analysis: &Analysis, template: &Template, recipe: &EffectiveRecipe) -> TemplateRow {
    let volume = analysis
        .selection
        .proof
        .per_template
        .get(&Some(template.id.clone()))
        .copied()
        .unwrap_or_default();
    TemplateRow {
        id: template.id.to_string(),
        source: template.source.to_string(),
        pattern: template.pattern.clone(),
        volume,
        actions: text::actions(recipe),
        adjustments: recipe.adjustments.iter().map(text::adjustment).collect(),
        provenance: analysis
            .proposals
            .get(&template.id)
            .map(|p| text::provenance(p.provenance())),
    }
}

/// For each source whose log source is not complete, the rules that apply only because an
/// attribute is undeclared: they would not apply if the declared attributes were all there is.
fn scope_hints(requirements: &[&RuleRequirements], templates: &[Template]) -> Vec<String> {
    let mut sources: BTreeMap<&str, &LogSource> = BTreeMap::new();
    for template in templates {
        sources
            .entry(template.source.as_str())
            .or_insert(&template.logsource);
    }
    sources
        .into_iter()
        .filter(|(_, logsource)| !logsource.complete)
        .filter_map(|(source, logsource)| {
            let complete = LogSource {
                complete: true,
                ..logsource.clone()
            };
            let only_unknown = requirements
                .iter()
                .filter(|r| {
                    r.logsource.may_apply_to(logsource) && !r.logsource.may_apply_to(&complete)
                })
                .count();
            (only_unknown > 0).then(|| {
                format!(
                    "{source}: {only_unknown} rules apply only because its log source ({}) leaves \
                     an attribute unknown; if that is all it is, add `complete: true`",
                    text::logsource(logsource)
                )
            })
        })
        .collect()
}

fn coverage_gaps(requirements: &[&RuleRequirements], templates: &[Template]) -> Vec<String> {
    let mut gaps: Vec<String> = requirements
        .iter()
        .filter(|r| {
            !templates
                .iter()
                .any(|t| r.logsource.may_apply_to(&t.logsource))
        })
        .map(|r| {
            format!(
                "{}: no data matches its log source {}",
                r.rule,
                text::logsource(&r.logsource)
            )
        })
        .collect();
    gaps.sort();
    gaps
}

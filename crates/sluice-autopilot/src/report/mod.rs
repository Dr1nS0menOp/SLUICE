//! What the autopilot did and why, as data (for tools) and as a self-contained HTML page.

mod html;
mod rules;
pub(crate) mod text;

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::problem::Problem;
use sluice_core::proof::Volume;
use sluice_core::rules::RuleRequirements;
use sluice_core::template::Template;

pub use self::html::render_html;
pub use self::rules::{RuleRow, RuleStatus};
use crate::analyze::{Analysis, Input};
use crate::basis::RulesBasis;
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
    /// One row per template, largest saving first.
    pub templates: Vec<TemplateRow>,
    /// Rules that no template's log source can feed: they can never fire on this data.
    pub coverage_gaps: Vec<String>,
    /// Rules or recipes that could not be fully understood.
    pub problems: Vec<Problem>,
    /// Sources where many rules apply only because the log source leaves an attribute unknown;
    /// declaring it (or `complete: true`) lets the guardrails ignore those rules.
    pub scope_hints: Vec<String>,
    /// The spot check with the SIEM's own rules, if one ran.
    pub spot_check: Option<SpotCheck>,
    /// On what grounds the rules counted as complete.
    pub rules_basis: RulesBasis,
    /// Every rule and query, next to what Sluice made of it.
    pub rule_rows: Vec<RuleRow>,
    /// What the fetched inventory says about rules that run but have no query to read (such
    /// as Fusion); filled in by whoever read the inventory.
    pub inventory_notes: Vec<String>,
}

/// Said when the full sample raises no alert: the proof then shows nothing about detections.
pub const EMPTY_PROOF: &str =
    "The sample raised no alerts, so this proof could not show that your detections still work.";

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
    /// Where the saving can run, in plain words; `None` when the template is sent unchanged.
    pub runs_in: Option<String>,
    /// The fields removed from its forwarded events on the sample, largest first.
    pub removed: Vec<RemovedField>,
    /// Why the recipe that removes fields holds that safe, in its author's words.
    pub rationale: Option<String>,
}

impl TemplateRow {
    /// Bytes the template no longer sends.
    #[must_use]
    pub fn saved_bytes(&self) -> u64 {
        self.volume.bytes_in.saturating_sub(self.volume.bytes_out)
    }
}

/// A field removed from a template's forwarded events on the sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedField {
    /// Its path.
    pub path: String,
    /// Forwarded events that lost it.
    pub events: u64,
    /// Bytes it took in them.
    pub bytes: u64,
    /// Why it may go, in plain words.
    pub why: String,
    /// Where its removal can run, in plain words.
    pub runs_in: String,
}

impl Report {
    /// Builds the report of an analysis of `input`.
    #[must_use]
    pub fn new(analysis: &Analysis, input: Input<'_>) -> Self {
        let proof = &analysis.selection.proof;
        let mut templates: Vec<TemplateRow> = analysis
            .discovery
            .templates
            .iter()
            .zip(&analysis.selection.recipes)
            .map(|(template, recipe)| row(analysis, template, recipe))
            .collect();
        templates.sort_by(|a, b| {
            b.saved_bytes()
                .cmp(&a.saved_bytes())
                .then(b.volume.bytes_in.cmp(&a.volume.bytes_in))
                .then(a.id.cmp(&b.id))
        });

        let mut rules = vec![("Sigma".to_owned(), count(input.sigma.requirements()))];
        let mut requirements: Vec<&RuleRequirements> = input.sigma.requirements().iter().collect();
        if let Some(wazuh) = input.wazuh {
            rules.push(("Wazuh".to_owned(), count(wazuh.requirements())));
            requirements.extend(wazuh.requirements());
        }
        if let Some(sentinel) = input.sentinel {
            rules.push(("Sentinel".to_owned(), count(sentinel.rules.requirements())));
            requirements.extend(sentinel.rules.requirements());
        }
        if let Some(elastic) = input.elastic {
            rules.push(("Elastic".to_owned(), count(elastic.rules.requirements())));
            requirements.extend(elastic.rules.requirements());
        }
        if let Some(splunk) = input.splunk {
            rules.push(("Splunk".to_owned(), count(splunk.requirements())));
            requirements.extend(splunk.requirements());
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
            rules_basis: analysis.rules,
            rule_rows: rules::rows(input),
            inventory_notes: Vec::new(),
        }
    }

    /// [`EMPTY_PROOF`] when the full sample raised no alert.
    #[must_use]
    pub fn proof_note(&self) -> Option<&'static str> {
        (self.alerts_full == 0).then_some(EMPTY_PROOF)
    }

    /// The closing sentence of the rules table.
    #[must_use]
    pub fn rules_verdict(&self) -> String {
        rules::verdict(&self.rule_rows)
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
    let proof = &analysis.selection.proof;
    let key = Some(template.id.clone());
    let volume = proof.per_template.get(&key).copied().unwrap_or_default();
    let shared = crate::plan::placements(template, recipe).len() > 1;
    let mut removed: Vec<RemovedField> = proof
        .removed
        .get(&key)
        .into_iter()
        .flatten()
        .map(|(path, removal)| RemovedField {
            path: path.to_string(),
            events: removal.events,
            bytes: removal.bytes,
            why: text::why_removed(path, recipe),
            runs_in: text::where_removed(path, recipe, shared),
        })
        .collect();
    removed.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.path.cmp(&b.path)));
    let proposal = analysis.proposals.get(&template.id);
    TemplateRow {
        id: template.id.to_string(),
        source: template.source.to_string(),
        pattern: template.pattern.clone(),
        volume,
        actions: text::actions(recipe),
        adjustments: unique(recipe.adjustments.iter().map(text::adjustment)),
        provenance: proposal.map(|p| text::provenance(p.provenance())),
        runs_in: text::placements(&crate::plan::placements(template, recipe)),
        rationale: proposal
            .map(|p| p.rationale().trim().to_owned())
            .filter(|r| !r.is_empty() && !recipe.drop_fields.is_empty()),
        removed,
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
                    "{source}: {} only because its log source ({}) leaves an attribute unknown; \
                     if that is all it is, add `complete: true`",
                    rules_apply(only_unknown),
                    text::logsource(logsource)
                )
            })
        })
        .collect()
}

/// "1 rule applies", "2 rules apply".
fn rules_apply(count: usize) -> String {
    if count == 1 {
        "1 rule applies".to_owned()
    } else {
        format!("{count} rules apply")
    }
}

/// `texts` in their order, each once. Two adjustments can read the same, such as a rare event
/// refusing both its field removals and its summary.
fn unique(texts: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    texts.filter(|text| seen.insert(text.clone())).collect()
}

/// The rules among `requirements`: a Sigma rule mapped through a pipeline, or an Elastic rule
/// per index pattern, has several requirements and counts once.
fn count(requirements: &[RuleRequirements]) -> usize {
    requirements
        .iter()
        .map(|r| &r.rule)
        .collect::<BTreeSet<_>>()
        .len()
}

fn coverage_gaps(requirements: &[&RuleRequirements], templates: &[Template]) -> Vec<String> {
    // A rule sees data when one of its requirements does.
    let seeing: BTreeSet<&RuleId> = requirements
        .iter()
        .filter(|r| {
            templates
                .iter()
                .any(|t| r.logsource.may_apply_to(&t.logsource))
        })
        .map(|r| &r.rule)
        .collect();
    let mut gaps: Vec<String> = requirements
        .iter()
        .filter(|r| !seeing.contains(&r.rule))
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

#[cfg(test)]
mod tests;

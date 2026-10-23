//! The savings plan: what Sluice proved may be sent less, in a form any tool can carry out
//! (PLAN.md M12, ADR 0023). `vector.yaml` is one rendering of it; a SIEM's own ingestion, such
//! as a Sentinel DCR transformation, is another. The plan says per source and kind of event what
//! may be removed, what may be counted instead of sent, which rules keep what, where each saving
//! can run, and the proof it all rests on.

use std::collections::BTreeMap;

use serde::Serialize;
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::TemplateId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::Predicate;
use sluice_core::proof::{Selection, Volume};
use sluice_core::recipe::{ImpliedValue, Recipe};
use sluice_core::schema::Schema;
use sluice_core::source::Source;
use sluice_core::template::{Template, TemplateShape};

use crate::analyze::Analysis;
use crate::basis::RulesBasis;
use crate::report::{Report, text};

/// The format of [`SavingsPlan`], changed whenever its meaning changes.
pub const PLAN_FORMAT: &str = "sluice.plan/1";

/// What may be sent less, and why that changes no detection.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SavingsPlan {
    /// [`PLAN_FORMAT`].
    pub format: &'static str,
    /// The proof the plan rests on.
    pub proof: PlanProof,
    /// Volume of the sample, in and as the plan forwards it.
    pub total: Volume,
    /// Every source, with every kind of event found in it.
    pub sources: Vec<SourcePlan>,
}

/// The proof on the sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanProof {
    /// Whether the forwarded data raises exactly the alerts of the full data.
    pub holds: bool,
    /// Alerts on the full sample.
    pub alerts_full: usize,
    /// Alerts on what the plan forwards.
    pub alerts_forwarded: usize,
    /// Said when the sample raised no alert: the proof then shows nothing about detections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    /// Rules per rule set.
    pub rules: BTreeMap<String, usize>,
    /// On what grounds the rules count as every rule the SIEM runs.
    pub rules_basis: RulesBasis,
}

/// One source.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SourcePlan {
    /// Source id.
    pub id: String,
    /// What the source is.
    pub logsource: LogSource,
    /// The naming convention of its field names.
    pub schema: Schema,
    /// Its kinds of event, largest volume first.
    pub templates: Vec<TemplatePlan>,
}

/// One kind of event (template) and what may be done to it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemplatePlan {
    /// Template id.
    pub id: String,
    /// Human-readable shape.
    pub pattern: String,
    /// How to recognise its events: the exact shape a tool compiles a classifier from.
    pub shape: TemplateShape,
    /// Its volume in the sample.
    pub volume: Volume,
    /// Fields that may be removed from every event sent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remove_fields: Vec<FieldPath>,
    /// If set, null and empty fields may be removed, except these.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_empty_fields_except: Option<Vec<FieldPath>>,
    /// Fields that may be removed while they hold the value given, after the removals above.
    /// An absent field means that value, so every removed value can be put back. Only a
    /// pipeline tool carries these out so far, whatever `runs_in` says of the others.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remove_implied: Vec<ImpliedValue>,
    /// Events matching this keep every field: a rule could match them (contract rule 3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_whole_when: Option<Predicate>,
    /// If set, events outside `forward_when` may be counted instead of sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_instead: Option<CountInstead>,
    /// Where the saving can run; empty when the template is sent unchanged.
    pub runs_in: Vec<Placement>,
    /// Why proposals were refused or narrowed, in plain words.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Where the proposal came from, if there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

/// Counting instead of sending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CountInstead {
    /// Events any applicable rule could match: these are sent.
    pub forward_when: Predicate,
    /// The fields the counts are kept per.
    pub keys: Vec<FieldPath>,
}

/// Where a saving can be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// A pipeline tool in front of the SIEM, such as Vector: every saving.
    Pipeline,
    /// The SIEM's own ingestion, such as a Sentinel DCR transformation or an Elasticsearch
    /// ingest pipeline: removing fields only, since counting needs state across events that
    /// ingestion-time transformations lack.
    SiemIngest,
    /// The collection agent, such as Fluent Bit or the OpenTelemetry Collector: removing fields
    /// only, as in the SIEM's ingestion.
    Agent,
}

impl SavingsPlan {
    /// The plan of `analysis`, whose `report` gives the proof and rule counts, over `sources`.
    #[must_use]
    pub fn new(analysis: &Analysis, report: &Report, sources: &[Source]) -> Self {
        Self::build(
            &analysis.discovery.templates,
            &analysis.selection,
            &analysis.proposals,
            report,
            sources,
        )
    }

    fn build(
        templates: &[Template],
        selection: &Selection,
        proposals: &BTreeMap<TemplateId, Recipe>,
        report: &Report,
        sources: &[Source],
    ) -> Self {
        let mut by_source: BTreeMap<&str, Vec<TemplatePlan>> = BTreeMap::new();
        for (template, recipe) in templates.iter().zip(&selection.recipes) {
            by_source
                .entry(template.source.as_str())
                .or_default()
                .push(template_plan(selection, proposals, template, recipe));
        }
        let sources = sources
            .iter()
            .map(|source| {
                let mut templates = by_source.remove(source.id.as_str()).unwrap_or_default();
                templates.sort_by(|a, b| {
                    b.volume
                        .bytes_in
                        .cmp(&a.volume.bytes_in)
                        .then_with(|| a.id.cmp(&b.id))
                });
                SourcePlan {
                    id: source.id.to_string(),
                    logsource: source.logsource.clone(),
                    schema: source.schema,
                    templates,
                }
            })
            .collect();
        Self {
            format: PLAN_FORMAT,
            proof: PlanProof {
                holds: report.proven,
                alerts_full: report.alerts_full,
                alerts_forwarded: report.alerts_forwarded,
                note: report.proof_note(),
                rules: report.rules.iter().cloned().collect(),
                rules_basis: report.rules_basis,
            },
            total: report.total,
            sources,
        }
    }

    /// The plan as pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns the serializer's error; the plan's types always serialize, so it does not occur.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self).map(|json| json + "\n")
    }
}

/// Where `recipe`'s saving on `template` can run; none when it changes nothing. Only a pipeline
/// tool counts, and only it recognises a text template (by a regex over the line): every
/// generator for a SIEM's ingestion or an agent recognises key sets only, and none of them
/// removes implied values yet.
pub(crate) fn placements(template: &Template, recipe: &EffectiveRecipe) -> Vec<Placement> {
    let keyset = matches!(
        template.shape,
        sluice_core::template::TemplateShape::Keyset { .. }
    );
    let removals = !recipe.drop_fields.is_empty() || recipe.drop_empty_except.is_some();
    if recipe.is_passthrough() {
        Vec::new()
    } else if recipe.route == Route::ForwardAll && keyset && removals {
        vec![Placement::Pipeline, Placement::SiemIngest, Placement::Agent]
    } else {
        vec![Placement::Pipeline]
    }
}

fn template_plan(
    selection: &Selection,
    proposals: &BTreeMap<TemplateId, Recipe>,
    template: &Template,
    recipe: &EffectiveRecipe,
) -> TemplatePlan {
    let count_instead = match &recipe.route {
        Route::ForwardAll => None,
        Route::ForwardMatching {
            prefilter,
            summary_keys,
        } => Some(CountInstead {
            forward_when: prefilter.clone(),
            keys: summary_keys.clone(),
        }),
    };
    let runs_in = placements(template, recipe);
    TemplatePlan {
        id: template.id.to_string(),
        pattern: template.pattern.clone(),
        shape: template.shape.clone(),
        volume: selection
            .proof
            .per_template
            .get(&Some(template.id.clone()))
            .copied()
            .unwrap_or_default(),
        remove_fields: recipe.drop_fields.iter().cloned().collect(),
        remove_empty_fields_except: recipe
            .drop_empty_except
            .as_ref()
            .map(|kept| kept.iter().cloned().collect()),
        remove_implied: recipe.drop_implied.clone(),
        keep_whole_when: recipe.keep_whole_when.clone(),
        count_instead,
        runs_in,
        reasons: recipe.adjustments.iter().map(text::adjustment).collect(),
        provenance: proposals
            .get(&template.id)
            .map(|p| text::provenance(p.provenance())),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sluice_core::template::{LineHeader, TemplateShape, TemplateStats};

    use super::*;

    fn template(shape: TemplateShape) -> Template {
        Template {
            id: "t".into(),
            source: "s".into(),
            logsource: sluice_core::logsource::LogSource::default(),
            schema: sluice_core::schema::Schema::default(),
            pattern: String::new(),
            shape,
            fields: ["Message".into()].into(),
            text_fields: BTreeSet::new(),
            stats: TemplateStats::default(),
        }
    }

    #[test]
    fn only_a_pipeline_tool_counts_or_recognises_a_line() {
        let removing = EffectiveRecipe {
            drop_fields: ["Message".into()].into(),
            ..EffectiveRecipe::passthrough("t".into())
        };
        let keyset = template(TemplateShape::Keyset {
            discriminators: Vec::new(),
            paths: ["Message".into()].into(),
            variants: vec![["Message".into()].into()],
        });
        let text = template(TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::None,
            tokens: vec!["x".into()],
        });
        assert_eq!(
            placements(&keyset, &removing),
            [Placement::Pipeline, Placement::SiemIngest, Placement::Agent]
        );
        assert_eq!(placements(&text, &removing), [Placement::Pipeline]);
        let counting = EffectiveRecipe {
            route: Route::ForwardMatching {
                prefilter: Predicate::Always,
                summary_keys: Vec::new(),
            },
            ..removing.clone()
        };
        assert_eq!(placements(&keyset, &counting), [Placement::Pipeline]);
        assert_eq!(
            placements(&keyset, &EffectiveRecipe::passthrough("t".into())),
            Vec::<Placement>::new()
        );
    }
}

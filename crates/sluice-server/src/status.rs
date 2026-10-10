//! What `GET /status` reports: the state of every template and the last cycle.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sluice_autopilot::{Cycle, Lifecycle, Report, Stage, Transition};
use sluice_core::event::Event;
use sluice_core::ids::TemplateId;
use sluice_core::logsource::LogSource;
use sluice_core::proof::Volume;
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::rules::{RequiredFields, RuleRequirements};
use sluice_core::source::Source;

/// The control plane's status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    /// The rule profile this status is about, such as `sigma` or `sigma+wazuh`: the rules the
    /// SIEMs of some destinations run, which their reductions are proven against.
    #[serde(default)]
    pub profile: String,
    /// Every profile, so a client can ask for another (`GET /status?profile=…`).
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Completed cycles since start.
    pub cycles: u64,
    /// Events held per source in the rolling window.
    pub window: BTreeMap<String, usize>,
    /// The last cycle, if one ran.
    pub last_cycle: Option<CycleStatus>,
    /// Every template with a proven recipe and its stage.
    pub templates: Vec<TemplateStatus>,
    /// Recent transitions, newest last (bounded).
    pub history: Vec<TransitionRecord>,
    /// The last error, if the last cycle failed.
    pub last_error: Option<String>,
    /// What the last cycle found per template: shape, volume, and what is done to it and why.
    #[serde(default)]
    pub details: Vec<TemplateDetail>,
    /// Per source, the last window through the deployed data plane.
    #[serde(default)]
    pub sources: Vec<SourceHealth>,
    /// Rules that no template's log source can feed: they cannot fire on this traffic.
    #[serde(default)]
    pub coverage_gaps: Vec<String>,
    /// Rules or recipes that could not be fully understood.
    #[serde(default)]
    pub problems: Vec<String>,
    /// Sources whose log source leaves an attribute unknown, so extra rules apply.
    #[serde(default)]
    pub scope_hints: Vec<String>,
}

/// One template of the last window and what Sluice does to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateDetail {
    /// Template id.
    pub template: String,
    /// Source id.
    pub source: String,
    /// Human-readable shape.
    pub pattern: String,
    /// `enforced`, `shadow`, or `none` (forwarded unchanged).
    pub stage: String,
    /// Volume of the template in the window, under its proven recipe.
    pub volume: Volume,
    /// The proven reductions in plain words; empty means forwarded unchanged.
    pub actions: Vec<String>,
    /// Why proposals were refused or narrowed, in plain words.
    pub adjustments: Vec<String>,
    /// Where the proposal came from, if there was one.
    pub provenance: Option<String>,
    /// One event of the window as it arrived and as the proven recipe forwards it.
    #[serde(default)]
    pub example: Option<Example>,
}

/// One event before and after its template's recipe, run through the same data plane the proof
/// ran. It shows what a recipe does better than a list of actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Example {
    /// The event as it arrived (and as the archive keeps it).
    pub before: Map<String, Value>,
    /// What the SIEM receives; `None` when the event is counted into a summary instead.
    pub after: Option<Map<String, Value>>,
}

/// Larger examples are left out of the status (a script block can run to megabytes).
const MAX_EXAMPLE_BYTES: usize = 64 * 1024;

/// One source in the last window, through the deployed data plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceHealth {
    /// Source id.
    pub source: String,
    /// Its log source.
    pub logsource: LogSource,
    /// Templates seen or deployed.
    pub templates: usize,
    /// Volume through the deployed data plane.
    pub volume: Volume,
}

/// What a loaded rule needs, for questions like "which detections use this field?".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    /// Rule id.
    pub rule: String,
    /// `sigma` or `wazuh`.
    pub engine: String,
    /// The log source it applies to.
    pub logsource: LogSource,
    /// The fields it reads; `None` when that cannot be known (it may read any field).
    pub fields: Option<Vec<String>>,
    /// Whether it counts or correlates events over time.
    pub stateful: bool,
}

impl RuleInfo {
    pub(crate) fn new(engine: &str, requirements: &RuleRequirements) -> Self {
        Self {
            rule: requirements.rule.to_string(),
            engine: engine.to_owned(),
            logsource: requirements.logsource.clone(),
            fields: match &requirements.fields {
                RequiredFields::Known(fields) => {
                    Some(fields.iter().map(ToString::to_string).collect())
                }
                RequiredFields::Unknown => None,
            },
            stateful: requirements.stateful,
        }
    }
}

/// Summary of one cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleStatus {
    /// When it ran (Unix seconds).
    pub at: i64,
    /// Events analyzed.
    pub events: u64,
    /// Templates discovered.
    pub templates: usize,
    /// Bytes the deployed data plane would forward of the window.
    pub bytes_in: u64,
    /// Bytes forwarded.
    pub bytes_out: u64,
    /// Alerts on the window (full data).
    pub alerts_full: usize,
    /// Alerts on the forwarded data.
    pub alerts_forwarded: usize,
    /// Whether the deployed data plane is proven on the window.
    pub proven: bool,
}

/// One template's stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateStatus {
    /// Template id.
    pub template: String,
    /// `shadow` or `enforced`.
    pub stage: String,
    /// Since when (Unix seconds).
    pub since: i64,
    /// Consecutive proofs (shadow only).
    pub proofs: Option<u32>,
}

/// A transition with its time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionRecord {
    /// When (Unix seconds).
    pub at: i64,
    /// `shadowing`, `promoted`, `demoted` or `rolled_back`.
    pub kind: String,
    /// Template id.
    pub template: String,
}

/// How many transitions the status keeps.
const HISTORY: usize = 200;

impl Status {
    pub(crate) fn record(
        &mut self,
        at: i64,
        cycle: &Cycle,
        lifecycle: &Lifecycle,
        report: &Report,
        sources: &[Source],
        events: &[Event],
    ) {
        self.cycles += 1;
        let proof = &cycle.deployed.proof;
        self.last_cycle = Some(CycleStatus {
            at,
            events: proof.total.events,
            templates: cycle.analysis.discovery.templates.len(),
            bytes_in: proof.total.bytes_in,
            bytes_out: proof.total.bytes_out,
            alerts_full: proof.full_alerts.len(),
            alerts_forwarded: proof.forwarded_alerts.len(),
            proven: proof.holds(),
        });
        self.templates = lifecycle
            .stages()
            .iter()
            .map(|(id, stage)| match stage {
                Stage::Shadow { since, proofs } => TemplateStatus {
                    template: id.to_string(),
                    stage: "shadow".to_owned(),
                    since: since.0,
                    proofs: Some(*proofs),
                },
                Stage::Enforced { since } => TemplateStatus {
                    template: id.to_string(),
                    stage: "enforced".to_owned(),
                    since: since.0,
                    proofs: None,
                },
            })
            .collect();
        self.history.extend(cycle.transitions.iter().map(|t| {
            let (kind, template) = match t {
                Transition::Shadowing(id) => ("shadowing", id),
                Transition::Promoted(id) => ("promoted", id),
                Transition::Demoted(id) => ("demoted", id),
                Transition::RolledBack(id) => ("rolled_back", id),
            };
            TransitionRecord {
                at,
                kind: kind.to_owned(),
                template: template.to_string(),
            }
        }));
        let excess = self.history.len().saturating_sub(HISTORY);
        self.history.drain(..excess);
        self.last_error = None;
        self.details = details(report, lifecycle, &examples(cycle, events));
        self.sources = health(cycle, sources);
        self.coverage_gaps.clone_from(&report.coverage_gaps);
        self.problems.clone_from(&report.problems);
        self.scope_hints.clone_from(&report.scope_hints);
    }
}

/// The first event of each template that fits [`MAX_EXAMPLE_BYTES`], reduced by the analysis's
/// data plane: the proven recipes, shadowed ones included, so a viewer sees what a recipe in
/// shadow would do once enforced.
fn examples(cycle: &Cycle, events: &[Event]) -> BTreeMap<TemplateId, Example> {
    let assignments = &cycle.analysis.discovery.assignments;
    let mut found = BTreeMap::new();
    for event in events {
        let Some(template) = assignments.get(&event.id) else {
            continue;
        };
        if found.contains_key(template)
            || serde_json::to_vec(&event.fields).map_or(true, |b| b.len() > MAX_EXAMPLE_BYTES)
        {
            continue;
        }
        let Ok(reduced) = cycle.analysis.data_plane.reduce(event) else {
            continue;
        };
        let after = match reduced.outcome {
            Outcome::Forwarded(body) => Some(body),
            Outcome::Summarized => None,
        };
        found.insert(
            template.clone(),
            Example {
                before: event.fields.clone(),
                after,
            },
        );
    }
    found
}

fn details(
    report: &Report,
    lifecycle: &Lifecycle,
    examples: &BTreeMap<TemplateId, Example>,
) -> Vec<TemplateDetail> {
    let stages = lifecycle.stages();
    report
        .templates
        .iter()
        .map(|row| {
            let id = TemplateId::new(row.id.as_str());
            let stage = match stages.get(&id) {
                Some(Stage::Enforced { .. }) => "enforced",
                Some(Stage::Shadow { .. }) => "shadow",
                None => "none",
            };
            TemplateDetail {
                template: row.id.clone(),
                source: row.source.clone(),
                pattern: row.pattern.clone(),
                stage: stage.to_owned(),
                volume: row.volume,
                actions: row.actions.clone(),
                adjustments: row.adjustments.clone(),
                provenance: row.provenance.clone(),
                example: examples.get(&id).cloned(),
            }
        })
        .collect()
}

fn health(cycle: &Cycle, sources: &[Source]) -> Vec<SourceHealth> {
    let per_template = &cycle.deployed.proof.per_template;
    sources
        .iter()
        .map(|source| {
            let mut volume = Volume::default();
            let mut templates = 0;
            for template in cycle.templates.iter().filter(|t| t.source == source.id) {
                templates += 1;
                if let Some(v) = per_template.get(&Some(template.id.clone())) {
                    volume.events += v.events;
                    volume.forwarded += v.forwarded;
                    volume.summarized += v.summarized;
                    volume.bytes_in += v.bytes_in;
                    volume.bytes_out += v.bytes_out;
                }
            }
            SourceHealth {
                source: source.id.to_string(),
                logsource: source.logsource.clone(),
                templates,
                volume,
            }
        })
        .collect()
}

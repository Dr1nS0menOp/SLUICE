//! Whether a plan still holds, later (ADR 0039).
//!
//! A plan is proven on one sample, with the rules the SIEM ran that day. `sluice verify` takes
//! the plan as it was written, a newer sample and the rules the SIEM runs now, and says whether
//! the plan still holds: the configuration it was written as raises the same alerts on the new
//! sample, and every rule it is meant to protect is one it was proven with. It also says what
//! the new sample does to the savings, which is not a matter of safety (events of a kind the
//! plan does not know are sent whole) but tells when an analysis would save more.

use std::collections::BTreeMap;

use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sluice_core::ids::SourceId;
use sluice_core::proof::{Proof, Volume};

use crate::basis::RulesBasis;
use crate::fingerprint::RuleFingerprint;
use crate::plan::PLAN_FORMAT;
use crate::report::EMPTY_PROOF;

/// A template whose saving fell by at least this many percentage points is listed.
pub const SAVING_DROP_POINTS: f64 = 10.0;

/// A plan as `plan.json` holds it: what verification needs. Fields it does not know are
/// ignored, so a plan of the same format with fields added later still reads.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RecordedPlan {
    /// The Sluice that wrote it, if it said.
    #[serde(default)]
    pub sluice: Option<String>,
    /// The proof it was written with.
    pub proof: RecordedProof,
    /// The sample's volume, in and as the plan forwards it.
    pub total: Volume,
    /// Its sources and their kinds of event.
    pub sources: Vec<RecordedSource>,
    /// The rules it was proven with; `None` in a plan written before Sluice recorded them.
    #[serde(default)]
    pub rules: Option<Vec<RuleFingerprint>>,
}

/// The proof a recorded plan was written with.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecordedProof {
    /// Whether it held.
    pub holds: bool,
    /// On what grounds the rules counted as complete.
    pub rules_basis: RulesBasis,
}

/// One source of a recorded plan.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RecordedSource {
    /// Its id.
    pub id: String,
    /// Its kinds of event.
    pub templates: Vec<RecordedTemplate>,
}

/// One kind of event of a recorded plan.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RecordedTemplate {
    /// Its id.
    pub id: String,
    /// Its volume in the plan's sample.
    pub volume: Volume,
    /// Present when events of it may be counted instead of sent.
    #[serde(default)]
    count_instead: Option<IgnoredAny>,
}

impl RecordedTemplate {
    /// Whether the plan counts some of its events instead of sending them, which only complete
    /// rules allow (ADR 0021).
    #[must_use]
    pub fn counts(&self) -> bool {
        self.count_instead.is_some()
    }
}

/// Why a `plan.json` cannot be verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanReadError {
    /// It is not JSON, or not a plan.
    #[error("not a Sluice plan: {0}")]
    NotAPlan(String),
    /// It is a plan of another format.
    #[error(
        "the plan is format {found}, written by Sluice {by}; this Sluice reads {PLAN_FORMAT}: \
         verify it with the Sluice that wrote it, or run `sluice analyze` again"
    )]
    OtherFormat {
        /// The format it says.
        found: String,
        /// The Sluice that wrote it, as it says.
        by: String,
    },
}

impl RecordedPlan {
    /// Reads `plan.json`, refusing another format than [`PLAN_FORMAT`].
    ///
    /// # Errors
    ///
    /// [`PlanReadError`] when the text is not a plan of this format.
    pub fn parse(json: &str) -> Result<Self, PlanReadError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| PlanReadError::NotAPlan(e.to_string()))?;
        let format = value.get("format").and_then(serde_json::Value::as_str);
        match format {
            Some(PLAN_FORMAT) => {}
            Some(found) => {
                return Err(PlanReadError::OtherFormat {
                    found: found.to_owned(),
                    by: value
                        .get("sluice")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("of an unknown version")
                        .to_owned(),
                });
            }
            None => return Err(PlanReadError::NotAPlan("it has no `format`".to_owned())),
        }
        serde_json::from_value(value).map_err(|e| PlanReadError::NotAPlan(e.to_string()))
    }

    /// Whether the plan counts any events instead of sending them.
    #[must_use]
    pub fn counts(&self) -> bool {
        self.sources
            .iter()
            .flat_map(|s| &s.templates)
            .any(RecordedTemplate::counts)
    }
}

/// What verification compares.
#[derive(Debug, Clone, Copy)]
pub struct VerifyInput<'a> {
    /// The plan as it was written.
    pub plan: &'a RecordedPlan,
    /// The rules the SIEM runs now, as Sluice reads them.
    pub rules: &'a [RuleFingerprint],
    /// On what grounds those rules count as complete.
    pub basis: RulesBasis,
    /// The proof of the plan's configuration on the new sample, with the rules of now.
    pub proof: &'a Proof,
    /// Sources of the new sample the configuration has no program for: sent as they are.
    pub unreduced: &'a [SourceId],
}

/// Whether the plan still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The same alerts on the new sample, and every rule is one the plan was proven with.
    Holds,
    /// The same alerts on the new sample, but the rules are not those the plan was proven with:
    /// it does not protect what they changed. Run `sluice analyze` again before relying on it.
    OutOfDate,
    /// The alerts on what the plan forwards differ from those on the full sample: a detection
    /// would change. Do not deploy the plan; take it out if it runs.
    DoesNotHold,
}

/// The outcome of [`verify`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Verification {
    /// The verdict.
    pub verdict: Verdict,
    /// Why the verdict is not [`Verdict::Holds`], in plain words.
    pub reasons: Vec<String>,
    /// The proof on the new sample.
    pub proof: ProofCheck,
    /// How the rules differ from those the plan was proven with.
    pub rules: RuleChanges,
    /// What the new sample does to the savings.
    pub savings: SavingsCheck,
    /// Kinds of event whose saving fell by [`SAVING_DROP_POINTS`] or more, the largest loss
    /// first.
    pub templates: Vec<TemplateDrift>,
}

/// The proof on the new sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofCheck {
    /// Whether the alerts on what the plan forwards equal those on the full sample.
    pub holds: bool,
    /// Alerts on the full sample.
    pub alerts_full: usize,
    /// Alerts on what the plan forwards.
    pub alerts_forwarded: usize,
    /// Alerts on the full sample only, as `rule on event N`.
    pub missing: Vec<String>,
    /// Alerts on what the plan forwards only.
    pub extra: Vec<String>,
    /// Said when the new sample raised no alert: the proof then shows nothing about detections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// How the rules of now differ from those the plan was proven with, by rule id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RuleChanges {
    /// Rules the plan was not proven with: it protects nothing they read.
    pub added: Vec<String>,
    /// Rules Sluice now reads differently (another field, log source or condition).
    pub changed: Vec<String>,
    /// Rules the plan was proven with that are gone: harmless, but an analysis may save more.
    pub removed: Vec<String>,
    /// Whether the plan recorded its rules at all.
    pub recorded: bool,
}

/// The savings, then and now.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SavingsCheck {
    /// The share of the bytes the plan saved on its own sample, in percent.
    pub saved_percent_plan: f64,
    /// The share it saves on the new sample.
    pub saved_percent_now: f64,
    /// The share of the plan's own sample in no kind of event its configuration recognises.
    pub unknown_percent_plan: f64,
    /// The share of the new sample in no kind of event the configuration recognises: sent as
    /// it is (safety contract rule 1). A large share means the data changed since the plan.
    pub unknown_percent_now: f64,
    /// The new sample's volume, in and as the plan forwards it.
    pub total: Volume,
    /// Kinds of event in the plan without a single event in the new sample.
    pub absent_templates: usize,
    /// Sources the configuration has no program for: sent as they are.
    pub unreduced_sources: Vec<String>,
}

/// One kind of event whose saving fell.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TemplateDrift {
    /// Its source.
    pub source: String,
    /// Its id.
    pub template: String,
    /// The share of its bytes the plan saved on its own sample, in percent.
    pub saved_percent_plan: f64,
    /// The share it saves on the new sample.
    pub saved_percent_now: f64,
    /// Its events in the new sample.
    pub events_now: u64,
}

/// Compares a plan with the rules and a sample of now.
#[must_use]
pub fn verify(input: VerifyInput<'_>) -> Verification {
    let VerifyInput {
        plan,
        rules,
        basis,
        proof,
        unreduced,
    } = input;
    let changes = rule_changes(plan.rules.as_deref(), rules);
    let mut reasons = Vec::new();
    let holds_now = proof.holds();
    if !holds_now {
        reasons.push(format!(
            "on the new sample, {} alerts are raised on the full events but not on what the plan \
             forwards, and {} the other way round: a detection would change",
            proof.missing.len(),
            proof.extra.len()
        ));
    }
    if !plan.proof.holds {
        reasons.push("the plan itself says its proof did not hold when it was written".to_owned());
    }
    if !changes.recorded {
        reasons.push(
            "the plan does not record the rules it was proven with (it was written before Sluice \
             1.0), so Sluice cannot tell which rules it protects: run `sluice analyze` again"
                .to_owned(),
        );
    }
    if !changes.added.is_empty() || !changes.changed.is_empty() {
        let mut what = Vec::new();
        if !changes.added.is_empty() {
            what.push(rules_count(changes.added.len(), "is new", "are new"));
        }
        if !changes.changed.is_empty() {
            what.push(rules_count(
                changes.changed.len(),
                "reads differently",
                "read differently",
            ));
        }
        reasons.push(format!(
            "{} since the plan was proven: it does not keep what they read, so run \
             `sluice analyze` with the rules of now",
            what.join(" and ")
        ));
    }
    if plan.counts() && !basis.is_complete() {
        reasons.push(
            "the plan counts events instead of sending them, which needs every rule the SIEM \
             runs, but the rules given now are not known to be complete: fetch them with \
             `sluice rules fetch`, or pass --rules-complete"
                .to_owned(),
        );
    }
    let verdict = if !holds_now || !plan.proof.holds {
        Verdict::DoesNotHold
    } else if reasons.is_empty() {
        Verdict::Holds
    } else {
        Verdict::OutOfDate
    };
    Verification {
        verdict,
        reasons,
        proof: ProofCheck {
            holds: holds_now,
            alerts_full: proof.full_alerts.len(),
            alerts_forwarded: proof.forwarded_alerts.len(),
            missing: proof
                .missing
                .iter()
                .map(|a| format!("{} on event {}", a.rule, a.event))
                .collect(),
            extra: proof
                .extra
                .iter()
                .map(|a| format!("{} on event {}", a.rule, a.event))
                .collect(),
            note: proof.full_alerts.is_empty().then_some(EMPTY_PROOF),
        },
        rules: changes,
        savings: savings(plan, proof, unreduced),
        templates: drift(plan, proof),
    }
}

fn rule_changes(recorded: Option<&[RuleFingerprint]>, now: &[RuleFingerprint]) -> RuleChanges {
    let Some(recorded) = recorded else {
        return RuleChanges::default();
    };
    let then: BTreeMap<&str, &str> = recorded
        .iter()
        .map(|r| (r.rule.as_str(), r.requirements.as_str()))
        .collect();
    let current: BTreeMap<&str, &str> = now
        .iter()
        .map(|r| (r.rule.as_str(), r.requirements.as_str()))
        .collect();
    let mut changes = RuleChanges {
        recorded: true,
        ..RuleChanges::default()
    };
    for (rule, digest) in &current {
        match then.get(rule) {
            None => changes.added.push((*rule).to_owned()),
            Some(before) if before != digest => changes.changed.push((*rule).to_owned()),
            Some(_) => {}
        }
    }
    changes.removed = then
        .keys()
        .filter(|rule| !current.contains_key(*rule))
        .map(|rule| (*rule).to_owned())
        .collect();
    changes
}

/// `1 rule is new`, `2 rules are new`.
fn rules_count(count: usize, one: &str, more: &str) -> String {
    if count == 1 {
        format!("1 rule {one}")
    } else {
        format!("{count} rules {more}")
    }
}

fn savings(plan: &RecordedPlan, proof: &Proof, unreduced: &[SourceId]) -> SavingsCheck {
    let known_plan: u64 = plan
        .sources
        .iter()
        .flat_map(|s| &s.templates)
        .map(|t| t.volume.bytes_in)
        .sum();
    let unknown_now = proof
        .per_template
        .get(&None)
        .map_or(0, |volume| volume.bytes_in);
    let absent_templates = plan
        .sources
        .iter()
        .flat_map(|s| &s.templates)
        .filter(|t| t.volume.events > 0)
        .filter(|t| {
            let id = sluice_core::ids::TemplateId::new(t.id.clone());
            proof
                .per_template
                .get(&Some(id))
                .is_none_or(|volume| volume.events == 0)
        })
        .count();
    SavingsCheck {
        saved_percent_plan: saved_percent(plan.total),
        saved_percent_now: saved_percent(proof.total),
        unknown_percent_plan: percent(
            plan.total.bytes_in.saturating_sub(known_plan),
            plan.total.bytes_in,
        ),
        unknown_percent_now: percent(unknown_now, proof.total.bytes_in),
        total: proof.total,
        absent_templates,
        unreduced_sources: unreduced.iter().map(ToString::to_string).collect(),
    }
}

fn drift(plan: &RecordedPlan, proof: &Proof) -> Vec<TemplateDrift> {
    let mut fallen: Vec<(u64, TemplateDrift)> = plan
        .sources
        .iter()
        .flat_map(|source| source.templates.iter().map(move |t| (source, t)))
        .filter_map(|(source, template)| {
            let id = sluice_core::ids::TemplateId::new(template.id.clone());
            let now = proof.per_template.get(&Some(id)).copied()?;
            let then_saved = saved_percent(template.volume);
            let now_saved = saved_percent(now);
            (now.events > 0 && then_saved - now_saved >= SAVING_DROP_POINTS).then(|| {
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    clippy::cast_precision_loss,
                    reason = "an ordering by roughly how many bytes the drop costs"
                )]
                let lost = ((then_saved - now_saved) * now.bytes_in as f64) as u64;
                (
                    lost,
                    TemplateDrift {
                        source: source.id.clone(),
                        template: template.id.clone(),
                        saved_percent_plan: round(then_saved),
                        saved_percent_now: round(now_saved),
                        events_now: now.events,
                    },
                )
            })
        })
        .collect();
    fallen.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.template.cmp(&b.1.template)));
    fallen.into_iter().map(|(_, drift)| drift).collect()
}

/// The share of `volume`'s bytes it saved, in percent.
fn saved_percent(volume: Volume) -> f64 {
    percent(
        volume.bytes_in.saturating_sub(volume.bytes_out),
        volume.bytes_in,
    )
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss, reason = "a percentage for people")]
    round(part as f64 * 100.0 / whole as f64)
}

/// One decimal, as the report shows percentages.
fn round(percent: f64) -> f64 {
    (percent * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests;

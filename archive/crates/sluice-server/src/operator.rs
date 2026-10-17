//! Operator actions (ADR 0016): hold or release a template, keep a field of a source, approve a
//! recipe, acknowledge a rollback. Each is recorded in the profile's history and in an
//! append-only audit log; holds and kept fields are stored, so they survive a restart.
//!
//! None of them can weaken the safety contract: holds and kept fields only add protection, and
//! an approved recipe is still enforced only on a cycle that proves it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::predicate::Predicate;
use sluice_core::rules::{RequiredFields, RuleRequirements};
use sluice_core::source::Source;

use crate::error::ServerError;

/// One action, as `POST /actions` receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Forward the template unchanged until released; its recipe stops now.
    Hold {
        /// Template id.
        template: String,
    },
    /// End a hold; the recipe starts over in shadow when next proven.
    Release {
        /// Template id.
        template: String,
    },
    /// Enforce the template's recipe at its next proof, without waiting out shadow.
    Approve {
        /// Template id.
        template: String,
    },
    /// Never remove `field` from the events of `source`.
    Keep {
        /// Source id.
        source: String,
        /// Field name.
        field: String,
    },
    /// End a keep.
    Unkeep {
        /// Source id.
        source: String,
        /// Field name.
        field: String,
    },
    /// Mark the rollback of `template` at time `at` as seen.
    Acknowledge {
        /// Template id.
        template: String,
        /// The rollback's time (Unix seconds), as the history shows it.
        at: i64,
    },
}

impl Action {
    /// The history kind of the action, such as `hold`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Hold { .. } => "hold",
            Self::Release { .. } => "release",
            Self::Approve { .. } => "approve",
            Self::Keep { .. } => "keep",
            Self::Unkeep { .. } => "unkeep",
            Self::Acknowledge { .. } => "acknowledge",
        }
    }

    /// What the action is about, for the history: a template, or `source:field`.
    #[must_use]
    pub fn target(&self) -> String {
        match self {
            Self::Hold { template }
            | Self::Release { template }
            | Self::Approve { template }
            | Self::Acknowledge { template, .. } => template.clone(),
            Self::Keep { source, field } | Self::Unkeep { source, field } => {
                format!("{source}:{field}")
            }
        }
    }
}

/// A request to `POST /actions`.
#[derive(Debug, Clone, Deserialize)]
pub struct ActionRequest {
    /// The rule profile; the first one when absent.
    #[serde(default)]
    pub profile: Option<String>,
    /// Why, for the audit log.
    #[serde(default)]
    pub reason: Option<String>,
    /// The action.
    #[serde(flatten)]
    pub action: Action,
}

/// What operators decided for one profile that outlives a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDecisions {
    /// Held templates.
    #[serde(default)]
    pub held: BTreeSet<String>,
    /// Kept fields per source.
    #[serde(default)]
    pub kept: BTreeMap<String, BTreeSet<String>>,
}

impl ProfileDecisions {
    /// The kept fields as requirements for the guardrails: an operator rule per field that
    /// reads it, scoped to its source's log source.
    pub(crate) fn rules(&self, sources: &[Source]) -> Vec<RuleRequirements> {
        let mut rules = Vec::new();
        for (source, fields) in &self.kept {
            let Some(found) = sources.iter().find(|s| s.id.as_str() == source) else {
                continue;
            };
            for field in fields {
                rules.push(RuleRequirements {
                    rule: RuleId::new(format!("operator:keep:{source}:{field}")),
                    logsource: found.logsource.clone(),
                    // The operator picked the field from the source's own records.
                    field_names: None,
                    fields: RequiredFields::Known(BTreeSet::from([FieldPath::new(field.as_str())])),
                    matches_raw_text: false,
                    stateful: false,
                    text_lines_only: false,
                    prefilter: Predicate::Always,
                });
            }
        }
        rules
    }
}

/// Where decisions and the audit log are kept.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    decisions: PathBuf,
    audit: PathBuf,
}

/// One audit log line.
#[derive(Debug, Serialize)]
struct AuditRecord<'a> {
    at: i64,
    profile: &'a str,
    actor: &'a str,
    #[serde(flatten)]
    action: &'a Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

impl Store {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            decisions: data_dir.join("operator.json"),
            audit: data_dir.join("audit.ndjson"),
        }
    }

    /// The stored decisions per profile; none when nothing was stored yet.
    pub(crate) fn load(&self) -> Result<BTreeMap<String, ProfileDecisions>, ServerError> {
        match std::fs::read_to_string(&self.decisions) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| ServerError::Config(format!("{}: {e}", self.decisions.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(ServerError::Io(format!(
                "{}: {e}",
                self.decisions.display()
            ))),
        }
    }

    pub(crate) fn save(
        &self,
        decisions: &BTreeMap<String, ProfileDecisions>,
    ) -> Result<(), ServerError> {
        let text = serde_json::to_string_pretty(decisions)
            .map_err(|e| ServerError::Io(format!("operator decisions: {e}")))?;
        crate::control::write_atomic(&self.decisions, &text)
    }

    /// Appends one action to the audit log, readable by this user only.
    pub(crate) fn audit(
        &self,
        at: i64,
        profile: &str,
        actor: &str,
        action: &Action,
        reason: Option<&str>,
    ) -> Result<(), ServerError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let io = |e: std::io::Error| ServerError::Io(format!("{}: {e}", self.audit.display()));
        if let Some(parent) = self.audit.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let line = serde_json::to_string(&AuditRecord {
            at,
            profile,
            actor,
            action,
            reason,
        })
        .map_err(|e| ServerError::Io(format!("audit record: {e}")))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.audit)
            .map_err(io)?;
        writeln!(file, "{line}").map_err(io)
    }
}

/// Why an action was not carried out.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// The request does not fit the current state (unknown profile, template not in shadow…).
    Invalid(String),
    /// Storing the decision or the audit record failed; nothing changed.
    Failed(ServerError),
}

impl crate::control::Shared {
    /// Carries out an operator action on a profile, records it in the history and the audit log,
    /// and stores held templates and kept fields.
    pub(crate) fn act(
        &self,
        request: &ActionRequest,
        actor: &str,
        now: i64,
    ) -> Result<(), Refusal> {
        let profile = self
            .profile(request.profile.as_deref())
            .ok_or_else(|| Refusal::Invalid("no such rule profile".to_owned()))?;
        let mut decisions = crate::control::lock(&self.decisions);
        let mut next = decisions.clone();
        let mine = next.entry(profile.name.clone()).or_default();
        let mut lifecycle = crate::control::lock(&profile.lifecycle);
        let mut status = profile
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let template = |t: &str| sluice_core::ids::TemplateId::new(t);
        match &request.action {
            Action::Hold { template: t } => {
                mine.held.insert(t.clone());
            }
            Action::Release { template: t } => {
                if !mine.held.remove(t) {
                    return Err(Refusal::Invalid(format!("{t} is not held")));
                }
            }
            Action::Approve { template: t } => {
                if !matches!(
                    lifecycle.stages().get(&template(t)),
                    Some(sluice_autopilot::Stage::Shadow { .. })
                ) {
                    return Err(Refusal::Invalid(format!("{t} has no recipe in shadow")));
                }
            }
            Action::Keep { source, field } => {
                if !self.sources.iter().any(|s| s.id.as_str() == source) {
                    return Err(Refusal::Invalid(format!("no source {source}")));
                }
                mine.kept
                    .entry(source.clone())
                    .or_default()
                    .insert(field.clone());
            }
            Action::Unkeep { source, field } => {
                let removed = mine.kept.get_mut(source).is_some_and(|f| f.remove(field));
                if !removed {
                    return Err(Refusal::Invalid(format!("{source}:{field} is not kept")));
                }
                mine.kept.retain(|_, fields| !fields.is_empty());
            }
            Action::Acknowledge { template: t, at } => {
                let found = status.history.iter_mut().find(|r| {
                    r.kind == "rolled_back" && &r.template == t && r.at == *at && !r.acknowledged
                });
                let Some(record) = found else {
                    return Err(Refusal::Invalid(format!("no open rollback of {t} at {at}")));
                };
                record.acknowledged = true;
            }
        }
        // Record first, so an action that cannot be audited never takes effect.
        self.store
            .audit(
                now,
                &profile.name,
                actor,
                &request.action,
                request.reason.as_deref(),
            )
            .map_err(Refusal::Failed)?;
        if next != *decisions {
            self.store.save(&next).map_err(Refusal::Failed)?;
            *decisions = next;
        }
        match &request.action {
            Action::Hold { template: t } => {
                lifecycle.hold(&template(t));
            }
            Action::Release { template: t } => {
                lifecycle.release(&template(t));
            }
            Action::Approve { template: t } => {
                lifecycle.approve(&template(t));
            }
            _ => {}
        }
        status.history.push(crate::status::TransitionRecord {
            at: now,
            kind: request.action.kind().to_owned(),
            template: request.action.target(),
            actor: Some(actor.to_owned()),
            reason: request.reason.clone(),
            acknowledged: false,
        });
        let decided = decisions.get(&profile.name).cloned().unwrap_or_default();
        status.operator = operator_status(&lifecycle, &decided, &status.history);
        Ok(())
    }
}

/// The operator decisions in force, for the status.
pub(crate) fn operator_status(
    lifecycle: &sluice_autopilot::Lifecycle,
    decisions: &ProfileDecisions,
    history: &[crate::status::TransitionRecord],
) -> crate::status::OperatorStatus {
    crate::status::OperatorStatus {
        approval_required: lifecycle.policy().approval,
        held: lifecycle.held().iter().map(ToString::to_string).collect(),
        approved: lifecycle
            .approved()
            .iter()
            .map(ToString::to_string)
            .collect(),
        kept: decisions
            .kept
            .iter()
            .flat_map(|(source, fields)| fields.iter().map(move |f| format!("{source}:{f}")))
            .collect(),
        unacknowledged_rollbacks: history
            .iter()
            .filter(|r| r.kind == "rolled_back" && !r.acknowledged)
            .count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_name_their_action() {
        let request: ActionRequest = serde_json::from_str(
            r#"{"action":"keep","source":"fw","field":"src_ip","reason":"IR needs it"}"#,
        )
        .expect("valid");
        assert_eq!(
            request.action,
            Action::Keep {
                source: "fw".into(),
                field: "src_ip".into()
            }
        );
        assert_eq!(request.action.target(), "fw:src_ip");
        assert_eq!(request.reason.as_deref(), Some("IR needs it"));
        assert!(serde_json::from_str::<ActionRequest>(r#"{"action":"delete_all"}"#).is_err());
    }

    #[test]
    fn decisions_and_the_audit_log_survive_on_disk() {
        let dir = std::env::temp_dir().join(format!("sluice-operator-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        assert!(store.load().expect("empty").is_empty());
        let mut decisions = BTreeMap::new();
        decisions.insert(
            "sigma".to_owned(),
            ProfileDecisions {
                held: BTreeSet::from(["t1".to_owned()]),
                kept: BTreeMap::new(),
            },
        );
        store.save(&decisions).expect("saved");
        assert_eq!(store.load().expect("loaded"), decisions);
        let hold = Action::Hold {
            template: "t1".into(),
        };
        store
            .audit(1, "sigma", "token", &hold, Some("why"))
            .expect("audited");
        store
            .audit(2, "sigma", "token", &hold, None)
            .expect("audited");
        let log = std::fs::read_to_string(dir.join("audit.ndjson")).expect("log");
        let lines: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).expect("json"))
            .collect();
        assert_eq!(lines.len(), 2, "appended, not overwritten");
        assert_eq!(lines[0]["action"], "hold");
        assert_eq!(lines[0]["template"], "t1");
        assert_eq!(lines[0]["reason"], "why");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

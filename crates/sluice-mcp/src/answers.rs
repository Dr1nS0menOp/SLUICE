//! Tool answers built from the control plane's status and rules: pure, so they are tested
//! without a server.

use serde_json::{Value, json};
use sluice_core::field::FieldPath;
use sluice_core::proof::Volume;
use sluice_server::{RuleInfo, Status};

/// Most transitions `status` returns.
const MAX_HISTORY: usize = 20;
/// Most templates `explain` returns.
const MAX_EXPLAINED: usize = 10;

pub(crate) fn status(status: &Status) -> Value {
    let count = |stage: &str| status.templates.iter().filter(|t| t.stage == stage).count();
    let history: Vec<Value> = status
        .history
        .iter()
        .rev()
        .take(MAX_HISTORY)
        .map(|t| json!({ "at": utc(t.at), "kind": t.kind, "template": t.template }))
        .collect();
    let last = status.last_cycle.as_ref().map(|c| {
        json!({
            "at": utc(c.at),
            "events": c.events,
            "templates": c.templates,
            "bytes_in": c.bytes_in,
            "bytes_out": c.bytes_out,
            "saved_percent": saved_percent(c.bytes_in, c.bytes_out),
            "alerts_on_full_data": c.alerts_full,
            "alerts_on_forwarded_data": c.alerts_forwarded,
            "detections_unchanged": c.proven,
        })
    });
    json!({
        "cycles": status.cycles,
        "last_cycle": last,
        "enforced": count("enforced"),
        "in_shadow": count("shadow"),
        "recent_transitions": history,
        "last_error": status.last_error,
    })
}

/// The templates whose id or pattern contains `query` (case-insensitive), largest first.
pub(crate) fn explain(status: &Status, query: &str) -> Value {
    let needle = query.to_lowercase();
    let mut found: Vec<_> = status
        .details
        .iter()
        .filter(|d| {
            d.template.to_lowercase().contains(&needle)
                || d.pattern.to_lowercase().contains(&needle)
        })
        .collect();
    found.sort_by_key(|d| std::cmp::Reverse(d.volume.bytes_in));
    let total = found.len();
    let templates: Vec<Value> = found
        .into_iter()
        .take(MAX_EXPLAINED)
        .map(|d| {
            json!({
                "template": d.template,
                "source": d.source,
                "pattern": d.pattern,
                "stage": d.stage,
                "what_is_done": if d.actions.is_empty() {
                    vec!["forwarded unchanged".to_owned()]
                } else {
                    d.actions.clone()
                },
                "why_not_more": d.adjustments,
                "proposed_by": d.provenance,
                "volume": volume(&d.volume),
            })
        })
        .collect();
    json!({ "matches": total, "templates": templates })
}

/// Rules that would lose data if `field` (or, without a field, any data of `source`) went
/// missing or changed upstream.
pub(crate) fn what_breaks(
    status: &Status,
    rules: &[RuleInfo],
    field: Option<&str>,
    source: Option<&str>,
) -> Result<Value, String> {
    let logsource = match source {
        Some(id) => Some(
            status
                .sources
                .iter()
                .find(|s| s.source == id)
                .map(|s| &s.logsource)
                .ok_or_else(|| format!("unknown source {id:?}"))?,
        ),
        None => None,
    };
    let field = field.map(FieldPath::new);
    let affected: Vec<Value> = rules
        .iter()
        .filter(|r| logsource.is_none_or(|l| r.logsource.may_apply_to(l)))
        .filter_map(|r| {
            let reason = match (&field, &r.fields) {
                (None, _) => "it applies to this source".to_owned(),
                (Some(_), None) => "its fields cannot be determined, so it may read any".to_owned(),
                (Some(field), Some(fields)) => {
                    let used = fields
                        .iter()
                        .map(FieldPath::new)
                        .find(|f| f.covers(field) || field.covers(f))?;
                    format!("it reads {used}")
                }
            };
            Some(json!({
                "rule": r.rule,
                "engine": r.engine,
                "stateful": r.stateful,
                "because": reason,
            }))
        })
        .collect();
    Ok(json!({
        "affected_rules": affected,
        "note": "Sluice never removes or summarizes data these rules need; this is about changes \
                 upstream (a renamed field, a silent source).",
    }))
}

pub(crate) fn coverage_gaps(status: &Status) -> Value {
    json!({
        "rules_without_data": status.coverage_gaps,
        "not_fully_understood": status.problems,
    })
}

pub(crate) fn source_health(status: &Status) -> Value {
    let sources: Vec<Value> = status
        .sources
        .iter()
        .map(|s| {
            let mut warnings = Vec::new();
            if s.volume.events == 0 {
                warnings.push("no events in the last window: is the source still sending?");
            }
            json!({
                "source": s.source,
                "logsource": s.logsource,
                "templates": s.templates,
                "volume": volume(&s.volume),
                "warnings": warnings,
            })
        })
        .collect();
    json!({ "sources": sources })
}

fn volume(v: &Volume) -> Value {
    json!({
        "events": v.events,
        "forwarded": v.forwarded,
        "summarized": v.summarized,
        "bytes_in": v.bytes_in,
        "bytes_out": v.bytes_out,
        "saved_percent": saved_percent(v.bytes_in, v.bytes_out),
    })
}

#[allow(clippy::cast_precision_loss, reason = "a percentage for people")]
fn saved_percent(bytes_in: u64, bytes_out: u64) -> f64 {
    if bytes_in == 0 {
        return 0.0;
    }
    let saved = 100.0 * (1.0 - bytes_out as f64 / bytes_in as f64);
    (saved * 10.0).round() / 10.0
}

pub(crate) fn utc(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0).map_or_else(
        || at.to_string(),
        |t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use sluice_core::logsource::LogSource;
    use sluice_server::{SourceHealth, TemplateDetail};

    use super::*;

    fn windows() -> LogSource {
        LogSource {
            product: Some("windows".into()),
            service: Some("security".into()),
            category: None,
        }
    }

    fn rule(id: &str, logsource: LogSource, fields: Option<&[&str]>) -> RuleInfo {
        RuleInfo {
            rule: id.into(),
            engine: "sigma".into(),
            logsource,
            fields: fields.map(|f| f.iter().map(|s| (*s).to_owned()).collect()),
            stateful: false,
        }
    }

    fn status() -> Status {
        Status {
            sources: vec![SourceHealth {
                source: "windows-security".into(),
                logsource: windows(),
                templates: 1,
                volume: Volume::default(),
            }],
            details: vec![TemplateDetail {
                template: "windows-security:4624:abc".into(),
                source: "windows-security".into(),
                pattern: "EventID=4624".into(),
                stage: "enforced".into(),
                volume: Volume::default(),
                actions: vec!["drop Message".into()],
                adjustments: vec![],
                provenance: Some("community".into()),
            }],
            ..Status::default()
        }
    }

    #[test]
    fn what_breaks_finds_rules_reading_the_field_or_any_field() {
        let linux = LogSource {
            product: Some("linux".into()),
            ..LogSource::default()
        };
        let rules = [
            rule(
                "logon",
                windows(),
                Some(&["TargetUserName", "process.name"]),
            ),
            rule("opaque", windows(), None),
            rule("other-field", windows(), Some(&["IpAddress"])),
            rule("linux", linux, Some(&["TargetUserName"])),
        ];
        let answer =
            what_breaks(&status(), &rules, Some("process"), Some("windows-security")).unwrap();
        let names: Vec<&str> = answer["affected_rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["rule"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["logon", "opaque"]);
        assert!(what_breaks(&status(), &rules, None, Some("nope")).is_err());
    }

    #[test]
    fn explain_matches_ids_and_patterns_and_says_unchanged() {
        let answer = explain(&status(), "4624");
        assert_eq!(answer["matches"], 1);
        assert_eq!(answer["templates"][0]["what_is_done"][0], "drop Message");
        assert_eq!(explain(&status(), "nothing")["matches"], 0);
    }

    #[test]
    fn a_silent_source_is_flagged() {
        let answer = source_health(&status());
        assert_eq!(
            answer["sources"][0]["warnings"].as_array().unwrap().len(),
            1
        );
    }
}

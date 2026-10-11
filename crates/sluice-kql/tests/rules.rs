//! The proof on Sentinel analytics rules, run by the real KQL engine (ADR 0015): reductions a
//! rule depends on are caught, reductions it does not see pass.
//!
//! Runs only with `SLUICE_KUSTO_URL` set (`scripts/kql-check.sh` starts the emulator and sets
//! it). The rules are written for this test in the style of Microsoft's; no third-party rule
//! content is in the repository.

#![allow(clippy::print_stderr, reason = "the test reports when it is skipped")]

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sluice_core::alert::RuleEngine;
use sluice_core::event::{Event, Timestamp};
use sluice_core::ids::{EventId, RuleId, SourceId};
use sluice_core::proof::prove;
use sluice_core::reduce::{Outcome, ReduceError, Reduced, Reducer};
use sluice_kql::{KustoEngine, Table};

const ENV: &str = "SLUICE_KUSTO_URL";

/// Brute force: three failed logons for one account on one host.
const BRUTE_FORCE: &str = "SecurityEvent
| where EventID == 4625
| summarize Failures = count() by TargetUserName, Computer
| where Failures >= 3";

/// A process whose command line, parsed out of `EventData`, names a credential dumper.
const DUMPER: &str = r#"SecurityEvent
| where EventID == 4688
| extend CommandLine = extract(@'Name="CommandLine">([^<]*)<', 1, EventData)
| where CommandLine has "mimikatz"
| project TimeGenerated, Computer, CommandLine"#;

/// A rule on a table the emulator does not have.
const SIGN_INS: &str = "SigninLogs | where ResultType == 50126";

#[test]
fn emulator_proof_catches_what_the_rules_read() {
    let Ok(url) = std::env::var(ENV) else {
        eprintln!("skipped: set {ENV} (scripts/kql-check.sh)");
        return;
    };
    let rules = [
        (RuleId::new("brute-force"), BRUTE_FORCE.to_owned()),
        (RuleId::new("dumper"), DUMPER.to_owned()),
        (RuleId::new("sign-ins"), SIGN_INS.to_owned()),
    ];
    let tables = BTreeMap::from([(SourceId::new("win"), Table::SecurityEvent)]);
    let engine = KustoEngine::connect(&url, &rules, tables).expect("emulator reachable");

    let skipped: Vec<&str> = engine.skipped().iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(skipped, ["sign-ins"], "{:?}", engine.skipped());

    let events = sample();
    let alerts = engine.alerts(&events).expect("rules run");
    let fired: Vec<&str> = alerts.iter().map(|a| a.rule.as_str()).collect();
    assert_eq!(fired, ["brute-force", "dumper"]);

    let holds = |plane: &Plane| prove(&events, &engine, plane).expect("proof runs").holds();
    assert!(
        holds(&Plane::Drop(4625, "EventData")),
        "no rule reads 4625's EventData"
    );
    assert!(
        !holds(&Plane::Drop(4625, "TargetUserName")),
        "brute force groups by it"
    );
    assert!(
        !holds(&Plane::Drop(4688, "EventData")),
        "the dumper rule parses it"
    );
    assert!(
        !holds(&Plane::SummarizeOne(4625)),
        "one failure fewer stays under 3"
    );
}

/// Three failed logons for alice, one for bob, a mimikatz process and an unrelated one.
fn sample() -> Vec<Event> {
    let process = |command: &str| {
        json!({
            "EventID": 4688,
            "EventData": format!(
                "<EventData><Data Name=\"NewProcessName\">C:\\x.exe</Data>\
                 <Data Name=\"CommandLine\">{command}</Data></EventData>"
            ),
        })
    };
    let failure = |user: &str| {
        json!({
            "EventID": 4625,
            "TargetUserName": user,
            "EventData": format!("<EventData><Data Name=\"TargetUserName\">{user}</Data></EventData>"),
        })
    };
    [
        failure("alice"),
        failure("alice"),
        failure("bob"),
        failure("alice"),
        process("x.exe mimikatz sekurlsa::logonpasswords"),
        process("x.exe --version"),
    ]
    .into_iter()
    .enumerate()
    .map(|(n, body)| {
        let mut fields: Map<String, Value> = serde_json::from_value(body).expect("object");
        fields.insert("Computer".into(), "ws1.example.test".into());
        fields.insert("TimeGenerated".into(), "2026-10-11T08:00:00Z".into());
        let n = u64::try_from(n).expect("small");
        Event {
            id: EventId(n),
            timestamp: Timestamp(1_791_792_000),
            source: SourceId::new("win"),
            fields,
        }
    })
    .collect()
}

/// A data plane that changes one event type.
enum Plane {
    /// Removes a field from every event with this `EventID`.
    Drop(u64, &'static str),
    /// Summarizes the first event with this `EventID`.
    SummarizeOne(u64),
}

impl Reducer for Plane {
    fn reduce(&self, event: &Event) -> Result<Reduced, ReduceError> {
        let id = event.fields.get("EventID").and_then(Value::as_u64);
        let mut body = event.fields.clone();
        let outcome = match *self {
            Self::Drop(target, field) if id == Some(target) => {
                body.remove(field);
                Outcome::Forwarded(body)
            }
            Self::SummarizeOne(target) if id == Some(target) && event.id == EventId(0) => {
                Outcome::Summarized
            }
            _ => Outcome::Forwarded(body),
        };
        Ok(Reduced {
            template: None,
            outcome,
        })
    }
}

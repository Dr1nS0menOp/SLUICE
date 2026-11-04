//! Splunk's searches in a real Splunk (ADR 0037): read by the reader, run by the engine, and
//! fetched over the REST API. They run when `SLUICE_SPLUNK_URL` names a Splunk for the proof
//! (`scripts/splunk-check.sh` starts one), with the password of its `admin` in
//! `SLUICE_SPLUNK_PASSWORD`; without it they pass without checking anything.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};
use sluice_core::alert::RuleEngine;
use sluice_core::event::{Event, Timestamp};
use sluice_core::ids::{EventId, RuleId, SourceId};
use sluice_rules::SplunkRules;
use sluice_splunk::{Auth, Proof, SplunkEngine};

struct Splunk {
    url: String,
    auth: Auth,
    hec: Option<String>,
}

fn splunk() -> Option<Splunk> {
    let url = std::env::var("SLUICE_SPLUNK_URL").ok()?;
    Some(Splunk {
        url,
        auth: Auth::Basic {
            user: "admin".to_owned(),
            password: std::env::var("SLUICE_SPLUNK_PASSWORD").unwrap_or_default(),
        },
        hec: std::env::var("SLUICE_SPLUNK_HEC").ok(),
    })
}

impl Splunk {
    fn proof(&self) -> Proof<'_> {
        Proof {
            url: &self.url,
            hec: self.hec.as_deref(),
            auth: &self.auth,
            insecure: true,
        }
    }

    /// A REST call the tests make themselves, to set Splunk up.
    fn call(&self, method: &str, path: &str, form: &[(&str, &str)]) -> sluice_http::Answer {
        let Auth::Basic { user, password } = &self.auth else {
            unreachable!("the tests log in with a password");
        };
        let body: Vec<String> = form
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    sluice_http::percent_encode(k),
                    sluice_http::percent_encode(v)
                )
            })
            .collect();
        sluice_http::Client::with(std::time::Duration::from_secs(60), true, 1 << 20)
            .send(
                method,
                &format!("{}{path}?output_mode=json", self.url),
                &[
                    ("authorization", sluice_http::basic_auth(user, password)),
                    (
                        "content-type",
                        "application/x-www-form-urlencoded".to_owned(),
                    ),
                ],
                (method == "POST").then(|| body.join("&")).as_deref(),
            )
            .expect("Splunk answers")
    }
}

const SEARCHES: &str = r"
[Failed Logon]
search = `wineventlog_security` EventCode=4625 User=*
enableSched = 1

[Failures By User]
search = index=main EventCode=4625 | stats count by User
enableSched = 1

[Logon Users]
search = NOT sourcetype=WinEventLog:System NOT eventtype=noise EventCode=4624 | table User
enableSched = 1

[Recent Only]
search = earliest=-15m@m EventCode=4625 | stats count
enableSched = 1

[Missing Lookup]
search = EventCode=4625 | lookup nobody_has_this user AS User
enableSched = 1

[Data Model]
search = | tstats count from datamodel=Authentication by Authentication.user
enableSched = 1

[Summarize]
search = EventCode=4625 | stats count by User | collect index=summary
enableSched = 1
";

const MACROS: &str = r"
[wineventlog_security]
definition = (index=wineventlog OR index=windows) sourcetype=XmlWinEventLog source=*Security
";

fn rules() -> SplunkRules {
    SplunkRules::parse([("savedsearches.conf", SEARCHES), ("macros.conf", MACROS)])
}

fn event(id: u64, fields: &Value) -> Event {
    Event {
        id: EventId(id),
        // 2020-05-02, as the APT29 sample: years ago, as samples often are.
        timestamp: Timestamp(1_588_377_600 + i64::try_from(id).expect("a small id")),
        source: SourceId::new("windows-security"),
        fields: fields.as_object().expect("an object").clone(),
    }
}

fn events() -> Vec<Event> {
    vec![
        event(
            1,
            &json!({ "EventCode": 4625, "User": "alice", "Message": "An account failed" }),
        ),
        event(
            2,
            &json!({ "EventCode": 4625, "User": "alice", "Message": "An account failed" }),
        ),
        event(
            3,
            &json!({ "EventCode": 4625, "User": "bob", "Message": "An account failed" }),
        ),
        event(
            4,
            &json!({ "EventCode": 4624, "User": "carol", "Message": "An account logged on" }),
        ),
    ]
}

fn without(events: &[Event], id: u64, field: &str) -> Vec<Event> {
    events
        .iter()
        .cloned()
        .map(|mut e| {
            if e.id == EventId(id) {
                e.fields.remove(field);
            }
            e
        })
        .collect()
}

#[test]
fn c5_in_splunk_a_removed_field_a_search_reads_changes_its_alerts() {
    let Some(splunk) = splunk() else {
        return;
    };
    let rules = rules();
    let engine = SplunkEngine::connect(&splunk.proof(), rules.queries()).expect("connects");
    assert_ne!(engine.version(), "");
    let run: BTreeSet<&str> = engine.searches().map(RuleId::as_str).collect();
    assert_eq!(
        run,
        BTreeSet::from([
            "splunk:Failed Logon",
            "splunk:Failures By User",
            "splunk:Logon Users",
            "splunk:Recent Only",
        ])
    );
    let skipped: Vec<(&str, &str)> = engine
        .skipped()
        .iter()
        .map(|(id, why)| (id.as_str(), why.as_str()))
        .collect();
    assert_eq!(skipped.len(), 3, "{skipped:?}");
    assert!(skipped[0].0 == "splunk:Data Model" && skipped[0].1.contains("generating"));
    assert!(skipped[1].0 == "splunk:Missing Lookup" && skipped[1].1.contains("lookup"));
    // Never run, so nothing is written to the Splunk it was given.
    assert!(skipped[2].0 == "splunk:Summarize" && skipped[2].1.contains("`collect`"));

    let events = events();
    let full = engine.alerts(&events).expect("the searches run");
    let by_rule = |rule: &str| full.iter().filter(|a| a.rule.as_str() == rule).count();
    // Whatever index, sourcetype, event type or time range a search names, it runs on every
    // event, years old as they are.
    assert_eq!(by_rule("splunk:Failed Logon"), 3, "{full:?}");
    assert_eq!(by_rule("splunk:Failures By User"), 2, "{full:?}");
    assert_eq!(by_rule("splunk:Logon Users"), 1, "{full:?}");
    assert_eq!(by_rule("splunk:Recent Only"), 1, "{full:?}");
    // An event a search returns alerts on that event.
    assert!(
        full.iter()
            .any(|a| a.rule.as_str() == "splunk:Failed Logon" && a.event == EventId(3))
    );

    // Another evaluation, in another index: the same alerts.
    assert_eq!(engine.alerts(&events).expect("runs again"), full);
    // A field no search reads may go.
    let trimmed: Vec<Event> = events
        .iter()
        .cloned()
        .map(|mut e| {
            e.fields.remove("Message");
            e
        })
        .collect();
    assert_eq!(engine.alerts(&trimmed).expect("runs"), full);
    // One they read may not: event 3 no longer matches `User=*`, and bob's count is gone.
    let changed = engine.alerts(&without(&events, 3, "User")).expect("runs");
    assert_ne!(changed, full);
    assert!(
        !changed
            .iter()
            .any(|a| a.rule.as_str() == "splunk:Failed Logon" && a.event == EventId(3))
    );
    // Neither may an event: the count of `Recent Only` changes.
    let fewer = engine.alerts(&events[1..]).expect("runs");
    assert_ne!(
        fewer
            .iter()
            .filter(|a| a.rule.as_str() == "splunk:Recent Only")
            .collect::<Vec<_>>(),
        full.iter()
            .filter(|a| a.rule.as_str() == "splunk:Recent Only")
            .collect::<Vec<_>>()
    );
}

#[test]
fn c5_in_splunk_events_it_cannot_search_fail_the_evaluation() {
    let Some(splunk) = splunk() else {
        return;
    };
    let rules = rules();
    let engine = SplunkEngine::connect(&splunk.proof(), rules.queries()).expect("connects");
    let mut events = events();
    events[0].timestamp = Timestamp(-1);
    let error = engine
        .alerts(&events)
        .expect_err("not an empty set of alerts");
    assert!(error.to_string().contains("1970 to 2038"), "{error}");
}

#[test]
fn in_splunk_large_events_lose_the_fields_splunk_does_not_extract() {
    // Splunk extracts a JSON event's fields from its first 10,240 characters (`[kv]
    // maxchars`); the proof sees what Splunk's searches see.
    let Some(splunk) = splunk() else {
        return;
    };
    let searches = [(RuleId::new("splunk:tail"), "Tail=end".to_owned())];
    let engine = SplunkEngine::connect(&splunk.proof(), &searches).expect("connects");
    let mut fields = Map::new();
    fields.insert("Pad".into(), json!("x".repeat(20_000)));
    fields.insert("Tail".into(), json!("end"));
    let large = Event {
        id: EventId(1),
        timestamp: Timestamp(1_767_225_600),
        source: SourceId::new("s"),
        fields,
    };
    assert!(
        engine
            .alerts(std::slice::from_ref(&large))
            .expect("runs")
            .is_empty()
    );
    let mut small = large;
    small.fields.remove("Pad");
    assert_eq!(engine.alerts(&[small]).expect("runs").len(), 1);
}

#[test]
fn in_splunk_a_fetch_reads_the_searches_and_macros_it_runs() {
    let Some(splunk) = splunk() else {
        return;
    };
    let tag = std::process::id();
    let search_name = format!("sluice fetch test {tag}");
    let macro_name = format!("sluice_fetch_test_{tag}");
    let created = splunk.call(
        "POST",
        "/servicesNS/nobody/search/admin/macros",
        &[
            ("name", &macro_name),
            ("definition", "index=windows EventCode=4625"),
        ],
    );
    assert!(created.is_success(), "{}", created.body);
    let created = splunk.call(
        "POST",
        "/servicesNS/nobody/search/saved/searches",
        &[
            ("name", &search_name),
            ("search", &format!("`{macro_name}` | stats count by User")),
            ("is_scheduled", "1"),
            ("cron_schedule", "*/15 * * * *"),
        ],
    );
    assert!(created.is_success(), "{}", created.body);

    let fetched = sluice_splunk::inventory::fetch(
        &sluice_splunk::inventory::Target {
            url: &splunk.url,
            auth: &splunk.auth,
            insecure: true,
        },
        "2026-11-03T00:00:00Z",
    );
    let encoded = |name: &str| sluice_http::percent_encode(name);
    splunk.call(
        "DELETE",
        &format!(
            "/servicesNS/nobody/search/saved/searches/{}",
            encoded(&search_name)
        ),
        &[],
    );
    splunk.call(
        "DELETE",
        &format!(
            "/servicesNS/nobody/search/admin/macros/{}",
            encoded(&macro_name)
        ),
        &[],
    );
    let inventory = fetched.expect("the fetch reads a real Splunk");
    assert!(inventory.manifest.complete, "{:?}", inventory.manifest);
    assert_eq!(inventory.manifest.system, "splunk");
    let rules = SplunkRules::parse(
        inventory
            .files
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str())),
    );
    let id = RuleId::new(format!("splunk:{search_name}"));
    let query = rules
        .queries()
        .iter()
        .find(|(rule, _)| *rule == id)
        .map(|(_, q)| q.as_str());
    assert_eq!(
        query,
        Some("index=windows EventCode=4625 | stats count by User"),
        "{:?}",
        rules.problems()
    );
}

//! Templates follow the kind of event, not only its shape (ADR 0019).

use std::collections::BTreeSet;

use serde_json::{Value, json};
use sluice_core::event::{Event, Timestamp};
use sluice_core::field::FieldPath;
use sluice_core::ids::EventId;
use sluice_core::logsource::LogSource;
use sluice_core::schema::Schema;
use sluice_core::source::{Source, SourceFormat};
use sluice_core::template::TemplateShape;
use sluice_discover::{DiscoverConfig, Discovery, discover};

fn source(id: &str, product: &str, format: SourceFormat, event_type: &[&str]) -> Source {
    Source {
        id: id.into(),
        logsource: LogSource {
            product: Some(product.into()),
            ..LogSource::default()
        },
        format,
        schema: Schema::Sigma,
        event_type: event_type.iter().map(|f| FieldPath::from(*f)).collect(),
    }
}

fn events(source: &str, records: impl IntoIterator<Item = Value>) -> Vec<Event> {
    records
        .into_iter()
        .zip(0u64..)
        .map(|(record, n)| Event {
            id: EventId(n),
            timestamp: Timestamp(i64::try_from(n).unwrap_or(0)),
            source: source.into(),
            fields: record.as_object().expect("an object").clone(),
        })
        .collect()
}

/// More users than the categorical limit (names without digits, which masking would merge).
const USERS: [&str; 9] = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan",
];

/// The review's case: three failed logons among 597 accepted ones.
fn sshd() -> (Vec<Event>, Discovery) {
    let lines = (0..600).map(|n| {
        let line = if (150..153).contains(&n) {
            format!(
                "Oct 11 08:02:{:02} web01 sshd[{}]: Failed password for root from 203.0.113.5 \
                 port {} ssh2",
                n % 60,
                4000 + n,
                40000 + n
            )
        } else {
            format!(
                "Oct 11 08:02:{:02} web01 sshd[{}]: Accepted password for {} from 10.0.0.{} \
                 port {} ssh2",
                n % 60,
                4000 + n,
                USERS[n % USERS.len()],
                n % 200,
                40000 + n
            )
        };
        json!({ "message": line })
    });
    let text = SourceFormat::Text {
        field: "message".into(),
    };
    let sources = [source("auth", "linux", text, &[])];
    let events = events("auth", lines);
    let discovery = discover(DiscoverConfig::default(), &sources, &events);
    (events, discovery)
}

#[test]
fn rare_failed_logons_keep_a_template_of_their_own() {
    let (events, discovery) = sshd();
    let failed: BTreeSet<_> = events[150..153]
        .iter()
        .map(|e| &discovery.assignments[&e.id])
        .collect();
    assert_eq!(failed.len(), 1, "the three failures share one template");
    let id = failed.into_iter().next().expect("one");
    let template = discovery
        .templates
        .iter()
        .find(|t| &t.id == id)
        .expect("known");
    assert_eq!(template.stats.events, 3, "{}", template.pattern);
    assert!(template.pattern.contains("Failed"), "{}", template.pattern);
    assert!(
        events[..150]
            .iter()
            .all(|e| &discovery.assignments[&e.id] != id),
        "no accepted logon shares it"
    );
}

#[test]
fn a_parameter_with_many_values_stays_a_wildcard() {
    let (_, discovery) = sshd();
    // Nine users is more than the categorical limit: one template for every accepted logon.
    let accepted: Vec<_> = discovery
        .templates
        .iter()
        .filter(|t| t.pattern.contains("Accepted"))
        .collect();
    assert_eq!(accepted.len(), 1, "{accepted:#?}");
    assert!(
        accepted[0].pattern.contains("for <*> from"),
        "{}",
        accepted[0].pattern
    );
    assert_eq!(accepted[0].stats.events, 597);
    assert!(matches!(accepted[0].shape, TemplateShape::Text { .. }));
}

#[test]
fn a_source_names_its_own_event_type_fields() {
    let records = (0..40).map(|n| {
        json!({
            "kind": if n == 7 { "admin.role.grant" } else { "user.login" },
            "user": format!("u{n}"),
        })
    });
    let plain = source("idp", "custom", SourceFormat::Json, &[]);
    let typed = source("idp", "custom", SourceFormat::Json, &["kind"]);
    let events = events("idp", records);
    let count = |s: &Source| {
        discover(DiscoverConfig::default(), std::slice::from_ref(s), &events)
            .templates
            .len()
    };
    assert_eq!(count(&plain), 1, "same keys, one shape");
    assert_eq!(count(&typed), 2, "the rare grant is a template of its own");
}

/// 4624 logons, most without the optional `ElevatedToken`, 300 with it, and two with a field no
/// other logon has.
fn logons(extra: &str) -> Vec<Event> {
    events(
        "sec",
        (0..1_000).map(|n| {
            let mut record = json!({ "EventID": 4624, "TargetUserName": format!("u{n}") });
            if n % 1_000 >= 700 {
                record["ElevatedToken"] = json!("%%1842");
            }
            if n == 5 || n == 6 {
                record[extra] = json!("x");
            }
            record
        }),
    )
}

fn security() -> Source {
    source("sec", "windows", SourceFormat::Json, &[])
}

#[test]
fn frequent_shapes_of_one_kind_share_a_template_rare_ones_do_not() {
    let events = logons("RareField");
    let discovery = discover(
        DiscoverConfig::default(),
        std::slice::from_ref(&security()),
        &events,
    );
    assert_eq!(discovery.templates.len(), 2, "{:#?}", discovery.templates);
    let common = &discovery.assignments[&events[0].id];
    assert_eq!(
        common, &discovery.assignments[&events[800].id],
        "both frequent shapes"
    );
    let rare = &discovery.assignments[&events[5].id];
    assert_ne!(rare, common);
    let template = discovery
        .templates
        .iter()
        .find(|t| &t.id == common)
        .expect("known");
    assert_eq!(template.stats.events, 998);
    let TemplateShape::Keyset {
        variants, paths, ..
    } = &template.shape
    else {
        panic!("a JSON template");
    };
    assert_eq!(variants.len(), 2);
    assert!(paths.contains("ElevatedToken"));
    assert!(!paths.contains("RareField"));
}

#[test]
fn a_new_optional_field_keeps_the_template_of_its_kind() {
    // An agent update: every logon now carries a field it did not before.
    let before = discover(
        DiscoverConfig::default(),
        std::slice::from_ref(&security()),
        &logons("RareField"),
    );
    let mut updated = logons("RareField");
    for event in &mut updated {
        event.fields.insert("AgentVersion".into(), json!("2"));
    }
    let after = discover(
        DiscoverConfig::default(),
        std::slice::from_ref(&security()),
        &updated,
    );
    assert_eq!(
        before.assignments[&EventId(0)],
        after.assignments[&EventId(0)],
        "the same template id, so its recipe keeps its stage"
    );
}

#[test]
fn cloudtrail_is_split_by_service_and_call_without_configuration() {
    let records = (0..10).map(|n| {
        json!({
            "eventSource": "iam.amazonaws.com",
            "eventName": if n == 0 { "CreateAccessKey" } else { "GetUser" },
        })
    });
    let trail = source("trail", "aws", SourceFormat::Json, &[]);
    let discovery = discover(
        DiscoverConfig::default(),
        std::slice::from_ref(&trail),
        &events("trail", records),
    );
    let ids: BTreeSet<&str> = discovery.templates.iter().map(|t| t.id.as_str()).collect();
    assert!(
        ids.iter()
            .any(|id| id.starts_with("trail:iam.amazonaws.com/CreateAccessKey:")),
        "{ids:?}"
    );
    assert_eq!(ids.len(), 2);
}

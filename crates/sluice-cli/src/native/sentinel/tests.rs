use std::collections::BTreeSet;

use serde_json::{Value, json};
use sluice_kql::{Table, Transformation};

use super::*;

fn rule() -> Value {
    json!({
        "id": "/subscriptions/x/dataCollectionRules/r",
        "location": "westeurope",
        "properties": {
            "immutableId": "dcr-1",
            "streamDeclarations": { "Custom-S": { "columns": [
                { "name": "EventID", "type": "int" },
                { "name": "EventData", "type": "string" },
            ] } },
            "dataFlows": [
                { "streams": ["Custom-S"], "destinations": ["ws"],
                  "transformKql": "source | extend X = 1",
                  "outputStream": "Microsoft-SecurityEvent" },
                { "streams": ["Custom-W"], "destinations": ["ws"],
                  "transformKql": "source", "outputStream": "Microsoft-WindowsEvent" },
            ],
        },
    })
}

const GENERATED: &str = "source\n| extend __sluice_s = \"1\"\n| extend EventData = \"\"";

fn proven(flow: &Flow) -> Proven {
    Proven {
        source: "win".to_owned(),
        table: Table::SecurityEvent,
        generated: Transformation {
            kql: GENERATED.to_owned(),
            templates: BTreeSet::new(),
            columns: BTreeSet::from(["EventData".to_owned()]),
            left_out: Vec::new(),
        },
        kql: flow.then(GENERATED),
    }
}

fn flow(rule: &Value) -> Flow {
    Flow::of(Some(rule), Table::SecurityEvent).expect("the rule has a flow into the table")
}

#[test]
fn c2_every_transformed_stream_also_flows_whole_into_an_archive() {
    let flow = flow(&rule());
    let one = proven(&flow);
    let written = deployment(rule(), &[(one, flow)]).expect("a deployable rule");
    let flows = written["properties"]["dataFlows"]
        .as_array()
        .expect("flows");
    assert_eq!(flows.len(), 3);
    assert_eq!(
        flows[0]["transformKql"],
        "source | extend X = 1\n| extend __sluice_s = \"1\"\n| extend EventData = \"\""
    );
    assert_eq!(flows[1]["transformKql"], "source");
    assert_eq!(
        flows[2],
        json!({
            "streams": ["Custom-S"],
            "destinations": ["ws"],
            "transformKql": "source",
            "outputStream": "Custom-SluiceSecurityEventArchive_CL",
        })
    );
    assert!(written.get("id").is_none());
    assert!(written["properties"].get("immutableId").is_none());
}

#[test]
fn c2_a_rule_written_twice_keeps_one_archive_flow() {
    let first = flow(&rule());
    let once = deployment(rule(), &[(proven(&first), first)]).expect("a deployable rule");
    let second = flow(&once);
    let twice = deployment(once.clone(), &[(proven(&second), second)]).expect("again");
    let archives = twice["properties"]["dataFlows"]
        .as_array()
        .expect("flows")
        .iter()
        .filter(|f| f["outputStream"] == "Custom-SluiceSecurityEventArchive_CL")
        .count();
    assert_eq!(archives, 1);
    assert_eq!(
        twice, once,
        "the second run replaces Sluice's part instead of adding one"
    );
}

#[test]
fn the_archive_table_has_the_stream_columns_and_a_time() {
    let table = archive_table(Table::SecurityEvent, &flow(&rule()));
    assert_eq!(table["properties"]["plan"], "Auxiliary");
    let names: Vec<&str> = table["properties"]["schema"]["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert_eq!(names, ["TimeGenerated", "EventID", "EventData"]);
}

#[test]
fn a_rule_without_a_flow_into_the_table_is_refused() {
    assert!(Flow::of(Some(&rule()), Table::Syslog).is_err());
}

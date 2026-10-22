use std::collections::BTreeSet;

use serde_json::{Value, json};
use sluice_kql::{SLUICE_PART, SLUICE_PART_END, Table, Transformation};

use super::dcr::{archive, archive_table, arm_shape, deployment, without_sluice_part};
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
    Flow::of(Some(rule), &Table::SecurityEvent).expect("the rule has a flow into the table")
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
    let table = archive_table(&Table::SecurityEvent, &flow(&rule()));
    assert_eq!(table["properties"]["plan"], "Auxiliary");
    let names: Vec<&str> = table["properties"]["schema"]["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert_eq!(names, ["TimeGenerated", "EventID", "EventData"]);
}

/// The rule as `az monitor data-collection rule show` prints it: `properties` flattened into
/// the top level, with the resource group the CLI adds.
fn flattened() -> Value {
    let mut flat = rule()["properties"].clone();
    let object = flat.as_object_mut().expect("an object");
    object.insert("id".to_owned(), rule()["id"].clone());
    object.insert("location".to_owned(), rule()["location"].clone());
    object.insert("resourceGroup".to_owned(), json!("rg"));
    flat
}

#[test]
fn the_cli_shape_of_a_rule_is_read_and_deployed_as_the_api_shape() {
    let api = rule();
    let cli = arm_shape(flattened());
    assert_eq!(cli["properties"], api["properties"]);
    assert_eq!(cli["location"], api["location"]);
    let (from_api, from_cli) = (flow(&api), flow(&cli));
    let written_api = deployment(api, &[(proven(&from_api), from_api)]).expect("from the API");
    let written_cli = deployment(cli, &[(proven(&from_cli), from_cli)]).expect("from the CLI");
    assert_eq!(written_cli, written_api);
}

#[test]
fn a_rule_in_the_api_shape_is_left_as_it_is() {
    assert_eq!(arm_shape(rule()), rule());
}

#[test]
fn a_rule_without_a_flow_into_the_table_is_refused() {
    assert!(Flow::of(Some(&rule()), &Table::Syslog).is_err());
}

fn custom() -> Table {
    let column = |name: &str, field: &str| sluice_kql::CustomColumn {
        name: name.to_owned(),
        kind: "string".to_owned(),
        field: field.to_owned(),
    };
    Table::custom(
        "Win_CL",
        vec![
            column("F_timestamp", "@timestamp"),
            column("Message", "Message"),
        ],
    )
    .expect("a custom table")
}

#[test]
fn a_custom_tables_flow_runs_sluices_part_first_on_the_stream_names() {
    let flow = Flow::of(None, &custom()).expect("a flow");
    assert!(flow.first);
    assert_eq!(
        flow.stream,
        [
            ("@timestamp".to_owned(), "string".to_owned()),
            ("Message".to_owned(), "string".to_owned())
        ]
    );
    let flow = Flow {
        before: "source | project-rename F_timestamp = ['@timestamp']".to_owned(),
        ..flow
    };
    assert_eq!(
        flow.then("source\n| extend x = 1"),
        "source\n| extend x = 1 | project-rename F_timestamp = ['@timestamp']"
    );
    assert_eq!(flow.then("source"), flow.before);
    assert_eq!(archive(&custom()), "SluiceWinArchive_CL");
    assert_eq!(
        archive(&Table::SecurityEvent),
        "SluiceSecurityEventArchive_CL"
    );
}

#[test]
fn a_part_sluice_wrote_before_goes_wherever_it_is() {
    let part = format!("{SLUICE_PART} = 1\n| extend y = 2\n{SLUICE_PART_END}");
    assert_eq!(
        without_sluice_part(&format!("source\n{part} | extend TimeGenerated = now()")),
        "source | extend TimeGenerated = now()"
    );
    assert_eq!(
        without_sluice_part(&format!("source | where a == 1\n{part}")),
        "source | where a == 1"
    );
    assert_eq!(without_sluice_part("source | x"), "source | x");
}

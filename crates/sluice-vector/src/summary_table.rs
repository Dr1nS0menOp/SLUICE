//! The Sentinel table Sluice's summary records go to (ADR 0029): one row per window, source, kind
//! of event and summary keys, with the number of events counted instead of sent.
//!
//! A table that takes one shape of record (`SecurityEvent`) has no columns for a summary, and a
//! data collection rule drops what its stream does not declare, so summaries need a table of
//! their own. The `SluiceCounts` function reads it the way queries count events.

use serde_json::{Value, json};

/// The custom table summaries are stored in.
pub const SUMMARY_TABLE: &str = "SluiceSummary_CL";

/// The data collection rule's stream that receives them, for the `azure_logs_ingestion` sink.
pub const SUMMARY_STREAM: &str = "Custom-SluiceSummary";

/// The summary record's fields as the stream declares them; the rest of the record (Sluice's
/// grouping key) is not kept.
const COLUMNS: [(&str, &str); 4] = [
    ("sluice_source", "string"),
    ("sluice_template", "string"),
    ("sluice_keys", "dynamic"),
    ("sluice_count", "long"),
];

/// The function to save in the workspace as `SluiceCounts`: every summary row as `Source`,
/// `Template`, `Keys` and `Count`, with the time it was stored.
pub const SUMMARY_COUNTS: &str = "SluiceSummary_CL\n| project TimeGenerated, Source = sluice_source, \
                                  Template = sluice_template, Keys = sluice_keys, Count = \
                                  sluice_count\n";

/// The body to create the table (`PUT …/workspaces/{ws}/tables/SluiceSummary_CL`).
#[must_use]
pub fn summary_table() -> Value {
    let mut columns = vec![json!({ "name": "TimeGenerated", "type": "datetime" })];
    columns.extend(
        COLUMNS
            .iter()
            .map(|(name, kind)| json!({ "name": name, "type": kind })),
    );
    json!({ "properties": { "schema": { "name": SUMMARY_TABLE, "columns": columns } } })
}

/// The data collection rule (kind `Direct`) that stores summary records in the table, stamped
/// with the time of ingestion.
#[must_use]
pub fn summary_dcr(location: &str, workspace_resource_id: &str) -> Value {
    let stream: Vec<Value> = COLUMNS
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    let names: Vec<&str> = COLUMNS.iter().map(|(name, _)| *name).collect();
    json!({
        "location": location,
        "kind": "Direct",
        "properties": {
            "streamDeclarations": { SUMMARY_STREAM: { "columns": stream } },
            "destinations": {
                "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
            },
            "dataFlows": [{
                "streams": [SUMMARY_STREAM],
                "destinations": ["sentinel"],
                "transformKql": format!(
                    "source | extend TimeGenerated = now() | project TimeGenerated, {}",
                    names.join(", ")
                ),
                "outputStream": format!("Custom-{SUMMARY_TABLE}"),
            }],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_and_the_rule_declare_the_same_columns() {
        let table = summary_table();
        let columns = table["properties"]["schema"]["columns"].as_array().unwrap();
        assert_eq!(columns.len(), COLUMNS.len() + 1);
        let dcr = summary_dcr("westeurope", "/ws");
        let flow = &dcr["properties"]["dataFlows"][0];
        assert_eq!(flow["outputStream"], "Custom-SluiceSummary_CL");
        assert!(
            flow["transformKql"]
                .as_str()
                .unwrap()
                .ends_with("sluice_keys, sluice_count")
        );
        assert_eq!(
            dcr["properties"]["streamDeclarations"][SUMMARY_STREAM]["columns"]
                .as_array()
                .unwrap()
                .len(),
            COLUMNS.len()
        );
    }
}

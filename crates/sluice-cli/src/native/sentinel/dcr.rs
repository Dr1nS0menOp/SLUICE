//! The data collection rule of `--sentinel-native`: the data flow a transformation joins, and the
//! rule written back with each proven transformation in its table's flow and, next to it, an
//! untransformed flow of the same stream into an archive table (contract rule 2).

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sluice_kql::{SLUICE_PART, SLUICE_PART_END, Table};

use super::Proven;

/// The top-level keys of a data collection rule as a resource; the rest of the rule sits under
/// `properties`.
const RESOURCE_KEYS: [&str; 10] = [
    "id",
    "name",
    "type",
    "location",
    "tags",
    "kind",
    "etag",
    "systemData",
    "identity",
    "resourceGroup",
];

/// `rule` in the shape of the Azure Resource Manager API, with the rule itself under
/// `properties`. `az monitor data-collection rule show` flattens `properties` into the top
/// level; the rule Sluice writes is put back through the API, so it reads both shapes and keeps
/// the API's.
pub(super) fn arm_shape(rule: Value) -> Value {
    let Value::Object(mut top) = rule else {
        return rule;
    };
    if top.contains_key("properties") {
        return Value::Object(top);
    }
    let properties: serde_json::Map<String, Value> = top
        .iter()
        .filter(|(key, _)| !RESOURCE_KEYS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    top.retain(|key, _| RESOURCE_KEYS.contains(&key.as_str()));
    top.insert("properties".to_owned(), Value::Object(properties));
    Value::Object(top)
}

/// What a data flow into a table gives the transformation: the stream's columns, and the
/// transformation the flow already has, which Sluice's runs after.
pub(super) struct Flow {
    /// Name and type of each column, as the stream declares it.
    pub(super) stream: Vec<(String, String)>,
    pub(super) before: String,
    /// Sluice's part runs before the flow's own transformation, on the stream's names: a
    /// custom table's flow renames fields that are no valid column names, and Vector removes
    /// fields before the flow sees them too.
    pub(super) first: bool,
    /// The stream's name, when the records go through a rule of their own.
    pub(super) name: Option<String>,
}

impl Flow {
    pub(super) fn of(rule: Option<&Value>, table: &Table) -> Result<Self> {
        let Some(rule) = rule else {
            return Ok(Self {
                stream: table
                    .stream_columns()
                    .into_iter()
                    .map(|(name, kind)| (name.to_owned(), kind.to_owned()))
                    .collect(),
                before: "source".to_owned(),
                name: None,
                first: matches!(table, Table::Custom(_)),
            });
        };
        let output = table.output_stream();
        let properties = &rule["properties"];
        let flow = properties["dataFlows"]
            .as_array()
            .and_then(|flows| flows.iter().find(|f| f["outputStream"] == output.as_str()))
            .with_context(|| format!("the data collection rule has no data flow into {output}"))?;
        let name = flow["streams"][0]
            .as_str()
            .context("the data flow names no stream")?;
        let stream: Vec<(String, String)> = properties["streamDeclarations"][name]["columns"]
            .as_array()
            .with_context(|| format!("the data collection rule does not declare {name}"))?
            .iter()
            .filter_map(|c| {
                Some((
                    c["name"].as_str()?.to_owned(),
                    c["type"].as_str()?.to_owned(),
                ))
            })
            .collect();
        let before = flow["transformKql"].as_str().unwrap_or("source").trim();
        // A rule Sluice wrote before: its own part goes, so a new one replaces it.
        let before = without_sluice_part(before);
        let before = before.as_str();
        if !before.starts_with("source") {
            bail!(
                "the data flow into {output} has a transformation that does not start with `source`"
            );
        }
        Ok(Self {
            stream,
            before: before.to_owned(),
            name: Some(name.to_owned()),
            first: matches!(table, Table::Custom(_)),
        })
    }

    /// The flow's transformation and `kql` (both start with `source`), in the order they run.
    pub(super) fn then(&self, kql: &str) -> String {
        if kql == "source" {
            return self.before.clone();
        }
        if self.first {
            format!("{kql}{}", &self.before["source".len()..])
        } else {
            format!("{}{}", self.before, &kql["source".len()..])
        }
    }

    pub(super) fn declared(&self) -> Vec<(&str, &str)> {
        self.stream
            .iter()
            .map(|(name, kind)| (name.as_str(), kind.as_str()))
            .collect()
    }
}

/// `kql` without the part Sluice wrote into it before: from [`SLUICE_PART`] to the end of
/// [`SLUICE_PART_END`] when the flow's own part follows it, else to the end.
pub(super) fn without_sluice_part(kql: &str) -> String {
    let Some(at) = kql.find(SLUICE_PART) else {
        return kql.to_owned();
    };
    let head = kql[..at].trim_end();
    match kql[at..].find(SLUICE_PART_END) {
        Some(end) => format!(
            "{head} {}",
            kql[at + end + SLUICE_PART_END.len()..].trim_start()
        )
        .trim_end()
        .to_owned(),
        None => head.to_owned(),
    }
}

/// The archive table of `table`: `Sluice<Table>Archive_CL`, a custom table's name without its
/// `_CL`.
pub(super) fn archive(table: &Table) -> String {
    let name = table.name();
    format!(
        "Sluice{}Archive_CL",
        name.strip_suffix("_CL").unwrap_or(name)
    )
}

/// Writes `rule` with every proven transformation in its table's data flow and an archive flow
/// next to each, the archive tables' definitions, and the transformations themselves.
pub(super) fn write(rule: Value, proven: &[(Proven, Flow)], dir: &Path) -> Result<()> {
    let rule = deployment(rule, proven)?;
    for (one, flow) in proven {
        crate::output::write(
            &dir.join(format!("{}.table.json", archive(&one.table))),
            &(serde_json::to_string_pretty(&archive_table(&one.table, flow))? + "\n"),
        )?;
        crate::output::write(
            &dir.join(format!("{}.transform.kql", one.source)),
            &(one.kql.clone() + "\n"),
        )?;
        let table = one.table.name();
        if let Some(function) = sluice_kql::rebuilding_function(&one.table, &one.generated.implied)
        {
            let path = dir.join(format!("{table}Full.kql"));
            crate::output::write(&path, &function)?;
            println!(
                "  native  wrote {}: save it in the workspace as the function {table}Full, which \
                 puts back the {} implied value(s) the rule empties",
                path.display(),
                one.generated.implied.len()
            );
        }
    }
    let path = dir.join("dcr.json");
    crate::output::write(&path, &(serde_json::to_string_pretty(&rule)? + "\n"))?;
    let tables: Vec<String> = proven.iter().map(|(one, _)| archive(&one.table)).collect();
    println!(
        "  native  wrote {}: first create {} from the .table.json next to it (Auxiliary plan, \
         every record kept whole), then update the rule with it",
        path.display(),
        tables.join(", ")
    );
    Ok(())
}

/// `rule` as it can be put back: each proven transformation in its table's data flow, and one
/// untransformed flow of the same stream into the table's archive.
pub(super) fn deployment(mut rule: Value, proven: &[(Proven, Flow)]) -> Result<Value> {
    if let Some(object) = rule.as_object_mut() {
        for key in ["id", "name", "type", "etag", "systemData", "resourceGroup"] {
            object.remove(key);
        }
    }
    if let Some(properties) = rule["properties"].as_object_mut() {
        for key in ["immutableId", "endpoints", "provisioningState"] {
            properties.remove(key);
        }
    }
    let flows = rule["properties"]["dataFlows"]
        .as_array_mut()
        .context("the data collection rule has no data flows")?;
    for (one, flow) in proven {
        let output = one.table.output_stream();
        let archived = format!("Custom-{}", archive(&one.table));
        let destinations = flows
            .iter()
            .find(|f| f["outputStream"] == output.as_str())
            .map(|f| f["destinations"].clone())
            .with_context(|| format!("the data collection rule has no data flow into {output}"))?;
        flows.retain(|f| f["outputStream"] != archived.as_str());
        for f in flows.iter_mut() {
            if f["outputStream"] == output.as_str() {
                f["transformKql"] = Value::String(one.kql.clone());
            }
        }
        flows.push(json!({
            "streams": [flow.name],
            "destinations": destinations,
            "transformKql": "source",
            "outputStream": archived,
        }));
    }
    Ok(rule)
}

/// The archive table for the tables API: the stream's columns, on the Auxiliary plan.
pub(super) fn archive_table(table: &Table, flow: &Flow) -> Value {
    let mut columns: Vec<Value> = flow
        .stream
        .iter()
        .map(|(name, kind)| json!({ "name": name, "type": kind }))
        .collect();
    if !flow.stream.iter().any(|(name, _)| name == "TimeGenerated") {
        columns.insert(0, json!({ "name": "TimeGenerated", "type": "datetime" }));
    }
    json!({
        "properties": {
            "plan": "Auxiliary",
            "totalRetentionInDays": 365,
            "schema": { "name": archive(table), "columns": columns },
        }
    })
}

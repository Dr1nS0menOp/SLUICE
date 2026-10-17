//! A Log Analytics custom table (`<Name>_CL`) and the data collection rule that fills it, for a
//! source whose records have no standard Sentinel table (docs/notes/sentinel-dcr.md).
//!
//! The columns come from the top-level fields of sample records. A DCR stream only passes the
//! columns it declares, so a field that never occurs in the sample does not reach the table:
//! generate from a sample that covers the source's templates, and again when they change.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::VectorError;

/// The type of a column, as Log Analytics names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColumnKind {
    /// Text, and any field whose values differ in type.
    String,
    /// Whole numbers.
    Long,
    /// Numbers with a fraction.
    Real,
    /// `true` or `false`.
    Boolean,
    /// Objects and arrays.
    Dynamic,
}

impl ColumnKind {
    /// The type's name in Log Analytics.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Long => "long",
            Self::Real => "real",
            Self::Boolean => "boolean",
            Self::Dynamic => "dynamic",
        }
    }

    fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Null => None,
            Value::Bool(_) => Some(Self::Boolean),
            Value::Number(n) if n.is_i64() || n.is_u64() => Some(Self::Long),
            Value::Number(_) => Some(Self::Real),
            Value::String(_) => Some(Self::String),
            Value::Array(_) | Value::Object(_) => Some(Self::Dynamic),
        }
    }

    /// The type that holds values of both: whole numbers widen to real, objects stay dynamic,
    /// anything else mixed becomes text.
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (a, b) if a == b => a,
            (Self::Long | Self::Real, Self::Long | Self::Real) => Self::Real,
            (Self::Dynamic, _) | (_, Self::Dynamic) => Self::Dynamic,
            _ => Self::String,
        }
    }
}

/// One column: the record field it holds, its valid column name and type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// The field name in the record, as the stream receives it.
    pub field: String,
    /// The column name in the table (the field name made valid).
    pub name: String,
    /// The column type.
    pub kind: ColumnKind,
}

/// A custom table for one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomTable {
    name: String,
    columns: Vec<Column>,
}

/// Columns every Log Analytics table has, or that Azure reserves.
const RESERVED: [&str; 2] = ["Type", "TimeGenerated"];

impl CustomTable {
    /// Infers the table `<name>_CL` from sample records (JSON objects as forwarded).
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::Config`] if `name` is not a valid table name (a letter, then
    /// letters, digits and `_`) or the sample has no fields.
    pub fn infer(name: &str, records: &[Map<String, Value>]) -> Result<Self, VectorError> {
        let valid = name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(VectorError::Config(format!(
                "table name `{name}`: use a letter, then letters, digits and `_`"
            )));
        }
        let mut kinds: BTreeMap<&str, Option<ColumnKind>> = BTreeMap::new();
        for record in records {
            for (field, value) in record {
                let kind = ColumnKind::of(value);
                let entry = kinds.entry(field.as_str()).or_insert(kind);
                *entry = match (*entry, kind) {
                    (Some(a), Some(b)) => Some(a.join(b)),
                    (a, b) => a.or(b),
                };
            }
        }
        if kinds.is_empty() {
            return Err(VectorError::Config("the sample has no fields".to_owned()));
        }
        kinds.remove("TimeGenerated");
        // Fields whose name is already a valid column keep it; the others are renamed into
        // names nobody holds, so no rename ever moves a column another one needs.
        let mut taken: BTreeSet<String> = RESERVED.iter().map(|r| r.to_lowercase()).collect();
        let mut names: BTreeMap<&str, String> = BTreeMap::new();
        for field in kinds.keys() {
            if is_column_name(field) && taken.insert(field.to_lowercase()) {
                names.insert(field, (*field).to_owned());
            }
        }
        let columns = kinds
            .into_iter()
            .map(|(field, kind)| Column {
                field: field.to_owned(),
                name: names
                    .remove(field)
                    .unwrap_or_else(|| column_name(field, &mut taken)),
                kind: kind.unwrap_or(ColumnKind::String),
            })
            .collect();
        Ok(Self {
            name: name.to_owned(),
            columns,
        })
    }

    /// The table's name in the workspace.
    #[must_use]
    pub fn table_name(&self) -> String {
        format!("{}_CL", self.name)
    }

    /// The DCR stream that receives the records, for the `azure_logs_ingestion` sink.
    #[must_use]
    pub fn stream_name(&self) -> String {
        format!("Custom-{}", self.name)
    }

    /// The columns, in field order.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The body to create the table (`PUT …/workspaces/{ws}/tables/{name}_CL`).
    #[must_use]
    pub fn table(&self) -> Value {
        let mut columns = vec![json!({ "name": "TimeGenerated", "type": "datetime" })];
        columns.extend(
            self.columns
                .iter()
                .map(|c| json!({ "name": c.name, "type": c.kind.name() })),
        );
        json!({ "properties": { "schema": { "name": self.table_name(), "columns": columns } } })
    }

    /// The data collection rule (kind `Direct`, so it has its own ingestion endpoint) that
    /// takes the records as they are, sets `TimeGenerated` from `time_field` (or the time of
    /// ingestion) and renames fields that are not valid column names.
    #[must_use]
    pub fn dcr(
        &self,
        location: &str,
        workspace_resource_id: &str,
        time_field: Option<&str>,
    ) -> Value {
        let mut stream: Vec<Value> = self
            .columns
            .iter()
            .map(|c| json!({ "name": c.field, "type": c.kind.name() }))
            .collect();
        let time = match time_field {
            Some(field) => {
                if !self.columns.iter().any(|c| c.field == field) {
                    stream.push(json!({ "name": field, "type": "string" }));
                }
                format!("todatetime({})", quoted(field))
            }
            None => "now()".to_owned(),
        };
        let mut transform = format!("source | extend TimeGenerated = {time}");
        let renames: Vec<String> = self
            .columns
            .iter()
            .filter(|c| c.field != c.name)
            .map(|c| format!("{} = {}", c.name, quoted(&c.field)))
            .collect();
        if !renames.is_empty() {
            transform.push_str(" | project-rename ");
            transform.push_str(&renames.join(", "));
        }
        json!({
            "location": location,
            "kind": "Direct",
            "properties": {
                "streamDeclarations": { self.stream_name(): { "columns": stream } },
                "destinations": {
                    "logAnalytics": [{ "workspaceResourceId": workspace_resource_id, "name": "sentinel" }]
                },
                "dataFlows": [{
                    "streams": [self.stream_name()],
                    "destinations": ["sentinel"],
                    "transformKql": transform,
                    "outputStream": format!("Custom-{}", self.table_name()),
                }],
            },
        })
    }
}

/// Whether Log Analytics accepts `name` as a column: a letter, then at least one letter, digit
/// or `_` (checked against the tables API, docs/notes/sentinel-dcr.md).
fn is_column_name(name: &str) -> bool {
    name.len() >= 2
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A valid, unused column name for `field`: invalid characters become `_`, a name that does not
/// start with a letter gets `F` in front, a one-letter name gets `_` after it, and a reserved or
/// taken name (compared without case) gets a number.
fn column_name(field: &str, taken: &mut BTreeSet<String>) -> String {
    let mut name: String = field
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        name.insert(0, 'F');
    }
    if name.len() < 2 {
        name.push('_');
    }
    let mut candidate = name.clone();
    let mut n = 1;
    while taken.contains(&candidate.to_lowercase()) {
        n += 1;
        candidate = format!("{name}{n}");
    }
    taken.insert(candidate.to_lowercase());
    candidate
}

/// A field name as KQL reads it: bare when it is an identifier, `['…']` otherwise.
fn quoted(field: &str) -> String {
    let identifier = field.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if identifier {
        field.to_owned()
    } else {
        format!("['{}']", field.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(lines: &[&str]) -> Vec<Map<String, Value>> {
        lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("object"))
            .collect()
    }

    #[test]
    fn columns_take_the_type_that_holds_every_value() {
        let table = CustomTable::infer(
            "Opnsense",
            &records(&[
                r#"{"action":"pass","bytes":10,"ratio":1,"tags":["a"],"ok":true,"gone":null}"#,
                r#"{"action":"block","bytes":12,"ratio":0.5,"tags":{"b":1},"ok":"yes"}"#,
            ]),
        )
        .expect("valid");
        let kinds: Vec<(&str, ColumnKind)> = table
            .columns()
            .iter()
            .map(|c| (c.name.as_str(), c.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("action", ColumnKind::String),
                ("bytes", ColumnKind::Long),
                ("gone", ColumnKind::String),
                ("ok", ColumnKind::String),
                ("ratio", ColumnKind::Real),
                ("tags", ColumnKind::Dynamic),
            ]
        );
    }

    #[test]
    fn invalid_field_names_become_valid_unique_columns() {
        let table = CustomTable::infer(
            "Dns",
            &records(&[r#"{"src-ip":"a","src_ip":"b","1st":"c","Type":"d","x":"e","_id":"f","TimeGenerated":"t"}"#]),
        )
        .expect("valid");
        let names: Vec<(&str, &str)> = table
            .columns()
            .iter()
            .map(|c| (c.field.as_str(), c.name.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("1st", "F1st"),
                ("Type", "Type2"),
                ("_id", "F_id"),
                ("src-ip", "src_ip2"),
                ("src_ip", "src_ip"),
                ("x", "x_"),
            ]
        );
        let dcr = table.dcr("westeurope", "/ws", Some("ts"));
        let transform = dcr["properties"]["dataFlows"][0]["transformKql"]
            .as_str()
            .expect("text");
        assert_eq!(
            transform,
            "source | extend TimeGenerated = todatetime(ts) | project-rename F1st = ['1st'], \
             Type2 = Type, F_id = _id, src_ip2 = ['src-ip'], x_ = x"
        );
    }

    #[test]
    fn bad_table_names_are_refused() {
        let sample = records(&[r#"{"a1":1}"#]);
        assert!(CustomTable::infer("1abc", &sample).is_err());
        assert!(CustomTable::infer("a-b", &sample).is_err());
        assert!(CustomTable::infer("Good_1", &[]).is_err());
    }
}

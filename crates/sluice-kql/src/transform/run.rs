//! Running a transformation in the Kusto emulator, as a data collection rule runs it on a stream.

use std::collections::BTreeMap;

use crate::syntax;

/// What a transformation leaves of each event: its record at the event's place, with its
/// non-empty columns only (an empty column and a missing one are the same to the table), or
/// `None` where the transformation dropped it.
pub type Records = Vec<Option<serde_json::Map<String, serde_json::Value>>>;

/// Runs each of `kqls` on `events` in the Kusto emulator at `url`, as a DCR runs a
/// transformation on a stream with `columns` (name and type, as a stream declaration gives
/// them), in one query so that what they share (`now()` in a data flow's own transformation)
/// is the same for all of them. Records are matched to events by a row number the emulator
/// carries along, not by their order: a transformation may drop rows.
///
/// # Errors
///
/// Returns [`crate::KustoError`] if the emulator cannot be used or rejects a transformation,
/// and if a transformation loses the row number (a `project`) or makes rows of its own.
pub fn run_transformations(
    url: &str,
    columns: &[(&str, &str)],
    kqls: &[&str],
    events: &[&sluice_core::event::Event],
) -> Result<Vec<Records>, crate::KustoError> {
    use serde_json::{Map, Value, json};

    const ROW: &str = "__sluice_n";
    const RUN: &str = "__sluice_run";
    let client = crate::engine::Client::new(url);
    let database = crate::engine::Database::create(&client, &[])?;
    let aliases = Aliases::new(columns);
    // Stream declarations say `boolean`; Kusto calls it `bool`.
    let mut declared: Vec<(&str, &str)> = columns
        .iter()
        .map(|(name, kind)| {
            let kind = if *kind == "boolean" { "bool" } else { *kind };
            (aliases.emulator_name(name), kind)
        })
        .collect();
    declared.push((ROW, "long"));
    let records: Vec<Value> = events
        .iter()
        .enumerate()
        .map(|(n, event)| {
            let mut record: Map<String, Value> = columns
                .iter()
                .filter_map(|(name, _)| {
                    event
                        .fields
                        .get(*name)
                        .map(|v| (aliases.emulator_name(name).to_owned(), v.clone()))
                })
                .collect();
            record.insert(ROW.to_owned(), json!(n));
            Value::Object(record)
        })
        .collect();
    database.load_table("SluiceInput", &declared, &records)?;
    let runs: Vec<String> = kqls
        .iter()
        .enumerate()
        .map(|(n, kql)| {
            let kql = aliases.rewrite(kql).replacen("source", "SluiceInput", 1);
            format!("({kql}\n| extend {RUN} = {n})")
        })
        .collect();
    let query = format!(
        "union kind=outer {}\n| order by {RUN} asc, {ROW} asc",
        runs.join(", ")
    );
    let mut out: Vec<Records> = vec![vec![None; events.len()]; kqls.len()];
    for row in database.query(&query)? {
        let row: Value =
            serde_json::from_str(&row).map_err(|e| crate::KustoError::Response(e.to_string()))?;
        let run = number(&row, RUN)
            .filter(|n| *n < kqls.len())
            .ok_or_else(|| crate::KustoError::Response("a row of no run".to_owned()))?;
        let n = number(&row, ROW)
            .filter(|n| *n < events.len())
            .ok_or_else(|| {
                crate::KustoError::Response(format!(
                    "a row without its record number ({ROW}): the transformation drops it, so \
                     its records cannot be matched to the sample's"
                ))
            })?;
        let slot = &mut out[run][n];
        if slot.is_some() {
            return Err(crate::KustoError::Response(format!(
                "record {n} came out twice: the transformation makes rows of its own"
            )));
        }
        *slot = Some(record(&row, &aliases, &[ROW, RUN])?);
    }
    Ok(out)
}

/// The whole number in column `column` of a result row (`[names, values]`).
fn number(row: &serde_json::Value, column: &str) -> Option<usize> {
    let names = row[0].as_array()?;
    let values = row[1].as_array()?;
    let at = names.iter().position(|n| n.as_str() == Some(column))?;
    values
        .get(at)?
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
}

/// One result row (`[names, values]`) as a record: its non-empty columns, under their stream
/// names, without the bookkeeping columns `skip`.
fn record(
    row: &serde_json::Value,
    aliases: &Aliases<'_>,
    skip: &[&str],
) -> Result<serde_json::Map<String, serde_json::Value>, crate::KustoError> {
    let (Some(names), Some(values)) = (row[0].as_array(), row[1].as_array()) else {
        return Err(crate::KustoError::Response(
            "a row without columns".to_owned(),
        ));
    };
    Ok(names
        .iter()
        .zip(values)
        .filter_map(|(name, value)| {
            let name = name.as_str()?;
            let empty = value.is_null() || value.as_str() == Some("");
            (!skip.contains(&name) && !empty)
                .then(|| (aliases.stream_name(name).to_owned(), value.clone()))
        })
        .collect())
}
/// Stream columns the emulator cannot name (`@timestamp`: it takes letters, digits, `_`, `.`,
/// `-` and spaces), which Azure's streams take: in the emulator they go by an alias, and every
/// reference to them in a transformation (`['@timestamp']`, `columnifexists('@timestamp'`)
/// is rewritten to it.
struct Aliases<'c> {
    by_name: BTreeMap<&'c str, String>,
}

impl<'c> Aliases<'c> {
    fn new(columns: &[(&'c str, &str)]) -> Self {
        let named = |name: &str| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || " _.-".contains(c))
        };
        Self {
            by_name: columns
                .iter()
                .filter(|(name, _)| !named(name))
                .enumerate()
                .map(|(i, (name, _))| (*name, format!("sluice_alias_{i}")))
                .collect(),
        }
    }

    fn emulator_name<'n>(&'n self, name: &'n str) -> &'n str {
        self.by_name.get(name).map_or(name, String::as_str)
    }

    fn stream_name<'n>(&'n self, name: &'n str) -> &'n str {
        self.by_name
            .iter()
            .find(|(_, alias)| alias.as_str() == name)
            .map_or(name, |(original, _)| original)
    }

    fn rewrite(&self, kql: &str) -> String {
        let mut out = kql.to_owned();
        for (name, alias) in &self.by_name {
            for (from, to) in [
                (syntax::quoted_name(name), syntax::quoted_name(alias)),
                (
                    syntax::string(name).map(|s| format!("columnifexists({s}")),
                    syntax::string(alias).map(|s| format!("columnifexists({s}")),
                ),
            ] {
                if let (Some(from), Some(to)) = (from, to) {
                    out = out.replace(&from, &to);
                }
            }
        }
        out
    }
}

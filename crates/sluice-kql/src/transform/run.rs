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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sluice_core::event::{Event, Timestamp};
    use sluice_core::ids::{EventId, SourceId};

    use super::*;

    #[test]
    fn a_column_the_emulator_cannot_name_goes_by_an_alias_both_ways() {
        let aliases = Aliases::new(&[("@timestamp", "string"), ("Message", "string")]);
        assert_eq!(aliases.emulator_name("@timestamp"), "sluice_alias_0");
        assert_eq!(aliases.emulator_name("Message"), "Message");
        assert_eq!(aliases.stream_name("sluice_alias_0"), "@timestamp");
        assert_eq!(aliases.stream_name("Message"), "Message");
        assert_eq!(
            aliases.rewrite(
                r#"source | extend T = ['@timestamp'], U = columnifexists("@timestamp", "")"#
            ),
            r#"source | extend T = ['sluice_alias_0'], U = columnifexists("sluice_alias_0", "")"#
        );
    }

    #[test]
    fn a_result_row_gives_its_numbers_and_its_non_empty_columns() {
        let aliases = Aliases::new(&[("@timestamp", "string")]);
        let row = json!([
            [
                "__sluice_n",
                "__sluice_run",
                "A",
                "B",
                "C",
                "sluice_alias_0"
            ],
            [3, 1, "x", "", null, "t"]
        ]);
        assert_eq!(number(&row, "__sluice_n"), Some(3));
        assert_eq!(number(&row, "A"), None, "not a number");
        assert_eq!(number(&row, "Missing"), None);
        let record = record(&row, &aliases, &["__sluice_n", "__sluice_run"]).expect("a record");
        assert_eq!(Value::Object(record), json!({"A": "x", "@timestamp": "t"}));
        assert!(record_of_nothing().is_err());
    }

    fn record_of_nothing() -> Result<serde_json::Map<String, Value>, crate::KustoError> {
        record(&json!({}), &Aliases::new(&[]), &[])
    }

    fn event(n: u64, fields: Value) -> Event {
        let Value::Object(fields) = fields else {
            unreachable!("an object")
        };
        Event {
            id: EventId(n),
            timestamp: Timestamp(0),
            source: SourceId::new("s"),
            fields,
        }
    }

    /// In the Kusto emulator (`SLUICE_KUSTO_URL`): each transformation's records come back at
    /// their events' places, emptied columns left out, dropped rows as `None`, and an aliased
    /// column under its own name.
    #[test]
    fn c1_in_the_kql_engine_records_come_back_at_their_events_places() {
        let Ok(url) = std::env::var("SLUICE_KUSTO_URL") else {
            return;
        };
        let columns = [
            ("EventID", "int"),
            ("Message", "string"),
            ("@timestamp", "string"),
            ("Ok", "boolean"),
        ];
        let events = [
            event(
                0,
                json!({"EventID": 4624, "Message": "m0", "@timestamp": "t0", "Ok": true}),
            ),
            event(
                1,
                json!({"EventID": 4625, "Message": "m1", "@timestamp": "t1", "Ok": false}),
            ),
            event(
                2,
                json!({"EventID": 4624, "Message": "m2", "@timestamp": "t2"}),
            ),
        ];
        let refs: Vec<&Event> = events.iter().collect();
        let kqls = [
            "source",
            r#"source | extend Message = iff(EventID == 4624, "", Message)"#,
            "source | where EventID != 4625",
            "source | extend T = ['@timestamp']",
        ];
        let runs = run_transformations(&url, &columns, &kqls, &refs).expect("the emulator runs");
        assert_eq!(runs.len(), 4);
        let at = |run: usize, n: usize| runs[run][n].clone().map(Value::Object);
        assert_eq!(
            at(0, 1),
            Some(json!({"EventID": 4625, "Message": "m1", "@timestamp": "t1", "Ok": false}))
        );
        assert_eq!(
            at(1, 0),
            Some(json!({"EventID": 4624, "@timestamp": "t0", "Ok": true})),
            "the emptied message is left out"
        );
        assert_eq!(
            at(1, 1).and_then(|r| r.get("Message").cloned()),
            Some(json!("m1"))
        );
        assert_eq!(at(2, 1), None, "the transformation dropped it");
        assert!(at(2, 2).is_some());
        assert_eq!(
            at(3, 2).and_then(|r| r.get("T").cloned()),
            Some(json!("t2"))
        );
        assert_eq!(
            at(3, 2).and_then(|r| r.get("Ok").cloned()),
            None,
            "not given"
        );
    }

    /// In the Kusto emulator: a transformation that loses the row number, or makes rows of its
    /// own, cannot be matched to the sample, and says so.
    #[test]
    fn c1_in_the_kql_engine_records_that_cannot_be_matched_are_an_error() {
        let Ok(url) = std::env::var("SLUICE_KUSTO_URL") else {
            return;
        };
        let columns = [("EventID", "int")];
        let events = [
            event(0, json!({"EventID": 1})),
            event(1, json!({"EventID": 2})),
        ];
        let refs: Vec<&Event> = events.iter().collect();
        // Alone, the emulator refuses to order by a column that is gone; beside one that keeps
        // it, the rows come back without it.
        let alone = run_transformations(&url, &columns, &["source | project EventID"], &refs);
        assert!(alone.is_err(), "{alone:?}");
        let lost = run_transformations(
            &url,
            &columns,
            &["source", "source | project EventID"],
            &refs,
        );
        assert!(
            matches!(&lost, Err(crate::KustoError::Response(m)) if m.contains("without its record number")),
            "{lost:?}"
        );
        let twice = run_transformations(
            &url,
            &columns,
            &["source | mv-expand x = dynamic([1, 2])"],
            &refs,
        );
        assert!(
            matches!(&twice, Err(crate::KustoError::Response(m)) if m.contains("came out twice")),
            "{twice:?}"
        );
    }
}

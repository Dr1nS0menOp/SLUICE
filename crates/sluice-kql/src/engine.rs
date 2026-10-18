//! Sentinel analytics rules evaluated by the real KQL engine, the Kusto emulator (ADR 0015).
//!
//! Every evaluation loads the events into a fresh volatile database whose tables carry the
//! names and column types Sentinel uses, so a rule's query runs unchanged: no table renaming
//! that could also rewrite a string such as `Type == "SecurityEvent"`. Each result row becomes
//! one alert, identified by its content. The same rows on full and on forwarded data are the
//! same alerts; a row that differs in any column (an entity a rule reports, say) is a changed
//! detection, so the proof fails closed on it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use sluice_core::alert::{Alert, EngineError, RuleEngine};
use sluice_core::event::Event;
use sluice_core::ids::{EventId, RuleId, SourceId};

use crate::table::Table;

/// Events per inline ingestion command, well below the emulator's request size limit.
const INGEST_BATCH: usize = 500;

/// How long one command or rule query may take.
const TIMEOUT: Duration = Duration::from_secs(300);

/// A rule id with its KQL query, or with the reason it was set aside.
type Rule = (RuleId, String);

/// The database every management command that creates or drops a database runs in.
const DEFAULT_DB: &str = "NetDefaultDB";

/// The emulator could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KustoError {
    /// No answer from the emulator.
    #[error("Kusto emulator at {url} unreachable: {reason}")]
    Unreachable {
        /// The emulator's base URL.
        url: String,
        /// The transport error.
        reason: String,
    },
    /// The emulator answered with an error, for a command Sluice generated or a rule's query.
    #[error("Kusto rejected the request ({status}): {}", sluice_http::excerpt(.message))]
    Rejected {
        /// HTTP status.
        status: u16,
        /// The emulator's error text.
        message: String,
    },
    /// The emulator answered something that is not a query result.
    #[error("unexpected answer from the Kusto emulator: {0}")]
    Response(String),
}

impl From<KustoError> for EngineError {
    fn from(error: KustoError) -> Self {
        Self(error.to_string())
    }
}

/// Runs Sentinel analytics rules on events in the Kusto emulator.
///
/// Rules that cannot run even on empty tables (they read a table, watchlist or function the
/// emulator does not have) are set aside when the engine is built and listed by
/// [`KustoEngine::skipped`]; the proof does not cover them. A rule that runs on empty tables
/// but fails on the events is an evaluation error: the proof is then not proven.
#[derive(Debug)]
pub struct KustoEngine {
    client: Client,
    tables: BTreeMap<SourceId, Table>,
    /// The custom tables among `tables`, which every database gets as well.
    custom: Vec<Table>,
    rules: Vec<(RuleId, String)>,
    skipped: Vec<(RuleId, String)>,
}

impl KustoEngine {
    /// Connects to the emulator at `url` (for example `http://127.0.0.1:8090`) and keeps the
    /// rules (id and KQL query) that run there. `tables` says which table each source's events
    /// belong in, the shape the destination gives them; events of other sources reach none of
    /// these tables and are not loaded.
    ///
    /// # Errors
    ///
    /// Returns [`KustoError`] if the emulator cannot be reached or cannot create a database.
    pub fn connect(
        url: &str,
        rules: &[(RuleId, String)],
        tables: BTreeMap<SourceId, Table>,
    ) -> Result<Self, KustoError> {
        let client = Client::new(url);
        let custom = custom_tables(tables.values());
        let (kept, skipped) = runnable(&client, rules, &custom)?;
        Ok(Self {
            custom,
            client,
            tables,
            rules: kept,
            skipped,
        })
    }

    /// The rules the proof runs.
    pub fn rules(&self) -> impl Iterator<Item = &RuleId> {
        self.rules.iter().map(|(id, _)| id)
    }

    /// The rules that cannot run in the emulator, with the reason.
    #[must_use]
    pub fn skipped(&self) -> &[(RuleId, String)] {
        &self.skipped
    }

    fn rows_per_table<'e>(&self, events: &[&'e Event]) -> BTreeMap<Table, Vec<&'e Event>> {
        let mut out: BTreeMap<Table, Vec<&Event>> = BTreeMap::new();
        for event in events {
            if let Some(table) = self.tables.get(&event.source) {
                out.entry(table.clone()).or_default().push(event);
            }
        }
        out
    }
}

impl RuleEngine for KustoEngine {
    fn alerts_refs(&self, events: &[&Event]) -> Result<BTreeSet<Alert>, EngineError> {
        let database = Database::create(&self.client, &self.custom)?;
        for (table, events) in self.rows_per_table(events) {
            database.load(&table, &events)?;
        }
        let mut alerts = BTreeSet::new();
        for (rule, query) in &self.rules {
            let rows = database.query(query)?;
            alerts.extend(alerts_from_rows(rule, rows));
        }
        Ok(alerts)
    }
}

/// Each custom table once.
fn custom_tables<'t>(tables: impl Iterator<Item = &'t Table>) -> Vec<Table> {
    let set: BTreeSet<&Table> = tables.filter(|t| matches!(t, Table::Custom(_))).collect();
    set.into_iter().cloned().collect()
}

/// Splits the rules into those that run on empty tables and those that do not, with the
/// emulator's reason.
fn runnable(
    client: &Client,
    rules: &[(RuleId, String)],
    custom: &[Table],
) -> Result<(Vec<Rule>, Vec<Rule>), KustoError> {
    let database = Database::create(client, custom)?;
    let mut kept = Vec::new();
    let mut skipped = Vec::new();
    for (id, query) in rules {
        match database.query(query) {
            Ok(_) => kept.push((id.clone(), query.clone())),
            Err(KustoError::Rejected { message, .. }) => {
                skipped.push((id.clone(), first_line(&message)));
            }
            Err(other) => return Err(other),
        }
    }
    Ok((kept, skipped))
}

/// One alert per result row. A row's identity is its content, with an occurrence number so
/// that identical rows stay distinct alerts.
fn alerts_from_rows(rule: &RuleId, rows: Vec<String>) -> impl Iterator<Item = Alert> + '_ {
    let mut rows = rows;
    rows.sort_unstable();
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    rows.into_iter().map(move |row| {
        let occurrence = seen.entry(row.clone()).or_default();
        let id = fnv1a(&[rule.as_str(), &row, &occurrence.to_string()]);
        *occurrence += 1;
        Alert {
            rule: rule.clone(),
            event: EventId(id),
        }
    })
}

/// FNV-1a over the parts, separated so that `("ab", "c")` and `("a", "bc")` differ.
fn fnv1a(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.bytes().chain([0xff]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn first_line(message: &str) -> String {
    message
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("rejected")
        .to_owned()
}

/// The record a table receives for an event: its columns, plus `Type`, which Log Analytics
/// sets from the table. Fields that are not columns are left out, as the workspace drops them.
fn record(table: &Table, event: &Event) -> Value {
    let mut out = Map::new();
    if let Table::Custom(custom) = table {
        // A custom table holds each field under the column the rule renamed it to.
        for column in custom.columns.iter() {
            if let Some(value) = event.fields.get(&column.field) {
                out.insert(column.name.clone(), value.clone());
            }
        }
    }
    for (column, _) in table.columns() {
        if let Some(value) = event.fields.get(column)
            && !out.contains_key(column)
        {
            out.insert(column.to_owned(), value.clone());
        }
    }
    out.insert("Type".to_owned(), Value::String(table.name().to_owned()));
    Value::Object(out)
}

/// A volatile database that lives as long as this value.
pub(crate) struct Database<'c> {
    client: &'c Client,
    name: String,
}

impl<'c> Database<'c> {
    /// Creates a database with every standard table and `custom`.
    pub(crate) fn create(client: &'c Client, custom: &[Table]) -> Result<Self, KustoError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "sluice_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        client.mgmt(DEFAULT_DB, &format!(".create database {name} volatile"))?;
        let database = Self { client, name };
        for table in Table::STANDARD.iter().chain(custom) {
            let columns: Vec<String> = table
                .columns()
                .map(|(name, kind)| format!("['{name}']:{kind}"))
                .collect();
            database.client.mgmt(
                &database.name,
                &format!(".create table {} ({})", table.name(), columns.join(", ")),
            )?;
        }
        Ok(database)
    }

    pub(crate) fn load(&self, table: &Table, events: &[&Event]) -> Result<(), KustoError> {
        for batch in events.chunks(INGEST_BATCH) {
            let lines: Vec<String> = batch
                .iter()
                .map(|event| record(table, event).to_string())
                .collect();
            self.client.mgmt(
                &self.name,
                &format!(
                    ".ingest inline into table {} with (format='multijson') <|\n{}",
                    table.name(),
                    lines.join("\n")
                ),
            )?;
        }
        Ok(())
    }

    /// Creates table `name` with `columns` and loads `records` (JSON objects) into it.
    pub(crate) fn load_table(
        &self,
        name: &str,
        columns: &[(&str, &str)],
        records: &[Value],
    ) -> Result<(), KustoError> {
        let declared: Vec<String> = columns
            .iter()
            .map(|(column, kind)| format!("['{column}']:{kind}"))
            .collect();
        self.client.mgmt(
            &self.name,
            &format!(".create table {name} ({})", declared.join(", ")),
        )?;
        for batch in records.chunks(INGEST_BATCH) {
            let lines: Vec<String> = batch.iter().map(Value::to_string).collect();
            self.client.mgmt(
                &self.name,
                &format!(
                    ".ingest inline into table {name} with (format='multijson') <|\n{}",
                    lines.join("\n")
                ),
            )?;
        }
        Ok(())
    }

    /// The rows of the query's primary result, each as JSON with its column names.
    pub(crate) fn query(&self, query: &str) -> Result<Vec<String>, KustoError> {
        let answer = self.client.query(&self.name, query)?;
        let table = answer
            .get("Tables")
            .and_then(|tables| tables.get(0))
            .ok_or_else(|| KustoError::Response("no result table".to_owned()))?;
        let columns: Vec<&str> = table
            .get("Columns")
            .and_then(Value::as_array)
            .map(|columns| {
                columns
                    .iter()
                    .filter_map(|c| c.get("ColumnName").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        let rows = table
            .get("Rows")
            .and_then(Value::as_array)
            .ok_or_else(|| KustoError::Response("result table without rows".to_owned()))?;
        Ok(rows
            .iter()
            .map(|row| json!([columns, row]).to_string())
            .collect())
    }
}

impl Drop for Database<'_> {
    fn drop(&mut self) {
        // A database left behind is volatile and goes with the emulator; nothing to report.
        let _ = self.client.mgmt(
            DEFAULT_DB,
            &format!(".drop database {} ifexists", self.name),
        );
    }
}

/// The emulator's REST API (v1).
#[derive(Debug)]
pub(crate) struct Client {
    http: sluice_http::Client,
    url: String,
}

impl Client {
    pub(crate) fn new(url: &str) -> Self {
        Self {
            http: sluice_http::Client::new(TIMEOUT),
            url: url.trim_end_matches('/').to_owned(),
        }
    }

    fn mgmt(&self, db: &str, command: &str) -> Result<Value, KustoError> {
        self.post("mgmt", db, command)
    }

    fn query(&self, db: &str, query: &str) -> Result<Value, KustoError> {
        self.post("query", db, query)
    }

    fn post(&self, kind: &str, db: &str, csl: &str) -> Result<Value, KustoError> {
        let body = json!({ "db": db, "csl": csl }).to_string();
        let answer = self
            .http
            .send(
                "POST",
                &format!("{}/v1/rest/{kind}", self.url),
                &[("content-type", "application/json".to_owned())],
                Some(&body),
            )
            .map_err(|e| KustoError::Unreachable {
                url: self.url.clone(),
                reason: e.reason,
            })?;
        if !answer.is_success() {
            return Err(KustoError::Rejected {
                status: answer.status,
                message: answer.body,
            });
        }
        serde_json::from_str(&answer.body).map_err(|e| KustoError::Response(e.to_string()))
    }
}

#[cfg(test)]
mod tests;

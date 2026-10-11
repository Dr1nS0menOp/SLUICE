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

use crate::schema;

/// Events per inline ingestion command, well below the emulator's request size limit.
const INGEST_BATCH: usize = 500;

/// How long one command or rule query may take.
const TIMEOUT: Duration = Duration::from_secs(300);

/// A rule id with its KQL query, or with the reason it was set aside.
type Rule = (RuleId, String);

/// The database every management command that creates or drops a database runs in.
const DEFAULT_DB: &str = "NetDefaultDB";

/// A Sentinel table Sluice can load records into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Table {
    /// Windows Security channel events.
    SecurityEvent,
    /// Windows events from every other channel.
    WindowsEvent,
    /// Syslog from Linux hosts and network devices.
    Syslog,
    /// Firewall and network device events (CEF).
    CommonSecurityLog,
    /// Network sessions in the ASIM schema.
    ASimNetworkSessionLogs,
    /// DNS queries in the ASIM schema.
    ASimDnsActivityLogs,
}

impl Table {
    const ALL: [Self; 6] = [
        Self::SecurityEvent,
        Self::WindowsEvent,
        Self::Syslog,
        Self::CommonSecurityLog,
        Self::ASimNetworkSessionLogs,
        Self::ASimDnsActivityLogs,
    ];

    /// The table's name in a Log Analytics workspace.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SecurityEvent => "SecurityEvent",
            Self::WindowsEvent => "WindowsEvent",
            Self::Syslog => "Syslog",
            Self::CommonSecurityLog => "CommonSecurityLog",
            Self::ASimNetworkSessionLogs => "ASimNetworkSessionLogs",
            Self::ASimDnsActivityLogs => "ASimDnsActivityLogs",
        }
    }

    /// The table's columns, with the ones every workspace table has but the tables API does
    /// not list; rules project `_ResourceId` for entity mapping.
    fn columns(self) -> impl Iterator<Item = (&'static str, &'static str)> {
        let own = match self {
            Self::SecurityEvent => schema::SECURITY_EVENT,
            Self::WindowsEvent => schema::WINDOWS_EVENT,
            Self::Syslog => schema::SYSLOG,
            Self::CommonSecurityLog => schema::COMMON_SECURITY_LOG,
            Self::ASimNetworkSessionLogs => schema::ASIM_NETWORK_SESSION_LOGS,
            Self::ASimDnsActivityLogs => schema::ASIM_DNS_ACTIVITY_LOGS,
        };
        own.iter().chain(HIDDEN_COLUMNS).copied()
    }
}

const HIDDEN_COLUMNS: &[(&str, &str)] = &[
    ("Type", "string"),
    ("_ResourceId", "string"),
    ("_SubscriptionId", "string"),
];

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
    #[error("Kusto rejected the request ({status}): {message}")]
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
        let (kept, skipped) = runnable(&client, rules)?;
        Ok(Self {
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
                out.entry(*table).or_default().push(event);
            }
        }
        out
    }
}

impl RuleEngine for KustoEngine {
    fn alerts_refs(&self, events: &[&Event]) -> Result<BTreeSet<Alert>, EngineError> {
        let database = Database::create(&self.client)?;
        for (table, events) in self.rows_per_table(events) {
            database.load(table, &events)?;
        }
        let mut alerts = BTreeSet::new();
        for (rule, query) in &self.rules {
            let rows = database.query(query)?;
            alerts.extend(alerts_from_rows(rule, rows));
        }
        Ok(alerts)
    }
}

/// Splits the rules into those that run on empty tables and those that do not, with the
/// emulator's reason.
fn runnable(
    client: &Client,
    rules: &[(RuleId, String)],
) -> Result<(Vec<Rule>, Vec<Rule>), KustoError> {
    let database = Database::create(client)?;
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
fn record(table: Table, event: &Event) -> Value {
    let mut out = Map::new();
    for (column, _) in table.columns() {
        if let Some(value) = event.fields.get(column) {
            out.insert(column.to_owned(), value.clone());
        }
    }
    out.insert("Type".to_owned(), Value::String(table.name().to_owned()));
    Value::Object(out)
}

/// A volatile database that lives as long as this value.
struct Database<'c> {
    client: &'c Client,
    name: String,
}

impl<'c> Database<'c> {
    fn create(client: &'c Client) -> Result<Self, KustoError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "sluice_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        client.mgmt(DEFAULT_DB, &format!(".create database {name} volatile"))?;
        let database = Self { client, name };
        for table in Table::ALL {
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

    fn load(&self, table: Table, events: &[&Event]) -> Result<(), KustoError> {
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

    /// The rows of the query's primary result, each as JSON with its column names.
    fn query(&self, query: &str) -> Result<Vec<String>, KustoError> {
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
struct Client {
    agent: ureq::Agent,
    url: String,
}

impl Client {
    fn new(url: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(TIMEOUT))
            .build()
            .into();
        Self {
            agent,
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
        let unreachable = |reason: String| KustoError::Unreachable {
            url: self.url.clone(),
            reason,
        };
        let body = json!({ "db": db, "csl": csl }).to_string();
        let mut answer = self
            .agent
            .post(format!("{}/v1/rest/{kind}", self.url))
            .header("content-type", "application/json")
            .send(&body)
            .map_err(|e| unreachable(e.to_string()))?;
        let status = answer.status();
        let text = answer
            .body_mut()
            .read_to_string()
            .map_err(|e| unreachable(e.to_string()))?;
        if !status.is_success() {
            return Err(KustoError::Rejected {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| KustoError::Response(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(rule: &str, rows: &[&str]) -> Vec<u64> {
        alerts_from_rows(
            &RuleId::new(rule),
            rows.iter().map(|r| (*r).to_owned()).collect(),
        )
        .map(|a| a.event.0)
        .collect()
    }

    #[test]
    fn identical_rows_are_distinct_alerts() {
        let alerts = ids("r", &["a", "a", "b"]);
        assert_eq!(alerts.iter().collect::<BTreeSet<_>>().len(), 3);
    }

    #[test]
    fn row_order_does_not_change_alerts() {
        let mut one = ids("r", &["a", "b", "a"]);
        let mut two = ids("r", &["b", "a", "a"]);
        one.sort_unstable();
        two.sort_unstable();
        assert_eq!(one, two);
    }

    #[test]
    fn a_changed_column_is_a_different_alert() {
        assert_ne!(
            ids("r", &["[[\"User\"],[\"alice\"]]"]),
            ids("r", &["[[\"User\"],[\"\"]]"])
        );
        assert_ne!(ids("r", &["a"]), ids("s", &["a"]));
    }

    #[test]
    fn records_hold_columns_and_the_table_type() {
        let event = Event {
            id: EventId(1),
            timestamp: sluice_core::event::Timestamp(0),
            source: SourceId::new("win"),
            fields: serde_json::from_str(r#"{"EventID":4625,"NotAColumn":1}"#).expect("json"),
        };
        assert_eq!(
            record(Table::SecurityEvent, &event),
            json!({ "EventID": 4625, "Type": "SecurityEvent" })
        );
    }
}

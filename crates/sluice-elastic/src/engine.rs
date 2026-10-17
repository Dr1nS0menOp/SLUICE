//! Elastic Security rules run in a real Elasticsearch, for the proof (ADR 0025): the alerts they
//! raise on full and on reduced documents must be the same.
//!
//! Each evaluation loads the events into a fresh index and runs every rule on it: EQL with
//! `_eql/search` (an alert per event, a sequence's on its last event), ES|QL with `_query` on the
//! index instead of its `FROM` (an alert per result row, by content), and KQL or Lucene as the
//! query Kibana builds from it with `_search` (an alert per document).
//!
//! The index maps every scalar as `keyword` (ECS maps most strings so; numbers here too, so that
//! sources sharing the index can disagree on a field's type), and maps every field the rules name
//! even when no event has it, as a real index's ECS mapping does: a query on a field no event
//! has would otherwise be refused instead of matching through its other branches. Where a rule
//! compares a field as a number, the comparison is then on its text, the same for full and
//! reduced documents.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use sluice_core::alert::{Alert, EngineError, RuleEngine};
use sluice_core::event::Event;
use sluice_core::field::FieldPath;
use sluice_core::ids::{EventId, RuleId};

use crate::simulate::ElasticError;

/// A rule's query in a language Elasticsearch runs itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleQuery {
    /// Event Query Language.
    Eql(String),
    /// ES|QL; its `FROM` is replaced by the proof's index.
    Esql(String),
    /// A query for `_search`, as Kibana builds one from KQL or Lucene: an alert per matching
    /// document, with the values of `keys` (what a threshold or new-terms rule groups by).
    Search {
        /// The Elasticsearch query.
        query: Value,
        /// Fields whose values are part of an alert.
        keys: Vec<FieldPath>,
    },
}

/// Most hits one EQL query may return before the comparison would be incomplete.
const MAX_HITS: usize = 10_000;

/// Documents per bulk request.
const BULK: usize = 1_000;

const TIMEOUT: Duration = Duration::from_secs(300);

/// Indices created by this process, for unique names.
static INDICES: AtomicU64 = AtomicU64::new(0);

/// Runs Elastic Security rules in Elasticsearch.
#[derive(Debug)]
pub struct ElasticEngine {
    client: Client,
    mapping: Value,
    rules: Vec<(RuleId, RuleQuery)>,
    skipped: Vec<(RuleId, String)>,
}

impl ElasticEngine {
    /// Connects to Elasticsearch at `url` and keeps the rules that run on an index with the
    /// mapping the proof uses: every field in `fields` (what the rules name) as `keyword`.
    /// Rules Elasticsearch refuses even there are set aside with its reason
    /// ([`ElasticEngine::skipped`]); the proof does not run them.
    ///
    /// # Errors
    ///
    /// [`ElasticError`] if Elasticsearch cannot be reached or cannot create an index.
    pub fn connect(
        url: &str,
        rules: &[(RuleId, RuleQuery)],
        fields: &BTreeSet<FieldPath>,
    ) -> Result<Self, ElasticError> {
        let mut engine = Self {
            client: Client::new(url),
            mapping: mapping(fields),
            rules: Vec::new(),
            skipped: Vec::new(),
        };
        let index = engine.create()?;
        let checked = rules.iter().try_for_each(|(id, query)| {
            match engine.run(&index, query) {
                Ok(_) => engine.rules.push((id.clone(), query.clone())),
                Err(ElasticError::Rejected { message, .. }) => {
                    engine.skipped.push((id.clone(), reason(&message)));
                }
                Err(other) => return Err(other),
            }
            Ok(())
        });
        engine.client.delete(&index);
        checked?;
        Ok(engine)
    }

    /// The rules the proof runs.
    pub fn rules(&self) -> impl Iterator<Item = &RuleId> {
        self.rules.iter().map(|(id, _)| id)
    }

    /// The rules Elasticsearch refuses, with its reason.
    #[must_use]
    pub fn skipped(&self) -> &[(RuleId, String)] {
        &self.skipped
    }

    fn create(&self) -> Result<String, ElasticError> {
        let index = format!(
            "sluice-proof-{}-{}",
            std::process::id(),
            INDICES.fetch_add(1, Ordering::Relaxed)
        );
        // The rules together name more fields than the default limit of 1,000 per index.
        let body = json!({
            "settings": {
                "index.mapping.total_fields.limit": 100_000,
                "analysis": { "normalizer": { "sluice_lowercase": {
                    "type": "custom", "filter": ["lowercase"],
                } } },
            },
            "mappings": self.mapping,
        });
        self.client.call("PUT", &index, &body.to_string())?;
        Ok(index)
    }

    fn load(&self, index: &str, events: &[&Event]) -> Result<(), ElasticError> {
        for chunk in events.chunks(BULK) {
            let mut body = String::new();
            for event in chunk {
                body.push_str(&json!({ "index": { "_id": event.id.0.to_string() } }).to_string());
                body.push('\n');
                body.push_str(&Value::Object(document(event)).to_string());
                body.push('\n');
            }
            let answer = self
                .client
                .call("POST", &format!("{index}/_bulk?refresh=true"), &body)?;
            if answer["errors"] != false {
                let first = answer["items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find_map(|item| item["index"].get("error"))
                    .map_or_else(String::new, Value::to_string);
                return Err(ElasticError::Response(format!(
                    "a document could not be indexed: {first}"
                )));
            }
        }
        Ok(())
    }

    /// The alerts of one rule on `index`.
    fn run(&self, index: &str, query: &RuleQuery) -> Result<Vec<Alert>, ElasticError> {
        let unnamed = RuleId::new("");
        self.rule_alerts(index, &unnamed, query)
    }

    fn rule_alerts(
        &self,
        index: &str,
        rule: &RuleId,
        query: &RuleQuery,
    ) -> Result<Vec<Alert>, ElasticError> {
        match query {
            RuleQuery::Eql(q) => {
                let answer = self.client.call(
                    "POST",
                    &format!("{index}/_eql/search"),
                    &json!({ "query": q, "size": MAX_HITS }).to_string(),
                )?;
                eql_alerts(rule, &answer)
            }
            RuleQuery::Esql(q) => {
                let answer = self.client.call(
                    "POST",
                    "_query",
                    &json!({ "query": from_index(q, index) }).to_string(),
                )?;
                Ok(esql_alerts(rule, &answer))
            }
            RuleQuery::Search { query, keys } => {
                let answer = self.client.call(
                    "POST",
                    &format!("{index}/_search"),
                    &json!({ "query": query, "size": MAX_HITS }).to_string(),
                )?;
                search_alerts(rule, &answer, keys)
            }
        }
    }
}

/// An alert per hit; with `keys`, one per hit and its values of them, so that a document whose
/// group changes alerts differently.
fn search_alerts(
    rule: &RuleId,
    answer: &Value,
    keys: &[FieldPath],
) -> Result<Vec<Alert>, ElasticError> {
    let hits: Vec<&Value> = answer["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    if hits.len() >= MAX_HITS {
        return Err(ElasticError::Response(format!(
            "{rule}: {MAX_HITS} hits or more, too many to compare"
        )));
    }
    hits.into_iter()
        .map(|hit| {
            let id: u64 = hit["_id"]
                .as_str()
                .and_then(|id| id.parse().ok())
                .ok_or_else(|| {
                    ElasticError::Response(format!("a hit without an event id: {hit}"))
                })?;
            if keys.is_empty() {
                return Ok(Alert {
                    rule: rule.clone(),
                    event: EventId(id),
                });
            }
            let values: Vec<String> = keys
                .iter()
                .map(|key| {
                    key.segments()
                        .try_fold(&hit["_source"], |v, s| v.get(s))
                        .map_or_else(String::new, Value::to_string)
                })
                .collect();
            Ok(Alert {
                rule: rule.clone(),
                event: EventId(fnv1a(&[
                    rule.as_str(),
                    &id.to_string(),
                    &values.join("\u{1f}"),
                ])),
            })
        })
        .collect()
}

impl RuleEngine for ElasticEngine {
    fn alerts_refs(&self, events: &[&Event]) -> Result<BTreeSet<Alert>, EngineError> {
        let failed = |e: ElasticError| EngineError(e.to_string());
        let index = self.create().map_err(failed)?;
        let result = self.load(&index, events).and_then(|()| {
            let mut alerts = BTreeSet::new();
            for (rule, query) in &self.rules {
                alerts.extend(self.rule_alerts(&index, rule, query)?);
            }
            Ok(alerts)
        });
        self.client.delete(&index);
        result.map_err(failed)
    }
}

/// The proof index's mapping: strings as `keyword`, and every named field, except one that is
/// the parent of another (an object, then).
fn mapping(fields: &BTreeSet<FieldPath>) -> Value {
    let mut properties = Map::new();
    properties.insert("@timestamp".to_owned(), json!({ "type": "date" }));
    // What `process where …` tests, in every EQL query that names a category.
    properties.insert("event.category".to_owned(), json!({ "type": "keyword" }));
    for field in fields {
        let name = field.as_str();
        // A name with an empty part (`a..b`, `a.`) is no field Elasticsearch can map, and one
        // starting with `_` is its metadata (`_id`, `_index`). ECS's multi-fields are mapped
        // with their parent.
        let mappable = field.segments().all(|s| !s.is_empty())
            && !name.contains('*')
            && !name.starts_with('_')
            && !MULTI_FIELDS
                .iter()
                .any(|(suffix, _)| name.ends_with(suffix));
        let parent = fields.iter().any(|other| {
            other.as_str().len() > name.len()
                && field.covers(other)
                && !MULTI_FIELDS
                    .iter()
                    .any(|(suffix, _)| other.as_str() == format!("{name}{suffix}"))
        });
        if !mappable || properties.contains_key(name) || parent {
            continue;
        }
        properties.insert(name.to_owned(), leaf(field));
    }
    // Every scalar as `keyword`: the sources share one index, and a field that is a number in one
    // and text in another must still index.
    let keyword = |kind: &str| json!({ kind: { "match_mapping_type": kind, "mapping": { "type": "keyword" } } });
    json!({
        "date_detection": false,
        "numeric_detection": false,
        "dynamic_templates": [keyword("string"), keyword("long"), keyword("double"), keyword("boolean")],
        "properties": properties,
    })
}

/// ECS's multi-fields of a `keyword`, which rules name as fields of their own: the value
/// lowercased, and analyzed.
const MULTI_FIELDS: [(&str, &str); 2] = [(".caseless", "caseless"), (".text", "text")];

/// How a field a rule names is mapped: as ECS maps it where the name says (`*.ip` is an `ip`,
/// which `CIDR_MATCH` needs; a value that is none is kept unindexed), else a `keyword` with
/// ECS's multi-fields.
fn leaf(field: &FieldPath) -> Value {
    if field.segments().last() == Some("ip") {
        return json!({ "type": "ip", "ignore_malformed": true });
    }
    json!({
        "type": "keyword",
        "fields": {
            "caseless": { "type": "keyword", "normalizer": "sluice_lowercase" },
            "text": { "type": "text" },
        },
    })
}

/// The event as a document, with `@timestamp` from the event's time when it has none.
fn document(event: &Event) -> Map<String, Value> {
    let mut fields = event.fields.clone();
    if !fields.contains_key("@timestamp") {
        fields.insert("@timestamp".to_owned(), json!(event.timestamp.0 * 1000));
    }
    fields
}

/// An alert per hit, and per sequence on its last event.
fn eql_alerts(rule: &RuleId, answer: &Value) -> Result<Vec<Alert>, ElasticError> {
    let hits = &answer["hits"];
    let id = |hit: &Value| -> Result<EventId, ElasticError> {
        hit["_id"]
            .as_str()
            .and_then(|id| id.parse().ok())
            .map(EventId)
            .ok_or_else(|| ElasticError::Response(format!("a hit without an event id: {hit}")))
    };
    let mut alerts = Vec::new();
    for event in hits["events"].as_array().into_iter().flatten() {
        alerts.push(Alert {
            rule: rule.clone(),
            event: id(event)?,
        });
    }
    for sequence in hits["sequences"].as_array().into_iter().flatten() {
        if let Some(last) = sequence["events"].as_array().and_then(|e| e.last()) {
            alerts.push(Alert {
                rule: rule.clone(),
                event: id(last)?,
            });
        }
    }
    if alerts.len() >= MAX_HITS {
        return Err(ElasticError::Response(format!(
            "{rule}: {MAX_HITS} hits or more, too many to compare"
        )));
    }
    Ok(alerts)
}

/// An alert per result row, by its content, numbered so identical rows stay distinct.
fn esql_alerts(rule: &RuleId, answer: &Value) -> Vec<Alert> {
    let names: Vec<&str> = answer["columns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["name"].as_str())
        .collect();
    let mut rows: Vec<String> = answer["values"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| json!([names, row]).to_string())
        .collect();
    rows.sort_unstable();
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    rows.into_iter()
        .map(|row| {
            let occurrence = seen.entry(row.clone()).or_default();
            let id = fnv1a(&[rule.as_str(), &row, &occurrence.to_string()]);
            *occurrence += 1;
            Alert {
                rule: rule.clone(),
                event: EventId(id),
            }
        })
        .collect()
}

/// `query` with its `FROM` sources replaced by `index` (its `METADATA` kept).
fn from_index(query: &str, index: &str) -> String {
    let trimmed = query.trim_start();
    let Some(rest) = trimmed
        .get(..4)
        .filter(|w| w.eq_ignore_ascii_case("from"))
        .map(|_| &trimmed[4..])
    else {
        return query.to_owned();
    };
    // The sources run to `METADATA` or the first pipe.
    let lower = rest.to_ascii_lowercase();
    let end = [lower.find(" metadata "), lower.find('|')]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(rest.len());
    format!("FROM {index}{}", &rest[end..])
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

/// The first line of Elasticsearch's reason.
fn reason(message: &str) -> String {
    serde_json::from_str::<Value>(message)
        .ok()
        .and_then(|v| v["error"]["reason"].as_str().map(str::to_owned))
        .unwrap_or_else(|| message.to_owned())
        .lines()
        .find(|l| !l.starts_with("Found "))
        .unwrap_or_default()
        .to_owned()
}

#[derive(Debug)]
struct Client {
    agent: ureq::Agent,
    url: String,
}

impl Client {
    fn new(url: &str) -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(TIMEOUT))
                .build()
                .into(),
            url: url.trim_end_matches('/').to_owned(),
        }
    }

    fn call(&self, method: &str, path: &str, body: &str) -> Result<Value, ElasticError> {
        let unreachable = |reason: String| ElasticError::Unreachable {
            url: self.url.clone(),
            reason,
        };
        let target = format!("{}/{path}", self.url);
        let content = if path.contains("_bulk") {
            "application/x-ndjson"
        } else {
            "application/json"
        };
        let request = match method {
            "PUT" => self.agent.put(&target),
            _ => self.agent.post(&target),
        };
        let mut answer = request
            .header("content-type", content)
            .send(body)
            .map_err(|e| unreachable(e.to_string()))?;
        let status = answer.status();
        let text = answer
            .body_mut()
            .with_config()
            .limit(256 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| unreachable(e.to_string()))?;
        if !status.is_success() {
            return Err(ElasticError::Rejected {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| ElasticError::Response(e.to_string()))
    }

    /// Deletes an index; one left behind is only a leftover, so a failure is not reported.
    fn delete(&self, index: &str) {
        let _ = self.agent.delete(format!("{}/{index}", self.url)).call();
    }
}

#[cfg(test)]
mod tests;

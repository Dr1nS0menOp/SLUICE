//! Elastic Security detection rules as requirements (ADR 0025).
//!
//! The rules come as Kibana exports them: the NDJSON of `POST
//! /api/detection_engine/rules/_export`, or the JSON of `GET /api/detection_engine/rules/_find`
//! (`data`), one rule per object with its `rule_id`, `name`, `type`, `language`, `query` and
//! `index`. Elastic's field names are ECS. Per type:
//!
//! - `query`, `saved_query` with its query, `threat_match`, `threshold` and `new_terms` in KQL:
//!   the fields it names and a superset pre-filter ([`kql`]); `threshold` and `new_terms` count
//!   or compare events, so they are stateful, and the fields they group by are read too.
//! - `eql`: fields and pre-filter ([`eql`]); sequences are stateful.
//! - `esql`: every name in the query is a field it may read, and it may match any event; ES|QL
//!   rules aggregate, so they are stateful. Lucene queries may read every field.
//! - `machine_learning`, and anything not understood: may read anything, anywhere (fail
//!   closed), and reported.
//!
//! A rule applies to the sources its index patterns can read ([`index`]): one requirement per
//! product they name, or every source when one pattern may hold anything.

mod eql;
mod esql;
mod index;
mod kql;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::Predicate;
use sluice_core::rules::{RequiredFields, RuleRequirements};
use sluice_core::schema::Schema;

/// A loaded set of Elastic Security detection rules.
#[derive(Debug, Clone, Default)]
pub struct ElasticRules {
    requirements: Vec<RuleRequirements>,
    queries: Vec<(RuleId, ElasticQuery)>,
    names: BTreeMap<RuleId, String>,
    problems: Vec<String>,
}

/// A rule's query, as Elasticsearch runs it.
#[derive(Debug, Clone, PartialEq)]
pub enum ElasticQuery {
    /// KQL or Lucene, as the query Kibana gives `_search`: an alert per matching document. A
    /// threshold or new-terms rule alerts on the values of `keys` too, the fields it groups by.
    Search {
        /// The Elasticsearch query.
        query: Value,
        /// Fields whose values are part of an alert.
        keys: Vec<FieldPath>,
    },
    /// EQL, run by `_eql/search`.
    Eql(String),
    /// ES|QL, run by `_query`.
    Esql(String),
}

impl ElasticRules {
    /// Reads rule files, each as `(name, text)`: NDJSON (one rule per line, as `_export` writes
    /// it, its closing summary line skipped) or JSON (one rule, a list, `_find`'s `data`, or a
    /// saved object of the prebuilt rules package). A rule that cannot be read becomes one that
    /// may read anything anywhere (fail closed) and is reported in [`ElasticRules::problems`].
    ///
    /// Only rules that run count, as the rules a SIEM runs are what the guardrails protect
    /// (ADR 0021): of several versions of a rule the highest, and neither a deprecated rule nor
    /// one with `enabled: false`. Disabled rules are counted in one problem, since enabling one
    /// later needs a new analysis.
    #[must_use]
    pub fn parse<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut rules = Self::default();
        let mut found = Vec::new();
        for (name, text) in files {
            rules.collect(name, text, &mut found);
        }
        // The highest version of each rule id; rules without one stay as they are.
        let mut newest: BTreeMap<String, (u64, usize)> = BTreeMap::new();
        for (n, (_, item)) in found.iter().enumerate() {
            if let Some(id) = item.get("rule_id").and_then(Value::as_str) {
                let version = item.get("version").and_then(Value::as_u64).unwrap_or(0);
                if newest.get(id).is_none_or(|(v, _)| *v < version) {
                    newest.insert(id.to_owned(), (version, n));
                }
            }
        }
        let mut disabled = 0usize;
        for (n, (place, item)) in found.iter().enumerate() {
            let id = item.get("rule_id").and_then(Value::as_str);
            if id.is_some_and(|id| newest.get(id).is_some_and(|(_, at)| *at != n)) {
                continue;
            }
            if item.get("enabled").and_then(Value::as_bool) == Some(false) {
                disabled += 1;
                continue;
            }
            rules.add(place, item);
        }
        if disabled > 0 {
            rules.problems.push(format!(
                "{disabled} Elastic rules are disabled and were left out: they detect nothing \
                 while disabled; analyze again after enabling rules"
            ));
        }
        rules
    }

    /// The rule objects of one file, saved objects unwrapped.
    fn collect(&mut self, name: &str, text: &str, found: &mut Vec<(String, Value)>) {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut push = |place: String, item: &Value| {
            // Elastic's prebuilt rules package (`security_detection_engine`) wraps each rule as
            // a saved object.
            let item = match item.get("attributes") {
                Some(attributes)
                    if item.get("type").and_then(Value::as_str) == Some("security-rule") =>
                {
                    attributes
                }
                _ => item,
            };
            found.push((place, item.clone()));
        };
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Array(items)) => {
                for (n, item) in items.iter().enumerate() {
                    push(format!("{name}#{}", n + 1), item);
                }
            }
            Ok(Value::Object(object)) if object.get("data").is_some_and(Value::is_array) => {
                for (n, item) in object["data"].as_array().into_iter().flatten().enumerate() {
                    push(format!("{name}#{}", n + 1), item);
                }
            }
            Ok(single) => push(name.to_owned(), &single),
            Err(_) => {
                for (n, line) in text.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let place = format!("{name}:{}", n + 1);
                    match serde_json::from_str::<Value>(line) {
                        Ok(item) => push(place, &item),
                        Err(error) => self.unreadable(&place, &error.to_string()),
                    }
                }
            }
        }
    }

    fn unreadable(&mut self, place: &str, why: &str) {
        self.problems.push(format!(
            "Elastic rule {place} could not be read ({why}); it is treated as a rule that may \
             read anything"
        ));
        self.requirements
            .push(RuleRequirements::opaque(RuleId::new(format!(
                "elastic:unreadable:{place}"
            ))));
    }

    fn add(&mut self, place: &str, item: &Value) {
        // `_export` ends with a summary line, and exceptions lists come along. A deprecated
        // rule no longer runs.
        if item.get("exported_count").is_some()
            || item.get("list_id").is_some()
            || item.get("deprecated").and_then(Value::as_bool) == Some(true)
        {
            return;
        }
        let Some(kind) = item.get("type").and_then(Value::as_str) else {
            self.unreadable(place, "no rule type");
            return;
        };
        let id = item
            .get("rule_id")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
            .map_or_else(|| format!("unnamed:{place}"), str::to_owned);
        let rule = RuleId::new(format!("elastic:{id}"));
        if let Some(name) = item.get("name").and_then(Value::as_str) {
            self.names.insert(rule.clone(), name.to_owned());
        }
        let query = item.get("query").and_then(Value::as_str);
        let read = read(kind, query, item.get("language").and_then(Value::as_str));
        let mut patterns: Vec<String> = item
            .get("index")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if kind == "esql"
            && let Some(q) = query
        {
            patterns.extend(index::esql_from(q));
        }
        let scopes = index::scopes(patterns.iter().map(String::as_str));
        match read {
            Ok(mut read) => {
                if index::reads_alerts(patterns.iter().map(String::as_str)) {
                    // Alerts carry the fields of the events other rules raised them on, so
                    // what such a rule tests about an alert bounds no source event.
                    read.prefilter = Predicate::Always;
                }
                let groups = grouped(item);
                read.fields.extend(groups.iter().cloned());
                read.stateful |= matches!(kind, "threshold" | "new_terms");
                if let ElasticQuery::Search { keys, .. } = &mut read.query {
                    keys.clone_from(&groups);
                }
                for scope in scopes {
                    let mut requirement = requirement(rule.clone(), &read);
                    requirement.logsource = scope;
                    self.requirements.push(requirement);
                }
                if let Some(why) = read.any_field {
                    self.problems
                        .push(format!("{rule}: {why}; treated as reading every field"));
                }
                self.queries.push((rule, read.query));
            }
            Err(why) => {
                self.problems.push(format!(
                    "{rule}: {why}; it is treated as a rule that may read anything"
                ));
                for scope in scopes {
                    // Under the rule's own id, so the report names it.
                    let mut opaque = RuleRequirements::opaque(rule.clone());
                    opaque.logsource = scope;
                    self.requirements.push(opaque);
                }
            }
        }
    }

    /// What each rule needs from the data.
    #[must_use]
    pub fn requirements(&self) -> &[RuleRequirements] {
        &self.requirements
    }

    /// The query of every rule that was read, for running the rules themselves on full and on
    /// reduced documents.
    #[must_use]
    pub fn queries(&self) -> &[(RuleId, ElasticQuery)] {
        &self.queries
    }

    /// Rule parts that could not be understood; the affected rules were widened.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    /// Each rule's name as Kibana shows it.
    #[must_use]
    pub fn names(&self) -> &BTreeMap<RuleId, String> {
        &self.names
    }
}

/// What a rule of `kind` with `query` in `language` (KQL when not given) reads.
fn read(kind: &str, query: Option<&str>, language: Option<&str>) -> Result<Read, String> {
    match (kind, query) {
        ("machine_learning", _) => Err("a machine learning job reads what it likes".to_owned()),
        (_, None) => Err(format!("a {kind} rule without a query")),
        ("eql", Some(q)) => eql::read(q).map(|r| Read {
            fields: r.fields,
            any_field: None,
            prefilter: r.prefilter,
            stateful: r.stateful,
            query: ElasticQuery::Eql(q.to_owned()),
        }),
        ("esql", Some(q)) => Ok(names_only(q, ElasticQuery::Esql(q.to_owned()), true)),
        (_, Some(q)) if language == Some("lucene") => {
            // Lucene is not parsed, so a term without a field, which searches every field,
            // cannot be told apart. Kibana gives it to Elasticsearch as a query string.
            let query = ElasticQuery::Search {
                query: serde_json::json!({ "query_string": { "query": q, "lenient": true } }),
                keys: Vec::new(),
            };
            let mut read = names_only(q, query, false);
            read.any_field = Some("a Lucene query, which Sluice does not parse");
            Ok(read)
        }
        (_, Some(q)) => kql::read(q).map(|r| Read {
            fields: r.fields,
            any_field: r.any_field,
            prefilter: r.prefilter,
            stateful: false,
            query: ElasticQuery::Search {
                query: r.dsl,
                keys: Vec::new(),
            },
        }),
    }
}

struct Read {
    fields: BTreeSet<FieldPath>,
    any_field: Option<&'static str>,
    prefilter: Predicate,
    stateful: bool,
    query: ElasticQuery,
}

/// The fields a rule groups or compares by: `threshold.field`, `new_terms_fields`, and the
/// event side of `threat_mapping`.
fn grouped(item: &Value) -> Vec<FieldPath> {
    let strings = |value: Option<&Value>| -> Vec<FieldPath> {
        match value {
            Some(Value::String(s)) => vec![FieldPath::new(s.as_str())],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(FieldPath::new)
                .collect(),
            _ => Vec::new(),
        }
    };
    let mut fields = strings(item.get("threshold").and_then(|t| t.get("field")));
    fields.extend(strings(item.get("new_terms_fields")));
    for mapping in item
        .get("threat_mapping")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for entry in mapping
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            fields.extend(strings(entry.get("field")));
        }
    }
    fields
}

/// A query in a language Sluice does not parse (ES|QL, Lucene): every name in it is a field it
/// may read; an ES|QL query may match what its first `WHERE` clauses keep.
fn names_only(query: &str, kind: ElasticQuery, stateful: bool) -> Read {
    let (mut fields, any_field) = esql::names(query);
    let prefilter = if matches!(kind, ElasticQuery::Esql(_)) {
        let (prefilter, named) = esql::prefilter(query);
        fields.extend(named);
        prefilter
    } else {
        Predicate::Always
    };
    Read {
        fields,
        any_field,
        prefilter,
        stateful,
        query: kind,
    }
}

/// The requirement of a rule read as `read`, for every source; the caller narrows its scope.
fn requirement(rule: RuleId, read: &Read) -> RuleRequirements {
    RuleRequirements {
        rule,
        logsource: LogSource::default(),
        field_names: Some(Schema::Ecs),
        fields: if read.any_field.is_some() {
            RequiredFields::Unknown
        } else {
            RequiredFields::Known(read.fields.clone())
        },
        matches_raw_text: read.any_field.is_some(),
        stateful: read.stateful,
        text_lines_only: false,
        prefilter: read.prefilter.clone(),
    }
}

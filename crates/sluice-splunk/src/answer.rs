//! What Splunk answers a search, read for the proof: the rows, or why it refused, and an alert
//! per row.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sluice_core::alert::Alert;
use sluice_core::ids::{EventId, RuleId};

use crate::SplunkError;
use crate::client::{Rest, content, messages};
use crate::engine::{EVENT_FIELD, RUN_FIELD};

/// What became of one search.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Outcome {
    /// Its result rows.
    Rows(Vec<Map<String, Value>>),
    /// Splunk refused it, for this reason.
    Refused(String),
}

/// The smallest of Splunk's limits on the rows one answer holds (50,000 by default): a search
/// that reaches it may have more, which the proof cannot compare.
pub(crate) fn max_rows(rest: &Rest) -> Result<usize, SplunkError> {
    let mut limit = 50_000;
    for stanza in ["restapi", "searchresults"] {
        let answer = rest.send(
            "GET",
            &format!("/services/configs/conf-limits/{stanza}"),
            &[],
        )?;
        let found = serde_json::from_str::<Value>(&answer.body)
            .ok()
            .and_then(|a| content(&a)["maxresultrows"].as_str()?.parse::<usize>().ok());
        if let Some(rows) = found {
            limit = limit.min(rows);
        }
    }
    Ok(limit)
}

/// What a `oneshot` answer says. Splunk refuses a search with `400`, or with `200` and a
/// `FATAL` or `ERROR` message (a lookup or data model it does not have), and it caps the rows
/// at `max_rows` with no more than a warning: reaching the cap fails, as rows may be missing.
pub(crate) fn outcome(status: u16, body: &str, max_rows: usize) -> Result<Outcome, SplunkError> {
    let refused = |answer: &Value| {
        let why = messages(answer, &["FATAL", "ERROR"]);
        (!why.is_empty()).then_some(why)
    };
    if status == 400 {
        let why = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|a| refused(&a))
            .unwrap_or_else(|| sluice_http::excerpt(body));
        return Ok(Outcome::Refused(why));
    }
    if !(200..300).contains(&status) {
        return Err(SplunkError::Rejected {
            status,
            message: body.to_owned(),
        });
    }
    let answer: Value =
        serde_json::from_str(body).map_err(|e| SplunkError::Response(e.to_string()))?;
    if let Some(why) = refused(&answer) {
        return Ok(Outcome::Refused(why));
    }
    let rows: Vec<Map<String, Value>> = answer["results"]
        .as_array()
        .ok_or_else(|| {
            SplunkError::Response(format!(
                "a search answer without results: {}",
                sluice_http::excerpt(body)
            ))
        })?
        .iter()
        .filter_map(|row| row.as_object().cloned())
        .collect();
    if rows.len() >= max_rows {
        return Err(SplunkError::Response(format!(
            "a search returned {max_rows} rows, Splunk's limit (`maxresultrows`): too many to \
             compare"
        )));
    }
    Ok(Outcome::Rows(rows))
}

/// An alert per row: a row that is an event by the event's id, any other (a count, a table)
/// by its content, numbered so that identical rows stay distinct. What differs between
/// evaluations by design (their number, the index's name) reads the same in every one.
pub(crate) fn alerts(rule: &RuleId, rows: &[Map<String, Value>], index: &str) -> Vec<Alert> {
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();
    rows.iter()
        .map(|row| {
            let id = row
                .get(EVENT_FIELD)
                .and_then(Value::as_str)
                .and_then(|id| id.parse().ok());
            if let Some(id) = id {
                return Alert {
                    rule: rule.clone(),
                    event: EventId(id),
                };
            }
            let text = row_content(row, index);
            let occurrence = seen.entry(text.clone()).or_default();
            let id = fnv1a(&[rule.as_str(), &text, &occurrence.to_string()]);
            *occurrence += 1;
            Alert {
                rule: rule.clone(),
                event: EventId(id),
            }
        })
        .collect()
}

/// A row's content: its fields but Splunk's own (`_cd`, `_bkt`, `_raw`, …; `_time` stays) and
/// the evaluation's number ([`RUN_FIELD`]), in name order, with the index's name replaced.
fn row_content(row: &Map<String, Value>, index: &str) -> String {
    fn same_index(value: &Value, index: &str) -> Value {
        match value {
            Value::String(s) if s == index => Value::String("sluice_proof".to_owned()),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| same_index(v, index)).collect())
            }
            other => other.clone(),
        }
    }
    let fields: BTreeMap<&str, Value> = row
        .iter()
        .filter(|(name, _)| (!name.starts_with('_') || *name == "_time") && *name != RUN_FIELD)
        .map(|(name, value)| (name.as_str(), same_index(value, index)))
        .collect();
    let object: Map<String, Value> = fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    Value::Object(object).to_string()
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

#[cfg(test)]
mod tests;

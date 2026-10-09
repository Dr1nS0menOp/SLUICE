//! Which archived events a search or replay selects.

use std::collections::BTreeSet;
use std::str::FromStr;

use chrono::{DateTime, NaiveDate};
use serde_json::{Map, Value};
use sluice_core::event::Timestamp;
use sluice_core::field::FieldPath;
use sluice_core::ids::SourceId;

use crate::error::ArchiveError;

/// Seconds in one archive file.
pub(crate) const HOUR: i64 = 3_600;

/// A selection of archived events: sources, a time range and field conditions, all of which must
/// hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Sources to read. Empty means every source.
    pub sources: BTreeSet<SourceId>,
    /// Earliest event time, inclusive.
    pub from: Option<Timestamp>,
    /// Latest event time, exclusive.
    pub to: Option<Timestamp>,
    /// Conditions on the event body.
    pub conditions: Vec<Condition>,
}

impl Query {
    /// Returns true if events of `source` are selected.
    #[must_use]
    pub fn wants_source(&self, source: &SourceId) -> bool {
        self.sources.is_empty() || self.sources.contains(source)
    }

    /// Returns true if the hour starting at `start` overlaps the time range.
    #[must_use]
    pub fn overlaps_hour(&self, start: Timestamp) -> bool {
        self.from.is_none_or(|from| start.0 + HOUR > from.0)
            && self.to.is_none_or(|to| start.0 < to.0)
    }

    /// Returns true if an event at `time` with body `fields` is selected (the source is checked
    /// separately, per file).
    #[must_use]
    pub fn matches(&self, time: Timestamp, fields: &Map<String, Value>) -> bool {
        self.from.is_none_or(|from| time >= from)
            && self.to.is_none_or(|to| time < to)
            && self.conditions.iter().all(|c| c.matches(fields))
    }
}

/// How a [`Condition`] compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `field=value`: the field's text equals the value.
    Equals,
    /// `field!=value`: the field is missing or its text differs.
    NotEquals,
    /// `field~text`: the field's text contains the text, ignoring case.
    Contains,
}

/// One condition on an event body, such as `EventID=4624` or `CommandLine~mimikatz`.
///
/// A field compares by its text: strings as they are, numbers and booleans as JSON writes them.
/// An array matches if any element does, so `dns.resolved_ip=10.0.0.1` finds it in a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// The field, as a dotted path into nested objects.
    pub field: FieldPath,
    /// The comparison.
    pub op: Op,
    /// The value compared with.
    pub value: String,
}

impl Condition {
    /// Returns true if the condition holds for `fields`.
    #[must_use]
    pub fn matches(&self, fields: &Map<String, Value>) -> bool {
        let value = lookup(fields, &self.field);
        match self.op {
            Op::Equals => value.is_some_and(|v| any_text(v, &|t| t == self.value)),
            Op::NotEquals => !value.is_some_and(|v| any_text(v, &|t| t == self.value)),
            Op::Contains => {
                let needle = self.value.to_lowercase();
                value.is_some_and(|v| any_text(v, &|t| t.to_lowercase().contains(&needle)))
            }
        }
    }
}

impl FromStr for Condition {
    type Err = ArchiveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || ArchiveError::Condition(s.to_owned());
        let at = s.find(['=', '~', '!']).ok_or_else(invalid)?;
        let (op, rest) = match &s[at..] {
            rest if rest.starts_with("!=") => (Op::NotEquals, &rest[2..]),
            rest if rest.starts_with('=') => (Op::Equals, &rest[1..]),
            rest if rest.starts_with('~') => (Op::Contains, &rest[1..]),
            _ => return Err(invalid()),
        };
        let field = s[..at].trim();
        if field.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            field: FieldPath::new(field),
            op,
            value: rest.to_owned(),
        })
    }
}

/// Parses a time given on the command line: RFC 3339, or a date meaning its UTC midnight.
///
/// # Errors
///
/// Returns [`ArchiveError::Time`] for anything else.
pub fn parse_time(s: &str) -> Result<Timestamp, ArchiveError> {
    if let Ok(time) = DateTime::parse_from_rfc3339(s) {
        return Ok(Timestamp(time.timestamp()));
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map(|midnight| Timestamp(midnight.and_utc().timestamp()))
        .ok_or_else(|| ArchiveError::Time(s.to_owned()))
}

/// The value at `path`: a key with that exact name (flattened events), else the nested path.
fn lookup<'a>(fields: &'a Map<String, Value>, path: &FieldPath) -> Option<&'a Value> {
    if let Some(value) = fields.get(path.as_str()) {
        return Some(value);
    }
    let mut segments = path.segments();
    let mut value = fields.get(segments.next()?)?;
    for segment in segments {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

fn any_text(value: &Value, test: &dyn Fn(&str) -> bool) -> bool {
    match value {
        Value::String(s) => test(s),
        Value::Number(n) => test(&n.to_string()),
        Value::Bool(b) => test(if *b { "true" } else { "false" }),
        Value::Array(items) => items.iter().any(|item| any_text(item, test)),
        Value::Null | Value::Object(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn body(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    fn condition(s: &str) -> Condition {
        s.parse().unwrap()
    }

    #[test]
    fn parses_each_operator() {
        assert_eq!(condition("EventID=4624").op, Op::Equals);
        assert_eq!(condition("a.b!=x").op, Op::NotEquals);
        let contains = condition("CommandLine~mimi=katz");
        assert_eq!(contains.op, Op::Contains);
        assert_eq!(contains.value, "mimi=katz", "the first operator splits");
        assert!("=x".parse::<Condition>().is_err());
        assert!("field".parse::<Condition>().is_err());
        assert!("a!b".parse::<Condition>().is_err());
    }

    #[test]
    fn compares_by_text_through_nesting_and_arrays() {
        let event = body(json!({
            "EventID": 4624,
            "process": {"name": "LSASS.exe"},
            "dns": {"resolved_ip": ["10.0.0.1", "10.0.0.2"]},
            "flat.key": true,
        }));
        assert!(condition("EventID=4624").matches(&event));
        assert!(condition("process.name~lsass").matches(&event));
        assert!(condition("dns.resolved_ip=10.0.0.2").matches(&event));
        assert!(condition("flat.key=true").matches(&event));
        assert!(
            !condition("process=x").matches(&event),
            "objects have no text"
        );
        assert!(condition("missing!=x").matches(&event));
        assert!(!condition("missing=x").matches(&event));
        assert!(!condition("EventID!=4624").matches(&event));
    }

    #[test]
    fn time_range_is_half_open_and_hours_overlap() {
        let query = Query {
            from: Some(Timestamp(7_200)),
            to: Some(Timestamp(10_800)),
            ..Query::default()
        };
        let empty = Map::new();
        assert!(query.matches(Timestamp(7_200), &empty));
        assert!(!query.matches(Timestamp(10_800), &empty));
        assert!(query.overlaps_hour(Timestamp(7_200)));
        assert!(
            query.overlaps_hour(Timestamp(5_000)),
            "ends inside the range"
        );
        assert!(!query.overlaps_hour(Timestamp(3_600)));
        assert!(!query.overlaps_hour(Timestamp(10_800)));
    }

    #[test]
    fn parses_rfc3339_and_dates() {
        assert_eq!(
            parse_time("2026-10-09T17:00:00+02:00").unwrap(),
            Timestamp(1_791_558_000)
        );
        assert_eq!(parse_time("2026-10-09").unwrap(), Timestamp(1_791_504_000));
        assert!(parse_time("yesterday").is_err());
    }
}

//! The rolling window of tapped events each cycle analyzes.

use std::collections::{BTreeMap, VecDeque};

use chrono::DateTime;
use serde_json::{Map, Value};
use sluice_core::event::{Event, Timestamp};
use sluice_core::ids::{EventId, SourceId};

use crate::config::WindowConfig;

/// Tapped events per source, bounded by count and age. The control plane's cost follows these
/// bounds, never the traffic volume.
#[derive(Debug)]
pub(crate) struct Windows {
    config: WindowConfig,
    by_source: BTreeMap<SourceId, VecDeque<Event>>,
    next_id: u64,
}

impl Windows {
    pub(crate) fn new(config: WindowConfig) -> Self {
        Self {
            config,
            by_source: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// Adds a tapped event. Its time is its `@timestamp` if present, else `now`.
    pub(crate) fn push(&mut self, source: &SourceId, fields: Map<String, Value>, now: i64) {
        let timestamp = fields
            .get("@timestamp")
            .and_then(Value::as_str)
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map_or(now, |t| t.timestamp());
        let event = Event {
            id: EventId(self.next_id),
            timestamp: Timestamp(timestamp),
            source: source.clone(),
            fields,
        };
        self.next_id += 1;
        let queue = self.by_source.entry(source.clone()).or_default();
        queue.push_back(event);
        while queue.len() > self.config.max_events_per_source {
            queue.pop_front();
        }
    }

    /// Drops events older than the window, and returns the rest in time order, numbered from 0.
    pub(crate) fn snapshot(&mut self, now: i64) -> Vec<Event> {
        let oldest = now - self.config.max_age_secs;
        for queue in self.by_source.values_mut() {
            queue.retain(|e| e.timestamp.0 >= oldest);
        }
        let mut events: Vec<Event> = self.by_source.values().flatten().cloned().collect();
        events.sort_by_key(|e| e.timestamp);
        for (event, n) in events.iter_mut().zip(0u64..) {
            event.id = EventId(n);
        }
        events
    }

    /// Events held per source.
    pub(crate) fn sizes(&self) -> BTreeMap<SourceId, usize> {
        self.by_source
            .iter()
            .map(|(s, q)| (s.clone(), q.len()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn fields(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    #[test]
    fn keeps_the_newest_events_within_count_and_age() {
        let mut windows = Windows::new(WindowConfig {
            max_events_per_source: 2,
            max_age_secs: 100,
        });
        let source = SourceId::new("s");
        for n in 0..3 {
            windows.push(&source, fields(json!({"n": n})), 1_000 + n);
        }
        let events = windows.snapshot(1_050);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].fields["n"], 1);
        assert_eq!(events[0].id, EventId(0));
        assert!(windows.snapshot(1_200).is_empty(), "everything aged out");
    }

    #[test]
    fn event_time_comes_from_the_timestamp_field() {
        let mut windows = Windows::new(WindowConfig::default());
        let source = SourceId::new("s");
        windows.push(
            &source,
            fields(json!({"@timestamp": "2026-10-10T08:00:00Z"})),
            0,
        );
        windows.push(
            &source,
            fields(json!({"@timestamp": "2026-10-10T07:00:00Z"})),
            0,
        );
        let events = windows.snapshot(1_791_619_200);
        assert!(
            events[0].timestamp < events[1].timestamp,
            "sorted by event time"
        );
    }
}

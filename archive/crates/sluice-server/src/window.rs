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

    /// Drops events older than the window and takes the rest out, in time order, numbered from
    /// 0, for one cycle; [`Windows::give_back`] returns them. Taking instead of copying keeps one
    /// copy of the window in memory, not two.
    pub(crate) fn take(&mut self, now: i64) -> Vec<Event> {
        let oldest = now - self.config.max_age_secs;
        let mut events: Vec<Event> = Vec::new();
        for queue in self.by_source.values_mut() {
            events.extend(queue.drain(..).filter(|e| e.timestamp.0 >= oldest));
        }
        events.sort_by_key(|e| e.timestamp);
        for (event, n) in events.iter_mut().zip(0u64..) {
            event.id = EventId(n);
        }
        events
    }

    /// Returns the events of [`Windows::take`]. Events tapped meanwhile stay newest, and the
    /// count bound applies again.
    pub(crate) fn give_back(&mut self, events: Vec<Event>) {
        let mut by_source: BTreeMap<SourceId, VecDeque<Event>> = BTreeMap::new();
        for event in events {
            by_source
                .entry(event.source.clone())
                .or_default()
                .push_back(event);
        }
        for (source, mut taken) in by_source {
            let queue = self.by_source.entry(source).or_default();
            taken.append(queue);
            while taken.len() > self.config.max_events_per_source {
                taken.pop_front();
            }
            *queue = taken;
        }
    }

    /// Events held per source.
    #[cfg(test)]
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
        let events = windows.take(1_050);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].fields["n"], 1);
        assert_eq!(events[0].id, EventId(0));
        windows.give_back(events);
        let again = windows.take(1_200);
        assert!(again.is_empty(), "everything aged out");
    }

    #[test]
    fn events_tapped_during_a_cycle_stay_newest_and_the_bound_holds() {
        let mut windows = Windows::new(WindowConfig {
            max_events_per_source: 3,
            max_age_secs: 1_000,
        });
        let source = SourceId::new("s");
        for n in 0..3 {
            windows.push(&source, fields(json!({"n": n})), 1_000 + n);
        }
        let taken = windows.take(1_010);
        assert_eq!(windows.sizes().get(&source), Some(&0), "taken, not copied");
        windows.push(&source, fields(json!({"n": 3})), 1_011);
        windows.give_back(taken);
        let events = windows.take(1_012);
        let order: Vec<_> = events.iter().map(|e| e.fields["n"].clone()).collect();
        assert_eq!(
            order,
            [json!(1), json!(2), json!(3)],
            "oldest dropped, newest kept"
        );
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
        let events = windows.take(1_791_619_200);
        assert!(
            events[0].timestamp < events[1].timestamp,
            "sorted by event time"
        );
    }
}

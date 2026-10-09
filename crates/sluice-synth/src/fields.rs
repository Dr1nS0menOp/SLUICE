//! Small helpers for building event bodies and timestamps.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

/// Builder for an event body. Output is deterministic either way: `serde_json::Map` is sorted, or
/// in insertion order if a dependency turns on `preserve_order`. Generation order is fixed in both
/// cases.
#[derive(Debug, Default)]
pub(crate) struct Fields(Map<String, Value>);

impl Fields {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.insert(key.to_owned(), value.into());
        self
    }

    pub(crate) fn into_map(self) -> Map<String, Value> {
        self.0
    }
}

/// Builds a JSON object from key/value pairs, for nested envelope objects.
pub(crate) fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// Wall-clock rendering of a Unix timestamp. Out-of-range values clamp to the epoch, which
/// cannot happen for the windows the generator uses.
pub(crate) fn datetime(unix_secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(unix_secs, 0).unwrap_or_default()
}

/// RFC 3339 with milliseconds, as Beats-style shippers write `@timestamp`.
pub(crate) fn rfc3339(unix_secs: i64) -> String {
    datetime(unix_secs)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Windows event-log style time with 100 ns precision, as in `TimeCreated` / `UtcTime`.
pub(crate) fn windows_time(unix_secs: i64, fraction: u64) -> String {
    format!(
        "{}.{:07}",
        datetime(unix_secs).format("%Y-%m-%d %H:%M:%S"),
        fraction % 10_000_000
    )
}

/// BSD syslog time (`Oct  9 08:15:30`).
pub(crate) fn syslog_time(unix_secs: i64) -> String {
    datetime(unix_secs).format("%b %e %H:%M:%S").to_string()
}

/// Common log format time (`09/Oct/2026:08:15:30 +0000`).
pub(crate) fn clf_time(unix_secs: i64) -> String {
    datetime(unix_secs)
        .format("%d/%b/%Y:%H:%M:%S +0000")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_791_620_130; // 2026-10-10T08:15:30Z

    #[test]
    fn formats_are_stable() {
        assert_eq!(rfc3339(T), "2026-10-10T08:15:30.000Z");
        assert_eq!(windows_time(T, 1_234_567), "2026-10-10 08:15:30.1234567");
        assert_eq!(syslog_time(T), "Oct 10 08:15:30");
        assert_eq!(clf_time(T), "10/Oct/2026:08:15:30 +0000");
    }
}

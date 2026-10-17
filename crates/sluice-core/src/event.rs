//! Events of a sample, as the analysis reads them.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ids::{EventId, SourceId};

/// Event time in whole seconds since the Unix epoch.
///
/// Time is always data, never read from a clock, so proofs over windows and correlations are
/// reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

/// One log event from a sample, with its identity and origin attached.
///
/// `fields` holds the event body exactly as it would reach a SIEM. Identity, time and source sit
/// outside the body, so a reduction can never change them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Identity within the sample.
    pub id: EventId,
    /// Event time.
    pub timestamp: Timestamp,
    /// Source the event came from.
    pub source: SourceId,
    /// The event body.
    pub fields: Map<String, Value>,
}

/// Approximate size in bytes of an event body as forwarded: its compact JSON encoding.
///
/// SIEMs bill on ingested bytes, and compact JSON is close to what most sinks send. This is an
/// estimate for reporting, not an exact bill.
#[must_use]
pub fn encoded_size(fields: &Map<String, Value>) -> usize {
    // Serializing a `Map<String, Value>` cannot fail: keys are strings and values are valid JSON.
    serde_json::to_vec(fields).map_or(0, |bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn encoded_size_is_the_compact_json_length() {
        let Value::Object(fields) = json!({"a": 1, "b": "x"}) else {
            unreachable!()
        };
        assert_eq!(encoded_size(&fields), r#"{"a":1,"b":"x"}"#.len());
        assert_eq!(encoded_size(&Map::new()), 2);
    }

    #[test]
    fn encoded_size_counts_escapes_and_utf8_bytes() {
        let Value::Object(fields) = json!({"q": "\"é\n"}) else {
            unreachable!()
        };
        // {"q":"\"é\n"}: the quote and newline escape to two bytes, é is two bytes in UTF-8.
        assert_eq!(encoded_size(&fields), 14);
    }
}

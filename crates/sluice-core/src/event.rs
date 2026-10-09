//! Events as seen by the control plane.

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

//! Log sources: where events come from and how they are encoded.

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::SourceId;
use crate::logsource::LogSource;

/// How a source's event bodies are encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceFormat {
    /// Structured fields; the event type follows from field names and discriminator values.
    Json,
    /// A raw text line in `field`, plus envelope fields; the event type follows from the line.
    Text {
        /// Field holding the raw line.
        field: FieldPath,
    },
}

/// A configured log source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// Identity, as set on every event of the source.
    pub id: SourceId,
    /// What the source is, for rule scoping.
    pub logsource: LogSource,
    /// How events are encoded.
    pub format: SourceFormat,
}

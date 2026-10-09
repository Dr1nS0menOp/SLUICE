//! Discovered log templates.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::{SourceId, TemplateId};
use crate::logsource::LogSource;

/// A recurring event shape within a source, such as "Windows 4624 logon, type 3".
///
/// The id is derived from the shape itself. A format change produces a new id with no recipe,
/// so drifted data falls back to pass-through by construction (safety contract rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    /// Stable identity of the shape.
    pub id: TemplateId,
    /// Source the template was discovered in.
    pub source: SourceId,
    /// What the template is, as far as it is known. Unknown attributes stay `None`.
    pub logsource: LogSource,
    /// Human-readable shape, such as a Drain pattern or a sorted key set.
    pub pattern: String,
    /// The exact shape, from which the data plane's classifier is compiled.
    pub shape: TemplateShape,
    /// Fields seen in events of this template.
    pub fields: BTreeSet<FieldPath>,
    /// Fields holding free text (rendered messages, original lines). Raw-text rules match here.
    pub text_fields: BTreeSet<FieldPath>,
    /// How often the template occurs.
    pub stats: TemplateStats,
}

/// The exact shape of a template: what an event must look like to belong to it.
///
/// Discovery produces it and the data plane compiles it into a classifier. Both sides must agree
/// on the definition, which is why it lives in core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TemplateShape {
    /// A JSON event: exactly these leaf paths (nested objects flattened with `.`, arrays and
    /// scalars as leaves, empty objects absent), with these discriminator values.
    Keyset {
        /// Discriminator fields and their rendered values (strings as-is, other scalars as JSON).
        discriminators: Vec<(FieldPath, String)>,
        /// Every leaf path.
        paths: BTreeSet<FieldPath>,
    },
    /// A text line in `field`, matching masked Drain tokens.
    Text {
        /// Field holding the line.
        field: FieldPath,
        /// Whether the line carried a syslog header (then `tokens[0]` is the program name).
        header: LineHeader,
        /// Masked tokens; see [`token`] for placeholders.
        tokens: Vec<String>,
    },
}

/// Header kind of the lines in a text template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineHeader {
    /// No recognised header; tokens cover the whole line.
    None,
    /// A syslog header was reduced to its program name, the first token.
    Syslog,
    /// Lines of both kinds merged. No classifier can describe the template, so it is never
    /// matched in the data plane and its events pass through.
    Mixed,
}

/// Placeholders inside masked text tokens.
pub mod token {
    /// A whole token that varies between lines.
    pub const WILDCARD: &str = "<*>";
    /// A run of decimal digits.
    pub const NUM: &str = "<NUM>";
    /// A hex identifier: `0x…`, or 8+ hex characters including a digit.
    pub const HEX: &str = "<HEX>";
}

/// Frequency of a template within the sample it was discovered in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateStats {
    /// Events of this template.
    pub events: u64,
    /// Bytes of this template (compact JSON, before reduction).
    pub bytes: u64,
    /// Events in the whole source over the same sample, for the template's share.
    pub source_events: u64,
}

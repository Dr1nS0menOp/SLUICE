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
    /// Fields seen in events of this template.
    pub fields: BTreeSet<FieldPath>,
    /// Fields holding free text (rendered messages, original lines). Raw-text rules match here.
    pub text_fields: BTreeSet<FieldPath>,
    /// How often the template occurs.
    pub stats: TemplateStats,
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

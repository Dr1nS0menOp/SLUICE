//! The fields a Sigma detection reads.

use std::collections::BTreeSet;

use rsigma_parser::ast::{Detection, Detections, Modifier};
use rsigma_parser::value::SigmaValue;
use sluice_core::field::FieldPath;
use sluice_core::rules::RequiredFields;

/// What a detection section reads from events.
#[derive(Debug, Default)]
pub(crate) struct Reads {
    fields: BTreeSet<FieldPath>,
    /// Keyword matching scans every string value of the event, so any field may matter.
    any_field: bool,
}

impl Reads {
    /// Everything every named detection reads, used by the condition or not: an unused
    /// selection costs nothing, and guessing which ones are used is a needless risk.
    pub(crate) fn of(detections: &Detections) -> Self {
        let mut reads = Self::default();
        for detection in detections.named.values() {
            reads.add(detection);
        }
        reads
    }

    /// Whether the rule does keyword (free-text) matching.
    pub(crate) fn matches_raw_text(&self) -> bool {
        self.any_field
    }

    pub(crate) fn extend_fields(&mut self, fields: impl IntoIterator<Item = FieldPath>) {
        self.fields.extend(fields);
    }

    pub(crate) fn merge(&mut self, other: Reads) {
        self.fields.extend(other.fields);
        self.any_field |= other.any_field;
    }

    pub(crate) fn into_required(self) -> RequiredFields {
        if self.any_field {
            RequiredFields::Unknown
        } else {
            RequiredFields::Known(self.fields)
        }
    }

    fn add(&mut self, detection: &Detection) {
        match detection {
            Detection::AllOf(items) => {
                for item in items {
                    let Some(name) = item.field.name.as_deref() else {
                        // A field-less item matches values anywhere, like a keyword.
                        self.any_field = true;
                        continue;
                    };
                    self.fields.insert(FieldPath::new(name));
                    if item.field.modifiers.contains(&Modifier::FieldRef) {
                        // `fieldref` values name another field to compare against.
                        self.fields
                            .extend(item.values.iter().filter_map(|v| match v {
                                SigmaValue::String(s) => Some(FieldPath::new(s.original.as_str())),
                                _ => None,
                            }));
                    }
                }
            }
            Detection::AnyOf(parts) | Detection::And(parts) => {
                for part in parts {
                    self.add(part);
                }
            }
            Detection::Keywords(_) => self.any_field = true,
            // Member-relative names live under the array field, which covers them.
            Detection::ArrayMatch { field, .. } => {
                self.fields.insert(FieldPath::new(field.as_str()));
            }
            Detection::Conditional { named, .. } => {
                for part in named.values() {
                    self.add(part);
                }
            }
        }
    }
}

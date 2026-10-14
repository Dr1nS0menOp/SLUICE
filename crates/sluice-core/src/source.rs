//! Log sources: where events come from and how they are encoded.

use serde::{Deserialize, Serialize};

use crate::field::FieldPath;
use crate::ids::SourceId;
use crate::logsource::LogSource;
use crate::schema::Schema;

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
    /// The convention the records' field names follow. Undeclared (the default) means no rule's
    /// field names can be compared with them, so nothing a rule could read is cut (ADR 0018).
    #[serde(default)]
    pub schema: Schema,
    /// Fields whose values name the kind of event (`eventName`, `event_type`), on top of the
    /// defaults discovery uses for every source and for the source's product. Events with other
    /// values become other templates, so a rare kind of event stays rare (ADR 0019).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_type: Vec<FieldPath>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_source_defaults_to_an_undeclared_schema_and_no_event_type_fields() {
        let source: Source = serde_json::from_str(
            r#"{"id":"s","logsource":{"product":"windows"},"format":{"kind":"json"}}"#,
        )
        .unwrap();
        assert_eq!(source.schema, Schema::Undeclared);
        assert_eq!(source.event_type.len(), 0);
        assert_eq!(source.format, SourceFormat::Json);
    }

    #[test]
    fn a_text_source_names_the_field_with_the_line() {
        let source: Source = serde_json::from_str(
            r#"{"id":"s","logsource":{},"format":{"kind":"text","field":"message"},"schema":"sigma"}"#,
        )
        .unwrap();
        assert_eq!(
            source.format,
            SourceFormat::Text {
                field: "message".into()
            }
        );
        assert_eq!(source.schema, Schema::Sigma);
    }

    #[test]
    fn an_unknown_format_or_schema_is_refused() {
        let bad_format = r#"{"id":"s","logsource":{},"format":{"kind":"xml"}}"#;
        assert!(serde_json::from_str::<Source>(bad_format).is_err());
        let bad_schema = r#"{"id":"s","logsource":{},"format":{"kind":"json"},"schema":"ECS"}"#;
        assert!(serde_json::from_str::<Source>(bad_schema).is_err());
    }

    #[test]
    fn empty_event_type_fields_are_not_serialized() {
        let source = Source {
            id: "s".into(),
            logsource: LogSource::default(),
            format: SourceFormat::Json,
            schema: Schema::Sigma,
            event_type: Vec::new(),
        };
        let json = serde_json::to_value(&source).unwrap();
        assert!(json.get("event_type").is_none());
    }
}

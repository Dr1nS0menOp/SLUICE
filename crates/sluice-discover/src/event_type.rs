//! The fields that name the kind of event in a JSON source (ADR 0019).
//!
//! Every value of these fields gets its own template, so the guardrails can tell a rare kind of
//! event from a frequent one, and rules and recipes can be scoped to one kind. A field that an
//! event lacks simply does not count, so more fields only ever split templates further.

use sluice_core::field::FieldPath;
use sluice_core::source::Source;

/// The fields for `source`: the ones discovery uses everywhere, the defaults for its product,
/// then its own, without repeats and in that order.
pub(crate) fn fields_for(everywhere: &[FieldPath], source: &Source) -> Vec<FieldPath> {
    let product = source.logsource.product.as_deref().unwrap_or_default();
    let mut fields: Vec<FieldPath> = Vec::new();
    let candidates = everywhere
        .iter()
        .cloned()
        .chain(by_product(product).iter().map(|f| FieldPath::from(*f)))
        .chain(source.event_type.iter().cloned());
    for field in candidates {
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    fields
}

/// Where well-known products name the kind of event, in their own field names (the names Sigma
/// rules for them use too).
fn by_product(product: &str) -> &'static [&'static str] {
    match product.to_ascii_lowercase().as_str() {
        // CloudTrail: `s3.amazonaws.com` / `GetObject`.
        "aws" => &["eventSource", "eventName"],
        // Okta System Log: `user.session.start`.
        "okta" => &["eventType"],
        // Microsoft 365 management activity: `Exchange` / `MailItemsAccessed`.
        "m365" => &["Workload", "Operation"],
        // Azure activity, sign-in and audit logs.
        "azure" => &["category", "operationName"],
        // Google Cloud audit logs.
        "gcp" => &["protoPayload.serviceName", "protoPayload.methodName"],
        // Kubernetes audit events: `create` / `pods`.
        "kubernetes" => &["verb", "objectRef.resource"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use sluice_core::logsource::LogSource;
    use sluice_core::source::SourceFormat;

    use super::*;

    fn source(product: &str, own: &[&str]) -> Source {
        Source {
            id: "s".into(),
            logsource: LogSource {
                product: Some(product.into()),
                ..LogSource::default()
            },
            format: SourceFormat::Json,
            schema: sluice_core::schema::Schema::default(),
            event_type: own.iter().map(|f| FieldPath::from(*f)).collect(),
        }
    }

    #[test]
    fn product_defaults_and_own_fields_follow_the_global_ones() {
        let everywhere = [FieldPath::from("EventID"), FieldPath::from("action")];
        let fields = fields_for(
            &everywhere,
            &source("AWS", &["userIdentity.type", "action"]),
        );
        let names: Vec<&str> = fields.iter().map(FieldPath::as_str).collect();
        assert_eq!(
            names,
            [
                "EventID",
                "action",
                "eventSource",
                "eventName",
                "userIdentity.type"
            ]
        );
    }

    #[test]
    fn an_unknown_product_adds_nothing() {
        let everywhere = [FieldPath::from("EventID")];
        assert_eq!(fields_for(&everywhere, &source("windows", &[])), everywhere);
    }
}

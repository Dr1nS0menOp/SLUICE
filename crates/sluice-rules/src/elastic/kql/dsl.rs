//! A KQL query as the Elasticsearch query Kibana builds from it, so the proof can run the rule
//! itself (ADR 0025).
//!
//! As Kibana does: `field: value` is a `match`, a quoted value a `match_phrase`, a value with a
//! wildcard a `query_string` on the field, `field: *` an `exists`, a range a `range`, a value
//! without a field a `multi_match` over every field (lenient, as a number field cannot take
//! text), and `and`, `or`, `not` a `bool` (`filter`, `should`, `must_not`). A nested query runs
//! as its inner query on the full paths: the proof index maps no nested objects.

use serde_json::{Value, json};

use super::{Literal, Node};

/// The Elasticsearch query of `node`.
pub(super) fn query(node: &Node) -> Value {
    match node {
        Node::All => json!({ "match_all": {} }),
        Node::Or(parts) => json!({ "bool": {
            "should": parts.iter().map(query).collect::<Vec<_>>(),
            "minimum_should_match": 1,
        } }),
        Node::And(parts) => json!({ "bool": {
            "filter": parts.iter().map(query).collect::<Vec<_>>(),
        } }),
        Node::Not(inner) => json!({ "bool": { "must_not": [query(inner)] } }),
        Node::Is { name, value, .. } => is(name, value),
        Node::Exists { name } => json!({ "exists": { "field": name } }),
        Node::Range { name, op, value } => json!({ "range": { name.as_str(): { *op: value } } }),
        Node::Free(value) => json!({ "multi_match": {
            "query": value.text,
            "type": if value.quoted { "phrase" } else { "best_fields" },
            "lenient": true,
        } }),
    }
}

fn is(name: &str, value: &Literal) -> Value {
    if value.wildcard {
        return json!({ "query_string": {
            "fields": [name],
            "query": escaped(&value.text),
            "analyze_wildcard": true,
            "lenient": true,
        } });
    }
    if name.contains('*') {
        return json!({ "multi_match": {
            "query": value.text,
            "fields": [name],
            "type": if value.quoted { "phrase" } else { "best_fields" },
            "lenient": true,
        } });
    }
    if value.quoted {
        json!({ "match_phrase": { name: value.text } })
    } else {
        json!({ "match": { name: { "query": value.text, "lenient": true } } })
    }
}

/// `text` for `query_string`: its special characters escaped, `*` and `?` kept as wildcards, as
/// Kibana's wildcard values are.
fn escaped(text: &str) -> String {
    const SPECIAL: &str = "+-=&|><!(){}[]^\"~:\\/ ";
    let mut out = String::new();
    for c in text.chars() {
        if SPECIAL.contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

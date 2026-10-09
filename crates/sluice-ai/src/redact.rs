//! Redaction of samples before any model sees them.
//!
//! The model needs the *shape* of an event (which fields exist, what kind of values they hold), not
//! who or where. Redaction is format-preserving and consistent within one call, so the model can
//! still see that two fields hold the same value:
//!
//! - fields whose name says they identify a person or machine (`user`, `account`, `host`,
//!   `computer`, `workstation`, `sid`, `domain`, `email`, `name`) → `<user-1>`, `<host-2>`, …
//! - IPv4 addresses anywhere in strings → `192.0.2.N` (documentation range);
//! - e-mail addresses → `user-N@example.invalid`;
//! - long opaque tokens (20+ alphanumerics, such as keys and hashes) → `<token-N>`.
//!
//! This is defense in depth, not anonymisation: run a local model when samples must not leave
//! the network at all.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// Replaces sensitive values consistently across the events of one call.
#[derive(Debug, Default)]
pub(crate) struct Redactor {
    seen: BTreeMap<(&'static str, String), String>,
}

const IDENTITY_KEYS: [(&str, &str); 9] = [
    ("user", "user"),
    ("account", "user"),
    ("email", "user"),
    ("sid", "sid"),
    ("host", "host"),
    ("computer", "host"),
    ("workstation", "host"),
    ("domain", "domain"),
    ("name", "name"),
];

impl Redactor {
    pub(crate) fn event(&mut self, fields: &Map<String, Value>) -> Map<String, Value> {
        self.object("", fields)
    }

    fn object(&mut self, prefix: &str, fields: &Map<String, Value>) -> Map<String, Value> {
        fields
            .iter()
            .map(|(key, value)| {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                (key.clone(), self.value(&path, value))
            })
            .collect()
    }

    /// `path` is the dotted field path, so `host.name` is recognised as a host.
    fn value(&mut self, path: &str, value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(self.object(path, map)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|v| self.value(path, v)).collect())
            }
            Value::String(text) => Value::String(self.string(path, text)),
            other => other.clone(),
        }
    }

    fn string(&mut self, path: &str, text: &str) -> String {
        let lower = path.to_ascii_lowercase();
        if let Some((_, kind)) = IDENTITY_KEYS.iter().find(|(k, _)| lower.contains(k))
            && !text.is_empty()
            && text != "-"
        {
            return self.pseudonym(kind, text, |n| format!("<{kind}-{n}>"));
        }
        self.scan(text)
    }

    /// Redacts IPv4 addresses, e-mail addresses and long tokens inside free text.
    fn scan(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for (is_word, piece) in split_words(text) {
            if !is_word {
                out.push_str(piece);
            } else if is_ipv4(piece) {
                out.push_str(&self.pseudonym("ip", piece, |n| format!("192.0.2.{}", n % 255)));
            } else if is_email(piece) {
                out.push_str(
                    &self.pseudonym("email", piece, |n| format!("user-{n}@example.invalid")),
                );
            } else if piece.len() >= 20 && piece.bytes().all(|b| b.is_ascii_alphanumeric()) {
                out.push_str(&self.pseudonym("token", piece, |n| format!("<token-{n}>")));
            } else {
                out.push_str(piece);
            }
        }
        out
    }

    fn pseudonym(
        &mut self,
        kind: &'static str,
        original: &str,
        render: impl Fn(usize) -> String,
    ) -> String {
        let next = 1 + self.seen.keys().filter(|(k, _)| *k == kind).count();
        self.seen
            .entry((kind, original.to_owned()))
            .or_insert_with(|| render(next))
            .clone()
    }
}

/// Splits text into maximal runs of word characters (alphanumerics plus `.@_-+`) and the rest.
fn split_words(text: &str) -> Vec<(bool, &str)> {
    let is_word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '@' | '_' | '-' | '+');
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut current: Option<bool> = None;
    for (i, c) in text.char_indices() {
        let word = is_word(c);
        if current.is_some_and(|w| w != word) {
            pieces.push((current.unwrap_or(false), &text[start..i]));
            start = i;
        }
        current = Some(word);
    }
    if let Some(word) = current {
        pieces.push((word, &text[start..]));
    }
    pieces
}

fn is_ipv4(piece: &str) -> bool {
    let piece = piece.trim_end_matches('.');
    let octets: Vec<&str> = piece.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.len() <= 3 && o.parse::<u8>().is_ok())
}

fn is_email(piece: &str) -> bool {
    piece
        .split_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn redact(value: Value) -> Value {
        let Value::Object(map) = value else {
            panic!("object")
        };
        Value::Object(Redactor::default().event(&map))
    }

    #[test]
    fn identity_fields_get_consistent_pseudonyms() {
        let out = redact(json!({
            "TargetUserName": "alice", "SubjectUserName": "alice", "WorkstationName": "WS-BOB",
            "host": {"name": "web01"}, "IpPort": "-"
        }));
        assert_eq!(out["TargetUserName"], "<user-1>");
        assert_eq!(
            out["SubjectUserName"], "<user-1>",
            "same value, same pseudonym"
        );
        assert_eq!(out["WorkstationName"], "<host-1>");
        assert_eq!(out["host"]["name"], "<host-2>");
        assert_eq!(out["IpPort"], "-", "placeholders stay");
    }

    #[test]
    fn free_text_ips_emails_and_tokens_are_replaced() {
        let out = redact(json!({
            "message": "Failed password for x from 198.51.100.23 port 22, mail bob@corp.example key 844d7f3d6c9855e22ed8ab22"
        }));
        assert_eq!(
            out["message"],
            "Failed password for x from 192.0.2.1 port 22, mail user-1@example.invalid key <token-1>"
        );
    }

    #[test]
    fn structure_and_non_strings_are_kept() {
        let out = redact(json!({"EventID": 4624, "ok": true, "list": ["10.0.0.1", "10.0.0.1"]}));
        assert_eq!(
            out,
            json!({"EventID": 4624, "ok": true, "list": ["192.0.2.1", "192.0.2.1"]})
        );
    }
}

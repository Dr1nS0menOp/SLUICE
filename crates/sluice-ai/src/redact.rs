//! Redaction of samples before any model sees them.
//!
//! The model needs the *shape* of an event (which fields exist, what kind of values they hold), not
//! who or where. Redaction is format-preserving and consistent within one call, so the model can
//! still see that two fields hold the same value:
//!
//! - fields whose name says they identify a person or machine (`user`, `account`, `host`,
//!   `computer`, `workstation`, `sid`, `domain`, `email`, `name`) → `<user-1>`, `<host-2>`, …
//! - IPv4 addresses anywhere in strings → `192.0.2.N`, IPv6 → `2001:db8::N` (documentation
//!   ranges), MAC addresses → `02:00:00:00:00:NN`;
//! - e-mail addresses → `user-N@example.invalid`;
//! - long opaque tokens (20+ alphanumerics, or 24+ characters of base64 or JWT text with letters
//!   and digits, such as keys, hashes and bearer tokens) → `<token-N>`.
//!
//! This is defense in depth, not anonymisation: run a local model when samples must not leave
//! the network at all.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

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

    /// Free text from the logs outside any field, such as a template's pattern.
    pub(crate) fn text(&mut self, text: &str) -> String {
        self.scan(text)
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

    /// Redacts addresses, e-mail addresses and long tokens inside free text: network addresses
    /// first (their `:` would split them into words), then base64 and JWT runs (their `/`, `=`
    /// and `.`), then word by word.
    fn scan(&mut self, text: &str) -> String {
        let text = replace_runs(text, is_address_char, |run| self.address(run));
        let text = replace_runs(&text, is_token_char, |run| {
            // `key=value`: keep the key readable, judge the value. Padding `=` stays with it.
            let (key, value) = match run.find('=') {
                Some(at) if !run[at + 1..].trim_end_matches('=').is_empty() => run.split_at(at + 1),
                _ => ("", run),
            };
            is_secret_like(value).then(|| {
                format!(
                    "{key}{}",
                    self.pseudonym("token", value, |n| format!("<token-{n}>"))
                )
            })
        });
        self.words(&text)
    }

    /// An IPv6 or MAC address's pseudonym, if `run` is one.
    fn address(&mut self, run: &str) -> Option<String> {
        let core = run.trim_end_matches(['.', ':', '-']);
        let rest = &run[core.len()..];
        let has_hex = core.bytes().any(|b| b.is_ascii_hexdigit());
        let pseudonym =
            if has_hex && core.matches(':').count() >= 2 && core.parse::<Ipv6Addr>().is_ok() {
                self.pseudonym("ip6", core, |n| format!("2001:db8::{n:x}"))
            } else if is_mac(core) {
                self.pseudonym("mac", core, |n| format!("02:00:00:00:00:{:02x}", n % 256))
            } else {
                return None;
            };
        Some(pseudonym + rest)
    }

    /// Redacts IPv4 addresses, e-mail addresses and long alphanumeric tokens word by word.
    fn words(&mut self, text: &str) -> String {
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

/// `text` with every maximal run of `in_run` characters that `replace` maps replaced.
fn replace_runs(
    text: &str,
    in_run: impl Fn(char) -> bool,
    mut replace: impl FnMut(&str) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut start: Option<usize> = None;
    let mut flush = |out: &mut String, run: &str| match replace(run) {
        Some(replacement) => out.push_str(&replacement),
        None => out.push_str(run),
    };
    for (i, c) in text.char_indices() {
        match (in_run(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                flush(&mut out, &text[s..i]);
                start = None;
                out.push(c);
            }
            (false, None) => out.push(c),
            (true, Some(_)) => {}
        }
    }
    if let Some(s) = start {
        flush(&mut out, &text[s..]);
    }
    out
}

fn is_address_char(c: char) -> bool {
    c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '-')
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '.')
}

/// Six groups of two hex digits, all separated by `:` or all by `-`.
fn is_mac(text: &str) -> bool {
    [':', '-'].iter().any(|&separator| {
        let groups: Vec<&str> = text.split(separator).collect();
        groups.len() == 6
            && groups
                .iter()
                .all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

/// A run that looks like a key, hash or bearer token: 24+ characters with letters and at least
/// two digits or base64 symbols (`/`, `+`, `=`), not an IPv4 address. A long plain name such as
/// `process_creation_win_susp` has neither, and stays.
fn is_secret_like(run: &str) -> bool {
    let letters = run.bytes().filter(u8::is_ascii_alphabetic).count();
    let marks = run
        .bytes()
        .filter(|b| b.is_ascii_digit() || matches!(b, b'/' | b'+' | b'='))
        .count();
    run.len() >= 24 && letters >= 2 && marks >= 2 && !is_ipv4(run)
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

    fn text(message: &str) -> String {
        redact(json!({ "message": message }))["message"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn ipv6_addresses_are_replaced() {
        for address in [
            "2001:db8:85a3::8a2e:370:7334",
            "fe80::1",
            "::ffff:198.51.100.7",
            "2a01:4f8:c0c:1234:0:0:0:1",
        ] {
            let out = text(&format!("from {address} port 22"));
            assert!(!out.contains(address), "{address} leaked: {out}");
            assert!(
                out.starts_with("from ") && out.ends_with(" port 22"),
                "{out}"
            );
        }
    }

    #[test]
    fn mac_addresses_are_replaced() {
        for mac in ["00:1A:2B:3C:4D:5E", "00-1a-2b-3c-4d-5e"] {
            let out = text(&format!("client {mac} joined"));
            assert!(!out.contains(mac), "{mac} leaked: {out}");
        }
    }

    #[test]
    fn jwts_and_base64_secrets_are_replaced() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let padded = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
        for secret in [jwt, aws, padded] {
            let out = text(&format!("token={secret} end"));
            assert!(!out.contains(secret), "{secret} leaked: {out}");
            assert!(out.ends_with(" end"), "{out}");
        }
    }

    #[test]
    fn times_ports_and_short_words_stay_readable() {
        for kept in [
            "08:00:02",
            "2026-10-14T08:00:02Z",
            "port 22",
            "cmd.exe",
            "a :: b",
            "EventID 4624",
            "process_creation_win_susp_whoami",
        ] {
            assert_eq!(text(kept), kept);
        }
    }

    #[test]
    fn the_key_of_a_key_value_secret_stays_readable() {
        assert_eq!(
            text("token=QWxhZGRpbjpvcGVuIHNlc2FtZQ== end"),
            "token=<token-1> end"
        );
    }

    #[test]
    fn pseudonyms_stay_consistent_across_fields_and_kinds() {
        let out = redact(json!({
            "a": "from fe80::1 and 10.0.0.1",
            "b": "again fe80::1 and 10.0.0.1",
        }));
        let (a, b) = (out["a"].as_str().unwrap(), out["b"].as_str().unwrap());
        assert_eq!(a.replace("from", "again"), b);
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

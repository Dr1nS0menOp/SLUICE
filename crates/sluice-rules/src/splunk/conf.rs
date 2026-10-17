//! Splunk's configuration as stanzas of settings, from `.conf` files (`savedsearches.conf`,
//! `macros.conf`) or from the REST API's JSON answers (`saved/searches`, `admin/macros`), which
//! carry the same settings per entry.

use std::collections::BTreeMap;

use serde_json::Value;

/// One stanza: its name and its settings.
pub(crate) type Stanzas = BTreeMap<String, BTreeMap<String, String>>;

/// Reads a `.conf` file. A line ending in `\` continues on the next; `#` starts a comment line.
/// Settings before the first stanza header belong to `default`, as in Splunk.
pub(crate) fn conf(text: &str) -> Stanzas {
    let mut stanzas = Stanzas::new();
    let mut stanza = "default".to_owned();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let mut line = line.trim_start().to_owned();
        while line.ends_with('\\') {
            line.pop();
            line.push('\n');
            match lines.next() {
                Some(next) => line.push_str(next),
                None => break,
            }
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(name) = line
            .trim_end()
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
        {
            name.clone_into(&mut stanza);
            stanzas.entry(stanza.clone()).or_default();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            stanzas
                .entry(stanza.clone())
                .or_default()
                .insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    stanzas
}

/// The setting that marks a macro several apps define differently: which definition a search
/// gets depends on its app, so a call to it cannot be read.
pub(crate) const AMBIGUOUS: &str = "sluice.ambiguous";

/// Reads a REST answer: `{"entry": [{"name": …, "content": {…}}]}`. Booleans become `1` or
/// `0`; other non-string values are left out. `None` when the text is no such answer.
///
/// Entries of different apps may share a name. A search keeps every copy, the later ones as
/// `name (app)`; a macro defined differently is marked [`AMBIGUOUS`].
pub(crate) fn rest(text: &str) -> Option<Stanzas> {
    let answer: Value = serde_json::from_str(text).ok()?;
    let entries = answer.get("entry")?.as_array()?;
    let mut stanzas = Stanzas::new();
    for entry in entries {
        let (Some(name), Some(content)) = (
            entry.get("name").and_then(Value::as_str),
            entry.get("content").and_then(Value::as_object),
        ) else {
            continue;
        };
        let settings = content
            .iter()
            .filter_map(|(key, value)| {
                let value = match value {
                    Value::String(s) => s.clone(),
                    Value::Bool(b) => u8::from(*b).to_string(),
                    Value::Number(n) => n.to_string(),
                    _ => return None,
                };
                Some((key.clone(), value))
            })
            .collect();
        insert(&mut stanzas, name, entry, settings);
    }
    Some(stanzas)
}

fn insert(stanzas: &mut Stanzas, name: &str, entry: &Value, settings: BTreeMap<String, String>) {
    let Some(existing) = stanzas.get_mut(name) else {
        stanzas.insert(name.to_owned(), settings);
        return;
    };
    if *existing == settings {
        return;
    }
    if existing.contains_key("definition") || settings.contains_key("definition") {
        existing.insert(AMBIGUOUS.to_owned(), "1".to_owned());
        return;
    }
    let app = entry
        .pointer("/acl/app")
        .and_then(Value::as_str)
        .unwrap_or("another app");
    let mut key = format!("{name} ({app})");
    while stanzas.contains_key(&key) {
        key.push('\'');
    }
    stanzas.insert(key, settings);
}

/// Whether a setting is true as Splunk reads booleans.
pub(crate) fn truthy(value: Option<&String>) -> bool {
    value.is_some_and(|v| {
        ["1", "true", "t", "yes", "y"]
            .iter()
            .any(|t| v.trim().eq_ignore_ascii_case(t))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_files_continue_lines_and_skip_comments() {
        let stanzas = conf(
            "disabled = 0\n# a comment\n[Brute Force]\nsearch = EventCode=4625 \\\n| stats count\n\
             enableSched = 1\n\n[other]\n",
        );
        assert_eq!(stanzas["default"]["disabled"], "0");
        assert_eq!(
            stanzas["Brute Force"]["search"],
            "EventCode=4625 \n| stats count"
        );
        assert_eq!(stanzas["Brute Force"]["enableSched"], "1");
        assert!(stanzas["other"].is_empty());
    }

    #[test]
    fn rest_answers_carry_settings_per_entry() {
        let stanzas = rest(
            r#"{"entry": [{"name": "x", "content": {"search": "a=1", "disabled": false,
                "is_scheduled": true, "cron_schedule": null}}]}"#,
        )
        .expect("a REST answer");
        assert_eq!(stanzas["x"]["search"], "a=1");
        assert_eq!(stanzas["x"]["disabled"], "0");
        assert_eq!(stanzas["x"]["is_scheduled"], "1");
        assert!(!stanzas["x"].contains_key("cron_schedule"));
        assert_eq!(rest("[]"), None);
    }

    #[test]
    fn c3_entries_of_several_apps_with_one_name_are_all_kept() {
        let stanzas = rest(
            r#"{"entry": [
                {"name": "s", "acl": {"app": "a"}, "content": {"search": "x=1"}},
                {"name": "s", "acl": {"app": "b"}, "content": {"search": "y=1"}},
                {"name": "m", "content": {"definition": "x=1"}},
                {"name": "m", "content": {"definition": "y=1"}},
                {"name": "same", "content": {"definition": "z=1"}},
                {"name": "same", "content": {"definition": "z=1"}}]}"#,
        )
        .expect("a REST answer");
        assert_eq!(stanzas["s"]["search"], "x=1");
        assert_eq!(stanzas["s (b)"]["search"], "y=1");
        assert_eq!(stanzas["m"][AMBIGUOUS], "1");
        assert!(!stanzas["same"].contains_key(AMBIGUOUS));
    }

    #[test]
    fn booleans_read_as_splunk_reads_them() {
        assert!(truthy(Some(&"True".to_owned())));
        assert!(truthy(Some(&" 1".to_owned())));
        assert!(!truthy(Some(&"0".to_owned())));
        assert!(!truthy(None));
    }
}

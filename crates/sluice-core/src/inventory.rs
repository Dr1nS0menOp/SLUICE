//! A rule inventory: the rules, queries and functions a SIEM runs, as read from its API
//! (ADR 0021).
//!
//! Fetchers live in the adapter crates and return an [`Inventory`]; the CLI writes it to a
//! directory the rule loaders read, with [`Manifest`] as `inventory.json`. Only a manifest
//! that says [`Manifest::complete`] lets the guardrails summarize.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The file name of the manifest in an inventory directory.
pub const MANIFEST_FILE: &str = "inventory.json";

/// What a fetch read, ready to be written.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inventory {
    /// Rule files, as `(relative path, contents)`. Paths use `/` and never leave the directory.
    pub files: Vec<(String, String)>,
    /// What the files hold and where they came from.
    pub manifest: Manifest,
}

/// The `inventory.json` of a fetched rule directory.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// The SIEM, such as `sentinel` or `wazuh`.
    pub system: String,
    /// Where the rules were read from, such as a workspace resource id or an API URL.
    pub from: String,
    /// When, as RFC 3339; passed in by the caller.
    pub fetched_at: String,
    /// Whether every rule and query the SIEM runs was read. A fetch that skipped anything it
    /// could not page through or download says `false`.
    pub complete: bool,
    /// How many files of each kind were written, such as `rules`, `hunting`, `functions`.
    pub counts: BTreeMap<String, usize>,
    /// Rules that run but have no query to read, and how they were treated.
    #[serde(default)]
    pub not_modeled: Vec<String>,
}

/// Whether `path` is a safe relative path inside an inventory directory: not empty, not
/// absolute, and without `.` or `..` components. File names come from the SIEM, so a hostile
/// or broken API must not be able to write elsewhere.
#[must_use]
pub fn is_safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// A file name for `name` that is safe on any file system: letters, digits, `-`, `_` and `.`
/// kept, everything else replaced by `_`, never empty and never only dots.
#[must_use]
pub fn file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();
    if cleaned.chars().all(|c| c == '.') {
        format!("_{cleaned}")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_that_leave_the_directory_are_unsafe() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "./a",
            "a\\b",
            "a/",
        ] {
            assert!(!is_safe_relative_path(bad), "{bad:?}");
        }
        for good in ["rules/a.yaml", "ruleset/rules/0010-rules_config.xml", "a"] {
            assert!(is_safe_relative_path(good), "{good:?}");
        }
    }

    #[test]
    fn file_names_keep_only_safe_characters() {
        assert_eq!(
            file_name("Brute force / RDP (4625)"),
            "Brute_force___RDP__4625_"
        );
        assert_eq!(file_name(".."), "_..");
        assert_eq!(file_name(""), "_");
        assert!(is_safe_relative_path(&file_name("../../etc")));
    }

    #[test]
    fn the_manifest_round_trips() {
        let manifest = Manifest {
            system: "sentinel".into(),
            from: "/subscriptions/x".into(),
            fetched_at: "2026-10-14T00:00:00Z".into(),
            complete: true,
            counts: BTreeMap::from([("rules".into(), 2)]),
            not_modeled: vec!["Fusion".into()],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&json).unwrap(), manifest);
    }
}

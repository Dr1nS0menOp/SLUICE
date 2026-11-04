//! Splunk's ES Content Update app (`DA-ESS-ContentUpdate`, Apache-2.0, fetched at runtime like
//! all third-party rule content) reads without a panic, and how much was understood.
//!
//! Runs only with `SLUICE_SPLUNK_RULES` set to the app's `default` directory
//! (`scripts/real-data/fetch-splunk-escu.sh`). The app ships every search disabled; the test
//! reads them as if all were enabled.

#![allow(clippy::print_stderr, reason = "the test reports what it read")]

use std::collections::BTreeMap;

use sluice_core::rules::RequiredFields;
use sluice_rules::SplunkRules;

#[test]
fn the_escu_searches_are_read_with_their_macros() {
    let Ok(dir) = std::env::var("SLUICE_SPLUNK_RULES") else {
        eprintln!("skipped: set SLUICE_SPLUNK_RULES");
        return;
    };
    let read = |name: &str| {
        std::fs::read_to_string(format!("{dir}/{name}")).expect("the app's configuration")
    };
    let searches = read("savedsearches.conf").replace("\ndisabled = 1\n", "\ndisabled = 0\n");
    let macros = read("macros.conf");
    let scheduled = searches.matches("\nenableSched = 1\n").count();
    let rules = SplunkRules::parse([
        ("savedsearches.conf", searches.as_str()),
        ("macros.conf", macros.as_str()),
    ]);
    let all = rules.requirements();
    let unknown = all
        .iter()
        .filter(|r| r.fields == RequiredFields::Unknown)
        .count();
    let unbounded = all.iter().filter(|r| r.prefilter.is_always()).count();
    let stateful = all.iter().filter(|r| r.stateful).count();
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for problem in rules.problems() {
        let reason = problem
            .message
            .split_once(": ")
            .map_or(problem.message.as_str(), |(_, r)| r);
        let reason = reason.split(';').next().unwrap_or(reason);
        // One line per kind: macro names differ per search.
        let kind: String = reason
            .split('`')
            .enumerate()
            .map(|(i, part)| if i % 2 == 1 { "…" } else { part })
            .collect();
        *reasons.entry(kind).or_default() += 1;
    }
    eprintln!(
        "{} searches: {unknown} may read any field, {unbounded} may match any event, {stateful} \
         stateful",
        all.len()
    );
    for (reason, n) in &reasons {
        eprintln!("  {n:>5}  {reason}");
    }
    assert_eq!(all.len(), scheduled, "every scheduled search, once");
    let mut unknown_macros: BTreeMap<&str, usize> = BTreeMap::new();
    for problem in rules.problems() {
        if let Some(name) = problem
            .message
            .split_once("the macro `")
            .and_then(|(_, rest)| rest.split_once("`, which is not among the files"))
        {
            *unknown_macros.entry(name.0).or_default() += 1;
        }
    }
    for (name, n) in &unknown_macros {
        eprintln!("  unknown macro {name}: {n}");
    }
    let missing: usize = unknown_macros.values().sum();
    assert!(missing * 100 < all.len(), "the app's own macros resolve");
}

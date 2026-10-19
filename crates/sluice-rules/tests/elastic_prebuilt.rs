//! Elastic's prebuilt detection rules (the `security_detection_engine` package, Elastic License
//! 2.0, so never in the repository) read without a panic, and how many were understood.
//!
//! Runs only with `SLUICE_ELASTIC_RULES` set to the package's `kibana/security_rule` directory
//! (`scripts/real-data/fetch-elastic-rules.sh`). The package installs every rule disabled; the
//! test reads them as if all were enabled.

#![allow(clippy::print_stderr, reason = "the test reports what it read")]

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::rules::RequiredFields;
use sluice_rules::ElasticRules;

#[test]
fn the_prebuilt_rules_are_read_and_most_are_bounded() {
    let Ok(dir) = std::env::var("SLUICE_ELASTIC_RULES") else {
        eprintln!("skipped: set SLUICE_ELASTIC_RULES");
        return;
    };
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the directory") {
        let path = entry.expect("an entry").path();
        let text = std::fs::read_to_string(&path).expect("a file");
        files.push((
            path.display().to_string(),
            text.replace("\"enabled\": false", "\"enabled\": true"),
        ));
    }
    // `<rule id>_<version>.json`: one rule per id runs, unless its newest version is deprecated.
    let mut newest: BTreeMap<&str, (u64, bool)> = BTreeMap::new();
    for (path, text) in &files {
        let stem = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .trim_end_matches(".json");
        let Some((id, version)) = stem.rsplit_once('_') else {
            continue;
        };
        let version: u64 = version.parse().unwrap_or(0);
        if newest.get(id).is_none_or(|(v, _)| *v < version) {
            newest.insert(id, (version, text.contains("\"deprecated\": true")));
        }
    }
    let running = newest
        .values()
        .filter(|(_, deprecated)| !deprecated)
        .count();
    let rules = ElasticRules::parse(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
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
        *reasons
            .entry(reason.chars().take(70).collect())
            .or_default() += 1;
    }
    eprintln!(
        "{} rules: {unknown} may read any field, {unbounded} may match any event, {stateful} \
         stateful",
        all.len()
    );
    for (reason, n) in &reasons {
        eprintln!("  {n:>5}  {reason}");
    }
    for problem in rules
        .problems()
        .iter()
        .filter(|p| p.message.contains("expected"))
    {
        eprintln!("  parse: {problem}");
    }
    let ids: BTreeSet<&str> = all.iter().map(|r| r.rule.as_str()).collect();
    let everywhere = all
        .iter()
        .filter(|r| r.logsource == sluice_core::logsource::LogSource::default())
        .count();
    eprintln!(
        "{} rules that run, {everywhere} requirements apply to every source",
        ids.len()
    );
    assert_eq!(ids.len(), running, "every rule that runs, once");
    assert!(
        unknown * 5 < all.len(),
        "more than a fifth may read any field"
    );
}

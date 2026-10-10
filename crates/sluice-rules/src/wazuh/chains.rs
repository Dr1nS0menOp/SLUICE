//! `<if_sid>` chains: a child rule is only evaluated when one of its parents matched.
//!
//! So a child can only see events some parent's pre-filter admits, and it effectively reads what
//! its parents read. Resolving that turns a child's own unbounded pre-filter (`<match>` on the
//! raw line) into "its own conditions and any parent's", which the parents' decoders usually bound.
//! A missing or cyclic parent adds nothing, which leaves the child as wide as on its own.

use std::collections::BTreeMap;

use sluice_core::predicate::Predicate;
use sluice_core::rules::{RequiredFields, RuleRequirements};

/// One parsed rule and the ids its `<if_sid>` names.
pub(super) struct Parsed {
    pub(super) requirements: RuleRequirements,
    pub(super) parents: Vec<String>,
}

/// Applies every chain; returns the rules in their original order.
pub(super) fn inherit(parsed: Vec<Parsed>) -> Vec<RuleRequirements> {
    let index: BTreeMap<String, usize> = parsed
        .iter()
        .enumerate()
        .map(|(i, p)| (p.requirements.rule.as_str().to_owned(), i))
        .collect();
    let mut resolved: Vec<Option<RuleRequirements>> = vec![None; parsed.len()];
    let mut visiting = vec![false; parsed.len()];
    for i in 0..parsed.len() {
        resolve(i, &parsed, &index, &mut resolved, &mut visiting);
    }
    resolved
        .into_iter()
        .zip(parsed)
        .map(|(r, p)| r.unwrap_or(p.requirements))
        .collect()
}

fn resolve(
    i: usize,
    parsed: &[Parsed],
    index: &BTreeMap<String, usize>,
    resolved: &mut [Option<RuleRequirements>],
    visiting: &mut [bool],
) -> Option<RuleRequirements> {
    if let Some(done) = &resolved[i] {
        return Some(done.clone());
    }
    if visiting[i] {
        return None; // a cycle: this parent adds nothing
    }
    visiting[i] = true;
    let own = &parsed[i];
    let mut rule = own.requirements.clone();
    if !own.parents.is_empty() {
        let mut parent_prefilters = Vec::new();
        // Only text lines reach the child if only text lines reach every parent.
        let mut parents_text_only = true;
        for id in &own.parents {
            let parent = index
                .get(&format!("wazuh:{id}"))
                .and_then(|&p| resolve(p, parsed, index, resolved, visiting));
            if let Some(parent) = parent {
                parent_prefilters.push(parent.prefilter);
                rule.fields = union(&rule.fields, &parent.fields);
                rule.matches_raw_text |= parent.matches_raw_text;
                rule.stateful |= parent.stateful;
                parents_text_only &= parent.text_lines_only;
            } else {
                parent_prefilters.push(Predicate::Always);
                parents_text_only = false;
            }
        }
        rule.text_lines_only |= parents_text_only;
        rule.prefilter = Predicate::all([rule.prefilter, Predicate::any(parent_prefilters)]);
    }
    visiting[i] = false;
    resolved[i] = Some(rule.clone());
    Some(rule)
}

fn union(a: &RequiredFields, b: &RequiredFields) -> RequiredFields {
    match (a, b) {
        (RequiredFields::Known(a), RequiredFields::Known(b)) => {
            RequiredFields::Known(a.union(b).cloned().collect())
        }
        _ => RequiredFields::Unknown,
    }
}

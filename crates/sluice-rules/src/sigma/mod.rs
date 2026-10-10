//! Sigma rules: parsing, requirements and evaluation.

mod engine;
mod fields;
mod prefilter;

use std::collections::{BTreeMap, BTreeSet};

use rsigma_parser::ast::{CorrelationCondition, CorrelationRule, FilterRuleTarget, SigmaRule};
use rsigma_parser::{SigmaCollection, parse_sigma_yaml};
use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::rules::RuleRequirements;
use sluice_core::source::Source;

pub use self::engine::SigmaEngine;
use self::fields::Reads;
use crate::error::RulesError;

/// The rule id Sluice uses for a Sigma rule: its `id`, else its title.
pub(crate) fn rule_id(id: Option<&str>, title: &str) -> RuleId {
    RuleId::new(format!("sigma:{}", id.unwrap_or(title)))
}

/// A loaded Sigma rule set.
#[derive(Debug, Clone)]
pub struct SigmaRules {
    collection: SigmaCollection,
    requirements: Vec<RuleRequirements>,
    problems: Vec<String>,
}

impl SigmaRules {
    /// Parses Sigma YAML documents (one string per file; files may hold several documents).
    ///
    /// Documents rsigma cannot understand do not fail the load. Each becomes an opaque
    /// requirement, which blocks every cut, and a [`problem`](Self::problems). The SIEM still
    /// runs that rule, so ignoring it would hide regressions from the proof.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError::SigmaParse`] if a file is not valid YAML at all.
    pub fn parse<'a>(files: impl IntoIterator<Item = &'a str>) -> Result<Self, RulesError> {
        let mut collection = SigmaCollection::new();
        for file in files {
            let parsed =
                parse_sigma_yaml(file).map_err(|e| RulesError::SigmaParse(e.to_string()))?;
            collection.rules.extend(parsed.rules);
            collection.correlations.extend(parsed.correlations);
            collection.filters.extend(parsed.filters);
            collection.errors.extend(parsed.errors);
        }
        let mut problems = collection.errors.clone();
        let requirements = requirements(&collection, &mut problems);
        Ok(Self {
            collection,
            requirements,
            problems,
        })
    }

    /// What each rule needs from the data, after applying filters and correlations.
    #[must_use]
    pub fn requirements(&self) -> &[RuleRequirements] {
        &self.requirements
    }

    /// Rules that could not be fully understood; each is covered by an opaque requirement.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    /// An engine evaluating these rules, scoped by the given sources' log sources.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError::SigmaCompile`] if rsigma rejects the collection.
    pub fn engine(&self, sources: &[Source]) -> Result<SigmaEngine, RulesError> {
        SigmaEngine::new(self.collection.clone(), sources)
    }
}

fn requirements(collection: &SigmaCollection, problems: &mut Vec<String>) -> Vec<RuleRequirements> {
    let mut reads: Vec<Reads> = collection
        .rules
        .iter()
        .map(|r| Reads::of(&r.detection))
        .collect();
    let mut stateful: Vec<bool> = collection
        .rules
        .iter()
        .map(|r| r.detection.timeframe.is_some())
        .collect();
    let index = RuleIndex::new(collection);

    for filter in &collection.filters {
        let targets: Vec<usize> = match &filter.rules {
            FilterRuleTarget::Any => (0..collection.rules.len()).collect(),
            FilterRuleTarget::Specific(refs) => refs.iter().flat_map(|r| index.rules(r)).collect(),
        };
        for target in targets {
            reads[target].merge(Reads::of(&filter.detection));
        }
    }

    let mut opaque = Vec::new();
    for correlation in &collection.correlations {
        let mut visited = BTreeSet::new();
        let resolved = index.base_rules(correlation, &mut visited);
        if resolved.unresolved {
            problems.push(format!(
                "correlation {:?} references a rule that is not loaded",
                correlation.title
            ));
            opaque.push(RuleRequirements::opaque(rule_id(
                correlation.id.as_deref(),
                &correlation.title,
            )));
        }
        for target in resolved.rules {
            stateful[target] = true;
            reads[target].extend_fields(correlation_fields(correlation, &collection.rules[target]));
        }
    }

    let mut out: Vec<RuleRequirements> = collection
        .rules
        .iter()
        .zip(reads)
        .zip(stateful)
        .map(|((rule, reads), stateful)| RuleRequirements {
            rule: rule_id(rule.id.as_deref(), &rule.title),
            logsource: logsource(rule),
            matches_raw_text: reads.matches_raw_text(),
            fields: reads.into_required(),
            stateful,
            prefilter: prefilter::rule_prefilter(&rule.detection),
        })
        .collect();
    out.extend(opaque);
    out.extend(
        (0..collection.errors.len())
            .map(|n| RuleRequirements::opaque(RuleId::new(format!("sigma:unparsed:{n}")))),
    );
    out
}

fn logsource(rule: &SigmaRule) -> LogSource {
    LogSource {
        product: rule.logsource.product.clone(),
        service: rule.logsource.service.clone(),
        category: rule.logsource.category.clone(),
        complete: false,
    }
}

/// Fields a correlation reads from one of its base rules' events: group-by fields (through
/// aliases where defined) and the condition's value field.
fn correlation_fields(correlation: &CorrelationRule, rule: &SigmaRule) -> Vec<FieldPath> {
    let names = [rule.id.as_deref(), rule.name.as_deref()];
    let mut fields: Vec<FieldPath> = correlation
        .group_by
        .iter()
        .map(|group| {
            correlation
                .aliases
                .iter()
                .find(|alias| &alias.alias == group)
                .and_then(|alias| {
                    names
                        .iter()
                        .flatten()
                        .find_map(|name| alias.mapping.get(*name))
                })
                .map_or_else(
                    || FieldPath::new(group.as_str()),
                    |f| FieldPath::new(f.as_str()),
                )
        })
        .collect();
    if let CorrelationCondition::Threshold {
        field: Some(value_fields),
        ..
    } = &correlation.condition
    {
        fields.extend(value_fields.iter().map(|f| FieldPath::new(f.as_str())));
    }
    fields
}

/// Lookup of rules and correlations by the references correlations and filters use.
struct RuleIndex<'a> {
    rules: BTreeMap<&'a str, Vec<usize>>,
    correlations: BTreeMap<&'a str, &'a CorrelationRule>,
}

#[derive(Default)]
struct Resolved {
    rules: BTreeSet<usize>,
    unresolved: bool,
}

impl<'a> RuleIndex<'a> {
    fn new(collection: &'a SigmaCollection) -> Self {
        let mut rules: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (i, rule) in collection.rules.iter().enumerate() {
            for name in [rule.id.as_deref(), rule.name.as_deref()]
                .into_iter()
                .flatten()
            {
                rules.entry(name).or_default().push(i);
            }
        }
        let mut correlations = BTreeMap::new();
        for correlation in &collection.correlations {
            for name in [correlation.id.as_deref(), correlation.name.as_deref()]
                .into_iter()
                .flatten()
            {
                correlations.insert(name, correlation);
            }
        }
        Self {
            rules,
            correlations,
        }
    }

    fn rules(&self, reference: &str) -> Vec<usize> {
        self.rules.get(reference).cloned().unwrap_or_default()
    }

    /// Base detection rules of a correlation, following chained correlations.
    fn base_rules(
        &self,
        correlation: &'a CorrelationRule,
        visited: &mut BTreeSet<&'a str>,
    ) -> Resolved {
        let mut resolved = Resolved::default();
        for reference in &correlation.rules {
            if let Some(found) = self.rules.get(reference.as_str()) {
                resolved.rules.extend(found);
            } else if let Some(&inner) = self.correlations.get(reference.as_str()) {
                if visited.insert(reference.as_str()) {
                    let nested = self.base_rules(inner, visited);
                    resolved.rules.extend(nested.rules);
                    resolved.unresolved |= nested.unresolved;
                }
            } else {
                resolved.unresolved = true;
            }
        }
        resolved
    }
}

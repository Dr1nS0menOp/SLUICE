//! The real engines the proof runs SIEM rules in: Elasticsearch for Elastic's rules, the Kusto
//! emulator for Sentinel's.

use anyhow::{Context, Result};
use sluice_core::event::Event;

/// Elasticsearch at `url`, running the rules of `rules` on an index that maps every field they
/// name (ADR 0025): EQL and ES|QL as they are, KQL as the query Kibana builds from it.
pub(crate) fn elasticsearch(
    url: &str,
    rules: &sluice_rules::ElasticRules,
) -> Result<sluice_elastic::ElasticEngine> {
    use sluice_rules::ElasticQuery;
    let queries: Vec<(sluice_core::ids::RuleId, sluice_elastic::RuleQuery)> = rules
        .queries()
        .iter()
        .map(|(id, query)| {
            let query = match query {
                ElasticQuery::Eql(q) => sluice_elastic::RuleQuery::Eql(q.clone()),
                ElasticQuery::Esql(q) => sluice_elastic::RuleQuery::Esql(q.clone()),
                ElasticQuery::Search { query, keys } => sluice_elastic::RuleQuery::Search {
                    query: query.clone(),
                    keys: keys.clone(),
                },
            };
            (id.clone(), query)
        })
        .collect();
    let fields: std::collections::BTreeSet<sluice_core::field::FieldPath> = rules
        .requirements()
        .iter()
        .filter_map(|r| match &r.fields {
            sluice_core::rules::RequiredFields::Known(fields) => Some(fields.iter().cloned()),
            sluice_core::rules::RequiredFields::Unknown => None,
        })
        .flatten()
        .collect();
    let engine = sluice_elastic::ElasticEngine::connect(url, &queries, &fields)
        .with_context(|| format!("connecting to Elasticsearch at {url}"))?;
    eprintln!(
        "Elastic: {} rules run in Elasticsearch; {} refused there are covered by their \
         requirements only",
        engine.rules().count(),
        engine.skipped().len(),
    );
    let mut reasons: std::collections::BTreeMap<&str, (usize, &str)> =
        std::collections::BTreeMap::new();
    for (_, reason) in engine.skipped() {
        // The reason without its position (`line 2:15: `) and the field or function it names
        // (`[…]`), so alike ones count together.
        let text = if reason.starts_with("line ") {
            reason.splitn(3, ':').nth(2).unwrap_or(reason)
        } else {
            reason.as_str()
        };
        let kind = text.split('[').next().unwrap_or(text).trim();
        reasons.entry(kind).or_insert((0, text.trim())).0 += 1;
    }
    let mut reasons: Vec<(usize, &str)> = reasons.into_values().collect();
    reasons.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    for (n, example) in reasons.iter().take(3) {
        let example: String = example.chars().take(140).collect();
        eprintln!("  {n:>5} refused, such as: {example}");
    }
    Ok(engine)
}

/// The source and table a `--sentinel-table SOURCE=TABLE` names: a standard table, or a
/// custom one (`<Name>_CL`) with the columns `sluice connect sentinel --sample` gives the
/// source's records in `events`.
pub(crate) fn sentinel_table(
    spec: &str,
    events: &[Event],
) -> Result<(sluice_core::ids::SourceId, sluice_kql::Table)> {
    let (source, table) = spec
        .split_once('=')
        .with_context(|| format!("--sentinel-table {spec}: expected SOURCE=TABLE"))?;
    let (source, table) = (source.trim(), table.trim());
    let found = match table.strip_suffix("_CL") {
        Some(name) => {
            let records: Vec<_> = events
                .iter()
                .filter(|e| e.source.as_str() == source)
                .map(|e| e.fields.clone())
                .collect();
            let inferred = sluice_vector::CustomTable::infer(name, &records)
                .with_context(|| format!("--sentinel-table {spec}"))?;
            let mut columns = vec![sluice_kql::CustomColumn {
                name: "TimeGenerated".to_owned(),
                kind: "datetime".to_owned(),
                field: "TimeGenerated".to_owned(),
            }];
            columns.extend(inferred.columns().iter().map(|c| sluice_kql::CustomColumn {
                name: c.name.clone(),
                kind: c.kind.name().to_owned(),
                field: c.field.clone(),
            }));
            sluice_kql::Table::custom(table, columns)
        }
        None => sluice_kql::Table::from_name(table),
    };
    let table = found
        .with_context(|| format!("--sentinel-table {spec}: Sluice cannot load table `{table}`"))?;
    Ok((sluice_core::ids::SourceId::new(source), table))
}

/// The Kusto emulator at `url`, running `rules` on the sources `--sentinel-table` names.
pub(crate) fn kusto(
    url: &str,
    rules: &sluice_rules::SentinelRules,
    specs: &[String],
    events: &[Event],
) -> Result<sluice_kql::KustoEngine> {
    let tables = specs
        .iter()
        .map(|spec| sentinel_table(spec, events))
        .collect::<Result<_>>()?;
    let engine = sluice_kql::KustoEngine::connect(url, rules.queries(), tables)
        .with_context(|| format!("connecting to the Kusto emulator at {url}"))?;
    eprintln!(
        "Sentinel: {} rules run in the emulator, {} cannot run there and are covered by their \
         requirements only",
        engine.rules().count(),
        engine.skipped().len()
    );
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_table_specs_are_checked_before_the_emulator_is_asked() {
        let rules = sluice_rules::SentinelRules::parse(std::iter::empty::<(&str, &str)>());
        // An address nothing listens on: the spec errors must come first.
        let url = "http://127.0.0.1:9";
        let error = format!(
            "{:#}",
            kusto(url, &rules, &["win".to_owned()], &[]).unwrap_err()
        );
        assert!(error.contains("expected SOURCE=TABLE"), "{error}");
        let error = format!(
            "{:#}",
            kusto(url, &rules, &["win=Nope".to_owned()], &[]).unwrap_err()
        );
        assert!(error.contains("cannot load table `Nope`"), "{error}");
        let error = format!(
            "{:#}",
            kusto(url, &rules, &["win = SecurityEvent".to_owned()], &[]).unwrap_err()
        );
        assert!(
            error.contains("connecting to the Kusto emulator"),
            "{error}"
        );
    }
}

//! Which sources a rule's index patterns can read.
//!
//! A rule reads the indices its `index` patterns name (for ES|QL, its `FROM`), and Elastic's
//! data streams are named after the integration that fills them: `logs-aws.cloudtrail-*`,
//! `logs-system.security-*`. Where the integration says unambiguously what the data is, the
//! pattern becomes a log source in the vocabulary sources declare (Sigma's): `windows`, `linux`,
//! `aws`, `m365`, … A pattern that does not (`logs-*`, `filebeat-*`, an integration not listed)
//! may read any source, and so does a rule with one such pattern (fail closed). Exclusions
//! (`-logs-…`) only narrow and are ignored.

use sluice_core::logsource::LogSource;

/// The log sources a rule over `patterns` may read: one per product it names, or a single
/// unbounded one.
pub(crate) fn scopes<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Vec<LogSource> {
    let mut scopes: Vec<LogSource> = Vec::new();
    let mut any = false;
    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty() || pattern.starts_with('-') {
            continue;
        }
        match scope(pattern) {
            Some(scope) if !scopes.contains(&scope) => scopes.push(scope),
            Some(_) => {}
            None => any = true,
        }
    }
    if any || scopes.is_empty() {
        return vec![LogSource::default()];
    }
    scopes.sort();
    scopes
}

/// The Windows datasets of the System integration, and their Sigma services.
const WINDOWS_SYSTEM: [(&str, &str); 3] = [
    ("logs-system.security", "security"),
    ("logs-system.application", "application"),
    ("logs-system.system", "system"),
];

/// The Linux datasets of the System integration.
const LINUX_SYSTEM: [(&str, &str); 2] = [
    ("logs-system.auth", "auth"),
    ("logs-system.syslog", "syslog"),
];

/// Integrations named as the product Sigma names (`logs-<integration>.<dataset>-…`). Not
/// `m365_defender`: it holds endpoint events Sigma calls `windows`.
const PRODUCTS: [(&str, &str); 8] = [
    ("aws", "aws"),
    ("gcp", "gcp"),
    ("azure", "azure"),
    ("okta", "okta"),
    ("github", "github"),
    ("o365", "m365"),
    ("google_workspace", "google_workspace"),
    ("kubernetes", "kubernetes"),
];

/// The data an index pattern names, where its integration says it unambiguously.
fn scope(pattern: &str) -> Option<LogSource> {
    let pattern = pattern.to_ascii_lowercase();
    // A cross-cluster name (`remote:logs-…`) reads the same data elsewhere.
    let pattern = pattern.rsplit(':').next().unwrap_or(&pattern);
    let source = |product: &str, service: Option<&str>| {
        Some(LogSource {
            product: Some(product.to_owned()),
            service: service.map(str::to_owned),
            category: None,
            complete: false,
        })
    };
    if let Some((_, service)) = WINDOWS_SYSTEM
        .iter()
        .find(|(prefix, _)| pattern.starts_with(prefix))
    {
        return source("windows", Some(service));
    }
    if let Some((_, service)) = LINUX_SYSTEM
        .iter()
        .find(|(prefix, _)| pattern.starts_with(prefix))
    {
        return source("linux", Some(service));
    }
    if pattern.starts_with("winlogbeat-") || pattern.starts_with("logs-windows.") {
        return source("windows", None);
    }
    if pattern.starts_with("logs-auditd") {
        return source("linux", Some("auditd"));
    }
    if pattern.starts_with("logs-endpoint.") {
        return source("elastic_defend", None);
    }
    let integration = pattern
        .strip_prefix("logs-")?
        .split(['.', '-', '*'])
        .next()?;
    PRODUCTS
        .iter()
        .find(|(name, _)| *name == integration)
        .and_then(|(_, product)| source(product, None))
}

/// Whether every one of `patterns` names Kibana's alert indices, so the rule reads the alerts
/// of other rules rather than events.
pub(crate) fn reads_alerts<'a>(patterns: impl IntoIterator<Item = &'a str>) -> bool {
    const ALERTS: [&str; 4] = [
        ".alerts-",
        ".internal.alerts-",
        ".siem-signals-",
        ".preview.alerts-",
    ];
    let mut any = false;
    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.starts_with('-') {
            continue;
        }
        if !ALERTS.iter().any(|a| pattern.starts_with(a)) {
            return false;
        }
        any = true;
    }
    any
}

/// The index patterns of an ES|QL query's `FROM`, up to the first pipe.
pub(crate) fn esql_from(query: &str) -> Vec<String> {
    let mut words = query.split_whitespace();
    let Some(first) = words.next() else {
        return Vec::new();
    };
    if !first.eq_ignore_ascii_case("from") {
        return Vec::new();
    }
    let mut patterns = Vec::new();
    for word in words {
        if word.starts_with('|') || word.eq_ignore_ascii_case("metadata") {
            break;
        }
        let ends = word.contains('|');
        patterns.extend(
            word.split('|')
                .next()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_owned),
        );
        if ends {
            break;
        }
    }
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    fn products(patterns: &[&str]) -> Vec<(Option<String>, Option<String>)> {
        scopes(patterns.iter().copied())
            .into_iter()
            .map(|s| (s.product, s.service))
            .collect()
    }

    fn named(product: &str, service: Option<&str>) -> (Option<String>, Option<String>) {
        (Some(product.to_owned()), service.map(str::to_owned))
    }

    #[test]
    fn windows_and_linux_system_logs_by_their_dataset() {
        assert_eq!(
            products(&[
                "logs-system.security*",
                "winlogbeat-*",
                "logs-windows.forwarded*"
            ]),
            [named("windows", None), named("windows", Some("security"))]
        );
        assert_eq!(
            products(&["logs-system.auth-*"]),
            [named("linux", Some("auth"))]
        );
    }

    #[test]
    fn cloud_integrations_are_their_products() {
        assert_eq!(products(&["logs-aws.cloudtrail-*"]), [named("aws", None)]);
        assert_eq!(products(&["logs-o365.audit-*"]), [named("m365", None)]);
        assert_eq!(
            products(&["logs-endpoint.events.process-*"]),
            [named("elastic_defend", None)]
        );
    }

    #[test]
    fn c3_a_pattern_that_may_hold_anything_reads_every_source() {
        for patterns in [
            &["logs-*"][..],
            &["filebeat-*", "logs-aws.cloudtrail-*"],
            &["logs-system.*"],
            &["logs-crowdstrike.fdr*"],
            &["logs-m365_defender.event-*"],
            &[],
            &["*"],
        ] {
            assert_eq!(
                scopes(patterns.iter().copied()),
                [LogSource::default()],
                "{patterns:?}"
            );
        }
    }

    #[test]
    fn exclusions_and_remote_clusters() {
        assert_eq!(
            products(&["-logs-endpoint.alerts-*", "remote:logs-gcp.audit-*"]),
            [named("gcp", None)]
        );
    }

    #[test]
    fn esql_reads_its_from_clause() {
        assert_eq!(
            esql_from("from logs-aws.cloudtrail-*, logs-gcp* metadata _id | where x == 1"),
            ["logs-aws.cloudtrail-*", "logs-gcp*"]
        );
        assert_eq!(esql_from("FROM logs-*|WHERE a"), ["logs-*"]);
        assert_eq!(esql_from("row a = 1"), Vec::<String>::new());
    }
}

//! Microsoft Sentinel analytics rules (YAML with a KQL `query`) as requirements (ADR 0015).
//!
//! Sentinel stores Windows events in `SecurityEvent` (Security channel) and `WindowsEvent`
//! (other channels), the shapes Sluice sends (ADR 0014). A rule's query is read for the tables it
//! references, every identifier it names (a superset of the columns it reads) and, per table
//! reference, the `EventID`s (and `EventSourceName`, `Channel`, `Provider`) its first `where`
//! clauses keep. ASIM parsers and helper functions whose source is among the files are resolved
//! (`functions`). Anything not understood widens: an unknown parser or function, `search` or
//! `union *` means the rule may read any column of any Windows table, `pack_all()` any column,
//! and any other condition keeps every row.

mod extract;
mod functions;
mod lexer;
#[cfg(test)]
mod tests;

use serde::Deserialize;

use self::functions::Functions;
use serde_yaml_ng::Value;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::Predicate;
use sluice_core::rules::{RequiredFields, RuleRequirements};

/// A loaded set of Sentinel analytics rules.
#[derive(Debug, Clone, Default)]
pub struct SentinelRules {
    requirements: Vec<RuleRequirements>,
    queries: Vec<(RuleId, String)>,
    problems: Vec<String>,
}

impl SentinelRules {
    /// Reads rule files, each as `(name, YAML text)`; a file may hold several YAML documents
    /// (`---`), as some in Azure/Azure-Sentinel do. A document that cannot be read becomes a
    /// rule that may read anything anywhere (fail closed) and is reported in
    /// [`SentinelRules::problems`] with its file name. Rules without a query (Fusion, incident
    /// creation) read no table and are left out.
    ///
    /// ASIM parser files (`ParserName`, `ParserQuery`) among them are read as functions: a rule
    /// that uses a parser reads what the parser reads. Without them, such a rule may read any
    /// column of any Windows table.
    #[must_use]
    pub fn parse<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut rules = Self::default();
        let mut functions = Functions::default();
        let mut documents = Vec::new();
        for (name, text) in files {
            // Many files in Azure/Azure-Sentinel start with a UTF-8 byte order mark, which the
            // multi-document reader does not skip.
            let text = text.strip_prefix('\u{feff}').unwrap_or(text);
            for (index, document) in serde_yaml_ng::Deserializer::from_str(text).enumerate() {
                let place = format!("{name}#{}", index + 1);
                match Value::deserialize(document) {
                    Ok(doc) => {
                        if !functions.add(&doc) {
                            documents.push((place, doc));
                        }
                    }
                    Err(error) => {
                        rules.problems.push(format!(
                            "Sentinel rule {place} could not be read ({error}); it is treated \
                             as a rule that may read anything"
                        ));
                        rules
                            .requirements
                            .push(RuleRequirements::opaque(RuleId::new(format!(
                                "sentinel:unreadable:{place}"
                            ))));
                        // After a syntax error the document iterator yields the same error
                        // forever; the rest of the file cannot be read either.
                        break;
                    }
                }
            }
        }
        for (place, doc) in &documents {
            rules.add(place, doc, &functions);
        }
        rules
    }

    fn add(&mut self, place: &str, doc: &Value, functions: &Functions) {
        let Some(query) = doc.get("query").and_then(Value::as_str) else {
            return;
        };
        let id = doc
            .get("id")
            .and_then(Value::as_str)
            .map_or_else(|| format!("unnamed:{place}"), str::to_owned);
        let reads = functions.reads(query);
        let modeled = !reads.tables.is_empty() || reads.any_table;
        let requirement = requirement(&id, reads, &mut self.problems);
        if modeled {
            self.queries
                .push((requirement.rule.clone(), query.to_owned()));
        }
        self.requirements.push(requirement);
    }

    /// What each rule needs from the data.
    #[must_use]
    pub fn requirements(&self) -> &[RuleRequirements] {
        &self.requirements
    }

    /// The query of every rule that may read a table Sluice shapes records for
    /// (`SecurityEvent`, `WindowsEvent`, `Syslog`, `CommonSecurityLog`,
    /// `ASimNetworkSessionLogs`, `ASimDnsActivityLogs`), for running the rules themselves on full and
    /// on forwarded records (the emulator proof).
    #[must_use]
    pub fn queries(&self) -> &[(RuleId, String)] {
        &self.queries
    }

    /// Rule parts that could not be understood; the affected rules were widened.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

fn requirement(id: &str, reads: extract::Reads, problems: &mut Vec<String>) -> RuleRequirements {
    let rule = RuleId::new(format!("sentinel:{id}"));
    if let Some(why) = &reads.any_field {
        problems.push(format!("{rule}: {why}; treated as reading every column"));
    }
    let modeled = !reads.tables.is_empty() || reads.any_table;
    RuleRequirements {
        logsource: logsource(&reads.tables, reads.any_table),
        fields: if reads.any_field.is_some() {
            RequiredFields::Unknown
        } else {
            RequiredFields::Known(reads.fields)
        },
        matches_raw_text: reads.any_field.is_some(),
        stateful: reads.stateful,
        text_lines_only: false,
        prefilter: if reads.any_table {
            // A parser or function may read any row of any table Sluice shapes for: bounded to
            // records of those shapes.
            Predicate::any([
                extract::present("EventID"),
                extract::present("Channel"),
                extract::present("SyslogMessage"),
                extract::present("DeviceVendor"),
                extract::present("EventSchemaVersion"),
                extract::present("DnsQuery"),
            ])
        } else if modeled {
            reads.prefilter
        } else {
            Predicate::Always
        },
        rule,
    }
}

/// The log source of a rule. `SecurityEvent` alone is Windows Security and `WindowsEvent` is
/// Windows. `Syslog` rows come from any product, and a parser or function may read any table, so
/// those rules apply to every product; their pre-filter bounds them to records of the table's
/// shape. Queries on other tables only get a product no source has.
fn logsource(tables: &std::collections::BTreeSet<String>, any_table: bool) -> LogSource {
    let windows_only = !any_table
        && !tables.is_empty()
        && tables.iter().all(|t| extract::table_marker(t).is_none());
    let only_security = windows_only && tables.len() == 1 && tables.contains("SecurityEvent");
    let product = if tables.is_empty() && !any_table {
        Some("sentinel-other-tables".to_owned())
    } else if windows_only {
        Some("windows".to_owned())
    } else {
        None
    };
    LogSource {
        product,
        service: only_security.then(|| "security".to_owned()),
        category: None,
        complete: false,
    }
}

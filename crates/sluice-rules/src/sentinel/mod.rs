//! Microsoft Sentinel analytics rules (YAML with a KQL `query`) as requirements (ADR 0015).
//!
//! Sentinel stores Windows events in `SecurityEvent` (Security channel) and `WindowsEvent`
//! (other channels), the shapes Sluice sends (ADR 0014). A rule's query is read for the tables it
//! references, every identifier it names (a superset of the columns it reads) and, per table
//! reference, the `EventID`s (and `EventSourceName`, `Channel`, `Provider`) its first `where`
//! clauses keep. ASIM parsers and helper functions whose source is among the files are resolved
//! (`functions`). Anything not understood widens: an unknown parser or function, `search`,
//! `find`, `union *` or `table()` means the rule may read any column of any row of any table,
//! custom tables included, which any source may fill; `pack_all()` any column, and any other
//! condition keeps every row.

mod extract;
mod functions;
mod lexer;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use self::functions::Functions;
use serde_yaml_ng::Value;
use sluice_core::field::FieldPath;
use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::predicate::Predicate;
use sluice_core::rules::{RequiredFields, RuleRequirements};

/// A loaded set of Sentinel analytics rules.
#[derive(Debug, Clone, Default)]
pub struct SentinelRules {
    requirements: Vec<RuleRequirements>,
    queries: Vec<(RuleId, String)>,
    names: BTreeMap<RuleId, String>,
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
        // Custom tables count too: the emulator holds the ones sources are sent to.
        let modeled =
            !reads.tables.is_empty() || reads.any_table || !reads.custom_tables.is_empty();
        let requirement = requirement(&id, reads, &mut self.problems);
        if let Some(name) = ["name", "displayName"]
            .iter()
            .find_map(|key| doc.get(*key).and_then(Value::as_str))
        {
            self.names.insert(requirement.rule.clone(), name.to_owned());
        }
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
    /// `ASimNetworkSessionLogs`, `ASimDnsActivityLogs`, `ASimWebSessionLogs`), for running the rules themselves on full and
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

    /// Each rule's name as the SIEM shows it, where the rule file gives one.
    #[must_use]
    pub fn names(&self) -> &BTreeMap<RuleId, String> {
        &self.names
    }
}

fn requirement(id: &str, reads: extract::Reads, problems: &mut Vec<String>) -> RuleRequirements {
    let rule = RuleId::new(format!("sentinel:{id}"));
    if let Some(why) = &reads.any_field {
        problems.push(format!(
            "{rule}: {why}; treated as reading every column of every record"
        ));
    }
    RuleRequirements {
        logsource: logsource(
            &reads.tables,
            reads.any_table || !reads.custom_tables.is_empty(),
        ),
        // The columns of the tables Sluice shapes records for, which no other schema names.
        field_names: None,
        fields: if reads.any_field.is_some() {
            RequiredFields::Unknown
        } else if reads.custom_tables.is_empty() {
            RequiredFields::Known(reads.fields)
        } else {
            RequiredFields::Known(reads.fields.iter().flat_map(renamed_from).collect())
        },
        matches_raw_text: reads.any_field.is_some(),
        stateful: reads.stateful,
        text_lines_only: false,
        // Only references to named shaped tables bound the rows. A rule that may read any table
        // may read a custom one, whose rows any record can be (fail closed); so may one that
        // names a custom table, whose reference adds `true`.
        prefilter: if !reads.tables.is_empty() && !reads.any_table {
            reads.prefilter
        } else {
            Predicate::Always
        },
        rule,
    }
}

/// `column` and every record field a custom table's rule may have renamed into it: a data
/// collection rule from `sluice connect sentinel --sample` makes an invalid name valid by
/// writing `_` for what Log Analytics refuses, putting `F` in front of a name that does not
/// start with a letter, and numbering a name taken twice (`user-agent` → `user_agent`,
/// `@timestamp` → `F_timestamp`, `ProcessId` → `ProcessId2`). A rule reading the column reads
/// the field, so each may be protected; extra names only cost savings.
fn renamed_from(column: &FieldPath) -> BTreeSet<FieldPath> {
    let name = column.as_str();
    let mut stems = vec![name.to_owned()];
    let unnumbered = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if unnumbered.len() < name.len() && !unnumbered.is_empty() {
        stems.push(unnumbered.to_owned());
    }
    for stem in stems.clone() {
        if let Some(rest) = stem.strip_prefix('F')
            && rest.starts_with(|c: char| c == '_' || c.is_ascii_digit())
        {
            stems.push(rest.to_owned());
        }
    }
    let mut out = BTreeSet::new();
    for stem in &stems {
        out.insert(FieldPath::new(stem.as_str()));
        if stem.contains('_') {
            for replacement in ['-', '.', ' ', '@', ':', '/'] {
                out.insert(FieldPath::new(stem.replace('_', &replacement.to_string())));
            }
        }
    }
    out
}

/// The log source of a rule. `SecurityEvent` alone is Windows Security and `WindowsEvent` is
/// Windows. `Syslog` rows come from any product, so those rules apply to every product and
/// their pre-filter bounds them to records of the table's shape; a rule that may read any table
/// or a custom one applies to every product and every record. Queries on other tables only get
/// a product no source has.
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

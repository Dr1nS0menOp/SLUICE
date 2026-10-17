//! Splunk saved searches (alerts, Enterprise Security correlation searches) as requirements
//! (ADR 0026).
//!
//! Searches come from `savedsearches.conf` or the REST API's `saved/searches` answer, macros
//! from `macros.conf` or `admin/macros`. Only searches that run on their own count: scheduled
//! ones and correlation searches, unless disabled. Their macros are expanded, then the search is
//! read by [`spl`]. A search names its fields as Splunk extracts them at search time
//! ([`Schema::Splunk`]), so the guardrails only compare them with records declared to carry
//! those names.

mod conf;
mod props;
mod spl;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use sluice_core::ids::RuleId;
use sluice_core::logsource::LogSource;
use sluice_core::rules::{RequiredFields, RuleRequirements};
use sluice_core::schema::Schema;

use self::conf::{Stanzas, truthy};
use self::props::Derived;

/// How deep macros may call macros before the search counts as unreadable.
const MAX_MACRO_DEPTH: usize = 32;

/// A loaded set of Splunk saved searches.
#[derive(Debug, Clone, Default)]
pub struct SplunkRules {
    requirements: Vec<RuleRequirements>,
    names: BTreeMap<RuleId, String>,
    problems: Vec<String>,
}

impl SplunkRules {
    /// Reads configuration files, each as `(name, text)`: `.conf` files or REST JSON answers.
    /// A stanza with a `definition` is a macro, one with a `search` a saved search; later files
    /// override settings of earlier ones, as `local` overrides `default`. A search that cannot be
    /// read becomes a rule that may read any field of any event (fail closed) and is reported in
    /// [`SplunkRules::problems`].
    ///
    /// Files whose name says `props` or `transforms` (`props.conf`, the REST API's
    /// `conf-props`) are the fields Splunk derives at search time: a search's test
    /// on an alias becomes a test on what it copies, one on a computed or extracted field
    /// `true`, and the search reads what they are made from.
    #[must_use]
    pub fn parse<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut stanzas = Stanzas::new();
        let mut props = Stanzas::new();
        let mut transforms = Stanzas::new();
        let mut rules = Self::default();
        for (name, text) in files {
            let file = std::path::Path::new(name)
                .file_name()
                .map(|f| f.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let into = if file.contains("props") {
                &mut props
            } else if file.contains("transforms") {
                &mut transforms
            } else {
                &mut stanzas
            };
            let text = text.strip_prefix('\u{feff}').unwrap_or(text);
            let json = std::path::Path::new(name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"));
            let read = if json {
                conf::rest(text)
            } else {
                Some(conf::conf(text))
            };
            let Some(read) = read else {
                rules.problems.push(format!(
                    "{name} is no Splunk REST answer (`entry`); it was left out"
                ));
                continue;
            };
            for (stanza, settings) in read {
                into.entry(stanza).or_default().extend(settings);
            }
        }
        let derived = Derived::new(&props, &transforms);
        if let Some(why) = &derived.dynamic {
            rules.problems.push(format!(
                "Splunk derives {why}: any field may be derived, so every search's field tests \
                 match every event"
            ));
        }
        let macros = Macros::new(&stanzas);
        let defaults = stanzas.get("default").cloned().unwrap_or_default();
        for (name, settings) in &stanzas {
            if name == "default" {
                continue;
            }
            let setting = |key: &str| settings.get(key).or_else(|| defaults.get(key));
            let Some(search) = settings.get("search") else {
                continue;
            };
            let runs = truthy(setting("enableSched"))
                || truthy(setting("is_scheduled"))
                || truthy(setting("action.correlationsearch.enabled"));
            if runs && !truthy(setting("disabled")) {
                rules.add(name, search, &macros, &derived);
            }
        }
        rules
    }

    fn add(&mut self, name: &str, search: &str, macros: &Macros<'_>, derived: &Derived) {
        let rule = RuleId::new(format!("splunk:{name}"));
        let reads = match macros.expand(&without_comments(search), 0) {
            Ok(search) => derived.apply(spl::read(&search)),
            Err(why) => {
                // A generating search may read anything anyway; its macros are not the reason.
                let why = if spl::generating(search) {
                    "a generating command (`tstats`, a data model or a lookup)".to_owned()
                } else {
                    why
                };
                self.problems.push(format!(
                    "{rule}: {why}; treated as reading every field of every event"
                ));
                self.names.insert(rule.clone(), name.to_owned());
                self.requirements.push(RuleRequirements::opaque(rule));
                return;
            }
        };
        if let Some(why) = reads.any_field {
            self.problems
                .push(format!("{rule}: {why}; treated as reading every field"));
        }
        self.names.insert(rule.clone(), name.to_owned());
        self.requirements.push(RuleRequirements {
            rule,
            logsource: LogSource::default(),
            field_names: Some(Schema::Splunk),
            fields: if reads.any_field.is_some() {
                RequiredFields::Unknown
            } else {
                RequiredFields::Known(reads.fields)
            },
            matches_raw_text: reads.raw || reads.any_field.is_some(),
            stateful: reads.stateful,
            text_lines_only: false,
            prefilter: reads.prefilter,
        });
    }

    /// What each search needs from the data.
    #[must_use]
    pub fn requirements(&self) -> &[RuleRequirements] {
        &self.requirements
    }

    /// Search parts that could not be understood; the affected searches were widened.
    #[must_use]
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    /// Each search's name as Splunk shows it.
    #[must_use]
    pub fn names(&self) -> &BTreeMap<RuleId, String> {
        &self.names
    }
}

/// Search macros by the name a call uses: `name`, or `name(n)` for one with `n` arguments.
struct Macros<'a> {
    by_name: BTreeMap<&'a str, &'a BTreeMap<String, String>>,
}

impl<'a> Macros<'a> {
    fn new(stanzas: &'a Stanzas) -> Self {
        Self {
            by_name: stanzas
                .iter()
                .filter(|(_, settings)| settings.contains_key("definition"))
                .map(|(name, settings)| (name.as_str(), settings))
                .collect(),
        }
    }

    /// `search` with every macro call replaced by its definition, its `$argument$`s filled in.
    fn expand(&self, search: &str, depth: usize) -> Result<String, String> {
        if !search.contains('`') {
            return Ok(search.to_owned());
        }
        if depth > MAX_MACRO_DEPTH {
            return Err(format!("macros nest deeper than {MAX_MACRO_DEPTH}"));
        }
        let mut out = String::new();
        let mut parts = search.split('`');
        out.push_str(parts.next().unwrap_or_default());
        while let Some(call) = parts.next() {
            let Some(after) = parts.next() else {
                return Err("an unclosed macro call (`` ` ``)".to_owned());
            };
            out.push_str(&self.call(call)?);
            out.push_str(after);
        }
        self.expand(&out, depth + 1)
    }

    fn call(&self, call: &str) -> Result<String, String> {
        let (name, args) = match call.split_once('(') {
            Some((name, rest)) => {
                let inner = rest
                    .trim_end()
                    .strip_suffix(')')
                    .ok_or_else(|| format!("the macro call `{call}` has no closing parenthesis"))?;
                (name.trim(), arguments(inner))
            }
            None => (call.trim(), Vec::new()),
        };
        let key = if args.is_empty() {
            name.to_owned()
        } else {
            format!("{name}({})", args.len())
        };
        let settings = self
            .by_name
            .get(key.as_str())
            .ok_or_else(|| format!("the macro `{key}`, which is not among the files"))?;
        if settings.contains_key(conf::AMBIGUOUS) {
            return Err(format!(
                "the macro `{key}`, which several apps define differently"
            ));
        }
        if truthy(settings.get("iseval")) {
            return Err(format!(
                "the macro `{key}`, whose definition is an expression"
            ));
        }
        let mut definition = settings.get("definition").cloned().unwrap_or_default();
        let names = settings.get("args").map_or_else(Vec::new, |a| {
            a.split(',').map(|n| n.trim().to_owned()).collect()
        });
        if names.len() != args.len() {
            return Err(format!(
                "the macro `{key}` declares {} arguments",
                names.len()
            ));
        }
        for (name, value) in names.iter().zip(&args) {
            definition = definition.replace(&format!("${name}$"), value);
        }
        // Splunk replaces the call's text, so neither is a space added.
        Ok(definition)
    }
}

/// `search` without its comments (```` ```text``` ````), which Splunk drops before it expands
/// macros. An unclosed comment is left in, so the search fails closed as an unclosed call.
fn without_comments(search: &str) -> String {
    let mut out = String::new();
    let mut rest = search;
    while let Some((before, after)) = rest.split_once("```") {
        let Some((_, after_comment)) = after.split_once("```") else {
            break;
        };
        out.push_str(before);
        // A comment separates what is around it.
        out.push(' ');
        rest = after_comment;
    }
    out.push_str(rest);
    out
}

/// The arguments of a macro call: split at commas outside quotes and parentheses.
fn arguments(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quoted = false;
    for c in inner.chars() {
        match c {
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth = depth.saturating_sub(1),
            ',' if !quoted && depth == 0 => {
                out.push(std::mem::take(&mut current).trim().to_owned());
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    if !current.trim().is_empty() || !out.is_empty() {
        out.push(current.trim().to_owned());
    }
    out
}

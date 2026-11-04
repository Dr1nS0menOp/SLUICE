//! The fields Splunk derives at search time (`props.conf`, `transforms.conf`): what a search
//! names may not be in the record at all.
//!
//! - `FIELDALIAS-x = orig AS new` makes `new` a copy of `orig`.
//! - `EVAL-new = expr` computes `new` from the fields `expr` names.
//! - `LOOKUP-x = table in [AS field] OUTPUT out [AS field]` adds the outputs from the inputs.
//! - `EXTRACT-x = regex [in field]` and `REPORT-x = transform` (and index-time `TRANSFORMS-x`)
//!   extract named groups or `FORMAT` names from `_raw` or the transform's `SOURCE_KEY`.
//!
//! Stanzas are per sourcetype, source or host, which a record does not carry, so every
//! derivation counts for every record. A field whose name the data decides (`$1::$2`,
//! `_KEY_1`, a lookup without `OUTPUT`) may be any field.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, Predicate};

use super::conf::Stanzas;
use super::spl::{self, Reads};

/// How far derivations may chain (an alias of an extracted field, …).
const MAX_DEPTH: usize = 16;

/// The raw event, which extractions read.
const RAW: &str = "_raw";

/// Every field Splunk derives, and from what.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Derived {
    /// A field copied from others (per sourcetype, one each).
    aliases: BTreeMap<String, BTreeSet<String>>,
    /// A field computed, looked up or extracted, with the fields it is made from.
    made: BTreeMap<String, BTreeSet<String>>,
    /// Why any field may be derived, if one may: a name the data decides.
    pub(crate) dynamic: Option<String>,
}

impl Derived {
    /// Reads `props` and the `transforms` its `REPORT` and `TRANSFORMS` settings name.
    pub(crate) fn new(props: &Stanzas, transforms: &Stanzas) -> Self {
        let mut derived = Self::default();
        for (stanza, settings) in props {
            for (key, value) in settings {
                let Some((class, name)) = key.split_once('-') else {
                    continue;
                };
                match class.trim().to_ascii_uppercase().as_str() {
                    "FIELDALIAS" => derived.alias(value),
                    "EVAL" => derived.make(name.trim(), spl::names(value, false)),
                    "LOOKUP" => derived.lookup(stanza, value),
                    "EXTRACT" => derived.extract(stanza, value),
                    "REPORT" | "TRANSFORMS" => {
                        for transform in value.split(',').map(str::trim) {
                            derived.transform(stanza, transform, transforms.get(transform));
                        }
                    }
                    _ => {}
                }
            }
        }
        derived
    }

    fn alias(&mut self, value: &str) {
        let words = words(value);
        for triple in words.windows(3) {
            if ["as", "asnew"].contains(&triple[1].to_ascii_lowercase().as_str()) {
                self.aliases
                    .entry(triple[2].clone())
                    .or_default()
                    .insert(triple[0].clone());
            }
        }
    }

    fn make(&mut self, field: &str, from: impl IntoIterator<Item = FieldPath>) {
        self.made
            .entry(field.to_owned())
            .or_default()
            .extend(from.into_iter().map(|f| f.as_str().to_owned()));
    }

    fn lookup(&mut self, stanza: &str, value: &str) {
        let words = words(value);
        let output = words
            .iter()
            .position(|w| ["output", "outputnew"].contains(&w.to_ascii_lowercase().as_str()));
        let Some(output) = output else {
            self.dynamic = Some(format!(
                "a lookup of [{stanza}] without OUTPUT, which adds every column of its table"
            ));
            return;
        };
        let event_fields = |words: &[String]| -> Vec<String> {
            let mut out = Vec::new();
            let mut i = 0;
            while let Some(word) = words.get(i) {
                if words
                    .get(i + 1)
                    .is_some_and(|w| w.eq_ignore_ascii_case("as"))
                {
                    out.extend(words.get(i + 2).cloned());
                    i += 3;
                } else {
                    out.push(word.clone());
                    i += 1;
                }
            }
            out
        };
        // The first word is the lookup table.
        let inputs = event_fields(words.get(1..output).unwrap_or_default());
        for out in event_fields(words.get(output + 1..).unwrap_or_default()) {
            self.make(&out, inputs.iter().map(|f| FieldPath::new(f.as_str())));
        }
    }

    fn extract(&mut self, stanza: &str, value: &str) {
        // `regex in field` names the source; ` in ` may also be part of the regex, so the
        // extraction counts as reading both.
        match value.rsplit_once(" in ") {
            Some((_, field)) if !field.trim().contains(char::is_whitespace) => {
                self.groups(stanza, value, &[field.trim(), RAW]);
            }
            _ => self.groups(stanza, value, &[RAW]),
        }
    }

    fn transform(&mut self, stanza: &str, name: &str, settings: Option<&BTreeMap<String, String>>) {
        let Some(settings) = settings else {
            self.dynamic = Some(format!(
                "the transform `{name}` of [{stanza}], which is not among the files"
            ));
            return;
        };
        let source = settings
            .get("SOURCE_KEY")
            .map_or(RAW, |s| s.trim().trim_start_matches("field:"));
        let source = if source.starts_with('_') && source != RAW {
            // `_meta`, `MetaData:…`: index-time keys beside the event.
            RAW
        } else {
            source
        };
        if let Some(fields) = settings.get("FIELDS") {
            for field in fields.split(',') {
                let field = field.trim().trim_matches('"');
                self.make(field, [FieldPath::new(source)]);
            }
        } else if let Some(format) = settings.get("FORMAT") {
            for pair in format.split_whitespace() {
                match pair.split_once("::") {
                    Some((name, _)) if !name.contains('$') => {
                        self.make(name, [FieldPath::new(source)]);
                    }
                    _ => {
                        self.dynamic = Some(format!(
                            "the transform `{name}` of [{stanza}] names fields by the data \
                             (`{pair}`)"
                        ));
                    }
                }
            }
        } else if let Some(regex) = settings.get("REGEX") {
            self.groups(stanza, regex, &[source]);
        }
    }

    /// The named groups of `regex` as fields made from `sources`.
    fn groups(&mut self, stanza: &str, regex: &str, sources: &[&str]) {
        for part in regex.split("(?").skip(1) {
            let part = part.strip_prefix('P').unwrap_or(part);
            let Some(name) = part
                .strip_prefix('<')
                .and_then(|p| p.split_once('>'))
                .map(|(n, _)| n)
            else {
                continue;
            };
            // `(?<=…)` and `(?<!…)` are look-behinds, not names.
            if name.is_empty() || name.starts_with(['=', '!']) {
                continue;
            }
            if name.starts_with("_KEY_") || name.starts_with("_VAL_") {
                self.dynamic = Some(format!(
                    "an extraction of [{stanza}] names fields by the data (`{name}`)"
                ));
                continue;
            }
            self.make(name, sources.iter().map(|s| FieldPath::new(*s)));
        }
    }

    /// What a search derived from these reads: the fields it names and what they come from,
    /// and a pre-filter whose tests on derived fields are tests on their origins, or `true`.
    pub(crate) fn apply(&self, mut reads: Reads) -> Reads {
        if reads.any_field.is_some() {
            return reads;
        }
        let named: Vec<String> = reads.fields.iter().map(|f| f.as_str().to_owned()).collect();
        for field in &named {
            for origin in self.origins(field, 0).unwrap_or_default() {
                reads.fields.insert(FieldPath::new(origin.as_str()));
            }
            self.inputs(field, 0, &mut reads.fields);
        }
        reads.raw |= reads.fields.iter().any(|f| f.as_str() == RAW);
        reads.fields.retain(|f| f.as_str() != RAW);
        reads.prefilter = self.rewrite(&reads.prefilter);
        if self.dynamic.is_some() {
            reads.raw = true;
        }
        reads
    }

    /// The fields `field` is an alias of, through any chain of aliases, or `None` when one of
    /// them is made (or the chain is too long).
    fn origins(&self, field: &str, depth: usize) -> Option<BTreeSet<String>> {
        if depth > MAX_DEPTH || self.made.contains_key(field) || self.dynamic.is_some() {
            return None;
        }
        let mut out = BTreeSet::new();
        for origin in self.aliases.get(field).into_iter().flatten() {
            out.insert(origin.clone());
            out.extend(self.origins(origin, depth + 1)?);
        }
        Some(out)
    }

    /// Adds every field `field` is made or copied from, transitively.
    fn inputs(&self, field: &str, depth: usize, into: &mut BTreeSet<FieldPath>) {
        if depth > MAX_DEPTH {
            into.insert(FieldPath::new(RAW));
            return;
        }
        let sources = self
            .made
            .get(field)
            .into_iter()
            .chain(self.aliases.get(field))
            .flatten();
        for source in sources {
            if into.insert(FieldPath::new(source.as_str())) {
                self.inputs(source, depth + 1, into);
            }
        }
    }

    fn rewrite(&self, predicate: &Predicate) -> Predicate {
        match predicate {
            Predicate::Any(parts) => Predicate::any(parts.iter().map(|p| self.rewrite(p))),
            Predicate::All(parts) => Predicate::all(parts.iter().map(|p| self.rewrite(p))),
            Predicate::Field(test) => self.test(test),
            other => other.clone(),
        }
    }

    /// A test on a field as it is in the record: on the field itself or what it is an alias
    /// of; `true` when it may be made.
    fn test(&self, test: &FieldTest) -> Predicate {
        let Some(origins) = self.origins(test.field.as_str(), 0) else {
            return Predicate::Always;
        };
        Predicate::any(
            std::iter::once(test.field.as_str().to_owned())
                .chain(origins)
                .map(|field| {
                    Predicate::Field(FieldTest {
                        field: FieldPath::new(field.as_str()),
                        ..test.clone()
                    })
                }),
        )
    }
}

/// The words of a setting, a quoted one as one word without its quotes.
fn words(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in value.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            ',' if !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

#[cfg(test)]
mod tests;

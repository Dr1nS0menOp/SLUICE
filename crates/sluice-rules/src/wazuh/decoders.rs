//! What Wazuh decoders say about the events a rule can see.
//!
//! A rule with `<decoded_as>sshd</decoded_as>` only sees events the `sshd` decoder decoded, and
//! that decoder only takes lines whose syslog program name matches `^sshd`. Such a line contains
//! the text `sshd`, so a keyword test for it is a superset of the rule's events. A `prematch`
//! that starts with a literal (`^ossec: `) bounds the same way. A rule's `<category>` is the
//! decoder `<type>`, so it is bounded by every decoder of that type. Decoders that select lines
//! any other way (regexes, plugins such as JSON) say nothing usable: `Always`.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::predicate::{KeywordTest, Predicate};

use super::xml::{self, RawElement};

/// Decoder name → literals every line it decodes contains (`None`: unknown, so any line).
#[derive(Debug, Clone, Default)]
pub(crate) struct Decoders {
    programs: BTreeMap<String, Option<Vec<String>>>,
    /// Decoder `<type>` → the decoders of that type.
    types: BTreeMap<String, Vec<String>>,
    /// Every name any decoder lists in `<fts>`: what an `<if_fts/>` rule may compare.
    fts: BTreeSet<String>,
}

/// What one `<decoder>` definition selects lines by.
enum Selects {
    /// Its own `program_name` or literal `prematch`: these literals, or `None` if not literal.
    Programs(Option<Vec<String>>),
    /// Nothing of its own: the lines its parent decoder selected.
    Parent(String),
    /// Something else (`prematch`, a plugin): unknown.
    Unknown,
}

impl Decoders {
    /// Parses decoder files; files that cannot be read are reported and add nothing (a rule
    /// whose decoder is unknown keeps an unbounded scope).
    pub(crate) fn parse<'a>(
        files: impl IntoIterator<Item = &'a str>,
        problems: &mut Vec<String>,
    ) -> Self {
        let mut definitions: BTreeMap<String, Vec<Selects>> = BTreeMap::new();
        let mut types: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut fts = BTreeSet::new();
        for (index, file) in files.into_iter().enumerate() {
            let elements = match xml::decoders(file) {
                Ok(elements) => elements,
                Err(error) => {
                    problems.push(format!(
                        "Wazuh decoder file {index} could not be read ({error})"
                    ));
                    continue;
                }
            };
            for element in elements {
                let Some(name) = element.attributes.get("name").cloned() else {
                    continue;
                };
                if let Some(kind) = child_text(&element, "type") {
                    types.entry(kind.to_owned()).or_default().push(name.clone());
                }
                if let Some(list) = child_text(&element, "fts") {
                    fts.extend(
                        list.split(',')
                            .map(str::trim)
                            .filter(|f| !f.is_empty())
                            .map(str::to_owned),
                    );
                }
                let program = child_text(&element, "program_name").and_then(programs);
                let prematch = element
                    .children
                    .iter()
                    .find(|c| c.tag == "prematch")
                    .filter(|c| c.attributes.get("type").is_none_or(|t| t == "osregex"))
                    .and_then(|c| prematch_literals(c.text.trim()));
                let selects = match (program.or(prematch), child_text(&element, "parent")) {
                    (Some(literals), _) => Selects::Programs(Some(literals)),
                    (None, Some(parent)) => Selects::Parent(parent.to_owned()),
                    (None, None) => Selects::Unknown,
                };
                definitions.entry(name).or_default().push(selects);
            }
        }
        let programs = definitions
            .keys()
            .map(|name| (name.clone(), resolve(name, &definitions, 0)))
            .collect();
        Self {
            programs,
            types,
            fts,
        }
    }

    /// The names an `<if_fts/>` rule may compare: the union of every decoder's `<fts>` list.
    /// `None` when no decoder declares one, because Wazuh's built-in default is then unknown here.
    pub(crate) fn fts_fields(&self) -> Option<&BTreeSet<String>> {
        (!self.fts.is_empty()).then_some(&self.fts)
    }

    /// A superset test for events whose decoder has `<type>` `kind` (a rule's `<category>`).
    pub(crate) fn category_condition(&self, kind: &str) -> Predicate {
        match self.types.get(kind.trim()) {
            Some(names) if !names.is_empty() => {
                Predicate::any(names.iter().map(|name| self.condition(name)))
            }
            _ => Predicate::Always,
        }
    }

    /// A superset test for events decoded by `decoder`.
    pub(crate) fn condition(&self, decoder: &str) -> Predicate {
        match self.programs.get(decoder.trim()) {
            Some(Some(programs)) if !programs.is_empty() => Predicate::Keywords(KeywordTest {
                values: programs.clone(),
                case_sensitive: false,
            }),
            _ => Predicate::Always,
        }
    }
}

/// The program names a decoder accepts over all its definitions; `None` if any is unknown.
fn resolve(
    name: &str,
    definitions: &BTreeMap<String, Vec<Selects>>,
    depth: usize,
) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for selects in definitions.get(name)? {
        match selects {
            Selects::Programs(Some(programs)) => names.extend(programs.iter().cloned()),
            Selects::Parent(parent) if depth < 8 => {
                names.extend(resolve(parent, definitions, depth + 1)?);
            }
            _ => return None,
        }
    }
    (!names.is_empty()).then_some(names)
}
fn child_text<'a>(element: &'a RawElement, tag: &str) -> Option<&'a str> {
    element
        .children
        .iter()
        .find(|c| c.tag == tag)
        .map(|c| c.text.trim())
}

/// Literals every line a `prematch` accepts contains: the literal start of each `|` alternative
/// (`^ossec: ` gives `ossec: `), up to the first character that means more than itself in
/// Wazuh's regex syntax. Any non-empty literal is a superset test; the two-character floor
/// admits the stock `su` decoder (`^SU \S+`) while refusing single letters that bound nothing
/// in practice. `None` if any alternative has none.
fn prematch_literals(pattern: &str) -> Option<Vec<String>> {
    pattern
        .split('|')
        .map(|alternative| {
            let literal: String = alternative
                .trim_start_matches('^')
                .chars()
                .take_while(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | ':' | '/' | ',')
                })
                .collect();
            let literal = literal.trim().to_owned();
            (literal.chars().count() >= 2).then_some(literal)
        })
        .collect()
}

/// The literal program names of a `program_name` pattern such as `^sshd` or `^apache2|^httpd`;
/// `None` if any alternative is more than an anchored literal.
fn programs(pattern: &str) -> Option<Vec<String>> {
    pattern
        .split('|')
        .map(|alternative| {
            let name = alternative
                .trim()
                .trim_start_matches('^')
                .trim_end_matches('$');
            let literal = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'));
            literal.then(|| name.to_owned())
        })
        .collect()
}

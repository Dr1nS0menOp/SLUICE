//! Parser packs: how a SIEM parses a text line into the named fields its rules test (ADR 0043).
//!
//! A pack is a YAML file under `parsers/` (embedded in the binary) or in a directory of the
//! operator's own (`--parsers DIR`, which replaces a built-in pack with the same id). It holds
//! regular expressions with named groups, the field each group gives, and example lines with
//! the fields they must give: [`ParserBook::parse`] refuses a pack whose examples do not parse
//! as it says. A source names its pack (`format: {kind: text, field: message, parser: ID}`),
//! and [`ParserBook::resolve`] puts the pack into the source. Naming one is the operator's claim
//! that the SIEM parses the lines that way, like a `--sigma-pipeline`: the proof parses them
//! with the same pack, so it cannot notice a different parser in the SIEM.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::Deserialize;
use sluice_core::field::FieldPath;
use sluice_core::logsource::LogSource;
use sluice_core::parser::{LineParser, LinePattern};
use sluice_core::schema::Schema;
use sluice_core::source::{Source, SourceFormat};

use crate::error::RulesError;

include!(concat!(env!("OUT_DIR"), "/embedded_parsers.rs"));

/// A pack as its YAML file writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    id: String,
    description: String,
    /// The data it is for, as a Sigma log source: what `sluice init` suggests it for.
    logsource: LogSource,
    /// The convention its field names are in.
    convention: Schema,
    /// Other packs whose patterns follow this pack's own, in order: one source, one parser, for
    /// a log that mixes programs (`linux/auth`).
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    patterns: Vec<PatternFile>,
    /// Lines the pack must parse, with fields they must give.
    #[serde(default)]
    examples: Vec<Example>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternFile {
    regex: String,
    /// Named group → the field it gives, or several.
    fields: BTreeMap<String, OneOrMore>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMore {
    One(String),
    More(Vec<String>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Example {
    line: String,
    /// The fields it must give; `~` for one it must not.
    fields: BTreeMap<String, Option<String>>,
}

/// One parser pack, checked.
#[derive(Debug, Clone)]
pub struct Pack {
    /// The parser, for sources to carry.
    pub parser: LineParser,
    /// What it parses, in a few words.
    pub description: String,
    /// The data it is for.
    pub logsource: LogSource,
    /// The packs it includes.
    pub included: Vec<String>,
    examples: Vec<Example>,
    compiled: CompiledParser,
}

impl Pack {
    /// The fields `line` gives with this pack, or `None` when no pattern matches it.
    #[must_use]
    pub fn parse(&self, line: &str) -> Option<BTreeMap<FieldPath, String>> {
        self.compiled.parse(line)
    }
}

/// Every parser pack, by id.
#[derive(Debug, Clone, Default)]
pub struct ParserBook {
    packs: BTreeMap<String, Pack>,
}

impl ParserBook {
    /// The packs built into Sluice.
    ///
    /// # Errors
    ///
    /// [`RulesError::Parser`] if a built-in pack is invalid (the tests catch that).
    pub fn embedded() -> Result<Self, RulesError> {
        Self::parse(EMBEDDED.iter().copied())
    }

    /// The packs in `files`, as `(path, YAML)`.
    ///
    /// # Errors
    ///
    /// [`RulesError::Parser`] for a pack that is not valid, whose regular expressions do not
    /// compile or name a group they lack, whose examples do not parse as they say, or whose id
    /// another pack in `files` has.
    pub fn parse<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, RulesError> {
        let mut parsed: Vec<(&str, PackFile)> = Vec::new();
        for (path, yaml) in files {
            let file: PackFile = serde_yaml_ng::from_str(yaml)
                .map_err(|e| RulesError::Parser(format!("{path}: {e}")))?;
            if parsed.iter().any(|(_, other)| other.id == file.id) {
                return Err(RulesError::Parser(format!(
                    "{path}: another pack is {}",
                    file.id
                )));
            }
            parsed.push((path, file));
        }
        // Packs of their own first, then those that include them.
        parsed.sort_by_key(|(_, file)| !file.include.is_empty());
        let mut packs: BTreeMap<String, Pack> = BTreeMap::new();
        for (path, file) in parsed {
            let built = pack(path, file, &packs)?;
            packs.insert(built.parser.id.clone(), built);
        }
        Ok(Self { packs })
    }

    /// The built-in packs, with `files` of the operator's own replacing any of the same id.
    ///
    /// # Errors
    ///
    /// As for [`ParserBook::parse`].
    pub fn embedded_with<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, RulesError> {
        let mut book = Self::embedded()?;
        book.packs.extend(Self::parse(files)?.packs);
        Ok(book)
    }

    /// The pack with `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Pack> {
        self.packs.get(id)
    }

    /// Every pack, by id.
    pub fn packs(&self) -> impl Iterator<Item = &Pack> {
        self.packs.values()
    }

    /// Puts the pack each text source names into it, unless it already has one.
    ///
    /// # Errors
    ///
    /// [`RulesError::Parser`] for a source that names a pack the book does not have.
    pub fn resolve(&self, sources: &mut [Source]) -> Result<(), RulesError> {
        for source in sources {
            if let SourceFormat::Text {
                parser: Some(name), ..
            } = &mut source.format
                && name.resolved.is_none()
            {
                let pack = self.get(&name.name).ok_or_else(|| {
                    RulesError::Parser(format!(
                        "source {} names the parser {}, which is not a pack (`sluice parsers` \
                         lists them)",
                        source.id, name.name
                    ))
                })?;
                name.resolved = Some(pack.parser.clone());
            }
        }
        Ok(())
    }
}

/// A [`LineParser`] with its regular expressions compiled.
#[derive(Debug, Clone)]
pub struct CompiledParser {
    patterns: Vec<(Regex, Vec<(String, FieldPath)>)>,
}

impl CompiledParser {
    /// Compiles `parser`'s patterns.
    ///
    /// # Errors
    ///
    /// [`RulesError::Parser`] for a pattern that does not compile, or a field from a group it
    /// does not have.
    pub fn new(parser: &LineParser) -> Result<Self, RulesError> {
        let patterns = parser
            .patterns
            .iter()
            .map(|pattern| {
                let regex = Regex::new(&pattern.regex).map_err(|e| {
                    RulesError::Parser(format!("{}: {}: {e}", parser.id, pattern.regex))
                })?;
                let groups: BTreeSet<&str> = regex.capture_names().flatten().collect();
                if let Some((group, _)) = pattern
                    .fields
                    .iter()
                    .find(|(group, _)| !groups.contains(group.as_str()))
                {
                    return Err(RulesError::Parser(format!(
                        "{}: no group {group} in {}",
                        parser.id, pattern.regex
                    )));
                }
                Ok((regex, pattern.fields.clone()))
            })
            .collect::<Result<_, RulesError>>()?;
        Ok(Self { patterns })
    }

    /// The fields of the first pattern that matches `line`; a group that took no part in the
    /// match gives no field. `None` when no pattern matches.
    #[must_use]
    pub fn parse(&self, line: &str) -> Option<BTreeMap<FieldPath, String>> {
        self.patterns.iter().find_map(|(regex, fields)| {
            let captures = regex.captures(line)?;
            Some(
                fields
                    .iter()
                    .filter_map(|(group, field)| {
                        captures
                            .name(group)
                            .map(|found| (field.clone(), found.as_str().to_owned()))
                    })
                    .collect(),
            )
        })
    }
}

fn pack(path: &str, file: PackFile, built: &BTreeMap<String, Pack>) -> Result<Pack, RulesError> {
    if file.include.is_empty() && (file.patterns.is_empty() || file.examples.is_empty()) {
        return Err(RulesError::Parser(format!(
            "{path}: a pack needs at least one pattern and one example, or packs to include"
        )));
    }
    let mut included = Vec::new();
    for id in &file.include {
        let pack = built
            .get(id)
            .filter(|p| p.included.is_empty())
            .ok_or_else(|| {
                RulesError::Parser(format!(
                    "{path}: includes {id}, which is no pack of patterns of its own"
                ))
            })?;
        included.push(pack);
    }
    let mut patterns = file
        .patterns
        .into_iter()
        .map(|pattern| {
            // VRL writes a regex literal between quotes; an escaped quote cannot be written there.
            if pattern.regex.contains("\\'") {
                return Err(RulesError::Parser(format!(
                    "{path}: write a quote in a pattern as \\x27, not \\'"
                )));
            }
            let fields = pattern
                .fields
                .into_iter()
                .flat_map(|(group, fields)| {
                    let names = match fields {
                        OneOrMore::One(name) => vec![name],
                        OneOrMore::More(names) => names,
                    };
                    names
                        .into_iter()
                        .map(move |name| (group.clone(), FieldPath::new(name)))
                })
                .collect();
            Ok(LinePattern {
                regex: pattern.regex,
                fields,
            })
        })
        .collect::<Result<Vec<_>, RulesError>>()?;
    patterns.extend(
        included
            .iter()
            .flat_map(|p| p.parser.patterns.iter().cloned()),
    );
    let parser = LineParser {
        id: file.id,
        convention: file.convention,
        patterns,
    };
    let compiled =
        CompiledParser::new(&parser).map_err(|e| RulesError::Parser(format!("{path}: {e}")))?;
    let examples = file
        .examples
        .iter()
        .chain(included.iter().flat_map(|p| p.examples.iter()));
    for example in examples {
        let parsed = compiled.parse(&example.line).ok_or_else(|| {
            RulesError::Parser(format!(
                "{path}: no pattern matches the example {:?}",
                example.line
            ))
        })?;
        for (field, expected) in &example.fields {
            let got = parsed.get(field.as_str());
            if got != expected.as_ref() {
                return Err(RulesError::Parser(format!(
                    "{path}: the example {:?} gives {field} = {got:?}, not {expected:?}",
                    example.line
                )));
            }
        }
    }
    Ok(Pack {
        parser,
        description: file.description,
        logsource: file.logsource,
        included: file.include,
        examples: file.examples,
        compiled,
    })
}

#[cfg(test)]
mod tests;

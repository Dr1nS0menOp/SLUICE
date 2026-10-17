//! ES|QL, and Lucene, which Sluice does not parse: the names in a query, and for ES|QL the
//! filter its first `WHERE` clauses put on the documents.

use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::predicate::Predicate;

use super::eql;

/// Every name in `query` that may be a field it reads, and why it may read any field, if it
/// may: `name.*` reads every field below `name`; a bare `*` in `KEEP` or `DROP` may name any
/// field (elsewhere it multiplies, or counts rows).
pub(super) fn names(query: &str) -> (BTreeSet<FieldPath>, Option<&'static str>) {
    let chars: Vec<char> = query.chars().collect();
    let mut names = Names::default();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(end) = skipped(&chars, i) {
            names.end_word(None);
            i = end;
            continue;
        }
        match c {
            '|' => {
                names.end_word(None);
                names.after_from = false;
                names.command = None;
            }
            c if c.is_alphanumeric() || "_.@".contains(c) => names.word.push(c),
            '*' if names.word.ends_with('.') => {
                let prefix = names.word.trim_end_matches('.').to_owned();
                names.word.clear();
                if !names.after_from {
                    names.fields.insert(FieldPath::new(prefix));
                }
            }
            '*' => {
                names.end_word(None);
                let columns = matches!(names.command.as_deref(), Some("keep" | "drop"));
                if !names.after_from && columns {
                    names.any_field = Some("a `*` that may name any field");
                }
            }
            _ => names.end_word(if c.is_whitespace() {
                next_non_space(&chars, i)
            } else {
                Some(c)
            }),
        }
        i += 1;
    }
    names.end_word(None);
    (names.fields, names.any_field)
}

/// A superset of the documents an ES|QL query can see: what its `WHERE` clauses keep, up to
/// the first command that is more than adding columns or dropping rows (`STATS`, `DISSECT`, …),
/// with the fields they name. A condition on a column the query made (`EVAL`, `RENAME`), or one
/// that cannot be read, is left out: every event may pass it. `true` without any.
pub(super) fn prefilter(query: &str) -> (Predicate, BTreeSet<FieldPath>) {
    const PASSING: [&str; 6] = ["keep", "drop", "sort", "limit", "mv_expand", "metadata"];
    let mut conditions = Vec::new();
    let mut fields = BTreeSet::new();
    let mut made: BTreeSet<String> = BTreeSet::new();
    for command in commands(query).iter().skip(1) {
        let command = command.trim();
        let (word, rest) = command
            .split_once(char::is_whitespace)
            .unwrap_or((command, ""));
        match word.to_ascii_lowercase().as_str() {
            "where" => {
                let Ok((predicate, named)) = eql::esql_condition(rest) else {
                    continue;
                };
                let computed = named.iter().any(|f| {
                    made.iter()
                        .any(|m| f.as_str() == m || f.as_str().starts_with(&format!("{m}.")))
                });
                if !computed {
                    conditions.push(predicate);
                    fields.extend(named);
                }
            }
            "eval" | "rename" => made.extend(columns(rest)),
            other if PASSING.contains(&other) => {}
            _ => break,
        }
    }
    (Predicate::all(conditions), fields)
}

/// The columns an `EVAL` (`a = …, b = …`) or `RENAME` (`x AS a`, or `a = x`) makes.
fn columns(assignments: &str) -> Vec<String> {
    assignments
        .split(',')
        .filter_map(|part| {
            let lower = part.to_ascii_lowercase();
            if let Some(at) = lower.find(" as ") {
                return Some(part[at + 4..].trim().to_owned());
            }
            let at = part.find('=')?;
            let comparison =
                part[at + 1..].starts_with('=') || part[..at].ends_with(['=', '!', '<', '>']);
            (!comparison).then(|| part[..at].trim().to_owned())
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// The query's commands: the text between top-level pipes, comments left out.
fn commands(query: &str) -> Vec<String> {
    let chars: Vec<char> = query.chars().collect();
    let mut commands = vec![String::new()];
    let mut i = 0;
    while i < chars.len() {
        if let Some(end) = skipped(&chars, i) {
            if let Some(command) = commands.last_mut() {
                // A comment separates like a space; a string is part of the command.
                if chars[i] == '/' {
                    command.push(' ');
                } else {
                    command.extend(&chars[i..end]);
                }
            }
            i = end;
            continue;
        }
        if chars[i] == '|' {
            commands.push(String::new());
        } else if let Some(command) = commands.last_mut() {
            command.push(chars[i]);
        }
        i += 1;
    }
    commands
}

/// Where a string or comment starting at `at` ends, if one does.
fn skipped(chars: &[char], at: usize) -> Option<usize> {
    let c = chars[at];
    let next = chars.get(at + 1).copied();
    if c == '"' && next == Some('"') && chars.get(at + 2) == Some(&'"') {
        return Some(find(chars, at + 3, &['"', '"', '"']).map_or(chars.len(), |end| end + 3));
    }
    match c {
        '"' | '\'' => {
            let mut i = at + 1;
            while i < chars.len() && chars[i] != c {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            Some((i + 1).min(chars.len()))
        }
        '/' if next == Some('/') => Some(find(chars, at, &['\n']).unwrap_or(chars.len())),
        '/' if next == Some('*') => {
            Some(find(chars, at + 2, &['*', '/']).map_or(chars.len(), |end| end + 2))
        }
        _ => None,
    }
}

/// The names [`names`] collects.
#[derive(Default)]
struct Names {
    fields: BTreeSet<FieldPath>,
    any_field: Option<&'static str>,
    word: String,
    /// Inside `FROM …`, up to the next pipe: index patterns, not fields.
    after_from: bool,
    /// The command the current one is (`keep`, `eval`, …), lowercased, once its first word
    /// ended.
    command: Option<String>,
}

impl Names {
    /// Ends the current word; `next` is the character after it, to tell function calls.
    fn end_word(&mut self, next: Option<char>) {
        const WORDS: [&str; 39] = [
            "from",
            "where",
            "stats",
            "by",
            "eval",
            "keep",
            "drop",
            "rename",
            "sort",
            "limit",
            "and",
            "or",
            "not",
            "in",
            "like",
            "rlike",
            "is",
            "null",
            "true",
            "false",
            "asc",
            "desc",
            "as",
            "metadata",
            "dissect",
            "grok",
            "enrich",
            "mv_expand",
            "on",
            "with",
            "row",
            "show",
            "lookup",
            "join",
            "nulls",
            "first",
            "last",
            "to",
            "inlinestats",
        ];
        let word = std::mem::take(&mut self.word);
        if word.is_empty() {
            return;
        }
        let lower = word.to_ascii_lowercase();
        if self.command.is_none() {
            self.command = Some(lower.clone());
        }
        if lower == "from" {
            self.after_from = true;
        } else if !self.after_from
            && next != Some('(')
            && !WORDS.contains(&lower.as_str())
            && !word.starts_with(|c: char| c.is_ascii_digit())
        {
            self.fields
                .insert(FieldPath::new(word.trim_end_matches(['.', ':'])));
        }
    }
}

/// Where `pattern` next starts at or after `from`.
fn find(chars: &[char], from: usize, pattern: &[char]) -> Option<usize> {
    chars
        .get(from..)?
        .windows(pattern.len())
        .position(|w| w == pattern)
        .map(|at| from + at)
}

fn next_non_space(chars: &[char], at: usize) -> Option<char> {
    chars
        .get(at + 1..)?
        .iter()
        .copied()
        .find(|c| !c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use sluice_core::predicate::{FieldTest, MatchOp};

    use super::*;

    fn eq(field: &str, value: &str) -> Predicate {
        Predicate::Field(FieldTest {
            field: field.into(),
            op: MatchOp::Equals,
            values: vec![value.into()],
            case_sensitive: false,
        })
    }

    #[test]
    fn the_first_where_clauses_filter_the_documents() {
        let (prefilter, fields) = prefilter(
            "FROM logs-windows.* METADATA _id\n\
             | WHERE host.os.type == \"windows\" // only Windows\n\
             | where event.code in (\"4624\", \"4625\") and user.name is not null\n\
             | EVAL n = 1\n\
             | WHERE n > 0 and process.name == \"x\"",
        );
        assert_eq!(
            prefilter,
            Predicate::all([
                eq("host.os.type", "windows"),
                Predicate::any([eq("event.code", "4624"), eq("event.code", "4625")]),
                Predicate::Field(FieldTest {
                    field: "user.name".into(),
                    op: MatchOp::Exists,
                    values: Vec::new(),
                    case_sensitive: false,
                }),
            ])
        );
        assert!(fields.contains(&FieldPath::from("event.code")));
        assert!(
            !fields.contains(&FieldPath::from("process.name")),
            "a condition on the column EVAL made"
        );
    }

    #[test]
    fn a_condition_on_a_made_column_or_after_stats_is_left_out() {
        let (prefilter, _) = prefilter(
            "from a | eval n = length(x), host = to_lower(h.name) | rename y AS z \
             | where n > 3 and host == \"a\" | where z == \"b\" | where b == \"c\" \
             | stats c = count(*) | where c > 1",
        );
        assert_eq!(prefilter, eq("b", "c"));
        assert_eq!(columns("a = f(x, y), b = 2, c == 3"), ["a", "b"]);
        assert_eq!(columns("x AS y, z AS w"), ["y", "w"]);
    }

    #[test]
    fn an_options_map_is_a_value() {
        let (prefilter, _) = prefilter(
            "from a | where event.type == \"start\" and match(process.name, \"svchost.exe\", \
             { \"fuzziness\": 1, \"max_expansions\": 10 })",
        );
        assert_eq!(prefilter, eq("event.type", "start"));
    }

    #[test]
    fn superset_what_esql_decides_otherwise_is_true() {
        for query in [
            "from a | stats n = count(*) | where n > 5",
            "from a | where message : \"error\"",
            "from a | where process.name rlike \"cmd.*\"",
            "from a | where to_lower(process.name) == \"cmd.exe\"",
            "from a",
        ] {
            assert!(prefilter(query).0.is_always(), "{query}");
        }
    }

    #[test]
    fn pipes_in_strings_and_comments_split_nothing() {
        assert_eq!(
            commands("from a | where x like \"*|*\" /* | */ | keep x").len(),
            3
        );
    }

    #[test]
    fn prefixes_comments_and_raw_strings() {
        let query = "/* a * comment */ from logs-* metadata _id | where x.y rlike \"\"\"a*b\"\"\" \
                     // and *\n | keep event.*, user.name";
        let (fields, any) = names(query);
        assert_eq!(any, None);
        let fields: Vec<&str> = fields.iter().map(FieldPath::as_str).collect();
        assert_eq!(fields, ["event", "user.name", "x.y"]);
        assert!(names("from a | keep *").1.is_some());
        assert!(names("from a | DROP b, *").1.is_some());
        for query in [
            "from a | eval r = (x / 1000) * y",
            "from a | stats n = count(*) by b",
            "from a | where x * 2 > 3",
        ] {
            assert_eq!(names(query).1, None, "{query}");
        }
    }
}

//! Kibana Query Language (`kuery`), the language of Elastic's custom query rules, as the fields
//! a query reads and a superset pre-filter.
//!
//! Elasticsearch decides a KQL test on a `text` field by its analyzed tokens and on a `keyword`
//! field by the whole value, case-sensitive. A pre-filter must match whatever either does, on
//! the event as VRL sees it, so a value becomes tests that its ASCII alphanumeric tokens are
//! *contained*, case-insensitively: a document that matches holds every token of a phrase or a
//! wildcard pattern, and some token of an unquoted value (a `match` query is an `or` of its
//! tokens). This assumes the standard analyzer (no stemming or synonyms), which ECS mappings
//! use. Everything else widens: `not`, ranges, nested queries and non-ASCII values are `true`;
//! `field: *` is `exists`.

use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

/// What a KQL query reads and which events it could match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reads {
    /// Every field the query names.
    pub(crate) fields: BTreeSet<FieldPath>,
    /// Why the query may read any field (free text, a wildcard field name), if it may.
    pub(crate) any_field: Option<&'static str>,
    /// A superset of the events it matches.
    pub(crate) prefilter: Predicate,
}

/// Reads `query`; `Err` with the reason when it is not KQL this parser knows.
pub(crate) fn read(query: &str) -> Result<Reads, String> {
    let tokens = lex(query)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        reads: Reads {
            fields: BTreeSet::new(),
            any_field: None,
            prefilter: Predicate::Always,
        },
    };
    if tokens.is_empty() {
        return Ok(parser.reads);
    }
    let prefilter = parser.or(None)?;
    if parser.at < tokens.len() {
        return Err(format!("unexpected {:?}", tokens[parser.at]));
    }
    parser.reads.prefilter = prefilter;
    Ok(parser.reads)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    OpenBrace,
    CloseBrace,
    Colon,
    Range,
    /// A value or field name; `wildcard` when it holds an unescaped `*` or `?`.
    Word {
        text: String,
        wildcard: bool,
    },
    Quoted(String),
}

fn lex(query: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = query.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' | ')' | '{' | '}' | ':' => {
                chars.next();
                tokens.push(match c {
                    '(' => Token::Open,
                    ')' => Token::Close,
                    '{' => Token::OpenBrace,
                    '}' => Token::CloseBrace,
                    _ => Token::Colon,
                });
            }
            '<' | '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                }
                tokens.push(Token::Range);
            }
            '"' => {
                chars.next();
                let mut text = String::new();
                loop {
                    match chars.next() {
                        None => return Err("an unterminated quoted value".to_owned()),
                        Some('"') => break,
                        Some('\\') => text.extend(chars.next()),
                        Some(c) => text.push(c),
                    }
                }
                tokens.push(Token::Quoted(text));
            }
            _ => {
                let mut text = String::new();
                let mut wildcard = false;
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || "(){}:<>\"".contains(c) {
                        break;
                    }
                    chars.next();
                    match c {
                        '\\' => text.extend(chars.next()),
                        '*' | '?' => {
                            wildcard = true;
                            text.push(c);
                        }
                        _ => text.push(c),
                    }
                }
                tokens.push(Token::Word { text, wildcard });
            }
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    reads: Reads,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn keyword(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word { text, wildcard: false }) if text.eq_ignore_ascii_case(word))
    }

    fn expect(&mut self, token: &Token) -> Result<(), String> {
        if self.peek() == Some(token) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected {token:?} at token {}", self.at))
        }
    }

    /// `a or b …`; `field` is set inside `field: ( … )`, where operands are values.
    fn or(&mut self, field: Option<&FieldPath>) -> Result<Predicate, String> {
        let mut parts = vec![self.and(field)?];
        while self.keyword("or") {
            self.at += 1;
            parts.push(self.and(field)?);
        }
        Ok(Predicate::any(parts))
    }

    fn and(&mut self, field: Option<&FieldPath>) -> Result<Predicate, String> {
        let mut parts = vec![self.not(field)?];
        while self.keyword("and") {
            self.at += 1;
            parts.push(self.not(field)?);
        }
        Ok(Predicate::all(parts))
    }

    fn not(&mut self, field: Option<&FieldPath>) -> Result<Predicate, String> {
        if self.keyword("not") {
            self.at += 1;
            // What a negation keeps cannot be bounded from inside it.
            self.not(field)?;
            return Ok(Predicate::Always);
        }
        self.primary(field)
    }

    fn primary(&mut self, field: Option<&FieldPath>) -> Result<Predicate, String> {
        match self.peek().cloned() {
            Some(Token::Open) => {
                self.at += 1;
                let inner = self.or(field)?;
                self.expect(&Token::Close)?;
                Ok(inner)
            }
            Some(Token::Word { text, wildcard }) if field.is_none() => {
                match self.tokens.get(self.at + 1) {
                    Some(Token::Colon) => {
                        self.at += 2;
                        self.field_value(&text, wildcard)
                    }
                    Some(Token::Range) => {
                        self.at += 2;
                        let path = self.name(&text, wildcard);
                        self.value_words()?;
                        Ok(path.map_or(Predicate::Always, exists))
                    }
                    _ => self.free_text(),
                }
            }
            Some(Token::Quoted(_)) if field.is_none() => self.free_text(),
            Some(Token::Word { .. } | Token::Quoted(_)) => {
                let (text, quoted, wildcard) = self.value_words()?;
                Ok(value(field, &text, quoted, wildcard))
            }
            other => Err(format!("unexpected {other:?}")),
        }
    }

    /// The field a name denotes, recorded as read; `None` for a wildcard name, which may read
    /// any field.
    fn name(&mut self, text: &str, wildcard: bool) -> Option<FieldPath> {
        if wildcard {
            self.reads.any_field = Some("a field name with a wildcard");
            return None;
        }
        let path = FieldPath::new(text);
        self.reads.fields.insert(path.clone());
        Some(path)
    }

    fn field_value(&mut self, name: &str, wildcard: bool) -> Result<Predicate, String> {
        let path = self.name(name, wildcard);
        match self.peek() {
            Some(Token::Open) => {
                self.at += 1;
                let inner = self.or(Some(&path.clone().unwrap_or_else(|| FieldPath::new("*"))))?;
                self.expect(&Token::Close)?;
                Ok(if path.is_some() {
                    inner
                } else {
                    Predicate::Always
                })
            }
            Some(Token::OpenBrace) => {
                self.at += 1;
                let before = self.reads.fields.clone();
                self.or(None)?;
                self.expect(&Token::CloseBrace)?;
                // Names inside a nested query are relative to the field.
                let inner: Vec<FieldPath> =
                    self.reads.fields.difference(&before).cloned().collect();
                if let (Some(path), false) = (&path, inner.is_empty()) {
                    // The fields inside say what of it is read.
                    self.reads.fields.remove(path);
                }
                for relative in inner {
                    self.reads.fields.remove(&relative);
                    if let Some(path) = &path {
                        self.reads
                            .fields
                            .insert(FieldPath::new(format!("{path}.{relative}")));
                    }
                }
                Ok(Predicate::Always)
            }
            _ => {
                let (text, quoted, wildcard_value) = self.value_words()?;
                if !quoted && text == "*" {
                    return Ok(path.map_or(Predicate::Always, exists));
                }
                Ok(match path {
                    Some(path) => value(Some(&path), &text, quoted, wildcard_value),
                    None => Predicate::Always,
                })
            }
        }
    }

    /// A value: one quoted string, or the unquoted words up to the next keyword or bracket.
    fn value_words(&mut self) -> Result<(String, bool, bool), String> {
        if let Some(Token::Quoted(text)) = self.peek().cloned() {
            self.at += 1;
            return Ok((text, true, false));
        }
        let mut words = Vec::new();
        let mut wildcard = false;
        while let Some(Token::Word { text, wildcard: w }) = self.peek().cloned() {
            if ["and", "or", "not"]
                .iter()
                .any(|k| text.eq_ignore_ascii_case(k))
                && !w
            {
                break;
            }
            self.at += 1;
            wildcard |= w;
            words.push(text);
        }
        if words.is_empty() {
            return Err(format!("expected a value at token {}", self.at));
        }
        Ok((words.join(" "), false, wildcard))
    }

    fn free_text(&mut self) -> Result<Predicate, String> {
        let (text, quoted, wildcard) = self.value_words()?;
        self.reads.any_field = Some("free text, which searches every field");
        Ok(value(None, &text, quoted, wildcard))
    }
}

fn exists(path: FieldPath) -> Predicate {
    Predicate::Field(FieldTest {
        field: path,
        op: MatchOp::Exists,
        values: Vec::new(),
        case_sensitive: false,
    })
}

/// The superset test of `text` on `field`, or on every field when there is none.
pub(crate) fn value(
    field: Option<&FieldPath>,
    text: &str,
    quoted: bool,
    wildcard: bool,
) -> Predicate {
    if !text.is_ascii() {
        return Predicate::Always;
    }
    // A word holds all of its alphanumeric runs: the analyzer keeps `cmd.exe` one token, and a
    // keyword is the whole value.
    let word = |word: &str| -> Option<Predicate> {
        let tests: Vec<Predicate> = word
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|token| test(field, &token.to_ascii_lowercase()))
            .collect();
        (!tests.is_empty()).then(|| Predicate::all(tests))
    };
    let words: Option<Vec<Predicate>> = text.split_whitespace().map(word).collect();
    let Some(words) = words.filter(|w| !w.is_empty()) else {
        // A word without letters or digits: only that the field has a value is known.
        return field.map_or(Predicate::Always, |f| exists(f.clone()));
    };
    // A phrase needs every word; so does a pattern. An unquoted value is a `match` query, an
    // `or` of its words.
    if quoted || wildcard {
        Predicate::all(words)
    } else {
        Predicate::any(words)
    }
}

fn test(field: Option<&FieldPath>, token: &str) -> Predicate {
    match field {
        Some(field) => Predicate::Field(FieldTest {
            field: field.clone(),
            op: MatchOp::Contains,
            values: vec![token.to_owned()],
            case_sensitive: false,
        }),
        None => Predicate::Keywords(KeywordTest {
            values: vec![token.to_owned()],
            case_sensitive: false,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(field: &str, value: &str) -> Predicate {
        Predicate::Field(FieldTest {
            field: field.into(),
            op: MatchOp::Contains,
            values: vec![value.into()],
            case_sensitive: false,
        })
    }

    fn fields(reads: &Reads) -> Vec<&str> {
        reads.fields.iter().map(FieldPath::as_str).collect()
    }

    #[test]
    fn a_field_value_is_a_test_that_its_tokens_are_contained() {
        let reads = read(r#"event.code : "4624" and winlog.logon.type : Network"#).unwrap();
        assert_eq!(fields(&reads), ["event.code", "winlog.logon.type"]);
        assert_eq!(reads.any_field, None);
        assert_eq!(
            reads.prefilter,
            Predicate::all([
                contains("event.code", "4624"),
                contains("winlog.logon.type", "network")
            ])
        );
    }

    #[test]
    fn value_lists_are_any_of_their_values_and_a_word_needs_all_its_parts() {
        let reads = read("process.name : (cmd.exe or powershell.exe)").unwrap();
        assert_eq!(fields(&reads), ["process.name"]);
        assert_eq!(
            reads.prefilter,
            Predicate::any([
                Predicate::all([
                    contains("process.name", "cmd"),
                    contains("process.name", "exe")
                ]),
                Predicate::all([
                    contains("process.name", "powershell"),
                    contains("process.name", "exe")
                ]),
            ])
        );
        // Unquoted words are a `match` query: any of them.
        assert_eq!(
            read("message : failed logon").unwrap().prefilter,
            Predicate::any([contains("message", "failed"), contains("message", "logon")])
        );
    }

    #[test]
    fn superset_negation_ranges_and_nested_queries_widen() {
        // A range only says that the field has a value.
        assert!(matches!(
            read("event.severity >= 3").unwrap().prefilter,
            Predicate::Field(FieldTest {
                op: MatchOp::Exists,
                ..
            })
        ));
        for query in [
            "not user.name : root",
            "user : { name : root }",
            "process.name : café",
        ] {
            let reads = read(query).unwrap();
            assert!(
                reads.prefilter.is_always(),
                "{query}: {:?}",
                reads.prefilter
            );
        }
        assert_eq!(
            fields(&read("user : { name : root }").unwrap()),
            ["user.name"]
        );
    }

    #[test]
    fn a_phrase_and_a_wildcard_need_every_token() {
        let phrase = read(r#"message : "logon failed""#).unwrap();
        assert_eq!(
            phrase.prefilter,
            Predicate::all([contains("message", "logon"), contains("message", "failed")])
        );
        let pattern = read("file.path : *\\Temp\\*.ps1").unwrap();
        assert_eq!(
            pattern.prefilter,
            Predicate::all([contains("file.path", "temp"), contains("file.path", "ps1")])
        );
    }

    #[test]
    fn exists_and_free_text() {
        let present = read("process.parent.name : *").unwrap();
        assert!(matches!(
            present.prefilter,
            Predicate::Field(FieldTest {
                op: MatchOp::Exists,
                ..
            })
        ));
        let free = read("mimikatz").unwrap();
        assert!(free.any_field.is_some());
        assert_eq!(
            free.prefilter,
            Predicate::Keywords(KeywordTest {
                values: vec!["mimikatz".into()],
                case_sensitive: false,
            })
        );
    }

    #[test]
    fn a_wildcard_field_name_may_read_anything() {
        let reads = read("process.* : x").unwrap();
        assert!(reads.any_field.is_some());
        assert!(reads.prefilter.is_always());
    }

    #[test]
    fn keywords_are_case_insensitive_and_escapes_are_values() {
        let reads = read(r"a : 1 AND b : x\:y OR NOT c : 2").unwrap();
        assert_eq!(fields(&reads), ["a", "b", "c"]);
        let escaped = read(r"b : x\:y").unwrap();
        assert_eq!(
            escaped.prefilter,
            Predicate::all([contains("b", "x"), contains("b", "y")])
        );
    }

    #[test]
    fn broken_queries_are_errors() {
        for query in [r#"a : "open"#, "(a : 1", "a : 1)", "a :"] {
            assert!(read(query).is_err(), "{query}");
        }
        assert!(read("").unwrap().prefilter.is_always());
    }
}

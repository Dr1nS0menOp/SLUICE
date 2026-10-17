//! Kibana Query Language (`kuery`), the language of Elastic's custom query rules: the fields a
//! query reads, a superset pre-filter, and the Elasticsearch query Kibana runs ([`dsl`]).
//!
//! Elasticsearch decides a KQL test on a `text` field by its analyzed tokens and on a `keyword`
//! field by the whole value, case-sensitive. A pre-filter must match whatever either does, on
//! the event as VRL sees it, so a value becomes tests that its ASCII alphanumeric tokens are
//! *contained*, case-insensitively: a document that matches holds every token of a phrase or a
//! wildcard pattern, and some word of an unquoted value (a `match` query is an `or` of its
//! words). This assumes the standard analyzer (no stemming or synonyms), which ECS mappings
//! use. Everything else widens: `not`, ranges, nested queries and non-ASCII values are `true`;
//! `field: *` is `exists`.

mod dsl;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use serde_json::Value;
use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

/// What a KQL query reads and which events it could match.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Reads {
    /// Every field the query names.
    pub(crate) fields: BTreeSet<FieldPath>,
    /// Why the query may read any field (free text, a wildcard field name), if it may.
    pub(crate) any_field: Option<&'static str>,
    /// A superset of the events it matches.
    pub(crate) prefilter: Predicate,
    /// The query as Kibana gives it to Elasticsearch.
    pub(crate) dsl: Value,
}

/// Reads `query`; `Err` with the reason when it is not KQL this parser knows.
pub(crate) fn read(query: &str) -> Result<Reads, String> {
    let tokens = lex(query)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        fields: BTreeSet::new(),
        any_field: None,
    };
    let node = if tokens.is_empty() {
        Node::All
    } else {
        let node = parser.or(None, "")?;
        if parser.at < tokens.len() {
            return Err(format!("unexpected {:?}", tokens[parser.at]));
        }
        node
    };
    Ok(Reads {
        prefilter: prefilter(&node),
        dsl: dsl::query(&node),
        fields: parser.fields,
        any_field: parser.any_field,
    })
}

/// A parsed query.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// Every document: the empty query.
    All,
    Or(Vec<Node>),
    And(Vec<Node>),
    Not(Box<Node>),
    /// `field: value`; `field` is `None` for a name with a wildcard, `name` is as written.
    Is {
        field: Option<FieldPath>,
        name: String,
        value: Literal,
    },
    /// `field: *`.
    Exists {
        name: String,
    },
    /// `field < value` and the like.
    Range {
        name: String,
        op: &'static str,
        value: String,
    },
    /// A value without a field: every field is searched.
    Free(Literal),
}

/// A value as written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Literal {
    text: String,
    quoted: bool,
    wildcard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    OpenBrace,
    CloseBrace,
    Colon,
    /// `<`, `<=`, `>`, `>=`, as Elasticsearch's range names them.
    Range(&'static str),
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
                let equal = chars.peek() == Some(&'=');
                if equal {
                    chars.next();
                }
                tokens.push(Token::Range(match (c, equal) {
                    ('<', false) => "lt",
                    ('<', true) => "lte",
                    (_, false) => "gt",
                    (_, true) => "gte",
                }));
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
    fields: BTreeSet<FieldPath>,
    any_field: Option<&'static str>,
}

/// Inside `field: ( … )`: the field operands are values of.
type Within<'a> = Option<(&'a Option<FieldPath>, &'a str)>;

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

    /// `a or b …`; `prefix` is the path of the nested query this is in.
    fn or(&mut self, within: Within<'_>, prefix: &str) -> Result<Node, String> {
        let mut parts = vec![self.and(within, prefix)?];
        while self.keyword("or") {
            self.at += 1;
            parts.push(self.and(within, prefix)?);
        }
        Ok(one_or(parts, Node::Or))
    }

    fn and(&mut self, within: Within<'_>, prefix: &str) -> Result<Node, String> {
        let mut parts = vec![self.not(within, prefix)?];
        while self.keyword("and") {
            self.at += 1;
            parts.push(self.not(within, prefix)?);
        }
        Ok(one_or(parts, Node::And))
    }

    fn not(&mut self, within: Within<'_>, prefix: &str) -> Result<Node, String> {
        if self.keyword("not") {
            self.at += 1;
            return Ok(Node::Not(Box::new(self.not(within, prefix)?)));
        }
        self.primary(within, prefix)
    }

    fn primary(&mut self, within: Within<'_>, prefix: &str) -> Result<Node, String> {
        match self.peek().cloned() {
            Some(Token::Open) => {
                self.at += 1;
                let inner = self.or(within, prefix)?;
                self.expect(&Token::Close)?;
                Ok(inner)
            }
            Some(Token::Word { text, wildcard }) if within.is_none() => {
                match self.tokens.get(self.at + 1).cloned() {
                    Some(Token::Colon) => {
                        self.at += 2;
                        let name = format!("{prefix}{text}");
                        self.field_value(&name, wildcard)
                    }
                    Some(Token::Range(op)) => {
                        self.at += 2;
                        let name = format!("{prefix}{text}");
                        self.name(&name, wildcard);
                        let value = self.value_words()?.text;
                        Ok(Node::Range { name, op, value })
                    }
                    _ => self.free_text(),
                }
            }
            Some(Token::Quoted(_)) if within.is_none() => self.free_text(),
            Some(Token::Word { .. } | Token::Quoted(_)) => {
                let value = self.value_words()?;
                let (field, name) = within.map_or((None, ""), |(f, n)| (f.clone(), n));
                Ok(Node::Is {
                    field,
                    name: name.to_owned(),
                    value,
                })
            }
            other => Err(format!("unexpected {other:?}")),
        }
    }

    /// The field a name denotes, recorded as read; `None` for a wildcard name, which may read
    /// any field.
    fn name(&mut self, name: &str, wildcard: bool) -> Option<FieldPath> {
        if wildcard {
            // `file.hash.*` reads the fields below `file.hash`; `*` or `proc*` may be any.
            match wildcard_prefix(name) {
                Some(prefix) => {
                    self.fields.insert(prefix);
                }
                None => self.any_field = Some("a field name with a wildcard"),
            }
            return None;
        }
        let path = FieldPath::new(name);
        self.fields.insert(path.clone());
        Some(path)
    }

    fn field_value(&mut self, name: &str, wildcard: bool) -> Result<Node, String> {
        let field = self.name(name, wildcard);
        match self.peek() {
            Some(Token::Open) => {
                self.at += 1;
                let inner = self.or(Some((&field, name)), "")?;
                self.expect(&Token::Close)?;
                Ok(inner)
            }
            Some(Token::OpenBrace) => {
                self.at += 1;
                let before = self.fields.len();
                let inner = self.or(None, &format!("{name}."))?;
                self.expect(&Token::CloseBrace)?;
                if let (Some(field), true) = (&field, self.fields.len() > before) {
                    // The fields inside say what of it is read.
                    self.fields.remove(field);
                }
                Ok(inner)
            }
            _ => {
                let value = self.value_words()?;
                if !value.quoted && value.text == "*" {
                    return Ok(Node::Exists {
                        name: name.to_owned(),
                    });
                }
                Ok(Node::Is {
                    field,
                    name: name.to_owned(),
                    value,
                })
            }
        }
    }

    /// A value: one quoted string, or the unquoted words up to the next keyword or bracket.
    fn value_words(&mut self) -> Result<Literal, String> {
        if let Some(Token::Quoted(text)) = self.peek().cloned() {
            self.at += 1;
            return Ok(Literal {
                text,
                quoted: true,
                wildcard: false,
            });
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
        Ok(Literal {
            text: words.join(" "),
            quoted: false,
            wildcard,
        })
    }

    fn free_text(&mut self) -> Result<Node, String> {
        let value = self.value_words()?;
        self.any_field = Some("free text, which searches every field");
        Ok(Node::Free(value))
    }
}

fn one_or(mut parts: Vec<Node>, join: fn(Vec<Node>) -> Node) -> Node {
    if parts.len() == 1 {
        parts.remove(0)
    } else {
        join(parts)
    }
}

/// The superset pre-filter of a parsed query.
fn prefilter(node: &Node) -> Predicate {
    match node {
        // A negation cannot be bounded from inside it, and a wildcard name may be any field.
        Node::All | Node::Not(_) => Predicate::Always,
        Node::Or(parts) => Predicate::any(parts.iter().map(prefilter)),
        Node::And(parts) => Predicate::all(parts.iter().map(prefilter)),
        Node::Is {
            field: Some(field),
            value,
            ..
        } => self::value(Some(field), value),
        // A wildcard name (`file.hash.*: *`) is a field below its prefix, which then exists; one
        // without a prefix may be any field.
        Node::Is {
            field: None, name, ..
        } => wildcard_prefix(name).map_or(Predicate::Always, exists),
        Node::Exists { name } | Node::Range { name, .. } if name.contains(['*', '?']) => {
            wildcard_prefix(name).map_or(Predicate::Always, exists)
        }
        // Only that the field has a value is known.
        Node::Exists { name } | Node::Range { name, .. } => exists(FieldPath::new(name.as_str())),
        Node::Free(value) => self::value(None, value),
    }
}

/// The whole segments of a wildcard field name before its first wildcard (`file.hash.*` and
/// `file.ha*` are below `file`… `file.hash`), or `None` when the wildcard is in the first one.
fn wildcard_prefix(name: &str) -> Option<FieldPath> {
    let before = &name[..name.find(['*', '?'])?];
    let prefix = &before[..before.rfind('.')?];
    (!prefix.is_empty()).then(|| FieldPath::new(prefix))
}

fn exists(path: FieldPath) -> Predicate {
    Predicate::Field(FieldTest {
        field: path,
        op: MatchOp::Exists,
        values: Vec::new(),
        case_sensitive: false,
    })
}

/// The superset test of a value on `field`, or on every field when there is none.
fn value(field: Option<&FieldPath>, value: &Literal) -> Predicate {
    if !value.text.is_ascii() {
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
    let words: Option<Vec<Predicate>> = value.text.split_whitespace().map(word).collect();
    let Some(words) = words.filter(|w| !w.is_empty()) else {
        // A word without letters or digits: only that the field has a value is known.
        return field.map_or(Predicate::Always, |f| exists(f.clone()));
    };
    // A phrase needs every word; so does a pattern. An unquoted value is a `match` query, an
    // `or` of its words.
    if value.quoted || value.wildcard {
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

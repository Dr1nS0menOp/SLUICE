//! Event Query Language, the language of Elastic's EQL rules, as the fields a query reads, a
//! superset pre-filter, and whether it correlates events.
//!
//! `category where condition` keeps events by their fields; `sequence` and `sample` correlate
//! several (stateful), as does any pipe (`| head`, `| tail`, …): which events alert depends on
//! the others. Tests become superset field tests, case-insensitive so they cover `==` (exact)
//! and `:` (case-insensitive) alike: `==`, `:` and `in` an equality, `like`, wildcard values
//! and `startsWith`/`endsWith`/`stringContains` that the value's literal parts are contained.
//! Everything else widens to `true`: `!=`, `not`, `regex`, comparisons, other functions,
//! non-ASCII values. The event category is not used: `event.category` is an array in ECS, which
//! a field test takes as matching anyway.

use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};

/// What an EQL query reads and which events it could match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reads {
    /// Every field the query names.
    pub(crate) fields: BTreeSet<FieldPath>,
    /// A superset of the events it matches (of every event a sequence needs).
    pub(crate) prefilter: Predicate,
    /// Whether it correlates events: a sequence, a sample, or a pipe.
    pub(crate) stateful: bool,
}

/// Reads `query`; `Err` with the reason when it is not EQL this parser knows.
pub(crate) fn read(query: &str) -> Result<Reads, String> {
    let tokens = lex(query)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        fields: BTreeSet::new(),
        stateful: false,
    };
    let prefilter = parser.query()?;
    if parser.at < tokens.len() {
        if parser.peek() == Some(&Token::Pipe) {
            parser.stateful = true;
            parser.rest_fields();
        } else {
            return Err(format!("unexpected {:?}", tokens[parser.at]));
        }
    }
    Ok(Reads {
        fields: parser.fields,
        prefilter,
        stateful: parser.stateful,
    })
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Name(String),
    Text(String),
    Number(String),
    Op(&'static str),
    Open,
    Close,
    OpenBracket,
    CloseBracket,
    Comma,
    Pipe,
}

const OPERATORS: [&str; 15] = [
    "==", "!=", "<=", ">=", ":", "<", ">", "=", "~", "!", "+", "-", "*", "/", "%",
];

/// Arithmetic: an operand combined with another is a value Sluice does not compute.
const ARITHMETIC: [&str; 5] = ["+", "-", "*", "/", "%"];

fn lex(query: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = query.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' || c == '\'' {
            let (text, next) = string(&chars, i)?;
            tokens.push(Token::Text(text));
            i = next;
        } else if c == '`' || c.is_alphabetic() || c == '_' || c == '@' || c == '?' {
            let (name, next) = name(&chars, if c == '?' { i + 1 } else { i })?;
            tokens.push(Token::Name(name));
            i = next;
        } else if c.is_ascii_digit()
            || (c == '-' && chars.get(i + 1).is_some_and(char::is_ascii_digit))
        {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            tokens.push(Token::Number(chars[start..i].iter().collect()));
        } else {
            i += 1;
            tokens.push(match c {
                '(' => Token::Open,
                ')' => Token::Close,
                '[' => Token::OpenBracket,
                ']' => Token::CloseBracket,
                ',' => Token::Comma,
                '|' => Token::Pipe,
                _ => {
                    let two: String = [c].into_iter().chain(chars.get(i).copied()).collect();
                    if let Some(op) = OPERATORS.iter().find(|op| **op == two) {
                        i += 1;
                        Token::Op(op)
                    } else if let Some(op) = OPERATORS
                        .iter()
                        .find(|op| op.len() == 1 && op.starts_with(c))
                    {
                        Token::Op(op)
                    } else {
                        return Err(format!("unexpected character {c:?}"));
                    }
                }
            });
        }
    }
    Ok(tokens)
}

/// A field name from `chars[start]`: letters, digits, `_`, `.`, `@`, `-`, and `` `quoted` ``
/// segments (`` a.`0`.b ``). Returns the name and the index after it.
fn name(chars: &[char], start: usize) -> Result<(String, usize), String> {
    let mut name = String::new();
    let mut i = start;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            let end = chars[i + 1..]
                .iter()
                .position(|&c| c == '`')
                .ok_or("an unterminated `name`")?;
            name.extend(&chars[i + 1..i + 1 + end]);
            i += end + 2;
        } else if c.is_alphanumeric() || "_.@-".contains(c) {
            name.push(c);
            i += 1;
        } else {
            break;
        }
    }
    Ok((name, i))
}

/// A quoted string from `chars[start]`, with escapes; `"""…"""` is raw. Returns the text and
/// the index after it.
fn string(chars: &[char], start: usize) -> Result<(String, usize), String> {
    let quote = chars[start];
    if quote == '"' && chars.get(start + 1) == Some(&'"') && chars.get(start + 2) == Some(&'"') {
        let body = &chars[start + 3..];
        let end = body
            .windows(3)
            .position(|w| w == ['"', '"', '"'])
            .ok_or("an unterminated raw string")?;
        return Ok((body[..end].iter().collect(), start + 3 + end + 3));
    }
    let mut text = String::new();
    let mut i = start + 1;
    while i < chars.len() {
        match chars[i] {
            c if c == quote => return Ok((text, i + 1)),
            '\\' => {
                i += 1;
                match chars.get(i) {
                    Some('n') => text.push('\n'),
                    Some('t') => text.push('\t'),
                    Some('r') => text.push('\r'),
                    Some(&c) => text.push(c),
                    None => break,
                }
            }
            c => text.push(c),
        }
        i += 1;
    }
    Err("an unterminated string".to_owned())
}

const KEYWORDS: [&str; 14] = [
    "and", "or", "not", "in", "like", "regex", "where", "by", "with", "maxspan", "until", "true",
    "false", "null",
];

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    fields: BTreeSet<FieldPath>,
    stateful: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Name(n)) if n.eq_ignore_ascii_case(word))
    }

    fn take_word(&mut self, word: &str) -> bool {
        let found = self.word(word);
        self.at += usize::from(found);
        found
    }

    fn expect(&mut self, token: &Token) -> Result<(), String> {
        if self.peek() == Some(token) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected {token:?} at token {}", self.at))
        }
    }

    fn query(&mut self) -> Result<Predicate, String> {
        if self.word("sequence") || self.word("sample") || self.word("join") {
            self.at += 1;
            self.stateful = true;
            return self.correlation();
        }
        self.event_query()
    }

    /// `sequence [by …] [with maxspan=…] [q] [by …] … [until [q]]`, and `sample` alike: any
    /// event any part keeps.
    fn correlation(&mut self) -> Result<Predicate, String> {
        let mut parts = Vec::new();
        loop {
            match self.peek() {
                Some(Token::OpenBracket) => {
                    self.at += 1;
                    parts.push(self.event_query()?);
                    self.expect(&Token::CloseBracket)?;
                }
                Some(Token::Name(n))
                    if ["by", "with", "maxspan", "until", "runs"]
                        .iter()
                        .any(|k| n.eq_ignore_ascii_case(k)) =>
                {
                    let by = n.eq_ignore_ascii_case("by");
                    self.at += 1;
                    if by {
                        self.names()?;
                    }
                }
                // A missing event (`![…]`): what it matches decides the alert too.
                Some(Token::Op("!"))
                    if self.tokens.get(self.at + 1) == Some(&Token::OpenBracket) =>
                {
                    self.at += 1;
                }
                Some(Token::Op("=")) => {
                    self.at += 1;
                    self.at += usize::from(matches!(
                        self.peek(),
                        Some(Token::Number(_) | Token::Name(_))
                    ));
                }
                _ => break,
            }
        }
        if parts.is_empty() {
            return Err("a sequence without queries".to_owned());
        }
        Ok(Predicate::any(parts))
    }

    /// `field, field …` after `by`.
    fn names(&mut self) -> Result<(), String> {
        loop {
            match self.peek().cloned() {
                Some(Token::Name(n)) => {
                    self.at += 1;
                    self.fields.insert(FieldPath::new(n));
                }
                _ => return Err(format!("expected a field at token {}", self.at)),
            }
            if self.peek() != Some(&Token::Comma) {
                return Ok(());
            }
            self.at += 1;
        }
    }

    fn event_query(&mut self) -> Result<Predicate, String> {
        match self.peek() {
            Some(Token::Name(_) | Token::Text(_)) => self.at += 1,
            other => return Err(format!("expected an event category, found {other:?}")),
        }
        if !self.take_word("where") {
            return Err(format!("expected `where` at token {}", self.at));
        }
        self.or()
    }

    fn or(&mut self) -> Result<Predicate, String> {
        let mut parts = vec![self.and()?];
        while self.take_word("or") {
            parts.push(self.and()?);
        }
        Ok(Predicate::any(parts))
    }

    fn and(&mut self) -> Result<Predicate, String> {
        let mut parts = vec![self.not()?];
        while self.take_word("and") {
            parts.push(self.not()?);
        }
        Ok(Predicate::all(parts))
    }

    fn not(&mut self) -> Result<Predicate, String> {
        if self.take_word("not") || self.peek() == Some(&Token::Op("!")) {
            if self.peek() == Some(&Token::Op("!")) {
                self.at += 1;
            }
            self.not()?;
            return Ok(Predicate::Always);
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Predicate, String> {
        let left = self.operand()?;
        let field = match &left {
            Operand::Field(path) => Some(path.clone()),
            _ => None,
        };
        let negated = self.take_word("not");
        let op = match self.peek().cloned() {
            Some(Token::Op(op)) if ["==", "!=", ":", "<", "<=", ">", ">="].contains(&op) => {
                self.at += 1;
                op.to_owned()
            }
            Some(Token::Name(n))
                if ["in", "like", "regex"]
                    .iter()
                    .any(|k| n.eq_ignore_ascii_case(k)) =>
            {
                self.at += 1;
                // `in~`, `like~`, `regex~`: case-insensitive, which the tests are anyway.
                if self.peek() == Some(&Token::Op("~")) {
                    self.at += 1;
                }
                n.to_ascii_lowercase()
            }
            _ if negated => return Err(format!("expected an operator at token {}", self.at)),
            _ => return Ok(left.predicate()),
        };
        let right = if matches!(self.peek(), Some(Token::Open)) && op != "==" && op != "!=" {
            self.at += 1;
            let mut values = vec![self.operand()?];
            while self.peek() == Some(&Token::Comma) {
                self.at += 1;
                values.push(self.operand()?);
            }
            self.expect(&Token::Close)?;
            values
        } else {
            vec![self.operand()?]
        };
        let (Some(field), false) = (field, negated) else {
            return Ok(Predicate::Always);
        };
        let texts: Option<Vec<String>> = right.iter().map(Operand::text).collect();
        let Some(texts) = texts else {
            return Ok(Predicate::Always);
        };
        Ok(match op.as_str() {
            "==" | ":" | "in" | "like" => Predicate::any(texts.iter().map(|t| matches(&field, t))),
            _ => Predicate::Always,
        })
    }

    /// An operand, with any arithmetic on it (`length(x) - 1`), which makes it a computed value.
    fn operand(&mut self) -> Result<Operand, String> {
        let mut operand = self.atom()?;
        loop {
            match self.peek() {
                Some(Token::Op(op)) if ARITHMETIC.contains(op) => {
                    self.at += 1;
                    self.atom()?;
                }
                // `x -1` lexes as a negative number.
                Some(Token::Number(n)) if n.starts_with('-') => self.at += 1,
                _ => return Ok(operand),
            }
            operand = Operand::Other;
        }
    }

    fn atom(&mut self) -> Result<Operand, String> {
        match self.peek().cloned() {
            Some(Token::Open) => {
                self.at += 1;
                let inner = self.or()?;
                self.expect(&Token::Close)?;
                Ok(Operand::Condition(inner))
            }
            Some(Token::Text(t)) => {
                self.at += 1;
                Ok(Operand::Text(t))
            }
            Some(Token::Number(n)) => {
                self.at += 1;
                Ok(Operand::Text(n))
            }
            Some(Token::Name(n))
                if self.tokens.get(self.at + 1) == Some(&Token::Open)
                    || (self.tokens.get(self.at + 1) == Some(&Token::Op("~"))
                        && self.tokens.get(self.at + 2) == Some(&Token::Open)) =>
            {
                self.at += 1;
                self.at += usize::from(self.peek() == Some(&Token::Op("~")));
                self.call(&n)
            }
            Some(Token::Name(n))
                if ["true", "false", "null"]
                    .iter()
                    .any(|k| n.eq_ignore_ascii_case(k)) =>
            {
                self.at += 1;
                Ok(Operand::Other)
            }
            Some(Token::Name(n)) if !KEYWORDS.iter().any(|k| n.eq_ignore_ascii_case(k)) => {
                self.at += 1;
                let path = FieldPath::new(n);
                self.fields.insert(path.clone());
                Ok(Operand::Field(path))
            }
            other => Err(format!("unexpected {other:?} at token {}", self.at)),
        }
    }

    /// A function call; the fields it reads are recorded.
    fn call(&mut self, function: &str) -> Result<Operand, String> {
        self.expect(&Token::Open)?;
        let mut arguments = Vec::new();
        if self.peek() != Some(&Token::Close) {
            arguments.push(self.operand()?);
            while self.peek() == Some(&Token::Comma) {
                self.at += 1;
                arguments.push(self.operand()?);
            }
        }
        self.expect(&Token::Close)?;
        let function = function.to_ascii_lowercase();
        if let [Operand::Field(field), values @ ..] = arguments.as_slice()
            && ["startswith", "endswith", "stringcontains"].contains(&function.as_str())
            && !values.is_empty()
        {
            let texts: Option<Vec<String>> = values.iter().map(Operand::text).collect();
            if let Some(texts) = texts {
                return Ok(Operand::Condition(Predicate::any(
                    texts.iter().map(|t| matches(field, &format!("*{t}*"))),
                )));
            }
        }
        Ok(Operand::Other)
    }

    /// After a pipe: every name that is not a pipe command is a field.
    fn rest_fields(&mut self) {
        const PIPES: [&str; 5] = ["head", "tail", "filter", "unique", "count"];
        while let Some(token) = self.peek().cloned() {
            self.at += 1;
            if let Token::Name(n) = token
                && !PIPES.iter().any(|p| n.eq_ignore_ascii_case(p))
                && !KEYWORDS.iter().any(|k| n.eq_ignore_ascii_case(k))
            {
                self.fields.insert(FieldPath::new(n));
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Operand {
    Field(FieldPath),
    Text(String),
    Condition(Predicate),
    Other,
}

impl Operand {
    fn text(&self) -> Option<String> {
        match self {
            Self::Text(t) => Some(t.clone()),
            _ => None,
        }
    }

    /// The operand as a condition on its own: a boolean field or call, or a nested condition.
    fn predicate(&self) -> Predicate {
        match self {
            Self::Condition(p) => p.clone(),
            _ => Predicate::Always,
        }
    }
}

/// `field` equals `value` case-insensitively, or, for a pattern (`*`, `?`), contains each of its
/// literal parts; `true` for non-ASCII.
fn matches(field: &FieldPath, value: &str) -> Predicate {
    if !value.is_ascii() {
        return Predicate::Always;
    }
    let test = |op, value: &str| {
        Predicate::Field(FieldTest {
            field: field.clone(),
            op,
            values: vec![value.to_ascii_lowercase()],
            case_sensitive: false,
        })
    };
    if !value.contains(['*', '?']) {
        return test(MatchOp::Equals, value);
    }
    let parts: Vec<Predicate> = value
        .split(['*', '?'])
        .filter(|p| !p.is_empty())
        .map(|p| test(MatchOp::Contains, p))
        .collect();
    if parts.is_empty() {
        return Predicate::Field(FieldTest {
            field: field.clone(),
            op: MatchOp::Exists,
            values: Vec::new(),
            case_sensitive: false,
        });
    }
    Predicate::all(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(field: &str, op: MatchOp, value: &str) -> Predicate {
        Predicate::Field(FieldTest {
            field: field.into(),
            op,
            values: vec![value.into()],
            case_sensitive: false,
        })
    }

    fn fields(reads: &Reads) -> Vec<&str> {
        reads.fields.iter().map(FieldPath::as_str).collect()
    }

    #[test]
    fn an_event_query_keeps_events_by_its_tests() {
        let reads = read(
            r#"process where event.type == "start" and process.name : ("cmd.exe", "pwsh.exe")"#,
        )
        .unwrap();
        assert_eq!(fields(&reads), ["event.type", "process.name"]);
        assert!(!reads.stateful);
        assert_eq!(
            reads.prefilter,
            Predicate::all([
                test("event.type", MatchOp::Equals, "start"),
                Predicate::any([
                    test("process.name", MatchOp::Equals, "cmd.exe"),
                    test("process.name", MatchOp::Equals, "pwsh.exe"),
                ]),
            ])
        );
    }

    #[test]
    fn patterns_and_string_functions_need_their_literal_parts() {
        let reads = read(
            r#"file where file.path like~ "C:\\Users\\*\\AppData\\*.exe" or startsWith~(process.name, "PS")"#,
        )
        .unwrap();
        assert_eq!(
            reads.prefilter,
            Predicate::any([
                Predicate::all([
                    test("file.path", MatchOp::Contains, "c:\\users\\"),
                    test("file.path", MatchOp::Contains, "\\appdata\\"),
                    test("file.path", MatchOp::Contains, ".exe"),
                ]),
                test("process.name", MatchOp::Contains, "ps"),
            ])
        );
    }

    #[test]
    fn superset_what_cannot_be_bounded_is_true() {
        for query in [
            r#"process where process.name != "x""#,
            r#"process where not process.name == "x""#,
            r#"process where process.name not in ("a", "b")"#,
            r"process where process.pid > 4",
            r#"process where process.name regex "a.*""#,
            r"process where length(process.name) == 3",
            r#"process where process.name == "café""#,
            r"process where true",
        ] {
            let reads = read(query).unwrap();
            assert!(
                reads.prefilter.is_always(),
                "{query}: {:?}",
                reads.prefilter
            );
        }
    }

    #[test]
    fn sequences_and_pipes_correlate_and_keep_what_any_part_keeps() {
        let reads = read(
            r#"sequence by host.id, user.name with maxspan=1m
                 [authentication where event.outcome == "failure"]
                 [authentication where event.outcome == "success"]
               until [process where process.name == "logoff.exe"]"#,
        )
        .unwrap();
        assert!(reads.stateful);
        assert_eq!(
            fields(&reads),
            ["event.outcome", "host.id", "process.name", "user.name"]
        );
        assert!(matches!(reads.prefilter, Predicate::Any(_)));
        let piped = read(r#"process where process.name == "a" | head 5"#).unwrap();
        assert!(piped.stateful);
    }

    #[test]
    fn optional_and_quoted_field_names_are_fields() {
        let reads =
            read("process where ?process.parent.name == \"x\" and `odd name` == 1").unwrap();
        assert_eq!(fields(&reads), ["odd name", "process.parent.name"]);
    }

    #[test]
    fn arithmetic_missing_events_and_quoted_segments() {
        let reads = read(
            "sequence by host.id [any where a == \"x\"] ![any where b == \"y\"] \
             [any where length(c.`0`.d) - 1 > 2 and e -1 == 3]",
        )
        .unwrap();
        let fields: Vec<&str> = reads.fields.iter().map(FieldPath::as_str).collect();
        assert_eq!(fields, ["a", "b", "c.0.d", "e", "host.id"]);
        assert!(reads.prefilter.is_always(), "the third part keeps anything");
        let two = read("sequence [any where a == \"x\"] ![any where b == \"y\"]").unwrap();
        assert_eq!(
            two.prefilter,
            Predicate::any([
                test("a", MatchOp::Equals, "x"),
                test("b", MatchOp::Equals, "y")
            ])
        );
    }

    #[test]
    fn broken_queries_are_errors() {
        for query in [
            "process process.name == \"x\"",
            "process where process.name == \"x",
            "sequence by host.id",
            "process where (a == 1",
        ] {
            assert!(read(query).is_err(), "{query}");
        }
    }
}

//! The Search Processing Language of Splunk's saved searches, as the fields a search reads, a
//! superset pre-filter, and whether it reads the raw event or counts events.
//!
//! The base search (before the first pipe) keeps events by its terms: `field=value` (values
//! compare case-insensitively, `*` is a wildcard), `field!=value`, `field IN (…)`, `AND`
//! (implied between terms), `OR`, `NOT` and parentheses. A term becomes a superset test on the
//! event: equality, or that a pattern's literal parts are contained. These widen to `true`:
//! `NOT`, `!=` and comparisons (`>`, `<`), a bare term (it searches `_raw`, so the search reads
//! the raw event), non-ASCII values, and the fields Splunk keeps beside the event (`index`,
//! `sourcetype`, `host`, time modifiers, …). A number may match as a number (`4624.0`), so it
//! becomes a test that its digits are contained. The rest of the pipeline is not parsed: every
//! name in it may be a field the search reads, and a command that counts or joins events
//! (`stats`, `transaction`, `streamstats`, …) makes it stateful.
//!
//! What cannot be read fails closed: a macro left unexpanded (`` `name` ``), a subsearch
//! (`[…]`), a wildcard field name, `tstats`, data models and other generating commands may read
//! any field of any event.

use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};

/// What a search reads and which events it could match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reads {
    /// Every field the search names.
    pub(crate) fields: BTreeSet<FieldPath>,
    /// Why the search may read any field of any event, if it may.
    pub(crate) any_field: Option<&'static str>,
    /// Whether it searches or parses the raw event (`_raw`).
    pub(crate) raw: bool,
    /// A superset of the events it matches.
    pub(crate) prefilter: Predicate,
    /// Whether it counts or correlates events.
    pub(crate) stateful: bool,
}

impl Reads {
    fn opaque(why: &'static str) -> Self {
        Self {
            fields: BTreeSet::new(),
            any_field: Some(why),
            raw: true,
            prefilter: Predicate::Always,
            stateful: true,
        }
    }
}

/// Fields Splunk keeps beside the event, and time modifiers: a test on them bounds no event as
/// Sluice sees it.
const METADATA: [&str; 16] = [
    "index",
    "sourcetype",
    "source",
    "host",
    "eventtype",
    "tag",
    "splunk_server",
    "linecount",
    "punct",
    "_time",
    "_indextime",
    "earliest",
    "latest",
    "_index_earliest",
    "_index_latest",
    "timeformat",
];

/// Commands that count, join or order events across them.
const STATEFUL: [&str; 24] = [
    "stats",
    "eventstats",
    "streamstats",
    "sistats",
    "transaction",
    "timechart",
    "chart",
    "bin",
    "bucket",
    "dedup",
    "uniq",
    "head",
    "tail",
    "join",
    "append",
    "appendcols",
    "top",
    "rare",
    "delta",
    "accum",
    "autoregress",
    "anomalydetection",
    "cluster",
    "geostats",
];

/// Commands that make events of their own rather than filter the search's.
const GENERATING: [&str; 14] = [
    "tstats",
    "mstats",
    "datamodel",
    "inputlookup",
    "inputcsv",
    "from",
    "pivot",
    "multisearch",
    "rest",
    "metadata",
    "makeresults",
    "loadjob",
    "savedsearch",
    "dbinspect",
];

/// Commands that parse fields out of the raw event.
const RAW: [&str; 8] = [
    "rex", "regex", "spath", "kv", "extract", "xmlkv", "multikv", "erex",
];

/// Reads a search whose macros are expanded.
pub(crate) fn read(search: &str) -> Reads {
    let search = search.trim();
    if search.contains('`') {
        return Reads::opaque("a macro Sluice has no definition of");
    }
    if outside_quotes(search).contains('[') {
        return Reads::opaque("a subsearch, which Sluice does not run");
    }
    let mut reads = Reads {
        fields: BTreeSet::new(),
        any_field: None,
        raw: false,
        prefilter: Predicate::Always,
        stateful: false,
    };
    let commands = commands(search);
    // A search that starts with a pipe starts with a generating command.
    let (base, rest) = match commands.split_first() {
        Some((first, rest)) if !search.starts_with('|') => (first.trim(), rest),
        _ => ("", &commands[..]),
    };
    let base = strip_word(base, "search").unwrap_or(base);
    for command in rest {
        let word = command
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if GENERATING.contains(&word.as_str()) {
            return Reads::opaque("a generating command (`tstats`, a data model or a lookup)");
        }
        reads.stateful |= STATEFUL.contains(&word.as_str());
        reads.raw |= RAW.contains(&word.as_str());
        let filter = strip_word(command.trim(), "search").map(base_search);
        if let Some(Ok(filter)) = filter {
            reads.raw |= filter.raw;
            reads.fields.extend(filter.fields);
            if filter.any_field {
                reads.any_field = Some("a wildcard (`*`) or array (`{}`) field name");
            }
        } else {
            if outside_quotes(command).contains('*') {
                reads.any_field = Some("a wildcard (`*`) in a command after the base search");
            }
            reads.fields.extend(names(command, true));
        }
    }
    if let Ok(filter) = base_search(base) {
        reads.prefilter = filter.predicate;
        reads.raw |= filter.raw;
        reads.fields.extend(filter.fields);
        if filter.any_field {
            reads.any_field = Some("a wildcard (`*`) or array (`{}`) field name");
        }
    } else {
        reads.raw = true;
        reads.fields.extend(names(base, false));
    }
    reads.raw |= reads.fields.iter().any(|f| f.as_str() == "_raw");
    // `a{}.b` names the members of an array as Splunk extracts them, a path no record has.
    if reads.fields.iter().any(|f| f.as_str().contains(['{', '}'])) {
        reads.any_field = Some("a JSON array path (`{}`)");
    }
    reads
        .fields
        .retain(|f| !METADATA.contains(&f.as_str().to_ascii_lowercase().as_str()));
    reads
}

/// Whether `search` starts with a generating command (`| tstats …`), which may read anything
/// whatever its macros say.
pub(crate) fn generating(search: &str) -> bool {
    search
        .trim()
        .strip_prefix('|')
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|word| GENERATING.contains(&word.to_ascii_lowercase().as_str()))
}

/// `text` without its leading `word` (any case) and the whitespace after it.
fn strip_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let (first, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    first.eq_ignore_ascii_case(word).then(|| rest.trim_start())
}

/// `text` with every quoted part removed.
fn outside_quotes(text: &str) -> String {
    let mut out = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in text.chars() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            _ if !quoted => out.push(c),
            _ => {}
        }
    }
    out
}

/// The commands of a search: the text between pipes outside quotes.
fn commands(search: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quoted = false;
    let mut escaped = false;
    for c in search.chars() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            '|' if !quoted => {
                out.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(command) = out.last_mut() {
            command.push(c);
        }
    }
    out.retain(|c| !c.trim().is_empty());
    out
}

/// Every name in a command that may be a field: the words outside quotes that are not the
/// command itself (when `command` is), a function's name or a number. Keywords stay in: a field
/// may be called `count`.
pub(crate) fn names(text: &str, command: bool) -> BTreeSet<FieldPath> {
    let mut out = BTreeSet::new();
    let text = outside_quotes(text);
    let chars: Vec<char> = text.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_alphanumeric() || "_.:{}@".contains(c) {
            word.push(c);
            continue;
        }
        let next = chars[i..].iter().copied().find(|c| !c.is_whitespace());
        words.push((std::mem::take(&mut word), next == Some('(')));
    }
    words.push((word, false));
    words.retain(|(word, _)| !word.is_empty());
    for (word, function) in words.into_iter().skip(usize::from(command)) {
        if !function && !word.starts_with(|c: char| c.is_ascii_digit()) {
            out.insert(FieldPath::new(word.as_str()));
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    Comma,
    /// A comparison: `=`, `!=`, `<`, `<=`, `>`, `>=`.
    Op(&'static str),
    /// A word or value. `\\` and `\"` are resolved; any other backslash, whose meaning varies
    /// between Splunk's commands, became a `*`.
    Word {
        text: String,
        quoted: bool,
    },
}

fn lex(search: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = search.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        i += 1;
        let token = match c {
            c if c.is_whitespace() => continue,
            '(' => Token::Open,
            ')' => Token::Close,
            ',' => Token::Comma,
            '!' if chars.get(i) == Some(&'=') => {
                i += 1;
                Token::Op("!=")
            }
            '<' | '>' | '=' => {
                let equal = c != '=' && chars.get(i) == Some(&'=');
                i += usize::from(equal);
                Token::Op(match (c, equal) {
                    ('<', false) => "<",
                    ('<', true) => "<=",
                    ('>', false) => ">",
                    ('>', true) => ">=",
                    _ => "=",
                })
            }
            '"' => {
                let mut text = String::new();
                loop {
                    match chars.get(i) {
                        None => return Err("an unterminated quoted value".to_owned()),
                        Some('"') => break,
                        Some('\\') => {
                            i += 1;
                            text.push(escaped(chars.get(i).copied()));
                        }
                        Some(&c) => text.push(c),
                    }
                    i += 1;
                }
                i += 1;
                Token::Word { text, quoted: true }
            }
            _ => {
                i -= 1;
                let mut text = String::new();
                while let Some(&c) = chars.get(i) {
                    let operator = c == '!' && chars.get(i + 1) == Some(&'=');
                    if c.is_whitespace() || "()=,\"<>".contains(c) || operator {
                        break;
                    }
                    if c == '\\' {
                        i += 1;
                        text.push(escaped(chars.get(i).copied()));
                    } else {
                        text.push(c);
                    }
                    i += 1;
                }
                Token::Word {
                    text,
                    quoted: false,
                }
            }
        };
        tokens.push(token);
    }
    Ok(tokens)
}

/// The character an escape stands for: `\\` and `\"` stand for themselves, anything else for
/// any text (a wildcard), as Splunk reads it differently per command.
fn escaped(next: Option<char>) -> char {
    next.filter(|c| matches!(c, '\\' | '"')).unwrap_or('*')
}

/// What the terms of a base search keep.
struct Filter {
    predicate: Predicate,
    fields: BTreeSet<FieldPath>,
    raw: bool,
    any_field: bool,
}

fn base_search(base: &str) -> Result<Filter, String> {
    let tokens = lex(base)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        filter: Filter {
            predicate: Predicate::Always,
            fields: BTreeSet::new(),
            raw: false,
            any_field: false,
        },
    };
    if tokens.is_empty() {
        return Ok(parser.filter);
    }
    let predicate = parser.and()?;
    if let Some(token) = tokens.get(parser.at) {
        return Err(format!("unexpected {token:?}"));
    }
    parser.filter.predicate = predicate;
    Ok(parser.filter)
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    filter: Filter,
}

impl Parser<'_> {
    /// Whether the next token is the operator `word`, which Splunk only knows in capitals.
    fn word(&self, word: &str) -> bool {
        matches!(self.tokens.get(self.at), Some(Token::Word { text, quoted: false }) if text == word)
    }

    /// Terms side by side are an `AND`, as is the word itself. It binds loosest: in Splunk's
    /// search, `a b OR c` is `a AND (b OR c)`.
    fn and(&mut self) -> Result<Predicate, String> {
        let mut parts = vec![self.or()?];
        loop {
            if self.word("AND") {
                self.at += 1;
            } else if self.at >= self.tokens.len()
                || self.tokens.get(self.at) == Some(&Token::Close)
            {
                break;
            }
            parts.push(self.or()?);
        }
        Ok(Predicate::all(parts))
    }

    /// `OR` binds tighter than `AND`, and `NOT` tighter still.
    fn or(&mut self) -> Result<Predicate, String> {
        let mut parts = vec![self.not()?];
        while self.word("OR") {
            self.at += 1;
            parts.push(self.not()?);
        }
        Ok(Predicate::any(parts))
    }

    fn not(&mut self) -> Result<Predicate, String> {
        if self.word("NOT") {
            self.at += 1;
            self.not()?;
            return Ok(Predicate::Always);
        }
        self.term()
    }

    fn term(&mut self) -> Result<Predicate, String> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        match token {
            Some(Token::Open) => {
                let inner = self.and()?;
                if self.tokens.get(self.at) != Some(&Token::Close) {
                    return Err("an unclosed `(`".to_owned());
                }
                self.at += 1;
                Ok(inner)
            }
            Some(Token::Word { text, quoted }) => match self.tokens.get(self.at).cloned() {
                Some(Token::Op(op)) if !quoted => {
                    self.at += 1;
                    let value = self.value()?;
                    // A value written as a function (`CASE(Admin)`, `TERM(10.0.0.1)`) is matched
                    // as the function says, not as its name: only that the field has a value is
                    // known, and only for `=`.
                    if self.tokens.get(self.at) == Some(&Token::Open) {
                        self.group()?;
                        return Ok(match (op, self.field(&text)) {
                            ("=", Some(field)) => Predicate::present(field),
                            _ => Predicate::Always,
                        });
                    }
                    Ok(self.comparison(&text, op, &value))
                }
                Some(Token::Word {
                    text: within,
                    quoted: false,
                }) if !quoted && within == "IN" => {
                    self.at += 1;
                    let values = self.list()?;
                    Ok(self.within(&text, &values))
                }
                // `*` alone keeps every event (`search *`, the body of many filter macros).
                _ if text == "*" && !quoted => Ok(Predicate::Always),
                // A bare term (or a function such as `TERM(…)`) searches the raw event.
                _ => {
                    self.filter.raw = true;
                    Ok(Predicate::Always)
                }
            },
            other => Err(format!("unexpected {other:?}")),
        }
    }

    /// Skips a parenthesised group, nested ones included: a function's arguments.
    fn group(&mut self) -> Result<(), String> {
        let mut depth = 0usize;
        loop {
            let token = self.tokens.get(self.at).cloned();
            self.at += 1;
            match token {
                Some(Token::Open) => depth += 1,
                Some(Token::Close) if depth <= 1 => return Ok(()),
                Some(Token::Close) => depth -= 1,
                None => return Err("an unclosed `(`".to_owned()),
                Some(_) => {}
            }
        }
    }

    fn value(&mut self) -> Result<String, String> {
        match self.tokens.get(self.at).cloned() {
            Some(Token::Word { text, .. }) => {
                self.at += 1;
                Ok(text)
            }
            other => Err(format!("expected a value, found {other:?}")),
        }
    }

    fn list(&mut self) -> Result<Vec<String>, String> {
        if self.tokens.get(self.at) != Some(&Token::Open) {
            return Err("expected `(` after IN".to_owned());
        }
        self.at += 1;
        let mut values = Vec::new();
        loop {
            let token = self.tokens.get(self.at).cloned();
            self.at += 1;
            match token {
                Some(Token::Close) => return Ok(values),
                Some(Token::Comma) => {}
                Some(Token::Word { text, .. }) => values.push(text),
                other => return Err(format!("unexpected {other:?} in a list")),
            }
        }
    }

    /// The field a term tests, or `None` when the test cannot bound the event: metadata, a
    /// wildcard name (which may be any field) or an array path (`a{}.b`).
    fn field(&mut self, name: &str) -> Option<FieldPath> {
        if name.contains(['*', '{', '}']) {
            self.filter.any_field = true;
            return None;
        }
        if METADATA.contains(&name.to_ascii_lowercase().as_str()) {
            return None;
        }
        let path = FieldPath::new(name);
        self.filter.fields.insert(path.clone());
        Some(path)
    }

    fn comparison(&mut self, name: &str, op: &str, value: &str) -> Predicate {
        match (self.field(name), op) {
            (Some(field), "=") => matches(&field, value),
            _ => Predicate::Always,
        }
    }

    fn within(&mut self, name: &str, values: &[String]) -> Predicate {
        match self.field(name) {
            Some(field) => Predicate::any(values.iter().map(|v| matches(&field, v))),
            None => Predicate::Always,
        }
    }
}

/// A superset of `field=value`: equality, ignoring case; for a pattern (`*`), each of its
/// literal parts contained; for a number, its digits contained, as `4624` also matches `4624.0`
/// and `04624`; `exists` for `*` alone; `true` for non-ASCII values, whose case folding differs.
fn matches(field: &FieldPath, value: &str) -> Predicate {
    if !value.is_ascii() {
        return Predicate::Always;
    }
    let test = |op, values: Vec<String>| {
        Predicate::Field(FieldTest {
            field: field.clone(),
            op,
            values,
            case_sensitive: false,
        })
    };
    if crate::is_cidr(value) {
        return test(MatchOp::Exists, Vec::new());
    }
    if let Some(digits) = number(value) {
        // A number written with an exponent (`4.624e3`) holds no such digits.
        return test(MatchOp::Contains, vec![digits, "e".to_owned()]);
    }
    if !value.contains('*') {
        return test(MatchOp::Equals, vec![value.to_ascii_lowercase()]);
    }
    let parts: Vec<Predicate> = value
        .split('*')
        .filter(|p| !p.is_empty())
        .map(|p| test(MatchOp::Contains, vec![p.to_ascii_lowercase()]))
        .collect();
    if parts.is_empty() {
        return test(MatchOp::Exists, Vec::new());
    }
    Predicate::all(parts)
}

/// The significant digits of a value that is a number: without sign, leading zeros and
/// trailing fractional zeros. `None` for anything else.
fn number(value: &str) -> Option<String> {
    let unsigned = value.trim_start_matches(['+', '-']);
    if unsigned.is_empty()
        || unsigned == "."
        || unsigned.matches('.').count() > 1
        || !unsigned.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return None;
    }
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let whole = whole.trim_start_matches('0');
    let fraction = fraction.trim_end_matches('0');
    let digits = if fraction.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fraction}")
    };
    // Zero: every way to write it holds a `0`.
    Some(if digits.is_empty() {
        "0".to_owned()
    } else {
        digits
    })
}

#[cfg(test)]
mod tests;

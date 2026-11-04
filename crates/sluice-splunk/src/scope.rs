//! A search as the proof runs it: on the events of one evaluation in the proof's index, whatever
//! index, sourcetype, source or time range it names (ADR 0037).
//!
//! The reader widens the fields Splunk keeps beside an event to `true`, so a search applies to
//! every source; the proof runs it the same way. In the base search, in every `search` command
//! and in every subsearch, a test on such a field (`index=…`, `sourcetype IN (…)`, `source!=…`,
//! `eventtype=…`, `tag::host=…`, `sourcetype::…`) or a time modifier (`earliest=-24h`) is
//! replaced by what keeps the most events: `*` where it counts as it is, and a test no event
//! passes ([`NEVER`]) where a `NOT` turns it around. The base search, and every subsearch's,
//! gets the evaluation's scope in front (`index=<proof index> sluice_run::<n>`). Every other
//! command is left as it is: `where`, `eval` and the like compare such
//! fields as values, which detections rarely do; a test there keeps no more events in the
//! proof than in the SIEM, the same on full and forwarded events.

use self::lex::{Kind, Token, closing, lex, outside};

/// The fields Splunk keeps beside an event, and the time modifiers, by their lower-case names.
const METADATA: [&str; 24] = [
    "index",
    "sourcetype",
    "source",
    "host",
    "eventtype",
    "tag",
    "splunk_server",
    "splunk_server_group",
    "earliest",
    "latest",
    "_index_earliest",
    "_index_latest",
    "starttime",
    "endtime",
    "starttimeu",
    "endtimeu",
    "daysago",
    "hoursago",
    "minutesago",
    "monthsago",
    "searchtimespandays",
    "searchtimespanhours",
    "searchtimespanminutes",
    "timeformat",
];

/// A test no event passes: a field no event has. `NOT` of it keeps every event.
pub(crate) const NEVER: &str = "sluice_never=1";

/// Commands that write or send something (to an index, a lookup, a file, a mail server, an
/// alert action, a model) or run other searches: the proof never runs a search with one, so
/// that even a production Splunk given by mistake keeps its data.
const WRITES: [&str; 20] = [
    "collect",
    "summaryindex",
    "mcollect",
    "meventcollect",
    "tscollect",
    "outputlookup",
    "outputcsv",
    "outputtext",
    "sendemail",
    "sendalert",
    "sendresults",
    "delete",
    "script",
    "run",
    "runshellscript",
    "dump",
    "map",
    "fit",
    "deletemodel",
    "savedsearch",
];

/// Why the proof does not run a search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotRun {
    /// It starts with a generating command (`| tstats …`), which runs on Splunk's own data
    /// rather than the events.
    Generating,
    /// It has this command, which writes or sends something.
    Writes(&'static str),
}

impl std::fmt::Display for NotRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generating => f.write_str(
                "a generating command (such as `tstats`), which runs on Splunk's own data rather \
                 than the events",
            ),
            Self::Writes(command) => write!(
                f,
                "the command `{command}`, which writes or sends something: the proof never runs \
                 it"
            ),
        }
    }
}

/// `search` as the proof runs it in `scope` ([`unscoped`]), ending in a command that keeps each
/// event's id (`EVENT_FIELD`) on the rows that are events: Splunk returns only the fields a
/// search names, and an indexed field is no exception.
pub(crate) fn prepare(search: &str, scope: &str) -> Result<String, NotRun> {
    if let Some(command) = writes(search) {
        return Err(NotRun::Writes(command));
    }
    let spl = unscoped(search, scope).ok_or(NotRun::Generating)?;
    let id = crate::engine::EVENT_FIELD;
    Ok(format!("{spl} | eval {id}={id}"))
}

/// The first command of `search` that writes or sends something, subsearches included.
fn writes(search: &str) -> Option<&'static str> {
    let chars: Vec<char> = search.chars().collect();
    let (mut quoted, mut escaped) = (false, false);
    for (at, &c) in chars.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            '|' if !quoted => {
                let word: String = chars[at + 1..]
                    .iter()
                    .skip_while(|c| c.is_whitespace())
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                    .collect::<String>()
                    .to_ascii_lowercase();
                if let Some(&command) = WRITES.iter().find(|w| **w == word) {
                    return Some(command);
                }
            }
            _ => {}
        }
    }
    None
}

/// `search` as the proof runs it on the events `scope` selects (such as `index=p sluice_run::2`),
/// or `None` for a generating search (`| tstats …`), which runs on Splunk's own data rather than
/// the events.
pub(crate) fn unscoped(search: &str, scope: &str) -> Option<String> {
    let search = search.trim();
    if search.starts_with('|') {
        return None;
    }
    let commands = commands(search);
    let (base, rest) = commands
        .split_first()
        .map_or(("", &[][..]), |(b, r)| (*b, r));
    let base = base.trim();
    let base = strip_word(base, "search").unwrap_or(base);
    let mut out = format!("search {scope}");
    let filter = terms(base, scope);
    if !filter.is_empty() {
        out.push(' ');
        out.push_str(&filter);
    }
    for command in rest {
        let command = command.trim();
        out.push_str(" | ");
        match strip_word(command, "search") {
            Some(filter) => {
                out.push_str("search ");
                out.push_str(&terms(filter, scope));
            }
            None => out.push_str(&subsearches(command, scope)),
        }
    }
    Some(out)
}

/// Whether `name` is a field Splunk keeps beside the event or a time modifier.
fn is_metadata(name: &str) -> bool {
    METADATA.contains(&name.to_ascii_lowercase().as_str())
}

/// `text` without its leading `word` (any case) and the whitespace after it.
fn strip_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let (first, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    first.eq_ignore_ascii_case(word).then(|| rest.trim_start())
}

/// The commands of a search: the text between pipes outside quotes and subsearches.
fn commands(search: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c, top) in outside(search) {
        if top && c == '|' {
            out.push(&search[start..i]);
            start = i + 1;
        }
    }
    out.push(&search[start..]);
    out
}

/// `command` with each subsearch in it run in `scope` too.
fn subsearches(command: &str, scope: &str) -> String {
    let mut out = String::new();
    let mut copied = 0;
    let chars = outside(command);
    let mut at = 0;
    while let Some(&(open, c, top)) = chars.get(at) {
        at += 1;
        if !(top && c == '[') {
            continue;
        }
        let Some(close) = closing(&chars, at) else {
            break;
        };
        out.push_str(&command[copied..open]);
        out.push('[');
        out.push_str(&subsearch(&command[open + 1..chars[close].0], scope));
        out.push(']');
        copied = chars[close].0 + 1;
        at = close + 1;
    }
    out.push_str(&command[copied..]);
    out
}

/// A subsearch's content as the proof runs it; a generating one stays as it is.
fn subsearch(inner: &str, scope: &str) -> String {
    unscoped(inner, scope).unwrap_or_else(|| inner.to_owned())
}

/// The terms of a base search or `search` command, with every test on metadata replaced.
fn terms(text: &str, scope: &str) -> String {
    let Some(tokens) = lex(text) else {
        return text.to_owned();
    };
    let word = |t: &Token| match t.kind {
        Kind::Word { quoted: false } => Some(&text[t.start..t.end]),
        _ => None,
    };
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    // Whether each open parenthesis is under an odd number of `NOT`s, and whether a `NOT` is
    // waiting for its term.
    let mut levels = vec![false];
    let mut not = false;
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        let negated = levels.last().copied().unwrap_or(false) ^ not;
        match (token.kind, word(token)) {
            (_, Some("NOT")) => {
                not = !not;
                at += 1;
                continue;
            }
            (_, Some("AND" | "OR")) | (Kind::Comma | Kind::Op, _) => {
                at += 1;
                continue;
            }
            (Kind::Open, _) => levels.push(negated),
            (Kind::Close, _) => {
                if levels.len() > 1 {
                    levels.pop();
                }
            }
            (Kind::Sub, _) => edits.push((
                token.start,
                token.end,
                format!(
                    "[{}]",
                    subsearch(&text[token.start + 1..token.end - 1], scope)
                ),
            )),
            (Kind::Word { .. }, name) => {
                let last = term_end(&tokens, at, text);
                // `sourcetype::x` is a test too, and `tag::host=x` one on a field's tags.
                let tests = last > at || name.is_some_and(|n| n.contains("::"));
                let field = name.map(|n| n.split("::").next().unwrap_or(n));
                if tests && field.is_some_and(is_metadata) {
                    let with = if negated { NEVER } else { "*" };
                    edits.push((token.start, tokens[last].end, with.to_owned()));
                }
                at = last;
            }
        }
        not = false;
        at += 1;
    }
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, end, with) in edits {
        out.push_str(&text[copied..start]);
        out.push_str(&with);
        copied = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// The last token of the term that starts with the word at `at`: `field op value`, the value
/// perhaps a function (`CASE(x)`), `field IN (…)`, a function term (`TERM(x)`), or the word.
fn term_end(tokens: &[Token], at: usize, text: &str) -> usize {
    let kind = |i: usize| tokens.get(i).map(|t| t.kind);
    let adjacent_group =
        |i: usize| kind(i) == Some(Kind::Open) && tokens[i].start == tokens[i - 1].end;
    let group_end = |open: usize| {
        let mut depth = 0usize;
        for (i, t) in tokens.iter().enumerate().skip(open) {
            match t.kind {
                Kind::Open => depth += 1,
                Kind::Close if depth <= 1 => return i,
                Kind::Close => depth -= 1,
                _ => {}
            }
        }
        tokens.len() - 1
    };
    let is_in = tokens
        .get(at + 1)
        .is_some_and(|t| t.kind == (Kind::Word { quoted: false }) && &text[t.start..t.end] == "IN");
    match kind(at + 1) {
        Some(Kind::Op) if matches!(kind(at + 2), Some(Kind::Word { .. })) => {
            if adjacent_group(at + 3) {
                group_end(at + 3)
            } else {
                at + 2
            }
        }
        _ if is_in && kind(at + 2) == Some(Kind::Open) => group_end(at + 2),
        _ if adjacent_group(at + 1) => group_end(at + 1),
        _ => at,
    }
}

mod lex;
#[cfg(test)]
mod tests;

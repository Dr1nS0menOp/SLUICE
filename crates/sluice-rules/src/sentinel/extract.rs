//! What one analytics rule's KQL query reads (ADR 0015).

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};

use super::lexer::Token;

/// The Sentinel tables Sluice shapes records for (`shape` on a source), and what each query part
/// needs from them.
pub(super) const TABLES: [&str; 7] = [
    "SecurityEvent",
    "WindowsEvent",
    "Syslog",
    "CommonSecurityLog",
    "ASimNetworkSessionLogs",
    "ASimDnsActivityLogs",
    "ASimWebSessionLogs",
];

/// A field every record of the table has, which no other shape gives: `Syslog`,
/// `CommonSecurityLog` and ASIM rows come from any product, so a reference to the table is bounded to
/// records that have it.
pub(super) fn table_marker(table: &str) -> Option<&'static str> {
    match table {
        "Syslog" => Some("SyslogMessage"),
        "CommonSecurityLog" => Some("DeviceVendor"),
        "ASimNetworkSessionLogs" => Some("EventSchemaVersion"),
        "ASimDnsActivityLogs" => Some("DnsQuery"),
        "ASimWebSessionLogs" => Some("Url"),
        _ => None,
    }
}

/// Text columns rules filter on besides `EventID`: of `SecurityEvent` and `WindowsEvent`, and of
/// `Syslog`.
const TEXT_COLUMNS: [&str; 6] = [
    "EventSourceName",
    "Channel",
    "Provider",
    "Facility",
    "ProcessName",
    "SeverityLevel",
];

/// A test that `field` is present.
pub(super) fn present(field: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: FieldPath::new(field),
        op: MatchOp::Exists,
        values: Vec::new(),
        case_sensitive: true,
    })
}

/// Operators after which a query only aggregates, joins or orders rows over time.
const STATEFUL: [&str; 8] = [
    "summarize",
    "join",
    "make",
    "serialize",
    "scan",
    "evaluate",
    "lookup",
    "partition",
];

/// What a query reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reads {
    /// The Windows tables it references.
    pub(super) tables: BTreeSet<String>,
    /// Every identifier it names, and every column it names as a string
    /// (`column_ifexists('X', …)`, `['X']`): a superset of the columns it reads.
    pub(super) fields: BTreeSet<FieldPath>,
    /// It may read any column (`search`, `union *`, `pack_all`, an unknown function).
    pub(super) any_field: Option<String>,
    /// It may read Windows tables it does not name: through an ASIM parser or a workspace
    /// function whose source is not known.
    pub(super) any_table: bool,
    /// It aggregates or correlates rows.
    pub(super) stateful: bool,
    /// For each table reference, a superset of the rows it keeps.
    pub(super) prefilter: Predicate,
    /// Known functions (ASIM parsers whose source was read) it uses.
    pub(super) calls: BTreeSet<String>,
}

/// What `tokens` read. `known` says whether a name is a function whose source is available;
/// the caller resolves those (`Reads::calls`).
pub(super) fn reads(tokens: &[Token], known: &dyn Fn(&str) -> bool) -> Reads {
    let mut reads = Reads {
        tables: BTreeSet::new(),
        fields: BTreeSet::new(),
        any_field: None,
        any_table: false,
        stateful: false,
        prefilter: Predicate::never(),
        calls: BTreeSet::new(),
    };
    let local = let_names(tokens);
    let lists = id_lists(tokens);
    let shadowed = parameter_scopes(tokens);
    let mut prefilters = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let next = tokens.get(i + 1);
        let previous = i.checked_sub(1).and_then(|p| tokens.get(p));
        if let Token::Str(text) = token {
            if names_a_column(tokens, i) {
                reads.fields.insert(FieldPath::new(text.as_str()));
            }
            continue;
        }
        let Token::Ident(name) = token else { continue };
        reads.fields.insert(FieldPath::new(name.as_str()));
        if is_symbol(previous, ".") {
            continue;
        }
        if TABLES.contains(&name.as_str())
            && !is_symbol(next, "(")
            && !is_symbol(next, ":")
            && !shadowed
                .iter()
                .any(|(table, range)| table == name && range.contains(&i))
        {
            reads.tables.insert(name.clone());
            let rows = first_wheres(&tokens[i + 1..], &lists);
            prefilters.push(match table_marker(name) {
                Some(marker) => Predicate::all([present(marker), rows]),
                None => rows,
            });
        }
        if STATEFUL.contains(&name.as_str()) && is_symbol(previous, "|") {
            reads.stateful = true;
        }
        let wildcard_union = name == "union" && union_wildcard(&tokens[i + 1..]);
        if let Some(why) = any_field(name, previous, next, tokens.get(i + 2), wildcard_union) {
            // These read every table as well as every column.
            reads.any_table |= matches!(name.as_str(), "search" | "find" | "union" | "table");
            reads.any_field.get_or_insert(why);
        }
        if local.contains(name.as_str()) {
            continue;
        }
        if known(name) {
            reads.calls.insert(name.clone());
        } else if is_asim_parser(name) || unknown_function(name, next) {
            reads.any_table = true;
            reads.any_field.get_or_insert(format!(
                "uses `{name}`, a parser or function whose source is not known"
            ));
        }
    }
    reads.prefilter = Predicate::any(prefilters);
    reads
}

impl Reads {
    /// A query part that may read any column of any Windows table.
    pub(super) fn unknown(why: String) -> Self {
        Self {
            tables: BTreeSet::new(),
            fields: BTreeSet::new(),
            any_field: Some(why),
            any_table: true,
            stateful: false,
            prefilter: Predicate::Always,
            calls: BTreeSet::new(),
        }
    }

    /// Adds what a function the query uses reads: rows reach the query through it as well.
    pub(super) fn merge(&mut self, callee: Reads) {
        self.tables.extend(callee.tables);
        self.fields.extend(callee.fields);
        if self.any_field.is_none() {
            self.any_field = callee.any_field;
        }
        self.any_table |= callee.any_table;
        self.stateful |= callee.stateful;
        let own = std::mem::replace(&mut self.prefilter, Predicate::Always);
        self.prefilter = Predicate::any([own, callee.prefilter]);
    }
}

/// `let` names bound to `EventID` literals: `dynamic([…])`, `pack_array(…)` or one literal.
/// `None` for a name with any other definition. A name defined more than once gets every value
/// (a superset).
type Lists = BTreeMap<String, Option<Vec<String>>>;

fn id_lists(tokens: &[Token]) -> Lists {
    let mut lists = Lists::new();
    for (i, w) in tokens.windows(3).enumerate() {
        let [Token::Ident(l), Token::Ident(name), Token::Symbol(eq)] = w else {
            continue;
        };
        if l != "let" || eq != "=" {
            continue;
        }
        let values = literal_ids(&tokens[i + 3..]);
        let entry = lists
            .entry(name.clone())
            .or_insert_with(|| Some(Vec::new()));
        match (entry.as_mut(), values) {
            (Some(all), Some(values)) => all.extend(values),
            _ => *entry = None,
        }
    }
    lists
}

/// The literals of `dynamic([a, b])`, `pack_array(a, b)` or `a` followed by `;`.
fn literal_ids(rest: &[Token]) -> Option<Vec<String>> {
    let (start, close) = if is_ident(rest.first(), "dynamic")
        && is_symbol(rest.get(1), "(")
        && is_symbol(rest.get(2), "[")
    {
        (3, "]")
    } else if is_ident(rest.first(), "pack_array") && is_symbol(rest.get(1), "(") {
        (2, ")")
    } else {
        return (is_symbol(rest.get(1), ";") || rest.len() == 1)
            .then(|| event_id(rest.first()))
            .flatten()
            .map(|id| vec![id]);
    };
    let mut values = Vec::new();
    for token in &rest[start..] {
        match token {
            Token::Symbol(s) if s == "," => {}
            Token::Symbol(s) if s == close => return Some(values),
            other => values.push(event_id(Some(other))?),
        }
    }
    None
}

/// Lambda bodies in which a table name is a tabular parameter
/// (`let f = (SecurityEvent: (Col: string)) { SecurityEvent | … }`): there the name is the
/// argument, whose rows the caller filtered, not the table.
fn parameter_scopes(tokens: &[Token]) -> Vec<(&str, std::ops::Range<usize>)> {
    let mut scopes = Vec::new();
    for (p, token) in tokens.iter().enumerate() {
        let Token::Ident(name) = token else { continue };
        if !TABLES.contains(&name.as_str()) || !is_symbol(tokens.get(p + 1), ":") {
            continue;
        }
        let Some(params_end) = closing(tokens, p, ")") else {
            continue;
        };
        if !is_symbol(tokens.get(params_end + 1), "{") {
            continue;
        }
        if let Some(body_end) = closing(tokens, params_end + 2, "}") {
            scopes.push((name.as_str(), params_end + 1..body_end + 1));
        }
    }
    scopes
}

/// The index of the `close` symbol that ends the group `start` is in.
fn closing(tokens: &[Token], start: usize, close: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate().skip(start) {
        match token {
            Token::Symbol(s) if s == "(" || s == "[" || s == "{" => depth += 1,
            Token::Symbol(s) if s == ")" || s == "]" || s == "}" => {
                if depth == 0 {
                    return (s == close).then_some(i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// Names the query defines itself: `let Name = …`, and columns it assigns (`extend Name = …`,
/// `summarize Name = …`). Their meaning is part of the query, so they are not parsers.
fn let_names(tokens: &[Token]) -> BTreeSet<&str> {
    tokens
        .windows(2)
        .filter_map(|w| match w {
            [Token::Ident(name), Token::Symbol(eq)] if eq == "=" => Some(name.as_str()),
            _ => None,
        })
        .collect()
}

/// Whether the string at `i` names a column: the first argument of `column_ifexists` or
/// `columnifexists`, or a bracketed name (`['Column']`).
fn names_a_column(tokens: &[Token], i: usize) -> bool {
    let before = |n: usize| i.checked_sub(n).and_then(|p| tokens.get(p));
    let bracketed = is_symbol(before(1), "[") && is_symbol(tokens.get(i + 1), "]");
    let argument = is_symbol(before(1), "(")
        && (is_ident(before(2), "column_ifexists") || is_ident(before(2), "columnifexists"));
    bracketed || argument
}

/// Why the identifier at hand means the query may read any column, if it does.
fn any_field(
    name: &str,
    previous: Option<&Token>,
    next: Option<&Token>,
    after: Option<&Token>,
    wildcard_union: bool,
) -> Option<String> {
    let piped = is_symbol(previous, "|") || previous.is_none();
    let call = is_symbol(next, "(");
    match name {
        "search" if piped => Some("`search` reads every column".into()),
        "find" if piped => Some("`find` reads every column of every table".into()),
        "union" if wildcard_union => Some("a `union` with a wildcard reads every table".into()),
        "table" if call => Some("`table()` names its table at run time".into()),
        "pack_all" if call => Some("`pack_all()` reads every column".into()),
        "bag_pack" | "pack" if call && is_symbol(after, "*") => {
            Some("`pack(*)` reads every column".into())
        }
        _ => None,
    }
}

/// Whether a `union`'s own clause (up to the next `|` or `;` at its level) has a `*`: `union *`,
/// `union isfuzzy=true *`, or a table wildcard such as `Security*`. A `*` inside a nested query
/// is that query's arithmetic.
fn union_wildcard(after: &[Token]) -> bool {
    let mut depth = 0usize;
    for token in after {
        match token {
            Token::Symbol(s) if s == "(" || s == "[" || s == "{" => depth += 1,
            Token::Symbol(s) if s == ")" || s == "]" || s == "}" => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            Token::Symbol(s) if depth == 0 && (s == "|" || s == ";") => return false,
            Token::Symbol(s) if depth == 0 && s == "*" => return true,
            _ => {}
        }
    }
    false
}

/// Reads a watchlist, never a table.
const WATCHLIST: &str = "_GetWatchlist";

/// An ASIM parser (`imProcessCreate`, `_Im_Dns`, `ASimDns`, `_ASim_ProcessEvent`,
/// `vimProcessCreateMicrosoftSysmon`). They may be used without parentheses. `ASim…Logs` names
/// are tables and `ASimMatching…` names are fields ASIM parsers output, not parsers.
pub(super) fn is_asim_parser(name: &str) -> bool {
    ["_Im_", "_ASim_", "vim", "im", "ASim"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix))
        .is_some_and(|rest| {
            rest.starts_with(|c: char| c.is_ascii_uppercase())
                && !rest.ends_with("Logs")
                && !rest.starts_with("Matching")
        })
}

/// A call to a workspace function. KQL's own functions are lower case; a call with an
/// upper-case letter is a workspace function, whose body is not known here.
fn unknown_function(name: &str, next: Option<&Token>) -> bool {
    is_symbol(next, "(") && name != WATCHLIST && name.chars().any(|c| c.is_ascii_uppercase())
}
fn is_symbol(token: Option<&Token>, symbol: &str) -> bool {
    matches!(token, Some(Token::Symbol(s)) if s == symbol)
}

fn is_ident(token: Option<&Token>, ident: &str) -> bool {
    matches!(token, Some(Token::Ident(s)) if s == ident)
}

/// The conjunction of the `where` (or `filter`) clauses after a table reference, up to the first
/// operator that may change rows or the filtered columns: the rows that reference passes on.
/// Projections and `extend`s that leave `EventID` and the filtered text columns alone keep rows
/// as they are, so `where`s after them still filter the table's rows. Anything else keeps every
/// row from there on.
fn first_wheres(after: &[Token], lists: &Lists) -> Predicate {
    let mut conditions = Vec::new();
    let mut i = 0;
    while is_symbol(after.get(i), "|") {
        let operator = i + 1;
        if is_ident(after.get(operator), "where") || is_ident(after.get(operator), "filter") {
            let end = clause_end(after, operator + 1);
            conditions.push(condition(&after[operator + 1..end], lists));
            i = end;
        } else if let Some(start) = keeps_rows(after, operator) {
            i = clause_end(after, start);
        } else {
            break;
        }
    }
    Predicate::all(conditions)
}

/// If the operator at `at` keeps every row and every filtered column as it is, where its
/// arguments start.
fn keeps_rows(tokens: &[Token], at: usize) -> Option<usize> {
    let projection = is_ident(tokens.get(at), "project");
    let start = if projection && is_symbol(tokens.get(at + 1), "-") {
        let kind = tokens.get(at + 2);
        (is_ident(kind, "away") || is_ident(kind, "keep") || is_ident(kind, "reorder"))
            .then_some(at + 3)?
    } else if projection || is_ident(tokens.get(at), "extend") {
        at + 1
    } else {
        return None;
    };
    let clause = &tokens[start..clause_end(tokens, start)];
    let assigns_filtered = clause.windows(2).any(|w| {
        matches!(w, [Token::Ident(name), Token::Symbol(eq)]
            if eq == "=" && (name == "EventID" || TEXT_COLUMNS.contains(&name.as_str())))
    });
    let assigns = clause
        .iter()
        .any(|t| matches!(t, Token::Symbol(s) if s == "="));
    // A projection that computes columns may also rename one into a filtered name.
    let safe = if projection {
        !assigns
    } else {
        !assigns_filtered
    };
    safe.then_some(start)
}

/// The end of a clause: the next `|` or `;` at depth 0, or a closing parenthesis below it.
fn clause_end(tokens: &[Token], start: usize) -> usize {
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate().skip(start) {
        match token {
            Token::Symbol(s) if s == "(" || s == "[" => depth += 1,
            Token::Symbol(s) if s == ")" || s == "]" => {
                if depth == 0 {
                    return i;
                }
                depth -= 1;
            }
            Token::Symbol(s) if (s == "|" || s == ";") && depth == 0 => return i,
            _ => {}
        }
    }
    tokens.len()
}

/// A `where` condition as a superset over `EventID`: `and`, `or`, parentheses, `EventID == N`
/// and `EventID in (…)` are kept; every other part is `true`.
fn condition(tokens: &[Token], lists: &Lists) -> Predicate {
    let mut parser = Parser {
        tokens,
        at: 0,
        lists,
    };
    let parsed = parser.or();
    if parser.at == tokens.len() {
        parsed
    } else {
        Predicate::Always
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    lists: &'a Lists,
}

impl Parser<'_> {
    fn or(&mut self) -> Predicate {
        let mut parts = vec![self.and()];
        while is_ident(self.tokens.get(self.at), "or") {
            self.at += 1;
            parts.push(self.and());
        }
        Predicate::any(parts)
    }

    fn and(&mut self) -> Predicate {
        let mut parts = vec![self.atom()];
        while is_ident(self.tokens.get(self.at), "and") {
            self.at += 1;
            parts.push(self.atom());
        }
        Predicate::all(parts)
    }

    /// One comparison or a parenthesized group; anything else is consumed up to the next
    /// `and`/`or` at its level and read as `true`.
    fn atom(&mut self) -> Predicate {
        if is_symbol(self.tokens.get(self.at), "(") {
            self.at += 1;
            let inner = self.or();
            if is_symbol(self.tokens.get(self.at), ")") {
                self.at += 1;
                return inner;
            }
            self.skip_rest();
            return Predicate::Always;
        }
        if let Some(test) = self.event_id_test().or_else(|| self.text_test()) {
            return test;
        }
        self.skip_rest();
        Predicate::Always
    }

    /// `EventID == N` or `EventID in (N, …)` (also `in~`), if that is exactly what follows.
    fn event_id_test(&mut self) -> Option<Predicate> {
        let t = self.tokens;
        let at = self.at;
        if !is_ident(t.get(at), "EventID") {
            return None;
        }
        // `in~` lexes as `in` and `~`.
        let open = if is_symbol(t.get(at + 2), "~") {
            at + 3
        } else {
            at + 2
        };
        let values: Vec<String> = if is_symbol(t.get(at + 1), "==") {
            let values = self.ids(t.get(at + 2))?;
            self.at = at + 3;
            values
        } else if is_ident(t.get(at + 1), "in") && is_symbol(t.get(open), "(") {
            let mut values = Vec::new();
            let mut i = open + 1;
            loop {
                match t.get(i) {
                    Some(Token::Symbol(s)) if s == "," => {}
                    Some(Token::Symbol(s)) if s == ")" => break,
                    other => values.extend(self.ids(other)?),
                }
                i += 1;
            }
            self.at = i + 1;
            values
        } else {
            return None;
        };
        Some(Predicate::Field(FieldTest {
            field: FieldPath::new("EventID"),
            op: MatchOp::Equals,
            values,
            case_sensitive: true,
        }))
    }

    /// The `EventID`s a literal or a `let` list of literals denotes.
    fn ids(&self, token: Option<&Token>) -> Option<Vec<String>> {
        if let Some(Token::Ident(name)) = token {
            return self.lists.get(name).cloned().flatten();
        }
        event_id(token).map(|id| vec![id])
    }

    /// `Column == "text"` or `Column =~ "text"` on a known text column of the Windows tables.
    /// Only those columns: the same shape on a `let` variable is not a test on the record.
    fn text_test(&mut self) -> Option<Predicate> {
        let t = self.tokens;
        let at = self.at;
        let Some(Token::Ident(column)) = t.get(at) else {
            return None;
        };
        if !TEXT_COLUMNS.contains(&column.as_str()) {
            return None;
        }
        let case_sensitive = match t.get(at + 1) {
            Some(Token::Symbol(s)) if s == "==" => true,
            Some(Token::Symbol(s)) if s == "=~" => false,
            _ => return None,
        };
        let Some(Token::Str(value)) = t.get(at + 2) else {
            return None;
        };
        self.at = at + 3;
        Some(Predicate::Field(FieldTest {
            field: FieldPath::new(column.as_str()),
            op: MatchOp::Equals,
            values: vec![value.clone()],
            case_sensitive,
        }))
    }

    /// Skips to the next `and`/`or`/`)` at this level.
    fn skip_rest(&mut self) {
        let mut depth = 0usize;
        while let Some(token) = self.tokens.get(self.at) {
            match token {
                Token::Symbol(s) if s == "(" || s == "[" => depth += 1,
                Token::Symbol(s) if s == ")" || s == "]" => {
                    if depth == 0 {
                        return;
                    }
                    depth -= 1;
                }
                Token::Ident(s) if depth == 0 && (s == "and" || s == "or") => return,
                _ => {}
            }
            self.at += 1;
        }
    }
}

/// The `EventID` a literal denotes, as decimal text without leading zeros. `EventID` is an
/// `int` column, and KQL converts a string operand to `int` (`'4656'`, `' 4656'` and `'04656'`
/// all match 4656, checked in the Kusto emulator). Any other literal is not understood.
fn event_id(token: Option<&Token>) -> Option<String> {
    let text = match token? {
        Token::Number(n) => n.as_str(),
        Token::Str(s) => s.trim(),
        _ => return None,
    };
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().map(|n| n.to_string())
}

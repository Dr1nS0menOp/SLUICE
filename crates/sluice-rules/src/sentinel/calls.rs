//! Which names a query calls are workspace functions: whose source Sluice must read, or else
//! widen the rule.
//!
//! KQL's own functions are all lower case, and a call with an upper-case letter is a workspace
//! function. A lower-case one may be either: by its name, `now()` looks like a workspace
//! function called `now_or_never()`. [`KqlNames`] tells them apart. With rules fetched from the
//! workspace, every name that is not one of its functions is KQL's own. Without that, nothing
//! here can check: the Kusto emulator answers a call to a function it does not know with the
//! same `General_BadRequest` as any other mistake (docs/notes/sentinel-dcr.md), so the names are
//! listed as unchecked.

use super::lexer::Token;

/// Tells KQL's own functions from workspace functions by name, for lower-case calls.
pub trait KqlNames {
    /// Whether KQL itself defines a function called `name`. `Some(false)` makes the call one to a
    /// workspace function whose source is missing; `None` means it could not be checked.
    fn is_kql_function(&self, name: &str) -> Option<bool>;
}

/// Checks nothing: a lower-case call counts as KQL's own unless only a table can stand where it
/// is, and the report lists the names that were not checked.
#[derive(Debug, Clone, Copy, Default)]
pub struct UncheckedNames;

impl KqlNames for UncheckedNames {
    fn is_kql_function(&self, _: &str) -> Option<bool> {
        None
    }
}

/// For rules read with every function of their workspace (`sluice rules fetch sentinel`): a name
/// that is not one of those functions is KQL's own.
#[derive(Debug, Clone, Copy, Default)]
pub struct FetchedNames;

impl KqlNames for FetchedNames {
    fn is_kql_function(&self, _: &str) -> Option<bool> {
        Some(true)
    }
}

/// What a name the query uses is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    /// KQL's own, or no call at all.
    Kql,
    /// A workspace function or ASIM parser whose source is not among the files.
    Unknown,
    /// A lower-case call nothing could check, read as KQL's own.
    Unchecked,
}

/// Reads a watchlist, never a table.
const WATCHLIST: &str = "_GetWatchlist";

/// Words that stand before `(` in KQL's syntax without calling a function: operators, string
/// operators, literals of a type, and the tabular functions and operators that may start a
/// statement. Never names a workspace function can have, so nothing needs to ask about them.
const SYNTAX: [&str; 62] = [
    "and",
    "app",
    "as",
    "between",
    "bool",
    "by",
    "cluster",
    "contains",
    "contains_cs",
    "database",
    "datatable",
    "datetime",
    "decimal",
    "double",
    "dynamic",
    "endswith",
    "endswith_cs",
    "evaluate",
    "extend",
    "externaldata",
    "facet",
    "false",
    "filter",
    "find",
    "fork",
    "guid",
    "has",
    "has_all",
    "has_any",
    "has_cs",
    "hasprefix",
    "hasprefix_cs",
    "hassuffix",
    "hassuffix_cs",
    "in",
    "int",
    "join",
    "long",
    "lookup",
    "materialize",
    "matches",
    "not",
    "on",
    "or",
    "partition",
    "print",
    "project",
    "range",
    "real",
    "search",
    "startswith",
    "startswith_cs",
    "string",
    "summarize",
    "table",
    "timespan",
    "toscalar",
    "true",
    "typeof",
    "union",
    "view",
    "where",
];

/// Options whose value may stand before `(`: `join kind=inner (…)`, `union isfuzzy=true (…)`,
/// `hint.strategy=shuffle (…)`, `union withsource=SourceTable (…)`.
const OPTIONS: [&str; 6] = [
    "kind",
    "isfuzzy",
    "withsource",
    "strategy",
    "remote",
    "shufflekey",
];

/// Tabular functions and operators that may start a statement with `(`; any other lower-case
/// call there is a workspace function.
const TABULAR: [&str; 15] = [
    "range",
    "datatable",
    "print",
    "externaldata",
    "materialize",
    "cluster",
    "database",
    "workspace",
    "app",
    "table",
    "view",
    "union",
    "find",
    "search",
    "evaluate",
];

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

/// What `tokens[i]`, a name that is neither defined in the query nor among the files, is.
pub(super) fn classify(tokens: &[Token], i: usize, names: &dyn KqlNames) -> Call {
    let Some(Token::Ident(name)) = tokens.get(i) else {
        return Call::Kql;
    };
    let before = |n: usize| i.checked_sub(n).and_then(|p| tokens.get(p));
    let previous = before(1);
    if is_asim_parser(name) {
        return Call::Unknown;
    }
    let option_value =
        is_symbol(previous, "=") && OPTIONS.iter().any(|option| is_ident(before(2), option));
    if !is_symbol(tokens.get(i + 1), "(") || name == WATCHLIST || option_value {
        return Call::Kql;
    }
    if name.chars().any(|c| c.is_ascii_uppercase()) {
        return Call::Unknown;
    }
    // A plugin (`evaluate bag_unpack(…)`) and query parameters (`declare query_parameters(…)`).
    if SYNTAX.contains(&name.as_str())
        || is_ident(previous, "evaluate")
        || is_ident(previous, "declare")
    {
        return Call::Kql;
    }
    let tabular = is_ident(previous, "invoke") || previous.is_none() || is_symbol(previous, ";");
    match names.is_kql_function(name) {
        Some(true) => Call::Kql,
        Some(false) => Call::Unknown,
        None if tabular && !TABULAR.contains(&name.as_str()) => Call::Unknown,
        None => Call::Unchecked,
    }
}

pub(super) fn is_symbol(token: Option<&Token>, symbol: &str) -> bool {
    matches!(token, Some(Token::Symbol(s)) if s == symbol)
}

pub(super) fn is_ident(token: Option<&Token>, ident: &str) -> bool {
    matches!(token, Some(Token::Ident(s)) if s == ident)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::lexer;

    /// Knows every name but `my_parser`.
    struct Knows;

    impl KqlNames for Knows {
        fn is_kql_function(&self, name: &str) -> Option<bool> {
            Some(name != "my_parser")
        }
    }

    fn call(query: &str, name: &str, names: &dyn KqlNames) -> Call {
        let tokens = lexer::tokens(query);
        let i = tokens
            .iter()
            .position(|t| matches!(t, Token::Ident(n) if n == name))
            .expect("the name is in the query");
        classify(&tokens, i, names)
    }

    #[test]
    fn c3_a_lower_case_call_kql_does_not_know_is_a_workspace_function() {
        for query in [
            "let events = my_parser(); events",
            "SecurityEvent | join kind=inner (my_parser()) on Account",
            "union isfuzzy=true my_parser(), SecurityEvent",
            "SecurityEvent | where Account in (my_parser())",
        ] {
            assert_eq!(call(query, "my_parser", &Knows), Call::Unknown, "{query}");
            assert_eq!(
                call(query, "my_parser", &UncheckedNames),
                Call::Unchecked,
                "{query}"
            );
            assert_eq!(
                call(query, "my_parser", &FetchedNames),
                Call::Kql,
                "{query}"
            );
        }
        assert_eq!(call("let x = ago(1d); x", "ago", &Knows), Call::Kql);
    }

    #[test]
    fn c3_where_only_a_table_stands_an_unchecked_lower_case_call_is_a_workspace_function() {
        assert_eq!(
            call("my_parser() | take 1", "my_parser", &UncheckedNames),
            Call::Unknown
        );
        assert_eq!(
            call("T | invoke my_parser()", "my_parser", &UncheckedNames),
            Call::Unknown
        );
        assert_eq!(call("range(1, 5, 1)", "range", &UncheckedNames), Call::Kql);
    }

    #[test]
    fn syntax_options_and_plugins_are_no_calls_to_ask_about() {
        struct Refuses;
        impl KqlNames for Refuses {
            fn is_kql_function(&self, name: &str) -> Option<bool> {
                panic!("asked about {name}")
            }
        }
        for (query, name) in [
            ("T | join kind=inner (U) on A", "inner"),
            ("T | where A in (1, 2)", "in"),
            ("T | where A between (1 .. 2)", "between"),
            ("T | evaluate bag_unpack(x)", "bag_unpack"),
            (
                "declare query_parameters(d:timespan = 1d); T",
                "query_parameters",
            ),
            ("union withsource=SourceTable (T), (U)", "SourceTable"),
            ("T | extend x = dynamic([1])", "dynamic"),
        ] {
            assert_eq!(call(query, name, &Refuses), Call::Kql, "{query}");
        }
    }

    #[test]
    fn upper_case_calls_and_asim_parsers_are_workspace_functions_and_watchlists_are_not() {
        assert_eq!(
            call("MyParser() | take 1", "MyParser", &FetchedNames),
            Call::Unknown
        );
        assert_eq!(
            call("imDns | take 1", "imDns", &FetchedNames),
            Call::Unknown
        );
        assert_eq!(
            call(
                "_GetWatchlist('x') | take 1",
                "_GetWatchlist",
                &UncheckedNames
            ),
            Call::Kql
        );
    }
}

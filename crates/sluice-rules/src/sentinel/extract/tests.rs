//! What one query reads, function by function: each test pins down a decision that, broken,
//! either hides a read (fail-open) or reads more than the query does (lost savings).

use sluice_core::field::FieldPath;
use sluice_core::predicate::Predicate;

use super::super::lexer::tokens;
use super::*;

fn of(query: &str) -> Reads {
    reads(&tokens(query), &|_| false)
}

fn widened(query: &str) -> bool {
    of(query).any_field.is_some()
}

fn has_field(query: &str, field: &str) -> bool {
    of(query).fields.contains(&FieldPath::new(field))
}

#[test]
fn every_table_with_a_marker_is_bounded_by_it() {
    for (table, marker) in [
        ("Syslog", "SyslogMessage"),
        ("CommonSecurityLog", "DeviceVendor"),
        ("ASimNetworkSessionLogs", "EventSchemaVersion"),
        ("ASimDnsActivityLogs", "DnsQuery"),
        ("ASimWebSessionLogs", "Url"),
    ] {
        assert_eq!(table_marker(table), Some(marker));
        assert_eq!(of(table).prefilter, present(marker), "{table}");
    }
    assert_eq!(table_marker("SecurityEvent"), None);
    assert_eq!(table_marker("WindowsEvent"), None);
}

#[test]
fn c3_pack_of_a_star_reads_every_column_and_pack_of_names_does_not() {
    for query in [
        "SecurityEvent | extend all = pack(*)",
        "SecurityEvent | extend all = bag_pack(*)",
        "SecurityEvent | where EventID == 1 | extend b = bag_pack(*)",
    ] {
        assert!(widened(query), "{query}");
    }
    for query in [
        "SecurityEvent | extend b = bag_pack(\"a\", Account)",
        "SecurityEvent | extend b = pack(\"a\", Account) | extend c = 2 * 3",
        "SecurityEvent | extend pack = 1",
    ] {
        assert!(!widened(query), "{query}");
    }
}

#[test]
fn search_and_find_widen_only_as_operators() {
    assert!(widened("search \"mimikatz\""));
    assert!(widened("SecurityEvent | search \"x\""));
    assert!(widened("find \"x\""));
    assert!(widened("SecurityEvent | find \"x\""));
    assert!(!widened("SecurityEvent | where search == 1"));
    assert!(!widened("SecurityEvent | where find == 1"));
}

#[test]
fn table_and_pack_all_widen_only_as_calls() {
    assert!(widened("table(\"SecurityEvent\")"));
    assert!(widened("SecurityEvent | extend p = pack_all()"));
    assert!(!widened("SecurityEvent | where table == \"x\""));
    assert!(!widened("SecurityEvent | where pack_all == 1"));
}

#[test]
fn c3_a_union_clause_with_a_star_widens_and_arithmetic_after_it_does_not() {
    assert!(widened("union *"));
    assert!(widened("union isfuzzy=true *"));
    assert!(widened("union Security*"));
    assert!(widened("SecurityEvent | union withsource=T *"));
    assert!(!widened("union SecurityEvent, Syslog | extend x = 2 * 3"));
    assert!(!widened("union SecurityEvent; print x = 2 * 3"));
    assert!(!widened("union (SecurityEvent | extend x = 2 * 3)"));
}

#[test]
fn only_column_strings_are_fields() {
    assert!(has_field(
        "SecurityEvent | where column_ifexists(\"Col\", \"\") == 1",
        "Col"
    ));
    assert!(has_field(
        "SecurityEvent | where columnifexists(\"Old\", \"\") == 1",
        "Old"
    ));
    assert!(has_field(
        "SecurityEvent | extend v = ['My Column']",
        "My Column"
    ));
    assert!(!has_field(
        "SecurityEvent | where Account == \"SYSTEM\"",
        "SYSTEM"
    ));
    assert!(!has_field("SecurityEvent | where f(\"Arg\") == 1", "Arg"));
    assert!(!has_field("SecurityEvent | extend v = [\"x\", 1]", "x"));
    assert!(!has_field(
        "SecurityEvent | extend v = column_ifexists",
        "column_ifexists_arg"
    ));
}

#[test]
fn c3_a_function_that_may_read_any_table_passes_that_on() {
    let mut query = of("SecurityEvent | where EventID == 1");
    assert!(!query.any_table);
    query.merge(Reads::unknown("a parser".into()));
    assert!(query.any_table, "any_table is kept from the function");
    assert!(query.any_field.is_some());
    assert_eq!(query.prefilter, Predicate::Always);

    let mut stateful = of("SecurityEvent");
    stateful.merge(of("Syslog | summarize count() by Computer"));
    assert!(stateful.stateful);
    assert!(stateful.tables.contains("Syslog"));
}

#[test]
fn let_lists_of_literals_bound_event_ids() {
    let ids = |query: &str| format!("{:?}", of(query).prefilter);
    let both = ids("let x = dynamic([4624, 4625]); SecurityEvent | where EventID in (x)");
    assert!(both.contains("4624") && both.contains("4625"), "{both}");
    let packed = ids("let x = pack_array(4624); SecurityEvent | where EventID in (x)");
    assert!(packed.contains("4624"), "{packed}");
    let one = ids("let x = 4624; SecurityEvent | where EventID == x");
    assert!(one.contains("4624"), "{one}");
}

#[test]
fn c3_a_let_that_is_not_a_plain_literal_list_does_not_bound() {
    for query in [
        "let x = dynamic([4624, f()]); SecurityEvent | where EventID in (x)",
        "let x = 4624 + 1; SecurityEvent | where EventID == x",
        "let x = dynamic([4624; SecurityEvent | where EventID in (x)",
        "let x = pack_array(4624; SecurityEvent | where EventID in (x)",
        "let x = dynamic({\"a\": 1}); SecurityEvent | where EventID in (x)",
        "let x = toscalar(T | take 1); SecurityEvent | where EventID == x",
    ] {
        let prefilter = of(query).prefilter;
        assert!(
            !format!("{prefilter:?}").contains("4624") || prefilter == Predicate::Always,
            "{query}: {prefilter:?}"
        );
        assert!(
            prefilter == Predicate::Always || !format!("{prefilter:?}").contains("Equals"),
            "{query} must not bound EventID: {prefilter:?}"
        );
    }
}

#[test]
fn literal_ids_reads_exactly_its_forms() {
    let ids = |text: &str| literal_ids(&tokens(text));
    assert_eq!(ids("dynamic([1, 2])"), Some(vec!["1".into(), "2".into()]));
    assert_eq!(ids("pack_array(3)"), Some(vec!["3".into()]));
    assert_eq!(ids("4"), Some(vec!["4".into()]));
    assert_eq!(ids("4;"), Some(vec!["4".into()]));
    assert_eq!(ids("4 + 1"), None);
    assert_eq!(ids("dynamic(1)"), None);
    assert_eq!(ids("dynamic[1]"), None);
    assert_eq!(ids("pack_array[1]"), None);
    assert_eq!(ids("dynamic([1, 2)"), None, "unclosed");
    assert_eq!(ids("dynamic([1, x])"), None);
}

#[test]
fn a_table_parameter_of_a_lambda_is_not_the_table() {
    let query = "let f = (SecurityEvent: (EventID: int)) { SecurityEvent | where EventID == 1 }; \
                 f(Syslog)";
    let r = of(query);
    assert!(!r.tables.contains("SecurityEvent"), "{:?}", r.tables);
    assert!(r.tables.contains("Syslog"));
    let after = "let f = (SecurityEvent: (EventID: int)) { SecurityEvent | take 1 }; \
                 SecurityEvent | where EventID == 2";
    assert!(
        of(after).tables.contains("SecurityEvent"),
        "outside the body it is the table"
    );
}

#[test]
fn closing_finds_the_matching_symbol_at_its_level() {
    let t = tokens("( a ( b ) [ c ] { d } ) e");
    assert_eq!(closing(&t, 1, ")"), Some(t.len() - 2));
    assert_eq!(closing(&t, 1, "]"), None, "the group ends with `)`");
    let square = tokens("[ a ( b ) ]");
    assert_eq!(closing(&square, 1, "]"), Some(square.len() - 1));
    let brace = tokens("{ a [ b ] }");
    assert_eq!(closing(&brace, 1, "}"), Some(brace.len() - 1));
}

#[test]
fn union_wildcard_looks_only_at_its_own_clause() {
    let wild = |text: &str| union_wildcard(&tokens(text));
    assert!(wild("*"));
    assert!(wild("kind=outer T*"));
    assert!(!wild("A, B"));
    assert!(!wild("A | extend x = 2 * 3"));
    assert!(!wild("A; print 2 * 3"));
    assert!(!wild("(A | extend x = 2 * 3)"));
    assert!(!wild("[1 * 2]"));
    assert!(!wild("{1 * 2}"));
    assert!(!wild(") * 2"), "the union's own group ended");
}

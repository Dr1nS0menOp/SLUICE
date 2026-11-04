use super::*;

fn run(search: &str) -> String {
    unscoped(search, "index=P").expect("a search with a base search")
}

#[test]
fn the_base_search_runs_on_the_proof_index_whatever_index_it_names() {
    assert_eq!(
        run("index=win EventCode=4625"),
        "search index=P * EventCode=4625"
    );
    assert_eq!(run("search index=win a=1"), "search index=P * a=1");
    assert_eq!(run("EventCode=4625"), "search index=P EventCode=4625");
    assert_eq!(run(""), "search index=P");
    assert_eq!(run("index IN (a, b) user=x"), "search index=P * user=x");
    assert_eq!(run("index!=_internal a"), "search index=P * a");
    assert_eq!(run("index::win a"), "search index=P * a");
}

#[test]
fn every_test_on_what_splunk_keeps_beside_the_event_keeps_every_event() {
    assert_eq!(
        run("(index=a OR index=b) sourcetype=\"Xml Win\" source=*Security user=x"),
        "search index=P (* OR *) * * user=x"
    );
    assert_eq!(
        run("eventtype=wineventlog_security earliest=-24h@h latest=now a=1"),
        "search index=P * * * a=1"
    );
    assert_eq!(run("Sourcetype=X host=web01 a"), "search index=P * * a");
    assert_eq!(
        run("sourcetype::XmlWinEventLog a=1"),
        "search index=P * a=1"
    );
    assert_eq!(run("tag::host=web a"), "search index=P * a");
    assert_eq!(run("tag=authentication a"), "search index=P * a");
    // A value written as a function is part of the test.
    assert_eq!(run("source=CASE(Foo) x"), "search index=P * x");
    assert_eq!(run("_index_earliest=-1h a"), "search index=P * a");
}

#[test]
fn under_not_a_test_on_metadata_keeps_every_event_too() {
    // `NOT eventtype=x` keeps nothing in a Splunk without that event type; replaced by a test no
    // event passes, its `NOT` keeps every event.
    assert_eq!(
        run("NOT sourcetype=x user=y"),
        format!("search index=P NOT {NEVER} user=y")
    );
    assert_eq!(
        run("NOT (eventtype=x OR user=y) z"),
        format!("search index=P NOT ({NEVER} OR user=y) z")
    );
    assert_eq!(run("NOT NOT source=x a"), "search index=P NOT NOT * a");
    assert_eq!(
        run("NOT (a=1 NOT (index=x))"),
        "search index=P NOT (a=1 NOT (*))"
    );
    // A `NOT` covers only its term.
    assert_eq!(run("NOT a=1 sourcetype=x"), "search index=P NOT a=1 *");
}

#[test]
fn field_tests_raw_terms_and_quotes_stay_as_they_are() {
    for base in [
        "EventCode=4625 user=\"index=x\"",
        "\"index=foo\" bar",
        "a>5 b<=3 c!=d e==f",
        "TERM(10.0.0.1) CASE(Admin)",
        "Image=\"*\\\\rundll32.exe\" OR (x IN (1, 2) y)",
        "indexed=1 sourcetypes=2 hostname=3",
        "index",
        "NOT host",
    ] {
        assert_eq!(run(base), format!("search index=P {base}"), "{base}");
    }
}

#[test]
fn search_commands_are_unscoped_and_other_commands_left_alone() {
    assert_eq!(
        run("a=1 | search sourcetype=x b=2 | stats count by host, sourcetype"),
        "search index=P a=1 | search * b=2 | stats count by host, sourcetype"
    );
    assert_eq!(
        run("a=1 | where sourcetype=\"x\" | eval index=\"y\""),
        "search index=P a=1 | where sourcetype=\"x\" | eval index=\"y\""
    );
    assert_eq!(
        run("a=\"x|y\" | stats count"),
        "search index=P a=\"x|y\" | stats count"
    );
    assert_eq!(run("a=1 | search"), "search index=P a=1 | search ");
}

#[test]
fn subsearches_run_on_the_proof_index_too() {
    assert_eq!(
        run("a=1 | join user [search index=x sourcetype=y | fields user]"),
        "search index=P a=1 | join user [search index=P * * | fields user]"
    );
    assert_eq!(
        run("a=1 [search index=x | fields user]"),
        "search index=P a=1 [search index=P * | fields user]"
    );
    assert_eq!(
        run("a=1 NOT [index=x | fields user]"),
        "search index=P a=1 NOT [search index=P * | fields user]"
    );
    // A generating subsearch runs on Splunk's own data.
    assert_eq!(
        run("a=1 [| inputlookup users.csv | fields user]"),
        "search index=P a=1 [| inputlookup users.csv | fields user]"
    );
    assert_eq!(
        run("a=1 | append [search index=x \"]\" | head 1]"),
        "search index=P a=1 | append [search index=P * \"]\" | head 1]"
    );
}

#[test]
fn a_generating_search_is_not_run() {
    assert_eq!(unscoped("| tstats count from datamodel=X", "P"), None);
    assert_eq!(unscoped("  | inputlookup x.csv", "P"), None);
    assert_eq!(
        prepare("| tstats count", "index=P"),
        Err(NotRun::Generating)
    );
}

#[test]
fn every_search_the_proof_runs_keeps_the_event_ids_of_its_rows() {
    assert_eq!(
        prepare(
            "index=a EventCode=1 | stats count by User",
            "index=P sluice_run::2"
        )
        .unwrap(),
        "search index=P sluice_run::2 * EventCode=1 | stats count by User | eval sluice_event=sluice_event"
    );
}

#[test]
fn a_search_that_writes_or_sends_is_never_run() {
    for (search, command) in [
        ("a=1 | collect index=summary", "collect"),
        ("a=1 | stats count | OutputLookup x.csv", "outputlookup"),
        ("a=1 | sendemail to=x@example.com", "sendemail"),
        ("a=1 |delete", "delete"),
        ("a=1 [search b=1 | outputcsv x] | table a", "outputcsv"),
        ("a=1 | map search=\"search b=$a$\"", "map"),
        ("| savedsearch other", "savedsearch"),
    ] {
        assert_eq!(
            prepare(search, "index=P"),
            Err(NotRun::Writes(command)),
            "{search}"
        );
    }
    // Only as a command: a word or a quoted value is no command.
    for search in [
        "collect=1 delete",
        "a=\"x | collect y\"",
        "a=1 | eval run=1",
        "a=1 | stats count by mapping",
    ] {
        assert!(prepare(search, "index=P").is_ok(), "{search}");
    }
}

#[test]
fn what_cannot_be_lexed_is_left_for_splunk_to_refuse() {
    assert_eq!(run("a=\"x"), "search index=P a=\"x");
    assert_eq!(run("a=1 [search b=2"), "search index=P a=1 [search b=2");
    assert_eq!(run("index="), "search index=P index=");
}

#[test]
fn non_ascii_text_survives_the_rewrite() {
    assert_eq!(
        run("user=\"Jürgen\" sourcetype=ü källa=1"),
        "search index=P user=\"Jürgen\" * källa=1"
    );
}

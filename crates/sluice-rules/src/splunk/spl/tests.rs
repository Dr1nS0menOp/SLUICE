use super::*;

fn test(field: &str, op: MatchOp, values: &[&str]) -> Predicate {
    Predicate::Field(FieldTest {
        field: FieldPath::new(field),
        op,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: false,
    })
}

fn fields(reads: &Reads) -> Vec<&str> {
    reads.fields.iter().map(FieldPath::as_str).collect()
}

#[test]
fn field_terms_become_tests_ignoring_case() {
    let reads = read(r#"Image="*\\Rundll32.EXE" User=SYSTEM"#);
    assert_eq!(
        reads.prefilter,
        Predicate::all([
            test("Image", MatchOp::Contains, &["\\rundll32.exe"]),
            test("User", MatchOp::Equals, &["system"]),
        ])
    );
    assert_eq!(fields(&reads), ["Image", "User"]);
    assert!(!reads.raw);
    assert!(!reads.stateful);
    assert_eq!(reads.any_field, None);
}

#[test]
fn c3_a_value_written_as_a_function_needs_only_its_field() {
    // `CASE(Admin)` matches `Admin` with its case, not the word `case`.
    let reads = read("user=CASE(Admin) action=success");
    assert_eq!(
        reads.prefilter,
        Predicate::all([
            Predicate::present(FieldPath::new("user")),
            test("action", MatchOp::Equals, &["success"]),
        ])
    );
    assert_eq!(fields(&reads), ["action", "user"]);
    assert_eq!(read("user!=TERM(x)").prefilter, Predicate::Always);
}

#[test]
fn or_in_and_parentheses_keep_their_structure() {
    let reads = read("(a=1 OR b IN (x, \"y z\")) AND c=*");
    assert_eq!(
        reads.prefilter,
        Predicate::all([
            Predicate::any([
                test("a", MatchOp::Contains, &["1", "e"]),
                test("b", MatchOp::Equals, &["x"]),
                test("b", MatchOp::Equals, &["y z"]),
            ]),
            test("c", MatchOp::Exists, &[]),
        ])
    );
}

#[test]
fn or_binds_tighter_than_and_as_in_splunk() {
    let equals = |field, value| test(field, MatchOp::Equals, &[value]);
    assert_eq!(
        read("a=x b=y OR c=z").prefilter,
        Predicate::all([
            equals("a", "x"),
            Predicate::any([equals("b", "y"), equals("c", "z")]),
        ])
    );
    assert_eq!(
        read("a=x OR b=y AND c=z").prefilter,
        Predicate::all([
            Predicate::any([equals("a", "x"), equals("b", "y")]),
            equals("c", "z"),
        ])
    );
}

#[test]
fn numbers_match_as_numbers() {
    let reads = read("EventCode=04624.50");
    assert_eq!(
        reads.prefilter,
        test("EventCode", MatchOp::Contains, &["4624.5", "e"])
    );
    assert_eq!(
        read("x=0").prefilter,
        test("x", MatchOp::Contains, &["0", "e"])
    );
}

#[test]
fn negations_comparisons_and_metadata_widen() {
    for search in [
        "NOT a=1",
        "a!=1",
        "a>1",
        "index=main sourcetype=XmlWinEventLog earliest=-24h",
        "a=\"ünïcode\"",
    ] {
        assert_eq!(read(search).prefilter, Predicate::Always, "{search}");
    }
    assert!(read("index=main").fields.is_empty());
}

#[test]
fn a_bare_term_reads_the_raw_event() {
    let reads = read("mimikatz a=1");
    assert!(reads.raw);
    assert_eq!(reads.prefilter, test("a", MatchOp::Contains, &["1", "e"]));
    // Lower-case operators are terms too.
    assert!(read("a=1 or b=2").raw);
    assert!(read("a in (1, 2)").raw);
}

#[test]
fn an_unclear_escape_is_a_wildcard() {
    assert_eq!(
        read(r#"p="C:\Windows""#).prefilter,
        Predicate::all([
            test("p", MatchOp::Contains, &["c:"]),
            test("p", MatchOp::Contains, &["indows"]),
        ])
    );
    assert_eq!(
        read(r#"p="say \"hi\"""#).prefilter,
        test("p", MatchOp::Equals, &["say \"hi\""])
    );
}

#[test]
fn the_pipeline_names_fields_and_counting_commands_make_it_stateful() {
    let reads = read(
        "EventCode=4625 | eval user=lower(TargetUserName) | stats count by user, IpAddress \
         | where count > 5",
    );
    assert!(reads.stateful);
    assert_eq!(
        fields(&reads),
        [
            "EventCode",
            "IpAddress",
            "TargetUserName",
            "by",
            "count",
            "user"
        ]
    );
    assert!(!fields(&reads).contains(&"lower"));
}

#[test]
fn a_later_search_command_is_read_as_a_filter_for_its_fields() {
    let reads = read("a=1 | search CommandLine=\"*-enc*\" | table a");
    assert_eq!(reads.any_field, None);
    assert!(fields(&reads).contains(&"CommandLine"));
}

#[test]
fn a_wildcard_after_the_base_search_may_read_any_field() {
    assert!(read("a=1 | table *").any_field.is_some());
    assert!(read("a=1 | fields - b*").any_field.is_some());
}

#[test]
fn rex_and_raw_read_the_raw_event() {
    assert!(read(r#"a=1 | rex "user=(?<u>\w+)""#).raw);
    assert!(read("a=1 | eval l=len(_raw)").raw);
}

#[test]
fn what_cannot_be_read_may_read_any_field_of_any_event() {
    for search in [
        "`sysmon` EventCode=1",
        "a=1 [search b=2 | fields c]",
        "| tstats count from datamodel=Endpoint.Processes by Processes.user",
        "a=1 | inputlookup x.csv",
    ] {
        let reads = read(search);
        assert!(reads.any_field.is_some(), "{search}");
        assert!(reads.stateful && reads.raw, "{search}");
        assert_eq!(reads.prefilter, Predicate::Always, "{search}");
    }
}

#[test]
fn wildcard_and_array_field_names_may_read_any_field() {
    for search in ["Event*=1", "a{}.b=1", "a=1 | table c{}.d"] {
        assert!(read(search).any_field.is_some(), "{search}");
    }
    // The base search still bounds the events.
    assert_eq!(
        read("a=1 | table c{}.d").prefilter,
        test("a", MatchOp::Contains, &["1", "e"])
    );
}

#[test]
fn a_base_search_that_cannot_be_parsed_matches_everything() {
    let reads = read("a=1 b=\"open");
    assert_eq!(reads.prefilter, Predicate::Always);
    assert!(reads.raw);
    assert!(fields(&reads).contains(&"a"));
}

#[test]
fn the_leading_search_command_is_the_base_search() {
    assert_eq!(
        read("search a=x").prefilter,
        test("a", MatchOp::Equals, &["x"])
    );
}

#[test]
fn pipes_and_brackets_in_quotes_are_text() {
    assert_eq!(commands(r#"a="x|y" | b"#), [r#"a="x|y" "#, " b"]);
    assert_eq!(commands(r#"a="x\"|y" | b"#), [r#"a="x\"|y" "#, " b"]);
    assert_eq!(commands(r"a=x\|y | b"), [r"a=x\|y ", " b"]);
    assert_eq!(outside_quotes(r#"a "b[c" d"#), "a  d");
    assert_eq!(outside_quotes(r#"a "x\"[" b"#), "a  b");
    assert_eq!(outside_quotes(r"a \[ b"), r"a  b");
    // A bracket in a quoted value is no subsearch.
    assert_eq!(read(r#"a="[x]""#).any_field, None);
}

#[test]
fn every_command_that_parses_the_raw_event_reads_it() {
    for command in [
        "rex", "regex", "spath", "kv", "extract", "xmlkv", "multikv", "erex",
    ] {
        assert!(read(&format!("a=1 | {command} field=b")).raw, "{command}");
    }
    assert!(!read("a=1 | eval b=c").raw);
}

#[test]
fn c3_a_network_matches_every_address_in_it() {
    assert_eq!(
        matches(&FieldPath::new("src"), "10.0.0.0/8"),
        test("src", MatchOp::Exists, &[])
    );
}

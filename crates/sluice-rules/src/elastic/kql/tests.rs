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
    // A nested query keeps what its inner query on the full paths keeps.
    assert_eq!(
        read("user : { name : root }").unwrap().prefilter,
        contains("user.name", "root")
    );
    for query in ["not user.name : root", "process.name : café"] {
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
fn the_query_is_what_kibana_gives_elasticsearch() {
    use serde_json::json;
    let dsl = |q: &str| read(q).unwrap().dsl;
    assert_eq!(
        dsl(r#"event.code : "4624" and not user.name : root"#),
        json!({"bool": {"filter": [
            {"match_phrase": {"event.code": "4624"}},
            {"bool": {"must_not": [{"match": {"user.name": {"query": "root", "lenient": true}}}]}},
        ]}})
    );
    assert_eq!(
        dsl("process.name : (cmd.exe or pwsh.exe)"),
        json!({"bool": {"should": [
            {"match": {"process.name": {"query": "cmd.exe", "lenient": true}}},
            {"match": {"process.name": {"query": "pwsh.exe", "lenient": true}}},
        ], "minimum_should_match": 1}})
    );
    assert_eq!(
        dsl("file.path : C\\:\\\\Temp\\\\*"),
        json!({"query_string": {"fields": ["file.path"], "query": "C\\:\\\\Temp\\\\*",
                                "analyze_wildcard": true, "lenient": true}})
    );
    assert_eq!(
        dsl("process.parent.name : * and event.severity >= 3"),
        json!({"bool": {"filter": [
            {"exists": {"field": "process.parent.name"}},
            {"range": {"event.severity": {"gte": "3"}}},
        ]}})
    );
    assert_eq!(
        dsl("user : { name : root }"),
        json!({"match": {"user.name": {"query": "root", "lenient": true}}})
    );
    assert_eq!(
        dsl("\"mimikatz\""),
        json!({"multi_match": {"query": "mimikatz", "type": "phrase", "lenient": true}})
    );
    assert_eq!(dsl(""), json!({"match_all": {}}));
}

#[test]
fn broken_queries_are_errors() {
    for query in [r#"a : "open"#, "(a : 1", "a : 1)", "a :"] {
        assert!(read(query).is_err(), "{query}");
    }
    assert!(read("").unwrap().prefilter.is_always());
}

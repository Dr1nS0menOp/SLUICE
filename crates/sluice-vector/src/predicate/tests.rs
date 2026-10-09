use serde_json::{Value, json};
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

use crate::runtime::PredicateProgram;

fn test(field: &str, op: MatchOp, values: &[&str], case_sensitive: bool) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive,
    })
}

fn matches(predicate: &Predicate, event: Value) -> bool {
    let Value::Object(fields) = event else {
        panic!("event must be an object")
    };
    let program =
        PredicateProgram::compile(predicate).unwrap_or_else(|e| panic!("does not compile: {e}"));
    program.matches(&fields).unwrap()
}

#[test]
fn equals_is_case_insensitive_by_default_and_compares_numbers_as_text() {
    let p = test("EventID", MatchOp::Equals, &["4625"], false);
    assert!(matches(&p, json!({"EventID": 4625})));
    assert!(matches(&p, json!({"EventID": "4625"})));
    assert!(!matches(&p, json!({"EventID": 4624})));
    let user = test("User", MatchOp::Equals, &["Admin"], false);
    assert!(matches(&user, json!({"User": "ADMIN"})));
    let cased = test("User", MatchOp::Equals, &["Admin"], true);
    assert!(!matches(&cased, json!({"User": "ADMIN"})));
}

#[test]
fn string_operators_work_on_nested_fields() {
    let event = json!({"query": {"name": "cdn-update.BadCDN.example"}});
    assert!(matches(
        &test("query.name", MatchOp::EndsWith, &[".badcdn.example"], false),
        event.clone()
    ));
    assert!(matches(
        &test("query.name", MatchOp::StartsWith, &["CDN-"], false),
        event.clone()
    ));
    assert!(matches(
        &test("query.name", MatchOp::Contains, &["update"], false),
        event.clone()
    ));
    assert!(!matches(
        &test("query.name", MatchOp::Contains, &["update"], false),
        json!({"query": {}})
    ));
}

#[test]
fn any_value_in_the_list_matches() {
    let p = test(
        "GrantedAccess",
        MatchOp::Equals,
        &["0x1010", "0x1410"],
        false,
    );
    assert!(matches(&p, json!({"GrantedAccess": "0x1410"})));
    assert!(!matches(&p, json!({"GrantedAccess": "0x1000"})));
}

#[test]
fn missing_and_null_fields_never_match() {
    let p = test("X", MatchOp::Contains, &[""], false);
    assert!(!matches(&p, json!({})));
    assert!(!matches(&p, json!({"X": null})));
}

#[test]
fn arrays_and_objects_widen_to_true() {
    let p = test("X", MatchOp::Equals, &["a"], false);
    assert!(matches(&p, json!({"X": ["b", "c"]})));
    assert!(matches(&p, json!({"X": {"y": 1}})));
}

#[test]
fn regexes_compile_and_invalid_ones_widen() {
    let p = test("X", MatchOp::Regex, &["^a.c$"], true);
    assert!(matches(&p, json!({"X": "abc"})));
    assert!(!matches(&p, json!({"X": "ABC"})));
    let insensitive = test("X", MatchOp::Regex, &["^a.c$"], false);
    assert!(matches(&insensitive, json!({"X": "ABC"})));
    // Lookahead is not supported by Rust's regex: the test must widen, not fail.
    let lookahead = test("X", MatchOp::Regex, &["a(?=b)"], true);
    assert!(matches(&lookahead, json!({"X": "zzz"})));
    let quoted = test("X", MatchOp::Regex, &["it's"], true);
    assert!(matches(&quoted, json!({"X": "it's here"})));
}

#[test]
fn exists_tests_presence() {
    let p = test("X", MatchOp::Exists, &[], false);
    assert!(matches(&p, json!({"X": "v"})));
    assert!(!matches(&p, json!({"Y": "v"})));
}

#[test]
fn hostile_values_stay_literal() {
    for value in ["{{ .secret }}", "a\"b", "back\\slash", "new\nline", "\u{1}"] {
        let p = test("X", MatchOp::Equals, &[value], true);
        assert!(matches(&p, json!({"X": value})), "{value:?}");
        assert!(
            !matches(&p, json!({"X": "other", "secret": value})),
            "{value:?}"
        );
    }
}

#[test]
fn boolean_structure_is_preserved() {
    let a = test("A", MatchOp::Equals, &["1"], false);
    let b = test("B", MatchOp::Equals, &["2"], false);
    let all = Predicate::all([a.clone(), b.clone()]);
    let any = Predicate::any([a, b]);
    assert!(matches(&all, json!({"A": 1, "B": 2})));
    assert!(!matches(&all, json!({"A": 1, "B": 3})));
    assert!(matches(&any, json!({"A": 9, "B": 2})));
    assert!(!matches(&Predicate::never(), json!({"A": 1})));
    assert!(matches(&Predicate::Always, json!({})));
}

#[test]
fn keywords_scan_every_string_and_integer_value() {
    let p = Predicate::Keywords(KeywordTest {
        values: vec!["invalid user".into(), "4625".into()],
        case_sensitive: false,
    });
    assert!(matches(
        &p,
        json!({"message": "sshd: Failed password for INVALID USER x"})
    ));
    assert!(matches(
        &p,
        json!({"a": {"b": {"c": "...invalid user..."}}})
    ));
    assert!(matches(&p, json!({"EventID": 4625})));
    assert!(!matches(
        &p,
        json!({"message": "Accepted publickey", "ok": true, "n": null})
    ));
    // Arrays and floats widen.
    assert!(matches(&p, json!({"list": ["x"]})));
    assert!(matches(&p, json!({"ratio": 0.5})));
}

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
fn an_array_matches_when_a_member_does_and_objects_widen() {
    let p = test("X", MatchOp::Equals, &["a"], false);
    assert!(!matches(&p, json!({"X": ["b", "c"]})));
    assert!(matches(&p, json!({"X": ["b", "A"]})));
    assert!(
        matches(&p, json!({"X": ["b", {"y": 1}]})),
        "a nested object widens"
    );
    assert!(matches(&p, json!({"X": [["a"]]})), "a nested array widens");
    // `a` could be part of `nan`; `cmd` is in no number's text.
    assert!(matches(&p, json!({"X": [null, 1.5]})));
    let cmd = test("X", MatchOp::Equals, &["cmd"], false);
    assert!(!matches(&cmd, json!({"X": [null, 1.5]})));
    assert!(matches(&p, json!({"X": {"y": 1}})));
}

#[test]
fn c3_a_float_widens_only_for_values_a_number_could_be_written_as() {
    for (values, widens) in [
        (&["cmd.exe"][..], false),
        (&["4625"][..], true),
        (&["1e21"][..], true),
        (&["nan"][..], true),
        (&["admin", "-1.5"][..], true),
    ] {
        let p = test("X", MatchOp::Equals, values, false);
        assert_eq!(matches(&p, json!({"X": 2.5})), widens, "{values:?}");
    }
    let regex = test("X", MatchOp::Regex, &["^c"], true);
    assert!(
        matches(&regex, json!({"X": 2.5})),
        "a regex may match anything"
    );
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
    // An array's members are searched; a nested one widens. `4625` could be a float's text.
    assert!(!matches(&p, json!({"list": ["x", 1, true]})));
    assert!(matches(&p, json!({"list": ["x", "an invalid user"]})));
    assert!(matches(&p, json!({"list": [4625]})));
    assert!(matches(&p, json!({"list": [["x"]]})));
    assert!(matches(&p, json!({"ratio": 0.5})));
}

#[test]
fn c3_a_float_value_may_match_any_number_text() {
    // `4625.0` renders differently between engines; a rule on `EventID: 4625` may still match.
    let p = test("EventID", MatchOp::Equals, &["4625"], false);
    assert!(matches(&p, json!({"EventID": 4625.0})));
    let many = test(
        "EventID",
        MatchOp::Equals,
        &["1", "2", "3", "4", "4625"],
        false,
    );
    assert!(
        matches(&many, json!({"EventID": 4625.0})),
        "the alternation path too"
    );
}

#[test]
fn c3_case_insensitive_tests_fold_non_ascii_letters() {
    for op in [
        MatchOp::Equals,
        MatchOp::Contains,
        MatchOp::StartsWith,
        MatchOp::EndsWith,
    ] {
        assert!(
            matches(&test("A", op, &["échec"], false), json!({"A": "ÉCHEC"})),
            "{op:?}"
        );
        let many = test("A", op, &["v1", "v2", "v3", "v4", "échec"], false);
        assert!(
            matches(&many, json!({"A": "ÉCHEC"})),
            "{op:?} as an alternation"
        );
        assert!(
            !matches(&test("A", op, &["échec"], true), json!({"A": "ÉCHEC"})),
            "{op:?}"
        );
    }
}

#[test]
fn the_alternation_and_the_comparisons_decide_alike() {
    let values = ["a.b", "(x)", "c*d", "e|f", "^g$", "h\\i"];
    let events = [
        json!({"X": "a.b"}),
        json!({"X": "aXb"}),
        json!({"X": "pre (x) post"}),
        json!({"X": "c*d"}),
        json!({"X": "cXd"}),
        json!({"X": "e|f"}),
        json!({"X": "^G$"}),
        json!({"X": "h\\i"}),
        json!({"X": "nothing"}),
    ];
    for op in [
        MatchOp::Equals,
        MatchOp::Contains,
        MatchOp::StartsWith,
        MatchOp::EndsWith,
    ] {
        for case_sensitive in [false, true] {
            let together = test("X", op, &values, case_sensitive);
            for event in &events {
                let one_by_one = values
                    .iter()
                    .any(|v| matches(&test("X", op, &[v], case_sensitive), event.clone()));
                assert_eq!(
                    matches(&together, event.clone()),
                    one_by_one,
                    "{op:?} case_sensitive={case_sensitive} on {event}"
                );
            }
        }
    }
}

#[test]
fn integer_values_compare_as_their_decimal_text_for_every_operator() {
    let event = json!({"Port": 44_389});
    assert!(matches(
        &test("Port", MatchOp::StartsWith, &["443"], false),
        event.clone()
    ));
    assert!(matches(
        &test("Port", MatchOp::EndsWith, &["89"], false),
        event.clone()
    ));
    assert!(matches(
        &test("Port", MatchOp::Contains, &["438"], false),
        event.clone()
    ));
    assert!(!matches(
        &test("Port", MatchOp::Equals, &["443"], false),
        event
    ));
}

#[test]
fn a_case_insensitive_regex_matches_any_case() {
    let p = test("X", MatchOp::Regex, &["^admin$"], false);
    assert!(matches(&p, json!({"X": "ADMIN"})));
    assert!(!matches(
        &test("X", MatchOp::Regex, &["^admin$"], true),
        json!({"X": "ADMIN"})
    ));
}

#[test]
fn empty_disjunctions_and_conjunctions_compile_to_their_neutral_value() {
    assert!(!matches(&Predicate::never(), json!({"A": 1})));
    assert!(matches(&Predicate::All(Vec::new()), json!({"A": 1})));
    assert!(matches(&Predicate::Always, json!({})));
}

#[test]
fn thousands_of_alternatives_compile_without_overflowing_the_stack() {
    let n = 3_000;
    let started = std::time::Instant::now();
    let parts: Vec<Predicate> = (0..n)
        .map(|i| test(&format!("F{i}"), MatchOp::Equals, &["x"], false))
        .collect();
    let p = Predicate::Any(parts);
    assert!(matches(&p, json!({format!("F{}", n - 1): "x"})));
    assert!(!matches(&p, json!({"F3000": "x"})));
    // Linear compile time: one variable per nesting level, not per test. Quadratic took
    // minutes for 800 tests and would take hours here. The bound leaves room for a loaded
    // machine: 30 s failed while a mutation run shared the CPU.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn nested_connectives_short_circuit_and_keep_their_meaning() {
    let a = test("A", MatchOp::Equals, &["1"], false);
    let b = test("B", MatchOp::Equals, &["2"], false);
    let c = test("C", MatchOp::Equals, &["3"], false);
    // (A and (B or C)) or (B and C), on every combination of present fields.
    let p = Predicate::Any(vec![
        Predicate::All(vec![a.clone(), Predicate::Any(vec![b.clone(), c.clone()])]),
        Predicate::All(vec![b.clone(), c.clone()]),
    ]);
    for (event, expected) in [
        (json!({"A": "1", "B": "2"}), true),
        (json!({"A": "1", "C": "3"}), true),
        (json!({"A": "1"}), false),
        (json!({"B": "2", "C": "3"}), true),
        (json!({"B": "2"}), false),
        (json!({}), false),
    ] {
        assert_eq!(matches(&p, event.clone()), expected, "{event}");
    }
}

#[test]
fn two_predicates_with_different_prefixes_share_one_program() {
    let first = super::compile(&test("A", MatchOp::Equals, &["1"], false), "_p");
    let second = super::compile(&test("B", MatchOp::Equals, &["2"], false), "_k");
    let source = format!(
        "{}\n{}\n.sluice_match = {} && {}\n",
        first.statements.join("\n"),
        second.statements.join("\n"),
        first.expression,
        second.expression
    );
    crate::runtime::CompiledProgram::compile("both", source).expect("compiles without warnings");
}

#[test]
fn keywords_ignore_keys_booleans_and_nulls_and_floats_no_number_could_hold() {
    let p = Predicate::Keywords(KeywordTest {
        values: vec!["admin".into()],
        case_sensitive: false,
    });
    assert!(!matches(&p, json!({"admin": "x"})), "keys are not values");
    assert!(!matches(&p, json!({"A": true, "B": null})));
    assert!(
        !matches(&p, json!({"A": 1.5, "B": [2.5]})),
        "no number reads `admin`"
    );
    let digits = Predicate::Keywords(KeywordTest {
        values: vec!["1.5".into()],
        case_sensitive: false,
    });
    assert!(
        matches(&digits, json!({"A": 1.25})),
        "a float may be written so"
    );
    assert!(
        matches(&p, json!({"A": {"B": "the ADMIN user"}})),
        "nested values count"
    );
}

#[test]
fn keywords_with_many_values_use_one_alternation_that_decides_alike() {
    let keywords: Vec<String> = ["mimikatz", "sekurlsa::", "a.b", "(x)", "ÉCHEC"]
        .map(String::from)
        .to_vec();
    let p = Predicate::Keywords(KeywordTest {
        values: keywords,
        case_sensitive: false,
    });
    assert!(matches(&p, json!({"A": "run SEKURLSA::logonpasswords"})));
    assert!(matches(&p, json!({"A": "échec total"})));
    assert!(!matches(&p, json!({"A": "aXb"})));
}

/// Every identifier in `compiled` that starts with `prefix`.
fn variables(
    compiled: &super::CompiledPredicate,
    prefix: &str,
) -> std::collections::BTreeSet<String> {
    let text = format!(
        "{}\n{}",
        compiled.statements.join("\n"),
        compiled.expression
    );
    regex::Regex::new(&format!(r"\b{prefix}\w*"))
        .unwrap()
        .find_iter(&text)
        .map(|m| m.as_str().to_owned())
        .collect()
}

#[test]
fn every_variable_carries_the_prefix_so_predicates_can_share_a_program() {
    let keywords = Predicate::Keywords(KeywordTest {
        values: vec!["mimikatz".into()],
        case_sensitive: false,
    });
    let p = Predicate::Any(vec![
        Predicate::All(vec![test("A", MatchOp::Equals, &["1"], true), keywords]),
        test("B", MatchOp::Contains, &["y"], false),
    ]);
    let compiled = super::compile(&p, "q7");
    let expected: std::collections::BTreeSet<String> = [
        "q70", "q71", "q7_v", "q7_m", "q7_s", "q7_kv", "q7_km", "q7_ks",
    ]
    .map(str::to_owned)
    .into();
    assert_eq!(variables(&compiled, "q7"), expected, "{compiled:?}");
    assert_eq!(compiled.expression, "q70");
    assert!(variables(&super::compile(&p, "r"), "q7").is_empty());
}

#[test]
fn five_or_more_values_become_one_alternation_and_fewer_stay_comparisons() {
    let values = ["a", "b", "c", "d", "e"];
    for op in [
        MatchOp::Equals,
        MatchOp::Contains,
        MatchOp::StartsWith,
        MatchOp::EndsWith,
    ] {
        let few = super::compile(&test("X", op, &values[..4], false), "p");
        let many = super::compile(&test("X", op, &values, false), "p");
        assert!(!few.statements.join("\n").contains("match("), "{op:?}");
        assert!(many.statements.join("\n").contains("match("), "{op:?}");
    }
    let keywords = |n: usize| {
        let p = Predicate::Keywords(KeywordTest {
            values: values[..n].iter().map(|v| (*v).to_owned()).collect(),
            case_sensitive: true,
        });
        super::compile(&p, "p").statements.join("\n")
    };
    assert!(!keywords(4).contains("match("));
    assert!(keywords(5).contains("match("));
    // Both forms decide alike.
    let field = test("X", MatchOp::Contains, &values, false);
    assert!(matches(&field, json!({"X": "zzEzz"})));
    assert!(!matches(&field, json!({"X": "zzz"})));
}

#[test]
fn joining_nothing_gives_the_operators_neutral_value() {
    assert_eq!(super::balanced(&[], " || "), "false");
    assert_eq!(super::balanced(&[], " && "), "true");
    assert_eq!(super::balanced(&["a".into()], " || "), "a");
    assert_eq!(
        super::balanced(&["a".into(), "b".into(), "c".into()], " && "),
        "(a && (b && c))"
    );
}

#[test]
fn a_predicate_program_shows_the_vrl_it_runs() {
    let program = PredicateProgram::compile(&test("A", MatchOp::Equals, &["1"], true)).unwrap();
    let source = program.source();
    assert!(source.contains(".sluice_match = _p0"), "{source}");
    assert!(source.contains("_p0 = false"), "{source}");
}

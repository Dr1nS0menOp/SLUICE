//! Conditions and times come from the command line and from MCP clients: no input may make
//! their parsers panic. Errors are fine.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use serde_json::{Map, json};
use sluice_archive::{Condition, parse_time};

#[test]
fn conditions_and_times_never_panic() {
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 512,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let text = prop_oneof![
        "[a-z.!=~ü🔥]{0,12}",
        ".{0,16}",
        Just("=".to_owned()),
        Just("!=".to_owned()),
        Just("a.b~".to_owned()),
        Just("2026-13-45".to_owned()),
    ];
    let mut event = Map::new();
    event.insert("a".into(), json!({"b": ["x", 1, null]}));
    event.insert("a.b".into(), json!(true));
    runner
        .run(&text, |input| {
            if let Ok(condition) = input.parse::<Condition>() {
                let _ = condition.matches(&event);
            }
            let _ = parse_time(&input);
            Ok(())
        })
        .expect("no panic");
}

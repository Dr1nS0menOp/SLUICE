//! Rule files come from users and third parties: no input may make the parsers panic (CLAUDE.md:
//! no `panic!` on input data). Any result is fine, an error included; a crash is not.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use sluice_rules::{SigmaRules, WazuhRules};

/// Fragments that steer random text towards the parsers' interesting paths.
const XML: [&str; 16] = [
    "<group name=\"x,\">",
    "</group>",
    "<rule id=\"1\" level=\"3\">",
    "</rule>",
    "<match>",
    "</match>",
    "<regex>",
    "</regex>",
    "</\\/\\w+\\>",
    "&&",
    "&amp;",
    "&#x41;",
    "<if_sid>1</if_sid>",
    "<decoded_as>sshd</decoded_as>",
    "<field name=\"a.b\">",
    "\u{1F525}",
];
const YAML: [&str; 14] = [
    "title: t\n",
    "id: x\n",
    "logsource:\n  product: windows\n",
    "detection:\n",
    "  sel:\n    A|contains|all:\n      - 'a*b'\n      - '?'\n",
    "  keywords:\n    - 'x'\n",
    "  condition: sel and not 1 of them\n",
    "---\n",
    "correlation:\n  type: event_count\n",
    "  '|all': ['a', 'b']\n",
    "  A: null\n",
    "  A|re: '(('\n",
    "\u{0}",
    "\t\t- [\n",
];

fn assembled(pieces: &'static [&'static str]) -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            prop::sample::select(pieces).prop_map(str::to_owned),
            ".{0,12}",
        ],
        0..24,
    )
    .prop_map(|parts| parts.concat())
}

fn runner() -> TestRunner {
    TestRunner::new_with_rng(
        Config {
            cases: 256,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    )
}

#[test]
fn wazuh_rule_and_decoder_files_never_panic() {
    runner()
        .run(&(assembled(&XML), assembled(&XML)), |(rules, decoders)| {
            let _ = WazuhRules::parse_with_decoders([rules.as_str()], [decoders.as_str()]);
            Ok(())
        })
        .expect("no panic");
}

#[test]
fn sigma_files_never_panic() {
    runner()
        .run(&assembled(&YAML), |yaml| {
            if let Ok(rules) = SigmaRules::parse([yaml.as_str()]) {
                let _ = rules.engine(&[]);
            }
            Ok(())
        })
        .expect("no panic");
}

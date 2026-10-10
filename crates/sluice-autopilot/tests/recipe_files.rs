//! Operators load their own recipe files (`--recipes`): no file may make the recipe parser
//! panic. Errors are fine.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use sluice_autopilot::RecipeBook;

const PIECES: [&str; 14] = [
    "id: r\n",
    "description: d\n",
    "rationale: x\n",
    "match:\n  logsource: { product: windows }\n",
    "  discriminators: { EventID: \"4624\" }\n",
    "  pattern: \"CRON\"\n",
    "reductions:\n",
    "  - op: drop_fields\n    fields: [Message]\n",
    "  - op: summarize\n    summary_keys: [host]\n",
    "  - op: forward_matching\n    summary_keys: []\n",
    "  - op: drop_empty_fields\n",
    "  - op: nonsense\n",
    "extra: 1\n",
    "\t[\u{0}",
];

#[test]
fn recipe_files_never_panic() {
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 512,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let file = prop::collection::vec(
        prop_oneof![
            prop::sample::select(&PIECES[..]).prop_map(str::to_owned),
            ".{0,10}",
        ],
        0..14,
    )
    .prop_map(|parts| parts.concat());
    runner
        .run(&file, |yaml| {
            let _ = RecipeBook::parse([("fuzz.yaml", yaml.as_str())]);
            Ok(())
        })
        .expect("no panic");
}

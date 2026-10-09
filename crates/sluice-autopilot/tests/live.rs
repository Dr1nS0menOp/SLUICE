//! The live control loop over successive windows: shadow, promotion, continuous verification,
//! and recipes that stay deployed when their template is absent from a window.

use sluice_autopilot::{
    Helpers, Input, Lifecycle, Policy, RecipeBook, Settings, Transition, cycle,
};
use sluice_core::event::Timestamp;
use sluice_core::proof::prove;
use sluice_core::source::Source;
use sluice_rules::SigmaRules;
use sluice_synth::{Sample, SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

fn window(seed: u64, hour: i64) -> Sample {
    generate(&SynthConfig {
        seed,
        start: Timestamp(1_791_619_200 + hour * 3_600),
        scale_percent: 5,
        ..SynthConfig::default()
    })
}

fn only(sample: &Sample, source: &str) -> (Vec<Source>, Vec<sluice_core::event::Event>) {
    let sources = sample
        .sources
        .iter()
        .filter(|s| s.id.as_str() == source)
        .cloned()
        .collect();
    let events = sample
        .events
        .iter()
        .filter(|e| e.source.as_str() == source)
        .cloned()
        .collect();
    (sources, events)
}

#[test]
fn recipes_are_shadowed_then_enforced_and_keep_holding() {
    let rules = SigmaRules::parse(SIGMA).expect("rules");
    let book = RecipeBook::embedded().expect("recipes");
    let mut lifecycle = Lifecycle::new(Policy {
        shadow_secs: 2 * 3_600,
        min_proofs: 2,
    });

    let mut enforced_after = Vec::new();
    for (n, hour) in [0, 1, 2].into_iter().enumerate() {
        let sample = window(u64::try_from(n).unwrap() + 1, hour);
        let input = Input {
            sources: &sample.sources,
            events: &sample.events,
            sigma: &rules,
            wazuh: None,
        };
        let now = Timestamp(1_791_619_200 + hour * 3_600);
        let result = cycle(
            input,
            &book,
            &Settings::default(),
            Helpers::default(),
            &mut lifecycle,
            now,
        )
        .expect("cycle succeeds");

        // Whatever is deployed holds on this window.
        let engine = rules.engine(&sample.sources).expect("engine");
        let proof = prove(&sample.events, &engine, &result.data_plane).expect("proof runs");
        assert!(
            proof.holds(),
            "hour {hour}: {:?} / {:?}",
            proof.missing,
            proof.extra
        );

        if hour == 0 {
            assert!(
                result
                    .transitions
                    .iter()
                    .all(|t| matches!(t, Transition::Shadowing(_)))
            );
            assert!(
                result
                    .deployed
                    .recipes
                    .iter()
                    .all(sluice_core::guard::EffectiveRecipe::is_passthrough)
            );
        }
        enforced_after.push(lifecycle.enforced().len());
    }
    assert_eq!(enforced_after[0], 0);
    assert_eq!(enforced_after[1], 0, "one hour of shadow is not enough");
    assert!(
        enforced_after[2] > 5,
        "JSON templates are stable across windows: {enforced_after:?}"
    );

    // A window with only Linux traffic: enforced Windows recipes stay deployed.
    let sample = window(9, 3);
    let (sources, events) = only(&sample, "linux-auth");
    let input = Input {
        sources: &sources,
        events: &events,
        sigma: &rules,
        wazuh: None,
    };
    let before = lifecycle.enforced();
    let result = cycle(
        input,
        &book,
        &Settings::default(),
        Helpers::default(),
        &mut lifecycle,
        Timestamp(1_791_619_200 + 3 * 3_600),
    )
    .expect("cycle succeeds");
    let windows_before = before
        .iter()
        .filter(|t| t.as_str().starts_with("windows-security:"))
        .count();
    let windows_deployed = result
        .deployed
        .recipes
        .iter()
        .filter(|r| r.template.as_str().starts_with("windows-security:") && !r.is_passthrough())
        .count();
    assert!(windows_before > 0);
    assert_eq!(
        windows_deployed, windows_before,
        "absent templates keep their recipe"
    );
}

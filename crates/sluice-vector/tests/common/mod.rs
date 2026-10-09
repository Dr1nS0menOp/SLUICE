//! Fixtures shared by the integration tests: the synthetic sample, its templates and the
//! example rules, each built once.

#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::sync::OnceLock;

use sluice_core::guard::{EffectiveRecipe, GuardContext, GuardrailConfig, guard};
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::template::Template;
use sluice_discover::{DiscoverConfig, Discovery, discover};
use sluice_rules::SigmaRules;
use sluice_synth::{Sample, SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../../examples/rules/sigma/network.yml"),
];

pub(crate) fn sample() -> &'static Sample {
    static SAMPLE: OnceLock<Sample> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        generate(&SynthConfig {
            scale_percent: 10,
            ..SynthConfig::default()
        })
    })
}

pub(crate) fn discovery() -> &'static Discovery {
    static DISCOVERY: OnceLock<Discovery> = OnceLock::new();
    DISCOVERY.get_or_init(|| {
        discover(
            DiscoverConfig::default(),
            &sample().sources,
            &sample().events,
        )
    })
}

pub(crate) fn rules() -> &'static SigmaRules {
    static RULES: OnceLock<SigmaRules> = OnceLock::new();
    RULES.get_or_init(|| SigmaRules::parse(SIGMA).expect("example rules parse"))
}

pub(crate) fn template(prefix: &str) -> &'static Template {
    let found = discovery()
        .templates
        .iter()
        .find(|t| t.id.as_str().starts_with(prefix));
    found.expect("template exists")
}

/// A recipe for `template`, through the guardrails with the example rules.
pub(crate) fn guarded(template: &Template, reductions: Vec<Reduction>) -> EffectiveRecipe {
    let recipe = Recipe::new(
        template.id.clone(),
        reductions,
        Provenance::Operator,
        "test",
    )
    .expect("valid recipe");
    guard(
        template,
        Some(&recipe),
        GuardContext {
            rules: rules().requirements(),
            config: GuardrailConfig::default(),
            archive_enabled: true,
        },
    )
}

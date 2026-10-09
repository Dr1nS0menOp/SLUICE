//! The autopilot with an advisor: only uncovered, frequent templates are asked, an eager
//! advisor cannot break detection, and a failing advisor cannot break the analysis.

use std::cell::RefCell;
use std::collections::BTreeSet;

use sluice_autopilot::{Helpers, Input, RecipeBook, Settings, analyze};
use sluice_core::advice::{AdviceError, Advisor};
use sluice_core::event::Event;
use sluice_core::ids::TemplateId;
use sluice_core::proof::prove;
use sluice_core::recipe::{Provenance, Recipe, Reduction};
use sluice_core::template::Template;
use sluice_rules::SigmaRules;
use sluice_synth::{SynthConfig, generate};

const SIGMA: [&str; 3] = [
    include_str!("../../../examples/rules/sigma/windows.yml"),
    include_str!("../../../examples/rules/sigma/linux.yml"),
    include_str!("../../../examples/rules/sigma/network.yml"),
];

/// Proposes to summarize every template it is asked about, by its first field, and to drop its
/// free-text fields: far more than is safe.
#[derive(Default)]
struct Eager {
    asked: RefCell<BTreeSet<TemplateId>>,
}

impl Advisor for Eager {
    fn propose(
        &self,
        template: &Template,
        samples: &[&Event],
    ) -> Result<Option<Recipe>, AdviceError> {
        assert!(!samples.is_empty() && samples.len() <= 5);
        self.asked.borrow_mut().insert(template.id.clone());
        let key = template.fields.iter().next().cloned().into_iter().collect();
        let mut reductions = vec![Reduction::Summarize { summary_keys: key }];
        if !template.text_fields.is_empty() {
            reductions.push(Reduction::DropFields {
                fields: template.text_fields.clone(),
            });
        }
        let recipe = Recipe::new(
            template.id.clone(),
            reductions,
            Provenance::Ai {
                model: "eager".into(),
            },
            "",
        );
        Ok(Some(recipe.expect("one routing reduction")))
    }
}

struct Broken;

impl Advisor for Broken {
    fn propose(&self, _: &Template, _: &[&Event]) -> Result<Option<Recipe>, AdviceError> {
        Err(AdviceError("unreachable".into()))
    }
}

#[test]
fn eager_advice_is_guarded_and_proven() {
    let sample = generate(&SynthConfig {
        scale_percent: 10,
        ..SynthConfig::default()
    });
    let rules = SigmaRules::parse(SIGMA).expect("rules parse");
    let input = Input {
        sources: &sample.sources,
        events: &sample.events,
        sigma: &rules,
        wazuh: None,
    };
    let book = RecipeBook::embedded().expect("recipes");
    let advisor = Eager::default();
    let analysis = analyze(
        input,
        &book,
        &Settings::default(),
        Helpers {
            advisor: Some(&advisor),
            ..Helpers::default()
        },
    )
    .expect("analysis");

    let asked = advisor.asked.borrow();
    assert!(
        asked.iter().any(|t| t.as_str().starts_with("nginx:")),
        "uncovered templates are asked"
    );
    assert!(
        !asked
            .iter()
            .any(|t| t.as_str().starts_with("windows-security:")),
        "templates with a community recipe are not asked: {asked:?}"
    );
    assert!(
        !asked
            .iter()
            .any(|t| t.as_str().starts_with("windows-security:4720:")),
        "rare templates are not asked"
    );
    assert!(analysis.proposals.values().any(|p| p.provenance()
        == &Provenance::Ai {
            model: "eager".into()
        }));

    let engine = rules.engine(&sample.sources).expect("engine");
    let proof = prove(&sample.events, &engine, &analysis.data_plane).expect("proof runs");
    assert!(
        proof.holds(),
        "missing {:?}, extra {:?}",
        proof.missing,
        proof.extra
    );
}

#[test]
fn a_failing_advisor_is_reported_not_fatal() {
    let sample = generate(&SynthConfig {
        scale_percent: 5,
        ..SynthConfig::default()
    });
    let rules = SigmaRules::parse(SIGMA).expect("rules parse");
    let input = Input {
        sources: &sample.sources,
        events: &sample.events,
        sigma: &rules,
        wazuh: None,
    };
    let book = RecipeBook::embedded().expect("recipes");
    let analysis = analyze(
        input,
        &book,
        &Settings::default(),
        Helpers {
            advisor: Some(&Broken),
            ..Helpers::default()
        },
    )
    .expect("analysis");
    assert!(analysis.problems.iter().any(|p| p.contains("unreachable")));
    assert!(analysis.selection.proof.holds());
}

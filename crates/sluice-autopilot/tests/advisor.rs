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
        sentinel: None,
        elastic: None,
        splunk: None,
    };
    let book = RecipeBook::embedded().expect("recipes");
    let advisor = Eager::default();
    let analysis = analyze(
        input,
        &book,
        &Settings::with_complete_rules(),
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
        sentinel: None,
        elastic: None,
        splunk: None,
    };
    let book = RecipeBook::embedded().expect("recipes");
    let analysis = analyze(
        input,
        &book,
        &Settings::with_complete_rules(),
        Helpers {
            advisor: Some(&Broken),
            ..Helpers::default()
        },
    )
    .expect("analysis");
    assert!(analysis.problems.iter().any(|p| p.contains("unreachable")));
    assert!(analysis.selection.proof.holds());
}

/// Proposes to drop the shipper's bookkeeping fields, which no detection reads.
struct Modest;

impl Advisor for Modest {
    fn propose(&self, template: &Template, _: &[&Event]) -> Result<Option<Recipe>, AdviceError> {
        let fields: BTreeSet<_> = template
            .fields
            .iter()
            .filter(|f| {
                let name = f.as_str();
                name.starts_with("agent.") || name.starts_with("ecs.") || name == "log.offset"
            })
            .cloned()
            .collect();
        if fields.is_empty() {
            return Ok(None);
        }
        let recipe = Recipe::new(
            template.id.clone(),
            vec![Reduction::DropFields { fields }],
            Provenance::Ai {
                model: "modest".into(),
            },
            "The shipper's own bookkeeping.",
        );
        Ok(Some(recipe.expect("a drop")))
    }
}

#[test]
fn advice_the_proof_kept_becomes_recipes_to_contribute() {
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
        sentinel: None,
        elastic: None,
        splunk: None,
    };
    // No built-in recipes: every frequent template is asked.
    let book = RecipeBook::parse(std::iter::empty()).expect("an empty book");
    let analysis = analyze(
        input,
        &book,
        &Settings::with_complete_rules(),
        Helpers {
            advisor: Some(&Modest),
            ..Helpers::default()
        },
    )
    .expect("analysis");
    let contributions = sluice_autopilot::ai_recipes(&analysis);
    assert!(!contributions.is_empty(), "some advice was kept");
    RecipeBook::embedded_with(
        contributions
            .iter()
            .map(|c| (c.path.as_str(), c.yaml.as_str())),
    )
    .expect("the recipe book takes them next to the built-in ones");
    for c in &contributions {
        assert!(c.path.starts_with("contrib/"), "{}", c.path);
        assert!(c.yaml.contains("Proposed by modest"), "{}", c.yaml);
    }
}

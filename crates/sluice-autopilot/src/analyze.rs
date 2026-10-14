//! One analysis: from a sample and rules to proven, enforceable recipes.

use std::collections::BTreeMap;

use sluice_core::advice::Advisor;
use sluice_core::alert::{Engines, EventRules, RuleEngine};
use sluice_core::event::Event;
use sluice_core::guard::{EffectiveRecipe, GuardContext, GuardrailConfig, guard};
use sluice_core::ids::TemplateId;
use sluice_core::proof::{ProofError, Selection, select_proven};
use sluice_core::recipe::Recipe;
use sluice_core::rules::RuleRequirements;
use sluice_core::source::Source;
use sluice_core::template::{LineHeader, Template, TemplateShape};
use sluice_discover::{DiscoverConfig, Discovery, discover};
use sluice_rules::{SentinelRules, SigmaRules, WazuhRules};
use sluice_vector::{Plan, VrlReducer, compile_reducer};

use crate::basis::RulesBasis;
use crate::error::AutopilotError;
use crate::recipes::RecipeBook;
use crate::spot::{self, SpotCheck};

/// Settings for an analysis.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Template discovery.
    pub discover: DiscoverConfig,
    /// Guardrail thresholds.
    pub guardrails: GuardrailConfig,
    /// Whether full-fidelity archiving runs before reductions (safety contract rule 2).
    pub archive_enabled: bool,
    /// Requirements operators added (ADR 0016), such as fields to keep. They constrain the
    /// guardrails like any rule, but are not evaluated in the proof.
    pub operator_rules: Vec<RuleRequirements>,
    /// Whether, and on what grounds, the rules are every rule and query the SIEM runs
    /// (ADR 0021). Not known by default: then only lossless savings are made, since a rule
    /// Sluice was not given could match any event that would be summarized.
    pub rules: RulesBasis,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            discover: DiscoverConfig::default(),
            guardrails: GuardrailConfig::default(),
            archive_enabled: true,
            operator_rules: Vec::new(),
            rules: RulesBasis::NotKnown,
        }
    }
}

impl Settings {
    /// The default settings for the rules of a self-contained sample, such as the demo's.
    #[must_use]
    pub fn with_complete_rules() -> Self {
        Self {
            rules: RulesBasis::SelfContained,
            ..Self::default()
        }
    }
}

/// What an analysis works on.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    /// The configured sources.
    pub sources: &'a [Source],
    /// The sample, in time order.
    pub events: &'a [Event],
    /// Sigma rules; these are evaluated in the proof.
    pub sigma: &'a SigmaRules,
    /// Wazuh rules, if any. They constrain the guardrails; exact verification needs `logtest`.
    pub wazuh: Option<&'a WazuhRules>,
    /// Microsoft Sentinel analytics rules, if any.
    pub sentinel: Option<Sentinel<'a>>,
}

/// Sentinel analytics rules (ADR 0015). Their requirements constrain the guardrails; with an
/// engine (the rules run in the Kusto emulator) the proof also evaluates them. Without one, the
/// proof covers the other rule sets only.
#[derive(Clone, Copy)]
pub struct Sentinel<'a> {
    /// The rules.
    pub rules: &'a SentinelRules,
    /// Runs the rules' queries on full and on forwarded records.
    pub engine: Option<&'a dyn RuleEngine>,
}

impl std::fmt::Debug for Sentinel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sentinel")
            .field("rules", &self.rules.requirements().len())
            .field("engine", &self.engine.is_some())
            .finish()
    }
}

/// Optional helpers that make an analysis smarter or stricter.
#[derive(Clone, Copy, Default)]
pub struct Helpers<'a> {
    /// Proposes recipes for frequent templates no community recipe covers.
    pub advisor: Option<&'a dyn Advisor>,
    /// The SIEM's own rules on single events (Wazuh `logtest`), for spot checks after the proof.
    pub event_rules: Option<&'a dyn EventRules>,
}

/// The result of an analysis.
#[derive(Debug)]
pub struct Analysis {
    /// Discovered templates and every event's template.
    pub discovery: Discovery,
    /// The proposal for each template that had one.
    pub proposals: BTreeMap<TemplateId, Recipe>,
    /// The proven selection: one effective recipe per template, in template order.
    pub selection: Selection,
    /// The data plane enforcing the selection.
    pub data_plane: VrlReducer,
    /// Rules or recipes that could not be fully understood.
    pub problems: Vec<String>,
    /// The spot check with the SIEM's own rules, if one ran.
    pub spot_check: Option<SpotCheck>,
    /// On what grounds the rules counted as complete.
    pub rules: RulesBasis,
}

impl Analysis {
    /// Each template with its enforced recipe, for generating the data plane's configuration.
    #[must_use]
    pub fn plans(&self) -> Vec<Plan<'_>> {
        self.discovery
            .templates
            .iter()
            .zip(&self.selection.recipes)
            .map(|(template, recipe)| Plan { template, recipe })
            .collect()
    }
}

/// How many events of a template an advisor sees.
const ADVISOR_SAMPLES: usize = 5;

/// Runs a full analysis with the recipes from `book`. The helpers' advisor (if any) is asked
/// about frequent templates no recipe covers; their event rules (if any) spot-check the result.
///
/// # Errors
///
/// Returns [`AutopilotError`] if rules cannot be compiled, the data plane cannot be generated, or
/// the proof cannot be carried out. An advisor failure is not an error: the template just gets
/// no proposal, and the failure is listed in [`Analysis::problems`].
pub fn analyze(
    input: Input<'_>,
    book: &RecipeBook,
    settings: &Settings,
    helpers: Helpers<'_>,
) -> Result<Analysis, AutopilotError> {
    // Discovery keeps rare key sets apart by the same floor the guardrails apply.
    let config = DiscoverConfig {
        rarity: settings.guardrails,
        ..settings.discover.clone()
    };
    let discovery = discover(config, input.sources, input.events);
    let mut resolution = book.resolve(&discovery.templates);
    let mut problems: Vec<String> = resolution
        .conflicts
        .iter()
        .map(|c| format!("conflicting recipes for {c}"))
        .collect();
    problems.extend(input.sigma.problems().iter().cloned());
    if let Some(wazuh) = input.wazuh {
        problems.extend(wazuh.problems().iter().cloned());
    }
    if let Some(sentinel) = input.sentinel {
        problems.extend(sentinel.rules.problems().iter().cloned());
    }
    if let Some(advisor) = helpers.advisor {
        let advice = advise(
            advisor,
            &discovery,
            input.events,
            &resolution.recipes,
            settings,
        );
        resolution.recipes.extend(advice.recipes);
        problems.extend(advice.problems);
    }
    analyze_proposals(
        input,
        discovery,
        resolution.recipes,
        settings,
        helpers,
        problems,
    )
}

#[derive(Default)]
struct Advice {
    recipes: BTreeMap<TemplateId, Recipe>,
    problems: Vec<String>,
}

/// Asks the advisor about every frequent, classifiable template without a recipe. Rare
/// templates would be refused by the guardrails anyway, so asking about them costs for nothing.
fn advise(
    advisor: &dyn Advisor,
    discovery: &Discovery,
    events: &[Event],
    existing: &BTreeMap<TemplateId, Recipe>,
    settings: &Settings,
) -> Advice {
    let mut samples: BTreeMap<&TemplateId, Vec<&Event>> = BTreeMap::new();
    for event in events {
        if let Some(template) = discovery.assignments.get(&event.id) {
            let bucket = samples.entry(template).or_default();
            if bucket.len() < ADVISOR_SAMPLES {
                bucket.push(event);
            }
        }
    }
    let mut advice = Advice::default();
    for template in &discovery.templates {
        let unmatchable = matches!(
            template.shape,
            TemplateShape::Text {
                header: LineHeader::Mixed,
                ..
            }
        );
        if existing.contains_key(&template.id)
            || settings.guardrails.is_rare(template)
            || unmatchable
        {
            continue;
        }
        let sample = samples.get(&template.id).map_or(&[][..], Vec::as_slice);
        match advisor.propose(template, sample) {
            Ok(Some(recipe)) => {
                advice.recipes.insert(template.id.clone(), recipe);
            }
            Ok(None) => {}
            Err(error) => advice.problems.push(format!("{}: {error}", template.id)),
        }
    }
    advice
}

/// Runs an analysis on given proposals, skipping recipe resolution. Used to test the autopilot
/// against arbitrary (including unsafe) proposals.
///
/// # Errors
///
/// As for [`analyze`].
pub fn analyze_proposals(
    input: Input<'_>,
    discovery: Discovery,
    proposals: BTreeMap<TemplateId, Recipe>,
    settings: &Settings,
    helpers: Helpers<'_>,
    problems: Vec<String>,
) -> Result<Analysis, AutopilotError> {
    let requirements: Vec<RuleRequirements> = input
        .sigma
        .requirements()
        .iter()
        .chain(input.wazuh.map_or(&[][..], WazuhRules::requirements))
        .chain(input.sentinel.map_or(&[][..], |s| s.rules.requirements()))
        .chain(&settings.operator_rules)
        .cloned()
        .collect();
    let context = GuardContext {
        rules: &requirements,
        config: settings.guardrails,
        archive_enabled: settings.archive_enabled,
        rules_complete: settings.rules.is_complete(),
    };
    let candidates: Vec<EffectiveRecipe> = discovery
        .templates
        .iter()
        .map(|template| guard(template, proposals.get(&template.id), context))
        .collect();

    let (mut selection, mut data_plane) = prove(input, &discovery.templates, candidates)?;
    let mut spot_check = None;
    if let Some(rules) = helpers.event_rules {
        let check = spot::check(
            rules,
            input.sources,
            input.events,
            &discovery.assignments,
            &selection.recipes,
            &data_plane,
        )?;
        if !check.rolled_back.is_empty() {
            let mut recipes = selection.recipes;
            spot::roll_back(&mut recipes, &check.rolled_back);
            (selection, data_plane) = prove(input, &discovery.templates, recipes)?;
        }
        spot_check = Some(check);
    }
    Ok(Analysis {
        discovery,
        proposals,
        selection,
        data_plane,
        problems,
        spot_check,
        rules: settings.rules,
    })
}

/// Proves `candidates` on the input's events (rolling back what fails) and builds the data plane
/// that enforces the result.
pub(crate) fn prove(
    input: Input<'_>,
    templates: &[Template],
    candidates: Vec<EffectiveRecipe>,
) -> Result<(Selection, VrlReducer), AutopilotError> {
    let sigma = input.sigma.engine(input.sources)?;
    let mut engines: Vec<&dyn RuleEngine> = vec![&sigma];
    engines.extend(input.sentinel.and_then(|s| s.engine));
    let engine = Engines(engines);
    let build = |recipes: &[EffectiveRecipe]| {
        let plans = templates
            .iter()
            .zip(recipes)
            .map(|(template, recipe)| Plan { template, recipe });
        compile_reducer(plans).map_err(|e| ProofError::Build(e.to_string()))
    };
    let selection = select_proven(candidates, input.events, &engine, build)?;
    let data_plane = build(&selection.recipes)?;
    Ok((selection, data_plane))
}

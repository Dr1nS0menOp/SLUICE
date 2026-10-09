//! One cycle of the live control loop (ADR 0005), as a pure function of a traffic window.

use std::collections::BTreeSet;

use sluice_core::event::Timestamp;
use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::TemplateId;
use sluice_core::proof::Selection;
use sluice_core::template::Template;
use sluice_vector::{Plan, VrlReducer};

use crate::analyze::{Analysis, Helpers, Input, Settings, analyze, prove};
use crate::error::AutopilotError;
use crate::lifecycle::{Lifecycle, Transition};
use crate::recipes::RecipeBook;

/// What one cycle decided.
#[derive(Debug)]
pub struct Cycle {
    /// The full analysis of the window: every recipe that is proven on it.
    pub analysis: Analysis,
    /// The templates the deployment covers: the window's, plus enforced ones absent from it.
    pub templates: Vec<Template>,
    /// The deployed recipes (enforced only, in `templates` order), proven on the same window.
    pub deployed: Selection,
    /// The data plane enforcing `deployed`.
    pub data_plane: VrlReducer,
    /// What changed for which template.
    pub transitions: Vec<Transition>,
}

impl Cycle {
    /// Each template with its deployed recipe, for the Vector configuration.
    #[must_use]
    pub fn plans(&self) -> Vec<Plan<'_>> {
        self.templates
            .iter()
            .zip(&self.deployed.recipes)
            .map(|(template, recipe)| Plan { template, recipe })
            .collect()
    }
}

/// Runs one cycle on a window of traffic.
///
/// 1. Analyze the window. Templates present in it advance in the lifecycle: proven recipes move
///    toward enforcement, unproven ones are demoted or rolled back.
/// 2. Deploy enforced recipes only (remembered ones for enforced templates absent from the
///    window), and prove exactly that deployment on the same window: continuous verification.
///    An enforced recipe this proof rolls back is rolled back in the lifecycle too.
///
/// # Errors
///
/// As for [`analyze`].
pub fn cycle(
    input: Input<'_>,
    book: &RecipeBook,
    settings: &Settings,
    helpers: Helpers<'_>,
    lifecycle: &mut Lifecycle,
    now: Timestamp,
) -> Result<Cycle, AutopilotError> {
    let analysis = analyze(input, book, settings, helpers)?;
    let window = &analysis.discovery.templates;
    let seen: BTreeSet<TemplateId> = window.iter().map(|t| t.id.clone()).collect();
    let proven: BTreeSet<TemplateId> = analysis
        .selection
        .recipes
        .iter()
        .filter(|r| !r.is_passthrough())
        .map(|r| r.template.clone())
        .collect();
    let mut transitions = lifecycle.advance(now, &seen, &proven);
    for (template, recipe) in window.iter().zip(&analysis.selection.recipes) {
        lifecycle.remember(template, recipe);
    }

    let enforced = lifecycle.enforced();
    let mut templates: Vec<Template> = window.clone();
    let mut deployment: Vec<EffectiveRecipe> = analysis
        .selection
        .recipes
        .iter()
        .map(|r| {
            if enforced.contains(&r.template) {
                r.clone()
            } else {
                EffectiveRecipe::passthrough(r.template.clone())
            }
        })
        .collect();
    for (id, (template, recipe)) in lifecycle.deployed() {
        if !seen.contains(id) {
            templates.push(template.clone());
            deployment.push(recipe.clone());
        }
    }

    let (deployed, data_plane) = prove(input, &templates, deployment)?;
    let failed: BTreeSet<TemplateId> = deployed
        .recipes
        .iter()
        .filter(|r| enforced.contains(&r.template) && r.is_passthrough())
        .map(|r| r.template.clone())
        .collect();
    transitions.extend(lifecycle.roll_back(&failed));

    Ok(Cycle {
        analysis,
        templates,
        deployed,
        data_plane,
        transitions,
    })
}

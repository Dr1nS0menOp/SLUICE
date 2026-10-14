//! The Sluice autopilot: everything between raw events and an enforceable, proven data plane.
//!
//! 1. Discover templates in a sample ([`sluice_discover`]).
//! 2. Resolve community recipes for them ([`RecipeBook`]).
//! 3. Narrow every recipe to what the loaded rules allow ([`sluice_core::guard`]).
//! 4. Prove the recipes on the sample, rolling back any that change an alert
//!    ([`sluice_core::proof`]).
//! 5. Compile the proven recipes into the VRL that Vector runs ([`sluice_vector`]).

mod analyze;
mod basis;
mod error;
mod lifecycle;
mod live;
mod recipes;
mod report;
mod spot;

pub use crate::analyze::{
    Analysis, Helpers, Input, Sentinel, Settings, analyze, analyze_proposals,
};
pub use crate::basis::RulesBasis;
pub use crate::error::AutopilotError;
pub use crate::lifecycle::{Evidence, Lifecycle, Policy, Stage, Transition};
pub use crate::live::{Cycle, cycle};
pub use crate::recipes::{RecipeBook, Resolution};
pub use crate::report::{EMPTY_PROOF, Report, RuleRow, RuleStatus, TemplateRow, render_html};
pub use crate::spot::SpotCheck;

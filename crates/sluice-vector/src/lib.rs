//! The data plane: Sluice recipes as VRL, and that VRL run exactly as Vector runs it.
//!
//! [`source_program`] compiles the templates and effective recipes of one source into a single
//! VRL program that classifies each event, decides its route and applies the reductions.
//! [`VrlReducer`] runs those programs with the `vrl` crate, the compiler and runtime Vector
//! embeds, so the shadow proof tests the code that is enforced, not a reimplementation of it.

mod classify;
mod config;
mod connect;
mod error;
mod live;
mod predicate;
mod program;
mod runtime;
mod syntax;

use std::collections::BTreeMap;

use sluice_core::ids::SourceId;

pub use crate::config::{Paths, vector_config};
pub use crate::connect::{SECRET_BACKEND, Target};
pub use crate::error::VectorError;
pub use crate::live::{
    FORMATS_KEY, LiveProfile, LiveSettings, LiveSource, RULES_KEY, destination_profile, live_config,
};
pub use crate::program::{
    FORWARD, Plan, ROUTE_METADATA, SUMMARIZE, TEMPLATE_METADATA, source_program,
};
pub use crate::runtime::{CompiledProgram, PredicateProgram, VrlReducer};

/// Compiles one program per source and returns a reducer running them.
///
/// # Errors
///
/// Returns [`VectorError::Compile`] if a generated program does not compile.
pub fn compile_reducer<'a>(
    plans: impl IntoIterator<Item = Plan<'a>>,
) -> Result<VrlReducer, VectorError> {
    let mut by_source: BTreeMap<SourceId, Vec<Plan<'a>>> = BTreeMap::new();
    for plan in plans {
        by_source
            .entry(plan.template.source.clone())
            .or_default()
            .push(plan);
    }
    let programs = by_source
        .into_iter()
        .map(|(source, plans)| {
            let program = CompiledProgram::compile(source.as_str(), source_program(&plans))?;
            Ok((source, program))
        })
        .collect::<Result<_, VectorError>>()?;
    Ok(VrlReducer::new(programs))
}

//! Fluent Bit Lua filters that carry out the field removals of a savings plan in the agent
//! (ADR 0027), and a real Fluent Bit to prove them in.
//!
//! [`lua_filter`] turns the plan of one source into a Lua script for Fluent Bit's `lua` filter,
//! recognising each record's template exactly as the VRL program does and keeping whole every
//! record a rule could match ([`compile`], a superset of the VRL). [`FluentBit::run`] puts
//! records through Fluent Bit with the filter and without it, for the proof that the filter
//! removes nothing Vector keeps and changes no detection.

mod filter;
mod lua;
mod predicate;
mod run;

pub use crate::filter::{CALL, FilterPlan, LuaFilter, lua_filter};
pub use crate::predicate::compile;
pub use crate::run::FluentBit;

/// Fluent Bit could not be used.
#[derive(Debug, thiserror::Error)]
pub enum FluentBitError {
    /// Fluent Bit could not be run, or failed.
    #[error("Fluent Bit: {0}")]
    Run(String),
    /// It forwarded something other than one record per record it was given.
    #[error("unexpected output from Fluent Bit: {0}")]
    Output(String),
}

/// The helper functions every generated filter starts with, for scripts of one's own that call
/// [`compile`]d predicates.
#[must_use]
pub fn functions() -> &'static str {
    lua::FUNCTIONS
}

/// The `[FILTER]` section that runs `script_path` on the records of `tag` (a Fluent Bit tag
/// pattern), for a classic configuration file. `enable_flb_null` is required: without it a
/// JSON null becomes `nil`, and a record the filter changes loses its null fields.
#[must_use]
pub fn filter_section(tag: &str, script_path: &str) -> String {
    format!(
        "[FILTER]\n    Name            lua\n    Match           {tag}\n    Script          \
         {script_path}\n    Call            {CALL}\n    enable_flb_null true\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_section_runs_the_script_with_nulls_kept() {
        let section = filter_section("windows.*", "/etc/fluent-bit/windows.lua");
        assert!(section.starts_with("[FILTER]\n"));
        assert!(section.contains("Match           windows.*"));
        assert!(section.contains("Call            sluice"));
        assert!(section.contains("enable_flb_null true"));
        assert!(functions().contains("local function sluice_keys"));
    }
}

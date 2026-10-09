//! Domain model and safety logic for Sluice.
//!
//! This crate is pure: no I/O, no async, no clocks or randomness. Engines that need third-party
//! code (Sigma evaluation, VRL execution) are injected through traits defined here, so that every
//! decision Sluice makes about what to forward can be tested deterministically.
//!
//! The flow through this crate:
//!
//! 1. A [`template::Template`] is discovered and a [`recipe::Recipe`] is proposed for it.
//! 2. Rule adapters describe each rule as [`rules::RuleRequirements`].
//! 3. [`guard::guard`] applies the safety contract and yields a [`guard::EffectiveRecipe`].

pub mod alert;
pub mod event;
pub mod field;
pub mod guard;
pub mod ids;
pub mod logsource;
pub mod predicate;
pub mod recipe;
pub mod rules;
pub mod source;
pub mod template;

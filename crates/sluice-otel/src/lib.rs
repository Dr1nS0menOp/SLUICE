//! OpenTelemetry Collector `transform` statements (OTTL) that carry out the field removals of a
//! savings plan in the collector (ADR 0028), and a real collector to prove them in.
//!
//! [`transform`] turns the plan of one source into OTTL statements for log records whose body
//! is the parsed JSON record (the `filelog` receiver's `json_parser` with `parse_to: body`),
//! recognising each record's template as the VRL program does and keeping whole every record a
//! rule could match ([`compile`], a superset of the VRL). [`Collector::run`] puts records
//! through the collector with the statements and without them, for the proof.

mod ottl;
mod predicate;
mod run;
mod transform;

pub use crate::predicate::compile;
pub use crate::run::Collector;
pub use crate::transform::{ROOT, Statements, TransformPlan, processor, transform};

/// The collector could not be used.
#[derive(Debug, thiserror::Error)]
pub enum OtelError {
    /// The collector could not be run, or failed.
    #[error("OpenTelemetry Collector: {0}")]
    Run(String),
    /// It forwarded something other than one record per record it was given.
    #[error("unexpected output from the OpenTelemetry Collector: {0}")]
    Output(String),
}

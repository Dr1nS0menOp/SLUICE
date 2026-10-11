//! Reductions as KQL, for Azure Monitor data collection rule (DCR) transformations, the way
//! Microsoft Sentinel ingests data (ADR 0013).
//!
//! A DCR transformation sees one record at a time as columns, one per top-level field, and only
//! accepts a subset of KQL (docs/notes/sentinel-dcr.md). Everything generated here stays inside
//! that subset.
//!
//! The KQL engine is not the VRL engine, so a predicate compiles to a *superset*: whenever the
//! VRL that Vector runs (and the proof checks) matches an event, the KQL matches it too. Where
//! KQL cannot decide exactly the same way, the test widens to `true`. A keep-whole condition can
//! then only keep more of an event, never less.

mod predicate;
mod syntax;

pub use crate::predicate::compile;

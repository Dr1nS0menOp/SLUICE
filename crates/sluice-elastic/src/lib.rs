//! Reductions as Elasticsearch ingest pipelines (ADR 0024), the way Elastic ingests data
//! without a pipeline tool in front of it.
//!
//! An ingest pipeline sees one document at a time and keeps no state between documents, so only
//! field removals run here (L1); counting instead of sending stays with a pipeline tool. The
//! pipeline is one Painless `script` processor that recognises a document's template exactly as
//! Vector's VRL does, decides whether a rule could match it, and only then removes fields.
//!
//! Painless is not VRL, so a keep-whole condition compiles to a *superset* ([`compile`]):
//! whenever the VRL that the proof checks matches an event, the Painless matches it too, and a
//! document can only keep more of its fields, never fewer. [`simulate`] runs a pipeline in a
//! real Elasticsearch, which is how the result is proven before it is written.
//!
//! [`ElasticEngine`] runs Elastic Security's EQL and ES|QL rules themselves in Elasticsearch,
//! so the proof for an Elastic destination compares what Elastic raises on full and on reduced
//! documents (ADR 0025).

mod engine;
pub mod inventory;
mod painless;
mod pipeline;
mod predicate;
mod simulate;

pub use crate::engine::{ElasticEngine, RuleQuery};
pub use crate::pipeline::{
    IngestPipeline, MAX_SCRIPT, METADATA_FIELDS, PipelinePlan, ingest_pipeline,
};
pub use crate::predicate::compile;
pub use crate::simulate::{ElasticError, simulate};

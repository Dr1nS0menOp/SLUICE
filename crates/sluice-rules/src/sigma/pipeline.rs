//! Sigma processing pipelines: Sigma's field names mapped onto another convention (ADR 0020).
//!
//! A SIEM converts a Sigma rule with a processing pipeline before it runs it: Elastic's
//! conversion maps `Image` to `process.executable`. Sluice applies the same pipeline, through
//! rsigma's implementation of pySigma's format, so that a rule's requirements and the proof name
//! the fields the SIEM's records carry.

use rsigma_eval::pipeline::builtin::resolve_builtin;
use rsigma_eval::pipeline::{
    Pipeline, apply_pipelines, apply_pipelines_to_correlation, parse_pipeline,
};
use rsigma_parser::SigmaCollection;
use sluice_core::schema::Schema;

use crate::error::RulesError;

/// A processing pipeline and the field naming convention its output follows.
#[derive(Debug, Clone)]
pub struct SigmaPipeline {
    schema: Schema,
    name: String,
    pipeline: Pipeline,
}

impl SigmaPipeline {
    /// A pipeline that ships with rsigma: `ecs_windows`, `sysmon` or `fibratus_windows`. Its
    /// output is taken to follow `schema`.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError::SigmaPipeline`] for an unknown name.
    pub fn builtin(schema: Schema, name: &str) -> Result<Self, RulesError> {
        let pipeline = resolve_builtin(name)
            .ok_or_else(|| RulesError::SigmaPipeline(format!("no built-in pipeline `{name}`")))?
            .map_err(|e| RulesError::SigmaPipeline(format!("{name}: {e}")))?;
        Self::checked(schema, name, pipeline)
    }

    /// A pipeline in pySigma's YAML format, whose output follows `schema`.
    ///
    /// # Errors
    ///
    /// Returns [`RulesError::SigmaPipeline`] if the YAML is not a pipeline, or if it reads
    /// external sources (`${source.…}`), which would fetch data or run commands at load time.
    pub fn parse(schema: Schema, name: &str, yaml: &str) -> Result<Self, RulesError> {
        let pipeline =
            parse_pipeline(yaml).map_err(|e| RulesError::SigmaPipeline(format!("{name}: {e}")))?;
        Self::checked(schema, name, pipeline)
    }

    fn checked(schema: Schema, name: &str, pipeline: Pipeline) -> Result<Self, RulesError> {
        if pipeline.is_dynamic() {
            return Err(RulesError::SigmaPipeline(format!(
                "{name} reads external sources (`${{source.…}}`); Sluice only uses pipelines \
                 whose mappings are in the file"
            )));
        }
        if !schema.is_declared() || schema == Schema::Sigma {
            return Err(RulesError::SigmaPipeline(format!(
                "{name}: a pipeline maps Sigma's names onto another convention; name it \
                 (ecs, cim, asim, ocsf, udm or sentinel)"
            )));
        }
        Ok(Self {
            schema,
            name: name.to_owned(),
            pipeline,
        })
    }

    /// The convention the pipeline's output follows.
    #[must_use]
    pub fn schema(&self) -> Schema {
        self.schema
    }

    /// The pipeline's name as given.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `collection` with the pipeline applied to every rule and correlation. Filters stay as
    /// they are: rsigma applies them to the transformed rules unchanged, as it does when it
    /// loads a collection through a pipeline.
    pub(crate) fn apply(
        &self,
        collection: &SigmaCollection,
    ) -> Result<SigmaCollection, RulesError> {
        let pipelines = std::slice::from_ref(&self.pipeline);
        let mut mapped = collection.clone();
        mapped.errors.clear();
        for rule in &mut mapped.rules {
            apply_pipelines(pipelines, rule)
                .map_err(|e| RulesError::SigmaPipeline(format!("{}: {e}", self.name)))?;
        }
        for correlation in &mut mapped.correlations {
            apply_pipelines_to_correlation(pipelines, correlation)
                .map_err(|e| RulesError::SigmaPipeline(format!("{}: {e}", self.name)))?;
        }
        Ok(mapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ecs_pipeline_ships_with_rsigma() {
        let ecs = SigmaPipeline::builtin(Schema::Ecs, "ecs_windows").expect("built in");
        assert_eq!(ecs.schema(), Schema::Ecs);
        assert_eq!(ecs.name(), "ecs_windows");
        assert!(SigmaPipeline::builtin(Schema::Ecs, "nope").is_err());
    }

    #[test]
    fn a_pipeline_must_name_another_convention() {
        let yaml = "name: x\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: process.executable\n";
        assert!(SigmaPipeline::parse(Schema::Sigma, "x", yaml).is_err());
        assert!(SigmaPipeline::parse(Schema::Undeclared, "x", yaml).is_err());
        assert!(SigmaPipeline::parse(Schema::Ecs, "x", yaml).is_ok());
    }

    #[test]
    fn pipelines_that_fetch_at_load_time_are_refused() {
        let yaml = "name: x\ntransformations:\n  - type: field_name_mapping\n    mapping:\n      Image: '${source.remote.field}'\n";
        let refused = SigmaPipeline::parse(Schema::Ecs, "x", yaml);
        assert!(refused.is_err(), "{refused:?}");
    }
}

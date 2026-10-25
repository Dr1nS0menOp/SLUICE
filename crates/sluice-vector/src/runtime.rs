//! Runs the generated VRL with the `vrl` crate, the same compiler and runtime Vector embeds.

use std::collections::BTreeMap;

use serde_json::Value as Json;
use sluice_core::event::Event;
use sluice_core::ids::{SourceId, TemplateId};
use sluice_core::predicate::Predicate;
use sluice_core::reduce::{Outcome, ReduceError, Reduced, Reducer};
use vrl::compiler::runtime::Runtime;
use vrl::compiler::state::ExternalEnv;
use vrl::compiler::{CompileConfig, Program, TargetValue, TimeZone};
use vrl::diagnostic::DiagnosticList;
use vrl::value::kind::Collection;
use vrl::value::{Kind, ObjectMap, Secrets, Value};

use crate::error::VectorError;
use crate::predicate;
use crate::program::{FORWARD, ROUTE_METADATA, SUMMARIZE, TEMPLATE_METADATA};

/// A compiled VRL program and its source text.
#[derive(Debug)]
pub struct CompiledProgram {
    source: String,
    program: Program,
}

impl CompiledProgram {
    /// Compiles VRL source with the full standard library, in the environment Vector's `remap`
    /// gives a log event: the event and its metadata are objects.
    ///
    /// Warnings are errors. Vector type-checks the same source, and a warning there (such as an
    /// unnecessary `!`) means our view of the program differs from Vector's.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::Compile`] with VRL's diagnostics if the source does not compile
    /// cleanly.
    pub fn compile(name: &str, source: String) -> Result<Self, VectorError> {
        let functions = vrl::stdlib::all();
        let object = || Kind::object(Collection::any());
        let environment = ExternalEnv::new_with_kind(object(), object());
        let failed = |diagnostics: DiagnosticList| VectorError::Compile {
            program: name.to_owned(),
            diagnostics: vrl::diagnostic::Formatter::new(&source, diagnostics).to_string(),
        };
        let result = vrl::compiler::compile_with_external(
            &source,
            &functions,
            &environment,
            CompileConfig::default(),
        )
        .map_err(failed)?;
        if !result.warnings.is_empty() {
            return Err(failed(result.warnings));
        }
        Ok(Self {
            source,
            program: result.program,
        })
    }

    /// The VRL source.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Runs the program on an event body; returns the body and metadata it produced.
    pub(crate) fn run(
        &self,
        fields: &serde_json::Map<String, Json>,
    ) -> Result<(Value, Value), String> {
        self.run_with(fields, Value::Object(ObjectMap::new()))
    }

    /// Runs the program on an event body with the metadata an earlier transform left.
    pub(crate) fn run_with(
        &self,
        fields: &serde_json::Map<String, Json>,
        metadata: Value,
    ) -> Result<(Value, Value), String> {
        let mut target = TargetValue {
            value: Value::from(Json::Object(fields.clone())),
            metadata,
            secrets: Secrets::default(),
        };
        Runtime::default()
            .resolve(&mut target, &self.program, &TimeZone::default())
            .map_err(|e| e.to_string())?;
        Ok((target.value, target.metadata))
    }
}

/// The data plane's reductions, run exactly as Vector runs them.
#[derive(Debug, Default)]
pub struct VrlReducer {
    programs: BTreeMap<SourceId, CompiledProgram>,
    summaries: BTreeMap<SourceId, CompiledProgram>,
}

impl VrlReducer {
    /// A reducer running `programs`, one per source. Sources without a program pass through.
    #[must_use]
    pub fn new(programs: BTreeMap<SourceId, CompiledProgram>) -> Self {
        Self {
            programs,
            summaries: BTreeMap::new(),
        }
    }

    /// With the program that turns a counted event of each source into its summary record, as
    /// Vector's `summarize` remap does.
    #[must_use]
    pub fn with_summaries(mut self, summaries: BTreeMap<SourceId, CompiledProgram>) -> Self {
        self.summaries = summaries;
        self
    }

    /// The summary record of a counted `body`: what the source's summary program makes of it,
    /// or, without one, a record that names the source and the template.
    fn summary(
        &self,
        event: &Event,
        body: &serde_json::Map<String, Json>,
        metadata: Value,
        template: Option<&TemplateId>,
    ) -> Result<serde_json::Map<String, Json>, ReduceError> {
        let Some(program) = self.summaries.get(&event.source) else {
            let mut record = serde_json::Map::new();
            record.insert("sluice_summary".into(), Json::Bool(true));
            record.insert("sluice_source".into(), Json::from(event.source.as_str()));
            record.insert(
                "sluice_template".into(),
                Json::from(template.map_or("", TemplateId::as_str)),
            );
            record.insert("sluice_keys".into(), Json::Object(serde_json::Map::new()));
            record.insert("sluice_count".into(), Json::from(1));
            return Ok(record);
        };
        let (record, _) = program
            .run_with(body, metadata)
            .map_err(|e| ReduceError(format!("event {} (summary): {e}", event.id)))?;
        match serde_json::to_value(&record) {
            Ok(Json::Object(map)) => Ok(map),
            _ => Err(ReduceError(format!(
                "event {}: the summary is not an object",
                event.id
            ))),
        }
    }

    /// The program of a source, if it has one.
    #[must_use]
    pub fn program(&self, source: &SourceId) -> Option<&CompiledProgram> {
        self.programs.get(source)
    }
}

impl Reducer for VrlReducer {
    fn reduce(&self, event: &Event) -> Result<Reduced, ReduceError> {
        let Some(program) = self.programs.get(&event.source) else {
            return Ok(Reduced {
                template: None,
                outcome: Outcome::Forwarded(event.fields.clone()),
            });
        };
        let (body, metadata) = program
            .run(&event.fields)
            .map_err(|e| ReduceError(format!("event {}: {e}", event.id)))?;
        let sluice = match &metadata {
            Value::Object(map) => map.get("sluice").cloned(),
            _ => None,
        };
        let field = |name: &str| match &sluice {
            Some(Value::Object(map)) => map.get(name).and_then(|v| match v {
                Value::Bytes(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
                _ => None,
            }),
            _ => None,
        };
        let template = field(TEMPLATE_METADATA).map(TemplateId::new);
        let outcome = match field(ROUTE_METADATA).as_deref() {
            Some(FORWARD) => match serde_json::to_value(&body) {
                Ok(Json::Object(map)) => Outcome::Forwarded(map),
                Ok(_) => {
                    return Err(ReduceError(format!(
                        "event {}: body is not an object",
                        event.id
                    )));
                }
                Err(e) => return Err(ReduceError(format!("event {}: {e}", event.id))),
            },
            Some(SUMMARIZE) => match serde_json::to_value(&body) {
                Ok(Json::Object(map)) => {
                    Outcome::Summarized(self.summary(event, &map, metadata, template.as_ref())?)
                }
                _ => {
                    return Err(ReduceError(format!(
                        "event {}: body is not an object",
                        event.id
                    )));
                }
            },
            other => {
                return Err(ReduceError(format!(
                    "event {}: unexpected route {other:?}",
                    event.id
                )));
            }
        };
        Ok(Reduced { template, outcome })
    }
}

/// A pre-filter compiled to a standalone VRL program, for checking it against events.
#[derive(Debug)]
pub struct PredicateProgram(CompiledProgram);

impl PredicateProgram {
    /// Compiles a predicate.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::Compile`] if the generated VRL does not compile (a Sluice bug).
    pub fn compile(predicate: &Predicate) -> Result<Self, VectorError> {
        let compiled = predicate::compile(predicate, "_p");
        let source = format!(
            "{}\n.sluice_match = {}\n",
            compiled.statements.join("\n"),
            compiled.expression
        );
        CompiledProgram::compile("predicate", source).map(Self)
    }

    /// Whether the predicate matches an event body.
    ///
    /// # Errors
    ///
    /// Returns [`ReduceError`] if the program aborts.
    pub fn matches(&self, fields: &serde_json::Map<String, Json>) -> Result<bool, ReduceError> {
        let (body, _) = self.0.run(fields).map_err(ReduceError)?;
        match body {
            Value::Object(map) => Ok(matches!(
                map.get("sluice_match"),
                Some(Value::Boolean(true))
            )),
            _ => Err(ReduceError(
                "predicate program produced no object".to_owned(),
            )),
        }
    }

    /// The VRL source.
    #[must_use]
    pub fn source(&self) -> &str {
        self.0.source()
    }
}

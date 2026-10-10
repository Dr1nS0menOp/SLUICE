//! Sigma evaluation through rsigma, behind the core [`RuleEngine`] trait.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use rsigma_eval::event::{Event as SigmaEvent, EventValue, JsonEvent};
use rsigma_eval::{CorrelationConfig, CorrelationEngine, LogSourceExtractor};
use rsigma_parser::SigmaCollection;
use serde_json::Value;
use sluice_core::alert::{Alert, EngineError, RuleEngine};
use sluice_core::event::Event;
use sluice_core::ids::SourceId;
use sluice_core::logsource::LogSource;
use sluice_core::source::Source;

use crate::error::RulesError;
use crate::sigma::rule_id;

/// Reserved field names under which [`Scoped`] reports an event's log source to rsigma. The
/// prefix keeps them from colliding with real event fields.
const PRODUCT: &str = "__sluice.logsource.product";
const SERVICE: &str = "__sluice.logsource.service";
const CATEGORY: &str = "__sluice.logsource.category";
/// Reported for an attribute a complete log source lacks: equal to no rule's value, so rsigma
/// skips rules that name it, exactly as [`LogSource::may_apply_to`] does.
const ABSENT: &str = "__sluice.absent";

/// Evaluates a Sigma rule collection, including correlations.
///
/// Rules are scoped by the log source of each event's [`Source`], with the same conflict-based
/// semantics as [`LogSource::may_apply_to`]: a rule only skips an event whose source provably
/// is something else.
#[derive(Debug)]
pub struct SigmaEngine {
    collection: SigmaCollection,
    logsources: BTreeMap<SourceId, LogSource>,
}

impl SigmaEngine {
    pub(crate) fn new(collection: SigmaCollection, sources: &[Source]) -> Result<Self, RulesError> {
        // Fail early on rules rsigma cannot compile, rather than on first evaluation.
        fresh_engine(&collection)?;
        Ok(Self {
            collection,
            logsources: sources
                .iter()
                .map(|s| (s.id.clone(), s.logsource.clone()))
                .collect(),
        })
    }
}

fn fresh_engine(collection: &SigmaCollection) -> Result<CorrelationEngine, RulesError> {
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    engine
        .add_collection(collection)
        .map_err(|e| RulesError::SigmaCompile(e.to_string()))?;
    engine.set_logsource_extractor(Some(
        LogSourceExtractor::new().with_field_names(PRODUCT, SERVICE, CATEGORY),
    ));
    Ok(engine)
}

impl RuleEngine for SigmaEngine {
    fn alerts(&self, events: &[Event]) -> Result<BTreeSet<Alert>, EngineError> {
        let mut engine = fresh_engine(&self.collection).map_err(|e| EngineError(e.to_string()))?;
        let unknown = LogSource::default();
        let mut alerts = BTreeSet::new();
        for event in events {
            let scoped = Scoped {
                inner: JsonEvent::owned(Value::Object(event.fields.clone())),
                logsource: self.logsources.get(&event.source).unwrap_or(&unknown),
            };
            for result in engine.process_event_at(&scoped, event.timestamp.0) {
                let id = rule_id(result.header.rule_id.as_deref(), &result.header.rule_title);
                alerts.insert(Alert {
                    rule: id,
                    event: event.id,
                });
            }
        }
        Ok(alerts)
    }
}

/// An event plus its source's log source, exposed to rsigma under reserved field names.
struct Scoped<'a> {
    inner: JsonEvent<'a>,
    logsource: &'a LogSource,
}

impl SigmaEvent for Scoped<'_> {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        let reserved = match path {
            PRODUCT => Some(&self.logsource.product),
            SERVICE => Some(&self.logsource.service),
            CATEGORY => Some(&self.logsource.category),
            _ => None,
        };
        match reserved {
            Some(value) => match value.as_deref() {
                Some(v) => Some(EventValue::Str(Cow::Borrowed(v))),
                None if self.logsource.complete => Some(EventValue::Str(Cow::Borrowed(ABSENT))),
                None => None,
            },
            None => self.inner.get_field(path),
        }
    }

    // Keyword search and serialization see only the real event, never the reserved fields.
    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        self.inner.any_string_value(pred)
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        self.inner.all_string_values()
    }

    fn visit_string_values(&self, visit: &mut dyn FnMut(&str)) {
        self.inner.visit_string_values(visit);
    }

    fn to_json(&self) -> Value {
        self.inner.to_json()
    }

    fn field_keys(&self) -> Vec<Cow<'_, str>> {
        self.inner.field_keys()
    }

    fn top_level_keys(&self) -> Option<Vec<Cow<'_, str>>> {
        // Unknown shape: the reserved fields are not real roots, so let rsigma probe every path.
        None
    }
}

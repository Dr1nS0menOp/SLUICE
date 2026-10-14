//! Reads the reductions back out of a Vector configuration Sluice generated, so a configuration
//! under review (a pull request, a proposal) can be proven as it is, not as it was meant to be
//! (`sluice prove`, M11).
//!
//! Per source, the program transform (`sluice_<src>`, or `sluice_<src>_<profile>` when the
//! configuration serves several rule profiles) is compiled with the `vrl` crate. The wiring
//! around it must be Sluice's own, or the proof would not describe what Vector does:
//!
//! - the program drops nothing on error (`drop_on_error` with `reroute_dropped`), and its
//!   `dropped` output is consumed: an event the program fails on is forwarded unmodified;
//! - the route forwards exactly `%sluice.route == "forward"` and summarizes exactly
//!   `%sluice.route == "summarize"`, and both `forward` and `_unmatched` are consumed.
//!
//! Every transform must be one Sluice generates (`sluice_…`, of type `remap`, `route`,
//! `reduce` or `sample`), and no remap may `abort`, which Vector answers by dropping the event.
//! Anything else is refused: the configuration cannot be proven. Sources and sinks are the
//! operator's, used verbatim, and are reviewed like any other configuration change.

use std::collections::BTreeMap;

use serde_json::Value;
use sluice_core::ids::SourceId;
use sluice_core::source::Source;

use crate::config::Components;
use crate::error::VectorError;
use crate::program::{FORWARD, ROUTE_METADATA, SUMMARIZE};
use crate::runtime::{CompiledProgram, VrlReducer};
use crate::syntax;

/// The reductions of a generated configuration.
#[derive(Debug)]
pub struct Deployed {
    /// The data plane, as the configuration runs it.
    pub reducer: VrlReducer,
    /// Sources the configuration does not reduce: their events are forwarded as they are.
    pub unreduced: Vec<SourceId>,
}

/// Reads the reductions of `yaml` for `sources`, for the rule profile `profile` when the
/// configuration was generated for several.
///
/// # Errors
///
/// Returns [`VectorError::NotProvable`] if the configuration cannot be read or a source's wiring is
/// not Sluice's, and [`VectorError::Compile`] if a program does not compile cleanly.
pub fn deployed(
    yaml: &str,
    sources: &[Source],
    profile: Option<&str>,
) -> Result<Deployed, VectorError> {
    let config: Value =
        serde_yaml_ng::from_str(yaml).map_err(|e| VectorError::NotProvable(e.to_string()))?;
    let transforms = config["transforms"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    check_transforms(&transforms)?;
    let consumed = consumed_outputs(&config);
    let mut programs = BTreeMap::new();
    let mut unreduced = Vec::new();
    for source in sources {
        let base = Components::for_source(&source.id);
        let c = profile.map_or_else(|| base.clone(), |p| base.for_profile(p));
        let Some(program) = transforms.get(&c.program) else {
            unreduced.push(source.id.clone());
            continue;
        };
        check_wiring(&source.id, &c, program, &transforms, &consumed)?;
        let text = program["source"].as_str().ok_or_else(|| {
            VectorError::NotProvable(format!("{}: the program has no VRL source", c.program))
        })?;
        programs.insert(
            source.id.clone(),
            CompiledProgram::compile(&c.program, text.to_owned())?,
        );
    }
    if programs.is_empty() && !sources.is_empty() {
        let hint = if profile.is_none() {
            "; for a configuration with several rule profiles, name one"
        } else {
            ""
        };
        return Err(VectorError::NotProvable(format!(
            "no Sluice program for any of the sources in this configuration{hint}"
        )));
    }
    Ok(Deployed {
        reducer: VrlReducer::new(programs),
        unreduced,
    })
}

/// Transform types Sluice generates.
const SLUICE_TRANSFORMS: [&str; 4] = ["remap", "route", "reduce", "sample"];

/// Refuses transforms Sluice does not generate: one that filters, or a remap that aborts,
/// would drop events the proof counts as forwarded.
fn check_transforms(transforms: &serde_json::Map<String, Value>) -> Result<(), VectorError> {
    for (id, transform) in transforms {
        let kind = transform["type"].as_str().unwrap_or_default();
        let aborts = kind == "remap"
            && transform["source"].as_str().is_some_and(|vrl| {
                vrl.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|word| word == "abort")
            });
        if !id.starts_with("sluice_") || !SLUICE_TRANSFORMS.contains(&kind) || aborts {
            return Err(VectorError::NotProvable(format!(
                "transform {id} ({kind}) is not one Sluice generates"
            )));
        }
    }
    Ok(())
}

/// Every `component.output` (or bare component) some component takes as input.
fn consumed_outputs(config: &Value) -> Vec<String> {
    ["transforms", "sinks"]
        .iter()
        .filter_map(|section| config[section].as_object())
        .flat_map(|components| components.values())
        .filter_map(|component| component["inputs"].as_array())
        .flatten()
        .filter_map(|input| input.as_str().map(str::to_owned))
        .collect()
}

fn check_wiring(
    source: &SourceId,
    c: &Components,
    program: &Value,
    transforms: &serde_json::Map<String, Value>,
    consumed: &[String],
) -> Result<(), VectorError> {
    let refuse = |why: &str| {
        Err(VectorError::NotProvable(format!(
            "source {source}: {why}; Sluice does not generate this wiring"
        )))
    };
    if program["type"] != "remap"
        || program["drop_on_error"] != true
        || program["reroute_dropped"] != true
    {
        return refuse(&format!(
            "{} must be a remap with drop_on_error and reroute_dropped",
            c.program
        ));
    }
    let route = transforms.get(&c.split).cloned().unwrap_or_default();
    let route_on = |value: &str| {
        Value::String(format!(
            "%sluice.{ROUTE_METADATA} == {}",
            syntax::string(value)
        ))
    };
    let routes = route["route"].as_object();
    let exact = routes.is_some_and(|r| {
        r.len() == 2
            && r.get(FORWARD) == Some(&route_on(FORWARD))
            && r.get(SUMMARIZE) == Some(&route_on(SUMMARIZE))
    });
    if route["type"] != "route" || route["inputs"] != serde_json::json!([c.program]) || !exact {
        return refuse(&format!(
            "{} must route on %sluice.{ROUTE_METADATA} only",
            c.split
        ));
    }
    for output in [
        format!("{}.{FORWARD}", c.split),
        format!("{}._unmatched", c.split),
        format!("{}.dropped", c.program),
    ] {
        if !consumed.contains(&output) {
            return refuse(&format!(
                "{output} goes nowhere, so its events would be lost"
            ));
        }
    }
    Ok(())
}

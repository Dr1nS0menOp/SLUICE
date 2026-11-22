//! One VRL program per source: classify, route, reduce.
//!
//! The program writes two metadata fields that the Vector config routes on, and that the proof
//! reads back:
//!
//! - `%sluice.template`: the template the event was classified as (absent if none);
//! - `%sluice.route`: `forward` (send to the SIEM) or `summarize` (count into a summary; the
//!   original is in the archive).
//!
//! Reductions only touch events that are forwarded. A summarized event keeps every field, so the
//! summary can be keyed on any of them.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::guard::Route;
use sluice_core::template::TemplateShape;

use crate::classify::{self, Classifier, KEYS};
use crate::predicate;
use crate::syntax;

/// Metadata field with the classified template.
pub const TEMPLATE_METADATA: &str = "template";
/// Metadata field with the route.
pub const ROUTE_METADATA: &str = "route";
/// Route value for events sent to the SIEM.
pub const FORWARD: &str = "forward";
/// Route value for events counted into summaries.
pub const SUMMARIZE: &str = "summarize";

pub use sluice_core::guard::Plan;

/// The VRL source for one source's templates.
#[must_use]
pub fn source_program(plans: &[Plan<'_>]) -> String {
    let mut ordered: Vec<(&Plan<'_>, Classifier)> = plans
        .iter()
        .filter_map(|plan| classify::classifier(&plan.template.shape).map(|c| (plan, c)))
        .collect();
    // Exact keysets first; then text templates, most specific (fewest wildcards) first.
    ordered.sort_by_key(|(plan, classifier)| {
        let rank = match classifier {
            Classifier::Keyset(_) => 0,
            Classifier::Text { .. } => 1 + wildcards(&plan.template.shape),
        };
        (rank, plan.template.id.clone())
    });

    let mut lines = vec![format!(
        "%sluice.{ROUTE_METADATA} = {}",
        syntax::string(FORWARD)
    )];
    if ordered
        .iter()
        .any(|(_, c)| matches!(c, Classifier::Keyset(_)))
    {
        lines.push(format!("{KEYS} = join(keys(flatten(.)), \"\\n\")"));
    }
    let text_vars = text_variables(&ordered, &mut lines);
    let parsed = parse_block(&ordered, &text_vars, &mut lines);

    lines.push("_sluice_t = \"\"".to_owned());
    for (n, (plan, classifier)) in ordered.iter().enumerate() {
        let condition = match classifier {
            Classifier::Keyset(expression) => expression.clone(),
            Classifier::Text { field, regex } => format!("match({}, {regex})", text_vars[field]),
        };
        let keyword = if n == 0 { "if" } else { "} else if" };
        lines.push(format!(
            "{keyword} {condition} {{\n  _sluice_t = {}",
            syntax::string(plan.template.id.as_str())
        ));
    }
    if !ordered.is_empty() {
        lines.push("}".to_owned());
    }
    lines.push(format!(
        "if _sluice_t != \"\" {{ %sluice.{TEMPLATE_METADATA} = _sluice_t }}"
    ));

    for (plan, _) in &ordered {
        if !plan.recipe.is_passthrough() {
            let fields = if plan.template.parser.is_some() {
                parsed.iter().collect()
            } else {
                BTreeSet::new()
            };
            lines.push(reduction(plan, &fields));
        }
    }
    let mut program = lines.join("\n");
    program.push('\n');
    program
}

/// Declares one variable per text field holding its string value (or `""`).
fn text_variables(
    ordered: &[(&Plan<'_>, Classifier)],
    lines: &mut Vec<String>,
) -> BTreeMap<FieldPath, String> {
    let mut vars = BTreeMap::new();
    for (_, classifier) in ordered {
        if let Classifier::Text { field, .. } = classifier
            && !vars.contains_key(field)
        {
            let var = format!("_sluice_line{}", vars.len());
            let path = syntax::path(field);
            lines.push(format!(
                "{var} = if is_string({path}) {{ string!({path}) }} else {{ \"\" }}"
            ));
            vars.insert(field.clone(), var);
        }
    }
    vars
}

/// Parses the line of a source whose text templates name a parser pack (ADR 0043) into
/// [`predicate::PARSED`]: the fields of the first pattern that matches, by their full names, or
/// none. Returns the fields it can give; none without a parser. A pattern VRL cannot quote is
/// skipped, so its fields stay missing and every test on them is true.
fn parse_block(
    ordered: &[(&Plan<'_>, Classifier)],
    text_vars: &BTreeMap<FieldPath, String>,
    lines: &mut Vec<String>,
) -> BTreeSet<FieldPath> {
    let Some((parser, line)) = ordered.iter().find_map(|(plan, _)| {
        let TemplateShape::Text { field, .. } = &plan.template.shape else {
            return None;
        };
        Some((plan.template.parser.as_ref()?, text_vars.get(field)?))
    }) else {
        return BTreeSet::new();
    };
    // Every field the pack can give is read from the parse, also one of a pattern skipped below:
    // read from the event instead, a test on it would be false where the SIEM's could be true.
    let given: BTreeSet<FieldPath> = parser.fields().into_iter().cloned().collect();
    // Each pattern is tried only when the ones before it did not match: built from the last one
    // back, so the last has no empty `else`, which VRL does not accept.
    let tries: Vec<(String, String)> = parser
        .patterns
        .iter()
        .enumerate()
        .filter_map(|(n, pattern)| {
            let regex = syntax::regex(&pattern.regex)?;
            let (found, error) = (format!("_sluice_pm{n}"), format!("_sluice_pe{n}"));
            let fields: Vec<String> = pattern
                .fields
                .iter()
                .map(|(group, field)| {
                    format!(
                        "{}: {found}.{}",
                        syntax::string(field.as_str()),
                        syntax::string(group)
                    )
                })
                .collect();
            Some((
                format!("{found}, {error} = parse_regex({line}, {regex})"),
                // Through JSON, so VRL types the values as anything, as it does an event's: the
                // tests on them are the ones written for event fields.
                format!(
                    "if {error} == null {{\n  {} = object(parse_json!(encode_json({{ {} }}))) ?? {{}}\n}}",
                    predicate::PARSED,
                    fields.join(", ")
                ),
            ))
        })
        .collect();
    let chain = tries
        .into_iter()
        .rev()
        .fold(String::new(), |rest, (parse, matched)| {
            if rest.is_empty() {
                format!("{parse}\n{matched}")
            } else {
                format!("{parse}\n{matched} else {{\n{}\n}}", indent(&rest))
            }
        });
    lines.push(format!("{} = {{}}", predicate::PARSED));
    if !chain.is_empty() {
        lines.push(chain);
    }
    given
}

/// `text` with every line indented by two spaces.
fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn wildcards(shape: &TemplateShape) -> usize {
    match shape {
        TemplateShape::Text { tokens, .. } => tokens.iter().filter(|t| t.contains('<')).count(),
        TemplateShape::Keyset { .. } => 0,
    }
}

/// The routing and reduction block of one template; its tests read `parsed` fields from the
/// line's parse.
fn reduction(plan: &Plan<'_>, parsed: &BTreeSet<&FieldPath>) -> String {
    let mut body = Vec::new();
    if let Route::ForwardMatching { prefilter, .. } = &plan.recipe.route {
        let compiled = predicate::compile_parsed(prefilter, "_sluice_p", parsed);
        body.extend(compiled.statements);
        body.push(format!(
            "if !({}) {{ %sluice.{ROUTE_METADATA} = {} }}",
            compiled.expression,
            syntax::string(SUMMARIZE)
        ));
    }
    let mut shaping: Vec<String> = plan
        .recipe
        .drop_fields
        .iter()
        .map(|field| format!("del({})", syntax::path(field)))
        .collect();
    if let Some(except) = &plan.recipe.drop_empty_except {
        let keep = |field: &FieldPath| except.iter().any(|e| e.covers(field) || field.covers(e));
        shaping.extend(
            plan.template
                .fields
                .iter()
                .filter(|field| !keep(field) && !plan.recipe.drop_fields.contains(*field))
                .map(|field| {
                    let path = syntax::path(field);
                    format!("if is_null({path}) || {path} == \"\" {{ del({path}) }}")
                }),
        );
    }
    // Last, so a field that implies another is tested as it is forwarded: the value is only
    // removed while what implies it stays, and can be put back from the plan.
    shaping.extend(plan.recipe.drop_implied.iter().map(|implied| {
        let path = syntax::path(&implied.field);
        let mut test = syntax::equals(&path, &implied.value);
        if let Some((on, value)) = &implied.when {
            test = format!("{test} && {}", syntax::equals(&syntax::path(on), value));
        }
        format!("if {test} {{ del({path}) }}")
    }));
    if !shaping.is_empty() {
        shaping = emptied_objects_go(&plan.emptiable_objects(), shaping);
        // Events a protecting rule could match are forwarded whole (contract rule 3). The test
        // runs on the event before any field is removed.
        let mut condition = format!("%sluice.{ROUTE_METADATA} == {}", syntax::string(FORWARD));
        if let Some(keep) = &plan.recipe.keep_whole_when {
            let compiled = predicate::compile_parsed(keep, "_sluice_k", parsed);
            body.extend(compiled.statements);
            condition = format!("{condition} && !({})", compiled.expression);
        }
        body.push(format!(
            "if {condition} {{\n    {}\n  }}",
            shaping.join("\n    ")
        ));
    }
    format!(
        "if _sluice_t == {} {{\n  {}\n}}",
        syntax::string(plan.template.id.as_str()),
        body.join("\n  ")
    )
}

/// `shaping`, followed by removing each of `parents` (deepest first) that it emptied. An object
/// is removed only if it held a field before the shaping: an empty object that came with the
/// event is sent as it came.
fn emptied_objects_go(parents: &[FieldPath], shaping: Vec<String>) -> Vec<String> {
    if parents.is_empty() {
        return shaping;
    }
    let mut out: Vec<String> = parents
        .iter()
        .enumerate()
        .map(|(n, parent)| {
            let path = syntax::path(parent);
            format!("_sluice_o{n} = is_object({path}) && (length({path}) ?? 0) > 0")
        })
        .collect();
    out.extend(shaping);
    out.extend(parents.iter().enumerate().map(|(n, parent)| {
        let path = syntax::path(parent);
        format!("if _sluice_o{n} && (length({path}) ?? 1) == 0 {{ del({path}) }}")
    }));
    out
}

#[cfg(test)]
mod tests;

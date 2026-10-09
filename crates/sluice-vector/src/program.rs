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

use std::collections::BTreeMap;

use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::template::{Template, TemplateShape};

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

/// A template and what may be enforced for it.
#[derive(Debug, Clone, Copy)]
pub struct Plan<'a> {
    /// The template.
    pub template: &'a Template,
    /// Its effective recipe.
    pub recipe: &'a EffectiveRecipe,
}

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
            lines.push(reduction(plan));
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

fn wildcards(shape: &TemplateShape) -> usize {
    match shape {
        TemplateShape::Text { tokens, .. } => tokens.iter().filter(|t| t.contains('<')).count(),
        TemplateShape::Keyset { .. } => 0,
    }
}

/// The routing and reduction block of one template.
fn reduction(plan: &Plan<'_>) -> String {
    let mut body = Vec::new();
    if let Route::ForwardMatching { prefilter, .. } = &plan.recipe.route {
        let compiled = predicate::compile(prefilter, "_sluice_p");
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
    if !shaping.is_empty() {
        body.push(format!(
            "if %sluice.{ROUTE_METADATA} == {} {{\n    {}\n  }}",
            syntax::string(FORWARD),
            shaping.join("\n    ")
        ));
    }
    format!(
        "if _sluice_t == {} {{\n  {}\n}}",
        syntax::string(plan.template.id.as_str()),
        body.join("\n  ")
    )
}

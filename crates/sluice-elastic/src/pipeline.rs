//! An ingest pipeline that carries out the field removals of a savings plan (ADR 0023, ADR 0024)
//! in Elasticsearch's own ingestion.
//!
//! Three rules keep it from ever removing more than Vector would:
//!
//! - **Recognition is exact and in Vector's order.** A document belongs to a template only if
//!   its leaf paths are exactly one of the template's key sets and its discriminators render to
//!   the recorded values, tested in the order of the VRL program (by template id). Every
//!   key-set template takes part, also those whose saving runs elsewhere, so no document is
//!   claimed by another template than in Vector. A document that fits none keeps every field
//!   (contract rule 1).
//! - **Keeping whole is a superset.** `keep_whole_when` compiles with [`crate::compile`], which
//!   matches at least what Vector's VRL matches.
//! - **Nothing changes before everything is decided.** The script first finds the template and
//!   evaluates its keep-whole condition, then removes. `ignore_failure` keeps what a failing
//!   script changed so far, so a failure while deciding leaves the document as it was.
//!
//! Text templates (a Drain pattern over a line) are left to a pipeline tool: Java's regexes are
//! not Rust's. So is counting, which needs state across documents.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::TemplateId;
use sluice_core::predicate::Predicate;
use sluice_core::template::{Template, TemplateShape};

use crate::painless;
use crate::predicate::compile;

/// The longest script Elasticsearch compiles by default (`script.max_size_in_bytes`).
pub const MAX_SCRIPT: usize = 65_535;

/// Top-level keys of an ingest document that are Elasticsearch's metadata, not fields. A
/// template with a field of one of these names is not recognised.
pub const METADATA_FIELDS: [&str; 10] = [
    "_index",
    "_id",
    "_version",
    "_routing",
    "_version_type",
    "_if_seq_no",
    "_if_primary_term",
    "_dynamic_templates",
    "_type",
    "_ingest",
];

/// One template and the recipe enforced on it.
#[derive(Debug, Clone, Copy)]
pub struct PipelinePlan<'a> {
    /// The template, discovered on documents as the index stores them.
    pub template: &'a Template,
    /// Its enforced recipe.
    pub recipe: &'a EffectiveRecipe,
}

/// A generated ingest pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct IngestPipeline {
    /// The pipeline, as `PUT _ingest/pipeline/<name>` takes it; no processors when nothing is
    /// removed.
    pub body: Value,
    /// The templates whose documents it removes fields from.
    pub templates: BTreeSet<TemplateId>,
    /// The fields it removes from documents of those templates outside keep-whole.
    pub fields: BTreeSet<FieldPath>,
    /// Whether it also removes null and empty fields from some of them.
    pub empty_fields: bool,
    /// Parts of the plan only a pipeline tool can carry out, and why.
    pub left_out: Vec<String>,
}

/// What a recognised document of one template loses.
struct Action {
    code: String,
    fields: BTreeSet<FieldPath>,
    empty_fields: bool,
}

/// The ingest pipeline carrying out `plans`' field removals; `description` says what it is for.
#[must_use]
pub fn ingest_pipeline(description: &str, plans: &[PipelinePlan<'_>]) -> IngestPipeline {
    let mut ordered: Vec<&PipelinePlan<'_>> = plans.iter().collect();
    ordered.sort_by(|a, b| a.template.id.cmp(&b.template.id));
    let mut left_out = Vec::new();
    let mut conditions = Conditions::default();
    let recognised: Vec<(&PipelinePlan<'_>, String, Option<Action>)> = ordered
        .into_iter()
        .filter_map(|plan| {
            let condition = recognition(plan.template, &mut left_out)?;
            let action = action(plan, &mut conditions, &mut left_out);
            Some((plan, condition, action))
        })
        .collect();
    let mut branches = Vec::new();
    let mut actions = Vec::new();
    let mut templates = BTreeSet::new();
    let mut fields = BTreeSet::new();
    let mut empty_fields = false;
    for (n, (plan, condition, action)) in recognised.iter().enumerate() {
        // A template that changes nothing only needs recognising where Vector would give it a
        // document before a template that does change it.
        let claims = action.is_some()
            || recognised[n + 1..]
                .iter()
                .any(|(later, _, a)| a.is_some() && overlap(plan.template, later.template));
        if !claims {
            continue;
        }
        let branch = branches.len();
        branches.push(format!("if ({condition}) {{ t = {branch}; }}"));
        if let Some(action) = action {
            actions.push(format!("if (t == {branch}) {{\n{}\n}}", action.code));
            templates.insert(plan.template.id.clone());
            fields.extend(action.fields.iter().cloned());
            empty_fields |= action.empty_fields;
        }
    }
    let mut pipeline = IngestPipeline {
        body: json!({ "description": description, "processors": [] }),
        templates,
        fields,
        empty_fields,
        left_out,
    };
    if actions.is_empty() {
        return pipeline;
    }
    let script = format!(
        "{}{}Set keys = sluiceKeys(ctx);\nint t = -1;\n{}\n{}\n",
        painless::FUNCTIONS,
        conditions.functions.concat(),
        branches.join("\nelse "),
        actions.join("\n")
    );
    if script.len() > MAX_SCRIPT {
        pipeline.left_out.push(format!(
            "the script would be {} bytes, more than the {MAX_SCRIPT} Elasticsearch compiles, so \
             nothing is removed",
            script.len()
        ));
        pipeline.templates.clear();
        pipeline.fields.clear();
        pipeline.empty_fields = false;
        return pipeline;
    }
    pipeline.body["processors"] = json!([{
        "script": {
            "lang": "painless",
            "tag": "sluice",
            "description": "Sluice: field removals proven to change no detection (ADR 0024)",
            "ignore_failure": true,
            "source": script,
        }
    }]);
    pipeline
}

/// Whether one document could fit both templates: they share a key set, and no discriminator
/// field asks for two different values.
fn overlap(a: &Template, b: &Template) -> bool {
    let (
        TemplateShape::Keyset {
            discriminators: a_discriminators,
            variants: a_variants,
            ..
        },
        TemplateShape::Keyset {
            discriminators: b_discriminators,
            variants: b_variants,
            ..
        },
    ) = (&a.shape, &b.shape)
    else {
        return false;
    };
    a_variants.iter().any(|v| b_variants.contains(v))
        && a_discriminators.iter().all(|(field, value)| {
            b_discriminators
                .iter()
                .all(|(other, theirs)| other != field || theirs == value)
        })
}

/// The condition recognising the template's documents, or `None` (with the reason) when it has
/// none.
fn recognition(template: &Template, left_out: &mut Vec<String>) -> Option<String> {
    let id = &template.id;
    let TemplateShape::Keyset {
        discriminators,
        variants,
        ..
    } = &template.shape
    else {
        left_out.push(format!(
            "{id}: a text template is recognised by a regex, which needs a pipeline tool"
        ));
        return None;
    };
    if variants.is_empty() {
        return None;
    }
    let metadata = variants
        .iter()
        .flatten()
        .chain(discriminators.iter().map(|(field, _)| field))
        .find(|path| {
            path.segments()
                .next()
                .is_some_and(|s| METADATA_FIELDS.contains(&s))
        });
    if let Some(path) = metadata {
        left_out.push(format!(
            "{id}: its field {path} has the name of Elasticsearch metadata"
        ));
        return None;
    }
    let key_sets: Vec<String> = variants
        .iter()
        .map(|variant| {
            format!(
                "keys.equals(new HashSet({}))",
                painless::list(variant.iter().map(FieldPath::as_str))
            )
        })
        .collect();
    let mut parts = vec![if key_sets.len() == 1 {
        key_sets.concat()
    } else {
        format!("({})", key_sets.join(" || "))
    }];
    parts.extend(discriminators.iter().map(|(field, value)| {
        format!(
            "sluiceDisc(sluiceGet(ctx, {})) == {}",
            painless::segments(field),
            painless::string(value)
        )
    }));
    Some(parts.join(" && "))
}

/// The keep-whole conditions of a pipeline's templates. Those of one source repeat the same
/// rules' pre-filters, so each distinct alternative is a function once, which every template's
/// condition calls: Elasticsearch compiles at most 65,535 bytes of script.
#[derive(Default)]
struct Conditions {
    functions: Vec<String>,
    ids: BTreeMap<String, usize>,
}

impl Conditions {
    /// The Painless of `predicate`, as calls of the functions of its alternatives.
    fn call(&mut self, predicate: &Predicate) -> String {
        let parts: &[Predicate] = match predicate {
            Predicate::Any(parts) => parts,
            other => std::slice::from_ref(other),
        };
        if parts.is_empty() {
            return "false".to_owned();
        }
        let calls: Vec<String> = parts
            .iter()
            .map(|part| {
                let code = compile(part);
                let next = self.ids.len();
                let id = *self.ids.entry(code.clone()).or_insert(next);
                if id == next {
                    self.functions.push(format!(
                        "boolean sluiceKeep{id}(Map ctx) {{\n  return {code};\n}}\n"
                    ));
                }
                format!("sluiceKeep{id}(ctx)")
            })
            .collect();
        calls.join(" || ")
    }
}

/// What a recognised document of the template loses; `None` when nothing.
fn action(
    plan: &PipelinePlan<'_>,
    conditions: &mut Conditions,
    left_out: &mut Vec<String>,
) -> Option<Action> {
    let recipe = plan.recipe;
    if recipe.is_passthrough() {
        return None;
    }
    let id = &plan.template.id;
    if recipe.route != Route::ForwardAll {
        left_out.push(format!(
            "{id}: counting instead of sending needs a pipeline tool"
        ));
        return None;
    }
    let mut empty_fields = false;
    let mut lines: Vec<String> = recipe
        .drop_fields
        .iter()
        .map(|field| format!("  sluiceRemove(ctx, {});", painless::segments(field)))
        .collect();
    if let Some(except) = &recipe.drop_empty_except {
        let keep = |field: &FieldPath| except.iter().any(|e| e.covers(field) || field.covers(e));
        if plan
            .template
            .fields
            .iter()
            .any(|field| !keep(field) && !recipe.drop_fields.contains(field))
        {
            // The document is exactly one of the template's key sets, so its leaves are the
            // template's fields VRL goes through, and only exceptions that touch one of them
            // can matter.
            let relevant = except.iter().filter(|e| {
                plan.template
                    .fields
                    .iter()
                    .any(|f| e.covers(f) || f.covers(e))
            });
            lines.push(format!(
                "  sluiceRemoveEmptyExcept(ctx, keys, {}, {});",
                painless::list(relevant.map(FieldPath::as_str)),
                painless::list(recipe.drop_fields.iter().map(FieldPath::as_str))
            ));
            empty_fields = true;
        }
    }
    if lines.is_empty() {
        return None;
    }
    let body = lines.join("\n");
    let code = match &recipe.keep_whole_when {
        Some(keep) => format!("  if (!({})) {{\n{body}\n  }}", conditions.call(keep)),
        None => body,
    };
    Some(Action {
        code,
        fields: recipe.drop_fields.iter().cloned().collect(),
        empty_fields,
    })
}

#[cfg(test)]
mod tests;

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
//!   (contract rule 1), as does one with a template's key set that the script cannot tell is
//!   that template's (a discriminator holding a fraction, a field named like metadata): no
//!   later template takes it.
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
use sluice_core::guard::{Plan, Route};
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
pub fn ingest_pipeline(description: &str, plans: &[Plan<'_>]) -> IngestPipeline {
    let mut ordered: Vec<&Plan<'_>> = plans.iter().collect();
    ordered.sort_by(|a, b| a.template.id.cmp(&b.template.id));
    let mut left_out = Vec::new();
    let mut conditions = Conditions::default();
    let recognised: Vec<(&Plan<'_>, Recognition, Option<Action>)> = ordered
        .into_iter()
        .filter_map(|plan| {
            let seen = recognition(plan.template, &mut left_out)?;
            let action = seen
                .claim
                .is_some()
                .then(|| action(plan, &mut conditions, &mut left_out))
                .flatten();
            Some((plan, seen, action))
        })
        .collect();
    let mut branches = Vec::new();
    let mut actions = Vec::new();
    let mut templates = BTreeSet::new();
    let mut fields = BTreeSet::new();
    let mut empty_fields = false;
    for (n, (plan, seen, action)) in recognised.iter().enumerate() {
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
        // A document Vector may give this template but the script cannot tell: no later
        // template takes it, and nothing is removed.
        let stop = seen
            .stop
            .as_ref()
            .map(|s| format!("if ({s}) {{ t = -2; }}"));
        branches.push(match (&seen.claim, stop) {
            (Some(claim), Some(stop)) => format!("if ({claim}) {{ t = {branch}; }}\nelse {stop}"),
            (Some(claim), None) => format!("if ({claim}) {{ t = {branch}; }}"),
            (None, Some(stop)) => stop,
            (None, None) => continue,
        });
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
    // As the script sees them: a field named like metadata is not among `sluiceKeys`.
    a_variants
        .iter()
        .any(|v| b_variants.iter().any(|w| visible(v) == visible(w)))
        && a_discriminators.iter().all(|(field, value)| {
            b_discriminators
                .iter()
                .all(|(other, theirs)| other != field || theirs == value)
        })
}

/// How the script recognises a template's documents.
struct Recognition {
    /// The condition that claims them; `None` when the script cannot, for a field named like
    /// Elasticsearch metadata.
    claim: Option<String>,
    /// The condition that stops the search where a document may be the template's but the
    /// script cannot tell: a metadata name, or a discriminator Painless cannot render.
    stop: Option<String>,
}

/// The template's recognition, or `None` (with the reason) when it has no key set.
fn recognition(template: &Template, left_out: &mut Vec<String>) -> Option<Recognition> {
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
    let refused = variants
        .iter()
        .flatten()
        .chain(discriminators.iter().map(|(field, _)| field))
        .find(|path| metadata(path));
    if let Some(path) = refused {
        left_out.push(format!(
            "{id}: its field {path} has the name of Elasticsearch metadata"
        ));
    }
    let key_sets: Vec<String> = variants
        .iter()
        .map(|variant| {
            format!(
                "keys.equals(new HashSet({}))",
                painless::list(visible(variant).into_iter().map(FieldPath::as_str))
            )
        })
        .collect();
    let key_set = if key_sets.len() == 1 {
        key_sets.concat()
    } else {
        format!("({})", key_sets.join(" || "))
    };
    let mut claim = vec![key_set.clone()];
    let mut stop = vec![key_set];
    let mut undecided = refused.is_some();
    for (field, value) in discriminators {
        if metadata(field) {
            continue; // The script would read Elasticsearch's own value there.
        }
        let at = format!("sluiceGet(ctx, {})", painless::segments(field));
        let literal = painless::string(value);
        let exact = format!("sluiceDisc({at}) == {literal}");
        if undecidable(value) {
            undecided = true;
            stop.push(format!("sluiceMay({at}, {literal})"));
        } else {
            stop.push(exact.clone());
        }
        claim.push(exact);
    }
    Some(Recognition {
        claim: refused.is_none().then(|| claim.join(" && ")),
        stop: undecided.then(|| stop.join(" && ")),
    })
}

/// Whether the path's first segment is a name of Elasticsearch metadata.
pub(crate) fn metadata(path: &FieldPath) -> bool {
    path.segments()
        .next()
        .is_some_and(|s| METADATA_FIELDS.contains(&s))
}

/// A key set as `sluiceKeys` shows it: metadata left out.
pub(crate) fn visible(variant: &BTreeSet<FieldPath>) -> BTreeSet<&FieldPath> {
    variant.iter().filter(|path| !metadata(path)).collect()
}

/// Whether VRL may render as `value` a float `sluiceDisc` cannot render: zero, a fraction, or
/// 10^15 and more. Any other value Painless renders exactly as VRL does.
pub(crate) fn undecidable(value: &str) -> bool {
    value
        .parse::<f64>()
        .is_ok_and(|x| x == 0.0 || x.fract() != 0.0 || x.abs() >= 1e15)
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
    plan: &Plan<'_>,
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
        // A field that may go as implied stays when it is empty, unlike in Vector: then a
        // document without it held the implied value, which `crate::rebuild` puts back.
        let except: BTreeSet<&FieldPath> = except
            .iter()
            .chain(recipe.drop_implied.iter().map(|v| &v.field))
            .collect();
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
                painless::list(relevant.map(|e| e.as_str())),
                painless::list(recipe.drop_fields.iter().map(FieldPath::as_str))
            ));
            empty_fields = true;
        }
    }
    // Last, as in Vector: a field that implies another is tested as it is sent.
    for implied in &recipe.drop_implied {
        let mut test = painless::equals(&implied.field, &implied.value);
        if let Some((on, value)) = &implied.when {
            test = format!("{test} && {}", painless::equals(on, value));
        }
        lines.push(format!(
            "  if ({test}) {{ sluiceRemove(ctx, {}); }}",
            painless::segments(&implied.field)
        ));
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
        fields: recipe
            .drop_fields
            .iter()
            .chain(recipe.drop_implied.iter().map(|v| &v.field))
            .cloned()
            .collect(),
        empty_fields,
    })
}

#[cfg(test)]
mod tests;

//! Runtime fields that put back the implied values an ingest pipeline removes, as Sentinel's
//! `<Table>Full` function does for a data collection rule.
//!
//! A runtime field with the name of a field shadows it when a query runs: in a search request's
//! `runtime_mappings`, in a Kibana data view, or in the index mapping's `runtime` section. Each
//! one Sluice writes reads the document's `_source`: a field that is there is read as it is; one
//! that is not gets its implied value back, but only on a document the pipeline can have taken
//! it from:
//!
//! - its discriminators hold the template's values, the field that implies the value (if any)
//!   holds its value, and its key set lies between the template's key set without everything
//!   the pipeline may remove and the template's key set without what it always removes;
//! - every template with the same discriminator values carries the field on every event, so a
//!   document without it lost it;
//! - the pipeline keeps the field when it is empty (see `crate::pipeline`), so a document
//!   without it held the implied value, not nothing.
//!
//! A document that already arrives without everything the pipeline removes looks like one it
//! reduced, and would get the value too. That is why the CLI proves the runtime fields on the
//! sample with [`rebuilt`] and leaves out every field they would read differently there.
//!
//! A runtime field has one type: `keyword` for text values, `long` for whole numbers, `boolean`
//! for booleans, and a field with values of more than one type is left out. A value the
//! document has is read as Elasticsearch reads it into a field of that type. The logic is one
//! Painless function per field, so [`rebuilt`] can prove it on documents in `_ingest/pipeline/_simulate` without
//! writing to the cluster.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{Map, Value, json};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Plan};
use sluice_core::recipe::{ImpliedValue, Literal};
use sluice_core::template::{Template, TemplateShape};

use crate::painless;
use crate::pipeline::{IngestPipeline, MAX_SCRIPT, metadata, undecidable, visible};
use crate::simulate::{ElasticError, simulate};

/// The runtime fields that put a source's implied values back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rebuild {
    /// Per field, its type and the body of its Painless function `List f(Map ctx)`: the values
    /// to emit.
    functions: BTreeMap<String, (Kind, String)>,
    /// Implied values that are not put back, and why.
    pub left_out: Vec<String>,
}

impl Rebuild {
    /// Whether no field is put back.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// The fields put back.
    pub fn fields(&self) -> impl Iterator<Item = &str> {
        self.functions.keys().map(String::as_str)
    }

    /// The runtime fields, as a search request's `runtime_mappings` or an index mapping's
    /// `runtime` section takes them.
    #[must_use]
    pub fn runtime_mappings(&self) -> Value {
        let fields: Map<String, Value> = self
            .functions
            .iter()
            .map(|(field, (kind, body))| {
                (
                    field.clone(),
                    json!({"type": kind.name(), "script": {"source": runtime_source(body)}}),
                )
            })
            .collect();
        Value::Object(fields)
    }
}

/// The runtime fields that put back what `pipeline`, generated from `plans`, removes as implied.
#[must_use]
pub fn rebuild(plans: &[Plan<'_>], pipeline: &IngestPipeline) -> Rebuild {
    let mut left_out = Vec::new();
    // Per field, each template's test and the value it puts back. A template whose values
    // cannot be put back leaves its documents as the pipeline sent them; the others still get
    // theirs.
    let mut cases: BTreeMap<String, Vec<(String, &Literal)>> = BTreeMap::new();
    for plan in plans
        .iter()
        .filter(|p| pipeline.templates.contains(&p.template.id))
    {
        for (field, values) in by_field(plan.recipe) {
            match cases_for(plan, plans, field, &values) {
                Ok(found) => cases.entry(field.to_string()).or_default().extend(found),
                Err(why) => {
                    left_out.push(format!("{}: the implied `{field}` {why}", plan.template.id));
                }
            }
        }
    }
    let mut functions = BTreeMap::new();
    for (field, cases) in cases {
        let kinds: BTreeSet<Kind> = cases.iter().map(|(_, value)| Kind::of(value)).collect();
        let [kind] = kinds.into_iter().collect::<Vec<_>>()[..] else {
            left_out.push(format!(
                "`{field}`: its implied values are of more than one type, and a runtime field \
                 has one"
            ));
            continue;
        };
        let body = function(&field, kind, &cases);
        if fits(&field, &body) {
            functions.insert(field, (kind, body));
        } else {
            left_out.push(format!(
                "`{field}`: its runtime field would be longer than the {MAX_SCRIPT} bytes \
                 Elasticsearch compiles"
            ));
        }
    }
    Rebuild {
        functions,
        left_out,
    }
}

impl Rebuild {
    /// Leaves out the fields `keep` refuses, saying `why` for each.
    pub fn retain(&mut self, keep: impl Fn(&str) -> bool, why: &str) {
        let dropped: Vec<String> = self
            .functions
            .keys()
            .filter(|field| !keep(field))
            .cloned()
            .collect();
        for field in dropped {
            self.functions.remove(&field);
            self.left_out.push(format!("`{field}`: {why}"));
        }
    }
}

/// The recipe's implied values per field.
fn by_field(recipe: &EffectiveRecipe) -> BTreeMap<&FieldPath, Vec<&ImpliedValue>> {
    let mut out: BTreeMap<&FieldPath, Vec<&ImpliedValue>> = BTreeMap::new();
    for value in &recipe.drop_implied {
        if !recipe.drop_fields.iter().any(|f| f.covers(&value.field)) {
            out.entry(&value.field).or_default().push(value);
        }
    }
    out
}

/// The tests that put `field`'s `values` back on documents of `plan`'s template, or why they
/// cannot be put back exactly.
fn cases_for<'a>(
    plan: &Plan<'_>,
    plans: &[Plan<'_>],
    field: &FieldPath,
    values: &[&'a ImpliedValue],
) -> Result<Vec<(String, &'a Literal)>, &'static str> {
    let TemplateShape::Keyset {
        discriminators,
        variants,
        ..
    } = &plan.template.shape
    else {
        return Err("is in a text template");
    };
    if metadata(field) || discriminators.iter().any(|(d, _)| d == field) {
        return Err("is not a field a runtime field can shadow");
    }
    if discriminators
        .iter()
        .any(|(d, v)| metadata(d) || undecidable(v))
    {
        return Err("is on a kind of event a script cannot recognise exactly");
    }
    let recipe = plan.recipe;
    if !plans
        .iter()
        .filter(|p| same_discriminators(p.template, discriminators))
        .all(|p| always_has(p.template, field))
    {
        return Err(
            "is missing from some events of the same kind, so a document without it may \
                    never have had it",
        );
    }
    let ons: BTreeSet<Option<&FieldPath>> = values
        .iter()
        .map(|v| v.when.as_ref().map(|(on, _)| on))
        .collect();
    if ons.len() > 1 {
        return Err("is implied in more than one way, so which value it held is not certain");
    }
    let implied: BTreeSet<&FieldPath> = recipe.drop_implied.iter().map(|v| &v.field).collect();
    let ranges: Vec<String> = variants
        .iter()
        .filter(|variant| variant.contains(field))
        .map(|variant| range(variant, recipe, &implied, field))
        .collect();
    if ranges.is_empty() {
        return Err("is in none of its kind's key sets");
    }
    let mut kind: Vec<String> = discriminators
        .iter()
        .map(|(d, v)| {
            format!(
                "sluiceDisc(sluiceGet(ctx, {})) == {}",
                painless::segments(d),
                painless::string(v)
            )
        })
        .collect();
    kind.push(format!("({})", ranges.join(" || ")));
    let kind = kind.join(" && ");
    Ok(values
        .iter()
        .map(|value| {
            let condition = match &value.when {
                None => kind.clone(),
                Some((on, holds)) => format!("{kind} && {}", painless::equals(on, holds)),
            };
            (condition, &value.value)
        })
        .collect())
}

/// The type of a runtime field, from the implied values it puts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Keyword,
    Long,
    Boolean,
}

impl Kind {
    fn of(value: &Literal) -> Self {
        match value {
            Literal::Text(_) => Self::Keyword,
            Literal::Integer(_) => Self::Long,
            Literal::Bool(_) => Self::Boolean,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Long => "long",
            Self::Boolean => "boolean",
        }
    }

    /// The Painless that adds member `m` of a field the document has to `out`, as Elasticsearch
    /// reads such a value into a field of this type: any scalar as its text; a number as a
    /// whole number, also from its text; a boolean, also from `"true"` or `"false"`. Anything
    /// else gives nothing.
    fn read(self) -> &'static str {
        match self {
            Self::Keyword => {
                "if (m != null && !(m instanceof Map) && !(m instanceof List)) { \
                 out.add(String.valueOf(m)); }"
            }
            Self::Long => {
                "if (m instanceof Number) { out.add(((Number) m).longValue()); } else if (m \
                 instanceof String) { try { out.add((long) Double.parseDouble((String) m)); } \
                 catch (NumberFormatException e) {} }"
            }
            Self::Boolean => {
                "if (m instanceof Boolean) { out.add(m); } else if (m == 'true' || m == \
                 'false') { out.add(m == 'true'); }"
            }
        }
    }

    /// `value` as a Painless literal of this type.
    fn literal(value: &Literal) -> String {
        match value {
            Literal::Text(text) => painless::string(text),
            Literal::Integer(i) => format!("{i}L"),
            Literal::Bool(b) => b.to_string(),
        }
    }
}

/// Whether the pipeline removes `field` when it is null or empty. It keeps an empty field that
/// may go as implied, so that its absence has one meaning.
fn empty_removable(recipe: &EffectiveRecipe, field: &FieldPath) -> bool {
    recipe.drop_empty_except.as_ref().is_some_and(|except| {
        !except
            .iter()
            .chain(recipe.drop_implied.iter().map(|v| &v.field))
            .any(|e| e.covers(field) || field.covers(e))
            && !recipe.drop_fields.iter().any(|f| f.covers(field))
    })
}

/// The test that a document's key set is what `variant` can become in the pipeline without
/// `field`: at most the variant without what is always removed, at least that without
/// everything that may be.
fn range(
    variant: &BTreeSet<FieldPath>,
    recipe: &EffectiveRecipe,
    implied: &BTreeSet<&FieldPath>,
    field: &FieldPath,
) -> String {
    let upper: Vec<&FieldPath> = visible(variant)
        .into_iter()
        .filter(|p| *p != field && !recipe.drop_fields.iter().any(|f| f.covers(p)))
        .collect();
    let lower = upper
        .iter()
        .filter(|p| !implied.contains(**p) && !empty_removable(recipe, p))
        .map(|p| p.as_str());
    format!(
        "keys.containsAll(new HashSet({})) && new HashSet({}).containsAll(keys)",
        painless::list(lower),
        painless::list(upper.iter().map(|p| p.as_str()))
    )
}

fn same_discriminators(template: &Template, discriminators: &[(FieldPath, String)]) -> bool {
    matches!(&template.shape, TemplateShape::Keyset { discriminators: d, .. } if d == discriminators)
}

fn always_has(template: &Template, field: &FieldPath) -> bool {
    match &template.shape {
        TemplateShape::Keyset { variants, .. } => variants.iter().all(|v| v.contains(field)),
        TemplateShape::Text { .. } => false,
    }
}

/// The body of `field`'s function: its values where it is there, otherwise the implied value
/// of the first test that holds.
fn function(field: &str, kind: Kind, cases: &[(String, &Literal)]) -> String {
    let path = painless::segments(&FieldPath::new(field));
    let mut out = format!(
        "  List out = new ArrayList();\n  if (sluiceHas(ctx, {path})) {{\n    def x = \
         sluiceGet(ctx, {path});\n    List ms = x instanceof List ? (List) x : [x];\n    for \
         (def m : ms) {{ {read} }}\n    return out;\n  }}\n  Set keys = sluiceKeys(ctx);\n",
        read = kind.read()
    );
    let branches: Vec<String> = cases
        .iter()
        .map(|(test, value)| format!("if ({test}) {{ out.add({}); }}", Kind::literal(value)))
        .collect();
    out.push_str("  ");
    out.push_str(&branches.join("\n  else "));
    out.push_str("\n  return out;");
    out
}

/// Each document's values of every field `rebuild` puts back, as its runtime fields read them,
/// run in Elasticsearch through `_ingest/pipeline/_simulate`. Fields go in groups whose script
/// stays within what Elasticsearch compiles.
///
/// # Errors
///
/// [`ElasticError`] when Elasticsearch is unreachable, refuses a script, or a script fails.
pub fn rebuilt(
    url: &str,
    rebuild: &Rebuild,
    documents: &[&Map<String, Value>],
) -> Result<Vec<BTreeMap<String, Value>>, ElasticError> {
    let mut out = vec![BTreeMap::new(); documents.len()];
    let functions: Vec<(&str, &str)> = rebuild
        .functions
        .iter()
        .map(|(field, (_, body))| (field.as_str(), body.as_str()))
        .collect();
    for script in simulations(&functions) {
        let pipeline = json!({"processors": [{"script": {"source": script}}]});
        for (row, document) in out.iter_mut().zip(simulate(url, &pipeline, documents)?) {
            if let Some(Value::Object(values)) = document.get("sluice_rebuilt") {
                row.extend(values.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
        }
    }
    Ok(out)
}

/// The runtime field's script around `body`, the body of a function `List f(Map ctx)`.
fn runtime_source(body: &str) -> String {
    format!(
        "{}List sluiceValues(Map ctx) {{\n{body}\n}}\nfor (def v : \
         sluiceValues(params['_source'])) {{ emit(v); }}\n",
        painless::FUNCTIONS
    )
}

/// The `_simulate` script that reads every one of `functions` (`(field, body)`) into
/// `ctx.sluice_rebuilt`. Every value is read before the result is stored, so no function sees it.
fn simulation(functions: &[(&str, &str)]) -> String {
    let mut script = painless::FUNCTIONS.to_owned();
    let mut calls = Vec::new();
    for (n, (field, body)) in functions.iter().enumerate() {
        let _ = write!(script, "List sluiceValues{n}(Map ctx) {{\n{body}\n}}\n");
        calls.push(format!("{}: sluiceValues{n}(ctx)", painless::string(field)));
    }
    let _ = write!(
        script,
        "Map r = [{}];\nctx.sluice_rebuilt = r;\n",
        calls.join(", ")
    );
    script
}

/// Whether `field`'s function compiles in Elasticsearch both as its runtime field and in a
/// `_simulate` script of its own.
fn fits(field: &str, body: &str) -> bool {
    runtime_source(body).len() <= MAX_SCRIPT && simulation(&[(field, body)]).len() <= MAX_SCRIPT
}

/// The `_simulate` scripts that read every one of `functions`, each as many as fit in
/// [`MAX_SCRIPT`]. A function that fits alone ([`fits`]) always has a script.
fn simulations(functions: &[(&str, &str)]) -> Vec<String> {
    let mut scripts = Vec::new();
    let mut group: Vec<(&str, &str)> = Vec::new();
    for &function in functions {
        group.push(function);
        if group.len() > 1 && simulation(&group).len() > MAX_SCRIPT {
            group.pop();
            scripts.push(simulation(&group));
            group = vec![function];
        }
    }
    if !group.is_empty() {
        scripts.push(simulation(&group));
    }
    scripts
}
#[cfg(test)]
mod tests;

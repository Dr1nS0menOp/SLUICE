//! A data collection rule `transformKql` that carries out the field removals of a savings plan
//! (ADR 0013, ADR 0023) in Sentinel's own ingestion, without Vector.
//!
//! A DCR transformation sees one record at a time as the table's columns and cannot summarize,
//! so only removals run here (L1). Three rules keep it from ever removing more than Vector would:
//!
//! - **Recognition is exact.** A record belongs to a template only if its discriminator columns
//!   hold the template's values and exactly the columns of one of its key sets are non-empty: a
//!   signature with one bit per column. A record that fits no template keeps every column
//!   (contract rule 1). Columns Azure fills itself ([`SERVICE_COLUMNS`]) are not part of it.
//! - **Templates the signature cannot tell apart share the least.** They remove only the columns
//!   every one of them removes, and keep every column where any of them keeps the event whole.
//! - **Keeping whole is a superset.** `keep_whole_when` compiles with [`crate::compile`], which
//!   matches at least what Vector's VRL matches, so a column is only emptied on records Vector
//!   empties it on.
//!
//! The template's key sets must have been discovered on records as the table stores them, where
//! an empty column and a missing one are the same: Sentinel records read back from the workspace.
//! Whole columns only: a nested field keeps its column. Emptying a column is what a DCR can do,
//! and an empty column is not billed (docs/notes/sentinel-dcr.md).

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::TemplateId;
use sluice_core::predicate::Predicate;
use sluice_core::template::{Template, TemplateShape};

use crate::engine::Table;
use crate::predicate::compile;
use crate::syntax;

/// Columns Azure Monitor sets on the record itself, which a DCR transformation may not see.
pub const SERVICE_COLUMNS: [&str; 9] = [
    "TenantId",
    "TimeGenerated",
    "Type",
    "MG",
    "ManagementGroupName",
    "SourceSystem",
    "TimeCollected",
    "_ResourceId",
    "_SubscriptionId",
];

/// Functions a generated transformation calls, typed null literals included: all on the list
/// DCR transformations accept (docs/notes/sentinel-dcr.md).
pub const ALLOWED_FUNCTIONS: [&str; 17] = [
    "bool",
    "case",
    "datetime",
    "dynamic",
    "gettype",
    "guid",
    "iff",
    "int",
    "isempty",
    "isnotnull",
    "long",
    "not",
    "real",
    "strcat",
    "strcat_delim",
    "tostring",
    "toint",
];

/// Most arguments one `strcat` call is given.
const STRCAT_MAX: usize = 60;

/// One template and the recipe enforced on it.
#[derive(Debug, Clone, Copy)]
pub struct TransformPlan<'a> {
    /// The template, discovered on the table's records.
    pub template: &'a Template,
    /// Its enforced recipe.
    pub recipe: &'a EffectiveRecipe,
}

/// A generated transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transformation {
    /// The `transformKql` text; `source` when nothing is removed.
    pub kql: String,
    /// The templates whose records it removes columns from.
    pub templates: BTreeSet<TemplateId>,
    /// The columns it may empty.
    pub columns: BTreeSet<String>,
    /// Parts of the plan only a pipeline tool can carry out, and why.
    pub left_out: Vec<String>,
}

/// Records the transformation cannot tell apart: one signature and its discriminator values.
#[derive(Debug, Default)]
struct Group {
    discriminators: BTreeMap<String, String>,
    templates: BTreeSet<TemplateId>,
    removes: Option<BTreeSet<String>>,
    keep_whole: Vec<Predicate>,
    /// Two templates with this signature test different discriminator fields: a record could
    /// fit both, so neither is recognised.
    conflict: bool,
}

/// A template's discriminator values and the columns of each of its key sets.
type Recognition = (BTreeMap<String, String>, Vec<BTreeSet<String>>);

/// Groups by signature, then by discriminator values.
type Groups = BTreeMap<String, BTreeMap<Vec<(String, String)>, Group>>;

/// The transformation for records of `table` carrying out `plans`' field removals.
#[must_use]
pub fn transformation(table: Table, plans: &[TransformPlan<'_>]) -> Transformation {
    let columns: Vec<(&str, &str)> = table
        .own_columns()
        .filter(|(name, _)| !SERVICE_COLUMNS.contains(name))
        .collect();
    let types: BTreeMap<&str, &str> = columns.iter().copied().collect();
    let mut left_out = Vec::new();
    let recognised: Vec<(&TransformPlan<'_>, Recognition)> = plans
        .iter()
        .filter_map(|plan| {
            recognition(plan.template, &types, &mut left_out).map(|recognition| (plan, recognition))
        })
        .collect();
    // The signature covers the columns some template has; every other column must be empty.
    let used: BTreeSet<&str> = recognised
        .iter()
        .flat_map(|(_, (_, variants))| variants.iter().flatten())
        .map(String::as_str)
        .collect();
    let signed: Vec<(&str, &str)> = columns
        .iter()
        .copied()
        .filter(|(name, _)| used.contains(name))
        .collect();
    let mut groups = Groups::new();
    for (plan, (discriminators, variants)) in &recognised {
        let id = &plan.template.id;
        if plan.recipe.route != Route::ForwardAll {
            left_out.push(format!(
                "{id}: counting instead of sending needs a pipeline tool"
            ));
        }
        let removes = removable(plan, discriminators, &types, table, &mut left_out);
        for variant in variants {
            let signature: String = signed
                .iter()
                .map(|(name, _)| if variant.contains(*name) { '1' } else { '0' })
                .collect();
            let group = groups
                .entry(signature)
                .or_default()
                .entry(
                    discriminators
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
                .or_default();
            group.discriminators.clone_from(discriminators);
            group.templates.insert(id.clone());
            group.removes = Some(match group.removes.take() {
                None => removes.clone(),
                Some(before) => before.intersection(&removes).cloned().collect(),
            });
            group.keep_whole.extend(plan.recipe.keep_whole_when.clone());
        }
    }
    // Under one signature, groups must test the same discriminator fields with different
    // values; otherwise one record could fit two of them.
    for by_values in groups.values_mut() {
        let fields: BTreeSet<Vec<&String>> = by_values
            .values()
            .map(|g| g.discriminators.keys().collect())
            .collect();
        if fields.len() > 1 {
            for group in by_values.values_mut() {
                group.conflict = true;
            }
        }
    }
    let mut kept = Vec::new();
    for (signature, by_values) in groups {
        for group in by_values.into_values() {
            if group.conflict {
                left_out.push(format!(
                    "{}: other templates with the same columns test other fields, so their \
                     records cannot be told apart",
                    group
                        .templates
                        .iter()
                        .map(TemplateId::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            } else if group.removes.as_ref().is_some_and(|r| !r.is_empty()) {
                kept.push((signature.clone(), group));
            }
        }
    }
    let rest: Vec<(&str, &str)> = columns
        .iter()
        .copied()
        .filter(|(name, _)| !used.contains(name))
        .collect();
    render(&signed, &rest, &columns, &kept, left_out)
}

/// The columns a plan removes that the transformation can empty: whole columns of the table,
/// not discriminators; the rest goes to `left_out`. A field no record of the template has is
/// nothing to remove.
fn removable(
    plan: &TransformPlan<'_>,
    discriminators: &BTreeMap<String, String>,
    types: &BTreeMap<&str, &str>,
    table: Table,
    left_out: &mut Vec<String>,
) -> BTreeSet<String> {
    let id = &plan.template.id;
    plan.recipe
        .drop_fields
        .iter()
        .filter(|field| plan.template.fields.contains(*field))
        .filter_map(|field| {
            let name = field.as_str();
            let whole = !name.contains('.')
                && types.contains_key(name)
                && !discriminators.contains_key(name);
            if !whole {
                left_out.push(format!(
                    "{id}: `{name}` is not a whole column of {} the transformation can empty",
                    table.name()
                ));
            }
            whole.then(|| name.to_owned())
        })
        .collect()
}

/// The discriminator values of `template` and the columns of each of its key sets (service
/// columns left out), or `None` (with the reason in `left_out`) when the transformation cannot
/// recognise it exactly.
fn recognition(
    template: &Template,
    types: &BTreeMap<&str, &str>,
    left_out: &mut Vec<String>,
) -> Option<Recognition> {
    let id = &template.id;
    let TemplateShape::Keyset {
        discriminators,
        variants,
        ..
    } = &template.shape
    else {
        left_out.push(format!(
            "{id}: a text template has no columns to recognise it by"
        ));
        return None;
    };
    let mut values = BTreeMap::new();
    for (field, value) in discriminators {
        let name = field.as_str();
        if !matches!(types.get(name), Some(&("string" | "int" | "long"))) {
            left_out.push(format!(
                "{id}: its discriminator `{name}` is not a text or whole-number column"
            ));
            return None;
        }
        if syntax::string(value).is_none() {
            left_out.push(format!(
                "{id}: its discriminator `{name}` holds a character a KQL literal cannot carry"
            ));
            return None;
        }
        values.insert(name.to_owned(), value.clone());
    }
    let mut sets = Vec::new();
    for variant in variants {
        let present: BTreeSet<String> = variant
            .iter()
            .map(sluice_core::field::FieldPath::as_str)
            .filter(|f| !SERVICE_COLUMNS.contains(f))
            .map(str::to_owned)
            .collect();
        if let Some(other) = present.iter().find(|f| !types.contains_key(f.as_str())) {
            left_out.push(format!(
                "{id}: `{other}` is not a whole column of the table"
            ));
            return None;
        }
        sets.push(present);
    }
    Some((values, sets))
}

/// Whether `column` of type `kind` holds nothing, as the table sees it.
fn empty(column: &str, kind: &str) -> String {
    if kind == "dynamic" {
        format!(r#"(isempty(tostring({column})) or tostring({column}) == "{{}}")"#)
    } else {
        format!("isempty(tostring({column}))")
    }
}

/// `signed` are the columns of the signature, `rest` the columns that must be empty, and
/// `columns` every column (keyword tests scan them all).
fn render(
    signed: &[(&str, &str)],
    rest: &[(&str, &str)],
    columns: &[(&str, &str)],
    groups: &[(String, Group)],
    left_out: Vec<String>,
) -> Transformation {
    let mut transformation = Transformation {
        kql: "source".to_owned(),
        templates: BTreeSet::new(),
        columns: BTreeSet::new(),
        left_out,
    };
    if groups.is_empty() {
        return transformation;
    }
    let names: Vec<&str> = columns.iter().map(|(name, _)| *name).collect();
    let types: BTreeMap<&str, &str> = columns.iter().copied().collect();
    let bits: Vec<String> = signed
        .iter()
        .map(|(name, kind)| format!(r#"iff({}, "0", "1")"#, empty(&column(name), kind)))
        .collect();
    // A dynamic `{}` counts as text here, so a record holding one keeps every column.
    let rest_empty = if rest.is_empty() {
        "true".to_owned()
    } else {
        let texts: Vec<String> = rest
            .iter()
            .map(|(name, _)| format!("tostring({})", column(name)))
            .collect();
        format!("isempty({})", strcat(&texts))
    };
    let mut cases = Vec::new();
    let mut removed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (n, (signature, group)) in groups.iter().enumerate() {
        let label = format!("g{n}");
        let mut tests: Vec<String> = group
            .discriminators
            .iter()
            .map(|(name, value)| {
                let literal = syntax::string(value)
                    .expect("recognition kept only values a literal can carry");
                format!("tostring({}) == {literal}", column(name))
            })
            .collect();
        tests.push(format!("__sluice_s == \"{signature}\" and __sluice_r"));
        cases.push(format!("{}, \"{label}\"", tests.join(" and ")));
        let keep = if group.keep_whole.is_empty() {
            "false".to_owned()
        } else {
            compile(&Predicate::any(group.keep_whole.clone()), &names)
        };
        let condition = format!("(__sluice_t == \"{label}\" and not({keep}))");
        for name in group.removes.iter().flatten() {
            removed
                .entry(name.clone())
                .or_default()
                .push(condition.clone());
        }
        transformation
            .templates
            .extend(group.templates.iter().cloned());
    }
    let mut lines = vec![
        "source".to_owned(),
        format!(
            "| extend __sluice_s = {}, __sluice_r = {rest_empty}",
            strcat(&bits)
        ),
        format!("| extend __sluice_t = case({}, \"\")", cases.join(", ")),
    ];
    for (name, conditions) in &removed {
        let quoted = column(name);
        lines.push(format!(
            "| extend {quoted} = iff({}, {}, {quoted})",
            conditions.join(" or "),
            empty_value(types.get(name.as_str()).copied().unwrap_or("string"))
        ));
        transformation.columns.insert(name.clone());
    }
    lines.push("| project-away __sluice_s, __sluice_r, __sluice_t".to_owned());
    transformation.kql = lines.join("\n");
    transformation
}

fn column(name: &str) -> String {
    syntax::quoted_name(name).expect("table schema names hold no control characters")
}

/// `parts` concatenated, nesting `strcat` where one call would take too many arguments.
fn strcat(parts: &[String]) -> String {
    match parts {
        [] => r#""""#.to_owned(),
        [one] => one.clone(),
        _ if parts.len() <= STRCAT_MAX => format!("strcat({})", parts.join(", ")),
        _ => strcat(&parts.chunks(STRCAT_MAX).map(strcat).collect::<Vec<_>>()),
    }
}

/// What an emptied column holds: `""` for text, which is not billed, else a typed null.
fn empty_value(kind: &str) -> String {
    if kind == "string" {
        r#""""#.to_owned()
    } else {
        format!("{kind}(null)")
    }
}

/// Runs a transformation's `kql` on `events` in the Kusto emulator at `url`, as a DCR runs it on
/// records of `table`. Returns each event's record afterwards, in the order of `events`, with
/// its non-empty columns only (an empty column and a missing one are the same to the table).
///
/// # Errors
///
/// Returns [`crate::KustoError`] if the emulator cannot be used or rejects the transformation.
pub fn run_transformation(
    url: &str,
    table: Table,
    kql: &str,
    events: &[&sluice_core::event::Event],
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, crate::KustoError> {
    use serde_json::{Value, json};

    const ROW: &str = "__sluice_n";
    let client = crate::engine::Client::new(url);
    let database = crate::engine::Database::create(&client)?;
    let mut columns: Vec<(&str, &str)> = table.own_columns().collect();
    columns.push((ROW, "long"));
    let records: Vec<Value> = events
        .iter()
        .enumerate()
        .map(|(n, event)| {
            let mut record = crate::engine::record(table, event);
            record[ROW] = json!(n);
            record
        })
        .collect();
    database.load_table("SluiceInput", &columns, &records)?;
    let query = format!(
        "{}\n| order by {ROW} asc",
        kql.replacen("source", "SluiceInput", 1)
    );
    database
        .query(&query)?
        .iter()
        .map(|row| {
            let row: Value = serde_json::from_str(row)
                .map_err(|e| crate::KustoError::Response(e.to_string()))?;
            let (Some(names), Some(values)) = (row[0].as_array(), row[1].as_array()) else {
                return Err(crate::KustoError::Response(
                    "a row without columns".to_owned(),
                ));
            };
            Ok(names
                .iter()
                .zip(values)
                .filter_map(|(name, value)| {
                    let name = name.as_str()?;
                    let empty = value.is_null() || value.as_str() == Some("");
                    (name != ROW && !empty).then(|| (name.to_owned(), value.clone()))
                })
                .collect())
        })
        .collect()
}

/// The functions `kql` calls (an identifier right before `(`, outside string literals) that are
/// not in [`ALLOWED_FUNCTIONS`]. Empty for every transformation Sluice generates.
#[must_use]
pub fn disallowed_functions(kql: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut word = String::new();
    for c in kql.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
            continue;
        }
        if c == '(' && !word.is_empty() && !ALLOWED_FUNCTIONS.contains(&word.as_str()) {
            found.insert(word.clone());
        }
        if c == '"' || c == '\'' {
            quote = Some(c);
        }
        word.clear();
    }
    found
}

#[cfg(test)]
mod tests;

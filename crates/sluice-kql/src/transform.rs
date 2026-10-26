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

use sluice_core::guard::{Plan, Route};
use sluice_core::ids::TemplateId;
use sluice_core::predicate::Predicate;
use sluice_core::template::{Template, TemplateShape};

pub use self::rebuild::{Rebuilt, function as rebuilding_function};
pub use self::run::{Records, run_transformations};
use crate::predicate::compile_known;
use crate::syntax::{self, STRCAT_MAX};
use crate::table::Table;

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
pub const ALLOWED_FUNCTIONS: [&str; 18] = [
    "bool",
    "case",
    "columnifexists",
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

/// The longest `transformKql` a data collection rule takes: Azure refuses a longer one with
/// `InvalidTransform` (checked 2026-10-17).
pub const MAX_TRANSFORM_KQL: usize = 15_360;

/// The line that begins what [`transformation`] adds after `source`. A data flow's transformation
/// that contains it was written by Sluice before, and everything from it on is Sluice's.
pub const SLUICE_PART: &str = "| extend __sluice_s";

/// The line that ends what [`transformation`] adds. Where Sluice's part runs before a data
/// flow's own transformation, the flow's part follows it.
pub const SLUICE_PART_END: &str = "| project-away __sluice_s, __sluice_r, __sluice_t";

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
    /// The implied values it empties: what the table's rebuilding function puts back.
    pub implied: Vec<Rebuilt>,
}

/// Records the transformation cannot tell apart: one signature and its discriminator values.
#[derive(Debug, Default, Clone)]
struct Group {
    discriminators: BTreeMap<String, String>,
    templates: BTreeSet<TemplateId>,
    removes: Option<BTreeSet<String>>,
    /// The implied values every template of the group removes.
    implied: Option<BTreeSet<Rebuilt>>,
    keep_whole: Vec<Predicate>,
    /// Two templates with this signature test different discriminator fields: a record could
    /// fit both, so neither is recognised.
    conflict: bool,
}

/// A template's discriminator values and the columns of each of its key sets.
type Recognition = (BTreeMap<String, String>, Vec<BTreeSet<String>>);

/// Groups by signature, then by discriminator values.
type Groups = BTreeMap<String, BTreeMap<Vec<(String, String)>, Group>>;

/// The transformation for records of `table` carrying out `plans`' field removals. `stream`
/// is every column the transformation sees (the data flow's stream); naming any other is an
/// error in a DCR, and a column outside it is always empty. Without a stream of its own, a data
/// flow into a standard table carries the table's columns: [`Table::column_names`].
#[must_use]
pub fn transformation(table: &Table, stream: &[&str], plans: &[Plan<'_>]) -> Transformation {
    transformation_within(table, stream, plans, MAX_TRANSFORM_KQL)
}

/// As [`transformation`], in at most `budget` characters: what a data flow's own
/// transformation leaves of [`MAX_TRANSFORM_KQL`].
#[must_use]
pub fn transformation_within(
    table: &Table,
    stream: &[&str],
    plans: &[Plan<'_>],
    budget: usize,
) -> Transformation {
    let columns: Vec<(&str, &str)> = table
        .own_columns()
        .filter(|(name, _)| stream.contains(name))
        .collect();
    transformation_on_within(table.name(), &columns, stream, plans, budget)
}

/// As [`transformation`], on `columns` (name and type, among `stream`) as they are where the
/// transformation runs: a stream's, when it runs before the data flow's own transformation
/// renames any. `table` only names the place in what is left out.
#[must_use]
pub fn transformation_on(
    table: &str,
    columns: &[(&str, &str)],
    stream: &[&str],
    plans: &[Plan<'_>],
) -> Transformation {
    transformation_on_within(table, columns, stream, plans, MAX_TRANSFORM_KQL)
}

/// As [`transformation_on`], in at most `budget` characters.
#[must_use]
pub fn transformation_on_within(
    table: &str,
    columns: &[(&str, &str)],
    stream: &[&str],
    plans: &[Plan<'_>],
    budget: usize,
) -> Transformation {
    let columns: Vec<(&str, &str)> = columns
        .iter()
        .copied()
        .filter(|(name, _)| !SERVICE_COLUMNS.contains(name))
        .collect();
    // The transformation reads every column; one KQL cannot name leaves the records as they come.
    if let Some((name, _)) = columns
        .iter()
        .find(|(name, _)| syntax::quoted_name(name).is_none())
    {
        return Transformation {
            kql: "source".to_owned(),
            templates: BTreeSet::new(),
            columns: BTreeSet::new(),
            left_out: vec![format!(
                "{table}: the column {name:?} holds a character KQL cannot name, so nothing is \
                 removed"
            )],
            implied: Vec::new(),
        };
    }
    let types: BTreeMap<&str, &str> = columns.iter().copied().collect();
    let mut left_out = Vec::new();
    let mut unrecognised = Vec::new();
    let recognised: Vec<(&Plan<'_>, Recognition)> = plans
        .iter()
        .filter_map(|plan| {
            let found = recognition(plan.template, &types, &mut left_out);
            if found.is_none() && matches!(plan.template.shape, TemplateShape::Keyset { .. }) {
                unrecognised.push(plan.template);
            }
            found.map(|recognition| (plan, recognition))
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
    for (plan, recognition) in &recognised {
        let id = &plan.template.id;
        if plan.recipe.route != Route::ForwardAll {
            left_out.push(format!(
                "{id}: counting instead of sending needs a pipeline tool"
            ));
        }
        let discriminators = &recognition.0;
        let removes = removable(plan, discriminators, &types, table, &mut left_out);
        let implied = rebuild::implied(plan, discriminators, &types, plans, &mut left_out);
        add(
            &mut groups,
            plan,
            recognition,
            &signed,
            (&removes, &implied),
        );
    }
    let rest: Vec<(&str, &str)> = columns
        .iter()
        .copied()
        .filter(|(name, _)| !used.contains(name))
        .collect();
    for template in &unrecognised {
        block(template, &signed, &rest, &mut groups);
    }
    let kept = separable(groups, &mut left_out);
    let mut transformation = fitting(&signed, &rest, stream, &kept, &left_out, budget);
    if transformation.kql.len() > budget {
        transformation.left_out.push(format!(
            "the transformation would be {} characters, more than the {budget} left of what a \
             data collection rule takes, so nothing is removed",
            transformation.kql.len()
        ));
        "source".clone_into(&mut transformation.kql);
        transformation.templates.clear();
        transformation.columns.clear();
    }
    transformation
}

/// Puts `plan`'s template into the group of each of its key sets, where it removes only what
/// every template of the group removes: `removes` (columns) and `implied` (values).
fn add(
    groups: &mut Groups,
    plan: &Plan<'_>,
    (discriminators, variants): &Recognition,
    signed: &[(&str, &str)],
    (removes, implied): (&BTreeSet<String>, &BTreeSet<Rebuilt>),
) {
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
        group.templates.insert(plan.template.id.clone());
        group.removes = Some(match group.removes.take() {
            None => removes.clone(),
            Some(before) => before.intersection(removes).cloned().collect(),
        });
        group.implied = Some(match group.implied.take() {
            None => implied.clone(),
            Some(before) => before.intersection(implied).cloned().collect(),
        });
        group.keep_whole.extend(plan.recipe.keep_whole_when.clone());
    }
}

/// Puts a key-set template the transformation cannot recognise into every group its records
/// could fall into, removing nothing there. Vector may give such a record to it, so no group
/// may take it: where a group has its discriminator values, nothing is removed; where a group
/// tests other fields, its records cannot be told apart from this template's. A record with a
/// column outside the signature is in no group anyway.
fn block(template: &Template, signed: &[(&str, &str)], rest: &[(&str, &str)], groups: &mut Groups) {
    let TemplateShape::Keyset {
        discriminators,
        variants,
        ..
    } = &template.shape
    else {
        return;
    };
    let values: BTreeMap<String, String> = discriminators
        .iter()
        .map(|(field, value)| (field.as_str().to_owned(), value.clone()))
        .collect();
    for variant in variants {
        // A field below a column (`EventData.X`) makes that column hold something.
        let present: BTreeSet<&str> = variant.iter().filter_map(|p| p.segments().next()).collect();
        if rest.iter().any(|(name, _)| present.contains(name)) {
            continue;
        }
        let signature: String = signed
            .iter()
            .map(|(name, _)| if present.contains(name) { '1' } else { '0' })
            .collect();
        let group = groups
            .entry(signature)
            .or_default()
            .entry(values.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .or_default();
        group.discriminators.clone_from(&values);
        group.templates.insert(template.id.clone());
        group.removes = Some(BTreeSet::new());
        group.implied = Some(BTreeSet::new());
    }
}

/// The groups a record can be placed in without doubt that remove something. Under one
/// signature, groups must test the same discriminator fields with different values; otherwise
/// one record could fit two of them, and none of them is used.
fn separable(mut groups: Groups, left_out: &mut Vec<String>) -> Vec<(String, Group)> {
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
            } else if group.removes.as_ref().is_some_and(|r| !r.is_empty())
                || group.implied.as_ref().is_some_and(|i| !i.is_empty())
            {
                kept.push((signature.clone(), group));
            }
        }
    }
    kept
}

/// The columns a plan removes that the transformation can empty: whole columns of the table,
/// not discriminators; the rest goes to `left_out`. A field no record of the template has is
/// nothing to remove.
fn removable(
    plan: &Plan<'_>,
    discriminators: &BTreeMap<String, String>,
    types: &BTreeMap<&str, &str>,
    table: &str,
    left_out: &mut Vec<String>,
) -> BTreeSet<String> {
    let id = &plan.template.id;
    plan.recipe
        .drop_fields
        .iter()
        .filter(|field| plan.template.fields.contains(*field))
        .filter_map(|field| {
            let name = field.as_str();
            let Some(kind) = types
                .get(name)
                .filter(|_| !name.contains('.') && !discriminators.contains_key(name))
            else {
                left_out.push(format!(
                    "{id}: `{name}` is not a whole column of {table} the transformation can empty"
                ));
                return None;
            };
            if empty_value(kind).is_none() {
                left_out.push(format!(
                    "{id}: `{name}` is a {kind} column, which has no null a transformation may \
                     write"
                ));
                return None;
            }
            Some(name.to_owned())
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

/// The transformation with as many implied values as fit in `budget` characters, the most
/// worthwhile first: values the kind of event implies alone (they hold on every record) before
/// those another column implies, longer values before shorter. The rest is left to a pipeline
/// tool.
fn fitting(
    signed: &[(&str, &str)],
    rest: &[(&str, &str)],
    stream: &[&str],
    groups: &[(String, Group)],
    left_out: &[String],
    budget: usize,
) -> Transformation {
    let mut ranked: Vec<&Rebuilt> = groups
        .iter()
        .flat_map(|(_, group)| group.implied.iter().flatten())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ranked.sort_by(|a, b| {
        (a.when.is_some(), std::cmp::Reverse(a.value.len()))
            .cmp(&(b.when.is_some(), std::cmp::Reverse(b.value.len())))
            .then(a.cmp(b))
    });
    let with = |count: usize| {
        let allowed: BTreeSet<&Rebuilt> = ranked.iter().take(count).copied().collect();
        let limited: Vec<(String, Group)> = groups
            .iter()
            .map(|(signature, group)| {
                let mut group = group.clone();
                group.implied = group
                    .implied
                    .map(|values| values.into_iter().filter(|v| allowed.contains(v)).collect());
                (signature.clone(), group)
            })
            .filter(|(_, group)| {
                group.removes.as_ref().is_some_and(|r| !r.is_empty())
                    || group.implied.as_ref().is_some_and(|i| !i.is_empty())
            })
            .collect();
        render(signed, rest, stream, &limited, left_out.to_vec())
    };
    let all = with(ranked.len());
    if all.kql.len() <= budget || ranked.is_empty() {
        return all;
    }
    // The largest count that fits: adding a value only adds text.
    let (mut fits, mut too_many) = (0, ranked.len());
    while too_many - fits > 1 {
        let middle = usize::midpoint(fits, too_many);
        if with(middle).kql.len() <= budget {
            fits = middle;
        } else {
            too_many = middle;
        }
    }
    let mut transformation = with(fits);
    transformation.left_out.push(format!(
        "{} of {} implied values did not fit in the {budget} characters left of what a data \
         collection rule takes; a pipeline tool removes them",
        ranked.len() - fits,
        ranked.len()
    ));
    transformation
}

/// `signed` are the columns of the signature, `rest` the columns that must be empty, and
/// `stream` every column (keyword tests scan them all).
fn render(
    signed: &[(&str, &str)],
    rest: &[(&str, &str)],
    stream: &[&str],
    groups: &[(String, Group)],
    left_out: Vec<String>,
) -> Transformation {
    let mut transformation = Transformation {
        kql: "source".to_owned(),
        templates: BTreeSet::new(),
        columns: BTreeSet::new(),
        left_out,
        implied: Vec::new(),
    };
    if groups.is_empty() {
        return transformation;
    }
    let types: BTreeMap<&str, &str> = signed.iter().chain(rest).copied().collect();
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
    let mut implied: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut rebuilt: BTreeSet<Rebuilt> = BTreeSet::new();
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
        // A record a protecting rule could match gets no label, so nothing is removed from it.
        // Tested once here, on the record as it came, rather than again in every column's test:
        // that kept the transformation within the size a data collection rule takes.
        if !group.keep_whole.is_empty() {
            let keep = compile_known(&Predicate::any(group.keep_whole.clone()), stream);
            tests.push(format!("not({keep})"));
        }
        cases.push(format!("{}, \"{label}\"", tests.join(" and ")));
        let condition = format!("__sluice_t == \"{label}\"");
        for name in group.removes.iter().flatten() {
            removed
                .entry(name.clone())
                .or_default()
                .push(condition.clone());
        }
        for value in group.implied.iter().flatten() {
            implied
                .entry(value.column.clone())
                .or_default()
                .push(format!("({condition} and {})", rebuild::holds(value)));
            rebuilt.insert(value.clone());
        }
        transformation
            .templates
            .extend(group.templates.iter().cloned());
    }
    let mut lines = vec![
        "source".to_owned(),
        format!(
            "{SLUICE_PART} = {}, __sluice_r = {rest_empty}",
            strcat(&bits)
        ),
        format!("| extend __sluice_t = case({}, \"\")", cases.join(", ")),
    ];
    for (name, conditions) in &removed {
        let quoted = column(name);
        lines.push(format!(
            "| extend {quoted} = iff({}, {}, {})",
            conditions.join(" or "),
            empty_value(types.get(name.as_str()).copied().unwrap_or("string"))
                .expect("removable keeps only columns whose type has a null"),
            quoted
        ));
        transformation.columns.insert(name.clone());
    }
    // Last, as in Vector: a column that implies another is tested as it is sent.
    for (name, conditions) in &implied {
        let quoted = column(name);
        lines.push(format!(
            "| extend {quoted} = iff({}, {}, {})",
            conditions.join(" or "),
            empty_value(types.get(name.as_str()).copied().unwrap_or("string"))
                .expect("rebuild::implied keeps only columns whose type has a null"),
            quoted
        ));
        transformation.columns.insert(name.clone());
    }
    transformation.implied = rebuilt.into_iter().collect();
    lines.push(SLUICE_PART_END.to_owned());
    transformation.kql = lines.join("\n");
    transformation
}

/// A column, read or as the target of `extend`.
fn column(name: &str) -> String {
    syntax::quoted_name(name).expect("transformation_on refuses columns KQL cannot name")
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

/// What an emptied column of type `kind` holds: `""` for text, which is not billed, else a
/// typed null of [`ALLOWED_FUNCTIONS`]. `None` for a type without one, such as `timespan`.
pub(crate) fn empty_value(kind: &str) -> Option<String> {
    match kind {
        "string" => Some(r#""""#.to_owned()),
        "bool" | "boolean" => Some("bool(null)".to_owned()),
        "int" | "long" | "real" | "datetime" | "dynamic" | "guid" => Some(format!("{kind}(null)")),
        _ => None,
    }
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

mod rebuild;
mod run;
#[cfg(test)]
mod tests;

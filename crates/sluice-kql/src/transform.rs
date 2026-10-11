//! L1 reductions as a DCR `transformKql` over the column model (ADR 0013, step 2).
//!
//! Each record is recognised as at most one template by its columns (which are filled, which are
//! empty) and its discriminator values, the view Sentinel's own rules have. For a recognised
//! record outside its recipe's keep-whole condition, the columns the recipe drops are set to an
//! empty value of their type. Everything else passes through unchanged:
//!
//! - text templates (their classifier is a regex over a line; L1 on a line is not a column);
//! - templates that look the same as another one in columns (fail closed: neither is touched);
//! - templates with a field outside the declared columns;
//! - nested fields (`a.b`): a DCR cannot remove a key inside a dynamic column.
//!
//! Routing and summaries are not expressible in a DCR (no `summarize`) and stay with Vector.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::guard::EffectiveRecipe;
use sluice_core::ids::TemplateId;
use sluice_core::predicate::Predicate;
use sluice_core::template::{Template, TemplateShape};

use crate::predicate::compile;
use crate::syntax;

/// The KQL type of a stream column, which decides its empty value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    /// `string`; emptied to `""`.
    String,
    /// `int`.
    Int,
    /// `long`.
    Long,
    /// `real`.
    Real,
    /// `bool`.
    Bool,
    /// `datetime`.
    DateTime,
    /// `dynamic` (objects and arrays).
    Dynamic,
}

impl ColumnType {
    fn empty(self) -> &'static str {
        match self {
            Self::String => r#""""#,
            Self::Int => "int(null)",
            Self::Long => "long(null)",
            Self::Real => "real(null)",
            Self::Bool => "bool(null)",
            Self::DateTime => "datetime(null)",
            Self::Dynamic => "dynamic(null)",
        }
    }
}

/// One column of the DCR input stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column<'a> {
    /// The column name: a top-level field of the source.
    pub name: &'a str,
    /// Its type.
    pub kind: ColumnType,
}

/// Why a template's recipe is not in the transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// A text template: its classifier is a regex over a line.
    Text,
    /// It looks the same as another template in columns and discriminators.
    Ambiguous,
    /// One of its fields is not a declared column.
    Undeclared,
    /// Nothing it removes is a whole top-level column outside its keep-whole condition.
    NothingToDo,
}

/// A generated transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transformation {
    /// The `transformKql` text.
    pub kql: String,
    /// Templates whose L1 reductions it applies.
    pub applied: BTreeSet<TemplateId>,
    /// Templates left unchanged, and why.
    pub skipped: BTreeMap<TemplateId, Skipped>,
}

/// The name of the helper column holding the recognised template; removed before output.
const TEMPLATE_COLUMN: &str = "sluice_template";

/// What the transformation does to one recognised template.
struct Shaping {
    id: TemplateId,
    recognise: String,
    keep_whole: Option<String>,
    drop: BTreeSet<String>,
    drop_if_empty: BTreeSet<String>,
}

/// Builds the transformation for one DCR input stream from the plans of its source.
#[must_use]
pub fn transformation(
    columns: &[Column<'_>],
    plans: &[(&Template, &EffectiveRecipe)],
) -> Transformation {
    let declared: BTreeMap<&str, ColumnType> = columns.iter().map(|c| (c.name, c.kind)).collect();
    let names: Vec<&str> = columns.iter().map(|c| c.name).collect();
    let mut skipped = BTreeMap::new();
    let mut signatures: BTreeMap<String, Vec<TemplateId>> = BTreeMap::new();
    let mut shapings = Vec::new();
    for (template, recipe) in plans {
        match shaping(template, recipe, &declared, &names) {
            Ok((signature, shaping)) => {
                signatures
                    .entry(signature)
                    .or_default()
                    .push(template.id.clone());
                shapings.push(shaping);
            }
            Err(reason) => {
                skipped.insert(template.id.clone(), reason);
            }
        }
    }
    let ambiguous: BTreeSet<TemplateId> = signatures
        .into_values()
        .filter(|ids| ids.len() > 1)
        .flatten()
        .collect();
    shapings.retain(|s| {
        let keep = !ambiguous.contains(&s.id);
        if !keep {
            skipped.insert(s.id.clone(), Skipped::Ambiguous);
        }
        keep
    });
    let applied = shapings.iter().map(|s| s.id.clone()).collect();
    Transformation {
        kql: render(&shapings, &declared),
        applied,
        skipped,
    }
}

/// The column signature (for ambiguity) and the shaping of one template.
fn shaping(
    template: &Template,
    recipe: &EffectiveRecipe,
    declared: &BTreeMap<&str, ColumnType>,
    names: &[&str],
) -> Result<(String, Shaping), Skipped> {
    let TemplateShape::Keyset {
        discriminators,
        paths,
    } = &template.shape
    else {
        return Err(Skipped::Text);
    };
    let present: BTreeSet<&str> = paths.iter().filter_map(|p| top(p)).collect();
    if present.iter().any(|c| !declared.contains_key(c)) {
        return Err(Skipped::Undeclared);
    }
    let keep_whole = match &recipe.keep_whole_when {
        Some(Predicate::Always) => return Err(Skipped::NothingToDo),
        Some(keep) => Some(compile(keep, names)),
        None => None,
    };
    let drop: BTreeSet<String> = recipe
        .drop_fields
        .iter()
        .filter(|f| !f.as_str().contains('.'))
        .map(|f| f.as_str().to_owned())
        .collect();
    let drop_if_empty: BTreeSet<String> = match &recipe.drop_empty_except {
        Some(except) => paths
            .iter()
            .filter(|f| !f.as_str().contains('.'))
            .filter(|f| !except.iter().any(|e| e.covers(f) || f.covers(e)))
            .filter(|f| !drop.contains(f.as_str()))
            .map(|f| f.as_str().to_owned())
            .collect(),
        None => BTreeSet::new(),
    };
    if drop.is_empty() && drop_if_empty.is_empty() {
        return Err(Skipped::NothingToDo);
    }
    let mut tests: Vec<String> = discriminators
        .iter()
        .map(|(field, value)| {
            syntax::string(value).map_or_else(
                || "false".to_owned(),
                |v| format!("tostring({}) == {v}", syntax::path(field)),
            )
        })
        .collect();
    for name in names {
        let column = syntax::quoted_name(name);
        tests.push(if present.contains(name) {
            format!("isnotnull({column})")
        } else {
            format!("isnull({column})")
        });
    }
    let signature = format!("{present:?}{discriminators:?}");
    Ok((
        signature,
        Shaping {
            id: template.id.clone(),
            recognise: tests.join(" and "),
            keep_whole,
            drop,
            drop_if_empty,
        },
    ))
}

/// The top-level column of a leaf path.
fn top(path: &FieldPath) -> Option<&str> {
    path.segments().next()
}

fn render(shapings: &[Shaping], declared: &BTreeMap<&str, ColumnType>) -> String {
    if shapings.is_empty() {
        return "source".to_owned();
    }
    let helper = syntax::quoted_name(TEMPLATE_COLUMN);
    let mut cases: Vec<String> = Vec::new();
    for s in shapings {
        cases.push(format!("({})", s.recognise));
        cases.push(syntax::string(s.id.as_str()).unwrap_or_else(|| r#""""#.to_owned()));
    }
    cases.push(r#""""#.to_owned());
    let mut lines = vec![
        "source".to_owned(),
        format!("| extend {helper} = case({})", cases.join(", ")),
    ];
    let mut assignments = Vec::new();
    for (name, kind) in declared {
        let mut when = Vec::new();
        for s in shapings {
            let empty_only = s.drop_if_empty.contains(*name);
            if !s.drop.contains(*name) && !empty_only {
                continue;
            }
            let id = syntax::string(s.id.as_str()).unwrap_or_else(|| r#""""#.to_owned());
            let mut condition = format!("{helper} == {id}");
            if let Some(keep) = &s.keep_whole {
                condition = format!("{condition} and not({keep})");
            }
            let column = syntax::quoted_name(name);
            if empty_only {
                condition = format!("{condition} and isempty({column})");
            }
            when.push(format!("({condition})"));
        }
        if !when.is_empty() {
            let column = syntax::quoted_name(name);
            assignments.push(format!(
                "{column} = iff({}, {}, {column})",
                when.join(" or "),
                kind.empty()
            ));
        }
    }
    if !assignments.is_empty() {
        lines.push(format!("| extend {}", assignments.join(",\n    ")));
    }
    lines.push(format!("| project-away {helper}"));
    lines.join("\n")
}

#[cfg(test)]
mod tests;

//! Implied values in a data collection rule, and the workspace function that puts them back.
//!
//! A transformation empties a column while it holds the value the kind of event, or another
//! column, implies (`drop_implied`). In the table an emptied column and an empty one look the
//! same, and the transformation's signature (which columns hold something) changes when one is
//! emptied, so the function recognises the records by their discriminator values alone. Only
//! values it can put back exactly are emptied:
//!
//! - every template with the same discriminator values carries the column on every record, so
//!   an empty column there was emptied;
//! - the value is not empty itself, and a KQL literal can carry it.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::guard::Plan;
use sluice_core::recipe::Literal;
use sluice_core::template::TemplateShape;

use super::{column, empty_value};
use crate::syntax;

/// An implied value the transformation empties, and how to put it back: on records with these
/// discriminator values whose column is empty (and whose `when` column holds its value).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rebuilt {
    /// The emptied column.
    pub column: String,
    /// Its type in the table.
    pub kind: String,
    /// The value it held, as text.
    pub value: String,
    /// The discriminator values of the records it was emptied on.
    pub discriminators: BTreeMap<String, String>,
    /// The column and value (as text) that implied it, if another column did.
    pub when: Option<(String, String)>,
}

/// The implied values of `plan` the transformation can empty and the function put back; the
/// others go to `left_out`. `plans` are every template of the table.
pub(super) fn implied(
    plan: &Plan<'_>,
    discriminators: &BTreeMap<String, String>,
    types: &BTreeMap<&str, &str>,
    plans: &[Plan<'_>],
    left_out: &mut Vec<String>,
) -> BTreeSet<Rebuilt> {
    let id = &plan.template.id;
    let alike: Vec<&TemplateShape> = plans
        .iter()
        .map(|p| &p.template.shape)
        .filter(|shape| values(shape).as_ref() == Some(discriminators))
        .collect();
    let mut out = BTreeSet::new();
    // One reason per column, however many of its values another column implies.
    let mut refused: BTreeSet<String> = BTreeSet::new();
    for implied in &plan.recipe.drop_implied {
        let name = implied.field.as_str();
        let mut refuse = |why: &str, left_out: &mut Vec<String>| {
            let reason = format!("{id}: the implied `{name}` {why}");
            if refused.insert(reason.clone()) {
                left_out.push(reason);
            }
        };
        let Some(kind) = types
            .get(name)
            .filter(|_| !name.contains('.') && !discriminators.contains_key(name))
        else {
            refuse(
                "is not a whole column the transformation can empty",
                left_out,
            );
            continue;
        };
        if empty_value(kind).is_none() {
            refuse(
                "is in a column with no null a transformation may write",
                left_out,
            );
            continue;
        }
        if !alike.iter().all(|shape| always_has(shape, name)) {
            refuse(
                "is missing from some records of the same kind, so a function could not tell \
                 an emptied column from an empty one",
                left_out,
            );
            continue;
        }
        let value = text(&implied.value);
        if value.is_empty() || syntax::string(&value).is_none() {
            refuse(
                "has a value an emptied column or a KQL literal cannot carry",
                left_out,
            );
            continue;
        }
        let when = match &implied.when {
            None => None,
            Some((on, literal)) => {
                let on = on.as_str();
                let literal = text(literal);
                if !types.contains_key(on) || on.contains('.') || syntax::string(&literal).is_none()
                {
                    refuse("is implied by a field that is not a whole column", left_out);
                    continue;
                }
                Some((on.to_owned(), literal))
            }
        };
        out.insert(Rebuilt {
            column: name.to_owned(),
            kind: (*kind).to_owned(),
            value,
            discriminators: discriminators.clone(),
            when,
        });
    }
    out
}

/// The KQL test that the record holds `value`'s implied value (and its condition), on the
/// columns as the transformation sees them.
pub(super) fn holds(value: &Rebuilt) -> String {
    let literal =
        |text: &str| syntax::string(text).expect("implied kept only literals KQL carries");
    let mut test = format!(
        "tostring({}) == {}",
        column(&value.column),
        literal(&value.value)
    );
    if let Some((on, implying)) = &value.when {
        test = format!(
            "{test} and tostring({}) == {}",
            column(on),
            literal(implying)
        );
    }
    test
}

/// The workspace function `{table}Full`: `table` with every implied value the transformation
/// empties put back. `None` when it empties none.
///
/// # Panics
///
/// Never for values of a [`super::Transformation`]: its implied values hold only text a KQL
/// literal can carry.
#[must_use]
pub fn function(table: &str, implied: &[Rebuilt]) -> Option<String> {
    if implied.is_empty() {
        return None;
    }
    let literal =
        |text: &str| syntax::string(text).expect("implied kept only literals KQL carries");
    let mut by_column: BTreeMap<&str, Vec<&Rebuilt>> = BTreeMap::new();
    for value in implied {
        by_column.entry(&value.column).or_default().push(value);
    }
    let mut lines = vec![
        format!(
            "// {table}Full: {table} with the values Sluice's data collection rule empties as \
             implied put back."
        ),
        format!(
            "// Save it in the workspace as a function named {table}Full (Logs, Save, Save as \
             function) and query {table}Full where you queried {table}."
        ),
        table.to_owned(),
    ];
    for (name, values) in by_column {
        let quoted = column(name);
        let mut cases = Vec::new();
        for value in values {
            let mut tests = vec![format!("isempty(tostring({quoted}))")];
            tests.extend(
                value
                    .discriminators
                    .iter()
                    .map(|(d, v)| format!("tostring({}) == {}", column(d), literal(v))),
            );
            if let Some((on, implying)) = &value.when {
                tests.push(format!("tostring({}) == {}", column(on), literal(implying)));
            }
            cases.push(format!(
                "{}, {}",
                tests.join(" and "),
                typed(&value.kind, &value.value)
            ));
        }
        lines.push(format!(
            "| extend {quoted} = case({}, {quoted})",
            cases.join(", ")
        ));
    }
    Some(lines.join("\n") + "\n")
}

/// `value` as a literal of a column of type `kind`.
fn typed(kind: &str, value: &str) -> String {
    let text = syntax::string(value).expect("implied kept only literals KQL carries");
    match kind {
        "string" => text,
        "bool" | "boolean" => format!("tobool({text})"),
        "int" => format!("toint({text})"),
        "long" => format!("tolong({text})"),
        "real" => format!("toreal({text})"),
        "datetime" => format!("todatetime({text})"),
        "guid" => format!("toguid({text})"),
        _ => format!("todynamic({text})"),
    }
}

/// The discriminator values of a key-set template.
fn values(shape: &TemplateShape) -> Option<BTreeMap<String, String>> {
    match shape {
        TemplateShape::Keyset { discriminators, .. } => Some(
            discriminators
                .iter()
                .map(|(field, value)| (field.as_str().to_owned(), value.clone()))
                .collect(),
        ),
        TemplateShape::Text { .. } => None,
    }
}

/// Whether every key set of `shape` has `column`.
fn always_has(shape: &TemplateShape, column: &str) -> bool {
    match shape {
        TemplateShape::Keyset { variants, .. } => variants
            .iter()
            .all(|variant| variant.iter().any(|f| f.as_str() == column)),
        TemplateShape::Text { .. } => false,
    }
}

/// A literal as the text `tostring` gives of the column holding it.
fn text(literal: &Literal) -> String {
    match literal {
        Literal::Bool(b) => b.to_string(),
        Literal::Integer(i) => i.to_string(),
        Literal::Text(s) => s.clone(),
    }
}

#[cfg(test)]
mod tests;

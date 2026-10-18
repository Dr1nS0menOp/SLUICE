//! A Fluent Bit Lua filter that carries out the field removals of a savings plan (ADR 0023,
//! ADR 0027) in the agent, before records leave the host.
//!
//! Four rules keep it from ever removing more than Vector would, or changing anything else:
//!
//! - **Recognition is exact and in Vector's order.** A record belongs to a template only if its
//!   leaf paths are exactly one of the template's key sets and its discriminators render to the
//!   recorded values, tested in the order of the VRL program (by template id). Every key-set
//!   template takes part that could claim a record before one that removes something. A record
//!   that fits none, or whose leaves an empty table makes unknown, is returned unchanged
//!   (contract rule 1). So is one with a template's key set whose discriminator holds a number
//!   Lua cannot render as VRL may (zero, a fraction): no later template takes it.
//! - **Keeping whole is a superset.** `keep_whole_when` compiles with [`crate::compile`], which
//!   matches at least what Vector's VRL matches.
//! - **Nothing changes before everything is decided.** The filter finds the template and
//!   evaluates its keep-whole condition first, then removes.
//! - **An unchanged record is not touched.** The filter returns code 0, so Fluent Bit keeps the
//!   record exactly as it was; a record Lua cannot give back as it was (a number past 2^53,
//!   `-0`) is never changed. A changed record goes through Lua's values: a whole float comes
//!   back as an integer (`2.0` as `2`), the same number.
//!
//! Text templates (a Drain pattern over a line) are left to a pipeline tool: Lua's patterns are
//! no regular expressions. So is counting, which needs state across records.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::guard::{Plan, Route};
use sluice_core::ids::TemplateId;
use sluice_core::predicate::Predicate;
use sluice_core::template::{Template, TemplateShape};

use crate::lua;
use crate::predicate::compile;

/// The function a generated filter defines, as the filter's `Call` names it.
pub const CALL: &str = "sluice";

/// A generated Lua filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuaFilter {
    /// The script; `None` when nothing is removed.
    pub script: Option<String>,
    /// The templates whose records it removes fields from.
    pub templates: BTreeSet<TemplateId>,
    /// The fields it removes from records of those templates outside keep-whole.
    pub fields: BTreeSet<FieldPath>,
    /// Whether it also removes null and empty fields from some of them.
    pub empty_fields: bool,
    /// Parts of the plan only a pipeline tool can carry out, and why.
    pub left_out: Vec<String>,
}

/// What a recognised record of one template loses.
struct Action {
    code: String,
    /// The keep-whole condition, if the recipe has one.
    keep: Option<String>,
    fields: BTreeSet<FieldPath>,
    empty_fields: bool,
}

/// The Lua filter carrying out `plans`' field removals; `description` says what it is for.
#[must_use]
pub fn lua_filter(description: &str, plans: &[Plan<'_>]) -> LuaFilter {
    let mut ordered: Vec<&Plan<'_>> = plans.iter().collect();
    ordered.sort_by(|a, b| a.template.id.cmp(&b.template.id));
    let mut left_out = Vec::new();
    let mut conditions = Conditions::default();
    let mut sets = Vec::new();
    let recognised: Vec<(&Plan<'_>, String, Option<String>, Option<Action>)> = ordered
        .into_iter()
        .filter_map(|plan| {
            let (condition, stop) = recognition(plan.template, &mut sets, &mut left_out)?;
            let action = action(plan, &mut conditions, &mut left_out);
            Some((plan, condition, stop, action))
        })
        .collect();
    let mut branches = Vec::new();
    let mut actions = Vec::new();
    let mut filter = LuaFilter {
        script: None,
        templates: BTreeSet::new(),
        fields: BTreeSet::new(),
        empty_fields: false,
        left_out,
    };
    for (n, (plan, condition, stop, action)) in recognised.iter().enumerate() {
        // A template that changes nothing only needs recognising where Vector would give it a
        // record before a template that does change it.
        let claims = action.is_some()
            || recognised[n + 1..]
                .iter()
                .any(|(later, _, _, a)| a.is_some() && overlap(plan.template, later.template));
        if !claims {
            continue;
        }
        let branch = branches.len();
        branches.push(match stop {
            // A record Vector may give this template but Lua cannot tell: no later template
            // takes it, and nothing is removed.
            Some(stop) => format!("if {condition} then t = {branch}\n  elseif {stop} then t = -2"),
            None => format!("if {condition} then t = {branch}"),
        });
        if let Some(action) = action {
            actions.push((branch, action));
            filter.templates.insert(plan.template.id.clone());
            filter.fields.extend(action.fields.iter().cloned());
            filter.empty_fields |= action.empty_fields;
        }
    }
    if actions.is_empty() {
        return filter;
    }
    let decide: Vec<String> = actions
        .iter()
        .map(|(branch, action)| match &action.keep {
            Some(keep) => format!("  if t == {branch} and not ({keep}) then act = {branch} end"),
            None => format!("  if t == {branch} then act = {branch} end"),
        })
        .collect();
    let apply: Vec<String> = actions
        .iter()
        .map(|(branch, action)| format!("  if act == {branch} then\n{}\n  end", action.code))
        .collect();
    filter.script = Some(format!(
        "-- {}\n{}local S = {{\n{}\n}}\nlocal K = {{}}\n{}function {CALL}(tag, ts, r)\n  local keys, \
         n = sluice_keys(r)\n  if keys == nil then return 0, ts, r end\n  local t = -1\n  {}\n  \
         end\n  local act = -1\n{}\n  if act < 0 or not sluice_safe(r) then return 0, ts, r end\n  \
         local changed = false\n{}\n  if changed then return 2, ts, r end\n  return 0, ts, r\nend\n",
        description.replace('\n', " "),
        lua::FUNCTIONS,
        sets.join(",\n"),
        conditions.functions.concat(),
        branches.join("\n  else"),
        decide.join("\n"),
        apply.join("\n")
    ));
    filter
}

/// Whether one record could fit both templates: they share a key set, and no discriminator
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

/// The condition recognising the template's records, and the one that stops the search where
/// a record may be the template's but Lua cannot tell; `None` (with the reason) when it has
/// none. Each key set becomes an entry of `sets`, the table `S` of the script.
fn recognition(
    template: &Template,
    sets: &mut Vec<String>,
    left_out: &mut Vec<String>,
) -> Option<(String, Option<String>)> {
    let TemplateShape::Keyset {
        discriminators,
        variants,
        ..
    } = &template.shape
    else {
        left_out.push(format!(
            "{}: a text template is recognised by a regex, which needs a pipeline tool",
            template.id
        ));
        return None;
    };
    if variants.is_empty() {
        return None;
    }
    let key_sets: Vec<String> = variants
        .iter()
        .map(|variant| {
            sets.push(format!(
                "  {}",
                lua::set(variant.iter().map(FieldPath::as_str))
            ));
            format!("sluice_is(keys, n, S[{}], {})", sets.len(), variant.len())
        })
        .collect();
    let key_set = if key_sets.len() == 1 {
        key_sets.concat()
    } else {
        format!("({})", key_sets.join(" or "))
    };
    let mut claim = vec![key_set.clone()];
    let mut stop = vec![key_set];
    for (field, value) in discriminators {
        let at = format!("sluice_get(r, {})", lua::segments(field));
        let literal = lua::string(value);
        let exact = format!("sluice_disc({at}) == {literal}");
        stop.push(if undecidable(value) {
            format!("sluice_may({at}, {literal})")
        } else {
            exact.clone()
        });
        claim.push(exact);
    }
    let stop = discriminators
        .iter()
        .any(|(_, value)| undecidable(value))
        .then(|| stop.join(" and "));
    Some((claim.join(" and "), stop))
}

/// Whether VRL may render as `value` a number `sluice_disc` cannot render: zero, a fraction,
/// or 10^15 and more. Any other value Lua renders exactly as VRL does.
fn undecidable(value: &str) -> bool {
    value
        .parse::<f64>()
        .is_ok_and(|x| x == 0.0 || x.fract() != 0.0 || x.abs() >= 1e15)
}

/// The keep-whole conditions of a filter's templates. Those of one source repeat the same
/// rules' pre-filters, so each distinct alternative is a function of the table `K` once, which
/// every template's condition calls.
#[derive(Default)]
struct Conditions {
    functions: Vec<String>,
    ids: BTreeMap<String, usize>,
}

impl Conditions {
    /// The Lua of `predicate`, as calls of the functions of its alternatives.
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
                    self.functions
                        .push(format!("K[{id}] = function(r)\n  return {code}\nend\n"));
                }
                format!("K[{id}](r)")
            })
            .collect();
        calls.join(" or ")
    }
}

/// What a recognised record of the template loses; `None` when nothing.
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
        .map(|field| {
            format!(
                "    if sluice_remove(r, {}) then changed = true end",
                lua::segments(field)
            )
        })
        .collect();
    if let Some(except) = &recipe.drop_empty_except {
        let keep = |field: &FieldPath| except.iter().any(|e| e.covers(field) || field.covers(e));
        if plan
            .template
            .fields
            .iter()
            .any(|field| !keep(field) && !recipe.drop_fields.contains(field))
        {
            // The record is exactly one of the template's key sets, so its leaves are the
            // template's fields VRL goes through, and only exceptions that touch one of them
            // can matter.
            let relevant = except.iter().filter(|e| {
                plan.template
                    .fields
                    .iter()
                    .any(|f| e.covers(f) || f.covers(e))
            });
            lines.push(format!(
                "    if sluice_remove_empty_except(r, keys, {}, {}) then changed = true end",
                lua::list(relevant.map(FieldPath::as_str)),
                lua::set(recipe.drop_fields.iter().map(FieldPath::as_str))
            ));
            empty_fields = true;
        }
    }
    if lines.is_empty() {
        return None;
    }
    Some(Action {
        code: lines.join("\n"),
        keep: recipe.keep_whole_when.as_ref().map(|k| conditions.call(k)),
        fields: recipe.drop_fields.iter().cloned().collect(),
        empty_fields,
    })
}

#[cfg(test)]
mod tests;

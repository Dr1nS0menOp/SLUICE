//! OTTL statements for the collector's `transform` processor that carry out the field removals
//! of a savings plan (ADR 0023, ADR 0028) on log records whose body is the parsed JSON record.
//!
//! The same rules as the other generators keep them from removing more than Vector would:
//!
//! - **Recognition is exact and in Vector's order.** A record belongs to a template only if its
//!   body is, level by level, a map of exactly the key set's keys (OTTL reads a null and a
//!   missing key alike, so each map is copied with the expected keys deleted, and none may be
//!   left), and its discriminators render to the recorded values. The first statements set the template's
//!   number in `log.cache`, in template id order, each only while none is set. Where a record has
//!   a template's key set and a discriminator VRL may render from a value OTTL does not compare
//!   (a fraction, a null), `-1` is set: no later template takes it, and nothing is removed.
//! - **Keeping whole is a superset, and the default.** `keep_whole_when` compiles with
//!   [`crate::compile`]; each distinct alternative is set in `log.cache` to hold, and then not
//!   to where its condition is false. A statement that fails is skipped (`error_mode: ignore`),
//!   so a condition that cannot be evaluated keeps the record whole.
//! - **Nothing changes before everything is decided.** The decision to remove is set before the
//!   first `delete_key`, and every removal tests only that decision.
//!
//! The statements change nothing else: OTTL edits the record in place. Text templates and
//! counting are left to a pipeline tool.

use std::collections::{BTreeMap, BTreeSet};

use sluice_core::field::FieldPath;
use sluice_core::guard::{Plan, Route};
use sluice_core::ids::TemplateId;
use sluice_core::predicate::Predicate;
use sluice_core::recipe::Literal;
use sluice_core::template::{Template, TemplateShape};

use crate::ottl;
use crate::predicate::compile;

/// Where the parsed record is: the filelog receiver's `json_parser` with `parse_to: body`.
pub const ROOT: &str = "log.body";

/// The cache keys the statements keep their decisions in.
const TEMPLATE: &str = "log.cache[\"sluice_t\"]";
const ACTION: &str = "log.cache[\"sluice_a\"]";

/// Generated transform statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statements {
    /// The OTTL statements, in order; empty when nothing is removed.
    pub statements: Vec<String>,
    /// The templates whose records they remove fields from.
    pub templates: BTreeSet<TemplateId>,
    /// The fields they remove from records of those templates outside keep-whole.
    pub fields: BTreeSet<FieldPath>,
    /// Whether they also remove empty fields from some of them.
    pub empty_fields: bool,
    /// Parts of the plan only a pipeline tool can carry out, and why.
    pub left_out: Vec<String>,
}

/// The statements carrying out `plans`' field removals.
#[must_use]
pub fn transform(plans: &[Plan<'_>]) -> Statements {
    let mut ordered: Vec<&Plan<'_>> = plans.iter().collect();
    ordered.sort_by(|a, b| a.template.id.cmp(&b.template.id));
    let mut out = Statements {
        statements: Vec::new(),
        templates: BTreeSet::new(),
        fields: BTreeSet::new(),
        empty_fields: false,
        left_out: Vec::new(),
    };
    let mut probes = 0usize;
    let mut recognised: Vec<(&Plan<'_>, Recognition, Option<Removal>)> = Vec::new();
    for plan in ordered {
        if let Some(recognition) = recognition(plan.template, &mut probes, &mut out.left_out) {
            let removal = removal(plan, &mut out.left_out);
            recognised.push((plan, recognition, removal));
        }
    }
    let mut prepare = Vec::new();
    let mut classify = Vec::new();
    let mut keeps = Keeps::default();
    let mut decide = Vec::new();
    let mut remove = Vec::new();
    let mut branches = 0usize;
    for (n, (plan, condition, removal)) in recognised.iter().enumerate() {
        let claims = removal.is_some()
            || recognised[n + 1..]
                .iter()
                .any(|(later, _, r)| r.is_some() && overlap(plan.template, later.template));
        if !claims {
            continue;
        }
        let branch = branches;
        branches += 1;
        prepare.extend(condition.prepare.iter().cloned());
        classify.push(format!(
            "set({TEMPLATE}, {branch}) where {TEMPLATE} == nil and {}",
            condition.condition
        ));
        // A record Vector may give this template but OTTL cannot tell: no later template takes
        // it, and nothing is removed.
        if let Some(stop) = &condition.stop {
            classify.push(format!(
                "set({TEMPLATE}, -1) where {TEMPLATE} == nil and {stop}"
            ));
        }
        let Some(removal) = removal else { continue };
        let keep = plan.recipe.keep_whole_when.as_ref().map(|k| keeps.call(k));
        decide.push(match keep {
            Some(keep) => {
                format!("set({ACTION}, {branch}) where {TEMPLATE} == {branch} and not ({keep})")
            }
            None => format!("set({ACTION}, {branch}) where {TEMPLATE} == {branch}"),
        });
        remove.extend(
            removal
                .statements
                .iter()
                .map(|s| format!("{s} and {ACTION} == {branch}")),
        );
        out.templates.insert(plan.template.id.clone());
        out.fields.extend(removal.fields.iter().cloned());
        out.empty_fields |= removal.empty_fields;
    }
    if remove.is_empty() {
        return out;
    }
    out.statements = prepare;
    out.statements.extend(classify);
    out.statements.extend(keeps.statements);
    out.statements.extend(decide);
    out.statements.extend(remove);
    out
}

/// The `transform` processor running `statements`, as collector configuration (YAML). Errors
/// are ignored, so a statement that fails leaves the record as the earlier ones left it: a
/// failing decision removes nothing.
#[must_use]
pub fn processor(name: &str, statements: &[String]) -> String {
    let quoted: Vec<String> = statements
        .iter()
        .map(|s| format!("          - '{}'\n", s.replace('\'', "''")))
        .collect();
    format!(
        "  transform/{name}:\n    error_mode: ignore\n    log_statements:\n      - context: \
         log\n        statements:\n{}",
        quoted.concat()
    )
}

/// What a recognised record of one template loses: `delete_key` statements, each still to be
/// guarded by the decision.
struct Removal {
    statements: Vec<String>,
    fields: BTreeSet<FieldPath>,
    empty_fields: bool,
}

/// A `delete_key` of `field`, where its parent is a map and `condition` holds.
fn delete(field: &FieldPath, condition: Option<&str>) -> String {
    let segments: Vec<&str> = field.segments().collect();
    let (last, parents) = segments.split_last().unwrap_or((&"", &[]));
    let parent = parents.iter().fold(ROOT.to_owned(), |path, s| {
        format!("{path}[{}]", ottl::string(s))
    });
    let mut statement = format!(
        "delete_key({parent}, {}) where IsMap({parent})",
        ottl::string(last)
    );
    if let Some(condition) = condition {
        statement.push_str(" and ");
        statement.push_str(condition);
    }
    statement
}

fn removal(plan: &Plan<'_>, left_out: &mut Vec<String>) -> Option<Removal> {
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
    let mut statements: Vec<String> = recipe
        .drop_fields
        .iter()
        .map(|field| delete(field, None))
        .collect();
    let mut empty_fields = false;
    if let Some(except) = &recipe.drop_empty_except {
        let keep = |field: &FieldPath| except.iter().any(|e| e.covers(field) || field.covers(e));
        for field in &plan.template.fields {
            if keep(field) || recipe.drop_fields.contains(field) {
                continue;
            }
            // Null reads as `nil`, as does a missing field, which `delete_key` leaves alone.
            let value = ottl::path(ROOT, field);
            statements.push(delete(
                field,
                Some(&format!("({value} == \"\" or {value} == nil)")),
            ));
            empty_fields = true;
        }
    }
    // Last, as in Vector: a field that implies another is tested as it is sent.
    let mut fields: BTreeSet<FieldPath> = recipe.drop_fields.iter().cloned().collect();
    for implied in &recipe.drop_implied {
        let when = implied.when.as_ref().map(|(on, value)| (on, value));
        let tests: Option<Vec<String>> = std::iter::once((&implied.field, &implied.value))
            .chain(when)
            .map(|(path, value)| {
                literal(value).map(|v| format!("{} == {v}", ottl::path(ROOT, path)))
            })
            .collect();
        let Some(tests) = tests else {
            left_out.push(format!(
                "{id}: the implied `{}` is tested against a whole number, which the collector \
                 cannot test: its JSON parser reads every number as a float",
                implied.field
            ));
            continue;
        };
        statements.push(delete(
            &implied.field,
            Some(&format!("({})", tests.join(" and "))),
        ));
        fields.insert(implied.field.clone());
    }
    (!statements.is_empty()).then_some(Removal {
        statements,
        fields,
        empty_fields,
    })
}

/// An OTTL literal equal to exactly the values VRL's `==` takes as `value`, or `None` for a
/// whole number: the filelog receiver's JSON parser reads every number as a float, so neither
/// `==` (which takes `3.0` for `3`) nor `IsInt` (never true then) tells them apart as VRL does.
fn literal(value: &Literal) -> Option<String> {
    match value {
        Literal::Text(text) => Some(ottl::string(text)),
        Literal::Bool(b) => Some(b.to_string()),
        Literal::Integer(_) => None,
    }
}

/// The keep-whole alternatives, each evaluated once into the cache where a record has a
/// template.
#[derive(Default)]
struct Keeps {
    statements: Vec<String>,
    ids: BTreeMap<String, usize>,
}

impl Keeps {
    /// The condition that some alternative of `predicate` holds, as cache tests.
    fn call(&mut self, predicate: &Predicate) -> String {
        let parts: &[Predicate] = match predicate {
            Predicate::Any(parts) => parts,
            other => std::slice::from_ref(other),
        };
        if parts.is_empty() {
            return "false".to_owned();
        }
        let tests: Vec<String> = parts
            .iter()
            .map(|part| {
                let code = compile(part, ROOT);
                let next = self.ids.len();
                let id = *self.ids.entry(code.clone()).or_insert(next);
                if id == next {
                    // Kept unless the test says otherwise: a statement that fails is skipped,
                    // and then the record stays whole.
                    self.statements
                        .push(format!("set(log.cache[\"sluice_k{id}\"], true)"));
                    self.statements.push(format!(
                        "set(log.cache[\"sluice_k{id}\"], false) where {TEMPLATE} != nil and \
                         not ({code})"
                    ));
                }
                format!("log.cache[\"sluice_k{id}\"] == true")
            })
            .collect();
        tests.join(" or ")
    }
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

/// A key set as a tree: each key with the keys below it (none for a leaf).
#[derive(Default)]
struct Node(BTreeMap<String, Node>);

/// A template's recognition: the statements that prepare it and the condition itself.
struct Recognition {
    /// Statements that copy each map of the record into the cache with the expected keys
    /// removed, so the condition can see whether any other key is there.
    prepare: Vec<String>,
    condition: String,
    /// The condition that stops the search where a record may be the template's but OTTL
    /// cannot tell: a discriminator VRL may render from a value OTTL does not compare.
    stop: Option<String>,
}

impl Node {
    fn of(variant: &BTreeSet<FieldPath>) -> Self {
        let mut root = Self::default();
        for path in variant {
            let mut node = &mut root;
            for segment in path.segments() {
                node = node.0.entry(segment.to_owned()).or_default();
            }
        }
        root
    }

    /// The condition that the map at `at` has exactly this node's keys, level by level, and no
    /// object where a leaf is. OTTL reads a null and a missing key alike, so each map is copied
    /// into the cache (a `probe`) with the expected keys deleted: none may be left, and the map
    /// must hold as many keys as expected. `guards` are the tests that every map above is one.
    fn condition(
        &self,
        at: &str,
        guards: &[String],
        probes: &mut usize,
        prepare: &mut Vec<String>,
    ) -> String {
        let probe = format!("log.cache[\"sluice_p{probes}\"]");
        *probes += 1;
        let mut here: Vec<String> = guards.to_vec();
        here.push(format!("IsMap({at})"));
        prepare.push(format!("set({probe}, {at}) where {}", here.join(" and ")));
        let keys: Vec<String> = self.0.keys().map(|k| ottl::quote_meta(k)).collect();
        prepare.push(format!(
            "delete_matching_keys({probe}, {}) where IsMap({probe})",
            ottl::string(&format!("^(?:{})$", keys.join("|")))
        ));
        let mut parts = here.clone();
        parts.push(format!("Len({at}) == {}", self.0.len()));
        parts.push(format!("IsMap({probe})"));
        parts.push(format!("Len({probe}) == 0"));
        for (key, child) in &self.0 {
            let value = format!("{at}[{}]", ottl::string(key));
            if child.0.is_empty() {
                parts.push(format!("not IsMap({value})"));
            } else {
                parts.push(child.condition(&value, &here, probes, prepare));
            }
        }
        parts.join(" and ")
    }
}

/// The recognition of the template's records, or `None` (with the reason) when it has none.
fn recognition(
    template: &Template,
    probes: &mut usize,
    left_out: &mut Vec<String>,
) -> Option<Recognition> {
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
    let mut prepare = Vec::new();
    let key_sets: Vec<String> = variants
        .iter()
        .map(|variant| {
            let condition = Node::of(variant).condition(ROOT, &[], probes, &mut prepare);
            format!("({condition})")
        })
        .collect();
    let key_set = if key_sets.len() == 1 {
        key_sets.concat()
    } else {
        format!("({})", key_sets.join(" or "))
    };
    let mut claim = vec![key_set.clone()];
    let mut stop = vec![key_set];
    let mut undecided = false;
    for (field, value) in discriminators {
        let at = ottl::path(ROOT, field);
        let exact = discriminator(&at, value);
        match undecidable(&at, value) {
            Some(maybe) => {
                undecided = true;
                stop.push(format!("({exact} or {maybe})"));
            }
            None => stop.push(exact.clone()),
        }
        claim.push(exact);
    }
    Some(Recognition {
        prepare,
        condition: claim.join(" and "),
        stop: undecided.then(|| stop.join(" and ")),
    })
}

/// That the value at `at` renders as VRL renders `value`: the string itself, or the whole number
/// or boolean it spells. A number written otherwise (`1.5`, `0`, whose `-0` VRL renders apart)
/// only matches as a string, so such a record is not recognised.
fn discriminator(at: &str, value: &str) -> String {
    let literal = ottl::string(value);
    if whole(value) || value == "true" || value == "false" {
        format!("({at} == {literal} or {at} == {value})")
    } else {
        format!("{at} == {literal}")
    }
}

/// Whether `value` spells a whole number OTTL compares exactly as VRL renders it: no zero,
/// leading zero or more than 15 digits.
fn whole(value: &str) -> bool {
    let integer = value.strip_prefix('-').unwrap_or(value);
    !integer.is_empty()
        && integer.len() < 16
        && integer.chars().all(|c| c.is_ascii_digit())
        && !integer.starts_with('0')
}

/// What else VRL may render as `value` that [`discriminator`] does not take: a null, list or
/// map for `""`, any number for a number that is not [`whole`].
fn undecidable(at: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        Some(format!("({at} == nil or IsList({at}) or IsMap({at}))"))
    } else if !whole(value) && value.parse::<f64>().is_ok() {
        Some(format!("(IsInt({at}) or IsDouble({at}))"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests;

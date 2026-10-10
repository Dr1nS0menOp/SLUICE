//! Superset pre-filters from Sigma detections.
//!
//! The result must match every event the rule could match, so every construct we cannot
//! express exactly is widened, never narrowed:
//!
//! - `not …` → [`Predicate::Always`] (exclusions only ever remove matches);
//! - array blocks, unsupported modifiers, `?` wildcards, non-string/integer values → `Always`;
//! - keywords become a free-text [`KeywordTest`] (substring of any value), exactly as rsigma
//!   matches them;
//! - `all of …` uses only selections every reading of the spec includes (fewer conjuncts is
//!   wider), `1 of …` uses every candidate (more disjuncts is wider).

use std::collections::HashMap;

use rsigma_parser::ast::{
    ConditionExpr, Detection, DetectionItem, Detections, Modifier, Quantifier, SelectorPattern,
};
use rsigma_parser::value::{SigmaString, SigmaValue, SpecialChar, StringPart};
use sluice_core::field::FieldPath;
use sluice_core::predicate::{FieldTest, KeywordTest, MatchOp, Predicate};

/// The superset pre-filter of one rule: any of its conditions.
pub(crate) fn rule_prefilter(detections: &Detections) -> Predicate {
    if detections.conditions.is_empty() {
        return Predicate::Always;
    }
    Predicate::any(
        detections
            .conditions
            .iter()
            .map(|c| condition(c, &detections.named)),
    )
}

fn condition(expr: &ConditionExpr, named: &HashMap<String, Detection>) -> Predicate {
    match expr {
        ConditionExpr::Identifier(name) => named.get(name).map_or(Predicate::Always, detection),
        ConditionExpr::And(parts) => Predicate::all(parts.iter().map(|p| condition(p, named))),
        ConditionExpr::Or(parts) => Predicate::any(parts.iter().map(|p| condition(p, named))),
        ConditionExpr::Not(_) => Predicate::Always,
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => selector(quantifier, pattern, named),
    }
}

fn selector(
    quantifier: &Quantifier,
    pattern: &SelectorPattern,
    named: &HashMap<String, Detection>,
) -> Predicate {
    let conjunctive = matches!(quantifier, Quantifier::All);
    let mut selected: Vec<(&String, &Detection)> = named
        .iter()
        .filter(|(name, _)| match pattern {
            // `them` excludes `_`-prefixed identifiers in pySigma. Including them is only wider
            // for a disjunction, so do that; leave them out of a conjunction.
            SelectorPattern::Them => !conjunctive || !name.starts_with('_'),
            SelectorPattern::Pattern(glob) => glob_match(glob, name),
        })
        .collect();
    selected.sort_by_key(|(name, _)| *name);
    if selected.is_empty() {
        return Predicate::Always;
    }
    let parts = selected.into_iter().map(|(_, d)| detection(d));
    if conjunctive {
        Predicate::all(parts)
    } else {
        // `N of …` implies `1 of …`, which is wider.
        Predicate::any(parts)
    }
}

/// Sigma selector globs only use `*`.
fn glob_match(glob: &str, name: &str) -> bool {
    match glob.split_once('*') {
        None => glob == name,
        Some((prefix, rest)) => {
            let Some(remaining) = name.strip_prefix(prefix) else {
                return false;
            };
            if rest.is_empty() {
                return true;
            }
            (0..=remaining.len())
                .filter(|&i| remaining.is_char_boundary(i))
                .any(|i| glob_match(rest, &remaining[i..]))
        }
    }
}

fn detection(detection_: &Detection) -> Predicate {
    match detection_ {
        Detection::AllOf(items) => Predicate::all(items.iter().map(item)),
        Detection::AnyOf(parts) => Predicate::any(parts.iter().map(detection)),
        Detection::And(parts) => Predicate::all(parts.iter().map(detection)),
        Detection::Keywords(values) => keywords(values),
        Detection::ArrayMatch { .. } | Detection::Conditional { .. } => Predicate::Always,
    }
}

/// Sigma keywords match a substring of any value, case-insensitively. Edge `*` wildcards fold
/// away (contains already allows anything around); inner wildcards and non-text values widen.
fn keywords(values: &[SigmaValue]) -> Predicate {
    let mut texts = Vec::new();
    for value in values {
        let text = match value {
            SigmaValue::String(s) => match string_test(Base::Contains, s) {
                Some((MatchOp::Contains, literal)) => literal,
                // `a*b` in a value: that value contains its longest literal piece.
                None => match pieces(s).into_iter().max_by_key(String::len) {
                    Some(piece) if piece.chars().count() >= MIN_PIECE => piece,
                    _ => return Predicate::Always,
                },
                _ => return Predicate::Always,
            },
            SigmaValue::Integer(n) => n.to_string(),
            _ => return Predicate::Always,
        };
        if text.is_empty() {
            return Predicate::Always;
        }
        texts.push(text);
    }
    if texts.is_empty() {
        return Predicate::Always;
    }
    Predicate::Keywords(KeywordTest {
        values: texts,
        case_sensitive: false,
    })
}

/// A keyword item written as a mapping, such as `keywords: {'|all': [a, b]}`: with `|all`
/// every keyword must occur somewhere in the event, without it any. Other modifiers widen.
fn keyword_item(item_: &DetectionItem) -> Predicate {
    match item_.field.modifiers.as_slice() {
        [] => keywords(&item_.values),
        [Modifier::All] => Predicate::all(
            item_
                .values
                .iter()
                .map(|value| keywords(std::slice::from_ref(value))),
        ),
        _ => Predicate::Always,
    }
}

/// How an item's values are compared, from its modifiers; `None` if not expressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Exists,
}

fn item(item_: &DetectionItem) -> Predicate {
    let Some(field) = item_.field.name.as_deref() else {
        return keyword_item(item_);
    };
    let Some((base, case_sensitive)) = base(&item_.field.modifiers) else {
        // Not expressible, but a positive match still needs a value in the field.
        return present_unless_null(field, &item_.values);
    };
    if base == Base::Exists {
        // `exists: true` is a field test; `exists: false` matches absence, which is unbounded.
        return if matches!(item_.values.as_slice(), [SigmaValue::Bool(true)]) {
            test(field, MatchOp::Exists, Vec::new(), case_sensitive)
        } else {
            Predicate::Always
        };
    }
    if item_.values.is_empty() {
        return Predicate::Always;
    }
    // A value list is OR-linked, or AND-linked with `|all`: every value must match.
    let tests = item_
        .values
        .iter()
        .map(|value| value_test(field, base, case_sensitive, value));
    if item_.field.modifiers.contains(&Modifier::All) {
        Predicate::all(tests)
    } else {
        Predicate::any(tests)
    }
}

/// The comparison and case sensitivity implied by a modifier list.
fn base(modifiers: &[Modifier]) -> Option<(Base, bool)> {
    let mut base = Base::Equals;
    let mut cased = false;
    let mut ignore_case = false;
    for modifier in modifiers {
        let next = match modifier {
            Modifier::Contains => Base::Contains,
            Modifier::StartsWith => Base::StartsWith,
            Modifier::EndsWith => Base::EndsWith,
            Modifier::Re => Base::Regex,
            Modifier::Exists => Base::Exists,
            Modifier::All => continue,
            Modifier::Cased => {
                cased = true;
                continue;
            }
            Modifier::IgnoreCase => {
                ignore_case = true;
                continue;
            }
            // Encodings, CIDR, comparisons, placeholders, field references, regex flags other
            // than `i`, and timestamp parts are not expressible: widen.
            _ => return None,
        };
        if base != Base::Equals && base != next {
            return None;
        }
        base = next;
    }
    // Sigma strings are case-insensitive unless `cased`; Sigma regexes are case-sensitive
    // unless `i`.
    let case_sensitive = if base == Base::Regex {
        !ignore_case
    } else {
        cased
    };
    Some((base, case_sensitive))
}

fn value_test(field: &str, base: Base, case_sensitive: bool, value: &SigmaValue) -> Predicate {
    match value {
        SigmaValue::String(s) if base == Base::Regex => test(
            field,
            MatchOp::Regex,
            vec![s.original.clone()],
            case_sensitive,
        ),
        SigmaValue::String(s) => match string_test(base, s) {
            Some((op, literal)) => test(field, op, vec![literal], case_sensitive),
            None => wildcard_superset(field, base, case_sensitive, s),
        },
        SigmaValue::Integer(n) if base == Base::Equals => {
            test(field, MatchOp::Equals, vec![n.to_string()], case_sensitive)
        }
        SigmaValue::Null => Predicate::Always,
        _ => Predicate::present(FieldPath::new(field)),
    }
}

/// `present(field)` for a value list without `null` (which matches a missing field), else
/// `Always`.
fn present_unless_null(field: &str, values: &[SigmaValue]) -> Predicate {
    if values.is_empty() || values.iter().any(|v| matches!(v, SigmaValue::Null)) {
        Predicate::Always
    } else {
        Predicate::present(FieldPath::new(field))
    }
}

/// Folds leading/trailing `*` into the comparison; any other wildcard is not expressible.
fn string_test(base: Base, s: &SigmaString) -> Option<(MatchOp, String)> {
    let parts = s.parts.as_slice();
    let is_multi = |p: &StringPart| matches!(p, StringPart::Special(SpecialChar::WildcardMulti));
    let leading = parts.iter().take_while(|p| is_multi(p)).count();
    let trailing = parts[leading..]
        .iter()
        .rev()
        .take_while(|p| is_multi(p))
        .count();
    let core = &parts[leading..parts.len() - trailing];

    let mut literal = String::new();
    for part in core {
        match part {
            StringPart::Plain(text) => literal.push_str(text),
            StringPart::Special(_) => return None,
        }
    }
    let anchored_start = matches!(base, Base::Equals | Base::StartsWith) && leading == 0;
    let anchored_end = matches!(base, Base::Equals | Base::EndsWith) && trailing == 0;
    let op = match (anchored_start, anchored_end) {
        (true, true) => MatchOp::Equals,
        (true, false) => MatchOp::StartsWith,
        (false, true) => MatchOp::EndsWith,
        (false, false) => MatchOp::Contains,
    };
    if literal.is_empty() && op != MatchOp::Equals {
        // `*` alone matches any present value.
        return Some((MatchOp::Exists, String::new()));
    }
    Some((op, literal))
}

/// Literal pieces shorter than this say too little to bound a keyword search.
const MIN_PIECE: usize = 3;

/// The literal pieces between a string's wildcards (`*` or `?`), in order.
fn pieces(s: &SigmaString) -> Vec<String> {
    let mut pieces = vec![String::new()];
    for part in &s.parts {
        match part {
            StringPart::Plain(text) => {
                if let Some(last) = pieces.last_mut() {
                    last.push_str(text);
                }
            }
            StringPart::Special(_) => pieces.push(String::new()),
        }
    }
    pieces
}

/// A superset test for a value with inner wildcards, such as `a*b?c`: a matching value starts
/// with its first piece (when the comparison is anchored there), ends with its last, and
/// contains its longest. `Always` if no piece is left.
fn wildcard_superset(field: &str, base: Base, case_sensitive: bool, s: &SigmaString) -> Predicate {
    if base == Base::Regex || base == Base::Exists {
        return Predicate::Always;
    }
    let pieces = pieces(s);
    let mut tests = Vec::new();
    if let Some(first) = pieces.first().filter(|p| !p.is_empty())
        && matches!(base, Base::Equals | Base::StartsWith)
    {
        tests.push(test(
            field,
            MatchOp::StartsWith,
            vec![first.clone()],
            case_sensitive,
        ));
    }
    if let Some(last) = pieces.last().filter(|p| !p.is_empty())
        && pieces.len() > 1
        && matches!(base, Base::Equals | Base::EndsWith)
    {
        tests.push(test(
            field,
            MatchOp::EndsWith,
            vec![last.clone()],
            case_sensitive,
        ));
    }
    if let Some(longest) = pieces
        .iter()
        .max_by_key(|p| p.len())
        .filter(|p| !p.is_empty())
    {
        tests.push(test(
            field,
            MatchOp::Contains,
            vec![longest.clone()],
            case_sensitive,
        ));
    }
    if tests.is_empty() {
        // Only wildcards: any value matches, but there must be one.
        return Predicate::present(FieldPath::new(field));
    }
    Predicate::all(tests)
}

fn test(field: &str, op: MatchOp, values: Vec<String>, case_sensitive: bool) -> Predicate {
    let values = if op == MatchOp::Exists {
        Vec::new()
    } else {
        values
    };
    Predicate::Field(FieldTest {
        field: FieldPath::new(field),
        op,
        values,
        case_sensitive,
    })
}

#[cfg(test)]
mod tests;

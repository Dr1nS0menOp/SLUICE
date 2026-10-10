//! Which fields applicable rules need, and on which events.
//!
//! A rule protects the fields it may read (all of them for a rule whose fields are unknown,
//! the text fields for a raw-text rule). The protection holds on every event the rule's
//! pre-filter matches. On any other event the rule cannot fire, before or after a field is
//! removed: pre-filters widen `not`, `null` and `exists: false` to "every event", so their
//! remaining tests only get harder to pass when fields go. A protected field may therefore be
//! removed from events outside the pre-filter, and kept whole on the rest (contract rule 3).
//! A rule with an unbounded pre-filter protects its fields everywhere.

use std::collections::BTreeSet;

use super::{Adjustment, ContractRule, Reason};
use crate::field::FieldPath;
use crate::ids::RuleId;
use crate::predicate::Predicate;
use crate::recipe::Level;
use crate::rules::{RequiredFields, RuleRequirements};
use crate::template::{Template, TemplateShape};

/// One rule's claim on a field (`None`: on every field).
struct Claim<'a> {
    field: Option<FieldPath>,
    rule: &'a RuleRequirements,
    /// The rule may match every event of the template (its pre-filter is unbounded, or holds
    /// for the template's fixed values), so the claim holds everywhere.
    everywhere: bool,
}

pub(super) struct Protection<'a> {
    claims: Vec<Claim<'a>>,
}

impl<'a> Protection<'a> {
    /// The claims of `applicable` rules. Without `conditional`, every claim holds everywhere.
    pub(super) fn of(
        template: &Template,
        applicable: &[&'a RuleRequirements],
        conditional: bool,
    ) -> Self {
        let fixed: &[(FieldPath, String)] = match &template.shape {
            TemplateShape::Keyset { discriminators, .. } => discriminators,
            TemplateShape::Text { .. } => &[],
        };
        let mut claims = Vec::new();
        for &rule in applicable {
            let everywhere = !conditional || rule.prefilter.holds_for_all_with(fixed);
            let claim = |field| Claim {
                field,
                rule,
                everywhere,
            };
            match &rule.fields {
                RequiredFields::Known(known) => {
                    claims.extend(known.iter().map(|f| claim(Some(f.clone()))));
                }
                RequiredFields::Unknown => claims.push(claim(None)),
            }
            if rule.matches_raw_text {
                claims.extend(template.text_fields.iter().map(|f| claim(Some(f.clone()))));
            }
        }
        Self { claims }
    }

    /// The claims that cover `field`: on the field itself, its parent or its child (dropping a
    /// parent removes the child, and a rule that tests a parent object sees its children).
    fn on<'s>(&'s self, field: &'s FieldPath) -> impl Iterator<Item = &'s Claim<'a>> {
        self.claims.iter().filter(move |claim| {
            claim
                .field
                .as_ref()
                .is_none_or(|kept| field.covers(kept) || kept.covers(field))
        })
    }

    /// The subset of `proposed` that may be removed. A field claimed by a rule with an
    /// unbounded pre-filter is kept; one claimed only by bounded rules is removed outside
    /// their pre-filters, which are added to `conditions`.
    pub(super) fn allowed_drops(
        &self,
        proposed: &BTreeSet<FieldPath>,
        adjustments: &mut Vec<Adjustment>,
        conditions: &mut Vec<Predicate>,
    ) -> BTreeSet<FieldPath> {
        let mut allowed = BTreeSet::new();
        for field in proposed {
            let claims: Vec<&Claim<'_>> = self.on(field).collect();
            if let Some(unbounded) = claims.iter().find(|c| c.everywhere) {
                adjustments.push(refused(field, unbounded));
                continue;
            }
            for claim in &claims {
                conditions.push(claim.rule.prefilter.clone());
                adjustments.push(narrowed(claim));
            }
            allowed.insert(field.clone());
        }
        allowed
    }

    /// Fields exempt from empty-field removal, or `None` if a rule with an unbounded pre-filter
    /// may read any field. Fields claimed only by bounded rules are removed outside their
    /// pre-filters, which are added to `conditions`.
    pub(super) fn drop_empty_exceptions(
        &self,
        adjustments: &mut Vec<Adjustment>,
        conditions: &mut Vec<Predicate>,
    ) -> Option<BTreeSet<FieldPath>> {
        let mut except = BTreeSet::new();
        for claim in &self.claims {
            let unbounded = claim.everywhere;
            match (&claim.field, unbounded) {
                (None, true) => {
                    adjustments.push(Adjustment {
                        contract: ContractRule::RuleMatchesForwarded,
                        level: Some(Level::Lossless),
                        reason: Reason::AllFieldsNeededByRule {
                            rule: claim.rule.rule.clone(),
                        },
                    });
                    return None;
                }
                (Some(field), true) => {
                    except.insert(field.clone());
                }
                (_, false) => conditions.push(claim.rule.prefilter.clone()),
            }
        }
        Some(except)
    }
}

fn refused(field: &FieldPath, claim: &Claim<'_>) -> Adjustment {
    let rule = claim.rule.rule.clone();
    let reason = match &claim.field {
        Some(_) => Reason::FieldNeededByRule {
            field: field.clone(),
            rule,
        },
        None => Reason::AllFieldsNeededByRule { rule },
    };
    Adjustment {
        contract: ContractRule::RuleMatchesForwarded,
        level: Some(Level::Lossless),
        reason,
    }
}

fn narrowed(claim: &Claim<'_>) -> Adjustment {
    Adjustment {
        contract: ContractRule::RuleMatchesForwarded,
        level: Some(Level::Lossless),
        reason: Reason::KeptWhereRuleMayMatch {
            field: claim.field.clone(),
            rule: RuleId::clone(&claim.rule.rule),
        },
    }
}

//! The objects a plan's removals may empty. An object whose every field went says nothing, and
//! a rule that reads an object keeps its fields (the guardrails protect a field and everything
//! above and below it), so every generator removes such an object after its removals.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use super::model::Plan;
use crate::field::FieldPath;

impl Plan<'_> {
    /// Every field the plan's reductions may remove from a forwarded event: the recipe's
    /// fields, the template's fields that may go when empty, and the implied values.
    #[must_use]
    pub fn removable_fields(&self) -> BTreeSet<FieldPath> {
        let mut removed: BTreeSet<FieldPath> = self.recipe.drop_fields.iter().cloned().collect();
        if let Some(except) = &self.recipe.drop_empty_except {
            removed.extend(
                self.template
                    .fields
                    .iter()
                    .filter(|field| !except.iter().any(|e| e.covers(field) || field.covers(e)))
                    .cloned(),
            );
        }
        removed.extend(self.recipe.drop_implied.iter().map(|v| v.field.clone()));
        removed
    }

    /// The objects above [`Plan::removable_fields`] that are not removed themselves, the deepest
    /// first, so an object is tested after the objects inside it. A generator removes each one
    /// that its removals emptied, and keeps one that came empty with the event.
    #[must_use]
    pub fn emptiable_objects(&self) -> Vec<FieldPath> {
        parents(&self.removable_fields())
    }
}

/// The objects above `removed` that no path of `removed` covers, the deepest first.
fn parents(removed: &BTreeSet<FieldPath>) -> Vec<FieldPath> {
    let mut parents: BTreeSet<(Reverse<usize>, FieldPath)> = BTreeSet::new();
    for field in removed {
        let segments: Vec<&str> = field.segments().collect();
        for depth in 1..segments.len() {
            let parent = FieldPath::new(segments[..depth].join("."));
            if !removed.iter().any(|r| r.covers(&parent)) {
                parents.insert((Reverse(depth), parent));
            }
        }
    }
    parents.into_iter().map(|(_, parent)| parent).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::EffectiveRecipe;
    use crate::logsource::LogSource;
    use crate::schema::Schema;
    use crate::template::{Template, TemplateShape, TemplateStats};

    fn set(paths: &[&str]) -> BTreeSet<FieldPath> {
        paths.iter().map(|p| FieldPath::from(*p)).collect()
    }

    #[test]
    fn the_objects_above_removed_fields_come_deepest_first_and_never_a_removed_one() {
        let removed = set(&["a.b.c", "a.x", "d.e", "d", "f"]);
        let parents: Vec<String> = parents(&removed).iter().map(ToString::to_string).collect();
        assert_eq!(
            parents,
            ["a.b", "a"],
            "d is removed itself; f has no parent"
        );
    }

    #[test]
    fn a_plan_may_remove_its_fields_its_empty_fields_but_those_kept_and_its_implied_values() {
        use crate::recipe::{ImpliedValue, Literal};
        let fields = set(&[
            "agent.id",
            "host.name",
            "host.os.name",
            "Keep.me",
            "Message",
        ]);
        let template = Template {
            id: "t".into(),
            source: "s".into(),
            logsource: LogSource::default(),
            schema: Schema::Sigma,
            pattern: String::new(),
            shape: TemplateShape::Keyset {
                discriminators: Vec::new(),
                paths: fields.clone(),
                variants: vec![fields.clone()],
            },
            fields,
            text_fields: BTreeSet::new(),
            stats: TemplateStats::default(),
        };
        let recipe = EffectiveRecipe {
            drop_fields: set(&["Message"]),
            drop_empty_except: Some(set(&["Keep", "host.os"])),
            drop_implied: vec![ImpliedValue {
                field: "x.y".into(),
                value: Literal::Integer(1),
                when: None,
            }],
            ..EffectiveRecipe::passthrough("t".into())
        };
        let plan = Plan {
            template: &template,
            recipe: &recipe,
        };
        assert_eq!(
            plan.removable_fields(),
            set(&["Message", "agent.id", "host.name", "x.y"])
        );
        let objects: Vec<String> = plan
            .emptiable_objects()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(objects, ["agent", "host", "x"]);
    }
}

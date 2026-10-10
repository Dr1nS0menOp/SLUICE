use std::collections::BTreeSet;

use sluice_core::field::FieldPath;
use sluice_core::template::{LineHeader, TemplateStats};

use super::*;

fn keyset(id: &str, product: &str, service: &str, event_id: &str) -> Template {
    Template {
        id: id.into(),
        source: "s".into(),
        logsource: LogSource {
            product: Some(product.into()),
            service: Some(service.into()),
            category: None,
            complete: false,
        },
        pattern: format!("EventID={event_id}"),
        shape: TemplateShape::Keyset {
            discriminators: vec![("EventID".into(), event_id.into())],
            paths: BTreeSet::new(),
        },
        fields: BTreeSet::new(),
        text_fields: BTreeSet::new(),
        stats: TemplateStats::default(),
    }
}

fn text(id: &str, pattern: &str) -> Template {
    Template {
        shape: TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::Syslog,
            tokens: vec![],
        },
        pattern: pattern.into(),
        ..keyset(id, "linux", "auth", "")
    }
}

const SOURCE_WIDE: &str = "id: a\ndescription: d\nmatch:\n  logsource: { product: windows, service: security }\nreductions:\n  - op: drop_fields\n    fields: [Message]\nrationale: r\n";
const SPECIFIC: &str = "id: b\ndescription: d\nmatch:\n  logsource: { product: windows, service: security }\n  discriminators: { EventID: \"5156\" }\nreductions:\n  - op: drop_fields\n    fields: [Noise]\n  - op: forward_matching\n    summary_keys: [Application]\nrationale: r\n";

#[test]
fn embedded_recipes_are_valid() {
    let book = RecipeBook::embedded().unwrap();
    assert!(book.len() >= 10);
    assert!(
        book.entries()
            .all(|(id, description)| !id.is_empty() && !description.is_empty())
    );
}

#[test]
fn source_wide_and_specific_recipes_merge() {
    let book = RecipeBook::parse([("a.yaml", SOURCE_WIDE), ("b.yaml", SPECIFIC)]).unwrap();
    let wfp = keyset("wfp", "windows", "security", "5156");
    let logon = keyset("logon", "windows", "security", "4624");
    let resolution = book.resolve(&[wfp, logon]);

    let merged = &resolution.recipes[&TemplateId::new("wfp")];
    assert_eq!(
        merged.reductions()[0],
        Reduction::DropFields {
            fields: BTreeSet::from([FieldPath::from("Message"), FieldPath::from("Noise")]),
        }
    );
    assert!(matches!(
        merged.reductions()[1],
        Reduction::ForwardMatching { .. }
    ));
    assert_eq!(
        merged.provenance(),
        &Provenance::Community {
            recipe: "a + b".into()
        }
    );
    assert_eq!(
        resolution.recipes[&TemplateId::new("logon")]
            .reductions()
            .len(),
        1
    );
}

#[test]
fn recipes_never_match_unknown_logsource_attributes() {
    let book = RecipeBook::parse([("a.yaml", SOURCE_WIDE)]).unwrap();
    let mut unknown = keyset("x", "windows", "security", "4624");
    unknown.logsource.service = None;
    assert!(book.resolve(&[unknown]).recipes.is_empty());
}

#[test]
fn text_recipes_match_on_pattern() {
    let yaml = "id: c\ndescription: d\nmatch:\n  logsource: { product: linux, service: auth }\n  pattern: \"CRON\"\nreductions:\n  - op: summarize\n    summary_keys: [host.name]\nrationale: r\n";
    let book = RecipeBook::parse([("c.yaml", yaml)]).unwrap();
    let resolution = book.resolve(&[
        text("cron", "CRON pam_unix ..."),
        text("sshd", "sshd Accepted ..."),
    ]);
    assert_eq!(resolution.recipes.len(), 1);
    assert!(resolution.recipes.contains_key(&TemplateId::new("cron")));
}

#[test]
fn two_specific_recipes_conflict_and_neither_applies() {
    let other = SPECIFIC.replace("id: b", "id: b2");
    let book = RecipeBook::parse([("b.yaml", SPECIFIC), ("b2.yaml", other.as_str())]).unwrap();
    let resolution = book.resolve(&[keyset("wfp", "windows", "security", "5156")]);
    assert!(resolution.recipes.is_empty());
    assert_eq!(resolution.conflicts.len(), 1);
}

#[test]
fn source_wide_recipes_may_not_route() {
    let routing = SOURCE_WIDE.replace(
        "  - op: drop_fields\n    fields: [Message]\n",
        "  - op: summarize\n    summary_keys: [x]\n",
    );
    assert!(RecipeBook::parse([("a.yaml", routing.as_str())]).is_err());
}

#[test]
fn unknown_fields_and_duplicate_ids_are_rejected() {
    let typo = SOURCE_WIDE.replace("rationale:", "rationalle:");
    assert!(RecipeBook::parse([("a.yaml", typo.as_str())]).is_err());
    assert!(RecipeBook::parse([("a.yaml", SOURCE_WIDE), ("a2.yaml", SOURCE_WIDE)]).is_err());
}

#[test]
fn the_published_schema_matches_the_parser() {
    let published = include_str!("../../../../recipes/recipe.schema.json");
    assert_eq!(
        RecipeBook::json_schema(),
        published,
        "recipes/recipe.schema.json is stale: run `sluice recipes schema > recipes/recipe.schema.json`"
    );
}

#[test]
fn an_operator_recipe_replaces_the_built_in_one_with_its_id() {
    let built_in = RecipeBook::embedded().unwrap();
    let (path, yaml) = RecipeBook::embedded_files()[0];
    let edited = yaml.replace("description:", "description: edited");
    let book = RecipeBook::embedded_with([(path, edited.as_str())]).unwrap();
    assert_eq!(book.len(), built_in.len());
    assert_eq!(
        book.entries()
            .filter(|(_, d)| d.starts_with("edited"))
            .count(),
        1
    );
}

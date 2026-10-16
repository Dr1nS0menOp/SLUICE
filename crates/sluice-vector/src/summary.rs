//! The VRL that turns a summarized event into a summary record (ADR 0020).
//!
//! A recipe names its summary keys as the event arrives (`Application`, `DestPort`). A shape can
//! move them: Sentinel's `WindowsEvent` keeps a provider's data under the `EventData` object, and
//! `SecurityEvent` keeps data without a column of its own only in its `EventData` XML. Each key is
//! therefore read where the template's records keep it, so a summary is keyed as the recipe
//! meant, instead of collapsing into one count with empty keys.

use sluice_core::field::FieldPath;
use sluice_core::guard::Route;
use sluice_core::ids::SourceId;
use sluice_core::template::Template;

use crate::program::{Plan, TEMPLATE_METADATA};
use crate::syntax;

/// The object that holds a provider's data in Sentinel's Windows shapes.
const EVENT_DATA: &str = "EventData";

/// Rewrites a summarized event into a summary record keyed by its template's summary keys.
pub(crate) fn summary_program(source: &SourceId, plans: &[Plan<'_>]) -> String {
    let mut lines = vec!["_sluice_keys = {}".to_owned()];
    for plan in plans.iter().filter(|p| &p.template.source == source) {
        let Route::ForwardMatching { summary_keys, .. } = &plan.recipe.route else {
            continue;
        };
        let keys: Vec<String> = summary_keys
            .iter()
            .map(|k| {
                format!(
                    "{}: {}",
                    syntax::string(k.as_str()),
                    key_value(plan.template, k)
                )
            })
            .collect();
        lines.push(format!(
            "if %sluice.{TEMPLATE_METADATA} == {} {{ _sluice_keys = {{ {} }} }}",
            syntax::string(plan.template.id.as_str()),
            keys.join(", ")
        ));
    }
    lines.push(format!(
        "_sluice_template = string(%sluice.{TEMPLATE_METADATA}) ?? \"\"\n\
         . = {{ \"sluice_summary\": true, \"sluice_source\": {}, \"sluice_template\": _sluice_template, \
         \"sluice_keys\": _sluice_keys, \"sluice_count\": 1 }}\n\
         .sluice_group = _sluice_template + \"|\" + encode_json(_sluice_keys)",
        syntax::string(source.as_str())
    ));
    let mut program = lines.join("\n");
    program.push('\n');
    program
}

/// The VRL expression for summary key `key` on an event of `template`: the field itself if the
/// template has it, else the same name in the `EventData` object, else the `<Data Name="key">`
/// item of the `EventData` XML. A key found nowhere is the field itself (null when absent).
fn key_value(template: &Template, key: &FieldPath) -> String {
    if template.fields.contains(key) {
        return syntax::path(key);
    }
    let nested = FieldPath::new(format!("{EVENT_DATA}.{key}"));
    if template.fields.contains(&nested) {
        return syntax::path(&nested);
    }
    let simple = key
        .as_str()
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if simple && template.fields.contains(EVENT_DATA) {
        // XML entities stay escaped (`&amp;`): a key, not a value to show.
        return format!(
            "parse_regex(string(.{EVENT_DATA}) ?? \"\", r'<Data Name=\"{key}\">(?P<value>[^<]*)</Data>').value ?? null"
        );
    }
    syntax::path(key)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{Value, json};
    use sluice_core::guard::EffectiveRecipe;
    use sluice_core::predicate::Predicate;
    use sluice_core::template::{TemplateShape, TemplateStats};

    use super::*;
    use crate::runtime::CompiledProgram;

    fn template(fields: &[&str]) -> Template {
        let paths: BTreeSet<FieldPath> = fields.iter().map(|f| FieldPath::from(*f)).collect();
        Template {
            id: "sec:5156:x".into(),
            source: "sec".into(),
            logsource: sluice_core::logsource::LogSource::default(),
            schema: sluice_core::schema::Schema::Sigma,
            pattern: "EventID=5156".into(),
            shape: TemplateShape::Keyset {
                discriminators: vec![("EventID".into(), "5156".into())],
                variants: vec![paths.clone()],
                paths: paths.clone(),
            },
            fields: paths,
            text_fields: BTreeSet::new(),
            stats: TemplateStats::default(),
        }
    }

    /// The summary keys this program writes for `event` of `template`.
    fn keys(template: &Template, event: &Value) -> Value {
        let recipe = EffectiveRecipe {
            route: Route::ForwardMatching {
                prefilter: Predicate::never(),
                summary_keys: vec!["Application".into(), "DestPort".into()],
            },
            ..EffectiveRecipe::passthrough(template.id.clone())
        };
        let plan = Plan {
            template,
            recipe: &recipe,
        };
        // The classifier sets the metadata in Vector; here it comes from the event, untyped as
        // Vector sees it.
        let source = format!(
            "%sluice.{TEMPLATE_METADATA} = .sluice_test_template\n{}",
            summary_program(&"sec".into(), &[plan])
        );
        let program = CompiledProgram::compile("summary", source).expect("compiles cleanly");
        let mut fields = event.as_object().expect("an object").clone();
        fields.insert("sluice_test_template".into(), json!(template.id.as_str()));
        let (body, _) = program.run(&fields).expect("runs");
        let body: Value = serde_json::to_value(&body).expect("json");
        body["sluice_keys"].clone()
    }

    #[test]
    fn keys_are_read_from_the_field_itself() {
        let t = template(&["EventID", "Application", "DestPort"]);
        let keys = keys(
            &t,
            &json!({"EventID": 5156, "Application": "a.exe", "DestPort": "53"}),
        );
        assert_eq!(keys, json!({"Application": "a.exe", "DestPort": "53"}));
    }

    #[test]
    fn keys_are_read_from_the_event_data_object() {
        let t = template(&["EventID", "EventData.Application", "EventData.DestPort"]);
        let event =
            json!({"EventID": 5156, "EventData": {"Application": "a.exe", "DestPort": "53"}});
        assert_eq!(
            keys(&t, &event),
            json!({"Application": "a.exe", "DestPort": "53"})
        );
    }

    #[test]
    fn keys_are_read_from_the_event_data_xml() {
        let t = template(&["EventID", "EventData"]);
        let xml = "<EventData xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
                   <Data Name=\"Application\">\\device\\a.exe</Data><Data Name=\"DestPort\">53</Data></EventData>";
        let keys = keys(&t, &json!({"EventID": 5156, "EventData": xml}));
        assert_eq!(
            keys,
            json!({"Application": "\\device\\a.exe", "DestPort": "53"})
        );
    }

    #[test]
    fn a_key_found_nowhere_is_null() {
        let t = template(&["EventID", "EventData"]);
        let keys = keys(
            &t,
            &json!({"EventID": 5156, "EventData": "<EventData></EventData>"}),
        );
        assert_eq!(keys, json!({"Application": null, "DestPort": null}));
    }

    #[test]
    fn only_plain_names_are_looked_up_in_the_xml() {
        let with_xml = template(&["EventID", "EventData"]);
        let regex = |key: &str| key_value(&with_xml, &FieldPath::new(key)).contains("parse_regex");
        assert!(
            regex("Logon_Type2"),
            "letters, digits and `_` are a plain name"
        );
        for key in ["Bad'Key", "a-b", "a.b", "a b"] {
            assert!(!regex(key), "{key} never reaches the pattern");
        }
        let without_xml = template(&["EventID"]);
        assert_eq!(
            key_value(&without_xml, &FieldPath::new("Logon_Type")),
            syntax::path(&FieldPath::new("Logon_Type"))
        );
    }
}

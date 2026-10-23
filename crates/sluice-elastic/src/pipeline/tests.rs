use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::{Map, Value, json};
use sluice_core::event::{Event, Timestamp};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Route};
use sluice_core::ids::{EventId, SourceId};
use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::reduce::{Outcome, Reducer};
use sluice_core::template::{LineHeader, Template, TemplateShape, TemplateStats};

use super::*;

const ENV: &str = "SLUICE_ELASTIC_URL";

fn paths(names: &[&str]) -> BTreeSet<FieldPath> {
    names.iter().map(|n| FieldPath::from(*n)).collect()
}

fn template(id: &str, discriminators: &[(&str, &str)], variants: &[&[&str]]) -> Template {
    let variants: Vec<BTreeSet<FieldPath>> = variants.iter().map(|v| paths(v)).collect();
    let all: BTreeSet<FieldPath> = variants.iter().flatten().cloned().collect();
    Template {
        id: id.into(),
        source: "windows".into(),
        logsource: sluice_core::logsource::LogSource::default(),
        schema: sluice_core::schema::Schema::default(),
        pattern: String::new(),
        shape: TemplateShape::Keyset {
            discriminators: discriminators
                .iter()
                .map(|(f, v)| (FieldPath::from(*f), (*v).to_owned()))
                .collect(),
            paths: all.clone(),
            variants,
        },
        fields: all,
        text_fields: BTreeSet::new(),
        stats: TemplateStats::default(),
    }
}

fn removing(id: &str, fields: &[&str], keep: Option<Predicate>) -> EffectiveRecipe {
    EffectiveRecipe {
        drop_fields: paths(fields),
        keep_whole_when: keep,
        ..EffectiveRecipe::passthrough(id.into())
    }
}

fn eq(field: &str, value: &str) -> Predicate {
    Predicate::Field(FieldTest {
        field: field.into(),
        op: MatchOp::Equals,
        values: vec![value.into()],
        case_sensitive: false,
    })
}

fn of(plans: &[(&Template, &EffectiveRecipe)]) -> IngestPipeline {
    let plans: Vec<Plan<'_>> = plans
        .iter()
        .map(|(template, recipe)| Plan { template, recipe })
        .collect();
    ingest_pipeline("test", &plans)
}

fn script(pipeline: &IngestPipeline) -> &str {
    pipeline.body["processors"][0]["script"]["source"]
        .as_str()
        .expect("a script")
}

fn logon() -> Template {
    template(
        "windows:4624:a",
        &[("EventID", "4624")],
        &[
            &["EventID", "Message", "User", "Host.name"],
            &["EventID", "Message", "User", "Host.name", "Ip"],
        ],
    )
}

#[test]
fn a_plan_that_removes_nothing_has_no_processors() {
    let t = logon();
    let unchanged = of(&[(&t, &EffectiveRecipe::passthrough(t.id.clone()))]);
    assert_eq!(unchanged.body["processors"], json!([]));
    assert!(unchanged.templates.is_empty() && unchanged.fields.is_empty());
    assert_eq!(of(&[]).body["processors"], json!([]));
}

#[test]
fn a_removal_is_one_script_that_decides_before_it_removes() {
    let t = logon();
    let recipe = removing(t.id.as_str(), &["Message"], Some(eq("User", "Admin")));
    let out = of(&[(&t, &recipe)]);
    assert_eq!(out.templates, [t.id.clone()].into());
    assert_eq!(out.fields, paths(&["Message"]));
    let processor = &out.body["processors"][0]["script"];
    assert_eq!(processor["ignore_failure"], true);
    let script = script(&out);
    let classify = script.find("t = 0").expect("classifies");
    let keep = script
        .find("if (!(sluiceKeep0(ctx)))")
        .expect("tests keep-whole");
    assert!(script.contains("boolean sluiceKeep0(Map ctx) {\n  return sluiceTest("));
    let remove = script
        .find("sluiceRemove(ctx, ['Message'])")
        .expect("removes");
    assert!(classify < keep && keep < remove, "{script}");
    assert!(
        script.contains("keys.equals(new HashSet(['EventID', 'Host.name', 'Message', 'User']))")
    );
    assert!(script.contains("sluiceDisc(sluiceGet(ctx, ['EventID'])) == '4624'"));
}

/// Takes the documents with an IP of [`logon`] first: its id sorts before.
fn overlapping() -> Template {
    template(
        "windows:1:a",
        &[],
        &[&["EventID", "Message", "User", "Host.name", "Ip"]],
    )
}

#[test]
fn c1_a_template_that_changes_nothing_still_claims_what_vector_gives_it() {
    let counted = overlapping();
    let removed = logon();
    let unrelated = template("windows:0:a", &[], &[&["Other"]]);
    let counting = EffectiveRecipe {
        route: Route::ForwardMatching {
            prefilter: eq("User", "x"),
            summary_keys: vec!["User".into()],
        },
        ..removing(counted.id.as_str(), &["User"], None)
    };
    let recipe = removing(removed.id.as_str(), &["Message"], None);
    let out = of(&[
        (&removed, &recipe),
        (&counted, &counting),
        (
            &unrelated,
            &EffectiveRecipe::passthrough(unrelated.id.clone()),
        ),
    ]);
    let script = script(&out);
    assert!(
        script.contains("t = 1"),
        "both overlapping templates classify: {script}"
    );
    assert!(
        !script.contains("t = 2"),
        "the unrelated one is not needed: {script}"
    );
    assert!(
        script.contains("if (t == 1)") && !script.contains("if (t == 0)"),
        "{script}"
    );
    assert!(
        out.left_out.iter().any(|r| r.contains("counting")),
        "{:?}",
        out.left_out
    );
    assert_eq!(out.templates, [removed.id.clone()].into());
}

#[test]
fn c1_text_templates_and_metadata_names_are_left_to_a_pipeline_tool() {
    let text = Template {
        shape: TemplateShape::Text {
            field: "message".into(),
            header: LineHeader::None,
            tokens: vec!["x".into()],
        },
        ..template("linux:a", &[], &[&["message"]])
    };
    let meta = template("windows:meta", &[], &[&["_id", "User"]]);
    let out = of(&[
        (&text, &removing(text.id.as_str(), &["message"], None)),
        (&meta, &removing(meta.id.as_str(), &["User"], None)),
    ]);
    assert_eq!(out.body["processors"], json!([]));
    assert_eq!(out.left_out.len(), 2, "{:?}", out.left_out);
}

/// A template whose discriminator is a float Painless cannot render (`0.5`), and a later one of
/// the same key set that removes `Status`.
fn undecided_then_later() -> [(Template, EffectiveRecipe); 2] {
    let undecided = template(
        "windows:0:b",
        &[("EventID", "0.5")],
        &[&["EventID", "Status"]],
    );
    let later = template("windows:0:c", &[], &[&["EventID", "Status"]]);
    let unchanged = EffectiveRecipe::passthrough(undecided.id.clone());
    let recipe = removing(later.id.as_str(), &["Status"], None);
    [(undecided, unchanged), (later, recipe)]
}

#[test]
fn c1_a_record_an_earlier_template_cannot_decide_is_claimed_by_no_later_one() {
    let [(undecided, unchanged), (later, recipe)] = undecided_then_later();
    let out = of(&[(&undecided, &unchanged), (&later, &recipe)]);
    let text = script(&out);
    let claim = text
        .find("{ t = 0; }")
        .expect("the undecided template claims");
    let stop = text
        .find(
            "else if (keys.equals(new HashSet(['EventID', 'Status'])) && \
             sluiceMay(sluiceGet(ctx, ['EventID']), '0.5')) { t = -2; }",
        )
        .expect("the search stops where Painless cannot decide");
    let taken = text
        .find("{ t = 1; }")
        .expect("the later template takes the rest");
    assert!(claim < stop && stop < taken, "{text}");

    // A field named like metadata hides from the script's keys: such a template stops the search
    // wherever its records may be.
    let meta = template("windows:0:a", &[], &[&["_id", "EventID", "Status"]]);
    let unchanged = EffectiveRecipe::passthrough(meta.id.clone());
    let out = of(&[(&meta, &unchanged), (&later, &recipe)]);
    let text = script(&out);
    let stop = text
        .find("if (keys.equals(new HashSet(['EventID', 'Status']))) { t = -2; }")
        .expect("the metadata template stops the search");
    let taken = text
        .find("{ t = 1; }")
        .expect("the later template comes after");
    assert!(stop < taken, "{text}");
    assert!(out.left_out.iter().any(|r| r.contains("metadata")));

    // Values Painless renders as VRL does need no stop.
    let t = logon();
    let plain = of(&[(&t, &removing(t.id.as_str(), &["Message"], None))]);
    assert!(!script(&plain).contains("t = -2"));
}

#[test]
fn templates_share_the_functions_of_their_keep_whole_alternatives() {
    let a = logon();
    let b = template(
        "windows:4634:a",
        &[("EventID", "4634")],
        &[&["EventID", "Message", "User"]],
    );
    let both = Predicate::Any(vec![eq("User", "Admin"), eq("User", "root")]);
    let one = eq("User", "root");
    let out = of(&[
        (&a, &removing(a.id.as_str(), &["Message"], Some(both))),
        (&b, &removing(b.id.as_str(), &["Message"], Some(one))),
    ]);
    let script = script(&out);
    assert_eq!(script.matches("boolean sluiceKeep").count(), 2, "{script}");
    assert!(script.contains("if (!(sluiceKeep0(ctx) || sluiceKeep1(ctx)))"));
    assert!(script.contains("if (!(sluiceKeep1(ctx)))"));
}

#[test]
fn empty_fields_are_removed_except_those_kept() {
    let t = logon();
    let recipe = EffectiveRecipe {
        drop_empty_except: Some(paths(&["User"])),
        ..EffectiveRecipe::passthrough(t.id.clone())
    };
    let out = of(&[(&t, &recipe)]);
    let script = script(&out);
    assert!(script.contains("sluiceRemoveEmptyExcept(ctx, keys, ['User'], [])"));
    assert!(out.empty_fields && out.fields.is_empty());
    assert_eq!(out.templates, [t.id.clone()].into());
}

#[test]
fn a_script_too_large_to_compile_removes_nothing() {
    let templates: Vec<Template> = (0..400)
        .map(|n| {
            template(
                &format!("windows:{n}:a"),
                &[("EventID", &n.to_string())],
                &[&["EventID", "Message", "User", "Host.name", "Ip", "Port"]],
            )
        })
        .collect();
    let recipes: Vec<EffectiveRecipe> = templates
        .iter()
        .map(|t| {
            removing(
                t.id.as_str(),
                &["Message"],
                Some(eq("User", "Administrator")),
            )
        })
        .collect();
    let plans: Vec<(&Template, &EffectiveRecipe)> = templates.iter().zip(&recipes).collect();
    let out = of(&plans);
    assert_eq!(out.body["processors"], json!([]));
    assert!(
        out.left_out
            .iter()
            .any(|r| r.contains(&MAX_SCRIPT.to_string()))
    );
}

fn event(fields: &Value) -> Event {
    Event {
        id: EventId(0),
        timestamp: Timestamp(0),
        source: SourceId::new("windows"),
        fields: fields.as_object().expect("an object").clone(),
    }
}

/// What Vector's VRL forwards of each event, for the same templates and recipes.
fn vrl(plans: &[(&Template, &EffectiveRecipe)], events: &[Event]) -> Vec<Map<String, Value>> {
    let reducer = sluice_vector::compile_reducer(
        plans
            .iter()
            .map(|(template, recipe)| sluice_vector::Plan { template, recipe }),
    )
    .expect("VRL compiles");
    events
        .iter()
        .map(|e| match reducer.reduce(e).expect("VRL runs").outcome {
            Outcome::Forwarded(body) => body,
            Outcome::Summarized => panic!("nothing is counted here"),
        })
        .collect()
}

/// In a real Elasticsearch (`SLUICE_ELASTIC_URL`, `scripts/elastic-check.sh`): every document
/// leaves the pipeline exactly as it leaves Vector's VRL, across the edges of recognition.
#[test]
fn c1_in_elasticsearch_documents_lose_exactly_what_they_lose_in_vector() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let t = logon();
    let other = template(
        "windows:4634:a",
        &[("EventID", "4634")],
        &[&["EventID", "User"]],
    );
    let recipe = EffectiveRecipe {
        drop_empty_except: Some(paths(&["User"])),
        ..removing(t.id.as_str(), &["Message"], Some(eq("User", "Admin")))
    };
    let other_recipe = removing(other.id.as_str(), &["User"], None);
    let claiming = overlapping();
    let unchanged = EffectiveRecipe::passthrough(claiming.id.clone());
    let plans = [
        (&t, &recipe),
        (&other, &other_recipe),
        (&claiming, &unchanged),
    ];
    let base = json!({"EventID": 4624, "Message": "An account logged on", "User": "bob",
                      "Host": {"name": "ws1"}});
    let with = |change: &dyn Fn(&mut Value)| {
        let mut fields = base.clone();
        change(&mut fields);
        event(&fields)
    };
    let events = [
        with(&|_| {}),
        with(&|f| f["Ip"] = json!("10.0.0.1")),
        with(&|f| f["Extra"] = json!(1)),
        with(&|f| f["User"] = json!("ADMIN")),
        with(&|f| f["User"] = json!("admİn")),
        with(&|f| f["EventID"] = json!("4624")),
        with(&|f| f["EventID"] = json!(4624.0)),
        with(&|f| f["EventID"] = json!(4625)),
        with(&|f| f["Host"] = json!({"name": "", "os": {}})),
        with(&|f| f["Host"] = json!({"name": null})),
        with(&|f| f["Host"] = json!("flat")),
        with(&|f| f["User"] = json!(["a", "b"])),
        with(&|f| f["Message"] = json!({"nested": "x"})),
        with(&|f| {
            f.as_object_mut().expect("an object").remove("User");
        }),
        event(&json!({"EventID": 4634, "User": "carol"})),
        event(&json!({"EventID": 4634, "User": "carol", "Message": "x"})),
        event(&json!({"EventID": "4634", "User": null})),
    ];
    let expected = vrl(&plans, &events);
    let out = of(&plans);
    let documents: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
    let actual = crate::simulate(&url, &out.body, &documents)
        .unwrap_or_else(|e| panic!("{e}\n{}", script(&out)));
    // Case folding of non-ASCII text widens to keeping the document whole.
    let widened = 4;
    for (n, ((event, vector), elastic)) in events.iter().zip(&expected).zip(&actual).enumerate() {
        let shown = Value::Object(event.fields.clone());
        if n == widened {
            assert_eq!(elastic, &event.fields, "kept whole: {shown}");
            assert_ne!(vector, &event.fields, "Vector removes: {shown}");
        } else {
            assert_eq!(elastic, vector, "event {shown}");
        }
    }
    assert!(
        expected.iter().zip(&events).any(|(v, e)| v != &e.fields),
        "some event loses fields, or the test shows nothing"
    );
}

/// In a real Elasticsearch: a document whose discriminator Painless cannot render as VRL does
/// stays whole, never handed to a later template of the same key set.
#[test]
fn c1_in_elasticsearch_a_document_an_earlier_template_cannot_decide_stays_whole() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let [(undecided, unchanged), (later, recipe)] = undecided_then_later();
    let plans = [(&undecided, &unchanged), (&later, &recipe)];
    let events = [
        event(&json!({"EventID": 0.5, "Status": "ok"})),
        event(&json!({"EventID": 0.25, "Status": "ok"})),
        event(&json!({"EventID": 7, "Status": "ok"})),
    ];
    let expected = vrl(&plans, &events);
    let out = of(&plans);
    let documents: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
    let actual = crate::simulate(&url, &out.body, &documents)
        .unwrap_or_else(|e| panic!("{e}\n{}", script(&out)));
    // Kept whole, where Vector removes `Status`.
    let widened = 1;
    for (n, ((event, vector), elastic)) in events.iter().zip(&expected).zip(&actual).enumerate() {
        let shown = Value::Object(event.fields.clone());
        if n == widened {
            assert_eq!(elastic, &event.fields, "kept whole: {shown}");
            assert_ne!(vector, &event.fields, "Vector removes: {shown}");
        } else {
            assert_eq!(elastic, vector, "event {shown}");
        }
    }
}

/// Installed as a real pipeline and indexed through, documents are stored as `_simulate` showed.
#[test]
fn c1_an_installed_pipeline_stores_what_the_simulation_showed() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let t = logon();
    let recipe = removing(t.id.as_str(), &["Message"], Some(eq("User", "Admin")));
    let out = of(&[(&t, &recipe)]);
    let base = json!({"EventID": 4624, "Message": "x", "User": "bob", "Host": {"name": "ws1"}});
    let mut admin = base.clone();
    admin["User"] = json!("admin");
    let mut drifted = base.clone();
    drifted["New"] = json!(true);
    let documents = [base, admin, drifted];
    let sources: Vec<&Map<String, Value>> = documents
        .iter()
        .map(|d| d.as_object().expect("an object"))
        .collect();
    let simulated = crate::simulate(&url, &out.body, &sources).expect("simulates");

    let client = sluice_http::Client::new(std::time::Duration::from_secs(60));
    let call = |method: &str, path: &str, body: Option<String>| -> Value {
        let content = if method == "POST" {
            "application/x-ndjson"
        } else {
            "application/json"
        };
        let answer = client
            .send(
                method,
                &format!("{url}/{path}"),
                &[("content-type", content.to_owned())],
                body.as_deref(),
            )
            .expect("Elasticsearch answers");
        serde_json::from_str(&answer.body).unwrap_or(Value::String(answer.body))
    };
    let index = "sluice-test-installed";
    call("DELETE", index, None);
    let put = call(
        "PUT",
        "_ingest/pipeline/sluice-test",
        Some(out.body.to_string()),
    );
    assert_eq!(put["acknowledged"], true, "{put}");
    let mut bulk = String::new();
    for (n, d) in documents.iter().enumerate() {
        writeln!(bulk, "{{\"index\":{{\"_id\":\"{n}\"}}}}\n{d}").expect("writes to a string");
    }
    let indexed = call(
        "POST",
        &format!("{index}/_bulk?pipeline=sluice-test&refresh=true"),
        Some(bulk),
    );
    assert_eq!(indexed["errors"], false, "{indexed}");
    for (n, expected) in simulated.iter().enumerate() {
        let stored = call("GET", &format!("{index}/_doc/{n}"), None);
        assert_eq!(&stored["_source"], &Value::Object(expected.clone()), "{n}");
    }
    assert!(
        !simulated[0].contains_key("Message"),
        "the template's document lost it"
    );
    assert!(simulated[1].contains_key("Message"), "kept whole");
    assert!(
        simulated[2].contains_key("Message"),
        "drift is not recognised"
    );
    call("DELETE", index, None);
    call("DELETE", "_ingest/pipeline/sluice-test", None);
}

/// A script Elasticsearch refuses is an error, not a pipeline that passes everything.
#[test]
fn a_script_that_does_not_compile_is_refused() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let broken =
        json!({"processors": [{"script": {"source": "ctx.x = ;", "ignore_failure": true}}]});
    let doc = Map::new();
    assert!(matches!(
        crate::simulate(&url, &broken, &[&doc]),
        Err(crate::ElasticError::Rejected { .. } | crate::ElasticError::Failed { .. })
    ));
}

fn implied_recipe(id: &str) -> EffectiveRecipe {
    use sluice_core::recipe::{ImpliedValue, Literal};
    let text = |s: &str| Literal::Text(s.into());
    EffectiveRecipe {
        drop_implied: vec![
            ImpliedValue {
                field: "Keywords".into(),
                value: text("0x80"),
                when: None,
            },
            ImpliedValue {
                field: "Level".into(),
                value: Literal::Integer(0),
                when: None,
            },
            ImpliedValue {
                field: "Mode".into(),
                value: text("-"),
                when: Some(("LogonType".into(), Literal::Integer(3))),
            },
        ],
        ..EffectiveRecipe::passthrough(id.into())
    }
}

fn implied_template() -> Template {
    template(
        "windows:4624:i",
        &[("EventID", "4624")],
        &[&["EventID", "Keywords", "Level", "LogonType", "Mode"]],
    )
}

#[test]
fn an_implied_value_is_removed_only_while_it_holds_and_its_type_matches() {
    let t = implied_template();
    let recipe = implied_recipe(t.id.as_str());
    let out = of(&[(&t, &recipe)]);
    let source = script(&out);
    assert!(source.contains("sluiceGet(ctx, ['Keywords']) instanceof String"));
    assert!(source.contains("sluiceIsInt(sluiceGet(ctx, ['Level']), 0L)"));
    assert!(source.contains("sluiceIsInt(sluiceGet(ctx, ['LogonType']), 3L)"));
    assert_eq!(out.fields, paths(&["Keywords", "Level", "Mode"]));
}

/// In a real Elasticsearch: implied values leave exactly as in Vector, whatever their type.
#[test]
fn c1_in_elasticsearch_implied_values_leave_exactly_as_in_vector() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let t = implied_template();
    let recipe = implied_recipe(t.id.as_str());
    let plans = [(&t, &recipe)];
    let base = json!({"EventID": 4624, "Keywords": "0x80", "Level": 0, "LogonType": 3,
                      "Mode": "-"});
    let with = |change: &dyn Fn(&mut Value)| {
        let mut fields = base.clone();
        change(&mut fields);
        event(&fields)
    };
    let events = [
        with(&|_| {}),
        with(&|f| f["Keywords"] = json!("0x10")),
        with(&|f| f["Level"] = json!(0.0)),
        with(&|f| f["Level"] = json!("0")),
        with(&|f| f["LogonType"] = json!(10)),
        with(&|f| f["LogonType"] = json!("3")),
        with(&|f| f["Mode"] = json!("Yes")),
    ];
    let expected = vrl(&plans, &events);
    let out = of(&plans);
    let documents: Vec<&Map<String, Value>> = events.iter().map(|e| &e.fields).collect();
    let actual = crate::simulate(&url, &out.body, &documents)
        .unwrap_or_else(|e| panic!("{e}\n{}", script(&out)));
    for ((event, vector), elastic) in events.iter().zip(&expected).zip(&actual) {
        assert_eq!(
            elastic,
            vector,
            "event {}",
            Value::Object(event.fields.clone())
        );
    }
    assert_ne!(
        expected[0], events[0].fields,
        "the first event loses its implied values"
    );
}

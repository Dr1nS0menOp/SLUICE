use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{Map, Value, json};
use sluice_core::field::FieldPath;
use sluice_core::guard::{EffectiveRecipe, Plan};
use sluice_core::recipe::{ImpliedValue, Literal};
use sluice_core::template::{Template, TemplateShape, TemplateStats};

use super::*;
use crate::pipeline::ingest_pipeline;

const ENV: &str = "SLUICE_ELASTIC_URL";

fn template(id: &str, event_id: &str, fields: &[&str]) -> Template {
    let variant: BTreeSet<FieldPath> = fields.iter().map(|f| FieldPath::from(*f)).collect();
    Template {
        id: id.into(),
        source: "windows".into(),
        logsource: sluice_core::logsource::LogSource::default(),
        schema: sluice_core::schema::Schema::default(),
        pattern: String::new(),
        shape: TemplateShape::Keyset {
            discriminators: vec![("EventID".into(), event_id.to_owned())],
            paths: variant.clone(),
            variants: vec![variant.clone()],
        },
        fields: variant,
        text_fields: BTreeSet::new(),
        stats: TemplateStats::default(),
    }
}

fn logon() -> Template {
    template(
        "windows:4624:i",
        "4624",
        &[
            "EventID",
            "Keywords",
            "Level",
            "LogonType",
            "Message",
            "Mode",
        ],
    )
}

fn failure() -> Template {
    template("windows:4625:j", "4625", &["EventID", "LogonType"])
}

fn recipe() -> EffectiveRecipe {
    let text = |s: &str| Literal::Text(s.into());
    EffectiveRecipe {
        drop_fields: ["Message".into()].into(),
        drop_empty_except: Some(BTreeSet::new()),
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
        ..EffectiveRecipe::passthrough("windows:4624:i".into())
    }
}

fn built() -> (IngestPipeline, Rebuild) {
    let (logon, failure) = (logon(), failure());
    let (recipe, passthrough) = (recipe(), EffectiveRecipe::passthrough(failure.id.clone()));
    let plans = [
        Plan {
            template: &logon,
            recipe: &recipe,
        },
        Plan {
            template: &failure,
            recipe: &passthrough,
        },
    ];
    let pipeline = ingest_pipeline("test", &plans);
    let rebuild = rebuild(&plans, &pipeline);
    (pipeline, rebuild)
}

#[test]
fn each_runtime_field_has_the_type_of_its_implied_values() {
    let (_, rebuild) = built();
    assert_eq!(
        rebuild.fields().collect::<Vec<_>>(),
        ["Keywords", "Level", "Mode"]
    );
    assert!(rebuild.left_out.is_empty(), "{:?}", rebuild.left_out);
    let mappings = rebuild.runtime_mappings();
    assert_eq!(mappings["Mode"]["type"], "keyword");
    assert_eq!(mappings["Level"]["type"], "long");
    let source = mappings["Mode"]["script"]["source"]
        .as_str()
        .expect("a script");
    assert!(source.contains("sluiceDisc(sluiceGet(ctx, ['EventID'])) == '4624'"));
    assert!(source.contains("sluiceIsInt(sluiceGet(ctx, ['LogonType']), 3L)"));
    assert!(source.ends_with("for (def v : sluiceValues(params['_source'])) { emit(v); }\n"));
    let level = mappings["Level"]["script"]["source"]
        .as_str()
        .expect("a script");
    assert!(level.contains("{ out.add(0L); }"), "{level}");
}

#[test]
fn a_field_whose_implied_values_differ_in_type_is_left_out_with_why() {
    let logon = logon();
    let mut mixed = recipe();
    mixed.drop_implied.push(ImpliedValue {
        field: "Mode".into(),
        value: Literal::Integer(1),
        when: Some(("LogonType".into(), Literal::Integer(10))),
    });
    let plans = [Plan {
        template: &logon,
        recipe: &mixed,
    }];
    let rebuild = rebuild(&plans, &ingest_pipeline("test", &plans));
    assert!(!rebuild.fields().any(|f| f == "Mode"));
    assert!(
        rebuild
            .left_out
            .iter()
            .any(|r| r.contains("`Mode`: its implied values are of more than one type")),
        "{:?}",
        rebuild.left_out
    );
}
#[test]
fn the_pipeline_keeps_an_empty_field_that_may_go_as_implied_so_its_absence_has_one_meaning() {
    let (pipeline, rebuild) = built();
    let source = pipeline.body["processors"][0]["script"]["source"]
        .as_str()
        .expect("a script");
    assert!(
        source.contains("sluiceRemoveEmptyExcept(ctx, keys, ['Keywords', 'Level', 'Mode'], "),
        "{source}"
    );
    assert_eq!(
        rebuild.fields().collect::<Vec<_>>(),
        ["Keywords", "Level", "Mode"]
    );
}

#[test]
fn a_field_some_events_of_the_kind_lack_is_not_put_back() {
    let (logon, recipe) = (logon(), recipe());
    // The same kind of event without `Mode`.
    let other = template(
        "windows:4624:k",
        "4624",
        &["EventID", "Keywords", "Level", "LogonType"],
    );
    let passthrough = EffectiveRecipe::passthrough(other.id.clone());
    let plans = [
        Plan {
            template: &logon,
            recipe: &recipe,
        },
        Plan {
            template: &other,
            recipe: &passthrough,
        },
    ];
    let rebuild = rebuild(&plans, &ingest_pipeline("test", &plans));
    assert_eq!(rebuild.fields().collect::<Vec<_>>(), ["Keywords", "Level"]);
    assert!(
        rebuild
            .left_out
            .iter()
            .any(|r| r.contains("`Mode` is missing from some events of the same kind"))
    );
}

#[test]
fn retain_leaves_a_field_out_and_says_why() {
    let (_, mut rebuild) = built();
    rebuild.retain(|field| field != "Mode", "read differently on the sample");
    assert_eq!(rebuild.fields().collect::<Vec<_>>(), ["Keywords", "Level"]);
    assert!(
        rebuild
            .left_out
            .contains(&"`Mode`: read differently on the sample".to_owned())
    );
}

fn documents() -> Vec<Map<String, Value>> {
    let base = json!({"EventID": 4624, "Keywords": "0x80", "Level": 0, "LogonType": 3,
                      "Message": "An account was logged on.", "Mode": "-"});
    let with = |change: &dyn Fn(&mut Value)| {
        let mut fields = base.clone();
        change(&mut fields);
        let Value::Object(map) = fields else {
            unreachable!("an object")
        };
        map
    };
    vec![
        with(&|_| {}),
        with(&|f| f["Keywords"] = json!("0x10")),
        with(&|f| f["LogonType"] = json!(10)),
        with(&|f| f["Mode"] = json!(["-", "x"])),
        with(&|f| f["Keywords"] = json!(null)),
        with(&|f| f["Keywords"] = json!("")),
        // Not this kind of event: nothing to put back.
        json!({"EventID": 4625, "LogonType": 3})
            .as_object()
            .cloned()
            .expect("an object"),
        // This kind's ID, but a key set the pipeline does not recognise.
        with(&|f| {
            f.as_object_mut().expect("an object").remove("Keywords");
            f["Extra"] = json!(1);
        }),
    ]
}

/// In a real Elasticsearch: the runtime fields read the documents the pipeline sends exactly as
/// they read the documents it was given.
#[test]
fn c1_in_elasticsearch_runtime_fields_read_forwarded_documents_as_the_full_ones() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let (pipeline, rebuild) = built();
    let full = documents();
    let refs: Vec<&Map<String, Value>> = full.iter().collect();
    let sent = crate::simulate(&url, &pipeline.body, &refs).expect("the pipeline runs");
    assert!(!sent[0].contains_key("Keywords"), "the pipeline removes it");
    let sent_refs: Vec<&Map<String, Value>> = sent.iter().collect();
    let read_full = rebuilt(&url, &rebuild, &refs).expect("the functions run");
    let read_sent = rebuilt(&url, &rebuild, &sent_refs).expect("the functions run");
    assert_eq!(read_sent, read_full);
    assert_eq!(read_full[0]["Mode"], json!(["-"]));
    assert_eq!(read_full[6]["Mode"], json!([]), "4625 has no Mode");
    assert_eq!(
        sent[5]["Keywords"],
        json!(""),
        "an empty implied field stays"
    );
}

/// In a real Elasticsearch: indexed, the forwarded documents searched with the runtime fields
/// show the values the full documents hold.
#[test]
fn c1_in_elasticsearch_a_search_with_the_runtime_fields_shows_the_values_back() {
    let Ok(url) = std::env::var(ENV) else {
        return;
    };
    let url = url.trim_end_matches('/');
    let (pipeline, rebuild) = built();
    let full = documents();
    let refs: Vec<&Map<String, Value>> = full.iter().collect();
    let sent = crate::simulate(url, &pipeline.body, &refs).expect("the pipeline runs");
    let client = sluice_http::Client::with(Duration::from_secs(60), false, 64 * 1024 * 1024);
    let call = |method: &str, path: &str, body: Option<String>| {
        let answer = client
            .send(
                method,
                &format!("{url}/{path}"),
                &[("content-type", "application/x-ndjson".to_owned())],
                body.as_deref(),
            )
            .expect("Elasticsearch answers");
        assert!(answer.is_success(), "{method} {path}: {}", answer.body);
        serde_json::from_str::<Value>(&answer.body).expect("JSON")
    };
    let index = "sluice-rebuild-test";
    let _ = client.send("DELETE", &format!("{url}/{index}"), &[], None);
    // Mapped as Elasticsearch maps them by itself, so each runtime field shadows a field the
    // documents that kept it have.
    call("PUT", index, None);
    let mut bulk = String::new();
    for (n, document) in sent.iter().enumerate() {
        bulk.push_str(&json!({"index": {"_id": n.to_string()}}).to_string());
        bulk.push('\n');
        bulk.push_str(&Value::Object(document.clone()).to_string());
        bulk.push('\n');
    }
    let indexed = call("POST", &format!("{index}/_bulk?refresh=true"), Some(bulk));
    assert_eq!(indexed["errors"], json!(false), "{indexed}");
    let fields: Vec<&str> = rebuild.fields().collect();
    let search = json!({
        "size": 100,
        "runtime_mappings": rebuild.runtime_mappings(),
        "fields": fields,
        "_source": false,
        "sort": [{"_doc": "asc"}],
    });
    let found = call(
        "POST",
        &format!("{index}/_search"),
        Some(search.to_string()),
    );
    let _ = client.send("DELETE", &format!("{url}/{index}"), &[], None);
    let expected = rebuilt(url, &rebuild, &refs).expect("the functions run");
    let hits = found["hits"]["hits"].as_array().expect("hits");
    assert_eq!(hits.len(), full.len());
    for hit in hits {
        let n: usize = hit["_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .expect("an id");
        for field in &fields {
            let shown = hit["fields"].get(*field).cloned().unwrap_or(json!([]));
            assert_eq!(
                shown, expected[n][*field],
                "document {n}, field {field}: {hit}"
            );
        }
    }
}

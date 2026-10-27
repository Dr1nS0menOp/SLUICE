use std::path::PathBuf;

use serde_json::json;

use super::*;

/// A plan with two sources: one with three kinds of event (one saving nothing), one empty.
fn plan() -> Value {
    let template = |id: &str, bytes_in: u64, bytes_out: u64| {
        json!({"id": id, "pattern": format!("pattern {id}"), "runs_in": ["pipeline"],
            "volume": {"bytes_in": bytes_in, "bytes_out": bytes_out}})
    };
    json!({
        "format": "sluice.plan/1",
        "proof": {"holds": true},
        "total": {"bytes_in": 1000, "bytes_out": 250},
        "saved_by_mode": {"rules": 700, "implied": 50},
        "problems": [
            {"kind": "unreadable", "message": "a.yaml"},
            {"kind": "unreadable", "message": "b.yaml"},
            {"kind": "recipe", "message": "r"},
        ],
        "sources": [
            {"id": "win", "logsource": {}, "schema": "sigma", "templates": [
                template("small", 100, 90),
                template("big", 600, 100),
                template("same", 300, 300),
                template("tie", 110, 100),
            ]},
            {"id": "empty", "templates": []},
        ],
    })
}

fn advice(files: Vec<(String, u64)>) -> Advice {
    Advice {
        dir: PathBuf::from("/nowhere"),
        plan: plan(),
        files,
    }
}

#[test]
fn percentages_have_one_decimal_and_an_empty_whole_is_none() {
    assert!((percent(1, 3) - 33.3).abs() < 1e-9);
    assert!((percent(2, 3) - 66.7).abs() < 1e-9);
    assert!((percent(750, 1000) - 75.0).abs() < 1e-9);
    assert!((percent(5, 0)).abs() < 1e-9);
}

#[test]
fn the_summary_counts_problems_by_kind_and_ranks_the_largest_savings() {
    let summary = summary(&advice(Vec::new()), None);
    assert_eq!(summary["saved_percent"], json!(75.0));
    assert_eq!(summary["problems"], json!({"unreadable": 2, "recipe": 1}));
    assert_eq!(summary["proof"], json!({"holds": true}));
    assert!(summary["proving"].is_null());
    let win = &summary["sources"][0];
    assert_eq!(win["kinds_of_event"], 4);
    assert_eq!(win["bytes_in"], 1110);
    assert_eq!(win["bytes_out"], 590);
    assert_eq!(win["saved_percent"], json!(46.8));
    let ranked: Vec<(&str, u64)> = win["largest_savings"]
        .as_array()
        .expect("savings")
        .iter()
        .map(|s| {
            (
                s["template"].as_str().expect("id"),
                s["saved_bytes"].as_u64().expect("bytes"),
            )
        })
        .collect();
    // Largest first, a tie by id, and a kind of event that saves nothing is left out.
    assert_eq!(ranked, [("big", 500), ("small", 10), ("tie", 10)]);
    assert_eq!(summary["sources"][1]["saved_percent"], json!(0.0));
}

#[test]
fn at_most_five_savings_are_named_per_source() {
    let templates: Vec<Value> = (0..7)
        .map(|i| json!({"id": format!("t{i}"), "volume": {"bytes_in": 100 + i, "bytes_out": 0}}))
        .collect();
    let summary = source_summary(&json!({"id": "s", "templates": templates}));
    assert_eq!(
        summary["largest_savings"].as_array().map(Vec::len),
        Some(LARGEST)
    );
    assert_eq!(summary["largest_savings"][0]["template"], "t6");
}

#[test]
fn a_source_or_one_of_its_kinds_of_event_is_given_by_id() {
    let plan = plan();
    assert_eq!(
        source_plan(&plan, "win", None).expect("a source")["id"],
        "win"
    );
    assert_eq!(
        source_plan(&plan, "win", Some("big")).expect("a template")["id"],
        "big"
    );
    let missing = source_plan(&plan, "nope", None).expect_err("no source");
    assert!(missing.contains("win, empty"), "{missing}");
    assert!(source_plan(&plan, "win", Some("nope")).is_err());
}

#[test]
fn problems_are_filtered_by_kind_with_their_advice() {
    let plan = plan();
    let all = problems(&plan, None);
    assert_eq!(all["problems"].as_array().map(Vec::len), Some(3));
    let unreadable = problems(&plan, Some("unreadable"));
    assert_eq!(unreadable["problems"].as_array().map(Vec::len), Some(2));
    let advice = unreadable["advice"].as_object().expect("advice");
    assert_eq!(advice.keys().collect::<Vec<_>>(), ["unreadable"]);
    assert_eq!(
        advice["unreadable"],
        sluice_autopilot::problem_advice("unreadable").expect("advice")
    );
}

#[test]
fn read_file_gives_only_listed_files_up_to_a_megabyte() {
    let dir = std::env::temp_dir().join(format!("sluice-mcp-read-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    std::fs::write(dir.join("vector.yaml"), "sources: {}\n").expect("written");
    let advice = Advice {
        dir: dir.clone(),
        plan: plan(),
        files: vec![
            ("vector.yaml".to_owned(), 12),
            ("big.json".to_owned(), MAX_READ + 1),
            ("exactly.json".to_owned(), MAX_READ),
        ],
    };
    assert_eq!(
        read_file(&advice, "vector.yaml").expect("read")["text"],
        "sources: {}\n"
    );
    let big = read_file(&advice, "big.json").expect_err("too big");
    assert!(big.contains("more than"), "{big}");
    // At the limit it is read (and here not found, which is another error).
    let exactly = read_file(&advice, "exactly.json").expect_err("not on disk");
    assert!(exactly.starts_with("reading"), "{exactly}");
    assert!(read_file(&advice, "../vector.yaml").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_transformation_a_rule_would_refuse_is_refused_before_the_emulator() {
    assert_eq!(
        refusals("source | project-away Message"),
        Vec::<String>::new()
    );
    assert_eq!(refusals("  source"), Vec::<String>::new());
    let long = format!("source{}", " ".repeat(sluice_kql::MAX_TRANSFORM_KQL - 6));
    assert_eq!(
        refusals(&long),
        Vec::<String>::new(),
        "exactly the limit is accepted"
    );
    let refused = refusals(&format!("{long} "));
    assert_eq!(refused.len(), 1);
    assert!(refused[0].contains("characters"), "{refused:?}");
    assert_eq!(refusals("print 1"), ["does not start with `source`"]);
}

#[test]
fn records_are_counted_as_their_json() {
    let event = |fields: Value| Event {
        id: sluice_core::ids::EventId(0),
        timestamp: sluice_core::event::Timestamp(0),
        source: sluice_core::ids::SourceId::new("s"),
        fields: fields.as_object().expect("an object").clone(),
    };
    assert_eq!(records_bytes(&[]), 0);
    assert_eq!(
        records_bytes(&[event(json!({"a": 1})), event(json!({}))]),
        7 + 2
    );
}

#[test]
fn arguments_are_strings_or_absent() {
    let arguments = json!({"source": "win", "none": null, "number": 3});
    let arguments = arguments.as_object().expect("an object");
    assert_eq!(text(arguments, "source"), Ok("win"));
    assert_eq!(optional(arguments, "none"), Ok(None));
    assert_eq!(optional(arguments, "absent"), Ok(None));
    assert!(text(arguments, "absent").is_err());
    assert!(optional(arguments, "number").is_err());
}

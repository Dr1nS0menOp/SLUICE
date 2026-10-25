use sluice_core::field::FieldPath;
use sluice_core::guard::{Adjustment, ContractRule, Reason};
use sluice_core::ids::{Engine, RuleId};
use sluice_core::problem::ProblemKind;
use sluice_core::schema::Schema;

use super::*;

const HOSTILE: &str = "\"><script>alert(1)</script><img src=x onerror='x'>&amp;";

pub(super) fn report() -> Report {
    Report {
        total: Volume {
            events: 10,
            forwarded: 10,
            summarized: 0,
            summaries: 0,
            bytes_in: 1_000,
            bytes_out: 400,
        },
        alerts_full: 3,
        alerts_forwarded: 3,
        proven: true,
        rules: vec![("Sigma".into(), 1)],
        templates: Vec::new(),
        coverage_gaps: Vec::new(),
        problems: Vec::new(),
        scope_hints: Vec::new(),
        spot_check: None,
        rules_basis: RulesBasis::NotKnown,
        rule_rows: Vec::new(),
        inventory_notes: Vec::new(),
        modes: Mode::ALL.into(),
        examples: Vec::new(),
    }
}

fn hostile() -> Report {
    Report {
        rules: vec![(HOSTILE.into(), 1)],
        templates: vec![TemplateRow {
            id: HOSTILE.into(),
            source: HOSTILE.into(),
            pattern: HOSTILE.repeat(5),
            volume: Volume::default(),
            actions: vec![HOSTILE.into()],
            adjustments: vec![HOSTILE.into()],
            provenance: Some(HOSTILE.into()),
            runs_in: Some(HOSTILE.into()),
            removed: vec![RemovedField {
                path: HOSTILE.into(),
                events: 1,
                bytes: 1,
                mode: Mode::Implied,
                constant: None,
                why: HOSTILE.into(),
                runs_in: HOSTILE.into(),
            }],
            rationale: Some(HOSTILE.into()),
        }],
        coverage_gaps: vec![HOSTILE.into()],
        problems: vec![
            Problem::new(ProblemKind::ReadBroadly, None, HOSTILE),
            Problem::new(
                ProblemKind::UnknownFunction {
                    engine: Engine::Sentinel,
                    name: HOSTILE.into(),
                },
                Some(RuleId::new(HOSTILE)),
                HOSTILE,
            ),
        ],
        scope_hints: vec![HOSTILE.into()],
        rule_rows: vec![RuleRow {
            set: HOSTILE.into(),
            rule: HOSTILE.into(),
            name: Some(HOSTILE.into()),
            status: RuleStatus::NotRead,
            detail: HOSTILE.into(),
        }],
        inventory_notes: vec![HOSTILE.into()],
        ..report()
    }
}

#[test]
fn text_from_logs_and_rules_cannot_add_markup_to_the_page() {
    let page = render_html(&hostile());
    for injected in ["<script", "<img", "onerror='"] {
        assert!(!page.contains(injected), "{injected} reached the page");
    }
    assert!(page.contains("&lt;script&gt;"));
}

#[test]
fn a_pattern_cut_for_the_table_is_cut_before_escaping() {
    // 90 characters of a pattern full of `&` must not end in half an entity.
    let mut report = hostile();
    report.templates[0].pattern = "&".repeat(200);
    let page = render_html(&report);
    let shown = format!(">{}</code>", "&amp;".repeat(90));
    assert!(page.contains(&shown));
}

#[test]
fn a_proof_that_fails_is_shown_as_failing() {
    let page = render_html(&Report {
        proven: false,
        alerts_forwarded: 2,
        ..report()
    });
    assert!(page.contains("✗ 3 ≠ 2"));
    assert!(!page.contains('✓'));
}

#[test]
fn an_empty_proof_says_so_and_a_non_empty_one_does_not() {
    let empty = Report {
        alerts_full: 0,
        alerts_forwarded: 0,
        ..report()
    };
    assert_eq!(empty.proof_note(), Some(EMPTY_PROOF));
    assert!(render_html(&empty).contains(EMPTY_PROOF));
    assert_eq!(report().proof_note(), None);
    assert!(!render_html(&report()).contains(EMPTY_PROOF));
}

#[test]
fn problems_appear_only_when_there_are_some() {
    assert!(!render_html(&report()).contains("<h2>Problems</h2>"));
    let with = Report {
        problems: vec![Problem::new(
            ProblemKind::Unreadable,
            None,
            "bad.yml: unreadable",
        )],
        ..report()
    };
    assert!(render_html(&with).contains("bad.yml: unreadable"));
}

#[test]
fn a_function_without_its_source_is_listed_once_with_its_rules_and_how_to_give_it() {
    let call = |rule: &str| {
        Problem::new(
            ProblemKind::UnknownFunction {
                engine: Engine::Sentinel,
                name: "my_parser".into(),
            },
            Some(RuleId::new(rule)),
            format!("{rule}: uses `my_parser`"),
        )
    };
    let page = render_html(&Report {
        problems: vec![call("sentinel:a"), call("sentinel:b")],
        ..report()
    });
    assert!(
        page.contains(
            "<li><code>my_parser</code>: called by 2 rules (<code>sentinel:a</code>, \
             <code>sentinel:b</code>)</li>"
        ),
        "{page}"
    );
    assert!(page.contains("sluice rules fetch sentinel"));
    assert!(page.contains("FunctionName: my_parser\nFunctionQuery: |"));
}

#[test]
fn saved_percent_is_bounded_and_defined_for_empty_samples() {
    assert!((report().saved_percent() - 60.0).abs() < 1e-9);
    let grown = Report {
        total: Volume {
            bytes_in: 100,
            bytes_out: 150,
            ..Volume::default()
        },
        ..report()
    };
    assert!(grown.saved_percent().abs() < f64::EPSILON, "never negative");
    let empty = Report {
        total: Volume::default(),
        ..report()
    };
    assert!(empty.saved_percent().abs() < f64::EPSILON);
    assert!((percent(1, 3) - 100.0 / 3.0).abs() < 1e-9);
}

#[test]
fn every_adjustment_names_its_contract_rule() {
    let rule = || RuleId::new("r");
    let reasons = [
        Reason::NoRecipe,
        Reason::NoArchive,
        Reason::RareTemplate {
            events: 1,
            source_events: 100,
        },
        Reason::AllFieldsNeededByRule { rule: rule() },
        Reason::FieldNeededByRule {
            field: FieldPath::new("f"),
            rule: rule(),
        },
        Reason::KeptWhereRuleMayMatch {
            field: Some(FieldPath::new("f")),
            rule: rule(),
        },
        Reason::KeptWhereRuleMayMatch {
            field: None,
            rule: rule(),
        },
        Reason::ProtectionTooBroad { tests: 300 },
        Reason::FieldNamesDiffer {
            rule: rule(),
            rules: 1,
            rule_names: Schema::Sigma,
            data_names: Schema::Ecs,
        },
        Reason::FieldNamesDiffer {
            rule: rule(),
            rules: 4,
            rule_names: Schema::Sigma,
            data_names: Schema::Undeclared,
        },
        Reason::FieldsParsedFromText {
            rule: rule(),
            rules: 1,
        },
        Reason::FieldsParsedFromText {
            rule: rule(),
            rules: 2,
        },
        Reason::RulesNotComplete,
        Reason::UnboundedRule { rule: rule() },
        Reason::SemanticOnCoveredTemplate,
        Reason::StatelessRulesChanged,
        Reason::DetectionChanged {
            missing: 1,
            extra: 0,
        },
    ];
    let mut seen = std::collections::BTreeSet::new();
    for reason in reasons {
        let said = text::adjustment(&Adjustment {
            contract: ContractRule::RareNeverCut,
            level: None,
            reason,
        });
        assert!(said.ends_with("(contract rule 4)"), "{said}");
        assert!(
            seen.insert(said.clone()),
            "two reasons read the same: {said}"
        );
    }
}

#[test]
fn a_log_source_without_attributes_reads_as_any() {
    assert_eq!(text::logsource(&LogSource::default()), "(any)");
    let windows = LogSource {
        product: Some("windows".into()),
        category: Some("process_creation".into()),
        ..LogSource::default()
    };
    assert_eq!(
        text::logsource(&windows),
        "product=windows, category=process_creation"
    );
}

#[test]
fn coverage_gaps_are_sorted_and_name_rules_no_template_can_reach() {
    let rule = |id: &str, product: &str| RuleRequirements {
        logsource: LogSource {
            product: Some(product.into()),
            ..LogSource::default()
        },
        ..RuleRequirements::opaque(RuleId::new(id))
    };
    let rules = [rule("z", "macos"), rule("a", "aix"), rule("w", "windows")];
    let template: Template = serde_json::from_value(serde_json::json!({
        "id": "t", "source": "s", "logsource": {"product": "windows"}, "pattern": "p",
        "shape": {"kind": "keyset", "discriminators": [], "paths": ["a"], "variants": [["a"]]},
        "fields": ["a"], "text_fields": [],
        "stats": {"events": 1, "bytes": 1, "source_events": 1}
    }))
    .unwrap();
    let gaps = coverage_gaps(
        &rules.iter().collect::<Vec<_>>(),
        std::slice::from_ref(&template),
    );
    assert_eq!(gaps.len(), 2);
    assert!(
        gaps[0].starts_with("a:") && gaps[1].starts_with("z:"),
        "{gaps:?}"
    );

    // A rule with a requirement per naming convention (a Sigma pipeline copy) counts once, and
    // sees data when one of its requirements does.
    let copies = [rule("r", "windows"), rule("r", "macos")];
    assert_eq!(count(&copies), 1);
    assert_eq!(
        coverage_gaps(&copies.iter().collect::<Vec<_>>(), &[template]),
        Vec::<String>::new()
    );
}

#[test]
fn equal_adjustments_are_listed_once_in_their_order() {
    let texts = ["rare", "kept", "rare", "proven"].map(String::from);
    assert_eq!(unique(texts.into_iter()), ["rare", "kept", "proven"]);
}

#[test]
fn a_scope_hint_counts_its_rules_in_words() {
    assert_eq!(rules_apply(1), "1 rule applies");
    assert_eq!(rules_apply(4), "4 rules apply");
}

#[test]
fn each_removed_field_says_why_it_may_go_and_where() {
    use sluice_core::guard::EffectiveRecipe;
    use sluice_core::recipe::{ImpliedValue, Literal};

    let implied = |field: &str, value: &str, when: Option<(&str, i64)>| ImpliedValue {
        field: FieldPath::new(field),
        value: Literal::Text(value.into()),
        when: when.map(|(on, v)| (FieldPath::new(on), Literal::Integer(v))),
    };
    let recipe = EffectiveRecipe {
        drop_fields: [FieldPath::new("Message")].into(),
        drop_empty_except: Some(std::collections::BTreeSet::new()),
        drop_implied: vec![
            implied("Keywords", "0x8020000000000000", None),
            implied("RestrictedAdminMode", "-", Some(("LogonType", 2))),
            implied("RestrictedAdminMode", "-", Some(("LogonType", 3))),
        ],
        ..EffectiveRecipe::passthrough("t".into())
    };
    let why = |field: &str| text::why_removed(&FieldPath::new(field), &recipe);
    assert!(why("Message").starts_with("the recipe removes it"));
    assert_eq!(
        why("Keywords"),
        "always \"0x8020000000000000\" on this kind of event; left out only when it is \
         \"0x8020000000000000\", and put back as \"0x8020000000000000\""
    );
    assert_eq!(
        why("RestrictedAdminMode"),
        "fixed by another field: \"-\" whenever LogonType is 2 or 3; left out only in those \
         cases, and put back as that value"
    );
    assert!(why("WorkstationName").starts_with("it was empty"));

    let place = |field: &str| text::where_removed(&FieldPath::new(field), &recipe, true);
    assert_eq!(
        place("Keywords"),
        "Vector, the SIEM's own ingestion, or the agent"
    );
    assert_eq!(
        place("RestrictedAdminMode"),
        "Vector or the SIEM's own ingestion (an agent cannot tell 3 from 3.0)"
    );
    assert_eq!(
        place("Message"),
        "Vector, the SIEM's own ingestion, or the agent"
    );
    assert_eq!(
        text::where_removed(&FieldPath::new("Message"), &recipe, false),
        "Vector (a pipeline tool)"
    );
}

#[test]
fn a_field_paired_with_another_is_described_by_one_pair() {
    use sluice_core::guard::EffectiveRecipe;
    use sluice_core::recipe::{ImpliedValue, Literal};

    let pair = |sid: &str, name: &str| ImpliedValue {
        field: FieldPath::new("TargetUserSid"),
        value: Literal::Text(sid.into()),
        when: Some((FieldPath::new("TargetUserName"), Literal::Text(name.into()))),
    };
    let recipe = EffectiveRecipe {
        drop_implied: vec![
            pair("S-1", "alice"),
            pair("S-2", "bob"),
            pair("S-3", "carol"),
            pair("S-4", "dave"),
        ],
        ..EffectiveRecipe::passthrough("t".into())
    };
    assert_eq!(
        text::why_removed(&FieldPath::new("TargetUserSid"), &recipe),
        "fixed per value of TargetUserName: the sample has 4 pairs, such as TargetUserName = \
         \"alice\" with TargetUserSid = \"S-1\"; left out only when an event matches its pair, \
         and put back from that pair"
    );
}

pub(super) fn row_removing(fields: &[(&str, u64, Mode)]) -> TemplateRow {
    TemplateRow {
        id: "t".into(),
        source: "s".into(),
        pattern: "p".into(),
        volume: Volume::default(),
        actions: Vec::new(),
        adjustments: Vec::new(),
        provenance: None,
        runs_in: None,
        removed: fields
            .iter()
            .map(|(path, bytes, mode)| RemovedField {
                path: (*path).into(),
                events: 1,
                bytes: *bytes,
                mode: *mode,
                constant: None,
                why: String::new(),
                runs_in: String::new(),
            })
            .collect(),
        rationale: None,
    }
}

#[test]
fn each_mode_is_credited_with_what_it_saved_and_together_they_make_the_whole() {
    // 600 of 1,000 bytes saved: 150 by implied values, the rest by the recipes.
    let report = Report {
        templates: vec![row_removing(&[
            ("Message", 400, Mode::Rules),
            ("Keywords", 100, Mode::Implied),
            ("Channel", 50, Mode::Implied),
        ])],
        ..report()
    };
    assert_eq!(report.saved_by(Mode::Implied), 150);
    assert_eq!(report.saved_by(Mode::Rules), 450);
    assert!((report.saved_percent_by(Mode::Rules) - 45.0).abs() < 1e-9);
    assert_eq!(
        report.saved_by(Mode::Rules) + report.saved_by(Mode::Implied),
        600
    );
}

#[test]
fn the_report_shows_every_mode_and_how_to_ask_for_one_not_run() {
    let page = render_html(&Report {
        modes: [Mode::Rules].into(),
        ..report()
    });
    assert!(page.contains("<code>rules</code>"));
    assert!(page.contains("<code>implied</code><span class=\"muted\">not run"));
}

fn windows_template(complete: bool) -> Template {
    serde_json::from_value(serde_json::json!({
        "id": "t", "source": "s", "logsource": {"product": "windows", "complete": complete},
        "pattern": "p",
        "shape": {"kind": "keyset", "discriminators": [], "paths": ["a"], "variants": [["a"]]},
        "fields": ["a"], "text_fields": [],
        "stats": {"events": 1, "bytes": 1, "source_events": 1}
    }))
    .expect("a template")
}

fn rule_for(id: &str, service: Option<&str>) -> RuleRequirements {
    RuleRequirements {
        logsource: LogSource {
            product: Some("windows".into()),
            service: service.map(Into::into),
            ..LogSource::default()
        },
        ..RuleRequirements::opaque(RuleId::new(id))
    }
}

#[test]
fn a_source_hears_which_rules_apply_only_because_its_log_source_is_not_fully_described() {
    let security = rule_for("a", Some("security"));
    let system = rule_for("b", Some("system"));
    let any = rule_for("c", None);
    let open = [windows_template(false)];
    assert_eq!(
        scope_hints(&[&security, &any], &open),
        [
            "s: 1 rule applies only because its log source (product=windows) leaves an attribute \
          unknown; if that is all it is, add `complete: true`"
        ]
    );
    assert!(scope_hints(&[&security, &system], &open)[0].starts_with("s: 2 rules apply only"));
    assert_eq!(scope_hints(&[&any], &open), Vec::<String>::new());
    let closed = [windows_template(true)];
    assert_eq!(scope_hints(&[&security], &closed), Vec::<String>::new());
}

#[test]
fn a_rule_with_several_requirements_counts_once() {
    let rules = [
        rule_for("a", None),
        rule_for("a", Some("x")),
        rule_for("b", None),
    ];
    assert_eq!(count(&rules), 2);
    assert_eq!(count(&[]), 0);
}

#[test]
fn only_a_key_set_template_that_forwards_everything_shares_its_saving_with_the_siem() {
    let template = windows_template(false);
    let removing = EffectiveRecipe {
        drop_fields: ["a".into()].into(),
        ..EffectiveRecipe::passthrough("t".into())
    };
    assert!(shared(&template, &removing));
    assert!(!shared(
        &template,
        &EffectiveRecipe::passthrough("t".into())
    ));
    let counting = EffectiveRecipe {
        route: sluice_core::guard::Route::ForwardMatching {
            prefilter: sluice_core::predicate::Predicate::Always,
            summary_keys: Vec::new(),
        },
        ..removing
    };
    assert!(
        !shared(&template, &counting),
        "counting needs a pipeline tool"
    );
}

#[test]
fn a_removed_field_says_its_mode_and_the_value_it_always_held() {
    use sluice_core::recipe::{ImpliedValue, Literal};
    let recipe = EffectiveRecipe {
        drop_fields: ["Message".into()].into(),
        drop_implied: vec![
            ImpliedValue {
                field: "Channel".into(),
                value: Literal::Text("Security".into()),
                when: None,
            },
            ImpliedValue {
                field: "Mode".into(),
                value: Literal::Text("-".into()),
                when: Some(("LogonType".into(), Literal::Integer(3))),
            },
            // Listed and implied: the recipe's removal is what takes it.
            ImpliedValue {
                field: "Message".into(),
                value: Literal::Text("x".into()),
                when: None,
            },
        ],
        ..EffectiveRecipe::passthrough("t".into())
    };
    let removal = Removal {
        events: 2,
        bytes: 40,
    };
    let field = |path: &str, shared: bool| removed_field(&path.into(), removal, &recipe, shared);
    let channel = field("Channel", true);
    assert_eq!(
        (channel.mode, channel.constant.as_deref()),
        (Mode::Implied, Some("\"Security\""))
    );
    assert_eq!((channel.events, channel.bytes), (2, 40));
    assert_eq!(
        channel.runs_in,
        "Vector, the SIEM's own ingestion, or the agent"
    );
    let mode = field("Mode", false);
    assert_eq!((mode.mode, mode.constant), (Mode::Implied, None));
    assert_eq!(mode.runs_in, "Vector (a pipeline tool)");
    let message = field("Message", true);
    assert_eq!((message.mode, message.constant), (Mode::Rules, None));
}

#[test]
fn a_proposal_s_reasoning_is_shown_only_when_it_says_something_and_fields_go_by_it() {
    use sluice_core::recipe::{Provenance, Recipe, Reduction};
    let proposal = |why: &str| {
        Recipe::new(
            "t".into(),
            vec![Reduction::DropFields {
                fields: ["a".into()].into(),
            }],
            Provenance::Operator,
            why.to_owned(),
        )
        .expect("a valid recipe")
    };
    let removing = EffectiveRecipe {
        drop_fields: ["a".into()].into(),
        ..EffectiveRecipe::passthrough("t".into())
    };
    assert_eq!(
        rationale(Some(&proposal("  it repeats the event  ")), &removing).as_deref(),
        Some("it repeats the event")
    );
    assert_eq!(rationale(Some(&proposal("   ")), &removing), None);
    assert_eq!(
        rationale(
            Some(&proposal("it repeats")),
            &EffectiveRecipe::passthrough("t".into())
        ),
        None,
        "the guardrails kept every field"
    );
    assert_eq!(rationale(None, &removing), None);
}

#[test]
fn the_rules_verdict_is_that_of_the_report_s_rules() {
    let report = report();
    let verdict = report.rules_verdict();
    assert_ne!(verdict, "");
    assert_eq!(verdict, rules::verdict(&report.rule_rows));
}

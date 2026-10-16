use sluice_core::field::FieldPath;
use sluice_core::guard::{Adjustment, ContractRule, Reason};
use sluice_core::ids::RuleId;
use sluice_core::schema::Schema;

use super::*;

const HOSTILE: &str = "\"><script>alert(1)</script><img src=x onerror='x'>&amp;";

fn report() -> Report {
    Report {
        total: Volume {
            events: 10,
            forwarded: 10,
            summarized: 0,
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
        }],
        coverage_gaps: vec![HOSTILE.into()],
        problems: vec![HOSTILE.into()],
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
        problems: vec!["bad.yml: unreadable".into()],
        ..report()
    };
    assert!(render_html(&with).contains("bad.yml: unreadable"));
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
    let gaps = coverage_gaps(&rules.iter().collect::<Vec<_>>(), &[template]);
    assert_eq!(gaps.len(), 2);
    assert!(
        gaps[0].starts_with("a:") && gaps[1].starts_with("z:"),
        "{gaps:?}"
    );
}

use sluice_core::predicate::{FieldTest, MatchOp, Predicate};
use sluice_core::rules::{RequiredFields, RuleRequirements};

use super::SentinelRules;

fn rule(query: &str) -> RuleRequirements {
    let yaml = format!("id: r1\nname: test\nquery: |\n{}\n", indent(query));
    let rules = SentinelRules::parse([("r1.yaml", yaml.as_str())]);
    assert_eq!(rules.requirements().len(), 1);
    rules.requirements()[0].clone()
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Records of any shape Sluice sends to a Sentinel table.
fn shaped_records() -> Predicate {
    Predicate::any([
        super::extract::present("EventID"),
        super::extract::present("Channel"),
        super::extract::present("SyslogMessage"),
        super::extract::present("DeviceVendor"),
        super::extract::present("EventSchemaVersion"),
        super::extract::present("DnsQuery"),
        super::extract::present("Url"),
    ])
}

fn event_ids(ids: &[&str]) -> Predicate {
    Predicate::Field(FieldTest {
        field: "EventID".into(),
        op: MatchOp::Equals,
        values: ids.iter().map(|i| (*i).to_owned()).collect(),
        case_sensitive: true,
    })
}

#[test]
fn a_filter_on_event_ids_bounds_the_rule() {
    let r = rule(
        "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where EventID == 4662 and \
         EventData has \"replication\"\n| extend Target = tostring(EventData)\n| project Target",
    );
    assert_eq!(r.rule.as_str(), "sentinel:r1");
    assert_eq!(r.prefilter, event_ids(&["4662"]));
    assert_eq!(r.logsource.product.as_deref(), Some("windows"));
    assert_eq!(r.logsource.service.as_deref(), Some("security"));
    let RequiredFields::Known(fields) = &r.fields else {
        panic!("known fields")
    };
    assert!(fields.contains("EventData") && fields.contains("EventID"));
    assert!(!r.stateful);
}

#[test]
fn in_lists_and_alternatives_are_kept_and_everything_else_widens() {
    let r = rule("SecurityEvent | where EventID in (4624, 4625) or (EventID == 4648)");
    assert_eq!(
        r.prefilter,
        Predicate::any([event_ids(&["4624", "4625"]), event_ids(&["4648"])])
    );
    for widening in [
        "SecurityEvent | where EventID != 4624",
        "SecurityEvent | where EventID == 4624 or Account has 'x'",
        "SecurityEvent | where not(EventID == 4624)",
        "SecurityEvent | where EventID in (events)",
        "SecurityEvent | extend EventID = 1 | where EventID == 4624",
        "let base = SecurityEvent; base | where EventID == 4624",
        "SecurityEvent | where EventID == '4624.0'",
        "SecurityEvent | where EventID in ('4624', 'x')",
        "SecurityEvent | where EventID !in ('4624')",
    ] {
        assert_eq!(rule(widening).prefilter, Predicate::Always, "{widening}");
    }
}

#[test]
fn event_ids_written_as_strings_bound_the_rule_as_kql_converts_them() {
    for (query, ids) in [
        ("SecurityEvent | where EventID == '4656'", &["4656"][..]),
        ("SecurityEvent | where EventID == \" 04656\"", &["4656"]),
        (
            "SecurityEvent | where EventID in (\"4723\",\"4724\")",
            &["4723", "4724"],
        ),
        (
            "SecurityEvent | where EventID in~ ('4723', 04724)",
            &["4723", "4724"],
        ),
    ] {
        assert_eq!(rule(query).prefilter, event_ids(ids), "{query}");
    }
}

#[test]
fn every_reference_counts() {
    let r = rule(
        "SecurityEvent | where EventID == 4720\n| join (SecurityEvent | where EventID == 4732) on \
         TargetSid\n| summarize count() by Computer",
    );
    assert_eq!(
        r.prefilter,
        Predicate::any([event_ids(&["4720"]), event_ids(&["4732"])])
    );
    assert!(r.stateful);
    let unbounded = rule("SecurityEvent | where EventID == 4720 | union (SecurityEvent | take 5)");
    assert_eq!(unbounded.prefilter, Predicate::Always);
}

#[test]
fn what_cannot_be_bounded_reads_every_column() {
    for query in [
        "search \"mimikatz\"",
        "union * | where EventID == 1",
        "SecurityEvent | extend all = pack_all()",
        "imAuthentication(starttime=ago(1d)) | where EventResult == 'Failure'",
        "SecurityEvent | where EventID == 4624 | invoke MyWorkspaceFunction()",
    ] {
        let r = rule(query);
        assert_eq!(r.fields, RequiredFields::Unknown, "{query}");
    }
}

#[test]
fn parsers_and_workspace_functions_may_read_every_windows_table() {
    for query in [
        "imProcessCreate | where CommandLine has 'mimikatz'",
        "_Im_Dns(starttime=ago(1d)) | where DnsQuery has 'x'",
        "ASimAuthentication | where EventResult == 'Failure'",
        "_ASim_RegistryEvent | take 1",
        "MyWorkspaceFunction() | take 1",
    ] {
        let r = rule(query);
        assert_eq!(r.logsource.product.as_deref(), None, "{query}");
        assert_eq!(r.logsource.service, None, "{query}");
        assert_eq!(r.prefilter, shaped_records(), "{query}");
        assert_eq!(r.fields, RequiredFields::Unknown, "{query}");
    }
    for other in [
        "ASimAuditEventLogs | where Operation has 'x'",
        "SigninLogs | join (_GetWatchlist('vip')) on UserPrincipalName",
    ] {
        assert_eq!(
            rule(other).logsource.product.as_deref(),
            Some("sentinel-other-tables"),
            "{other}"
        );
    }
}

#[test]
fn c3_a_rule_on_a_custom_table_applies_to_every_source_and_keeps_its_rows() {
    for query in [
        "MyApp_CL | where action == 'deny' | project user",
        "union SecurityEvent, MyApp_CL | where EventID == 4625",
    ] {
        let r = rule(query);
        assert_eq!(r.logsource.product, None, "{query}");
        assert_eq!(r.prefilter, Predicate::Always, "{query}");
        let RequiredFields::Known(fields) = &r.fields else {
            panic!("{query}: fields are known");
        };
        let named = |f: &str| fields.contains(&sluice_core::field::FieldPath::new(f));
        assert!(
            named("EventID") || (named("action") && named("user")),
            "{query}"
        );
    }
}

#[test]
fn rules_on_other_tables_do_not_apply_to_windows_sources() {
    let r = rule("SigninLogs | where ResultType != 0");
    assert_eq!(
        r.logsource.product.as_deref(),
        Some("sentinel-other-tables")
    );
    let both = rule("union SecurityEvent, WindowsEvent | where EventID == 1");
    assert_eq!(both.logsource.product.as_deref(), Some("windows"));
    assert_eq!(
        both.logsource.service, None,
        "WindowsEvent spans every channel"
    );
}

#[test]
fn unreadable_files_fail_closed_and_rules_without_a_query_are_skipped() {
    let rules = SentinelRules::parse([
        ("bad.yaml", "id: [unclosed"),
        ("fusion.yaml", "id: fusion\nkind: Fusion\n"),
    ]);
    assert_eq!(rules.requirements().len(), 1);
    assert_eq!(rules.requirements()[0].fields, RequiredFields::Unknown);
    assert_eq!(rules.problems().len(), 1);
    assert!(
        rules.problems()[0].contains("bad.yaml"),
        "{:?}",
        rules.problems()
    );
}

#[test]
fn every_document_of_a_file_is_a_rule() {
    let rules = SentinelRules::parse([(
        "two.yaml",
        "id: a\nquery: SecurityEvent | where EventID == 1\n---\nid: b\nquery: SecurityEvent | \
         where EventID == 2\n---\n",
    )]);
    let ids: Vec<&str> = rules
        .requirements()
        .iter()
        .map(|r| r.rule.as_str())
        .collect();
    assert_eq!(ids, ["sentinel:a", "sentinel:b"]);
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
    assert_eq!(rules.queries().len(), 2);
}

#[test]
fn equality_on_known_text_columns_bounds_the_rule() {
    let r = rule("SecurityEvent | where EventSourceName == 'AD FS Auditing' | distinct Computer");
    assert_eq!(
        r.prefilter,
        Predicate::Field(FieldTest {
            field: "EventSourceName".into(),
            op: MatchOp::Equals,
            values: vec!["AD FS Auditing".into()],
            case_sensitive: true,
        })
    );
    let insensitive = rule("WindowsEvent | where Channel =~ 'System'");
    assert!(matches!(
        insensitive.prefilter,
        Predicate::Field(FieldTest {
            case_sensitive: false,
            ..
        })
    ));
    for widening in [
        "let enabled = 'yes'; SecurityEvent | where enabled == 'yes'",
        "SecurityEvent | where Account == 'x'",
        "SecurityEvent | where EventSourceName == someVariable",
    ] {
        assert_eq!(rule(widening).prefilter, Predicate::Always, "{widening}");
    }
}

#[test]
fn a_byte_order_mark_is_not_a_problem() {
    let rules = SentinelRules::parse([(
        "bom.yaml",
        "\u{feff}id: a\r\nquery: SecurityEvent | where EventID == 1\r\n",
    )]);
    assert!(rules.problems().is_empty(), "{:?}", rules.problems());
    assert_eq!(rules.requirements().len(), 1);
}

fn parser(names: &str, query: &str) -> String {
    format!("{names}\nParserQuery: |\n{}\n", indent(query))
}

fn with_parsers(rule_query: &str, parsers: &[String]) -> RuleRequirements {
    let rule_yaml = format!("id: r1\nquery: |\n{}\n", indent(rule_query));
    let mut files: Vec<(&str, &str)> = parsers
        .iter()
        .map(|p| ("parser.yaml", p.as_str()))
        .collect();
    files.push(("rule.yaml", rule_yaml.as_str()));
    let rules = SentinelRules::parse(files);
    assert_eq!(rules.requirements().len(), 1, "parsers are not rules");
    rules.requirements()[0].clone()
}

#[test]
fn a_rule_reads_what_the_parsers_it_uses_read() {
    let parsers = [
        parser(
            "ParserName: imProcessCreate\nEquivalentBuiltInParser: _Im_ProcessCreate",
            "let Generic = (starttime: datetime = datetime(null)) {\n  union isfuzzy=true \
             vimProcessCreateSecurity, vimProcessCreateSyslog\n};\nGeneric(starttime)",
        ),
        parser(
            "ParserName: vimProcessCreateSecurity",
            "SecurityEvent\n| where EventID == 4688\n| project CommandLine, NewProcessName, \
             Extra = column_ifexists('MandatoryLabel', '')",
        ),
        parser(
            "ParserName: vimProcessCreateSyslog",
            "AzureDiagnostics | where Category == 'x' | project-away *",
        ),
    ];
    for call in ["imProcessCreate", "_Im_ProcessCreate(starttime=ago(1d))"] {
        let r = with_parsers(
            &format!("{call} | where CommandLine has 'mimikatz'"),
            &parsers,
        );
        assert_eq!(r.logsource.product.as_deref(), Some("windows"), "{call}");
        assert_eq!(r.logsource.service.as_deref(), Some("security"), "{call}");
        assert_eq!(r.prefilter, event_ids(&["4688"]), "{call}");
        let RequiredFields::Known(fields) = &r.fields else {
            panic!("known fields for {call}")
        };
        assert!(
            fields.contains("CommandLine") && fields.contains("MandatoryLabel"),
            "{call}"
        );
    }
}

#[test]
fn unknown_or_recursive_parsers_fail_closed() {
    let calls_unknown = [parser("ParserName: imDns", "vimDnsMissing | take 1")];
    let recursive = [
        parser("ParserName: imDns", "vimDnsLoop"),
        parser("ParserName: vimDnsLoop", "imDns | where EventID == 1"),
    ];
    for parsers in [&calls_unknown[..], &recursive[..]] {
        let r = with_parsers("imDns | where DnsQuery has 'x'", parsers);
        assert_eq!(r.logsource.product.as_deref(), None);
        assert_eq!(r.prefilter, shaped_records());
        assert_eq!(r.fields, RequiredFields::Unknown);
    }
}

#[test]
fn columns_named_as_strings_are_read() {
    let r = rule(
        "SecurityEvent | where EventID == 1 | extend a = column_ifexists('Hidden', ''), b = \
         ['Odd Name']",
    );
    let RequiredFields::Known(fields) = &r.fields else {
        panic!("known fields")
    };
    assert!(
        fields.contains("Hidden") && fields.contains("Odd Name"),
        "{fields:?}"
    );
}

#[test]
fn union_star_and_search_may_read_every_windows_table() {
    for query in ["union * | where EventID == 1", "search \"mimikatz\""] {
        let r = rule(query);
        assert_eq!(r.logsource.product.as_deref(), None, "{query}");
        assert_eq!(r.prefilter, shaped_records(), "{query}");
    }
}

#[test]
fn let_lists_of_event_ids_bound_the_rule() {
    for (query, ids) in [
        (
            "let Logon = dynamic([4624, '4625']);\nSecurityEvent | where EventID in (Logon)",
            &["4624", "4625"][..],
        ),
        (
            "let Ids = pack_array(4720, 4722);\nSecurityEvent | where EventID in (Ids, 4738)",
            &["4720", "4722", "4738"],
        ),
        (
            "let Cleared = 1102;\nSecurityEvent | where EventID == Cleared",
            &["1102"],
        ),
    ] {
        assert_eq!(rule(query).prefilter, event_ids(ids), "{query}");
    }
    for widening in [
        "let Ids = dynamic([4624, x]);\nSecurityEvent | where EventID in (Ids)",
        "let Ids = toscalar(Other | take 1);\nSecurityEvent | where EventID in (Ids)",
        "let Ids = dynamic([4624]);\nlet Ids = Other;\nSecurityEvent | where EventID in (Ids)",
    ] {
        assert_eq!(rule(widening).prefilter, Predicate::Always, "{widening}");
    }
}

#[test]
fn a_tabular_parameter_named_like_a_table_is_not_the_table() {
    let query = "let Parse = (SecurityEvent: (SubjectUserName: string)) {\n  SecurityEvent | extend \
                 User = SubjectUserName\n};\nSecurityEvent\n| where EventID == 4657\n| invoke \
                 Parse()";
    assert_eq!(rule(query).prefilter, event_ids(&["4657"]));
    let outside = "let Parse = (SecurityEvent: (A: string)) { SecurityEvent };\nSecurityEvent | \
                   invoke Parse()";
    assert_eq!(
        rule(outside).prefilter,
        Predicate::Always,
        "the real table stays a reference"
    );
}

#[test]
fn projections_that_keep_rows_do_not_end_the_filter() {
    for query in [
        "WindowsEvent | where not(disabled) | project EventID, EventData, Provider | where \
         Provider == 'Microsoft-Windows-Sysmon' and EventID == 22",
        "WindowsEvent | project-away Channel | extend Size = 1 | where EventID == 22",
    ] {
        let r = rule(query);
        assert!(
            matches!(&r.prefilter, Predicate::All(_)) || r.prefilter == event_ids(&["22"]),
            "{query}: {:?}",
            r.prefilter
        );
    }
    for widening in [
        "WindowsEvent | extend EventID = 22 | where EventID == 22",
        "WindowsEvent | project EventID = toint(Other) | where EventID == 22",
        "WindowsEvent | summarize count() by EventID | where EventID == 22",
    ] {
        assert_eq!(rule(widening).prefilter, Predicate::Always, "{widening}");
    }
}

#[test]
fn syslog_rules_apply_to_syslog_records_of_any_product() {
    let r = rule("Syslog | where Facility == 'authpriv' and SyslogMessage has 'Failed password'");
    assert_eq!(r.logsource.product, None);
    assert_eq!(
        r.prefilter,
        Predicate::all([
            super::extract::present("SyslogMessage"),
            Predicate::Field(FieldTest {
                field: "Facility".into(),
                op: MatchOp::Equals,
                values: vec!["authpriv".into()],
                case_sensitive: true,
            }),
        ])
    );
    let RequiredFields::Known(fields) = &r.fields else {
        panic!("known fields")
    };
    assert!(fields.contains("SyslogMessage") && fields.contains("Facility"));
    let rules = SentinelRules::parse([(
        "s.yaml",
        "id: s\nquery: Syslog | where ProcessName == 'sshd'\n",
    )]);
    assert_eq!(
        rules.queries().len(),
        1,
        "the emulator runs Syslog rules too"
    );
}

#[test]
fn c3_tables_named_at_run_time_by_wildcard_or_by_find_may_read_every_windows_table() {
    for query in [
        "table('SecurityEvent') | where EventID == 4625",
        "union isfuzzy=true * | where EventID == 4625",
        "union withsource=SourceTable Security* | take 1",
        "union kind=outer (WindowsEvent | take 1), Security*",
        "find \"mimikatz\"",
        "find in (SecurityEvent) where Account has 'x'",
    ] {
        let r = rule(query);
        assert_eq!(r.fields, RequiredFields::Unknown, "{query}");
        assert_eq!(r.logsource.product, None, "{query}: any product's records");
        assert_eq!(r.prefilter, shaped_records(), "{query}");
    }
}

#[test]
fn a_union_of_named_tables_reads_only_those() {
    let r = rule("union SecurityEvent, WindowsEvent | where EventID == 4625");
    assert_eq!(r.logsource.product.as_deref(), Some("windows"));
    assert!(matches!(r.fields, RequiredFields::Known(_)));
    // A `*` inside a nested query is arithmetic, not a wildcard.
    let r = rule("union (SecurityEvent | where EventID * 2 == 9250)");
    assert!(matches!(r.fields, RequiredFields::Known(_)));
}

#[test]
fn rule_names_are_the_names_the_siem_shows() {
    let rules = SentinelRules::parse([(
        "r1.yaml",
        "id: r1\nname: Brute force\nquery: |\n  SecurityEvent | where EventID == 4625\n",
    )]);
    assert_eq!(rules.names().len(), 1);
    assert_eq!(rules.names()[&"sentinel:r1".into()], "Brute force");
}

#[test]
fn c3_a_custom_table_rule_protects_the_fields_its_columns_were_renamed_from() {
    let r = rule("MyApp_CL | where user_agent has 'curl' | project F_timestamp, ProcessId2");
    let RequiredFields::Known(fields) = &r.fields else {
        panic!("fields are known");
    };
    for field in [
        "user_agent",
        "user-agent",
        "@timestamp",
        "F_timestamp",
        "ProcessId",
    ] {
        assert!(
            fields.contains(&sluice_core::field::FieldPath::new(field)),
            "{field}: {fields:?}"
        );
    }
    // Rules on standard tables name their columns only.
    let r = rule("SecurityEvent | where Target_User == 'x'");
    let RequiredFields::Known(fields) = &r.fields else {
        panic!("fields are known");
    };
    assert!(!fields.contains(&sluice_core::field::FieldPath::new("Target-User")));
}

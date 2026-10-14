use std::cell::RefCell;

use super::*;

const WORKSPACE: &str = "/subscriptions/0000/resourceGroups/rg-test/providers/Microsoft.OperationalInsights/workspaces/ws";

/// Azure, answering in the documented shapes; records every request.
struct Azure {
    rules: Vec<Value>,
    searches: Vec<Value>,
    /// Splits the alert rules over two pages.
    paged: bool,
    /// The query log's answer.
    log: Value,
    requests: RefCell<Vec<(String, Option<String>)>>,
}

impl Azure {
    fn new() -> Self {
        Self {
            rules: vec![
                rule(
                    "r1",
                    "Scheduled",
                    true,
                    Some("SecurityEvent | where EventID == 4625"),
                ),
                rule(
                    "r2",
                    "NRT",
                    true,
                    Some("SecurityEvent | where EventID == 4720"),
                ),
                rule("r3", "Scheduled", false, Some("Syslog")),
                rule("r4", "Fusion", true, None),
                rule("r5", "MLBehaviorAnalytics", true, None),
            ],
            searches: vec![
                search(
                    "h1",
                    "Hunting Queries",
                    "Rare logons",
                    "SecurityEvent | take 1",
                    None,
                ),
                search(
                    "f1",
                    "Functions",
                    "Parser",
                    "SecurityEvent | where EventID == 1",
                    Some("MyParser"),
                ),
                search("l1", "Log Management", "All events", "Event", None),
            ],
            paged: false,
            log: json!({ "tables": [{ "name": "PrimaryResult",
                "columns": [{ "name": "QueryText", "type": "string" }, { "name": "Runs", "type": "long" }],
                "rows": [["SecurityEvent | count", 9], ["Heartbeat | take 5", 2]] }] }),
            requests: RefCell::new(Vec::new()),
        }
    }
}

fn rule(name: &str, kind: &str, enabled: bool, query: Option<&str>) -> Value {
    let mut properties = json!({ "displayName": format!("Rule {name}"), "enabled": enabled });
    if let Some(query) = query {
        properties["query"] = json!(query);
    }
    json!({ "name": name, "kind": kind, "properties": properties })
}

fn search(name: &str, category: &str, display: &str, query: &str, alias: Option<&str>) -> Value {
    let mut properties = json!({ "category": category, "displayName": display, "query": query });
    if let Some(alias) = alias {
        properties["functionAlias"] = json!(alias);
    }
    json!({ "name": name, "properties": properties })
}

impl Transport for Azure {
    fn send(
        &self,
        _method: &str,
        url: &str,
        _headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), SentinelError> {
        self.requests
            .borrow_mut()
            .push((url.to_owned(), body.map(str::to_owned)));
        let answer = if url.starts_with("https://login.microsoftonline.com/") {
            json!({ "access_token": "token" })
        } else if url.contains("/alertRules") && url.contains("page=2") {
            json!({ "value": self.rules[2..] })
        } else if url.contains("/alertRules") {
            if self.paged {
                json!({ "value": self.rules[..2], "nextLink": format!("{url}&page=2") })
            } else {
                json!({ "value": self.rules })
            }
        } else if url.contains("/savedSearches") {
            json!({ "value": self.searches })
        } else if url.contains("api.loganalytics.io") {
            self.log.clone()
        } else if url.contains("/workspaces/ws?") {
            json!({ "properties": { "customerId": "abcd-1234" } })
        } else {
            return Ok((404, json!({"error": {"message": "not found"}}).to_string()));
        };
        Ok((200, answer.to_string()))
    }
}

fn credentials() -> Credentials {
    Credentials {
        tenant: "tenant".into(),
        client_id: "client".into(),
        client_secret: "s3cr&t=".into(),
    }
}

fn options() -> Options {
    Options {
        workspace: WORKSPACE.into(),
        all_saved_searches: false,
        query_log_days: None,
        fetched_at: "2026-10-14T00:00:00Z".into(),
    }
}

fn file(inventory: &Inventory, path: &str) -> Option<Value> {
    inventory
        .files
        .iter()
        .find(|(p, _)| p == path)
        .map(|(_, text)| serde_json::from_str(text).unwrap())
}

#[test]
fn enabled_scheduled_and_nrt_rules_are_written_with_their_query() {
    let inventory = fetch(&Azure::new(), &credentials(), &options()).unwrap();
    assert_eq!(
        file(&inventory, "rules/r1.yaml").unwrap()["query"],
        "SecurityEvent | where EventID == 4625"
    );
    assert_eq!(file(&inventory, "rules/r2.yaml").unwrap()["kind"], "NRT");
    assert!(file(&inventory, "rules/r3.yaml").is_none(), "disabled");
    assert_eq!(inventory.manifest.counts["disabled"], 1);
    assert!(inventory.manifest.complete);
}

#[test]
fn c3_a_rule_without_a_query_reads_everything_unless_it_reads_only_alerts() {
    let inventory = fetch(&Azure::new(), &credentials(), &options()).unwrap();
    assert!(
        file(&inventory, "rules/r4.yaml").is_none(),
        "Fusion reads alerts"
    );
    assert_eq!(
        file(&inventory, "rules/r5.yaml").unwrap()["query"],
        "search *"
    );
    assert_eq!(inventory.manifest.not_modeled.len(), 2);
}

#[test]
fn hunting_queries_and_functions_are_read_and_other_searches_counted() {
    let inventory = fetch(&Azure::new(), &credentials(), &options()).unwrap();
    assert_eq!(file(&inventory, "saved/h1.yaml").unwrap()["id"], "saved-h1");
    assert_eq!(
        file(&inventory, "functions/MyParser.yaml").unwrap()["FunctionName"],
        "MyParser"
    );
    assert!(file(&inventory, "saved/l1.yaml").is_none());
    assert_eq!(inventory.manifest.counts["saved_searches_not_read"], 1);

    let all = Options {
        all_saved_searches: true,
        ..options()
    };
    let inventory = fetch(&Azure::new(), &credentials(), &all).unwrap();
    assert!(file(&inventory, "saved/l1.yaml").is_some());
}

#[test]
fn rule_lists_follow_next_link() {
    let mut azure = Azure::new();
    azure.paged = true;
    let inventory = fetch(&azure, &credentials(), &options()).unwrap();
    assert!(file(&inventory, "rules/r5.yaml").is_some(), "from page 2");
}

#[test]
fn the_query_log_becomes_one_rule_per_distinct_query() {
    let with_log = Options {
        query_log_days: Some(30),
        ..options()
    };
    let azure = Azure::new();
    let inventory = fetch(&azure, &credentials(), &with_log).unwrap();
    assert_eq!(inventory.manifest.counts["queries"], 2);
    let id = format!("query-{:016x}", fnv1a("SecurityEvent | count"));
    assert_eq!(
        file(&inventory, &format!("queries/{id}.yaml")).unwrap()["query"],
        "SecurityEvent | count"
    );
    let requests = azure.requests.borrow();
    let (_, body) = requests
        .iter()
        .find(|(url, _)| url == "https://api.loganalytics.io/v1/workspaces/abcd-1234/query")
        .unwrap();
    assert!(body.as_deref().unwrap().contains("ago(30d)"));
}

#[test]
fn the_secret_is_form_encoded_and_never_in_a_url() {
    let azure = Azure::new();
    fetch(&azure, &credentials(), &options()).unwrap();
    let requests = azure.requests.borrow();
    assert!(requests.iter().all(|(url, _)| !url.contains("s3cr")));
    let token_body = requests[0].1.as_deref().unwrap();
    assert!(token_body.contains("client_secret=s3cr%26t%3D"));
    assert!(token_body.contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default"));
    assert!(!format!("{:?}", credentials()).contains("s3cr"));
}

#[test]
fn a_malformed_workspace_id_is_refused_before_any_request() {
    let azure = Azure::new();
    for bad in [
        "sluice-test",
        "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/x",
        "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws?x=1",
        "/subscriptions/../resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws",
    ] {
        let refused = fetch(
            &azure,
            &credentials(),
            &Options {
                workspace: bad.into(),
                ..options()
            },
        );
        assert!(matches!(refused, Err(SentinelError::Invalid(_))), "{bad}");
    }
    assert!(azure.requests.borrow().is_empty());
}

#[test]
fn an_api_error_fails_the_fetch_with_azures_message() {
    struct Forbidden;
    impl Transport for Forbidden {
        fn send(
            &self,
            _: &str,
            url: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), SentinelError> {
            if url.starts_with("https://login") {
                return Ok((200, json!({ "access_token": "t" }).to_string()));
            }
            Ok((
                403,
                json!({ "error": { "message": "no access" } }).to_string(),
            ))
        }
    }
    let refused = fetch(&Forbidden, &credentials(), &options());
    assert!(matches!(refused, Err(SentinelError::Http(m)) if m.contains("no access")));
}

#[test]
fn colliding_file_names_get_a_suffix() {
    let mut azure = Azure::new();
    azure.rules = vec![
        rule("a/b", "Scheduled", true, Some("SecurityEvent")),
        rule("a_b", "Scheduled", true, Some("SecurityEvent")),
    ];
    let inventory = fetch(&azure, &credentials(), &options()).unwrap();
    assert!(file(&inventory, "rules/a_b.yaml").is_some());
    assert!(file(&inventory, "rules/a_b-2.yaml").is_some());
}

#[test]
fn c3_a_rule_without_an_enabled_flag_is_read() {
    let mut azure = Azure::new();
    let mut unknown = rule("u1", "Scheduled", true, Some("Syslog"));
    unknown["properties"]
        .as_object_mut()
        .unwrap()
        .remove("enabled");
    azure.rules = vec![unknown];
    let inventory = fetch(&azure, &credentials(), &options()).unwrap();
    assert!(file(&inventory, "rules/u1.yaml").is_some());
    assert!(!inventory.manifest.counts.contains_key("disabled"));
}

#[test]
fn c3_a_scheduled_rule_without_a_query_reads_everything() {
    let mut azure = Azure::new();
    azure.rules = vec![rule("s1", "Scheduled", true, None)];
    let inventory = fetch(&azure, &credentials(), &options()).unwrap();
    assert_eq!(
        file(&inventory, "rules/s1.yaml").unwrap()["query"],
        "search *"
    );
}

#[test]
fn an_alert_rule_without_a_name_fails_the_fetch() {
    let mut azure = Azure::new();
    azure.rules =
        vec![json!({ "kind": "Scheduled", "properties": { "enabled": true, "query": "Syslog" } })];
    assert!(matches!(
        fetch(&azure, &credentials(), &options()),
        Err(SentinelError::Invalid(_))
    ));
}

#[test]
fn saved_searches_without_a_query_or_with_an_empty_alias_are_handled() {
    let mut azure = Azure::new();
    azure.searches = vec![
        json!({ "name": "nq", "properties": { "category": "Hunting Queries" } }),
        search("ea", "Hunting Queries", "Empty alias", "Syslog", Some("")),
    ];
    let inventory = fetch(&azure, &credentials(), &options()).unwrap();
    assert!(file(&inventory, "saved/nq.yaml").is_none());
    assert!(
        file(&inventory, "saved/ea.yaml").is_some(),
        "a hunting query"
    );
    let searches = inventory
        .files
        .iter()
        .filter(|(p, _)| !p.starts_with("rules/"))
        .count();
    assert_eq!(searches, 1);
}

#[test]
fn the_hunting_category_is_matched_without_case() {
    let mut azure = Azure::new();
    azure.searches = vec![search("h", "hunting queries", "H", "Syslog", None)];
    let inventory = fetch(&azure, &credentials(), &options()).unwrap();
    assert!(file(&inventory, "saved/h.yaml").is_some());
}

#[test]
fn an_empty_query_log_says_auditing_may_be_off() {
    let mut azure = Azure::new();
    azure.log = json!({ "tables": [{ "columns": [{ "name": "QueryText" }], "rows": [] }] });
    let with_log = Options {
        query_log_days: Some(7),
        ..options()
    };
    let inventory = fetch(&azure, &credentials(), &with_log).unwrap();
    assert_eq!(inventory.manifest.counts["queries"], 0);
    assert!(
        inventory
            .manifest
            .not_modeled
            .iter()
            .any(|n| n.contains("query auditing"))
    );
}

#[test]
fn a_query_log_without_a_query_column_fails_the_fetch() {
    let mut azure = Azure::new();
    azure.log = json!({ "tables": [{ "columns": [{ "name": "Other" }], "rows": [["x"]] }] });
    let with_log = Options {
        query_log_days: Some(7),
        ..options()
    };
    assert!(matches!(
        fetch(&azure, &credentials(), &with_log),
        Err(SentinelError::Invalid(_))
    ));
}

#[test]
fn a_query_log_at_the_cap_says_it_was_cut_short() {
    let mut azure = Azure::new();
    let rows: Vec<Value> = (0..MAX_LOGGED_QUERIES)
        .map(|i| json!([format!("Syslog | take {i}"), 1]))
        .collect();
    azure.log = json!({ "tables": [{ "columns": [{ "name": "QueryText" }, { "name": "Runs" }], "rows": rows }] });
    let with_log = Options {
        query_log_days: Some(7),
        ..options()
    };
    let inventory = fetch(&azure, &credentials(), &with_log).unwrap();
    assert_eq!(inventory.manifest.counts["queries"], MAX_LOGGED_QUERIES);
    assert!(
        inventory
            .manifest
            .not_modeled
            .iter()
            .any(|n| n.contains("run most often"))
    );
}

#[test]
fn the_same_query_text_gets_the_same_id() {
    assert_eq!(fnv1a("Syslog"), fnv1a("Syslog"));
    assert_ne!(fnv1a("Syslog"), fnv1a("syslog"));
    assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn a_trailing_slash_on_the_workspace_id_is_accepted() {
    let azure = Azure::new();
    let options = Options {
        workspace: format!("{WORKSPACE}/"),
        ..options()
    };
    let inventory = fetch(&azure, &credentials(), &options).unwrap();
    assert_eq!(inventory.manifest.from, WORKSPACE);
    assert!(
        azure
            .requests
            .borrow()
            .iter()
            .all(|(url, _)| !url.contains("ws//"))
    );
}

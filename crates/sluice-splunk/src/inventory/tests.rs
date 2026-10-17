use super::*;

/// A fake Splunk: `searches` and `macros` as `(name, content)`, served `per_page` at a time;
/// `total` overrides the reported total.
struct Fake {
    searches: Vec<Value>,
    macros: Vec<Value>,
    props: Vec<Value>,
    per_page: usize,
    total: Option<usize>,
}

impl Fake {
    fn get(&self, collection: &str, offset: usize) -> Value {
        let none = Vec::new();
        let all = match collection {
            "saved/searches" => &self.searches,
            "admin/macros" => &self.macros,
            "configs/conf-props" => &self.props,
            _ => &none,
        };
        let page: Vec<&Value> = all.iter().skip(offset).take(self.per_page).collect();
        json!({
            "paging": {"total": self.total.unwrap_or(all.len()), "offset": offset},
            "entry": page,
        })
    }
}

fn entry(name: &str, content: &Value) -> Value {
    json!({"name": name, "acl": {"app": "search", "owner": "admin"}, "links": {}, "content": content})
}

fn fake() -> Fake {
    Fake {
        searches: (0..5)
            .map(|i| {
                entry(
                    &format!("s{i}"),
                    &json!({"search": format!("`m` a={i}"), "is_scheduled": true, "disabled": false}),
                )
            })
            .collect(),
        macros: vec![entry("m", &json!({"definition": "index=main"}))],
        props: vec![entry("XmlWinEventLog", &json!({"FIELDALIAS-a": "orig AS a"}))],
        per_page: 2,
        total: None,
    }
}

#[test]
fn every_page_of_both_collections_is_read() {
    let fake = fake();
    let inventory = collect(|c, o| Ok(fake.get(c, o)), "https://s:8089", "t").unwrap();
    assert!(inventory.manifest.complete);
    assert_eq!(inventory.manifest.counts["searches"], 5);
    assert_eq!(inventory.manifest.counts["macros"], 1);
    let names: Vec<&str> = inventory.files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "saved-searches.json",
            "macros.json",
            "props.json",
            "transforms.json"
        ]
    );
    assert_eq!(inventory.manifest.counts["props stanzas"], 1);
}

#[test]
fn c3_a_fetch_that_ends_short_is_not_complete() {
    let fake = Fake {
        total: Some(9),
        ..fake()
    };
    let inventory = collect(|c, o| Ok(fake.get(c, o)), "https://s:8089", "t").unwrap();
    assert!(!inventory.manifest.complete);
    assert!(inventory.manifest.not_modeled[0].contains("9 searches but 5"));
}

#[test]
fn the_files_read_as_splunk_rules_with_their_macros() {
    let fake = fake();
    let inventory = collect(|c, o| Ok(fake.get(c, o)), "https://s:8089", "t").unwrap();
    let rules = sluice_rules::SplunkRules::parse(
        inventory
            .files
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str())),
    );
    assert_eq!(rules.requirements().len(), 5);
    assert_eq!(rules.problems(), [] as [String; 0]);
    // `a` is an alias of `orig` in props.json.
    assert!(
        format!("{:?}", rules.requirements()[0].prefilter).contains("\"orig\""),
        "{:?}",
        rules.requirements()[0].prefilter
    );
}

#[test]
fn an_answer_without_entries_is_an_error() {
    let error = collect(|_, _| Ok(json!({"messages": []})), "https://s:8089", "t");
    assert!(matches!(error, Err(SplunkError::Response(_))));
}

#[test]
fn base64_as_basic_authorization_needs_it() {
    assert_eq!(base64("admin:changeme"), "YWRtaW46Y2hhbmdlbWU=");
    assert_eq!(base64("ab"), "YWI=");
}

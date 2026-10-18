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

/// A Splunk that answers each GET with `answer(path and query, authorization)`.
fn splunk(answer: fn(&str, &str) -> (u16, String)) -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let url = format!("http://{}", listener.local_addr().expect("bound"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let target = line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let mut authorization = String::new();
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
                if let Some((name, value)) = header.trim_end().split_once(':')
                    && name.eq_ignore_ascii_case("authorization")
                {
                    value.trim().clone_into(&mut authorization);
                }
            }
            let (status, body) = answer(&target, &authorization);
            let response = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = reader.get_mut().write_all(response.as_bytes());
        }
    });
    url
}

/// One page of three searches and one macro, for the token `t` only.
fn answers(target: &str, authorization: &str) -> (u16, String) {
    if authorization != "Bearer t" {
        return (
            401,
            r#"{"messages":[{"text":"call not properly authenticated"}]}"#.to_owned(),
        );
    }
    assert!(target.contains("output_mode=json"), "{target}");
    let (entries, total) = if target.contains("saved/searches") {
        let offset: usize = target
            .split("offset=")
            .nth(1)
            .and_then(|o| o.split('&').next())
            .and_then(|o| o.parse().ok())
            .unwrap_or(0);
        let all: Vec<Value> = (0..3)
            .map(|i| {
                entry(
                    &format!("s{i}"),
                    &json!({"search": "a=1", "is_scheduled": true}),
                )
            })
            .collect();
        (all.into_iter().skip(offset).take(2).collect::<Vec<_>>(), 3)
    } else if target.contains("admin/macros") {
        (vec![entry("m", &json!({"definition": "index=x"}))], 1)
    } else {
        (Vec::new(), 0)
    };
    (
        200,
        json!({"paging": {"total": total}, "entry": entries}).to_string(),
    )
}

#[test]
fn a_fetch_reads_every_page_over_http_with_the_token() {
    let url = splunk(answers);
    let auth = Auth::Token("t".into());
    let target = Target {
        url: &url,
        auth: &auth,
        insecure: false,
    };
    let inventory = fetch(&target, "2026-10-17T00:00:00Z").expect("fetches");
    assert!(inventory.manifest.complete);
    assert_eq!(inventory.manifest.counts["searches"], 3);
    assert_eq!(inventory.manifest.counts["macros"], 1);
    assert_eq!(inventory.manifest.from, url);
}

#[test]
fn a_refused_or_unreachable_splunk_is_an_error() {
    let url = splunk(answers);
    let wrong = Auth::Basic {
        user: "u".into(),
        password: "p".into(),
    };
    let refused = fetch(
        &Target {
            url: &url,
            auth: &wrong,
            insecure: true,
        },
        "t",
    );
    assert!(
        matches!(refused, Err(SplunkError::Rejected { status: 401, .. })),
        "{refused:?}"
    );
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        format!("http://{}", listener.local_addr().expect("bound"))
    };
    let unreachable = fetch(
        &Target {
            url: &closed,
            auth: &Auth::Token("t".into()),
            insecure: false,
        },
        "t",
    );
    assert!(
        matches!(unreachable, Err(SplunkError::Unreachable { .. })),
        "{unreachable:?}"
    );
}

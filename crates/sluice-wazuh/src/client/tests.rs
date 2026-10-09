use std::cell::RefCell;

use serde_json::{Value, json};

use super::*;

/// One recorded request.
struct Sent {
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Value>,
}

/// Answers by path, and records every request.
struct Fake {
    logtest_reply: Value,
    requests: RefCell<Vec<Sent>>,
}

impl Fake {
    fn new(logtest_reply: Value) -> Self {
        Self {
            logtest_reply,
            requests: RefCell::new(Vec::new()),
        }
    }

    fn count(&self, path: &str) -> usize {
        self.requests
            .borrow()
            .iter()
            .filter(|r| r.url.ends_with(path))
            .count()
    }

    fn last_body(&self) -> Value {
        self.requests
            .borrow()
            .last()
            .and_then(|r| r.body.clone())
            .unwrap_or_default()
    }
}

impl Transport for &Fake {
    fn send(
        &self,
        _method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), WazuhError> {
        let headers = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        let parsed = body.map(|b| serde_json::from_str(b).unwrap());
        self.requests.borrow_mut().push(Sent {
            url: url.to_owned(),
            headers,
            body: parsed,
        });
        let reply = if url.ends_with("/security/user/authenticate") {
            json!({"error": 0, "data": {"token": "jwt-1"}})
        } else {
            self.logtest_reply.clone()
        };
        Ok((200, reply.to_string()))
    }
}

fn client(fake: &Fake) -> Logtest<&Fake> {
    Logtest::new(
        LogtestConfig {
            url: "https://wazuh:55000/".into(),
            user: "user".into(),
            password: "pass".into(),
        },
        fake,
    )
}

fn event() -> Map<String, Value> {
    match json!({"EventID": 4625, "TargetUserName": "bob"}) {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

#[test]
fn base64_matches_rfc_4648_vectors() {
    assert_eq!(base64(""), "");
    assert_eq!(base64("f"), "Zg==");
    assert_eq!(base64("fo"), "Zm8=");
    assert_eq!(base64("foo"), "Zm9v");
    assert_eq!(base64("foobar"), "Zm9vYmFy");
    assert_eq!(base64("user:pass"), "dXNlcjpwYXNz");
}

#[test]
fn alerting_rule_is_reported_with_its_wazuh_id() {
    let fake = Fake::new(
        json!({"error": 0, "data": {"token": "s1", "alert": true, "output": {"rule": {"id": "100100", "level": 5}}}}),
    );
    let rules = client(&fake).fired(&event()).unwrap();
    assert_eq!(rules, BTreeSet::from([RuleId::new("wazuh:100100")]));

    let body = fake.last_body();
    assert_eq!(body["log_format"], "json");
    assert_eq!(body["location"], "sluice");
    let sent: Value = serde_json::from_str(body["event"].as_str().unwrap()).unwrap();
    assert_eq!(sent["TargetUserName"], "bob");
    let auth = &fake.requests.borrow()[0].headers;
    assert!(
        auth.iter()
            .any(|(k, v)| k == "authorization" && v == "Basic dXNlcjpwYXNz")
    );
}

#[test]
fn non_alerting_matches_fire_nothing() {
    let fake = Fake::new(
        json!({"error": 0, "data": {"token": "s1", "alert": false, "output": {"rule": {"id": 1002, "level": 0}}}}),
    );
    assert!(client(&fake).fired(&event()).unwrap().is_empty());
}

#[test]
fn authenticates_once_and_reuses_the_session() {
    let fake = Fake::new(json!({"error": 0, "data": {"token": "s1", "alert": false}}));
    let logtest = client(&fake);
    logtest.fired(&event()).unwrap();
    logtest.fired(&event()).unwrap();
    assert_eq!(fake.count("/security/user/authenticate"), 1);
    assert_eq!(fake.count("/logtest"), 2);
    assert_eq!(fake.last_body()["token"], "s1");
}

#[test]
fn api_errors_fail_closed() {
    let fake = Fake::new(json!({"error": 1, "message": "permission denied"}));
    assert!(client(&fake).fired(&event()).is_err());
}

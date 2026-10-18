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

#[test]
fn an_expired_jwt_is_renewed_once() {
    /// Accepts only the second JWT it hands out, like a manager whose first token expired.
    struct Expiring {
        issued: RefCell<u32>,
        bearers: RefCell<Vec<String>>,
    }
    impl Transport for &Expiring {
        fn send(
            &self,
            _: &str,
            url: &str,
            headers: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            if url.ends_with("/security/user/authenticate") {
                *self.issued.borrow_mut() += 1;
                let token = format!("jwt-{}", self.issued.borrow());
                return Ok((
                    200,
                    json!({"error": 0, "data": {"token": token}}).to_string(),
                ));
            }
            let bearer = headers[0].1.clone();
            self.bearers.borrow_mut().push(bearer.clone());
            if bearer == "Bearer jwt-2" {
                Ok((
                    200,
                    json!({"error": 0, "data": {"alert": false}}).to_string(),
                ))
            } else {
                Ok((401, json!({"title": "Unauthorized"}).to_string()))
            }
        }
    }
    let manager = Expiring {
        issued: RefCell::new(0),
        bearers: RefCell::new(Vec::new()),
    };
    let logtest = Logtest::new(
        LogtestConfig {
            url: "https://wazuh:55000".into(),
            user: "u".into(),
            password: "p".into(),
        },
        &manager,
    );
    assert_eq!(logtest.alert_line("x").unwrap(), None);
    assert_eq!(*manager.bearers.borrow(), ["Bearer jwt-1", "Bearer jwt-2"]);
}

#[test]
fn a_401_after_renewal_fails_closed() {
    struct Never;
    impl Transport for &Never {
        fn send(
            &self,
            _: &str,
            url: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), WazuhError> {
            if url.ends_with("/authenticate") {
                return Ok((200, json!({"error": 0, "data": {"token": "t"}}).to_string()));
            }
            Ok((401, "{}".into()))
        }
    }
    let logtest = Logtest::new(
        LogtestConfig {
            url: "https://wazuh:55000".into(),
            user: "u".into(),
            password: "p".into(),
        },
        &Never,
    );
    assert!(matches!(logtest.alert_line("x"), Err(WazuhError::Http(_))));
}

#[test]
fn a_numeric_rule_id_is_read_and_an_alert_without_one_fails() {
    let fake =
        Fake::new(json!({"error": 0, "data": {"alert": true, "output": {"rule": {"id": 5715}}}}));
    assert_eq!(
        client(&fake).alert_line("x").unwrap().as_deref(),
        Some("5715")
    );
    let fake = Fake::new(json!({"error": 0, "data": {"alert": true, "output": {}}}));
    assert!(matches!(
        client(&fake).alert_line("x"),
        Err(WazuhError::Invalid(_))
    ));
}

#[test]
fn only_an_alert_flag_of_true_is_an_alert() {
    for flag in [json!("true"), json!(1), Value::Null] {
        let fake = Fake::new(
            json!({"error": 0, "data": {"alert": flag, "output": {"rule": {"id": "1"}}}}),
        );
        assert_eq!(client(&fake).alert_line("x").unwrap(), None, "{flag}");
    }
}

#[test]
fn a_raw_line_is_sent_as_syslog() {
    let fake = Fake::new(json!({"error": 0, "data": {"alert": false}}));
    client(&fake)
        .fired_line("sshd[1]: Failed password")
        .unwrap();
    assert_eq!(fake.last_body()["log_format"], "syslog");
    assert_eq!(fake.last_body()["event"], "sshd[1]: Failed password");
}

#[test]
fn error_bodies_are_cut_to_an_excerpt() {
    let long = "x".repeat(10_000);
    let Err(WazuhError::Http(m)) = ok_json(500, &long) else {
        panic!("expected an HTTP error");
    };
    assert!(m.len() < 400, "{}", m.len());
    assert!(m.ends_with('…'));
    assert_eq!(excerpt("short"), "short");
    assert_eq!(excerpt(&"é".repeat(300)), "é".repeat(300));
}

#[test]
fn a_non_zero_error_field_or_a_missing_one_fails() {
    assert!(ok_json(200, r#"{"error": 1}"#).is_err());
    assert!(ok_json(200, r#"{"data": {}}"#).is_err());
    assert!(ok_json(200, "not json").is_err());
    assert!(ok_json(200, r#"{"error": 0}"#).is_ok());
}

/// A server that answers one request with `status` and `body`, and hands back what it got:
/// the request line, the headers (lower-case names) and the body.
fn one_request(status: u16, body: &'static str) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{BufRead, BufReader, Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let url = format!("http://{}", listener.local_addr().expect("bound"));
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("a connection");
        let mut reader = BufReader::new(stream);
        let mut seen = String::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("a header line");
            if line.trim_end().is_empty() {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("content-length:") {
                length = value.trim().parse().expect("a length");
            }
            seen.push_str(&lower);
        }
        let mut sent = vec![0; length];
        reader.read_exact(&mut sent).expect("the body");
        seen.push_str(&String::from_utf8(sent).expect("UTF-8"));
        let answer = format!(
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        reader
            .get_mut()
            .write_all(answer.as_bytes())
            .expect("answer");
        seen
    });
    (url, handle)
}

#[test]
fn the_http_transport_sends_method_headers_and_body_and_returns_any_status() {
    let (url, server) = one_request(401, "{\"title\": \"Unauthorized\"}");
    let answer = Http::new(false).send(
        "PUT",
        &format!("{url}/logtest"),
        &[("authorization", "Bearer t".to_owned())],
        Some("{\"event\": 1}"),
    );
    assert_eq!(
        answer,
        Ok((401, "{\"title\": \"Unauthorized\"}".to_owned())),
        "an error status is an answer, not a transport failure"
    );
    let seen = server.join().unwrap();
    assert!(seen.starts_with("put /logtest http/1.1"), "{seen}");
    assert!(seen.contains("authorization: bearer t"), "{seen}");
    assert!(seen.contains("content-type: application/json"), "{seen}");
    assert!(seen.ends_with("{\"event\": 1}"), "{seen}");
}

#[test]
fn the_http_transport_names_the_request_it_could_not_send() {
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!(
            "http://{}/security/user/authenticate",
            listener.local_addr().unwrap()
        )
    };
    let Err(WazuhError::Http(message)) = Http::new(true).send("POST", &closed, &[], None) else {
        panic!("a refused connection is an error");
    };
    assert!(
        message.starts_with(&format!("POST {closed}: ")),
        "{message}"
    );
    assert!(matches!(
        Http::new(false).send("NOT A METHOD", &closed, &[], None),
        Err(WazuhError::Http(_))
    ));
}

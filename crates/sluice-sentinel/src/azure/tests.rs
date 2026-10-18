use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::json;

use super::*;

const SECRET: &str = "s3cr&t=x";

/// A request's headers, as sent.
type Headers = Vec<(String, String)>;

/// Answers from a fixed table; any other URL is a 404. Records every request.
#[derive(Default)]
struct Table {
    answers: BTreeMap<String, (u16, String)>,
    /// The token endpoint repeats the request body in its error, as a careless proxy might.
    echo_token_request: bool,
    requests: RefCell<Vec<(String, Headers)>>,
}

impl Table {
    fn answer(mut self, url: &str, status: u16, body: &Value) -> Self {
        self.answers
            .insert(url.to_owned(), (status, body.to_string()));
        self
    }

    fn urls(&self) -> Vec<String> {
        self.requests
            .borrow()
            .iter()
            .map(|(u, _)| u.clone())
            .collect()
    }
}

impl Transport for Table {
    fn send(
        &self,
        _method: &str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), SentinelError> {
        self.requests.borrow_mut().push((
            url.to_owned(),
            headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ));
        if url.starts_with("https://login.microsoftonline.com/") {
            if self.echo_token_request {
                return Ok((400, format!("bad request: {}", body.unwrap_or_default())));
            }
            return Ok((200, json!({ "access_token": "tok" }).to_string()));
        }
        Ok(self
            .answers
            .get(url)
            .cloned()
            .unwrap_or((404, json!({"error": {"message": "not found"}}).to_string())))
    }
}

fn credentials() -> Credentials {
    Credentials {
        tenant: "tenant".into(),
        client_id: "client".into(),
        client_secret: SECRET.into(),
    }
}

fn page(values: &[i64], next: Option<&str>) -> Value {
    let mut page = json!({ "value": values });
    if let Some(next) = next {
        page["nextLink"] = json!(next);
    }
    page
}

const FIRST: &str = "https://management.azure.com/x?api-version=1";

#[test]
fn json_accepts_exactly_the_2xx_statuses() {
    for status in [200, 201, 299] {
        assert!(json(status, "{}").is_ok(), "{status}");
    }
    for status in [0, 199, 300, 401, 500] {
        assert!(
            matches!(json(status, "{}"), Err(SentinelError::Http(_))),
            "{status}"
        );
    }
}

#[test]
fn an_error_body_gives_azures_message_or_a_bounded_prefix() {
    let message = json!({"error": {"code": "X", "message": "denied"}}).to_string();
    assert_eq!(
        json(403, &message),
        Err(SentinelError::Http("HTTP 403: denied".into()))
    );
    let long = "é".repeat(1000);
    let Err(SentinelError::Http(m)) = json(502, &long) else {
        panic!("expected an HTTP error");
    };
    assert_eq!(m.chars().count(), "HTTP 502: ".len() + 300);
}

#[test]
fn a_2xx_body_that_is_not_json_is_invalid() {
    assert!(matches!(json(200, ""), Err(SentinelError::Invalid(_))));
    assert!(matches!(
        json(200, "<html>"),
        Err(SentinelError::Invalid(_))
    ));
}

#[test]
fn origin_is_scheme_and_host_only() {
    assert_eq!(
        origin("https://Management.Azure.com/a/b?c#d"),
        "https://management.azure.com"
    );
    assert_eq!(origin("https://h:8443"), "https://h:8443");
    assert_ne!(
        origin("https://management.azure.com@evil.example/x"),
        "https://management.azure.com"
    );
    assert_ne!(origin("http://management.azure.com/x"), origin(FIRST));
}

#[test]
fn a_list_concatenates_its_pages_in_order() {
    let second = "https://management.azure.com/x?api-version=1&$skipToken=2";
    let third = "https://management.azure.com/x?api-version=1&$skipToken=3";
    let azure = Table::default()
        .answer(FIRST, 200, &page(&[1, 2], Some(second)))
        .answer(second, 200, &page(&[], Some(third)))
        .answer(third, 200, &page(&[3], None));
    let client = Client::new(&azure, &credentials(), ARM).unwrap();
    assert_eq!(
        client.list(FIRST).unwrap(),
        vec![json!(1), json!(2), json!(3)]
    );
}

#[test]
fn c1_a_next_link_to_another_host_never_gets_the_token() {
    for evil in [
        "https://evil.example/steal",
        "https://management.azure.com@evil.example/x",
        "http://management.azure.com/x?api-version=1&page=2",
    ] {
        let azure = Table::default().answer(FIRST, 200, &page(&[1], Some(evil)));
        let client = Client::new(&azure, &credentials(), ARM).unwrap();
        assert!(
            matches!(client.list(FIRST), Err(SentinelError::Invalid(m)) if m.contains("leaves")),
            "{evil}"
        );
        assert!(
            !azure.urls().iter().any(|u| u == evil),
            "{evil} was requested"
        );
    }
}

#[test]
fn a_next_link_that_repeats_stops_the_list() {
    let second = "https://management.azure.com/x?api-version=1&page=2";
    let azure = Table::default()
        .answer(FIRST, 200, &page(&[1], Some(second)))
        .answer(second, 200, &page(&[2], Some(FIRST)));
    let client = Client::new(&azure, &credentials(), ARM).unwrap();
    assert!(matches!(client.list(FIRST), Err(SentinelError::Invalid(m)) if m.contains("repeats")));
    assert_eq!(azure.urls().len(), 3, "token, page 1, page 2");
}

#[test]
fn a_page_without_a_value_array_fails_the_list() {
    let azure = Table::default().answer(FIRST, 200, &json!({ "value": "nope" }));
    let client = Client::new(&azure, &credentials(), ARM).unwrap();
    let Err(SentinelError::Invalid(m)) = client.list(FIRST) else {
        panic!("expected Invalid");
    };
    assert!(
        !m.contains("api-version"),
        "the query string stays out: {m}"
    );
}

#[test]
fn requests_carry_the_bearer_token() {
    let azure = Table::default().answer(FIRST, 200, &json!({}));
    let client = Client::new(&azure, &credentials(), ARM).unwrap();
    client.get(FIRST).unwrap();
    let requests = azure.requests.borrow();
    let (_, headers) = requests.last().unwrap();
    assert!(headers.contains(&("authorization".into(), "Bearer tok".into())));
}

#[test]
fn c1_the_secret_never_appears_in_a_token_error() {
    let azure = Table {
        echo_token_request: true,
        ..Table::default()
    };
    let Err(error) = Client::new(&azure, &credentials(), ARM) else {
        panic!("expected an error");
    };
    let text = error.to_string();
    assert!(!text.contains(SECRET), "{text}");
    assert!(!text.contains(&encode(SECRET)), "{text}");
    assert!(text.contains("<redacted>"), "{text}");
}

#[test]
fn c1_the_secret_never_appears_in_a_transport_error() {
    struct Leaky;
    impl Transport for Leaky {
        fn send(
            &self,
            _: &str,
            _: &str,
            _: &[(&str, String)],
            body: Option<&str>,
        ) -> Result<(u16, String), SentinelError> {
            Err(SentinelError::Http(body.unwrap_or_default().to_owned()))
        }
    }
    let Err(error) = Client::new(&Leaky, &credentials(), ARM) else {
        panic!("expected an error");
    };
    assert!(!error.to_string().contains(&encode(SECRET)));
}

#[test]
fn a_token_response_without_a_token_is_invalid() {
    struct NoToken;
    impl Transport for NoToken {
        fn send(
            &self,
            _: &str,
            _: &str,
            _: &[(&str, String)],
            _: Option<&str>,
        ) -> Result<(u16, String), SentinelError> {
            Ok((200, json!({ "token_type": "Bearer" }).to_string()))
        }
    }
    assert!(matches!(
        Client::new(&NoToken, &credentials(), ARM),
        Err(SentinelError::Invalid(_))
    ));
}

#[test]
fn the_tenant_is_encoded_into_the_token_url() {
    let azure = Table::default();
    let credentials = Credentials {
        tenant: "../evil?x".into(),
        ..credentials()
    };
    Client::new(&azure, &credentials, ARM).unwrap();
    assert_eq!(
        azure.urls()[0],
        "https://login.microsoftonline.com/..%2Fevil%3Fx/oauth2/v2.0/token"
    );
}

#[test]
fn credentials_debug_shows_who_but_not_the_secret() {
    let shown = format!("{:?}", credentials());
    assert!(
        shown.contains("tenant") && shown.contains("client"),
        "{shown}"
    );
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(!shown.contains("s3cr"), "{shown}");
}

#[test]
fn errors_name_the_path_without_the_query_string() {
    assert_eq!(short("https://h/a/b?api-version=1&x=2"), "https://h/a/b");
    assert_eq!(short("https://h/a"), "https://h/a");
}

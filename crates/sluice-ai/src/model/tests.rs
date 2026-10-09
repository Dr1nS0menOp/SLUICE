use std::cell::RefCell;

use serde_json::{Value, json};

use super::*;

/// One recorded request.
struct Request {
    headers: Vec<(String, String)>,
    body: Value,
}

/// Records the last request and answers with a canned body.
struct Canned {
    reply: String,
    seen: RefCell<Option<Request>>,
}

impl Canned {
    fn new(reply: &Value) -> Self {
        Self {
            reply: reply.to_string(),
            seen: RefCell::new(None),
        }
    }

    fn header(&self, name: &str) -> Option<String> {
        let seen = self.seen.borrow();
        let request = seen.as_ref()?;
        request
            .headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    fn body(&self) -> Value {
        let seen = self.seen.borrow();
        seen.as_ref().map(|r| r.body.clone()).unwrap_or_default()
    }
}

impl Transport for &Canned {
    fn post(&self, _url: &str, headers: &[(&str, String)], body: &str) -> Result<String, AiError> {
        let headers = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        *self.seen.borrow_mut() = Some(Request {
            headers,
            body: serde_json::from_str(body).unwrap(),
        });
        Ok(self.reply.clone())
    }
}

fn schema() -> Value {
    json!({"type": "object"})
}

fn claude<'a>(model: &str, transport: &'a Canned) -> Anthropic<&'a Canned> {
    Anthropic::new(
        model,
        Credential::ApiKey("k".into()),
        "https://api.example/",
        transport,
    )
}

#[test]
fn anthropic_requests_structured_output_and_reads_the_text_block() {
    let transport = Canned::new(&json!({
        "stop_reason": "end_turn",
        "content": [
            {"type": "thinking", "thinking": ""},
            {"type": "text", "text": "{\"summarize\": true}"}
        ]
    }));
    let answer = claude("claude-opus-5-5", &transport)
        .complete("sys", "usr", &schema())
        .unwrap();
    assert_eq!(answer, json!({"summarize": true}));

    let body = transport.body();
    assert_eq!(body["model"], "claude-opus-5-5");
    assert_eq!(body["system"], "sys");
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    assert_eq!(body["output_config"]["format"]["schema"], schema());
    assert_eq!(body["output_config"]["effort"], "medium");
    assert_eq!(body["fallbacks"], "default");
    assert_eq!(transport.header("x-api-key").as_deref(), Some("k"));
    assert_eq!(
        transport.header("anthropic-version").as_deref(),
        Some("2023-06-01")
    );
    assert_eq!(
        transport.header("anthropic-beta").as_deref(),
        Some("server-side-fallback-2026-07-01")
    );
    assert!(
        body.get("thinking").is_none(),
        "thinking stays at its default"
    );
}

#[test]
fn anthropic_omits_fallbacks_for_models_without_them() {
    let transport = Canned::new(
        &json!({"stop_reason": "end_turn", "content": [{"type": "text", "text": "{}"}]}),
    );
    claude("claude-haiku-5-5", &transport)
        .complete("s", "u", &schema())
        .unwrap();
    assert!(transport.body().get("fallbacks").is_none());
    assert_eq!(transport.header("anthropic-beta"), None);
}

#[test]
fn anthropic_refusals_and_truncation_are_errors() {
    let refused = Canned::new(
        &json!({"stop_reason": "refusal", "stop_details": {"category": "cyber"}, "content": []}),
    );
    assert_eq!(
        claude("claude-opus-5-5", &refused).complete("s", "u", &schema()),
        Err(AiError::Refused("cyber".into()))
    );
    let truncated = Canned::new(
        &json!({"stop_reason": "max_tokens", "content": [{"type": "text", "text": "{"}]}),
    );
    assert_eq!(
        claude("claude-opus-5-5", &truncated).complete("s", "u", &schema()),
        Err(AiError::Truncated)
    );
}

#[test]
fn openai_compatible_uses_json_schema_response_format() {
    let transport = Canned::new(&json!({
        "choices": [{"finish_reason": "stop", "message": {"content": "{\"summarize\": false}"}}]
    }));
    let model = OpenAiCompatible::new("llama3.2", "http://localhost:11434/v1/", None, &transport);
    assert_eq!(
        model.complete("s", "u", &schema()).unwrap(),
        json!({"summarize": false})
    );
    let body = transport.body();
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(transport.header("authorization"), None);
}

#[test]
fn invalid_json_is_an_error() {
    let transport = Canned::new(&json!({"choices": [{"message": {"content": "not json"}}]}));
    let model = OpenAiCompatible::new("m", "http://x", None, &transport);
    assert!(matches!(
        model.complete("s", "u", &schema()),
        Err(AiError::Invalid(_))
    ));
}

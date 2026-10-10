//! Language models that answer with JSON constrained to a schema.
//!
//! - [`Anthropic`]: the Claude API, called over HTTP (there is no official Rust SDK). Structured
//!   output via `output_config.format`; server-side fallback on safety declines for the models
//!   that support it.
//! - [`OpenAiCompatible`]: any `/chat/completions` endpoint with JSON-schema response formats,
//!   which covers local models in Ollama and LM Studio. Local is the private default: samples
//!   never leave the machine.

use std::time::Duration;

use serde_json::{Value, json};

use crate::error::AiError;

/// A model that answers one prompt with JSON matching `schema`.
pub trait LanguageModel {
    /// A short identifier for reports and caching, such as `anthropic:claude-opus-5-5`.
    fn name(&self) -> String;

    /// Sends one system + user prompt and returns the parsed JSON answer.
    ///
    /// # Errors
    ///
    /// Returns [`AiError`] on transport failure, refusal, truncation or invalid output.
    fn complete(&self, system: &str, user: &str, schema: &Value) -> Result<Value, AiError>;
}

/// How requests leave the process; swapped out in tests.
pub trait Transport {
    /// POSTs a JSON body and returns the response body.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Http`] on connection failure or a non-success status.
    fn post(&self, url: &str, headers: &[(&str, String)], body: &str) -> Result<String, AiError>;
}

/// HTTP transport with a generous timeout: one call per template, never per event.
#[derive(Debug)]
pub struct Http {
    agent: ureq::Agent,
}

impl Default for Http {
    fn default() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(300)))
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl Transport for Http {
    fn post(&self, url: &str, headers: &[(&str, String)], body: &str) -> Result<String, AiError> {
        let mut request = self
            .agent
            .post(url)
            .header("content-type", "application/json");
        for (name, value) in headers {
            request = request.header(*name, value.as_str());
        }
        let mut response = request
            .send(body)
            .map_err(|e| AiError::Http(format!("{url}: {e}")))?;
        let status = response.status();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| AiError::Http(format!("{url}: {e}")))?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(AiError::Http(format!("{url}: HTTP {status}: {text}")))
        }
    }
}

/// Models that accept server-side fallback on a safety decline.
const FALLBACK_MODELS: [&str; 4] = [
    "claude-fable-5-1",
    "claude-opus-5-5",
    "claude-opus-5",
    "claude-sonnet-5-5",
];

/// The Claude API.
pub struct Anthropic<T = Http> {
    model: String,
    credential: Credential,
    base_url: String,
    transport: T,
}

/// How to authenticate to the Claude API.
#[derive(Debug, Clone)]
pub enum Credential {
    /// `x-api-key`.
    ApiKey(String),
    /// `Authorization: Bearer` (for example from `ANTHROPIC_AUTH_TOKEN`).
    Bearer(String),
}

impl Anthropic<Http> {
    /// A client for `model`, reading `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` and, if set,
    /// `ANTHROPIC_BASE_URL`.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Config`] if neither credential variable is set.
    pub fn from_env(model: &str) -> Result<Self, AiError> {
        let credential = match (
            std::env::var("ANTHROPIC_API_KEY"),
            std::env::var("ANTHROPIC_AUTH_TOKEN"),
        ) {
            (Ok(key), _) if !key.is_empty() => Credential::ApiKey(key),
            (_, Ok(token)) if !token.is_empty() => Credential::Bearer(token),
            _ => {
                return Err(AiError::Config(
                    "set ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) to use Claude".into(),
                ));
            }
        };
        let base_url = std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".into());
        Ok(Self::new(model, credential, &base_url, Http::default()))
    }
}

impl<T: Transport> Anthropic<T> {
    /// A client with an explicit credential, base URL and transport.
    pub fn new(model: &str, credential: Credential, base_url: &str, transport: T) -> Self {
        Self {
            model: model.to_owned(),
            credential,
            base_url: base_url.trim_end_matches('/').to_owned(),
            transport,
        }
    }

    fn request(
        &self,
        system: &str,
        user: &str,
        schema: &Value,
    ) -> (Vec<(&'static str, String)>, Value) {
        let mut headers = vec![("anthropic-version", "2023-06-01".to_owned())];
        match &self.credential {
            Credential::ApiKey(key) => headers.push(("x-api-key", key.clone())),
            Credential::Bearer(token) => headers.push(("authorization", format!("Bearer {token}"))),
        }
        let mut body = json!({
            "model": self.model,
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {
                "effort": "medium",
                "format": {"type": "json_schema", "schema": schema}
            }
        });
        if FALLBACK_MODELS.contains(&self.model.as_str()) {
            headers.push((
                "anthropic-beta",
                "server-side-fallback-2026-07-01".to_owned(),
            ));
            body["fallbacks"] = json!("default");
        }
        (headers, body)
    }
}

impl<T: Transport> LanguageModel for Anthropic<T> {
    fn name(&self) -> String {
        format!("anthropic:{}", self.model)
    }

    fn complete(&self, system: &str, user: &str, schema: &Value) -> Result<Value, AiError> {
        let (headers, body) = self.request(system, user, schema);
        let url = format!("{}/v1/messages", self.base_url);
        let header_refs: Vec<(&str, String)> =
            headers.iter().map(|(k, v)| (*k, v.clone())).collect();
        let response: Value =
            parse(&self.transport.post(&url, &header_refs, &body.to_string())?)?;
        match response["stop_reason"].as_str() {
            Some("refusal") => {
                let category = response["stop_details"]["category"]
                    .as_str()
                    .unwrap_or("unspecified");
                return Err(AiError::Refused(category.to_owned()));
            }
            Some("max_tokens") => return Err(AiError::Truncated),
            _ => {}
        }
        // Thinking blocks may precede the answer; the structured output is the text block.
        let text = response["content"]
            .as_array()
            .and_then(|blocks| blocks.iter().find(|b| b["type"] == "text"))
            .and_then(|b| b["text"].as_str())
            .ok_or_else(|| AiError::Invalid("no text block in the response".into()))?;
        parse(text)
    }
}

/// An OpenAI-compatible chat-completions endpoint (Ollama, LM Studio, …).
pub struct OpenAiCompatible<T = Http> {
    model: String,
    base_url: String,
    api_key: Option<String>,
    transport: T,
}

impl OpenAiCompatible<Http> {
    /// Ollama's OpenAI-compatible endpoint on this machine.
    #[must_use]
    pub fn ollama(model: &str) -> Self {
        Self::new(model, "http://localhost:11434/v1", None, Http::default())
    }

    /// LM Studio's server on this machine.
    #[must_use]
    pub fn lm_studio(model: &str) -> Self {
        Self::new(model, "http://localhost:1234/v1", None, Http::default())
    }
}

impl<T: Transport> OpenAiCompatible<T> {
    /// A client for any compatible endpoint.
    pub fn new(model: &str, base_url: &str, api_key: Option<String>, transport: T) -> Self {
        Self {
            model: model.to_owned(),
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            transport,
        }
    }
}

impl<T: Transport> LanguageModel for OpenAiCompatible<T> {
    fn name(&self) -> String {
        format!("openai-compatible:{}@{}", self.model, self.base_url)
    }

    fn complete(&self, system: &str, user: &str, schema: &Value) -> Result<Value, AiError> {
        let body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "sluice_proposal", "strict": true, "schema": schema}
            }
        });
        let headers: Vec<(&str, String)> = self
            .api_key
            .iter()
            .map(|key| ("authorization", format!("Bearer {key}")))
            .collect();
        let url = format!("{}/chat/completions", self.base_url);
        let response: Value = parse(&self.transport.post(&url, &headers, &body.to_string())?)?;
        let choice = &response["choices"][0];
        if choice["finish_reason"] == "length" {
            return Err(AiError::Truncated);
        }
        let message = &choice["message"];
        let text = message["content"]
            .as_str()
            .filter(|t| !t.trim().is_empty())
            // LM Studio with a reasoning model puts the schema-constrained answer in
            // `reasoning_content` and leaves `content` empty (docs/notes/ai.md). It is used only
            // if it parses; the proposal is validated against the schema afterwards anyway.
            .or_else(|| {
                message["reasoning_content"]
                    .as_str()
                    .filter(|t| serde_json::from_str::<Value>(t).is_ok())
            })
            .ok_or_else(|| AiError::Invalid("no message content in the response".into()))?;
        parse(text)
    }
}

fn parse(text: &str) -> Result<Value, AiError> {
    serde_json::from_str(text).map_err(|e| AiError::Invalid(format!("not JSON: {e}")))
}

#[cfg(test)]
mod tests;

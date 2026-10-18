//! Runs an ingest pipeline in a real Elasticsearch, `POST _ingest/pipeline/_simulate`, which is
//! how a generated pipeline is proven before it is written.

use std::time::Duration;

use serde_json::{Map, Value, json};

/// Documents per request.
const BATCH: usize = 200;

/// Longest a request may take.
const TIMEOUT: Duration = Duration::from_secs(300);

/// Largest answer read.
const MAX_ANSWER: u64 = 512 * 1024 * 1024;

/// Elasticsearch or Kibana could not be used, or the pipeline failed on a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElasticError {
    /// No answer.
    #[error("cannot reach {url}: {reason}")]
    Unreachable {
        /// The base URL.
        url: String,
        /// The transport error.
        reason: String,
    },
    /// The request was refused: a script that does not compile, a key without the privilege.
    #[error("{url} answered HTTP {status}: {}", excerpt(.message))]
    Rejected {
        /// The base URL.
        url: String,
        /// HTTP status.
        status: u16,
        /// The whole answer.
        message: String,
    },
    /// The pipeline failed on a document.
    #[error("the pipeline failed on document {index}: {message}")]
    Failed {
        /// Position of the document in the input.
        index: usize,
        /// Elasticsearch's error.
        message: String,
    },
    /// An answer that is not what was asked for.
    #[error("unexpected answer: {0}")]
    Response(String),
}

/// What an error answer says, short enough for a message: Elasticsearch's or Kibana's reason
/// when the answer gives one, otherwise its first 300 characters.
fn excerpt(answer: &str) -> String {
    let reason = serde_json::from_str::<Value>(answer).ok().and_then(|v| {
        v["error"]["reason"]
            .as_str()
            .or_else(|| v["message"].as_str())
            .map(str::to_owned)
    });
    let text = reason.unwrap_or_else(|| answer.to_owned());
    let mut short: String = text.chars().take(300).collect();
    if short.len() < text.len() {
        short.push('…');
    }
    short
}

/// Each document as `pipeline` (a `PUT _ingest/pipeline` body) leaves it, in order. The pipeline
/// runs strictly: `ignore_failure` is turned off, so a script that fails on a document is an
/// error instead of a document passed on unchanged.
///
/// # Errors
///
/// [`ElasticError`] when Elasticsearch is unreachable, refuses the pipeline, or the pipeline
/// fails on a document.
pub fn simulate(
    url: &str,
    pipeline: &Value,
    documents: &[&Map<String, Value>],
) -> Result<Vec<Map<String, Value>>, ElasticError> {
    let mut strict = pipeline.clone();
    if let Some(processors) = strict["processors"].as_array_mut() {
        for processor in processors.iter_mut().filter_map(Value::as_object_mut) {
            for settings in processor.values_mut().filter_map(Value::as_object_mut) {
                settings.insert("ignore_failure".to_owned(), Value::Bool(false));
            }
        }
    }
    let url = url.trim_end_matches('/');
    let client = sluice_http::Client::with(TIMEOUT, false, MAX_ANSWER);
    let mut out = Vec::with_capacity(documents.len());
    for (batch, chunk) in documents.chunks(BATCH).enumerate() {
        let docs: Vec<Value> = chunk
            .iter()
            .map(|d| json!({ "_index": "sluice", "_source": d }))
            .collect();
        let body = json!({ "pipeline": strict, "docs": docs }).to_string();
        let answer = post(&client, url, &body)?;
        let results = answer["docs"]
            .as_array()
            .filter(|r| r.len() == chunk.len())
            .ok_or_else(|| ElasticError::Response(format!("{} documents back", chunk.len())))?;
        for (n, result) in results.iter().enumerate() {
            if let Some(error) = result.get("error") {
                return Err(ElasticError::Failed {
                    index: batch * BATCH + n,
                    message: error.to_string(),
                });
            }
            let source = result["doc"]["_source"]
                .as_object()
                .ok_or_else(|| ElasticError::Response("a document without _source".to_owned()))?;
            out.push(source.clone());
        }
    }
    Ok(out)
}

fn post(client: &sluice_http::Client, url: &str, body: &str) -> Result<Value, ElasticError> {
    let answer = client
        .send(
            "POST",
            &format!("{url}/_ingest/pipeline/_simulate"),
            &[("content-type", "application/json".to_owned())],
            Some(body),
        )
        .map_err(|e| ElasticError::Unreachable {
            url: url.to_owned(),
            reason: e.reason,
        })?;
    if !answer.is_success() {
        return Err(ElasticError::Rejected {
            url: url.to_owned(),
            status: answer.status,
            message: answer.body,
        });
    }
    serde_json::from_str(&answer.body).map_err(|e| ElasticError::Response(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_where_and_says_why_in_short() {
        let kibana = ElasticError::Rejected {
            url: "https://kibana:5601".into(),
            status: 401,
            message: r#"{"statusCode":401,"error":"Unauthorized","message":"bad key"}"#.into(),
        };
        assert_eq!(
            kibana.to_string(),
            "https://kibana:5601 answered HTTP 401: bad key"
        );
        let elastic = ElasticError::Rejected {
            url: "http://es:9200".into(),
            status: 400,
            message: r#"{"error":{"type":"script_exception","reason":"compile error"}}"#.into(),
        };
        assert!(elastic.to_string().ends_with(": compile error"));
        let long = ElasticError::Rejected {
            url: "http://es:9200".into(),
            status: 502,
            message: "x".repeat(10_000),
        };
        assert!(long.to_string().len() < 400, "{long}");
    }
}

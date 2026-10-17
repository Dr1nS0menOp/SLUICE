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

/// Elasticsearch could not be used, or the pipeline failed on a document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElasticError {
    /// No answer from Elasticsearch.
    #[error("Elasticsearch at {url} unreachable: {reason}")]
    Unreachable {
        /// The base URL.
        url: String,
        /// The transport error.
        reason: String,
    },
    /// Elasticsearch refused the request, for example a script that does not compile.
    #[error("Elasticsearch refused the pipeline ({status}): {message}")]
    Rejected {
        /// HTTP status.
        status: u16,
        /// Elasticsearch's error text.
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
    /// Elasticsearch answered something that is not a simulation result.
    #[error("unexpected answer from Elasticsearch: {0}")]
    Response(String),
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
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let mut out = Vec::with_capacity(documents.len());
    for (batch, chunk) in documents.chunks(BATCH).enumerate() {
        let docs: Vec<Value> = chunk
            .iter()
            .map(|d| json!({ "_index": "sluice", "_source": d }))
            .collect();
        let body = json!({ "pipeline": strict, "docs": docs }).to_string();
        let answer = post(&agent, url, &body)?;
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

fn post(agent: &ureq::Agent, url: &str, body: &str) -> Result<Value, ElasticError> {
    let unreachable = |reason: String| ElasticError::Unreachable {
        url: url.to_owned(),
        reason,
    };
    let mut answer = agent
        .post(format!("{url}/_ingest/pipeline/_simulate"))
        .header("content-type", "application/json")
        .send(body)
        .map_err(|e| unreachable(e.to_string()))?;
    let status = answer.status();
    let text = answer
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER)
        .read_to_string()
        .map_err(|e| unreachable(e.to_string()))?;
    if !status.is_success() {
        return Err(ElasticError::Rejected {
            status: status.as_u16(),
            message: text,
        });
    }
    serde_json::from_str(&text).map_err(|e| ElasticError::Response(e.to_string()))
}

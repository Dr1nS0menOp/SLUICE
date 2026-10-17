//! The detection rules a Kibana space runs, read through its API (ADR 0021, ADR 0025):
//! `GET /api/detection_engine/rules/_find`, page by page, written as one `rules.ndjson` that
//! `sluice_rules::ElasticRules` reads. Read-only.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
use sluice_core::inventory::{Inventory, Manifest};

use crate::simulate::ElasticError;

/// Rules per page; Kibana takes up to 10,000, smaller pages keep answers small.
const PAGE: usize = 500;

/// How a request is authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// A Kibana API key, as `Authorization: ApiKey …` takes it (base64 of `id:key`).
    ApiKey(String),
    /// A user and password.
    Basic {
        /// The user.
        user: String,
        /// The password.
        password: String,
    },
}

/// Reads every detection rule of `space` (the default space when `None`) from Kibana at `url`.
/// The inventory is complete only when every page arrived and the count matches Kibana's
/// total.
///
/// # Errors
///
/// [`ElasticError`] when Kibana cannot be reached or refuses a request.
pub fn fetch(
    url: &str,
    auth: &Auth,
    space: Option<&str>,
    fetched_at: &str,
) -> Result<Inventory, ElasticError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into();
    let base = url.trim_end_matches('/');
    let prefix = space.map_or_else(String::new, |s| format!("/s/{s}"));
    let get = |page: usize| -> Result<Value, ElasticError> {
        let target = format!(
            "{base}{prefix}/api/detection_engine/rules/_find?page={page}&per_page={PAGE}&sort_field=rule_id"
        );
        let request = agent
            .get(&target)
            .header("elastic-api-version", "2023-10-31");
        let request = match auth {
            Auth::ApiKey(key) => request.header("authorization", format!("ApiKey {key}")),
            Auth::Basic { user, password } => request.header(
                "authorization",
                format!("Basic {}", base64(&format!("{user}:{password}"))),
            ),
        };
        let mut answer = request.call().map_err(|e| ElasticError::Unreachable {
            url: base.to_owned(),
            reason: e.to_string(),
        })?;
        let status = answer.status();
        let text = answer
            .body_mut()
            .with_config()
            .limit(256 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| ElasticError::Response(e.to_string()))?;
        if !status.is_success() {
            return Err(ElasticError::Rejected {
                status: status.as_u16(),
                message: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| ElasticError::Response(e.to_string()))
    };
    let from = format!("{base}{prefix}");
    collect(get, &from, fetched_at)
}

/// The inventory of every page `get` (by page number from 1) returns.
fn collect(
    mut get: impl FnMut(usize) -> Result<Value, ElasticError>,
    from: &str,
    fetched_at: &str,
) -> Result<Inventory, ElasticError> {
    let mut rules: Vec<Value> = Vec::new();
    let mut total = None;
    for page in 1.. {
        let answer = get(page)?;
        let data = answer["data"]
            .as_array()
            .ok_or_else(|| ElasticError::Response("an answer without `data`".to_owned()))?;
        total = answer["total"]
            .as_u64()
            .and_then(|t| usize::try_from(t).ok());
        rules.extend(data.iter().cloned());
        if data.is_empty() || total.is_some_and(|t| rules.len() >= t) {
            break;
        }
    }
    let mut not_modeled = Vec::new();
    let complete = total == Some(rules.len());
    if !complete {
        not_modeled.push(format!(
            "Kibana reported {} rules but {} were read",
            total.map_or_else(|| "no total of".to_owned(), |t| t.to_string()),
            rules.len()
        ));
    }
    let learning = rules
        .iter()
        .filter(|r| r["type"] == "machine_learning" && r["enabled"] != false)
        .count();
    if learning > 0 {
        not_modeled.push(format!(
            "{learning} enabled machine learning rules: their jobs are not in the rule, so each \
             may read any field and keeps every event whole"
        ));
    }
    let mut body = String::new();
    for rule in &rules {
        body.push_str(&rule.to_string());
        body.push('\n');
    }
    Ok(Inventory {
        files: vec![("rules.ndjson".to_owned(), body)],
        manifest: Manifest {
            system: "elastic".to_owned(),
            from: from.to_owned(),
            fetched_at: fetched_at.to_owned(),
            complete,
            counts: BTreeMap::from([("rules".to_owned(), rules.len())]),
            not_modeled,
        },
    })
}

/// Standard base64, for a basic authorization header.
fn base64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn page(rules: &[&str], total: usize) -> Value {
        json!({
            "page": 1, "perPage": PAGE, "total": total,
            "data": rules.iter().map(|id| json!({"rule_id": id, "type": "query", "query": "a : b"})).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn every_page_is_read_into_one_file() {
        let pages = [page(&["a", "b"], 3), page(&["c"], 3)];
        let inventory = collect(|n| Ok(pages[n - 1].clone()), "http://k", "t").unwrap();
        assert!(inventory.manifest.complete);
        assert_eq!(inventory.manifest.counts["rules"], 3);
        assert_eq!(inventory.files[0].0, "rules.ndjson");
        assert_eq!(inventory.files[0].1.lines().count(), 3);
    }

    #[test]
    fn c3_a_fetch_that_ends_short_is_not_complete() {
        let pages = [page(&["a"], 3), page(&[], 3)];
        let inventory = collect(|n| Ok(pages[n - 1].clone()), "http://k", "t").unwrap();
        assert!(!inventory.manifest.complete);
        assert!(inventory.manifest.not_modeled[0].contains("3 rules but 1"));
    }

    #[test]
    fn enabled_machine_learning_rules_are_noted() {
        let answer = json!({"total": 1, "data": [{"rule_id": "m", "type": "machine_learning", "enabled": true}]});
        let inventory = collect(|_| Ok(answer.clone()), "http://k", "t").unwrap();
        assert!(
            inventory
                .manifest
                .not_modeled
                .iter()
                .any(|n| n.contains("machine learning"))
        );
    }

    #[test]
    fn base64_as_basic_authorization_needs_it() {
        assert_eq!(base64("elastic:changeme"), "ZWxhc3RpYzpjaGFuZ2VtZQ==");
        assert_eq!(base64("ab"), "YWI=");
        assert_eq!(base64("abc"), "YWJj");
    }
}

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
    let client = sluice_http::Client::new(Duration::from_secs(120));
    let base = url.trim_end_matches('/');
    // The space goes into the path as one segment.
    let prefix = space.map_or_else(String::new, |s| {
        format!("/s/{}", sluice_http::percent_encode(s))
    });
    let authorization = match auth {
        Auth::ApiKey(key) => format!("ApiKey {key}"),
        Auth::Basic { user, password } => sluice_http::basic_auth(user, password),
    };
    let get = |page: usize| -> Result<Value, ElasticError> {
        let target = format!(
            "{base}{prefix}/api/detection_engine/rules/_find?page={page}&per_page={PAGE}&sort_field=name&sort_order=asc"
        );
        let headers = [
            ("elastic-api-version", "2023-10-31".to_owned()),
            ("authorization", authorization.clone()),
        ];
        let answer =
            client
                .send("GET", &target, &headers, None)
                .map_err(|e| ElasticError::Unreachable {
                    url: base.to_owned(),
                    reason: e.reason,
                })?;
        if !answer.is_success() {
            return Err(ElasticError::Rejected {
                url: base.to_owned(),
                status: answer.status,
                message: answer.body,
            });
        }
        serde_json::from_str(&answer.body).map_err(|e| ElasticError::Response(e.to_string()))
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
    // By rule id: a rule that moved between pages while they were read is there once.
    let mut by_id: BTreeMap<String, Value> = BTreeMap::new();
    let mut total = None;
    let mut read = 0usize;
    for page in 1.. {
        let answer = get(page)?;
        let data = answer["data"]
            .as_array()
            .ok_or_else(|| ElasticError::Response("an answer without `data`".to_owned()))?;
        total = answer["total"]
            .as_u64()
            .and_then(|t| usize::try_from(t).ok());
        read += data.len();
        let known = by_id.len();
        for rule in data {
            let id = rule["rule_id"]
                .as_str()
                .or_else(|| rule["id"].as_str())
                .map_or_else(|| format!("#{}", by_id.len()), str::to_owned);
            by_id.insert(id, rule.clone());
        }
        // A page of rules already read also ends it: a Kibana that ignores `page` and gives no
        // total would otherwise be asked forever. The count then decides completeness.
        if data.is_empty() || by_id.len() == known || total.is_some_and(|t| read >= t) {
            break;
        }
    }
    let rules: Vec<Value> = by_id.into_values().collect();
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
    fn c3_a_rule_read_twice_while_pages_shift_does_not_make_a_fetch_complete() {
        // A rule moved to the next page: `c` is read twice and `b` never.
        let pages = [page(&["a", "c"], 3), page(&["c"], 3)];
        let inventory = collect(|n| Ok(pages[n - 1].clone()), "http://k", "t").unwrap();
        assert_eq!(inventory.manifest.counts["rules"], 2);
        assert!(!inventory.manifest.complete);
    }

    #[test]
    fn a_kibana_that_ignores_the_page_and_gives_no_total_ends_the_fetch() {
        let answer = json!({"data": [{"rule_id": "a", "type": "query", "query": "a : b"}]});
        let inventory = collect(|_| Ok(answer.clone()), "http://k", "t").unwrap();
        assert_eq!(inventory.manifest.counts["rules"], 1);
        assert!(
            !inventory.manifest.complete,
            "no total to check the count against"
        );
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
}

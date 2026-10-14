//! What a Sentinel workspace runs, as rule files.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sluice_core::inventory::{Inventory, Manifest, file_name};

use crate::azure::{ARM, Client, Credentials, LOG_ANALYTICS, SentinelError, Transport};

/// The `alertRules` API version (Microsoft.SecurityInsights, stable).
const ALERT_RULES_API: &str = "2024-09-01";
/// The `savedSearches` API version (Microsoft.OperationalInsights).
const SAVED_SEARCHES_API: &str = "2020-08-01";
/// The workspace API version, for its `customerId`.
const WORKSPACE_API: &str = "2022-10-01";
/// The most distinct queries read from the query log.
const MAX_LOGGED_QUERIES: usize = 5_000;

/// What to read.
#[derive(Debug, Clone)]
pub struct Options {
    /// The Log Analytics workspace's resource id
    /// (`/subscriptions/…/resourceGroups/…/providers/Microsoft.OperationalInsights/workspaces/…`).
    pub workspace: String,
    /// Also read every saved search, not only hunting queries and functions. Most workspaces
    /// carry dozens of example searches nobody runs; the query log is the better source.
    pub all_saved_searches: bool,
    /// Read the distinct queries of this many days from `LAQueryLogs` (query auditing must be
    /// enabled on the workspace).
    pub query_log_days: Option<u32>,
    /// When, as RFC 3339, for the manifest.
    pub fetched_at: String,
}

/// Reads the workspace's inventory.
///
/// # Errors
///
/// Returns [`SentinelError`] if the workspace id is malformed, a token cannot be obtained, or
/// an API cannot be read. Nothing is returned half-read: an inventory that is returned is
/// complete.
pub fn fetch(
    transport: &impl Transport,
    credentials: &Credentials,
    options: &Options,
) -> Result<Inventory, SentinelError> {
    let workspace = workspace_id(&options.workspace)?;
    let arm = Client::new(transport, credentials, ARM)?;
    let mut out = Out::new(options);

    let rules = arm.list(&format!(
        "{ARM}{workspace}/providers/Microsoft.SecurityInsights/alertRules?api-version={ALERT_RULES_API}"
    ))?;
    for rule in &rules {
        out.alert_rule(rule)?;
    }
    let searches = arm.list(&format!(
        "{ARM}{workspace}/savedSearches?api-version={SAVED_SEARCHES_API}"
    ))?;
    for search in &searches {
        out.saved_search(search, options.all_saved_searches);
    }
    if let Some(days) = options.query_log_days {
        let customer_id = arm.get(&format!("{ARM}{workspace}?api-version={WORKSPACE_API}"))?
            ["properties"]["customerId"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| SentinelError::Invalid("the workspace has no customerId".into()))?;
        let logs = Client::new(transport, credentials, LOG_ANALYTICS)?;
        let queries = logged_queries(&logs, &customer_id, days)?;
        if queries.is_empty() {
            out.inventory.manifest.not_modeled.push(format!(
                "the query log has no queries for the last {days} days: is query auditing \
                 enabled on the workspace (diagnostic setting \"Audit\")?"
            ));
        }
        out.inventory
            .manifest
            .counts
            .insert("queries".to_owned(), 0);
        for query in queries {
            out.logged_query(&query);
        }
    }
    Ok(out.inventory)
}

/// Checks the shape of a workspace resource id and returns it without a trailing `/`.
fn workspace_id(id: &str) -> Result<&str, SentinelError> {
    let id = id.trim_end_matches('/');
    let parts: Vec<&str> = id.split('/').collect();
    let valid = parts.len() == 9
        && parts[0].is_empty()
        && parts[1].eq_ignore_ascii_case("subscriptions")
        && parts[3].eq_ignore_ascii_case("resourceGroups")
        && parts[5].eq_ignore_ascii_case("providers")
        && parts[6].eq_ignore_ascii_case("Microsoft.OperationalInsights")
        && parts[7].eq_ignore_ascii_case("workspaces")
        && parts.iter().skip(1).all(|p| {
            !p.is_empty()
                && !p.chars().all(|c| c == '.')
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '(' | ')'))
        });
    if valid {
        Ok(id)
    } else {
        Err(SentinelError::Invalid(format!(
            "not a Log Analytics workspace resource id: {id}"
        )))
    }
}

/// The distinct queries that succeeded in the last `days` days, most-run first.
fn logged_queries<T: Transport>(
    logs: &Client<'_, T>,
    customer_id: &str,
    days: u32,
) -> Result<Vec<String>, SentinelError> {
    let query = format!(
        "LAQueryLogs | where TimeGenerated > ago({days}d) and ResponseCode == 200 \
         | summarize Runs = count() by QueryText | top {MAX_LOGGED_QUERIES} by Runs desc"
    );
    let result = logs.post(
        &format!(
            "{LOG_ANALYTICS}/v1/workspaces/{}/query",
            crate::azure::encode(customer_id)
        ),
        &json!({ "query": query }),
    )?;
    let table = &result["tables"][0];
    let column = table["columns"]
        .as_array()
        .and_then(|c| c.iter().position(|c| c["name"] == "QueryText"))
        .ok_or_else(|| SentinelError::Invalid("no QueryText column in the query log".into()))?;
    Ok(table["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row[column].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default())
}

/// The inventory being built.
struct Out {
    inventory: Inventory,
}

impl Out {
    fn new(options: &Options) -> Self {
        Self {
            inventory: Inventory {
                files: Vec::new(),
                manifest: Manifest {
                    system: "sentinel".to_owned(),
                    from: options.workspace.trim_end_matches('/').to_owned(),
                    fetched_at: options.fetched_at.clone(),
                    complete: true,
                    counts: BTreeMap::new(),
                    not_modeled: Vec::new(),
                },
            },
        }
    }

    fn write(&mut self, kind: &str, name: &str, document: &Value) {
        let text = serde_json::to_string_pretty(document).unwrap_or_default() + "\n";
        let mut path = format!("{kind}/{}.yaml", file_name(name));
        // Names are unique per kind in Azure, but file_name() can make two equal.
        let mut n = 1;
        while self.inventory.files.iter().any(|(p, _)| *p == path) {
            n += 1;
            path = format!("{kind}/{}-{n}.yaml", file_name(name));
        }
        self.inventory.files.push((path, text));
        *self
            .inventory
            .manifest
            .counts
            .entry(kind.to_owned())
            .or_default() += 1;
    }

    fn count(&mut self, what: &str) {
        *self
            .inventory
            .manifest
            .counts
            .entry(what.to_owned())
            .or_default() += 1;
    }

    fn alert_rule(&mut self, rule: &Value) -> Result<(), SentinelError> {
        let properties = &rule["properties"];
        let kind = rule["kind"].as_str().unwrap_or("unknown");
        let id = rule["name"]
            .as_str()
            .ok_or_else(|| SentinelError::Invalid("an alert rule without a name".into()))?;
        let display = properties["displayName"].as_str().unwrap_or(id);
        if properties["enabled"] != json!(true) {
            self.count("disabled");
            return Ok(());
        }
        match (kind, properties["query"].as_str()) {
            ("Scheduled" | "NRT", Some(query)) => self.write(
                "rules",
                id,
                &json!({ "id": id, "name": display, "kind": kind, "query": query }),
            ),
            ("Fusion" | "MicrosoftSecurityIncidentCreation", _) => {
                self.inventory.manifest.not_modeled.push(format!(
                    "{kind} rule \"{display}\": correlates alerts, reads no records"
                ));
            }
            _ => {
                // No query to read (machine learning, threat intelligence matching, or a kind
                // this version does not know): read as reading every record (fail closed).
                self.inventory.manifest.not_modeled.push(format!(
                    "{kind} rule \"{display}\": no query; read as reading every record"
                ));
                self.write(
                    "rules",
                    id,
                    &json!({
                        "id": id,
                        "name": display,
                        "kind": kind,
                        "query": "search *",
                        "sluiceStandIn": format!("{kind} has no query; `search *` stands in for it"),
                    }),
                );
            }
        }
        Ok(())
    }

    fn saved_search(&mut self, search: &Value, all: bool) {
        let properties = &search["properties"];
        let Some(query) = properties["query"].as_str() else {
            return;
        };
        let name = search["name"].as_str().unwrap_or("unnamed");
        let display = properties["displayName"].as_str().unwrap_or(name);
        let category = properties["category"].as_str().unwrap_or_default();
        if let Some(alias) = properties["functionAlias"]
            .as_str()
            .filter(|a| !a.is_empty())
        {
            self.write(
                "functions",
                alias,
                &json!({ "FunctionName": alias, "FunctionQuery": query }),
            );
        } else if all || category.eq_ignore_ascii_case("Hunting Queries") {
            let id = format!("saved-{name}");
            self.write(
                "saved",
                name,
                &json!({ "id": id, "name": display, "category": category, "query": query }),
            );
        } else {
            self.count("saved_searches_not_read");
        }
    }

    fn logged_query(&mut self, query: &str) {
        let id = format!("query-{:016x}", fnv1a(query));
        self.write("queries", &id, &json!({ "id": id, "query": query }));
    }
}

/// FNV-1a, 64 bits: a stable id for a query text.
fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests;

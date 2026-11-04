//! The saved searches and macros a Splunk runs, and the fields it derives, read through its
//! REST API (ADR 0021, ADR 0026): `saved/searches`, `admin/macros`, `configs/conf-props` and
//! `configs/conf-transforms` of every app (`servicesNS/-/-`), page by page, written as the
//! JSON answers `sluice_rules::SplunkRules` reads. Read-only.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Value, json};
use sluice_core::inventory::{Inventory, Manifest};

use crate::SplunkError;
pub use crate::client::Auth;
use crate::client::Rest;

/// Entries per page.
const PAGE: usize = 500;

/// Where and how to read.
#[derive(Debug, Clone)]
pub struct Target<'a> {
    /// The management port, such as `https://splunk:8089`.
    pub url: &'a str,
    /// The credentials.
    pub auth: &'a Auth,
    /// Accept a self-signed certificate (Splunk's default). Only on a trusted network path.
    pub insecure: bool,
}

/// The collections read, and the file each is written to.
const COLLECTIONS: [(&str, &str, &str); 4] = [
    ("saved/searches", "saved-searches.json", "searches"),
    ("admin/macros", "macros.json", "macros"),
    ("configs/conf-props", "props.json", "props stanzas"),
    ("configs/conf-transforms", "transforms.json", "transforms"),
];

/// Reads every saved search and macro visible to the user. The inventory is complete only
/// when every page arrived and each count matches Splunk's total.
///
/// # Errors
///
/// [`SplunkError`] when Splunk cannot be reached or refuses a request.
pub fn fetch(target: &Target<'_>, fetched_at: &str) -> Result<Inventory, SplunkError> {
    let rest = Rest::new(
        target.url,
        target.auth,
        target.insecure,
        Duration::from_secs(120),
    );
    let get = |collection: &str, offset: usize| -> Result<Value, SplunkError> {
        rest.json(
            "GET",
            &format!("/servicesNS/-/-/{collection}?count={PAGE}&offset={offset}"),
            &[],
        )
    };
    collect(get, rest.base(), fetched_at)
}

/// The inventory of every page `get` (by collection and offset) returns.
fn collect(
    mut get: impl FnMut(&str, usize) -> Result<Value, SplunkError>,
    from: &str,
    fetched_at: &str,
) -> Result<Inventory, SplunkError> {
    let mut files = Vec::new();
    let mut counts = BTreeMap::new();
    let mut not_modeled = Vec::new();
    for (collection, file, kind) in COLLECTIONS {
        let (entries, total) = pages(&mut get, collection)?;
        if total != Some(entries.len()) {
            not_modeled.push(format!(
                "Splunk reported {} {kind} but {} were read",
                total.map_or_else(|| "no total of".to_owned(), |t| t.to_string()),
                entries.len()
            ));
        }
        counts.insert(kind.to_owned(), entries.len());
        files.push((file.to_owned(), json!({ "entry": entries }).to_string()));
    }
    let complete = not_modeled.is_empty();
    not_modeled.push(
        "automatic extraction (`KV_MODE`) is not read: declare a source `schema: splunk` only \
         when Splunk extracts its JSON keys as they are (`KV_MODE = json`)"
            .to_owned(),
    );
    Ok(Inventory {
        files,
        manifest: Manifest {
            system: "splunk".to_owned(),
            from: from.to_owned(),
            fetched_at: fetched_at.to_owned(),
            complete,
            counts,
            not_modeled,
        },
    })
}

/// Every entry of `collection`, reduced to what Sluice reads (name, app, settings), and the
/// total Splunk reported.
fn pages(
    get: &mut impl FnMut(&str, usize) -> Result<Value, SplunkError>,
    collection: &str,
) -> Result<(Vec<Value>, Option<usize>), SplunkError> {
    let mut entries = Vec::new();
    loop {
        let answer = get(collection, entries.len())?;
        let page = answer["entry"]
            .as_array()
            .ok_or_else(|| SplunkError::Response(format!("{collection} without `entry`")))?;
        let total = answer
            .pointer("/paging/total")
            .and_then(Value::as_u64)
            .and_then(|t| usize::try_from(t).ok());
        entries.extend(page.iter().map(|entry| {
            json!({
                "name": entry["name"],
                "acl": { "app": entry.pointer("/acl/app").cloned().unwrap_or(Value::Null) },
                "content": entry["content"],
            })
        }));
        if page.is_empty() || total.is_none_or(|t| entries.len() >= t) {
            return Ok((entries, total));
        }
    }
}

#[cfg(test)]
mod tests;

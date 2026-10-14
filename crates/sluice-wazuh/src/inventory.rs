//! The rule and decoder files a Wazuh manager loads, read over its API (ADR 0021).
//!
//! `GET /rules/files?status=enabled` and `GET /decoders/files?status=enabled` list the files the
//! manager loads, with their directory (`ruleset/rules`, `etc/rules`, …); `GET
//! /rules/files/{filename}?raw=true&relative_dirname=…` returns one as it is on disk. The files
//! are written under `rules/` and `decoders/` with their directories, the layout
//! `--wazuh-rules DIR/rules --wazuh-decoders DIR/decoders` reads.

use std::collections::BTreeMap;

use serde_json::Value;
use sluice_core::inventory::{Inventory, Manifest, is_safe_relative_path};

use crate::client::{Transport, WazuhError, basic_auth, excerpt, ok_json};

/// Files per listing request; the API allows up to 100,000.
const PAGE: u64 = 500;

/// Reads the enabled rule and decoder files of the manager at `url` as `user`.
///
/// `fetched_at` (RFC 3339) is recorded in the manifest. A file whose name or directory would
/// leave the inventory directory is skipped, and the inventory is then not complete.
///
/// # Errors
///
/// Returns [`WazuhError`] if the API cannot be used or answers in an unexpected shape.
pub fn fetch(
    transport: &impl Transport,
    url: &str,
    user: &str,
    password: &str,
    fetched_at: &str,
) -> Result<Inventory, WazuhError> {
    let api = Api {
        transport,
        base: url.trim_end_matches('/'),
        jwt: authenticate(transport, url.trim_end_matches('/'), user, password)?,
    };
    let mut inventory = Inventory {
        manifest: Manifest {
            system: "wazuh".to_owned(),
            from: url.to_owned(),
            fetched_at: fetched_at.to_owned(),
            complete: true,
            counts: BTreeMap::new(),
            not_modeled: Vec::new(),
        },
        ..Inventory::default()
    };
    for kind in ["rules", "decoders"] {
        let mut written = 0;
        for (dirname, filename) in api.list(kind)? {
            let path = format!("{kind}/{dirname}/{filename}");
            if !is_safe_relative_path(&path) || filename.contains('/') {
                inventory.manifest.complete = false;
                inventory.manifest.not_modeled.push(format!(
                    "{kind} file {dirname}/{filename}: unsafe name, skipped"
                ));
                continue;
            }
            let text = api.file(kind, &dirname, &filename)?;
            inventory.files.push((path, text));
            written += 1;
        }
        inventory.manifest.counts.insert(kind.to_owned(), written);
    }
    Ok(inventory)
}

struct Api<'a, T> {
    transport: &'a T,
    base: &'a str,
    jwt: String,
}

impl<T: Transport> Api<'_, T> {
    fn get(&self, path_and_query: &str) -> Result<(u16, String), WazuhError> {
        self.transport.send(
            "GET",
            &format!("{}{path_and_query}", self.base),
            &[("authorization", format!("Bearer {}", self.jwt))],
            None,
        )
    }

    /// Every enabled file of `kind` (`rules` or `decoders`), as `(relative_dirname, filename)`.
    ///
    /// The listing must add up to the total the API reports: a missing total, or a listing
    /// that comes up short or long, fails rather than passing as complete.
    fn list(&self, kind: &str) -> Result<Vec<(String, String)>, WazuhError> {
        let mut files = Vec::new();
        let mut offset = 0;
        let total = loop {
            let (status, body) = self.get(&format!(
                "/{kind}/files?status=enabled&limit={PAGE}&offset={offset}"
            ))?;
            let data = &ok_json(status, &body)?["data"];
            let items = data["affected_items"].as_array().ok_or_else(|| {
                WazuhError::Invalid(format!("no data.affected_items listing {kind} files"))
            })?;
            for item in items {
                let field = |name: &str| {
                    item[name]
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| WazuhError::Invalid(format!("a {kind} file without {name}")))
                };
                files.push((field("relative_dirname")?, field("filename")?));
            }
            offset += PAGE;
            let total = data["total_affected_items"].as_u64().ok_or_else(|| {
                WazuhError::Invalid(format!("no data.total_affected_items listing {kind} files"))
            })?;
            if items.is_empty() || offset >= total {
                break total;
            }
        };
        if u64::try_from(files.len()).ok() != Some(total) {
            return Err(WazuhError::Invalid(format!(
                "listed {} {kind} files of {total}; did the ruleset change while it was read?",
                files.len()
            )));
        }
        Ok(files)
    }

    /// One file's contents, as the manager has it on disk.
    fn file(&self, kind: &str, dirname: &str, filename: &str) -> Result<String, WazuhError> {
        let (status, body) = self.get(&format!(
            "/{kind}/files/{}?raw=true&relative_dirname={}",
            encode(filename),
            encode(dirname)
        ))?;
        if !(200..300).contains(&status) {
            return Err(WazuhError::Http(format!(
                "HTTP {status} reading {kind} file {dirname}/{filename}: {}",
                excerpt(&body)
            )));
        }
        // An error comes back as JSON even with `raw=true`.
        if serde_json::from_str::<Value>(&body).is_ok_and(|v| v.get("error").is_some()) {
            return Err(WazuhError::Invalid(format!(
                "reading {kind} file {dirname}/{filename}: {}",
                excerpt(&body)
            )));
        }
        Ok(body)
    }
}

fn authenticate(
    transport: &impl Transport,
    base: &str,
    user: &str,
    password: &str,
) -> Result<String, WazuhError> {
    let (status, body) = transport.send(
        "POST",
        &format!("{base}/security/user/authenticate"),
        &[("authorization", basic_auth(user, password))],
        None,
    )?;
    ok_json(status, &body)?["data"]["token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| WazuhError::Invalid("no data.token in the authentication response".into()))
}

/// Percent-encodes a query or path value: everything but unreserved characters.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;

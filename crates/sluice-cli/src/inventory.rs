//! `sluice rules fetch`: a SIEM's rule inventory, written to a directory (ADR 0021).

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use sluice_core::inventory::{Inventory, MANIFEST_FILE, Manifest, is_safe_relative_path};

use crate::cli::{FetchArgs, FetchTarget};

pub(crate) fn fetch(args: &FetchArgs) -> Result<()> {
    let Some(out) = &args.out else {
        bail!("--out DIR is required: the directory the rules are written to");
    };
    let fetched_at = now_rfc3339();
    let (inventory, next) = match &args.target {
        FetchTarget::Sentinel {
            workspace,
            all_saved_searches,
            query_log_days,
        } => {
            let credentials = sluice_sentinel::Credentials {
                tenant: env("AZURE_TENANT_ID")?,
                client_id: env("AZURE_CLIENT_ID")?,
                client_secret: env("AZURE_CLIENT_SECRET")?,
            };
            let options = sluice_sentinel::Options {
                workspace: workspace.clone(),
                all_saved_searches: *all_saved_searches,
                query_log_days: *query_log_days,
                fetched_at,
            };
            let inventory =
                sluice_sentinel::fetch(&sluice_sentinel::Http::default(), &credentials, &options)?;
            (inventory, format!("--sentinel-rules {}", out.display()))
        }
        FetchTarget::Wazuh {
            api,
            user,
            insecure,
        } => {
            let password = env("WAZUH_API_PASSWORD")?;
            let inventory = sluice_wazuh::inventory::fetch(
                &sluice_wazuh::Http::new(*insecure),
                api,
                user,
                &password,
                &fetched_at,
            )?;
            (
                inventory,
                format!(
                    "--wazuh-rules {} --wazuh-decoders {}",
                    out.join("rules").display(),
                    out.join("decoders").display()
                ),
            )
        }
        FetchTarget::Elastic { kibana, space } => {
            let auth = match std::env::var("KIBANA_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
            {
                Some(key) => sluice_elastic::inventory::Auth::ApiKey(key),
                None => sluice_elastic::inventory::Auth::Basic {
                    user: env("KIBANA_USER")?,
                    password: env("KIBANA_PASSWORD")?,
                },
            };
            let inventory =
                sluice_elastic::inventory::fetch(kibana, &auth, space.as_deref(), &fetched_at)?;
            (inventory, format!("--elastic-rules {}", out.display()))
        }
        FetchTarget::Splunk { api, insecure } => (
            splunk(api, *insecure, &fetched_at)?,
            format!("--splunk-rules {}", out.display()),
        ),
    };
    write(&inventory, out)?;
    let counts: Vec<String> = inventory
        .manifest
        .counts
        .iter()
        .map(|(kind, n)| format!("{n} {kind}"))
        .collect();
    println!(
        "fetched from {}: {}",
        inventory.manifest.from,
        counts.join(", ")
    );
    for note in &inventory.manifest.not_modeled {
        println!("  note: {note}");
    }
    if inventory.manifest.complete {
        println!("wrote {} (complete); use {next}", out.display());
    } else {
        println!(
            "wrote {} (NOT complete: see the notes); use {next}",
            out.display()
        );
    }
    Ok(())
}

/// Splunk's saved searches and macros, with `SPLUNK_TOKEN` or `SPLUNK_USER` and
/// `SPLUNK_PASSWORD`.
fn splunk(api: &str, insecure: bool, fetched_at: &str) -> Result<Inventory> {
    use sluice_splunk::inventory::{Auth, Target};
    let auth = match std::env::var("SPLUNK_TOKEN").ok().filter(|t| !t.is_empty()) {
        Some(token) => Auth::Token(token),
        None => Auth::Basic {
            user: env("SPLUNK_USER")?,
            password: env("SPLUNK_PASSWORD")?,
        },
    };
    let target = Target {
        url: api,
        auth: &auth,
        insecure,
    };
    Ok(sluice_splunk::inventory::fetch(&target, fetched_at)?)
}

/// Writes `inventory` to `out`: a new or empty directory, or an earlier fetch, which is
/// replaced. Any other directory is refused, so a fetch never deletes the operator's files.
///
/// The fetch is written next to `out` first and then renamed into place, so a reader (`sluice
/// up --reload-rules`) never sees half of one: only the old fetch, the new one, or for a moment
/// none.
pub(crate) fn write(inventory: &Inventory, out: &Path) -> Result<()> {
    if let Some((path, _)) = inventory
        .files
        .iter()
        .find(|(path, _)| !is_safe_relative_path(path))
    {
        bail!("refusing to write outside {}: {path}", out.display());
    }
    let replace = if out.exists() {
        let empty = fs::read_dir(out)
            .with_context(|| format!("reading {}", out.display()))?
            .next()
            .is_none();
        if !empty && manifest(out).is_none() {
            bail!(
                "{} is not empty and holds no {MANIFEST_FILE}; fetch into a new directory",
                out.display()
            );
        }
        true
    } else {
        false
    };
    let beside = |what: &str| {
        let name = out
            .file_name()
            .map_or_else(|| "inventory".into(), |n| n.to_string_lossy());
        out.with_file_name(format!(".{name}.{what}-{}", std::process::id()))
    };
    let staging = beside("fetching");
    if staging.exists() {
        fs::remove_dir_all(&staging).with_context(|| format!("clearing {}", staging.display()))?;
    }
    for (path, text) in &inventory.files {
        crate::output::write(&staging.join(path), text)?;
    }
    let manifest = serde_json::to_string_pretty(&inventory.manifest)? + "\n";
    crate::output::write(&staging.join(MANIFEST_FILE), &manifest)?;
    if replace {
        let old = beside("replaced");
        fs::rename(out, &old).with_context(|| format!("replacing {}", out.display()))?;
        fs::rename(&staging, out).with_context(|| format!("writing {}", out.display()))?;
        fs::remove_dir_all(&old).with_context(|| format!("removing {}", old.display()))
    } else {
        fs::rename(&staging, out).with_context(|| format!("writing {}", out.display()))
    }
}

/// The manifest of a fetched inventory in `dir`, if there is one.
pub(crate) fn manifest(dir: &Path) -> Option<Manifest> {
    let text = fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// The manifest of the fetched inventory `dir` belongs to: in `dir` itself, or in the
/// directory a fetch wrote it into (`OUT/rules` → `OUT`).
pub(crate) fn find_manifest(dir: &Path) -> Option<Manifest> {
    [Some(dir), dir.parent()]
        .into_iter()
        .flatten()
        .find_map(manifest)
}

/// Whether `dir` belongs to a complete fetched inventory.
pub(crate) fn is_complete(dir: &Path) -> bool {
    find_manifest(dir).is_some_and(|m| m.complete)
}

fn env(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .with_context(|| format!("{name} is not set"))
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap_or(0), 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sluice-inventory-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn inventory(complete: bool) -> Inventory {
        Inventory {
            files: vec![("rules/a.yaml".into(), "{}\n".into())],
            manifest: Manifest {
                system: "sentinel".into(),
                from: "ws".into(),
                fetched_at: "2026-10-14T00:00:00Z".into(),
                complete,
                counts: BTreeMap::new(),
                not_modeled: Vec::new(),
            },
        }
    }

    #[test]
    fn a_fetch_is_written_with_its_manifest_and_found_from_a_subdirectory() {
        let out = scratch("write");
        write(&inventory(true), &out).unwrap();
        assert!(out.join("rules/a.yaml").is_file());
        assert!(is_complete(&out));
        assert!(is_complete(&out.join("rules")));
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn an_incomplete_fetch_does_not_count_as_complete() {
        let out = scratch("incomplete");
        write(&inventory(false), &out).unwrap();
        assert!(!is_complete(&out));
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn a_directory_of_the_operators_own_files_is_never_replaced() {
        let out = scratch("foreign");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("mine.yaml"), "x").unwrap();
        assert!(write(&inventory(true), &out).is_err());
        assert!(out.join("mine.yaml").is_file());
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn an_earlier_fetch_is_replaced_whole() {
        let out = scratch("refetch");
        let mut first = inventory(true);
        first.files.push(("rules/gone.yaml".into(), "{}\n".into()));
        write(&first, &out).unwrap();
        write(&inventory(true), &out).unwrap();
        assert!(!out.join("rules/gone.yaml").exists());
        // Nothing of the staging is left beside it.
        let name = out.file_name().unwrap().to_string_lossy().into_owned();
        let leftovers: Vec<_> = fs::read_dir(out.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".{name}."))
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn a_path_outside_the_directory_is_refused() {
        let out = scratch("escape");
        let mut hostile = inventory(true);
        hostile.files.push(("../escaped.yaml".into(), "{}".into()));
        assert!(write(&hostile, &out).is_err());
        assert!(!out.parent().unwrap().join("escaped.yaml").exists());
        let _ = fs::remove_dir_all(&out);
    }
}

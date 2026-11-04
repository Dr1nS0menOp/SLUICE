//! `sluice rules fetch`: a SIEM's rule inventory, written to a directory (ADR 0021).

use std::fs;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use sluice_core::inventory::{Inventory, MANIFEST_FILE, Manifest, is_safe_relative_path};

use crate::cli::{FetchArgs, FetchTarget};
use crate::stdout::out;

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
            use sluice_elastic::inventory::Auth;
            let auth = match token_or_login("KIBANA_API_KEY", "KIBANA_USER", "KIBANA_PASSWORD")? {
                Credential::Token(key) => Auth::ApiKey(key),
                Credential::Login { user, password } => Auth::Basic { user, password },
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
    out!(
        "fetched from {}: {}",
        inventory.manifest.from,
        counts.join(", ")
    );
    for note in &inventory.manifest.not_modeled {
        out!("  note: {note}");
    }
    if inventory.manifest.complete {
        out!("wrote {} (complete); use {next}", out.display());
    } else {
        out!(
            "wrote {} (NOT complete: see the notes); use {next}",
            out.display()
        );
    }
    Ok(())
}

/// Splunk's saved searches and macros, with `SPLUNK_TOKEN` or `SPLUNK_USER` and
/// `SPLUNK_PASSWORD`.
fn splunk(api: &str, insecure: bool, fetched_at: &str) -> Result<Inventory> {
    use sluice_splunk::Auth;
    let auth = match token_or_login("SPLUNK_TOKEN", "SPLUNK_USER", "SPLUNK_PASSWORD")? {
        Credential::Token(token) => Auth::Token(token),
        Credential::Login { user, password } => Auth::Basic { user, password },
    };
    let target = sluice_splunk::inventory::Target {
        url: api,
        auth: &auth,
        insecure,
    };
    Ok(sluice_splunk::inventory::fetch(&target, fetched_at)?)
}

/// The credentials of the Splunk the proof runs in (`--splunk`): `SPLUNK_PROOF_TOKEN`, or
/// `SPLUNK_PROOF_PASSWORD` for `SPLUNK_PROOF_USER` (`admin` by default). Variables of their own,
/// so that the read-only account the fetch uses never goes to the proof's Splunk, nor the
/// proof's account to the SIEM.
pub(crate) fn splunk_proof_auth() -> Result<sluice_splunk::Auth> {
    use sluice_splunk::Auth;
    if let Some(token) = var("SPLUNK_PROOF_TOKEN") {
        return Ok(Auth::Token(token));
    }
    let Some(password) = var("SPLUNK_PROOF_PASSWORD") else {
        bail!(
            "set SPLUNK_PROOF_PASSWORD (the password of the proof's Splunk, for \
             SPLUNK_PROOF_USER, `admin` by default) or SPLUNK_PROOF_TOKEN"
        );
    };
    Ok(Auth::Basic {
        user: var("SPLUNK_PROOF_USER").unwrap_or_else(|| "admin".to_owned()),
        password,
    })
}

/// Writes `inventory` to `out`: a new or empty directory, or an earlier fetch, which is
/// replaced. Any other directory is refused, so a fetch never deletes the operator's files.
///
/// The fetch is written next to `out` first and then renamed into place, so an analysis reading
/// `out` meanwhile, or a fetch that fails halfway, never leaves half of one: only the old fetch,
/// the new one, or for a moment none.
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
    var(name).with_context(|| format!("{name} is not set"))
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// A token, or else a user and password, from the environment.
enum Credential {
    Token(String),
    Login { user: String, password: String },
}

/// The credential in the environment variable `token`, or in `user` and `password`; the error
/// names both ways.
fn token_or_login(token: &str, user: &str, password: &str) -> Result<Credential> {
    if let Some(token) = var(token) {
        return Ok(Credential::Token(token));
    }
    match (var(user), var(password)) {
        (Some(user), Some(password)) => Ok(Credential::Login { user, password }),
        _ => bail!("set {token}, or {user} and {password}"),
    }
}

fn now_rfc3339() -> String {
    chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
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

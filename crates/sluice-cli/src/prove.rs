//! `sluice prove`: the proof for a configuration under review, for CI (M11).
//!
//! The reductions are read from the configuration itself (`sluice_vector::deployed`), run on a
//! sample with the `vrl` crate, and the rules' alerts on the full sample are compared with
//! their alerts on what the configuration forwards. The command fails when they differ, so a
//! pull request that would change a detection cannot pass.

use anyhow::{Context, Result, bail};
use serde_json::json;
use sluice_autopilot::EMPTY_PROOF;
use sluice_core::alert::{Engines, RuleEngine};
use sluice_core::proof::prove as run_proof;
use sluice_rules::SigmaRules;

use crate::cli::ProveArgs;
use crate::input;

pub(crate) fn prove(args: &ProveArgs) -> Result<()> {
    let sources = input::sources(&args.sources)?;
    let events = input::events(&args.input, &sources)?;
    let yaml = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let sigma_files = match &args.rules {
        Some(dir) => input::files(dir, &["yml", "yaml"])?,
        None => Vec::new(),
    };
    let sigma = SigmaRules::parse_with(
        sigma_files.iter().map(|(_, text)| text.as_str()),
        &input::sigma_pipelines(&args.sigma_pipeline)?,
    )?;
    let sigma_engine = sigma.engine(&sources)?;
    let sentinel = input::sentinel(args.sentinel_rules.as_deref(), &args.sentinel_table)?;
    let kusto = match (&sentinel, &args.kusto) {
        (Some(rules), Some(url)) => Some(crate::engines::kusto(
            url,
            rules,
            &args.sentinel_table,
            &events,
        )?),
        _ => None,
    };
    if sigma.requirements().is_empty() && kusto.is_none() {
        match &args.rules {
            Some(dir) => bail!(
                "{} holds no Sigma rule to prove against (see the warnings), and no \
                 --sentinel-rules with --kusto were given",
                dir.display()
            ),
            None => {
                bail!("no rules to prove against: give --rules, or --sentinel-rules with --kusto")
            }
        }
    }
    let mut engines: Vec<&dyn RuleEngine> = vec![&sigma_engine];
    engines.extend(kusto.as_ref().map(|k| k as &dyn RuleEngine));
    let (proof, unreduced) = proof_of(&yaml, &sources, &events, &Engines(engines))
        .with_context(|| format!("proving {}", args.config.display()))?;

    print(args, &proof, &unreduced)?;
    let empty = proof.full_alerts.is_empty();
    if !args.json && empty {
        println!("  note    {EMPTY_PROOF}");
    }
    if !proof.holds() {
        bail!(
            "the configuration changes detections: {} missing, {} extra alerts",
            proof.missing.len(),
            proof.extra.len()
        );
    }
    if empty && !args.allow_no_alerts {
        bail!(
            "{EMPTY_PROOF} Add a sample with the attacks your rules detect, or pass --allow-no-alerts."
        );
    }
    if !args.json {
        println!("  ✓ no detection changed");
    }
    Ok(())
}

/// The proof of the Vector configuration `yaml` on `events`, with the sources it leaves
/// unreduced. Refuses a configuration whose programs are not all Sluice's: the proof would not
/// cover them.
pub(crate) fn proof_of(
    yaml: &str,
    sources: &[sluice_core::source::Source],
    events: &[sluice_core::event::Event],
    engines: &Engines<'_>,
) -> Result<(sluice_core::proof::Proof, Vec<sluice_core::ids::SourceId>)> {
    let deployed =
        sluice_vector::deployed(yaml, sources).context("reading the configuration's reductions")?;
    let unproven = deployed.unproven();
    if !unproven.is_empty() {
        bail!(
            "the configuration runs programs this proof does not cover ({}): they are not \
             Sluice's programs for these sources",
            unproven
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if deployed.unreduced.len() == sources.len() {
        bail!("the configuration has no Sluice program for any of these sources");
    }
    let proof = run_proof(events, engines, &deployed.reducer)?;
    Ok((proof, deployed.unreduced))
}

/// The proof and the savings as JSON, as `--json` prints them (without the file's name).
pub(crate) fn summary(
    proof: &sluice_core::proof::Proof,
    unreduced: &[sluice_core::ids::SourceId],
) -> serde_json::Value {
    let total = proof.total;
    json!({
        "holds": proof.holds(),
        "alerts_full": proof.full_alerts.len(),
        "alerts_forwarded": proof.forwarded_alerts.len(),
        "missing": proof.missing.iter().map(|a| format!("{} on event {}", a.rule, a.event)).collect::<Vec<_>>(),
        "extra": proof.extra.iter().map(|a| format!("{} on event {}", a.rule, a.event)).collect::<Vec<_>>(),
        "events": total.events,
        "summarized": total.summarized,
        "summaries": total.summaries,
        "bytes_in": total.bytes_in,
        "bytes_out": total.bytes_out,
        "saved_percent": (saved_percent(total) * 10.0).round() / 10.0,
        "note": proof.full_alerts.is_empty().then_some(EMPTY_PROOF),
        "unreduced_sources": unreduced.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

fn saved_percent(total: sluice_core::proof::Volume) -> f64 {
    if total.bytes_in == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss, reason = "a percentage for people")]
    let share =
        (total.bytes_in - total.bytes_out.min(total.bytes_in)) as f64 / total.bytes_in as f64;
    share * 100.0
}

/// Prints the proof and the savings, as text or as JSON.
fn print(
    args: &ProveArgs,
    proof: &sluice_core::proof::Proof,
    unreduced: &[sluice_core::ids::SourceId],
) -> Result<()> {
    let total = proof.total;
    let saved = saved_percent(total);
    if args.json {
        let mut summary = summary(proof, unreduced);
        summary["config"] = json!(args.config.display().to_string());
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("{}", args.config.display());
        let records = if total.summarized == 0 {
            String::new()
        } else {
            format!(" into {} records", total.summaries)
        };
        println!(
            "  ingest  {} → {} bytes ({saved:.1}% saved, {} of {} events summarized{records})",
            total.bytes_in, total.bytes_out, total.summarized, total.events
        );
        println!(
            "  proof   {} alerts on full data, {} on forwarded data",
            proof.full_alerts.len(),
            proof.forwarded_alerts.len()
        );
        for alert in &proof.missing {
            println!("  missing {} on event {}", alert.rule, alert.event);
        }
        for alert in &proof.extra {
            println!("  extra   {} on event {}", alert.rule, alert.event);
        }
    }
    Ok(())
}

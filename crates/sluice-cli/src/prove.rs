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
    let deployed = sluice_vector::deployed(&yaml, &sources, args.profile.as_deref())
        .with_context(|| format!("reading the reductions of {}", args.config.display()))?;
    let unproven = deployed.unproven();
    if !unproven.is_empty() && args.profile.is_none() {
        bail!(
            "{} runs programs this proof does not cover ({}): name the rule profile with \
             --profile, or the programs are not Sluice's",
            args.config.display(),
            unproven
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if deployed.unreduced.len() == sources.len() {
        bail!(
            "{} has no Sluice program for any of these sources{}",
            args.config.display(),
            if args.profile.is_none() {
                "; for a configuration with several rule profiles, name one with --profile"
            } else {
                ""
            }
        );
    }

    let sigma_files = match &args.rules {
        Some(dir) => input::files(dir, &["yml", "yaml"])?,
        None => Vec::new(),
    };
    let sigma = SigmaRules::parse_with(
        sigma_files.iter().map(|(_, text)| text.as_str()),
        &input::sigma_pipelines(&args.sigma_pipeline)?,
    )?;
    let sigma_engine = sigma.engine(&sources)?;
    let sentinel = input::sentinel(args.sentinel_rules.as_deref())?;
    let kusto = match (&sentinel, &args.kusto) {
        (Some(rules), Some(url)) => Some(input::kusto(url, rules, &args.sentinel_table, &events)?),
        _ => None,
    };
    if sigma.requirements().is_empty() && kusto.is_none() {
        bail!("no rules to prove against: give --rules, or --sentinel-rules with --kusto");
    }
    let mut engines: Vec<&dyn RuleEngine> = vec![&sigma_engine];
    engines.extend(kusto.as_ref().map(|k| k as &dyn RuleEngine));
    let proof = run_proof(&events, &Engines(engines), &deployed.reducer)?;

    print(args, &proof, &deployed.unreduced)?;
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

/// Prints the proof and the savings, as text or as JSON.
fn print(
    args: &ProveArgs,
    proof: &sluice_core::proof::Proof,
    unreduced: &[sluice_core::ids::SourceId],
) -> Result<()> {
    let total = proof.total;
    let saved = if total.bytes_in == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss, reason = "a percentage for people")]
        let share =
            (total.bytes_in - total.bytes_out.min(total.bytes_in)) as f64 / total.bytes_in as f64;
        share * 100.0
    };
    if args.json {
        let summary = json!({
            "config": args.config.display().to_string(),
            "holds": proof.holds(),
            "alerts_full": proof.full_alerts.len(),
            "alerts_forwarded": proof.forwarded_alerts.len(),
            "missing": proof.missing.iter().map(|a| format!("{} on event {}", a.rule, a.event)).collect::<Vec<_>>(),
            "extra": proof.extra.iter().map(|a| format!("{} on event {}", a.rule, a.event)).collect::<Vec<_>>(),
            "events": total.events,
            "summarized": total.summarized,
            "bytes_in": total.bytes_in,
            "bytes_out": total.bytes_out,
            "saved_percent": (saved * 10.0).round() / 10.0,
            "note": proof.full_alerts.is_empty().then_some(EMPTY_PROOF),
            "unreduced_sources": unreduced.iter().map(ToString::to_string).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("{}", args.config.display());
        println!(
            "  ingest  {} → {} bytes ({saved:.1}% saved, {} of {} events summarized)",
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
